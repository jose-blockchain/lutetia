//! Symbolic EVM interpreter with BFS control-flow exploration.
//!
//! Executes EVM bytecode symbolically using breadth-first search to follow
//! all reachable paths. Detects loops via back-edge detection (when the same
//! jump-destination signature is revisited) and produces a trace with
//! `label`/`goto`/`if` constructs that `whiles.rs` converts to while loops.

use crate::core::algebra;
use crate::core::arithmetic as arith;
use crate::errors;
use crate::expr::{Expr, Trace};
use crate::loader::Loader;
use crate::stack::{fold_stacks, Stack};
use primitive_types::U256;
use std::collections::HashMap;
use std::time::Instant;

const DEFAULT_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Jump-destination signature for loop detection
// ---------------------------------------------------------------------------

/// Uniquely identifies a program state for loop-detection purposes.
/// Two nodes with the same JdKey at the same execution depth indicate a
/// revisited state (back-edge → loop).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JdKey {
    offset: usize,
    stack_len: usize,
    jump_dests: Vec<usize>,
}

impl JdKey {
    fn new(offset: usize, stack: &Stack, known_jds: &[usize]) -> Self {
        Self {
            offset,
            stack_len: stack.len(),
            jump_dests: stack.jump_dests(known_jds).iter().filter_map(|s| s.parse().ok()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Control-flow graph node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum CfgEdge {
    /// Not yet determined.
    Pending,
    /// Terminal: stop/return/revert/selfdestruct/invalid.
    Terminal,
    /// Unconditional jump to another node.
    Jump(usize),
    /// Conditional branch: (condition, true_node, false_node).
    Branch(Expr, usize, usize),
    /// Back-edge detected (loop): (loop_head, current_stack, folded_stack, vars).
    LoopBack(usize, Vec<Expr>, Vec<Expr>, Vec<(String, usize, Expr, usize)>),
    /// Goto: (target_node, setvars as (var_idx, value)).
    Goto(usize, Vec<Expr>),
}

#[derive(Debug, Clone)]
struct CfgNode {
    id: usize,
    start: usize,
    safe: bool,
    stack: Vec<Expr>,
    condition: Expr,
    /// Lines produced by executing this basic block (None = not yet executed).
    trace: Option<Trace>,
    edge: CfgEdge,
    /// History: jd_key → node_id of the ancestor that had that key.
    history: HashMap<JdKey, usize>,
    depth: usize,
    jd: JdKey,
    prev: Option<usize>,
    next: Vec<usize>,
    /// Loop variables for a label node.
    begin_vars: Vec<(String, usize, Expr, usize)>,
    is_label: bool,
}

// ---------------------------------------------------------------------------
// Node arena
// ---------------------------------------------------------------------------

struct Arena {
    nodes: Vec<CfgNode>,
}

impl Arena {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn alloc(&mut self, start: usize, safe: bool, stack: Vec<Expr>, condition: Expr, known_jds: &[usize]) -> usize {
        let id = self.nodes.len();
        let s = Stack::from_vec(stack.clone());
        let jd = JdKey::new(start, &s, known_jds);
        self.nodes.push(CfgNode {
            id,
            start,
            safe,
            stack,
            condition,
            trace: None,
            edge: CfgEdge::Pending,
            history: HashMap::new(),
            depth: 0,
            jd,
            prev: None,
            next: Vec::new(),
            begin_vars: Vec::new(),
            is_label: false,
        });
        id
    }

    fn get(&self, id: usize) -> &CfgNode {
        &self.nodes[id]
    }

    fn get_mut(&mut self, id: usize) -> &mut CfgNode {
        &mut self.nodes[id]
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Link child to parent, propagating history.
    fn set_prev(&mut self, child_id: usize, parent_id: usize) {
        let parent = &self.nodes[parent_id];
        let mut history = parent.history.clone();
        history.insert(parent.jd.clone(), parent_id);
        let depth = parent.depth + 1;

        let child = &mut self.nodes[child_id];
        child.prev = Some(parent_id);
        child.depth = depth;
        child.history = history;

        self.nodes[parent_id].next.push(child_id);
    }

    /// Find all nodes whose trace is None (unexplored).
    fn unexplored(&self) -> Vec<usize> {
        self.nodes.iter().filter(|n| n.trace.is_none()).map(|n| n.id).collect()
    }

    // (Removed unused loop_backs method)
}

// ---------------------------------------------------------------------------
// The symbolic VM
// ---------------------------------------------------------------------------

/// Helper: build `("mem", ("range", pos, size))`.
fn mem_load(pos: Expr, size: Expr) -> Expr {
    Expr::node1("mem", Expr::node2("range", pos, size))
}

pub struct VM {
    pub loader: Loader,
    pub just_fdests: bool,
    counter: usize,
}

impl VM {
    /// Create a new VM instance. If `just_fdests` is true, only discover function
    /// destinations without full execution.
    pub fn new(loader: Loader, just_fdests: bool) -> Self {
        Self {
            loader,
            just_fdests,
            counter: 0,
        }
    }

    /// Run BFS symbolic execution from a given start offset.
    pub fn run(&mut self, start: usize, stack: Vec<Expr>, timeout_secs: u64) -> Trace {
        let time_start = Instant::now();
        let timeout = if timeout_secs == 0 { DEFAULT_TIMEOUT_SECS } else { timeout_secs };
        let known_jds = self.loader.jump_dests.clone();

        let mut arena = Arena::new();

        // Create root node and func_node.
        let root_id = arena.alloc(start, true, stack.clone(), Expr::Bool(true), &known_jds);

        // Initial memory setup trace for root.
        let init_trace = vec![Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(0x40), Expr::val(32)),
            Expr::val(0x60),
        )];

        let func_id = arena.alloc(start, true, stack, Expr::Bool(true), &known_jds);
        arena.set_prev(func_id, root_id);

        // Root's trace just jumps to func_node.
        arena.get_mut(root_id).trace = Some(init_trace);
        arena.get_mut(root_id).edge = CfgEdge::Jump(func_id);

        let max_nodes = errors::MAX_NODE_COUNT;
        let should_quit = |arena: &Arena| -> bool {
            arena.len() > max_nodes || time_start.elapsed().as_secs() > timeout
        };

        // BFS: outer loop (up to 20 iterations for loop re-expansion).
        for _outer in 0..20 {
            // Inner loop: expand + detect loops.
            for _inner in 0..200 {
                self.expand_all(&mut arena, &known_jds);
                self.detect_loops(&mut arena);

                if arena.unexplored().is_empty() || should_quit(&arena) {
                    break;
                }
            }

            self.resolve_loops(&mut arena, &known_jds);

            if arena.unexplored().is_empty() || should_quit(&arena) {
                break;
            }
        }

        if should_quit(&arena) {
            log::warn!(
                "VM stopped prematurely: {} nodes, {:.1}s elapsed",
                arena.len(),
                time_start.elapsed().as_secs_f64()
            );
        }

        // Convert the node graph to a linear trace.
        let mut visited = std::collections::HashSet::new();
        self.make_trace(&arena, root_id, &mut visited)
    }

    // -- BFS phases ---------------------------------------------------------

    /// Expand all unexplored nodes.
    fn expand_all(&mut self, arena: &mut Arena, known_jds: &[usize]) {
        let unexplored: Vec<usize> = arena.unexplored();
        for node_id in unexplored {
            self.execute_node(arena, node_id, known_jds);
        }
    }

    /// Execute a single node: run bytecode from its start until the next
    /// control-flow event (jump/jumpi/stop/return/jumpdest).
    fn execute_node(&mut self, arena: &mut Arena, node_id: usize, known_jds: &[usize]) {
        let node = arena.get(node_id);
        let start = node.start;
        let safe = node.safe;
        let stack_vec = node.stack.clone();
        let condition = node.condition.clone();

        let mut stack = Stack::from_vec(stack_vec);
        let mut trace = Trace::new();
        let mut offset = start;

        // Validate jumpdest if not safe.
        if !safe {
            match self.loader.lines.get(&offset) {
                Some(inst) if inst.op == "jumpdest" => {
                    match self.loader.next_line(offset) {
                        Some(next) => offset = next,
                        None => {
                            arena.get_mut(node_id).trace = Some(vec![Expr::node1("invalid", Expr::atom("eof"))]);
                            arena.get_mut(node_id).edge = CfgEdge::Terminal;
                            return;
                        }
                    }
                }
                _ => {
                    arena.get_mut(node_id).trace = Some(vec![Expr::node1("invalid", Expr::atom("bad jumpdest"))]);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
            }
        }

        loop {
            // Borrow the instruction briefly to extract op and param, avoiding
            // a full clone on every iteration.
            let (op_owned, param, inst_offset) = match self.loader.lines.get(&offset) {
                Some(i) => (i.op.clone(), i.param, i.offset),
                None => {
                    trace.push(Expr::node1("invalid", Expr::atom("missing instruction")));
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
            };

            let op = op_owned.as_str();

            match op {
                // -- Terminal opcodes --
                "stop" => {
                    trace.push(Expr::node0("stop"));
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
                "invalid" => {
                    trace.push(Expr::node0("invalid"));
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
                "return" | "revert" => {
                    let p = stack.pop();
                    let n = stack.pop();
                    if n.is_zero() {
                        trace.push(Expr::node1(op, Expr::zero()));
                    } else {
                        trace.push(Expr::node1(op, mem_load(p, n)));
                    }
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
                "selfdestruct" => {
                    trace.push(Expr::node1("selfdestruct", stack.pop()));
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }

                // -- Unconditional jump --
                "jump" => {
                    let target = stack.pop();
                    if let Some(target_offset) = target.as_u64() {
                        let child_id = arena.alloc(
                            target_offset as usize,
                            false,
                            stack.items.clone(),
                            condition,
                            known_jds,
                        );
                        arena.set_prev(child_id, node_id);
                        arena.get_mut(node_id).trace = Some(trace);
                        arena.get_mut(node_id).edge = CfgEdge::Jump(child_id);
                    } else {
                        trace.push(Expr::node1("undefined", Expr::atom("dynamic jump target")));
                        arena.get_mut(node_id).trace = Some(trace);
                        arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    }
                    return;
                }

                // -- Conditional jump (JUMPI) --
                "jumpi" => {
                    let target = stack.pop();
                    let if_cond = stack.pop();
                    let stack_snapshot = stack.items.clone();

                    // Try to evaluate the condition concretely.
                    if let Some(v) = if_cond.as_val() {
                        if !v.is_zero() {
                            // Always true → take the jump.
                            if let Some(t) = target.as_u64() {
                                let child = arena.alloc(t as usize, false, stack_snapshot, condition, known_jds);
                                arena.set_prev(child, node_id);
                                arena.get_mut(node_id).trace = Some(trace);
                                arena.get_mut(node_id).edge = CfgEdge::Jump(child);
                            } else {
                                trace.push(Expr::node1("undefined", Expr::atom("dynamic jump")));
                                arena.get_mut(node_id).trace = Some(trace);
                                arena.get_mut(node_id).edge = CfgEdge::Terminal;
                            }
                            return;
                        } else {
                            // Always false → fall through.
                            match self.loader.next_line(offset) {
                                Some(next) => { offset = next; continue; }
                                None => {
                                    arena.get_mut(node_id).trace = Some(trace);
                                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                                    return;
                                }
                            }
                        }
                    }

                    // Create two child nodes for both branches.
                    if let Some(target_offset) = target.as_u64() {
                        let true_id = arena.alloc(
                            target_offset as usize,
                            false,
                            stack_snapshot.clone(),
                            if_cond.clone(),
                            known_jds,
                        );
                        let next_offset = self.loader.next_line(offset).unwrap_or(offset + 1);
                        let false_id = arena.alloc(
                            next_offset,
                            true,
                            stack_snapshot,
                            if_cond.is_zero_wrap(),
                            known_jds,
                        );
                        arena.set_prev(true_id, node_id);
                        arena.set_prev(false_id, node_id);

                        // Function discovery mode: detect selector checks.
                        if self.just_fdests {
                            self.detect_selector_check(arena, &if_cond, true_id, target_offset as usize);
                        }

                        arena.get_mut(node_id).trace = Some(trace);
                        arena.get_mut(node_id).edge = CfgEdge::Branch(if_cond, true_id, false_id);
                    } else {
                        trace.push(Expr::node1("undefined", Expr::atom("dynamic jump target")));
                        arena.get_mut(node_id).trace = Some(trace);
                        arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    }
                    return;
                }

                // -- JUMPDEST in the middle of execution → create a new node --
                "jumpdest" => {
                    let child_id = arena.alloc(
                        offset,
                        false,
                        stack.items.clone(),
                        condition,
                        known_jds,
                    );
                    arena.set_prev(child_id, node_id);
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Jump(child_id);
                    return;
                }

                // -- All other opcodes: process symbolically --
                _ => {
                    self.apply_stack(&mut trace, op, param.unwrap_or(U256::zero()), inst_offset, &mut stack);
                }
            }

            match self.loader.next_line(offset) {
                Some(next) => offset = next,
                None => {
                    arena.get_mut(node_id).trace = Some(trace);
                    arena.get_mut(node_id).edge = CfgEdge::Terminal;
                    return;
                }
            }
        }
    }

    /// Detect back-edges (loops): if a node's JdKey matches an ancestor's.
    fn detect_loops(&self, arena: &mut Arena) {
        let unexplored: Vec<usize> = arena.unexplored();
        for node_id in unexplored {
            let node = arena.get(node_id);
            if let Some(&ancestor_id) = node.history.get(&node.jd) {
                let ancestor = arena.get(ancestor_id);
                if node.jd.stack_len > 0 && ancestor.stack.len() == node.stack.len() {
                    // Back-edge found → fold stacks to identify loop variables.
                    let (folded, vars) = fold_stacks(&ancestor.stack, &node.stack, node.depth);
                    let current_stack = node.stack.clone();
                    let n = arena.get_mut(node_id);
                    n.trace = Some(vec![]);
                    n.edge = CfgEdge::LoopBack(ancestor_id, current_stack, folded, vars);
                }
            }
        }
    }

    /// Convert loop-back edges into labels/gotos. May re-open nodes for
    /// re-execution with abstracted loop variables.
    fn resolve_loops(&mut self, arena: &mut Arena, _known_jds: &[usize]) {
        let loop_nodes: Vec<usize> = arena.nodes.iter()
            .filter(|n| matches!(n.edge, CfgEdge::LoopBack(..)))
            .map(|n| n.id)
            .collect();

        for node_id in loop_nodes {
            let node = arena.get(node_id).clone();
            if let CfgEdge::LoopBack(dest_id, stack, folded, vars) = &node.edge {
                let dest = arena.get(*dest_id);
                if dest.is_label {
                    // Destination is already a label → emit goto with setvars.
                    let mut setvars = Vec::new();
                    for (_vname, vidx, _init, spos) in &dest.begin_vars {
                        if let Some(val) = stack.get(*spos) {
                            setvars.push(Expr::node2("setvar", Expr::val(*vidx as u64), val.clone()));
                        }
                    }
                    arena.get_mut(node_id).edge = CfgEdge::Goto(*dest_id, setvars);
                } else {
                    // First time: set up the label.
                    let vars_clone = vars.clone();
                    let folded_clone = folded.clone();
                    let dest_id_copy = *dest_id;

                    // Mark destination as a label.
                    arena.get_mut(dest_id_copy).is_label = true;
                    arena.get_mut(dest_id_copy).begin_vars = vars_clone.clone();

                    // Replace the destination's stack with the folded (variable) stack.
                    arena.get_mut(dest_id_copy).stack = folded_clone;

                    // Re-open the destination for re-execution with new stack.
                    arena.get_mut(dest_id_copy).trace = None;
                    arena.get_mut(dest_id_copy).edge = CfgEdge::Pending;
                    arena.get_mut(dest_id_copy).next.clear();

                    // Mark this node as a goto.
                    let mut setvars = Vec::new();
                    for (_vname, vidx, _init, spos) in &vars_clone {
                        if let Some(val) = stack.get(*spos) {
                            setvars.push(Expr::node2("setvar", Expr::val(*vidx as u64), val.clone()));
                        }
                    }
                    arena.get_mut(node_id).edge = CfgEdge::Goto(dest_id_copy, setvars);
                }
            }
        }
    }

    /// In just_fdests mode, detect function selector dispatch patterns.
    fn detect_selector_check(&self, arena: &mut Arena, cond: &Expr, true_id: usize, target: usize) {
        // Pattern: eq(HASH, cd(0)) or eq(cd(0), HASH)
        if let Some(ch) = cond.children() {
            if cond.opcode() == Some("eq") && ch.len() == 2 {
                let (a, b) = (&ch[0], &ch[1]);
                let (hash, cd) = if a.is_val() { (a, b) } else { (b, a) };
                if hash.is_val() {
                    // Use proper AST traversal instead of format!("{:?}") string matching.
                    if cd.contains_op("cd") {
                        if let Some(h) = hash.as_val() {
                            arena.get_mut(true_id).trace = Some(vec![
                                Expr::node3("funccall", Expr::Val(h), Expr::val(target as u64), Expr::zero()),
                            ]);
                            arena.get_mut(true_id).edge = CfgEdge::Terminal;
                        }
                    }
                }
            }
        }
    }

    // -- Trace generation ---------------------------------------------------

    /// Convert the CFG node graph into a flat trace with if/label/goto constructs.
    /// Uses iterative traversal for Jump edges to avoid stack overflow on long chains.
    fn make_trace(&self, arena: &Arena, start_id: usize, visited: &mut std::collections::HashSet<usize>) -> Trace {
        let mut result = Trace::new();
        let mut current_id = start_id;

        loop {
            if !visited.insert(current_id) {
                // Already visited — emit a goto to prevent cycles.
                result.push(Expr::node1("goto", Expr::val(current_id as u64)));
                return result;
            }

            let node = arena.get(current_id);

            // If this is a label node, emit the label marker.
            if node.is_label {
                let vars: Vec<Expr> = node.begin_vars.iter()
                    .map(|(name, idx, init, _)| Expr::node3("_var", Expr::atom(name), Expr::val(*idx as u64), init.clone()))
                    .collect();
                result.push(Expr::Node("label".to_string(), vec![
                    Expr::val(current_id as u64),
                    Expr::node("_vars", vars),
                ]));
            }

            // Append the node's computed trace.
            if let Some(ref trace) = node.trace {
                result.extend(trace.clone());
            }

            // Follow the edge.
            match &node.edge {
                CfgEdge::Terminal | CfgEdge::Pending => return result,
                CfgEdge::Jump(target_id) => {
                    // Iterative: continue with the target (no recursion).
                    current_id = *target_id;
                    continue;
                }
                CfgEdge::Branch(cond, true_id, false_id) => {
                    let mut true_visited = visited.clone();
                    let mut false_visited = visited.clone();
                    let if_true = self.make_trace(arena, *true_id, &mut true_visited);
                    let if_false = self.make_trace(arena, *false_id, &mut false_visited);
                    result.push(Expr::node3(
                        "if",
                        cond.clone(),
                        Expr::node("seq", if_true),
                        Expr::node("seq", if_false),
                    ));
                    // Merge visited sets back.
                    visited.extend(true_visited);
                    visited.extend(false_visited);
                    return result;
                }
                CfgEdge::LoopBack(dest_id, _stack, _folded, _vars) => {
                    result.push(Expr::node1("goto", Expr::val(*dest_id as u64)));
                    return result;
                }
                CfgEdge::Goto(dest_id, setvars) => {
                    let mut goto_children = vec![Expr::val(*dest_id as u64)];
                    goto_children.extend(setvars.clone());
                    result.push(Expr::Node("goto".to_string(), goto_children));
                    return result;
                }
            }
        }
    }

    // -- Individual opcode handling -----------------------------------------

    /// Process a single non-terminal opcode: update the stack and optionally
    /// append to the trace.
    fn apply_stack(&mut self, trace: &mut Trace, op: &str, param: U256, inst_offset: usize, stack: &mut Stack) {

        match op {
            "add" => {
                let a = stack.pop();
                let b = stack.pop();
                stack.push(algebra::add_op(a, b));
            }
            "sub" => {
                let a = stack.pop();
                let b = stack.pop();
                stack.push(algebra::sub_op(a, b));
            }
            "mul" => {
                let a = stack.pop();
                let b = stack.pop();
                stack.push(algebra::mul_op(a, b));
            }
            "div" | "sdiv" | "mod" | "smod" | "exp" | "signextend" | "lt" | "gt"
            | "slt" | "sgt" | "eq" | "xor" => {
                let a = stack.pop();
                let b = stack.pop();
                if let (Some(va), Some(vb)) = (a.as_val(), b.as_val()) {
                    if let Some(result) = arith::eval_concrete(op, &[va, vb]) {
                        stack.push(Expr::Val(result));
                        return;
                    }
                }
                stack.push(Expr::node2(op, a, b));
            }
            "addmod" | "mulmod" => {
                let a = stack.pop();
                let b = stack.pop();
                let c = stack.pop();
                if let (Some(va), Some(vb), Some(vc)) = (a.as_val(), b.as_val(), c.as_val()) {
                    if let Some(result) = arith::eval_concrete(op, &[va, vb, vc]) {
                        stack.push(Expr::Val(result));
                        return;
                    }
                }
                stack.push(Expr::node3(op, a, b, c));
            }
            "and" => {
                let a = stack.pop();
                let b = stack.pop();
                if let (Some(va), Some(vb)) = (a.as_val(), b.as_val()) {
                    stack.push(Expr::Val(va & vb));
                } else {
                    stack.push(Expr::node2("and", a, b));
                }
            }
            "or" => {
                let a = stack.pop();
                let b = stack.pop();
                stack.push(algebra::or_op(a, b));
            }
            "not" | "iszero" => {
                let a = stack.pop();
                if let Some(va) = a.as_val() {
                    if let Some(result) = arith::eval_concrete(op, &[va]) {
                        stack.push(Expr::Val(result));
                        return;
                    }
                }
                stack.push(Expr::node1(op, a));
            }
            "byte" => {
                let pos = stack.pop();
                let val = stack.pop();
                if let (Some(vp), Some(vv)) = (pos.as_val(), val.as_val()) {
                    stack.push(Expr::Val(arith::byte_op(vp, vv)));
                } else {
                    stack.push(Expr::node2("byte", pos, val));
                }
            }
            "shl" => {
                let shift = stack.pop();
                let val = stack.pop();
                if let (Some(vs), Some(vv)) = (shift.as_val(), val.as_val()) {
                    stack.push(Expr::Val(arith::shl(vs, vv)));
                } else {
                    stack.push(Expr::node2("shl", shift, val));
                }
            }
            "shr" => {
                let shift = stack.pop();
                let val = stack.pop();
                if let (Some(vs), Some(vv)) = (shift.as_val(), val.as_val()) {
                    stack.push(Expr::Val(arith::shr(vs, vv)));
                } else {
                    stack.push(Expr::node2("shr", shift, val));
                }
            }
            "sar" => {
                let shift = stack.pop();
                let val = stack.pop();
                if let (Some(vs), Some(vv)) = (shift.as_val(), val.as_val()) {
                    stack.push(Expr::Val(arith::sar(vs, vv)));
                } else {
                    stack.push(Expr::node2("sar", shift, val));
                }
            }
            p if p.starts_with("push") => {
                stack.push(Expr::Val(param));
            }
            "pop" => { stack.pop(); }
            "dup" => { stack.dup(param.low_u64() as usize); }
            "swap" => { stack.swap(param.low_u64() as usize); }
            "mload" => {
                self.counter += 1;
                let loc = stack.pop();
                let vname = format!("_{}", self.counter);
                trace.push(Expr::node2("setvar", Expr::atom(&vname), mem_load(loc, Expr::val(32))));
                stack.push(Expr::node1("var", Expr::atom(&vname)));
            }
            "mstore" => {
                let loc = stack.pop();
                let val = stack.pop();
                trace.push(Expr::node2("setmem", Expr::node2("range", loc, Expr::val(32)), val));
            }
            "mstore8" => {
                let loc = stack.pop();
                let val = stack.pop();
                trace.push(Expr::node2("setmem", Expr::node2("range", loc, Expr::val(1)), val));
            }
            "sload" => {
                let slot = stack.pop();
                stack.push(Expr::Node("storage".into(), vec![Expr::val(256), Expr::zero(), slot]));
            }
            "sstore" => {
                let slot = stack.pop();
                let val = stack.pop();
                trace.push(Expr::Node("store".into(), vec![Expr::val(256), Expr::zero(), slot, val]));
            }
            "tload" => {
                let slot = stack.pop();
                stack.push(Expr::Node("tstorage".into(), vec![Expr::val(256), Expr::zero(), slot]));
            }
            "tstore" => {
                let slot = stack.pop();
                let val = stack.pop();
                trace.push(Expr::Node("tstore".into(), vec![Expr::val(256), Expr::zero(), slot, val]));
            }
            "sha3" => {
                let p = stack.pop();
                let n = stack.pop();
                self.counter += 1;
                let vname = format!("_{}", self.counter);
                trace.push(Expr::node2("setvar", Expr::atom(&vname), Expr::node1("sha3", mem_load(p, n))));
                stack.push(Expr::node1("var", Expr::atom(&vname)));
            }
            "calldataload" => {
                let off = stack.pop();
                stack.push(Expr::node1("cd", off));
            }
            "calldatasize" => stack.push(Expr::atom("calldatasize")),
            "calldatacopy" => {
                let mp = stack.pop();
                let cp = stack.pop();
                let dl = stack.pop();
                if !dl.is_zero() {
                    trace.push(Expr::node2("setmem", Expr::node2("range", mp, dl.clone()), Expr::node2("call.data", cp, dl)));
                }
            }
            "address" | "caller" | "callvalue" | "origin" | "gasprice" | "coinbase"
            | "timestamp" | "number" | "difficulty" | "gaslimit" | "chainid"
            | "basefee" | "returndatasize" | "gas" => {
                stack.push(Expr::atom(op));
            }
            "selfbalance" => stack.push(Expr::node1("balance", Expr::atom("address"))),
            "balance" => { let a = stack.pop(); stack.push(Expr::node1("balance", a)); }
            "extcodesize" | "extcodehash" | "blockhash" => { let a = stack.pop(); stack.push(Expr::node1(op, a)); }
            "codesize" => stack.push(Expr::val(self.loader.binary.len() as u64)),
            "codecopy" => {
                let mp = stack.pop(); let cp = stack.pop(); let dl = stack.pop();
                trace.push(Expr::node2("setmem", Expr::node2("range", mp, dl.clone()), Expr::node2("code.data", cp, dl)));
            }
            "extcodecopy" => {
                let addr = stack.pop(); let mp = stack.pop(); let cp = stack.pop(); let dl = stack.pop();
                trace.push(Expr::node2("setmem", Expr::node2("range", mp, dl.clone()), Expr::node2("extcodecopy", addr, Expr::node2("range", cp, dl))));
            }
            "returndatacopy" => {
                let mp = stack.pop(); let rp = stack.pop(); let dl = stack.pop();
                if !dl.is_zero() {
                    trace.push(Expr::node2("setmem", Expr::node2("range", mp, dl.clone()), Expr::node2("ext_call.return_data", rp, dl)));
                }
            }
            "mcopy" => {
                let dst = stack.pop(); let src = stack.pop(); let len = stack.pop();
                trace.push(Expr::node2("setmem", Expr::node2("range", dst, len.clone()), mem_load(src, len)));
            }
            "blobhash" => { let idx = stack.pop(); stack.push(Expr::node1("blobhash", idx)); }
            "blobbasefee" => stack.push(Expr::atom("blobbasefee")),
            l if l.starts_with("log") => {
                let p = stack.pop(); let s = stack.pop();
                let n = l[3..].parse::<usize>().unwrap_or(0);
                let mut topics = Vec::new();
                for _ in 0..n { topics.push(stack.pop()); }
                let mut children = vec![mem_load(p, s)];
                children.extend(topics);
                trace.push(Expr::Node("log".into(), children));
            }
            "call" | "staticcall" | "delegatecall" | "callcode" => {
                self.handle_call(op, trace, stack);
            }
            "create" => {
                let wei = stack.pop(); let ms = stack.pop(); let ml = stack.pop();
                trace.push(Expr::node2("create", wei, mem_load(ms, ml)));
                stack.push(Expr::atom("create.new_address"));
            }
            "create2" => {
                let wei = stack.pop(); let ms = stack.pop(); let ml = stack.pop(); let salt = stack.pop();
                trace.push(Expr::node3("create2", wei, mem_load(ms, ml), salt));
                stack.push(Expr::atom("create2.new_address"));
            }
            "pc" => stack.push(Expr::val(inst_offset as u64)),
            "msize" => {
                self.counter += 1;
                let vname = format!("_{}", self.counter);
                trace.push(Expr::node2("setvar", Expr::atom(&vname), Expr::atom("msize")));
                stack.push(Expr::node1("var", Expr::atom(&vname)));
            }
            "jumpdest" => { /* no-op */ }
            _ => { log::warn!("Unhandled opcode: {op}"); }
        }
    }

    fn handle_call(&mut self, op: &str, trace: &mut Trace, stack: &mut Stack) {
        let gas = stack.pop();
        let addr = stack.pop();
        let wei = if op == "call" || op == "callcode" { stack.pop() } else { Expr::zero() };
        let arg_start = stack.pop();
        let arg_len = stack.pop();
        let ret_start = stack.pop();
        let ret_len = stack.pop();

        let (fname, fparams) = if arg_len.is_zero() {
            (Expr::Bool(false), Expr::Bool(false))
        } else if arg_len == Expr::val(4) {
            (mem_load(arg_start.clone(), Expr::val(4)), Expr::Bool(false))
        } else {
            let fname = mem_load(arg_start.clone(), Expr::val(4));
            let fp = mem_load(
                algebra::add_op(arg_start.clone(), Expr::val(4)),
                algebra::sub_op(arg_len.clone(), Expr::val(4)),
            );
            (fname, fp)
        };

        trace.push(Expr::Node(op.into(), vec![gas, addr, wei, fname, fparams]));
        stack.push(Expr::atom("ext_call.success"));

        if !ret_len.is_zero() {
            trace.push(Expr::node2(
                "setmem",
                Expr::node2("range", ret_start, ret_len.clone()),
                Expr::node2("ext_call.return_data", Expr::zero(), ret_len),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_bytecode(hex: &str) -> Trace {
        let mut loader = Loader::new();
        loader.load_binary(hex).unwrap();
        let mut vm = VM::new(loader, false);
        vm.run(0, vec![], 5)
    }

    #[test]
    fn test_vm_simple_stop() {
        let trace = run_bytecode("00");
        let last = trace.last().unwrap();
        assert_eq!(last.opcode(), Some("stop"));
    }

    #[test]
    fn test_vm_push_and_stop() {
        let trace = run_bytecode("604200");
        let last = trace.last().unwrap();
        assert_eq!(last.opcode(), Some("stop"));
    }

    #[test]
    fn test_vm_add() {
        let trace = run_bytecode("6002600301600052600000");
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_vm_revert() {
        let trace = run_bytecode("60006000fd");
        let last = trace.last().unwrap();
        assert_eq!(last.opcode(), Some("revert"));
    }

    #[test]
    fn test_vm_shl_shr() {
        let trace = run_bytecode("600160041b601060041c00");
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_vm_conditional_branch() {
        // PUSH1 1, PUSH1 target, JUMPI, STOP, JUMPDEST, STOP
        // Bytecode: PUSH1 1, PUSH1 6, JUMPI, STOP, JUMPDEST, STOP
        let trace = run_bytecode("6001600657005b00");
        // Should have an if branch or follow one path.
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_vm_unconditional_jump() {
        // PUSH1 target, JUMP, STOP, JUMPDEST, STOP
        // PUSH1 4, JUMP, STOP, JUMPDEST, STOP
        let trace = run_bytecode("6004565b00");
        // Should follow the jump and reach the JUMPDEST then STOP.
        let has_stop = trace.iter().any(|e| e.opcode() == Some("stop"));
        let has_invalid = trace.iter().any(|e| e.opcode() == Some("invalid"));
        assert!(has_stop || has_invalid);
    }

    #[test]
    fn test_vm_sstore() {
        let trace = run_bytecode("602a60005500");
        assert!(trace.iter().any(|e| e.contains_op("store")));
    }

    #[test]
    fn test_vm_calldataload() {
        let trace = run_bytecode("600035600052600000");
        assert!(trace.iter().any(|e| e.contains_op("cd")));
    }

    #[test]
    fn test_vm_timeout() {
        // A loop that the BFS should handle (or timeout).
        let trace = run_bytecode("5b6000565b00");
        assert!(!trace.is_empty());
    }
}
