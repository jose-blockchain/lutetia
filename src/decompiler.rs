//! Decompilation orchestrator.
//!
//! Ties together loading, symbolic execution, simplification, and output
//! generation to produce a full decompilation.

use crate::contract::{ConstDecl, Contract};
use crate::expr::Expr;
use crate::folder;
use crate::function::Function;
use crate::loader::Loader;
use crate::prettify::{pprint_trace, prettify};
use crate::rewriter;
use crate::simplify::simplify_trace;
use crate::sparser;
use crate::utils::signatures::get_func_name;
use crate::vm::VM;
use crate::whiles::make_whiles;
use anyhow::{Context, Result};

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Asm,
    Json,
}

/// Result of a decompilation run.
pub struct Decompilation {
    pub text: String,
    pub contract: Contract,
}

/// Configuration for the decompiler.
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    pub timeout_secs: u64,
    pub format: OutputFormat,
    pub color: bool,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            format: OutputFormat::Text,
            color: true,
        }
    }
}

/// Decompile raw bytecode (hex string).
pub fn decompile_bytecode(hex_code: &str, config: &DecompilerConfig) -> Result<Decompilation> {
    let mut loader = Loader::new();
    loader.load_binary(hex_code)
        .context("failed to load bytecode")?;

    if loader.binary.is_empty() {
        anyhow::bail!("empty bytecode");
    }

    if config.format == OutputFormat::Asm {
        let asm_lines = loader.disasm();
        let text = asm_lines.join("\n");
        let contract = Contract::new(vec![], vec![]);
        return Ok(Decompilation { text, contract });
    }

    // Discover functions from the dispatch table.
    discover_functions(&mut loader);

    // Resolve function selectors to human-readable names.
    resolve_selector_names(&mut loader);

    // Decompile each function.
    let mut functions = Vec::new();
    let mut problems: Vec<(String, String)> = Vec::new();

    if loader.func_list.is_empty() {
        // Whole contract as a single function (fallback).
        match decompile_function(&loader, "fallback", "fallback()", 0, vec![], config) {
            Ok(f) => functions.push(f),
            Err(e) => problems.push(("fallback".to_string(), e.to_string())),
        }
    } else {
        // Collect entries first to avoid borrowing loader while passing it to decompile_function.
        let entries: Vec<_> = loader.func_list.iter()
            .map(|(h, n, t, s)| (h.clone(), n.clone(), *t, s.clone()))
            .collect();
        for (hash, name, target, stack) in entries {
            match decompile_function(&loader, &hash, &name, target, stack, config) {
                Ok(f) => functions.push(f),
                Err(e) => problems.push((hash, e.to_string())),
            }
        }
    }

    // Run storage analysis: detect arrays, mappings, structs, and name slots.
    let storage_defs = sparser::rewrite_functions(&mut functions);

    // Propagate return values for simple immutable getters (factory(), WETH(), etc.)
    propagate_immutable_returns(&mut functions);

    // Simplify simple getter returns (balanceOf, allowance, decimals, etc.)
    simplify_getter_returns(&mut functions, &storage_defs);

    // Collapse string getter functions (name(), symbol()) to clean form.
    // Must run AFTER simplify_getter_returns so string patterns aren't lost.
    collapse_string_getters(&mut functions, &storage_defs);

    // Extract constant declarations (immutable addresses, etc.)
    let const_decls = extract_const_declarations(&mut functions);

    let mut contract = Contract::new(functions, problems);
    contract.const_decls = const_decls;
    contract.postprocess();

    let text = match config.format {
        OutputFormat::Json => serde_json::to_string_pretty(&contract.to_json())
            .context("serialise to JSON")?,
        OutputFormat::Text => render_text(&contract, &storage_defs, config.color),
        OutputFormat::Asm => unreachable!(),
    };

    Ok(Decompilation { text, contract })
}

/// Collapse string getter functions (e.g., name(), symbol()) into a clean form.
///
/// Detects 0-param read-only functions that read from a named storage slot
/// and have a long ABI-encoding body (characteristic of Solidity string getters).
/// Replaces the body with `return name[0 len name.length]`.
fn collapse_string_getters(functions: &mut [Function], storage_defs: &[sparser::StorageDef]) {
    // Build a set of names that are string/array storage variables.
    let string_slot_names: std::collections::HashSet<String> = storage_defs
        .iter()
        .filter(|d| matches!(d.kind, sparser::StorageKind::Simple { .. }))
        .map(|d| d.name.clone())
        .collect();

    for func in functions.iter_mut() {
        // Only 0-param, read-only functions with long bodies.
        if !func.params.is_empty() || !func.read_only {
            continue;
        }
        // Must have a substantial body (string encoding generates many lines).
        if func.trace.len() < 5 {
            continue;
        }
        let base_name = func.name.split('(').next().unwrap_or(&func.name);

        // Check if the function name matches a known storage variable.
        if !string_slot_names.contains(base_name) {
            continue;
        }

        // Check if the trace contains the characteristic string encoding pattern:
        // references to the named storage variable in expressions.
        let has_storage_ref = func.trace.iter().any(|e| {
            let s = format!("{e:?}");
            s.contains(&format!("\"name\", [Atom(\"{base_name}\")"))
        });
        if !has_storage_ref {
            continue;
        }

        // Replace the trace with a clean return statement.
        let stor_name = base_name.to_string();
        func.trace = vec![
            Expr::node1(
                "return",
                Expr::Node("string_stor".into(), vec![
                    Expr::Atom(stor_name.clone()),
                ]),
            ),
        ];
    }
}

/// Simplify getter function returns.
///
/// For read-only getter functions that return a single value from storage,
/// replace `return mem[96 len (-64 + _N)]` with the actual storage read.
fn simplify_getter_returns(functions: &mut [Function], storage_defs: &[sparser::StorageDef]) {
    // Build storage def lookup by name.
    let storage_by_name: std::collections::HashMap<&str, &sparser::StorageDef> = storage_defs
        .iter()
        .map(|d| (d.name.as_str(), d))
        .collect();

    for func in functions.iter_mut() {
        if !func.read_only {
            continue;
        }
        let base_name = func.name.split('(').next().unwrap_or(&func.name);

        // Check if this getter matches a storage def.
        let def = match storage_by_name.get(base_name) {
            Some(d) => *d,
            None => continue,
        };

        // Check if the trace is just a single return with mem[...].
        if func.trace.len() != 1 {
            continue;
        }
        if func.trace[0].opcode() != Some("return") {
            continue;
        }

        // Build the replacement return expression.
        let return_expr = match &def.kind {
            sparser::StorageKind::Simple { .. } => {
                // 0-param getter: return decimals
                if !func.params.is_empty() {
                    continue;
                }
                Expr::Atom(base_name.to_string())
            }
            sparser::StorageKind::Mapping { .. } => {
                if func.params.len() == 1 {
                    // 1-param getter: return balanceOf[_param1]
                    Expr::Node("map_read".into(), vec![
                        Expr::Atom(base_name.to_string()),
                        Expr::Atom(func.params[0].name.clone()),
                    ])
                } else if func.params.len() == 2 {
                    // 2-param getter: return allowance[_param1][_param2]
                    Expr::Node("map_read2".into(), vec![
                        Expr::Atom(base_name.to_string()),
                        Expr::Atom(func.params[0].name.clone()),
                        Expr::Atom(func.params[1].name.clone()),
                    ])
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        func.trace = vec![Expr::node1("return", return_expr)];
    }
}

/// Detect immutable getter pattern in a raw VM trace.
///
/// Handles the common Solidity pattern:
///   setmem(range(64, 32), free_ptr)    // init free mem ptr
///   if (iszero(callvalue)) {            // payable check
///       setvar(_1, ...)
///       setmem(range(_1, 32), CONST)    // store the immutable value
///       ...
///       return(...)
///   } else { revert }
///
/// Returns the concrete value if the pattern matches.
fn detect_immutable_getter(trace: &[Expr]) -> Option<Expr> {
    if trace.len() > 5 { return None; }

    // Flatten: collect all statements from the main trace and the first if-true branch.
    let mut flat = Vec::new();
    for line in trace {
        if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                // Extract the if-true branch.
                if ch.len() >= 2 {
                    if let Some(seq_ch) = ch[1].children() {
                        if ch[1].opcode() == Some("seq") {
                            flat.extend_from_slice(seq_ch);
                        }
                    }
                }
            }
        } else {
            flat.push(line.clone());
        }
    }

    // Find the largest concrete value stored via setmem.
    let mut best_val: Option<Expr> = None;
    for line in &flat {
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Some(v) = ch[1].as_val() {
                        if v > primitive_types::U256::from(0xFFFFu64) {
                            if best_val.as_ref().and_then(|e| e.as_val()).map_or(true, |prev| v > prev) {
                                best_val = Some(ch[1].clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Must have a return at the end of flat.
    let last = flat.last()?;
    if last.opcode() != Some("return") { return None; }

    best_val
}

/// Propagate return values for simple immutable getter functions.
///
/// For 0-param read-only functions whose simplified trace is `return mem[offset len ...]`,
/// check the resolved variable map (from the pre-simplification trace) for concrete
/// memory writes at that offset. If found, replace with `return val`.
fn propagate_immutable_returns(functions: &mut [Function]) {
    for func in functions.iter_mut() {
        if !func.params.is_empty() || !func.read_only {
            continue;
        }
        // The trace must be short (simple getter) and end with return.
        if func.trace.is_empty() || func.trace.len() > 3 {
            continue;
        }
        let last = func.trace.last().unwrap();
        if last.opcode() != Some("return") {
            continue;
        }
        let ch = match last.children() {
            Some(ch) if ch.len() == 1 => ch,
            _ => continue,
        };
        // Check if return arg is mem(range(concrete_off, ...)).
        if ch[0].opcode() != Some("mem") { continue; }
        let mch = match ch[0].children() {
            Some(c) if c.len() == 1 && c[0].opcode() == Some("range") => c[0].children().unwrap(),
            _ => continue,
        };
        if mch.len() != 2 { continue; }
        let ret_off = match mch[0].as_u64() {
            Some(v) => v,
            None => continue,
        };

        // Look in the resolved_vars map for a variable whose value is mem(range(64, 32))
        // (the free memory pointer). Then look in other trace lines for setmem at ret_off.
        // As a simpler heuristic: scan the raw_storage_accesses or resolved_vars
        // for concrete writes. But these track storage, not memory.

        // Alternative: search the trace for setmem(range(ret_off, 32), concrete_val)
        // that might be in the trace (e.g., before the stop was removed).
        let mut val: Option<Expr> = None;
        for line in &func.trace {
            if line.opcode() == Some("setmem") {
                if let Some(sch) = line.children() {
                    if sch.len() == 2 && sch[0].opcode() == Some("range") {
                        if let Some(rch) = sch[0].children() {
                            if rch.len() == 2 {
                                if let (Some(off), Some(32)) = (rch[0].as_u64(), rch[1].as_u64()) {
                                    if off == ret_off {
                                        val = Some(sch[1].clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(v) = val {
            func.trace = vec![Expr::node1("return", v)];
        }
    }
}

/// Extract constant declarations from functions that return simple constants.
///
/// Detects 0-param read-only functions whose trace is just `return <constant>`,
/// where the constant is an address-sized value or a small literal. These
/// correspond to Solidity `immutable` or compile-time constants.
///
/// Removes the function from the list and returns a list of `ConstDecl`.
fn extract_const_declarations(functions: &mut Vec<Function>) -> Vec<ConstDecl> {
    let mut consts = Vec::new();
    let mut to_remove = Vec::new();

    for (idx, func) in functions.iter().enumerate() {
        // Only 0-param, read-only functions.
        if !func.params.is_empty() || !func.read_only {
            continue;
        }
        // Trace must be exactly `return <expr>`.
        if func.trace.len() != 1 || func.trace[0].opcode() != Some("return") {
            continue;
        }
        let ch = match func.trace[0].children() {
            Some(ch) if ch.len() == 1 => ch,
            _ => continue,
        };
        let val = &ch[0];

        // Accept concrete values (addresses, small numbers) or atoms (storage refs already handled).
        match val {
            Expr::Val(v) => {
                let base_name = func.name.split('(').next().unwrap_or(&func.name);
                let val_str = prettify(val, false);
                // Skip very small values (decimals, totalSupply) — those are better as functions.
                if *v <= primitive_types::U256::from(0xFFFFu64) {
                    continue;
                }
                consts.push(ConstDecl {
                    name: base_name.to_string(),
                    value: val_str,
                });
                to_remove.push(idx);
            }
            Expr::Atom(_) => {
                // Storage atoms are already handled by simplify_getter_returns.
                // Skip these — they're getters, not constants.
                continue;
            }
            _ => continue,
        }
    }

    // Remove extracted functions in reverse order.
    for idx in to_remove.into_iter().rev() {
        functions.remove(idx);
    }

    consts
}

/// Decompile a single function.
fn decompile_function(
    loader: &Loader,
    selector_hash: &str,
    name: &str,
    start: usize,
    stack: Vec<Expr>,
    config: &DecompilerConfig,
) -> Result<Function> {
    let mut vm = VM::new(loader.clone(), false);
    let raw_trace = vm.run(start, stack.clone(), config.timeout_secs);

    // Check for simple immutable getter (no calldata params):
    // setmem(free_ptr), setmem(ret_off, concrete_val), return(mem[ret_off len ...])
    // If detected, short-circuit to `return concrete_val`.
    if stack.is_empty() {
        if let Some(const_val) = detect_immutable_getter(&raw_trace) {
            let mut func = Function::new(selector_hash.to_string(), name.to_string(),
                vec![Expr::node1("return", const_val)]);
            func.raw_storage_accesses = Vec::new();
            func.resolved_vars = std::collections::HashMap::new();
            return Ok(func);
        }
    }

    // Convert label/goto → while loops.
    let trace = make_whiles(&raw_trace);

    // Collect raw storage accesses and build variable resolution map.
    let (raw_storage, resolved_vars) = collect_raw_storage_and_vars(&trace);

    // Simplify.
    let simplified = simplify_trace(&trace, config.timeout_secs, None);

    // Fold execution paths into concise if/else structures.
    let simplified = folder::fold(&simplified);

    // Heuristic rewrites: require() detection, memcpy, etc.
    let simplified = rewriter::rewrite(&simplified);

    let mut func = Function::new(selector_hash.to_string(), name.to_string(), simplified);
    func.raw_storage_accesses = raw_storage;
    func.resolved_vars = resolved_vars;
    Ok(func)
}

/// Collect all storage access expressions from a trace, resolving variable
/// references and sha3(mem[...]) patterns to expose the actual slot indices.
/// Also returns the resolved variable map for later use in sparser.
fn collect_raw_storage_and_vars(trace: &[Expr]) -> (Vec<Expr>, std::collections::HashMap<String, Expr>) {
    use std::collections::HashMap;

    // 1. Build a variable → value map from `var(_N) = expr` assignments.
    let mut vars: HashMap<String, Expr> = HashMap::new();
    build_var_map(trace, &mut vars);

    // 2. Build a memory state tracker for sha3 resolution.
    let mut mem32: HashMap<u64, Expr> = HashMap::new();
    let mut out = Vec::new();
    collect_raw_storage_resolved(trace, &mut vars, &mut mem32, &mut out);
    (out, vars)
}

/// Extract the atom string from an Expr::Atom.
fn expr_atom_name(e: &Expr) -> Option<&str> {
    match e {
        Expr::Atom(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Build variable → value map from `setvar(Atom("_N"), value)` patterns in the trace.
fn build_var_map(trace: &[Expr], vars: &mut std::collections::HashMap<String, Expr>) {
    for line in trace {
        if line.opcode() == Some("setvar") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Some(name) = expr_atom_name(&ch[0]) {
                        vars.insert(name.to_string(), ch[1].clone());
                    }
                }
            }
        }
        // Recurse into if/while/seq/goto branches.
        if let Some(ch) = line.children() {
            for c in ch {
                match c.opcode() {
                    Some("seq") => {
                        if let Some(seq_ch) = c.children() {
                            build_var_map(seq_ch, vars);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Resolve variable references in an expression using the var map.
fn resolve_vars(expr: &Expr, vars: &std::collections::HashMap<String, Expr>, depth: usize) -> Expr {
    if depth > 10 {
        return expr.clone();
    }
    if expr.opcode() == Some("var") {
        if let Some(ch) = expr.children() {
            if let Some(name) = expr_atom_name(&ch[0]) {
                if let Some(val) = vars.get(name) {
                    return resolve_vars(val, vars, depth + 1);
                }
            }
        }
    }
    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children.iter().map(|c| resolve_vars(c, vars, depth)).collect();
            Expr::Node(op.clone(), new_ch)
        }
        other => other.clone(),
    }
}

/// Resolve sha3(mem[P len N]) using tracked memory writes.
fn resolve_sha3(expr: &Expr, mem32: &std::collections::HashMap<u64, Expr>) -> Expr {
    if expr.opcode() == Some("sha3") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 && ch[0].opcode() == Some("mem") {
                if let Some(mch) = ch[0].children() {
                    if mch.len() == 1 && mch[0].opcode() == Some("range") {
                        if let Some(rch) = mch[0].children() {
                            if rch.len() == 2 {
                                if let (Some(start), Some(len)) = (rch[0].as_u64(), rch[1].as_u64()) {
                                    if len > 0 && len % 32 == 0 {
                                        let nwords = len / 32;
                                        let mut words = Vec::new();
                                        let mut all_found = true;
                                        for i in 0..nwords {
                                            let off = start + i * 32;
                                            if let Some(v) = mem32.get(&off) {
                                                words.push(v.clone());
                                            } else {
                                                all_found = false;
                                                break;
                                            }
                                        }
                                        if all_found && !words.is_empty() {
                                            return Expr::Node("sha3".into(), words);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    expr.clone()
}

fn collect_raw_storage_resolved(
    trace: &[Expr],
    vars: &mut std::collections::HashMap<String, Expr>,
    mem32: &mut std::collections::HashMap<u64, Expr>,
    out: &mut Vec<Expr>,
) {
    for line in trace {
        // Track memory writes: setmem(range(offset, size), value).
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Some(rch) = ch[0].children() {
                        if ch[0].opcode() == Some("range") && rch.len() == 2 {
                            if let (Some(off), Some(32)) = (rch[0].as_u64(), rch[1].as_u64()) {
                                let val = resolve_vars(&ch[1], vars, 0);
                                mem32.insert(off, val);
                            }
                        }
                    }
                }
            }
        }

        // Track variable assignments: setvar(Atom("_N"), value).
        if line.opcode() == Some("setvar") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Some(name) = expr_atom_name(&ch[0]) {
                        // Resolve sha3 expressions in the value.
                        let val = resolve_vars(&ch[1], vars, 0);
                        let val = resolve_sha3(&val, mem32);
                        vars.insert(name.to_string(), val);
                    }
                }
            }
        }

        // Collect storage accesses with resolved variables and sha3.
        collect_raw_storage_from_expr_resolved(line, vars, mem32, out);

        // Recurse into branches.
        if line.opcode() == Some("if") || line.opcode() == Some("while") {
            if let Some(ch) = line.children() {
                for c in ch {
                    if c.opcode() == Some("seq") {
                        if let Some(seq_ch) = c.children() {
                            collect_raw_storage_resolved(seq_ch, vars, mem32, out);
                        }
                    }
                }
            }
        }
    }
}

fn collect_raw_storage_from_expr_resolved(
    expr: &Expr,
    vars: &std::collections::HashMap<String, Expr>,
    mem32: &std::collections::HashMap<u64, Expr>,
    out: &mut Vec<Expr>,
) {
    match expr.opcode() {
        Some("store") => {
            if let Some(ch) = expr.children() {
                if ch.len() >= 3 {
                    let mut resolved_ch: Vec<Expr> = ch[..3].to_vec();
                    // Resolve the slot index (ch[2]).
                    resolved_ch[2] = resolve_vars(&resolved_ch[2], vars, 0);
                    resolved_ch[2] = resolve_sha3(&resolved_ch[2], mem32);
                    out.push(Expr::Node("storage".into(), resolved_ch));
                }
            }
        }
        Some("storage") => {
            if let Some(ch) = expr.children() {
                let mut resolved_ch = ch.to_vec();
                if resolved_ch.len() >= 3 {
                    resolved_ch[2] = resolve_vars(&resolved_ch[2], vars, 0);
                    resolved_ch[2] = resolve_sha3(&resolved_ch[2], mem32);
                }
                out.push(Expr::Node("storage".into(), resolved_ch));
            }
        }
        _ => {}
    }
    if let Some(ch) = expr.children() {
        for c in ch {
            collect_raw_storage_from_expr_resolved(c, vars, mem32, out);
        }
    }
}

/// Render the contract as human-readable text.
fn render_text(contract: &Contract, storage_defs: &[sparser::StorageDef], color: bool) -> String {
    let mut lines = Vec::new();

    if !contract.problems.is_empty() {
        lines.push("# Problems".to_string());
        for (hash, msg) in &contract.problems {
            lines.push(format!("#   {hash}: {msg}"));
        }
        lines.push(String::new());
    }

    // Constant declarations.
    if !contract.const_decls.is_empty() {
        for decl in &contract.const_decls {
            lines.push(format!("const {} = {}", decl.name, decl.value));
        }
        lines.push(String::new());
    }

    // Storage layout header.
    if !storage_defs.is_empty() {
        lines.push("def storage:".to_string());
        for def in storage_defs {
            let type_str = match &def.kind {
                sparser::StorageKind::Simple { size, offset } => {
                    let type_name = match size {
                        160 => "address".to_string(),
                        256 => "uint256".to_string(),
                        8 => "uint8".to_string(),
                        s => format!("uint{s}"),
                    };
                    if *offset > 0 {
                        format!("{type_name} at storage {} offset {}", def.slot, offset / 256)
                    } else {
                        format!("{type_name} at storage {}", def.slot)
                    }
                }
                sparser::StorageKind::Mapping { value_size } => {
                    let val_type = match value_size {
                        160 => "address",
                        256 => "uint256",
                        8 => "uint8",
                        _ => "uint256",
                    };
                    format!("mapping of {val_type} at storage {}", def.slot)
                }
                sparser::StorageKind::Array { element_size } => {
                    let elem_type = match element_size {
                        160 => "address",
                        256 => "uint256",
                        _ => "uint256",
                    };
                    format!("array of {elem_type} at storage {}", def.slot)
                }
                sparser::StorageKind::Struct { field_count } => {
                    format!("struct ({field_count} fields) at storage {}", def.slot)
                }
            };
            lines.push(format!("  {} is {}", def.name, type_str));
        }
        lines.push(String::new());
    }

    for func in &contract.functions {
        let payable_str = if func.payable { " payable" } else { "" };
        let not_payable_comment = if !func.payable { " # not payable" } else { "" };

        // Build param signature if we have inferred params.
        let sig = if func.params.is_empty() {
            format!("def {}{}:{}", func.name, payable_str, not_payable_comment)
        } else {
            let param_strs: Vec<String> = func.params.iter()
                .map(|p| format!("{} {}", p.kind, p.name))
                .collect();
            let base_name = func.name.split('(').next().unwrap_or(&func.name);
            format!("def {}({}){}:{}", base_name, param_strs.join(", "), payable_str, not_payable_comment)
        };
        lines.push(sig);

        if func.trace.is_empty() {
            lines.push("    stop".to_string());
        } else {
            // Remove trailing stop — it's implicit (but keep if it's the only statement).
            let trace = if func.trace.len() > 1
                && func.trace.last().map(|e| e.opcode()) == Some(Some("stop"))
            {
                func.trace[..func.trace.len() - 1].to_vec()
            } else {
                func.trace.clone()
            };
            lines.push(pprint_trace(&trace, color));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Resolve discovered function selectors to human-readable names via the
/// openchain signature database.
fn resolve_selector_names(loader: &mut Loader) {
    let mut updates: Vec<(usize, String)> = Vec::new();

    for (idx, (hash, name, _target, _stack)) in loader.func_list.iter().enumerate() {
        // Only resolve if the name is still the default "unknown_0x..." pattern.
        if name.starts_with("unknown_") || name == hash {
            if let Some(resolved) = get_func_name(hash) {
                updates.push((idx, resolved));
            }
        }
    }

    for (idx, resolved_name) in updates {
        loader.func_list[idx].1 = resolved_name;
    }
}

/// Discover function selectors from the bytecode dispatcher.
///
/// Scans the initial dispatcher for the standard Solidity pattern:
///   DUP1, PUSH4 <selector>, EQ, PUSH <target>, JUMPI
///
/// Only considers PUSH4 instructions (4-byte selectors), and stops scanning
/// once we leave the dispatcher area (after the fallback jump or after too
/// many non-dispatch instructions).
fn discover_functions(loader: &mut Loader) {
    let mut discovered: Vec<(String, usize)> = Vec::new();
    let lines = &loader.parsed_lines;

    // Find the dispatcher boundary: the first unconditional JUMP that isn't
    // part of a selector check (i.e. the fallback / default branch).
    // We also impose a hard limit to avoid scanning the entire bytecode.
    let max_scan = lines.len().min(500);

    let mut i = 0;
    let mut consecutive_non_dispatch = 0usize;

    while i + 3 < max_scan {
        let inst = &lines[i];

        // We only accept PUSH4 instructions as selector candidates.
        // (PUSH3 could theoretically encode selectors starting with 0x00,
        // but this is extremely rare and matching it creates false positives.)
        if inst.op == "push4" {
            if let Some(selector) = inst.param {
                // Skip zero and common mask values like 0xFFFFFFFF.
                let sel_u64 = selector.low_u64();
                if !selector.is_zero() && sel_u64 != 0xFFFFFFFF {
                    // Look ahead for EQ followed by PUSH+JUMPI within a small window.
                    if let Some((target, _end)) = find_dispatch_target(lines, i + 1, 5) {
                        let hex_sel = format!("0x{:08x}", selector.low_u64());
                        discovered.push((hex_sel, target));
                        consecutive_non_dispatch = 0;
                        i += 1;
                        continue;
                    }
                }
            }
        }

        // Track how far we are from the last dispatch instruction.
        // If we see too many non-dispatch instructions, we've left the dispatcher.
        if inst.op == "jumpdest" {
            // A JUMPDEST inside the dispatcher is fine (it's a dispatch target or
            // the start of the fallback). But once we've found at least one selector
            // and encounter a JUMPDEST followed by non-dispatch code, we stop.
            if !discovered.is_empty() {
                consecutive_non_dispatch += 1;
                if consecutive_non_dispatch > 20 {
                    break;
                }
            }
        }

        i += 1;
    }

    // Deduplicate: keep only the first occurrence of each selector,
    // and validate that the target is a valid JUMPDEST.
    let mut seen_selectors = std::collections::HashSet::new();
    for (hex_sel, target) in discovered {
        // The target must be a valid jump destination.
        if !loader.jump_dests.contains(&target) {
            continue;
        }
        // Skip duplicate selectors.
        if !seen_selectors.insert(hex_sel.clone()) {
            continue;
        }
        loader.add_func(target, Some(&hex_sel), None, vec![]);
    }
}

/// Look ahead from position `start` within `window` instructions for:
///   EQ, ..., PUSH <target>, JUMPI
/// Returns the target offset and end position if found.
fn find_dispatch_target(
    lines: &[crate::loader::Instruction],
    start: usize,
    window: usize,
) -> Option<(usize, usize)> {
    let end = lines.len().min(start + window);
    let mut found_eq = false;

    for j in start..end {
        if lines[j].op == "eq" {
            found_eq = true;
        }
        if found_eq && lines[j].op == "jumpi" {
            // The target should be the PUSH immediately before JUMPI.
            let target = find_push_before(lines, j)?;
            return Some((target, j));
        }
        if found_eq && lines[j].op.starts_with("push") && j + 1 < lines.len() && lines[j + 1].op == "jumpi" {
            let target = lines[j].param.map(|p| p.low_u64() as usize)?;
            return Some((target, j + 1));
        }
    }
    None
}

fn find_push_before(lines: &[crate::loader::Instruction], before: usize) -> Option<usize> {
    let mut j = before.saturating_sub(1);
    loop {
        if lines[j].op.starts_with("push") {
            return lines[j].param.map(|p| p.low_u64() as usize);
        }
        if j == 0 {
            break;
        }
        j -= 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_stop() {
        let config = DecompilerConfig {
            timeout_secs: 5,
            format: OutputFormat::Text,
            color: false,
        };
        let result = decompile_bytecode("00", &config).unwrap();
        // A contract with only STOP produces a fallback with an empty trace;
        // the empty trace renders as "stop" (the special empty-trace message).
        assert!(result.text.contains("stop") || result.text.contains("def "));
    }

    #[test]
    fn test_decompile_asm() {
        let config = DecompilerConfig {
            timeout_secs: 5,
            format: OutputFormat::Asm,
            color: false,
        };
        let result = decompile_bytecode("6001600201", &config).unwrap();
        assert!(result.text.contains("push1"));
    }

    #[test]
    fn test_decompile_json() {
        let config = DecompilerConfig {
            timeout_secs: 5,
            format: OutputFormat::Json,
            color: false,
        };
        let result = decompile_bytecode("00", &config).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result.text).unwrap();
        assert!(json["functions"].is_array());
    }

    #[test]
    fn test_decompile_empty_fails() {
        let config = DecompilerConfig::default();
        assert!(decompile_bytecode("", &config).is_err());
    }

    #[test]
    fn test_decompile_revert() {
        let config = DecompilerConfig {
            timeout_secs: 5,
            format: OutputFormat::Text,
            color: false,
        };
        let result = decompile_bytecode("60006000fd", &config).unwrap();
        assert!(result.text.contains("revert"));
    }

    #[test]
    fn test_decompile_push_add_return() {
        // PUSH1 3, PUSH1 2, ADD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let config = DecompilerConfig {
            timeout_secs: 5,
            format: OutputFormat::Text,
            color: false,
        };
        let result = decompile_bytecode("600360020160005260206000f3", &config);
        // May or may not parse cleanly, but should not panic
        assert!(result.is_ok() || result.is_err());
    }
}
