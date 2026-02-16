//! Function-level analysis.
//!
//! Determines function properties: payable, read-only, const, getter.
//! Infers parameter types from calldata (cd) mask patterns.

use crate::core::masks::mask_to_type;
use crate::expr::{Expr, Trace};
use crate::utils::helpers::{find_f_list, replace_f};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Inferred parameter type and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamInfo {
    pub kind: String,
    pub name: String,
    pub offset: u64,
}

/// A decompiled function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub hash: String,
    pub name: String,
    pub trace: Trace,
    pub payable: bool,
    pub read_only: bool,
    pub is_const: bool,
    pub getter: Option<Expr>,
    pub returns: Vec<Expr>,
    pub params: Vec<ParamInfo>,
    /// Raw storage accesses collected before simplification (for sparser).
    #[serde(skip)]
    pub raw_storage_accesses: Vec<Expr>,
    /// Resolved variable values from the raw trace (var name → sha3-resolved value).
    #[serde(skip)]
    pub resolved_vars: std::collections::HashMap<String, Expr>,
}

impl Function {
    /// Create a new function from its selector hash, resolved name, and trace.
    pub fn new(hash: String, name: String, trace: Trace) -> Self {
        let mut f = Self {
            hash,
            name,
            trace: trace.clone(),
            payable: true,
            read_only: true,
            is_const: false,
            getter: None,
            returns: Vec::new(),
            params: Vec::new(),
            raw_storage_accesses: Vec::new(),
            resolved_vars: std::collections::HashMap::new(),
        };
        f.analyse();

        // Try trace-based parameter inference first.
        f.infer_params();

        // Parse params from the signature (always, to get complete param list).
        // If the signature yields more params, use those (they include ABI names
        // and correct types for dynamic params that trace inference might miss).
        let mut sig_params = Vec::new();
        {
            let saved = std::mem::take(&mut f.params);
            f.parse_params_from_signature();
            sig_params = std::mem::replace(&mut f.params, saved);
        }

        if sig_params.len() > f.params.len() {
            // Signature-based params are more complete.
            // Overlay type refinements from trace inference (e.g., bool detection).
            for sp in &mut sig_params {
                if let Some(tp) = f.params.iter().find(|p| p.offset == sp.offset) {
                    // Keep trace-inferred type if it's more specific (e.g., bool, address).
                    if tp.kind == "bool" || tp.kind == "address" {
                        sp.kind = tp.kind.clone();
                    }
                }
            }
            f.params = sig_params;
        }

        f.cleanup_masks();
        f.substitute_params();
        f
    }

    /// Analyse the trace to determine function properties.
    fn analyse(&mut self) {
        // Detect payability: check for callvalue guard at the start.
        self.detect_payability(&self.trace.clone());

        // If non-payable, strip the callvalue guard from the trace.
        if !self.payable {
            self.trace = strip_callvalue_guard(&self.trace);
        }

        // Detect read_only (no store/call/delegatecall/selfdestruct/create).
        self.read_only = !trace_has_write_ops(&self.trace);

        // Collect returns.
        self.returns = collect_returns(&self.trace);

        // Detect const (read_only, no storage refs, no calldata refs).
        if self.read_only && self.returns.len() == 1
            && !trace_contains_ops(&self.trace, &["storage", "stor", "cd"]) {
                self.is_const = true;
            }
    }

    fn detect_payability(&mut self, trace: &[Expr]) {
        for line in trace {
            if line.opcode() == Some("if") {
                if let Some(ch) = line.children() {
                    if let Some(cond) = ch.first() {
                        // Check if condition involves callvalue.
                        if cond.contains_op("callvalue") || cond.contains(&Expr::atom("callvalue")) {
                            self.payable = false;
                            return;
                        }
                    }
                }
            }
            if line.opcode() == Some("require") {
                if let Some(ch) = line.children() {
                    if let Some(cond) = ch.first() {
                        if cond.contains_op("callvalue") || cond.contains(&Expr::atom("callvalue")) {
                            self.payable = false;
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Infer parameter types from calldata access patterns in the trace.
    fn infer_params(&mut self) {
        // Collect all calldata occurrences: mask_shl(size, _, _, cd(idx)) and cd(idx).
        let occurrences = find_f_list_in_trace(&self.trace, &|e| {
            if e.opcode() == Some("cd") {
                return vec![e.clone()];
            }
            if e.opcode() == Some("mask_shl") {
                if let Some(ch) = e.children() {
                    if ch.len() == 4 && ch[3].opcode() == Some("cd") {
                        return vec![e.clone()];
                    }
                }
            }
            if e.opcode() == Some("bool") {
                if let Some(ch) = e.children() {
                    if ch.len() == 1 && ch[0].opcode() == Some("cd") {
                        return vec![e.clone()];
                    }
                }
            }
            vec![]
        });

        // Build sizes map: cd_offset → bit_size.
        let mut sizes: BTreeMap<u64, i64> = BTreeMap::new();

        for occ in &occurrences {
            match occ.opcode() {
                Some("mask_shl") => {
                    if let Some(ch) = occ.children() {
                        if ch.len() == 4 {
                            let size = ch[0].as_u64().unwrap_or(256) as i64;
                            if let Some(cd_ch) = ch[3].children() {
                                if let Some(idx) = cd_ch.first().and_then(|e| e.as_u64()) {
                                    if idx == 0 { continue; }
                                    // Pointer detection: if idx is add(4, cd(in_idx)).
                                    if let Some(add_ch) = cd_ch.first().and_then(|e| e.children()) {
                                        if cd_ch.first().map(|e| e.opcode()) == Some(Some("add"))
                                            && add_ch.len() == 2 && add_ch[0] == Expr::val(4) {
                                                if let Some(in_ch) = add_ch[1].children() {
                                                    if add_ch[1].opcode() == Some("cd") {
                                                        if let Some(in_idx) = in_ch.first().and_then(|e| e.as_u64()) {
                                                            sizes.insert(in_idx, -1); // array
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                    }

                                    sizes.entry(idx).or_insert(size);
                                }
                            }
                        }
                    }
                }
                Some("bool") => {
                    if let Some(ch) = occ.children() {
                        if ch.len() == 1 {
                            if let Some(cd_ch) = ch[0].children() {
                                if let Some(idx) = cd_ch.first().and_then(|e| e.as_u64()) {
                                    if idx > 0 {
                                        sizes.insert(idx, 1); // bool
                                    }
                                }
                            }
                        }
                    }
                }
                Some("cd") => {
                    if let Some(ch) = occ.children() {
                        if let Some(idx) = ch.first().and_then(|e| e.as_u64()) {
                            if idx == 0 { continue; }

                            // Check if cd(idx) is used as a pointer: add(4, cd(idx)).
                            if let Some(add_ch) = ch.first().and_then(|e| e.children()) {
                                if ch.first().map(|e| e.opcode()) == Some(Some("add"))
                                    && add_ch.len() == 2 && add_ch[0] == Expr::val(4)
                                        && add_ch[1].opcode() == Some("cd") {
                                            // The inner cd is being used as a pointer.
                                            continue;
                                        }
                            }

                            sizes.entry(idx).or_insert(256);
                        }
                    }
                }
                _ => {}
            }
        }

        // Also detect bools: if cd(idx) is only used in iszero/bool/if contexts.
        for (&idx, size) in sizes.iter_mut() {
            if *size > 1 {
                // Check if this cd is only used as a boolean.
                if cd_used_only_as_bool(&self.trace, idx) {
                    *size = 1;
                }
            }
        }

        // Fetch ABI parameter names from the local signature DB.
        // Map them by calldata offset: param[i] is at offset 4 + i*32.
        let abi_names = crate::utils::signatures::get_param_names(&self.hash);
        let abi_by_offset: std::collections::HashMap<u64, &str> = abi_names
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.is_empty())
            .map(|(i, n)| (4 + (i as u64) * 32, n.as_str()))
            .collect();

        // Convert to params.
        let mut count = 0usize;
        for (&offset, &size) in &sizes {
            if offset == 0 { continue; }

            // Validate alignment.
            if (offset - 4) % 32 != 0 {
                log::warn!("Unusual non-aligned calldata offset: {offset}");
                continue;
            }

                let kind = match size {
                    -2 => "tuple".to_string(),
                    -1 => "array".to_string(),
                    1 => "bool".to_string(),
                    s if s > 0 => mask_to_type(s as u16, false)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("uint{s}")),
                    _ => "uint256".to_string(),
                };

            // Use ABI name by offset, otherwise _paramN.
            let name = abi_by_offset
                .get(&offset)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("_param{}", count + 1));

            self.params.push(ParamInfo {
                kind,
                name,
                offset,
            });
            count += 1;
        }
    }

    /// Parse parameter types from the function signature string.
    ///
    /// Fallback for when trace-based `infer_params` found nothing (e.g.,
    /// because the calldata references were consumed by simplification).
    fn parse_params_from_signature(&mut self) {
        let sig = &self.name;
        let start = match sig.find('(') {
            Some(i) => i + 1,
            None => return,
        };
        let end = match sig.rfind(')') {
            Some(i) => i,
            None => return,
        };
        if start >= end {
            return;
        }
        let params_str = &sig[start..end];
        if params_str.is_empty() {
            return;
        }

        // Try to get ABI parameter names from the local signature DB.
        let abi_names = crate::utils::signatures::get_param_names(&self.hash);

        let types: Vec<&str> = params_str.split(',').collect();
        for (i, ty) in types.iter().enumerate() {
            let ty = ty.trim();
            if ty.is_empty() {
                continue;
            }
            let offset = 4 + (i as u64) * 32;
            let name = abi_names
                .get(i)
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or_else(|| format!("_param{}", i + 1));
            self.params.push(ParamInfo {
                kind: ty.to_string(),
                name,
                offset,
            });
        }
    }

    /// Replace `cd(offset)` with named parameter atoms in the trace.
    fn substitute_params(&mut self) {
        if self.params.is_empty() {
            return;
        }
        let params = self.params.clone();
        self.trace = self.trace.iter().map(|e| {
            replace_f(e, &|expr| {
                if expr.opcode() == Some("cd") {
                    if let Some(ch) = expr.children() {
                        if let Some(idx) = ch.first().and_then(|e| e.as_u64()) {
                            if idx > 0 {
                                if let Some(p) = params.iter().find(|p| p.offset == idx) {
                                    return Expr::atom(&p.name);
                                }
                            }
                        }
                    }
                }
                expr.clone()
            })
        }).collect();
    }

    /// Try to extract better parameter names from the resolved function signature.
    fn refine_param_names(&mut self) {
        // Parse the function signature to extract parameter types.
        // e.g. "transfer(address,uint256)" → ["address", "uint256"]
        let sig = &self.name;
        let start = match sig.find('(') {
            Some(i) => i + 1,
            None => return,
        };
        let end = match sig.rfind(')') {
            Some(i) => i,
            None => return,
        };
        if start >= end {
            return;
        }
        let params_str = &sig[start..end];
        let sig_types: Vec<&str> = params_str.split(',').collect();

        if sig_types.len() != self.params.len() {
            return;
        }

        // Assign names based on common patterns.
        for (i, p) in self.params.iter_mut().enumerate() {
            let ty = sig_types[i].trim();
            // Use generic but readable names based on type.
            let name = match ty {
                "address" => {
                    match i {
                        0 => "_param1",
                        1 => "_param2",
                        _ => "_param3",
                    }
                }
                _ => continue,
            };
            p.name = name.to_string();
        }
    }

    /// Remove redundant mask wrappers now that param types are known.
    fn cleanup_masks(&mut self) {
        if self.params.is_empty() {
            return;
        }
        let params = self.params.clone();
        self.trace = self.trace.iter().map(|e| {
            replace_f(e, &|expr| {
                // bool(cd(idx)) → cd(idx) if param is bool.
                if expr.opcode() == Some("bool") {
                    if let Some(ch) = expr.children() {
                        if ch.len() == 1 && ch[0].opcode() == Some("cd") {
                            if let Some(cd_ch) = ch[0].children() {
                                if let Some(idx) = cd_ch.first().and_then(|e| e.as_u64()) {
                                    if params.iter().any(|p| p.offset == idx && p.kind == "bool") {
                                        return ch[0].clone();
                                    }
                                }
                            }
                        }
                    }
                }
                // mask_shl(size, 0, 0, cd(idx)) → cd(idx) if size matches the param's type.
                if expr.opcode() == Some("mask_shl") {
                    if let Some(ch) = expr.children() {
                        if ch.len() == 4
                            && ch[1].is_zero()
                            && ch[2].is_zero()
                            && ch[3].opcode() == Some("cd")
                        {
                            if let Some(size) = ch[0].as_u64() {
                                if let Some(cd_ch) = ch[3].children() {
                                    if let Some(idx) = cd_ch.first().and_then(|e| e.as_u64()) {
                                        if params.iter().any(|p| {
                                            p.offset == idx && type_default_size(&p.kind) == Some(size)
                                        }) {
                                            return ch[3].clone();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                expr.clone()
            })
        }).collect();
    }

    /// Print the function as decompiled pseudo-code.
    pub fn print_decompiled(&self) -> String {
        let mut lines = Vec::new();
        let payable_str = if self.payable { " payable" } else { "" };

        // Build param signature.
        if self.params.is_empty() {
            lines.push(format!("def {}{}:", self.name, payable_str));
        } else {
            let param_strs: Vec<String> = self.params.iter()
                .map(|p| format!("{} {}", p.kind, p.name))
                .collect();
            let base_name = self.name.split('(').next().unwrap_or(&self.name);
            lines.push(format!("def {}({}){}:", base_name, param_strs.join(", "), payable_str));
        }

        if self.trace.is_empty() {
            lines.push("  stop".to_string());
        } else {
            for line in &self.trace {
                lines.push(format!("  {line}"));
            }
        }
        lines.join("\n")
    }

    /// Serialise to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let params_json: Vec<serde_json::Value> = self.params.iter()
            .map(|p| serde_json::json!({"type": p.kind, "name": p.name, "offset": p.offset}))
            .collect();
        serde_json::json!({
            "hash": self.hash,
            "name": self.name,
            "payable": self.payable,
            "read_only": self.read_only,
            "const": self.is_const,
            "params": params_json,
        })
    }
}

/// Strip the callvalue guard from the beginning of a trace.
///
/// Patterns handled:
///   `if callvalue { revert } else { body }` → body
///   `require(iszero(callvalue))` → remove
fn strip_callvalue_guard(trace: &[Expr]) -> Trace {
    if trace.is_empty() {
        return trace.to_vec();
    }
    let first = &trace[0];

    // Pattern 1: if (callvalue) { revert } else { body }
    if first.opcode() == Some("if") {
        if let Some(ch) = first.children() {
            if ch.len() >= 3 {
                let cond = &ch[0];
                if cond.contains_op("callvalue") || cond.contains(&Expr::atom("callvalue")) {
                    // Extract the false branch (else body) — the non-reverting path.
                    let true_branch = extract_seq_children(&ch[1]);
                    let false_branch = extract_seq_children(&ch[2]);

                    let (body, _revert) = if is_revert_branch(&true_branch) {
                        (false_branch, true_branch)
                    } else if is_revert_branch(&false_branch) {
                        (true_branch, false_branch)
                    } else {
                        // Can't determine which branch reverts; keep the if.
                        return trace.to_vec();
                    };

                    let mut result = body;
                    result.extend_from_slice(&trace[1..]);
                    return result;
                }
            }
        }
    }

    // Pattern 2: require(iszero(callvalue)) or require(not callvalue)
    if first.opcode() == Some("require") {
        if let Some(ch) = first.children() {
            if let Some(cond) = ch.first() {
                if cond.contains_op("callvalue") || cond.contains(&Expr::atom("callvalue")) {
                    return trace[1..].to_vec();
                }
            }
        }
    }

    trace.to_vec()
}

/// Check if a branch is a revert path (single revert/invalid/stop).
fn is_revert_branch(branch: &[Expr]) -> bool {
    if branch.len() != 1 {
        return false;
    }
    matches!(branch[0].opcode(), Some("revert") | Some("invalid"))
}

/// Extract the children of a seq node, or wrap a single expr in a vec.
fn extract_seq_children(expr: &Expr) -> Vec<Expr> {
    if expr.opcode() == Some("seq") {
        expr.children().map(|ch| ch.to_vec()).unwrap_or_default()
    } else {
        vec![expr.clone()]
    }
}

/// Check if cd(idx) is only used in boolean contexts (iszero, bool, if conditions).
fn cd_used_only_as_bool(trace: &[Expr], idx: u64) -> bool {
    let cd_expr = Expr::node1("cd", Expr::val(idx));
    let parents = find_parents_in_trace(trace, &cd_expr);

    if parents.is_empty() {
        return false;
    }

    parents.iter().all(|p| {
        matches!(p.opcode(), Some("bool") | Some("iszero") | Some("if") | Some("require"))
    })
}

/// Find all expressions that directly contain the target as a child.
fn find_parents_in_trace(trace: &[Expr], target: &Expr) -> Vec<Expr> {
    let mut results = Vec::new();
    for line in trace {
        find_parents_in_expr(line, target, &mut results);
    }
    results
}

fn find_parents_in_expr(expr: &Expr, target: &Expr, results: &mut Vec<Expr>) {
    if let Some(ch) = expr.children() {
        if ch.iter().any(|c| c == target) {
            results.push(expr.clone());
        }
        for c in ch {
            find_parents_in_expr(c, target, results);
        }
    }
}

/// Collect all `find_f_list` results from a trace (recursing into sub-traces).
fn find_f_list_in_trace(trace: &[Expr], f: &dyn Fn(&Expr) -> Vec<Expr>) -> Vec<Expr> {
    let mut results = Vec::new();
    for line in trace {
        results.extend(find_f_list(line, f));
    }
    results
}

/// Get the default bit-size for a type string.
fn type_default_size(kind: &str) -> Option<u64> {
    match kind {
        "bool" => Some(8),
        "address" => Some(160),
        "uint256" | "int256" | "bytes32" => Some(256),
        s if s.starts_with("uint") => s[4..].parse::<u64>().ok(),
        s if s.starts_with("int") => s[3..].parse::<u64>().ok(),
        s if s.starts_with("bytes") && s.len() <= 7 => {
            s[5..].parse::<u64>().ok().map(|n| n * 8)
        }
        _ => None,
    }
}

/// Check if the trace contains any write operations (AST-based, not string-based).
fn trace_has_write_ops(trace: &[Expr]) -> bool {
    for line in trace {
        if expr_has_write_ops(line) {
            return true;
        }
    }
    false
}

fn expr_has_write_ops(expr: &Expr) -> bool {
    match expr.opcode() {
        Some("store") | Some("tstore") | Some("selfdestruct") | Some("create") | Some("create2") => true,
        Some("call") | Some("delegatecall") | Some("callcode") => true,
        _ => {
            if let Some(ch) = expr.children() {
                ch.iter().any(expr_has_write_ops)
            } else {
                false
            }
        }
    }
}

/// Check if the trace contains any of the given opcodes (AST-based).
fn trace_contains_ops(trace: &[Expr], ops: &[&str]) -> bool {
    trace.iter().any(|line| ops.iter().any(|op| line.contains_op(op)))
}

fn collect_returns(trace: &[Expr]) -> Vec<Expr> {
    let mut results = Vec::new();
    for expr in trace {
        if expr.opcode() == Some("return") {
            if let Some(ch) = expr.children() {
                if ch.len() == 1 {
                    results.push(ch[0].clone());
                }
            }
        }
        // Recurse into if/while branches.
        if let Some(children) = expr.children() {
            for child in children {
                if child.opcode() == Some("seq") {
                    if let Some(seq_ch) = child.children() {
                        results.extend(collect_returns(seq_ch));
                    }
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_basic() {
        let trace = vec![
            Expr::node1("return", Expr::val(42)),
        ];
        let f = Function::new("0x12345678".to_string(), "test()".to_string(), trace);
        assert!(f.read_only);
        assert_eq!(f.returns.len(), 1);
    }

    #[test]
    fn test_function_print() {
        let trace = vec![Expr::node0("stop")];
        let f = Function::new("0xdeadbeef".to_string(), "fallback()".to_string(), trace);
        let output = f.print_decompiled();
        assert!(output.contains("def fallback()"));
    }

    #[test]
    fn test_payable_detection() {
        // A non-payable function has a callvalue guard.
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("callvalue"),
            Expr::node("seq", vec![Expr::node0("revert")]),
            Expr::node("seq", vec![Expr::node0("stop")]),
        )];
        let f = Function::new("0x1234".into(), "test()".into(), trace);
        assert!(!f.payable);
    }

    #[test]
    fn test_read_only_detection() {
        // A function with store is not read-only.
        let trace = vec![
            Expr::Node("store".into(), vec![Expr::val(256), Expr::zero(), Expr::val(1), Expr::val(42)]),
            Expr::node0("stop"),
        ];
        let f = Function::new("0x1234".into(), "test()".into(), trace);
        assert!(!f.read_only);
    }

    #[test]
    fn test_param_inference_simple() {
        // cd(4) with mask_shl(160, 0, 0, cd(4)) → address param.
        let trace = vec![
            Expr::Node("mask_shl".into(), vec![
                Expr::val(160), Expr::zero(), Expr::zero(), Expr::node1("cd", Expr::val(4)),
            ]),
            Expr::node0("stop"),
        ];
        let f = Function::new("0x1234".into(), "test()".into(), trace);
        assert!(!f.params.is_empty());
        assert_eq!(f.params[0].kind, "address");
    }

    #[test]
    fn test_param_inference_bool() {
        // bool(cd(4)) → bool param.
        let trace = vec![
            Expr::node1("bool", Expr::node1("cd", Expr::val(4))),
            Expr::node0("stop"),
        ];
        let f = Function::new("0x1234".into(), "test()".into(), trace);
        assert!(!f.params.is_empty());
        assert_eq!(f.params[0].kind, "bool");
    }

    #[test]
    fn test_param_inference_uint256() {
        // Bare cd(4) → uint256.
        let trace = vec![
            Expr::node1("cd", Expr::val(4)),
            Expr::node0("stop"),
        ];
        let f = Function::new("0x1234".into(), "test()".into(), trace);
        assert!(!f.params.is_empty());
        assert_eq!(f.params[0].kind, "uint256");
    }

    #[test]
    fn test_type_default_size() {
        assert_eq!(type_default_size("bool"), Some(8));
        assert_eq!(type_default_size("address"), Some(160));
        assert_eq!(type_default_size("uint256"), Some(256));
        assert_eq!(type_default_size("uint8"), Some(8));
        assert_eq!(type_default_size("bytes4"), Some(32));
    }

    #[test]
    fn test_trace_has_write_ops() {
        let trace = vec![Expr::node0("stop")];
        assert!(!trace_has_write_ops(&trace));

        let trace = vec![Expr::Node("store".into(), vec![Expr::val(256), Expr::zero(), Expr::val(1), Expr::val(42)])];
        assert!(trace_has_write_ops(&trace));
    }
}
