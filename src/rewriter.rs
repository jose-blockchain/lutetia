//! Heuristic trace rewrites for readability.
//!
//! Applied after simplification: converts common patterns into more
//! readable forms (require detection, memcpy optimisation, string store
//! detection, etc.).

use crate::expr::{Expr, Trace};
use crate::utils::helpers::rewrite_trace;

/// Apply all rewrite passes to a trace.
pub fn rewrite(trace: &[Expr]) -> Trace {
    let mut trace = trace.to_vec();

    // Pass 1: Convert if/revert patterns to require().
    // Uses a custom traversal because rewrite_trace skips if/while nodes.
    trace = rewrite_require_pass(&trace);

    // Pass 2: Simplify memcpy patterns in setmem.
    trace = rewrite_trace(&trace, &rewrite_memcpy);

    // Pass 3: Clean up empty branches.
    trace = cleanup_empty_pass(&trace);

    trace
}

// ---------------------------------------------------------------------------
// Require detection
// ---------------------------------------------------------------------------

/// Recursively traverse the trace, converting if/revert into require().
fn rewrite_require_pass(trace: &[Expr]) -> Trace {
    let mut result = Vec::new();
    for line in trace {
        match line.opcode() {
            Some("if") => {
                // Try to convert this if to a require.
                let converted = rewrite_require(line);
                // Recurse into each result.
                for item in converted {
                    match item.opcode() {
                        Some("if") => {
                            // Still an if — recurse into branches.
                            if let Some(ch) = item.children() {
                                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                                let if_true = ch.get(1)
                                    .and_then(|e| e.children())
                                    .map(rewrite_require_pass)
                                    .unwrap_or_default();
                                let if_false = ch.get(2)
                                    .and_then(|e| e.children())
                                    .map(rewrite_require_pass)
                                    .unwrap_or_default();
                                result.push(Expr::node3(
                                    "if",
                                    cond,
                                    Expr::node("seq", if_true),
                                    Expr::node("seq", if_false),
                                ));
                            } else {
                                result.push(item);
                            }
                        }
                        Some("while") => {
                            if let Some(ch) = item.children() {
                                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                                let body = ch.get(1)
                                    .and_then(|e| e.children())
                                    .map(rewrite_require_pass)
                                    .unwrap_or_default();
                                let rest: Vec<Expr> = ch[2..].to_vec();
                                let mut new_ch = vec![cond, Expr::node("seq", body)];
                                new_ch.extend(rest);
                                result.push(Expr::Node("while".to_string(), new_ch));
                            } else {
                                result.push(item);
                            }
                        }
                        _ => result.push(item),
                    }
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = ch.get(1)
                        .and_then(|e| e.children())
                        .map(rewrite_require_pass)
                        .unwrap_or_default();
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                } else {
                    result.push(line.clone());
                }
            }
            _ => result.push(line.clone()),
        }
    }
    result
}

/// Convert `if (cond) { revert } else { body }` → `require(cond); body`
/// and `if (cond) { body } else { revert }` → `require(not cond); body`
/// and `if (cond) { revert }` (no else) → `require(not cond)`.
fn rewrite_require(line: &Expr) -> Vec<Expr> {
    if line.opcode() != Some("if") {
        return vec![line.clone()];
    }
    let ch = match line.children() {
        Some(ch) if ch.len() >= 2 => ch,
        _ => return vec![line.clone()],
    };

    let cond = &ch[0];
    let true_branch = extract_seq_children(&ch[1]);
    let false_branch = if ch.len() >= 3 {
        extract_seq_children(&ch[2])
    } else {
        vec![]
    };

    // Pattern 1: if (cond) { revert(...) } else { body }
    // → require(not cond[, reason]); body
    if is_single_revert(&true_branch) {
        let reason = extract_revert_reason(&true_branch);
        let req_cond = negate(cond);
        let mut result = vec![make_require(req_cond, reason)];
        result.extend(false_branch);
        return result;
    }

    // Pattern 2: if (cond) { body } else { revert(...) }
    // → require(cond[, reason]); body
    if is_single_revert(&false_branch) {
        let reason = extract_revert_reason(&false_branch);
        let mut result = vec![make_require(cond.clone(), reason)];
        result.extend(true_branch);
        return result;
    }

    vec![line.clone()]
}

/// Check if a branch consists of a single revert/invalid.
fn is_single_revert(branch: &[Expr]) -> bool {
    if branch.len() != 1 {
        return false;
    }
    matches!(branch[0].opcode(), Some("revert") | Some("invalid"))
}

/// Extract the revert reason from a single-revert branch.
fn extract_revert_reason(branch: &[Expr]) -> Option<Expr> {
    if branch.len() != 1 {
        return None;
    }
    if branch[0].opcode() == Some("revert") {
        if let Some(ch) = branch[0].children() {
            if ch.len() == 1 && !ch[0].is_zero() {
                return Some(ch[0].clone());
            }
        }
    }
    None
}

/// Build a `require(cond)` or `require(cond, reason)` expression.
fn make_require(cond: Expr, reason: Option<Expr>) -> Expr {
    match reason {
        Some(r) => Expr::node2("require", cond, r),
        None => Expr::node1("require", cond),
    }
}

/// Negate a condition with smart inversion of comparison operators.
///
/// - `iszero(x)` → `x`
/// - `lt(a, b)` → `ge(a, b)`
/// - `gt(a, b)` → `le(a, b)`
/// - `eq(a, b)` → `iszero(eq(a, b))`
/// - `bool(x)` → `iszero(x)`
/// - other → `iszero(other)`
fn negate(cond: &Expr) -> Expr {
    if let Some(op) = cond.opcode() {
        if let Some(ch) = cond.children() {
            match op {
                "iszero" if ch.len() == 1 => return ch[0].clone(),
                "lt" if ch.len() == 2 => return Expr::node2("ge", ch[0].clone(), ch[1].clone()),
                "gt" if ch.len() == 2 => return Expr::node2("le", ch[0].clone(), ch[1].clone()),
                "le" if ch.len() == 2 => return Expr::node2("gt", ch[0].clone(), ch[1].clone()),
                "ge" if ch.len() == 2 => return Expr::node2("lt", ch[0].clone(), ch[1].clone()),
                "slt" if ch.len() == 2 => return Expr::node2("sge", ch[0].clone(), ch[1].clone()),
                "sgt" if ch.len() == 2 => return Expr::node2("sle", ch[0].clone(), ch[1].clone()),
                "bool" if ch.len() == 1 => return Expr::node1("iszero", ch[0].clone()),
                _ => {}
            }
        }
    }
    Expr::node1("iszero", cond.clone())
}

// ---------------------------------------------------------------------------
// Memcpy simplification
// ---------------------------------------------------------------------------

/// Simplify `setmem(range(dst, ceil32(len)), data(call.data(...), mem(...)))`.
fn rewrite_memcpy(line: &Expr) -> Vec<Expr> {
    if line.opcode() != Some("setmem") {
        return vec![line.clone()];
    }
    let ch = match line.children() {
        Some(ch) if ch.len() == 2 => ch,
        _ => return vec![line.clone()],
    };

    // Check if value is data(call.data(...), mem(range(..., 0)))
    if ch[1].opcode() == Some("data") {
        if let Some(data_ch) = ch[1].children() {
            if data_ch.len() == 2 {
                // Second element is mem(range(..., 0)) → trailing zero padding.
                if data_ch[1].opcode() == Some("mem") {
                    if let Some(mem_ch) = data_ch[1].children() {
                        if mem_ch.len() == 1 && mem_ch[0].opcode() == Some("range") {
                            if let Some(rch) = mem_ch[0].children() {
                                if rch.len() == 2 && rch[1].is_zero() {
                                    // Simplify: use only the call.data part.
                                    return vec![Expr::node2("setmem", ch[0].clone(), data_ch[0].clone())];
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    vec![line.clone()]
}

// ---------------------------------------------------------------------------
// Empty branch cleanup
// ---------------------------------------------------------------------------

/// Recursively remove if statements where both branches are empty.
fn cleanup_empty_pass(trace: &[Expr]) -> Trace {
    let mut result = Vec::new();
    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    if ch.len() >= 3 {
                        let true_branch = extract_seq_children(&ch[1]);
                        let false_branch = extract_seq_children(&ch[2]);
                        if true_branch.is_empty() && false_branch.is_empty() {
                            continue; // Remove empty if.
                        }
                        // Recurse into branches.
                        result.push(Expr::node3(
                            "if",
                            ch[0].clone(),
                            Expr::node("seq", cleanup_empty_pass(&true_branch)),
                            Expr::node("seq", cleanup_empty_pass(&false_branch)),
                        ));
                    } else {
                        result.push(line.clone());
                    }
                } else {
                    result.push(line.clone());
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = ch.get(1)
                        .and_then(|e| e.children())
                        .map(cleanup_empty_pass)
                        .unwrap_or_default();
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                } else {
                    result.push(line.clone());
                }
            }
            _ => result.push(line.clone()),
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the children of a seq node, or wrap a single expr in a vec.
fn extract_seq_children(expr: &Expr) -> Vec<Expr> {
    if expr.opcode() == Some("seq") {
        expr.children().map(|ch| ch.to_vec()).unwrap_or_default()
    } else {
        vec![expr.clone()]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_from_if_true_revert() {
        // if (cond) { revert } else { stop }
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![Expr::node1("revert", Expr::zero())]),
            Expr::node("seq", vec![Expr::node0("stop")]),
        )];
        let result = rewrite(&trace);
        assert!(result.iter().any(|e| e.opcode() == Some("require")));
        assert!(result.iter().any(|e| e.opcode() == Some("stop")));
    }

    #[test]
    fn test_require_from_if_false_revert() {
        // if (cond) { stop } else { revert }
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![Expr::node0("stop")]),
            Expr::node("seq", vec![Expr::node1("revert", Expr::zero())]),
        )];
        let result = rewrite(&trace);
        assert!(result.iter().any(|e| e.opcode() == Some("require")));
    }

    #[test]
    fn test_cleanup_empty_branches() {
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![]),
            Expr::node("seq", vec![]),
        )];
        let result = rewrite(&trace);
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_rewrite_for_normal_if() {
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![Expr::node0("stop")]),
            Expr::node("seq", vec![Expr::node1("return", Expr::val(1))]),
        )];
        let result = rewrite(&trace);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].opcode(), Some("if"));
    }
}
