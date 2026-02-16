//! Simplifier tests.

use lutetia::expr::Expr;
use lutetia::simplify::simplify_trace;

#[test]
fn test_simplify_removes_unused_vars() {
    let trace = vec![
        Expr::node2("setvar", Expr::atom("_1"), Expr::val(42)),
        Expr::node0("stop"),
    ];
    let result = simplify_trace(&trace, 5, None);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].opcode(), Some("stop"));
}

#[test]
fn test_simplify_keeps_used_vars() {
    let trace = vec![
        Expr::node2("setvar", Expr::atom("_1"), Expr::val(42)),
        Expr::node1("return", Expr::node1("var", Expr::atom("_1"))),
    ];
    let result = simplify_trace(&trace, 5, None);
    // The var should be inlined: return(42)
    assert!(result.len() >= 1);
}

#[test]
fn test_simplify_iszero_iszero() {
    let trace = vec![
        Expr::node1("iszero", Expr::node1("iszero", Expr::atom("x"))),
        Expr::node0("stop"),
    ];
    let result = simplify_trace(&trace, 5, None);
    // iszero(iszero(x)) → bool(x)
    assert!(result.iter().any(|e| e.contains_op("bool")));
}

#[test]
fn test_simplify_eq_zero() {
    let trace = vec![
        Expr::node2("eq", Expr::atom("x"), Expr::zero()),
        Expr::node0("stop"),
    ];
    let result = simplify_trace(&trace, 5, None);
    // eq(x, 0) → iszero(x)
    assert!(result.iter().any(|e| e.contains_op("iszero")));
}

#[test]
fn test_simplify_identity_mask() {
    let trace = vec![
        Expr::Node(
            "mask_shl".to_string(),
            vec![Expr::val(256), Expr::zero(), Expr::zero(), Expr::atom("x")],
        ),
        Expr::node0("stop"),
    ];
    let result = simplify_trace(&trace, 5, None);
    // mask_shl(256, 0, 0, x) → x  — the atom "x" should appear directly.
    assert!(result.iter().any(|e| e.contains(&Expr::atom("x"))));
}

#[test]
fn test_simplify_true_condition() {
    let trace = vec![Expr::node3(
        "if",
        Expr::one(),
        Expr::node("seq", vec![Expr::node1("return", Expr::val(42))]),
        Expr::node("seq", vec![Expr::node0("stop")]),
    )];
    let result = simplify_trace(&trace, 5, None);
    // The true branch should be inlined
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].opcode(), Some("return"));
}

#[test]
fn test_simplify_false_condition() {
    let trace = vec![Expr::node3(
        "if",
        Expr::zero(),
        Expr::node("seq", vec![Expr::node1("return", Expr::val(42))]),
        Expr::node("seq", vec![Expr::node0("stop")]),
    )];
    let result = simplify_trace(&trace, 5, None);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].opcode(), Some("stop"));
}

#[test]
fn test_simplify_mul_one() {
    let trace = vec![
        Expr::node2("mul", Expr::one(), Expr::atom("x")),
        Expr::node0("stop"),
    ];
    let result = simplify_trace(&trace, 5, None);
    // mul(1, x) → x  — "x" should appear but "mul" should be gone.
    assert!(result.iter().any(|e| e.contains(&Expr::atom("x"))));
    assert!(!result.iter().any(|e| e.contains_op("mul")));
}

#[test]
fn test_simplify_empty_trace() {
    let result = simplify_trace(&[], 5, None);
    assert!(result.is_empty());
}

#[test]
fn test_simplify_timeout() {
    // Should not panic even with 0-second timeout.
    let trace = vec![Expr::node0("stop")];
    let result = simplify_trace(&trace, 0, None);
    assert!(!result.is_empty());
}
