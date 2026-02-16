//! Extended matcher tests.

use lutetia::expr::Expr;
use lutetia::matcher::*;

#[test]
fn test_match_nested_node() {
    let e = Expr::node2("add", Expr::node2("mul", Expr::val(2), Expr::val(3)), Expr::val(4));
    let p = Pattern::node(
        "add",
        vec![
            Pattern::node("mul", vec![Pattern::capture("a"), Pattern::capture("b")]),
            Pattern::capture("c"),
        ],
    );
    let m = match_expr(&e, &p).unwrap();
    assert_eq!(m.get("a"), Some(&Expr::val(2)));
    assert_eq!(m.get("b"), Some(&Expr::val(3)));
    assert_eq!(m.get("c"), Some(&Expr::val(4)));
}

#[test]
fn test_match_atom_pattern() {
    let e = Expr::atom("caller");
    assert!(match_expr(&e, &Pattern::atom("caller")).is_some());
    assert!(match_expr(&e, &Pattern::atom("origin")).is_none());
}

#[test]
fn test_match_wrong_arity() {
    let e = Expr::node2("add", Expr::val(1), Expr::val(2));
    let p = Pattern::node("add", vec![Pattern::Any]); // only 1 child pattern for 2 children
    assert!(match_expr(&e, &p).is_none());
}

#[test]
fn test_match_ellipsis_at_end() {
    let e = Expr::node(
        "log",
        vec![Expr::val(1), Expr::val(2), Expr::val(3)],
    );
    let p = Pattern::node("log", vec![Pattern::capture("first"), Pattern::Ellipsis]);
    let m = match_expr(&e, &p).unwrap();
    assert_eq!(m.get("first"), Some(&Expr::val(1)));
}

#[test]
fn test_replace_pattern_simple() {
    let e = Expr::node2("add", Expr::val(0), Expr::atom("x"));
    let p = Pattern::node("add", vec![Pattern::val(0), Pattern::capture("a")]);
    let replacement = Expr::Atom(":a".to_string());
    let result = replace_pattern(&e, &p, &replacement);
    assert_eq!(result, Expr::atom("x"));
}

#[test]
fn test_replace_pattern_nested() {
    // Replace all (add 0 :x) → :x
    let e = Expr::node2(
        "mul",
        Expr::node2("add", Expr::val(0), Expr::atom("y")),
        Expr::val(5),
    );
    let p = Pattern::node("add", vec![Pattern::val(0), Pattern::capture("x")]);
    let replacement = Expr::Atom(":x".to_string());
    let result = replace_pattern(&e, &p, &replacement);
    assert_eq!(result, Expr::node2("mul", Expr::atom("y"), Expr::val(5)));
}

#[test]
fn test_match_bool_val() {
    let e = Expr::val(42);
    let p = Pattern::val(42);
    assert!(match_expr(&e, &p).is_some());

    let p2 = Pattern::val(0);
    assert!(match_expr(&e, &p2).is_none());
}

#[test]
fn test_match_any_accepts_all() {
    assert!(match_expr(&Expr::val(42), &Pattern::Any).is_some());
    assert!(match_expr(&Expr::atom("x"), &Pattern::Any).is_some());
    assert!(match_expr(&Expr::Bool(true), &Pattern::Any).is_some());
    assert!(match_expr(&Expr::node0("stop"), &Pattern::Any).is_some());
}

#[test]
fn test_match_get_val() {
    let e = Expr::val(42);
    let m = match_expr(&e, &Pattern::capture("n")).unwrap();
    assert_eq!(m.get_val("n"), Some(primitive_types::U256::from(42)));
    assert_eq!(m.get_val("missing"), None);
}
