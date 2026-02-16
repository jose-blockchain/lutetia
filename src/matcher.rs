//! Pattern matching on symbolic expressions.
//!
//! Mirrors the Python `matcher.py`: match an expression against a pattern
//! and extract named bindings.

use crate::expr::Expr;
use std::collections::HashMap;

/// The result of a successful match — a map of named captures.
#[derive(Debug, Clone, Default)]
pub struct Match {
    pub bindings: HashMap<String, Expr>,
}

impl Match {
    /// Retrieve a captured expression by name.
    pub fn get(&self, name: &str) -> Option<&Expr> {
        self.bindings.get(name)
    }

    /// Retrieve a captured value (U256) by name, or `None` if not a concrete value.
    pub fn get_val(&self, name: &str) -> Option<primitive_types::U256> {
        self.bindings.get(name).and_then(|e| e.as_val())
    }
}

/// Pattern atoms used when building match patterns.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Match anything, don't capture.
    Any,
    /// Match anything and bind to the given name.
    Capture(String),
    /// Match a specific concrete value.
    Val(primitive_types::U256),
    /// Match a specific atom string.
    Atom(String),
    /// Match a node with the given opcode and child patterns.
    Node(String, Vec<Pattern>),
    /// Match remaining children (like `...` / Ellipsis in Python).
    Ellipsis,
}

impl Pattern {
    /// A capture pattern that matches any expression and stores it under `name`.
    pub fn capture(name: &str) -> Self {
        Pattern::Capture(name.to_string())
    }

    /// A pattern that matches a specific atom.
    pub fn atom(s: &str) -> Self {
        Pattern::Atom(s.to_string())
    }

    /// A pattern that matches a specific numeric value.
    pub fn val(v: u64) -> Self {
        Pattern::Val(primitive_types::U256::from(v))
    }

    /// A pattern that matches a node with the given opcode and child patterns.
    pub fn node(op: &str, children: Vec<Pattern>) -> Self {
        Pattern::Node(op.to_string(), children)
    }
}

/// Try to match `expr` against `pattern`.
/// Returns `Some(Match)` on success, `None` on failure.
pub fn match_expr(expr: &Expr, pattern: &Pattern) -> Option<Match> {
    let mut m = Match::default();
    if match_helper(expr, pattern, &mut m) {
        Some(m)
    } else {
        None
    }
}

fn match_helper(expr: &Expr, pattern: &Pattern, m: &mut Match) -> bool {
    match pattern {
        Pattern::Any => true,
        Pattern::Ellipsis => true,
        Pattern::Capture(name) => {
            if let Some(existing) = m.bindings.get(name) {
                existing == expr
            } else {
                m.bindings.insert(name.clone(), expr.clone());
                true
            }
        }
        Pattern::Val(v) => {
            matches!(expr, Expr::Val(ev) if ev == v)
        }
        Pattern::Atom(s) => {
            matches!(expr, Expr::Atom(ea) if ea == s)
        }
        Pattern::Node(op, children) => {
            if let Expr::Node(eop, echildren) = expr {
                if eop != op {
                    return false;
                }
                let mut ci = 0;
                let mut pi = 0;
                while pi < children.len() && ci < echildren.len() {
                    if matches!(children[pi], Pattern::Ellipsis) {
                        return true; // rest matches anything
                    }
                    if !match_helper(&echildren[ci], &children[pi], m) {
                        return false;
                    }
                    ci += 1;
                    pi += 1;
                }
                // Check trailing Ellipsis
                if pi < children.len() && matches!(children[pi], Pattern::Ellipsis) {
                    return true;
                }
                ci == echildren.len() && pi == children.len()
            } else {
                false
            }
        }
    }
}

/// Replace occurrences of `pattern` with `replacement` throughout `expr`.
/// Named captures in the replacement (Pattern::Capture) are substituted from
/// the match bindings.
pub fn replace_pattern(expr: &Expr, pattern: &Pattern, replacement: &Expr) -> Expr {
    if let Some(m) = match_expr(expr, pattern) {
        substitute(replacement, &m)
    } else {
        match expr {
            Expr::Node(op, children) => {
                let new_children: Vec<Expr> = children
                    .iter()
                    .map(|c| replace_pattern(c, pattern, replacement))
                    .collect();
                Expr::Node(op.clone(), new_children)
            }
            other => other.clone(),
        }
    }
}

fn substitute(template: &Expr, m: &Match) -> Expr {
    match template {
        Expr::Atom(name) if name.starts_with(':') => {
            let key = &name[1..];
            m.bindings.get(key).cloned().unwrap_or_else(|| template.clone())
        }
        Expr::Node(op, children) => {
            let new_children: Vec<Expr> = children.iter().map(|c| substitute(c, m)).collect();
            Expr::Node(op.clone(), new_children)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::Expr;

    #[test]
    fn test_match_any() {
        let e = Expr::val(42);
        assert!(match_expr(&e, &Pattern::Any).is_some());
    }

    #[test]
    fn test_match_val() {
        let e = Expr::val(42);
        assert!(match_expr(&e, &Pattern::val(42)).is_some());
        assert!(match_expr(&e, &Pattern::val(43)).is_none());
    }

    #[test]
    fn test_match_capture() {
        let e = Expr::val(42);
        let m = match_expr(&e, &Pattern::capture("x")).unwrap();
        assert_eq!(m.get("x"), Some(&Expr::val(42)));
    }

    #[test]
    fn test_match_node() {
        let e = Expr::node2("add", Expr::val(1), Expr::val(2));
        let p = Pattern::node("add", vec![Pattern::capture("a"), Pattern::capture("b")]);
        let m = match_expr(&e, &p).unwrap();
        assert_eq!(m.get("a"), Some(&Expr::val(1)));
        assert_eq!(m.get("b"), Some(&Expr::val(2)));
    }

    #[test]
    fn test_match_node_wrong_op() {
        let e = Expr::node2("add", Expr::val(1), Expr::val(2));
        let p = Pattern::node("mul", vec![Pattern::Any, Pattern::Any]);
        assert!(match_expr(&e, &p).is_none());
    }

    #[test]
    fn test_match_ellipsis() {
        let e = Expr::node("add", vec![Expr::val(1), Expr::val(2), Expr::val(3)]);
        let p = Pattern::node("add", vec![Pattern::capture("first"), Pattern::Ellipsis]);
        let m = match_expr(&e, &p).unwrap();
        assert_eq!(m.get("first"), Some(&Expr::val(1)));
    }

    #[test]
    fn test_match_repeated_capture() {
        // (:a, :a, :b) should match (1, 1, 3) but not (1, 2, 3)
        let e_ok = Expr::node("t", vec![Expr::val(1), Expr::val(1), Expr::val(3)]);
        let e_bad = Expr::node("t", vec![Expr::val(1), Expr::val(2), Expr::val(3)]);
        let p = Pattern::node(
            "t",
            vec![Pattern::capture("a"), Pattern::capture("a"), Pattern::capture("b")],
        );
        assert!(match_expr(&e_ok, &p).is_some());
        assert!(match_expr(&e_bad, &p).is_none());
    }
}
