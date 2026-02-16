//! Symbolic expression type used throughout the decompiler.
//!
//! In the original Python code, expressions are represented as nested tuples
//! such as `("add", 1, ("mul", 2, "x"))`.  Here we use a proper Rust enum so
//! that the compiler can help us keep things correct.

use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum unsigned 256-bit value.
pub const UINT_256_MAX: U256 = U256::MAX;
/// 2^255 (used for signed arithmetic).
pub const UINT_256_CEILING: U256 = U256::zero(); // handled via wrapping; see arithmetic
/// 2^255 − 1
pub const UINT_255_MAX: U256 = U256([
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX >> 1, // clear the top bit
]);

// -- Serde helpers for U256 --------------------------------------------------

mod u256_serde {
    use primitive_types::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize a U256 as a hex string (e.g. `"0x1a2b"`).
    pub fn serialize<S: Serializer>(val: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{val:x}"))
    }

    /// Deserialize a U256 from a hex string (with or without `0x` prefix).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let hex_str = String::deserialize(d)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        U256::from_str_radix(hex_str, 16).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Core expression type
// ---------------------------------------------------------------------------

/// A symbolic expression.
///
/// We intentionally keep this as a tree (like the Python tuples) rather than
/// a flat SSA form, because the simplifier and prettifier both operate on
/// tree patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Expr {
    /// Concrete 256-bit value.
    Val(#[serde(with = "u256_serde")] U256),
    /// Symbolic string atom: `"caller"`, `"callvalue"`, etc.
    Atom(String),
    /// Boolean literal.
    Bool(bool),
    /// A tagged node: `(opcode, children…)`.
    /// The first element is the opcode string and the rest are children.
    Node(String, Vec<Expr>),
}

impl Expr {
    // -- Convenience constructors ------------------------------------------

    /// Create a value expression from a `u64`.
    pub fn val(v: u64) -> Self {
        Expr::Val(U256::from(v))
    }

    /// Create a value expression from a `U256`.
    pub fn val_u256(v: U256) -> Self {
        Expr::Val(v)
    }

    /// Create a named atom (symbolic constant, variable name, etc.).
    pub fn atom(s: &str) -> Self {
        Expr::Atom(s.to_string())
    }

    /// Create a node expression with an opcode and list of children.
    pub fn node(op: &str, children: Vec<Expr>) -> Self {
        Expr::Node(op.to_string(), children)
    }

    /// Create a node with zero children (e.g. `stop`, `invalid`).
    pub fn node0(op: &str) -> Self {
        Expr::Node(op.to_string(), vec![])
    }

    /// Create a node with one child.
    pub fn node1(op: &str, a: Expr) -> Self {
        Expr::Node(op.to_string(), vec![a])
    }

    /// Create a node with two children.
    pub fn node2(op: &str, a: Expr, b: Expr) -> Self {
        Expr::Node(op.to_string(), vec![a, b])
    }

    /// Create a node with three children (e.g. `if`, `store`).
    pub fn node3(op: &str, a: Expr, b: Expr, c: Expr) -> Self {
        Expr::Node(op.to_string(), vec![a, b, c])
    }

    // -- Predicates --------------------------------------------------------

    /// Return the opcode string if this is a `Node`, `None` otherwise.
    pub fn opcode(&self) -> Option<&str> {
        match self {
            Expr::Node(op, _) => Some(op.as_str()),
            _ => None,
        }
    }

    /// Return the children if this is a `Node`.
    pub fn children(&self) -> Option<&[Expr]> {
        match self {
            Expr::Node(_, ch) => Some(ch.as_slice()),
            _ => None,
        }
    }

    /// Return `true` if the expression is a concrete integer.
    pub fn is_val(&self) -> bool {
        matches!(self, Expr::Val(_))
    }

    /// Try to extract a concrete `U256`.
    pub fn as_val(&self) -> Option<U256> {
        match self {
            Expr::Val(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract as u64 (returns None if value > u64::MAX).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Expr::Val(v) if *v <= U256::from(u64::MAX) => Some(v.low_u64()),
            _ => None,
        }
    }

    /// Try to extract as i64 (treating value as two's-complement).
    pub fn as_i64(&self) -> Option<i64> {
        self.as_u64().map(|v| v as i64)
    }

    /// Return `true` if all provided expressions are concrete integers.
    pub fn all_concrete(exprs: &[&Expr]) -> bool {
        exprs.iter().all(|e| e.is_val())
    }

    /// The zero expression.
    pub fn zero() -> Self {
        Expr::Val(U256::zero())
    }

    /// The one expression.
    pub fn one() -> Self {
        Expr::Val(U256::one())
    }

    /// Check if this is the zero value.
    pub fn is_zero(&self) -> bool {
        matches!(self, Expr::Val(v) if v.is_zero())
    }

    /// Check if this expression tree contains `target` anywhere.
    pub fn contains(&self, target: &Expr) -> bool {
        if self == target {
            return true;
        }
        match self {
            Expr::Node(_, children) => children.iter().any(|c| c.contains(target)),
            _ => false,
        }
    }

    /// Check if this expression tree contains an atom or node with the given opcode.
    pub fn contains_op(&self, op: &str) -> bool {
        match self {
            Expr::Node(o, children) => {
                o == op || children.iter().any(|c| c.contains_op(op))
            }
            Expr::Atom(s) => s == op,
            _ => false,
        }
    }

    /// Replace all occurrences of `from` with `to` in this expression tree.
    pub fn replace(&self, from: &Expr, to: &Expr) -> Expr {
        if self == from {
            return to.clone();
        }
        match self {
            Expr::Node(op, children) => {
                let new_ch: Vec<Expr> = children.iter().map(|c| c.replace(from, to)).collect();
                Expr::Node(op.clone(), new_ch)
            }
            other => other.clone(),
        }
    }

    /// Negate a boolean expression: wrap in iszero or unwrap if already iszero.
    pub fn is_zero_wrap(&self) -> Expr {
        if let Expr::Node(op, ch) = self {
            if op == "iszero" && ch.len() == 1 {
                return ch[0].clone();
            }
        }
        Expr::node1("iszero", self.clone())
    }

    /// Construct a node with 4 children.
    pub fn node4(op: &str, a: Expr, b: Expr, c: Expr, d: Expr) -> Self {
        Expr::Node(op.to_string(), vec![a, b, c, d])
    }

    /// Construct a node with 5 children.
    pub fn node5(op: &str, a: Expr, b: Expr, c: Expr, d: Expr, e: Expr) -> Self {
        Expr::Node(op.to_string(), vec![a, b, c, d, e])
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Val(v) => {
                if *v <= U256::from(9999u64) {
                    write!(f, "{v}")
                } else {
                    write!(f, "0x{v:x}")
                }
            }
            Expr::Atom(s) => write!(f, "{s}"),
            Expr::Bool(b) => write!(f, "{b}"),
            Expr::Node(op, children) => {
                write!(f, "({op}")?;
                for c in children {
                    write!(f, " {c}")?;
                }
                write!(f, ")")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trace type alias
// ---------------------------------------------------------------------------

/// A trace is just a flat list of expressions (each one is a "line").
pub type Trace = Vec<Expr>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_val_display() {
        assert_eq!(Expr::val(42).to_string(), "42");
        assert_eq!(Expr::val(0).to_string(), "0");
    }

    #[test]
    fn test_node_display() {
        let e = Expr::node2("add", Expr::val(1), Expr::val(2));
        assert_eq!(e.to_string(), "(add 1 2)");
    }

    #[test]
    fn test_opcode() {
        let e = Expr::node2("mul", Expr::val(3), Expr::atom("x"));
        assert_eq!(e.opcode(), Some("mul"));
        assert_eq!(Expr::val(10).opcode(), None);
    }

    #[test]
    fn test_all_concrete() {
        let a = Expr::val(1);
        let b = Expr::val(2);
        let c = Expr::atom("x");
        assert!(Expr::all_concrete(&[&a, &b]));
        assert!(!Expr::all_concrete(&[&a, &c]));
    }
}
