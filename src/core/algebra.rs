//! Symbolic algebra operations.
//!
//! Handles operations on expressions that may not be concrete, e.g.
//! adding a symbolic value to a concrete one.

use crate::expr::Expr;
use primitive_types::U256;

/// Custom error for incomparable symbolic expressions.
#[derive(Debug, Clone)]
pub struct CannotCompare;

impl std::fmt::Display for CannotCompare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot compare symbolic expressions")
    }
}

impl std::error::Error for CannotCompare {}

/// Symbolic addition.
pub fn add_op(left: Expr, right: Expr) -> Expr {
    match (&left, &right) {
        (Expr::Val(a), Expr::Val(b)) => Expr::Val(a.overflowing_add(*b).0),
        (Expr::Val(v), _) if v.is_zero() => right,
        (_, Expr::Val(v)) if v.is_zero() => left,
        _ => Expr::node2("add", left, right),
    }
}

/// Symbolic subtraction.
pub fn sub_op(left: Expr, right: Expr) -> Expr {
    match (&left, &right) {
        (Expr::Val(a), Expr::Val(b)) => Expr::Val(a.overflowing_sub(*b).0),
        (_, Expr::Val(v)) if v.is_zero() => left,
        _ if left == right => Expr::zero(),
        _ => Expr::node2("add", left, minus_op(right)),
    }
}

/// Symbolic multiplication.
pub fn mul_op(left: Expr, right: Expr) -> Expr {
    match (&left, &right) {
        (Expr::Val(a), Expr::Val(b)) => Expr::Val(a.overflowing_mul(*b).0),
        (Expr::Val(v), _) if v.is_zero() => Expr::zero(),
        (_, Expr::Val(v)) if v.is_zero() => Expr::zero(),
        (Expr::Val(v), _) if *v == U256::one() => right,
        (_, Expr::Val(v)) if *v == U256::one() => left,
        _ => Expr::node2("mul", left, right),
    }
}

/// Negate: `−exp` = `mul(-1, exp)`.
pub fn minus_op(exp: Expr) -> Expr {
    mul_op(Expr::Val(U256::MAX), exp) // -1 in two's complement
}

/// Symbolic OR.
pub fn or_op(left: Expr, right: Expr) -> Expr {
    match (&left, &right) {
        (Expr::Val(a), Expr::Val(b)) => Expr::Val(*a | *b),
        (Expr::Val(v), _) if v.is_zero() => right,
        (_, Expr::Val(v)) if v.is_zero() => left,
        _ => Expr::node2("or", left, right),
    }
}

/// Symbolic mask operation: `mask_shl(size, offset, shl, val)`.
///
/// Extracts `size` bits starting at `offset` from `val`, then shifts left by `shl`.
pub fn mask_op(val: Expr, size: Expr, offset: Expr, shift: Expr) -> Expr {
    // Trivial: size == 0 → 0
    if let Expr::Val(s) = &size {
        if s.is_zero() {
            return Expr::zero();
        }
    }

    // Identity: (256, 0, 0, val) → val
    if let (Expr::Val(s), Expr::Val(o), Expr::Val(sh)) = (&size, &offset, &shift) {
        if *s == U256::from(256u64) && o.is_zero() && sh.is_zero() {
            return val;
        }
    }

    Expr::Node(
        "mask_shl".to_string(),
        vec![size, offset, shift, val],
    )
}

/// Convert expression to bits (multiply by 8).
pub fn bits(exp: Expr) -> Expr {
    mul_op(exp, Expr::val(8))
}

/// Try to determine if `left < right` symbolically.
pub fn lt_op(left: &Expr, right: &Expr) -> Result<Option<bool>, CannotCompare> {
    match (left.as_val(), right.as_val()) {
        (Some(a), Some(b)) => Ok(Some(a < b)),
        _ => Err(CannotCompare),
    }
}

/// Try to determine if `left <= right` symbolically.
pub fn le_op(left: &Expr, right: &Expr) -> Result<Option<bool>, CannotCompare> {
    match (left.as_val(), right.as_val()) {
        (Some(a), Some(b)) => Ok(Some(a <= b)),
        _ => Err(CannotCompare),
    }
}

/// Safe version of `lt_op` that returns `None` on error.
pub fn safe_lt_op(left: &Expr, right: &Expr) -> Option<bool> {
    lt_op(left, right).ok().flatten()
}

/// Safe version of `le_op` that returns `None` on error.
pub fn safe_le_op(left: &Expr, right: &Expr) -> Option<bool> {
    le_op(left, right).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_op_concrete() {
        let result = add_op(Expr::val(10), Expr::val(20));
        assert_eq!(result, Expr::val(30));
    }

    #[test]
    fn test_add_op_zero() {
        let x = Expr::atom("x");
        assert_eq!(add_op(Expr::zero(), x.clone()), x);
    }

    #[test]
    fn test_sub_op_same() {
        let x = Expr::atom("x");
        assert_eq!(sub_op(x.clone(), x), Expr::zero());
    }

    #[test]
    fn test_mul_op() {
        assert_eq!(mul_op(Expr::val(3), Expr::val(7)), Expr::val(21));
        let x = Expr::atom("x");
        assert_eq!(mul_op(Expr::zero(), x), Expr::zero());
    }

    #[test]
    fn test_lt_op_concrete() {
        let a = Expr::val(5);
        let b = Expr::val(10);
        assert_eq!(lt_op(&a, &b).unwrap(), Some(true));
        assert_eq!(lt_op(&b, &a).unwrap(), Some(false));
    }

    #[test]
    fn test_lt_op_symbolic() {
        let a = Expr::atom("x");
        let b = Expr::val(10);
        assert!(lt_op(&a, &b).is_err());
    }
}
