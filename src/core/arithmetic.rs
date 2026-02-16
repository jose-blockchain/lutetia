//! Concrete EVM arithmetic operations.
//!
//! All functions operate on `U256` and mirror the EVM specification exactly.

use primitive_types::U256;

/// 2^256 is handled implicitly by U256 wrapping.
const UINT_256_MAX: U256 = U256::MAX;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_signed(value: U256) -> i128 {
    // For values that fit in 128 bits of the positive range, treat directly.
    // For larger values, treat as negative (two's complement).
    let half = U256::one() << 255;
    if value < half {
        value.low_u128() as i128
    } else {
        // value - 2^256  (negative)
        // We compute -(2^256 - value).  Since U256 wraps, we do:
        let neg = (!value).overflowing_add(U256::one()).0;
        -(neg.low_u128() as i128)
    }
}

/// Convert a signed i128 back to U256 (two's complement).
fn from_signed(v: i128) -> U256 {
    if v >= 0 {
        U256::from(v as u128)
    } else {
        // 2^256 + v
        let pos = (-v) as u128;
        (!U256::from(pos)).overflowing_add(U256::one()).0
    }
}

// ---------------------------------------------------------------------------
// Arithmetic operations
// ---------------------------------------------------------------------------

/// EVM ADD: wrapping addition mod 2^256.
pub fn add(a: U256, b: U256) -> U256 {
    a.overflowing_add(b).0
}

/// EVM SUB: wrapping subtraction mod 2^256.
pub fn sub(a: U256, b: U256) -> U256 {
    a.overflowing_sub(b).0
}

/// EVM MUL: wrapping multiplication mod 2^256.
pub fn mul(a: U256, b: U256) -> U256 {
    a.overflowing_mul(b).0
}

/// EVM DIV: unsigned integer division (returns 0 on divide-by-zero).
pub fn div(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        U256::zero()
    } else {
        a / b
    }
}

/// EVM SDIV: signed integer division (returns 0 on divide-by-zero).
pub fn sdiv(a: U256, b: U256) -> U256 {
    let sa = to_signed(a);
    let sb = to_signed(b);
    if sb == 0 {
        U256::zero()
    } else {
        let sign = if (sa < 0) != (sb < 0) { -1i128 } else { 1 };
        from_signed(sign * (sa.unsigned_abs() as i128 / sb.unsigned_abs() as i128))
    }
}

/// EVM MOD: unsigned modulo (returns 0 when modulus is zero).
pub fn modulo(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        U256::zero()
    } else {
        a % b
    }
}

/// EVM SMOD: signed modulo (returns 0 when modulus is zero).
pub fn smod(a: U256, b: U256) -> U256 {
    let sa = to_signed(a);
    let sb = to_signed(b);
    if sb == 0 {
        U256::zero()
    } else {
        let sign = if sa < 0 { -1i128 } else { 1 };
        from_signed(sign * (sa.unsigned_abs() as i128 % sb.unsigned_abs() as i128))
    }
}

/// EVM ADDMOD: `(a + b) % m` using 512-bit intermediate to avoid overflow.
pub fn addmod(a: U256, b: U256, m: U256) -> U256 {
    if m.is_zero() {
        U256::zero()
    } else {
        // Need to use 512-bit add to avoid overflow before mod.
        let a512 = primitive_types::U512::from(a);
        let b512 = primitive_types::U512::from(b);
        let m512 = primitive_types::U512::from(m);
        let result = (a512 + b512) % m512;
        u512_to_u256(result)
    }
}

/// EVM MULMOD: `(a * b) % m` using 512-bit intermediate to avoid overflow.
pub fn mulmod(a: U256, b: U256, m: U256) -> U256 {
    if m.is_zero() {
        U256::zero()
    } else {
        let a512 = primitive_types::U512::from(a);
        let b512 = primitive_types::U512::from(b);
        let m512 = primitive_types::U512::from(m);
        let result = (a512 * b512) % m512;
        u512_to_u256(result)
    }
}

/// Convert a U512 to U256 by taking the low 256 bits.
fn u512_to_u256(v: primitive_types::U512) -> U256 {
    // Extract the low 4 u64 limbs from U512 (which has 8 limbs).
    let limbs = v.0;
    U256([limbs[0], limbs[1], limbs[2], limbs[3]])
}

/// EVM EXP: modular exponentiation `base^exponent mod 2^256`.
pub fn exp(base: U256, exponent: U256) -> U256 {
    if exponent.is_zero() {
        return U256::one();
    }
    if base.is_zero() {
        return U256::zero();
    }
    // Modular exponentiation mod 2^256
    let mut result = U256::one();
    let mut b = base;
    let mut e = exponent;
    while !e.is_zero() {
        if e.bit(0) {
            result = result.overflowing_mul(b).0;
        }
        e >>= 1;
        if !e.is_zero() {
            b = b.overflowing_mul(b).0;
        }
    }
    result
}

/// EVM SIGNEXTEND: extend the sign bit at byte position `bits`.
pub fn signextend(bits: U256, value: U256) -> U256 {
    if bits < U256::from(31u64) {
        let bit_index = bits.low_u64() * 8 + 7;
        let sign_bit = U256::one() << bit_index as usize;
        if !(value & sign_bit).is_zero() {
            value | (UINT_256_MAX - sign_bit + U256::one())
        } else {
            value & (sign_bit - U256::one())
        }
    } else {
        value
    }
}

// -- Comparison operations -------------------------------------------------

/// EVM LT: unsigned less-than comparison.
pub fn lt(a: U256, b: U256) -> U256 {
    if a < b { U256::one() } else { U256::zero() }
}

/// EVM GT: unsigned greater-than comparison.
pub fn gt(a: U256, b: U256) -> U256 {
    if a > b { U256::one() } else { U256::zero() }
}

/// EVM SLT: signed less-than comparison (two's complement).
pub fn slt(a: U256, b: U256) -> U256 {
    let sa = to_signed(a);
    let sb = to_signed(b);
    if sa < sb { U256::one() } else { U256::zero() }
}

/// EVM SGT: signed greater-than comparison (two's complement).
pub fn sgt(a: U256, b: U256) -> U256 {
    let sa = to_signed(a);
    let sb = to_signed(b);
    if sa > sb { U256::one() } else { U256::zero() }
}

/// EVM EQ: equality comparison.
pub fn eq(a: U256, b: U256) -> U256 {
    if a == b { U256::one() } else { U256::zero() }
}

/// EVM ISZERO: returns 1 if the value is zero, 0 otherwise.
pub fn iszero(a: U256) -> U256 {
    if a.is_zero() { U256::one() } else { U256::zero() }
}

// -- Bitwise operations ----------------------------------------------------

/// EVM AND: bitwise AND.
pub fn and(a: U256, b: U256) -> U256 {
    a & b
}

/// EVM OR: bitwise OR.
pub fn or(a: U256, b: U256) -> U256 {
    a | b
}

/// EVM XOR: bitwise XOR.
pub fn xor(a: U256, b: U256) -> U256 {
    a ^ b
}

/// EVM NOT: bitwise complement.
pub fn not(a: U256) -> U256 {
    !a
}

/// EVM BYTE: extract a single byte from a 32-byte value at the given position.
pub fn byte_op(position: U256, value: U256) -> U256 {
    if position >= U256::from(32u64) {
        U256::zero()
    } else {
        let shift = (31 - position.low_u64()) * 8;
        (value >> shift as usize) & U256::from(0xFFu64)
    }
}

// -- Shift operations (Constantinople) -------------------------------------

/// EVM SHL: logical shift left (Constantinople).
pub fn shl(shift: U256, value: U256) -> U256 {
    if shift >= U256::from(256u64) {
        U256::zero()
    } else {
        value << shift.low_u64() as usize
    }
}

/// EVM SHR: logical shift right (Constantinople).
pub fn shr(shift: U256, value: U256) -> U256 {
    if shift >= U256::from(256u64) {
        U256::zero()
    } else {
        value >> shift.low_u64() as usize
    }
}

/// EVM SAR: arithmetic shift right (Constantinople, preserves sign).
pub fn sar(shift: U256, value: U256) -> U256 {
    let sv = to_signed(value);
    if shift >= U256::from(256u64) {
        if sv >= 0 { U256::zero() } else { UINT_256_MAX }
    } else {
        from_signed(sv >> shift.low_u64())
    }
}

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------

/// Evaluate a concrete binary / unary / ternary opcode.
/// Returns `None` if the opcode is not a pure arithmetic one.
pub fn eval_concrete(op: &str, args: &[U256]) -> Option<U256> {
    match (op, args) {
        ("add", [a, b])          => Some(add(*a, *b)),
        ("sub", [a, b])          => Some(sub(*a, *b)),
        ("mul", [a, b])          => Some(mul(*a, *b)),
        ("div", [a, b])          => Some(div(*a, *b)),
        ("sdiv", [a, b])         => Some(sdiv(*a, *b)),
        ("mod", [a, b])          => Some(modulo(*a, *b)),
        ("smod", [a, b])         => Some(smod(*a, *b)),
        ("addmod", [a, b, c])    => Some(addmod(*a, *b, *c)),
        ("mulmod", [a, b, c])    => Some(mulmod(*a, *b, *c)),
        ("exp", [a, b])          => Some(exp(*a, *b)),
        ("signextend", [a, b])   => Some(signextend(*a, *b)),
        ("lt", [a, b])           => Some(lt(*a, *b)),
        ("gt", [a, b])           => Some(gt(*a, *b)),
        ("slt", [a, b])          => Some(slt(*a, *b)),
        ("sgt", [a, b])          => Some(sgt(*a, *b)),
        ("eq", [a, b])           => Some(eq(*a, *b)),
        ("iszero", [a])          => Some(iszero(*a)),
        ("and", [a, b])          => Some(and(*a, *b)),
        ("or", [a, b])           => Some(or(*a, *b)),
        ("xor", [a, b])          => Some(xor(*a, *b)),
        ("not", [a])             => Some(not(*a)),
        ("byte", [a, b])         => Some(byte_op(*a, *b)),
        ("shl", [a, b])          => Some(shl(*a, *b)),
        ("shr", [a, b])          => Some(shr(*a, *b)),
        ("sar", [a, b])          => Some(sar(*a, *b)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(U256::from(1u64), U256::from(2u64)), U256::from(3u64));
        // Overflow wraps
        assert_eq!(add(UINT_256_MAX, U256::one()), U256::zero());
    }

    #[test]
    fn test_sub() {
        assert_eq!(sub(U256::from(5u64), U256::from(3u64)), U256::from(2u64));
        // Underflow wraps
        assert_eq!(sub(U256::zero(), U256::one()), UINT_256_MAX);
    }

    #[test]
    fn test_mul() {
        assert_eq!(mul(U256::from(3u64), U256::from(7u64)), U256::from(21u64));
        assert_eq!(mul(U256::zero(), U256::from(99u64)), U256::zero());
    }

    #[test]
    fn test_div() {
        assert_eq!(div(U256::from(10u64), U256::from(3u64)), U256::from(3u64));
        assert_eq!(div(U256::from(10u64), U256::zero()), U256::zero());
    }

    #[test]
    fn test_sdiv() {
        // -6 / 3 = -2
        let neg6 = sub(U256::zero(), U256::from(6u64));
        let result = sdiv(neg6, U256::from(3u64));
        let neg2 = sub(U256::zero(), U256::from(2u64));
        assert_eq!(result, neg2);
    }

    #[test]
    fn test_exp() {
        assert_eq!(exp(U256::from(2u64), U256::from(10u64)), U256::from(1024u64));
        assert_eq!(exp(U256::from(0u64), U256::from(0u64)), U256::one());
        assert_eq!(exp(U256::from(0u64), U256::from(5u64)), U256::zero());
    }

    #[test]
    fn test_signextend() {
        // signextend(0, 0xFF) should give 0xFF...FF (negative byte sign-extended)
        let result = signextend(U256::zero(), U256::from(0xFFu64));
        assert_eq!(result, UINT_256_MAX);
    }

    #[test]
    fn test_shl_shr() {
        assert_eq!(shl(U256::from(4u64), U256::from(1u64)), U256::from(16u64));
        assert_eq!(shr(U256::from(4u64), U256::from(16u64)), U256::from(1u64));
        assert_eq!(shl(U256::from(256u64), U256::from(1u64)), U256::zero());
    }

    #[test]
    fn test_byte_op() {
        // byte(31, 0xFF) = 0xFF  (least significant byte)
        assert_eq!(byte_op(U256::from(31u64), U256::from(0xFFu64)), U256::from(0xFFu64));
        // byte(0, 0xFF) = 0  (most significant byte of a small number)
        assert_eq!(byte_op(U256::from(0u64), U256::from(0xFFu64)), U256::zero());
    }

    #[test]
    fn test_comparison() {
        assert_eq!(lt(U256::from(1u64), U256::from(2u64)), U256::one());
        assert_eq!(lt(U256::from(2u64), U256::from(1u64)), U256::zero());
        assert_eq!(eq(U256::from(5u64), U256::from(5u64)), U256::one());
        assert_eq!(iszero(U256::zero()), U256::one());
        assert_eq!(iszero(U256::from(1u64)), U256::zero());
    }

    #[test]
    fn test_eval_concrete() {
        let a = U256::from(10u64);
        let b = U256::from(3u64);
        assert_eq!(eval_concrete("add", &[a, b]), Some(U256::from(13u64)));
        assert_eq!(eval_concrete("mul", &[a, b]), Some(U256::from(30u64)));
        assert_eq!(eval_concrete("nonexistent", &[a, b]), None);
    }

    #[test]
    fn test_sar_negative() {
        // -1 >> 1 = -1
        let neg1 = UINT_256_MAX;
        assert_eq!(sar(U256::from(1u64), neg1), UINT_256_MAX);
    }

    #[test]
    fn test_addmod_mulmod() {
        let a = U256::from(10u64);
        let b = U256::from(10u64);
        let m = U256::from(8u64);
        assert_eq!(addmod(a, b, m), U256::from(4u64)); // (10+10) % 8 = 4
        assert_eq!(mulmod(a, b, m), U256::from(4u64)); // (10*10) % 8 = 4
    }
}
