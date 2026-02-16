//! Extended unit tests for EVM arithmetic.

use lutetia::core::arithmetic::*;
use primitive_types::U256;

const MAX: U256 = U256::MAX;

#[test]
fn test_add_overflow_wraps() {
    assert_eq!(add(MAX, U256::from(2u64)), U256::one());
}

#[test]
fn test_sub_underflow_wraps() {
    assert_eq!(sub(U256::from(3u64), U256::from(5u64)), MAX - U256::one());
}

#[test]
fn test_mul_overflow_wraps() {
    let two = U256::from(2u64);
    // 2^255 * 2 = 0 (mod 2^256)
    let half = U256::one() << 255;
    assert_eq!(mul(half, two), U256::zero());
}

#[test]
fn test_div_by_zero() {
    assert_eq!(div(U256::from(42u64), U256::zero()), U256::zero());
}

#[test]
fn test_sdiv_negative_dividend() {
    let neg6 = sub(U256::zero(), U256::from(6u64));
    let three = U256::from(3u64);
    let neg2 = sub(U256::zero(), U256::from(2u64));
    assert_eq!(sdiv(neg6, three), neg2);
}

#[test]
fn test_sdiv_both_negative() {
    let neg6 = sub(U256::zero(), U256::from(6u64));
    let neg3 = sub(U256::zero(), U256::from(3u64));
    assert_eq!(sdiv(neg6, neg3), U256::from(2u64));
}

#[test]
fn test_modulo() {
    assert_eq!(modulo(U256::from(10u64), U256::from(3u64)), U256::one());
    assert_eq!(modulo(U256::from(10u64), U256::zero()), U256::zero());
}

#[test]
fn test_smod() {
    let neg10 = sub(U256::zero(), U256::from(10u64));
    let three = U256::from(3u64);
    // smod(-10, 3) = -(10 % 3) = -1
    let neg1 = sub(U256::zero(), U256::one());
    assert_eq!(smod(neg10, three), neg1);
}

#[test]
fn test_addmod_no_overflow() {
    let a = U256::from(100u64);
    let b = U256::from(200u64);
    let m = U256::from(7u64);
    assert_eq!(addmod(a, b, m), U256::from(300u64 % 7));
}

#[test]
fn test_addmod_zero_modulus() {
    assert_eq!(addmod(U256::from(5u64), U256::from(3u64), U256::zero()), U256::zero());
}

#[test]
fn test_mulmod_zero_modulus() {
    assert_eq!(mulmod(U256::from(5u64), U256::from(3u64), U256::zero()), U256::zero());
}

#[test]
fn test_exp_zero_base() {
    assert_eq!(exp(U256::zero(), U256::from(5u64)), U256::zero());
}

#[test]
fn test_exp_zero_exponent() {
    assert_eq!(exp(U256::from(42u64), U256::zero()), U256::one());
}

#[test]
fn test_exp_large() {
    assert_eq!(exp(U256::from(2u64), U256::from(16u64)), U256::from(65536u64));
}

#[test]
fn test_signextend_positive() {
    // signextend(0, 0x7F) = 0x7F (positive byte stays positive)
    let result = signextend(U256::zero(), U256::from(0x7Fu64));
    assert_eq!(result, U256::from(0x7Fu64));
}

#[test]
fn test_signextend_negative() {
    // signextend(0, 0xFF) → all ones (negative byte sign-extended)
    assert_eq!(signextend(U256::zero(), U256::from(0xFFu64)), MAX);
}

#[test]
fn test_signextend_large_bits() {
    // bits >= 31 → identity
    assert_eq!(signextend(U256::from(31u64), U256::from(42u64)), U256::from(42u64));
}

#[test]
fn test_shl_zero_shift() {
    assert_eq!(shl(U256::zero(), U256::from(0xFFu64)), U256::from(0xFFu64));
}

#[test]
fn test_shl_over_256() {
    assert_eq!(shl(U256::from(300u64), U256::from(1u64)), U256::zero());
}

#[test]
fn test_shr_over_256() {
    assert_eq!(shr(U256::from(300u64), U256::from(1u64)), U256::zero());
}

#[test]
fn test_sar_positive_value() {
    assert_eq!(sar(U256::from(1u64), U256::from(4u64)), U256::from(2u64));
}

#[test]
fn test_sar_negative_value() {
    // -1 >> n = -1
    assert_eq!(sar(U256::from(5u64), MAX), MAX);
}

#[test]
fn test_sar_over_256_positive() {
    assert_eq!(sar(U256::from(300u64), U256::from(42u64)), U256::zero());
}

#[test]
fn test_sar_over_256_negative() {
    assert_eq!(sar(U256::from(300u64), MAX), MAX);
}

#[test]
fn test_byte_op_out_of_range() {
    assert_eq!(byte_op(U256::from(32u64), U256::from(0xFFu64)), U256::zero());
}

#[test]
fn test_comparison_edge_cases() {
    assert_eq!(eq(U256::zero(), U256::zero()), U256::one());
    assert_eq!(lt(U256::zero(), U256::zero()), U256::zero());
    assert_eq!(gt(U256::zero(), U256::zero()), U256::zero());
}

#[test]
fn test_slt_sgt() {
    let neg1 = MAX; // -1 in two's complement
    let one = U256::one();
    assert_eq!(slt(neg1, one), U256::one());   // -1 < 1
    assert_eq!(sgt(neg1, one), U256::zero());  // -1 > 1 is false
    assert_eq!(sgt(one, neg1), U256::one());   // 1 > -1
}

#[test]
fn test_iszero() {
    assert_eq!(iszero(U256::zero()), U256::one());
    assert_eq!(iszero(U256::from(1u64)), U256::zero());
    assert_eq!(iszero(MAX), U256::zero());
}

#[test]
fn test_not() {
    assert_eq!(not(U256::zero()), MAX);
    assert_eq!(not(MAX), U256::zero());
}

#[test]
fn test_xor() {
    assert_eq!(xor(U256::from(0xFFu64), U256::from(0x0Fu64)), U256::from(0xF0u64));
}

#[test]
fn test_and() {
    assert_eq!(and(U256::from(0xFFu64), U256::from(0x0Fu64)), U256::from(0x0Fu64));
}

#[test]
fn test_or() {
    assert_eq!(or(U256::from(0xF0u64), U256::from(0x0Fu64)), U256::from(0xFFu64));
}

#[test]
fn test_eval_concrete_all_opcodes() {
    let a = U256::from(10u64);
    let b = U256::from(3u64);
    let m = U256::from(7u64);

    assert!(eval_concrete("add", &[a, b]).is_some());
    assert!(eval_concrete("sub", &[a, b]).is_some());
    assert!(eval_concrete("mul", &[a, b]).is_some());
    assert!(eval_concrete("div", &[a, b]).is_some());
    assert!(eval_concrete("sdiv", &[a, b]).is_some());
    assert!(eval_concrete("mod", &[a, b]).is_some());
    assert!(eval_concrete("smod", &[a, b]).is_some());
    assert!(eval_concrete("addmod", &[a, b, m]).is_some());
    assert!(eval_concrete("mulmod", &[a, b, m]).is_some());
    assert!(eval_concrete("exp", &[a, b]).is_some());
    assert!(eval_concrete("signextend", &[a, b]).is_some());
    assert!(eval_concrete("lt", &[a, b]).is_some());
    assert!(eval_concrete("gt", &[a, b]).is_some());
    assert!(eval_concrete("slt", &[a, b]).is_some());
    assert!(eval_concrete("sgt", &[a, b]).is_some());
    assert!(eval_concrete("eq", &[a, b]).is_some());
    assert!(eval_concrete("iszero", &[a]).is_some());
    assert!(eval_concrete("and", &[a, b]).is_some());
    assert!(eval_concrete("or", &[a, b]).is_some());
    assert!(eval_concrete("xor", &[a, b]).is_some());
    assert!(eval_concrete("not", &[a]).is_some());
    assert!(eval_concrete("byte", &[a, b]).is_some());
    assert!(eval_concrete("shl", &[a, b]).is_some());
    assert!(eval_concrete("shr", &[a, b]).is_some());
    assert!(eval_concrete("sar", &[a, b]).is_some());
    assert!(eval_concrete("invalid_op", &[a, b]).is_none());
}
