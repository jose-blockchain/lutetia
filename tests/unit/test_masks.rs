//! Extended mask tests.

use lutetia::core::masks::*;
use primitive_types::U256;

#[test]
fn test_type_to_mask_all_types() {
    assert_eq!(type_to_mask("bool"), Some(1));
    assert_eq!(type_to_mask("uint8"), Some(8));
    assert_eq!(type_to_mask("address"), Some(160));
    assert_eq!(type_to_mask("uint256"), Some(256));
    assert_eq!(type_to_mask("bytes32"), Some(256));
    assert_eq!(type_to_mask("int256"), Some(256));
    assert_eq!(type_to_mask("unknown_type"), None);
}

#[test]
fn test_mask_to_type_exact() {
    assert_eq!(mask_to_type(1, false), Some("bool"));
    assert_eq!(mask_to_type(8, false), Some("uint8"));
    assert_eq!(mask_to_type(160, false), Some("address"));
    assert_eq!(mask_to_type(256, false), Some("uint256"));
}

#[test]
fn test_mask_to_type_force() {
    assert_eq!(mask_to_type(3, true), Some("uint8"));    // 3 < 8
    assert_eq!(mask_to_type(150, true), Some("address")); // 150 < 160
}

#[test]
fn test_mask_to_int_zero() {
    assert_eq!(mask_to_int(0, 0), U256::zero());
}

#[test]
fn test_mask_to_int_full_256() {
    assert_eq!(mask_to_int(256, 0), U256::MAX);
}

#[test]
fn test_mask_to_int_byte() {
    assert_eq!(mask_to_int(8, 0), U256::from(0xFFu64));
    assert_eq!(mask_to_int(8, 8), U256::from(0xFF00u64));
    assert_eq!(mask_to_int(8, 16), U256::from(0xFF0000u64));
}

#[test]
fn test_to_mask_contiguous() {
    // 0xFF = 8 bits at offset 0
    assert_eq!(to_mask(U256::from(0xFFu64)), Some((8, 0)));
    // 0xFF00 = 8 bits at offset 8
    assert_eq!(to_mask(U256::from(0xFF00u64)), Some((8, 8)));
    // 0xFFFF = 16 bits at offset 0
    assert_eq!(to_mask(U256::from(0xFFFFu64)), Some((16, 0)));
}

#[test]
fn test_to_mask_non_contiguous() {
    assert_eq!(to_mask(U256::from(0b1010u64)), None);
    assert_eq!(to_mask(U256::from(0b10001u64)), None);
}

#[test]
fn test_to_mask_zero() {
    assert_eq!(to_mask(U256::zero()), Some((0, 0)));
}

#[test]
fn test_to_neg_mask() {
    // ~0xFF = everything except bits 0..7
    let neg_mask = !U256::from(0xFFu64);
    assert_eq!(to_neg_mask(neg_mask), Some((8, 0)));
}

#[test]
fn test_get_bit() {
    let val = U256::from(0b10100u64);
    assert_eq!(get_bit(val, 0), 0);
    assert_eq!(get_bit(val, 1), 0);
    assert_eq!(get_bit(val, 2), 1);
    assert_eq!(get_bit(val, 3), 0);
    assert_eq!(get_bit(val, 4), 1);
}

#[test]
fn test_find_mask_small() {
    let val = U256::from(0xFF00u64);
    let (size, offset) = find_mask(val);
    // Byte boundaries: bits 8..15 set → offset=8, size=8
    assert_eq!(offset, 8);
    assert_eq!(size, 8);
}

#[test]
fn test_address_mask() {
    let addr_mask = (U256::one() << 160) - U256::one();
    assert_eq!(to_mask(addr_mask), Some((160, 0)));
}
