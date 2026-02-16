//! Bitmask operations: type ↔ mask conversions and bit extraction.

use primitive_types::U256;
use std::collections::HashMap;

/// Convert a Solidity type name to its mask size in bits.
pub fn type_to_mask(s: &str) -> Option<u16> {
    let lookup: HashMap<&str, u16> = HashMap::from([
        ("bool", 1),
        ("uint8", 8),
        ("uint16", 16),
        ("uint32", 32),
        ("uint64", 64),
        ("int8", 8),
        ("bytes1", 8),
        ("int16", 16),
        ("bytes2", 16),
        ("int32", 32),
        ("bytes4", 32),
        ("int64", 64),
        ("bytes8", 64),
        ("int128", 128),
        ("uint128", 128),
        ("bytes16", 128),
        ("address", 160),
        ("uint256", 256),
        ("bytes32", 256),
        ("int256", 256),
        ("int", 256),
        ("uint", 256),
    ]);
    lookup.get(s).copied()
}

/// Convert a mask size in bits to a Solidity type name.
pub fn mask_to_type(num: u16, force: bool) -> Option<&'static str> {
    let lookup: &[(u16, &str)] = &[
        (1, "bool"),
        (8, "uint8"),
        (16, "uint16"),
        (32, "uint32"),
        (64, "uint64"),
        (128, "uint128"),
        (160, "address"),
        (256, "uint256"),
    ];

    for &(bits, name) in lookup {
        if bits == num {
            return Some(name);
        }
    }

    if force {
        // Return the smallest type that fits.
        for &(bits, name) in lookup {
            if bits > num {
                return Some(name);
            }
        }
    }

    None
}

/// Extract bit at position `pos` from `num`.
pub fn get_bit(num: U256, pos: u16) -> u8 {
    if num.bit(pos as usize) { 1 } else { 0 }
}

/// Compute `(2^size - 1) * 2^offset` — the integer mask.
pub fn mask_to_int(size: u16, offset: u16) -> U256 {
    if size == 0 {
        return U256::zero();
    }
    if size >= 256 {
        if offset == 0 {
            return U256::MAX;
        }
        // (2^256 - 1) << offset — but since we only have 256 bits, saturate.
        return U256::MAX << offset as usize;
    }
    let mask = (U256::one() << size as usize) - U256::one();
    mask << offset as usize
}

/// Find a mask that encompasses `num`: returns (size, offset) in bits,
/// both rounded to byte boundaries.
pub fn find_mask(num: U256) -> (u16, u16) {
    let mut i: u16 = 0;
    while get_bit(num, i) == 0 && i < 256 {
        i += 1;
    }
    let mask_pos = i - i % 8;

    let mut mask_pos_plus_len: u16 = 256;
    while i < 256 {
        if get_bit(num, i) != 0 {
            mask_pos_plus_len = i - i % 8 + 8;
        }
        i += 1;
    }

    (mask_pos_plus_len - mask_pos, mask_pos)
}

/// Try to decompose `num` into a contiguous bitmask: returns `(size, offset)`
/// such that `num == mask_to_int(size, offset)`, or `None` if `num` is not a
/// contiguous mask.
pub fn to_mask(num: U256) -> Option<(u16, u16)> {
    if num.is_zero() {
        return Some((0, 0));
    }

    let mut i: u16 = 0;
    while get_bit(num, i) == 0 && i < 256 {
        i += 1;
    }
    let mask_pos = i;

    while get_bit(num, i) == 1 && i < 256 {
        i += 1;
    }
    let mask_pos_plus_len = i;

    while i < 256 {
        if get_bit(num, i) != 0 {
            return None;
        }
        i += 1;
    }

    Some((mask_pos_plus_len - mask_pos, mask_pos))
}

/// Decompose `num` as a negative mask (complement of a contiguous range).
pub fn to_neg_mask(num: U256) -> Option<(u16, u16)> {
    let mut i: u16 = 0;
    while get_bit(num, i) == 1 && i < 256 {
        i += 1;
    }
    let mask_pos = i;

    while get_bit(num, i) == 0 && i < 256 {
        i += 1;
    }
    let mask_pos_plus_len = i;

    while i < 256 {
        if get_bit(num, i) != 1 {
            return None;
        }
        i += 1;
    }

    Some((mask_pos_plus_len - mask_pos, mask_pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_to_mask() {
        assert_eq!(type_to_mask("address"), Some(160));
        assert_eq!(type_to_mask("bool"), Some(1));
        assert_eq!(type_to_mask("unknown"), None);
    }

    #[test]
    fn test_mask_to_type() {
        assert_eq!(mask_to_type(160, false), Some("address"));
        assert_eq!(mask_to_type(1, false), Some("bool"));
        assert_eq!(mask_to_type(5, false), None);
        assert_eq!(mask_to_type(5, true), Some("uint8")); // smallest fitting
    }

    #[test]
    fn test_get_bit() {
        assert_eq!(get_bit(U256::from(0b1010u64), 0), 0);
        assert_eq!(get_bit(U256::from(0b1010u64), 1), 1);
        assert_eq!(get_bit(U256::from(0b1010u64), 3), 1);
    }

    #[test]
    fn test_mask_to_int() {
        // mask_to_int(8, 0) = 0xFF
        assert_eq!(mask_to_int(8, 0), U256::from(0xFFu64));
        // mask_to_int(8, 8) = 0xFF00
        assert_eq!(mask_to_int(8, 8), U256::from(0xFF00u64));
        // mask_to_int(160, 0) = 2^160 - 1
        let addr_mask = (U256::one() << 160) - U256::one();
        assert_eq!(mask_to_int(160, 0), addr_mask);
    }

    #[test]
    fn test_find_mask() {
        assert_eq!(find_mask(U256::from(0xFABBA10000u64)), (24, 16));
        assert_eq!(find_mask(U256::from(0x7ABBA20000u64)), (24, 16));
    }

    #[test]
    fn test_to_mask() {
        // 0xFF = 8-bit mask at offset 0
        assert_eq!(to_mask(U256::from(0xFFu64)), Some((8, 0)));
        // 0xFF00 = 8-bit mask at offset 8
        assert_eq!(to_mask(U256::from(0xFF00u64)), Some((8, 8)));
        // non-contiguous
        assert_eq!(to_mask(U256::from(0b1010u64)), None);
    }

    #[test]
    fn test_to_neg_mask() {
        // ~0xFF00 should be neg mask (8, 8) if it were a full 256-bit number.
        let val = !U256::from(0xFF00u64);
        assert_eq!(to_neg_mask(val), Some((8, 8)));
    }
}
