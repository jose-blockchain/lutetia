//! Memory location algebra.
//!
//! Provides precise memory-range arithmetic for the simplifier's memory model.
//! Memory ranges are represented as `("range", position, length)` Expr nodes.

use crate::core::algebra;
use crate::expr::Expr;
use primitive_types::U256;

// ===========================================================================
// Range overlap detection
// ===========================================================================

/// Check if two memory ranges might overlap.
/// Returns `Some(true)` if definitely overlap, `Some(false)` if definitely not,
/// `None` if indeterminate.
pub fn range_overlaps(range1: &Expr, range2: &Expr) -> Option<bool> {
    let (r1_begin, r1_len) = extract_range(range1)?;
    let (r2_begin, r2_len) = extract_range(range2)?;

    let r1_end = add_vals(&r1_begin, &r1_len)?;
    let r2_end = add_vals(&r2_begin, &r2_len)?;

    // Canonicalize so r1 starts at the earlier position.
    let (_b1, e1, b2) = if concrete_le(&r1_begin, &r2_begin).unwrap_or(true) {
        (r1_begin, r1_end, r2_begin)
    } else {
        (r2_begin, r2_end, r1_begin)
    };

    // Ranges overlap iff the earlier one's end > the later one's begin.
    match concrete_le(&e1, &b2) {
        Some(true) => Some(false),  // r1 ends before r2 starts → no overlap
        Some(false) => Some(true),  // r1 ends after r2 starts → overlap
        None => None,               // can't determine
    }
}

/// Compute surviving memory fragments after a partial overwrite.
/// Given `memloc` is the original range and `split` is the overwritten range,
/// returns the sub-ranges of `memloc` that are NOT overwritten.
pub fn memloc_overwrite(memloc: &Expr, split: &Expr) -> Vec<Expr> {
    let (m_left, m_len) = match extract_range(memloc) {
        Some(v) => v,
        None => return vec![memloc.clone()],
    };
    let (s_left, s_len) = match extract_range(split) {
        Some(v) => v,
        None => return vec![memloc.clone()],
    };

    let m_right = match add_vals(&m_left, &m_len) {
        Some(v) => v,
        None => return vec![memloc.clone()],
    };
    let s_right = match add_vals(&s_left, &s_len) {
        Some(v) => v,
        None => return vec![memloc.clone()],
    };

    // No overlap early exits.
    if concrete_le(&m_right, &s_left) == Some(true) {
        return vec![memloc.clone()];
    }
    if concrete_le(&s_right, &m_left) == Some(true) {
        return vec![memloc.clone()];
    }

    // Left fragment: [m_left, s_left) — exists only if s_left > m_left.
    let left_result = sub_vals_checked(&s_left, &m_left);
    // Right fragment: [s_right, m_right) — exists only if m_right > s_right.
    let right_result = sub_vals_checked(&m_right, &s_right);

    // If either is unknown (symbolic), we can't determine — conservative.
    if left_result.is_none() || right_result.is_none() {
        return vec![memloc.clone()];
    }

    let mut result = Vec::new();

    // Left fragment: concrete and positive.
    if let Some(Ok(ll)) = &left_result {
        if is_positive(ll) {
            result.push(Expr::node2("range", m_left.clone(), ll.clone()));
        }
    }
    // If Err, the fragment is negative → doesn't exist → skip.

    // Right fragment: concrete and positive.
    if let Some(Ok(rl)) = &right_result {
        if is_positive(rl) {
            result.push(Expr::node2("range", s_right.clone(), rl.clone()));
        }
    }
    // If Err, the fragment is negative → doesn't exist → skip.

    result
}

/// Substitute a known memory write into a memory read.
/// If `read_range` partially overlaps `write_range`, produces a composite value.
pub fn fill_mem(read_expr: &Expr, write_range: &Expr, write_val: &Expr) -> Expr {
    // Exact match shortcut.
    if let Some(rch) = read_expr.children() {
        if read_expr.opcode() == Some("mem") && rch.len() == 1 && rch[0] == *write_range {
            return write_val.clone();
        }
    }

    // For now, only handle exact matches. Partial overlap filling requires
    // the full slice_exp infrastructure which we'll add incrementally.
    read_expr.clone()
}

/// Apply a bit mask to a memory range, producing a sub-range.
/// In EVM's big-endian memory model, low offset bits correspond to rightmost bytes.
pub fn apply_mask_to_range(memloc: &Expr, size_bits: u64, offset_bits: u64) -> Option<Expr> {
    let (pos, len) = extract_range(memloc)?;
    let pos_val = pos.as_val()?;
    let len_val = len.as_val()?;

    let size_bytes = size_bits / 8;
    let offset_bytes = offset_bits / 8;

    if size_bits % 8 != 0 || offset_bits % 8 != 0 {
        return None; // Not byte-aligned.
    }

    let total = size_bytes + offset_bytes;
    if U256::from(total) > len_val {
        return None; // Mask doesn't fit in range.
    }

    // Big-endian: low offset = rightmost bytes.
    let new_pos = pos_val + (len_val - U256::from(total));
    Some(Expr::node2(
        "range",
        Expr::Val(new_pos),
        Expr::val(size_bytes),
    ))
}

/// Decompose an `or(mask_shl(...), ...)` value into (size_bits, offset_bits, value) triples.
pub fn split_or(value: &Expr) -> Vec<(u64, u64, Expr)> {
    match value.opcode() {
        Some("or") => {
            if let Some(ch) = value.children() {
                let mut result = Vec::new();
                for term in ch {
                    if let Some(components) = extract_mask_shl(term) {
                        result.push(components);
                    } else if let Some(v) = term.as_val() {
                        // Concrete value — find its bit range.
                        if v.is_zero() {
                            continue;
                        }
                        let (size, offset) = find_bit_range(v);
                        result.push((size, offset, term.clone()));
                    } else if term.opcode() == Some("mem") {
                        // Memory read — assume 256 bits at offset 0.
                        result.push((256, 0, term.clone()));
                    } else if term.opcode() == Some("storage") {
                        if let Some(sch) = term.children() {
                            let size = sch.first().and_then(|e| e.as_u64()).unwrap_or(256);
                            result.push((size, 0, term.clone()));
                        }
                    } else {
                        result.push((256, 0, term.clone()));
                    }
                }
                // Sort by offset.
                result.sort_by_key(|(_, off, _)| *off);
                return result;
            }
        }
        Some("mask_shl") => {
            if let Some(c) = extract_mask_shl(value) {
                return vec![c];
            }
        }
        _ => {}
    }

    vec![(256, 0, value.clone())]
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Extract (position, length) from a range expression.
fn extract_range(expr: &Expr) -> Option<(Expr, Expr)> {
    if expr.opcode() == Some("range") {
        if let Some(ch) = expr.children() {
            if ch.len() == 2 {
                return Some((ch[0].clone(), ch[1].clone()));
            }
        }
    }
    None
}

/// Extract (size, offset, value) from a mask_shl expression.
fn extract_mask_shl(expr: &Expr) -> Option<(u64, u64, Expr)> {
    if expr.opcode() == Some("mask_shl") {
        if let Some(ch) = expr.children() {
            if ch.len() == 4 {
                let size = ch[0].as_u64()?;
                let offset = ch[1].as_u64().unwrap_or(0);
                let shl = ch[2].as_u64().unwrap_or(0);
                let stor_offset = offset + shl;
                return Some((size, stor_offset, ch[3].clone()));
            }
        }
    }
    None
}

/// Add two Expr values if both are concrete.
fn add_vals(a: &Expr, b: &Expr) -> Option<Expr> {
    match (a.as_val(), b.as_val()) {
        (Some(va), Some(vb)) => Some(Expr::Val(va.overflowing_add(vb).0)),
        _ => Some(algebra::add_op(a.clone(), b.clone())),
    }
}

/// Subtract two Expr values.
/// Returns `Some(Ok(result))` if concrete and non-negative,
/// `Some(Err(()))` if concrete but negative,
/// `None` if symbolic/unknown.
fn sub_vals_checked(a: &Expr, b: &Expr) -> Option<Result<Expr, ()>> {
    match (a.as_val(), b.as_val()) {
        (Some(va), Some(vb)) => {
            if va >= vb {
                Some(Ok(Expr::Val(va - vb)))
            } else {
                Some(Err(())) // Concrete negative — fragment doesn't exist.
            }
        }
        _ => None,
    }
}

/// Check if a <= b for concrete values.
fn concrete_le(a: &Expr, b: &Expr) -> Option<bool> {
    match (a.as_val(), b.as_val()) {
        (Some(va), Some(vb)) => Some(va <= vb),
        _ => None,
    }
}

/// Check if a value is provably positive (> 0).
fn is_positive(expr: &Expr) -> bool {
    match expr.as_val() {
        Some(v) => !v.is_zero(),
        None => false,
    }
}

/// Find the bit range occupied by a concrete value: (size, offset).
fn find_bit_range(val: U256) -> (u64, u64) {
    if val.is_zero() {
        return (0, 0);
    }
    let mut low = 0u64;
    let mut high = 0u64;
    for i in 0..256 {
        if val.bit(i) {
            if low == 0 && i > 0 {
                low = i as u64;
            } else if i == 0 {
                low = 0;
            }
            high = i as u64 + 1;
        }
    }
    (high - low, low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_overlaps_no_overlap() {
        let r1 = Expr::node2("range", Expr::val(0), Expr::val(32));
        let r2 = Expr::node2("range", Expr::val(64), Expr::val(32));
        assert_eq!(range_overlaps(&r1, &r2), Some(false));
    }

    #[test]
    fn test_range_overlaps_overlap() {
        let r1 = Expr::node2("range", Expr::val(0), Expr::val(32));
        let r2 = Expr::node2("range", Expr::val(16), Expr::val(32));
        assert_eq!(range_overlaps(&r1, &r2), Some(true));
    }

    #[test]
    fn test_range_overlaps_adjacent() {
        let r1 = Expr::node2("range", Expr::val(0), Expr::val(32));
        let r2 = Expr::node2("range", Expr::val(32), Expr::val(32));
        assert_eq!(range_overlaps(&r1, &r2), Some(false));
    }

    #[test]
    fn test_memloc_overwrite_partial() {
        let mem = Expr::node2("range", Expr::val(64), Expr::val(32));
        let split = Expr::node2("range", Expr::val(70), Expr::val(10));
        let result = memloc_overwrite(&mem, &split);
        assert_eq!(result.len(), 2);
        // Left fragment: [64, 70) = range(64, 6)
        // Right fragment: [80, 96) = range(80, 16)
    }

    #[test]
    fn test_memloc_overwrite_complete() {
        let mem = Expr::node2("range", Expr::val(64), Expr::val(32));
        let split = Expr::node2("range", Expr::val(60), Expr::val(40));
        let result = memloc_overwrite(&mem, &split);
        assert!(result.is_empty());
    }

    #[test]
    fn test_memloc_overwrite_no_overlap() {
        let mem = Expr::node2("range", Expr::val(64), Expr::val(32));
        let split = Expr::node2("range", Expr::val(100), Expr::val(10));
        let result = memloc_overwrite(&mem, &split);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_apply_mask_to_range() {
        // 160-bit mask at offset 0 on a 32-byte range starting at 212.
        let range = Expr::node2("range", Expr::val(212), Expr::val(32));
        let result = apply_mask_to_range(&range, 160, 0).unwrap();
        // Low 160 bits = rightmost 20 bytes → position 212 + (32-20) = 224
        assert_eq!(result, Expr::node2("range", Expr::val(224), Expr::val(20)));
    }

    #[test]
    fn test_apply_mask_to_range_full() {
        let range = Expr::node2("range", Expr::val(0), Expr::val(32));
        let result = apply_mask_to_range(&range, 256, 0).unwrap();
        assert_eq!(result, Expr::node2("range", Expr::val(0), Expr::val(32)));
    }

    #[test]
    fn test_split_or_single_mask() {
        let expr = Expr::Node("mask_shl".into(), vec![
            Expr::val(160), Expr::val(0), Expr::val(0), Expr::atom("caller"),
        ]);
        let result = split_or(&expr);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 160); // size
        assert_eq!(result[0].1, 0);   // offset
    }

    #[test]
    fn test_split_or_multiple() {
        let expr = Expr::node("or", vec![
            Expr::Node("mask_shl".into(), vec![
                Expr::val(160), Expr::val(0), Expr::val(0), Expr::atom("caller"),
            ]),
            Expr::Node("mask_shl".into(), vec![
                Expr::val(8), Expr::val(0), Expr::val(160), Expr::atom("flag"),
            ]),
        ]);
        let result = split_or(&expr);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_fill_mem_exact() {
        let range = Expr::node2("range", Expr::val(64), Expr::val(32));
        let read = Expr::node1("mem", range.clone());
        let val = Expr::val(42);
        assert_eq!(fill_mem(&read, &range, &val), Expr::val(42));
    }
}
