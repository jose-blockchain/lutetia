//! General helper utilities.

use crate::expr::Expr;
use std::collections::HashMap;

/// ANSI colour codes (mirrors the Python colour constants).
pub mod colors {
    pub const HEADER: &str = "\x1b[95m";
    pub const BLUE: &str = "\x1b[94m";
    pub const OKGREEN: &str = "\x1b[92m";
    pub const WARNING: &str = "\x1b[93m";
    pub const FAIL: &str = "\x1b[91m";
    pub const ENDC: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const GREEN: &str = "\x1b[32m";
    pub const GRAY: &str = "\x1b[38;5;8m";

    /// Wrap `text` in ANSI colour escape codes (no-op when `add_color` is false).
    pub fn colorize(text: &str, color: &str, add_color: bool) -> String {
        if add_color && !text.is_empty() {
            format!("{color}{text}{ENDC}")
        } else {
            text.to_string()
        }
    }
}

/// Precompiled contract addresses (1-8).
pub fn precompiled_contracts() -> HashMap<u64, &'static str> {
    HashMap::from([
        (1, "ecrecover"),
        (2, "sha256hash"),
        (3, "ripemd160hash"),
        // 4 = identity (handled separately)
        (5, "bigModExp"),
        (6, "bn256Add"),
        (7, "bn256ScalarMul"),
        (8, "bn256Pairing"),
    ])
}

/// Variable names for precompiled results.
pub fn precompiled_var_names() -> HashMap<u64, &'static str> {
    HashMap::from([
        (1, "signer"),
        (2, "hash"),
        (3, "hash"),
        (5, "mod_exp"),
        (6, "bn_add"),
        (7, "bn_scalar_mul"),
        (8, "bn_pairing"),
    ])
}

/// Pad a hex value to `len` hex characters.
pub fn padded_hex(value: primitive_types::U256, len: usize) -> String {
    let hex = format!("{value:x}");
    if hex.len() > len {
        "?".repeat(len)
    } else {
        format!("0x{hex:0>len$}")
    }
}

/// Convert a big integer to a printable string if it looks like ASCII.
pub fn pretty_bignum(num: primitive_types::U256) -> Option<String> {
    if num.is_zero() {
        return None;
    }
    let mut s = String::new();
    let mut n = num;
    while !n.is_zero() {
        let byte = (n.low_u64() & 0xFF) as u8;
        if byte == 0 {
            n >>= 8;
            continue;
        }
        if byte.is_ascii_graphic() || byte == b' ' {
            s.insert(0, byte as char);
        } else {
            return None;
        }
        n >>= 8;
    }
    if s.is_empty() {
        None
    } else {
        Some(format!("'{s}'"))
    }
}

/// Check if `num` is a power of 2 and return the exponent.
pub fn to_exp2(num: primitive_types::U256) -> Option<u16> {
    if num.is_zero() || num == primitive_types::U256::one() {
        if num == primitive_types::U256::one() {
            return Some(0);
        }
        return None;
    }
    // Check single-bit
    let mut n = num;
    let mut count = 0u16;
    while !n.is_zero() {
        if n.low_u64() & 1 == 1 {
            if n == primitive_types::U256::one() {
                return Some(count);
            }
            return None;
        }
        n >>= 1;
        count += 1;
    }
    None
}

/// Recursively apply function `f` to every sub-expression.
pub fn replace_f(expr: &Expr, f: &dyn Fn(&Expr) -> Expr) -> Expr {
    let transformed = match expr {
        Expr::Node(op, children) => {
            let new_children: Vec<Expr> = children.iter().map(|c| replace_f(c, f)).collect();
            Expr::Node(op.clone(), new_children)
        }
        other => other.clone(),
    };
    f(&transformed)
}

/// Find all sub-expressions where `f` returns a non-empty list.
pub fn find_f_list(expr: &Expr, f: &dyn Fn(&Expr) -> Vec<Expr>) -> Vec<Expr> {
    let mut result = f(expr);
    if let Expr::Node(_, children) = expr {
        for child in children {
            result.extend(find_f_list(child, f));
        }
    }
    result
}

/// Rewrite every line of a trace using function `f`.
/// `f` returns a Vec<Expr> (0 = remove, 1 = keep/replace, >1 = expand).
/// Recurses into if/while sub-traces.
pub fn rewrite_trace(trace: &[Expr], f: &dyn Fn(&Expr) -> Vec<Expr>) -> Vec<Expr> {
    let mut result = Vec::new();
    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = ch
                        .get(1)
                        .and_then(|e| e.children())
                        .map(|c| rewrite_trace(c, f))
                        .unwrap_or_default();
                    let if_false = ch
                        .get(2)
                        .and_then(|e| e.children())
                        .map(|c| rewrite_trace(c, f))
                        .unwrap_or_default();
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", if_true),
                        Expr::node("seq", if_false),
                    ));
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = ch
                        .get(1)
                        .and_then(|e| e.children())
                        .map(|c| rewrite_trace(c, f))
                        .unwrap_or_default();
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => {
                result.extend(f(line));
            }
        }
    }
    result
}

/// Check if a trace contains a specific expression anywhere.
pub fn trace_contains(trace: &[Expr], target: &Expr) -> bool {
    trace.iter().any(|line| line.contains(target))
}

/// Check if a trace contains an opcode anywhere.
pub fn trace_contains_op(trace: &[Expr], op: &str) -> bool {
    trace.iter().any(|line| line.contains_op(op))
}

/// Replace all occurrences of `from` with `to` in every expression of a trace.
pub fn replace_in_trace(trace: &[Expr], from: &Expr, to: &Expr) -> Vec<Expr> {
    trace.iter().map(|e| e.replace(from, to)).collect()
}

/// Check if a string is an array-like opcode.
pub fn is_array(op: &str) -> bool {
    matches!(
        op,
        "call.data"
            | "ext_call.return_data"
            | "delegate.return_data"
            | "callcode.return_data"
            | "staticcall.return_data"
            | "code.data"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_hex() {
        assert_eq!(padded_hex(primitive_types::U256::from(0xABu64), 8), "0x000000ab");
    }

    #[test]
    fn test_to_exp2() {
        assert_eq!(to_exp2(primitive_types::U256::from(1u64)), Some(0));
        assert_eq!(to_exp2(primitive_types::U256::from(2u64)), Some(1));
        assert_eq!(to_exp2(primitive_types::U256::from(256u64)), Some(8));
        assert_eq!(to_exp2(primitive_types::U256::from(3u64)), None);
        assert_eq!(to_exp2(primitive_types::U256::zero()), None);
    }

    #[test]
    fn test_pretty_bignum() {
        assert_eq!(pretty_bignum(primitive_types::U256::from(0x414243u64)), Some("'ABC'".to_string()));
        assert_eq!(pretty_bignum(primitive_types::U256::zero()), None);
    }

    #[test]
    fn test_is_array() {
        assert!(is_array("call.data"));
        assert!(!is_array("add"));
    }
}
