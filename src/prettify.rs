//! Human-readable output formatting.
//!
//! Converts symbolic expressions and traces into Solidity-like pseudo-code.
//! Covers: require() detection, string literal recovery, call/log formatting,
//! Solidity panic codes, data() rendering, and precompiled contract names.

use crate::core::masks::mask_to_type;
use crate::expr::Expr;
use crate::utils::helpers::{colors::*, is_array, padded_hex, precompiled_contracts, pretty_bignum};
use crate::utils::signatures::get_event_name;
use primitive_types::U256;

// ---------------------------------------------------------------------------
// Solidity panic codes
// ---------------------------------------------------------------------------

/// Map a Solidity 0.8+ panic code to a human-readable description.
pub fn panic_code_description(code: u64) -> Option<&'static str> {
    match code {
        0x00 => Some("Used for generic compiler inserted panics."),
        0x01 => Some("assert with false argument."),
        0x11 => Some("Arithmetic overflow/underflow."),
        0x12 => Some("Division or modulo by zero."),
        0x21 => Some("Enum conversion out of range."),
        0x22 => Some("Incorrectly encoded storage byte array."),
        0x31 => Some(".pop() on an empty array."),
        0x32 => Some("Out-of-bounds array access."),
        0x41 => Some("Too much memory allocated."),
        0x51 => Some("Zero-initialized internal function pointer."),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Pretty-print a single expression to a one-line string.
pub fn prettify(expr: &Expr, add_color: bool) -> String {
    match expr {
        Expr::Val(v) => pretty_num(*v),
        Expr::Atom(s) => pretty_atom(s, add_color),
        Expr::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Expr::Node(op, children) => pretty_node(op, children, add_color),
    }
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// Format a U256 as a readable number or hex constant.
fn pretty_num(v: U256) -> String {
    if v.is_zero() {
        return "0".to_string();
    }
    // U256::MAX = -1 in two's complement.
    if v == U256::MAX {
        return "-1".to_string();
    }
    // Values close to U256::MAX are small negative numbers.
    let neg = U256::MAX - v + 1;
    if neg <= U256::from(256u64) && neg > U256::zero() {
        return format!("-{neg}");
    }
    // Try to decode as ASCII string (e.g. error selectors like 'NH{q').
    if v > U256::from(0xFFFFu64) {
        if let Some(s) = pretty_bignum(v) {
            return s;
        }
    }
    // Time constants (checked before decimal to catch small multiples of 3600).
    let low = v.low_u64();
    if v == U256::from(low) {
        if low % 86400 == 0 && low > 86400 {
            return format!("{} * 24 * 3600", low / 86400);
        }
        if low % 3600 == 0 && low > 3600 {
            return format!("{} * 3600", low / 3600);
        }
    }
    // Small numbers: decimal.
    if v <= U256::from(9999u64) {
        return format!("{v}");
    }
    // Large numbers: hex.
    if v > U256::from(10u64).pow(U256::from(15u64)) {
        format!("0x{v:x}")
    } else {
        format!("{v}")
    }
}

// ---------------------------------------------------------------------------
// Atoms
// ---------------------------------------------------------------------------

/// Prettify an atom (named constant / environment variable).
fn pretty_atom(s: &str, add_color: bool) -> String {
    match s {
        "caller" => "caller".to_string(),
        "callvalue" => "call.value".to_string(),
        "address" => "this.address".to_string(),
        "origin" => "tx.origin".to_string(),
        "timestamp" => "block.timestamp".to_string(),
        "number" => "block.number".to_string(),
        "difficulty" => "block.difficulty".to_string(),
        "gaslimit" => "block.gas_limit".to_string(),
        "coinbase" => "block.coinbase".to_string(),
        "gasprice" => "block.gasprice".to_string(),
        "basefee" => "block.basefee".to_string(),
        "blobbasefee" => "block.blobbasefee".to_string(),
        "chainid" => "chainid".to_string(),
        "gas" => "gas_remaining".to_string(),
        "calldatasize" => "calldata.size".to_string(),
        "returndatasize" => "return_data.size".to_string(),
        "msize" => "msize".to_string(),
        "ext_call.success" => "ext_call.success".to_string(),
        "create.new_address" => "create.new_address".to_string(),
        "create2.new_address" => "create2.new_address".to_string(),
        other => {
            if add_color {
                colorize(other, GREEN, true)
            } else {
                other.to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Node formatting
// ---------------------------------------------------------------------------

/// Prettify a node expression (operator + children).
fn pretty_node(op: &str, children: &[Expr], add_color: bool) -> String {
    let pret = |e: &Expr| prettify(e, add_color);

    match op {
        // -- Arithmetic --
        "add" => {
            // Detect add(X, mul(-1, Y)) → (X - Y) pattern.
            if children.len() == 2 {
                let neg_child = |c: &Expr| -> Option<String> {
                    if c.opcode() == Some("mul") {
                        if let Some(ch) = c.children() {
                            if ch.len() == 2 {
                                if ch[0].as_val() == Some(U256::MAX) {
                                    return Some(pret(&ch[1]));
                                }
                                if ch[1].as_val() == Some(U256::MAX) {
                                    return Some(pret(&ch[0]));
                                }
                            }
                        }
                    }
                    None
                };
                if let Some(neg_str) = neg_child(&children[1]) {
                    return format!("({} - {})", pret(&children[0]), neg_str);
                }
                if let Some(neg_str) = neg_child(&children[0]) {
                    return format!("({} - {})", pret(&children[1]), neg_str);
                }
            }
            let terms: Vec<String> = children.iter().map(&pret).collect();
            format!("({})", terms.join(" + "))
        }
        "sub" if children.len() == 2 => {
            format!("({} - {})", pret(&children[0]), pret(&children[1]))
        }
        "mul" if children.len() == 2 => {
            // mul(-1, X) → -X  (negation pattern from U256 two's complement)
            if children[0].as_val() == Some(U256::MAX) {
                return format!("(-{})", pret(&children[1]));
            }
            if children[1].as_val() == Some(U256::MAX) {
                return format!("(-{})", pret(&children[0]));
            }
            format!("({} * {})", pret(&children[0]), pret(&children[1]))
        }
        "div" if children.len() == 2 => {
            format!("({} / {})", pret(&children[0]), pret(&children[1]))
        }
        "sdiv" if children.len() == 2 => {
            format!("({} /s {})", pret(&children[0]), pret(&children[1]))
        }
        "mod" if children.len() == 2 => {
            format!("({} % {})", pret(&children[0]), pret(&children[1]))
        }
        "smod" if children.len() == 2 => {
            format!("({} %s {})", pret(&children[0]), pret(&children[1]))
        }
        "exp" if children.len() == 2 => {
            format!("{}^{}", pret(&children[0]), pret(&children[1]))
        }
        "addmod" if children.len() == 3 => {
            format!("addmod({}, {}, {})", pret(&children[0]), pret(&children[1]), pret(&children[2]))
        }
        "mulmod" if children.len() == 3 => {
            format!("mulmod({}, {}, {})", pret(&children[0]), pret(&children[1]), pret(&children[2]))
        }

        // -- Comparisons --
        "eq" if children.len() == 2 => {
            format!("{} == {}", pret(&children[0]), pret(&children[1]))
        }
        "lt" if children.len() == 2 => {
            format!("{} < {}", pret(&children[0]), pret(&children[1]))
        }
        "gt" if children.len() == 2 => {
            format!("{} > {}", pret(&children[0]), pret(&children[1]))
        }
        "slt" if children.len() == 2 => {
            format!("{} <s {}", pret(&children[0]), pret(&children[1]))
        }
        "sgt" if children.len() == 2 => {
            format!("{} >s {}", pret(&children[0]), pret(&children[1]))
        }
        "le" if children.len() == 2 => {
            format!("{} <= {}", pret(&children[0]), pret(&children[1]))
        }
        "ge" if children.len() == 2 => {
            format!("{} >= {}", pret(&children[0]), pret(&children[1]))
        }
        "sle" if children.len() == 2 => {
            format!("{} <=s {}", pret(&children[0]), pret(&children[1]))
        }
        "sge" if children.len() == 2 => {
            format!("{} >=s {}", pret(&children[0]), pret(&children[1]))
        }

        // -- Bit shifts --
        "shl" if children.len() == 2 => {
            format!("{} << {}", pret(&children[1]), pret(&children[0]))
        }
        "shr" if children.len() == 2 => {
            format!("{} >> {}", pret(&children[1]), pret(&children[0]))
        }
        "sar" if children.len() == 2 => {
            format!("{} >>s {}", pret(&children[1]), pret(&children[0]))
        }

        // -- Logic --
        "and" => {
            let terms: Vec<String> = children.iter().map(&pret).collect();
            format!("({})", terms.join(" and "))
        }
        "or" => {
            let terms: Vec<String> = children.iter().map(&pret).collect();
            format!("({})", terms.join(" or "))
        }
        "xor" if children.len() == 2 => {
            format!("({} xor {})", pret(&children[0]), pret(&children[1]))
        }
        "not" if children.len() == 1 => {
            format!("!{}", pret(&children[0]))
        }
        "iszero" if children.len() == 1 => {
            format!("not {}", pret(&children[0]))
        }
        "bool" if children.len() == 1 => {
            format!("bool({})", pret(&children[0]))
        }
        "byte" if children.len() == 2 => {
            format!("byte({}, {})", pret(&children[0]), pret(&children[1]))
        }
        "signextend" if children.len() == 2 => {
            format!("signextend({}, {})", pret(&children[0]), pret(&children[1]))
        }

        // -- Storage (raw, before sparser) --
        "storage" if children.len() >= 3 => {
            format!("stor[{}]", pret(&children[2]))
        }
        "tstorage" if children.len() >= 3 => {
            format!("tstor[{}]", pret(&children[2]))
        }
        "store" if children.len() == 4 => {
            format!("stor[{}] = {}", pret(&children[2]), pret(&children[3]))
        }
        "tstore" if children.len() == 4 => {
            format!("tstor[{}] = {}", pret(&children[2]), pret(&children[3]))
        }

        // -- Storage (resolved, after sparser) --
        "stor" if children.len() == 3 => {
            pretty_stor_read(&children[2], add_color)
        }
        "stor" if children.len() == 4 => {
            let lhs = pretty_stor_read(&children[2], add_color);
            let rhs = pret(&children[3]);
            let lhs_expr = &children[2];
            // Detect += and -= patterns: stor(_, _, X, add(read(X), val)) etc.
            if let Some(ch) = children[3].children() {
                if children[3].opcode() == Some("add") && ch.len() == 2 {
                    // Check which operand is the storage read.
                    let (read_idx, val_idx) = if is_same_stor_key(&ch[0], lhs_expr) {
                        (Some(0), Some(1))
                    } else if is_same_stor_key(&ch[1], lhs_expr) {
                        (Some(1), Some(0))
                    } else {
                        (None, None)
                    };
                    if let (Some(_), Some(vi)) = (read_idx, val_idx) {
                        let val = &ch[vi];
                        // add(read, mul(-1, Y)) → read -= Y
                        if val.opcode() == Some("mul") {
                            if let Some(mc) = val.children() {
                                if mc.len() == 2 && mc[0].as_val() == Some(U256::MAX) {
                                    return format!("{lhs} -= {}", pret(&mc[1]));
                                }
                            }
                        }
                        return format!("{lhs} += {}", pret(val));
                    }
                }
                if children[3].opcode() == Some("sub") && ch.len() == 2 {
                    if is_same_stor_key(&ch[0], lhs_expr) {
                        return format!("{lhs} -= {}", pret(&ch[1]));
                    }
                }
            }
            format!("{lhs} = {rhs}")
        }
        "loc" if children.len() == 1 => {
            format!("stor{}", pret(&children[0]))
        }
        "string_stor" if children.len() == 1 => {
            let name = pret(&children[0]);
            format!("{name}[0 len {name}.length]")
        }
        "map_read" if children.len() == 2 => {
            format!("{}[{}]", pret(&children[0]), pret(&children[1]))
        }
        "map_read2" if children.len() == 3 => {
            format!("{}[{}][{}]", pret(&children[0]), pret(&children[1]), pret(&children[2]))
        }
        "name" if children.len() == 2 => {
            pret(&children[0])
        }
        "map" if children.len() == 2 => {
            format!("{}[{}]", pretty_stor_read(&children[1], add_color), pret(&children[0]))
        }
        "array" if children.len() == 2 => {
            format!("{}[{}]", pretty_stor_read(&children[1], add_color), pret(&children[0]))
        }
        "length" if children.len() == 1 => {
            format!("{}.length", pretty_stor_read(&children[0], add_color))
        }

        // -- Memory --
        "mem" if children.len() == 1 => {
            format!("mem[{}]", pret(&children[0]))
        }
        "setmem" if children.len() == 2 => {
            format!("mem[{}] = {}", pret(&children[0]), pret(&children[1]))
        }
        "range" if children.len() == 2 => {
            format!("{} len {}", pret(&children[0]), pret(&children[1]))
        }

        // -- Variables --
        "var" if children.len() == 1 => {
            if add_color {
                colorize(&pret(&children[0]), BLUE, true)
            } else {
                pret(&children[0])
            }
        }
        "setvar" if children.len() == 2 => {
            format!("{} = {}", pret(&children[0]), pret(&children[1]))
        }

        // -- Calldata --
        "cd" if children.len() == 1 => {
            if children[0].is_zero() {
                "call.func_hash".to_string()
            } else {
                format!("cd[{}]", pret(&children[0]))
            }
        }

        // -- SHA3 / Keccak --
        "sha3" => {
            let args: Vec<String> = children.iter().map(&pret).collect();
            format!("sha3({})", args.join(", "))
        }

        // -- Balance --
        "balance" if children.len() == 1 => {
            format!("eth.balance({})", pret(&children[0]))
        }

        // -- External calls (detailed formatting) --
        "call" if children.len() >= 5 => {
            pretty_external_call("call", children, add_color)
        }
        "staticcall" if children.len() >= 5 => {
            pretty_external_call("staticcall", children, add_color)
        }
        "delegatecall" if children.len() >= 5 => {
            pretty_external_call("delegatecall", children, add_color)
        }
        "callcode" if children.len() >= 5 => {
            pretty_external_call("callcode", children, add_color)
        }

        // -- Call data arrays --
        "call.data" | "ext_call.return_data" | "code.data" if children.len() == 2 => {
            format!("{op}[{} len {}]", pret(&children[0]), pret(&children[1]))
        }

        // -- Return / Revert (with string/panic detection) --
        "return" if children.len() == 1 => {
            let val = &children[0];
            let formatted = try_format_data(val, add_color);
            format!("return {formatted}")
        }
        "revert" if children.len() == 1 => {
            if children[0].is_zero() {
                "revert".to_string()
            } else {
                // Try to detect Solidity panic: data('NH{q', panic_code)
                if let Some(panic_str) = try_detect_panic(&children[0]) {
                    return panic_str;
                }
                // Try to detect revert reason string.
                if let Some(reason) = try_extract_revert_reason(&children[0], add_color) {
                    return reason;
                }
                let formatted = try_format_data(&children[0], add_color);
                format!("revert with {formatted}")
            }
        }

        // -- Require pattern (if + revert = require) --
        "require" if !children.is_empty() => {
            // Strip bool() wrapper in require context — it's redundant.
            let cond_expr = if children[0].opcode() == Some("bool") {
                if let Some(inner) = children[0].children() {
                    if inner.len() == 1 { &inner[0] } else { &children[0] }
                } else { &children[0] }
            } else { &children[0] };
            let cond = pret(cond_expr);
            if children.len() >= 2 && !children[1].is_zero() {
                // Try revert-reason extraction first (handles Error(string) ABI encoding).
                if let Some(reason_str) = try_extract_revert_reason(&children[1], add_color) {
                    // reason_str is "revert with 'message'" — strip prefix for require.
                    let msg = reason_str.strip_prefix("revert with ").unwrap_or(&reason_str);
                    return format!("require {cond}, {msg}");
                }
                let reason = try_format_data(&children[1], add_color);
                format!("require {cond}, {reason}")
            } else {
                format!("require {cond}")
            }
        }

        // -- If / While --
        "if" if children.len() >= 3 => {
            format!("if {}:", pret(&children[0]))
        }
        "while" if children.len() >= 2 => {
            format!("while {}:", pret(&children[0]))
        }
        "continue" => "continue".to_string(),

        // -- Log (with event signature formatting) --
        "log" if !children.is_empty() => {
            pretty_log(children, add_color)
        }

        // -- Data (multi-value concatenation) --
        "data" => {
            // Try to detect a string literal in data(32, length, ...chunks).
            if let Some(s) = try_data_as_string(children) {
                return s;
            }
            let args: Vec<String> = children.iter().map(&pret).collect();
            format!("data({})", args.join(", "))
        }

        // -- Stop / selfdestruct / invalid --
        "stop" => "stop".to_string(),
        "invalid" => "revert".to_string(),
        "selfdestruct" if children.len() == 1 => {
            format!("selfdestruct({})", pret(&children[0]))
        }

        // -- Mask --
        "mask_shl" if children.len() == 4 => {
            let size = &children[0];
            let offset = &children[1];
            let shift = &children[2];
            let val = &children[3];
            // Type cast: mask_shl(N, 0, 0, x) → type(x) or uintN(x)
            if offset.is_zero() && shift.is_zero() {
                if let Some(s) = size.as_u64() {
                    if let Some(type_name) = mask_to_type(s as u16, false) {
                        return format!("{type_name}({})", pret(val));
                    }
                    // For non-standard sizes, render as uintN(x)
                    if s > 0 && s < 256 {
                        return format!("uint{}({})", s, pret(val));
                    }
                }
            }
            // Right-shift extraction: mask_shl(N, 0, -M, x) → uintN(x >> M)
            if offset.is_zero() {
                if let Some(s) = size.as_u64() {
                    if let Some(sh) = shift.as_val() {
                        if sh > U256::from(256u64) {
                            // Negative shift (as U256 wrapping): right-shift
                            let rshift = U256::zero().overflowing_sub(sh).0;
                            if rshift <= U256::from(256u64) {
                                let type_name = mask_to_type(s as u16, false)
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| format!("uint{s}"));
                                return format!("{type_name}({} >> {})", pret(val), rshift);
                            }
                        }
                    }
                }
            }
            // Selector extraction: mask_shl(32, 224, 0, x) → bytes4(x)
            if size == &Expr::val(32) && offset == &Expr::val(224) && shift.is_zero() {
                return format!("bytes4({})", pret(val));
            }
            // Left-shift: mask_shl(N, 0, M, x) → x << M (when offset is 0)
            if offset.is_zero() {
                if let Some(s) = size.as_u64() {
                    if let Some(sh) = shift.as_u64() {
                        if sh > 0 && sh < 256 && s == 256 {
                            return format!("({} << {})", pret(val), sh);
                        }
                    }
                }
            }
            format!("Mask({}, {}, {}, {})", pret(size), pret(offset), pret(shift), pret(val))
        }

        // -- Create --
        "create" if children.len() == 2 => {
            format!("create contract with {} wei", pret(&children[0]))
        }
        "create2" if children.len() == 3 => {
            format!("create2 contract with {} wei, salt {}", pret(&children[0]), pret(&children[2]))
        }

        // -- Environment queries --
        "blockhash" if children.len() == 1 => format!("block.hash({})", pret(&children[0])),
        "extcodehash" if children.len() == 1 => format!("ext_code.hash({})", pret(&children[0])),
        "extcodesize" if children.len() == 1 => format!("ext_code.size({})", pret(&children[0])),
        "extcodecopy" if children.len() == 2 => {
            format!("ext_code.copy({}, {})", pret(&children[0]), pret(&children[1]))
        }
        "blobhash" if children.len() == 1 => format!("blobhash({})", pret(&children[0])),
        "codesize" if children.is_empty() => "code.size".to_string(),

        // -- Sequence (sub-trace) --
        "seq" => {
            // Handled by pprint_logic; if we get here, flatten.
            let args: Vec<String> = children.iter().map(&pret).collect();
            args.join("; ")
        }

        // -- Goto / label (leftover from while conversion) --
        "goto" if !children.is_empty() => {
            format!("goto {}", pret(&children[0]))
        }
        "label" if !children.is_empty() => {
            format!("label_{}:", pret(&children[0]))
        }

        // -- Undefined / abort --
        "undefined" => {
            let msg = children.first().map(pret).unwrap_or_default();
            format!("...  # Decompilation aborted: {msg}")
        }

        // -- Function call markers --
        "funccall" => {
            let args: Vec<String> = children.iter().map(&pret).collect();
            format!("funccall({})", args.join(", "))
        }

        // -- Fallback --
        _ => {
            if is_array(op) {
                let args: Vec<String> = children.iter().map(&pret).collect();
                format!("{op}[{}]", args.join(", "))
            } else {
                let args: Vec<String> = children.iter().map(pret).collect();
                format!("({op} {})", args.join(" "))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// External call formatting
// ---------------------------------------------------------------------------

/// Format an external call with gas, address, value, function name, and params.
fn pretty_external_call(kind: &str, children: &[Expr], add_color: bool) -> String {
    let pret = |e: &Expr| prettify(e, add_color);

    let gas = &children[0];
    let addr = &children[1];
    let wei = &children[2];
    let fname = children.get(3);
    let fparams = children.get(4);

    // Format address: if it's a concrete value, try precompiled name or pad to 40 hex.
    let addr_str = if let Some(v) = addr.as_val() {
        let low = v.low_u64();
        if let Some(name) = precompiled_contracts().get(&low) {
            name.to_string()
        } else if v <= U256::from(u64::MAX) {
            padded_hex(v, 40)
        } else {
            pret(addr)
        }
    } else {
        pret(addr)
    };

    // Format function name from selector — resolve via signature DB when possible.
    let fname_str = match fname {
        Some(f) if !matches!(f, Expr::Bool(false)) => {
            // If fname is a concrete value, try to resolve the 4-byte selector.
            if let Some(v) = f.as_val() {
                let sel = format!("0x{:08x}", v.low_u64());
                if let Some(resolved) = crate::utils::signatures::get_func_name(&sel) {
                    format!(".{resolved}")
                } else {
                    format!(".{}", padded_hex(v, 8))
                }
            } else {
                // Dynamic selector (expression, not concrete) — don't render
                // as .funcname since it looks like a method call.
                String::new()
            }
        }
        _ => String::new(),
    };

    let mut parts = vec![format!("{kind} {addr_str}{fname_str}")];

    // Value (for call/callcode).
    if (kind == "call" || kind == "callcode") && !wei.is_zero() {
        parts.push(format!("  value: {} wei", pret(wei)));
    }

    // Gas.
    if !gas.is_zero() && gas.as_val() != Some(U256::MAX) {
        // Detect the 2300 * iszero(value) gas stipend pattern.
        if let Some(ch) = gas.children() {
            if gas.opcode() == Some("mul") && ch.len() == 2 {
                if ch[0] == Expr::val(2300) && ch[1].opcode() == Some("iszero") {
                    parts.push("  gas: 2300 * is_zero(value)".to_string());
                } else {
                    parts.push(format!("  gas: {}", pret(gas)));
                }
            } else {
                parts.push(format!("  gas: {}", pret(gas)));
            }
        } else {
            parts.push(format!("  gas: {}", pret(gas)));
        }
    }

    // Params.
    if let Some(fp) = fparams {
        if !matches!(fp, Expr::Bool(false)) && !fp.is_zero() {
            parts.push(format!("  args: {}", pret(fp)));
        }
    }

    parts.join("\n")
}

// ---------------------------------------------------------------------------
// Log formatting
// ---------------------------------------------------------------------------

/// Format a log expression with topics and data.
fn pretty_log(children: &[Expr], add_color: bool) -> String {
    let pret = |e: &Expr| prettify(e, add_color);

    if children.is_empty() {
        return "log()".to_string();
    }

    let data = &children[0];
    let topics = &children[1..];

    // Try to resolve topic0 (event selector) to a human-readable event name.
    let (event_name, event_short) = if let Some(topic0) = topics.first() {
        if let Some(v) = topic0.as_val() {
            let hex = format!("0x{v:064x}");
            // Look up event name via openchain signature database.
            if let Some(full_sig) = get_event_name(&hex) {
                // Extract just the event name (before the parentheses).
                let short = full_sig.split('(').next().unwrap_or(&full_sig).to_string();
                (Some(full_sig), Some(short))
            } else {
                // Fall back to abbreviated hex.
                let abbrev = format!("0x{v:08x}");
                (None, Some(abbrev))
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let data_str = pret(data);
    let topic_strs: Vec<String> = topics.iter().map(pret).collect();

    // Use the short name for display.
    let display_name = event_short.unwrap_or_default();

    if !display_name.is_empty() {
        if topic_strs.len() > 1 {
            let indexed = topic_strs[1..].join(", ");
            // If we have a full signature, try to label the indexed params.
            if let Some(ref full) = event_name {
                let labels = extract_event_indexed_labels(full, topics.len() - 1);
                if !labels.is_empty() && labels.len() == topics.len() - 1 {
                    let labeled: Vec<String> = labels.iter().zip(topic_strs[1..].iter())
                        .map(|(l, v)| format!("{l}={v}"))
                        .collect();
                    return format!("log {display_name}(\n        {data_str},\n        {}))",
                        labeled.join(",\n        "));
                }
            }
            format!("log {display_name}({data_str}, topics=[{indexed}])")
        } else {
            format!("log {display_name}({data_str})")
        }
    } else if topic_strs.is_empty() {
        format!("log({data_str})")
    } else {
        format!("log(data={data_str}, topics=[{}])", topic_strs.join(", "))
    }
}

/// Extract indexed parameter labels from an event signature like
/// `"Transfer(address,address,uint256)"`. Returns up to `count` labels.
fn extract_event_indexed_labels(sig: &str, count: usize) -> Vec<String> {
    let start = sig.find('(').map(|i| i + 1).unwrap_or(0);
    let end = sig.rfind(')').unwrap_or(sig.len());
    let params_str = &sig[start..end];
    let params: Vec<&str> = params_str.split(',').collect();
    // Return the first `count` parameter types as labels (indexed topics).
    params.iter().take(count).map(|p| p.trim().to_string()).collect()
}

// ---------------------------------------------------------------------------
// String / data detection
// ---------------------------------------------------------------------------

/// Try to detect a Solidity panic revert: data('NH{q', code).
fn try_detect_panic(val: &Expr) -> Option<String> {
    if val.opcode() != Some("data") {
        return None;
    }
    let ch = val.children()?;
    if ch.len() < 2 {
        return None;
    }
    // The panic selector is 'NH{q' = 0x4e487b71
    let selector = &ch[0];
    let is_panic = match selector.as_val() {
        Some(v) => v == U256::from(0x4e487b71u64),
        None => {
            if let Some(s) = pretty_bignum_raw(selector) {
                s == "NH{q"
            } else {
                false
            }
        }
    };
    if !is_panic {
        return None;
    }
    let code = ch.get(1)?;
    if let Some(c) = code.as_u64() {
        let desc = panic_code_description(c).unwrap_or("unknown");
        Some(format!("revert with Panic({c})  # {desc}"))
    } else {
        Some(format!("revert with Panic({})", prettify(code, false)))
    }
}

/// Try to extract a revert reason string from a data() expression.
fn try_extract_revert_reason(val: &Expr, add_color: bool) -> Option<String> {
    if val.opcode() != Some("data") {
        return None;
    }
    let ch = val.children()?;
    if ch.len() < 2 {
        return None;
    }
    // Error(string) selector = 0x08c379a0
    let selector = &ch[0];
    let is_error = match selector.as_val() {
        Some(v) => v == U256::from(0x08c379a0u64),
        None => false,
    };
    if !is_error {
        return None;
    }
    // Try to extract the string from the remaining data elements.
    let rest: Vec<&Expr> = ch[1..].iter().collect();
    if let Some(s) = try_extract_string_from_abi(&rest) {
        Some(format!("revert with {s}"))
    } else {
        Some(format!("revert with Error({})", prettify(val, add_color)))
    }
}

/// Try to extract a string from ABI-encoded data: [offset=32, length, ...chunks].
fn try_extract_string_from_abi(parts: &[&Expr]) -> Option<String> {
    if parts.len() < 2 {
        return None;
    }
    // First element should be offset (32).
    if parts[0].as_u64() != Some(32) {
        return None;
    }
    // Second element is the string length.
    let len = parts.get(1)?.as_u64()? as usize;
    if len == 0 || len > 1024 {
        return None;
    }
    // Remaining elements are 32-byte chunks.
    let mut bytes = Vec::new();
    for chunk in &parts[2..] {
        if let Some(v) = chunk.as_val() {
            for i in (0..32).rev() {
                let byte = ((v >> (i * 8)) & U256::from(0xFFu64)).low_u64() as u8;
                bytes.push(byte);
            }
        } else {
            return None;
        }
    }
    bytes.truncate(len);
    // Check all printable.
    if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        Some(format!("'{}'", String::from_utf8_lossy(&bytes)))
    } else {
        None
    }
}

/// Try to detect a string literal in a `data(32, length, ...chunks)` pattern.
fn try_data_as_string(children: &[Expr]) -> Option<String> {
    if children.len() < 3 {
        return None;
    }
    // First child = 32 (offset), second = length.
    if children[0].as_u64() != Some(32) {
        return None;
    }
    let refs: Vec<&Expr> = children.iter().collect();
    try_extract_string_from_abi(&refs)
}

/// Format data with string detection applied.
fn try_format_data(val: &Expr, add_color: bool) -> String {
    if val.opcode() == Some("data") {
        if let Some(ch) = val.children() {
            if let Some(s) = try_data_as_string(ch) {
                return s;
            }
        }
    }
    prettify(val, add_color)
}

/// Raw ASCII decode (without quoting).
fn pretty_bignum_raw(expr: &Expr) -> Option<String> {
    let v = expr.as_val()?;
    if v.is_zero() {
        return None;
    }
    let mut s = String::new();
    let mut n = v;
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
    if s.is_empty() { None } else { Some(s) }
}

// ---------------------------------------------------------------------------
// Storage read formatting
// ---------------------------------------------------------------------------

/// Check if an expression is a storage read of the given key.
/// Matches either the key itself or a `stor(_, _, key)` read expression.
fn is_same_stor_key(expr: &Expr, key: &Expr) -> bool {
    if *expr == *key {
        return true;
    }
    // stor(size, off, key) — 3-child read node.
    if expr.opcode() == Some("stor") {
        if let Some(ch) = expr.children() {
            if ch.len() == 3 && ch[2] == *key {
                return true;
            }
        }
    }
    false
}

/// Pretty-print a resolved storage index expression.
fn pretty_stor_read(idx: &Expr, add_color: bool) -> String {
    match idx.opcode() {
        Some("loc") => {
            if let Some(ch) = idx.children() {
                format!("stor{}", prettify(&ch[0], add_color))
            } else {
                "stor?".to_string()
            }
        }
        Some("name") => {
            if let Some(ch) = idx.children() {
                prettify(&ch[0], add_color)
            } else {
                "named?".to_string()
            }
        }
        Some("map") => {
            if let Some(ch) = idx.children() {
                if ch.len() == 2 {
                    format!(
                        "{}[{}]",
                        pretty_stor_read(&ch[1], add_color),
                        prettify(&ch[0], add_color)
                    )
                } else {
                    format!("mapping({})", ch.iter().map(|c| prettify(c, add_color)).collect::<Vec<_>>().join(", "))
                }
            } else {
                "map?".to_string()
            }
        }
        Some("array") => {
            if let Some(ch) = idx.children() {
                if ch.len() == 2 {
                    format!(
                        "{}[{}]",
                        pretty_stor_read(&ch[1], add_color),
                        prettify(&ch[0], add_color)
                    )
                } else {
                    format!("array({})", ch.iter().map(|c| prettify(c, add_color)).collect::<Vec<_>>().join(", "))
                }
            } else {
                "array?".to_string()
            }
        }
        Some("length") => {
            if let Some(ch) = idx.children() {
                format!("{}.length", pretty_stor_read(&ch[0], add_color))
            } else {
                "length?".to_string()
            }
        }
        _ => prettify(idx, add_color),
    }
}

// ---------------------------------------------------------------------------
// Trace pretty-printing
// ---------------------------------------------------------------------------

/// Pretty-print a trace (list of expressions) to a multi-line string.
pub fn pprint_trace(trace: &[Expr], add_color: bool) -> String {
    let mut lines = Vec::new();
    for expr in trace {
        pprint_logic(expr, 2, add_color, &mut lines);
    }
    lines.join("\n")
}

/// Recursively format a trace expression with indentation.
fn pprint_logic(expr: &Expr, indent: usize, add_color: bool, lines: &mut Vec<String>) {
    let prefix = " ".repeat(indent);

    match expr.opcode() {
        Some("if") => {
            if let Some(children) = expr.children() {
                let cond = prettify(&children[0], add_color);
                lines.push(format!("{prefix}if {cond}:"));
                if children.len() > 1 {
                    if let Some(if_true) = children.get(1) {
                        pprint_seq(if_true, indent + 4, add_color, lines);
                    }
                }
                if children.len() > 2 {
                    if let Some(if_false) = children.get(2) {
                        // Skip empty else branches.
                        let is_empty = if_false.opcode() == Some("seq")
                            && if_false.children().is_none_or(|ch| ch.is_empty());
                        if !is_empty {
                            lines.push(format!("{prefix}else:"));
                            pprint_seq(if_false, indent + 4, add_color, lines);
                        }
                    }
                }
            }
        }
        Some("while") => {
            if let Some(children) = expr.children() {
                let cond = prettify(&children[0], add_color);
                lines.push(format!("{prefix}while {cond}:"));
                if let Some(body) = children.get(1) {
                    pprint_seq(body, indent + 4, add_color, lines);
                }
                // Print loop vars (setvars after the body).
                for extra in children.iter().skip(2) {
                    pprint_logic(extra, indent + 4, add_color, lines);
                }
            }
        }
        Some("require") => {
            lines.push(format!("{prefix}{}", prettify(expr, add_color)));
        }
        Some("seq") => {
            if let Some(children) = expr.children() {
                for child in children {
                    pprint_logic(child, indent, add_color, lines);
                }
            }
        }
        _ => {
            lines.push(format!("{prefix}{}", prettify(expr, add_color)));
        }
    }
}

/// Print a seq expression's children, or the expression itself if not a seq.
fn pprint_seq(expr: &Expr, indent: usize, add_color: bool, lines: &mut Vec<String>) {
    if expr.opcode() == Some("seq") {
        if let Some(children) = expr.children() {
            for child in children {
                pprint_logic(child, indent, add_color, lines);
            }
            return;
        }
    }
    pprint_logic(expr, indent, add_color, lines);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prettify_val() {
        assert_eq!(prettify(&Expr::val(42), false), "42");
    }

    #[test]
    fn test_prettify_zero() {
        assert_eq!(prettify(&Expr::zero(), false), "0");
    }

    #[test]
    fn test_prettify_atom() {
        assert_eq!(prettify(&Expr::atom("caller"), false), "caller");
        assert_eq!(prettify(&Expr::atom("timestamp"), false), "block.timestamp");
    }

    #[test]
    fn test_prettify_add() {
        let e = Expr::node2("add", Expr::val(1), Expr::val(2));
        assert_eq!(prettify(&e, false), "(1 + 2)");
    }

    #[test]
    fn test_prettify_storage() {
        let e = Expr::Node(
            "storage".to_string(),
            vec![Expr::val(256), Expr::zero(), Expr::val(5)],
        );
        assert_eq!(prettify(&e, false), "stor[5]");
    }

    #[test]
    fn test_prettify_revert() {
        assert_eq!(prettify(&Expr::node1("revert", Expr::zero()), false), "revert");
    }

    #[test]
    fn test_pprint_trace() {
        let trace = vec![Expr::node0("stop")];
        let output = pprint_trace(&trace, false);
        assert!(output.contains("stop"));
    }

    #[test]
    fn test_panic_codes() {
        assert!(panic_code_description(0x01).is_some());
        assert!(panic_code_description(0x32).is_some());
        assert!(panic_code_description(0xFF).is_none());
    }

    #[test]
    fn test_panic_revert_detection() {
        let panic_data = Expr::node(
            "data",
            vec![Expr::Val(U256::from(0x4e487b71u64)), Expr::val(0x11)],
        );
        let revert = Expr::node1("revert", panic_data);
        let output = prettify(&revert, false);
        assert!(output.contains("Panic(17)"));
        assert!(output.contains("overflow"));
    }

    #[test]
    fn test_require_formatting() {
        let require = Expr::node1("require", Expr::atom("cond"));
        let output = prettify(&require, false);
        assert_eq!(output, "require cond");
    }

    #[test]
    fn test_time_constant_formatting() {
        // 7200 = 2 * 3600
        assert_eq!(prettify(&Expr::val(7200), false), "2 * 3600");
        // 172800 = 2 * 86400
        assert_eq!(prettify(&Expr::val(172800), false), "2 * 24 * 3600");
    }

    #[test]
    fn test_bignum_string_detection() {
        // 0x414243 = "ABC"
        let v = U256::from(0x414243u64);
        let output = prettify(&Expr::Val(v), false);
        assert_eq!(output, "'ABC'");
    }

    #[test]
    fn test_external_call_formatting() {
        let call = Expr::Node("call".to_string(), vec![
            Expr::val(2300),     // gas
            Expr::val(1),        // addr (ecrecover)
            Expr::val(100),      // wei
            Expr::Bool(false),   // fname
            Expr::Bool(false),   // fparams
        ]);
        let output = prettify(&call, false);
        assert!(output.contains("ecrecover"));
        assert!(output.contains("100 wei"));
    }

    #[test]
    fn test_empty_else_suppressed() {
        let if_expr = Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![Expr::node0("stop")]),
            Expr::node("seq", vec![]),
        );
        let output = pprint_trace(&[if_expr], false);
        assert!(output.contains("if cond:"));
        assert!(!output.contains("else:"));
    }
}
