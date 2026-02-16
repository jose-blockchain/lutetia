//! Comprehensive trace simplification engine.
//!
//! Runs a fixed-point loop applying multiple passes:
//! - Expression-level algebraic simplification
//! - Variable inlining with dependency tracking
//! - Memory cleanup with overwrite detection
//! - Condition elimination
//! - Loop-to-memcpy/memzero detection
//! - msize resolution
//! - Readability improvements
//!
//! Each pass produces a simpler but semantically equivalent trace.

use crate::core::algebra;
use crate::core::arithmetic as arith;
use crate::expr::{Expr, Trace, UINT_256_MAX};
use crate::utils::helpers::{replace_f, rewrite_trace, to_exp2};
use primitive_types::U256;
use std::time::Instant;

/// Maximum number of simplification iterations.
const MAX_ITERATIONS: usize = 40;

// ===========================================================================
// Public entry point
// ===========================================================================

/// Simplify a trace by running all passes until convergence.
pub fn simplify_trace(trace: &[Expr], timeout_secs: u64, _debug_name: Option<&str>) -> Trace {
    let start = Instant::now();
    let timeout = if timeout_secs == 0 { 30 } else { timeout_secs };

    let should_quit = || start.elapsed().as_secs() > timeout;

    let mut trace = trace.to_vec();
    let mut count = 0;

    loop {
        count += 1;
        if count > MAX_ITERATIONS || should_quit() {
            break;
        }

        let old = trace.clone();

        // 1. Expression-level simplification (bottom-up).
        trace = trace
            .iter()
            .map(|e| replace_f(e, &simplify_exp))
            .collect();

        // 2. Decode revert/require reason strings from memory write patterns
        // BEFORE cleanup_vars removes setvar nodes (needed for base resolution)
        // and BEFORE cleanup_mems removes the setmem stores.
        trace = decode_revert_strings(&trace);

        // 2.5. Variable inlining.
        trace = cleanup_vars(&trace, &[]);

        // 2.6. Resolve SHA3 memory patterns BEFORE cleanup_mems removes the setmem stores.
        trace = resolve_sha3_mem(&trace);

        // 3. Memory cleanup (also resolves symbolic-length return/log mem references
        // via fill_mem data() nodes).
        trace = cleanup_mems(&trace);



        // 4. Split packed setmem/store.
        trace = rewrite_trace(&trace, &split_setmem);
        trace = rewrite_trace(&trace, &split_store);

        // 5. Second variable/expression pass.
        trace = cleanup_vars(&trace, &[]);
        trace = trace
            .iter()
            .map(|e| replace_f(e, &simplify_exp))
            .collect();

        // 6. Condition elimination.
        trace = cleanup_conds(&trace);

        // 6.5. Dominated condition elimination.
        trace = eliminate_dominated_conds(&trace, &[]);

        // 7. Loop optimizations.
        trace = rewrite_trace(&trace, &loop_to_setmem);

        // Converged?
        if trace == old {
            break;
        }
    }

    // Post-processing: readability.
    trace = readability_pass(&trace);

    trace
}

// ===========================================================================
// Expression simplification
// ===========================================================================

/// Simplify a single expression. Applied bottom-up via `replace_f`.
fn simplify_exp(expr: &Expr) -> Expr {
    let op = match expr.opcode() {
        Some(op) => op.to_string(),
        None => return expr.clone(),
    };
    let ch = match expr.children() {
        Some(ch) => ch,
        None => return expr.clone(),
    };

    match op.as_str() {
        // -- Double negation: iszero(iszero(x)) → bool(x) --
        "iszero" if ch.len() == 1 => {
            if let Some(inner_ch) = ch[0].children() {
                if ch[0].opcode() == Some("iszero") && inner_ch.len() == 1 {
                    return Expr::node1("bool", inner_ch[0].clone());
                }
            }
            // iszero(bool(x)) → iszero(x)
            if let Some(inner_ch) = ch[0].children() {
                if ch[0].opcode() == Some("bool") && inner_ch.len() == 1 {
                    return Expr::node1("iszero", inner_ch[0].clone());
                }
            }
            // Constant fold.
            if let Some(v) = ch[0].as_val() {
                return if v.is_zero() { Expr::val(1) } else { Expr::zero() };
            }
            expr.clone()
        }

        // -- bool(bool(x)) → bool(x) --
        "bool" if ch.len() == 1 => {
            if ch[0].opcode() == Some("bool") {
                return ch[0].clone();
            }
            // bool(iszero(x)) → iszero(x)
            if ch[0].opcode() == Some("iszero") {
                return ch[0].clone();
            }
            // Constant fold.
            if let Some(v) = ch[0].as_val() {
                return if v.is_zero() { Expr::zero() } else { Expr::val(1) };
            }
            expr.clone()
        }

        // -- eq(x, 0) or eq(0, x) → iszero(x) --
        "eq" if ch.len() == 2 => {
            // Tautology: eq(X, X) → 1 (always true).
            if ch[0] == ch[1] {
                return Expr::val(1);
            }
            if ch[0].is_zero() && !ch[1].is_zero() {
                return Expr::node1("iszero", ch[1].clone());
            }
            if ch[1].is_zero() && !ch[0].is_zero() {
                return Expr::node1("iszero", ch[0].clone());
            }
            // Constant fold.
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return if a == b { Expr::val(1) } else { Expr::zero() };
            }
            expr.clone()
        }

        // -- not(x) → constant fold --
        "not" if ch.len() == 1 => {
            if let Some(v) = ch[0].as_val() {
                Expr::Val(!v)
            } else {
                expr.clone()
            }
        }

        // -- add simplifications --
        "add" => simplify_add(ch),

        // -- mul simplifications --
        "mul" => simplify_mul(ch),

        // -- div simplifications --
        "div" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                if b.is_zero() {
                    return Expr::zero();
                }
                return Expr::Val(a / b);
            }
            if ch[1] == Expr::val(1) {
                return ch[0].clone();
            }
            expr.clone()
        }

        // -- mod simplifications --
        "mod" if ch.len() == 2 => {
            if ch[0].is_zero() {
                return Expr::zero();
            }
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                if b.is_zero() {
                    return Expr::zero();
                }
                return Expr::Val(a % b);
            }
            // mod(x, 2^k) → mask_shl(k, 0, 0, x)
            if let Some(m) = ch[1].as_val() {
                if let Some(k) = to_exp2(m) {
                    return algebra::mask_op(
                        ch[0].clone(),
                        Expr::val(k as u64),
                        Expr::zero(),
                        Expr::zero(),
                    );
                }
            }
            expr.clone()
        }

        // -- exp simplifications --
        "exp" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::exp(a, b));
            }
            if ch[1].is_zero() {
                return Expr::val(1);
            }
            if ch[1] == Expr::val(1) {
                return ch[0].clone();
            }
            expr.clone()
        }

        // -- or simplifications --
        "or" => simplify_or(ch),

        // -- and simplifications --
        "and" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(a & b);
            }
            if ch[0].is_zero() || ch[1].is_zero() {
                return Expr::zero();
            }
            if ch[0] == Expr::Val(UINT_256_MAX) {
                return ch[1].clone();
            }
            if ch[1] == Expr::Val(UINT_256_MAX) {
                return ch[0].clone();
            }
            // and(x, mask) → simplify_mask
            if let Some(mask_val) = ch[0].as_val().or(ch[1].as_val()) {
                let other = if ch[0].is_val() { &ch[1] } else { &ch[0] };
                return simplify_and_mask(other, mask_val);
            }
            expr.clone()
        }

        // -- xor simplifications --
        "xor" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(a ^ b);
            }
            if ch[0] == ch[1] {
                return Expr::zero();
            }
            expr.clone()
        }

        // -- shl/shr simplifications --
        "shl" if ch.len() == 2 => {
            if let (Some(s), Some(v)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::shl(s, v));
            }
            if ch[0].is_zero() {
                return ch[1].clone();
            }
            expr.clone()
        }
        "shr" if ch.len() == 2 => {
            if let (Some(s), Some(v)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::shr(s, v));
            }
            if ch[0].is_zero() {
                return ch[1].clone();
            }
            expr.clone()
        }
        "sar" if ch.len() == 2 => {
            if let (Some(s), Some(v)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::sar(s, v));
            }
            if ch[0].is_zero() {
                return ch[1].clone();
            }
            expr.clone()
        }

        // -- mask_shl simplifications --
        "mask_shl" if ch.len() == 4 => simplify_mask_shl(ch),

        // -- lt/gt/slt/sgt comparisons --
        "lt" | "gt" | "slt" | "sgt" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                if let Some(r) = arith::eval_concrete(&op, &[a, b]) {
                    return Expr::Val(r);
                }
            }
            // Remove common addends from both sides.
            simplify_comparison(&op, &ch[0], &ch[1])
        }

        // -- mem(range(_, 0)) → nothing --
        "mem" if ch.len() == 1 => {
            if let Some(rch) = ch[0].children() {
                if ch[0].opcode() == Some("range") && rch.len() == 2 && rch[1].is_zero() {
                    return Expr::zero();
                }
            }
            expr.clone()
        }

        // -- max(single) → single --
        "max" if ch.len() == 1 => ch[0].clone(),

        // -- data() simplification --
        "data" => {
            if ch.iter().all(|c| c.is_zero()) {
                return Expr::zero();
            }
            // data(X, mem(...)) → X: the remaining mem is ABI padding.
            // This handles the common pattern from fill_mem: value + trailing bytes.
            if ch.len() == 2 && ch[1].opcode() == Some("mem") {
                return ch[0].clone();
            }
            // data(X, 0) → X: trailing zero is padding.
            if ch.len() == 2 && ch[1].is_zero() {
                return ch[0].clone();
            }
            // data(X) → X: single-element data is just the value.
            if ch.len() == 1 {
                return ch[0].clone();
            }
            // Flatten nested data.
            let mut flat = Vec::new();
            let mut changed = false;
            for c in ch {
                if c.opcode() == Some("data") {
                    if let Some(inner) = c.children() {
                        flat.extend(inner.iter().cloned());
                        changed = true;
                        continue;
                    }
                }
                flat.push(c.clone());
            }
            if changed {
                Expr::node("data", flat)
            } else {
                expr.clone()
            }
        }

        // -- signextend constant fold --
        "signextend" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::signextend(a, b));
            }
            expr.clone()
        }

        // -- byte constant fold --
        "byte" if ch.len() == 2 => {
            if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                return Expr::Val(arith::byte_op(a, b));
            }
            expr.clone()
        }

        _ => expr.clone(),
    }
}

// -- Add simplification ----------------------------------------------------

fn simplify_add(ch: &[Expr]) -> Expr {
    if ch.is_empty() {
        return Expr::zero();
    }
    if ch.len() == 1 {
        return ch[0].clone();
    }

    // Flatten nested adds and collect terms.
    let mut terms = Vec::new();
    let mut constant = U256::zero();

    for c in ch {
        collect_add_terms(c, &mut terms, &mut constant);
    }

    // Cancel: x + (-1)*x → 0
    let mut cancelled = vec![false; terms.len()];
    for i in 0..terms.len() {
        if cancelled[i] { continue; }
        for j in (i + 1)..terms.len() {
            if cancelled[j] { continue; }
            if is_neg_of(&terms[i], &terms[j]) || is_neg_of(&terms[j], &terms[i]) {
                cancelled[i] = true;
                cancelled[j] = true;
            }
        }
    }

    let active_terms: Vec<&Expr> = terms.iter().enumerate()
        .filter(|(i, _)| !cancelled[*i])
        .map(|(_, t)| t)
        .collect();

    // Reassemble.
    let mut parts: Vec<Expr> = Vec::new();
    if !constant.is_zero() {
        parts.push(Expr::Val(constant));
    }
    parts.extend(active_terms.into_iter().cloned());

    match parts.len() {
        0 => Expr::zero(),
        1 => parts.remove(0),
        _ => Expr::Node("add".to_string(), parts),
    }
}

fn collect_add_terms(expr: &Expr, terms: &mut Vec<Expr>, constant: &mut U256) {
    match expr {
        Expr::Val(v) => {
            *constant = constant.overflowing_add(*v).0;
        }
        Expr::Node(op, ch) if op == "add" => {
            for c in ch {
                collect_add_terms(c, terms, constant);
            }
        }
        _ => terms.push(expr.clone()),
    }
}

fn is_neg_of(a: &Expr, b: &Expr) -> bool {
    // Check if a == mul(-1, b)
    if let Some(ch) = a.children() {
        if a.opcode() == Some("mul") && ch.len() == 2
            && ch[0] == Expr::Val(UINT_256_MAX) && ch[1] == *b {
                return true;
            }
    }
    false
}

// -- Mul simplification ----------------------------------------------------

fn simplify_mul(ch: &[Expr]) -> Expr {
    if ch.is_empty() {
        return Expr::val(1);
    }
    if ch.len() == 1 {
        return ch[0].clone();
    }

    // Flatten.
    let mut factors = Vec::new();
    let mut constant = U256::one();
    let mut has_zero = false;

    for c in ch {
        match c {
            Expr::Val(v) if v.is_zero() => { has_zero = true; }
            Expr::Val(v) => { constant = constant.overflowing_mul(*v).0; }
            Expr::Node(op, inner) if op == "mul" => {
                for ic in inner {
                    if let Expr::Val(v) = ic {
                        constant = constant.overflowing_mul(*v).0;
                    } else {
                        factors.push(ic.clone());
                    }
                }
            }
            _ => factors.push(c.clone()),
        }
    }

    if has_zero {
        return Expr::zero();
    }

    // mul(-1, mul(-1, x)) → x
    if constant == UINT_256_MAX && factors.len() == 1 {
        if let Some(inner) = factors[0].children() {
            if factors[0].opcode() == Some("mul") && inner.len() == 2
                && inner[0] == Expr::Val(UINT_256_MAX) {
                    return inner[1].clone();
                }
        }
    }

    let mut parts = Vec::new();
    if constant != U256::one() {
        parts.push(Expr::Val(constant));
    }
    parts.extend(factors);

    match parts.len() {
        0 => Expr::val(1),
        1 => parts.remove(0),
        _ => Expr::Node("mul".to_string(), parts),
    }
}

// -- Or simplification -----------------------------------------------------

fn simplify_or(ch: &[Expr]) -> Expr {
    if ch.is_empty() {
        return Expr::zero();
    }
    if ch.len() == 1 {
        return ch[0].clone();
    }

    let mut constant = U256::zero();
    let mut others = Vec::new();
    for c in ch {
        match c {
            Expr::Val(v) => { constant |= *v; }
            _ => others.push(c.clone()),
        }
    }

    if !constant.is_zero() {
        others.insert(0, Expr::Val(constant));
    }

    // or(A, mask_shl(S, OFF, 0, B)) where A fits entirely below bit OFF → A
    // This is the Solidity address-slot packing pattern:
    //   or(address_val, mask_shl(96, 160, 0, old_storage_read))
    // The upper bits from old_storage_read are typically zero, so the OR reduces to just A.
    if others.len() == 2 {
        if let Some(simplified) = try_simplify_or_pack(&others[0], &others[1]) {
            return simplified;
        }
        if let Some(simplified) = try_simplify_or_pack(&others[1], &others[0]) {
            return simplified;
        }
    }

    match others.len() {
        0 => Expr::Val(constant),
        1 => others.remove(0),
        _ => Expr::Node("or".to_string(), others),
    }
}

/// Try to simplify or(low_val, mask_shl(S, OFF, 0, high_val)) → low_val
/// when low_val is guaranteed to fit in bits 0..OFF-1.
fn try_simplify_or_pack(low_val: &Expr, high_part: &Expr) -> Option<Expr> {
    // high_part must be mask_shl(S, OFF, 0, X) with OFF > 0
    if high_part.opcode() != Some("mask_shl") { return None; }
    let hch = high_part.children()?;
    if hch.len() != 4 || !hch[2].is_zero() { return None; }
    let off = hch[1].as_val()?;
    if off.is_zero() || off > U256::from(256u64) { return None; }
    let off_bits = off.low_u64();

    // Check if low_val fits entirely below bit OFF.
    let low_bits = expr_max_bits(low_val);
    if low_bits <= off_bits {
        return Some(low_val.clone());
    }
    None
}

/// Estimate the maximum number of bits an expression can occupy.
fn expr_max_bits(e: &Expr) -> u64 {
    match e {
        Expr::Val(v) => {
            if v.is_zero() { return 0; }
            256 - v.leading_zeros() as u64
        }
        Expr::Bool(_) => 1,
        Expr::Node(op, ch) => {
            match op.as_str() {
                "mask_shl" if ch.len() == 4 => {
                    // mask_shl(S, _, shift, _): result fits in S bits (shifted).
                    if let Some(s) = ch[0].as_val() {
                        if ch[2].is_zero() {
                            // No shift: result fits in S bits at offset ch[1].
                            if ch[1].is_zero() {
                                return s.low_u64().min(256);
                            }
                        }
                    }
                    256
                }
                "address" => 160, // address() wraps to 160 bits
                _ => 256,
            }
        }
        Expr::Atom(name) => {
            match name.as_str() {
                "caller" | "origin" | "address" | "coinbase" => 160,
                _ => 256,
            }
        }
    }
}

// -- And/mask simplification -----------------------------------------------

fn simplify_and_mask(val: &Expr, mask: U256) -> Expr {
    // Detect if mask is a contiguous bit range: (1 << n) - 1  (low-bit mask)
    // If so, convert to mask_shl(n, 0, 0, val).
    if let Some(n) = to_exp2(mask.overflowing_add(U256::one()).0) {
        if n <= 256 {
            return algebra::mask_op(
                val.clone(),
                Expr::val(n as u64),
                Expr::zero(),
                Expr::zero(),
            );
        }
    }

    // Detect contiguous bit range with non-zero offset.
    // E.g., 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
    //   = 160 ones starting at bit 96 → mask_shl(160, 96, 0, val)
    if !mask.is_zero() {
        let trailing = mask.trailing_zeros() as u64;
        let shifted = mask >> trailing as usize;
        // Check if shifted is (1 << n) - 1 (all ones in low bits).
        if let Some(n) = to_exp2(shifted.overflowing_add(U256::one()).0) {
            if n <= 256 && trailing + n as u64 <= 256 {
                return algebra::mask_op(
                    val.clone(),
                    Expr::val(n as u64),
                    Expr::val(trailing),
                    Expr::zero(),
                );
            }
        }
    }

    Expr::node2("and", Expr::Val(mask), val.clone())
}

// -- mask_shl simplification -----------------------------------------------

fn simplify_mask_shl(ch: &[Expr]) -> Expr {
    let (size, offset, shift, val) = (&ch[0], &ch[1], &ch[2], &ch[3]);

    // Identity: mask_shl(256, 0, 0, v) → v
    if size == &Expr::val(256) && offset.is_zero() && shift.is_zero() {
        return val.clone();
    }

    // Zero size → 0.
    if size.is_zero() {
        return Expr::zero();
    }

    // Constant fold: all concrete → compute the mask.
    if let (Some(sz), Some(off), Some(sh), Some(v)) =
        (size.as_val(), offset.as_val(), shift.as_val(), val.as_val())
    {
        return Expr::Val(apply_mask(v, sz, off, sh));
    }

    // mask_shl(s, off, 0, storage(sz2, 0, k)) where s >= sz2 → storage(sz2, 0, k)
    if shift.is_zero() && offset.is_zero() {
        if let (Some(s), Some("storage")) = (size.as_val(), val.opcode()) {
            if let Some(vch) = val.children() {
                if let Some(sz2) = vch.first().and_then(|e| e.as_val()) {
                    if s >= sz2 {
                        return val.clone();
                    }
                }
            }
        }
    }

    // mask_shl(160, 0, 0, caller) → caller (caller is always an address).
    // Same for origin, address, coinbase.
    if offset.is_zero() && shift.is_zero() && size == &Expr::val(160) {
        if let Expr::Atom(name) = val {
            if matches!(name.as_str(), "caller" | "origin" | "address" | "coinbase") {
                return val.clone();
            }
        }
    }

    // mask_shl(S, 0, 0, mask_shl(S, 0, 0, x)) → mask_shl(S, 0, 0, x)
    // Idempotent mask: applying the same mask twice has no effect.
    if offset.is_zero() && shift.is_zero() {
        if val.opcode() == Some("mask_shl") {
            if let Some(vch) = val.children() {
                if vch.len() == 4 && vch[0] == *size && vch[1].is_zero() && vch[2].is_zero() {
                    return val.clone();
                }
                // mask_shl(S, 0, 0, mask_shl(S2, 0, 0, x)) where S >= S2 → mask_shl(S2, 0, 0, x)
                if vch.len() == 4 && vch[1].is_zero() && vch[2].is_zero() {
                    if let (Some(s1), Some(s2)) = (size.as_val(), vch[0].as_val()) {
                        if s1 >= s2 {
                            return val.clone();
                        }
                    }
                }
            }
        }
    }

    // mask_shl(S, OFF, 0, shl(OFF, X)) → mask_shl(S, 0, 0, X)
    // Extracting S bits at offset OFF from X shifted left by OFF is just
    // extracting the lower S bits of X.
    if shift.is_zero() {
        if let (Some(off_val), Some("shl")) = (offset.as_val(), val.opcode()) {
            if let Some(vch) = val.children() {
                if vch.len() == 2 {
                    if let Some(shl_amt) = vch[0].as_val() {
                        if shl_amt == off_val && !off_val.is_zero() {
                            return algebra::mask_op(
                                vch[1].clone(),
                                size.clone(),
                                Expr::zero(),
                                Expr::zero(),
                            );
                        }
                    }
                }
            }
        }
    }

    // mask_shl(S, OFF, 0, mask_shl(S2, 0, OFF, X)) → mask_shl(min(S,S2), 0, 0, X)
    // Extracting S bits at offset OFF from (X left-shifted by OFF, masked to S2) = lower min(S,S2) bits of X.
    if shift.is_zero() {
        if let Some(off_val) = offset.as_val() {
            if !off_val.is_zero() && val.opcode() == Some("mask_shl") {
                if let Some(vch) = val.children() {
                    if vch.len() == 4 && vch[1].is_zero() {
                        if let Some(inner_shift) = vch[2].as_val() {
                            if inner_shift == off_val {
                                if let (Some(s1), Some(s2)) = (size.as_val(), vch[0].as_val()) {
                                    let min_s = s1.min(s2);
                                    return algebra::mask_op(
                                        vch[3].clone(),
                                        Expr::Val(min_s),
                                        Expr::zero(),
                                        Expr::zero(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Expr::Node("mask_shl".to_string(), ch.to_vec())
}

fn apply_mask(val: U256, size: U256, offset: U256, shift: U256) -> U256 {
    let sz = size.low_u64().min(256) as usize;
    let off = offset.low_u64().min(256) as usize;

    // Create a bitmask of `size` ones.
    let mask = if sz >= 256 {
        UINT_256_MAX
    } else {
        (U256::one() << sz) - U256::one()
    };

    let extracted = if off >= 256 { U256::zero() } else { (val >> off) & mask };

    // Apply shift. Shift can be negative (stored as large U256).
    let half = U256::one() << 255;
    if shift.is_zero() {
        extracted
    } else if shift < half {
        // Positive shift → left shift.
        let s = shift.low_u64().min(256) as usize;
        extracted << s
    } else {
        // Negative shift → right shift.
        let neg = (!shift).overflowing_add(U256::one()).0;
        let s = neg.low_u64().min(256) as usize;
        extracted >> s
    }
}

// -- Comparison simplification ---------------------------------------------

fn simplify_comparison(op: &str, left: &Expr, right: &Expr) -> Expr {
    // Try to remove common addends: (a + X) < (b + X) → a < b
    let left_terms = collect_add_terms_vec(left);
    let right_terms = collect_add_terms_vec(right);

    let mut left_remaining: Vec<Expr> = left_terms.clone();
    let mut right_remaining: Vec<Expr> = right_terms.clone();

    let mut changed = false;
    for lt in &left_terms {
        if let Some(pos) = right_remaining.iter().position(|r| r == lt) {
            left_remaining.retain(|x| x != lt);
            right_remaining.remove(pos);
            changed = true;
        }
    }

    if changed && !left_remaining.is_empty() && !right_remaining.is_empty() {
        let new_left = terms_to_add(&left_remaining);
        let new_right = terms_to_add(&right_remaining);
        return Expr::node2(op, new_left, new_right);
    }

    Expr::node2(op, left.clone(), right.clone())
}

fn collect_add_terms_vec(expr: &Expr) -> Vec<Expr> {
    let mut terms = Vec::new();
    let mut constant = U256::zero();
    collect_add_terms(expr, &mut terms, &mut constant);
    if !constant.is_zero() {
        terms.insert(0, Expr::Val(constant));
    }
    if terms.is_empty() {
        terms.push(Expr::zero());
    }
    terms
}

fn terms_to_add(terms: &[Expr]) -> Expr {
    match terms.len() {
        0 => Expr::zero(),
        1 => terms[0].clone(),
        _ => Expr::Node("add".to_string(), terms.to_vec()),
    }
}

// ===========================================================================
// Variable inlining (cleanup_vars)
// ===========================================================================

/// Build a usage map: for each variable name, count how many times it appears
/// in the trace as `var(name)`. This is O(n) and avoids the previous O(n²)
/// approach of formatting the entire remaining trace as a string per variable.
fn build_usage_map(trace: &[Expr]) -> std::collections::HashMap<String, usize> {
    let mut map = std::collections::HashMap::new();
    for line in trace {
        count_var_usage(line, &mut map);
    }
    map
}

fn count_var_usage(expr: &Expr, map: &mut std::collections::HashMap<String, usize>) {
    if expr.opcode() == Some("var") {
        if let Some(ch) = expr.children() {
            if let Some(Expr::Atom(name)) = ch.first() {
                *map.entry(name.clone()).or_insert(0) += 1;
            }
        }
    }
    if let Some(ch) = expr.children() {
        for c in ch {
            count_var_usage(c, map);
        }
    }
}

/// Inline variable definitions into subsequent uses, removing dead assignments.
///
/// Uses an iterative approach with a substitution map instead of the previous
/// recursive approach that was O(n²) due to re-scanning the remaining trace
/// for each variable.
fn cleanup_vars(trace: &[Expr], required_after: &[Expr]) -> Trace {
    // Phase 1: build a usage map counting var references in the trace — O(n).
    // This lets us quickly identify dead variables (used 0 times) without
    // rescanning the entire remaining trace per variable (was O(n²)).
    let usage = build_usage_map(trace);

    let mut result = Trace::new();
    // Pending substitutions: var_ref → var_val.
    let mut subs: Vec<(Expr, Expr)> = Vec::new();
    // Set of variable names whose values depend on memory and must not be
    // substituted past a setmem.
    let mut mem_vars: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (idx, line) in trace.iter().enumerate() {
        // Apply all pending substitutions to the current line.
        let line = apply_subs(line, &subs);

        if line.opcode() == Some("setvar") {
            if let Some(ch) = line.children() {
                if ch.len() >= 2 {
                    let var_name = match &ch[0] {
                        Expr::Atom(s) => s.clone(),
                        _ => {
                            result.push(line.clone());
                            continue;
                        }
                    };
                    let var_ref = Expr::node1("var", ch[0].clone());
                    let var_val = ch[1].clone();

                    // Track memory-dependent variables.
                    if expr_uses_mem(&var_val) {
                        mem_vars.insert(var_name.clone());
                    }

                    // Fast path: if the usage map says this var is never referenced
                    // (count == 0, which means it only appears in this setvar),
                    // skip the expensive per-trace scan.
                    let global_count = usage.get(&var_name).copied().unwrap_or(0);
                    let required_externally = required_after.iter().any(|r| r.contains(&var_ref));

                    if global_count == 0 && !required_externally {
                        // Dead assignment: drop it entirely.
                        continue;
                    }

                    // Add to substitution map (will be applied to subsequent lines).
                    subs.push((var_ref.clone(), var_val));
                    continue;
                }
            }
        }

        // Handle setmem: invalidate memory-dependent substitutions.
        // Re-emit setvar for flushed variables that still have references
        // in the remaining trace, so they're available for later passes.
        if line.opcode() == Some("setmem")
            && !mem_vars.is_empty() {
                let remaining = &trace[idx + 1..];
                let mut flushed: Vec<(Expr, Expr)> = Vec::new();
                subs.retain(|(ref_expr, val_expr)| {
                    if let Some(ch) = ref_expr.children() {
                        if let Some(Expr::Atom(name)) = ch.first() {
                            if mem_vars.contains(name) {
                                flushed.push((ref_expr.clone(), val_expr.clone()));
                                return false;
                            }
                        }
                    }
                    true
                });
                // Re-emit setvar for flushed vars that are still used downstream.
                for (ref_expr, val_expr) in &flushed {
                    let still_used = remaining.iter().any(|r| r.contains(ref_expr));
                    if still_used {
                        if let Some(ch) = ref_expr.children() {
                            result.push(Expr::node2("setvar", ch[0].clone(), val_expr.clone()));
                        }
                    }
                }
                mem_vars.clear();
            }

        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));

                    let after = &trace[idx + 1..];
                    let vars_after = find_var_refs(after);
                    let mut all_required: Vec<Expr> = required_after.to_vec();
                    all_required.extend(vars_after);

                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", cleanup_vars(&if_true, &all_required)),
                        Expr::node("seq", cleanup_vars(&if_false, &all_required)),
                    ));
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();

                    let after = &trace[idx + 1..];
                    let mut all_required: Vec<Expr> = required_after.to_vec();
                    all_required.extend(find_var_refs(after));
                    all_required.extend(find_var_refs_in_expr(&cond));

                    let clean_body = cleanup_vars(&body, &all_required);
                    let mut new_ch = vec![cond, Expr::node("seq", clean_body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => {
                result.push(line);
            }
        }
    }

    result
}

/// Apply all pending substitutions to an expression.
fn apply_subs(expr: &Expr, subs: &[(Expr, Expr)]) -> Expr {
    let mut result = expr.clone();
    for (var_ref, var_val) in subs {
        result = result.replace(var_ref, var_val);
    }
    result
}


/// Check if an expression reads from memory.
fn expr_uses_mem(expr: &Expr) -> bool {
    expr.contains_op("mem")
}

/// Find all var references in a trace.
fn find_var_refs(trace: &[Expr]) -> Vec<Expr> {
    let mut refs = Vec::new();
    for line in trace {
        find_var_refs_in_expr_collect(line, &mut refs);
    }
    refs
}

fn find_var_refs_in_expr(expr: &Expr) -> Vec<Expr> {
    let mut refs = Vec::new();
    find_var_refs_in_expr_collect(expr, &mut refs);
    refs
}

fn find_var_refs_in_expr_collect(expr: &Expr, refs: &mut Vec<Expr>) {
    if expr.opcode() == Some("var") {
        refs.push(expr.clone());
    }
    if let Some(ch) = expr.children() {
        for c in ch {
            find_var_refs_in_expr_collect(c, refs);
        }
    }
}

// ===========================================================================
// Memory cleanup (cleanup_mems)
// ===========================================================================

/// Propagate memory writes into subsequent reads, removing dead stores.
fn cleanup_mems(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for (idx, line) in trace.iter().enumerate() {
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if ch.len() >= 2 {
                    let mem_idx = &ch[0];
                    let mem_val = &ch[1];

                    // Skip self-assignment: setmem(range, mem(range)).
                    if mem_val.opcode() == Some("mem") {
                        if let Some(mch) = mem_val.children() {
                            if mch.len() == 1 && mch[0] == *mem_idx {
                                continue;
                            }
                        }
                    }

                    let remaining = &trace[idx + 1..];

                    // If the write's value depends on memory, don't propagate.
                    if expr_uses_mem(mem_val) {
                        result.push(line.clone());
                        result.extend(cleanup_mems(remaining));
                        return result;
                    }

                    // Propagate: replace mem(idx) with val in the remaining trace.
                    let substituted = replace_mem_in_trace(remaining, mem_idx, mem_val);

                    // Check if the memory location is still read.
                    if trace_uses_mem_location(&substituted, mem_idx) {
                        result.push(line.clone());
                    }
                    // Else: dead store elimination.

                    result.extend(cleanup_mems(&substituted));
                    return result;
                }
            }
        }

        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", cleanup_mems(&if_true)),
                        Expr::node("seq", cleanup_mems(&if_false)),
                    ));
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", cleanup_mems(&body))];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => result.push(line.clone()),
        }
    }

    result
}

/// Replace memory reads matching `mem_idx` with `mem_val` in a trace.
fn replace_mem_in_trace(trace: &[Expr], mem_idx: &Expr, mem_val: &Expr) -> Trace {
    let mut result = Trace::new();

    for (idx, line) in trace.iter().enumerate() {
        // If this is another setmem that overlaps, stop propagation.
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if !ch.is_empty() {
                    // Resolve mem references in the range BEFORE checking overlap,
                    // so that e.g. range(mem(range(64,32)), 32) becomes range(96, 32)
                    // when propagating setmem(range(64,32), 96).
                    let resolved_range = replace_mem_in_expr(&ch[0], mem_idx, mem_val);
                    if ranges_might_overlap(&resolved_range, mem_idx) {
                        result.push(replace_mem_in_expr(line, mem_idx, mem_val));
                        result.extend(trace[idx + 1..].to_vec());
                        return result;
                    }
                }
            }
        }

        // For return/log nodes (including nested inside if/while), use fill_mem
        // variant that handles symbolic-length reads.
        if expr_contains_return_or_log(line) {
            result.push(replace_mem_in_expr_fill(line, mem_idx, mem_val));
        } else {
            result.push(replace_mem_in_expr(line, mem_idx, mem_val));
        }
    }

    result
}

/// Like `replace_mem_in_expr` but also creates data() nodes for symbolic-length reads
/// (Panoramix fill_mem approach). Only used for return/log contexts.
fn replace_mem_in_expr_fill(expr: &Expr, mem_idx: &Expr, mem_val: &Expr) -> Expr {
    if expr.opcode() == Some("mem") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 {
                // First try exact match and sub-range.
                let basic = replace_mem_in_expr(expr, mem_idx, mem_val);
                if basic != *expr {
                    return basic;
                }
                // Symbolic-length fill: same offset, write is 32 bytes, read is longer/symbolic.
                if let (Some("range"), Some("range")) = (ch[0].opcode(), mem_idx.opcode()) {
                    if let (Some(rch), Some(wch)) = (ch[0].children(), mem_idx.children()) {
                        if rch.len() == 2 && wch.len() == 2 {
                            if let Some(wlen) = wch[1].as_u64() {
                                let offsets_match = rch[0] == wch[0]
                                    || (rch[0].as_u64().is_some() && rch[0].as_u64() == wch[0].as_u64());
                                if offsets_match && wlen == 32 && rch[1].as_u64() != Some(32) {
                                    let off_expr = &wch[0];
                                    let new_off = if let Some(o) = off_expr.as_u64() {
                                        Expr::val(o + 32)
                                    } else {
                                        Expr::node2("add", off_expr.clone(), Expr::val(32))
                                    };
                                    let new_len = if let Some(l) = rch[1].as_u64() {
                                        Expr::val(l - 32)
                                    } else {
                                        Expr::node2("add", rch[1].clone(), Expr::Val(U256::MAX - U256::from(31u64)))
                                    };
                                    return Expr::node2("data",
                                        mem_val.clone(),
                                        Expr::node1("mem",
                                            Expr::node2("range", new_off, new_len)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children
                .iter()
                .map(|c| replace_mem_in_expr_fill(c, mem_idx, mem_val))
                .collect();
            Expr::Node(op.clone(), new_ch)
        }
        _ => expr.clone(),
    }
}

/// Replace `mem(mem_idx)` with `mem_val` in an expression.
/// Also handles sub-range reads: if the write is `range(off, 32)` and the
/// read is `range(off, N)` where N < 32 and both offsets are concrete,
/// extract the top N bytes via right-shift: `val >> (256 - N*8)`.
fn replace_mem_in_expr(expr: &Expr, mem_idx: &Expr, mem_val: &Expr) -> Expr {
    if expr.opcode() == Some("mem") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 {
                // Exact match.
                if ch[0] == *mem_idx {
                    return mem_val.clone();
                }
                // Partial overlap: write is range(off, W), read starts at the same off.
                if let (Some("range"), Some("range")) = (ch[0].opcode(), mem_idx.opcode()) {
                    if let (Some(rch), Some(wch)) = (ch[0].children(), mem_idx.children()) {
                        if rch.len() == 2 && wch.len() == 2 {
                            if let Some(wlen) = wch[1].as_u64() {
                                let offsets_match = rch[0] == wch[0]
                                    || (rch[0].as_u64().is_some() && rch[0].as_u64() == wch[0].as_u64());
                                if offsets_match && wlen == 32 {
                                    if let Some(rlen) = rch[1].as_u64() {
                                        // Concrete read length < 32: extract top rlen bytes.
                                        if rlen < 32 && rlen > 0 {
                                            let shift = 256 - rlen * 8;
                                            if let Some(v) = mem_val.as_val() {
                                                return Expr::Val(v >> shift);
                                            }
                                            return Expr::Node(
                                                "mask_shl".into(),
                                                vec![
                                                    Expr::val(rlen * 8),
                                                    Expr::zero(),
                                                    Expr::Val(U256::zero().overflowing_sub(U256::from(shift)).0),
                                                    mem_val.clone(),
                                                ],
                                            );
                                        }
                                    }
                                    // Symbolic or larger read: NOT resolved in general context.
                                    // Use replace_mem_in_expr_fill for return/log contexts.
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children
                .iter()
                .map(|c| replace_mem_in_expr(c, mem_idx, mem_val))
                .collect();
            Expr::Node(op.clone(), new_ch)
        }
        other => other.clone(),
    }
}

/// Check if a memory location is read in the trace (considering overwrites).
fn trace_uses_mem_location(trace: &[Expr], mem_idx: &Expr) -> bool {
    trace.iter().any(|line| {
        // Check if any expression reads this memory.
        expr_contains_mem_read(line, mem_idx)
    })
}

/// Check if an expression tree contains return or log nodes at any depth.
fn expr_contains_return_or_log(expr: &Expr) -> bool {
    match expr.opcode() {
        Some("return") | Some("log") => true,
        _ => {
            if let Expr::Node(_, children) = expr {
                children.iter().any(expr_contains_return_or_log)
            } else {
                false
            }
        }
    }
}

fn expr_contains_mem_read(expr: &Expr, mem_idx: &Expr) -> bool {
    if expr.opcode() == Some("mem") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 && ch[0] == *mem_idx {
                return true;
            }
        }
    }
    match expr {
        Expr::Node(_, children) => children.iter().any(|c| expr_contains_mem_read(c, mem_idx)),
        _ => false,
    }
}

/// Conservative check if two memory ranges might overlap.
fn ranges_might_overlap(range1: &Expr, range2: &Expr) -> bool {
    // If both are range(offset, size) with concrete values, check overlap.
    if let (Some(r1ch), Some(r2ch)) = (range1.children(), range2.children()) {
        if range1.opcode() == Some("range")
            && range2.opcode() == Some("range")
            && r1ch.len() == 2
            && r2ch.len() == 2
        {
            if let (Some(o1), Some(s1), Some(o2), Some(s2)) =
                (r1ch[0].as_val(), r1ch[1].as_val(), r2ch[0].as_val(), r2ch[1].as_val())
            {
                let end1 = o1.overflowing_add(s1).0;
                let end2 = o2.overflowing_add(s2).0;
                // No overlap if one ends before the other starts.
                return !(end1 <= o2 || end2 <= o1);
            }
        }
    }
    // Conservative: assume overlap.
    true
}

// ===========================================================================
// Condition elimination
// ===========================================================================

/// Remove branches with conditions that are provably always true/false.
fn cleanup_conds(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));

                    match eval_bool_simple(&cond) {
                        Some(true) => result.extend(cleanup_conds(&if_true)),
                        Some(false) => result.extend(cleanup_conds(&if_false)),
                        None => {
                            result.push(Expr::node3(
                                "if",
                                cond,
                                Expr::node("seq", cleanup_conds(&if_true)),
                                Expr::node("seq", cleanup_conds(&if_false)),
                            ));
                        }
                    }
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();

                    match eval_bool_simple(&cond) {
                        Some(false) => {
                            // Loop never executes.
                        }
                        Some(true) => {
                            let mut new_ch = vec![Expr::Bool(true), Expr::node("seq", cleanup_conds(&body))];
                            new_ch.extend(rest);
                            result.push(Expr::Node("while".to_string(), new_ch));
                        }
                        None => {
                            let mut new_ch = vec![cond, Expr::node("seq", cleanup_conds(&body))];
                            new_ch.extend(rest);
                            result.push(Expr::Node("while".to_string(), new_ch));
                        }
                    }
                }
            }
            _ => result.push(line.clone()),
        }
    }

    result
}

/// Eliminate dominated conditions: if we're inside `if A`, then any nested
/// `if A` is always true and can be inlined.
fn eliminate_dominated_conds(trace: &[Expr], known_true: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                let if_true = extract_seq(ch.get(1));
                let if_false = extract_seq(ch.get(2));

                // Check if this condition is known to be true.
                if known_true.contains(&cond) {
                    result.extend(eliminate_dominated_conds(&if_true, known_true));
                    continue;
                }

                // Check if the negation is known true (condition is false).
                // (not implemented for now — would need negation matching)

                // Recurse with the condition added to known_true.
                let mut inner_true = known_true.to_vec();
                inner_true.push(cond.clone());
                let new_true = eliminate_dominated_conds(&if_true, &inner_true);
                let new_false = eliminate_dominated_conds(&if_false, known_true);

                result.push(Expr::node3(
                    "if",
                    cond,
                    Expr::node("seq", new_true),
                    Expr::node("seq", new_false),
                ));
            }
        } else {
            result.push(line.clone());
        }
    }

    result
}

/// Simple boolean evaluation: returns Some(true/false) if decidable, None otherwise.
fn eval_bool_simple(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Val(v) => Some(!v.is_zero()),
        Expr::Bool(b) => Some(*b),
        Expr::Node(op, ch) => {
            match op.as_str() {
                "iszero" if ch.len() == 1 => {
                    eval_bool_simple(&ch[0]).map(|b| !b)
                }
                "bool" if ch.len() == 1 => {
                    eval_bool_simple(&ch[0])
                }
                "or" => {
                    let mut result = false;
                    for c in ch {
                        match eval_bool_simple(c) {
                            Some(b) => result = result || b,
                            None => return None,
                        }
                    }
                    Some(result)
                }
                "and" if ch.len() == 2 => {
                    match (eval_bool_simple(&ch[0]), eval_bool_simple(&ch[1])) {
                        (Some(a), Some(b)) => Some(a && b),
                        _ => None,
                    }
                }
                "eq" if ch.len() == 2 => {
                    // Tautology: eq(X, X) → true.
                    if ch[0] == ch[1] {
                        return Some(true);
                    }
                    if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                        arith::eval_concrete(op, &[a, b]).map(|r| !r.is_zero())
                    } else {
                        None
                    }
                }
                "lt" | "gt" | "slt" | "sgt" if ch.len() == 2 => {
                    if let (Some(a), Some(b)) = (ch[0].as_val(), ch[1].as_val()) {
                        arith::eval_concrete(op, &[a, b]).map(|r| !r.is_zero())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// ===========================================================================
// Split packed setmem/store
// ===========================================================================

/// Split `setmem` of `or(mask_shl(...), mask_shl(...))` into individual writes.
fn split_setmem(line: &Expr) -> Vec<Expr> {
    if line.opcode() != Some("setmem") {
        return vec![line.clone()];
    }
    if let Some(ch) = line.children() {
        if ch.len() == 2 && ch[1].opcode() == Some("or") {
            if let Some(or_terms) = ch[1].children() {
                let mut splits = Vec::new();
                let mut can_split = true;

                for term in or_terms {
                    if term.opcode() == Some("mask_shl") {
                        if let Some(mch) = term.children() {
                            if mch.len() == 4 {
                                if let (Some(sz), Some(off), Some(_sh)) =
                                    (mch[0].as_val(), mch[1].as_val(), mch[2].as_val())
                                {
                                    splits.push((sz, off, mch[3].clone()));
                                    continue;
                                }
                            }
                        }
                        can_split = false;
                    } else {
                        can_split = false;
                    }
                }

                if can_split && splits.len() > 1 {
                    let mem_range = &ch[0];
                    return splits
                        .into_iter()
                        .map(|(size, offset, val)| {
                            let byte_off = offset / U256::from(8u64);
                            let byte_size = size / U256::from(8u64);
                            if let Some(rch) = mem_range.children() {
                                if mem_range.opcode() == Some("range") && rch.len() == 2 {
                                    let new_offset = algebra::add_op(rch[0].clone(), Expr::Val(byte_off));
                                    return Expr::node2(
                                        "setmem",
                                        Expr::node2("range", new_offset, Expr::Val(byte_size)),
                                        val,
                                    );
                                }
                            }
                            Expr::node2("setmem", mem_range.clone(), val)
                        })
                        .collect();
                }
            }
        }
    }
    vec![line.clone()]
}

/// Split storage writes with packed or-values.
fn split_store(line: &Expr) -> Vec<Expr> {
    if line.opcode() != Some("store") {
        return vec![line.clone()];
    }
    // For now, pass through — full storage splitting requires more context.
    vec![line.clone()]
}

// ===========================================================================
// Loop optimizations
// ===========================================================================

/// Detect loops that are memory copy/zero patterns and replace with setmem.
fn loop_to_setmem(line: &Expr) -> Vec<Expr> {
    if line.opcode() != Some("while") {
        return vec![line.clone()];
    }

    if let Some(ch) = line.children() {
        let body = extract_seq(ch.get(1));

        // Pattern: while(cond) { setmem(range(idx, 32), val); continue(...) }
        if body.len() == 2
            && body[0].opcode() == Some("setmem")
            && body[1].opcode() == Some("continue")
        {
            if let Some(sm_ch) = body[0].children() {
                if sm_ch.len() == 2 && sm_ch[0].opcode() == Some("range") {
                    if let Some(rch) = sm_ch[0].children() {
                        if rch.len() == 2 && rch[1] == Expr::val(32) {
                            // Check if the memory value is zero → memzero pattern.
                            if sm_ch[1].is_zero() {
                                // Could compute the range from loop vars, but for now
                                // leave as-is and let the loop remain.
                            }
                        }
                    }
                }
            }
        }
    }

    vec![line.clone()]
}

// ===========================================================================
// SHA3 memory resolution
// ===========================================================================

/// Resolve `sha3(mem(range(P, N)))` patterns by tracking 32-byte memory writes.
///
/// When the EVM computes a mapping slot, it does:
///   MSTORE(0, key)       → setmem(range(0, 32), key)
///   MSTORE(32, slot)     → setmem(range(32, 32), slot_number)
///   SHA3(0, 64)          → sha3(mem(range(0, 64)))
///
/// This pass tracks the writes and decomposes the SHA3 read into:
///   sha3(key, slot_number)
///
/// which the sparser can then resolve to `map(key, loc(slot))`.
fn resolve_sha3_mem(trace: &[Expr]) -> Trace {
    use std::collections::HashMap;

    // Memory model: maps 32-byte-aligned positions to values.
    let mut mem_slots: HashMap<u64, Expr> = HashMap::new();
    let mut result = Trace::new();

    for line in trace {
        // Track setmem(range(pos, 32), val) writes.
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Some(rch) = ch[0].children() {
                        if ch[0].opcode() == Some("range") && rch.len() == 2 {
                            if let (Some(pos), Some(size)) = (rch[0].as_u64(), rch[1].as_u64()) {
                                if size == 32 && pos % 32 == 0 {
                                    // Don't track writes whose value depends on memory.
                                    if !expr_uses_mem(&ch[1]) {
                                        mem_slots.insert(pos, ch[1].clone());
                                        // Keep the setmem in the trace (cleanup_mems will
                                        // remove it later if it becomes dead).
                                        result.push(line.clone());
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // For if/while, recurse into branches (with fresh memory models).
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = resolve_sha3_in_expr(&ch[0], &mem_slots);
                    let if_true = ch.get(1)
                        .and_then(|e| e.children())
                        .map(|t| resolve_sha3_mem(t))
                        .unwrap_or_default();
                    let if_false = ch.get(2)
                        .and_then(|e| e.children())
                        .map(|t| resolve_sha3_mem(t))
                        .unwrap_or_default();
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", if_true),
                        Expr::node("seq", if_false),
                    ));
                    // After branches, invalidate memory (both branches may write).
                    mem_slots.clear();
                } else {
                    result.push(line.clone());
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = resolve_sha3_in_expr(&ch[0], &mem_slots);
                    let body = ch.get(1)
                        .and_then(|e| e.children())
                        .map(|t| resolve_sha3_mem(t))
                        .unwrap_or_default();
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                    mem_slots.clear();
                } else {
                    result.push(line.clone());
                }
            }
            _ => {
                // Resolve SHA3 memory references in this expression.
                let resolved = resolve_sha3_in_expr(line, &mem_slots);
                // If a setmem value was resolved (sha3 mem refs eliminated),
                // retroactively track it in mem_slots for subsequent reads.
                if resolved.opcode() == Some("setmem") {
                    if let Some(rch) = resolved.children() {
                        if rch.len() == 2 {
                            if let Some(range_ch) = rch[0].children() {
                                if rch[0].opcode() == Some("range") && range_ch.len() == 2 {
                                    if let (Some(pos), Some(size)) = (range_ch[0].as_u64(), range_ch[1].as_u64()) {
                                        if size == 32 && pos % 32 == 0 && !expr_uses_mem(&rch[1]) {
                                            mem_slots.insert(pos, rch[1].clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                result.push(resolved);
            }
        }
    }

    result
}

/// Resolve `sha3(mem(range(P, N)))` using the tracked memory slots.
fn resolve_sha3_in_expr(expr: &Expr, mem_slots: &std::collections::HashMap<u64, Expr>) -> Expr {
    // Bottom-up: first resolve children, then check this node.
    let expr = match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children.iter()
                .map(|c| resolve_sha3_in_expr(c, mem_slots))
                .collect();
            Expr::Node(op.clone(), new_ch)
        }
        other => other.clone(),
    };

    // Check for sha3(mem(range(P, N))) pattern.
    if expr.opcode() == Some("sha3") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 && ch[0].opcode() == Some("mem") {
                if let Some(mch) = ch[0].children() {
                    if mch.len() == 1 && mch[0].opcode() == Some("range") {
                        if let Some(rch) = mch[0].children() {
                            if rch.len() == 2 {
                                if let (Some(pos), Some(size)) = (rch[0].as_u64(), rch[1].as_u64()) {
                                    if size > 0 && size % 32 == 0 {
                                        let num_slots = size / 32;
                                        let mut values = Vec::new();
                                        let mut all_found = true;
                                        for i in 0..num_slots {
                                            let slot_pos = pos + i * 32;
                                            if let Some(val) = mem_slots.get(&slot_pos) {
                                                values.push(val.clone());
                                            } else {
                                                all_found = false;
                                                break;
                                            }
                                        }
                                        if all_found && !values.is_empty() {
                                            if values.len() == 1 {
                                                return Expr::node1("sha3", values.remove(0));
                                            }
                                            return Expr::Node("sha3".into(), values);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Also check for setvar(_N, sha3(mem(...))) — inline resolution.
    if expr.opcode() == Some("setvar") {
        if let Some(ch) = expr.children() {
            if ch.len() == 2 {
                let resolved_val = resolve_sha3_in_expr(&ch[1], mem_slots);
                if resolved_val != ch[1] {
                    return Expr::node2("setvar", ch[0].clone(), resolved_val);
                }
            }
        }
    }

    expr
}

// ===========================================================================
// Revert string decoding
// ===========================================================================

/// Decode revert reason strings from memory write patterns within revert branches.
///
/// Handles the Solidity pattern where setmem writes (using symbolic base offsets
/// like the free memory pointer) are followed by a revert reading from the same base.
/// Matches writes by their offset relative to the base address and reconstructs
/// ABI-encoded Error(string) into a `data()` node for the prettifier to decode.
fn decode_revert_strings(trace: &[Expr]) -> Trace {
    // Build a global variable map from the entire trace (all scopes).
    let mut var_map = std::collections::HashMap::new();
    collect_var_defs(trace, &mut var_map);

    decode_revert_strings_inner(trace, &var_map)
}

/// Collect setvar definitions from a trace, recursing into branches.
fn collect_var_defs(trace: &[Expr], var_map: &mut std::collections::HashMap<String, Expr>) {
    for line in trace {
        if line.opcode() == Some("setvar") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    if let Expr::Atom(name) = &ch[0] {
                        var_map.insert(name.clone(), ch[1].clone());
                    }
                }
            }
        }
        // Recurse into branches.
        if let Some(ch) = line.children() {
            for c in ch {
                if c.opcode() == Some("seq") {
                    if let Some(seq_ch) = c.children() {
                        collect_var_defs(seq_ch, var_map);
                    }
                }
            }
        }
    }
}

fn decode_revert_strings_inner(trace: &[Expr], var_map: &std::collections::HashMap<String, Expr>) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", decode_revert_branch(&if_true, var_map)),
                        Expr::node("seq", decode_revert_branch(&if_false, var_map)),
                    ));
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", decode_revert_branch(&body, var_map))];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => result.push(line.clone()),
        }
    }

    result
}

/// Process a branch looking for setmem+revert patterns.
///
/// Collects setmem writes by their relative offset from a common base expression,
/// then when a revert is found, tries to reconstruct the Error(string) from those writes.
fn decode_revert_branch(trace: &[Expr], var_map: &std::collections::HashMap<String, Expr>) -> Trace {
    // First recurse into nested branches.
    let trace = decode_revert_strings_inner(trace, var_map);

    // Resolve a variable reference to its value using the global var_map.
    let resolve_base = |expr: &Expr| -> Expr {
        if expr.opcode() == Some("var") {
            if let Some(ch) = expr.children() {
                if let Some(Expr::Atom(name)) = ch.first() {
                    if let Some(val) = var_map.get(name) {
                        return val.clone();
                    }
                }
            }
        }
        expr.clone()
    };

    // Collect setmem writes: maps (resolved_base, delta) → value for 32-byte writes.
    let mut writes: Vec<(Expr, u64, Expr)> = Vec::new();

    for line in &trace {
        if line.opcode() == Some("setmem") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 && ch[0].opcode() == Some("range") {
                    if let Some(rch) = ch[0].children() {
                        if rch.len() == 2 && rch[1].as_u64() == Some(32) {
                            let (base, delta) = decompose_add(&rch[0]);
                            let resolved = resolve_base(&base);
                            writes.push((resolved, delta, ch[1].clone()));
                        }
                    }
                }
            }
        }
    }

    if writes.is_empty() {
        return trace;
    }

    // Find revert nodes and try to decode their string reasons.
    let mut result = Trace::new();
    for line in &trace {
        if line.opcode() == Some("revert") {
            if let Some(decoded) = try_decode_revert_from_writes(line, &writes, &resolve_base) {
                result.push(decoded);
                continue;
            }
        }
        result.push(line.clone());
    }

    result
}

/// Decompose an expression into (base, constant_offset).
/// E.g., `add(base, 32)` → (base, 32); `add(base, 64)` → (base, 64); `base` → (base, 0).
fn decompose_add(expr: &Expr) -> (Expr, u64) {
    if expr.opcode() == Some("add") {
        if let Some(ch) = expr.children() {
            if ch.len() >= 2 {
                // Check if the last child is a constant.
                if let Some(v) = ch.last().and_then(|e| e.as_u64()) {
                    // Base is everything except the constant.
                    if ch.len() == 2 {
                        return (ch[0].clone(), v);
                    }
                    let base = Expr::Node("add".to_string(), ch[..ch.len()-1].to_vec());
                    return (base, v);
                }
                // Check if the first child is a constant.
                if let Some(v) = ch[0].as_u64() {
                    if ch.len() == 2 {
                        return (ch[1].clone(), v);
                    }
                    let base = Expr::Node("add".to_string(), ch[1..].to_vec());
                    return (base, v);
                }
            }
        }
    }
    // No constant offset found.
    (expr.clone(), 0)
}

/// Try to decode a revert from collected memory writes.
///
/// Handles Solidity ABI Error(string) layout with 4-byte selector prefix:
///   offset 0: selector << 224 (MSTORE writes 32 bytes; selector in top 4)
///   offset 4: ABI offset (32)
///   offset 36: string length
///   offset 68: first 32 bytes of string data
///   offset 100: next 32 bytes (if any)
///   ...
fn try_decode_revert_from_writes<F>(revert: &Expr, writes: &[(Expr, u64, Expr)], resolve: &F) -> Option<Expr>
where F: Fn(&Expr) -> Expr,
{
    let ch = revert.children()?;
    if ch.len() != 1 { return None; }
    let mem_arg = &ch[0];

    // revert(mem(range(offset, size)))
    if mem_arg.opcode() != Some("mem") { return None; }
    let mch = mem_arg.children()?;
    if mch.len() != 1 || mch[0].opcode() != Some("range") { return None; }
    let rch = mch[0].children()?;
    if rch.len() != 2 { return None; }

    let revert_base_expr = &rch[0];
    let (rb, rd) = decompose_add(revert_base_expr);
    let revert_base = resolve(&rb);

    // Find writes with the same resolved base expression, collecting by adjusted delta.
    let mut slots: std::collections::BTreeMap<u64, &Expr> = std::collections::BTreeMap::new();
    for (base, delta, val) in writes {
        if *base == revert_base && *delta >= rd {
            slots.insert(*delta - rd, val);
        }
    }

    if slots.is_empty() { return None; }

    // Check for Error(string) selector at delta 0.
    let selector_shifted = U256::from(0x08c379a0u64) << 224;
    let word0 = slots.get(&0)?;
    let v0 = word0.as_val()?;
    if v0 != selector_shifted { return None; }

    // Solidity ABI layout: selector at +0, offset at +4, length at +36, data at +68.
    let abi_offset = slots.get(&4)?.as_u64()?;
    if abi_offset != 32 { return None; }
    let str_len = slots.get(&36)?.as_u64()? as usize;
    if str_len == 0 || str_len > 1024 { return None; }

    // Collect string data words starting at delta 68.
    let mut bytes = Vec::new();
    let num_chunks = (str_len + 31) / 32;
    for i in 0..num_chunks {
        let delta = 68 + (i as u64) * 32;
        if let Some(val) = slots.get(&delta) {
            if let Some(v) = val.as_val() {
                for j in (0..32).rev() {
                    let byte = ((v >> (j * 8)) & U256::from(0xFFu64)).low_u64() as u8;
                    bytes.push(byte);
                }
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    bytes.truncate(str_len);

    // Check if all bytes are printable ASCII.
    if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        // Build data(0x08c379a0, 32, len, chunks...) node for the prettifier.
        let mut data_ch = vec![
            Expr::Val(U256::from(0x08c379a0u64)),
            Expr::val(32),
            Expr::val(str_len as u64),
        ];
        for chunk in bytes.chunks(32) {
            let mut val = U256::zero();
            for (j, &b) in chunk.iter().enumerate() {
                val |= U256::from(b as u64) << ((31 - j) * 8);
            }
            data_ch.push(Expr::Val(val));
        }
        Some(Expr::node1("revert", Expr::Node("data".into(), data_ch)))
    } else {
        None
    }
}

// ===========================================================================
// Readability improvements
// ===========================================================================

fn readability_pass(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));

                    // Normalize: if the false branch is a single revert,
                    // flip to put the revert in the true branch for require() style.
                    if crate::whiles::is_revert_public(&if_false) && !crate::whiles::is_revert_public(&if_true) {
                        result.push(Expr::node3(
                            "if",
                            cond.is_zero_wrap(),
                            Expr::node("seq", readability_pass(&if_false)),
                            Expr::node("seq", readability_pass(&if_true)),
                        ));
                    } else {
                        result.push(Expr::node3(
                            "if",
                            cond,
                            Expr::node("seq", readability_pass(&if_true)),
                            Expr::node("seq", readability_pass(&if_false)),
                        ));
                    }
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", readability_pass(&body))];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => result.push(line.clone()),
        }
    }

    result
}

/// Resolve `return mem[off len X]` and `log(..., mem[off len X], ...)` by matching
/// against `setmem(range(off, 32), val)` writes in the same scope.
/// Matches by offset expression equality (handles both concrete and symbolic offsets).
/// Only resolves when the mem read has a non-matching length (to avoid interfering
/// with exact matching in cleanup_mems).
/// Resolve symbolic-length mem reads in return/log nodes using setmem writes
/// that are still present in the trace. All setmem nodes are preserved.
/// Runs BEFORE cleanup_mems so the writes are available.
// (resolve_return_log_before_cleanup and supporting functions removed —
//  symbolic-length return/log resolution is now handled by replace_mem_in_expr_fill
//  inside cleanup_mems via replace_mem_in_trace.)

/// Extract seq children (used by cleanup_vars etc.)
fn extract_seq(expr: Option<&Expr>) -> Vec<Expr> {
    match expr {
        Some(Expr::Node(op, ch)) if op == "seq" => ch.clone(),
        Some(e) => vec![e.clone()],
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplify_double_negation() {
        let e = Expr::node1("iszero", Expr::node1("iszero", Expr::atom("x")));
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::node1("bool", Expr::atom("x")));
    }

    #[test]
    fn test_simplify_eq_zero() {
        let e = Expr::node2("eq", Expr::atom("x"), Expr::zero());
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::node1("iszero", Expr::atom("x")));
    }

    #[test]
    fn test_simplify_add_flatten() {
        let e = Expr::node2("add", Expr::val(1), Expr::node2("add", Expr::val(2), Expr::val(3)));
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::val(6));
    }

    #[test]
    fn test_simplify_add_cancel() {
        // x + (-1)*x → 0
        let x = Expr::atom("x");
        let neg_x = Expr::node2("mul", Expr::Val(UINT_256_MAX), x.clone());
        let e = Expr::node2("add", x, neg_x);
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::zero());
    }

    #[test]
    fn test_simplify_mul_zero() {
        let e = Expr::node2("mul", Expr::zero(), Expr::atom("x"));
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::zero());
    }

    #[test]
    fn test_simplify_mul_one() {
        let e = Expr::node2("mul", Expr::val(1), Expr::atom("x"));
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::atom("x"));
    }

    #[test]
    fn test_simplify_mask_identity() {
        let e = Expr::Node("mask_shl".into(), vec![
            Expr::val(256), Expr::zero(), Expr::zero(), Expr::atom("x"),
        ]);
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::atom("x"));
    }

    #[test]
    fn test_simplify_and_mask() {
        // and(0xFF, x) → mask_shl(8, 0, 0, x)
        let e = Expr::node2("and", Expr::val(0xFF), Expr::atom("x"));
        let s = simplify_exp(&e);
        assert_eq!(s.opcode(), Some("mask_shl"));
    }

    #[test]
    fn test_simplify_or_with_zero() {
        let e = Expr::node2("or", Expr::atom("x"), Expr::zero());
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::atom("x"));
    }

    #[test]
    fn test_simplify_div_by_one() {
        let e = Expr::node2("div", Expr::atom("x"), Expr::val(1));
        let s = simplify_exp(&e);
        assert_eq!(s, Expr::atom("x"));
    }

    #[test]
    fn test_simplify_mod_power_of_2() {
        // mod(x, 256) → mask_shl(8, 0, 0, x)
        let e = Expr::node2("mod", Expr::atom("x"), Expr::val(256));
        let s = simplify_exp(&e);
        assert_eq!(s.opcode(), Some("mask_shl"));
    }

    #[test]
    fn test_eval_bool_simple() {
        assert_eq!(eval_bool_simple(&Expr::val(1)), Some(true));
        assert_eq!(eval_bool_simple(&Expr::val(0)), Some(false));
        assert_eq!(eval_bool_simple(&Expr::Bool(true)), Some(true));
        assert_eq!(eval_bool_simple(&Expr::node1("iszero", Expr::val(0))), Some(true));
        assert_eq!(eval_bool_simple(&Expr::node1("iszero", Expr::val(5))), Some(false));
        assert_eq!(eval_bool_simple(&Expr::atom("x")), None);
    }

    #[test]
    fn test_cleanup_vars_inline() {
        // setvar(_1, 42) followed by add(var(_1), 1) → add(42, 1)
        let trace = vec![
            Expr::node2("setvar", Expr::atom("_1"), Expr::val(42)),
            Expr::node2("add", Expr::node1("var", Expr::atom("_1")), Expr::val(1)),
        ];
        let result = cleanup_vars(&trace, &[]);
        // The setvar should be removed and var(_1) replaced with 42.
        assert!(!result.iter().any(|e| e.opcode() == Some("setvar")));
    }

    #[test]
    fn test_cleanup_conds_true() {
        let trace = vec![Expr::node3(
            "if",
            Expr::val(1),
            Expr::node("seq", vec![Expr::atom("a")]),
            Expr::node("seq", vec![Expr::atom("b")]),
        )];
        let result = cleanup_conds(&trace);
        assert_eq!(result, vec![Expr::atom("a")]);
    }

    #[test]
    fn test_cleanup_conds_false() {
        let trace = vec![Expr::node3(
            "if",
            Expr::val(0),
            Expr::node("seq", vec![Expr::atom("a")]),
            Expr::node("seq", vec![Expr::atom("b")]),
        )];
        let result = cleanup_conds(&trace);
        assert_eq!(result, vec![Expr::atom("b")]);
    }

    #[test]
    fn test_simplify_trace_converges() {
        let trace = vec![
            Expr::node2("setvar", Expr::atom("_1"), Expr::val(42)),
            Expr::node2("add", Expr::node1("var", Expr::atom("_1")), Expr::val(1)),
        ];
        let result = simplify_trace(&trace, 5, None);
        // After simplification, the add(42, 1) should become 43.
        assert!(result.iter().any(|e| e == &Expr::val(43)));
    }

    #[test]
    fn test_apply_mask() {
        // Extract 8 bits at offset 0 from 0xFF → 0xFF
        assert_eq!(
            apply_mask(U256::from(0xFFu64), U256::from(8u64), U256::zero(), U256::zero()),
            U256::from(0xFFu64)
        );
        // Extract 8 bits at offset 8 from 0xFF00 → 0xFF
        assert_eq!(
            apply_mask(U256::from(0xFF00u64), U256::from(8u64), U256::from(8u64), U256::zero()),
            U256::from(0xFFu64)
        );
    }

    #[test]
    fn test_ranges_overlap() {
        let r1 = Expr::node2("range", Expr::val(0), Expr::val(32));
        let r2 = Expr::node2("range", Expr::val(16), Expr::val(32));
        assert!(ranges_might_overlap(&r1, &r2));

        let r3 = Expr::node2("range", Expr::val(64), Expr::val(32));
        assert!(!ranges_might_overlap(&r1, &r3));
    }
}
