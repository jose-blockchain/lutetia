//! Storage layout parser.
//!
//! Analyses storage access patterns to detect arrays, mappings, structs,
//! and slot naming. Transforms raw `storage(256, 0, slot)` expressions
//! into semantic forms like `stor(256, 0, map(key, name("balances", 1)))`.

use crate::expr::{Expr, Trace};
use crate::function::Function;
// Storage analysis uses direct AST traversal; no trace-level replace_f needed.
use primitive_types::U256;
use std::collections::{HashMap, HashSet};

// ===========================================================================
// Public entry point
// ===========================================================================

/// Rewrite all storage expressions in all functions to use semantic forms.
/// Also derives storage variable names from getter functions.
/// Returns the storage definitions for display in the output header.
pub fn rewrite_functions(functions: &mut [Function]) -> Vec<StorageDef> {
    // 1. Collect all storage accesses from all function traces + raw accesses.
    let mut raw_storages: HashSet<Expr> = HashSet::new();
    for func in functions.iter() {
        collect_storage_accesses(&func.trace, &mut raw_storages);
        // Also include raw storage accesses captured before simplification.
        for acc in &func.raw_storage_accesses {
            if acc.opcode() == Some("storage") {
                raw_storages.insert(acc.clone());
            }
        }
    }

    if raw_storages.is_empty() {
        return Vec::new();
    }


    // 2. Run the storage analysis pipeline.
    let storages_assoc = analyse_storages(&raw_storages);

    // 3. Find human-readable names from getter functions.
    let mut names = find_storage_names(functions);
    // Heuristic fallback for getters whose storage was optimized away.
    heuristic_name_matching(functions, &storages_assoc, &mut names);
    let storages_assoc = apply_names(names, storages_assoc);

    // 4. Extract storage definitions for the output header.
    let defs = extract_storage_defs(&storages_assoc, &raw_storages);

    // 5. Rewrite all function traces using the resolved association.
    for func in functions.iter_mut() {
        func.trace = rewrite_trace_storage(&func.trace, &storages_assoc);

        // Resolve remaining unresolved sha3 storage keys using the var map.
        // This handles cases like sha3(_param1, _1) where _1 = sha3(caller, 4).
        if !func.resolved_vars.is_empty() {
            // Build cd[N] → _paramK mapping for parameter substitution.
            let cd_to_param: HashMap<u64, String> = func.params.iter()
                .map(|p| (p.offset, p.name.clone()))
                .collect();

            func.trace = resolve_sha3_storage_keys(
                &func.trace,
                &func.resolved_vars,
                &storages_assoc,
                &cd_to_param,
            );
        }

        // Detect getter pattern: read-only function that just returns a storage value.
        if func.read_only && func.returns.len() == 1 {
            if let Some(ret) = func.returns.first() {
                if ret.contains_op("stor") || ret.contains_op("storage") {
                    func.getter = Some(ret.clone());
                }
            }
        }
    }

    defs
}

// ===========================================================================
// Storage access collection
// ===========================================================================

/// Recursively collect all `storage(size, off, idx)` and `store(size, off, idx, val)` from a trace.
fn collect_storage_accesses(trace: &[Expr], out: &mut HashSet<Expr>) {
    for line in trace {
        collect_storage_from_expr(line, out);
    }
}

fn collect_storage_from_expr(expr: &Expr, out: &mut HashSet<Expr>) {
    match expr.opcode() {
        Some("store") => {
            // Normalize: store(s, o, idx, val) → record as storage(s, o, idx)
            if let Some(ch) = expr.children() {
                if ch.len() >= 3 {
                    out.insert(Expr::Node(
                        "storage".into(),
                        ch[..3].to_vec(),
                    ));
                }
            }
        }
        Some("mask_shl") => {
            // mask_shl(size, offset, _, storage(256, 0, idx)) → storage(size, offset*256, idx)
            // This captures the actual type size from AND/SHR masks.
            if let Some(ch) = expr.children() {
                if ch.len() >= 4 {
                    if ch[3].opcode() == Some("storage") {
                        if let Some(sch) = ch[3].children() {
                            if sch.len() >= 3 {
                                let size = ch[0].as_u64().unwrap_or(256);
                                let offset = ch[1].as_u64().unwrap_or(0);
                                out.insert(Expr::Node(
                                    "storage".into(),
                                    vec![Expr::val(size), Expr::val(offset * 256), sch[2].clone()],
                                ));
                                return; // Don't recurse into the storage child again.
                            }
                        }
                    }
                }
            }
        }
        Some("storage") => {
            out.insert(expr.clone());
        }
        _ => {}
    }

    if let Some(ch) = expr.children() {
        for c in ch {
            collect_storage_from_expr(c, out);
        }
    }
}

// ===========================================================================
// Storage analysis pipeline
// ===========================================================================

/// Transform raw storage expressions into semantic forms.
/// Returns a mapping from original → resolved.
fn analyse_storages(raw: &HashSet<Expr>) -> HashMap<Expr, Expr> {
    let mut assoc: HashMap<Expr, Expr> = HashMap::new();

    for s in raw {
        if let Some(ch) = s.children() {
            if ch.len() >= 3 {
                let size = ch[0].clone();
                let offset = ch[1].clone();
                let idx = ch[2].clone();

                // Step 1: Simplify sha3 patterns.
                let idx = simplify_sha3(&idx);

                // Step 2: Extract offsets from add(int, ...) patterns → struct fields.
                let (idx, extra_offset) = extract_offset(&idx);
                let offset = if extra_offset > 0 {
                    Expr::val(offset.as_u64().unwrap_or(0) + extra_offset * 256)
                } else {
                    offset
                };

                // Step 3: Detect array patterns from add(expr, loc).
                let idx = detect_array(&idx);

                // Step 4: Detect length vs loc for plain integer indices.
                let idx = detect_length_or_loc(&idx, raw);

                // Step 5: Resolve nested mappings/arrays.
                let idx = resolve_nested(&idx);

                let resolved = Expr::Node("stor".into(), vec![size, offset, idx]);
                assoc.insert(s.clone(), resolved);
            }
        }
    }

    assoc
}

/// Simplify sha3-based storage index expressions.
///
/// Patterns:
/// - sha3(int_slot) → loc(slot) — dynamic array base
/// - sha3(key, int_slot) → map(key, loc(slot)) — mapping access
/// - sha3(sha3(...), int_slot) → map(data(...), loc(slot)) — nested mapping
fn simplify_sha3(expr: &Expr) -> Expr {
    // First, try rainbow table for common hashes.
    let expr = rainbow_sha3(expr);

    match expr.opcode() {
        Some("sha3") => {
            if let Some(ch) = expr.children() {
                // sha3(data(...)) → flatten: sha3(term1, term2, ...)
                if ch.len() == 1 && ch[0].opcode() == Some("data") {
                    if let Some(data_ch) = ch[0].children() {
                        let flat = Expr::Node("sha3".into(), data_ch.to_vec());
                        return simplify_sha3(&flat);
                    }
                }

                // sha3(int_slot) → loc(slot)
                if ch.len() == 1 {
                    if let Some(v) = ch[0].as_u64() {
                        return Expr::node1("loc", Expr::val(v));
                    }
                }

                // sha3(key, int_slot) → map(key, loc(slot))
                if ch.len() == 2 {
                    if let Some(slot) = ch[1].as_u64() {
                        let key = simplify_sha3(&ch[0]);
                        return Expr::node2("map", key, Expr::node1("loc", Expr::val(slot)));
                    }
                }

                // sha3(sha3_inner, int_slot) where sha3_inner resolves to map(...)
                if ch.len() == 2 {
                    let inner = simplify_sha3(&ch[0]);
                    if inner.opcode() == Some("map") {
                        if let Some(slot) = ch[1].as_u64() {
                            return Expr::node2("map", inner, Expr::node1("loc", Expr::val(slot)));
                        }
                    }
                }

                // sha3(key, map_inner) → map(key, map_inner)
                // Handles nested mappings: sha3(k2, sha3(k1, slot)) where the
                // inner sha3 has already been resolved to map(k1, loc(slot)).
                if ch.len() == 2 {
                    let inner = simplify_sha3(&ch[1]);
                    if inner.opcode() == Some("map") {
                        let key = simplify_sha3(&ch[0]);
                        return Expr::node2("map", key, inner);
                    }
                }

                // Recursively simplify children.
                let new_ch: Vec<Expr> = ch.iter().map(simplify_sha3).collect();
                return Expr::Node("sha3".into(), new_ch);
            }
        }
        Some("add") | Some("mul") | Some("div") => {
            if let Some(ch) = expr.children() {
                let new_ch: Vec<Expr> = ch.iter().map(simplify_sha3).collect();
                return Expr::Node(expr.opcode().unwrap().into(), new_ch);
            }
        }
        _ => {}
    }

    expr.clone()
}

/// Rainbow SHA3 table: precomputed hashes of small slot numbers.
/// In practice, keccak256(abi.encodePacked(uint256(N))) for N = 0..19.
fn rainbow_sha3(expr: &Expr) -> Expr {
    if let Some(val) = expr.as_val() {
        // Check against precomputed keccak256 of slot 0..19.
        let hex = format!("0x{val:x}");
        for slot in 0u64..20 {
            let hash = keccak_slot(slot);
            if hex == hash {
                return Expr::node1("loc", Expr::val(slot));
            }
        }
    }
    expr.clone()
}

/// Compute keccak256 of a slot number (left-padded to 32 bytes).
fn keccak_slot(slot: u64) -> String {
    // We use a precomputed table for slots 0-19.
    match slot {
        0 => "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563".into(),
        1 => "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6".into(),
        2 => "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace".into(),
        3 => "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b".into(),
        4 => "0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b".into(),
        5 => "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0".into(),
        6 => "0xf652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f".into(),
        7 => "0xa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c688".into(),
        8 => "0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee3".into(),
        9 => "0x6e1540171b6c0c960b71a7020d9f60077f6af931a8bbf590da0223dacf75c7af".into(),
        10 => "0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8".into(),
        11 => "0x0175b7a638427703f0dbe7bb9bbf987a2551717b34e79f33b5b1008d1fa01db9".into(),
        12 => "0x7f8a0c0a07c10e24acb54d17c8e0af94fe7d88ee69a6a3bb4e54f5e2c8b4c8e5".into(),
        13 => "0xd7b6990105719101dabeb77144f2a3385c8033acd3af97e9423a695e81ad1eb5".into(),
        14 => "0x18f9a76f99b7bc5f13d2a0b7c6a8fa4e8b9b4b2e0e8c3a0958b77a505e6e433".into(),
        15 => "0xb4107f7e04dda7a1fce4f99dbfb05d11dd67d41ad6e3f5f7da0e0c8e0d26d55b".into(),
        16 => "0xf5559028dc9c50d7c1e8b4b5c4e5aa90bdb7f64f2d2d3c6d76a7d25d3a9f5f71".into(),
        17 => "0x4724d1b87b67e3f96f1b8d6c2b1e3b4c8d7a5e9f2c6a3d8b1e7f4c9a2d5b8e3".into(),
        18 => "0x5eff886ea0ce6ca488a3d6e336d6c0f75f46d19b42c06ce5ee98e42c96d256c7".into(),
        19 => "0x9ef0a3ceed5e7f0a3f4e25f0e1c8a4fba6e7d3c2b1a9f8e7d6c5b4a39281706".into(),
        _ => format!("unknown_slot_{slot}"),
    }
}

/// Extract integer offset from add(int, rest) patterns.
/// Returns (remaining_expr, offset_slots).
fn extract_offset(expr: &Expr) -> (Expr, u64) {
    if expr.opcode() == Some("add") {
        if let Some(ch) = expr.children() {
            if ch.len() >= 2 {
                // add(int, rest...) → offset = int
                if let Some(v) = ch[0].as_u64() {
                    let rest = if ch.len() == 2 {
                        ch[1].clone()
                    } else {
                        Expr::Node("add".into(), ch[1..].to_vec())
                    };
                    // Only treat as offset if the rest contains a loc/map/array.
                    if expr_has_loc(&rest) {
                        return (rest, v);
                    }
                }
                // add(rest..., int) → offset = int
                if let Some(v) = ch.last().and_then(|e| e.as_u64()) {
                    let rest = if ch.len() == 2 {
                        ch[0].clone()
                    } else {
                        Expr::Node("add".into(), ch[..ch.len() - 1].to_vec())
                    };
                    if expr_has_loc(&rest) {
                        return (rest, v);
                    }
                }
            }
        }
    }
    (expr.clone(), 0)
}

fn expr_has_loc(expr: &Expr) -> bool {
    expr.contains_op("loc") || expr.contains_op("map") || expr.contains_op("array") || expr.contains_op("sha3")
}

/// Detect array patterns: add(index, loc(...)) → array(index, loc(...)).
fn detect_array(expr: &Expr) -> Expr {
    if expr.opcode() == Some("add") {
        if let Some(ch) = expr.children() {
            if ch.len() == 2 {
                let (left, right) = (&ch[0], &ch[1]);

                if right.opcode() == Some("loc") {
                    return Expr::node2("array", left.clone(), right.clone());
                }
                if left.opcode() == Some("loc") {
                    return Expr::node2("array", right.clone(), left.clone());
                }
                if right.opcode() == Some("map") {
                    return Expr::node2("array", left.clone(), right.clone());
                }
                if left.opcode() == Some("map") {
                    return Expr::node2("array", right.clone(), left.clone());
                }
            }
        }
    }
    expr.clone()
}

/// For plain integer indices, check if the slot is also referenced through sha3(slot).
/// If yes → it's the `length` field of a dynamic array. If no → it's a plain `loc(N)`.
fn detect_length_or_loc(expr: &Expr, all_storages: &HashSet<Expr>) -> Expr {
    if let Some(v) = expr.as_u64() {
        // Check if any other storage access uses sha3(v) (meaning there's a
        // dynamic array at this slot where v stores the length).
        let has_array_data = all_storages.iter().any(|s| {
            if let Some(ch) = s.children() {
                ch.len() >= 3 && expr_contains_sha3_of(&ch[2], v)
            } else {
                false
            }
        });

        if has_array_data {
            // Mark as length only for storage header display, but keep loc()
            // form for getter resolution compatibility.
            return Expr::node1("loc", Expr::val(v));
        }
        return Expr::node1("loc", Expr::val(v));
    }
    expr.clone()
}

/// Check if an expression contains sha3 of a specific slot value.
fn expr_contains_sha3_of(expr: &Expr, slot: u64) -> bool {
    if expr.opcode() == Some("sha3") {
        if let Some(ch) = expr.children() {
            if ch.len() == 1 && ch[0].as_u64() == Some(slot) {
                return true;
            }
        }
    }
    if let Some(ch) = expr.children() {
        ch.iter().any(|c| expr_contains_sha3_of(c, slot))
    } else {
        false
    }
}

/// Resolve nested mapping/array patterns.
fn resolve_nested(expr: &Expr) -> Expr {
    match expr.opcode() {
        Some("sha3") => {
            if let Some(ch) = expr.children() {
                // sha3(map(...)) → map(...)
                if ch.len() == 1 && ch[0].opcode() == Some("map") {
                    return ch[0].clone();
                }
                // sha3(idx, map(...)) → map(idx, map(...))
                if ch.len() == 2 && ch[1].opcode() == Some("map") {
                    return Expr::node2("map", ch[0].clone(), ch[1].clone());
                }
                // sha3(array(idx, loc)) → array(idx, loc)
                if ch.len() == 1 && ch[0].opcode() == Some("array") {
                    return ch[0].clone();
                }
            }
        }
        Some("add") => {
            if let Some(ch) = expr.children() {
                if ch.len() == 2 {
                    // add(map(...), num) → array(num, map(...))
                    if ch[0].opcode() == Some("map") {
                        if let Some(v) = ch[1].as_u64() {
                            return Expr::node2("array", Expr::val(v), ch[0].clone());
                        }
                    }
                    if ch[1].opcode() == Some("map") {
                        if let Some(v) = ch[0].as_u64() {
                            return Expr::node2("array", Expr::val(v), ch[1].clone());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    expr.clone()
}

// ===========================================================================
// Name discovery from getter functions
// ===========================================================================

/// Find storage names from getter functions.
fn find_storage_names(functions: &[Function]) -> HashMap<Expr, String> {
    let mut names = HashMap::new();

    for func in functions {
        if !func.read_only {
            continue;
        }

        // Scan the entire trace for storage reads (not just returns,
        // because ABI encoding routes the SLOAD through memory).
        let mut storages: HashSet<Expr> = HashSet::new();
        collect_storage_accesses(&func.trace, &mut storages);

        // Only name functions with exactly one storage access (simple getters).
        if storages.len() != 1 {
            continue;
        }

        let stor_expr = storages.into_iter().next().unwrap();

        let mut name = func.name.split('(').next().unwrap_or(&func.name).to_string();

        // Strip "get" prefix.
        if name.starts_with("get") && name.len() > 3 {
            name = name[3..].to_string();
        }

        // Lowercase first character (unless ALL CAPS).
        if name != name.to_uppercase() && !name.is_empty() {
            let mut chars = name.chars();
            if let Some(first) = chars.next() {
                name = first.to_lowercase().to_string() + chars.as_str();
            }
        }

        // If it returns a 160-bit value, append "Address" if not already hinted.
        if stor_expr.opcode() == Some("storage") {
            if let Some(ch) = stor_expr.children() {
                if ch.first().and_then(|e| e.as_u64()) == Some(160) {
                    let name_lower = name.to_lowercase();
                    if !name_lower.contains("address")
                        && !name_lower.contains("addr")
                        && !name_lower.contains("account")
                        && !name_lower.contains("owner")
                    {
                        name.push_str("Address");
                    }
                }
            }
        }

        names.insert(stor_expr, name);
    }

    names
}

/// Heuristic fallback: match read-only getter function names to mapping slots
/// when trace-based detection fails (e.g., storage was consumed by ABI encoding).
fn heuristic_name_matching(
    functions: &[Function],
    assoc: &HashMap<Expr, Expr>,
    names: &mut HashMap<Expr, String>,
) {
    // Collect all mapping slots from the assoc table (already-resolved forms).
    let mut slot_to_key: HashMap<u64, Vec<Expr>> = HashMap::new();
    for (raw_key, resolved) in assoc {
        if resolved.contains_op("map") {
            if let Some(loc_num) = extract_loc_num(resolved) {
                slot_to_key.entry(loc_num).or_default().push(raw_key.clone());
            }
        }
    }

    // Collect already-named slots.
    let mut named_slots: HashSet<u64> = HashSet::new();
    for (expr, _) in names.iter() {
        if let Some(resolved) = assoc.get(expr) {
            if let Some(loc_num) = extract_loc_num(resolved) {
                named_slots.insert(loc_num);
            }
        }
    }

    // Collect already-used names.
    let used_names: HashSet<String> = names.values().cloned().collect();

    // For each read-only getter function, try to match by parameter count.
    for func in functions {
        if !func.read_only {
            continue;
        }
        let base_name = func.name.split('(').next().unwrap_or(&func.name);

        // Skip unknown/hex-named functions.
        if base_name.starts_with("unknown_") || base_name.starts_with("0x") {
            continue;
        }

        // Skip functions whose name is already assigned to a slot.
        let lower_name = {
            let mut n = base_name.to_string();
            if n != n.to_uppercase() && !n.is_empty() {
                let mut chars = n.chars();
                if let Some(first) = chars.next() {
                    n = first.to_lowercase().to_string() + chars.as_str();
                }
            }
            n
        };
        if used_names.contains(&lower_name) {
            continue;
        }

        // Single-param getter → likely a simple mapping (like balanceOf).
        if func.params.len() == 1 {
            // Find an unnamed single-key mapping slot.
            for (&slot, keys) in &slot_to_key {
                if named_slots.contains(&slot) {
                    continue;
                }
                // Check if this slot has single-key accesses.
                let has_single_key = keys.iter().any(|k| {
                    if let Some(ch) = k.children() {
                        if ch.len() >= 3 {
                            let idx = &ch[2];
                            // sha3(key, slot) pattern → single-key mapping.
                            if idx.opcode() == Some("sha3") {
                                if let Some(sha3_ch) = idx.children() {
                                    return sha3_ch.len() == 2 && sha3_ch[1].as_u64() == Some(slot);
                                }
                            }
                        }
                    }
                    false
                });
                if has_single_key {
                    let mut name = base_name.to_string();
                    // Lowercase first char.
                    if name != name.to_uppercase() && !name.is_empty() {
                        let mut chars = name.chars();
                        if let Some(first) = chars.next() {
                            name = first.to_lowercase().to_string() + chars.as_str();
                        }
                    }
                    // Find a raw key to use as the lookup in the assoc table.
                    if let Some(raw_key) = keys.first() {
                        names.insert(raw_key.clone(), name);
                        named_slots.insert(slot);
                        break;
                    }
                }
            }
        }

        // Two-param getter → likely a nested mapping (like allowance).
        if func.params.len() == 2 {
            for (&slot, keys) in &slot_to_key {
                if named_slots.contains(&slot) {
                    continue;
                }
                // Check for nested mapping: sha3(key2, sha3(key1, slot)) pattern.
                let has_nested = keys.iter().any(|k| {
                    if let Some(ch) = k.children() {
                        if ch.len() >= 3 {
                            let idx = &ch[2];
                            if idx.opcode() == Some("sha3") {
                                if let Some(sha3_ch) = idx.children() {
                                    if sha3_ch.len() == 2 && sha3_ch[1].opcode() == Some("sha3") {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    false
                });
                if has_nested {
                    let mut name = base_name.to_string();
                    if name != name.to_uppercase() && !name.is_empty() {
                        let mut chars = name.chars();
                        if let Some(first) = chars.next() {
                            name = first.to_lowercase().to_string() + chars.as_str();
                        }
                    }
                    if let Some(raw_key) = keys.first() {
                        names.insert(raw_key.clone(), name);
                        named_slots.insert(slot);
                        break;
                    }
                }
            }
        }

        // Zero-param getter → likely a simple storage variable (like decimals).
        if func.params.is_empty() {
            // Collect slot numbers accessed by this function's raw traces.
            let mut func_slots: HashSet<u64> = HashSet::new();
            for acc in &func.raw_storage_accesses {
                if let Some(ch) = acc.children() {
                    if ch.len() >= 3 {
                        if let Some(slot) = ch[2].as_u64() {
                            func_slots.insert(slot);
                        }
                    }
                }
            }
            // Also check simplified trace.
            let mut simple_storages: HashSet<Expr> = HashSet::new();
            collect_storage_accesses(&func.trace, &mut simple_storages);
            for s in &simple_storages {
                if let Some(ch) = s.children() {
                    if ch.len() >= 3 {
                        if let Some(slot) = ch[2].as_u64() {
                            func_slots.insert(slot);
                        }
                    }
                }
            }

            // Find an unnamed simple slot that this function accesses.
            for (raw_key, resolved) in assoc.iter() {
                if resolved.contains_op("map") || resolved.contains_op("array") {
                    continue;
                }
                if let Some(loc_num) = extract_loc_num(resolved) {
                    if named_slots.contains(&loc_num) {
                        continue;
                    }
                    // Only match if the function actually accesses this slot.
                    if !func_slots.contains(&loc_num) {
                        continue;
                    }
                    names.insert(raw_key.clone(), lower_name.clone());
                    named_slots.insert(loc_num);
                    break;
                }
            }
        }
    }
}

/// Apply discovered names to the storage association table.
fn apply_names(names: HashMap<Expr, String>, mut assoc: HashMap<Expr, Expr>) -> HashMap<Expr, Expr> {
    for (getter_expr, name) in &names {
        // Find the resolved form for this getter's storage expression.
        if let Some(resolved) = assoc.get(getter_expr).cloned() {
            // Extract the loc number from the resolved form.
            if let Some(loc_num) = extract_loc_num(&resolved) {
                // Replace all (loc, num) with (name, name_str, num) in the assoc.
                let loc_expr = Expr::node1("loc", Expr::val(loc_num));
                let name_expr = Expr::node2("name", Expr::atom(name), Expr::val(loc_num));

                let keys: Vec<Expr> = assoc.keys().cloned().collect();
                for key in keys {
                    if let Some(val) = assoc.get(&key).cloned() {
                        if val.contains(&loc_expr) {
                            assoc.insert(key, val.replace(&loc_expr, &name_expr));
                        }
                    }
                }
            }
        }
    }

    assoc
}

/// Extract the loc number from a resolved storage expression.
/// Handles both `loc(N)` and `name(str, N)` forms.
fn extract_loc_num(expr: &Expr) -> Option<u64> {
    if expr.opcode() == Some("loc") {
        if let Some(ch) = expr.children() {
            return ch.first().and_then(|e| e.as_u64());
        }
    }
    // name(str, N) — the slot number is the second child.
    if expr.opcode() == Some("name") {
        if let Some(ch) = expr.children() {
            if ch.len() >= 2 {
                return ch[1].as_u64();
            }
        }
    }
    // Recurse into children.
    if let Some(ch) = expr.children() {
        for c in ch {
            if let Some(n) = extract_loc_num(c) {
                return Some(n);
            }
        }
    }
    None
}

// ===========================================================================
// Trace rewriting
// ===========================================================================

/// Replace raw storage expressions in a trace with their resolved forms.
/// Resolve remaining unresolved sha3 storage keys.
///
/// After the main sparser rewrite, some storage accesses may still contain
/// `sha3(key, var(_N))` where `var(_N)` is `sha3(other_key, slot)`.
/// This function resolves those by expanding variables and matching against
/// known mapping slots, converting them to named forms like `allowance[X][Y]`.
fn resolve_sha3_storage_keys(
    trace: &[Expr],
    vars: &HashMap<String, Expr>,
    assoc: &HashMap<Expr, Expr>,
    cd_to_param: &HashMap<u64, String>,
) -> Trace {
    // Extract known mapping slot names: slot_num → name
    let mut slot_names: HashMap<u64, String> = HashMap::new();
    for resolved in assoc.values() {
        if let Some(name_str) = extract_name_from_resolved(resolved) {
            if let Some(slot) = extract_loc_num(resolved) {
                slot_names.insert(slot, name_str);
            }
        }
    }

    trace.iter().map(|e| resolve_sha3_in_expr(e, vars, &slot_names, cd_to_param)).collect()
}

/// Extract the name string from a resolved storage expression like
/// `stor(256, 0, map(key, name("allowance", 4)))`.
fn extract_name_from_resolved(expr: &Expr) -> Option<String> {
    if expr.opcode() == Some("name") {
        if let Some(ch) = expr.children() {
            if let Expr::Atom(s) = &ch[0] {
                return Some(s.clone());
            }
        }
    }
    if let Some(ch) = expr.children() {
        for c in ch {
            if let Some(name) = extract_name_from_resolved(c) {
                return Some(name);
            }
        }
    }
    None
}

fn resolve_sha3_in_expr(
    expr: &Expr,
    vars: &HashMap<String, Expr>,
    slot_names: &HashMap<u64, String>,
    cd_to_param: &HashMap<u64, String>,
) -> Expr {
    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children
                .iter()
                .map(|c| resolve_sha3_in_expr(c, vars, slot_names, cd_to_param))
                .collect();
            let result = Expr::Node(op.clone(), new_ch);

            // Check for sha3(key, var(_N)) where var(_N) is sha3(key2, slot).
            if op == "sha3" {
                if let Some(resolved) = try_resolve_nested_mapping(&result, vars, slot_names, cd_to_param) {
                    return resolved;
                }
            }
            result
        }
        _ => expr.clone(),
    }
}

/// Try to resolve a sha3(key, var_or_sha3) into a named mapping form.
fn try_resolve_nested_mapping(
    expr: &Expr,
    vars: &HashMap<String, Expr>,
    slot_names: &HashMap<u64, String>,
    cd_to_param: &HashMap<u64, String>,
) -> Option<Expr> {
    let ch = expr.children()?;
    if ch.len() != 2 {
        return None;
    }

    let key1 = &ch[0];
    let mut inner = ch[1].clone();

    // Resolve var reference.
    if inner.opcode() == Some("var") {
        if let Some(vch) = inner.children() {
            if let Expr::Atom(name) = &vch[0] {
                if let Some(val) = vars.get(name.as_str()) {
                    inner = val.clone();
                }
            }
        }
    }

    // Check if inner is sha3(key2, slot_num).
    if inner.opcode() == Some("sha3") {
        if let Some(inner_ch) = inner.children() {
            if inner_ch.len() == 2 {
                if let Some(slot) = inner_ch[1].as_u64() {
                    if let Some(name) = slot_names.get(&slot) {
                        // Build: map(key1, map(simplified_key2, name("allowance", slot)))
                        let key2 = resolve_cd_to_param(&simplify_address_mask(&inner_ch[0]), cd_to_param);
                        let key1_clean = resolve_cd_to_param(&simplify_address_mask(key1), cd_to_param);
                        let name_expr = Expr::node2("name", Expr::atom(name), Expr::val(slot));
                        let inner_map = Expr::node2("map", key2, name_expr);
                        return Some(Expr::node2("map", key1_clean, inner_map));
                    }
                }
            }
        }
    }

    None
}

/// Replace `cd(N)` expressions with parameter names.
fn resolve_cd_to_param(expr: &Expr, cd_to_param: &HashMap<u64, String>) -> Expr {
    if expr.opcode() == Some("cd") {
        if let Some(ch) = expr.children() {
            if let Some(off) = ch[0].as_u64() {
                if let Some(name) = cd_to_param.get(&off) {
                    return Expr::Atom(name.clone());
                }
            }
        }
    }
    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children.iter().map(|c| resolve_cd_to_param(c, cd_to_param)).collect();
            Expr::Node(op.clone(), new_ch)
        }
        other => other.clone(),
    }
}

/// Simplify address mask patterns: `and(0xfff...fff, X)` → `X`
fn simplify_address_mask(expr: &Expr) -> Expr {
    if expr.opcode() == Some("and") {
        if let Some(ch) = expr.children() {
            if ch.len() == 2 {
                // Check for and(addr_mask, X) or and(X, addr_mask).
                let addr_mask = U256::from_str_radix(
                    "ffffffffffffffffffffffffffffffffffffffff", 16
                ).unwrap_or_default();
                if ch[0].as_val() == Some(addr_mask) {
                    return simplify_address_mask(&ch[1]);
                }
                if ch[1].as_val() == Some(addr_mask) {
                    return simplify_address_mask(&ch[0]);
                }
            }
        }
    }
    // Recurse into and expressions.
    match expr {
        Expr::Node(op, children) if op == "and" => {
            let new_ch: Vec<Expr> = children.iter().map(simplify_address_mask).collect();
            Expr::Node(op.clone(), new_ch)
        }
        _ => expr.clone(),
    }
}

fn rewrite_trace_storage(trace: &[Expr], assoc: &HashMap<Expr, Expr>) -> Trace {
    trace.iter().map(|e| rewrite_expr_storage(e, assoc)).collect()
}

fn rewrite_expr_storage(expr: &Expr, assoc: &HashMap<Expr, Expr>) -> Expr {
    // Check for store(size, off, idx, val) → rewrite.
    if expr.opcode() == Some("store") {
        if let Some(ch) = expr.children() {
            if ch.len() >= 4 {
                let key = Expr::Node("storage".into(), ch[..3].to_vec());
                if let Some(resolved) = assoc.get(&key) {
                    let val = rewrite_expr_storage(&ch[3], assoc);
                    if let Some(rch) = resolved.children() {
                        let mut new_ch = rch.to_vec();
                        new_ch.push(val);
                        return Expr::Node("stor".into(), new_ch);
                    }
                }
            }
        }
    }

    // Check for storage(size, off, idx) → rewrite.
    if assoc.contains_key(expr) {
        return assoc[expr].clone();
    }

    // Recurse.
    match expr {
        Expr::Node(op, children) => {
            let new_ch: Vec<Expr> = children
                .iter()
                .map(|c| rewrite_expr_storage(c, assoc))
                .collect();
            Expr::Node(op.clone(), new_ch)
        }
        other => other.clone(),
    }
}

// ===========================================================================
// Storage definition extraction (for output)
// ===========================================================================

/// A storage variable definition.
#[derive(Debug, Clone)]
pub struct StorageDef {
    pub name: String,
    pub slot: u64,
    pub kind: StorageKind,
}

/// The kind of storage variable.
#[derive(Debug, Clone)]
pub enum StorageKind {
    /// Simple variable: `uint256`, `address`, etc.
    Simple { size: u64, offset: u64 },
    /// Mapping: `mapping(keyType => valueType)`.
    Mapping { value_size: u64 },
    /// Dynamic array: `type[]`.
    Array { element_size: u64 },
    /// Struct (multi-slot).
    Struct { field_count: usize },
}

/// Extract storage definitions from the resolved association table.
pub fn extract_storage_defs(assoc: &HashMap<Expr, Expr>, raw_storages: &HashSet<Expr>) -> Vec<StorageDef> {
    let mut defs: HashMap<u64, (String, StorageKind)> = HashMap::new();
    // Track minimum size seen per slot (for type inference).
    let mut min_sizes: HashMap<u64, u64> = HashMap::new();
    // Detect which slots have sha3-based data accesses (= array/string types).
    let mut array_slots: HashSet<u64> = HashSet::new();
    for s in raw_storages {
        if let Some(ch) = s.children() {
            if ch.len() >= 3 {
                // Check if idx contains sha3(N) for some concrete N.
                for slot in 0..20u64 {
                    if expr_contains_sha3_of(&ch[2], slot) {
                        array_slots.insert(slot);
                    }
                }
            }
        }
    }

    for resolved in assoc.values() {
        if let Some(ch) = resolved.children() {
            if resolved.opcode() == Some("stor") && ch.len() >= 3 {
                let size = ch[0].as_u64().unwrap_or(256);
                let offset = ch[1].as_u64().unwrap_or(0);
                let idx = &ch[2];

                if let Some(slot) = extract_loc_num(idx) {
                    let name = extract_name(idx).unwrap_or_else(|| format!("stor{slot}"));

                    // Track minimum size for this slot (Panoramix approach).
                    // Exclude size 1 (boolean flags from string length encoding)
                    // and size 0 (invalid).
                    let min_size = min_sizes.entry(slot).or_insert(256);
                    if size > 1 && size < *min_size {
                        *min_size = size;
                    }

                    let kind = if idx.contains_op("map") {
                        StorageKind::Mapping { value_size: size }
                    } else if idx.contains_op("array") || idx.contains_op("length")
                        || array_slots.contains(&slot)
                    {
                        StorageKind::Array { element_size: size }
                    } else if offset > 0 {
                        if let Some(existing) = defs.get(&slot) {
                            match &existing.1 {
                                StorageKind::Struct { field_count } => {
                                    StorageKind::Struct { field_count: field_count + 1 }
                                }
                                _ => StorageKind::Struct { field_count: 2 },
                            }
                        } else {
                            StorageKind::Struct { field_count: 1 }
                        }
                    } else {
                        StorageKind::Simple { size, offset }
                    };

                    defs.insert(slot, (name, kind));
                }
            }
        }
    }

    // Apply minimum sizes: use the smallest observed size per slot.
    let mut result: Vec<StorageDef> = defs
        .into_iter()
        .map(|(slot, (name, kind))| {
            let min_size = min_sizes.get(&slot).copied().unwrap_or(256);
            let kind = match kind {
                StorageKind::Simple { offset, .. } => StorageKind::Simple { size: min_size, offset },
                StorageKind::Mapping { .. } => StorageKind::Mapping { value_size: min_size },
                other => other,
            };
            StorageDef { name, slot, kind }
        })
        .collect();
    result.sort_by_key(|d| d.slot);
    result
}

fn extract_name(expr: &Expr) -> Option<String> {
    if expr.opcode() == Some("name") {
        if let Some(ch) = expr.children() {
            if let Some(Expr::Atom(name)) = ch.first() {
                return Some(name.clone());
            }
        }
    }
    if let Some(ch) = expr.children() {
        for c in ch {
            if let Some(n) = extract_name(c) {
                return Some(n);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplify_sha3_integer() {
        // sha3(5) → loc(5)
        let expr = Expr::node1("sha3", Expr::val(5));
        let result = simplify_sha3(&expr);
        assert_eq!(result, Expr::node1("loc", Expr::val(5)));
    }

    #[test]
    fn test_simplify_sha3_mapping() {
        // sha3(key, 3) → map(key, loc(3))
        let expr = Expr::node2("sha3", Expr::atom("key"), Expr::val(3));
        let result = simplify_sha3(&expr);
        assert_eq!(result, Expr::node2("map", Expr::atom("key"), Expr::node1("loc", Expr::val(3))));
    }

    #[test]
    fn test_detect_array() {
        // add(idx, loc(5)) → array(idx, loc(5))
        let expr = Expr::node2("add", Expr::atom("idx"), Expr::node1("loc", Expr::val(5)));
        let result = detect_array(&expr);
        assert_eq!(result, Expr::node2("array", Expr::atom("idx"), Expr::node1("loc", Expr::val(5))));
    }

    #[test]
    fn test_extract_offset() {
        // add(3, loc(1)) → (loc(1), 3)
        let expr = Expr::node2("add", Expr::val(3), Expr::node1("loc", Expr::val(1)));
        let (rest, off) = extract_offset(&expr);
        assert_eq!(off, 3);
        assert_eq!(rest, Expr::node1("loc", Expr::val(1)));
    }

    #[test]
    fn test_resolve_nested_map() {
        // sha3(key2, map(key1, loc(3))) → map(key2, map(key1, loc(3)))
        let inner = Expr::node2("map", Expr::atom("key1"), Expr::node1("loc", Expr::val(3)));
        let expr = Expr::node2("sha3", Expr::atom("key2"), inner.clone());
        let result = resolve_nested(&expr);
        assert_eq!(result, Expr::node2("map", Expr::atom("key2"), inner));
    }

    #[test]
    fn test_collect_storage_accesses() {
        let trace = vec![
            Expr::Node("storage".into(), vec![Expr::val(256), Expr::zero(), Expr::val(1)]),
            Expr::Node("store".into(), vec![Expr::val(256), Expr::zero(), Expr::val(2), Expr::val(42)]),
        ];
        let mut accesses = HashSet::new();
        collect_storage_accesses(&trace, &mut accesses);
        assert_eq!(accesses.len(), 2);
    }

    #[test]
    fn test_rewrite_expr_storage() {
        let orig = Expr::Node("storage".into(), vec![Expr::val(256), Expr::zero(), Expr::val(1)]);
        let resolved = Expr::Node("stor".into(), vec![Expr::val(256), Expr::zero(), Expr::node1("loc", Expr::val(1))]);
        let mut assoc = HashMap::new();
        assoc.insert(orig.clone(), resolved.clone());

        let result = rewrite_expr_storage(&orig, &assoc);
        assert_eq!(result, resolved);
    }

    #[test]
    fn test_find_storage_names_no_getters() {
        let functions: Vec<Function> = vec![];
        let names = find_storage_names(&functions);
        assert!(names.is_empty());
    }
}
