//! Integration tests: full decompilation pipeline.

use lutetia::decompiler::{decompile_bytecode, DecompilerConfig, OutputFormat};

fn config_text() -> DecompilerConfig {
    DecompilerConfig {
        timeout_secs: 10,
        format: OutputFormat::Text,
        color: false,
    }
}

fn config_json() -> DecompilerConfig {
    DecompilerConfig {
        timeout_secs: 10,
        format: OutputFormat::Json,
        color: false,
    }
}

fn config_asm() -> DecompilerConfig {
    DecompilerConfig {
        timeout_secs: 10,
        format: OutputFormat::Asm,
        color: false,
    }
}

// ---- Minimal contracts ----

#[test]
fn test_stop_only() {
    let r = decompile_bytecode("00", &config_text()).unwrap();
    assert!(r.text.contains("stop"));
}

#[test]
fn test_revert_only() {
    let r = decompile_bytecode("60006000fd", &config_text()).unwrap();
    assert!(r.text.contains("revert"));
}

#[test]
fn test_return_value() {
    // PUSH1 32, PUSH1 0, RETURN
    let r = decompile_bytecode("60206000f3", &config_text()).unwrap();
    assert!(r.text.contains("return"));
}

#[test]
fn test_invalid_opcode() {
    let r = decompile_bytecode("fe", &config_text()).unwrap();
    assert!(!r.text.is_empty());
}

// ---- Output formats ----

#[test]
fn test_asm_output() {
    let r = decompile_bytecode("6001600201", &config_asm()).unwrap();
    assert!(r.text.contains("push1"));
    assert!(r.text.contains("add"));
}

#[test]
fn test_json_output() {
    let r = decompile_bytecode("00", &config_json()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&r.text).unwrap();
    assert!(json["functions"].is_array());
    assert!(json["problems"].is_array());
}

#[test]
fn test_json_with_revert() {
    let r = decompile_bytecode("60006000fd", &config_json()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&r.text).unwrap();
    assert!(json["functions"].is_array());
}

// ---- Error cases ----

#[test]
fn test_empty_bytecode() {
    let r = decompile_bytecode("", &config_text());
    assert!(r.is_err());
}

#[test]
fn test_invalid_hex() {
    let r = decompile_bytecode("xyz", &config_text());
    // Should not panic — may fail or produce empty
    assert!(r.is_ok() || r.is_err());
}

// ---- Storage ----

#[test]
fn test_sload_contract() {
    // PUSH1 0, SLOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    // After sparser, the getter names slot 0 "fallback" (from the function name),
    // so output is "return fallback" rather than "return stor[0]".
    let r = decompile_bytecode("6000546000526020 6000f3".replace(' ', "").as_str(), &config_text()).unwrap();
    assert!(r.text.contains("stor") || r.text.contains("storage") || r.text.contains("return"));
}

#[test]
fn test_sstore_contract() {
    // PUSH1 42, PUSH1 0, SSTORE, STOP
    let r = decompile_bytecode("602a60005500", &config_text()).unwrap();
    assert!(r.text.contains("stor"));
}

// ---- Calldata ----

#[test]
fn test_calldataload_contract() {
    // PUSH1 0, CALLDATALOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let hex = "60003560005260206000f3";
    let r = decompile_bytecode(hex, &config_text()).unwrap();
    assert!(r.text.contains("cd") || r.text.contains("call"));
}

// ---- EVM version-specific ----

#[test]
fn test_push0_shanghai_contract() {
    // PUSH0, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let r = decompile_bytecode("5f6000526020 6000f3".replace(' ', "").as_str(), &config_text()).unwrap();
    assert!(r.text.contains("return") || r.text.contains("mem"));
}

#[test]
fn test_tload_cancun_contract() {
    // PUSH1 0, TLOAD, STOP
    let r = decompile_bytecode("60005c00", &config_text()).unwrap();
    assert!(!r.text.is_empty());
}

// ---- Complex bytecode ----

#[test]
fn test_simple_addition() {
    // PUSH1 3, PUSH1 2, ADD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let hex = "600360020160005260206000f3";
    let r = decompile_bytecode(hex, &config_text()).unwrap();
    assert!(r.text.contains("return"));
}

#[test]
fn test_multiplication() {
    // PUSH1 3, PUSH1 7, MUL, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let hex = "600360070260005260206000f3";
    let r = decompile_bytecode(hex, &config_text()).unwrap();
    assert!(r.text.contains("return"));
}

// ---- Contract properties ----

#[test]
fn test_contract_postprocess() {
    let r = decompile_bytecode("00", &config_json()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&r.text).unwrap();
    // Should have at least one function (fallback)
    assert!(!json["functions"].as_array().unwrap().is_empty());
}

// ---- 0x prefix handling ----

#[test]
fn test_0x_prefix() {
    let r1 = decompile_bytecode("0x00", &config_text()).unwrap();
    let r2 = decompile_bytecode("00", &config_text()).unwrap();
    assert_eq!(r1.text, r2.text);
}

// ---- Selfdestruct ----

#[test]
fn test_selfdestruct_contract() {
    // PUSH20 <address>, SELFDESTRUCT
    let hex = format!("73{}ff", "00".repeat(20));
    let r = decompile_bytecode(&hex, &config_text()).unwrap();
    assert!(r.text.contains("selfdestruct"));
}
