//! Robustness tests: malformed bytecode, stack underflow, depth limits,
//! and real Solidity-compiled contract patterns.

use lutetia::decompiler::{decompile_bytecode, DecompilerConfig, OutputFormat};
use lutetia::errors::StackError;
use lutetia::expr::Expr;
use lutetia::loader::Loader;
use lutetia::stack::Stack;

fn config() -> DecompilerConfig {
    DecompilerConfig {
        timeout_secs: 5,
        format: OutputFormat::Text,
        color: false,
    }
}

// =========================================================================
// Malformed bytecode — should not panic
// =========================================================================

#[test]
fn test_malformed_empty_hex() {
    let r = decompile_bytecode("", &config());
    assert!(r.is_err());
}

#[test]
fn test_malformed_invalid_chars() {
    let r = decompile_bytecode("ZZZZ", &config());
    // Must not panic. May return error or empty result.
    let _ = r;
}

#[test]
fn test_malformed_odd_length_hex() {
    // Odd-length hex string (one nibble missing).
    let r = decompile_bytecode("6001f", &config());
    let _ = r; // must not panic
}

#[test]
fn test_malformed_truncated_push() {
    // PUSH2 but only 1 byte follows.
    let r = decompile_bytecode("6100", &config());
    assert!(r.is_ok()); // should handle gracefully
}

#[test]
fn test_malformed_truncated_push32() {
    // PUSH32 but only 10 bytes follow.
    let r = decompile_bytecode("7f00112233445566778899", &config());
    assert!(r.is_ok());
}

#[test]
fn test_malformed_only_invalid() {
    // Just the INVALID opcode.
    let r = decompile_bytecode("fe", &config());
    assert!(r.is_ok());
}

#[test]
fn test_malformed_single_byte_ff() {
    let r = decompile_bytecode("ff", &config());
    assert!(r.is_ok()); // SELFDESTRUCT with empty stack
}

#[test]
fn test_malformed_random_garbage() {
    // Random bytes that don't form valid EVM.
    let r = decompile_bytecode("deadbeefcafebabe1337", &config());
    let _ = r; // must not panic
}

#[test]
fn test_malformed_all_zeros() {
    // 100 zero bytes: all STOPs.
    let hex = "00".repeat(100);
    let r = decompile_bytecode(&hex, &config());
    assert!(r.is_ok());
}

#[test]
fn test_malformed_very_long_bytecode() {
    // 10,000 bytes of NOPs followed by STOP.
    let hex = format!("{}{}", "5b".repeat(5000), "00");
    let r = decompile_bytecode(&hex, &config());
    assert!(r.is_ok());
}

#[test]
fn test_malformed_repeated_jumps() {
    // PUSH1 3, JUMP, JUMPDEST — infinite loop should timeout, not panic.
    let r = decompile_bytecode("6003565b", &config());
    assert!(r.is_ok());
}

// =========================================================================
// Stack underflow scenarios
// =========================================================================

#[test]
fn test_stack_underflow_pop_empty() {
    let mut stack = Stack::new();
    let result = stack.try_pop();
    assert!(matches!(result, Err(StackError::Underflow { .. })));
}

#[test]
fn test_stack_underflow_pop_graceful() {
    let mut stack = Stack::new();
    let val = stack.pop(); // uses graceful version
    assert_eq!(val, Expr::atom("STACK_UNDERFLOW"));
}

#[test]
fn test_stack_underflow_dup_empty() {
    let mut stack = Stack::new();
    let result = stack.try_dup(1);
    assert!(result.is_err());
}

#[test]
fn test_stack_underflow_swap_empty() {
    let mut stack = Stack::new();
    let result = stack.try_swap(1);
    assert!(result.is_err());
}

#[test]
fn test_stack_underflow_in_bytecode_add() {
    // ADD with empty stack — should not panic.
    let r = decompile_bytecode("0100", &config());
    assert!(r.is_ok());
}

#[test]
fn test_stack_underflow_in_bytecode_sstore() {
    // SSTORE with only one value on stack.
    let r = decompile_bytecode("60015500", &config());
    assert!(r.is_ok());
}

#[test]
fn test_stack_underflow_in_bytecode_mstore() {
    // MSTORE with empty stack.
    let r = decompile_bytecode("5200", &config());
    assert!(r.is_ok());
}

// =========================================================================
// Real Solidity-compiled patterns
// =========================================================================

/// Minimal "constructor" that returns runtime bytecode.
/// PUSH1 n, PUSH1 0, CODECOPY, PUSH1 n, PUSH1 0, RETURN
/// This just exercises the codecopy/return path.
#[test]
fn test_real_constructor_pattern() {
    // Runtime code: 0x00 (STOP)
    // Constructor: PUSH1 1, PUSH1 0, CODECOPY, PUSH1 1, PUSH1 0, RETURN
    let hex = "600160003960016000f300";
    let r = decompile_bytecode(hex, &config());
    assert!(r.is_ok());
}

/// Simple getter: returns a storage slot.
/// Compiled pattern: PUSH1 0, SLOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN.
#[test]
fn test_real_simple_getter() {
    let hex = "60005460005260206000f3";
    let r = decompile_bytecode(hex, &config()).unwrap();
    assert!(r.text.contains("return") || r.text.contains("stor"));
}

/// Simple setter: stores a calldata value.
/// Pattern: PUSH1 0, CALLDATALOAD, PUSH1 0, SSTORE, STOP.
#[test]
fn test_real_simple_setter() {
    let hex = "600035600055 00".replace(' ', "");
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(r.text.contains("stor"));
}

/// Payable check pattern: CALLVALUE, ISZERO, PUSH1 target, JUMPI.
/// Tests the conditional branching path.
#[test]
fn test_real_payable_check() {
    // CALLVALUE, ISZERO, PUSH1 6, JUMPI, PUSH1 0, PUSH1 0, REVERT, JUMPDEST, STOP
    let hex = "341560065760006000fd5b00";
    let r = decompile_bytecode(hex, &config()).unwrap();
    // Should produce something with a condition or require.
    assert!(!r.text.is_empty());
}

/// Minimal ERC20-like function dispatcher.
/// Checks msg.sig and dispatches to different code paths.
#[test]
fn test_real_function_dispatcher() {
    // PUSH1 0, CALLDATALOAD, PUSH29 (shift right to get selector),
    // Then compare against a selector.
    // Simplified: PUSH1 0, CALLDATALOAD, PUSH1 224, SHR,
    //   DUP1, PUSH4 0x70a08231 (balanceOf), EQ, PUSH1 target, JUMPI,
    //   JUMPDEST, STOP, JUMPDEST, POP, STOP
    let hex = "60003560e01c80 6370a08231 14 600e 57 5b00 5b5000";
    let r = decompile_bytecode(&hex.replace(' ', ""), &config()).unwrap();
    // Should detect function(s).
    assert!(!r.text.is_empty());
}

/// Contract that reverts with a reason string.
/// Pattern: PUSH4 0x08c379a0 + ABI-encoded string.
#[test]
fn test_real_revert_with_reason() {
    // Simple revert: PUSH1 0, PUSH1 0, REVERT
    // More complex reverts need memory store + revert, tested at expression level.
    let hex = "60006000fd";
    let r = decompile_bytecode(hex, &config()).unwrap();
    assert!(r.text.contains("revert"));
}

/// Test with PUSH0 (Shanghai).
#[test]
fn test_real_shanghai_push0() {
    // PUSH0, PUSH1 0, MSTORE, PUSH1 32, PUSH0, RETURN
    let hex = "5f60005260205ff3";
    let r = decompile_bytecode(hex, &config()).unwrap();
    assert!(r.text.contains("return"));
}

/// Test with TLOAD/TSTORE (Cancun).
#[test]
fn test_real_cancun_transient() {
    // PUSH1 42, PUSH1 0, TSTORE, PUSH1 0, TLOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let hex = "602a60005d60005c60005260206000f3";
    let r = decompile_bytecode(hex, &config()).unwrap();
    assert!(r.text.contains("return") || r.text.contains("tstor"));
}

/// DUP / SWAP chain — stress test for stack operations.
#[test]
fn test_real_deep_stack() {
    // Push 16 values, then DUP16, POP, STOP.
    let mut hex = String::new();
    for i in 0..16u8 {
        hex.push_str(&format!("60{i:02x}"));
    }
    hex.push_str("8f"); // DUP16
    hex.push_str("50"); // POP
    hex.push_str("00"); // STOP
    let r = decompile_bytecode(&hex, &config());
    assert!(r.is_ok());
}

/// Expression depth: deeply nested add chain.
/// Ensures we don't stack overflow on deep AST.
#[test]
fn test_recursive_expression_depth() {
    // Build: PUSH1 1, PUSH1 1, ADD, PUSH1 1, ADD, ... (100 ADDs)
    let mut hex = String::from("60016001");
    for _ in 0..100 {
        hex.push_str("0160 01"); // ADD, PUSH1 1
    }
    hex.push_str("01"); // final ADD
    hex.push_str("60005260206000f3"); // MSTORE, RETURN
    let hex = hex.replace(' ', "");
    let r = decompile_bytecode(&hex, &config());
    assert!(r.is_ok());
}

/// Loader: load_binary returns proper error for bad hex.
#[test]
fn test_loader_error_propagation() {
    let mut loader = Loader::new();
    let result = loader.load_binary("not_hex!");
    assert!(result.is_err());
}

/// Loader: empty hex after 0x prefix.
#[test]
fn test_loader_empty_after_prefix() {
    let mut loader = Loader::new();
    let result = loader.load_binary("0x");
    // Should succeed (empty bytecode is valid in loader, caught in decompiler).
    assert!(result.is_ok());
}

// =========================================================================
// Output format consistency
// =========================================================================

#[test]
fn test_json_output_malformed() {
    let cfg = DecompilerConfig {
        timeout_secs: 5,
        format: OutputFormat::Json,
        color: false,
    };
    let r = decompile_bytecode("deadbeef", &cfg);
    if let Ok(result) = r {
        // JSON should be valid.
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&result.text);
        assert!(parsed.is_ok());
    }
}

#[test]
fn test_asm_output_malformed() {
    let cfg = DecompilerConfig {
        timeout_secs: 5,
        format: OutputFormat::Asm,
        color: false,
    };
    let r = decompile_bytecode("deadbeef", &cfg);
    if let Ok(result) = r {
        assert!(!result.text.is_empty());
    }
}
