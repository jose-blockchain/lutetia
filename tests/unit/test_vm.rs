//! Extended VM tests — symbolic execution of bytecode sequences.

use lutetia::expr::Expr;
use lutetia::loader::Loader;
use lutetia::vm::VM;

fn run_bytecode(hex: &str) -> Vec<Expr> {
    let mut loader = Loader::new();
    loader.load_binary(hex).unwrap();
    let mut vm = VM::new(loader, false);
    vm.run(0, vec![], 5)
}

#[test]
fn test_vm_stop() {
    let trace = run_bytecode("00");
    let last = trace.last().unwrap();
    assert_eq!(last.opcode(), Some("stop"));
}

#[test]
fn test_vm_push_stop() {
    let trace = run_bytecode("604200");
    assert_eq!(trace.last().unwrap().opcode(), Some("stop"));
}

#[test]
fn test_vm_add_concrete() {
    // PUSH1 3, PUSH1 2, ADD, PUSH1 0, MSTORE, STOP
    let trace = run_bytecode("6003600201600052600000");
    assert!(!trace.is_empty());
    assert_eq!(trace.last().unwrap().opcode(), Some("stop"));
}

#[test]
fn test_vm_revert() {
    // PUSH1 0, PUSH1 0, REVERT
    let trace = run_bytecode("60006000fd");
    assert_eq!(trace.last().unwrap().opcode(), Some("revert"));
}

#[test]
fn test_vm_return() {
    // PUSH1 32, PUSH1 0, RETURN
    let trace = run_bytecode("6020 6000 f3".replace(' ', "").as_str());
    assert_eq!(trace.last().unwrap().opcode(), Some("return"));
}

#[test]
fn test_vm_sload() {
    // PUSH1 0, SLOAD, PUSH1 0, MSTORE, STOP
    let trace = run_bytecode("6000546000526000600000");
    // Should contain a storage reference somewhere (AST traversal, not string matching).
    assert!(trace.iter().any(|e| e.contains_op("storage")));
}

#[test]
fn test_vm_sstore() {
    // PUSH1 42, PUSH1 0, SSTORE, STOP
    let trace = run_bytecode("602a60005500");
    assert!(trace.iter().any(|e| e.contains_op("store")));
}

#[test]
fn test_vm_calldataload() {
    // PUSH1 0, CALLDATALOAD, PUSH1 0, MSTORE, STOP
    let trace = run_bytecode("600035600052600000");
    assert!(trace.iter().any(|e| e.contains_op("cd")));
}

#[test]
fn test_vm_caller() {
    // CALLER, PUSH1 0, MSTORE, STOP
    let trace = run_bytecode("33600052600000");
    assert!(trace.iter().any(|e| e.contains_op("caller")));
}

#[test]
fn test_vm_callvalue() {
    // CALLVALUE, PUSH1 0, MSTORE, STOP
    let trace = run_bytecode("34600052600000");
    assert!(trace.iter().any(|e| e.contains_op("callvalue")));
}

#[test]
fn test_vm_invalid() {
    let trace = run_bytecode("fe");
    assert_eq!(trace.last().unwrap().opcode(), Some("invalid"));
}

#[test]
fn test_vm_selfdestruct() {
    // PUSH1 0, SELFDESTRUCT
    let trace = run_bytecode("6000ff");
    assert_eq!(trace.last().unwrap().opcode(), Some("selfdestruct"));
}

#[test]
fn test_vm_log1() {
    // PUSH1 topic, PUSH1 32, PUSH1 0, LOG1, STOP
    let trace = run_bytecode("60aa602060 00a100".replace(' ', "").as_str());
    assert!(trace.iter().any(|e| e.contains_op("log")));
}

#[test]
fn test_vm_tload_tstore() {
    // PUSH1 0, TLOAD, PUSH1 42, PUSH1 0, TSTORE, STOP
    let trace = run_bytecode("60005c602a60005d00");
    assert!(trace.iter().any(|e| e.contains_op("tstorage") || e.contains_op("tstore")));
}

#[test]
fn test_vm_push0() {
    // PUSH0, PUSH0, ADD, STOP
    let trace = run_bytecode("5f5f0100");
    assert_eq!(trace.last().unwrap().opcode(), Some("stop"));
}

#[test]
fn test_vm_chainid() {
    // CHAINID, STOP
    let trace = run_bytecode("4600");
    // chainid was pushed but not stored so it's on the stack
    assert!(!trace.is_empty());
}

#[test]
fn test_vm_basefee() {
    // BASEFEE, STOP
    let trace = run_bytecode("4800");
    assert!(!trace.is_empty());
}

#[test]
fn test_vm_blobbasefee() {
    // BLOBBASEFEE, STOP
    let trace = run_bytecode("4a00");
    assert!(!trace.is_empty());
}

#[test]
fn test_vm_timeout() {
    // Create a loop that would run forever: JUMPDEST, PUSH1 0, JUMP
    // But with a 1-second timeout it should abort.
    let trace = run_bytecode("5b6000565b00");
    // Should contain some output (likely an undefined or jump)
    assert!(!trace.is_empty());
}
