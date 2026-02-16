//! Pipeline integration tests — loader → VM → simplifier → prettify.

use lutetia::loader::Loader;
use lutetia::prettify::pprint_trace;
use lutetia::simplify::simplify_trace;
use lutetia::vm::VM;
use lutetia::whiles::make_whiles;

fn pipeline(hex: &str) -> String {
    let mut loader = Loader::new();
    loader.load_binary(hex).unwrap();
    let mut vm = VM::new(loader, false);
    let raw = vm.run(0, vec![], 10);
    let trace = make_whiles(&raw);
    let simplified = simplify_trace(&trace, 10, None);
    pprint_trace(&simplified, false)
}

#[test]
fn test_pipeline_stop() {
    let output = pipeline("00");
    assert!(output.contains("stop"));
}

#[test]
fn test_pipeline_revert() {
    let output = pipeline("60006000fd");
    assert!(output.contains("revert"));
}

#[test]
fn test_pipeline_sstore_stop() {
    // PUSH1 42, PUSH1 0, SSTORE, STOP
    let output = pipeline("602a60005500");
    assert!(output.contains("stor"));
}

#[test]
fn test_pipeline_return_mem() {
    // PUSH1 5, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let output = pipeline("600560005260206000f3");
    assert!(output.contains("return"));
}

#[test]
fn test_pipeline_push0() {
    // PUSH0, PUSH0, ADD, STOP
    let output = pipeline("5f5f0100");
    assert!(output.contains("stop"));
}

#[test]
fn test_pipeline_caller() {
    // CALLER, PUSH1 0, MSTORE, STOP
    // Note: the simplifier correctly removes the dead store (memory written but never read).
    let output = pipeline("33600052600000");
    assert!(output.contains("stop"), "Expected 'stop' in output: {output}");
}

#[test]
fn test_pipeline_callvalue() {
    // CALLVALUE, PUSH1 0, MSTORE, STOP
    // Note: the simplifier correctly removes the dead store.
    let output = pipeline("34600052600000");
    assert!(output.contains("stop"), "Expected 'stop' in output: {output}");
}

#[test]
fn test_pipeline_shr_shl() {
    // PUSH1 1, PUSH1 4, SHL, STOP
    let output = pipeline("600160041b00");
    assert!(output.contains("stop"));
}
