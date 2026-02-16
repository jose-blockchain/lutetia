//! Prettify tests.

use lutetia::expr::Expr;
use lutetia::prettify::{panic_code_description, pprint_trace, prettify};

#[test]
fn test_prettify_atoms() {
    assert_eq!(prettify(&Expr::atom("caller"), false), "caller");
    assert_eq!(prettify(&Expr::atom("callvalue"), false), "call.value");
    assert_eq!(prettify(&Expr::atom("timestamp"), false), "block.timestamp");
    assert_eq!(prettify(&Expr::atom("number"), false), "block.number");
    assert_eq!(prettify(&Expr::atom("coinbase"), false), "block.coinbase");
    assert_eq!(prettify(&Expr::atom("basefee"), false), "block.basefee");
    assert_eq!(prettify(&Expr::atom("blobbasefee"), false), "block.blobbasefee");
    assert_eq!(prettify(&Expr::atom("chainid"), false), "chainid");
    assert_eq!(prettify(&Expr::atom("gas"), false), "gas_remaining");
}

#[test]
fn test_prettify_arithmetic() {
    assert_eq!(
        prettify(&Expr::node2("add", Expr::val(1), Expr::val(2)), false),
        "(1 + 2)"
    );
    assert_eq!(
        prettify(&Expr::node2("sub", Expr::val(5), Expr::val(3)), false),
        "(5 - 3)"
    );
    assert_eq!(
        prettify(&Expr::node2("mul", Expr::val(3), Expr::val(7)), false),
        "(3 * 7)"
    );
    assert_eq!(
        prettify(&Expr::node2("div", Expr::val(10), Expr::val(3)), false),
        "(10 / 3)"
    );
    assert_eq!(
        prettify(&Expr::node2("mod", Expr::val(10), Expr::val(3)), false),
        "(10 % 3)"
    );
}

#[test]
fn test_prettify_comparisons() {
    assert_eq!(
        prettify(&Expr::node2("eq", Expr::atom("x"), Expr::val(5)), false),
        "x == 5"
    );
    assert_eq!(
        prettify(&Expr::node2("lt", Expr::atom("x"), Expr::val(5)), false),
        "x < 5"
    );
    assert_eq!(
        prettify(&Expr::node2("gt", Expr::atom("x"), Expr::val(5)), false),
        "x > 5"
    );
}

#[test]
fn test_prettify_boolean() {
    assert_eq!(prettify(&Expr::Bool(true), false), "True");
    assert_eq!(prettify(&Expr::Bool(false), false), "False");
}

#[test]
fn test_prettify_storage() {
    let s = Expr::Node(
        "storage".to_string(),
        vec![Expr::val(256), Expr::zero(), Expr::val(0)],
    );
    assert_eq!(prettify(&s, false), "stor[0]");
}

#[test]
fn test_prettify_tstorage() {
    let s = Expr::Node(
        "tstorage".to_string(),
        vec![Expr::val(256), Expr::zero(), Expr::val(1)],
    );
    assert_eq!(prettify(&s, false), "tstor[1]");
}

#[test]
fn test_prettify_stop() {
    assert_eq!(prettify(&Expr::node0("stop"), false), "stop");
}

#[test]
fn test_prettify_revert_zero() {
    assert_eq!(prettify(&Expr::node1("revert", Expr::zero()), false), "revert");
}

#[test]
fn test_prettify_revert_data() {
    let r = Expr::node1("revert", Expr::atom("data"));
    assert!(prettify(&r, false).contains("revert with"));
}

#[test]
fn test_prettify_selfdestruct() {
    let s = Expr::node1("selfdestruct", Expr::atom("addr"));
    assert!(prettify(&s, false).contains("selfdestruct"));
}

#[test]
fn test_prettify_balance() {
    let b = Expr::node1("balance", Expr::atom("addr"));
    assert_eq!(prettify(&b, false), "eth.balance(addr)");
}

#[test]
fn test_prettify_cd_zero() {
    let cd = Expr::node1("cd", Expr::zero());
    assert_eq!(prettify(&cd, false), "call.func_hash");
}

#[test]
fn test_prettify_cd_nonzero() {
    let cd = Expr::node1("cd", Expr::val(4));
    assert_eq!(prettify(&cd, false), "cd[4]");
}

#[test]
fn test_prettify_not() {
    assert_eq!(prettify(&Expr::node1("not", Expr::atom("x")), false), "!x");
}

#[test]
fn test_prettify_shifts() {
    assert_eq!(
        prettify(&Expr::node2("shl", Expr::val(4), Expr::atom("x")), false),
        "x << 4"
    );
    assert_eq!(
        prettify(&Expr::node2("shr", Expr::val(4), Expr::atom("x")), false),
        "x >> 4"
    );
}

#[test]
fn test_pprint_trace_if() {
    let trace = vec![Expr::node3(
        "if",
        Expr::atom("cond"),
        Expr::node0("stop"),
        Expr::node1("revert", Expr::zero()),
    )];
    let output = pprint_trace(&trace, false);
    assert!(output.contains("if cond:"));
    assert!(output.contains("else:"));
}

#[test]
fn test_pprint_trace_while() {
    let trace = vec![Expr::node2(
        "while",
        Expr::atom("cond"),
        Expr::node0("stop"),
    )];
    let output = pprint_trace(&trace, false);
    assert!(output.contains("while cond:"));
}

#[test]
fn test_panic_codes() {
    assert_eq!(panic_code_description(0x00), Some("Used for generic compiler inserted panics."));
    assert_eq!(panic_code_description(0x01), Some("assert with false argument."));
    assert_eq!(panic_code_description(0x11), Some("Arithmetic overflow/underflow."));
    assert_eq!(panic_code_description(0x12), Some("Division or modulo by zero."));
    assert_eq!(panic_code_description(0x32), Some("Out-of-bounds array access."));
    assert_eq!(panic_code_description(0x99), None);
}
