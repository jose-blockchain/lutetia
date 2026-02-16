//! Extended loader tests.

use lutetia::loader::Loader;

#[test]
fn test_load_all_push_variants() {
    let mut loader = Loader::new();
    // PUSH1 through PUSH32 — we just test a few key ones.
    // PUSH1 0xFF
    loader.load_binary("60ff").unwrap();
    assert_eq!(loader.parsed_lines.len(), 1);
    assert!(loader.parsed_lines[0].op.starts_with("push"));

    // PUSH2 0x0100
    let mut loader = Loader::new();
    loader.load_binary("610100").unwrap();
    assert_eq!(loader.parsed_lines.len(), 1);

    // PUSH32 (all zeros)
    let mut loader = Loader::new();
    loader.load_binary(&format!("7f{}", "00".repeat(32))).unwrap();
    assert_eq!(loader.parsed_lines.len(), 1);
    assert_eq!(loader.parsed_lines[0].op, "push32");
}

#[test]
fn test_dup_and_swap_disassembly() {
    let mut loader = Loader::new();
    // DUP1 (0x80), SWAP1 (0x90)
    loader.load_binary("8090").unwrap();
    assert_eq!(loader.parsed_lines.len(), 2);
    assert_eq!(loader.parsed_lines[0].op, "dup1");
    assert_eq!(loader.parsed_lines[1].op, "swap1");
}

#[test]
fn test_log_disassembly() {
    let mut loader = Loader::new();
    // LOG0 (0xA0), LOG4 (0xA4)
    loader.load_binary("a0a4").unwrap();
    assert_eq!(loader.parsed_lines.len(), 2);
    assert_eq!(loader.parsed_lines[0].op, "log0");
    assert_eq!(loader.parsed_lines[1].op, "log4");
}

#[test]
fn test_unknown_opcode() {
    let mut loader = Loader::new();
    // 0xEF is not assigned in any EVM version
    loader.load_binary("ef").unwrap();
    assert_eq!(loader.parsed_lines.len(), 1);
    assert_eq!(loader.parsed_lines[0].op, "UNKNOWN");
}

#[test]
fn test_multiple_jumpdests() {
    let mut loader = Loader::new();
    // JUMPDEST (0x5B) at offset 0 and offset 2
    // offset 0: JUMPDEST, offset 1: STOP, offset 2: JUMPDEST
    loader.load_binary("5b005b").unwrap();
    assert_eq!(loader.jump_dests.len(), 2);
    assert!(loader.jump_dests.contains(&0));
    assert!(loader.jump_dests.contains(&2));
}

#[test]
fn test_disasm_format() {
    let mut loader = Loader::new();
    loader.load_binary("6042600001").unwrap();
    let lines = loader.disasm();
    assert!(lines[0].starts_with("0x0000"));
    assert!(lines[0].contains("push1"));
}

#[test]
fn test_next_line_at_end() {
    let mut loader = Loader::new();
    loader.load_binary("00").unwrap(); // single STOP
    assert_eq!(loader.next_line(0), None);
}

#[test]
fn test_add_func() {
    let mut loader = Loader::new();
    loader.load_binary("00").unwrap();
    loader.add_func(0, Some("0x12345678"), None, vec![]);
    assert_eq!(loader.func_list.len(), 1);
    assert!(loader.hash_targets.contains_key("0x12345678"));
}

#[test]
fn test_cancun_opcodes_present() {
    let mut loader = Loader::new();
    // TLOAD, TSTORE, MCOPY, BLOBHASH (preceded by a push), BLOBBASEFEE
    loader.load_binary("5c5d5e49004a").unwrap();
    // 0x5C=tload, 0x5D=tstore, 0x5E=mcopy
    assert_eq!(loader.parsed_lines[0].op, "tload");
    assert_eq!(loader.parsed_lines[1].op, "tstore");
    assert_eq!(loader.parsed_lines[2].op, "mcopy");
    // 0x49=blobhash, 0x4A=blobbasefee
    assert_eq!(loader.parsed_lines[3].op, "blobhash");
}

#[test]
fn test_push0_shanghai() {
    let mut loader = Loader::new();
    loader.load_binary("5f00").unwrap(); // PUSH0, STOP
    assert_eq!(loader.parsed_lines.len(), 2);
    assert_eq!(loader.parsed_lines[0].op, "push0");
}

#[test]
fn test_0x_prefix_stripped() {
    let mut l1 = Loader::new();
    l1.load_binary("0x6042").unwrap();
    let mut l2 = Loader::new();
    l2.load_binary("6042").unwrap();
    assert_eq!(l1.binary, l2.binary);
}
