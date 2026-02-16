//! Extended tests for opcode table coverage across all hard forks.

use lutetia::utils::opcodes::*;

#[test]
fn test_all_frontier_opcodes_present() {
    let table = build_opcode_table();
    let frontier_ops: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
        0x20,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0xF0, 0xF1, 0xF2, 0xF3, 0xFE, 0xFF,
    ];
    for &byte in frontier_ops {
        assert!(table.contains_key(&byte), "missing frontier opcode 0x{byte:02x}");
    }
}

#[test]
fn test_push_range() {
    let table = build_opcode_table();
    for n in 0u8..=32 {
        let byte = 0x5F + n;
        assert!(table.contains_key(&byte), "missing push{n} at 0x{byte:02x}");
    }
}

#[test]
fn test_dup_range() {
    let table = build_opcode_table();
    for n in 1u8..=16 {
        let byte = 0x7F + n;
        assert!(table.contains_key(&byte), "missing dup{n} at 0x{byte:02x}");
        let info = &table[&byte];
        assert_eq!(info.stack_diff(), 1, "dup{n} should have stack_diff=1");
    }
}

#[test]
fn test_swap_range() {
    let table = build_opcode_table();
    for n in 1u8..=16 {
        let byte = 0x8F + n;
        assert!(table.contains_key(&byte), "missing swap{n} at 0x{byte:02x}");
        let info = &table[&byte];
        assert_eq!(info.stack_diff(), 0, "swap{n} should have stack_diff=0");
    }
}

#[test]
fn test_log_range() {
    let table = build_opcode_table();
    for n in 0u8..=4 {
        let byte = 0xA0 + n;
        assert!(table.contains_key(&byte), "missing log{n} at 0x{byte:02x}");
    }
}

#[test]
fn test_byzantium_opcodes() {
    let table = build_opcode_table();
    assert_eq!(table[&0x3D].name, "returndatasize");
    assert_eq!(table[&0x3E].name, "returndatacopy");
    assert_eq!(table[&0xFA].name, "staticcall");
    assert_eq!(table[&0xFD].name, "revert");
}

#[test]
fn test_constantinople_shifts_create2() {
    let table = build_opcode_table();
    assert_eq!(table[&0x1B].since, EvmVersion::Constantinople);
    assert_eq!(table[&0x1C].since, EvmVersion::Constantinople);
    assert_eq!(table[&0x1D].since, EvmVersion::Constantinople);
    assert_eq!(table[&0xF5].since, EvmVersion::Constantinople);
}

#[test]
fn test_istanbul_chainid_selfbalance() {
    let table = build_opcode_table();
    assert_eq!(table[&0x46].since, EvmVersion::Istanbul);
    assert_eq!(table[&0x47].since, EvmVersion::Istanbul);
}

#[test]
fn test_london_basefee() {
    let table = build_opcode_table();
    assert_eq!(table[&0x48].since, EvmVersion::London);
}

#[test]
fn test_shanghai_push0() {
    let table = build_opcode_table();
    assert_eq!(table[&0x5F].since, EvmVersion::Shanghai);
    assert_eq!(table[&0x5F].immediate_bytes, 0);
    assert_eq!(table[&0x5F].pushes, 1);
    assert_eq!(table[&0x5F].pops, 0);
}

#[test]
fn test_cancun_tload_tstore_mcopy_blob() {
    let table = build_opcode_table();
    assert_eq!(table[&0x5C].since, EvmVersion::Cancun);
    assert_eq!(table[&0x5D].since, EvmVersion::Cancun);
    assert_eq!(table[&0x5E].since, EvmVersion::Cancun);
    assert_eq!(table[&0x49].since, EvmVersion::Cancun);
    assert_eq!(table[&0x4A].since, EvmVersion::Cancun);
}

#[test]
fn test_immediate_size_lookup() {
    assert_eq!(immediate_size(0x60), 1);   // PUSH1
    assert_eq!(immediate_size(0x7F), 32);  // PUSH32
    assert_eq!(immediate_size(0x00), 0);   // STOP
    assert_eq!(immediate_size(0x01), 0);   // ADD
}

#[test]
fn test_opcode_name_lookup() {
    assert_eq!(opcode_name(0x00), Some("stop"));
    assert_eq!(opcode_name(0x01), Some("add"));
    assert_eq!(opcode_name(0xFE), Some("invalid"));
    assert_eq!(opcode_name(0xEF), None); // unused
}

#[test]
fn test_build_stack_diffs() {
    let diffs = build_stack_diffs();
    assert_eq!(diffs["add"], -1);   // 2 pop, 1 push
    assert_eq!(diffs["stop"], 0);
    assert_eq!(diffs["push"], 1);
    assert_eq!(diffs["dup"], 1);
    assert_eq!(diffs["swap"], 0);
}

#[test]
fn test_evm_version_ordering() {
    assert!(EvmVersion::Frontier < EvmVersion::Homestead);
    assert!(EvmVersion::Homestead < EvmVersion::Cancun);
    assert!(EvmVersion::Cancun < EvmVersion::Prague);
}
