//! EVM opcode definitions covering every hard-fork from Frontier through Prague.
//!
//! Each opcode carries its byte value, mnemonic, the stack items it pops / pushes,
//! and the hard-fork that introduced it.

use std::collections::HashMap;

/// EVM hard-fork versions (chronological order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvmVersion {
    Frontier,
    Homestead,
    TangerineWhistle,
    SpuriousDragon,
    Byzantium,
    Constantinople,
    Istanbul,
    Berlin,
    London,
    Paris,        // The Merge
    Shanghai,
    Cancun,
    Prague,
}

impl EvmVersion {
    /// Return all EVM versions in chronological order.
    pub fn all() -> &'static [EvmVersion] {
        &[
            EvmVersion::Frontier,
            EvmVersion::Homestead,
            EvmVersion::TangerineWhistle,
            EvmVersion::SpuriousDragon,
            EvmVersion::Byzantium,
            EvmVersion::Constantinople,
            EvmVersion::Istanbul,
            EvmVersion::Berlin,
            EvmVersion::London,
            EvmVersion::Paris,
            EvmVersion::Shanghai,
            EvmVersion::Cancun,
            EvmVersion::Prague,
        ]
    }
}

/// Information about a single opcode.
#[derive(Debug, Clone)]
pub struct OpcodeInfo {
    pub byte: u8,
    pub name: &'static str,
    /// Number of stack items consumed.
    pub pops: u8,
    /// Number of stack items produced.
    pub pushes: u8,
    /// The hard-fork that introduced this opcode.
    pub since: EvmVersion,
    /// If this is a `PUSHn`, the number of immediate bytes.
    pub immediate_bytes: u8,
}

impl OpcodeInfo {
    /// Stack diff = pushes − pops  (may be negative).
    pub fn stack_diff(&self) -> i16 {
        self.pushes as i16 - self.pops as i16
    }
}

/// Build the full opcode table (byte → info).
pub fn build_opcode_table() -> HashMap<u8, OpcodeInfo> {
    use EvmVersion::*;

    let mut m: HashMap<u8, OpcodeInfo> = HashMap::new();

    macro_rules! op {
        ($byte:expr, $name:expr, $pops:expr, $pushes:expr, $since:expr) => {
            m.insert($byte, OpcodeInfo {
                byte: $byte,
                name: $name,
                pops: $pops,
                pushes: $pushes,
                since: $since,
                immediate_bytes: 0,
            });
        };
        ($byte:expr, $name:expr, $pops:expr, $pushes:expr, $since:expr, $imm:expr) => {
            m.insert($byte, OpcodeInfo {
                byte: $byte,
                name: $name,
                pops: $pops,
                pushes: $pushes,
                since: $since,
                immediate_bytes: $imm,
            });
        };
    }

    // -- Stop and Arithmetic -----------------------------------------------
    op!(0x00, "stop",         0, 0, Frontier);
    op!(0x01, "add",          2, 1, Frontier);
    op!(0x02, "mul",          2, 1, Frontier);
    op!(0x03, "sub",          2, 1, Frontier);
    op!(0x04, "div",          2, 1, Frontier);
    op!(0x05, "sdiv",         2, 1, Frontier);
    op!(0x06, "mod",          2, 1, Frontier);
    op!(0x07, "smod",         2, 1, Frontier);
    op!(0x08, "addmod",       3, 1, Frontier);
    op!(0x09, "mulmod",       3, 1, Frontier);
    op!(0x0A, "exp",          2, 1, Frontier);
    op!(0x0B, "signextend",   2, 1, Frontier);

    // -- Comparison and Bitwise Logic --------------------------------------
    op!(0x10, "lt",           2, 1, Frontier);
    op!(0x11, "gt",           2, 1, Frontier);
    op!(0x12, "slt",          2, 1, Frontier);
    op!(0x13, "sgt",          2, 1, Frontier);
    op!(0x14, "eq",           2, 1, Frontier);
    op!(0x15, "iszero",       1, 1, Frontier);
    op!(0x16, "and",          2, 1, Frontier);
    op!(0x17, "or",           2, 1, Frontier);
    op!(0x18, "xor",          2, 1, Frontier);
    op!(0x19, "not",          1, 1, Frontier);
    op!(0x1A, "byte",         2, 1, Frontier);
    // Constantinople
    op!(0x1B, "shl",          2, 1, Constantinople);
    op!(0x1C, "shr",          2, 1, Constantinople);
    op!(0x1D, "sar",          2, 1, Constantinople);

    // -- SHA3 --------------------------------------------------------------
    op!(0x20, "sha3",         2, 1, Frontier);

    // -- Environment Information -------------------------------------------
    op!(0x30, "address",      0, 1, Frontier);
    op!(0x31, "balance",      1, 1, Frontier);
    op!(0x32, "origin",       0, 1, Frontier);
    op!(0x33, "caller",       0, 1, Frontier);
    op!(0x34, "callvalue",    0, 1, Frontier);
    op!(0x35, "calldataload", 1, 1, Frontier);
    op!(0x36, "calldatasize", 0, 1, Frontier);
    op!(0x37, "calldatacopy", 3, 0, Frontier);
    op!(0x38, "codesize",     0, 1, Frontier);
    op!(0x39, "codecopy",     3, 0, Frontier);
    op!(0x3A, "gasprice",     0, 1, Frontier);
    op!(0x3B, "extcodesize",  1, 1, Frontier);
    op!(0x3C, "extcodecopy",  4, 0, Frontier);
    // Byzantium
    op!(0x3D, "returndatasize", 0, 1, Byzantium);
    op!(0x3E, "returndatacopy", 3, 0, Byzantium);
    // Constantinople
    op!(0x3F, "extcodehash",  1, 1, Constantinople);

    // -- Block Information -------------------------------------------------
    op!(0x40, "blockhash",    1, 1, Frontier);
    op!(0x41, "coinbase",     0, 1, Frontier);
    op!(0x42, "timestamp",    0, 1, Frontier);
    op!(0x43, "number",       0, 1, Frontier);
    op!(0x44, "difficulty",   0, 1, Frontier);  // prevrandao post-Paris
    op!(0x45, "gaslimit",     0, 1, Frontier);
    // Istanbul
    op!(0x46, "chainid",      0, 1, Istanbul);
    op!(0x47, "selfbalance",  0, 1, Istanbul);
    // London
    op!(0x48, "basefee",      0, 1, London);
    // Cancun
    op!(0x49, "blobhash",     1, 1, Cancun);
    op!(0x4A, "blobbasefee",  0, 1, Cancun);

    // -- Stack, Memory, Storage and Flow -----------------------------------
    op!(0x50, "pop",          1, 0, Frontier);
    op!(0x51, "mload",        1, 1, Frontier);
    op!(0x52, "mstore",       2, 0, Frontier);
    op!(0x53, "mstore8",      2, 0, Frontier);
    op!(0x54, "sload",        1, 1, Frontier);
    op!(0x55, "sstore",       2, 0, Frontier);
    op!(0x56, "jump",         1, 0, Frontier);
    op!(0x57, "jumpi",        2, 0, Frontier);
    op!(0x58, "pc",           0, 1, Frontier);
    op!(0x59, "msize",        0, 1, Frontier);
    op!(0x5A, "gas",          0, 1, Frontier);
    op!(0x5B, "jumpdest",     0, 0, Frontier);
    // Cancun
    op!(0x5C, "tload",        1, 1, Cancun);
    op!(0x5D, "tstore",       2, 0, Cancun);
    op!(0x5E, "mcopy",        3, 0, Cancun);

    // -- PUSH0 (Shanghai) --------------------------------------------------
    op!(0x5F, "push0",        0, 1, Shanghai, 0);

    // -- PUSH1..PUSH32 -----------------------------------------------------
    for n in 1u8..=32 {
        let byte = 0x5F + n;
        // We use a leaked string to get a &'static str for the name.
        // This is fine — the table is built once.
        let name: &'static str = Box::leak(format!("push{n}").into_boxed_str());
        m.insert(byte, OpcodeInfo {
            byte,
            name,
            pops: 0,
            pushes: 1,
            since: Frontier,
            immediate_bytes: n,
        });
    }

    // -- DUP1..DUP16 -------------------------------------------------------
    for n in 1u8..=16 {
        let byte = 0x7F + n;
        let name: &'static str = Box::leak(format!("dup{n}").into_boxed_str());
        m.insert(byte, OpcodeInfo {
            byte,
            name,
            pops: n,
            pushes: n + 1,
            since: Frontier,
            immediate_bytes: 0,
        });
    }

    // -- SWAP1..SWAP16 -----------------------------------------------------
    for n in 1u8..=16 {
        let byte = 0x8F + n;
        let name: &'static str = Box::leak(format!("swap{n}").into_boxed_str());
        m.insert(byte, OpcodeInfo {
            byte,
            name,
            pops: n + 1,
            pushes: n + 1,
            since: Frontier,
            immediate_bytes: 0,
        });
    }

    // -- LOG0..LOG4 ---------------------------------------------------------
    for n in 0u8..=4 {
        let byte = 0xA0 + n;
        let name: &'static str = Box::leak(format!("log{n}").into_boxed_str());
        m.insert(byte, OpcodeInfo {
            byte,
            name,
            pops: n + 2,
            pushes: 0,
            since: Frontier,
            immediate_bytes: 0,
        });
    }

    // -- System operations -------------------------------------------------
    op!(0xF0, "create",       3, 1, Frontier);
    op!(0xF1, "call",         7, 1, Frontier);
    op!(0xF2, "callcode",     7, 1, Frontier);
    op!(0xF3, "return",       2, 0, Frontier);
    // Byzantium
    op!(0xF4, "delegatecall", 6, 1, Homestead);
    // Constantinople
    op!(0xF5, "create2",      4, 1, Constantinople);
    // Byzantium
    op!(0xFA, "staticcall",   6, 1, Byzantium);
    op!(0xFD, "revert",       2, 0, Byzantium);
    op!(0xFE, "invalid",      0, 0, Frontier);
    op!(0xFF, "selfdestruct", 1, 0, Frontier);

    m
}

/// Build a name → stack-diff lookup (like the Python `stack_diffs`).
pub fn build_stack_diffs() -> HashMap<&'static str, i16> {
    let table = build_opcode_table();
    let mut diffs: HashMap<&'static str, i16> = HashMap::new();
    for info in table.values() {
        diffs.insert(info.name, info.stack_diff());
    }
    // Aliases used internally
    diffs.insert("push", 1);
    diffs.insert("dup", 1);
    diffs.insert("swap", 0);
    diffs.insert("assert_fail", 0);
    diffs
}

/// Lookup opcode name by byte value.
pub fn opcode_name(byte: u8) -> Option<&'static str> {
    // Use a thread-local cache so we don't rebuild each time.
    thread_local! {
        static TABLE: HashMap<u8, OpcodeInfo> = build_opcode_table();
    }
    TABLE.with(|t| t.get(&byte).map(|info| info.name))
}

/// Get the number of immediate bytes for a given opcode byte.
pub fn immediate_size(byte: u8) -> u8 {
    thread_local! {
        static TABLE: HashMap<u8, OpcodeInfo> = build_opcode_table();
    }
    TABLE.with(|t| t.get(&byte).map(|info| info.immediate_bytes).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_opcodes() {
        let table = build_opcode_table();
        assert_eq!(table[&0x00].name, "stop");
        assert_eq!(table[&0x01].name, "add");
        assert_eq!(table[&0x60].name, "push1");
        assert_eq!(table[&0x60].immediate_bytes, 1);
        assert_eq!(table[&0x7F].name, "push32");
        assert_eq!(table[&0x7F].immediate_bytes, 32);
        assert_eq!(table[&0x80].name, "dup1");
        assert_eq!(table[&0x90].name, "swap1");
        assert_eq!(table[&0xA0].name, "log0");
    }

    #[test]
    fn test_stack_diffs() {
        let table = build_opcode_table();
        assert_eq!(table[&0x01].stack_diff(), -1); // add: 2 pop, 1 push
        assert_eq!(table[&0x33].stack_diff(), 1);  // caller: 0 pop, 1 push
        assert_eq!(table[&0x55].stack_diff(), -2); // sstore: 2 pop, 0 push
    }

    #[test]
    fn test_cancun_opcodes() {
        let table = build_opcode_table();
        assert!(table.contains_key(&0x5C)); // tload
        assert!(table.contains_key(&0x5D)); // tstore
        assert!(table.contains_key(&0x5E)); // mcopy
        assert!(table.contains_key(&0x49)); // blobhash
        assert!(table.contains_key(&0x4A)); // blobbasefee
    }

    #[test]
    fn test_shanghai_push0() {
        let table = build_opcode_table();
        assert_eq!(table[&0x5F].name, "push0");
        assert_eq!(table[&0x5F].since, EvmVersion::Shanghai);
    }

    #[test]
    fn test_constantinople_opcodes() {
        let table = build_opcode_table();
        assert_eq!(table[&0x1B].name, "shl");
        assert_eq!(table[&0x1C].name, "shr");
        assert_eq!(table[&0x1D].name, "sar");
        assert_eq!(table[&0x3F].name, "extcodehash");
        assert_eq!(table[&0xF5].name, "create2");
    }

    #[test]
    fn test_istanbul_opcodes() {
        let table = build_opcode_table();
        assert_eq!(table[&0x46].name, "chainid");
        assert_eq!(table[&0x47].name, "selfbalance");
    }

    #[test]
    fn test_london_basefee() {
        let table = build_opcode_table();
        assert_eq!(table[&0x48].name, "basefee");
        assert_eq!(table[&0x48].since, EvmVersion::London);
    }

    #[test]
    fn test_all_hardfork_versions() {
        let versions = EvmVersion::all();
        assert_eq!(versions.len(), 13);
        assert_eq!(versions[0], EvmVersion::Frontier);
        assert_eq!(versions[12], EvmVersion::Prague);
    }

    #[test]
    fn test_opcode_name_lookup() {
        assert_eq!(opcode_name(0x01), Some("add"));
        assert_eq!(opcode_name(0xFE), Some("invalid"));
        assert_eq!(opcode_name(0xEF), None); // unused
    }
}
