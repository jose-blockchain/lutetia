//! Bytecode loading and disassembly.
//!
//! Parses EVM bytecode into a sequence of `(offset, opcode, param)` instructions
//! and discovers function selectors.

use crate::errors::LoaderError;
use crate::expr::Expr;
use crate::utils::helpers::padded_hex;
use crate::utils::opcodes;
use primitive_types::U256;
use std::collections::HashMap;

/// A parsed instruction: (byte offset, opcode name, optional immediate).
#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset: usize,
    pub op: String,
    pub param: Option<U256>,
}

/// The Loader holds disassembled bytecode and discovered function entry points.
#[derive(Debug, Clone)]
pub struct Loader {
    /// Raw bytecode as bytes.
    pub binary: Vec<u8>,
    /// Parsed instructions keyed by byte offset.
    pub lines: HashMap<usize, Instruction>,
    /// Parsed instructions in order.
    pub parsed_lines: Vec<Instruction>,
    /// Jump destination offsets.
    pub jump_dests: Vec<usize>,
    /// Discovered function selectors: hash → (target offset, stack).
    pub hash_targets: HashMap<String, (usize, Vec<Expr>)>,
    /// Function list: (hash, name, target, stack).
    pub func_list: Vec<(String, String, usize, Vec<Expr>)>,
    /// Last byte offset.
    pub last_line: usize,
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl Loader {
    /// Create a new, empty loader ready to accept bytecode.
    pub fn new() -> Self {
        Self {
            binary: Vec::new(),
            lines: HashMap::new(),
            parsed_lines: Vec::new(),
            jump_dests: Vec::new(),
            hash_targets: HashMap::new(),
            func_list: Vec::new(),
            last_line: 0,
        }
    }

    /// Load bytecode from a hex string (with or without `0x` prefix).
    ///
    /// Returns `Err(LoaderError::InvalidHex)` on malformed hex instead of
    /// silently returning empty.
    pub fn load_binary(&mut self, source: &str) -> Result<(), LoaderError> {
        let hex_str = source
            .strip_prefix("0x")
            .unwrap_or(source)
            .trim();

        if hex_str.is_empty() {
            self.binary = Vec::new();
            return Ok(());
        }

        self.binary = hex::decode(hex_str)
            .map_err(|_| LoaderError::InvalidHex(
                if hex_str.len() > 40 { format!("{}...", &hex_str[..40]) } else { hex_str.to_string() }
            ))?;

        self.disassemble();
        Ok(())
    }

    /// Disassemble the loaded binary into instructions.
    fn disassemble(&mut self) {
        let opcode_table = opcodes::build_opcode_table();
        let bytes = &self.binary;
        let mut offset = 0usize;
        let mut parsed = Vec::new();

        while offset < bytes.len() {
            let byte = bytes[offset];
            let orig_offset = offset;

            if let Some(info) = opcode_table.get(&byte) {
                let op = info.name.to_string();

                if op == "jumpdest" {
                    self.jump_dests.push(orig_offset);
                }

                let param = if info.immediate_bytes > 0 {
                    let mut val = U256::zero();
                    for _ in 0..info.immediate_bytes {
                        offset += 1;
                        if offset < bytes.len() {
                            val = (val << 8) | U256::from(bytes[offset] as u64);
                        }
                    }
                    Some(val)
                } else {
                    None
                };

                parsed.push(Instruction {
                    offset: orig_offset,
                    op,
                    param,
                });
            } else {
                parsed.push(Instruction {
                    offset: orig_offset,
                    op: "UNKNOWN".to_string(),
                    param: Some(U256::from(byte as u64)),
                });
            }

            offset += 1;
        }

        self.last_line = offset;

        // Build the lines lookup and normalize dup/swap/push.
        for inst in &parsed {
            let mut op = inst.op.clone();
            let mut param = inst.param;

            if op.starts_with("dup") && op.len() > 3 {
                if let Ok(n) = op[3..].parse::<u64>() {
                    param = Some(U256::from(n));
                    op = "dup".to_string();
                }
            } else if op.starts_with("swap") && op.len() > 4 {
                if let Ok(n) = op[4..].parse::<u64>() {
                    param = Some(U256::from(n));
                    op = "swap".to_string();
                }
            } else if op.starts_with("push") && op != "push0" {
                // param is already set from the immediate bytes
                // Normalize large constants to printable strings if possible
            }

            self.lines.insert(
                inst.offset,
                Instruction {
                    offset: inst.offset,
                    op,
                    param,
                },
            );
        }

        self.parsed_lines = parsed;
    }

    /// Find the next line after byte offset `i`.
    pub fn next_line(&self, i: usize) -> Option<usize> {
        let mut j = i + 1;
        while j <= self.last_line {
            if self.lines.contains_key(&j) {
                return Some(j);
            }
            j += 1;
        }
        None
    }

    /// Add a discovered function.
    pub fn add_func(&mut self, target: usize, hash: Option<&str>, name: Option<&str>, stack: Vec<Expr>) {
        let (key, display_name) = match (hash, name) {
            (Some(h), _) => {
                let padded = padded_hex(
                    U256::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)
                        .unwrap_or_default(),
                    8,
                );
                let n = format!("unknown_{padded}");
                (padded, n)
            }
            (None, Some(n)) => (n.to_string(), n.to_string()),
            _ => ("unknown".to_string(), "unknown".to_string()),
        };
        self.hash_targets.insert(key.clone(), (target, stack.clone()));
        self.func_list.push((key, display_name, target, stack));
    }

    /// Generate disassembly lines.
    pub fn disasm(&self) -> Vec<String> {
        self.parsed_lines
            .iter()
            .map(|inst| {
                let param_str = match &inst.param {
                    Some(v) if !v.is_zero() => format!(" 0x{v:x}"),
                    _ => String::new(),
                };
                format!("0x{:04x} {}{}", inst.offset, inst.op, param_str)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_simple_bytecode() {
        let mut loader = Loader::new();
        loader.load_binary("6042600052600000").unwrap();
        assert!(!loader.lines.is_empty());
        assert!(!loader.binary.is_empty());
    }

    #[test]
    fn test_load_with_0x_prefix() {
        let mut loader = Loader::new();
        loader.load_binary("0x6042600052").unwrap();
        assert!(!loader.binary.is_empty());
    }

    #[test]
    fn test_jumpdest_detection() {
        let mut loader = Loader::new();
        loader.load_binary("5b00").unwrap();
        assert!(loader.jump_dests.contains(&0));
    }

    #[test]
    fn test_disasm_output() {
        let mut loader = Loader::new();
        loader.load_binary("6001600201").unwrap();
        let disasm = loader.disasm();
        assert!(!disasm.is_empty());
        assert!(disasm[0].contains("push1"));
    }

    #[test]
    fn test_next_line() {
        let mut loader = Loader::new();
        loader.load_binary("60016002").unwrap();
        assert_eq!(loader.next_line(0), Some(2));
    }

    #[test]
    fn test_push0_shanghai() {
        let mut loader = Loader::new();
        loader.load_binary("5f").unwrap();
        assert_eq!(loader.parsed_lines.len(), 1);
        assert_eq!(loader.parsed_lines[0].op, "push0");
    }

    #[test]
    fn test_cancun_opcodes_disasm() {
        let mut loader = Loader::new();
        loader.load_binary("5c5d5e").unwrap();
        assert_eq!(loader.parsed_lines.len(), 3);
        assert_eq!(loader.parsed_lines[0].op, "tload");
        assert_eq!(loader.parsed_lines[1].op, "tstore");
        assert_eq!(loader.parsed_lines[2].op, "mcopy");
    }

    #[test]
    fn test_empty_bytecode() {
        let mut loader = Loader::new();
        loader.load_binary("").unwrap();
        assert!(loader.binary.is_empty());
        assert!(loader.parsed_lines.is_empty());
    }

    #[test]
    fn test_invalid_hex_returns_error() {
        let mut loader = Loader::new();
        let result = loader.load_binary("not_valid_hex!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoaderError::InvalidHex(_)));
    }
}
