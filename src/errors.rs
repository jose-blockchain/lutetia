//! Domain-specific error types.
//!
//! Uses `thiserror` for structured error definitions rather than relying
//! solely on `anyhow` for everything.

use thiserror::Error;

/// Errors from the bytecode loader.
#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("invalid hex input: {0}")]
    InvalidHex(String),

    #[error("empty bytecode")]
    EmptyBytecode,

    #[error("bytecode too large ({0} bytes, max {1})")]
    BytecodeTooLarge(usize, usize),
}

/// Errors from the symbolic VM.
#[derive(Debug, Error)]
pub enum VmError {
    #[error("execution timeout after {0}s")]
    Timeout(u64),

    #[error("node limit exceeded ({0} nodes, max {1})")]
    NodeLimitExceeded(usize, usize),

    #[error("dynamic jump target at offset {0}")]
    DynamicJump(usize),

    #[error("invalid jump destination at offset {0}")]
    InvalidJumpDest(usize),

    #[error("missing instruction at offset {0}")]
    MissingInstruction(usize),
}

/// Errors from the symbolic stack.
#[derive(Debug, Error)]
pub enum StackError {
    #[error("stack underflow: needed {needed} items, have {have}")]
    Underflow { needed: usize, have: usize },

    #[error("dup{0} out of range (stack depth {1})")]
    DupOutOfRange(usize, usize),

    #[error("swap{0} out of range (stack depth {1})")]
    SwapOutOfRange(usize, usize),
}

/// Maximum allowed bytecode size (24 KB, the EVM contract limit).
pub const MAX_BYTECODE_SIZE: usize = 24_576;
/// Maximum number of CFG nodes before aborting.
pub const MAX_NODE_COUNT: usize = 5_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = LoaderError::InvalidHex("bad".into());
        assert_eq!(e.to_string(), "invalid hex input: bad");

        let e = VmError::Timeout(60);
        assert_eq!(e.to_string(), "execution timeout after 60s");

        let e = StackError::Underflow { needed: 2, have: 1 };
        assert!(e.to_string().contains("underflow"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoaderError>();
        assert_send_sync::<VmError>();
        assert_send_sync::<StackError>();
    }
}
