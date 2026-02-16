//! Contract-level analysis and post-processing.

use crate::function::Function;
use serde::{Deserialize, Serialize};

/// A constant declaration extracted from the bytecode (immutable addresses, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstDecl {
    pub name: String,
    pub value: String,
}

/// A decompiled contract containing all discovered functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub functions: Vec<Function>,
    pub problems: Vec<(String, String)>,
    #[serde(default)]
    pub const_decls: Vec<ConstDecl>,
}

impl Contract {
    /// Create a new contract with a list of functions and any decompilation problems.
    pub fn new(functions: Vec<Function>, problems: Vec<(String, String)>) -> Self {
        Self {
            functions,
            problems,
            const_decls: Vec::new(),
        }
    }

    /// Post-process: sort functions, detect storage layout, etc.
    pub fn postprocess(&mut self) {
        // Sort functions: const first, then getters, then by size.
        self.functions.sort_by_key(|f| {
            if f.is_const {
                0
            } else if f.getter.is_some() {
                1
            } else {
                2
            }
        });
    }

    /// Serialise the contract to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "problems": self.problems,
            "functions": self.functions.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::Expr;

    #[test]
    fn test_contract_json() {
        let funcs = vec![Function::new(
            "0x12345678".to_string(),
            "test()".to_string(),
            vec![Expr::node0("stop")],
        )];
        let c = Contract::new(funcs, vec![]);
        let j = c.to_json();
        assert!(j["functions"].is_array());
    }

    #[test]
    fn test_postprocess_ordering() {
        let f1 = Function::new(
            "0x1".to_string(),
            "regular()".to_string(),
            vec![Expr::node0("stop")],
        );
        let mut f2 = Function::new(
            "0x2".to_string(),
            "constant()".to_string(),
            vec![Expr::node1("return", Expr::val(42))],
        );
        f2.is_const = true;
        let mut c = Contract::new(vec![f1, f2], vec![]);
        c.postprocess();
        assert!(c.functions[0].is_const); // const should come first
    }
}
