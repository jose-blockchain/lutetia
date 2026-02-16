//! Symbolic stack used by the VM.

use crate::errors::StackError;
use crate::expr::Expr;
use primitive_types::U256;

/// A symbolic EVM stack.
#[derive(Debug, Clone)]
pub struct Stack {
    pub items: Vec<Expr>,
}

impl Stack {
    /// Create a new empty stack.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create a stack from an existing vector of expressions.
    pub fn from_vec(v: Vec<Expr>) -> Self {
        Self { items: v }
    }

    /// Return the current stack depth.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Push a value onto the stack, clamping integers to 256 bits.
    pub fn push(&mut self, val: Expr) {
        // Simple simplification: mask integers to 256 bits.
        let val = match val {
            Expr::Val(v) => Expr::Val(v & U256::MAX),
            other => other,
        };
        self.items.push(val);
    }

    /// Pop the top element. Returns `Err(StackError::Underflow)` if empty.
    pub fn try_pop(&mut self) -> Result<Expr, StackError> {
        self.items.pop().ok_or(StackError::Underflow { needed: 1, have: 0 })
    }

    /// Pop the top element. Returns a sentinel `Expr::atom("STACK_UNDERFLOW")`
    /// on underflow — used in the VM where we want to keep executing rather
    /// than aborting.
    pub fn pop(&mut self) -> Expr {
        self.items.pop().unwrap_or_else(|| {
            log::debug!("stack underflow (depth 0)");
            Expr::atom("STACK_UNDERFLOW")
        })
    }

    /// Peek at the top element without removing it.
    pub fn peek(&self) -> Option<&Expr> {
        self.items.last()
    }

    /// Duplicate the n-th element from the top. Returns `Err` if out of range.
    pub fn try_dup(&mut self, n: usize) -> Result<(), StackError> {
        if n == 0 || n > self.items.len() {
            return Err(StackError::DupOutOfRange(n, self.items.len()));
        }
        let idx = self.items.len() - n;
        let val = self.items[idx].clone();
        self.items.push(val);
        Ok(())
    }

    /// Duplicate the n-th element from the top (graceful, logs on error).
    pub fn dup(&mut self, n: usize) {
        if let Err(e) = self.try_dup(n) {
            log::debug!("{e}");
            self.items.push(Expr::atom("STACK_UNDERFLOW"));
        }
    }

    /// Swap the top element with the n-th element below it. Returns `Err` if out of range.
    pub fn try_swap(&mut self, n: usize) -> Result<(), StackError> {
        if n == 0 || self.items.len() <= n {
            return Err(StackError::SwapOutOfRange(n, self.items.len()));
        }
        let top = self.items.len() - 1;
        let target = self.items.len() - 1 - n;
        self.items.swap(top, target);
        Ok(())
    }

    /// Swap the top element with the n-th below it (graceful, logs on error).
    pub fn swap(&mut self, n: usize) {
        if let Err(e) = self.try_swap(n) {
            log::debug!("{e}");
        }
    }

    /// Get the jump destination candidates from the stack.
    pub fn jump_dests(&self, known_jds: &[usize]) -> Vec<String> {
        self.items
            .iter()
            .filter_map(|el| {
                if let Expr::Val(v) = el {
                    let n = v.low_u64() as usize;
                    if known_jds.contains(&n) || (n > 2000 && n < 5000) {
                        return Some(n.to_string());
                    }
                }
                None
            })
            .collect()
    }
}

/// When a loop is detected, fold the stacks from the beginning and end of the
/// loop to identify loop variables.
///
/// Returns (folded_stack, vars).
pub fn fold_stacks(
    first: &[Expr],
    second: &[Expr],
    depth: usize,
) -> (Vec<Expr>, Vec<(String, usize, Expr, usize)>) {
    assert_eq!(first.len(), second.len());
    let mut folded = first.to_vec();
    let mut vars = Vec::new();

    for idx in (0..first.len()).rev() {
        if first[idx] != second[idx] {
            let var_counter = first.len() - idx + depth * 1000;
            let var_name = format!("_{var_counter}");
            vars.push((var_name.clone(), var_counter, first[idx].clone(), idx));
            folded[idx] = Expr::node1("var", Expr::Atom(var_name));
        }
    }

    (folded, vars)
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop() {
        let mut s = Stack::new();
        s.push(Expr::val(42));
        assert_eq!(s.len(), 1);
        assert_eq!(s.pop(), Expr::val(42));
        assert!(s.is_empty());
    }

    #[test]
    fn test_dup() {
        let mut s = Stack::new();
        s.push(Expr::val(1));
        s.push(Expr::val(2));
        s.dup(2); // dup the element 2 from top
        assert_eq!(s.len(), 3);
        assert_eq!(s.pop(), Expr::val(1));
    }

    #[test]
    fn test_swap() {
        let mut s = Stack::new();
        s.push(Expr::val(1));
        s.push(Expr::val(2));
        s.swap(1);
        assert_eq!(s.pop(), Expr::val(1));
        assert_eq!(s.pop(), Expr::val(2));
    }

    #[test]
    fn test_fold_stacks() {
        let first = vec![Expr::val(10), Expr::val(20)];
        let second = vec![Expr::val(10), Expr::val(30)];
        let (folded, vars) = fold_stacks(&first, &second, 0);
        assert_eq!(vars.len(), 1);
        assert!(matches!(&folded[1], Expr::Node(op, _) if op == "var"));
    }
}
