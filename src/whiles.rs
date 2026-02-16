//! Label/goto → while loop conversion.
//!
//! Takes a trace containing `label`, `goto`, and `if` constructs
//! (produced by the VM's BFS execution) and converts them into
//! structured `while` loops with `continue` statements.

use crate::expr::{Expr, Trace};

/// Entry point: convert all labels/gotos to while loops, then clean up.
pub fn make_whiles(trace: &[Expr]) -> Trace {
    let result = make(trace);

    // Remove leftover jumpdest markers.
    let result = rewrite_each(&result, &|line| {
        if line.opcode() == Some("jumpdest") {
            vec![]
        } else {
            vec![line.clone()]
        }
    });

    result
}

/// Recursively transform a trace: convert `label`+body → `while` and `goto` → `continue`.
fn make(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();
    let mut idx = 0;

    while idx < trace.len() {
        let line = &trace[idx];

        if line.opcode() == Some("if") {
            // Recurse into both branches.
            if let Some(ch) = line.children() {
                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                let if_true = extract_seq(ch.get(1));
                let if_false = extract_seq(ch.get(2));
                result.push(Expr::node3(
                    "if",
                    cond,
                    Expr::node("seq", make(&if_true)),
                    Expr::node("seq", make(&if_false)),
                ));
            }
            idx += 1;
        } else if line.opcode() == Some("label") {
            // Label → extract the loop structure.
            if let Some(ch) = line.children() {
                let jd = ch.first().cloned().unwrap_or(Expr::zero());
                let vars = extract_seq(ch.get(1));

                let remaining = &trace[idx + 1..];

                match to_while(remaining, &jd) {
                    Some((before, inside, after, cond)) => {
                        // Substitute initial variable values into 'before' block.
                        let mut before = before;
                        for var_def in &vars {
                            if var_def.opcode() == Some("_var") {
                                if let Some(vch) = var_def.children() {
                                    let var_idx = vch.get(1).cloned().unwrap_or(Expr::zero());
                                    let var_init = vch.get(2).cloned().unwrap_or(Expr::zero());
                                    let var_ref = Expr::node1("var", var_idx.clone());
                                    before = before
                                        .iter()
                                        .map(|e| e.replace(&var_ref, &var_init))
                                        .collect();
                                }
                            }
                        }

                        let before = make(&before);
                        let inside = make(&inside);
                        let after = make(&after);

                        result.extend(before);
                        result.push(Expr::Node(
                            "while".to_string(),
                            vec![
                                cond,
                                Expr::node("seq", inside),
                                jd,
                                Expr::node("_vars", vars),
                            ],
                        ));
                        result.extend(after);
                        return result;
                    }
                    None => {
                        // Couldn't extract a while loop — pass the label through.
                        log::warn!("Couldn't convert label to while loop: {jd}");
                    }
                }
            }
            idx += 1;
        } else if line.opcode() == Some("goto") {
            // Convert goto to continue.
            if let Some(ch) = line.children() {
                let jd = ch.first().cloned().unwrap_or(Expr::zero());
                let setvars: Vec<Expr> = ch[1..].to_vec();
                result.push(Expr::Node(
                    "continue".to_string(),
                    std::iter::once(jd).chain(setvars).collect(),
                ));
            }
            idx += 1;
        } else {
            result.push(line.clone());
            idx += 1;
        }
    }

    result
}

/// Extract a while loop from the trace following a label.
///
/// Returns `(before, inside, remaining, condition)` or `None` on failure.
fn to_while(trace: &[Expr], jd: &Expr) -> Option<(Trace, Trace, Trace, Expr)> {
    let mut path: Trace = Vec::new();
    let mut remaining = trace.to_vec();

    loop {
        if remaining.is_empty() {
            return None;
        }

        let line = remaining.remove(0);

        if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                let if_true = extract_seq(ch.get(1));
                let if_false = extract_seq(ch.get(2));

                // Check for revert guards: if one branch is a revert, it's a require().
                if is_revert(&if_true) {
                    // require(!cond)
                    path.push(Expr::node1("require", cond.is_zero_wrap()));
                    remaining = if_false;
                    continue;
                }
                if is_revert(&if_false) {
                    // require(cond)
                    path.push(Expr::node1("require", cond.clone()));
                    remaining = if_true;
                    continue;
                }

                // Find which branch contains the goto to our label.
                let true_has_goto = trace_has_goto(&if_true, jd);
                let false_has_goto = trace_has_goto(&if_false, jd);

                if true_has_goto && !false_has_goto {
                    // True branch loops, false branch exits.
                    let inside = prepend_path_to_gotos(&if_true, &path, jd);
                    return Some((path, inside, if_false, cond));
                } else if false_has_goto && !true_has_goto {
                    // False branch loops, true branch exits.
                    let inside = prepend_path_to_gotos(&if_false, &path, jd);
                    return Some((path, inside, if_true, cond.is_zero_wrap()));
                } else if true_has_goto && false_has_goto {
                    // Both branches loop: wrap both into the body.
                    let body = vec![Expr::node3(
                        "if",
                        cond.clone(),
                        Expr::node("seq", prepend_path_to_gotos(&if_true, &path, jd)),
                        Expr::node("seq", prepend_path_to_gotos(&if_false, &path, jd)),
                    )];
                    return Some((path, body, remaining, Expr::Bool(true)));
                } else {
                    // Neither branch has the goto — shouldn't happen after a label.
                    path.push(line);
                    continue;
                }
            }
            path.push(line);
        } else if line.opcode() == Some("goto") {
            // Direct goto without an if — infinite loop with just the path as body.
            let mut body = path.clone();
            body.push(line);
            return Some((vec![], body, remaining, Expr::Bool(true)));
        } else {
            path.push(line);
        }
    }
}

/// Check if a trace is a single revert/return(0)/invalid. (Public for use in simplify.rs.)
pub fn is_revert_public(trace: &[Expr]) -> bool {
    is_revert(trace)
}

/// Check if a trace is a single revert/return(0)/invalid.
fn is_revert(trace: &[Expr]) -> bool {
    if trace.len() != 1 {
        return false;
    }
    let line = &trace[0];
    match line.opcode() {
        Some("revert") | Some("invalid") => true,
        Some("return") => {
            if let Some(ch) = line.children() {
                ch.len() == 1 && ch[0].is_zero()
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Check if a trace contains a `goto` targeting the given jd.
fn trace_has_goto(trace: &[Expr], jd: &Expr) -> bool {
    for line in trace {
        if line.opcode() == Some("goto") {
            if let Some(ch) = line.children() {
                if ch.first() == Some(jd) {
                    return true;
                }
            }
        }
        // Recurse into if branches.
        if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                let if_true = extract_seq(ch.get(1));
                let if_false = extract_seq(ch.get(2));
                if trace_has_goto(&if_true, jd) || trace_has_goto(&if_false, jd) {
                    return true;
                }
            }
        }
    }
    false
}

/// Prepend the accumulated `path` (with variable substitutions from goto setvars)
/// before each `goto` in the trace. This places the loop-body-prefix before the continue.
fn prepend_path_to_gotos(trace: &[Expr], path: &[Expr], jd: &Expr) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        if line.opcode() == Some("goto") {
            if let Some(ch) = line.children() {
                if ch.first() == Some(jd) {
                    // Substitute goto's setvars into the path.
                    let mut substituted_path = path.to_vec();
                    for sv in &ch[1..] {
                        if sv.opcode() == Some("setvar") {
                            if let Some(sv_ch) = sv.children() {
                                let var_idx = sv_ch.first().cloned().unwrap_or(Expr::zero());
                                let var_val = sv_ch.get(1).cloned().unwrap_or(Expr::zero());
                                let var_ref = Expr::node1("var", var_idx);
                                substituted_path = substituted_path
                                    .iter()
                                    .map(|e| e.replace(&var_ref, &var_val))
                                    .collect();
                            }
                        }
                    }
                    result.extend(substituted_path);
                }
            }
            result.push(line.clone());
        } else if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                let if_true = extract_seq(ch.get(1));
                let if_false = extract_seq(ch.get(2));
                result.push(Expr::node3(
                    "if",
                    cond,
                    Expr::node("seq", prepend_path_to_gotos(&if_true, path, jd)),
                    Expr::node("seq", prepend_path_to_gotos(&if_false, path, jd)),
                ));
            }
        } else {
            result.push(line.clone());
        }
    }

    result
}

/// Extract a seq node's children as a Vec, or return the expression wrapped in a Vec.
fn extract_seq(expr: Option<&Expr>) -> Vec<Expr> {
    match expr {
        Some(Expr::Node(op, ch)) if op == "seq" => ch.clone(),
        Some(e) => vec![e.clone()],
        None => vec![],
    }
}

/// Apply a function to each line in a trace (non-recursing into sub-traces, unlike rewrite_trace).
fn rewrite_each(trace: &[Expr], f: &dyn Fn(&Expr) -> Vec<Expr>) -> Trace {
    let mut result = Trace::new();
    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", rewrite_each(&if_true, f)),
                        Expr::node("seq", rewrite_each(&if_false, f)),
                    ));
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let mut new_ch = vec![cond, Expr::node("seq", rewrite_each(&body, f))];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => result.extend(f(line)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_revert() {
        assert!(is_revert(&[Expr::node0("revert")]));
        assert!(is_revert(&[Expr::node0("invalid")]));
        assert!(is_revert(&[Expr::node1("return", Expr::zero())]));
        assert!(!is_revert(&[Expr::node1("return", Expr::val(42))]));
        assert!(!is_revert(&[Expr::node0("stop")]));
        assert!(!is_revert(&[Expr::node0("revert"), Expr::node0("stop")]));
    }

    #[test]
    fn test_extract_seq() {
        let seq = Expr::node("seq", vec![Expr::val(1), Expr::val(2)]);
        assert_eq!(extract_seq(Some(&seq)), vec![Expr::val(1), Expr::val(2)]);

        let single = Expr::val(42);
        assert_eq!(extract_seq(Some(&single)), vec![Expr::val(42)]);

        assert_eq!(extract_seq(None), Vec::<Expr>::new());
    }

    #[test]
    fn test_make_whiles_passthrough() {
        // A simple trace without labels should pass through unchanged.
        let trace = vec![Expr::node0("stop")];
        let result = make_whiles(&trace);
        assert_eq!(result, vec![Expr::node0("stop")]);
    }

    #[test]
    fn test_goto_becomes_continue() {
        let trace = vec![Expr::Node(
            "goto".to_string(),
            vec![Expr::val(1)],
        )];
        let result = make(&trace);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].opcode(), Some("continue"));
    }

    #[test]
    fn test_label_with_goto_becomes_while() {
        // label(1, vars) followed by if(cond, [goto(1)], [stop])
        let trace = vec![
            Expr::Node("label".to_string(), vec![
                Expr::val(1),
                Expr::node("_vars", vec![]),
            ]),
            Expr::node3(
                "if",
                Expr::atom("cond"),
                Expr::node("seq", vec![
                    Expr::Node("goto".to_string(), vec![Expr::val(1)]),
                ]),
                Expr::node("seq", vec![Expr::node0("stop")]),
            ),
        ];
        let result = make(&trace);

        // Should produce a while loop.
        let has_while = result.iter().any(|e| e.opcode() == Some("while"));
        assert!(has_while, "Expected a while loop in result: {result:?}");
    }

    #[test]
    fn test_revert_guard_becomes_require() {
        // label(1, vars) → if(cond, [revert], [body..., if(cond2, [goto(1)], [stop])])
        let trace = vec![
            Expr::Node("label".to_string(), vec![
                Expr::val(1),
                Expr::node("_vars", vec![]),
            ]),
            Expr::node3(
                "if",
                Expr::atom("guard"),
                Expr::node("seq", vec![Expr::node0("revert")]),
                Expr::node("seq", vec![
                    Expr::node3(
                        "if",
                        Expr::atom("loop_cond"),
                        Expr::node("seq", vec![
                            Expr::Node("goto".to_string(), vec![Expr::val(1)]),
                        ]),
                        Expr::node("seq", vec![Expr::node0("stop")]),
                    ),
                ]),
            ),
        ];
        let result = make(&trace);

        // Should have a require and a while.
        let has_while = result.iter().any(|e| e.opcode() == Some("while"));
        assert!(has_while, "Expected a while loop: {result:?}");
    }

    #[test]
    fn test_trace_has_goto() {
        let trace = vec![
            Expr::val(1),
            Expr::Node("goto".to_string(), vec![Expr::val(5)]),
        ];
        assert!(trace_has_goto(&trace, &Expr::val(5)));
        assert!(!trace_has_goto(&trace, &Expr::val(3)));
    }

    #[test]
    fn test_trace_has_goto_nested_in_if() {
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("c"),
            Expr::node("seq", vec![
                Expr::Node("goto".to_string(), vec![Expr::val(7)]),
            ]),
            Expr::node("seq", vec![Expr::node0("stop")]),
        )];
        assert!(trace_has_goto(&trace, &Expr::val(7)));
        assert!(!trace_has_goto(&trace, &Expr::val(99)));
    }
}
