//! Execution path folding.
//!
//! Takes a trace with `if`/`while`/`require` constructs and merges
//! execution paths into concise if/else structures.
//!
//! Three-phase pipeline:
//! 1. `as_paths` — Unfold the trace into flat, branchless execution paths.
//! 2. `fold_paths` — Re-fold by finding common prefixes/suffixes.
//! 3. `fold_aux` — Post-processing: remove unnecessary else when one branch terminates.

use crate::expr::{Expr, Trace};

// ===========================================================================
// Public entry point
// ===========================================================================

/// Fold a trace into a more concise if/else structure.
pub fn fold(trace: &[Expr]) -> Trace {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let paths = as_paths(trace, &[]);
        if paths.is_empty() {
            return trace.to_vec();
        }
        let merged = fold_paths(&paths);
        let merged = flatten(&merged);
        let merged = make_ifs(&merged);
        let merged = merge_ifs(&merged);
        fold_aux(&merged)
    })) {
        Ok(result) => result,
        Err(_) => {
            log::warn!("Folder failed, returning trace as-is");
            trace.to_vec()
        }
    }
}

// ===========================================================================
// Phase 1: Unfold into branchless paths
// ===========================================================================

/// Convert a structured trace into a list of branchless paths.
/// Each path is a Vec<Expr> representing one complete execution route.
/// `if` nodes become condition assertions inline in the path.
fn as_paths(trace: &[Expr], prefix: &[Expr]) -> Vec<Vec<Expr>> {
    let mut path = prefix.to_vec();

    for line in trace {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = extract_seq(ch.get(1));
                    let if_false = extract_seq(ch.get(2));

                    let mut true_prefix = path.clone();
                    true_prefix.push(cond.clone());
                    let mut false_prefix = path.clone();
                    false_prefix.push(cond.is_zero_wrap());

                    let mut result = as_paths(&if_true, &true_prefix);
                    result.extend(as_paths(&if_false, &false_prefix));
                    return result;
                }
                path.push(line.clone());
            }
            Some("while") => {
                // Preserve while loops in paths as markers.
                if let Some(ch) = line.children() {
                    let body = extract_seq(ch.get(1));
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    path.push(Expr::node2("LOOP", cond, Expr::node("seq", body)));
                    // Don't recurse into loop body for path extraction.
                }
            }
            _ => {
                path.push(line.clone());
            }
        }
    }

    vec![path]
}

// ===========================================================================
// Phase 2: Fold common prefixes/suffixes
// ===========================================================================

/// Merge paths by finding common prefixes and suffixes.
fn fold_paths(paths: &[Vec<Expr>]) -> Trace {
    if paths.is_empty() {
        return vec![];
    }
    if paths.len() == 1 {
        return paths[0].clone();
    }

    // Find common prefix length.
    let prefix_len = common_prefix_len(paths);

    // Find common suffix length.
    let suffix_len = common_suffix_len(paths, prefix_len);

    let common_prefix: Vec<Expr> = paths[0][..prefix_len].to_vec();
    let common_suffix: Vec<Expr> = if suffix_len > 0 {
        paths[0][paths[0].len() - suffix_len..].to_vec()
    } else {
        vec![]
    };

    // Extract the diverging middles.
    let middles: Vec<Vec<Expr>> = paths
        .iter()
        .map(|p| {
            let end = p.len() - suffix_len;
            p[prefix_len..end].to_vec()
        })
        .filter(|m| !m.is_empty())
        .collect();

    let mut result = common_prefix;

    if middles.is_empty() {
        // All paths are identical.
    } else if middles.len() == 1 {
        result.extend(middles.into_iter().next().unwrap());
    } else {
        // Try to split into two groups by the first differing element.
        let (group1, group2) = split_into_groups(&middles);

        if !group1.is_empty() && !group2.is_empty() {
            let folded1 = fold_paths(&group1);
            let folded2 = fold_paths(&group2);
            result.push(Expr::node2("_or", Expr::node("seq", folded1), Expr::node("seq", folded2)));
        } else {
            // Can't split cleanly — just create a multi-way or.
            let branches: Vec<Expr> = middles
                .iter()
                .map(|m| Expr::node("seq", m.clone()))
                .collect();
            result.push(Expr::Node("_or".to_string(), branches));
        }
    }

    result.extend(common_suffix);
    result
}

fn common_prefix_len(paths: &[Vec<Expr>]) -> usize {
    if paths.is_empty() {
        return 0;
    }
    let min_len = paths.iter().map(|p| p.len()).min().unwrap_or(0);
    let mut prefix = 0;
    while prefix < min_len {
        let first = &paths[0][prefix];
        if paths.iter().all(|p| p[prefix] == *first) {
            prefix += 1;
        } else {
            break;
        }
    }
    prefix
}

fn common_suffix_len(paths: &[Vec<Expr>], prefix_len: usize) -> usize {
    if paths.is_empty() {
        return 0;
    }
    let min_remaining = paths.iter().map(|p| p.len() - prefix_len).min().unwrap_or(0);
    let mut suffix = 0;
    while suffix < min_remaining {
        let first = &paths[0];
        let idx = first.len() - 1 - suffix;
        if paths.iter().all(|p| p[p.len() - 1 - suffix] == first[idx]) {
            suffix += 1;
        } else {
            break;
        }
    }
    suffix
}

/// Split paths into two groups based on the first element.
fn split_into_groups(middles: &[Vec<Expr>]) -> (Vec<Vec<Expr>>, Vec<Vec<Expr>>) {
    if middles.len() < 2 {
        return (middles.to_vec(), vec![]);
    }

    let first_elem = &middles[0][0];
    let mut group1 = Vec::new();
    let mut group2 = Vec::new();

    for m in middles {
        if !m.is_empty() && m[0] == *first_elem {
            group1.push(m.clone());
        } else {
            group2.push(m.clone());
        }
    }

    (group1, group2)
}

// ===========================================================================
// Phase 2.5: Convert _or nodes to if/else
// ===========================================================================

/// Flatten: remove unnecessary else when one branch always terminates.
fn flatten(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        if line.opcode() == Some("_or") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    let branch1 = extract_seq(Some(&ch[0]));
                    let branch2 = extract_seq(Some(&ch[1]));

                    // If both branches are identical after folding, skip the if.
                    if branch1 == branch2 {
                        result.extend(flatten(&branch1));
                        continue;
                    }

                    // If branch1 always terminates, we can emit it as a guard.
                    if ends_execution(&branch1) {
                        result.extend(try_merge_branches(&flatten(&branch1), &flatten(&branch2)));
                    } else {
                        result.push(Expr::node2(
                            "_or",
                            Expr::node("seq", flatten(&branch1)),
                            Expr::node("seq", flatten(&branch2)),
                        ));
                    }
                } else {
                    result.push(line.clone());
                }
            }
        } else {
            result.push(line.clone());
        }
    }

    result
}

/// Check if a trace always terminates (return/revert/stop/selfdestruct/continue).
fn ends_execution(trace: &[Expr]) -> bool {
    if trace.is_empty() {
        return false;
    }
    let last = trace.last().unwrap();
    match last.opcode() {
        Some("return") | Some("revert") | Some("stop") | Some("selfdestruct")
        | Some("invalid") | Some("continue") => true,
        Some("_or") => {
            if let Some(ch) = last.children() {
                ch.iter().all(|b| ends_execution(&extract_seq(Some(b))))
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Try to merge two branches by factoring out common suffixes.
fn try_merge_branches(one: &[Expr], two: &[Expr]) -> Trace {
    let shorter_len = one.len().min(two.len());
    let mut common_suffix = 0;
    while common_suffix < shorter_len
        && one[one.len() - 1 - common_suffix] == two[two.len() - 1 - common_suffix]
    {
        common_suffix += 1;
    }

    if common_suffix > 0 {
        let one_unique = &one[..one.len() - common_suffix];
        let two_unique = &two[..two.len() - common_suffix];
        let suffix = &one[one.len() - common_suffix..];

        let mut result = vec![Expr::node2(
            "_or",
            Expr::node("seq", one_unique.to_vec()),
            Expr::node("seq", two_unique.to_vec()),
        )];
        result.extend(suffix.to_vec());
        result
    } else {
        vec![Expr::node2(
            "_or",
            Expr::node("seq", one.to_vec()),
            Expr::node("seq", two.to_vec()),
        )]
    }
}

/// Convert `_or` nodes into `if` nodes by using the first element of each branch
/// as a condition.
fn make_ifs(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace {
        if line.opcode() == Some("_or") {
            if let Some(ch) = line.children() {
                if ch.len() == 2 {
                    let branch1 = extract_seq(Some(&ch[0]));
                    let branch2 = extract_seq(Some(&ch[1]));

                    // The first element of each branch should be the condition
                    // (inserted by as_paths).
                    if !branch1.is_empty() && !branch2.is_empty() {
                        let cond = branch1[0].clone();
                        let if_true = make_ifs(&branch1[1..]);
                        let if_false = make_ifs(&branch2[1..]);

                        // Verify the false branch's first element is iszero(cond).
                        if branch2[0] == cond.is_zero_wrap() {
                            result.push(Expr::node3(
                                "if",
                                cond,
                                Expr::node("seq", if_true),
                                Expr::node("seq", if_false),
                            ));
                        } else {
                            // Non-complementary conditions: use the first branch condition.
                            result.push(Expr::node3(
                                "if",
                                cond,
                                Expr::node("seq", if_true),
                                Expr::node("seq", make_ifs(&branch2)),
                            ));
                        }
                    } else if branch1.is_empty() {
                        result.extend(make_ifs(&branch2));
                    } else {
                        result.extend(make_ifs(&branch1));
                    }
                } else {
                    // Multi-way or: convert to nested if/else.
                    result.push(or_to_nested_if(ch));
                }
            }
        } else {
            result.push(line.clone());
        }
    }

    result
}

fn or_to_nested_if(branches: &[Expr]) -> Expr {
    if branches.len() <= 1 {
        let b = extract_seq(branches.first());
        return Expr::node("seq", b);
    }

    let first = extract_seq(Some(&branches[0]));
    if first.is_empty() {
        return or_to_nested_if(&branches[1..]);
    }

    let cond = first[0].clone();
    let if_true = first[1..].to_vec();
    let else_branch = or_to_nested_if(&branches[1..]);

    Expr::node3("if", cond, Expr::node("seq", if_true), else_branch)
}

/// Hoist common beginnings from if-else branches.
fn merge_ifs(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace.iter() {
        if line.opcode() == Some("if") {
            if let Some(ch) = line.children() {
                let cond = ch.first().cloned().unwrap_or(Expr::zero());
                let if_true = merge_ifs(&extract_seq(ch.get(1)));
                let if_false = merge_ifs(&extract_seq(ch.get(2)));

                // Find common prefix.
                let common_len = {
                    let min_len = if_true.len().min(if_false.len());
                    let mut n = 0;
                    while n < min_len && if_true[n] == if_false[n] {
                        n += 1;
                    }
                    n
                };

                if common_len > 0 {
                    // Hoist common prefix before the if.
                    result.extend(if_true[..common_len].to_vec());
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", if_true[common_len..].to_vec()),
                        Expr::node("seq", if_false[common_len..].to_vec()),
                    ));
                } else {
                    result.push(Expr::node3(
                        "if",
                        cond,
                        Expr::node("seq", if_true),
                        Expr::node("seq", if_false),
                    ));
                }
                continue;
            }
        }
        result.push(line.clone());
    }

    result
}

// ===========================================================================
// Phase 3: Post-processing
// ===========================================================================

/// Remove unnecessary else when if-branch always terminates.
fn fold_aux(trace: &[Expr]) -> Trace {
    let mut result = Trace::new();

    for line in trace.iter() {
        match line.opcode() {
            Some("if") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let if_true = fold_aux(&extract_seq(ch.get(1)));
                    let if_false = fold_aux(&extract_seq(ch.get(2)));

                    if ends_execution(&if_true) && !if_false.is_empty() {
                        // if-branch terminates → no else needed.
                        result.push(Expr::node2("if", cond, Expr::node("seq", if_true)));
                        result.extend(if_false);
                    } else if ends_execution(&if_false) && !if_true.is_empty() {
                        // else-branch terminates → flip and remove else.
                        result.push(Expr::node2(
                            "if",
                            cond.is_zero_wrap(),
                            Expr::node("seq", if_false),
                        ));
                        result.extend(if_true);
                    } else {
                        result.push(Expr::node3(
                            "if",
                            cond,
                            Expr::node("seq", if_true),
                            Expr::node("seq", if_false),
                        ));
                    }
                }
            }
            Some("while") => {
                if let Some(ch) = line.children() {
                    let cond = ch.first().cloned().unwrap_or(Expr::zero());
                    let body = extract_seq(ch.get(1));
                    let rest: Vec<Expr> = ch[2..].to_vec();
                    let folded_body = fold(&body);
                    let mut new_ch = vec![cond, Expr::node("seq", folded_body)];
                    new_ch.extend(rest);
                    result.push(Expr::Node("while".to_string(), new_ch));
                }
            }
            _ => result.push(line.clone()),
        }
    }

    result
}

/// Extract seq children helper.
fn extract_seq(expr: Option<&Expr>) -> Vec<Expr> {
    match expr {
        Some(Expr::Node(op, ch)) if op == "seq" => ch.clone(),
        Some(e) => vec![e.clone()],
        None => vec![],
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_paths_simple() {
        let trace = vec![Expr::atom("a"), Expr::atom("b"), Expr::node0("stop")];
        let paths = as_paths(&trace, &[]);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 3);
    }

    #[test]
    fn test_as_paths_with_if() {
        let trace = vec![
            Expr::atom("a"),
            Expr::node3(
                "if",
                Expr::atom("cond"),
                Expr::node("seq", vec![Expr::atom("b"), Expr::node0("stop")]),
                Expr::node("seq", vec![Expr::atom("c"), Expr::node0("revert")]),
            ),
        ];
        let paths = as_paths(&trace, &[]);
        assert_eq!(paths.len(), 2);
        // Path 1: a, cond, b, stop
        assert!(paths[0].contains(&Expr::atom("cond")));
        assert!(paths[0].contains(&Expr::atom("b")));
        // Path 2: a, iszero(cond), c, revert
        assert!(paths[1].contains(&Expr::atom("c")));
    }

    #[test]
    fn test_fold_identical_paths() {
        let paths = vec![
            vec![Expr::atom("a"), Expr::node0("stop")],
            vec![Expr::atom("a"), Expr::node0("stop")],
        ];
        let folded = fold_paths(&paths);
        // Should merge into a single path.
        assert_eq!(folded, vec![Expr::atom("a"), Expr::node0("stop")]);
    }

    #[test]
    fn test_fold_common_prefix() {
        let paths = vec![
            vec![Expr::atom("a"), Expr::atom("b"), Expr::node0("stop")],
            vec![Expr::atom("a"), Expr::atom("c"), Expr::node0("revert")],
        ];
        let folded = fold_paths(&paths);
        // Should have common prefix "a", then an _or node, then no common suffix.
        assert!(!folded.is_empty());
        assert_eq!(folded[0], Expr::atom("a"));
    }

    #[test]
    fn test_ends_execution() {
        assert!(ends_execution(&[Expr::node0("stop")]));
        assert!(ends_execution(&[Expr::atom("a"), Expr::node0("return")]));
        assert!(!ends_execution(&[Expr::atom("a")]));
        assert!(!ends_execution(&[]));
    }

    #[test]
    fn test_fold_roundtrip() {
        // A simple if/else should survive folding.
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("cond"),
            Expr::node("seq", vec![Expr::node0("stop")]),
            Expr::node("seq", vec![Expr::node0("revert")]),
        )];
        let result = fold(&trace);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_merge_ifs_common_prefix() {
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("c"),
            Expr::node("seq", vec![Expr::atom("x"), Expr::atom("a")]),
            Expr::node("seq", vec![Expr::atom("x"), Expr::atom("b")]),
        )];
        let result = merge_ifs(&trace);
        // "x" should be hoisted before the if.
        assert_eq!(result[0], Expr::atom("x"));
        assert_eq!(result[1].opcode(), Some("if"));
    }

    #[test]
    fn test_fold_aux_remove_else() {
        let trace = vec![Expr::node3(
            "if",
            Expr::atom("c"),
            Expr::node("seq", vec![Expr::node0("return")]),
            Expr::node("seq", vec![Expr::atom("b")]),
        )];
        let result = fold_aux(&trace);
        // Should become: if(c, [return]) followed by b (no else).
        assert!(result.len() >= 2);
        assert_eq!(result[0].opcode(), Some("if"));
        // The if should only have 2 children (no else).
        if let Some(ch) = result[0].children() {
            assert_eq!(ch.len(), 2);
        }
    }
}
