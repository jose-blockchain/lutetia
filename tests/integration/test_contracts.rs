//! Contract-level regression tests.
//!
//! These tests decompile real contract bytecodes and verify that key
//! output features are preserved. They serve as regression guards for
//! improvements to the simplifier, sparser, and memory propagation.

use lutetia::decompiler::{decompile_bytecode, DecompilerConfig, OutputFormat};

fn config() -> DecompilerConfig {
    DecompilerConfig {
        timeout_secs: 30,
        format: OutputFormat::Text,
        color: false,
    }
}

/// Load bytecode from the comparison/bytecodes directory.
fn load_bytecode(name: &str) -> String {
    let path = format!(
        "{}/comparison/bytecodes/{}.hex",
        env!("CARGO_MANIFEST_DIR").trim_end_matches("/lutetia"),
        name
    );
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            // Fall back to relative from workspace root
            let alt = format!("../comparison/bytecodes/{}.hex", name);
            std::fs::read_to_string(&alt)
                .unwrap_or_default()
                .trim()
                .to_string()
        }
    }
}

// =========================================================================
// WETH contract tests
// =========================================================================

#[test]
fn test_weth_deposit_log_resolves_callvalue() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return; // skip if bytecode not available
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // deposit() should resolve log data to call.value, not mem[96 len 32]
    assert!(
        r.text.contains("call.value"),
        "deposit() log should contain 'call.value', got:\n{}",
        r.text.lines()
            .filter(|l| l.contains("deposit") || l.contains("Deposit") || l.contains("call.value"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn test_weth_deposit_log_event_name() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("log Deposit("),
        "Should resolve Deposit event name"
    );
}

#[test]
fn test_weth_withdrawal_log_event_name() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("log Withdrawal("),
        "Should resolve Withdrawal event name"
    );
}

#[test]
fn test_weth_transfer_log_event_name() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("log Transfer("),
        "Should resolve Transfer event name"
    );
}

#[test]
fn test_weth_approval_log_event_name() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("log Approval("),
        "Should resolve Approval event name"
    );
}

#[test]
fn test_weth_totalsupply_resolves_balance() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // totalSupply should return eth.balance, not data(eth.balance, 0)
    assert!(
        r.text.contains("eth.balance(this.address)"),
        "totalSupply should return eth.balance(this.address)"
    );
}

#[test]
fn test_weth_decimals_type() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // decimals should be typed as uint8 in storage header
    assert!(
        r.text.contains("uint8"),
        "decimals should be typed as uint8"
    );
}

#[test]
fn test_weth_balanceof_mapping() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // balanceOf should be a mapping
    assert!(
        r.text.contains("balanceOf is mapping"),
        "balanceOf should be declared as mapping"
    );
}

#[test]
fn test_weth_allowance_nested_mapping() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // allowance[owner][spender] should have both params
    assert!(
        r.text.contains("allowance[") && r.text.contains("]["),
        "allowance should be a nested mapping with two keys"
    );
}

#[test]
fn test_weth_return_one_for_approve() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // approve should return 1
    assert!(
        r.text.contains("return 1"),
        "approve/transfer should return 1"
    );
}

#[test]
fn test_weth_deposit_storage_increment() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // deposit() should use += for balance increment
    assert!(
        r.text.contains("+="),
        "deposit should use += for balance"
    );
}

#[test]
fn test_weth_withdraw_storage_decrement() {
    let hex = load_bytecode("weth");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("-="),
        "withdraw should use -= for balance"
    );
}

// =========================================================================
// UniswapV2 Factory tests
// =========================================================================

#[test]
fn test_factory_getpair_nested_mapping() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // getPair should return pair[_param1][_param2], not pair[_param2]
    let getpair_section: String = r
        .text
        .lines()
        .skip_while(|l| !l.contains("getPair"))
        .take(4)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        getpair_section.contains("[_param1]") && getpair_section.contains("[_param2]"),
        "getPair should have both _param1 and _param2 in nested mapping.\nGot:\n{getpair_section}"
    );
}

#[test]
fn test_factory_storage_address_types() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // feeToAddress should be typed as address
    assert!(
        r.text.contains("is address at storage"),
        "Factory should have address-typed storage slots"
    );
}

#[test]
fn test_factory_allpairs_array_type() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("array of"),
        "allPairs should be typed as array"
    );
}

#[test]
fn test_factory_revert_string_forbidden() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("UniswapV2: FORBIDDEN"),
        "Should decode 'UniswapV2: FORBIDDEN' revert string"
    );
}

#[test]
fn test_factory_allpairslength_getter() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // allPairsLength() should return the named storage variable
    assert!(
        r.text.contains("return allPairsLength"),
        "allPairsLength() should return the named storage variable"
    );
}

#[test]
fn test_factory_feeto_getter() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("return address(feeTo"),
        "feeTo() should return address(feeToAddress)"
    );
}

#[test]
fn test_factory_createpair_exists() {
    let hex = load_bytecode("uniswap_v2_factory");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("createPair"),
        "Should decompile createPair function (Panoramix fails this)"
    );
}

// =========================================================================
// DAI contract tests
// =========================================================================

#[test]
fn test_dai_permit_typehash_const() {
    let hex = load_bytecode("dai");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("PERMIT_TYPEHASH"),
        "DAI should have PERMIT_TYPEHASH constant"
    );
}

#[test]
fn test_dai_storage_mappings() {
    let hex = load_bytecode("dai");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("wards is mapping"),
        "DAI should have wards mapping"
    );
    assert!(
        r.text.contains("balanceOf is mapping"),
        "DAI should have balanceOf mapping"
    );
    assert!(
        r.text.contains("allowance is mapping"),
        "DAI should have allowance mapping"
    );
}

#[test]
fn test_dai_require_balance_check() {
    let hex = load_bytecode("dai");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // DAI should have balance checks in require statements
    assert!(
        r.text.contains("require balanceOf["),
        "DAI should have balance-checking require statements"
    );
}

// =========================================================================
// USDT contract tests
// =========================================================================

#[test]
fn test_usdt_storage_header() {
    let hex = load_bytecode("usdt");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("balances is mapping"),
        "USDT should have balances mapping"
    );
    assert!(
        r.text.contains("allowed is mapping"),
        "USDT should have allowed mapping"
    );
}

#[test]
fn test_usdt_max_uint_const() {
    let hex = load_bytecode("usdt");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("MAX_UINT") || r.text.contains("const"),
        "USDT should have MAX_UINT or similar constant"
    );
}

#[test]
fn test_usdt_blacklist_mapping() {
    let hex = load_bytecode("usdt");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("isBlackListed") || r.text.contains("blackList"),
        "USDT should have blacklist-related storage"
    );
}

// =========================================================================
// UniswapV2 Router tests
// =========================================================================

#[test]
fn test_router_does_not_timeout() {
    let hex = load_bytecode("uniswap_v2_router");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // Router is the largest contract (~22KB). Verify it completes.
    assert!(
        r.text.len() > 1000,
        "Router output should be substantial (>1000 chars)"
    );
}

#[test]
fn test_router_factory_const() {
    let hex = load_bytecode("uniswap_v2_router");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    assert!(
        r.text.contains("factory") || r.text.contains("0x5c69"),
        "Router should reference factory address"
    );
}

#[test]
fn test_router_function_names() {
    let hex = load_bytecode("uniswap_v2_router");
    if hex.is_empty() {
        return;
    }
    let r = decompile_bytecode(&hex, &config()).unwrap();
    // Should resolve key function names from the signature database
    assert!(
        r.text.contains("swapExactTokensForTokens")
            || r.text.contains("addLiquidity")
            || r.text.contains("removeLiquidity"),
        "Router should resolve function names from signature DB"
    );
}

// =========================================================================
// Simplifier unit tests for recent fixes
// =========================================================================

#[test]
fn test_simplify_data_trailing_zero() {
    use lutetia::expr::Expr;
    use lutetia::simplify::simplify_trace;

    // data(X, 0) should collapse to X
    let trace = vec![Expr::node1(
        "return",
        Expr::node2("data", Expr::atom("value"), Expr::zero()),
    )];
    let result = simplify_trace(&trace, 5, None);
    let output = format!("{result:?}");
    assert!(
        !output.contains("data"),
        "data(X, 0) should be simplified away. Got: {output}"
    );
}

#[test]
fn test_simplify_data_single_element() {
    use lutetia::expr::Expr;
    use lutetia::simplify::simplify_trace;

    // data(X) should collapse to X
    let trace = vec![Expr::node1(
        "return",
        Expr::node1("data", Expr::atom("value")),
    )];
    let result = simplify_trace(&trace, 5, None);
    let output = format!("{result:?}");
    assert!(
        !output.contains("data"),
        "data(X) should be simplified away. Got: {output}"
    );
}

#[test]
fn test_simplify_mem_propagation_resolved_overlap() {
    use lutetia::expr::Expr;
    use lutetia::simplify::simplify_trace;

    // Verify that setmem(range(mem(...), 32), val) resolves the range
    // before checking overlap, allowing propagation to continue past it.
    let trace = vec![
        // setmem(range(64, 32), 96) — write free memory pointer
        Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(64), Expr::val(32)),
            Expr::val(96),
        ),
        // setmem(range(mem(range(64, 32)), 32), 42) — write at indirect offset
        Expr::node2(
            "setmem",
            Expr::node2(
                "range",
                Expr::node1("mem", Expr::node2("range", Expr::val(64), Expr::val(32))),
                Expr::val(32),
            ),
            Expr::val(42),
        ),
        // return mem(range(mem(range(64, 32)), 32)) — read it back
        Expr::node1(
            "return",
            Expr::node1(
                "mem",
                Expr::node2(
                    "range",
                    Expr::node1("mem", Expr::node2("range", Expr::val(64), Expr::val(32))),
                    Expr::val(32),
                ),
            ),
        ),
    ];
    let result = simplify_trace(&trace, 5, None);
    let output = format!("{result:?}");
    // After propagation: setmem(range(96, 32), 42), return(42)
    // The mem references should be resolved, not left as raw mem[...]
    assert!(
        output.contains("Val(42)") && !output.contains("\"mem\""),
        "Memory propagation should resolve through indirect setmem. Got: {output}"
    );
}

#[test]
fn test_simplify_sha3_mem_retroactive_tracking() {
    use lutetia::expr::Expr;
    use lutetia::simplify::simplify_trace;

    // Simulate nested mapping pattern:
    // setmem(range(0, 32), key1)
    // setmem(range(32, 32), 2)
    // setvar(_1, sha3(mem(range(0, 64))))  → sha3(key1, 2)
    // setmem(range(0, 32), key2)
    // setmem(range(32, 32), var(_1))       → writes sha3(key1, 2)
    // setvar(_2, sha3(mem(range(0, 64))))  → should be sha3(key2, sha3(key1, 2))
    // return storage(256, 0, var(_2))
    let trace = vec![
        Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(0), Expr::val(32)),
            Expr::atom("key1"),
        ),
        Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(32), Expr::val(32)),
            Expr::val(2),
        ),
        Expr::node2(
            "setvar",
            Expr::atom("_1"),
            Expr::node1(
                "sha3",
                Expr::node1("mem", Expr::node2("range", Expr::val(0), Expr::val(64))),
            ),
        ),
        Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(0), Expr::val(32)),
            Expr::atom("key2"),
        ),
        Expr::node2(
            "setmem",
            Expr::node2("range", Expr::val(32), Expr::val(32)),
            Expr::node1("var", Expr::atom("_1")),
        ),
        Expr::node2(
            "setvar",
            Expr::atom("_2"),
            Expr::node1(
                "sha3",
                Expr::node1("mem", Expr::node2("range", Expr::val(0), Expr::val(64))),
            ),
        ),
        Expr::node1(
            "return",
            Expr::Node(
                "storage".to_string(),
                vec![
                    Expr::val(256),
                    Expr::val(0),
                    Expr::node1("var", Expr::atom("_2")),
                ],
            ),
        ),
    ];
    let result = simplify_trace(&trace, 5, None);
    let output = format!("{result:?}");
    // The result should contain a nested sha3: sha3(key2, sha3(key1, 2))
    // Count sha3 occurrences — should be at least 2 for the nested structure
    let sha3_count = output.matches("sha3").count();
    assert!(
        sha3_count >= 2,
        "Nested mapping should preserve both sha3 levels. sha3_count={sha3_count}, got: {output}"
    );
}
