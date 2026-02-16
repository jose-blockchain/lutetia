# Lutetia EVM Decompiler

**EVM bytecode decompiler** — Lutetia is the fastest EVM decompiler. Turns EVM bytecode (hex or contract address) into readable pseudo-Python (Python-style `def`/`if`/`while` with EVM/Solidity types and `require`/calls).

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p align="center">
  <img src="https://fonduevilla.com/wp-content/uploads/2023/11/Asterix-Obelix-Cheese-Fondue-Adventures-in-Switzerland-26-1024x442.jpg" width="600" alt="Asterix & Obelix — Cheese Fondue" />
</p>

Decompiling EVM bytecode is a bit like staring into a fondue pot: everything’s melted together and it’s not obvious what went in. Lutetia is the Obelix at the table — we dig in and turn that goo back into something you can read.

---

## Benchmarks (vs Panoramix)

Tested on mainnet bytecodes (WETH, USDT, DAI, Uniswap V2 Factory, Uniswap V2 Router). Single run, release build.

| Contract            | Panoramix (s) | **Lutetia (s)** | Pan lines | Lut lines |
|---------------------|---------------|-----------------|-----------|-----------|
| weth                | 0.70          | **0.38**        | 89        | 111       |
| dai                 | 1.14          | **0.97**        | 225       | 282       |
| usdt                | 1.39          | **1.09**        | 365       | 484       |
| uniswap_v2_factory  | 0.55          | **0.45**        | 50        | 73        |
| **uniswap_v2_router** | **122.58**  | **16.65**       | 7910      | **3043**  |

- **UniV2 Router: Lutetia is ~6.7× faster** (16.6 s vs 122.6 s) and produces **~55% fewer lines** (3043 vs 7910).
- Lutetia is faster than Panoramix on 4 of 5 contracts.
- Panoramix fails on Uniswap V2 Factory’s `createPair`; Lutetia decompiles it fully.

---

## Install

Lutetia is [published on crates.io](https://crates.io/crates/lutetia). Install the CLI and run `lutetia` from the command line:

```bash
cargo install lutetia
lutetia --help
```

To install from a local clone:

```bash
cargo install --path .
```

Or build and run from the repo:

```bash
cargo build --release
./target/release/lutetia --help
```

---

## Usage

```bash
# From hex string
lutetia 6001600201

# From file
lutetia -f bytecode.hex

# From contract address (mainnet)
lutetia 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

# Options
lutetia --help
#   -f, --file <FILE>     Read bytecode from file
#   -o, --format <FMT>    text (default), asm, json
#   -t, --timeout <SEC>   Execution timeout (default: 60)
#   --no-color            Disable coloured output
```

---

## Example output

```text
$ lutetia 00
stop

$ lutetia 602a60005500
stor[0] = 42
stop
```

Real contract output is pseudo-Python with `def`, `require`, and resolved calls/storage:

```python
def balanceOf(address account): # not payable
  return balanceOf[account]

def approve(address spender, uint256 amount): # not payable
  allowance[caller][spender] = amount
  log Approval(amount, address=caller, address=spender)
  return 1
```

---

## Thanks

Lutetia builds on ideas and prior art from [Panoramix](https://github.com/palkeo/panoramix) and [Eveem (eveem.org)](https://eveem.org). We thank the Panoramix and Eveem-org contributors.

---

## License

MIT
