//! Function and event signature lookup.
//!
//! Uses a bundled compressed database (~536K entries extracted from Panoramix's
//! abi_dump plus curated event signatures) for fast offline resolution.
//! Falls back to the OpenChain API when the local database has no match.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;

/// The gzip-compressed signature database, embedded at compile time.
/// Format: one line per entry,
///   `f\t<hex_selector>\t<signature>\t<param_names>\n`   for functions,
///   `e\t<hex_topic>\t<signature>\t<param_names>\n`      for events.
/// `<param_names>` is a comma-separated list (may contain empty strings).
static EMBEDDED_DB: &[u8] = include_bytes!("../../data/signatures.db.gz");

/// Lazily-initialised local database (decompressed on first access).
static LOCAL_DB: Mutex<Option<LocalDb>> = Mutex::new(None);

/// Network lookup cache (to avoid duplicate HTTP requests within one run).
static NET_CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);

/// Entry in the local DB: signature + optional parameter names.
#[derive(Clone, Debug)]
struct SigEntry {
    signature: String,
    param_names: Vec<String>,
}

struct LocalDb {
    functions: HashMap<String, SigEntry>,
    events: HashMap<String, SigEntry>,
}

/// Decompress and parse the embedded DB.  Called once, lazily.
fn load_local_db() -> LocalDb {
    let mut decoder = flate2::read::GzDecoder::new(EMBEDDED_DB);
    let mut text = String::new();
    decoder.read_to_string(&mut text).unwrap_or_default();

    let mut functions = HashMap::new();
    let mut events = HashMap::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let kind = parts[0];
        let selector = format!("0x{}", parts[1]);
        let signature = parts[2].to_string();
        let param_names: Vec<String> = if parts.len() >= 4 && !parts[3].is_empty() {
            parts[3].split(',').map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };
        let entry = SigEntry {
            signature,
            param_names,
        };
        match kind {
            "f" => {
                functions.entry(selector).or_insert(entry);
            }
            "e" => {
                events.entry(selector).or_insert(entry);
            }
            _ => {}
        }
    }

    log::info!(
        "Loaded local signature DB: {} functions, {} events",
        functions.len(),
        events.len()
    );
    LocalDb { functions, events }
}

/// Get or initialise the local DB.
fn with_local_db<F, T>(f: F) -> T
where
    F: FnOnce(&LocalDb) -> T,
{
    let mut guard = LOCAL_DB.lock().unwrap();
    let db = guard.get_or_insert_with(load_local_db);
    f(db)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Look up a 4-byte function selector (hex, e.g. `"0xa9059cbb"`).
/// Returns the function signature such as `"transfer(address,uint256)"` or `None`.
pub fn get_func_name(hash: &str) -> Option<String> {
    let lower = hash.to_lowercase();

    // 1. Try local DB
    if let Some(entry) = with_local_db(|db| db.functions.get(&lower).cloned()) {
        return Some(entry.signature);
    }

    // 2. Try network cache
    {
        let guard = NET_CACHE.lock().unwrap();
        if let Some(ref map) = *guard {
            if let Some(cached) = map.get(&lower) {
                return cached.clone();
            }
        }
    }

    // 3. Fetch from network
    let result = fetch_signature(&lower, "function");
    {
        let mut guard = NET_CACHE.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(lower, result.clone());
    }
    result
}

/// Look up a 4-byte function selector and return parameter names from the ABI.
/// Returns `["tokenA", "tokenB", ...]` or an empty vec if not found.
pub fn get_param_names(hash: &str) -> Vec<String> {
    let lower = hash.to_lowercase();
    with_local_db(|db| {
        db.functions
            .get(&lower)
            .map(|e| e.param_names.clone())
            .unwrap_or_default()
    })
}

/// Look up a 32-byte event topic hash (hex, e.g. `"0xddf252ad..."`).
/// Returns the event name such as `"Transfer(address,address,uint256)"` or `None`.
pub fn get_event_name(hash: &str) -> Option<String> {
    let lower = hash.to_lowercase();

    // 1. Try local DB
    if let Some(entry) = with_local_db(|db| db.events.get(&lower).cloned()) {
        return Some(entry.signature);
    }

    // 2. Try network cache
    {
        let guard = NET_CACHE.lock().unwrap();
        if let Some(ref map) = *guard {
            if let Some(cached) = map.get(&lower) {
                return cached.clone();
            }
        }
    }

    // 3. Fetch from network
    let result = fetch_signature(&lower, "event");
    {
        let mut guard = NET_CACHE.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(lower, result.clone());
    }
    result
}

// ---------------------------------------------------------------------------
// Network fallback
// ---------------------------------------------------------------------------

/// Fetch a function or event signature from the OpenChain API.
///
/// When multiple results are returned (collision names), prefer the
/// shortest / most natural name.
fn fetch_signature(hash: &str, kind: &str) -> Option<String> {
    let url = format!(
        "https://api.openchain.xyz/signature-database/v1/lookup?{kind}={hash}&filter=true"
    );
    let resp = reqwest::blocking::get(&url).ok()?;
    let json: serde_json::Value = resp.json().ok()?;
    let results = json.get("result")?.get(kind)?.get(hash)?;
    let candidates: Vec<&str> = results
        .as_array()?
        .iter()
        .filter_map(|e| e.get("name")?.as_str())
        .collect();

    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates[0].to_string());
    }

    // Filter out known collision/scam patterns, then prefer shortest natural name.
    let is_collision = |name: &str| -> bool {
        let base = name.split('(').next().unwrap_or(name);
        if base.contains("tg_invmru")
            || base.contains("SIMONdotBLACK")
            || base.contains("simon")
            || base.contains("_attention_")
        {
            return true;
        }
        if base.len() > 6 {
            let tail: String = base.chars().rev().take(5).collect();
            if tail
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
                && tail.chars().any(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
        if base.len() > 3 && !base.chars().any(|c| "aeiouAEIOU".contains(c)) {
            return true;
        }
        false
    };

    let clean: Vec<&str> = candidates
        .iter()
        .filter(|n| !is_collision(n))
        .copied()
        .collect();
    let pool = if clean.is_empty() { &candidates } else { &clean };

    let score = |name: &str| -> (bool, usize) {
        let base = name.split('(').next().unwrap_or(name);
        let has_uppercase = base.chars().any(|c| c.is_ascii_uppercase());
        (has_uppercase, name.len())
    };

    let mut scored: Vec<_> = pool.iter().map(|n| (score(n), *n)).collect();
    scored.sort();
    Some(scored[0].1.to_string())
}

// ---------------------------------------------------------------------------
// ABI builder
// ---------------------------------------------------------------------------

/// Build a minimal ABI from a list of (hash, name) pairs.
pub fn make_abi(hash_targets: &HashMap<String, String>) -> serde_json::Value {
    let mut functions = Vec::new();
    for (hash, name) in hash_targets {
        functions.push(serde_json::json!({
            "type": "function",
            "name": name,
            "selector": hash,
        }));
    }
    serde_json::json!({ "functions": functions })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_db_loads() {
        let entry = with_local_db(|db| db.functions.get("0xa9059cbb").cloned());
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().signature, "transfer(address,uint256)");
    }

    #[test]
    fn test_local_db_events() {
        let entry = with_local_db(|db| {
            db.events
                .get("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
                .cloned()
        });
        assert!(entry.is_some());
        assert_eq!(
            entry.unwrap().signature,
            "Transfer(address,address,uint256)"
        );
    }

    #[test]
    fn test_get_func_name_local() {
        let name = get_func_name("0xa9059cbb");
        assert_eq!(name, Some("transfer(address,uint256)".to_string()));
    }

    #[test]
    fn test_get_param_names() {
        let params = get_param_names("0xe8e33700"); // addLiquidity
        assert!(!params.is_empty());
        assert_eq!(params[0], "tokenA");
        assert_eq!(params[1], "tokenB");
    }

    #[test]
    fn test_make_abi() {
        let mut targets = HashMap::new();
        targets.insert("0xa9059cbb".to_string(), "transfer".to_string());
        let abi = make_abi(&targets);
        assert!(abi["functions"].is_array());
    }
}
