//! descriptor-forge: build & inspect Bitcoin Core `importdescriptors` commands.
//!
//! Compiled to WebAssembly; all descriptor validation and checksums are done by
//! rust-miniscript (the same checksum algorithm Bitcoin Core uses).

use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use serde::Deserialize;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

type Desc = Descriptor<DescriptorPublicKey>;

/// The user's reference command (used in tests to prove byte-exact reproduction).
#[cfg(test)]
const USER_COMMAND: &str = r##"importdescriptors '[{"active":true,"timestamp":1783209600,"range":[0,100],"internal":false,"desc":"wsh(multi(2,[00000004/0/0/0/0]tpubDEkyrFWPSbb3oULL1q7Z4m8CmHX1fk9iUXdpKzhEdjWqsZojk2PfDTryVeF33AEREW5SGqXYXsPS8XhJqYvGs7iCr7wxdj8t3EeRCs2w89j/0/0/20/*,[00000003/0/0/0/0]tpubDEmyALkSddGqNHP8v7wTXv5teRA4Yt83chfLJQA1MTnHsFEtiHwyQacN8yGCZBDPzCTSPaNwRqpH5PaaiHYygAavQtKWSDLcAtNVAKdEV5U/0/0/20/*,tpubD6NzVbkrYhZ4Xvdjr5T8Q8TyhpdGzbXhcRaKBioPdNj9F5qAq6mbQeHffrYm5GPppQ2eCzqMPr2mzU1sk9Kq9xt6UU2DtrUbU92724tVYLz/0/0/20/*))#mvqsfxpe"},{"active":true,"timestamp":1783209600,"range":[0,100],"internal":true,"desc":"wsh(multi(2,[00000004/0/0/0/0]tpubDEkyrFWPSbb3oULL1q7Z4m8CmHX1fk9iUXdpKzhEdjWqsZojk2PfDTryVeF33AEREW5SGqXYXsPS8XhJqYvGs7iCr7wxdj8t3EeRCs2w89j/0/0/21/*,[00000003/0/0/0/0]tpubDEmyALkSddGqNHP8v7wTXv5teRA4Yt83chfLJQA1MTnHsFEtiHwyQacN8yGCZBDPzCTSPaNwRqpH5PaaiHYygAavQtKWSDLcAtNVAKdEV5U/0/0/21/*,tpubD6NzVbkrYhZ4Xvdjr5T8Q8TyhpdGzbXhcRaKBioPdNj9F5qAq6mbQeHffrYm5GPppQ2eCzqMPr2mzU1sk9Kq9xt6UU2DtrUbU92724tVYLz/0/0/21/*))#2l3zaz08"}]'"##;

#[cfg(test)]
const EXT_DESC: &str = "wsh(multi(2,[00000004/0/0/0/0]tpubDEkyrFWPSbb3oULL1q7Z4m8CmHX1fk9iUXdpKzhEdjWqsZojk2PfDTryVeF33AEREW5SGqXYXsPS8XhJqYvGs7iCr7wxdj8t3EeRCs2w89j/0/0/20/*,[00000003/0/0/0/0]tpubDEmyALkSddGqNHP8v7wTXv5teRA4Yt83chfLJQA1MTnHsFEtiHwyQacN8yGCZBDPzCTSPaNwRqpH5PaaiHYygAavQtKWSDLcAtNVAKdEV5U/0/0/20/*,tpubD6NzVbkrYhZ4Xvdjr5T8Q8TyhpdGzbXhcRaKBioPdNj9F5qAq6mbQeHffrYm5GPppQ2eCzqMPr2mzU1sk9Kq9xt6UU2DtrUbU92724tVYLz/0/0/20/*))";

// ---------------------------------------------------------------------------
// core helpers
// ---------------------------------------------------------------------------

/// Undo shell quoting artefacts from pasted commands: `'\''`, `'"'"'`, `\'`
/// (single quotes, e.g. hardened path markers) and `\"` from $'...'/double-quoted wraps.
fn shell_unescape(s: &str) -> String {
    s.replace(r##"'"'"'"##, "'")
        .replace(r#"'\''"#, "'")
        .replace(r#"\""#, "\"")
        .replace(r"\'", "'")
}

/// Parse a descriptor (with or without `#checksum`, with or without shell
/// escapes) and return the canonical parsed form.
fn canonical(desc: &str) -> Result<Desc, String> {
    let clean = shell_unescape(desc);
    let base = clean.trim().split('#').next().unwrap_or("").trim();
    if base.is_empty() {
        return Err("empty descriptor".to_string());
    }
    Desc::from_str(base).map_err(|e| e.to_string())
}

/// Collect every `after(N)` absolute timelock mentioned in the descriptor text.
fn find_timelocks(base: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut rest = base;
    while let Some(pos) = rest.find("after(") {
        rest = &rest[pos + "after(".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            if let Ok(n) = digits.parse::<u64>() {
                out.push(n);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Top-level script type label + every key (with origin/wildcard) in the descriptor.
fn describe(d: &Desc) -> (String, Vec<String>) {
    let label = match d {
        Descriptor::Bare(_) => "Bare script",
        Descriptor::Pkh(_) => "P2PKH (legacy)",
        Descriptor::Wpkh(_) => "P2WPKH (segwit v0, keyhash)",
        Descriptor::Sh(_) => "P2SH (wrapped)",
        Descriptor::Wsh(_) => "P2WSH (segwit v0, scripthash)",
        Descriptor::Tr(_) => "P2TR (taproot)",
    };
    let mut keys = Vec::new();
    d.for_each_key(|k| {
        keys.push(k.to_string());
        true
    });
    (label.to_string(), keys)
}

// ---------------------------------------------------------------------------
// generator params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct KeySpec {
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    origin: String,
    xpub: String,
    /// Derivation suffix appended after the xpub, e.g. "/0/0/20". Wildcard is added for you.
    #[serde(default)]
    path: String,
}

#[derive(Debug, Deserialize)]
struct GenParams {
    /// "single" | "multi" | "raw"
    mode: String,
    /// pkh | wpkh | sh_wpkh | wsh_multi | wsh_sortedmulti
    #[serde(default)]
    script: String,
    #[serde(default)]
    threshold: Option<u32>,
    #[serde(default)]
    keys: Vec<KeySpec>,
    #[serde(default)]
    raw: String,
    /// Generate both internal=false and internal=true entries.
    #[serde(default)]
    both_branches: bool,
    /// Path suffix used for the change (internal=true) branch, e.g. "/0/0/21".
    #[serde(default)]
    change_path: String,
    #[serde(default)]
    active: Option<bool>,
    /// Unix timestamp number, or the string "now".
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
    #[serde(default)]
    range: Option<(u32, u32)>,
    #[serde(default)]
    internal: bool,
    #[serde(default)]
    label: String,
    #[serde(default)]
    next_index: Option<u32>,
}

fn key_string(k: &KeySpec, path_override: Option<&str>) -> Result<String, String> {
    let xpub = k.xpub.trim();
    if xpub.is_empty() {
        return Err("a key is missing its xpub".to_string());
    }
    let mut s = String::new();
    let fp = k.fingerprint.trim();
    if !fp.is_empty() {
        let origin = k.origin.trim();
        s.push('[');
        s.push_str(fp);
        if !origin.is_empty() {
            if !origin.starts_with('/') {
                s.push('/');
            }
            s.push_str(origin);
        }
        s.push(']');
    }
    s.push_str(xpub);
    let mut path = k.path.trim();
    if let Some(p) = path_override {
        let p = p.trim();
        if !p.is_empty() {
            path = p;
        }
    }
    if !path.is_empty() {
        if !path.starts_with('/') {
            s.push('/');
        }
        s.push_str(path);
    }
    s.push_str("/*");
    Ok(s)
}

/// On the change branch of a both-branches build, swap every key's path suffix.
fn branch_override<'a>(p: &'a GenParams, internal: bool) -> Option<&'a str> {
    if internal && p.both_branches {
        Some(p.change_path.as_str())
    } else {
        None
    }
}

/// Build the descriptor body (no checksum) for one branch.
fn build_body(p: &GenParams, internal: bool) -> Result<String, String> {
    match p.mode.as_str() {
        "raw" => {
            if p.raw.trim().is_empty() {
                return Err("raw mode needs a descriptor".to_string());
            }
            Ok(p.raw.trim().to_string())
        }
        "single" => {
            let k = p
                .keys
                .first()
                .ok_or_else(|| "single-key mode needs one key".to_string())?;
            let key = key_string(k, branch_override(p, internal))?;
            match p.script.as_str() {
                "pkh" => Ok(format!("pkh({key})")),
                "wpkh" => Ok(format!("wpkh({key})")),
                "sh_wpkh" => Ok(format!("sh(wpkh({key}))")),
                other => Err(format!("unknown single-key script type: {other}")),
            }
        }
        "multi" => {
            if p.keys.is_empty() {
                return Err("multisig needs at least one key".to_string());
            }
            let m = p
                .threshold
                .ok_or_else(|| "multisig needs a threshold".to_string())? as usize;
            if m == 0 || m > p.keys.len() {
                return Err(format!(
                    "threshold must be between 1 and {} (the number of keys)",
                    p.keys.len()
                ));
            }
            let ks: Result<Vec<String>, String> = p
                .keys
                .iter()
                .map(|k| key_string(k, branch_override(p, internal)))
                .collect();
            let wrapper = if p.script == "wsh_sortedmulti" {
                "sortedmulti"
            } else {
                "multi"
            };
            Ok(format!("wsh({wrapper}({m},{}))", ks?.join(",")))
        }
        other => Err(format!("unknown mode: {other}")),
    }
}

// ---------------------------------------------------------------------------
// wasm exports
// ---------------------------------------------------------------------------

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn wasm_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Validate a descriptor and return it with its (correct) checksum appended.
#[wasm_bindgen]
pub fn compute_checksum(desc: &str) -> Result<String, String> {
    Ok(canonical(desc)?.to_string())
}

/// Shared per-entry options applied when assembling the JSON array.
struct ImportOpts {
    active: bool,
    timestamp: serde_json::Value,
    range: Option<(u32, u32)>,
    next_index: Option<u32>,
    label: String,
}

/// One `importdescriptors` array element. Field order matches Core's examples.
fn make_item(full_desc: String, internal: bool, o: &ImportOpts) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("active".into(), serde_json::Value::Bool(o.active));
    m.insert("timestamp".into(), o.timestamp.clone());
    if let Some((a, b)) = o.range {
        m.insert("range".into(), serde_json::json!([a, b]));
        if let Some(ni) = o.next_index {
            m.insert("next_index".into(), serde_json::json!(ni));
        }
    }
    m.insert("internal".into(), serde_json::Value::Bool(internal));
    if !o.label.trim().is_empty() {
        m.insert("label".into(), serde_json::json!(o.label.trim()));
    }
    m.insert("desc".into(), serde_json::Value::String(full_desc));
    serde_json::Value::Object(m)
}

/// Wrap assembled items into the response payload. `command` is for the Core
/// console; `command_shell` has single quotes escaped (`'\''`) so it can be
/// pasted into bash/sh even when descriptors contain hardened `'` markers.
fn wrap_response(items: Vec<serde_json::Value>, descs: Vec<serde_json::Value>) -> Result<String, String> {
    let json = serde_json::to_string(&items).map_err(|e| e.to_string())?;
    let pretty = serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?;
    let command = format!("importdescriptors '{json}'");
    let command_shell = format!("importdescriptors '{}'", json.replace('\'', r"'\''"));
    Ok(serde_json::json!({
        "command": command,
        "command_shell": command_shell,
        "json": json,
        "pretty": pretty,
        "descriptors": descs,
        "count": items.len(),
    })
    .to_string())
}

/// Build a complete `importdescriptors '<json>'` command from UI params.
/// Input/output are JSON strings.
#[wasm_bindgen]
pub fn build_import(params_json: &str) -> Result<String, String> {
    let p: GenParams =
        serde_json::from_str(params_json).map_err(|e| format!("bad params: {e}"))?;
    let branches: Vec<bool> = if p.both_branches {
        vec![false, true]
    } else {
        vec![p.internal]
    };
    let opts = ImportOpts {
        active: p.active.unwrap_or(true),
        timestamp: p
            .timestamp
            .clone()
            .unwrap_or(serde_json::Value::String("now".into())),
        range: p.range,
        next_index: p.next_index,
        label: p.label.clone(),
    };

    let mut items = Vec::new();
    let mut descs = Vec::new();
    for internal in branches {
        let body = build_body(&p, internal)?;
        let d = canonical(&body)?; // validates structure, keys, paths
        let full = d.to_string();
        let checksum = full.rsplit('#').next().unwrap_or("").to_string();
        items.push(make_item(full.clone(), internal, &opts));
        descs.push(serde_json::json!({
            "desc": full,
            "checksum": checksum,
            "internal": internal,
        }));
    }
    wrap_response(items, descs)
}

#[derive(Debug, Deserialize)]
struct RebuildEntry {
    desc: String,
    #[serde(default)]
    internal: bool,
}

#[derive(Debug, Deserialize)]
struct RebuildParams {
    entries: Vec<RebuildEntry>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
    #[serde(default)]
    range: Option<(u32, u32)>,
    #[serde(default)]
    label: String,
}

/// Mint a fresh `importdescriptors` command from previously extracted
/// descriptors plus new shared options. Every descriptor is re-validated and
/// its checksum recomputed, so mangled pastes self-heal.
#[wasm_bindgen]
pub fn rebuild_command(params_json: &str) -> Result<String, String> {
    let p: RebuildParams =
        serde_json::from_str(params_json).map_err(|e| format!("bad params: {e}"))?;
    if p.entries.is_empty() {
        return Err("nothing to rebuild — no descriptors given".to_string());
    }
    let opts = ImportOpts {
        active: p.active.unwrap_or(true),
        timestamp: p
            .timestamp
            .clone()
            .unwrap_or(serde_json::Value::String("now".into())),
        range: p.range,
        next_index: None,
        label: p.label.clone(),
    };

    let mut items = Vec::new();
    let mut descs = Vec::new();
    for e in &p.entries {
        let d = canonical(&e.desc)?; // also strips shell escapes + bad checksums
        let full = d.to_string();
        let checksum = full.rsplit('#').next().unwrap_or("").to_string();
        items.push(make_item(full.clone(), e.internal, &opts));
        descs.push(serde_json::json!({
            "desc": full,
            "checksum": checksum,
            "internal": e.internal,
        }));
    }
    wrap_response(items, descs)
}

/// Parse a pasted `importdescriptors ...` command (or bare JSON array) and
/// extract + validate every descriptor inside it.
#[wasm_bindgen]
pub fn extract_command(text: &str) -> Result<String, String> {
    let t = text.trim();
    let start = t.find('[').ok_or_else(|| {
        "couldn't find a JSON array — paste the full importdescriptors command or just its JSON"
            .to_string()
    })?;
    let end = t
        .rfind(']')
        .ok_or_else(|| "couldn't find the end of the JSON array".to_string())?;
    if end <= start {
        return Err("malformed JSON array".to_string());
    }
    // Undo shell quoting ('\'' etc. from hardened path markers) before JSON parsing.
    let cleaned = shell_unescape(&t[start..=end]);
    let items: Vec<serde_json::Value> =
        serde_json::from_str(&cleaned).map_err(|e| format!("invalid JSON: {e}"))?;
    if items.is_empty() {
        return Err("the JSON array is empty".to_string());
    }

    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let desc = item
            .get("desc")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("entry #{i} has no \"desc\" string"))?;
        let clean_desc = shell_unescape(desc);
        let (base, provided) = match clean_desc.split_once('#') {
            Some((b, c)) => (b.to_string(), Some(c.to_string())),
            None => (clean_desc.clone(), None),
        };

        let mut entry = serde_json::Map::new();
        entry.insert("index".into(), serde_json::json!(i));
        entry.insert("desc".into(), serde_json::json!(clean_desc));
        entry.insert("base".into(), serde_json::json!(base));
        entry.insert("provided_checksum".into(), serde_json::json!(provided));
        entry.insert("timelocks".into(), serde_json::json!(find_timelocks(&base)));

        match canonical(&base) {
            Ok(d) => {
                let full = d.to_string();
                let computed = full.rsplit('#').next().unwrap_or("").to_string();
                let checksum_valid = provided
                    .as_deref()
                    .map(|pc| pc == computed)
                    .unwrap_or(false);
                let (script_type, keys) = describe(&d);
                entry.insert("valid".into(), serde_json::json!(true));
                entry.insert("computed_checksum".into(), serde_json::json!(computed));
                entry.insert("checksum_valid".into(), serde_json::json!(checksum_valid));
                entry.insert("canonical".into(), serde_json::json!(full));
                entry.insert("script_type".into(), serde_json::json!(script_type));
                entry.insert("keys".into(), serde_json::json!(keys));
            }
            Err(e) => {
                entry.insert("valid".into(), serde_json::json!(false));
                entry.insert("error".into(), serde_json::json!(e));
            }
        }
        for field in ["active", "timestamp", "internal", "range", "next_index", "label"] {
            if let Some(v) = item.get(field) {
                entry.insert(field.into(), v.clone());
            }
        }
        out.push(serde_json::Value::Object(entry));
    }

    Ok(serde_json::json!({ "ok": true, "count": out.len(), "descriptors": out }).to_string())
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_user_example() {
        let full = compute_checksum(EXT_DESC).unwrap();
        assert!(full.ends_with("#mvqsfxpe"), "got {full}");
        let int_desc = EXT_DESC.replace("/0/0/20/*", "/0/0/21/*");
        let full_int = compute_checksum(&int_desc).unwrap();
        assert!(full_int.ends_with("#2l3zaz08"), "got {full_int}");
    }

    #[test]
    fn parses_with_and_against_bad_checksum() {
        let good = format!("{EXT_DESC}#mvqsfxpe");
        assert!(Desc::from_str(&good).is_ok());
        let bad = format!("{EXT_DESC}#xxxxxxxx");
        assert!(Desc::from_str(&bad).is_err());
    }

    fn user_params() -> serde_json::Value {
        serde_json::json!({
            "mode": "multi",
            "script": "wsh_multi",
            "threshold": 2,
            "keys": [
                {"fingerprint":"00000004","origin":"/0/0/0/0","xpub":"tpubDEkyrFWPSbb3oULL1q7Z4m8CmHX1fk9iUXdpKzhEdjWqsZojk2PfDTryVeF33AEREW5SGqXYXsPS8XhJqYvGs7iCr7wxdj8t3EeRCs2w89j","path":"/0/0/20"},
                {"fingerprint":"00000003","origin":"/0/0/0/0","xpub":"tpubDEmyALkSddGqNHP8v7wTXv5teRA4Yt83chfLJQA1MTnHsFEtiHwyQacN8yGCZBDPzCTSPaNwRqpH5PaaiHYygAavQtKWSDLcAtNVAKdEV5U","path":"/0/0/20"},
                {"fingerprint":"","origin":"","xpub":"tpubD6NzVbkrYhZ4Xvdjr5T8Q8TyhpdGzbXhcRaKBioPdNj9F5qAq6mbQeHffrYm5GPppQ2eCzqMPr2mzU1sk9Kq9xt6UU2DtrUbU92724tVYLz","path":"/0/0/20"}
            ],
            "both_branches": true,
            "change_path": "/0/0/21",
            "active": true,
            "timestamp": 1783209600u64,
            "range": [0, 100],
            "internal": false
        })
    }

    #[test]
    fn reproduces_user_command_byte_for_byte() {
        let out = build_import(&user_params().to_string()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let command = v["command"].as_str().unwrap();

        // Compare generated JSON against the JSON inside the user's pasted command.
        let user_json = &USER_COMMAND[USER_COMMAND.find('[').unwrap()..=USER_COMMAND.rfind(']').unwrap()];
        let expected: Vec<serde_json::Value> = serde_json::from_str(user_json).unwrap();
        let actual: Vec<serde_json::Value> =
            serde_json::from_str(v["json"].as_str().unwrap()).unwrap();
        assert_eq!(actual, expected);
        assert!(command.starts_with("importdescriptors '"));
        assert!(command.ends_with("'"));
        assert!(command.contains("#mvqsfxpe"));
        assert!(command.contains("#2l3zaz08"));
    }

    #[test]
    fn extracts_user_command() {
        let out = extract_command(USER_COMMAND).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 2);
        let d0 = &v["descriptors"][0];
        assert_eq!(d0["checksum_valid"], true);
        assert_eq!(d0["provided_checksum"], "mvqsfxpe");
        assert_eq!(d0["script_type"], "P2WSH (segwit v0, scripthash)");
        assert_eq!(d0["keys"].as_array().unwrap().len(), 3);
        assert_eq!(d0["internal"], false);
        assert_eq!(v["descriptors"][1]["internal"], true);
        assert_eq!(v["descriptors"][1]["provided_checksum"], "2l3zaz08");
    }

    #[test]
    fn rejects_garbage() {
        assert!(build_import(r#"{"mode":"multi","script":"wsh_multi","threshold":2,"keys":[]}"#)
            .is_err());
        assert!(extract_command("hello world").is_err());
        assert!(compute_checksum("wsh(multi(2,notanxpub))").is_err());
    }

    /// The user's timelocked 2-of-3 + fallback-keys command, exactly as pasted
    /// from a shell (with '\'' escapes around hardened path markers).
    const ANDOR_COMMAND: &str = r##"importdescriptors '[{"active":true,"timestamp":1786924800,"range":[0,100],"internal":false,"desc":"wsh(andor(multi(2,[00000000/0/0/0/0]tpubDDxm2GDBtg4RZjoYWZoutdtbZ2BFGsTv9ha7i9CrPLKDHE2QVg3fECq1nU2VyDoVozavH4NjpTVKTyoUuLqWZ3bauwcFTvpBwHhiv7EFZjy/0/*,[00000001/0/0/0/0]tpubDDz2auawERTfkjFoHm9Dk3m4NnDrw1Xb792tAssf4SWDVVwbHoE59rBKzSU8psFR9u9C7avbRRgS2XCfvk2Cc7WQ9Ndf6JU1qSv3JSSyoUy/0/*,[00000002/0/0/0/0]tpubDEgdruGzqmmTUXsuef8YBCWuWa4MfKiLGCtCiipnaHmAynnUhic8o9UgWV9mqrGMktDUrBFbCNdaZdkiRwPBbkTDgFmCL4qoevsVqELSuTm/0/*),or_d(pk([85a08f85/48'\''/1'\''/0'\''/2'\'']tpubDEVfXE9sbG6EJeSariXJdqxzAso6NHQjbAs1vze7jo8hFda9Av8q4vX3kLzYY1pywayiBJxA1qZ6VSLJbqkzqVymr1yF28C3kjjA95kxnLr/0/*),and_v(v:pk([00000003/0/0/0/0]tpubDExA63tLHPf94cmb2EhLTW6FvoQz5RADEkJSGRpmXBEC62MjcbrWrh8DcJ6BZsb2tLBS3FxVruFgxPLbW7f9xPAX2fRsGefBxKu8ux1HHYb/0/*),after(1819756800))),and_v(v:pkh([85a08f85/48'\''/1'\''/0'\''/2'\'']tpubDEVfXE9sbG6EJeSariXJdqxzAso6NHQjbAs1vze7jo8hFda9Av8q4vX3kLzYY1pywayiBJxA1qZ6VSLJbqkzqVymr1yF28C3kjjA95kxnLr/2/*),after(1815868800))))#p2hdex78"}, {"active":true,"timestamp":1786924800,"range":[0,100],"internal":true,"desc":"wsh(andor(multi(2,[00000000/0/0/0/0]tpubDDxm2GDBtg4RZjoYWZoutdtbZ2BFGsTv9ha7i9CrPLKDHE2QVg3fECq1nU2VyDoVozavH4NjpTVKTyoUuLqWZ3bauwcFTvpBwHhiv7EFZjy/1/*,[00000001/0/0/0/0]tpubDDz2auawERTfkjFoHm9Dk3m4NnDrw1Xb792tAssf4SWDVVwbHoE59rBKzSU8psFR9u9C7avbRRgS2XCfvk2Cc7WQ9Ndf6JU1qSv3JSSyoUy/1/*,[00000002/0/0/0/0]tpubDEgdruGzqmmTUXsuef8YBCWuWa4MfKiLGCtCiipnaHmAynnUhic8o9UgWV9mqrGMktDUrBFbCNdaZdkiRwPBbkTDgFmCL4qoevsVqELSuTm/1/*),or_d(pk([85a08f85/48'\''/1'\''/0'\''/2'\'']tpubDEVfXE9sbG6EJeSariXJdqxzAso6NHQjbAs1vze7jo8hFda9Av8q4vX3kLzYY1pywayiBJxA1qZ6VSLJbqkzqVymr1yF28C3kjjA95kxnLr/1/*),and_v(v:pk([00000003/0/0/0/0]tpubDExA63tLHPf94cmb2EhLTW6FvoQz5RADEkJSGRpmXBEC62MjcbrWrh8DcJ6BZsb2tLBS3FxVruFgxPLbW7f9xPAX2fRsGefBxKu8ux1HHYb/1/*),after(1819756800))),and_v(v:pkh([85a08f85/48'\''/1'\''/0'\''/2'\'']tpubDEVfXE9sbG6EJeSariXJdqxzAso6NHQjbAs1vze7jo8hFda9Av8q4vX3kLzYY1pywayiBJxA1qZ6VSLJbqkzqVymr1yF28C3kjjA95kxnLr/3/*),after(1815868800))))#yywy6hda"}]'"##;

    #[test]
    fn extracts_shell_escaped_andor_command() {
        let out = extract_command(ANDOR_COMMAND).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 2);
        let d0 = &v["descriptors"][0];
        assert_eq!(d0["valid"], true);
        assert_eq!(d0["checksum_valid"], true);
        assert_eq!(d0["provided_checksum"], "p2hdex78");
        assert_eq!(v["descriptors"][1]["provided_checksum"], "yywy6hda");
        assert_eq!(v["descriptors"][1]["checksum_valid"], true);
        // multi(3 keys) + pk + pk + pkh = 6 keys total
        assert_eq!(d0["keys"].as_array().unwrap().len(), 6);
        // hardened path survived the '\'' unescaping
        assert!(d0["canonical"]
            .as_str()
            .unwrap()
            .contains("[85a08f85/48'/1'/0'/2']"));
        // both after() timelocks decoded, sorted + deduped
        assert_eq!(
            d0["timelocks"],
            serde_json::json!([1815868800u64, 1819756800u64])
        );
    }

    #[test]
    fn rebuild_mints_fresh_command_from_extracted() {
        let extracted = extract_command(ANDOR_COMMAND).unwrap();
        let v: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        let entries: Vec<serde_json::Value> = v["descriptors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| serde_json::json!({"desc": d["canonical"], "internal": d["internal"]}))
            .collect();
        let rebuild = serde_json::json!({
            "entries": entries,
            "timestamp": "now",
            "range": [0, 250],
            "label": "vault v2",
        });
        let out = rebuild_command(&rebuild.to_string()).unwrap();
        let r: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(r["count"], 2);
        assert!(r["command"].as_str().unwrap().contains("#p2hdex78"));
        assert!(r["command"].as_str().unwrap().contains("\"timestamp\":\"now\""));
        assert!(r["command"].as_str().unwrap().contains("\"range\":[0,250]"));
        assert!(r["command"].as_str().unwrap().contains("\"label\":\"vault v2\""));
        // bash-safe variant escapes the hardened ' markers
        let shell = r["command_shell"].as_str().unwrap();
        assert!(shell.contains(r"48'\''/1'\''"));
        // every single quote *inside* the wrapper must be part of a '\'' escape
        let inner = shell
            .strip_prefix("importdescriptors '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap();
        assert!(!inner.replace(r"'\''", "").contains('\''));
        // and it must still parse as JSON after re-unescaping
        let start = shell.find('[').unwrap();
        let end = shell.rfind(']').unwrap();
        let un = shell_unescape(&shell[start..=end]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&un).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn shell_unescape_variants() {
        assert_eq!(shell_unescape(r#"a'\''b"#,), "a'b");
        assert_eq!(shell_unescape(r##"a'"'"'b"##), "a'b");
        assert_eq!(shell_unescape(r#"a\'b"#), "a'b");
        assert_eq!(shell_unescape(r#"[{\"a\":1}]"#), r#"[{"a":1}]"#);
        assert_eq!(shell_unescape("plain"), "plain");
    }

    #[test]
    fn single_key_modes() {
        let params = serde_json::json!({
            "mode": "single",
            "script": "wpkh",
            "keys": [{"xpub":"tpubD6NzVbkrYhZ4Xvdjr5T8Q8TyhpdGzbXhcRaKBioPdNj9F5qAq6mbQeHffrYm5GPppQ2eCzqMPr2mzU1sk9Kq9xt6UU2DtrUbU92724tVYLz","path":"/0/0"}],
            "timestamp": "now"
        });
        let out = build_import(&params.to_string()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["descriptors"][0]["desc"]
            .as_str()
            .unwrap()
            .starts_with("wpkh(tpubD6Nz"));
        assert_eq!(v["descriptors"][0]["desc"].as_str().unwrap().matches('#').count(), 1);
    }
}
