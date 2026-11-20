//! Edits of the relay's `policy.json` for the end-to-end test, in the format
//! `setup::grant` writes. The relay reads the file again on every request and every few
//! seconds for its open streams.

use std::{io::Write, path::Path};

use anyhow::Result;
use serde_json::{Map, Value, json};

/// The rules a freshly granted desktop has: read-only, every read tool, any package.
pub fn read_only() -> Value {
    json!({"read_only": true, "actions": null, "packages": null})
}

/// Read-only rules that allow only the named tools.
pub fn only(tools: &[&str]) -> Value {
    json!({"read_only": true, "actions": tools, "packages": null})
}

/// Replace `policy.json`: every desktop in `desktops` (fingerprint and rules) is granted
/// `endpoint`, and legacy `/mcp` sessions for the endpoint are refused when `require_e2e`.
pub fn write(
    pki: &Path,
    endpoint: &str,
    desktops: &[(String, Value)],
    require_e2e: bool,
) -> Result<()> {
    let mut rules = Map::new();
    let mut grants = Map::new();
    for (desktop, desktop_rules) in desktops {
        rules.insert(desktop.clone(), desktop_rules.clone());
        grants.insert(desktop.clone(), json!([endpoint]));
    }
    let mut required = Map::new();
    if require_e2e {
        required.insert(endpoint.to_owned(), json!(true));
    }
    let document = json!({
        "global": {"read_only": false, "actions": null, "packages": null},
        "desktops": rules,
        "endpoint_grants": grants,
        "require_e2e": false,
        "require_e2e_endpoints": required,
    });
    let mut file = tempfile::NamedTempFile::new_in(pki)?;
    file.write_all(&serde_json::to_vec(&document)?)?;
    file.persist(pki.join("policy.json"))?;
    Ok(())
}
