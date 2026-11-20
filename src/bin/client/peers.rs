//! Pinned Eclipse keys (`peers.json`, `docs/plan-e2e-envelope.md` §1 and §7).
//!
//! The file maps an endpoint ID to the SHA-256 of the `SubjectPublicKeyInfo` of that Eclipse's
//! inner key. A missing file means "nothing paired". A damaged file is an error and never
//! "nothing paired": reading it as empty would turn a broken file into a silent downgrade to
//! the relay-readable path.

use std::{collections::BTreeMap, io, path::Path};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{storage, transport::read_file};

pub const PEERS_FILE: &str = "peers.json";

fn valid_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One pinned Eclipse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// SHA-256 of the `SubjectPublicKeyInfo` DER, 64 lowercase hex characters.
    pub key: String,
    pub label: String,
    /// RFC 3339, UTC.
    #[serde(rename = "pairedAt")]
    pub paired_at: String,
}

/// How a session to an endpoint reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// End to end through the tunnel, pinned to this key.
    Tunnel([u8; 32]),
    /// The relay-readable `/mcp` path, for an endpoint that was never paired.
    Legacy,
}

impl Route {
    /// Whether the relay-readable path may be used. Once a pin exists it never may,
    /// whatever the relay says.
    #[must_use]
    pub const fn legacy_allowed(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

/// The contents of `peers.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Peers {
    entries: BTreeMap<String, Peer>,
}

impl Peers {
    /// Reads the profile's pins; a missing file is an empty set.
    ///
    /// # Errors
    /// The file is unreadable or damaged.
    pub fn load(directory: &Path) -> Result<Self> {
        let bytes = match read_file(&directory.join(PEERS_FILE)) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).context("Could not read peers.json."),
        };
        let peers: Self =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("peers.json is damaged."))?;
        for (endpoint, peer) in &peers.entries {
            ensure!(
                valid_hex_32(endpoint) && valid_hex_32(&peer.key),
                "peers.json is damaged."
            );
        }
        Ok(peers)
    }

    /// Replaces the file atomically; it stays owner-only.
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn save(&self, directory: &Path) -> Result<()> {
        let path = directory.join(PEERS_FILE);
        let bytes = serde_json::to_vec_pretty(self)?;
        storage::stage(&path, &bytes)?
            .persist(&path)
            .context("Could not save peers.json.")?;
        Ok(())
    }

    /// The pinned key of `endpoint`, if it is paired.
    #[must_use]
    pub fn pin(&self, endpoint: &str) -> Option<[u8; 32]> {
        let peer = self.entries.get(endpoint)?;
        let mut key = [0; 32];
        hex::decode_to_slice(&peer.key, &mut key).ok()?;
        Some(key)
    }

    /// The route for `endpoint`: the tunnel whenever a pin exists.
    #[must_use]
    pub fn route(&self, endpoint: &str) -> Route {
        self.pin(endpoint).map_or(Route::Legacy, Route::Tunnel)
    }

    /// Pins `key` for `endpoint`, replacing an earlier pin.
    pub fn insert(&mut self, endpoint: &str, key: &[u8; 32], label: &str, paired_at: &str) {
        self.entries.insert(
            endpoint.to_owned(),
            Peer {
                key: hex::encode(key),
                label: label.to_owned(),
                paired_at: paired_at.to_owned(),
            },
        );
    }

    /// Removes the pin of an endpoint named by its full ID or an exact, unique label.
    ///
    /// # Errors
    /// Nothing or more than one pin matches.
    pub fn remove(&mut self, choice: &str) -> Result<String> {
        if self.entries.remove(choice).is_some() {
            return Ok(choice.to_owned());
        }
        let mut matches = self
            .entries
            .iter()
            .filter(|(_, peer)| peer.label == choice)
            .map(|(endpoint, _)| endpoint.clone());
        let found = matches
            .next()
            .context("No paired endpoint has this ID or label.")?;
        ensure!(
            matches.next().is_none(),
            "Several paired endpoints have this label. Use the full endpoint ID."
        );
        self.entries.remove(&found);
        Ok(found)
    }
}

/// The current time as RFC 3339 in UTC, to the second.
#[must_use]
pub fn rfc3339_now() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// `unpair --profile <dir> --endpoint <id-or-label>`.
///
/// # Errors
/// The pin file cannot be read or written, or no pin matches.
pub fn unpair(directory: &Path, choice: &str) -> Result<()> {
    let mut peers = Peers::load(directory)?;
    let endpoint = peers.remove(choice)?;
    peers.save(directory)?;
    println!(
        "Removed the pin for endpoint {endpoint}. This endpoint is no longer paired; remove this desktop in Eclipse's MCP view as well."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_round_trip_through_the_file() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(Peers::load(directory.path()).unwrap(), Peers::default());
        let mut peers = Peers::default();
        let endpoint = "ab".repeat(32);
        peers.insert(
            &endpoint,
            &[7; 32],
            "Eclipse Laptop",
            "2026-11-20T10:00:00Z",
        );
        peers.save(directory.path()).unwrap();
        let text = std::fs::read_to_string(directory.path().join(PEERS_FILE)).unwrap();
        assert!(text.contains("\"pairedAt\""));
        let loaded = Peers::load(directory.path()).unwrap();
        assert_eq!(loaded, peers);
        assert_eq!(loaded.pin(&endpoint), Some([7; 32]));
        assert_eq!(loaded.pin(&"cd".repeat(32)), None);
    }

    #[test]
    fn a_damaged_file_is_an_error_not_an_empty_set() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(PEERS_FILE), b"{not json").unwrap();
        assert!(Peers::load(directory.path()).is_err());
        std::fs::write(
            directory.path().join(PEERS_FILE),
            br#"{"short":{"key":"00","label":"x","pairedAt":"y"}}"#,
        )
        .unwrap();
        assert!(Peers::load(directory.path()).is_err());
    }

    #[test]
    fn removal_works_by_id_or_unique_label() {
        let mut peers = Peers::default();
        let (first, second, third) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        peers.insert(&first, &[1; 32], "DEV", "t");
        peers.insert(&second, &[2; 32], "DEV", "t");
        peers.insert(&third, &[3; 32], "QAS", "t");
        assert!(peers.remove("DEV").is_err());
        assert_eq!(peers.remove("QAS").unwrap(), third);
        assert_eq!(peers.remove(&first).unwrap(), first);
        assert!(peers.remove("missing").is_err());
        assert_eq!(peers.pin(&second), Some([2; 32]));
    }

    #[test]
    fn once_paired_the_route_is_the_tunnel_and_never_legacy() {
        let mut peers = Peers::default();
        let paired = "aa".repeat(32);
        let other = "bb".repeat(32);
        peers.insert(&paired, &[9; 32], "DEV", "t");
        let route = peers.route(&paired);
        assert_eq!(route, Route::Tunnel([9; 32]));
        assert!(!route.legacy_allowed());
        assert!(peers.route(&other).legacy_allowed());
    }

    #[test]
    fn the_timestamp_is_rfc_3339_utc() {
        let text = rfc3339_now();
        assert_eq!(text.len(), 20);
        assert!(text.ends_with('Z') && text.as_bytes()[10] == b'T');
    }
}
