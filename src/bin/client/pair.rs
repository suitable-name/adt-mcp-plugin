//! `pair --profile <dir> --link "<sap-adt://pair link>"` (`docs/plan-e2e-envelope.md` §1).
//!
//! The link comes from Eclipse's **Pair Desktop** and never travels through the relay. Its
//! token holds the pairing secret (first 32 bytes) and the SHA-256 of the plugin's inner key
//! (last 32 bytes). The client runs the inner handshake pinned to that fingerprint before it
//! sends anything, so a relay in the middle neither learns the secret nor can complete the
//! handshake.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    channel::{Channel, Parts, PinMismatch, Sent},
    endpoints,
    inner_tls::MISMATCH,
    keys::{InnerKey, short_form},
    link::PairLink,
    peers::{Peers, rfc3339_now},
    rt,
    transport::Profile,
    tunnel::Tunnel,
};

/// Eclipse waits two minutes for the user's click; allow for the relay on top.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(150);
const REFUSED: &str =
    "The link was wrong, expired, already used, or the pairing was refused in Eclipse.";

/// The pairing secret and the plugin key pin, from the link's token.
fn split_token(link: &PairLink) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let decoded = crate::token::decode(&link.token).context("The link's token is damaged.")?;
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(&decoded[..32]);
    let mut pin = [0_u8; 32];
    pin.copy_from_slice(&decoded[32..]);
    Ok((secret, pin))
}

/// The inner JSON-RPC request that claims the pairing. It holds the secret: keep it out of logs.
fn claim_request(secret: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let secret = Zeroizing::new(hex::encode(secret));
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "pair/claim",
        "params": {"secret": secret.as_str()}
    });
    Ok(Zeroizing::new(serde_json::to_vec(&request)?))
}

/// Whether Eclipse's answer to `pair/claim` is a success.
fn accepted(reply: &[u8]) -> bool {
    serde_json::from_slice::<Value>(reply).is_ok_and(|message| {
        message["jsonrpc"] == "2.0"
            && message["id"] == 1
            && message.get("result").is_some()
            && message.get("error").is_none()
    })
}

async fn claim(
    tunnel: &Tunnel,
    link: &PairLink,
    key: &InnerKey,
    secret: &[u8; 32],
    pin: [u8; 32],
) -> Result<()> {
    let mut channel = match Channel::open(tunnel, &link.endpoint, key, pin).await {
        Ok(channel) => channel,
        Err(error) if error.downcast_ref::<PinMismatch>().is_some() => {
            bail!(
                "The Eclipse behind this link presented a different key: {MISMATCH}. Nothing was sent."
            );
        }
        Err(error) => {
            return Err(error).context(
                "Could not reach the Eclipse in this link. Check that this desktop's endpoint grant exists and Eclipse is connected to the relay.",
            );
        }
    };
    eprintln!(
        "Confirm the pairing in Eclipse. This desktop's key: {}.",
        key.short_fingerprint()
    );
    let request = claim_request(secret)?;
    let parts = Parts {
        method: "pair/claim".into(),
        tool: None,
    };
    let sent = rt::timeout(CLAIM_TIMEOUT, channel.send(&parts, &request, true)).await;
    // A wrong secret, a refused click, a denial and a failed session all read the same.
    match sent {
        Ok(Ok(Sent::Reply(reply))) if accepted(&reply) => Ok(()),
        _ => bail!("{REFUSED}"),
    }
}

pub async fn run(directory: &Path, link: &str) -> Result<()> {
    let link = PairLink::parse(link)?;
    let (secret, pin) = split_token(&link)?;
    let profile = Profile::load(directory).with_context(|| {
        format!(
            "Cannot load the desktop profile at {}. Enroll it first with sap-adt-mcp-client enroll --help.",
            directory.display()
        )
    })?;
    // Fails on a damaged peers.json before anything is sent.
    let mut peers = Peers::load(directory)?;
    let key = InnerKey::load_or_create(directory)?;
    let tunnel = Tunnel::connect(&profile).await?;
    let outcome = claim(&tunnel, &link, &key, &secret, pin).await;
    tunnel.shutdown().await;
    outcome?;
    let label = if link.name.is_empty() {
        short_form(&pin)
    } else {
        link.name.clone()
    };
    peers.insert(&link.endpoint, &pin, &label, &rfc3339_now());
    peers.save(directory)?;
    endpoints::select_id(directory, &link.endpoint)
        .await
        .context(
            "Paired, but the endpoint could not be selected. Select it with --set-endpoint.",
        )?;
    println!(
        "Paired with {label} and selected it. Eclipse's key is pinned in peers.json; this desktop's key is {}. Restart the MCP connection to use it end to end.",
        key.fingerprint_hex()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "GW1-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FJ089-24CJ2-A9H75-0MJMA-SC5MQ-2YC1H-68SK8-D9P6W-W3JEH-V7GYK-WFR";

    fn link() -> PairLink {
        PairLink::parse(&format!(
            "sap-adt://pair?v=1&p={}&n=Eclipse+Laptop&t={TOKEN}",
            "ab".repeat(32)
        ))
        .unwrap()
    }

    #[test]
    fn the_token_splits_into_secret_and_plugin_key_pin() {
        let (secret, pin) = split_token(&link()).unwrap();
        let first: Vec<u8> = (0..32).collect();
        let second: Vec<u8> = (32..64).collect();
        assert_eq!(secret.as_slice(), first.as_slice());
        assert_eq!(pin.as_slice(), second.as_slice());
    }

    #[test]
    fn the_claim_carries_the_secret_as_hex_and_nothing_else() {
        let request = claim_request(&[0xab; 32]).unwrap();
        let value: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(value["method"], "pair/claim");
        assert_eq!(value["id"], 1);
        assert_eq!(value["params"]["secret"], "ab".repeat(32));
        assert_eq!(value["params"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn only_a_matching_result_counts_as_paired() {
        assert!(accepted(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#));
        assert!(!accepted(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"no"}}"#
        ));
        assert!(!accepted(br#"{"jsonrpc":"2.0","id":2,"result":{}}"#));
        assert!(!accepted(b"nonsense"));
    }
}
