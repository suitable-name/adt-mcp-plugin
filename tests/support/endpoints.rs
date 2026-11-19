use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, ensure};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Value, json};
use trillium_client::{Method, Status};

use super::{
    DESKTOP, Desktop, Identity, Operator, ResponseExt, Server, connect_bridge, http, matching_log,
    process, read_rpc, send_result, tls,
};
use crate::https::Client;

pub async fn assign_workspaces(operator: &Operator) -> Result<()> {
    for (label, choose_second) in [("Alice Desktop", false), ("Bob Desktop", true)] {
        operator.keys(b"\x1b[Be")?;
        operator.visible("Allowed Endpoints").await?;
        ensure!(
            operator.visible("Desktop ID").await?.contains(label),
            "Wrong desktop in endpoint editor."
        );
        if choose_second {
            operator.keys(b"\x1b[B")?;
        }
        operator.keys(b" s")?;
        operator.visible("Endpoint assignments saved.").await?;
    }
    Ok(())
}

fn fingerprint(identity: &Identity) -> Result<String> {
    let cert = rustls_pemfile::certs(&mut identity.client_cert_pem.as_bytes())
        .next()
        .context("Missing leaf.")??;
    Ok(hex::encode(digest(&SHA256, cert.as_ref())))
}

#[derive(Deserialize)]
struct TestProfile {
    credentials: Identity,
}

fn stored_identity(profile: &Path) -> Result<Identity> {
    let profile: TestProfile =
        serde_json::from_slice(&fs::read(profile.join("credentials.json"))?)?;
    Ok(profile.credentials)
}

async fn select(profile: &Path, endpoint: &str, allowed: bool) -> Result<()> {
    let output = process(DESKTOP)
        .arg(format!("--set-endpoint={endpoint}"))
        .arg("--profile")
        .arg(profile)
        .output()
        .await?;
    ensure!(
        output.status.success() == allowed,
        "Unexpected endpoint selection result: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}})
}

async fn verify_setup_error(profile: &Path, instruction: &str) -> Result<()> {
    let mut desktop = Desktop::connect(profile)?;
    desktop
        .rpc(1, "initialize", &initialize()["params"])
        .await?;
    let reply = desktop.reply(1).await?;
    ensure!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(instruction)),
        "Missing configuration did not explain how to set up the MCP client."
    );
    drop(desktop.stdin);
    desktop.child.status().await?;
    Ok(())
}

async fn catalog(http: &Client, server: &Server) -> Result<Value> {
    http.request(Method::Get, format!("https://{}/endpoints", server.data))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

fn revoke_grants(pki: &Path, desktop: &Identity) -> Result<()> {
    // Simulate an operator committing a live policy change while the clients are connected.
    let path = pki.join("policy.json");
    let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let grants = document["endpoint_grants"]
        .as_object_mut()
        .context("Missing endpoint policy.")?;
    ensure!(
        grants.remove(&fingerprint(desktop)?).is_some(),
        "Missing desktop grant."
    );
    let mut file = tempfile::NamedTempFile::new_in(pki)?;
    file.write_all(&serde_json::to_vec(&document)?)?;
    file.persist(path)?;
    Ok(())
}

/// The desktop client lists only the endpoints assigned to its own desktop.
async fn check_listing(alice_profile: &Path, alice_id: &str, bob_id: &str) -> Result<()> {
    let listing = process(DESKTOP)
        .args(["endpoints", "--profile"])
        .arg(alice_profile)
        .output()
        .await?;
    let stdout = String::from_utf8(listing.stdout)?;
    ensure!(
        listing.status.success() && stdout.contains(alice_id) && !stdout.contains(bob_id),
        "Client did not list only Alice's assigned endpoint."
    );
    Ok(())
}

/// Bob can neither open Alice's endpoint nor reuse Alice's MCP session ID.
async fn check_cross_desktop_access(
    alice_http: &Client,
    bob_http: &Client,
    mcp: &str,
    alice_id: &str,
    bob_id: &str,
) -> Result<()> {
    let denied = bob_http
        .post(mcp)
        .header("x-sap-adt-endpoint", alice_id.to_owned())
        .json(&initialize())
        .send()
        .await?;
    assert_eq!(denied.status(), Status::Forbidden);
    let initialized = alice_http
        .post(mcp)
        .header("x-sap-adt-endpoint", alice_id.to_owned())
        .json(&initialize())
        .send()
        .await?
        .error_for_status()?;
    let session = initialized
        .header("mcp-session-id")
        .context("Missing Alice's session ID.")?
        .to_owned();
    let ping = json!({"jsonrpc":"2.0","method":"ping","id":2});
    let stolen = bob_http
        .post(mcp)
        .header("x-sap-adt-endpoint", bob_id.to_owned())
        .header("mcp-session-id", session)
        .json(&ping)
        .send()
        .await?;
    assert_eq!(stolen.status(), Status::NotFound);
    Ok(())
}

pub async fn exercise_isolation(
    server: &mut Server,
    ca: &[u8],
    pki: &Path,
    alice: (&Path, &Identity),
    bob: (&Path, &Identity),
) -> Result<()> {
    let (alice_profile, alice_eclipse) = alice;
    let (bob_profile, bob_eclipse) = bob;
    let alice_id = fingerprint(alice_eclipse)?;
    let bob_id = fingerprint(bob_eclipse)?;
    let bob_desktop = stored_identity(bob_profile)?;
    let alice_http = http(tls(ca, Some(&stored_identity(alice_profile)?))?);
    let bob_http = http(tls(ca, Some(&bob_desktop))?);
    let mcp = format!("https://{}/mcp", server.data);
    assert_eq!(
        catalog(&alice_http, server).await?,
        json!({"endpoints":[{"id":alice_id,"label":"Alice Eclipse","online":false}]})
    );
    verify_setup_error(&alice_profile.join("missing-profile"), "enroll").await?;
    verify_setup_error(alice_profile, "--set-endpoint").await?;
    select(alice_profile, &alice_id, true).await?;
    select(alice_profile, &bob_id, false).await?;
    select(bob_profile, "Bob Eclipse", true).await?;
    let offline = alice_http
        .post(&mcp)
        .header("x-sap-adt-endpoint", alice_id.clone())
        .json(&initialize())
        .send()
        .await?;
    assert_eq!(offline.status(), Status::ServiceUnavailable);

    let alice_bridge = connect_bridge(&tls(ca, Some(alice_eclipse))?, server).await?;
    let mut bob_bridge = connect_bridge(&tls(ca, Some(bob_eclipse))?, server).await?;
    assert_eq!(
        catalog(&bob_http, server).await?,
        json!({"endpoints":[{"id":bob_id,"label":"Bob Eclipse","online":true}]})
    );
    check_listing(alice_profile, &alice_id, &bob_id).await?;
    check_cross_desktop_access(&alice_http, &bob_http, &mcp, &alice_id, &bob_id).await?;

    let mut desktop = Desktop::connect(bob_profile)?;
    desktop
        .rpc(1, "initialize", &initialize()["params"])
        .await?;
    assert_eq!(
        desktop.reply(1).await?["result"]["_meta"]["com.sap.adt.mcp/endpoint"],
        bob_id
    );
    desktop
        .rpc(
            2,
            "tools/call",
            &json!({"name":"relay_list_endpoints","arguments":{}}),
        )
        .await?;
    let listed = desktop.reply(2).await?;
    assert_eq!(listed["result"]["structuredContent"]["selected"], bob_id);
    assert_eq!(
        listed["result"]["structuredContent"]["endpoints"],
        catalog(&bob_http, server).await?["endpoints"]
    );

    drop(alice_bridge);
    matching_log(&mut server.logs, "Eclipse bridge disconnected.").await?;
    let query = json!({"name":"sap_search_object","arguments":{"query":"Z_BOB"}});
    desktop.rpc(3, "tools/call", &query).await?;
    let call = read_rpc(&mut bob_bridge).await?;
    assert_eq!(call["params"]["arguments"], query["arguments"]);
    let result = json!({"content":[{"type":"text","text":"Bob's workspace"}]});
    send_result(&mut bob_bridge, &call, &result).await?;
    assert_eq!(desktop.reply(3).await?["result"], result);
    revoke_grants(pki, &bob_desktop)?;
    desktop.rpc(4, "tools/call", &query).await?;
    ensure!(
        desktop.reply(4).await?["error"].is_object(),
        "Revoked endpoint grant permitted a tool call."
    );
    assert_eq!(catalog(&bob_http, server).await?, json!({"endpoints":[]}));
    drop(desktop.stdin);
    desktop.child.status().await?;
    drop(bob_bridge);
    matching_log(&mut server.logs, "Eclipse bridge disconnected.").await?;
    Ok(())
}
