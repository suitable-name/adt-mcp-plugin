//! End-to-end encrypted path (`docs/plan-e2e-envelope.md` §1, §2 and §9): a desktop client
//! pairs with a fake Eclipse plugin through the relay, makes tool calls inside the pinned inner
//! TLS session, and the relay enforces its rules on the envelopes without ever seeing a
//! payload.
//!
//! A second test (`real_plugin`, with `SAP_ADT_INTEROP=1` and a JDK) runs the real Java plugin
//! bridge instead of the fake one, including a rogue relay that tampers with envelopes.

use std::{fs, time::Duration};

use anyhow::{Context, Result, ensure};
use rustls::ClientConfig;
use sap_adt_mcp_server_relay::{https, link, rt, rt::timeout, tunnel_proto};
use serde_json::{Value, json};

use client::Host;
use fake_plugin::{ARGUMENT_MARKER, FakePlugin, RESULT_MARKER, SERVER_NAME};
use setup::{EclipseIdentity, LogBuffer, Relay, desktop_fingerprint, run_client, text, tls};

#[path = "support/e2e_client.rs"]
mod client;
#[path = "support/fake_plugin.rs"]
mod fake_plugin;
#[path = "support/e2e_policy.rs"]
mod policy_file;
#[path = "support/real_plugin.rs"]
mod real_plugin;
#[path = "support/e2e_setup.rs"]
mod setup;

/// What the scenario shares: the relay, the two enrolled desktops and the Eclipse endpoint.
struct World {
    relay: Relay,
    alice: std::path::PathBuf,
    bob: std::path::PathBuf,
    /// The Eclipse's relay identity, for connecting the fake plugin.
    bridge: ClientConfig,
    endpoint: String,
}

/// What the relay tells a stream it ends because the rules changed (`tunnel/hub.rs`
/// `ACCESS_CHANGED`); the client prints it in "Relay request failed: ...".
const RULES_CHANGED: &str = "The access rules changed.";
/// The relay's refusal of a legacy session on an endpoint that requires encryption
/// (`mcp.rs` `REQUIRE_E2E`).
const REQUIRES_E2E: &str = "requires end-to-end encryption";
const PAIR_HINT: &str = "sap-adt-mcp-client pair --link";

fn initialize() -> Value {
    json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}})
}

fn get_source() -> Value {
    json!({"name": "sap_get_source", "arguments": {"objectType": "PROG", "objectName": ARGUMENT_MARKER}})
}

fn answered_with_marker(reply: &Value) -> bool {
    reply["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|text| text.contains(RESULT_MARKER))
}

/// Enroll both desktops and the Eclipse by link, grant the endpoint read-only.
async fn prepare(directory: &std::path::Path) -> Result<World> {
    let relay = Relay::start(&directory.join("pki")).await?;
    let (alice, bob) = (directory.join("alice"), directory.join("bob"));
    relay.enroll_desktop(&alice, "Alice Desktop").await?;
    relay.enroll_desktop(&bob, "Bob Desktop").await?;
    let eclipse: EclipseIdentity = relay.eclipse_identity("Fake Eclipse").await?;
    setup::grant(
        &relay.pki,
        &[desktop_fingerprint(&alice)?, desktop_fingerprint(&bob)?],
        &eclipse.endpoint,
    )?;
    let bridge = tls(&relay.ca, Some((&eclipse.cert_pem, &eclipse.key_pem)))?;
    Ok(World {
        relay,
        alice,
        bob,
        bridge,
        endpoint: eclipse.endpoint,
    })
}

/// `pair --link` with a link the fake plugin minted: success, and the plugin's key is pinned.
async fn pair_alice(world: &World, plugin: &FakePlugin) -> Result<()> {
    let link = plugin.pair_link(&world.endpoint, "Fake Eclipse")?;
    let ran = run_client(&["pair", "--profile", text(&world.alice)?, "--link", &link]).await?;
    ensure!(
        ran.ok && ran.stdout.contains("Paired with Fake Eclipse"),
        "Pairing failed: {}",
        ran.stderr
    );
    ensure!(
        !ran.stdout.contains("sap-adt://") && !ran.stderr.contains("sap-adt://"),
        "The client printed the pairing link."
    );
    let peers: Value = serde_json::from_slice(&fs::read(world.alice.join("peers.json"))?)
        .context("peers.json was not written.")?;
    ensure!(
        peers[&world.endpoint]["key"] == plugin.fingerprint_hex(),
        "peers.json does not pin the plugin's key: {peers}"
    );
    ensure!(plugin.pinned() == 1, "The plugin did not pin the desktop.");
    Ok(())
}

/// `connect` over stdio: initialize, tools/list, an allowed call, a denied call, and an
/// allowed call again on the same session.
async fn use_tunnel(world: &World, plugin: &FakePlugin) -> Result<()> {
    let mut host = Host::start(&world.alice)?;
    let init = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["result"]["serverInfo"]["name"] == SERVER_NAME,
        "initialize was not answered by the plugin: {init}"
    );
    host.notify("notifications/initialized").await?;
    let listing = host.call(2, "tools/list", &json!({})).await?;
    let names: Vec<&str> = listing["result"]["tools"]
        .as_array()
        .context("Missing tool list.")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for expected in [
        "sap_get_source",
        "sap_search_object",
        "sap_set_source",
        "relay_list_endpoints",
    ] {
        ensure!(
            names.contains(&expected),
            "tools/list lacks {expected}: {names:?}"
        );
    }

    let get = get_source();
    let reply = host.call(3, "tools/call", &get).await?;
    ensure!(answered_with_marker(&reply), "Missing result: {reply}");
    ensure!(
        plugin.calls() == [("sap_get_source".to_owned(), get["arguments"].clone())],
        "The plugin did not receive the arguments intact: {:?}",
        plugin.calls()
    );

    // The relay's rules forbid source writes; the stream stays usable.
    let write = json!({"name": "sap_set_source", "arguments": {"objectName": "Z_E2E", "source": "WRITE 1."}});
    let denied = host.call(4, "tools/call", &write).await?;
    ensure!(
        denied["error"]["code"] == -32_001,
        "The write was not denied by the relay: {denied}"
    );
    let again = host.call(5, "tools/call", &get).await?;
    ensure!(
        answered_with_marker(&again),
        "The stream broke after a denial: {again}"
    );
    ensure!(
        plugin.calls().len() == 2,
        "The denied call reached the plugin."
    );
    ensure!(
        plugin
            .calls()
            .iter()
            .all(|(name, _)| name == "sap_get_source"),
        "Unexpected calls reached the plugin."
    );
    ensure!(
        plugin.binding_failures() == 0 && plugin.legacy_calls().is_empty(),
        "The plugin saw a binding failure or a clear-text call."
    );
    let stderr = host.finish().await?;
    ensure!(
        !stderr.contains("not paired"),
        "The client fell back to the unpaired path: {stderr}"
    );
    Ok(())
}

/// A reused pair link is refused, and an unpaired desktop key can send only `pair/claim`.
async fn refusals(world: &World, plugin: &FakePlugin) -> Result<()> {
    let link = plugin.pair_link(&world.endpoint, "Fake Eclipse")?;
    let bob = run_client(&["pair", "--profile", text(&world.bob)?, "--link", &link]).await?;
    ensure!(bob.ok, "Bob could not pair: {}", bob.stderr);
    ensure!(plugin.pinned() == 2, "Bob's key was not pinned.");

    let reused = run_client(&["pair", "--profile", text(&world.alice)?, "--link", &link]).await?;
    ensure!(
        !reused.ok && reused.stderr.contains("already used") && !reused.stdout.contains("Paired"),
        "A reused pairing link was accepted: {}",
        reused.stderr
    );

    // The plugin forgets Bob's key while a new pairing link is outstanding: the handshake
    // passes, but the stream may carry only `pair/claim`.
    plugin.unpin_last();
    let _outstanding = plugin.pair_link(&world.endpoint, "Fake Eclipse")?;
    let mut host = Host::start(&world.bob)?;
    let reply = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        reply["error"].is_object() && reply["result"].is_null(),
        "An unpaired key got an answer: {reply}"
    );
    ensure!(
        plugin.refused_unpaired() == 1 && plugin.calls().len() == 2,
        "The plugin did not refuse the unpaired key."
    );
    host.finish().await?;
    Ok(())
}

/// The relay certificate fingerprints of Alice and Bob, as `policy.json` keys them.
fn fingerprints(world: &World) -> Result<[String; 2]> {
    Ok([
        desktop_fingerprint(&world.alice)?,
        desktop_fingerprint(&world.bob)?,
    ])
}

/// Alice's open session loses `sap_get_source` in the rules: the relay ends her stream, her
/// next call fails, and the client reports why.
async fn rules_end_open_streams(world: &World, plugin: &FakePlugin) -> Result<()> {
    let [alice, bob] = fingerprints(world)?;
    let mut host = Host::start(&world.alice)?;
    let init = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["result"]["serverInfo"]["name"] == SERVER_NAME,
        "initialize was not answered by the plugin: {init}"
    );
    host.notify("notifications/initialized").await?;
    let first = host.call(2, "tools/call", &get_source()).await?;
    ensure!(answered_with_marker(&first), "Missing result: {first}");
    let before = plugin.calls().len();

    // The same session, now with rules that no longer allow the tool.
    let rules = [
        (alice, policy_file::only(&["sap_search_object"])),
        (bob, policy_file::read_only()),
    ];
    policy_file::write(&world.relay.pki, &world.endpoint, &rules, false)?;
    let cut = host.call(3, "tools/call", &get_source()).await?;
    ensure!(
        cut["error"].is_object() && cut["result"].is_null(),
        "A call on the stream whose rules changed was answered: {cut}"
    );
    // The application learns why, and that the tool did not run (the close came before the
    // request was sent).
    let text = cut["error"]["message"].as_str().unwrap_or_default();
    ensure!(
        text.contains(RULES_CHANGED) && text.contains("did not run"),
        "The error does not say what happened: {cut}"
    );
    ensure!(
        plugin.calls().len() == before,
        "The call reached the plugin after the rules changed."
    );
    let stderr = host.finish().await?;
    ensure!(
        stderr.contains(RULES_CHANGED),
        "The client did not report the rules change: {stderr}"
    );
    let closed = world.relay.logs.wait_for(RULES_CHANGED, 1).await?;
    ensure!(
        closed.contains("Stream closed."),
        "The relay did not log the closed stream: {closed}"
    );
    Ok(())
}

/// A new session runs under the new rules: the relay refuses the tool, the plugin never
/// sees it, and a tool that is still allowed works. The original rules are restored.
async fn new_session_follows_new_rules(world: &World, plugin: &FakePlugin) -> Result<()> {
    let before = plugin.calls().len();
    let mut host = Host::start(&world.alice)?;
    let init = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["result"]["serverInfo"]["name"] == SERVER_NAME,
        "initialize was not answered by the plugin: {init}"
    );
    host.notify("notifications/initialized").await?;
    let denied = host.call(2, "tools/call", &get_source()).await?;
    ensure!(
        denied["error"]["code"] == -32_001,
        "The relay did not refuse the tool under the new rules: {denied}"
    );
    ensure!(
        plugin.calls().len() == before,
        "The refused call reached the plugin."
    );
    let search = json!({"name": "sap_search_object", "arguments": {"query": ARGUMENT_MARKER}});
    let found = host.call(3, "tools/call", &search).await?;
    ensure!(
        found["result"].is_object(),
        "The allowed tool failed: {found}"
    );
    ensure!(
        plugin
            .calls()
            .last()
            .is_some_and(|(name, _)| name == "sap_search_object"),
        "The plugin did not receive the allowed call."
    );
    host.finish().await?;
    setup::grant(&world.relay.pki, &fingerprints(world)?, &world.endpoint)
}

/// With encryption required, an unpaired desktop is refused on the legacy path while a
/// paired one keeps working.
async fn required_encryption_refuses_unpaired(world: &World, plugin: &FakePlugin) -> Result<()> {
    let [alice, bob] = fingerprints(world)?;
    let rules = [
        (alice, policy_file::read_only()),
        (bob, policy_file::read_only()),
    ];
    policy_file::write(&world.relay.pki, &world.endpoint, &rules, true)?;
    let ran = run_client(&[
        "unpair",
        "--profile",
        text(&world.bob)?,
        "--endpoint",
        &world.endpoint,
    ])
    .await?;
    ensure!(
        ran.ok && ran.stdout.contains("no longer paired"),
        "Bob could not be unpaired: {}",
        ran.stderr
    );

    let mut unpaired = Host::start(&world.bob)?;
    let refused = unpaired.call(1, "initialize", &initialize()).await?;
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    ensure!(
        refused["result"].is_null()
            && message.contains(REQUIRES_E2E)
            && message.contains(PAIR_HINT),
        "The unpaired desktop was not refused with the pairing hint: {refused}"
    );
    let stderr = unpaired.finish().await?;
    ensure!(
        stderr.contains("not paired"),
        "Bob did not take the unpaired path: {stderr}"
    );

    // Alice is paired: she never touches the legacy path, whatever the flag says.
    let mut paired = Host::start(&world.alice)?;
    let init = paired.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["result"]["serverInfo"]["name"] == SERVER_NAME,
        "The paired desktop was refused: {init}"
    );
    let reply = paired.call(2, "tools/call", &get_source()).await?;
    ensure!(answered_with_marker(&reply), "Missing result: {reply}");
    paired.finish().await?;
    ensure!(
        plugin.legacy_calls().is_empty(),
        "A clear-text call reached the plugin while encryption was required."
    );
    Ok(())
}

/// Switching the requirement off lets the unpaired desktop's legacy session start again:
/// the relay answers `initialize` itself, and `tools/list` goes to the plugin in clear text.
async fn legacy_path_returns(world: &World, plugin: &FakePlugin) -> Result<()> {
    setup::grant(&world.relay.pki, &fingerprints(world)?, &world.endpoint)?;
    let mut host = Host::start(&world.bob)?;
    let init = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["error"].is_null() && init["result"]["serverInfo"]["name"] == "sap-adt-relay",
        "The legacy session did not start after the requirement was lifted: {init}"
    );
    // The relay forwards this one to the plugin's legacy path; the fake plugin refuses it.
    let listing = host.call(2, "tools/list", &json!({})).await?;
    ensure!(listing.is_object(), "No answer on the legacy path.");
    ensure!(
        plugin
            .legacy_calls()
            .iter()
            .any(|method| method == "tools/list"),
        "The legacy call did not reach the plugin: {:?}",
        plugin.legacy_calls()
    );
    host.finish().await?;
    Ok(())
}

/// The relay saw tool names and decisions, never a payload.
fn check_relay_logs(logs: &LogBuffer) -> Result<()> {
    let text = logs.text();
    ensure!(
        !text.contains(ARGUMENT_MARKER) && !text.contains(RESULT_MARKER),
        "A payload reached the relay's logs."
    );
    ensure!(
        !text.contains("GW1-") && !text.contains("sap-adt://"),
        "A link or token reached the relay's logs."
    );
    let line = |tool: &str, decision: &str| {
        text.lines().any(|line| {
            line.contains("Admission.") && line.contains(tool) && line.contains(decision)
        })
    };
    ensure!(
        line("sap_get_source", "admitted"),
        "The relay did not log the admitted sap_get_source call."
    );
    ensure!(
        line("sap_set_source", "denied"),
        "The relay did not log the denied sap_set_source call."
    );
    Ok(())
}

/// A different plugin key answers on the same endpoint: the client refuses, and does not
/// fall back to the relay-readable path.
async fn pin_mismatch(world: &World) -> Result<()> {
    world
        .relay
        .logs
        .wait_for("Eclipse bridge disconnected.", 1)
        .await?;
    let impostor = FakePlugin::connect(world.relay.data, &world.bridge).await?;
    world
        .relay
        .logs
        .wait_for("Eclipse bridge connected.", 2)
        .await?;
    let mut host = Host::start(&world.alice)?;
    let reply = host.call(1, "initialize", &initialize()).await?;
    ensure!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("wrong Eclipse or attacker in the middle")),
        "The client did not refuse the other key: {reply}"
    );
    // No session exists, so nothing can be sent on any path.
    let follow = host.call(2, "tools/call", &get_source()).await?;
    ensure!(follow["error"].is_object(), "A call went through: {follow}");
    let stderr = host.finish().await?;
    ensure!(
        !stderr.contains("not paired") && !stderr.contains(ARGUMENT_MARKER),
        "The client fell back to the unpaired path: {stderr}"
    );
    ensure!(
        impostor.legacy_calls().is_empty() && impostor.calls().is_empty(),
        "The other plugin received a request."
    );
    ensure!(
        !world.relay.logs.text().contains(ARGUMENT_MARKER),
        "A payload reached the relay's logs."
    );
    Ok(())
}

async fn scenario() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let world = prepare(directory.path()).await?;
    let plugin = FakePlugin::connect(world.relay.data, &world.bridge).await?;
    let connected = world
        .relay
        .logs
        .wait_for("Eclipse bridge connected.", 1)
        .await?;
    ensure!(
        connected.contains("e2e=true"),
        "The relay did not see the plugin's e2e support: {connected}"
    );
    pair_alice(&world, &plugin).await?;
    use_tunnel(&world, &plugin).await?;
    refusals(&world, &plugin).await?;
    rules_end_open_streams(&world, &plugin).await?;
    new_session_follows_new_rules(&world, &plugin).await?;
    required_encryption_refuses_unpaired(&world, &plugin).await?;
    legacy_path_returns(&world, &plugin).await?;
    check_relay_logs(&world.relay.logs)?;
    drop(plugin);
    pin_mismatch(&world).await
}

#[test]
fn encrypted_calls_pass_the_relay_without_being_readable() -> Result<()> {
    smol::block_on(async {
        // The whole scenario's state machine is large; keep it on the heap.
        Box::pin(timeout(Duration::from_secs(240), scenario()))
            .await
            .context("End-to-end scenario timed out.")?
    })
}

#[test]
fn the_real_plugin_answers_only_bound_encrypted_calls() -> Result<()> {
    smol::block_on(async {
        Box::pin(timeout(Duration::from_secs(300), real_plugin::scenario()))
            .await
            .context("Real plugin scenario timed out.")?
    })
}
