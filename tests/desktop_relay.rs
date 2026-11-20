use std::{fs, net::SocketAddr, path::Path, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use async_tungstenite::{WebSocketStream, client_async, tungstenite::Message};
use futures_rustls::{TlsConnector, client::TlsStream};
use futures_util::StreamExt;
use rustls::{ClientConfig, RootCertStore, crypto::ring, pki_types::ServerName};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use smol::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use trillium_client::Status;

use sap_adt_mcp_server_relay::{https, rt, rt::timeout};

#[path = "support/endpoints.rs"]
mod endpoints;
#[path = "support/headless_issue.rs"]
mod headless_issue;
#[path = "support/operator.rs"]
mod operator;
#[path = "support/rogue.rs"]
mod rogue;
#[path = "support/terminal.rs"]
mod terminal;
use operator::Operator;

const SERVER: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-server-relay");
const DESKTOP: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-client");
/// Link lifetime of the headless server (the relay only accepts a value below 10 minutes).
const LINK_TTL_MS: u64 = 5000;
type Logs = Lines<BufReader<ChildStderr>>;
type Socket = WebSocketStream<TlsStream<TcpStream>>;

fn process(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .kill_on_drop(true)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*");
    command
}

async fn matching_log(logs: &mut Logs, marker: &'static str) -> Result<String> {
    timeout(Duration::from_secs(15), async {
        while let Some(line) = logs.next().await {
            let line = line?;
            if line.contains(marker) {
                return Ok(line);
            }
        }
        anyhow::bail!("Process exited before logging {marker:?}.");
    })
    .await
    .with_context(|| format!("Process timed out before logging {marker:?}."))?
}

async fn input(stdin: &mut ChildStdin, line: &str) -> Result<()> {
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

struct Server {
    child: Child,
    logs: Logs,
    data: SocketAddr,
}

struct Registration {
    operator: Operator,
    data: SocketAddr,
    enrollment: SocketAddr,
}

fn address(screen: &str, marker: &str) -> Result<SocketAddr> {
    let (_, tail) = screen
        .split_once(marker)
        .context("Missing bound address.")?;
    let port = tail
        .trim_start()
        .split(|c: char| !c.is_ascii_digit() && c != '.' && c != ':')
        .next()
        .context("Missing port.")?;
    Ok(port.trim_end_matches('.').parse()?)
}

impl Registration {
    async fn start(pki: &Path) -> Result<Self> {
        let status = process(SERVER)
            .args(["init", "--dns", "127.0.0.1", "--pki"])
            .arg(pki)
            .status()
            .await?;
        ensure!(status.success(), "Server initialization failed.");
        let operator = Operator::start(SERVER, pki)?;
        operator.visible("Enrollment").await?;
        operator.keys(b"\t\t\t")?;
        operator.visible("No Eclipse bridge is connected.").await?;
        operator.keys(b"\t")?;
        let screen = operator.visible("Enrollment listening on").await?;
        let data = address(&screen, "mutual TLS on")?;
        let enrollment = address(&screen, "Enrollment listening on")?;
        operator.keys(b"\t")?;
        Ok(Self {
            operator,
            data,
            enrollment,
        })
    }

    /// Enroll a desktop with a link the TUI minted, and expect success.
    async fn enroll_desktop(&self, profile: &Path, label: &str) -> Result<()> {
        let link = self.operator.new_link(false, label).await?;
        let (ok, stderr) = enroll(&link, profile).await?;
        ensure!(
            ok && stderr.contains("Client profile saved."),
            "Desktop enrollment failed: {stderr}"
        );
        // A link works once.
        let again = profile.with_extension("again");
        let (ok, stderr) = enroll(&link, &again).await?;
        ensure!(
            !ok && stderr.contains("already used, expired or cancelled") && !again.exists(),
            "A link was accepted twice."
        );
        Ok(())
    }

    /// An Eclipse identity is claimed straight from the link's token, as the plugin does.
    async fn eclipse_identity(&self, http: &https::Client, label: &str) -> Result<Identity> {
        let link = self.operator.new_link(true, label).await?;
        let token = link
            .split_once("&t=")
            .map(|(_, token)| token)
            .context("The link has no token.")?;
        let grant = json!({"token": token});
        let claim = format!("https://{}/claim", self.enrollment);
        let identity = http
            .post(&claim)
            .json(&grant)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(
            http.post(claim).json(&grant).send().await?.status(),
            Status::Forbidden
        );
        Ok(identity)
    }

    /// Links that must never enroll anyone: a cancelled one, a damaged one, and one that
    /// points at a relay with another CA (the secret must not even be sent there).
    async fn refused_links(&self, scratch: &Path) -> Result<()> {
        let cancelled = self.operator.new_link(false, "Cancel Me").await?;
        self.operator.cancel_first_link().await?;
        let (ok, stderr) = enroll(&cancelled, &scratch.join("cancelled")).await?;
        ensure!(
            !ok && stderr.contains("already used, expired or cancelled")
                && !scratch.join("cancelled").exists(),
            "A cancelled link was accepted."
        );
        let (ok, stderr) = enroll(&cancelled.replace("v=1", "v=2"), &scratch.join("newer")).await?;
        ensure!(
            !ok && stderr.contains("newer version"),
            "A link from the future was not diagnosed."
        );
        let (ok, stderr) = enroll(
            &cancelled.replace("r=desktop", "r=eclipse"),
            &scratch.join("wrong-role"),
        )
        .await?;
        ensure!(
            !ok && stderr.contains("Eclipse"),
            "An Eclipse link enrolled a desktop."
        );

        let link = self.operator.new_link(false, "Pin Check").await?;
        let (rogue, handshake) = rogue::start().await?;
        let swapped = link.replace(&format!("&e={}&", self.enrollment), &format!("&e={rogue}&"));
        ensure!(
            swapped != link,
            "The link did not name the enrollment address."
        );
        let (ok, stderr) = enroll(&swapped, &scratch.join("rogue")).await?;
        ensure!(
            !ok && stderr.contains("attacker in the middle") && !scratch.join("rogue").exists(),
            "A relay with another CA was trusted: {stderr}"
        );
        ensure!(
            !timeout(Duration::from_secs(15), handshake).await?,
            "The client completed a handshake with a relay of another CA."
        );
        // The failed attempt did not use up the link.
        let profile = scratch.join("pin-check");
        let (ok, stderr) = enroll(&link, &profile).await?;
        ensure!(
            ok && stderr.contains("Client profile saved."),
            "The pin check consumed the link: {stderr}"
        );
        Ok(())
    }
}

/// Run `enroll --link`: whether it succeeded, and what it wrote to stderr (never the link).
async fn enroll(link: &str, profile: &Path) -> Result<(bool, String)> {
    let output = process(DESKTOP)
        .args(["enroll", "--link", link, "--profile"])
        .arg(profile)
        .stdin(Stdio::null())
        .output()
        .await?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    ensure!(
        !stderr.contains("GW1-") && !stderr.contains("sap-adt://"),
        "The client wrote the link or token to stderr."
    );
    Ok((output.status.success(), stderr))
}

#[derive(Deserialize)]
struct Identity {
    client_cert_pem: String,
    client_key_pem: String,
}

fn tls(mut ca: &[u8], identity: Option<&Identity>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(
        rustls_pemfile::certs(&mut ca)
            .next()
            .context("Missing test CA.")??,
    )?;
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots);
    match identity {
        Some(identity) => {
            let certs = rustls_pemfile::certs(&mut identity.client_cert_pem.as_bytes())
                .collect::<std::io::Result<Vec<_>>>()?;
            let key = rustls_pemfile::private_key(&mut identity.client_key_pem.as_bytes())?
                .context("Missing key.")?;
            Ok(config.with_client_auth_cert(certs, key)?)
        }
        None => Ok(config.with_no_client_auth()),
    }
}

fn http(config: ClientConfig) -> https::Client {
    https::Client::new(config)
}

/// The few `reqwest::Response` conveniences the tests rely on.
trait ResponseExt: Sized {
    fn error_for_status(self) -> Result<Self>;
    async fn text(self) -> Result<String>;
    async fn json<T: DeserializeOwned>(self) -> Result<T>;
}

/// Largest response body the tests accept.
const BODY_LIMIT: usize = 4 * 1024 * 1024;

impl ResponseExt for https::Response {
    fn error_for_status(self) -> Result<Self> {
        let status = self.status();
        ensure!(
            !status.is_client_error() && !status.is_server_error(),
            "HTTP status {status}."
        );
        Ok(self)
    }

    async fn text(self) -> Result<String> {
        let bytes = self.bytes(BODY_LIMIT).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    async fn json<T: DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes(BODY_LIMIT).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

async fn connect_bridge(config: &ClientConfig, server: &mut Server) -> Result<Socket> {
    // async-io marks the sockets it connects as inheritable on Windows, so desktop
    // processes spawned later would hold this connection open after the test drops
    // it. `std` sockets are not inheritable.
    let address = server.data;
    let stream =
        TcpStream::try_from(smol::unblock(move || std::net::TcpStream::connect(address)).await?)?;
    let connector = TlsConnector::from(Arc::new(config.clone()));
    let tls = connector
        .connect(ServerName::from(server.data.ip()), stream)
        .await?;
    let (mut ws, _) = client_async(format!("wss://{}/bridge", server.data), tls).await?;
    let hello = read_rpc(&mut ws).await?;
    assert_eq!(hello["method"], "relay/hello");
    ensure!(
        hello["params"]["policyVersion"] == 2,
        "The relay did not announce policy version 2."
    );
    send_result(&mut ws, &hello, &json!({"policyVersion":2})).await?;
    matching_log(&mut server.logs, "Eclipse bridge connected.").await?;
    Ok(ws)
}

/// A forwarded tool call without its `relayAllowedTools`, after checking that list
/// against the access rules the scenario set (source writes are not allowed).
fn without_allowed_tools(mut params: Value) -> Result<Value> {
    let allowed = params
        .as_object_mut()
        .and_then(|fields| fields.remove("relayAllowedTools"))
        .context("The relay sent no relayAllowedTools.")?;
    let names: Vec<_> = allowed
        .as_array()
        .context("relayAllowedTools is not a list.")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    ensure!(
        names.contains(&"sap_get_source") && !names.contains(&"sap_set_source"),
        "relayAllowedTools does not match the access rules."
    );
    Ok(params)
}

async fn read_rpc(ws: &mut Socket) -> Result<Value> {
    let frame = ws.next().await.context("Missing bridge request.")??;
    Ok(serde_json::from_str(frame.to_text()?)?)
}

async fn send_result(ws: &mut Socket, request: &Value, result: &Value) -> Result<()> {
    let reply = json!({"jsonrpc":"2.0", "id":request["id"], "result":result});
    ws.send(Message::Text(reply.to_string().into())).await?;
    Ok(())
}

struct Desktop {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl Desktop {
    fn connect(profile: &Path) -> Result<Self> {
        let mut child = process(DESKTOP)
            .args(["connect", "--profile"])
            .arg(profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().context("Missing MCP input.")?;
        let stdout = BufReader::new(child.stdout.take().context("Missing MCP output.")?).lines();
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    async fn rpc(&mut self, id: u64, method: &str, params: &Value) -> Result<()> {
        input(
            &mut self.stdin,
            &json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}).to_string(),
        )
        .await
    }

    async fn reply(&mut self, id: u64) -> Result<Value> {
        let line = self
            .stdout
            .next()
            .await
            .context("Missing desktop response.")??;
        let reply: Value = serde_json::from_str(&line)?;
        assert_eq!(reply["id"], id);
        Ok(reply)
    }
}

async fn roundtrip(profile: &Path, server: &mut Server, config: &ClientConfig) -> Result<()> {
    let mut ws = connect_bridge(config, server).await?;
    let mut desk = Desktop::connect(profile)?;
    desk.rpc(1, "initialize", &json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}})).await?;
    assert_eq!(
        desk.reply(1).await?["result"]["protocolVersion"],
        "2025-11-25"
    );
    input(
        &mut desk.stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await?;
    desk.rpc(2, "tools/list", &json!({})).await?;
    let listing = read_rpc(&mut ws).await?;
    assert_eq!(listing["method"], "tools/list");
    let tools = json!({"tools":[{"name":"sap_get_source","inputSchema":{"type":"object"}},
        {"name":"sap_set_source","inputSchema":{"type":"object"}}]});
    send_result(&mut ws, &listing, &tools).await?;
    let reply = desk.reply(2).await?;
    let visible = reply["result"]["tools"]
        .as_array()
        .context("Missing tool list.")?;
    assert!(visible.contains(&tools["tools"][0]));
    assert!(
        visible
            .iter()
            .any(|tool| tool["name"] == "relay_list_endpoints")
    );
    assert!(!visible.iter().any(|tool| tool["name"] == "sap_set_source"));

    desk.rpc(
        6,
        "tools/call",
        &json!({"name":"sap_set_source","arguments":{}}),
    )
    .await?;
    assert_eq!(desk.reply(6).await?["error"]["code"], -32_001);
    let params =
        json!({"name":"sap_get_source","arguments":{"objectType":"PROG","objectName":"Z_EXAMPLE"}});
    let mut forwarded = params.clone();
    forwarded["relayPackageScopes"] = json!([["Z_TEST*"]]);
    desk.rpc(3, "tools/call", &params).await?;
    let call = read_rpc(&mut ws).await?;
    assert_eq!(without_allowed_tools(call["params"].clone())?, forwarded);
    let result = json!({"content":[{"type":"text","text":"REPORT Z_EXAMPLE."}],"isError":false});
    send_result(&mut ws, &call, &result).await?;
    assert_eq!(desk.reply(3).await?["result"], result);

    desk.rpc(4, "tools/call", &params).await?;
    assert_eq!(
        without_allowed_tools(read_rpc(&mut ws).await?["params"].clone())?,
        forwarded
    );
    // Losing the socket after dispatch leaves the outcome indeterminate.
    drop(ws);
    let failed = desk.reply(4).await?;
    ensure!(
        failed["error"]["message"]
            .as_str()
            .is_some_and(|text| text.contains("outcome is unknown")),
        "A lost tool reply did not report an unknown SAP outcome."
    );
    matching_log(&mut server.logs, "Eclipse bridge disconnected.").await?;
    let _replacement = connect_bridge(config, server).await?;
    desk.rpc(5, "tools/call", &params).await?;
    assert!(desk.reply(5).await?["error"]["message"].is_string());
    drop(desk.stdin);
    ensure!(
        desk.child.status().await?.success(),
        "Desktop failed to shut down."
    );
    Ok(())
}

/// The Enrollment tab lists what was enrolled, the log never holds a link or token, and the
/// global rules and workspace grants are set through the TUI.
async fn operate(operator: &Operator) -> Result<()> {
    operator.visible("Alice Desktop  desktop").await?;
    operator.keys(b"\t\t\t\t")?;
    let logs = operator
        .visible("Alice Desktop (desktop) enrolled from")
        .await?;
    ensure!(
        !logs.contains("GW1-") && !logs.contains("sap-adt://"),
        "A link or token reached the relay log."
    );
    operator.keys(b"\t")?;
    operator.keys(b"\t\t")?;
    operator.visible("Global Rules").await?;
    operator.keys(b"\rp")?;
    operator.visible("Separate package patterns").await?;
    operator.keys(b"\x15Z_TEST*\rs")?;
    operator.visible("Access rules saved.").await?;
    endpoints::assign_workspaces(operator).await?;
    Ok(())
}

async fn scenario() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pki = directory.path().join("pki");
    let profile = directory.path().join("desktop");
    let bob = directory.path().join("bob");
    let registration = Registration::start(&pki).await?;
    let ca = fs::read(pki.join("ca.pem"))?;
    let bootstrap = http(tls(&ca, None)?);
    // The request endpoint of the old approval flow is gone.
    let request = json!({"id":"11111111111111111111111111111111","role":"desktop","label":"Old"});
    let gone = bootstrap
        .post(format!("https://{}/request", registration.enrollment))
        .json(&request)
        .send()
        .await?;
    assert_eq!(gone.status(), Status::NotFound);
    assert_eq!(gone.text().await?, "");
    let mcp = format!("https://{}/mcp", registration.data);
    assert!(bootstrap.post(&mcp).json(&json!({})).send().await.is_err());
    registration.refused_links(directory.path()).await?;
    registration
        .enroll_desktop(&profile, "Alice Desktop")
        .await?;
    registration.enroll_desktop(&bob, "Bob Desktop").await?;
    let eclipse = registration
        .eclipse_identity(&bootstrap, "Alice Eclipse")
        .await?;
    let bob_eclipse = registration
        .eclipse_identity(&bootstrap, "Bob Eclipse")
        .await?;
    operate(&registration.operator).await?;
    let data = registration.data;
    let enrollment = registration.enrollment;
    drop(registration);
    let mut child = process(SERVER)
        .args([
            "serve",
            "--headless",
            "--listen",
            &data.to_string(),
            "--enrollment-listen",
            &enrollment.to_string(),
            "--pki",
        ])
        .arg(&pki)
        // Links of this server live a few seconds, so that expiry can be tested.
        .env("SAP_ADT_RELAY_TEST_LINK_TTL_MS", LINK_TTL_MS.to_string())
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut logs = BufReader::new(child.stderr.take().context("Missing headless logs.")?).lines();
    matching_log(&mut logs, "Headless mode.").await?;
    matching_log(&mut logs, "Enrollment listening on").await?;
    headless_issue::exercise(
        &pki,
        enrollment,
        directory.path(),
        &ca,
        Duration::from_millis(LINK_TTL_MS),
    )
    .await?;
    let mut server = Server { child, logs, data };
    let config = tls(&ca, Some(&eclipse))?;
    let denied = http(config.clone())
        .post(mcp)
        .json(&json!({}))
        .send()
        .await?;
    assert_eq!(denied.status(), Status::Forbidden);
    endpoints::exercise_isolation(
        &mut server,
        &ca,
        &pki,
        (&profile, &eclipse),
        (&bob, &bob_eclipse),
    )
    .await?;
    roundtrip(&profile, &mut server, &config).await?;
    server.child.kill()?;
    Ok(())
}

#[test]
fn enrolled_desktop_reaches_only_its_live_eclipse_session() -> Result<()> {
    smol::block_on(async {
        // The whole scenario's state machine is large; keep it on the heap.
        Box::pin(timeout(Duration::from_secs(180), scenario()))
            .await
            .context("Desktop relay scenario timed out.")?
    })
}
