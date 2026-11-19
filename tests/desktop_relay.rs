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

use rt::timeout;

#[path = "../src/rt.rs"]
mod rt;
// https.rs is shared with the client binary; the tests use only a subset of it.
#[path = "support/endpoints.rs"]
mod endpoints;
#[path = "../src/https.rs"]
#[allow(dead_code)]
mod https;
#[path = "support/operator.rs"]
mod operator;
#[path = "support/terminal.rs"]
mod terminal;
use operator::Operator;

#[cfg(any(unix, windows))]
#[path = "support/headless_console.rs"]
mod headless_console;

const SERVER: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-server-relay");
const DESKTOP: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-client");
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

    async fn enroll_desktop(&self, profile: &Path, label: &str, wrong_ca: bool) -> Result<()> {
        let mut child = process(DESKTOP)
            .args([
                "enroll",
                "--server",
                &format!("https://{}", self.data),
                "--enrollment",
                &format!("https://{}", self.enrollment),
                "--label",
                label,
                "--profile",
            ])
            .arg(profile)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut logs = BufReader::new(
            child
                .stderr
                .take()
                .context("Missing desktop enrollment log.")?,
        )
        .lines();
        let client_id = matching_log(&mut logs, "Enrollment request ID: ").await?;
        let id = client_id
            .strip_prefix("Enrollment request ID: ")
            .context("Missing desktop request ID.")?;
        ensure!(id.len() == 32, "Invalid desktop request ID.");
        let mut token = self.operator.approve(id).await?;
        ensure!(
            token.is_ascii() && token.len() > 100 && token.starts_with("GW1-"),
            "Malformed operator token."
        );
        if wrong_ca {
            // Alter a fingerprint symbol after the secret and before the final padding.
            let index = token[90..]
                .bytes()
                .position(|b| b != b'-')
                .context("Missing fingerprint symbol.")?
                + 90;
            let replacement = if token.as_bytes()[index] == b'0' {
                "1"
            } else {
                "0"
            };
            token.replace_range(index..=index, replacement);
        }
        input(
            child
                .stdin
                .as_mut()
                .context("Missing desktop token input.")?,
            &token,
        )
        .await?;
        if wrong_ca {
            matching_log(&mut logs, "different CA").await?;
            ensure!(
                !child.status().await?.success() && !profile.exists(),
                "Rejected identity was persisted."
            );
        } else {
            matching_log(&mut logs, "Client profile saved.").await?;
            ensure!(
                child.status().await?.success(),
                "Desktop enrollment failed."
            );
        }
        Ok(())
    }

    async fn eclipse_identity(&self, http: &https::Client, label: &str) -> Result<Identity> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let body = json!({"id": id, "label": label, "role": "eclipse"});
        let request = http
            .post(format!("https://{}/request", self.enrollment))
            .json(&body);
        // The task is cancelled if dropped, so it stays bound until awaited.
        let submit = rt::spawn(async move { request.send().await });
        let token = self.operator.approve(&id).await?;
        let approval: Value = submit.await?.error_for_status()?.json().await?;
        assert_eq!(approval["id"], id);
        ensure!(
            approval["ca_pem"].is_string() && approval.get("token").is_none(),
            "Invalid public approval."
        );
        let grant = json!({"token":token});
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
    send_result(&mut ws, &hello, &json!({"policyVersion":1})).await?;
    matching_log(&mut server.logs, "Eclipse bridge connected.").await?;
    Ok(ws)
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
    assert_eq!(call["params"], forwarded);
    let result = json!({"content":[{"type":"text","text":"REPORT Z_EXAMPLE."}],"isError":false});
    send_result(&mut ws, &call, &result).await?;
    assert_eq!(desk.reply(3).await?["result"], result);

    desk.rpc(4, "tools/call", &params).await?;
    assert_eq!(read_rpc(&mut ws).await?["params"], forwarded);
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

async fn scenario() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pki = directory.path().join("pki");
    let profile = directory.path().join("desktop");
    let bob = directory.path().join("bob");
    let registration = Registration::start(&pki).await?;
    let ca = fs::read(pki.join("ca.pem"))?;
    let bootstrap = http(tls(&ca, None)?);
    let request =
        json!({"id":"11111111111111111111111111111111","role":"desktop","label":"Closed"});
    let denied = bootstrap
        .post(format!("https://{}/request", registration.enrollment))
        .json(&request)
        .send()
        .await?;
    assert_eq!(denied.status(), Status::Forbidden);
    assert_eq!(denied.text().await?, "registration-closed");
    // The operator sees that a request was turned away while closed.
    registration
        .operator
        .visible("refused while closed")
        .await?;
    let mcp = format!("https://{}/mcp", registration.data);
    assert!(bootstrap.post(&mcp).json(&json!({})).send().await.is_err());
    registration.operator.keys(b"o")?;
    registration.operator.visible("Enrollment · Open").await?;
    registration
        .enroll_desktop(&directory.path().join("bad-pin"), "Bad Pin", true)
        .await?;
    registration
        .enroll_desktop(&profile, "Alice Desktop", false)
        .await?;
    registration
        .enroll_desktop(&bob, "Bob Desktop", false)
        .await?;
    let eclipse = registration
        .eclipse_identity(&bootstrap, "Alice Eclipse")
        .await?;
    let bob_eclipse = registration
        .eclipse_identity(&bootstrap, "Bob Eclipse")
        .await?;
    registration.operator.keys(b"\t\t")?;
    registration.operator.visible("Global Rules").await?;
    registration.operator.keys(b"\rp")?;
    registration
        .operator
        .visible("Separate package patterns")
        .await?;
    registration.operator.keys(b"\x15Z_TEST*\rs")?;
    registration.operator.visible("Access rules saved.").await?;
    endpoints::assign_workspaces(&registration.operator).await?;
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
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut logs = BufReader::new(child.stderr.take().context("Missing headless logs.")?).lines();
    matching_log(&mut logs, "Headless mode.").await?;
    ensure!(
        TcpStream::connect(enrollment).await.is_err(),
        "Headless enrollment socket is open."
    );
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
