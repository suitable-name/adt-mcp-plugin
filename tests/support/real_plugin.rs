//! The real Java plugin bridge against the real relay and the real desktop client, plus a rogue
//! relay (`docs/plan-e2e-envelope.md` §1, §2, §7, §9 and the threat model).
//!
//! `tests/PluginHost.java` runs the plugin's own `RelayBridge`, stream handler and pairing
//! headless (no Eclipse), with a fake SAP client. The scenario needs a JDK in `JAVA_HOME` and
//! runs only with `SAP_ADT_INTEROP=1`; otherwise it returns at once.
//!
//! The crate root must provide the modules `setup` (`support/e2e_setup.rs`) and `client`
//! (`support/e2e_client.rs`).

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command as Blocking, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use async_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
use futures_rustls::{TlsAcceptor, server::TlsStream};
use futures_util::StreamExt;
use rustls::ServerConfig;
use sap_adt_mcp_server_relay::{
    inner_tls::InnerTls,
    keys::InnerKey,
    link::PairLink,
    rt, token,
    tunnel_proto::{
        Class, Control, Envelope, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, RelayPolicy, decode_data,
        encode_data_chunks,
    },
};
use serde_json::{Value, json};
use smol::{
    Timer,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin},
};

use crate::{
    client::Host,
    setup::{EclipseIdentity, LogBuffer, Relay, desktop_fingerprint, process, run_client, text},
};

/// Placed in the arguments of a tool call; must never reach the relay's logs.
const ARGUMENT_MARKER: &str = "REAL-E2E-ARG-5d1e";
/// What the fake SAP in `PluginHost` returns; must never reach the relay's logs.
const RESULT_MARKER: &str = "REAL-E2E-RESULT-a9c4";
/// The Eclipse's label; the relay puts it into the certificate.
const LABEL: &str = "Real Eclipse";
const HOST_CLASS: &str = "com.sap.adt.mcp.server.PluginHost";
/// What the plugin reports in `initialize`.
const SERVER_NAME: &str = "sap-adt-eclipse";
/// The plugin's refusal of a clear-text call.
const REFUSED_TEXT: &str = "accepts only end-to-end encrypted calls";

type Socket = WebSocketStream<TlsStream<TcpStream>>;

// ------------------------------------------------------------------ Java

/// The JDK tool `name` from `JAVA_HOME` (`.exe` on Windows).
fn jdk_tool(name: &str) -> Result<PathBuf> {
    let home = std::env::var_os("JAVA_HOME").ok_or_else(|| anyhow!("JAVA_HOME is not set."))?;
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    Ok(Path::new(&home).join("bin").join(file))
}

/// The compiled harness and the paths its class path needs.
struct Java {
    classes: tempfile::TempDir,
    gson: PathBuf,
    plugin: PathBuf,
}

impl Java {
    /// Compiles `PluginHost.java` and the plugin classes it uses into a temporary directory.
    fn compile() -> Result<Self> {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("java-plugin/sap-adt-mcp-server");
        let plugin = project.join("com.sap.adt.mcp.server.plugin");
        let gson = fs::read_dir(&plugin)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("gson-"))
                    && path
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("jar"))
            })
            .ok_or_else(|| anyhow!("No gson jar in the plugin directory."))?;
        let classes = tempfile::tempdir()?;
        let status = Blocking::new(jdk_tool("javac")?)
            .args(["--release", "17", "-encoding", "UTF-8", "-cp"])
            .arg(&gson)
            .arg("-sourcepath")
            .arg(plugin.join("src"))
            .arg("-d")
            .arg(classes.path())
            .arg(project.join("tests/PluginHost.java"))
            .status()
            .context("Could not start javac.")?;
        ensure!(status.success(), "javac failed: {status}");
        Ok(Self {
            classes,
            gson,
            plugin,
        })
    }

    /// The harness classes, gson, and the plugin directory (its `resources/tools.json`).
    fn class_path(&self) -> Result<std::ffi::OsString> {
        Ok(std::env::join_paths([
            self.classes.path(),
            self.gson.as_path(),
            self.plugin.as_path(),
        ])?)
    }
}

/// The relay identity file `RelayIdentity.fromProfile` reads, pointing at `bridge`.
fn write_profile(
    directory: &Path,
    name: &str,
    bridge: SocketAddr,
    ca: &[u8],
    eclipse: &EclipseIdentity,
) -> Result<PathBuf> {
    let path = directory.join(name);
    let profile = json!({
        "bridge": format!("wss://{bridge}/bridge"),
        "ca_pem": String::from_utf8(ca.to_vec())?,
        "client_cert_pem": eclipse.cert_pem,
        "client_key_pem": eclipse.key_pem,
        "label": LABEL,
    });
    fs::write(&path, serde_json::to_vec(&profile)?)?;
    Ok(path)
}

/// A running `PluginHost`. The Java process is killed when this is dropped.
struct PluginProc {
    child: Child,
    stdin: ChildStdin,
    logs: LogBuffer,
}

impl PluginProc {
    /// Starts the plugin for `profile` and waits until its bridge connected.
    async fn start(java: &Java, profile: &Path, allow_unencrypted: bool) -> Result<Self> {
        let mut child = process(text(&jdk_tool("java")?)?)
            .args(["-ea", "-cp"])
            .arg(java.class_path()?)
            .arg(HOST_CLASS)
            .arg(profile)
            .arg(format!("allowUnencrypted={allow_unencrypted}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Could not start java.")?;
        let stdin = child.stdin.take().context("Missing plugin input.")?;
        let logs = LogBuffer::capture(child.stdout.take().context("Missing plugin output.")?);
        let host = Self { child, stdin, logs };
        host.logs.wait_for("\"event\":\"connected\"", 1).await?;
        Ok(host)
    }

    async fn command(&mut self, line: &str) -> Result<()> {
        self.stdin.write_all(format!("{line}\n").as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Mints a pairing link through the plugin's real `Pairing`. The link is a secret.
    async fn pair_link(&mut self) -> Result<String> {
        let before = self
            .logs
            .text()
            .lines()
            .filter(|line| line.starts_with("PAIR "))
            .count();
        self.command("pair").await?;
        let line = self
            .logs
            .wait_for("PAIR sap-adt://pair?", before + 1)
            .await?;
        line.strip_prefix("PAIR ")
            .map(str::to_owned)
            .context("The plugin printed no link.")
    }

    /// Asks the plugin to exit and waits for it.
    async fn quit(mut self) -> Result<()> {
        self.command("quit").await?;
        rt::timeout(Duration::from_secs(20), self.child.status())
            .await
            .context("The plugin did not exit.")??;
        Ok(())
    }

    /// The JSON events of one kind that the plugin printed so far.
    fn events(&self, name: &str) -> Vec<Value> {
        self.logs
            .text()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["event"] == name)
            .collect()
    }
}

// ------------------------------------------------------------------ the real relay

/// What the scenario shares: the relay, the two desktops, the Eclipse identity and the harness.
struct World {
    relay: Relay,
    alice: PathBuf,
    bob: PathBuf,
    eclipse: EclipseIdentity,
    /// The plugin's profile for the real relay.
    profile: PathBuf,
    java: Java,
}

fn initialize() -> Value {
    json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "real-e2e", "version": "1"}})
}

fn get_source() -> Value {
    json!({"name": "sap_get_source", "arguments": {"objectType": "PROG", "objectName": ARGUMENT_MARKER}})
}

fn answered_with_marker(reply: &Value) -> bool {
    reply["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|text| text.contains(RESULT_MARKER))
}

/// Compile the harness, start the relay, enroll both desktops and the Eclipse by link, and
/// grant the endpoint read-only.
async fn prepare(directory: &Path) -> Result<World> {
    let java = Java::compile()?;
    let relay = Relay::start(&directory.join("pki")).await?;
    let (alice, bob) = (directory.join("alice"), directory.join("bob"));
    relay.enroll_desktop(&alice, "Alice Desktop").await?;
    relay.enroll_desktop(&bob, "Bob Desktop").await?;
    let eclipse = relay.eclipse_identity(LABEL).await?;
    crate::setup::grant(
        &relay.pki,
        &[desktop_fingerprint(&alice)?, desktop_fingerprint(&bob)?],
        &eclipse.endpoint,
    )?;
    // Bob never pairs (pairing would select the endpoint), so select it for his legacy path.
    let selection = format!("--set-endpoint={}", eclipse.endpoint);
    let ran = run_client(&[&selection, "--profile", text(&bob)?]).await?;
    ensure!(ran.ok, "Bob could not select the endpoint: {}", ran.stderr);
    let profile = write_profile(
        directory,
        "eclipse-real.json",
        relay.data,
        &relay.ca,
        &eclipse,
    )?;
    Ok(World {
        relay,
        alice,
        bob,
        eclipse,
        profile,
        java,
    })
}

/// `pair --link` for Alice with a link the real plugin minted.
async fn pair_alice(world: &World, host: &mut PluginProc) -> Result<()> {
    let link = host.pair_link().await?;
    let ran = run_client(&["pair", "--profile", text(&world.alice)?, "--link", &link]).await?;
    ensure!(
        ran.ok && ran.stdout.contains("Paired with"),
        "Pairing failed: {}",
        ran.stderr
    );
    ensure!(
        !ran.stdout.contains("sap-adt://") && !ran.stderr.contains("sap-adt://"),
        "The client printed the pairing link."
    );
    Ok(())
}

/// Alice's call goes end to end: the real plugin received the arguments intact and the relay
/// logged the tool name but neither marker.
async fn alice_calls(world: &World, host: &PluginProc) -> Result<()> {
    let mut mcp = Host::start(&world.alice)?;
    let init = mcp.call(1, "initialize", &initialize()).await?;
    ensure!(
        init["result"]["serverInfo"]["name"] == SERVER_NAME,
        "initialize was not answered by the real plugin: {init}"
    );
    mcp.notify("notifications/initialized").await?;
    let reply = mcp.call(2, "tools/call", &get_source()).await?;
    ensure!(answered_with_marker(&reply), "Missing result: {reply}");
    host.logs.wait_for("\"event\":\"sap\"", 1).await?;
    let sap = host.events("sap");
    ensure!(
        sap.len() == 1
            && sap[0]["tool"] == "sap_get_source"
            && sap[0]["args"] == get_source()["arguments"],
        "The SAP call did not arrive intact: {sap:?}"
    );
    let stderr = mcp.finish().await?;
    ensure!(
        !stderr.contains("not paired"),
        "The client fell back to the unpaired path: {stderr}"
    );
    let relay = world.relay.logs.text();
    ensure!(
        relay.contains("sap_get_source"),
        "The relay did not log the tool name."
    );
    ensure!(
        !relay.contains(ARGUMENT_MARKER) && !relay.contains(RESULT_MARKER),
        "A payload reached the relay's logs."
    );
    ensure!(
        !relay.contains("GW1-") && !relay.contains("sap-adt://"),
        "A link or token reached the relay's logs."
    );
    Ok(())
}

/// Bob never paired, so his call takes the legacy path, which the plugin refuses with `-32002`.
async fn bob_refused(world: &World, host: &PluginProc) -> Result<()> {
    let mut mcp = Host::start(&world.bob)?;
    let init = mcp.call(1, "initialize", &initialize()).await?;
    ensure!(init["result"].is_object(), "initialize failed: {init}");
    let denied = mcp.call(2, "tools/call", &get_source()).await?;
    ensure!(
        denied["error"]["code"] == -32_002
            && denied["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(REFUSED_TEXT)),
        "The legacy call was not refused by the plugin: {denied}"
    );
    mcp.finish().await?;
    host.logs.wait_for("\"event\":\"legacyRefused\"", 1).await?;
    Timer::after(Duration::from_millis(300)).await;
    ensure!(
        host.events("sap").len() == 1 && host.events("sapHttp").len() == 1,
        "The refused call reached SAP."
    );
    Ok(())
}

/// With the switch on, the same legacy call works. This shows the refusal came from the
/// switch and not from a broken path.
async fn legacy_allowed(world: &World, first: PluginProc) -> Result<()> {
    first.quit().await?;
    world
        .relay
        .logs
        .wait_for("Eclipse bridge disconnected.", 1)
        .await?;
    let mut host = PluginProc::start(&world.java, &world.profile, true).await?;
    world
        .relay
        .logs
        .wait_for("Eclipse bridge connected.", 2)
        .await?;
    // The plugin's keys and pins live in memory, so the new process needs a new pairing.
    pair_alice(world, &mut host).await?;

    let mut mcp = Host::start(&world.bob)?;
    mcp.call(1, "initialize", &initialize()).await?;
    let reply = mcp.call(2, "tools/call", &get_source()).await?;
    ensure!(
        answered_with_marker(&reply),
        "The legacy call failed with the switch on: {reply}"
    );
    mcp.finish().await?;
    let sap = host.events("sap");
    ensure!(
        sap.len() == 1 && sap[0]["args"] == get_source()["arguments"],
        "The legacy call did not reach SAP intact: {sap:?}"
    );
    ensure!(
        host.events("legacyRefused").is_empty(),
        "The plugin refused a legacy call with the switch on."
    );
    host.quit().await
}

// ------------------------------------------------------------------ the rogue relay

/// The relay side of what the plugin sends.
enum Incoming {
    Control(Box<Control>),
    Data(u32, Vec<u8>),
    Json(Value),
}

/// What the plugin did with one stream.
enum Outcome {
    Reply(Value),
    Closed,
}

/// The desktop key the rogue relay speaks for.
struct Peer {
    key: InnerKey,
    relay_fingerprint: String,
    endpoint: String,
    /// The plugin's inner key pin and the pairing secret, both from the pairing link.
    pin: [u8; 32],
    secret: [u8; 32],
}

/// One inner TLS session on a stream, with the `seq` of the last message sent.
struct Inner {
    id: u32,
    tls: InnerTls,
    seq: u64,
}

/// A relay that holds the real relay's server certificate and so passes the plugin's check.
struct Rogue {
    ws: Socket,
    peer: Peer,
}

fn rogue_acceptor(pki: &Path) -> Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut fs::read(pki.join("server.pem"))?.as_slice())
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut fs::read(pki.join("server.key"))?.as_slice())?
        .context("Missing the relay's server key.")?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn accept(listener: TcpListener, acceptor: TlsAcceptor) -> Result<Socket> {
    let (socket, _) = listener.accept().await?;
    let tls = acceptor.accept(socket).await?;
    Ok(accept_async(tls).await?)
}

impl Rogue {
    async fn send(&mut self, message: Message) -> Result<()> {
        rt::timeout(Duration::from_secs(10), self.ws.send(message))
            .await
            .context("Timed out sending to the plugin.")??;
        Ok(())
    }

    async fn control(&mut self, control: &Control) -> Result<()> {
        self.send(Message::Text(control.encode()?.into())).await
    }

    async fn data(&mut self, stream: u32, bytes: &[u8]) -> Result<()> {
        for frame in encode_data_chunks(stream, bytes) {
            self.send(Message::Binary(frame.into())).await?;
        }
        Ok(())
    }

    async fn next(&mut self) -> Result<Incoming> {
        loop {
            let item = rt::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .context("The plugin sent nothing in time.")?;
            match item.context("The plugin closed the connection.")?? {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(text.as_str())?;
                    if value.get("type").is_some() {
                        return Ok(Incoming::Control(Box::new(Control::decode(text.as_str())?)));
                    }
                    return Ok(Incoming::Json(value));
                }
                Message::Binary(frame) => {
                    let (stream, payload) = decode_data(&frame[..])?;
                    return Ok(Incoming::Data(stream, payload.to_vec()));
                }
                Message::Close(_) => bail!("The plugin closed the connection."),
                _ => {}
            }
        }
    }

    /// `relay/hello`, as the real relay sends it; the plugin must announce `e2e`.
    async fn hello(&mut self) -> Result<()> {
        let hello = json!({"jsonrpc": "2.0", "id": 1, "method": "relay/hello", "params": {"policyVersion": 2}});
        self.send(Message::Text(hello.to_string().into())).await?;
        loop {
            if let Incoming::Json(reply) = self.next().await? {
                ensure!(
                    reply["id"] == 1 && reply["result"]["e2e"] == 1,
                    "Unexpected hello answer: {reply}"
                );
                return Ok(());
            }
        }
    }

    async fn flush(&mut self, id: u32, tls: &mut InnerTls) -> Result<()> {
        let output = tls.take_output()?;
        if !output.is_empty() {
            self.data(id, &output).await?;
        }
        Ok(())
    }

    /// Opens stream `id` for Alice's key and finishes the inner handshake.
    async fn open(&mut self, id: u32) -> Result<Inner> {
        let open = Control::Open {
            stream: id,
            endpoint: self.peer.endpoint.clone(),
            desktop: Some(self.peer.relay_fingerprint.clone()),
            label: Some("Alice Desktop".to_owned()),
        };
        self.control(&open).await?;
        let mut tls = InnerTls::new(&self.peer.key, self.peer.pin)?;
        self.flush(id, &mut tls).await?;
        while tls.handshaking() {
            match self.next().await? {
                Incoming::Data(stream, bytes) if stream == id => {
                    tls.feed(&bytes).context("The inner handshake failed.")?;
                    self.flush(id, &mut tls).await?;
                }
                Incoming::Control(control) => {
                    if let Control::Close { reason, .. } = *control {
                        bail!("The plugin closed the stream during the handshake: {reason}");
                    }
                }
                _ => {}
            }
        }
        Ok(Inner { id, tls, seq: 0 })
    }

    /// Announces `envelope` as the relay would forward it, then sends `message` encrypted.
    /// The envelope is not checked against the message: that is what the plugin must do.
    async fn request(
        &mut self,
        inner: &mut Inner,
        envelope: Envelope,
        message: &Value,
    ) -> Result<()> {
        let sealed = inner
            .tls
            .seal(message.to_string().as_bytes(), MAX_REQUEST_BYTES)?;
        let announce = Control::Request {
            stream: inner.id,
            envelope,
            policy: Some(RelayPolicy {
                allowed_tools: vec!["sap_get_source".to_owned(), "sap_set_source".to_owned()],
                package_scopes: Vec::new(),
            }),
            len: u32::try_from(sealed.len())?,
        };
        self.control(&announce).await?;
        self.data(inner.id, &sealed).await
    }

    /// The plugin's next answer on the stream, decrypted, or its `close`.
    async fn outcome(&mut self, inner: &mut Inner) -> Result<Outcome> {
        let len = loop {
            match self.next().await? {
                Incoming::Data(stream, bytes) if stream == inner.id => {
                    // Tickets and alerts; a broken session shows as the stream's `close`.
                    let _ = inner.tls.feed(&bytes);
                }
                Incoming::Control(control) => match *control {
                    Control::Response { stream, len, .. } if stream == inner.id => break len,
                    Control::Close { stream, .. } if stream == inner.id => {
                        return Ok(Outcome::Closed);
                    }
                    _ => {}
                },
                _ => {}
            }
        };
        let mut received = 0_u64;
        while received < u64::from(len) {
            match self.next().await? {
                Incoming::Data(stream, bytes) if stream == inner.id => {
                    received += bytes.len() as u64;
                    inner.tls.feed(&bytes)?;
                }
                Incoming::Control(control) => {
                    if matches!(*control, Control::Close { .. }) {
                        return Ok(Outcome::Closed);
                    }
                }
                _ => {}
            }
        }
        let message = inner
            .tls
            .next_message(MAX_RESPONSE_BYTES)?
            .context("The plugin's answer is incomplete.")?;
        Ok(Outcome::Reply(serde_json::from_slice(&message)?))
    }

    /// A truthful message: the next `seq`, and an envelope derived from the message.
    async fn exchange(
        &mut self,
        inner: &mut Inner,
        method: &str,
        tool: Option<(&str, Class)>,
        message: &Value,
    ) -> Result<Value> {
        inner.seq += 1;
        self.request(inner, Envelope::new(inner.seq, method, tool), message)
            .await?;
        match self.outcome(inner).await? {
            Outcome::Reply(reply) => Ok(reply),
            Outcome::Closed => bail!("The plugin closed the stream on a truthful {method}."),
        }
    }

    /// Everything the plugin answers until it closes the stream. A stream that stays open
    /// fails with a timeout.
    async fn until_closed(&mut self, inner: &mut Inner) -> Result<Vec<Value>> {
        let mut replies = Vec::new();
        loop {
            match self.outcome(inner).await? {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Closed => return Ok(replies),
            }
        }
    }

    /// Pairs Alice's inner key with the plugin, as the real relay would forward it.
    async fn pair(&mut self) -> Result<()> {
        let mut inner = self.open(1).await?;
        let claim = json!({"jsonrpc": "2.0", "id": 1, "method": "pair/claim", "params": {"secret": hex::encode(self.peer.secret)}});
        let reply = self
            .exchange(&mut inner, "pair/claim", None, &claim)
            .await?;
        ensure!(
            reply["result"]["paired"] == true,
            "The pairing was refused: {reply}"
        );
        Ok(())
    }
}

fn peer(world: &World, link: &str) -> Result<Peer> {
    let link = PairLink::parse(link)?;
    let decoded = token::decode(&link.token).context("The link's token is damaged.")?;
    let (mut secret, mut pin) = ([0_u8; 32], [0_u8; 32]);
    secret.copy_from_slice(&decoded[..32]);
    pin.copy_from_slice(&decoded[32..]);
    Ok(Peer {
        key: InnerKey::load_or_create(&world.alice)?,
        relay_fingerprint: desktop_fingerprint(&world.alice)?,
        endpoint: world.eclipse.endpoint.clone(),
        pin,
        secret,
    })
}

fn request_message(id: u64, method: &str, params: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// A rogue relay cannot downgrade: a clear-text call over the bridge is refused locally.
async fn downgrade(rogue: &mut Rogue) -> Result<()> {
    let mut params = get_source();
    params["relayAllowedTools"] = json!(["sap_get_source"]);
    params["relayPackageScopes"] = json!([]);
    let call = request_message(2, "tools/call", &params);
    rogue.send(Message::Text(call.to_string().into())).await?;
    loop {
        if let Incoming::Json(reply) = rogue.next().await? {
            ensure!(
                reply["id"] == 2 && reply["error"]["code"] == -32_002,
                "The plugin did not refuse the clear-text call: {reply}"
            );
            return Ok(());
        }
    }
}

/// A forged envelope and a wrong `seq`, each on a fresh stream of the paired desktop.
async fn forgeries(rogue: &mut Rogue) -> Result<()> {
    // The envelope says `sap_get_source` (read); the encrypted message calls `sap_set_source`.
    let mut forged = rogue.open(2).await?;
    let init = request_message(1, "initialize", &initialize());
    let reply = rogue
        .exchange(&mut forged, "initialize", None, &init)
        .await?;
    ensure!(
        reply["result"]["serverInfo"]["name"] == SERVER_NAME,
        "A truthful initialize was not answered: {reply}"
    );
    let write = request_message(
        2,
        "tools/call",
        &json!({"name": "sap_set_source", "arguments": {"objectType": "PROG", "objectName": "Z_ROGUE", "source": "WRITE 'rogue'."}}),
    );
    let lie = Envelope::new(2, "tools/call", Some(("sap_get_source", Class::Read)));
    rogue.request(&mut forged, lie, &write).await?;
    let replies = rogue.until_closed(&mut forged).await?;
    ensure!(
        replies.iter().all(|reply| reply.get("result").is_none()),
        "The plugin answered a forged request with a result: {replies:?}"
    );

    // A truthful `ping`, announced with the wrong `seq`.
    let mut skewed = rogue.open(3).await?;
    rogue
        .exchange(&mut skewed, "initialize", None, &init)
        .await?;
    let ping = request_message(2, "ping", &json!({}));
    rogue
        .request(&mut skewed, Envelope::new(7, "ping", None), &ping)
        .await?;
    let replies = rogue.until_closed(&mut skewed).await?;
    ensure!(
        replies.iter().all(|reply| reply.get("result").is_none()),
        "The plugin answered a request with a wrong seq: {replies:?}"
    );
    Ok(())
}

/// The plugin as a compromised relay's victim: paired through the rogue relay, then lied to.
async fn rogue_relay(world: &World, directory: &Path) -> Result<()> {
    let acceptor = rogue_acceptor(&world.relay.pki)?;
    // `std` sockets are not inheritable on Windows, so no child process keeps them open.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let accepting = rt::spawn(accept(TcpListener::try_from(listener)?, acceptor));
    let profile = write_profile(
        directory,
        "eclipse-rogue.json",
        address,
        &world.relay.ca,
        &world.eclipse,
    )?;
    let mut host = Box::pin(PluginProc::start(&world.java, &profile, false)).await?;
    let ws = accepting.await?;
    let link = host.pair_link().await?;
    let mut rogue = Rogue {
        ws,
        peer: peer(world, &link)?,
    };
    rogue.hello().await?;
    rogue.pair().await?;
    downgrade(&mut rogue).await?;
    Box::pin(forgeries(&mut rogue)).await?;

    Timer::after(Duration::from_millis(300)).await;
    ensure!(
        host.events("sap").is_empty() && host.events("sapHttp").is_empty(),
        "A forged request reached SAP."
    );
    let failures = host
        .events("streamClosed")
        .iter()
        .filter(|event| {
            event["reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("Binding failure"))
        })
        .count();
    ensure!(
        failures >= 2,
        "The plugin logged {failures} binding failures, expected 2."
    );
    ensure!(
        host.events("legacyRefused").len() == 1,
        "The clear-text call was not logged as refused."
    );
    host.quit().await
}

/// The scenario of the lead's `#[test]`: call it inside `smol::block_on` with a timeout of a
/// few minutes. Without `SAP_ADT_INTEROP=1` it returns at once.
pub async fn scenario() -> Result<()> {
    if std::env::var("SAP_ADT_INTEROP").as_deref() != Ok("1") {
        eprintln!("SAP_ADT_INTEROP is not 1: skipping the real plugin end-to-end scenario.");
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let world = Box::pin(prepare(directory.path())).await?;
    let mut host = Box::pin(PluginProc::start(&world.java, &world.profile, false)).await?;
    let connected = world
        .relay
        .logs
        .wait_for("Eclipse bridge connected.", 1)
        .await?;
    ensure!(
        connected.contains("e2e=true"),
        "The relay did not see the plugin's e2e support: {connected}"
    );
    pair_alice(&world, &mut host).await?;
    Box::pin(alice_calls(&world, &host)).await?;
    Box::pin(bob_refused(&world, &host)).await?;
    Box::pin(legacy_allowed(&world, host)).await?;
    Box::pin(rogue_relay(&world, directory.path())).await
}
