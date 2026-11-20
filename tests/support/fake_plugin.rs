//! A stand-in for the Eclipse plugin, speaking the end-to-end protocol over `/bridge`.
//!
//! It answers `relay/hello` with `e2e: 1`, runs one inner TLS 1.3 server per stream
//! (`TLS13_AES_256_GCM_SHA384`, its own P-256 key, client certificate required), moves the
//! encrypted bytes in tunnel data frames and derives the envelope of every decrypted request
//! itself, closing the stream when it differs from the one the relay forwarded.
//!
//! The crate root must include `src/rt.rs` as `rt`, `src/link.rs` as `link` and
//! `src/tunnel_proto.rs` as `tunnel_proto`.

use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex, PoisonError},
};

use anyhow::{Context, Result, anyhow};
use async_tungstenite::{WebSocketStream, client_async, tungstenite::Message};
use futures_rustls::{TlsConnector, client::TlsStream};
use futures_util::StreamExt;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, ServerConnection,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::{
        NoServerSessionStorage, ParsedCertificate,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use serde_json::{Value, json};
use smol::{Task, net::TcpStream};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    link::PairLink,
    rt,
    tunnel_proto::{
        Class, Control, Envelope, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MessageReader,
        RelayPolicy, Status as ReplyStatus, decode_data, encode_data_chunks, frame_message,
    },
};

/// Placed in a tool call's arguments by the test; must never reach the relay's logs.
pub const ARGUMENT_MARKER: &str = "E2E-SECRET-ARGUMENT-7f3a";
/// Placed in a tool call's result; must never reach the relay's logs.
pub const RESULT_MARKER: &str = "E2E-SECRET-RESULT-91c2";
/// The server name the fake plugin reports in `initialize`.
pub const SERVER_NAME: &str = "fake-eclipse-plugin";

type Socket = WebSocketStream<TlsStream<TcpStream>>;

static CLASSES: LazyLock<HashMap<String, Class>> = LazyLock::new(|| {
    let table: Value = serde_json::from_str(include_str!(
        "../../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/resources/tools.json"
    ))
    .expect("tools.json is valid");
    table["tools"]
        .as_array()
        .expect("tools.json lists tools")
        .iter()
        .map(|tool| {
            let class: Class =
                serde_json::from_value(tool["class"].clone()).expect("tools.json has classes");
            (
                tool["name"]
                    .as_str()
                    .expect("tools.json names tools")
                    .to_owned(),
                class,
            )
        })
        .collect()
});

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}

fn spki_of(cert: &CertificateDer<'_>) -> Result<Vec<u8>, Error> {
    Ok(ParsedCertificate::try_from(cert)?
        .subject_public_key_info()
        .as_ref()
        .to_vec())
}

/// The token of a pairing link: Crockford Base32 with the `GW1-` prefix, groups of five.
fn encode_token(bytes: &[u8; 64]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut symbols = Vec::new();
    let mut accumulator = 0_u16;
    let mut bits = 0_u32;
    for &byte in bytes {
        accumulator = (accumulator << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols.push(ALPHABET[usize::from((accumulator >> bits) & 31)]);
            accumulator &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        symbols.push(ALPHABET[usize::from((accumulator << (5 - bits)) & 31)]);
    }
    let groups: Vec<String> = symbols
        .chunks(5)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect();
    format!("GW1-{}", groups.join("-"))
}

/// The plugin's inner identity: a P-256 key with a self-signed certificate.
struct PluginKey {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
    fingerprint: [u8; 32],
}

impl PluginKey {
    fn generate() -> Result<Self> {
        let pair = KeyPair::generate()?;
        let cert = CertificateParams::new(Vec::<String>::new())?.self_signed(&pair)?;
        Ok(Self {
            cert: cert.der().clone(),
            pkcs8: pair.serialize_der(),
            fingerprint: sha256(&pair.subject_public_key_info()),
        })
    }
}

/// What the test can look at, and what the handshake verifier needs.
#[derive(Debug, Default)]
struct State {
    /// Pinned desktop inner keys (SPKI SHA-256), in pairing order.
    pins: Vec<[u8; 32]>,
    /// The outstanding pairing secret, if a link was minted and not yet used.
    pairing: Option<[u8; 32]>,
    /// `tools/call` requests that arrived: tool and arguments, as decrypted.
    calls: Vec<(String, Value)>,
    /// Clear-text JSON-RPC methods that arrived on the bridge besides hello and ping.
    legacy: Vec<String>,
    /// Requests whose forwarded envelope differed from the derived one.
    binding_failures: usize,
    /// Messages other than `pair/claim` from a key that is not pinned.
    refused_unpaired: usize,
}

#[derive(Debug)]
struct Shared {
    fingerprint: [u8; 32],
    state: Mutex<State>,
}

impl Shared {
    fn with<R>(&self, edit: impl FnOnce(&mut State) -> R) -> R {
        edit(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Client authentication of the inner session: a pinned key passes, and so does any key
/// while a pairing secret is outstanding (such a stream may then only send `pair/claim`).
#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    shared: Arc<Shared>,
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let found = sha256(&spki_of(end_entity)?);
        if self
            .shared
            .with(|state| state.pins.contains(&found) || state.pairing.is_some())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General("unknown desktop key".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 refused".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// One cipher suite, two key-exchange groups, as the plan's inner session.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
        ],
        ..rustls::crypto::ring::default_provider()
    })
}

fn server_config(key: &PluginKey, shared: &Arc<Shared>) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let verifier = Verifier {
        provider: Arc::clone(&provider),
        shared: Arc::clone(shared),
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(
            vec![key.cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.pkcs8.clone())),
        )?;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// The envelope the plugin expects for `message`, from the decrypted request alone.
fn derive(message: &Value, seq: u64) -> Option<Envelope> {
    let method = message["method"].as_str()?;
    let tool = if method == "tools/call" {
        let name = message["params"]["name"].as_str()?;
        Some((name, *CLASSES.get(name)?))
    } else {
        None
    };
    Some(Envelope::new(seq, method, tool))
}

fn result(id: &Value, value: Value) -> Value {
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply["result"] = value;
    reply
}

fn failure(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tools_list() -> Value {
    let tool = |name: &str| json!({"name": name, "description": "Fake tool.", "inputSchema": {"type": "object"}});
    json!({"tools": [tool("sap_get_source"), tool("sap_search_object"), tool("sap_set_source")]})
}

/// Feeds TLS bytes to the connection. `false` when the session is broken.
fn feed(conn: &mut ServerConnection, payload: &[u8]) -> bool {
    let mut input = payload;
    while !input.is_empty() {
        match conn.read_tls(&mut input) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
        if conn.process_new_packets().is_err() {
            return false;
        }
    }
    true
}

/// Every TLS byte the connection has queued: handshake flights, alerts and sealed messages.
fn take_tls(conn: &mut ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

/// One inner TLS session.
struct StreamState {
    conn: ServerConnection,
    reader: MessageReader,
    /// Envelopes the relay forwarded and the plugin has not matched to a message yet.
    announced: VecDeque<(Envelope, Option<RelayPolicy>)>,
    /// The plugin's own counter: the `seq` of the last message it matched.
    seq: u64,
    /// The desktop's key, once the handshake is done.
    peer: Option<[u8; 32]>,
}

struct Session {
    shared: Arc<Shared>,
    config: Arc<ServerConfig>,
    streams: HashMap<u32, StreamState>,
    out: Vec<Message>,
}

impl Session {
    fn push_control(&mut self, control: &Control) {
        if let Ok(text) = control.encode() {
            self.out.push(Message::Text(text.into()));
        }
    }

    fn push_data(&mut self, stream: u32, bytes: &[u8]) {
        for frame in encode_data_chunks(stream, bytes) {
            self.out.push(Message::Binary(frame.into()));
        }
    }

    fn close(&mut self, stream: u32, reason: &str) {
        self.streams.remove(&stream);
        self.push_control(&Control::Close {
            stream,
            reason: reason.to_owned(),
        });
    }

    fn on_text(&mut self, text: &str) {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return;
        };
        if value.get("type").is_some() {
            if let Ok(control) = Control::decode(text) {
                self.on_control(control);
            }
        } else {
            self.on_legacy(&value);
        }
    }

    /// The legacy bridge exchange: `relay/hello` and the heartbeat.
    fn on_legacy(&mut self, value: &Value) {
        let Some(method) = value["method"].as_str() else {
            return;
        };
        let id = &value["id"];
        let reply = match method {
            "relay/hello" => result(id, json!({"policyVersion": 2, "e2e": 1})),
            "ping" => result(id, json!({})),
            other => {
                self.shared
                    .with(|state| state.legacy.push(other.to_owned()));
                failure(id, -32_601, "Legacy calls are not served.")
            }
        };
        self.out.push(Message::Text(reply.to_string().into()));
    }

    fn on_control(&mut self, control: Control) {
        match control {
            Control::Open { stream, .. } => match ServerConnection::new(Arc::clone(&self.config)) {
                Ok(conn) => {
                    self.streams.insert(
                        stream,
                        StreamState {
                            conn,
                            reader: MessageReader::default(),
                            announced: VecDeque::new(),
                            seq: 0,
                            peer: None,
                        },
                    );
                }
                Err(_) => self.close(stream, "The inner session could not start."),
            },
            Control::Request {
                stream,
                envelope,
                policy,
                ..
            } => {
                if let Some(known) = self.streams.get_mut(&stream) {
                    known.announced.push_back((envelope, policy));
                }
            }
            Control::Close { stream, .. } => {
                self.streams.remove(&stream);
            }
            _ => {}
        }
    }

    fn on_binary(&mut self, frame: &[u8]) {
        let Ok((id, payload)) = decode_data(frame) else {
            return;
        };
        let Some(mut stream) = self.streams.remove(&id) else {
            return;
        };
        let mut alive = feed(&mut stream.conn, payload);
        // Handshake flights and alerts go out before any response.
        let wire = take_tls(&mut stream.conn);
        if !wire.is_empty() {
            self.push_data(id, &wire);
        }
        if alive {
            alive = self.process(id, &mut stream);
        }
        if alive {
            self.streams.insert(id, stream);
        } else {
            self.close(id, "Closed by the plugin.");
        }
    }

    /// Reads the decrypted messages of a stream. `false` ends the stream.
    fn process(&mut self, id: u32, stream: &mut StreamState) -> bool {
        if stream.peer.is_none() && !stream.conn.is_handshaking() {
            stream.peer = stream
                .conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| spki_of(cert).ok())
                .map(|spki| sha256(&spki));
        }
        let mut buffer = [0_u8; 16 * 1024];
        while let Ok(count) = stream.conn.reader().read(&mut buffer) {
            if count == 0 {
                break;
            }
            stream.reader.push(&buffer[..count]);
        }
        loop {
            match stream.reader.next_message(MAX_REQUEST_BYTES) {
                Ok(Some(message)) => {
                    if !self.handle(id, stream, &message) {
                        return false;
                    }
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    /// One decrypted message: match it to its announced envelope, check the desktop's key
    /// and answer. `false` ends the stream.
    fn handle(&mut self, id: u32, stream: &mut StreamState, raw: &[u8]) -> bool {
        let Ok(message) = serde_json::from_slice::<Value>(raw) else {
            return false;
        };
        let Some((announced, policy)) = stream.announced.pop_front() else {
            return false;
        };
        stream.seq += 1;
        if derive(&message, stream.seq).as_ref() != Some(&announced) {
            self.shared.with(|state| state.binding_failures += 1);
            return false;
        }
        let paired = stream
            .peer
            .is_some_and(|key| self.shared.with(|state| state.pins.contains(&key)));
        if !paired && announced.method != "pair/claim" {
            self.shared.with(|state| state.refused_unpaired += 1);
            return false;
        }
        let Some(reply) = self.answer(stream.peer, &announced.method, &message, policy.as_ref())
        else {
            return true;
        };
        self.respond(id, stream, announced.seq, &reply)
    }

    /// The reply to one request, or `None` for a notification.
    fn answer(
        &self,
        peer: Option<[u8; 32]>,
        method: &str,
        message: &Value,
        policy: Option<&RelayPolicy>,
    ) -> Option<Value> {
        let id = &message["id"];
        if method.starts_with("notifications/") {
            return None;
        }
        Some(match method {
            "initialize" => result(
                id,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": "0.0.1"}
                }),
            ),
            "ping" => result(id, json!({})),
            "tools/list" => result(id, tools_list()),
            "tools/call" => self.call(id, &message["params"], policy),
            "pair/claim" => self.claim(id, peer, &message["params"]),
            _ => failure(id, -32_601, "Unknown method."),
        })
    }

    /// Records the arguments as they arrived and answers with a fixed result.
    fn call(&self, id: &Value, params: &Value, policy: Option<&RelayPolicy>) -> Value {
        let name = params["name"].as_str().unwrap_or_default();
        if let Some(policy) = policy
            && !policy.allowed_tools.iter().any(|allowed| allowed == name)
        {
            return failure(id, -32_003, "Denied by this Eclipse's permissions.");
        }
        self.shared.with(|state| {
            state
                .calls
                .push((name.to_owned(), params["arguments"].clone()));
        });
        let text = if name == "sap_get_source" {
            format!("REPORT Z_E2E. \" {RESULT_MARKER}")
        } else {
            "ok".to_owned()
        };
        result(
            id,
            json!({"content": [{"type": "text", "text": text}], "isError": false}),
        )
    }

    /// Compares the secret, pins the desktop's key and burns the secret (the "click" is
    /// confirmed automatically).
    fn claim(&self, id: &Value, peer: Option<[u8; 32]>, params: &Value) -> Value {
        let given = params["secret"]
            .as_str()
            .and_then(|text| hex::decode(text).ok())
            .unwrap_or_default();
        let accepted = self.shared.with(|state| {
            let (Some(secret), Some(key)) = (state.pairing, peer) else {
                return false;
            };
            if !bool::from(secret.as_slice().ct_eq(given.as_slice())) {
                return false;
            }
            state.pairing = None;
            state.pins.push(key);
            true
        });
        if accepted {
            result(id, json!({}))
        } else {
            failure(id, -32_003, "The pairing was refused.")
        }
    }

    /// Encrypts the reply and sends it as `Response {seq, status, len}` plus data frames.
    fn respond(&mut self, id: u32, stream: &mut StreamState, seq: u64, reply: &Value) -> bool {
        let Ok(framed) = frame_message(reply.to_string().as_bytes(), MAX_RESPONSE_BYTES) else {
            return false;
        };
        if stream.conn.writer().write_all(&framed).is_err() {
            return false;
        }
        let wire = take_tls(&mut stream.conn);
        let Ok(len) = u32::try_from(wire.len()) else {
            return false;
        };
        let status = if reply.get("error").is_some() {
            ReplyStatus::Error
        } else {
            ReplyStatus::Ok
        };
        self.push_control(&Control::Response {
            stream: id,
            seq,
            status,
            len,
        });
        self.push_data(id, &wire);
        true
    }
}

async fn run(mut ws: Socket, mut session: Session) {
    while let Some(Ok(message)) = ws.next().await {
        match message {
            Message::Text(text) => session.on_text(text.as_str()),
            Message::Binary(frame) => session.on_binary(&frame[..]),
            Message::Close(_) => break,
            _ => {}
        }
        let pending = std::mem::take(&mut session.out);
        for out in pending {
            if ws.send(out).await.is_err() {
                return;
            }
        }
    }
}

/// A connected fake plugin. Dropping it closes the bridge connection.
pub struct FakePlugin {
    shared: Arc<Shared>,
    _task: Task<()>,
}

impl FakePlugin {
    /// Connects `/bridge` with the Eclipse identity inside `config` and serves it with a new
    /// inner key.
    pub async fn connect(data: SocketAddr, config: &ClientConfig) -> Result<Self> {
        let key = PluginKey::generate()?;
        let shared = Arc::new(Shared {
            fingerprint: key.fingerprint,
            state: Mutex::new(State::default()),
        });
        let inner = server_config(&key, &shared)?;
        // async-io marks the sockets it connects as inheritable on Windows, so client
        // processes spawned later would hold this connection open after it is dropped.
        // `std` sockets are not inheritable.
        let stream =
            TcpStream::try_from(smol::unblock(move || std::net::TcpStream::connect(data)).await?)?;
        let tls = TlsConnector::from(Arc::new(config.clone()))
            .connect(ServerName::from(data.ip()), stream)
            .await?;
        let (ws, _) = client_async(format!("wss://{data}/bridge"), tls).await?;
        let session = Session {
            shared: Arc::clone(&shared),
            config: inner,
            streams: HashMap::new(),
            out: Vec::new(),
        };
        Ok(Self {
            shared,
            _task: rt::spawn(run(ws, session)),
        })
    }

    /// Mint a pairing link for `endpoint`: the token is a fresh 32-byte secret followed by the
    /// SHA-256 of this plugin's key. A new link replaces the outstanding one.
    pub fn pair_link(&self, endpoint: &str, name: &str) -> Result<String> {
        let mut secret = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| anyhow!("No randomness."))?;
        let mut token = Zeroizing::new([0_u8; 64]);
        token[..32].copy_from_slice(&secret);
        token[32..].copy_from_slice(&self.shared.fingerprint);
        self.shared.with(|state| state.pairing = Some(secret));
        let link = PairLink {
            endpoint: endpoint.to_owned(),
            name: name.to_owned(),
            token: Zeroizing::new(encode_token(&token)),
        };
        link.build().context("The pairing link could not be built.")
    }

    /// The SHA-256 of this plugin's inner key, as the client pins it.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.shared.fingerprint)
    }

    /// How many desktop keys are pinned.
    pub fn pinned(&self) -> usize {
        self.shared.with(|state| state.pins.len())
    }

    /// Forget the most recently pinned desktop key.
    pub fn unpin_last(&self) {
        self.shared.with(|state| {
            state.pins.pop();
        });
    }

    /// The `tools/call` requests that arrived, as decrypted: tool name and arguments.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.shared.with(|state| state.calls.clone())
    }

    /// Clear-text calls the relay made on the bridge besides hello and ping.
    pub fn legacy_calls(&self) -> Vec<String> {
        self.shared.with(|state| state.legacy.clone())
    }

    pub fn binding_failures(&self) -> usize {
        self.shared.with(|state| state.binding_failures)
    }

    pub fn refused_unpaired(&self) -> usize {
        self.shared.with(|state| state.refused_unpaired)
    }
}
