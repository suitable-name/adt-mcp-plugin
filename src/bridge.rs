use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    rt::timeout,
    security::Pki,
    transport::{PeerCertificate, Transport, Upgrade},
    tunnel::{Hub, StreamRow},
    tunnel_proto::{Control, MAX_CONTROL_BYTES},
    web::{Prefixed, Reply},
};
use async_tungstenite::{
    WebSocketReceiver, WebSocketSender, WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use smol::{
    Timer, channel, future,
    lock::{Semaphore, SemaphoreGuardArc},
};
use trillium_http::{Headers, KnownHeaderName, Status};
use uuid::Uuid;

pub type Socket = WebSocketStream<Prefixed<Transport>>;
/// The sending half of a split [`Socket`].
pub type SocketSender = WebSocketSender<Prefixed<Transport>>;
/// The receiving half of a split [`Socket`].
pub type SocketReceiver = WebSocketReceiver<Prefixed<Transport>>;

const CALL_LIMIT: Duration = Duration::from_secs(600);
const HEARTBEAT: Duration = Duration::from_secs(20);
const SESSION_IDLE: Duration = Duration::from_hours(8);
const MAX_SESSIONS: usize = 128;
// WebSocket upgrades outlive the HTTP connection permit used by the transport.
const MAX_BRIDGES: usize = 128;
/// Messages waiting for the bridge's writer: legacy requests, stream control and data frames.
const OUTBOUND_QUEUE: usize = 256;
/// Largest WebSocket message from the plugin (a legacy response may be 8 MiB).
const MESSAGE_LIMIT: usize = 8 * 1024 * 1024;

pub type Outcome = Result<Value, Value>;

pub fn error(code: i32, message: &str) -> Value {
    json!({"code": code, "message": message})
}

fn disconnected() -> Value {
    error(
        -32_000,
        "The Eclipse bridge disconnected. Reinitialize the MCP session.",
    )
}

fn lost_reply(method: &str) -> Value {
    if method == "tools/call" {
        error(
            -32_000,
            "The relay lost the tool reply. The SAP operation's outcome is unknown. Check SAP before retrying.",
        )
    } else {
        disconnected()
    }
}

struct Call {
    method: &'static str,
    params: Value,
    reply: channel::Sender<Outcome>,
    deadline: Instant,
    _permit: SemaphoreGuardArc,
}

#[derive(Clone)]
pub struct Client {
    pub(super) endpoint: Arc<str>,
    sender: channel::Sender<Call>,
    admission: Arc<Semaphore>,
}

impl Client {
    fn channel(endpoint: Arc<str>) -> (Self, channel::Receiver<Call>) {
        let (sender, receiver) = channel::bounded(1);
        (
            Self {
                endpoint,
                sender,
                admission: Arc::new(Semaphore::new(1)),
            },
            receiver,
        )
    }

    #[cfg(test)]
    pub(super) fn expecting(
        method: &'static str,
        params: Value,
        result: Value,
    ) -> (Self, smol::Task<()>) {
        let (client, receiver) = Self::channel(Arc::from("test"));
        let task = crate::rt::spawn(async move {
            let call = receiver.recv().await.unwrap();
            assert_eq!(call.method, method);
            assert_eq!(call.params, params);
            call.reply.try_send(Ok(result)).unwrap();
        });
        (client, task)
    }

    pub(super) async fn call(&self, method: &'static str, params: Value) -> Outcome {
        let permit = self
            .admission
            .try_acquire_arc()
            .ok_or_else(|| error(-32_000, "The Eclipse bridge is busy."))?;
        let (reply, result) = channel::bounded(1);
        let deadline = Instant::now() + CALL_LIMIT;
        self.sender
            .try_send(Call {
                method,
                params,
                reply,
                deadline,
                _permit: permit,
            })
            .map_err(|_| disconnected())?;
        timeout(
            deadline.saturating_duration_since(Instant::now()),
            result.recv(),
        )
        .await
        .map_err(|_| lost_reply(method))?
        .map_err(|_| lost_reply(method))?
    }
}

struct Session {
    owner: [u8; 32],
    last_used: Instant,
    version: &'static str,
    // Monitoring only.
    created: Instant,
    peer: SocketAddr,
    requests: u64,
    activity: String,
}

impl Session {
    fn valid(&self, owner: &[u8; 32]) -> bool {
        &self.owner == owner && self.last_used.elapsed() < SESSION_IDLE
    }
}

struct Slot {
    bridge: Client,
    ready: bool,
    /// The end-to-end streams of this bridge connection.
    hub: Arc<Hub>,
    sessions: HashMap<Uuid, Session>,
    // Monitoring only.
    peer: SocketAddr,
    since: Instant,
    calls: u64,
    last_call: Option<(String, Instant)>,
}

impl Slot {
    fn initialize(
        &mut self,
        version: &'static str,
        owner: [u8; 32],
        peer: SocketAddr,
    ) -> Result<Uuid, Status> {
        if !self.ready {
            return Err(Status::ServiceUnavailable);
        }
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < SESSION_IDLE);
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Status::TooManyRequests);
        }
        let id = Uuid::new_v4();
        let now = Instant::now();
        self.sessions.insert(
            id,
            Session {
                owner,
                last_used: now,
                version,
                created: now,
                peer,
                requests: 1,
                activity: "initialize".to_owned(),
            },
        );
        Ok(id)
    }

    fn session(&self, id: Uuid, owner: &[u8; 32]) -> Result<(Client, &'static str), Status> {
        let session = self
            .sessions
            .get(&id)
            .filter(|s| s.valid(owner))
            .ok_or(Status::NotFound)?;
        Ok((self.bridge.clone(), session.version))
    }
}

#[derive(Clone, Default)]
pub struct Registry(Arc<Mutex<HashMap<Arc<str>, Slot>>>);

impl Registry {
    fn slots(&self) -> MutexGuard<'_, HashMap<Arc<str>, Slot>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reserve(
        &self,
        endpoint: Arc<str>,
        peer: SocketAddr,
    ) -> Result<(Reservation, channel::Receiver<Call>), Status> {
        let mut slots = self.slots();
        let full = slots.len() >= MAX_BRIDGES;
        let std::collections::hash_map::Entry::Vacant(slot) = slots.entry(Arc::clone(&endpoint))
        else {
            return Err(Status::Conflict);
        };
        if full {
            return Err(Status::TooManyRequests);
        }
        let (bridge, receiver) = Client::channel(Arc::clone(&endpoint));
        let (to_bridge, outbound) = channel::bounded(OUTBOUND_QUEUE);
        let hub = Arc::new(Hub::new(Arc::clone(&endpoint), to_bridge));
        slot.insert(Slot {
            bridge,
            ready: false,
            hub: Arc::clone(&hub),
            sessions: HashMap::new(),
            peer,
            since: Instant::now(),
            calls: 0,
            last_call: None,
        });
        drop(slots);
        Ok((
            Reservation {
                registry: self.clone(),
                endpoint,
                hub,
                outbound,
            },
            receiver,
        ))
    }

    pub(super) fn online(&self, endpoint: &str) -> bool {
        self.slots().get(endpoint).is_some_and(|slot| slot.ready)
    }

    /// The stream hub of a ready bridge. Streams open only on it, and only if the plugin
    /// announced `e2e` support.
    pub(crate) fn hub(&self, endpoint: &str) -> Option<Arc<Hub>> {
        self.slots()
            .get(endpoint)
            .filter(|slot| slot.ready)
            .map(|slot| Arc::clone(&slot.hub))
    }

    /// Live end-to-end streams of all bridges, for the operator interface.
    pub(crate) fn stream_snapshot(&self) -> Vec<StreamRow> {
        let hubs: Vec<Arc<Hub>> = self
            .slots()
            .values()
            .map(|slot| Arc::clone(&slot.hub))
            .collect();
        let mut rows: Vec<StreamRow> = hubs.iter().flat_map(|hub| hub.snapshot()).collect();
        rows.sort_by_key(|row| row.since);
        rows
    }

    pub(super) fn initialize(
        &self,
        endpoint: &str,
        version: &'static str,
        owner: [u8; 32],
        peer: SocketAddr,
    ) -> Result<Uuid, Status> {
        self.slots()
            .get_mut(endpoint)
            .ok_or(Status::ServiceUnavailable)?
            .initialize(version, owner, peer)
    }

    /// Record a desktop request on an admitted session, for monitoring.
    pub(super) fn note_request(&self, client: &Client, id: Uuid, peer: SocketAddr, activity: &str) {
        if let Some(session) = self
            .slots()
            .get_mut(&client.endpoint)
            .and_then(|slot| slot.sessions.get_mut(&id))
        {
            session.peer = peer;
            session.requests = session.requests.saturating_add(1);
            activity.clone_into(&mut session.activity);
        }
    }

    /// Live bridges and their sessions, for the operator interface.
    pub(crate) fn snapshot(&self) -> Vec<BridgeRow> {
        let slots = self.slots();
        let mut rows: Vec<_> = slots
            .iter()
            .map(|(endpoint, slot)| {
                let mut sessions: Vec<_> = slot
                    .sessions
                    .iter()
                    .filter(|(_, session)| session.last_used.elapsed() < SESSION_IDLE)
                    .map(|(id, session)| SessionRow {
                        id: *id,
                        desktop: hex::encode(session.owner),
                        peer: session.peer,
                        since: session.created,
                        last_used: session.last_used,
                        requests: session.requests,
                        activity: session.activity.clone(),
                    })
                    .collect();
                sessions.sort_by_key(|session| session.since);
                BridgeRow {
                    endpoint: endpoint.to_string(),
                    peer: slot.peer,
                    since: slot.since,
                    ready: slot.ready,
                    e2e: slot.hub.e2e(),
                    busy: slot.bridge.admission.available_permits() == 0,
                    calls: slot.calls,
                    last_call: slot.last_call.clone(),
                    sessions,
                }
            })
            .collect();
        drop(slots);
        rows.sort_by_key(|row| row.since);
        rows
    }

    pub(super) fn session(
        &self,
        endpoint: Option<&str>,
        id: Uuid,
        owner: &[u8; 32],
    ) -> Result<(Client, &'static str), Status> {
        let slots = self.slots();
        let slot = endpoint
            .map_or_else(
                || slots.values().find(|slot| slot.sessions.contains_key(&id)),
                |endpoint| slots.get(endpoint),
            )
            .ok_or(Status::NotFound)?;
        slot.session(id, owner)
    }

    /// Refresh only after admission, on the same bridge connection used for lookup.
    pub(super) fn refresh(
        &self,
        client: &Client,
        id: Uuid,
        owner: &[u8; 32],
    ) -> Result<(), Status> {
        let mut slots = self.slots();
        let session = slots
            .get_mut(&client.endpoint)
            .filter(|slot| slot.bridge.sender.same_channel(&client.sender))
            .and_then(|slot| slot.sessions.get_mut(&id))
            .filter(|session| session.valid(owner))
            .ok_or(Status::NotFound)?;
        session.last_used = Instant::now();
        Ok(())
    }

    pub(super) fn remove(&self, endpoint: &str, id: Uuid) {
        if let Some(slot) = self.slots().get_mut(endpoint) {
            slot.sessions.remove(&id);
        }
    }
}

// Dropping the upgrade callback (including failed upgrades) releases the slot.
// Each socket owns a distinct channel and session map for its entire lifetime.
struct Reservation {
    registry: Registry,
    endpoint: Arc<str>,
    hub: Arc<Hub>,
    /// Everything that goes to the plugin: legacy requests and stream frames.
    outbound: channel::Receiver<Message>,
}

impl Reservation {
    fn mark_ready(&self) {
        if let Some(slot) = self.registry.slots().get_mut(&self.endpoint) {
            slot.ready = true;
        }
    }

    /// Count a call forwarded to Eclipse, for monitoring.
    fn note_call(&self, activity: String) {
        if let Some(slot) = self.registry.slots().get_mut(&self.endpoint) {
            slot.calls = slot.calls.saturating_add(1);
            slot.last_call = Some((activity, Instant::now()));
        }
    }
}

/// A connected (or handshaking) Eclipse bridge, as shown to the operator.
pub struct BridgeRow {
    pub endpoint: String,
    pub peer: SocketAddr,
    pub since: Instant,
    pub ready: bool,
    /// The plugin announced end-to-end support (`e2e: 1`) in its hello.
    pub e2e: bool,
    /// A call is being processed by Eclipse right now.
    pub busy: bool,
    pub calls: u64,
    pub last_call: Option<(String, Instant)>,
    pub sessions: Vec<SessionRow>,
}

/// A desktop MCP session bound to a bridge, as shown to the operator.
pub struct SessionRow {
    pub id: Uuid,
    pub desktop: String,
    /// Address of the desktop's most recent request.
    pub peer: SocketAddr,
    pub since: Instant,
    pub last_used: Instant,
    pub requests: u64,
    pub activity: String,
}

/// What a call does, for monitoring: the tool name for `tools/call`, else the method.
pub fn activity(method: &str, params: &Value) -> String {
    match params["name"].as_str() {
        Some(tool) if method == "tools/call" => tool.to_owned(),
        _ => method.to_owned(),
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.registry.slots().remove(&self.endpoint);
        // Every stream of this connection ends, and its desktop is told.
        self.hub.close_all("The Eclipse bridge disconnected.");
    }
}

/// A reserved bridge slot waiting for its WebSocket upgrade to complete.
pub struct Bridge {
    reservation: Reservation,
    calls: channel::Receiver<Call>,
}

/// Validate a `/bridge` request (GET only; the caller checks the method) and
/// answer it. When the answer is `101`, the returned [`Bridge`] must be passed
/// to [`serve_upgraded`] once the response has been sent.
pub fn upgrade(
    registry: &Registry,
    headers: &Headers,
    cert: &PeerCertificate,
    peer: SocketAddr,
) -> (Reply, Option<Bridge>) {
    let accept = match handshake(headers) {
        Ok(accept) => accept,
        Err(message) => return (Reply::text(Status::BadRequest, message), None),
    };
    let (reservation, calls) =
        match registry.reserve(Arc::from(hex::encode(cert.fingerprint)), peer) {
            Ok(connection) => connection,
            Err(Status::Conflict) => {
                return (
                    Reply::text(
                        Status::Conflict,
                        "This Eclipse endpoint is already connected.",
                    ),
                    None,
                );
            }
            Err(status) => {
                return (
                    Reply::text(
                        status,
                        "The relay has reached its Eclipse connection limit.",
                    ),
                    None,
                );
            }
        };
    (switching(accept), Some(Bridge { reservation, calls }))
}

/// The `101` answer of a WebSocket upgrade with this `Sec-WebSocket-Accept` value.
pub fn switching(accept: String) -> Reply {
    Reply::from(Status::SwitchingProtocols)
        .with_header(KnownHeaderName::Connection, "upgrade")
        .with_header(KnownHeaderName::Upgrade, "websocket")
        .with_header(KnownHeaderName::SecWebsocketAccept, accept)
}

/// Validates an HTTP/1.1 WebSocket upgrade request, with the checks and
/// statuses of axum's former `WebSocketUpgrade` extractor. Returns the
/// `Sec-WebSocket-Accept` value, or the rejection.
pub fn handshake(headers: &Headers) -> Result<String, &'static str> {
    if !headers
        .token_iter(KnownHeaderName::Connection)
        .any(|token| token.eq_ignore_ascii_case("upgrade"))
    {
        return Err("Connection header did not include `upgrade`");
    }
    if !headers.eq_ignore_ascii_case(KnownHeaderName::Upgrade, "websocket") {
        return Err("`Upgrade` header did not include `websocket`");
    }
    let Some(key) = headers.get_str(KnownHeaderName::SecWebsocketKey) else {
        return Err("`Sec-WebSocket-Key` header missing");
    };
    if !headers.eq_ignore_ascii_case(KnownHeaderName::SecWebsocketVersion, "13") {
        return Err("`Sec-WebSocket-Version` header did not include `13`");
    }
    Ok(derive_accept_key(key.as_bytes()))
}

/// The server side of a WebSocket on an upgraded connection, with messages up to `limit` bytes.
pub async fn socket(mut upgrade: Upgrade, limit: usize) -> Socket {
    let config = WebSocketConfig::default()
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    let buffered = upgrade.take_buffer();
    let io = Prefixed::new(buffered, upgrade.into_transport());
    WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await
}

/// Run the bridge on an upgraded connection.
pub async fn serve_upgraded(upgrade: Upgrade, bridge: Bridge, pki: &Pki, cert: &PeerCertificate) {
    let socket = socket(upgrade, MESSAGE_LIMIT).await;
    serve(socket, bridge, pki, cert).await;
}

async fn serve(socket: Socket, bridge: Bridge, pki: &Pki, cert: &PeerCertificate) {
    let Bridge { reservation, calls } = bridge;
    serve_connected(socket, &reservation, &calls, pki, cert).await;
    // Dropping a closed channel's receiver would leave queued calls (and their
    // reply senders) alive while a client handle exists, so release them now.
    calls.close();
    while calls.try_recv().is_ok() {}
}

// One bridge connection is three futures raced in one task, and the first to end ends the
// connection:
// - the writer sends everything queued for the plugin: legacy requests, stream control frames
//   and data frames, in queue order;
// - the reader routes what the plugin sends: stream frames to the hub, legacy replies to the
//   driver, which owns the strictly one-at-a-time legacy exchange;
// - the driver runs `relay/hello`, the serialized legacy calls and the heartbeat.
async fn serve_connected(
    socket: Socket,
    reservation: &Reservation,
    calls: &channel::Receiver<Call>,
    pki: &Pki,
    cert: &PeerCertificate,
) {
    let (sink, stream) = socket.split();
    let legacy = Legacy::new();
    let connected = AtomicBool::new(false);
    future::race(
        write_loop(sink, &reservation.outbound),
        future::race(
            read_loop(stream, &reservation.hub, &legacy),
            drive(reservation, calls, &legacy, pki, cert, &connected),
        ),
    )
    .await;
    if connected.load(Ordering::Acquire) {
        tracing::info!(endpoint = %reservation.endpoint, "Eclipse bridge disconnected.");
    }
}

/// The legacy JSON-RPC exchange, shared by the reader (which routes replies) and the driver
/// (which sends one request at a time).
struct Legacy {
    replies_in: channel::Sender<String>,
    replies: channel::Receiver<String>,
    /// A request was sent and its reply has not been taken yet.
    awaiting: AtomicBool,
}

impl Legacy {
    fn new() -> Self {
        let (replies_in, replies) = channel::bounded(1);
        Self {
            replies_in,
            replies,
            awaiting: AtomicBool::new(false),
        }
    }
}

async fn write_loop(mut sink: SocketSender, outbound: &channel::Receiver<Message>) {
    while let Ok(message) = outbound.recv().await {
        if sink.send(message).await.is_err() {
            break;
        }
    }
}

/// Ends (and so ends the bridge) when the plugin closes the socket or sends something this
/// relay does not accept, such as a legacy reply nobody asked for.
async fn read_loop(mut stream: SocketReceiver, hub: &Hub, legacy: &Legacy) {
    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Ping(payload) => {
                // Only a reader sees the ping, so the reader answers it.
                let _ = hub.try_queue(Message::Pong(payload));
            }
            Message::Pong(_) => {}
            Message::Binary(frame) if hub.e2e() => {
                if !hub.on_plugin_data(&frame) {
                    return;
                }
            }
            Message::Text(text) => {
                // A stream control frame has a top-level `type`; a JSON-RPC reply never does.
                if hub.e2e()
                    && text.len() <= MAX_CONTROL_BYTES
                    && let Ok(control) = Control::decode(&text)
                {
                    hub.on_plugin_control(control);
                } else if !legacy.awaiting.load(Ordering::Acquire)
                    || legacy.replies_in.try_send(text.to_string()).is_err()
                {
                    return;
                }
            }
            _ => return,
        }
    }
}

enum Event {
    Call(Call),
    Heartbeat,
}

/// `relay/hello`. `false` if the plugin does not confirm package policies.
async fn greet(hub: &Hub, legacy: &Legacy) -> bool {
    let hello = exchange(
        hub,
        legacy,
        1,
        "relay/hello",
        // Version 2: every bridge call carries `relayAllowedTools` next to the package scopes.
        json!({"policyVersion": 2}),
        Instant::now() + HEARTBEAT,
    )
    .await;
    let capabilities = match hello {
        Ok(Ok(capabilities)) if matches!(capabilities["policyVersion"].as_u64(), Some(1 | 2)) => {
            capabilities
        }
        _ => {
            tracing::warn!(
                "Eclipse did not confirm support for package policies. Upgrade the plugin and reconnect."
            );
            return false;
        }
    };
    // A plugin that announces `e2e: 1` also accepts end-to-end streams on this connection.
    if capabilities["e2e"].as_u64() == Some(1) {
        hub.set_e2e();
    }
    true
}

async fn drive(
    reservation: &Reservation,
    calls: &channel::Receiver<Call>,
    legacy: &Legacy,
    pki: &Pki,
    cert: &PeerCertificate,
    connected: &AtomicBool,
) {
    let hub = &*reservation.hub;
    if !greet(hub, legacy).await {
        return;
    }
    let mut id = 1;
    reservation.mark_ready();
    connected.store(true, Ordering::Release);
    tracing::info!(endpoint = %reservation.endpoint, e2e = hub.e2e(), "Eclipse bridge connected.");
    loop {
        id += 1;
        // `race` polls its futures fairly, like the former `select!`.
        let event = future::race(
            async {
                match calls.recv().await {
                    Ok(call) => Event::Call(call),
                    // No sender is left: only the socket and the heartbeat can wake us.
                    Err(_) => future::pending().await,
                }
            },
            async {
                Timer::after(HEARTBEAT).await;
                Event::Heartbeat
            },
        )
        .await;
        match event {
            Event::Call(call) => {
                if !pki.authorize(&cert.der, "eclipse") {
                    let _ = call.reply.try_send(Err(error(
                        -32_000,
                        "The Eclipse certificate has been revoked.",
                    )));
                    break;
                }
                if call.reply.is_closed() || call.deadline <= Instant::now() {
                    continue;
                }
                reservation.note_call(activity(call.method, &call.params));
                match exchange(hub, legacy, id, call.method, call.params, call.deadline).await {
                    Ok(result) => {
                        let _ = call.reply.try_send(result);
                    }
                    Err(()) => break,
                }
            }
            Event::Heartbeat => {
                if !pki.authorize(&cert.der, "eclipse")
                    || !matches!(
                        exchange(
                            hub,
                            legacy,
                            id,
                            "ping",
                            Value::Null,
                            Instant::now() + HEARTBEAT
                        )
                        .await,
                        Ok(Ok(_))
                    )
                {
                    break;
                }
            }
        }
    }
}

// Serializing ADT calls also bounds in-flight work. A lost or invalid reply
// closes this bridge so a later call can never consume an earlier reply. Stream frames
// share the connection but never take part in this exchange.
async fn exchange(
    hub: &Hub,
    legacy: &Legacy,
    id: u64,
    method: &str,
    params: Value,
    deadline: Instant,
) -> Result<Outcome, ()> {
    let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        request["params"] = params;
    }
    // Set before sending: the reader accepts a legacy reply only while one is expected.
    legacy.awaiting.store(true, Ordering::Release);
    let outcome = timeout(deadline.saturating_duration_since(Instant::now()), async {
        if !hub
            .send_message(Message::Text(request.to_string().into()))
            .await
        {
            return Err(());
        }
        let text = legacy.replies.recv().await.map_err(|_| ())?;
        decode_reply(&text, id)
    })
    .await;
    legacy.awaiting.store(false, Ordering::Release);
    outcome.map_err(|_| ())?
}

fn decode_reply(text: &str, id: u64) -> Result<Outcome, ()> {
    let mut reply: Value = serde_json::from_str(text).map_err(|_| ())?;
    if reply["jsonrpc"] != "2.0"
        || reply["id"].as_u64() != Some(id)
        || reply.get("method").is_some()
    {
        return Err(());
    }
    match (reply.get("result"), reply.get("error")) {
        (Some(result), None) if result.is_object() => Ok(Ok(reply["result"].take())),
        (None, Some(err)) if err["code"].is_i64() && err["message"].is_string() => {
            Ok(Err(reply["error"].take()))
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        4000,
    ));

    #[test]
    fn snapshot_reports_bridges_sessions_and_their_activity() {
        let registry = Registry::default();
        let (bridge, _calls) = registry.reserve("endpoint".into(), PEER).unwrap();
        let rows = registry.snapshot();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].ready && rows[0].sessions.is_empty() && rows[0].calls == 0);
        bridge.mark_ready();
        let desktop = SocketAddr::from(([10, 0, 0, 7], 5000));
        let id = registry
            .initialize("endpoint", "test", [3; 32], desktop)
            .unwrap();
        let (client, _) = registry.session(None, id, &[3; 32]).unwrap();
        registry.note_request(&client, id, desktop, "sap_search_object");
        bridge.note_call(activity(
            "tools/call",
            &json!({"name": "sap_search_object", "arguments": {}}),
        ));
        let rows = registry.snapshot();
        let row = &rows[0];
        assert!(row.ready && !row.busy);
        assert_eq!(
            (row.endpoint.as_str(), row.peer, row.calls),
            ("endpoint", PEER, 1)
        );
        assert_eq!(row.last_call.as_ref().unwrap().0, "sap_search_object");
        let session = &row.sessions[0];
        assert_eq!(session.id, id);
        assert_eq!(session.desktop, hex::encode([3; 32]));
        assert_eq!(session.peer, desktop);
        assert_eq!(session.requests, 2);
        assert_eq!(session.activity, "sap_search_object");
        drop(bridge);
        assert!(registry.snapshot().is_empty());
        drop(registry);
    }

    #[test]
    fn sessions_belong_to_one_desktop_and_one_bridge_connection() {
        let registry = Registry::default();
        let (first, first_calls) = registry.reserve("first".into(), PEER).unwrap();
        let (other, _other_calls) = registry.reserve("other".into(), PEER).unwrap();
        assert!(matches!(
            registry.reserve("first".into(), PEER),
            Err(Status::Conflict)
        ));
        assert_eq!(
            registry.initialize("first", "test", [1; 32], PEER),
            Err(Status::ServiceUnavailable)
        );
        first.mark_ready();
        other.mark_ready();
        assert!(registry.online("first"));
        let id = registry.initialize("first", "test", [1; 32], PEER).unwrap();
        let other_id = registry.initialize("other", "test", [1; 32], PEER).unwrap();
        assert!(matches!(
            registry.session(None, id, &[2; 32]),
            Err(Status::NotFound)
        ));
        assert!(matches!(
            registry.session(Some("other"), id, &[1; 32]),
            Err(Status::NotFound)
        ));
        let (old_client, _) = registry.session(None, id, &[1; 32]).unwrap();
        assert_eq!(old_client.endpoint.as_ref(), "first");
        let last_used = registry.slots()["first"].sessions[&id].last_used;
        assert!(registry.session(None, id, &[1; 32]).is_ok());
        assert_eq!(registry.slots()["first"].sessions[&id].last_used, last_used);
        assert_eq!(
            registry.refresh(&old_client, id, &[2; 32]),
            Err(Status::NotFound)
        );
        assert!(registry.refresh(&old_client, id, &[1; 32]).is_ok());
        drop(first_calls);
        drop(first);
        assert!(!registry.online("first"));
        let (second, _second_calls) = registry.reserve("first".into(), PEER).unwrap();
        second.mark_ready();
        assert!(old_client.sender.is_closed());
        assert_eq!(
            registry.refresh(&old_client, id, &[1; 32]),
            Err(Status::NotFound)
        );
        assert!(matches!(
            registry.session(None, id, &[1; 32]),
            Err(Status::NotFound)
        ));
        assert!(registry.session(Some("other"), other_id, &[1; 32]).is_ok());
        drop(registry);
    }

    #[test]
    fn bridge_limit_includes_pending_handshakes_and_releases_on_disconnect() {
        let registry = Registry::default();
        let mut connections: Vec<_> = (0..MAX_BRIDGES)
            .map(|n| registry.reserve(n.to_string().into(), PEER).unwrap())
            .collect();
        connections[0].0.mark_ready();
        let id = registry.initialize("0", "test", [1; 32], PEER).unwrap();
        assert!(matches!(
            registry.reserve("0".into(), PEER),
            Err(Status::Conflict)
        ));
        assert!(matches!(
            registry.reserve("overflow".into(), PEER),
            Err(Status::TooManyRequests)
        ));
        drop(connections.pop());
        let _replacement = registry.reserve("overflow".into(), PEER).unwrap();
        assert!(registry.session(Some("0"), id, &[1; 32]).is_ok());
        drop(registry);
    }

    #[test]
    fn streams_use_the_hub_of_a_ready_bridge_and_end_with_its_connection() {
        let registry = Registry::default();
        let (bridge, _calls) = registry.reserve("endpoint".into(), PEER).unwrap();
        assert!(registry.hub("endpoint").is_none());
        bridge.mark_ready();
        let hub = registry.hub("endpoint").unwrap();
        assert_eq!(hub.endpoint(), "endpoint");
        assert!(!hub.e2e());
        assert!(registry.hub("other").is_none());
        assert!(registry.stream_snapshot().is_empty());
        hub.set_e2e();
        // A frame for a stream nobody opened is ignored; a malformed data frame ends the bridge.
        assert!(hub.on_plugin_data(&crate::tunnel_proto::encode_data(9, &[1]).unwrap()));
        assert!(!hub.on_plugin_data(&[0, 0, 0]));
        drop(bridge);
        assert!(registry.hub("endpoint").is_none());
        drop(registry);
    }

    #[test]
    fn replies_must_match_the_active_request() {
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(decode_reply(reply, 1), Ok(Ok(json!({}))));
        assert_eq!(decode_reply(reply, 2), Err(()));
        let ambiguous =
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"failure"}}"#;
        assert_eq!(decode_reply(ambiguous, 1), Err(()));
    }
}
