use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use crate::{
    rt::timeout,
    security::Pki,
    transport::{PeerCertificate, Transport, Upgrade},
    web::{Prefixed, Reply},
};
use async_tungstenite::{
    WebSocketStream,
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

type Socket = WebSocketStream<Prefixed<Transport>>;

const CALL_LIMIT: Duration = Duration::from_secs(600);
const HEARTBEAT: Duration = Duration::from_secs(20);
const SESSION_IDLE: Duration = Duration::from_hours(8);
const MAX_SESSIONS: usize = 128;
// WebSocket upgrades outlive the HTTP connection permit used by the transport.
const MAX_BRIDGES: usize = 128;

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
        slot.insert(Slot {
            bridge,
            ready: false,
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
            },
            receiver,
        ))
    }

    pub(super) fn online(&self, endpoint: &str) -> bool {
        self.slots().get(endpoint).is_some_and(|slot| slot.ready)
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
pub(crate) fn activity(method: &str, params: &Value) -> String {
    match params["name"].as_str() {
        Some(tool) if method == "tools/call" => tool.to_owned(),
        _ => method.to_owned(),
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.registry.slots().remove(&self.endpoint);
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
    let reply = Reply::from(Status::SwitchingProtocols)
        .with_header(KnownHeaderName::Connection, "upgrade")
        .with_header(KnownHeaderName::Upgrade, "websocket")
        .with_header(KnownHeaderName::SecWebsocketAccept, accept);
    (reply, Some(Bridge { reservation, calls }))
}

/// Validates an HTTP/1.1 WebSocket upgrade request, with the checks and
/// statuses of axum's former `WebSocketUpgrade` extractor. Returns the
/// `Sec-WebSocket-Accept` value, or the rejection.
fn handshake(headers: &Headers) -> Result<String, &'static str> {
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

/// Run the bridge on an upgraded connection.
pub async fn serve_upgraded(
    mut upgrade: Upgrade,
    bridge: Bridge,
    pki: &Pki,
    cert: &PeerCertificate,
) {
    let config = WebSocketConfig::default()
        .max_message_size(Some(8 * 1024 * 1024))
        .max_frame_size(Some(8 * 1024 * 1024));
    let buffered = upgrade.take_buffer();
    let io = Prefixed::new(buffered, upgrade.into_transport());
    let socket = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
    serve(socket, bridge, pki, cert).await;
}

async fn serve(mut socket: Socket, bridge: Bridge, pki: &Pki, cert: &PeerCertificate) {
    let Bridge { reservation, calls } = bridge;
    serve_connected(&mut socket, &reservation, &calls, pki, cert).await;
    // Dropping a closed channel's receiver would leave queued calls (and their
    // reply senders) alive while a client handle exists, so release them now.
    calls.close();
    while calls.try_recv().is_ok() {}
}

async fn serve_connected(
    socket: &mut Socket,
    reservation: &Reservation,
    calls: &channel::Receiver<Call>,
    pki: &Pki,
    cert: &PeerCertificate,
) {
    let mut id = 1;
    let hello = exchange(
        socket,
        id,
        "relay/hello",
        Value::Null,
        Instant::now() + HEARTBEAT,
    )
    .await;
    if !matches!(hello, Ok(Ok(ref capabilities)) if capabilities["policyVersion"].as_u64() == Some(1))
    {
        tracing::warn!(
            "Eclipse did not confirm support for package policies. Upgrade the plugin and reconnect."
        );
        return;
    }
    reservation.mark_ready();
    tracing::info!(endpoint = %reservation.endpoint, "Eclipse bridge connected.");
    loop {
        id += 1;
        // `race` polls its futures fairly, like the former `select!`.
        let event = future::race(
            async { Event::Socket(socket.next().await) },
            future::race(
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
            ),
        )
        .await;
        match event {
            Event::Socket(message) => {
                if !matches!(message, Some(Ok(Message::Ping(_) | Message::Pong(_)))) {
                    break;
                }
            }
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
                match exchange(socket, id, call.method, call.params, call.deadline).await {
                    Ok(result) => {
                        let _ = call.reply.try_send(result);
                    }
                    Err(()) => break,
                }
            }
            Event::Heartbeat => {
                if !pki.authorize(&cert.der, "eclipse")
                    || !matches!(
                        exchange(socket, id, "ping", Value::Null, Instant::now() + HEARTBEAT).await,
                        Ok(Ok(_))
                    )
                {
                    break;
                }
            }
        }
    }
    tracing::info!(endpoint = %reservation.endpoint, "Eclipse bridge disconnected.");
}

enum Event {
    Socket(Option<Result<Message, async_tungstenite::tungstenite::Error>>),
    Call(Call),
    Heartbeat,
}

// Serializing ADT calls also bounds in-flight work. A lost or invalid reply
// closes this bridge so a later call can never consume an earlier reply.
async fn exchange(
    socket: &mut Socket,
    id: u64,
    method: &str,
    params: Value,
    deadline: Instant,
) -> Result<Outcome, ()> {
    let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        request["params"] = params;
    }
    timeout(deadline.saturating_duration_since(Instant::now()), async {
        socket
            .send(Message::Text(request.to_string().into()))
            .await
            .map_err(|_| ())?;
        loop {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => return decode_reply(&text, id),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => return Err(()),
            }
        }
    })
    .await
    .map_err(|_| ())?
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
    fn replies_must_match_the_active_request() {
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(decode_reply(reply, 1), Ok(Ok(json!({}))));
        assert_eq!(decode_reply(reply, 2), Err(()));
        let ambiguous =
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"failure"}}"#;
        assert_eq!(decode_reply(ambiguous, 1), Err(()));
    }
}
