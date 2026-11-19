use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use crate::{security::Pki, transport::PeerCertificate};
use axum::{
    extract::{
        WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{Instant as Deadline, timeout_at},
};
use uuid::Uuid;

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
    reply: oneshot::Sender<Outcome>,
    deadline: Deadline,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub struct Client {
    pub(super) endpoint: Arc<str>,
    sender: mpsc::Sender<Call>,
    admission: Arc<Semaphore>,
}

impl Client {
    fn channel(endpoint: Arc<str>) -> (Self, mpsc::Receiver<Call>) {
        let (sender, receiver) = mpsc::channel(1);
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
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (client, mut receiver) = Self::channel(Arc::from("test"));
        let task = tokio::spawn(async move {
            let call = receiver.recv().await.unwrap();
            assert_eq!(call.method, method);
            assert_eq!(call.params, params);
            call.reply.send(Ok(result)).unwrap();
        });
        (client, task)
    }

    pub(super) async fn call(&self, method: &'static str, params: Value) -> Outcome {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| error(-32_000, "The Eclipse bridge is busy."))?;
        let (reply, result) = oneshot::channel();
        let deadline = Deadline::now() + CALL_LIMIT;
        self.sender
            .try_send(Call {
                method,
                params,
                reply,
                deadline,
                _permit: permit,
            })
            .map_err(|_| disconnected())?;
        timeout_at(deadline, result)
            .await
            .map_err(|_| lost_reply(method))?
            .map_err(|_| lost_reply(method))?
    }
}

struct Session {
    owner: [u8; 32],
    last_used: Instant,
    version: &'static str,
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
}

impl Slot {
    fn initialize(&mut self, version: &'static str, owner: [u8; 32]) -> Result<Uuid, StatusCode> {
        if !self.ready {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < SESSION_IDLE);
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let id = Uuid::new_v4();
        self.sessions.insert(
            id,
            Session {
                owner,
                last_used: Instant::now(),
                version,
            },
        );
        Ok(id)
    }

    fn session(&self, id: Uuid, owner: &[u8; 32]) -> Result<(Client, &'static str), StatusCode> {
        let session = self
            .sessions
            .get(&id)
            .filter(|s| s.valid(owner))
            .ok_or(StatusCode::NOT_FOUND)?;
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
    ) -> Result<(Reservation, mpsc::Receiver<Call>), StatusCode> {
        let mut slots = self.slots();
        let full = slots.len() >= MAX_BRIDGES;
        let std::collections::hash_map::Entry::Vacant(slot) = slots.entry(Arc::clone(&endpoint))
        else {
            return Err(StatusCode::CONFLICT);
        };
        if full {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let (bridge, receiver) = Client::channel(Arc::clone(&endpoint));
        slot.insert(Slot {
            bridge,
            ready: false,
            sessions: HashMap::new(),
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
    ) -> Result<Uuid, StatusCode> {
        self.slots()
            .get_mut(endpoint)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .initialize(version, owner)
    }

    pub(super) fn session(
        &self,
        endpoint: Option<&str>,
        id: Uuid,
        owner: &[u8; 32],
    ) -> Result<(Client, &'static str), StatusCode> {
        let slots = self.slots();
        let slot = endpoint
            .map_or_else(
                || slots.values().find(|slot| slot.sessions.contains_key(&id)),
                |endpoint| slots.get(endpoint),
            )
            .ok_or(StatusCode::NOT_FOUND)?;
        slot.session(id, owner)
    }

    /// Refresh only after admission, on the same bridge connection used for lookup.
    pub(super) fn refresh(
        &self,
        client: &Client,
        id: Uuid,
        owner: &[u8; 32],
    ) -> Result<(), StatusCode> {
        let mut slots = self.slots();
        let session = slots
            .get_mut(&client.endpoint)
            .filter(|slot| slot.bridge.sender.same_channel(&client.sender))
            .and_then(|slot| slot.sessions.get_mut(&id))
            .filter(|session| session.valid(owner))
            .ok_or(StatusCode::NOT_FOUND)?;
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
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.registry.slots().remove(&self.endpoint);
    }
}

pub fn upgrade(
    registry: &Registry,
    pki: Arc<Pki>,
    cert: PeerCertificate,
    ws: WebSocketUpgrade,
) -> Response {
    let (reservation, calls) = match registry.reserve(Arc::from(hex::encode(cert.fingerprint))) {
        Ok(connection) => connection,
        Err(StatusCode::CONFLICT) => {
            return (
                StatusCode::CONFLICT,
                "This Eclipse endpoint is already connected.",
            )
                .into_response();
        }
        Err(status) => {
            return (
                status,
                "The relay has reached its Eclipse connection limit.",
            )
                .into_response();
        }
    };
    ws.max_message_size(8 * 1024 * 1024)
        .max_frame_size(8 * 1024 * 1024)
        .on_upgrade(move |socket| serve(socket, reservation, calls, pki, cert))
}

async fn serve(
    mut socket: WebSocket,
    reservation: Reservation,
    mut calls: mpsc::Receiver<Call>,
    pki: Arc<Pki>,
    cert: PeerCertificate,
) {
    let mut id = 1;
    let hello = exchange(
        &mut socket,
        id,
        "relay/hello",
        Value::Null,
        Deadline::now() + HEARTBEAT,
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
        tokio::select! {
            message = socket.recv() => {
                if !matches!(message, Some(Ok(Message::Ping(_) | Message::Pong(_)))) {
                    break;
                }
            }
            Some(call) = calls.recv() => {
                if !pki.authorize(&cert.der, "eclipse") {
                    let _ = call.reply.send(Err(error(-32_000, "The Eclipse certificate has been revoked.")));
                    break;
                }
                if call.reply.is_closed() || call.deadline <= Deadline::now() {
                    continue;
                }
                match exchange(&mut socket, id, call.method, call.params, call.deadline).await {
                    Ok(result) => { let _ = call.reply.send(result); }
                    Err(()) => break,
                }
            }
            () = tokio::time::sleep(HEARTBEAT) => {
                if !pki.authorize(&cert.der, "eclipse") ||
                    !matches!(exchange(&mut socket, id, "ping", Value::Null, Deadline::now() + HEARTBEAT).await, Ok(Ok(_))) {
                    break;
                }
            }
        }
    }
    tracing::info!(endpoint = %reservation.endpoint, "Eclipse bridge disconnected.");
}

// Serializing ADT calls also bounds in-flight work. A lost or invalid reply
// closes this bridge so a later call can never consume an earlier reply.
async fn exchange(
    socket: &mut WebSocket,
    id: u64,
    method: &str,
    params: Value,
    deadline: Deadline,
) -> Result<Outcome, ()> {
    let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        request["params"] = params;
    }
    timeout_at(deadline, async {
        socket
            .send(Message::Text(request.to_string().into()))
            .await
            .map_err(|_| ())?;
        loop {
            match socket.recv().await {
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

    #[test]
    fn sessions_belong_to_one_desktop_and_one_bridge_connection() {
        let registry = Registry::default();
        let (first, first_calls) = registry.reserve("first".into()).unwrap();
        let (other, _other_calls) = registry.reserve("other".into()).unwrap();
        assert!(matches!(
            registry.reserve("first".into()),
            Err(StatusCode::CONFLICT)
        ));
        assert_eq!(
            registry.initialize("first", "test", [1; 32]),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        first.mark_ready();
        other.mark_ready();
        assert!(registry.online("first"));
        let id = registry.initialize("first", "test", [1; 32]).unwrap();
        let other_id = registry.initialize("other", "test", [1; 32]).unwrap();
        assert!(matches!(
            registry.session(None, id, &[2; 32]),
            Err(StatusCode::NOT_FOUND)
        ));
        assert!(matches!(
            registry.session(Some("other"), id, &[1; 32]),
            Err(StatusCode::NOT_FOUND)
        ));
        let (old_client, _) = registry.session(None, id, &[1; 32]).unwrap();
        assert_eq!(old_client.endpoint.as_ref(), "first");
        let last_used = registry.slots()["first"].sessions[&id].last_used;
        assert!(registry.session(None, id, &[1; 32]).is_ok());
        assert_eq!(registry.slots()["first"].sessions[&id].last_used, last_used);
        assert_eq!(
            registry.refresh(&old_client, id, &[2; 32]),
            Err(StatusCode::NOT_FOUND)
        );
        assert!(registry.refresh(&old_client, id, &[1; 32]).is_ok());
        drop(first_calls);
        drop(first);
        assert!(!registry.online("first"));
        let (second, _second_calls) = registry.reserve("first".into()).unwrap();
        second.mark_ready();
        assert!(old_client.sender.is_closed());
        assert_eq!(
            registry.refresh(&old_client, id, &[1; 32]),
            Err(StatusCode::NOT_FOUND)
        );
        assert!(matches!(
            registry.session(None, id, &[1; 32]),
            Err(StatusCode::NOT_FOUND)
        ));
        assert!(registry.session(Some("other"), other_id, &[1; 32]).is_ok());
        drop(registry);
    }

    #[test]
    fn bridge_limit_includes_pending_handshakes_and_releases_on_disconnect() {
        let registry = Registry::default();
        let mut connections: Vec<_> = (0..MAX_BRIDGES)
            .map(|n| registry.reserve(n.to_string().into()).unwrap())
            .collect();
        connections[0].0.mark_ready();
        let id = registry.initialize("0", "test", [1; 32]).unwrap();
        assert!(matches!(
            registry.reserve("0".into()),
            Err(StatusCode::CONFLICT)
        ));
        assert!(matches!(
            registry.reserve("overflow".into()),
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        drop(connections.pop());
        let _replacement = registry.reserve("overflow".into()).unwrap();
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
