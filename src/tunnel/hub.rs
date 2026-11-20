//! The streams of one Eclipse bridge (`docs/plan-e2e-envelope.md` §3, "Relay").
//!
//! The hub is the table that connects the desktop tunnels to the bridge connection: it
//! allocates the bridge-side stream IDs, translates them, enforces the stream limits,
//! holds each stream's admissions and policy fingerprint, and records its statistics.
//! All of its methods are synchronous and never hold the lock across an await point; the
//! callers send the frames the methods ask for.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_tungstenite::tungstenite::Message;
use smol::channel;
use uuid::Uuid;

use super::admission::Admissions;
use crate::{
    rt,
    tunnel_proto::{
        Control, Envelope, HANDSHAKE_DEADLINE, MAX_STREAMS_PER_BRIDGE, MAX_STREAMS_PER_DESKTOP,
        RelayPolicy, Status, close, decode_data, encode_data,
    },
};

/// Streams without traffic for this long are closed, as MCP sessions were.
pub(super) const STREAM_IDLE: Duration = Duration::from_hours(8);
/// Close reason when a stream's grant or policy changed after it was opened.
pub(super) const ACCESS_CHANGED: &str = close::ACCESS_CHANGED;
/// Longest close reason forwarded from a peer, in characters.
const MAX_REASON_CHARS: usize = 200;

/// A control frame as a WebSocket text message, or `None` if it is too large.
pub(super) fn control_message(control: &Control) -> Option<Message> {
    control.encode().ok().map(|text| Message::Text(text.into()))
}

/// A data frame as a WebSocket binary message, or `None` if the payload is too large.
pub(super) fn data_message(stream: u32, payload: &[u8]) -> Option<Message> {
    encode_data(stream, payload)
        .ok()
        .map(|frame| Message::Binary(frame.into()))
}

/// A peer-supplied close reason, shortened so that it cannot grow a frame.
pub(super) fn plain_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

/// The queue of messages for one desktop tunnel. It is bounded: a desktop that does not
/// read loses its stream instead of making the relay buffer without limit.
#[derive(Clone)]
pub struct Outbox(channel::Sender<Message>);

impl Outbox {
    pub(super) fn channel(capacity: usize) -> (Self, channel::Receiver<Message>) {
        let (sender, receiver) = channel::bounded(capacity);
        (Self(sender), receiver)
    }

    /// Queues `message` unless the queue is full or closed.
    pub(super) fn push(&self, message: Message) -> bool {
        self.0.try_send(message).is_ok()
    }

    pub(super) fn push_control(&self, control: &Control) -> bool {
        control_message(control).is_some_and(|message| self.push(message))
    }
}

/// What the relay measures about one stream, from clear-text frames only.
#[derive(Default)]
struct Stats {
    requests: u64,
    last_method: String,
    last_tool: Option<String>,
    last_status: Option<Status>,
    /// Data bytes received from the desktop.
    bytes_in: u64,
    /// Data bytes sent to the desktop.
    bytes_out: u64,
    last_response: Option<Duration>,
}

struct Stream {
    uuid: Uuid,
    owner: [u8; 32],
    label: Option<String>,
    outbox: Outbox,
    client_id: u32,
    tunnel: u64,
    peer: SocketAddr,
    /// The effective policy and grant when the stream opened, re-checked on every admission.
    policy: RelayPolicy,
    admissions: Admissions,
    /// Sent requests that expect a response: `seq` and the time of their admission.
    awaiting: VecDeque<(u64, Instant)>,
    opened: Instant,
    last_active: Instant,
    /// The first `Admit` arrived, so the inner handshake is done.
    handshaken: bool,
    stats: Stats,
}

struct Inner {
    closed: bool,
    next: u32,
    streams: HashMap<u32, Stream>,
}

impl Inner {
    /// A bridge-side ID that no live stream uses. There are fewer streams than IDs.
    fn allocate(&mut self) -> u32 {
        loop {
            self.next = if self.next == u32::MAX {
                1
            } else {
                self.next + 1
            };
            if !self.streams.contains_key(&self.next) {
                return self.next;
            }
        }
    }
}

/// A stream a desktop asks to open.
pub(super) struct NewStream {
    pub(super) owner: [u8; 32],
    pub(super) label: Option<String>,
    pub(super) outbox: Outbox,
    pub(super) client_id: u32,
    pub(super) tunnel: u64,
    pub(super) peer: SocketAddr,
    pub(super) policy: RelayPolicy,
}

/// The result of an `Admit`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Admit {
    Admitted,
    Denied(&'static str),
    Close(&'static str),
    Unknown,
}

/// The result of a `Request`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Forward {
    /// Forward it with this policy attached.
    Send(RelayPolicy),
    Close(&'static str),
    Unknown,
}

/// Where a frame from the plugin goes.
pub(super) enum Toward {
    Client {
        outbox: Outbox,
        client_id: u32,
    },
    /// The plugin broke the protocol on this stream.
    Violation,
    Unknown,
}

/// A stream that was taken out of the table.
pub(super) struct Removed {
    pub(super) outbox: Outbox,
    pub(super) client_id: u32,
    pub(super) owner: [u8; 32],
    pub(super) requests: u64,
}

/// One stream as shown to the operator.
pub struct StreamRow {
    pub id: Uuid,
    pub endpoint: String,
    pub desktop: String,
    pub label: Option<String>,
    /// Address of the desktop's tunnel.
    pub peer: SocketAddr,
    pub since: Instant,
    pub last_active: Instant,
    /// The inner handshake completed (the desktop sent its first `Admit`).
    pub handshaken: bool,
    pub requests: u64,
    pub last_method: String,
    pub last_tool: Option<String>,
    pub last_status: Option<Status>,
    /// Data bytes the desktop sent.
    pub bytes_in: u64,
    /// Data bytes sent to the desktop.
    pub bytes_out: u64,
    /// Admit-to-response time of the last response, measured by the relay.
    pub last_response: Option<Duration>,
}

pub struct Hub {
    endpoint: Arc<str>,
    to_bridge: channel::Sender<Message>,
    e2e: AtomicBool,
    inner: Mutex<Inner>,
}

impl Hub {
    pub(crate) fn new(endpoint: Arc<str>, to_bridge: channel::Sender<Message>) -> Self {
        Self {
            endpoint,
            to_bridge,
            e2e: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                closed: false,
                next: 0,
                streams: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The plugin announced `e2e: 1` in its `relay/hello` reply.
    pub(crate) fn set_e2e(&self) {
        self.e2e.store(true, Ordering::Release);
    }

    pub(crate) fn e2e(&self) -> bool {
        self.e2e.load(Ordering::Acquire)
    }

    /// Whether the bridge still serves this hub.
    #[cfg(test)]
    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Whether the stream still exists.
    pub(super) fn contains(&self, id: u32) -> bool {
        self.lock().streams.contains_key(&id)
    }

    /// Queues a message for the plugin without waiting.
    pub(crate) fn try_queue(&self, message: Message) -> bool {
        self.to_bridge.try_send(message).is_ok()
    }

    /// Queues a message for the plugin and waits for room in the bridge's queue.
    pub(crate) async fn send_message(&self, message: Message) -> bool {
        self.to_bridge.send(message).await.is_ok()
    }

    pub(super) async fn send(&self, control: &Control) -> bool {
        match control_message(control) {
            Some(message) => self.send_message(message).await,
            None => false,
        }
    }

    pub(super) async fn send_data(&self, stream: u32, payload: &[u8]) -> bool {
        match data_message(stream, payload) {
            Some(message) => self.send_message(message).await,
            None => false,
        }
    }

    /// Tells the plugin a stream ended, without ever waiting: the reader of the bridge must
    /// not block on the bridge's own queue.
    fn notify_close(&self, stream: u32, reason: &str) {
        let Some(message) = control_message(&Control::Close {
            stream,
            reason: plain_reason(reason),
        }) else {
            return;
        };
        if let Err(channel::TrySendError::Full(message)) = self.to_bridge.try_send(message) {
            let sender = self.to_bridge.clone();
            rt::spawn(async move {
                let _ = sender.send(message).await;
            })
            .detach();
        }
    }

    /// Registers a stream and returns its bridge-side ID.
    ///
    /// # Errors
    /// A plain reason when the plugin has no `e2e` support, the bridge is gone, or a limit
    /// (per bridge, or per desktop on this endpoint) is reached.
    pub(super) fn open(&self, new: NewStream) -> Result<u32, &'static str> {
        if !self.e2e() {
            return Err("The Eclipse plugin does not support end-to-end streams.");
        }
        let mut inner = self.lock();
        if inner.closed {
            return Err(close::BRIDGE_GONE);
        }
        if inner.streams.len() >= MAX_STREAMS_PER_BRIDGE {
            return Err("This Eclipse endpoint has reached its stream limit.");
        }
        let owned = inner
            .streams
            .values()
            .filter(|stream| stream.owner == new.owner)
            .count();
        if owned >= MAX_STREAMS_PER_DESKTOP {
            return Err("This desktop has reached its stream limit for this endpoint.");
        }
        let id = inner.allocate();
        let now = Instant::now();
        inner.streams.insert(
            id,
            Stream {
                uuid: Uuid::new_v4(),
                owner: new.owner,
                label: new.label,
                outbox: new.outbox,
                client_id: new.client_id,
                tunnel: new.tunnel,
                peer: new.peer,
                policy: new.policy,
                admissions: Admissions::default(),
                awaiting: VecDeque::new(),
                opened: now,
                last_active: now,
                handshaken: false,
                stats: Stats::default(),
            },
        );
        drop(inner);
        Ok(id)
    }

    /// Takes a stream out of the table. The caller notifies both sides.
    pub(super) fn remove(&self, id: u32) -> Option<Removed> {
        self.lock().streams.remove(&id).map(|stream| Removed {
            outbox: stream.outbox,
            client_id: stream.client_id,
            owner: stream.owner,
            requests: stream.stats.requests,
        })
    }

    /// Checks an `Admit` against the current policy and the stream's admission state.
    ///
    /// A stream whose policy fingerprint differs from `current` is closed, never answered.
    pub(super) fn admit(
        &self,
        id: u32,
        envelope: &Envelope,
        current: &RelayPolicy,
        now: Instant,
    ) -> Admit {
        let mut inner = self.lock();
        let Some(stream) = inner.streams.get_mut(&id) else {
            return Admit::Unknown;
        };
        if stream.policy != *current {
            return Admit::Close(ACCESS_CHANGED);
        }
        stream.handshaken = true;
        stream.last_active = now;
        let outcome = match stream.admissions.admit(envelope, current, now) {
            Ok(()) => Admit::Admitted,
            Err(message) => {
                stream.stats.last_status = Some(Status::Denied);
                stream.stats.last_method.clone_from(&envelope.method);
                stream.stats.last_tool.clone_from(&envelope.tool);
                Admit::Denied(message)
            }
        };
        drop(inner);
        outcome
    }

    /// Checks that a `Request` carries the admitted envelope, and returns what to forward.
    pub(super) fn request(&self, id: u32, envelope: &Envelope, now: Instant) -> Forward {
        let mut inner = self.lock();
        let Some(stream) = inner.streams.get_mut(&id) else {
            return Forward::Unknown;
        };
        let forward = match stream.admissions.take_request(envelope, now) {
            Ok(admitted) => {
                stream.last_active = now;
                stream.stats.requests = stream.stats.requests.saturating_add(1);
                stream.stats.last_method.clone_from(&envelope.method);
                stream.stats.last_tool.clone_from(&envelope.tool);
                if !envelope.is_notification() {
                    stream.awaiting.push_back((envelope.seq, admitted));
                }
                Forward::Send(stream.policy.clone())
            }
            Err(reason) => Forward::Close(reason),
        };
        drop(inner);
        forward
    }

    /// Records `len` data bytes from the desktop. `false` if the stream is gone.
    pub(super) fn client_data(&self, id: u32, len: usize) -> bool {
        let mut inner = self.lock();
        let Some(stream) = inner.streams.get_mut(&id) else {
            return false;
        };
        stream.last_active = Instant::now();
        stream.stats.bytes_in = stream.stats.bytes_in.saturating_add(len as u64);
        drop(inner);
        true
    }

    /// Records a `Response` from the plugin and says where to forward it.
    pub(super) fn response(&self, id: u32, seq: u64, status: Status) -> Toward {
        let mut inner = self.lock();
        let Some(stream) = inner.streams.get_mut(&id) else {
            return Toward::Unknown;
        };
        let Some(position) = stream.awaiting.iter().position(|(sent, _)| *sent == seq) else {
            return Toward::Violation;
        };
        if let Some((_, admitted)) = stream.awaiting.remove(position) {
            stream.stats.last_response = Some(admitted.elapsed());
        }
        stream.stats.last_status = Some(status);
        stream.last_active = Instant::now();
        let toward = Toward::Client {
            outbox: stream.outbox.clone(),
            client_id: stream.client_id,
        };
        drop(inner);
        toward
    }

    /// Records `len` data bytes from the plugin and says where to forward them.
    pub(super) fn plugin_data(&self, id: u32, len: usize) -> Option<(Outbox, u32)> {
        let mut inner = self.lock();
        let stream = inner.streams.get_mut(&id)?;
        stream.last_active = Instant::now();
        stream.stats.bytes_out = stream.stats.bytes_out.saturating_add(len as u64);
        let target = (stream.outbox.clone(), stream.client_id);
        drop(inner);
        Some(target)
    }

    /// The streams of `tunnel` that must end: no first `Admit` in time, an admitted request
    /// that never arrived, or no traffic for [`STREAM_IDLE`].
    pub(super) fn due(&self, tunnel: u64, now: Instant) -> Vec<(u32, &'static str)> {
        self.lock()
            .streams
            .iter()
            .filter(|(_, stream)| stream.tunnel == tunnel)
            .filter_map(|(id, stream)| {
                let reason = if !stream.handshaken
                    && now.saturating_duration_since(stream.opened) >= HANDSHAKE_DEADLINE
                {
                    close::HANDSHAKE_TIMEOUT
                } else if stream.admissions.expired(now) {
                    close::ADMISSION_EXPIRED
                } else if now.saturating_duration_since(stream.last_active) >= STREAM_IDLE {
                    close::IDLE
                } else {
                    return None;
                };
                Some((*id, reason))
            })
            .collect()
    }

    /// The streams of `tunnel` whose policy fingerprint differs from `current`.
    pub(super) fn stale(&self, tunnel: u64, current: &RelayPolicy) -> Vec<u32> {
        self.lock()
            .streams
            .iter()
            .filter(|(_, stream)| stream.tunnel == tunnel && stream.policy != *current)
            .map(|(id, _)| *id)
            .collect()
    }

    /// All streams of `tunnel`.
    pub(super) fn of_tunnel(&self, tunnel: u64) -> Vec<u32> {
        self.lock()
            .streams
            .iter()
            .filter(|(_, stream)| stream.tunnel == tunnel)
            .map(|(id, _)| *id)
            .collect()
    }

    /// The bridge is gone: every stream ends and its desktop is told why.
    pub(crate) fn close_all(&self, reason: &str) {
        let streams: Vec<Stream> = {
            let mut inner = self.lock();
            inner.closed = true;
            inner.streams.drain().map(|(_, stream)| stream).collect()
        };
        for stream in streams {
            stream.outbox.push_control(&Control::Close {
                stream: stream.client_id,
                reason: reason.to_owned(),
            });
            tracing::info!(
                endpoint = %self.endpoint,
                desktop = %desktop_prefix(&stream.owner),
                reason,
                "Stream closed."
            );
        }
    }

    /// A control frame from the plugin.
    pub(crate) fn on_plugin_control(&self, control: Control) {
        match control {
            Control::Response {
                stream,
                seq,
                status,
                len,
            } => match self.response(stream, seq, status) {
                Toward::Client { outbox, client_id } => {
                    let frame = Control::Response {
                        stream: client_id,
                        seq,
                        status,
                        len,
                    };
                    if !outbox.push_control(&frame) {
                        self.drop_slow(stream);
                    }
                }
                Toward::Violation => {
                    self.end(stream, close::UNEXPECTED_RESPONSE);
                }
                Toward::Unknown => {}
            },
            Control::Close { stream, reason } => {
                if let Some(removed) = self.remove(stream) {
                    removed.outbox.push_control(&Control::Close {
                        stream: removed.client_id,
                        reason: plain_reason(&reason),
                    });
                    log_closed(&self.endpoint, &removed, &reason);
                }
            }
            // Only the relay sends these; a plugin that sends them is ignored.
            Control::Open { .. }
            | Control::Admit { .. }
            | Control::Admitted { .. }
            | Control::Denied { .. }
            | Control::Request { .. } => {}
        }
    }

    /// A data frame from the plugin, still encoded (`[stream][kind][payload]`). `false` if
    /// it is malformed, which ends the bridge.
    pub(crate) fn on_plugin_data(&self, frame: &[u8]) -> bool {
        let Ok((stream, payload)) = decode_data(frame) else {
            return false;
        };
        if let Some((outbox, client_id)) = self.plugin_data(stream, payload.len()) {
            let delivered =
                data_message(client_id, payload).is_some_and(|message| outbox.push(message));
            if !delivered {
                self.drop_slow(stream);
            }
        }
        true
    }

    /// The desktop does not keep up (or its tunnel is gone): its stream ends.
    fn drop_slow(&self, stream: u32) {
        self.end(stream, close::SLOW_DESKTOP);
    }

    /// Ends a stream from the bridge side: the desktop and the plugin are told.
    fn end(&self, stream: u32, reason: &str) {
        if let Some(removed) = self.remove(stream) {
            removed.outbox.push_control(&Control::Close {
                stream: removed.client_id,
                reason: reason.to_owned(),
            });
            self.notify_close(stream, reason);
            log_closed(&self.endpoint, &removed, reason);
        }
    }

    /// The streams of this bridge, for the operator interface.
    pub(crate) fn snapshot(&self) -> Vec<StreamRow> {
        let inner = self.lock();
        let mut rows: Vec<_> = inner
            .streams
            .values()
            .map(|stream| StreamRow {
                id: stream.uuid,
                endpoint: self.endpoint.to_string(),
                desktop: hex::encode(stream.owner),
                label: stream.label.clone(),
                peer: stream.peer,
                since: stream.opened,
                last_active: stream.last_active,
                handshaken: stream.handshaken,
                requests: stream.stats.requests,
                last_method: stream.stats.last_method.clone(),
                last_tool: stream.stats.last_tool.clone(),
                last_status: stream.stats.last_status,
                bytes_in: stream.stats.bytes_in,
                bytes_out: stream.stats.bytes_out,
                last_response: stream.stats.last_response,
            })
            .collect();
        drop(inner);
        rows.sort_by_key(|row| row.since);
        rows
    }
}

/// The first eight hex characters of a desktop fingerprint, for logs.
pub(super) fn desktop_prefix(owner: &[u8; 32]) -> String {
    hex::encode(&owner[..4])
}

/// Logs the end of a stream: endpoint, desktop prefix and reason, never payload bytes.
pub(super) fn log_closed(endpoint: &str, removed: &Removed, reason: &str) {
    tracing::info!(
        %endpoint,
        desktop = %desktop_prefix(&removed.owner),
        requests = removed.requests,
        reason = ?plain_reason(reason),
        "Stream closed."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_proto::{ADMISSION_TTL, Class};

    const PEER: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        4000,
    ));

    fn policy(tools: &[&str]) -> RelayPolicy {
        RelayPolicy {
            allowed_tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            package_scopes: vec![vec!["Z*".to_owned()]],
        }
    }

    fn hub() -> (Hub, channel::Receiver<Message>) {
        let (sender, receiver) = channel::bounded(256);
        let hub = Hub::new(Arc::from("endpoint"), sender);
        hub.set_e2e();
        (hub, receiver)
    }

    fn new_stream(
        owner: u8,
        client_id: u32,
        tunnel: u64,
        policy: RelayPolicy,
    ) -> (NewStream, channel::Receiver<Message>) {
        let (outbox, receiver) = Outbox::channel(8);
        (
            NewStream {
                owner: [owner; 32],
                label: Some("Laptop".to_owned()),
                outbox,
                client_id,
                tunnel,
                peer: PEER,
                policy,
            },
            receiver,
        )
    }

    fn open(hub: &Hub, owner: u8, client_id: u32) -> (u32, channel::Receiver<Message>) {
        let (stream, receiver) = new_stream(owner, client_id, 1, policy(&["sap_get_source"]));
        (hub.open(stream).unwrap(), receiver)
    }

    fn control(message: &Message) -> Control {
        match message {
            Message::Text(text) => Control::decode(text).unwrap(),
            other => panic!("expected a control frame, got {other:?}"),
        }
    }

    #[test]
    fn streams_need_an_e2e_plugin_and_a_live_bridge() {
        let (sender, _receiver) = channel::bounded(4);
        let hub = Hub::new(Arc::from("endpoint"), sender);
        let (stream, _outbox) = new_stream(1, 1, 1, policy(&[]));
        assert!(hub.open(stream).is_err());
        hub.set_e2e();
        let (stream, _outbox) = new_stream(1, 1, 1, policy(&[]));
        assert!(hub.open(stream).is_ok());
        hub.close_all("gone");
        assert!(hub.is_closed());
        let (stream, _outbox) = new_stream(1, 2, 1, policy(&[]));
        assert!(hub.open(stream).is_err());
    }

    #[test]
    fn stream_limits_hold_per_desktop_and_per_bridge_and_release_on_close() {
        let (hub, _bridge) = hub();
        let mut first = None;
        let mut keep = Vec::new();
        for n in 0..MAX_STREAMS_PER_DESKTOP {
            let (id, receiver) = open(&hub, 1, u32::try_from(n).unwrap());
            first.get_or_insert(id);
            keep.push(receiver);
        }
        let (stream, _outbox) = new_stream(1, 99, 1, policy(&[]));
        assert!(hub.open(stream).is_err());
        // Another desktop is not affected, up to the bridge limit.
        let mut owner = 2_u8;
        while hub.lock().streams.len() < MAX_STREAMS_PER_BRIDGE {
            let count = hub
                .lock()
                .streams
                .values()
                .filter(|stream| stream.owner == [owner; 32])
                .count();
            if count >= MAX_STREAMS_PER_DESKTOP {
                owner += 1;
            }
            keep.push(open(&hub, owner, 1000).1);
        }
        assert_eq!(keep.len(), MAX_STREAMS_PER_BRIDGE);
        let (stream, _outbox) = new_stream(200, 1, 1, policy(&[]));
        assert!(hub.open(stream).is_err());
        // Closing one frees a slot for the same desktop.
        assert!(hub.remove(first.unwrap()).is_some());
        let (stream, _outbox) = new_stream(1, 99, 1, policy(&[]));
        assert!(hub.open(stream).is_ok());
    }

    #[test]
    fn bridge_ids_are_unique_and_translate_back_to_the_desktop_ids() {
        let (hub, _bridge) = hub();
        let (a, a_out) = open(&hub, 1, 7);
        let (b, b_out) = open(&hub, 2, 7);
        assert_ne!(a, b);
        let toward = hub.plugin_data(b, 3).unwrap();
        assert_eq!(toward.1, 7);
        assert!(toward.0.push_control(&Control::Close {
            stream: toward.1,
            reason: "x".to_owned()
        }));
        assert!(b_out.try_recv().is_ok());
        assert!(a_out.try_recv().is_err());
        assert!(hub.plugin_data(a + b + 1000, 1).is_none());
        // A plugin `Close` reaches the right desktop with its own ID and ends only that stream.
        hub.on_plugin_control(Control::Close {
            stream: a,
            reason: "done".to_owned(),
        });
        assert_eq!(
            control(&a_out.try_recv().unwrap()),
            Control::Close {
                stream: 7,
                reason: "done".to_owned()
            }
        );
        assert!(!hub.contains(a) && hub.contains(b));
    }

    #[test]
    fn a_policy_change_closes_the_stream_instead_of_answering() {
        let (hub, _bridge) = hub();
        let (id, _out) = open(&hub, 1, 1);
        let now = Instant::now();
        let envelope = Envelope::new(1, "tools/call", Some(("sap_get_source", Class::Read)));
        let same = policy(&["sap_get_source"]);
        assert_eq!(hub.admit(id, &envelope, &same, now), Admit::Admitted);
        assert_eq!(hub.stale(1, &same), Vec::<u32>::new());
        let stricter = policy(&[]);
        assert_eq!(hub.stale(1, &stricter), [id]);
        assert_eq!(
            hub.admit(id, &Envelope::new(2, "ping", None), &stricter, now),
            Admit::Close(ACCESS_CHANGED)
        );
        let wider = RelayPolicy {
            package_scopes: Vec::new(),
            ..same
        };
        assert_eq!(hub.stale(1, &wider), [id]);
        assert_eq!(hub.stale(2, &wider), Vec::<u32>::new());
        assert_eq!(hub.of_tunnel(1), [id]);
    }

    #[test]
    fn requests_are_forwarded_only_with_their_admission_and_responses_are_recorded() {
        let (hub, _bridge) = hub();
        let (id, out) = open(&hub, 1, 5);
        let now = Instant::now();
        let current = policy(&["sap_get_source"]);
        let envelope = Envelope::new(1, "tools/call", Some(("sap_get_source", Class::Read)));
        assert_eq!(
            hub.request(id, &envelope, now),
            Forward::Close("A request was sent without admission.")
        );
        assert_eq!(hub.admit(id, &envelope, &current, now), Admit::Admitted);
        assert_eq!(hub.request(id, &envelope, now), Forward::Send(current));
        assert!(hub.client_data(id, 100));
        hub.on_plugin_control(Control::Response {
            stream: id,
            seq: 1,
            status: Status::Ok,
            len: 40,
        });
        assert_eq!(
            control(&out.try_recv().unwrap()),
            Control::Response {
                stream: 5,
                seq: 1,
                status: Status::Ok,
                len: 40
            }
        );
        assert!(hub.on_plugin_data(&encode_data(id, &[0; 40]).unwrap()));
        assert!(matches!(out.try_recv(), Ok(Message::Binary(_))));
        let rows = hub.snapshot();
        let row = &rows[0];
        assert_eq!(
            (row.requests, row.bytes_in, row.bytes_out, row.last_status),
            (1, 100, 40, Some(Status::Ok))
        );
        assert_eq!(row.last_tool.as_deref(), Some("sap_get_source"));
        assert!(row.handshaken && row.last_response.is_some());
        // A response nobody asked for ends the stream on both sides.
        hub.on_plugin_control(Control::Response {
            stream: id,
            seq: 9,
            status: Status::Ok,
            len: 1,
        });
        assert!(matches!(
            control(&out.try_recv().unwrap()),
            Control::Close { stream: 5, .. }
        ));
        assert!(!hub.contains(id));
    }

    #[test]
    fn timers_close_silent_streams() {
        let (hub, _bridge) = hub();
        let (id, _out) = open(&hub, 1, 1);
        let now = Instant::now();
        assert_eq!(hub.due(1, now), Vec::<(u32, &str)>::new());
        assert_eq!(hub.due(1, now + HANDSHAKE_DEADLINE).len(), 1);
        // The policy the stream was opened under (see `open`).
        let current = policy(&["sap_get_source"]);
        let ping = Envelope::new(1, "ping", None);
        assert_eq!(hub.admit(id, &ping, &current, now), Admit::Admitted);
        // The handshake is done, but the admitted request is overdue.
        assert_eq!(
            hub.due(
                1,
                now + ADMISSION_TTL.saturating_sub(Duration::from_secs(1))
            ),
            Vec::<(u32, &str)>::new()
        );
        assert_eq!(hub.due(1, now + ADMISSION_TTL).len(), 1);
        assert_eq!(hub.due(2, now + ADMISSION_TTL), Vec::<(u32, &str)>::new());
        assert_eq!(hub.request(id, &ping, now), Forward::Send(current));
        assert_eq!(hub.due(1, now + STREAM_IDLE).len(), 1);
    }

    #[test]
    fn a_stalled_desktop_loses_its_stream() {
        let (hub, bridge) = hub();
        let (outbox, receiver) = Outbox::channel(1);
        let id = hub
            .open(NewStream {
                owner: [1; 32],
                label: None,
                outbox,
                client_id: 3,
                tunnel: 1,
                peer: PEER,
                policy: policy(&[]),
            })
            .unwrap();
        assert!(hub.on_plugin_data(&encode_data(id, &[1]).unwrap()));
        assert!(hub.contains(id));
        // The queue holds one frame and nobody reads it.
        assert!(hub.on_plugin_data(&encode_data(id, &[2]).unwrap()));
        assert!(!hub.contains(id));
        drop(receiver);
        // The plugin is told too.
        assert!(matches!(
            control(&bridge.try_recv().unwrap()),
            Control::Close { .. }
        ));
        assert!(!hub.on_plugin_data(&[0, 0]));
    }

    #[test]
    fn closing_the_bridge_tells_every_desktop() {
        let (hub, _bridge) = hub();
        let (_, a) = open(&hub, 1, 1);
        let (_, b) = open(&hub, 2, 2);
        hub.close_all(close::BRIDGE_GONE);
        for (receiver, client_id) in [(a, 1), (b, 2)] {
            assert!(matches!(
                control(&receiver.try_recv().unwrap()),
                Control::Close { stream, .. } if stream == client_id
            ));
        }
        assert!(hub.snapshot().is_empty());
    }
}
