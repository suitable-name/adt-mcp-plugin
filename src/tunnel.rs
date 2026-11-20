//! `GET /tunnel`: the desktop side of the end-to-end streams
//! (`docs/plan-e2e-envelope.md` §2 and §3).
//!
//! One WebSocket per desktop client carries many streams. The relay is a forwarder: it
//! checks the desktop's grant when a stream opens, enforces its access rules on every
//! request's envelope (`Admit`), translates stream IDs between the tunnel and the Eclipse
//! bridge, and forwards the inner TLS bytes without reading them. The stream table and the
//! limits live in [`hub`]; the admission rules in [`admission`].

mod admission;
mod hub;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_tungstenite::tungstenite::Message;
use futures_util::StreamExt;
use smol::{Timer, future};
use trillium_http::{Headers, Status};

use crate::{
    Relay,
    bridge::{self, SocketReceiver},
    mcp,
    policy::Effective,
    security::valid_fingerprint,
    transport::{PeerCertificate, Upgrade},
    tunnel_proto::{Class, Control, Envelope, MAX_DATA_PAYLOAD, RelayPolicy, decode_data},
    web::Reply,
};
use admission::DENIED;
use hub::{
    ACCESS_CHANGED, Admit, Forward, NewStream, Outbox, desktop_prefix, log_closed, plain_reason,
};
pub use hub::{Hub, StreamRow};

/// Messages queued for one desktop. A desktop that falls further behind loses its stream.
const OUTBOX_CAPACITY: usize = 1024;
/// Interval of the local timers: handshake, admission, idle.
const TICK: Duration = Duration::from_secs(1);
/// Ticks between policy re-checks of idle streams (five seconds).
const POLICY_TICKS: u32 = 5;
/// Ticks between pings to the desktop.
const PING_TICKS: u32 = 30;
/// Tunnels per desktop and in total.
const MAX_TUNNELS_PER_DESKTOP: usize = 4;
const MAX_TUNNELS: usize = 256;
/// WebSocket message limit: a data frame or control frame plus its header.
const MESSAGE_LIMIT: usize = 2 * MAX_DATA_PAYLOAD;

static NEXT_TUNNEL: AtomicU64 = AtomicU64::new(1);

/// Open tunnels per desktop, so that a desktop cannot take every connection slot.
#[derive(Clone, Default)]
pub struct Tunnels(Arc<Mutex<HashMap<[u8; 32], usize>>>);

impl Tunnels {
    fn reserve(&self, owner: [u8; 32]) -> Option<TunnelSlot> {
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let total: usize = counts.values().sum();
        let current = counts.get(&owner).copied().unwrap_or(0);
        if total >= MAX_TUNNELS || current >= MAX_TUNNELS_PER_DESKTOP {
            return None;
        }
        counts.insert(owner, current + 1);
        drop(counts);
        Some(TunnelSlot {
            tunnels: self.clone(),
            owner,
        })
    }
}

struct TunnelSlot {
    tunnels: Tunnels,
    owner: [u8; 32],
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        let mut counts = self
            .tunnels
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.owner) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.owner);
            }
        }
    }
}

/// A reserved tunnel slot waiting for its WebSocket upgrade to complete.
pub struct Tunnel {
    _slot: TunnelSlot,
}

/// Validates a `/tunnel` request (GET only; the caller checks the method, the certificate
/// and the `Origin`) and answers it. When the answer is `101`, the returned [`Tunnel`] must
/// be passed to [`serve_upgraded`] once the response has been sent.
pub fn upgrade(
    relay: &Relay,
    headers: &Headers,
    cert: &PeerCertificate,
) -> (Reply, Option<Tunnel>) {
    let accept = match bridge::handshake(headers) {
        Ok(accept) => accept,
        Err(message) => return (Reply::text(Status::BadRequest, message), None),
    };
    let Some(slot) = relay.tunnels.reserve(cert.fingerprint) else {
        return (
            Reply::text(
                Status::TooManyRequests,
                "This desktop has too many open tunnels.",
            ),
            None,
        );
    };
    (bridge::switching(accept), Some(Tunnel { _slot: slot }))
}

/// Run the tunnel on an upgraded connection until it ends.
pub async fn serve_upgraded(
    upgrade: Upgrade,
    _tunnel: Tunnel,
    relay: &Relay,
    cert: &PeerCertificate,
    peer: SocketAddr,
) {
    let socket = bridge::socket(upgrade, MESSAGE_LIMIT).await;
    let (mut sink, mut incoming) = socket.split();
    let (outbox, outbound) = Outbox::channel(OUTBOX_CAPACITY);
    let mut session = Session {
        relay,
        cert,
        peer,
        id: NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed),
        outbox,
        routes: HashMap::new(),
        ticks: 0,
    };
    tracing::info!(desktop = %desktop_prefix(&cert.fingerprint), %peer, "Tunnel opened.");
    // Everything for the desktop goes through the queue, in order.
    let writer = async {
        while let Ok(message) = outbound.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    };
    future::race(writer, session.run(&mut incoming)).await;
    session.shutdown().await;
    drop(session);
    tracing::info!(desktop = %desktop_prefix(&cert.fingerprint), %peer, "Tunnel closed.");
}

/// A stream of this tunnel: the hub it lives in and its ID there.
struct Route {
    hub: Arc<Hub>,
    bridge_id: u32,
}

enum Event {
    Frame(Option<Result<Message, async_tungstenite::tungstenite::Error>>),
    Tick,
}

struct Session<'a> {
    relay: &'a Relay,
    cert: &'a PeerCertificate,
    peer: SocketAddr,
    id: u64,
    outbox: Outbox,
    /// Desktop stream ID to the hub stream.
    routes: HashMap<u32, Route>,
    ticks: u32,
}

/// The relay's policy for a desktop on an endpoint, as it is sent to the plugin. Two equal
/// values mean that neither the grant nor the rules changed.
fn relay_policy(effective: &Effective) -> RelayPolicy {
    RelayPolicy {
        allowed_tools: effective
            .allowed_tools()
            .iter()
            .map(|tool| (*tool).to_owned())
            .collect(),
        package_scopes: effective.package_scopes().to_vec(),
    }
}

const fn class_name(class: Option<Class>) -> &'static str {
    match class {
        Some(Class::Read) => "read",
        Some(Class::Execute) => "execute",
        Some(Class::Write) => "write",
        None => "-",
    }
}

impl Session<'_> {
    /// Handles frames and timers until the desktop leaves or breaks the protocol.
    async fn run(&mut self, incoming: &mut SocketReceiver) {
        let mut next_tick = Instant::now() + TICK;
        loop {
            let event = future::race(async { Event::Frame(incoming.next().await) }, async {
                Timer::at(next_tick).await;
                Event::Tick
            })
            .await;
            match event {
                Event::Frame(Some(Ok(message))) => {
                    if !self.frame(message).await {
                        return;
                    }
                }
                Event::Frame(_) => return,
                Event::Tick => {
                    self.tick().await;
                    next_tick = Instant::now() + TICK;
                }
            }
        }
    }

    /// `false` ends the tunnel: the frame is not part of the protocol.
    async fn frame(&mut self, message: Message) -> bool {
        match message {
            Message::Text(text) => match Control::decode(&text) {
                Ok(control) => self.control(control).await,
                Err(_) => false,
            },
            Message::Binary(frame) => match decode_data(&frame) {
                Ok((stream, payload)) => {
                    self.data(stream, payload).await;
                    true
                }
                Err(_) => false,
            },
            Message::Ping(payload) => {
                self.outbox.push(Message::Pong(payload));
                true
            }
            Message::Pong(_) => true,
            _ => false,
        }
    }

    async fn control(&mut self, control: Control) -> bool {
        match control {
            Control::Open {
                stream, endpoint, ..
            } => self.open(stream, &endpoint).await,
            Control::Admit { stream, envelope } => self.admit(stream, &envelope).await,
            Control::Request {
                stream,
                envelope,
                len,
                ..
            } => self.request(stream, envelope, len).await,
            Control::Close { stream, reason } => self.client_close(stream, &reason).await,
            // Frames the relay sends to the desktop are not valid from it.
            Control::Admitted { .. } | Control::Denied { .. } | Control::Response { .. } => {
                return false;
            }
        }
        true
    }

    fn refuse(&self, stream: u32, reason: &str) {
        self.outbox.push_control(&Control::Close {
            stream,
            reason: reason.to_owned(),
        });
    }

    fn deny(&self, stream: u32, seq: u64, message: &str) {
        self.outbox.push_control(&Control::Denied {
            stream,
            seq,
            code: DENIED,
            message: message.to_owned(),
        });
    }

    /// Tells the desktop that a frame named a stream that is not open.
    fn unknown(&self, stream: u32) {
        self.refuse(stream, "The stream is closed.");
    }

    fn route(&self, client_id: u32) -> Option<(Arc<Hub>, u32)> {
        self.routes
            .get(&client_id)
            .map(|route| (Arc::clone(&route.hub), route.bridge_id))
    }

    /// The distinct hubs this tunnel has streams on.
    fn hubs(&self) -> Vec<Arc<Hub>> {
        let mut hubs: Vec<Arc<Hub>> = Vec::new();
        for route in self.routes.values() {
            if !hubs.iter().any(|known| Arc::ptr_eq(known, &route.hub)) {
                hubs.push(Arc::clone(&route.hub));
            }
        }
        hubs
    }

    /// The label the relay holds for this desktop's certificate, if any.
    async fn desktop_label(&self) -> Option<String> {
        let pki = Arc::clone(&self.relay.pki);
        let pin = hex::encode(self.cert.fingerprint);
        smol::unblock(move || {
            pki.clients()
                .ok()?
                .into_iter()
                .find(|client| client.role == "desktop" && client.fingerprint == pin)
                .map(|client| plain_reason(&client.label))
        })
        .await
    }

    async fn open(&mut self, client_id: u32, endpoint: &str) {
        let in_use = self
            .routes
            .get(&client_id)
            .is_some_and(|route| route.hub.contains(route.bridge_id));
        if in_use {
            self.refuse(client_id, "This stream ID is already in use.");
            return;
        }
        if !valid_fingerprint(endpoint) {
            self.refuse(client_id, "The endpoint ID is invalid.");
            return;
        }
        let effective = match mcp::endpoint_policy(self.relay, self.cert, endpoint).await {
            Ok(effective) => effective,
            Err(Status::Forbidden) => {
                self.refuse(client_id, "This endpoint is unavailable to this desktop.");
                return;
            }
            Err(_) => {
                self.refuse(client_id, "The access policy is unavailable.");
                return;
            }
        };
        let Some(hub) = self.relay.registry.hub(endpoint) else {
            self.refuse(
                client_id,
                "The selected Eclipse endpoint is offline. Connect that Eclipse workspace and retry.",
            );
            return;
        };
        let label = self.desktop_label().await;
        let new = NewStream {
            owner: self.cert.fingerprint,
            label: label.clone(),
            outbox: self.outbox.clone(),
            client_id,
            tunnel: self.id,
            peer: self.peer,
            policy: relay_policy(&effective),
        };
        let bridge_id = match hub.open(new) {
            Ok(id) => id,
            Err(reason) => {
                self.refuse(client_id, reason);
                return;
            }
        };
        let frame = Control::Open {
            stream: bridge_id,
            endpoint: endpoint.to_owned(),
            desktop: Some(hex::encode(self.cert.fingerprint)),
            label,
        };
        if !hub.send(&frame).await {
            hub.remove(bridge_id);
            self.refuse(client_id, "The Eclipse bridge disconnected.");
            return;
        }
        tracing::info!(
            %endpoint,
            desktop = %desktop_prefix(&self.cert.fingerprint),
            "Stream opened."
        );
        self.routes.insert(client_id, Route { hub, bridge_id });
    }

    async fn admit(&mut self, client_id: u32, envelope: &Envelope) {
        let Some((hub, bridge_id)) = self.route(client_id) else {
            self.unknown(client_id);
            return;
        };
        // Read the grant and the rules fresh for every admission.
        let current = match mcp::endpoint_policy(self.relay, self.cert, hub.endpoint()).await {
            Ok(effective) => relay_policy(&effective),
            Err(Status::Forbidden) => {
                self.end_stream(&hub, bridge_id, ACCESS_CHANGED).await;
                return;
            }
            Err(_) => {
                self.deny(client_id, envelope.seq, "The access policy is unavailable.");
                return;
            }
        };
        let outcome = hub.admit(bridge_id, envelope, &current, Instant::now());
        self.log_admission(&hub, envelope, &outcome);
        match outcome {
            Admit::Admitted => {
                self.outbox.push_control(&Control::Admitted {
                    stream: client_id,
                    seq: envelope.seq,
                });
            }
            Admit::Denied(message) => self.deny(client_id, envelope.seq, message),
            Admit::Close(reason) => self.end_stream(&hub, bridge_id, reason).await,
            Admit::Unknown => self.unknown(client_id),
        }
    }

    /// Logs tool admissions and every denial, never payload bytes.
    fn log_admission(&self, hub: &Hub, envelope: &Envelope, outcome: &Admit) {
        let decision = match outcome {
            Admit::Admitted if envelope.method == "tools/call" => "admitted",
            Admit::Denied(_) => "denied",
            _ => return,
        };
        tracing::info!(
            endpoint = %hub.endpoint(),
            desktop = %desktop_prefix(&self.cert.fingerprint),
            method = %envelope.method,
            tool = envelope.tool.as_deref().unwrap_or("-"),
            class = class_name(envelope.class),
            decision,
            "Admission."
        );
    }

    async fn request(&mut self, client_id: u32, envelope: Envelope, len: u32) {
        let Some((hub, bridge_id)) = self.route(client_id) else {
            self.unknown(client_id);
            return;
        };
        match hub.request(bridge_id, &envelope, Instant::now()) {
            Forward::Send(policy) => {
                let frame = Control::Request {
                    stream: bridge_id,
                    envelope,
                    policy: Some(policy),
                    len,
                };
                if !hub.send(&frame).await {
                    self.end_stream(&hub, bridge_id, "The Eclipse bridge disconnected.")
                        .await;
                }
            }
            Forward::Close(reason) => {
                tracing::warn!(
                    endpoint = %hub.endpoint(),
                    desktop = %desktop_prefix(&self.cert.fingerprint),
                    reason,
                    "Refused a request that does not match its admission."
                );
                self.end_stream(&hub, bridge_id, reason).await;
            }
            Forward::Unknown => self.unknown(client_id),
        }
    }

    /// Inner TLS bytes: forwarded as they come. Data for a stream that is gone is dropped.
    async fn data(&mut self, client_id: u32, payload: &[u8]) {
        let Some((hub, bridge_id)) = self.route(client_id) else {
            return;
        };
        if !hub.client_data(bridge_id, payload.len()) {
            return;
        }
        if !hub.send_data(bridge_id, payload).await {
            self.end_stream(&hub, bridge_id, "The Eclipse bridge disconnected.")
                .await;
        }
    }

    /// The desktop closed a stream: the plugin is told, the desktop needs no answer.
    async fn client_close(&mut self, client_id: u32, reason: &str) {
        let Some(route) = self.routes.remove(&client_id) else {
            return;
        };
        if let Some(removed) = route.hub.remove(route.bridge_id) {
            route
                .hub
                .send(&Control::Close {
                    stream: route.bridge_id,
                    reason: plain_reason(reason),
                })
                .await;
            log_closed(route.hub.endpoint(), &removed, reason);
        }
    }

    /// Ends a stream from the relay's side: the plugin and the desktop are told why.
    async fn end_stream(&mut self, hub: &Arc<Hub>, bridge_id: u32, reason: &str) {
        let Some(removed) = hub.remove(bridge_id) else {
            return;
        };
        let current = self
            .routes
            .get(&removed.client_id)
            .is_some_and(|route| route.bridge_id == bridge_id && Arc::ptr_eq(&route.hub, hub));
        if current {
            self.routes.remove(&removed.client_id);
        }
        removed.outbox.push_control(&Control::Close {
            stream: removed.client_id,
            reason: reason.to_owned(),
        });
        hub.send(&Control::Close {
            stream: bridge_id,
            reason: reason.to_owned(),
        })
        .await;
        log_closed(hub.endpoint(), &removed, reason);
    }

    async fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        // Streams the plugin or a bridge disconnect already ended need no route anymore.
        self.routes
            .retain(|_, route| route.hub.contains(route.bridge_id));
        let now = Instant::now();
        for hub in self.hubs() {
            for (bridge_id, reason) in hub.due(self.id, now) {
                self.end_stream(&hub, bridge_id, reason).await;
            }
        }
        if self.ticks.is_multiple_of(POLICY_TICKS) {
            self.recheck_policy().await;
        }
        if self.ticks.is_multiple_of(PING_TICKS) {
            self.outbox.push(Message::Ping(Vec::<u8>::new().into()));
        }
    }

    /// Closes streams whose grant is gone or whose policy fingerprint changed. A request
    /// is never dropped on its own: the stream ends, so the inner TLS stays in step.
    async fn recheck_policy(&mut self) {
        for hub in self.hubs() {
            let ids = match mcp::endpoint_policy(self.relay, self.cert, hub.endpoint()).await {
                Ok(effective) => hub.stale(self.id, &relay_policy(&effective)),
                Err(Status::Forbidden) => hub.of_tunnel(self.id),
                // The policy could not be read just now; the next admission checks again.
                Err(_) => continue,
            };
            for bridge_id in ids {
                self.end_stream(&hub, bridge_id, ACCESS_CHANGED).await;
            }
        }
    }

    /// The tunnel is gone: its streams end and the plugin is told. Nobody is left to tell.
    async fn shutdown(&mut self) {
        let routes: Vec<Route> = self.routes.drain().map(|(_, route)| route).collect();
        for route in routes {
            if let Some(removed) = route.hub.remove(route.bridge_id) {
                route
                    .hub
                    .send(&Control::Close {
                        stream: route.bridge_id,
                        reason: "The desktop disconnected.".to_owned(),
                    })
                    .await;
                log_closed(route.hub.endpoint(), &removed, "The desktop disconnected.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyStore;

    #[test]
    fn tunnels_are_limited_per_desktop_and_in_total_and_released_on_drop() {
        let tunnels = Tunnels::default();
        let mut held: Vec<TunnelSlot> = (0..MAX_TUNNELS_PER_DESKTOP)
            .map(|_| tunnels.reserve([1; 32]).unwrap())
            .collect();
        assert!(tunnels.reserve([1; 32]).is_none());
        assert!(tunnels.reserve([2; 32]).is_some());
        drop(held.pop());
        assert!(tunnels.reserve([1; 32]).is_some());
        drop(held);
        assert!(tunnels.0.lock().unwrap().len() <= 1);
        // The total limit holds across desktops.
        let mut many = Vec::new();
        for n in 0..MAX_TUNNELS {
            let owner = [u8::try_from(n % 64).unwrap(); 32];
            let mut tagged = owner;
            tagged[1] = u8::try_from(n / 64).unwrap();
            many.push(tunnels.reserve(tagged).unwrap());
        }
        assert!(tunnels.reserve([250; 32]).is_none());
        drop(many);
        assert!(tunnels.0.lock().unwrap().is_empty());
    }

    #[test]
    fn the_stream_policy_follows_the_effective_policy_and_changes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::load(dir.path()).unwrap();
        let owner = [1; 32];
        let endpoint = hex::encode([2; 32]);
        store
            .set_endpoint_grants(
                &store.snapshot().unwrap().revision,
                &hex::encode(owner),
                vec![endpoint.clone()],
            )
            .unwrap();
        let before = relay_policy(
            &store
                .effective_for_endpoint(&owner, &endpoint)
                .unwrap()
                .unwrap(),
        );
        assert!(before.allowed_tools.contains(&"sap_get_source".to_owned()));
        assert!(!before.allowed_tools.contains(&"sap_set_source".to_owned()));
        let again = relay_policy(
            &store
                .effective_for_endpoint(&owner, &endpoint)
                .unwrap()
                .unwrap(),
        );
        assert_eq!(before, again);
        store
            .set_desktop(
                &store.snapshot().unwrap().revision,
                &hex::encode(owner),
                Some(crate::policy::Rules {
                    read_only: false,
                    actions: None,
                    packages: Some(vec!["Z*".to_owned()]),
                }),
            )
            .unwrap();
        let after = relay_policy(
            &store
                .effective_for_endpoint(&owner, &endpoint)
                .unwrap()
                .unwrap(),
        );
        assert_ne!(before, after);
        assert_eq!(after.package_scopes, [vec!["Z*".to_owned()]]);
    }

    #[test]
    fn class_names_are_the_clear_text_vocabulary() {
        assert_eq!(class_name(Some(Class::Write)), "write");
        assert_eq!(class_name(None), "-");
    }
}
