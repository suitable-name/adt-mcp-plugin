use std::{
    collections::HashMap,
    io::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use smol::{channel, lock::Mutex, net::TcpListener};
use subtle::ConstantTimeEq;
use trillium_http::{KnownHeaderName, Method, Status};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    rt::timeout,
    security::{
        Pki, fingerprint,
        token::{self, ALPHABET},
    },
    transport::{self, Conn, Handoff, Peer, Service, Upgrade},
    web::{Reply, is_json},
};

const WINDOW_CAP: usize = 16;
const APPROVAL_TTL: Duration = Duration::from_secs(180);
const CLAIM_TTL: Duration = Duration::from_secs(180);
/// Refusals on the public enrollment port are logged at most this often.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Plain-text bodies of 403 replies to `/request`. The desktop client
/// (`src/bin/client/enroll.rs`) and the Eclipse plugin (`RelayEnrollment.java`)
/// map them to their own messages; keep the three in step.
const REFUSED_CLOSED: &str = "registration-closed";
const REFUSED_DENIED: &str = "request-denied";

/// Registration requests turned away while registration was closed, since it was last opened.
#[derive(Default)]
struct Refusals {
    count: u64,
    last_peer: Option<SocketAddr>,
    last_logged: Option<Instant>,
    unlogged: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Applicant {
    id: String,
    label: String,
    role: String,
}

impl Applicant {
    fn valid(&self) -> bool {
        self.id.len() == 32
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && matches!(self.role.as_str(), "desktop" | "eclipse")
            && (1..=64).contains(&self.label.len())
            && !self.label.trim().is_empty()
            && self
                .label
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
    }
}

struct Pending {
    applicant: Applicant,
    number: u64,
    peer: SocketAddr,
    deadline: Instant,
    reply: channel::Sender<channel::Receiver<()>>,
}

struct Grant {
    applicant: Applicant,
    deadline: Instant,
    hash: [u8; 32],
}

#[derive(Default)]
struct Window {
    enabled: bool,
    last_number: u64,
    pending: HashMap<String, Pending>,
    grants: Vec<Grant>,
}

impl Window {
    fn close(&mut self) {
        self.enabled = false;
        self.pending.clear();
        self.grants.clear();
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.pending
            .retain(|_, p| !p.reply.is_closed() && now < p.deadline);
        self.grants.retain(|g| now < g.deadline);
    }

    fn request(
        &mut self,
        applicant: Applicant,
        peer: SocketAddr,
    ) -> Result<channel::Receiver<channel::Receiver<()>>, Status> {
        self.expire();
        if !self.enabled {
            return Err(Status::Forbidden);
        }
        if self.pending.contains_key(&applicant.id)
            || self.grants.iter().any(|g| g.applicant.id == applicant.id)
        {
            return Err(Status::Conflict);
        }
        if self.pending.len() + self.grants.len() >= WINDOW_CAP {
            return Err(Status::TooManyRequests);
        }
        self.last_number = self
            .last_number
            .checked_add(1)
            .ok_or(Status::ServiceUnavailable)?;
        let (reply, receiver) = channel::bounded(1);
        let pending = Pending {
            applicant,
            number: self.last_number,
            peer,
            reply,
            deadline: Instant::now() + APPROVAL_TTL,
        };
        tracing::info!(peer = %pending.peer, role = %pending.applicant.role, "Enrollment requested.");
        self.pending.insert(pending.applicant.id.clone(), pending);
        Ok(receiver)
    }

    fn approve(&mut self, id: &str, pin: &[u8; 32], console: &mut impl Write) -> Result<()> {
        anyhow::ensure!(self.enabled, "Enrollment is closed.");
        self.expire();
        let pending = self
            .pending
            .remove(id)
            .ok_or_else(|| anyhow!("No live request has that ID."))?;
        let mut secret = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(secret.as_mut_slice())
            .map_err(|_| anyhow!("System randomness unavailable."))?;
        let hash = fingerprint(secret.as_slice());
        let mut token = Zeroizing::new(encode(&secret, pin));
        // Reserve a live waiter before revealing the token. Its HTTP response
        // is released only once the console has accepted the complete line.
        let (commit, confirmation) = channel::bounded(1);
        pending
            .reply
            .try_send(confirmation)
            .map_err(|_| anyhow!("The requester disconnected."))?;
        token.push('\n');
        console.write_all(token.as_bytes())?;
        console.flush()?;
        self.grants.push(Grant {
            hash,
            applicant: pending.applicant,
            deadline: Instant::now() + CLAIM_TTL,
        });
        // Once the operator receives a complete token, it is valid. Loss
        // of the HTTP approval response after that point cannot undo it.
        let _ = commit.try_send(());
        Ok(())
    }

    fn claim(&mut self, encoded: &str, pin: &[u8; 32]) -> Option<Applicant> {
        self.expire();
        if !self.enabled {
            return None;
        }
        let payload = token::decode(encoded)?;
        let hash = fingerprint(&payload[..32]);
        let pin_ok = pin.as_slice().ct_eq(&payload[32..]);
        let mut index = None;
        for (i, grant) in self.grants.iter().enumerate() {
            if bool::from(grant.hash.ct_eq(&hash) & pin_ok) {
                index = Some(i);
            }
        }
        Some(self.grants.swap_remove(index?).applicant)
    }
}

fn encode(secret: &[u8; 32], pin: &[u8; 32]) -> String {
    let mut output = String::with_capacity(127);
    output.push_str("GW1-");
    let mut accumulator = 0_u16;
    let mut bits = 0;
    let mut symbols = 0_usize;
    for &byte in secret.iter().chain(pin) {
        accumulator = (accumulator << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            if symbols > 0 && symbols.is_multiple_of(5) {
                output.push('-');
            }
            bits -= 5;
            output.push(char::from(ALPHABET[usize::from(accumulator >> bits)]));
            accumulator &= (1 << bits) - 1;
            symbols += 1;
        }
    }
    // 512 bits leave two data bits in the final (103rd) symbol.
    output.push(char::from(ALPHABET[usize::from(accumulator << 3)]));
    output
}

#[derive(Clone)]
pub struct Enrollment {
    window: Arc<Mutex<Window>>,
    pki: Arc<Pki>,
    refusals: Arc<std::sync::Mutex<Refusals>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApplicantRow {
    pub(crate) id: String,
    pub(crate) role: String,
    pub(crate) label: String,
    pub(crate) peer: SocketAddr,
    pub(crate) number: u64,
}

impl Enrollment {
    pub(crate) fn new(pki: Arc<Pki>, initially_open: bool) -> Self {
        Self {
            window: Arc::new(Mutex::new(Window {
                enabled: initially_open,
                ..Window::default()
            })),
            pki,
            refusals: Arc::default(),
        }
    }

    fn refusals_lock(&self) -> std::sync::MutexGuard<'_, Refusals> {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count a request turned away because registration is closed, and tell the operator
    /// in the log (rate-limited: the enrollment port is reachable from the network).
    fn note_closed_refusal(&self, peer: SocketAddr) {
        let mut refusals = self.refusals_lock();
        refusals.count = refusals.count.saturating_add(1);
        refusals.last_peer = Some(peer);
        let now = Instant::now();
        if refusals
            .last_logged
            .is_some_and(|logged| now.duration_since(logged) < REFUSAL_LOG_INTERVAL)
        {
            refusals.unlogged = refusals.unlogged.saturating_add(1);
            return;
        }
        refusals.last_logged = Some(now);
        let suppressed = std::mem::take(&mut refusals.unlogged);
        drop(refusals);
        tracing::info!(%peer, suppressed,
            "Refused a registration request because registration is closed. Open registration (O in the Enrollment tab, or `open` in the headless console) and ask the requester to try again.");
    }

    /// Requests refused while closed since registration was last opened, and the latest peer.
    pub(crate) fn closed_refusals(&self) -> (u64, Option<SocketAddr>) {
        let refusals = self.refusals_lock();
        (refusals.count, refusals.last_peer)
    }

    // Operator methods run on the terminal thread, outside the async runtime.
    pub(crate) fn snapshot(&self) -> (bool, Vec<ApplicantRow>) {
        let mut window = self.window.lock_blocking();
        window.expire();
        let enabled = window.enabled;
        let mut rows: Vec<_> = window
            .pending
            .values()
            .map(|p| ApplicantRow {
                id: p.applicant.id.clone(),
                label: p.applicant.label.clone(),
                role: p.applicant.role.clone(),
                peer: p.peer,
                number: p.number,
            })
            .collect();
        drop(window);
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        (enabled, rows)
    }

    pub(crate) fn set_open(&self, open: bool) {
        let mut window = self.window.lock_blocking();
        if open {
            window.enabled = true;
        } else {
            window.close();
        }
        drop(window);
        if open {
            let mut refusals = self.refusals_lock();
            refusals.count = 0;
            refusals.last_peer = None;
        }
        tracing::info!(open, "Enrollment state changed.");
    }

    pub(crate) fn approve(&self, applicant: &ApplicantRow) -> Result<Zeroizing<String>> {
        let mut secret = Zeroizing::new(Vec::new());
        self.approve_to(applicant, &mut *secret)?;
        let text = std::str::from_utf8(&secret)?.trim_end();
        Ok(Zeroizing::new(text.to_owned()))
    }

    pub(crate) fn approve_to(
        &self,
        applicant: &ApplicantRow,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut window = self.window.lock_blocking();
        ensure_selected(&window, applicant)?;
        window.approve(&applicant.id, &self.pki.ca_pin(), output)?;
        drop(window);
        tracing::info!("Enrollment approved locally.");
        Ok(())
    }

    pub(crate) fn deny(&self, applicant: &ApplicantRow) -> Result<()> {
        let mut window = self.window.lock_blocking();
        ensure_selected(&window, applicant)?;
        window.pending.remove(&applicant.id);
        drop(window);
        tracing::info!("Enrollment denied locally.");
        Ok(())
    }
}

fn ensure_selected(window: &Window, row: &ApplicantRow) -> Result<()> {
    anyhow::ensure!(
        window
            .pending
            .get(&row.id)
            .is_some_and(|pending| pending.number == row.number),
        "The selected request has changed. Review it again."
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    token: String,
}

#[derive(Serialize)]
struct Approval<'a> {
    ca_pem: &'a str,
    id: &'a str,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

async fn read<T: DeserializeOwned>(conn: &mut Conn) -> Result<T, Status> {
    // trillium refuses a body over 4096 bytes: by its declared length, or
    // while counting the bytes of a chunked body. Nothing larger is buffered.
    let bytes = timeout(
        Duration::from_secs(5),
        conn.request_body().with_max_len(4096).read_bytes(),
    )
    .await
    .map_err(|_| Status::RequestTimeout)?
    .map_err(|_| Status::PayloadTooLarge)?;
    serde_json::from_slice(&bytes).map_err(|_| Status::BadRequest)
}

async fn request(state: &Enrollment, peer: SocketAddr, conn: &mut Conn) -> Result<Reply, Status> {
    let applicant: Applicant = read(conn).await?;
    if !applicant.valid() {
        return Err(Status::BadRequest);
    }
    let id = applicant.id.clone();
    let requested = state.window.lock().await.request(applicant, peer);
    let reply = match requested {
        Ok(reply) => reply,
        // Registration closed between the guard and this point.
        Err(Status::Forbidden) => {
            state.note_closed_refusal(peer);
            return Ok(Reply::text(Status::Forbidden, REFUSED_CLOSED));
        }
        Err(status) => return Err(status),
    };
    let decision = timeout(APPROVAL_TTL, async {
        let confirmation = reply.recv().await?;
        confirmation.recv().await
    })
    .await
    .map_err(|_| Status::RequestTimeout)?;
    if decision.is_err() {
        // Denied, or discarded because registration was closed while it waited.
        return Ok(Reply::text(Status::Forbidden, REFUSED_DENIED));
    }
    Ok(Reply::json(
        Status::Ok,
        &Approval {
            id: &id,
            ca_pem: state.pki.ca_pem(),
        },
    ))
}

async fn claim(state: &Enrollment, conn: &mut Conn) -> Result<Reply, Status> {
    let claim: Claim = read(conn).await?;
    let state = state.clone();
    // A single linearization point for close and claim: close either revokes
    // the grant or observes a certificate already committed to the allowlist.
    smol::unblock(move || {
        let mut window = state.window.lock_blocking();
        let applicant = window
            .claim(&claim.token, &state.pki.ca_pin())
            .ok_or(Status::Forbidden)?;
        let bundle = state
            .pki
            .issue(&applicant.role, &applicant.label)
            .map_err(|_| Status::InternalServerError)?;
        drop(window);
        Ok(Reply::json(Status::Ok, &bundle))
    })
    .await
}

impl Enrollment {
    /// Route one request to the enrollment endpoints behind the guard checks.
    async fn respond(&self, conn: &mut Conn, peer: SocketAddr) -> Reply {
        let is_request = match conn.path() {
            "/request" => true,
            "/claim" => false,
            _ => return Status::NotFound.into(),
        };
        if conn.request_headers().has_header(KnownHeaderName::Origin) {
            return Status::Forbidden.into();
        }
        if !self.window.lock().await.enabled {
            self.note_closed_refusal(peer);
            return Reply::text(Status::Forbidden, REFUSED_CLOSED);
        }
        if !is_json(conn.request_headers()) {
            return Status::UnsupportedMediaType.into();
        }
        let result = if conn.method() != Method::Post {
            Err(Status::MethodNotAllowed)
        } else if is_request {
            request(self, peer, conn).await
        } else {
            claim(self, conn).await
        };
        result
            .unwrap_or_else(Reply::from)
            .with_header(KnownHeaderName::CacheControl, "no-store")
    }
}

impl Service for Enrollment {
    type Pending = ();

    async fn handle(&self, mut conn: Conn, peer: &Peer, _handoff: &Handoff<()>) -> Conn {
        let reply = self.respond(&mut conn, peer.addr).await;
        reply.into_conn(conn)
    }

    async fn upgrade(&self, _upgrade: Upgrade, _peer: &Peer, _pending: Option<()>) {}
}

pub async fn run(addr: SocketAddr, state: Enrollment, listen_enabled: bool) -> Result<()> {
    if !listen_enabled {
        return std::future::pending().await;
    }
    let tls = state.pki.enroll_tls()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Enrollment listening on {}.", listener.local_addr()?);
    transport::listen(listener, tls, 32, state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applicant() -> Applicant {
        Applicant {
            id: "ab".repeat(16),
            label: "Eclipse 1".into(),
            role: "eclipse".into(),
        }
    }

    fn approve(window: &mut Window, id: &str, pin: &[u8; 32]) -> String {
        let mut console = Vec::new();
        window.approve(id, pin, &mut console).unwrap();
        let token = String::from_utf8(console).unwrap();
        token.strip_suffix('\n').unwrap().to_owned()
    }

    #[test]
    fn approval_is_required_and_only_one_pinned_claim_succeeds() {
        let mut window = Window::default();
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let pin = [19; 32];
        assert!(window.request(applicant(), peer).is_err());
        window.enabled = true;
        let reply = window.request(applicant(), peer).unwrap();
        assert!(reply.try_recv().is_err());
        assert!(window.request(applicant(), peer).is_err());
        let grant = approve(&mut window, &applicant().id, &pin);
        reply.try_recv().unwrap().try_recv().unwrap();
        assert!(window.claim(&grant, &[0; 32]).is_none());
        assert_eq!(window.claim(&grant, &pin).unwrap().role, "eclipse");
        assert!(window.claim(&grant, &pin).is_none());
    }

    #[test]
    fn closing_discards_unclaimed_grants_and_requests() {
        let mut window = Window {
            enabled: true,
            ..Window::default()
        };
        let pin = [5; 32];
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let approved = window.request(applicant(), peer).unwrap();
        let token = approve(&mut window, &applicant().id, &pin);
        approved.try_recv().unwrap().try_recv().unwrap();
        let mut other = applicant();
        other.id = "cd".repeat(16);
        let pending = window.request(other, peer).unwrap();
        window.close();
        assert!(pending.try_recv().is_err());
        window.enabled = true;
        assert!(window.claim(&token, &pin).is_none());
    }

    #[test]
    fn expired_requests_and_expired_grants_cannot_issue_credentials() {
        let mut window = Window {
            enabled: true,
            ..Window::default()
        };
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let id = applicant().id;
        let pin = [3; 32];
        let _request = window.request(applicant(), peer).unwrap();
        window.pending.get_mut(&id).unwrap().deadline = Instant::now();
        assert!(window.approve(&id, &pin, &mut std::io::sink()).is_err());
        let reply = window.request(applicant(), peer).unwrap();
        let token = approve(&mut window, &id, &pin);
        reply.try_recv().unwrap().try_recv().unwrap();
        window.grants[0].deadline = Instant::now();
        assert!(window.claim(&token, &pin).is_none());
    }

    #[test]
    fn disconnected_requesters_and_failed_console_writes_cannot_create_grants() {
        let mut window = Window {
            enabled: true,
            ..Window::default()
        };
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let id = applicant().id;
        let pin = [91; 32];
        drop(window.request(applicant(), peer).unwrap());
        let mut untouched = Vec::new();
        assert!(window.approve(&id, &pin, &mut untouched).is_err());
        assert_eq!(
            untouched.len(),
            0,
            "A disconnected request wrote token bytes."
        );

        let receiver = window.request(applicant(), peer).unwrap();
        let mut too_short = [0_u8; 4];
        assert!(
            window
                .approve(&id, &pin, &mut too_short.as_mut_slice())
                .is_err()
        );
        assert!(receiver.try_recv().unwrap().try_recv().is_err());
        assert!(window.grants.is_empty());
    }
}
