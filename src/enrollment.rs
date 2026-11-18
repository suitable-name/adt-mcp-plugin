use std::{
    collections::HashMap,
    io::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::{Mutex, oneshot}, time::timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    security::{Pki, fingerprint, token::{self, ALPHABET}},
    transport,
};

const WINDOW_CAP: usize = 16;
const APPROVAL_TTL: Duration = Duration::from_secs(180);
const CLAIM_TTL: Duration = Duration::from_secs(180);

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
            && self.id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && matches!(self.role.as_str(), "desktop" | "eclipse")
            && (1..=64).contains(&self.label.len())
            && !self.label.trim().is_empty()
            && self.label.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    }
}

struct Pending {
    applicant: Applicant,
    number: u64,
    peer: SocketAddr,
    deadline: Instant,
    reply: oneshot::Sender<oneshot::Receiver<()>>,
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
        self.pending.retain(|_, p| !p.reply.is_closed() && now < p.deadline);
        self.grants.retain(|g| now < g.deadline);
    }

    fn request(&mut self, applicant: Applicant, peer: SocketAddr) -> Result<oneshot::Receiver<oneshot::Receiver<()>>, StatusCode> {
        self.expire();
        if !self.enabled {
            return Err(StatusCode::FORBIDDEN);
        }
        if self.pending.contains_key(&applicant.id) || self.grants.iter().any(|g| g.applicant.id == applicant.id) {
            return Err(StatusCode::CONFLICT);
        }
        if self.pending.len() + self.grants.len() >= WINDOW_CAP {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        self.last_number = self.last_number.checked_add(1).ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let (reply, receiver) = oneshot::channel();
        let pending = Pending { applicant, number: self.last_number, peer, reply, deadline: Instant::now() + APPROVAL_TTL };
        tracing::info!(peer = %pending.peer, role = %pending.applicant.role, "Enrollment requested.");
        self.pending.insert(pending.applicant.id.clone(), pending);
        Ok(receiver)
    }

    fn approve(&mut self, id: &str, pin: &[u8; 32], console: &mut impl Write) -> Result<()> {
        anyhow::ensure!(self.enabled, "Enrollment is closed.");
        self.expire();
        let pending = self.pending.remove(id).ok_or_else(|| anyhow!("No live request has that ID."))?;
        let mut secret = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(secret.as_mut_slice()).map_err(|_| anyhow!("System randomness unavailable."))?;
        let hash = fingerprint(secret.as_slice());
        let mut token = Zeroizing::new(encode(&secret, pin));
        // Reserve a live waiter before revealing the token. Its HTTP response
        // is released only once the console has accepted the complete line.
        let (commit, confirmation) = oneshot::channel();
        pending.reply.send(confirmation).map_err(|_| anyhow!("The requester disconnected."))?;
        token.push('\n');
        console.write_all(token.as_bytes())?;
        console.flush()?;
        self.grants.push(Grant { hash, applicant: pending.applicant, deadline: Instant::now() + CLAIM_TTL });
        // Once the operator receives a complete token, it is valid. Loss
        // of the HTTP approval response after that point cannot undo it.
        let _ = commit.send(());
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
        Self { window: Arc::new(Mutex::new(Window { enabled: initially_open, ..Window::default() })), pki }
    }

    // Operator methods run on the terminal thread, outside the async runtime.
    pub(crate) fn snapshot(&self) -> (bool, Vec<ApplicantRow>) {
        let mut window = self.window.blocking_lock();
        window.expire();
        let enabled = window.enabled;
        let mut rows: Vec<_> = window.pending.values().map(|p| ApplicantRow {
            id: p.applicant.id.clone(),
            label: p.applicant.label.clone(),
            role: p.applicant.role.clone(),
            peer: p.peer,
            number: p.number,
        }).collect();
        drop(window);
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        (enabled, rows)
    }

    pub(crate) fn set_open(&self, open: bool) {
        let mut window = self.window.blocking_lock();
        if open {
            window.enabled = true;
        } else {
            window.close();
        }
        drop(window);
        tracing::info!(open, "Enrollment state changed.");
    }

    pub(crate) fn approve(&self, applicant: &ApplicantRow) -> Result<Zeroizing<String>> {
        let mut secret = Zeroizing::new(Vec::new());
        self.approve_to(applicant, &mut *secret)?;
        let text = std::str::from_utf8(&secret)?.trim_end();
        Ok(Zeroizing::new(text.to_owned()))
    }

    pub(crate) fn approve_to(&self, applicant: &ApplicantRow, output: &mut impl Write) -> Result<()> {
        let mut window = self.window.blocking_lock();
        ensure_selected(&window, applicant)?;
        window.approve(&applicant.id, &self.pki.ca_pin(), output)?;
        drop(window);
        tracing::info!("Enrollment approved locally.");
        Ok(())
    }

    pub(crate) fn deny(&self, applicant: &ApplicantRow) -> Result<()> {
        let mut window = self.window.blocking_lock();
        ensure_selected(&window, applicant)?;
        window.pending.remove(&applicant.id);
        drop(window);
        tracing::info!("Enrollment denied locally.");
        Ok(())
    }
}

fn ensure_selected(window: &Window, row: &ApplicantRow) -> Result<()> {
    anyhow::ensure!(window.pending.get(&row.id).is_some_and(|pending| pending.number == row.number),
        "The selected request has changed. Review it again.");
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

async fn read<T: DeserializeOwned>(body: Body) -> Result<T, StatusCode> {
    let bytes = timeout(Duration::from_secs(5), to_bytes(body, 4096)).await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)
}

async fn request(
    State(state): State<Enrollment>, Extension(peer): Extension<SocketAddr>, body: Body,
) -> Result<Response, StatusCode> {
    let applicant: Applicant = read(body).await?;
    if !applicant.valid() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = applicant.id.clone();
    let reply = state.window.lock().await.request(applicant, peer)?;
    timeout(APPROVAL_TTL, async {
        let confirmation = reply.await?;
        confirmation.await
    }).await.map_err(|_| StatusCode::REQUEST_TIMEOUT)?.map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(Json(Approval { id: &id, ca_pem: state.pki.ca_pem() }).into_response())
}

async fn claim(State(state): State<Enrollment>, body: Body) -> Result<Response, StatusCode> {
    let claim: Claim = read(body).await?;
    // A single linearization point for close and claim: close either revokes
    // the grant or observes a certificate already committed to the allowlist.
    tokio::task::spawn_blocking(move || {
        let mut window = state.window.blocking_lock();
        let applicant = window.claim(&claim.token, &state.pki.ca_pin()).ok_or(StatusCode::FORBIDDEN)?;
        let bundle = state.pki.issue(&applicant.role, &applicant.label)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        drop(window);
        Ok(Json(bundle).into_response())
    }).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

async fn guard(State(state): State<Enrollment>, request: Request, next: Next) -> Response {
    if request.headers().contains_key(header::ORIGIN) || !state.window.lock().await.enabled {
        return StatusCode::FORBIDDEN.into_response();
    }
    let json = request.headers().get(header::CONTENT_TYPE).and_then(|field| field.to_str().ok())
        .and_then(|media| media.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
}

pub async fn run(addr: SocketAddr, state: Enrollment, listen_enabled: bool) -> Result<()> {
    if !listen_enabled {
        return std::future::pending().await;
    }
    let tls = state.pki.enroll_tls()?;
    let listener = TcpListener::bind(addr).await?;
    let router = Router::new().route("/request", post(request)).route("/claim", post(claim))
        .route_layer(middleware::from_fn_with_state(state.clone(), guard)).with_state(state);
    tracing::info!("Enrollment listening on {}.", listener.local_addr()?);
    transport::listen(listener, tls, 32, router).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applicant() -> Applicant {
        Applicant { id: "ab".repeat(16), label: "Eclipse 1".into(), role: "eclipse".into() }
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
        let mut reply = window.request(applicant(), peer).unwrap();
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
        let mut window = Window { enabled: true, ..Window::default() };
        let pin = [5; 32];
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut approved = window.request(applicant(), peer).unwrap();
        let token = approve(&mut window, &applicant().id, &pin);
        approved.try_recv().unwrap().try_recv().unwrap();
        let mut other = applicant();
        other.id = "cd".repeat(16);
        let mut pending = window.request(other, peer).unwrap();
        window.close();
        assert!(pending.try_recv().is_err());
        window.enabled = true;
        assert!(window.claim(&token, &pin).is_none());
    }

    #[test]
    fn expired_requests_and_expired_grants_cannot_issue_credentials() {
        let mut window = Window { enabled: true, ..Window::default() };
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let id = applicant().id;
        let pin = [3; 32];
        let _request = window.request(applicant(), peer).unwrap();
        window.pending.get_mut(&id).unwrap().deadline = Instant::now();
        assert!(window.approve(&id, &pin, &mut std::io::sink()).is_err());
        let mut reply = window.request(applicant(), peer).unwrap();
        let token = approve(&mut window, &id, &pin);
        reply.try_recv().unwrap().try_recv().unwrap();
        window.grants[0].deadline = Instant::now();
        assert!(window.claim(&token, &pin).is_none());
    }

    #[test]
    fn disconnected_requesters_and_failed_console_writes_cannot_create_grants() {
        let mut window = Window { enabled: true, ..Window::default() };
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let id = applicant().id;
        let pin = [91; 32];
        drop(window.request(applicant(), peer).unwrap());
        let mut untouched = Vec::new();
        assert!(window.approve(&id, &pin, &mut untouched).is_err());
        assert_eq!(untouched.len(), 0, "A disconnected request wrote token bytes.");

        let mut receiver = window.request(applicant(), peer).unwrap();
        let mut too_short = [0_u8; 4];
        assert!(window.approve(&id, &pin, &mut too_short.as_mut_slice()).is_err());
        assert!(receiver.try_recv().unwrap().try_recv().is_err());
        assert!(window.grants.is_empty());
    }
}
