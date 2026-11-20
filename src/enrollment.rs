//! Enrollment by one-time links. The operator mints a link (TUI, or `POST /issue` from
//! `issue-link`); whoever holds it claims a certificate once through `POST /claim`.
//! Minting a link is the approval: there is no request step and no registration window.

mod issue_link;

use std::{
    collections::VecDeque,
    fmt,
    net::{Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, de::DeserializeOwned};
use smol::net::TcpListener;
use subtle::ConstantTimeEq;
use trillium_http::{KnownHeaderName, Method, Status};
use zeroize::{Zeroize, Zeroizing};

pub use issue_link::issue_link;

use crate::{
    link::{self, EnrollLink, LinkError, Role},
    rt::timeout,
    security::{
        Pki, fingerprint,
        token::{self, ALPHABET},
    },
    transport::{self, Conn, Handoff, Peer, Service, Upgrade},
    web::{Reply, is_json},
};

/// At most this many links are outstanding at once.
const LINK_CAP: usize = 16;
/// A link lives this long unless it is used or cancelled.
const LINK_TTL: Duration = Duration::from_secs(600);
/// The Enrollment tab remembers this many recent enrollments.
const RECENT_CAP: usize = 16;
/// Test hook: a number of milliseconds that shortens (never lengthens) the link lifetime.
const TTL_OVERRIDE: &str = "SAP_ADT_RELAY_TEST_LINK_TTL_MS";

/// What the relay writes into every link besides the secret.
pub struct Addresses {
    /// The relay's display name (`n`).
    pub name: String,
    /// The public data (mutual TLS) address (`s`).
    pub server: String,
    /// The public enrollment address (`e`).
    pub enrollment: String,
}

impl Addresses {
    /// Use the operator's choices where given, otherwise the PKI's DNS name with the bound ports.
    ///
    /// # Errors
    /// An operator choice that is not valid in a link.
    pub fn resolve(
        pki: &Pki,
        name: Option<String>,
        public_data: Option<String>,
        public_enrollment: Option<String>,
        ports: (u16, u16),
    ) -> Result<Self> {
        let dns = pki.dns_name();
        let host = if dns.parse::<Ipv6Addr>().is_ok() {
            format!("[{dns}]")
        } else {
            dns.to_owned()
        };
        let name = name.unwrap_or_else(|| dns.to_owned());
        let server = public_data.unwrap_or_else(|| format!("{host}:{}", ports.0));
        let enrollment = public_enrollment.unwrap_or_else(|| format!("{host}:{}", ports.1));
        link::check_name(&name)
            .context("--name must be at most 64 bytes without control characters.")?;
        link::check_hostport(&server).context("--public-data must be host:port.")?;
        link::check_hostport(&enrollment).context("--public-enrollment must be host:port.")?;
        Ok(Self {
            name,
            server,
            enrollment,
        })
    }
}

/// Why a link could not be minted.
#[derive(Debug)]
pub enum MintError {
    BadLabel,
    Full,
    Unavailable,
    Link(LinkError),
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLabel => f.write_str("Use a printable ASCII label of 1 to 64 characters."),
            Self::Full => write!(
                f,
                "{LINK_CAP} links are already outstanding. Cancel one or wait for it to expire."
            ),
            Self::Unavailable => f.write_str("System randomness unavailable."),
            Self::Link(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MintError {}

/// A label becomes part of the certificate name and of log lines.
fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.len())
        && !label.trim().is_empty()
        && label.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

struct Entry {
    number: u64,
    hash: [u8; 32],
    role: Role,
    label: String,
    expires: Instant,
}

struct Enrolled {
    label: String,
    role: Role,
    peer: SocketAddr,
    at: Instant,
}

#[derive(Default)]
struct Store {
    last_number: u64,
    links: Vec<Entry>,
    recent: VecDeque<Enrolled>,
}

impl Store {
    fn expire(&mut self) {
        let now = Instant::now();
        self.links.retain(|entry| now < entry.expires);
    }

    /// Store a hash of a new random secret and return the secret.
    fn mint(
        &mut self,
        role: Role,
        label: &str,
        ttl: Duration,
    ) -> Result<Zeroizing<[u8; 32]>, MintError> {
        self.expire();
        if self.links.len() >= LINK_CAP {
            return Err(MintError::Full);
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(secret.as_mut_slice())
            .map_err(|_| MintError::Unavailable)?;
        self.last_number = self
            .last_number
            .checked_add(1)
            .ok_or(MintError::Unavailable)?;
        self.links.push(Entry {
            number: self.last_number,
            hash: fingerprint(secret.as_slice()),
            role,
            label: label.to_owned(),
            expires: Instant::now() + ttl,
        });
        Ok(secret)
    }

    /// Consume the link whose secret hashes to `hash`. Every stored hash is compared in
    /// constant time, whatever matches.
    fn redeem(&mut self, hash: &[u8; 32]) -> Option<Entry> {
        self.expire();
        let mut index = None;
        for (i, entry) in self.links.iter().enumerate() {
            if bool::from(entry.hash.ct_eq(hash)) {
                index = Some(i);
            }
        }
        Some(self.links.swap_remove(index?))
    }

    fn cancel(&mut self, number: u64) -> bool {
        self.expire();
        let before = self.links.len();
        self.links.retain(|entry| entry.number != number);
        self.links.len() != before
    }

    fn note_enrolled(&mut self, entry: &Entry, peer: SocketAddr) {
        self.recent.push_front(Enrolled {
            label: entry.label.clone(),
            role: entry.role,
            peer,
            at: Instant::now(),
        });
        self.recent.truncate(RECENT_CAP);
    }
}

/// `GW1-` token: the 32-byte secret and the 32-byte CA fingerprint, Crockford Base32.
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

/// One outstanding link as the Enrollment tab shows it. The link text is not kept.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkRow {
    pub(crate) number: u64,
    pub(crate) role: Role,
    pub(crate) label: String,
    pub(crate) expires_in: Duration,
}

/// A completed enrollment as the Enrollment tab shows it.
#[derive(Clone)]
pub struct EnrolledRow {
    pub(crate) label: String,
    pub(crate) role: Role,
    pub(crate) peer: SocketAddr,
    pub(crate) at: Instant,
}

#[derive(Clone)]
pub struct Enrollment {
    store: Arc<Mutex<Store>>,
    pki: Arc<Pki>,
    addresses: Arc<Addresses>,
    /// The operator secret for `POST /issue`.
    secret: Arc<Zeroizing<String>>,
    ttl: Duration,
}

impl Enrollment {
    pub(crate) fn new(pki: Arc<Pki>, addresses: Addresses, secret: Zeroizing<String>) -> Self {
        let ttl = std::env::var(TTL_OVERRIDE)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .map(Duration::from_millis)
            .filter(|ttl| *ttl < LINK_TTL)
            .unwrap_or(LINK_TTL);
        Self {
            store: Arc::default(),
            pki,
            addresses: Arc::new(addresses),
            secret: Arc::new(secret),
            ttl,
        }
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Mint a single-use link for `role`. The result contains a secret: show it once and
    /// never log it.
    ///
    /// # Errors
    /// An invalid label, 16 links already outstanding, or no randomness.
    pub(crate) fn new_link(&self, role: Role, label: &str) -> Result<Zeroizing<String>, MintError> {
        if !valid_label(label) {
            return Err(MintError::BadLabel);
        }
        let secret = self.store().mint(role, label, self.ttl)?;
        let link = EnrollLink {
            role,
            name: self.addresses.name.clone(),
            server: self.addresses.server.clone(),
            enrollment: self.addresses.enrollment.clone(),
            label: Some(label.to_owned()),
            token: Zeroizing::new(encode(&secret, &self.pki.ca_pin())),
        };
        let text = link.build().map_err(MintError::Link)?;
        tracing::info!("Minted an enrollment link for {label} ({}).", role.as_str());
        Ok(Zeroizing::new(text))
    }

    /// Outstanding links (oldest first) and recent enrollments (newest first).
    /// Called from the terminal thread, outside the async runtime.
    pub(crate) fn snapshot(&self) -> (Vec<LinkRow>, Vec<EnrolledRow>) {
        let mut store = self.store();
        store.expire();
        let now = Instant::now();
        let mut links: Vec<_> = store
            .links
            .iter()
            .map(|entry| LinkRow {
                number: entry.number,
                role: entry.role,
                label: entry.label.clone(),
                expires_in: entry.expires.saturating_duration_since(now),
            })
            .collect();
        let recent = store
            .recent
            .iter()
            .map(|done| EnrolledRow {
                label: done.label.clone(),
                role: done.role,
                peer: done.peer,
                at: done.at,
            })
            .collect();
        drop(store);
        links.sort_by_key(|row| row.number);
        (links, recent)
    }

    pub(crate) fn cancel(&self, number: u64) -> bool {
        let cancelled = self.store().cancel(number);
        if cancelled {
            tracing::info!("Enrollment link cancelled.");
        }
        cancelled
    }

    /// Consume the link a `GW1-` token belongs to. `None` for anything wrong with it:
    /// malformed, another relay's CA, unknown, used, expired or cancelled.
    fn redeem(&self, encoded: &str, peer: SocketAddr) -> Option<Entry> {
        let payload = token::decode(encoded)?;
        if !bool::from(self.pki.ca_pin().as_slice().ct_eq(&payload[32..])) {
            return None;
        }
        let hash = fingerprint(&payload[..32]);
        let mut store = self.store();
        let entry = store.redeem(&hash)?;
        store.note_enrolled(&entry, peer);
        drop(store);
        Some(entry)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    token: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    role: String,
    label: String,
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

/// One generic 403 for a wrong, used, expired or cancelled link.
async fn claim(state: &Enrollment, peer: SocketAddr, conn: &mut Conn) -> Result<Reply, Status> {
    let claim: Claim = read(conn).await?;
    let state = state.clone();
    smol::unblock(move || {
        let Some(entry) = state.redeem(&claim.token, peer) else {
            tracing::debug!(%peer, "Refused an enrollment claim.");
            return Err(Status::Forbidden);
        };
        let bundle = state
            .pki
            .issue(entry.role.as_str(), &entry.label)
            .map_err(|_| Status::InternalServerError)?;
        tracing::info!(
            "{} ({}) enrolled from {peer}.",
            entry.label,
            entry.role.as_str()
        );
        Ok(Reply::json(Status::Ok, &bundle))
    })
    .await
}

/// `POST /issue`: loopback peers holding the operator secret only.
async fn issue(state: &Enrollment, peer: SocketAddr, conn: &mut Conn) -> Result<Reply, Status> {
    if !peer.ip().to_canonical().is_loopback() {
        return Err(Status::Forbidden);
    }
    let authorized = conn
        .request_headers()
        .get_str(KnownHeaderName::Authorization)
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|presented| bool::from(presented.as_bytes().ct_eq(state.secret.as_bytes())));
    if !authorized {
        return Err(Status::Forbidden);
    }
    let request: IssueRequest = read(conn).await?;
    let role = Role::from_word(&request.role).map_err(|_| Status::BadRequest)?;
    let link = state
        .new_link(role, &request.label)
        .map_err(|error| match error {
            MintError::BadLabel => Status::BadRequest,
            MintError::Full => Status::TooManyRequests,
            MintError::Unavailable | MintError::Link(_) => Status::InternalServerError,
        })?;
    Ok(Reply::text(Status::Ok, &link))
}

impl Enrollment {
    /// Route one request to the enrollment endpoints behind the guard checks.
    async fn respond(&self, conn: &mut Conn, peer: SocketAddr) -> Reply {
        let is_issue = match conn.path() {
            "/claim" => false,
            "/issue" => true,
            _ => return Status::NotFound.into(),
        };
        if conn.request_headers().has_header(KnownHeaderName::Origin) {
            return Status::Forbidden.into();
        }
        if !is_json(conn.request_headers()) {
            return Status::UnsupportedMediaType.into();
        }
        let result = if conn.method() != Method::Post {
            Err(Status::MethodNotAllowed)
        } else if is_issue {
            issue(self, peer, conn).await
        } else {
            claim(self, peer, conn).await
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

/// Serve the enrollment listener. It always runs, headless too.
pub async fn run(listener: TcpListener, state: Enrollment) -> Result<()> {
    let tls = state.pki.enroll_tls()?;
    tracing::info!("Enrollment listening on {}.", listener.local_addr()?);
    transport::listen(listener, tls, 32, state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::Link;

    fn store_with_link(store: &mut Store, label: &str) -> [u8; 32] {
        let secret = store
            .mint(Role::Eclipse, label, Duration::from_secs(60))
            .unwrap();
        fingerprint(secret.as_slice())
    }

    #[test]
    fn a_link_works_once() {
        let mut store = Store::default();
        let hash = store_with_link(&mut store, "Eclipse 1");
        assert!(store.redeem(&[0; 32]).is_none());
        let entry = store.redeem(&hash).unwrap();
        assert_eq!(entry.role, Role::Eclipse);
        assert_eq!(entry.label, "Eclipse 1");
        assert!(store.redeem(&hash).is_none());
    }

    #[test]
    fn an_expired_link_is_refused() {
        let mut store = Store::default();
        let hash = store_with_link(&mut store, "Late");
        store.links[0].expires = Instant::now();
        assert!(store.redeem(&hash).is_none());
        assert!(store.links.is_empty());
    }

    #[test]
    fn a_cancelled_link_is_refused_and_frees_a_slot() {
        let mut store = Store::default();
        let hash = store_with_link(&mut store, "Cancelled");
        let number = store.links[0].number;
        assert!(!store.cancel(number + 1));
        assert!(store.cancel(number));
        assert!(!store.cancel(number));
        assert!(store.redeem(&hash).is_none());
    }

    #[test]
    fn at_most_sixteen_links_are_outstanding() {
        let mut store = Store::default();
        for index in 0..LINK_CAP {
            store_with_link(&mut store, &format!("Link {index}"));
        }
        assert!(matches!(
            store.mint(Role::Desktop, "One too many", LINK_TTL),
            Err(MintError::Full)
        ));
        let number = store.links[0].number;
        assert!(store.cancel(number));
        assert!(store.mint(Role::Desktop, "Fits again", LINK_TTL).is_ok());
    }

    #[test]
    fn only_the_hash_of_the_secret_is_stored() {
        let mut store = Store::default();
        let secret = store.mint(Role::Desktop, "Hashed", LINK_TTL).unwrap();
        assert_ne!(store.links[0].hash.as_slice(), secret.as_slice());
        assert_eq!(store.links[0].hash, fingerprint(secret.as_slice()));
    }

    #[test]
    fn labels_follow_the_certificate_rules() {
        assert!(valid_label("Anna Laptop"));
        assert!(!valid_label(""));
        assert!(!valid_label("   "));
        assert!(!valid_label(&"a".repeat(65)));
        assert!(!valid_label("caf\u{e9}"));
        assert!(!valid_label("tab\t"));
    }

    #[test]
    fn the_token_round_trips_through_the_shared_decoder() {
        let secret = [7_u8; 32];
        let pin = [9_u8; 32];
        let text = encode(&secret, &pin);
        assert_eq!(text.len(), 127);
        let decoded = token::decode(&text).unwrap();
        assert_eq!(&decoded[..32], secret.as_slice());
        assert_eq!(&decoded[32..], pin.as_slice());
    }

    #[derive(Deserialize)]
    struct Vectors {
        valid: Vec<Valid>,
        invalid: Vec<Invalid>,
    }

    #[derive(Deserialize)]
    struct Valid {
        link: String,
        kind: String,
        role: Option<String>,
        name: String,
        server: Option<String>,
        enrollment: Option<String>,
        endpoint: Option<String>,
        label: Option<String>,
        token: String,
    }

    #[derive(Deserialize)]
    struct Invalid {
        link: String,
        error: String,
    }

    /// The tokens in the vectors file: real encodings, regenerated here so the file cannot drift.
    fn vector_token(seed: u8) -> String {
        encode(&[seed; 32], &[seed + 1; 32])
    }

    #[test]
    fn link_vectors_agree_with_the_parser() {
        let vectors: Vectors = serde_json::from_str(include_str!(
            "../java-plugin/sap-adt-mcp-server/tests/link-vectors.json"
        ))
        .unwrap();
        assert!(vectors.valid.len() >= 8 && vectors.invalid.len() >= 20);
        let tokens: Vec<String> = (1..=16).map(vector_token).collect();
        for vector in &vectors.valid {
            assert!(tokens.contains(&vector.token), "{}", vector.link);
            assert!(token::decode(&vector.token).is_some());
            match Link::parse(&vector.link).unwrap() {
                Link::Enroll(link) => {
                    assert_eq!(vector.kind, "enroll");
                    assert_eq!(Some(link.role.as_str()), vector.role.as_deref());
                    assert_eq!(link.name, vector.name);
                    assert_eq!(Some(&link.server), vector.server.as_ref());
                    assert_eq!(Some(&link.enrollment), vector.enrollment.as_ref());
                    assert_eq!(link.label, vector.label);
                    assert_eq!(link.token.as_str(), vector.token);
                    let again = EnrollLink::parse(&link.build().unwrap()).unwrap();
                    assert_eq!(again.server, link.server);
                    assert_eq!(again.name, link.name);
                    assert_eq!(again.label, link.label);
                }
                Link::Pair(link) => {
                    assert_eq!(vector.kind, "pair");
                    assert!(vector.role.is_none() && vector.server.is_none());
                    assert_eq!(link.name, vector.name);
                    assert_eq!(Some(&link.endpoint), vector.endpoint.as_ref());
                    assert_eq!(link.token.as_str(), vector.token);
                    assert!(link.build().is_ok());
                }
            }
        }
        let mut codes = Vec::new();
        for vector in &vectors.invalid {
            let code = Link::parse(&vector.link).unwrap_err().code();
            assert_eq!(code, vector.error, "{}", vector.link);
            codes.push(code);
        }
        for code in [
            "NotALink",
            "TooLong",
            "NeedsNewerVersion",
            "MissingPart",
            "RepeatedPart",
            "UnknownRole",
            "BadName",
            "BadAddress",
            "BadPort",
            "MissingToken",
            "BadToken",
            "BadEndpoint",
            "BadEncoding",
        ] {
            assert!(codes.contains(&code), "No invalid vector for {code}.");
        }
    }
}
