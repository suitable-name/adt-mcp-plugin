//! Minimal HTTPS/1.1 client on Trillium (trillium-client, trillium-rustls, trillium-smol),
//! replacing reqwest.
//!
//! Design:
//! - Every [`Client`] owns one rustls configuration (custom roots, pinned verifiers, client
//!   certificates) and one Trillium client built from it. The configuration is never shared
//!   between clients, so a connection can never be reused under another TLS identity.
//! - Connection reuse is off (`without_keepalive`): every request opens its own TCP and TLS
//!   connection, sends one request and reads one response, then closes it.
//! - HTTPS only (checked before the request is built), HTTP/1.1 only: ALPN is `http/1.1`, the
//!   request pins `Version::Http1_1`, and the client is built without QUIC, so there is no h2,
//!   no h3 and no `Alt-Svc` handling. Trillium's `hickory` (encrypted DNS) feature is not enabled.
//! - No proxies: Trillium only uses a proxy after `with_proxy`/`Proxy::from_env`, which this
//!   module never calls, so `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are ignored.
//! - No redirects, retries, cookies or default `User-Agent`: Trillium follows redirects and retries
//!   only through a `ClientHandler`, and none is installed.
//! - The 10 s connect timeout covers TCP and the TLS handshake (a connector wrapper bounds
//!   `connect`/`connect_to`); the request timeout covers everything up to the end of the body.
//!
//! Part of the shared library, next to [`crate::rt`].

use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use rustls::ClientConfig;
use serde::Serialize;
use smol::io::AsyncReadExt;
use trillium_client::{
    Conn, Connector, HeaderName, HeaderValues, KnownHeaderName, Method, Status, Url, Version,
};
use trillium_rustls::RustlsConfig;
use trillium_server_common::Destination;
use trillium_smol::ClientConfig as TcpConfig;
use zeroize::Zeroizing;

use crate::rt;

/// TCP connection and TLS handshake together.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole request unless overridden: connect, send, response headers and body.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(620);
/// Bytes moved per body read.
const CHUNK: usize = 8 * 1024;

type Tls = RustlsConfig<TcpConfig>;

/// The rustls connector with a bounded connect phase.
struct Dialer(Tls);

async fn within_connect_limit<T>(connect: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    rt::timeout(CONNECT_TIMEOUT, connect)
        .await
        .unwrap_or_else(|elapsed| Err(io::Error::new(io::ErrorKind::TimedOut, elapsed)))
}

impl Connector for Dialer {
    type Transport = <Tls as Connector>::Transport;
    type Runtime = <Tls as Connector>::Runtime;
    type Udp = <Tls as Connector>::Udp;

    async fn connect(&self, url: &Url) -> io::Result<Self::Transport> {
        within_connect_limit(self.0.connect(url)).await
    }

    async fn connect_to(&self, destination: Destination) -> io::Result<Self::Transport> {
        within_connect_limit(self.0.connect_to(destination)).await
    }

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.0.resolve(host, port).await
    }

    fn runtime(&self) -> Self::Runtime {
        self.0.runtime()
    }
}

#[derive(Clone)]
pub struct Client {
    inner: trillium_client::Client,
}

impl Client {
    /// Use `config` for every connection. ALPN is forced to HTTP/1.1.
    #[must_use]
    pub fn new(mut config: ClientConfig) -> Self {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = RustlsConfig::new(config, TcpConfig::new().with_nodelay(true)).without_http2();
        let inner = trillium_client::Client::new(Dialer(tls))
            .without_keepalive()
            .without_default_header(KnownHeaderName::UserAgent);
        Self { inner }
    }

    #[must_use]
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        let conn = parse_https(url.as_ref()).map(|url| {
            Box::new(
                self.inner
                    .build_conn(method, url)
                    .with_http_version(Version::Http1_1),
            )
        });
        RequestBuilder {
            conn,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::Post, url)
    }
}

fn parse_https(url: &str) -> Result<Url> {
    let url = Url::parse(url).context("Invalid URL.")?;
    ensure!(url.scheme() == "https", "Only HTTPS URLs are supported.");
    ensure!(url.has_host(), "The URL has no host.");
    Ok(url)
}

pub struct RequestBuilder {
    // Boxed: a Trillium `Conn` is large, and builders and send futures live in callers' futures.
    conn: Result<Box<Conn>>,
    timeout: Duration,
}

impl RequestBuilder {
    #[must_use]
    pub fn header(
        mut self,
        name: impl Into<HeaderName<'static>>,
        value: impl Into<HeaderValues>,
    ) -> Self {
        self.conn = self
            .conn
            .map(|conn| Box::new(conn.with_request_header(name, value)));
        self
    }

    /// Send `body` as the request body (omitted entirely unless this is called).
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        let body: Vec<u8> = body.into();
        self.conn = self.conn.map(|conn| Box::new(conn.with_body(body)));
        self
    }

    /// Serialize `value` as the body and set `Content-Type: application/json`.
    #[must_use]
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        self.conn = match serde_json::to_vec(value) {
            Ok(body) => self.conn.map(|conn| {
                Box::new(
                    conn.with_body(body)
                        .with_request_header(KnownHeaderName::ContentType, "application/json"),
                )
            }),
            Err(error) => Err(error.into()),
        };
        self
    }

    /// Whole-request timeout (connect, headers and body) for this request.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// # Errors
    /// Returns an error for an invalid request, a connection or TLS failure, or a timeout.
    /// An HTTP error status is not an error.
    pub async fn send(self) -> Result<Response> {
        let conn = self.conn?;
        let deadline = Instant::now() + self.timeout;
        let host = conn.url().host_str().unwrap_or_default().to_owned();
        // Trillium's request future is tens of KiB; keep it off every caller's stack frame.
        let conn = Box::pin(rt::timeout(self.timeout, (*conn).into_future()))
            .await
            .map_err(|_| anyhow!("Timed out waiting for {host}."))?
            .map_err(|error| anyhow!("{error}"))?;
        let status = conn
            .status()
            .context("The relay sent no response status.")?;
        Ok(Response {
            conn: Box::new(conn),
            status,
            deadline,
        })
    }
}

pub struct Response {
    // Boxed so that futures holding a `Response` stay small.
    conn: Box<Conn>,
    status: Status,
    deadline: Instant,
}

impl Response {
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// The first value of the response header `name`, if it is valid text.
    #[must_use]
    pub fn header(&self, name: impl Into<HeaderName<'static>>) -> Option<&str> {
        let name: HeaderName<'static> = name.into();
        self.conn.response_headers().get_str(name)
    }

    /// Read the whole body, failing once it exceeds `limit` bytes.
    ///
    /// # Errors
    /// Returns an error if the body exceeds `limit`, the connection fails, or the request deadline passes.
    pub async fn bytes(mut self, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        Box::pin(rt::timeout(remaining, async {
            let mut body = self.conn.response_body().with_max_len(cap);
            let mut bytes = Zeroizing::new(Vec::new());
            let mut chunk = Zeroizing::new(vec![0_u8; CHUNK]);
            loop {
                let read = body.read(&mut chunk[..]).await?;
                if read == 0 {
                    return Ok::<_, anyhow::Error>(bytes);
                }
                ensure!(
                    read <= limit - bytes.len(),
                    "Relay response exceeds the size limit."
                );
                bytes.extend_from_slice(&chunk[..read]);
            }
        }))
        .await
        .map_err(|_| anyhow!("Timed out reading the response body."))?
    }
}
