use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use futures_rustls::{TlsAcceptor, server::TlsStream};
use rustls::ServerConfig;
use smol::{
    Timer,
    io::{AsyncRead, AsyncWrite},
    lock::{Semaphore, SemaphoreGuardArc},
    net::{TcpListener, TcpStream},
};
use trillium_http::{
    HttpConfig, HttpContext,
    h1::{H1Connection, H1ConnectionResult},
};

use crate::rt::{self, timeout};

/// The longest a connection may wait for the peer's next bytes while the HTTP
/// parser is reading (a request head, or a request body).
const READ_IDLE: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct PeerCertificate {
    pub(crate) der: Arc<[u8]>,
    pub(crate) fingerprint: [u8; 32],
}

impl PeerCertificate {
    fn from_der(der: &[u8]) -> Self {
        Self {
            der: Arc::from(der),
            fingerprint: crate::security::fingerprint(der),
        }
    }
}

/// Who is on the other end of a connection. The certificate is the leaf of the
/// chain verified during the TLS handshake.
#[derive(Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub cert: Option<PeerCertificate>,
}

/// The TLS stream with a read-idle limit that is lifted after an upgrade.
pub type Transport = Guarded<TlsStream<TcpStream>>;
pub type Conn = trillium_http::Conn<Transport>;
pub type Upgrade = trillium_http::Upgrade<Transport>;

/// Fails reads that wait longer than [`READ_IDLE`] for the peer while enforced.
/// `trillium-http` has no head-read timeout, and this bounds a slow request
/// head in the same way: the HTTP parser only reads while it expects bytes.
pub struct Guarded<T> {
    inner: T,
    idle: Option<Timer>,
    enforce: Arc<AtomicBool>,
}

impl<T> Guarded<T> {
    fn new(inner: T) -> (Self, Arc<AtomicBool>) {
        let enforce = Arc::new(AtomicBool::new(true));
        (
            Self {
                inner,
                idle: None,
                enforce: Arc::clone(&enforce),
            },
            enforce,
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => {
                if this.enforce.load(Ordering::Relaxed) {
                    let timer = this.idle.get_or_insert_with(|| Timer::after(READ_IDLE));
                    if Pin::new(timer).poll(cx).is_ready() {
                        this.idle = None;
                        return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                    }
                }
                Poll::Pending
            }
            ready @ Poll::Ready(_) => {
                this.idle = None;
                ready
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// A value a request handler leaves for the upgrade that follows its response.
pub struct Handoff<P>(Arc<Mutex<Option<P>>>);

impl<P> Clone for Handoff<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<P> Default for Handoff<P> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<P> Handoff<P> {
    pub fn set(&self, value: P) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
    }

    fn take(&self) -> Option<P> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// The application behind a listener.
pub trait Service: Clone + Send + Sync + 'static {
    /// What a handler passes to [`Service::upgrade`].
    type Pending: Send + 'static;

    /// Answer one request. Setting status 101 hands the connection to
    /// [`Service::upgrade`] once the response is sent.
    fn handle(
        &self,
        conn: Conn,
        peer: &Peer,
        handoff: &Handoff<Self::Pending>,
    ) -> impl Future<Output = Conn> + Send;

    /// Take over an upgraded connection.
    fn upgrade(
        &self,
        upgrade: Upgrade,
        peer: &Peer,
        pending: Option<Self::Pending>,
    ) -> impl Future<Output = ()> + Send;
}

/// How long a finished connection may take to close gracefully.
const GRACEFUL_CLOSE: Duration = Duration::from_secs(5);

/// Each listener has its own connection budget. Only an authenticated TLS
/// handshake can populate a peer certificate.
pub async fn listen<S: Service>(
    listener: TcpListener,
    mut tls: ServerConfig,
    max_connections: usize,
    service: S,
) -> Result<()> {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let slots = Arc::new(Semaphore::new(max_connections));
    // Header blocks are limited to 32 KiB. Request bodies are limited where they are read.
    let context = Arc::new(
        HttpContext::new().with_config(HttpConfig::default().with_head_max_len(32 * 1024)),
    );
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "Could not accept a connection. Retrying in one second.");
                Timer::after(Duration::from_secs(1)).await;
                continue;
            }
        };
        let Some(permit) = slots.try_acquire_arc() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let context = Arc::clone(&context);
        let service = service.clone();
        rt::spawn(async move {
            let Ok(Ok(stream)) = timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                tracing::debug!(%peer, "TLS handshake refused or timed out.");
                return;
            };
            serve(context, stream, peer, &service, permit).await;
        })
        .detach();
    }
}

async fn serve<S: Service>(
    context: Arc<HttpContext>,
    stream: TlsStream<TcpStream>,
    addr: SocketAddr,
    service: &S,
    permit: SemaphoreGuardArc,
) {
    let cert = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| PeerCertificate::from_der(leaf.as_ref()));
    let peer = Peer { addr, cert };
    let (transport, enforce) = Guarded::new(stream);
    let handoff = Handoff::default();
    let result = H1Connection::new(context, transport)
        .run(|conn| {
            let service = service.clone();
            let peer = peer.clone();
            let handoff = handoff.clone();
            async move { service.handle(conn, &peer, &handoff).await }
        })
        .await;
    match result {
        H1ConnectionResult::Upgrade(upgrade) => {
            // An upgraded connection outlives the HTTP connection budget
            // and is bounded by its own limit (for example, the bridge limit).
            drop(permit);
            enforce.store(false, Ordering::Relaxed);
            service.upgrade(upgrade, &peer, handoff.take()).await;
        }
        H1ConnectionResult::Close(close) => {
            // Close gracefully: stop sending, then discard what the client still sends (such
            // as the body of a refused request) until it closes. Dropping the socket instead
            // makes the OS answer with a TCP reset, which can destroy the response before the
            // client reads it (seen on Linux). The timeout bounds a client that never closes.
            let _ = timeout(GRACEFUL_CLOSE, close).await;
            drop(permit);
        }
        // An error, or a kind of ending this trillium-http version does not have yet.
        _ => {
            drop(permit);
            tracing::debug!(%addr, "HTTP connection ended before completion.");
        }
    }
}
