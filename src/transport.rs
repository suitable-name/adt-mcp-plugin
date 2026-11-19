use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::TlsAcceptor;

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

/// Each listener has its own connection budget. Only an authenticated TLS
/// handshake can populate a peer certificate in a request's extensions.
pub async fn listen(
    listener: TcpListener,
    mut tls: ServerConfig,
    max_connections: usize,
    router: Router,
) -> Result<()> {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "Could not accept a connection. Retrying in one second.");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(stream)) = timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                tracing::debug!(%peer, "TLS handshake refused or timed out.");
                return;
            };
            let mut app = router.layer(Extension::<SocketAddr>(peer));
            if let Some(leaf) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
            {
                app = app.layer(Extension(PeerCertificate::from_der(leaf.as_ref())));
            }
            let result = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15))
                .max_buf_size(32 * 1024)
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .with_upgrades()
                .await;
            if result.is_err() {
                tracing::debug!(%peer, "HTTP connection ended before completion.");
            }
        });
    }
}
