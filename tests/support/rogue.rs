//! A rogue "relay": a TLS listener with a CA of its own, which a desktop client must refuse
//! because the CA differs from the fingerprint in the enrollment link.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use futures_rustls::TlsAcceptor;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use smol::{Task, net::TcpListener};

use crate::rt::{self, timeout};

/// Listen once on loopback. The task yields whether a TLS handshake completed, which would
/// mean the client trusted the rogue relay and went on to send its request.
pub async fn start() -> Result<(SocketAddr, Task<bool>)> {
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_cert = ca.self_signed(&ca_key)?;
    let issuer = Issuer::from_params(&ca, &ca_key);
    let key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])?.signed_by(&key, &issuer)?;
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca_cert.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = rt::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return false;
        };
        timeout(Duration::from_secs(10), acceptor.accept(socket))
            .await
            .is_ok_and(|handshake| handshake.is_ok())
    });
    Ok((address, task))
}
