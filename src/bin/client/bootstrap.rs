//! The first request contains only the request ID, role, and operator-visible label.
//! The token and private profile are handled on separate, CA-pinned connections.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use reqwest::{Response, Url};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, ring, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Serialize;

use super::transport::http_client;

#[derive(Debug)]
struct PresentedRoot(Arc<CryptoProvider>);

impl ServerCertVerifier for PresentedRoot {
    fn verify_server_cert(
        &self, leaf: &CertificateDer<'_>, chain: &[CertificateDer<'_>], name: &ServerName<'_>,
        ocsp: &[u8], now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (ca, intermediates) = chain.split_last()
            .ok_or_else(|| Error::General("The relay did not present its bootstrap CA.".into()))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.0.clone())
            .build().map_err(|err| Error::General(err.to_string()))?;
        verifier.verify_server_cert(leaf, intermediates, name, ocsp, now)
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("The bootstrap connection requires TLS 1.3.".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, signature: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, signature, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Serialize)]
struct Request<'a> {
    id: &'a str,
    label: &'a str,
    role: &'a str,
}

pub async fn request(endpoint: Url, id: &str, label: &str) -> Result<Response> {
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous().with_custom_certificate_verifier(Arc::new(PresentedRoot(provider)))
        .with_no_client_auth();
    Ok(http_client(config)?.post(endpoint).timeout(Duration::from_secs(190))
        .json(&Request { id, label, role: "desktop" }).send().await?)
}
