//! The enrollment connection. The link's token carries the SHA-256 of the relay CA; the
//! relay presents its CA during the handshake, and the handshake fails unless that CA
//! matches the pin. Nothing is sent before the handshake succeeds, so a wrong relay or a
//! man in the middle never receives the link's secret.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, ring, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use super::transport::http_client;
use crate::https::Client;

#[derive(Debug)]
struct PinnedPresentedCa {
    provider: Arc<CryptoProvider>,
    pin: [u8; 32],
    /// Set when the presented CA is not the pinned one.
    mismatch: Arc<AtomicBool>,
}

impl PinnedPresentedCa {
    fn refuse(&self) -> Error {
        self.mismatch.store(true, Ordering::Release);
        Error::General("wrong relay or attacker in the middle".into())
    }
}

impl ServerCertVerifier for PinnedPresentedCa {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let Some((ca, intermediates)) = chain.split_last() else {
            return Err(self.refuse());
        };
        let presented = ::ring::digest::digest(&::ring::digest::SHA256, ca.as_ref());
        if presented.as_ref() != self.pin.as_slice() {
            return Err(self.refuse());
        }
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone())?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|err| Error::General(err.to_string()))?;
        verifier.verify_server_cert(leaf, intermediates, name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General(
            "The enrollment connection requires TLS 1.3.".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An HTTPS client that completes a handshake only with a relay whose CA has SHA-256 `pin`.
/// The flag turns true when a handshake failed because the CA differed.
///
/// # Errors
/// The TLS configuration cannot be built.
pub fn pinned_client(pin: [u8; 32]) -> Result<(Client, Arc<AtomicBool>)> {
    let provider = Arc::new(ring::default_provider());
    let mismatch = Arc::new(AtomicBool::new(false));
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedPresentedCa {
            provider,
            pin,
            mismatch: Arc::clone(&mismatch),
        }))
        .with_no_client_auth();
    Ok((http_client(config), mismatch))
}
