//! A stand-in for the plugin's side of the inner TLS, for unit tests of the library and of the
//! desktop client: client authentication required, only the pinned desktop key accepted.
//!
//! Test-only: the library declares it under `#[cfg(test)]`, and the client binary includes it
//! with `#[path]` under `#[cfg(test)]`, so both test builds share one copy.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, ServerConfig, ServerConnection,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

use crate::{
    inner_tls::provider,
    keys::{spki_fingerprint, spki_of},
};

/// A key with its certificate and pin, standing in for either side.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub pin: [u8; 32],
}

pub fn identity() -> Identity {
    let pair = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&pair)
        .unwrap();
    Identity {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der())),
        pin: spki_fingerprint(&pair.subject_public_key_info()),
    }
}

/// The plugin's side as the plan describes it: client authentication required, only the
/// pinned desktop key accepted.
#[derive(Debug)]
struct PinnedClient {
    provider: Arc<CryptoProvider>,
    pin: [u8; 32],
}

impl ClientCertVerifier for PinnedClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let found = spki_fingerprint(&spki_of(end_entity)?);
        if found == self.pin {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General("unknown desktop key".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 refused".into()))
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
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

pub fn plugin(server: Identity, desktop_pin: [u8; 32]) -> ServerConnection {
    let provider = provider();
    let verifier = PinnedClient {
        provider: provider.clone(),
        pin: desktop_pin,
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![server.cert], server.key)
        .unwrap();
    ServerConnection::new(Arc::new(config)).unwrap()
}
