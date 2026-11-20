//! `sap-adt-mcp-server-relay issue-link`: mint a link on the running relay over loopback TLS.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Serialize;
use trillium_client::{KnownHeaderName, Status};
use zeroize::Zeroizing;

use crate::{https::Client, security};

/// Trusts only the relay CA read from the PKI directory. The listener is addressed by
/// IP (loopback), so the certificate is checked for the name the PKI issued it for.
#[derive(Debug)]
struct PinnedCa {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(leaf, intermediates, &self.name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Serialize)]
struct Request<'a> {
    role: &'a str,
    label: &'a str,
}

fn client(pki: &Path) -> Result<Client> {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(security::read_ca(pki)?)?;
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("Cannot trust the relay CA of this PKI directory.")?;
    let name = ServerName::try_from(security::read_server_name(pki)?)
        .context("The server certificate has no usable name.")?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCa { inner, name }))
        .with_no_client_auth();
    Ok(Client::new(config))
}

/// Ask the running relay for a new link. `relay` is the `host:port` of its enrollment
/// listener on this machine. The operator secret comes from `<pki>/issue.secret`.
///
/// # Errors
/// The relay is unreachable, refuses the request, or answers with something unreadable.
pub async fn issue_link(
    pki: &Path,
    role: &str,
    label: &str,
    relay: &str,
) -> Result<Zeroizing<String>> {
    let secret = security::read_issue_secret(pki)?;
    let response = client(pki)?
        .post(format!("https://{relay}/issue"))
        .header(
            KnownHeaderName::Authorization,
            format!("Bearer {}", secret.as_str()),
        )
        .json(&Request { role, label })
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .with_context(|| {
            format!("Could not reach the enrollment listener at {relay}. Is `serve` running with this PKI directory?")
        })?;
    let status = response.status();
    if !status.is_success() {
        bail!(match status {
            Status::Forbidden => "The relay refused the request. Run issue-link on the relay's machine with the PKI directory it was started with.".to_owned(),
            Status::TooManyRequests => "The relay already has 16 outstanding links. Cancel one in the Enrollment tab or wait for one to expire.".to_owned(),
            Status::BadRequest => "The relay refused the role or label.".to_owned(),
            other => format!("The relay answered HTTP {other}."),
        });
    }
    let body = response.bytes(4096).await?;
    let link = Zeroizing::new(
        std::str::from_utf8(&body)
            .context("The relay sent an unreadable link.")?
            .trim()
            .to_owned(),
    );
    Ok(link)
}
