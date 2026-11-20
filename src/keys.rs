//! The desktop profile's inner identity key (`docs/plan-e2e-envelope.md` §1, D1).
//!
//! An ECDSA P-256 key with a self-signed certificate, separate from the relay certificate.
//! The pin the Eclipse plugin stores is the SHA-256 of the key's `SubjectPublicKeyInfo` DER, not
//! of the certificate. Both files live in the profile directory, created owner-only like
//! `credentials.json`.

use std::{io::BufReader, path::Path};

use anyhow::{Context, Result, anyhow, ensure};
use rcgen::{CertificateParams, DnType, KeyPair, PublicKeyData};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::ParsedCertificate,
};
use zeroize::Zeroizing;

use crate::storage::{self, read_file};

/// Parses exactly one PEM certificate.
///
/// # Errors
/// The input holds no certificate, more than one, or a damaged one.
pub fn certificate(pem: &[u8]) -> Result<CertificateDer<'static>> {
    let mut input = BufReader::new(pem);
    let mut certs = rustls_pemfile::certs(&mut input);
    let cert = certs
        .next()
        .transpose()?
        .context("Expected a PEM certificate.")?;
    ensure!(
        certs.next().is_none(),
        "Expected exactly one PEM certificate."
    );
    Ok(cert)
}

pub const KEY_FILE: &str = "inner_key.pem";
pub const CERT_FILE: &str = "inner_cert.pem";

/// The SPKI DER of an X.509 certificate.
///
/// # Errors
/// The certificate cannot be parsed.
pub fn spki_of(cert: &CertificateDer<'_>) -> Result<Vec<u8>, rustls::Error> {
    let parsed = ParsedCertificate::try_from(cert)?;
    let spki = parsed.subject_public_key_info();
    Ok(spki.as_ref().to_vec())
}

/// The SHA-256 of a `SubjectPublicKeyInfo` DER: the pin.
#[must_use]
pub fn spki_fingerprint(spki: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, spki).as_ref());
    value
}

/// The first 16 hex characters of a fingerprint, grouped in fours: `ab12 cd34 ef56 7890`.
#[must_use]
pub fn short_form(fingerprint: &[u8; 32]) -> String {
    hex::encode(&fingerprint[..8])
        .as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The inner identity: private key, self-signed certificate and pin.
pub struct InnerKey {
    pair: KeyPair,
    cert: CertificateDer<'static>,
    fingerprint: [u8; 32],
}

impl InnerKey {
    /// Loads the profile's inner key, creating key and certificate on first use.
    ///
    /// # Errors
    /// A file is unreadable or damaged, or the certificate does not belong to the key.
    pub fn load_or_create(directory: &Path) -> Result<Self> {
        let key_path = directory.join(KEY_FILE);
        let cert_path = directory.join(CERT_FILE);
        let pair = if key_path.try_exists()? {
            let pem = read_file(&key_path).context("Could not read the inner key.")?;
            let text = std::str::from_utf8(&pem).map_err(|_| anyhow!("Invalid inner key."))?;
            KeyPair::from_pem(text).map_err(|_| anyhow!("Invalid inner key."))?
        } else {
            let pair = KeyPair::generate().context("Could not generate the inner key.")?;
            let pem = Zeroizing::new(pair.serialize_pem());
            storage::write_new(&key_path, pem.as_bytes())
                .context("Could not store the inner key.")?;
            pair
        };
        let spki = pair.subject_public_key_info();
        let cert = if cert_path.try_exists()? {
            let pem = read_file(&cert_path).context("Could not read the inner certificate.")?;
            let cert = certificate(&pem).context("Invalid inner certificate.")?;
            let found = spki_of(&cert).map_err(|_| anyhow!("Invalid inner certificate."))?;
            ensure!(
                found == spki,
                "The inner certificate does not belong to the inner key."
            );
            cert
        } else {
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params
                .distinguished_name
                .push(DnType::CommonName, "sap-adt-mcp-client");
            let made = params.self_signed(&pair)?;
            storage::write_new(&cert_path, made.pem().as_bytes())
                .context("Could not store the inner certificate.")?;
            made.der().clone()
        };
        Ok(Self {
            fingerprint: spki_fingerprint(&spki),
            pair,
            cert,
        })
    }

    /// The pin: SHA-256 of the `SubjectPublicKeyInfo` DER.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// The pin as 64 lowercase hex characters.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// The short form for display, as the plugin shows it in its pairing dialog.
    #[must_use]
    pub fn short_fingerprint(&self) -> String {
        short_form(&self.fingerprint)
    }

    /// The self-signed certificate to present as the TLS client certificate.
    #[must_use]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    /// The private key in the form rustls wants.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pair.serialize_der()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_is_stored_and_reloaded_with_the_same_pin() {
        let directory = tempfile::tempdir().unwrap();
        let first = InnerKey::load_or_create(directory.path()).unwrap();
        assert!(directory.path().join(KEY_FILE).exists());
        assert!(directory.path().join(CERT_FILE).exists());
        let second = InnerKey::load_or_create(directory.path()).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint_hex().len(), 64);
        // The pin is the SPKI hash of the certificate the plugin will see.
        let spki = spki_of(&first.certificate()).unwrap();
        assert_eq!(&spki_fingerprint(&spki), first.fingerprint());
    }

    #[test]
    fn a_certificate_of_another_key_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        InnerKey::load_or_create(directory.path()).unwrap();
        let other = tempfile::tempdir().unwrap();
        InnerKey::load_or_create(other.path()).unwrap();
        std::fs::copy(
            other.path().join(CERT_FILE),
            directory.path().join(CERT_FILE),
        )
        .unwrap();
        assert!(InnerKey::load_or_create(directory.path()).is_err());
    }

    #[test]
    fn the_short_form_is_sixteen_characters_in_groups_of_four() {
        let mut fingerprint = [0_u8; 32];
        fingerprint[..8].copy_from_slice(&[0xab, 0x12, 0xcd, 0x34, 0xef, 0x56, 0x78, 0x90]);
        assert_eq!(short_form(&fingerprint), "ab12 cd34 ef56 7890");
    }
}
