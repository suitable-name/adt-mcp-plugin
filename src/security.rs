use anyhow::{Context, Result, anyhow, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SerialNumber,
};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::{ParsedCertificate, WebPkiClientVerifier},
};
use serde::Serialize;
use std::{
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub use sap_adt_mcp_server_relay::{storage, token};

pub struct Pki {
    dir: PathBuf,
    issuer: Issuer<'static, KeyPair>,
    ca: CertificateDer<'static>,
    ca_pem: String,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    /// The DNS name or IP address the server certificate was issued for.
    dns: String,
}

/// File in the PKI directory with the operator secret for `POST /issue`.
const ISSUE_SECRET_FILE: &str = "issue.secret";

#[derive(Clone)]
pub struct EnrolledClient {
    pub(crate) role: String,
    pub(crate) label: String,
    pub(crate) fingerprint: String,
}

#[derive(Serialize)]
pub struct Credentials {
    #[serde(rename = "ca_pem")]
    authority: String,
    #[serde(rename = "client_cert_pem")]
    certificate: String,
    #[serde(rename = "client_key_pem")]
    private_key: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}

pub fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    value
}

fn params(name: &str, sans: Vec<String>, days: i64) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(sans)?;
    params.distinguished_name.push(DnType::CommonName, name);
    // Renewal deliberately keeps the same public key. Give each issuance
    // its own serial, including renewals on the same day.
    params.serial_number = Some(SerialNumber::from_slice(uuid::Uuid::new_v4().as_bytes()));
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(days);
    Ok(params)
}

fn server_pem(
    dns: &str,
    key: &KeyPair,
    issuer: &Issuer<'_, impl rcgen::SigningKey>,
) -> Result<String> {
    ServerName::try_from(dns)
        .context("Use a DNS name or IP address for the server certificate.")?;
    let mut server = params(dns, vec![dns.into()], 825)?;
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(server.signed_by(key, issuer)?.pem())
}

fn check_key(cert: &CertificateDer<'_>, key: &KeyPair) -> Result<()> {
    let public = ParsedCertificate::try_from(cert)?.subject_public_key_info();
    ensure!(
        public.as_ref() == key.subject_public_key_info().as_slice(),
        "Certificate and private key do not match."
    );
    Ok(())
}

fn initialize_files(dir: &Path, files: &[(&str, &str)]) -> Result<()> {
    storage::new_directory(dir)?;
    let mut created_dirs = vec![dir.to_path_buf()];
    let mut created_files = Vec::new();
    let result = (|| -> Result<()> {
        for role in ["desktop", "eclipse"] {
            let path = dir.join(role);
            fs::create_dir(&path)?;
            created_dirs.push(path);
        }
        for &(name, contents) in files {
            let path = dir.join(name);
            storage::write_new(&path, contents.as_bytes())?;
            created_files.push(path);
        }
        Ok(())
    })();
    if result.is_err() {
        for path in created_files {
            if let Err(error) = fs::remove_file(&path) {
                eprintln!(
                    "Failed to remove incomplete PKI file {}: {error}",
                    path.display()
                );
            }
        }
        for path in created_dirs.into_iter().rev() {
            if let Err(error) = fs::remove_dir(&path) {
                eprintln!(
                    "Failed to remove incomplete PKI directory {}: {error}",
                    path.display()
                );
            }
        }
    }
    result
}

fn pem_cert(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let mut certs = rustls_pemfile::certs(&mut reader);
    let first = certs.next().context("Certificate PEM is empty.")??;
    ensure!(certs.next().is_none(), "Expected one certificate.");
    Ok(first)
}

impl Pki {
    pub(crate) fn init(dir: &Path, dns: &str) -> Result<()> {
        let ca_key = KeyPair::generate()?;
        let mut ca = params("SAP ADT relay CA", Vec::new(), 3650)?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca.self_signed(&ca_key)?;
        let issuer = Issuer::from_params(&ca, &ca_key);
        let server_key = KeyPair::generate()?;
        let server_cert = server_pem(dns, &server_key, &issuer)?;
        // Publish the bootstrap certificate only after the other files exist.
        initialize_files(
            dir,
            &[
                ("ca.key", &Zeroizing::new(ca_key.serialize_pem())),
                ("server.key", &Zeroizing::new(server_key.serialize_pem())),
                ("server.pem", &server_cert),
                ("ca.pem", &ca_cert.pem()),
            ],
        )
    }

    pub(crate) fn load(dir: &Path) -> Result<Self> {
        let ca_pem = fs::read_to_string(dir.join("ca.pem"))
            .context("Cannot read the initialized relay CA.")?;
        let ca = pem_cert(&ca_pem)?;
        let issuer_key = Zeroizing::new(fs::read_to_string(dir.join("ca.key"))?);
        let ca_key = KeyPair::from_pem(&issuer_key)?;
        check_key(&ca, &ca_key).context("Checking ca.pem against ca.key")?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;
        let server_cert = pem_cert(&fs::read_to_string(dir.join("server.pem"))?)?;
        let mut reader = BufReader::new(fs::File::open(dir.join("server.key"))?);
        let server_key =
            rustls_pemfile::private_key(&mut reader)?.context("Missing server private key.")?;
        check_key(&server_cert, &KeyPair::try_from(&server_key)?)
            .context("Checking server.pem against server.key")?;
        for role in ["desktop", "eclipse"] {
            ensure!(dir.join(role).is_dir(), "Missing role directory: {role}.");
        }
        let dns = certificate_name(&server_cert)?;
        Ok(Self {
            dir: dir.to_owned(),
            issuer,
            ca,
            ca_pem,
            server_cert,
            server_key,
            dns,
        })
    }

    /// The name the server certificate was issued for.
    pub(crate) fn dns_name(&self) -> &str {
        &self.dns
    }

    /// Create a fresh operator secret (32 random bytes as hex) in `<pki>/issue.secret`,
    /// replacing the one of an earlier run. The file is private to the owner like the CA key.
    pub(crate) fn create_issue_secret(&self) -> Result<Zeroizing<String>> {
        use ring::rand::{SecureRandom, SystemRandom};

        let mut bytes = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(bytes.as_mut_slice())
            .map_err(|_| anyhow!("System randomness unavailable."))?;
        let secret = Zeroizing::new(hex::encode(bytes.as_slice()));
        let path = self.dir.join(ISSUE_SECRET_FILE);
        storage::stage(&path, secret.as_bytes())?
            .persist(&path)
            .map_err(|error| error.error)
            .context("Cannot write the operator secret.")?;
        Ok(secret)
    }

    pub(crate) fn ca_pin(&self) -> [u8; 32] {
        fingerprint(self.ca.as_ref())
    }

    pub(crate) fn renew_server(&self, dns: &str) -> Result<()> {
        let pem = server_pem(dns, &KeyPair::try_from(&self.server_key)?, &self.issuer)?;
        let path = self.dir.join("server.pem");
        storage::stage(&path, pem.as_bytes())?
            .persist(&path)
            .map_err(|error| error.error)?;
        Ok(())
    }

    fn tls(&self, client_auth: bool) -> Result<ServerConfig> {
        let provider = Arc::new(default_provider());
        let config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let config = if client_auth {
            let mut roots = RootCertStore::empty();
            roots.add(self.ca.clone())?;
            config.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build()?,
            )
        } else {
            config.with_no_client_auth()
        };
        let mut config = config.with_single_cert(
            vec![self.server_cert.clone(), self.ca.clone()],
            self.server_key.clone_key(),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    pub(crate) fn data_tls(&self) -> Result<ServerConfig> {
        self.tls(true)
    }

    pub(crate) fn enroll_tls(&self) -> Result<ServerConfig> {
        self.tls(false)
    }

    pub(crate) fn eclipse_enrolled(&self, endpoint: &str) -> bool {
        valid_fingerprint(endpoint)
            && fs::symlink_metadata(self.dir.join("eclipse").join(endpoint))
                .is_ok_and(|metadata| metadata.is_file())
    }

    pub(crate) fn eclipse_label(&self, endpoint: &str) -> Result<Option<String>> {
        ensure!(valid_fingerprint(endpoint), "Invalid Eclipse endpoint ID.");
        enrolled_label(&self.dir.join("eclipse").join(endpoint))
    }

    pub(crate) fn authorize(&self, leaf_der: &[u8], role: &str) -> bool {
        matches!(role, "desktop" | "eclipse")
            && fs::symlink_metadata(self.dir.join(role).join(hex::encode(fingerprint(leaf_der))))
                .is_ok_and(|file| file.is_file())
            && has_signed_role(leaf_der, role)
    }

    pub(crate) fn clients(&self) -> Result<Vec<EnrolledClient>> {
        let mut clients = Vec::new();
        for role in ["desktop", "eclipse"] {
            for entry in fs::read_dir(self.dir.join(role))? {
                let entry = entry?;
                let name = entry.file_name();
                if let Some(pin) = name.to_str().filter(|pin| valid_fingerprint(pin))
                    && let Some(label) = enrolled_label(&entry.path())?
                {
                    clients.push(EnrolledClient {
                        role: role.to_owned(),
                        label,
                        fingerprint: pin.to_owned(),
                    });
                }
            }
        }
        Ok(clients)
    }

    pub(crate) fn revoke(&self, role: &str, pin: &str) -> Result<()> {
        ensure!(
            matches!(role, "desktop" | "eclipse") && valid_fingerprint(pin),
            "Use a role and its full lowercase SHA-256 fingerprint."
        );
        fs::remove_file(self.dir.join(role).join(pin))
            .context("Cannot remove the enrolled certificate pin.")
    }

    pub(crate) fn issue(&self, role: &str, label: &str) -> Result<Credentials> {
        ensure!(
            matches!(role, "desktop" | "eclipse"),
            "Unknown certificate role."
        );
        let key = KeyPair::generate()?;
        let mut client = params(&format!("{role}:{label}"), Vec::new(), 365)?;
        client.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = client.signed_by(&key, &self.issuer)?;
        let pin = self
            .dir
            .join(role)
            .join(hex::encode(fingerprint(cert.der().as_ref())));
        storage::write_new(&pin, label.as_bytes())?;
        Ok(Credentials {
            authority: self.ca_pem.clone(),
            certificate: cert.pem(),
            private_key: key.serialize_pem(),
        })
    }
}

/// The common name of a certificate, which for the server certificate is its DNS name.
fn certificate_name(cert: &CertificateDer<'_>) -> Result<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|_| anyhow!("Cannot read the server certificate."))?;
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|field| field.as_str().ok())
        .map(str::to_owned)
        .context("The server certificate has no name.")
}

/// The CA certificate of a PKI directory (read-only access for `issue-link`).
pub fn read_ca(dir: &Path) -> Result<CertificateDer<'static>> {
    pem_cert(&fs::read_to_string(dir.join("ca.pem")).context("Cannot read the relay CA.")?)
}

/// The DNS name of the server certificate of a PKI directory.
pub fn read_server_name(dir: &Path) -> Result<String> {
    certificate_name(&pem_cert(
        &fs::read_to_string(dir.join("server.pem"))
            .context("Cannot read the server certificate.")?,
    )?)
}

/// The operator secret the running relay created in `<pki>/issue.secret`.
pub fn read_issue_secret(dir: &Path) -> Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(dir.join(ISSUE_SECRET_FILE))
            .context("Cannot read issue.secret. Start the relay with this PKI directory first.")?,
    );
    let secret = text.trim();
    ensure!(
        secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()),
        "issue.secret is malformed."
    );
    Ok(Zeroizing::new(secret.to_owned()))
}

fn enrolled_label(path: &Path) -> Result<Option<String>> {
    use std::io::{ErrorKind, Read};

    let file = match fs::symlink_metadata(path).and_then(|metadata| {
        if metadata.is_file() {
            fs::File::open(path).map(Some)
        } else {
            Ok(None)
        }
    }) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(64).read_to_end(&mut bytes)?;
    let label = bytes
        .into_iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                char::from(byte)
            } else {
                '?'
            }
        })
        .collect();
    Ok(Some(label))
}

pub fn valid_fingerprint(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn has_signed_role(der: &[u8], expected: &str) -> bool {
    let Ok((remainder, cert)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    let mut names = cert.subject().iter_common_name();
    let role = names
        .next()
        .and_then(|field| field.as_str().ok())
        .and_then(|name| name.split_once(':'));
    remainder.is_empty()
        && cert.validity().is_valid()
        && names.next().is_none()
        && role.is_some_and(|(role, label)| role == expected && !label.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_initialization_rolls_back_only_its_files_and_can_be_retried() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("pki");
        assert!(initialize_files(&dir, &[("ca.key", "first"), ("ca.key", "second")]).is_err());
        assert!(!dir.exists());
        Pki::init(&dir, "localhost").unwrap();
        assert!(Pki::load(&dir).is_ok());
    }

    #[test]
    fn load_refuses_a_mismatched_ca_private_key() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("pki");
        Pki::init(&dir, "localhost").unwrap();
        fs::write(
            dir.join("ca.key"),
            KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        assert!(Pki::load(&dir).is_err());
    }

    #[test]
    fn renewal_preserves_keys_and_enrolled_clients() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("pki");
        Pki::init(&dir, "localhost").unwrap();
        let pki = Pki::load(&dir).unwrap();
        let leaf = pem_cert(&pki.issue("desktop", "test").unwrap().certificate).unwrap();
        assert!(pki.renew_server("https://invalid.example").is_err());
        assert_eq!(Pki::load(&dir).unwrap().server_cert, pki.server_cert);
        pki.renew_server("replacement.example").unwrap();
        let renewed = Pki::load(&dir).unwrap();
        assert_eq!(renewed.ca, pki.ca);
        assert_ne!(renewed.server_cert, pki.server_cert);
        assert_eq!(
            fingerprint(renewed.server_key.secret_der()),
            fingerprint(pki.server_key.secret_der())
        );
        assert!(renewed.authorize(&leaf, "desktop"));
        let cert = ParsedCertificate::try_from(&renewed.server_cert).unwrap();
        rustls::client::verify_server_name(
            &cert,
            &ServerName::try_from("replacement.example").unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn authorization_is_role_scoped_persistent_and_revocable() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("pki");
        Pki::init(&dir, "localhost").unwrap();
        assert!(Pki::init(&dir, "localhost").is_err());
        let pki = Pki::load(&dir).unwrap();
        let bundle = pki.issue("desktop", "test desktop").unwrap();
        let leaf = pem_cert(&bundle.certificate).unwrap();
        let pki = Pki::load(&dir).unwrap();
        assert!(pki.authorize(&leaf, "desktop"));
        assert!(!pki.authorize(&leaf, "eclipse"));
        assert!(!pki.authorize(&leaf, "../desktop"));
        let pin = hex::encode(fingerprint(&leaf));
        fs::copy(
            dir.join("desktop").join(&pin),
            dir.join("eclipse").join(&pin),
        )
        .unwrap();
        assert!(!pki.authorize(&leaf, "eclipse"));
        assert!(pki.revoke("desktop", "../ca.key").is_err());
        pki.revoke("desktop", &pin).unwrap();
        assert!(!pki.authorize(&leaf, "desktop"));
    }
}
