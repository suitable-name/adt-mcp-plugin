use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use reqwest::{Client, Response, Url};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, UnixTime},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const PROFILE_NAME: &str = "credentials.json";

#[derive(Deserialize, Serialize)]
pub struct Credentials {
    #[serde(rename = "ca_pem")]
    pub ca: String,
    #[serde(rename = "client_cert_pem")]
    client_cert: String,
    #[serde(rename = "client_key_pem")]
    client_key: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.client_key.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
pub struct Profile {
    pub server: String,
    pub credentials: Credentials,
}

impl Profile {
    pub fn load(directory: &Path) -> Result<Self> {
        let bytes = read_file(&directory.join(PROFILE_NAME))
            .context("Could not open the client profile.")?;
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid client profile."))
    }

    pub fn connection(&self) -> Result<(Client, Url)> {
        let url = endpoint(&self.server, "/mcp")?;
        let ca = certificate(self.credentials.ca.as_bytes())?;
        Ok((https_client(ca, Some(&self.credentials))?, url))
    }
}

pub fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?
        .take(MAX_CREDENTIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_CREDENTIAL_BYTES,
        "Credential file exceeds the size limit."
    );
    Ok(bytes)
}

pub fn endpoint(origin: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(origin).map_err(|_| anyhow!("Invalid relay URL."))?;
    ensure!(
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Use an HTTPS origin containing only the relay hostname and optional port."
    );
    url.set_path(path);
    Ok(url)
}

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

pub fn https_client(ca: CertificateDer<'static>, identity: Option<&Credentials>) -> Result<Client> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(ca)?;
    let roots = Arc::new(roots);
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone());
    let config = match identity {
        Some(credentials) => {
            let leaf = certificate(credentials.client_cert.as_bytes())?;
            let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider).build()?;
            verifier
                .verify_client_cert(&leaf, &[], UnixTime::now())
                .map_err(|_| anyhow!("Invalid client certificate for this CA."))?;
            let key =
                rustls_pemfile::private_key(&mut Cursor::new(credentials.client_key.as_bytes()))?
                    .context("Expected a PEM private key.")?;
            builder
                .with_client_auth_cert(vec![leaf], key)
                .map_err(|_| anyhow!("Client certificate and private key do not match."))?
        }
        None => builder.with_no_client_auth(),
    };
    http_client(config)
}

pub fn http_client(config: ClientConfig) -> Result<Client> {
    Ok(Client::builder()
        .use_preconfigured_tls(config)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(620))
        .build()?)
}

pub async fn read_body(mut response: Response, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit - bytes.len(),
            "Relay response exceeds the size limit."
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
