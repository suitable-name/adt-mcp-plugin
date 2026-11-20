use std::{io::Cursor, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow, ensure};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, UnixTime},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use trillium_client::Url;
use zeroize::Zeroize;

pub use sap_adt_mcp_server_relay::{
    keys::certificate,
    storage::{MAX_CREDENTIAL_BYTES, read_file},
};

use crate::https::Client;

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

    /// The mutual-TLS client configuration for the relay's data port (the tunnel socket).
    pub fn tls_config(&self) -> Result<ClientConfig> {
        let ca = certificate(self.credentials.ca.as_bytes())?;
        client_config(ca, Some(&self.credentials))
    }
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

pub fn https_client(ca: CertificateDer<'static>, identity: Option<&Credentials>) -> Result<Client> {
    Ok(http_client(client_config(ca, identity)?))
}

fn client_config(
    ca: CertificateDer<'static>,
    identity: Option<&Credentials>,
) -> Result<ClientConfig> {
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
    Ok(config)
}

pub fn http_client(config: ClientConfig) -> Client {
    Client::new(config)
}
