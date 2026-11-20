//! Processes and enrollment for the end-to-end test: the headless relay, enrollment by link,
//! the Eclipse identity, the policy file and the client commands.
//!
//! The crate root must include `src/rt.rs` as `rt` and `src/https.rs` as `https`.

use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use ring::digest::{SHA256, digest};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use serde_json::{Value, json};
use smol::{
    Timer,
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
};

use crate::{https, rt};

pub const SERVER: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-server-relay");
pub const DESKTOP: &str = env!("CARGO_BIN_EXE_sap-adt-mcp-client");
/// Largest response body the helpers accept.
const BODY_LIMIT: usize = 1024 * 1024;

pub fn process(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .kill_on_drop(true)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*");
    command
}

/// Every line a child wrote, collected by a background task until the child closes the pipe.
#[derive(Clone, Default)]
pub struct LogBuffer {
    lines: Arc<Mutex<Vec<String>>>,
}

impl LogBuffer {
    pub fn capture(reader: impl AsyncRead + Send + Unpin + 'static) -> Self {
        let buffer = Self::default();
        let sink = buffer.clone();
        rt::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Some(Ok(line)) = lines.next().await {
                sink.lines
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(line);
            }
        })
        .detach();
        buffer
    }

    /// Everything captured so far, one line per row.
    pub fn text(&self) -> String {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .join("\n")
    }

    fn nth(&self, marker: &str, times: usize) -> Option<String> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|line| line.contains(marker))
            .nth(times.saturating_sub(1))
            .cloned()
    }

    /// The line that holds `marker` for the `times`-th time, once the child has written it.
    pub async fn wait_for(&self, marker: &str, times: usize) -> Result<String> {
        rt::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(line) = self.nth(marker, times) {
                    return line;
                }
                Timer::after(Duration::from_millis(25)).await;
            }
        })
        .await
        .with_context(|| format!("Timed out waiting for {marker:?} (occurrence {times})."))
    }
}

/// The `host:port` that follows `marker` in a log line.
fn address(line: &str, marker: &str) -> Result<SocketAddr> {
    let (_, tail) = line.split_once(marker).context("Missing bound address.")?;
    let text = tail
        .trim_start()
        .split(|c: char| !c.is_ascii_digit() && c != '.' && c != ':')
        .next()
        .context("Missing port.")?;
    Ok(text.trim_end_matches('.').parse()?)
}

/// SHA-256 of the first certificate of a PEM text, as 64 lowercase hex digits.
pub fn fingerprint(pem: &str) -> Result<String> {
    let cert = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .context("Missing certificate.")??;
    Ok(hex::encode(digest(&SHA256, cert.as_ref())))
}

/// The relay certificate fingerprint of an enrolled desktop profile.
pub fn desktop_fingerprint(profile: &Path) -> Result<String> {
    let saved: Value = serde_json::from_slice(&fs::read(profile.join("credentials.json"))?)?;
    fingerprint(
        saved["credentials"]["client_cert_pem"]
            .as_str()
            .context("The profile holds no certificate.")?,
    )
}

/// The TLS client configuration for the relay's data port, optionally with an identity
/// given as certificate and key PEM.
pub fn tls(ca: &[u8], identity: Option<(&str, &str)>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut ca = ca;
    roots.add(
        rustls_pemfile::certs(&mut ca)
            .next()
            .context("Missing test CA.")??,
    )?;
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots);
    match identity {
        Some((cert, key)) => {
            let certs =
                rustls_pemfile::certs(&mut cert.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
            let key = rustls_pemfile::private_key(&mut key.as_bytes())?
                .context("Missing private key.")?;
            Ok(builder.with_client_auth_cert(certs, key)?)
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

/// What the relay's `/claim` hands an Eclipse, and the endpoint ID that follows from it.
pub struct EclipseIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub endpoint: String,
}

#[derive(Deserialize)]
struct Claimed {
    client_cert_pem: String,
    client_key_pem: String,
}

/// The headless relay with a fresh PKI.
pub struct Relay {
    _child: Child,
    pub logs: LogBuffer,
    pub data: SocketAddr,
    pub enrollment: SocketAddr,
    pub pki: PathBuf,
    pub ca: Vec<u8>,
}

impl Relay {
    pub async fn start(pki: &Path) -> Result<Self> {
        let status = process(SERVER)
            .args(["init", "--dns", "127.0.0.1", "--pki"])
            .arg(pki)
            .status()
            .await?;
        ensure!(status.success(), "Relay initialization failed.");
        let mut child = process(SERVER)
            .args([
                "serve",
                "--headless",
                "--listen",
                "127.0.0.1:0",
                "--enrollment-listen",
                "127.0.0.1:0",
                "--pki",
            ])
            .arg(pki)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let logs = LogBuffer::capture(child.stderr.take().context("Missing relay logs.")?);
        let serving = logs.wait_for("mutual TLS on", 1).await?;
        let listening = logs.wait_for("Enrollment listening on", 1).await?;
        Ok(Self {
            _child: child,
            data: address(&serving, "mutual TLS on")?,
            enrollment: address(&listening, "Enrollment listening on")?,
            pki: pki.to_path_buf(),
            ca: fs::read(pki.join("ca.pem"))?,
            logs,
        })
    }

    /// Mint an enrollment link with the headless `issue-link`; only the link is on stdout.
    async fn issue_link(&self, role: &str, label: &str) -> Result<String> {
        let output = process(SERVER)
            .args(["issue-link", "--role", role, "--label", label, "--relay"])
            .arg(self.enrollment.to_string())
            .arg("--pki")
            .arg(&self.pki)
            .output()
            .await?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(output.status.success(), "issue-link failed: {stderr}");
        let stdout = String::from_utf8(output.stdout)?;
        let link = stdout
            .lines()
            .next()
            .context("issue-link printed nothing.")?;
        ensure!(
            link.starts_with("sap-adt://enroll?"),
            "issue-link printed no link."
        );
        Ok(link.to_owned())
    }

    /// Enroll a desktop with `enroll --link`.
    pub async fn enroll_desktop(&self, profile: &Path, label: &str) -> Result<()> {
        let link = self.issue_link("desktop", label).await?;
        let ran = run_client(&["enroll", "--link", &link, "--profile", text(profile)?]).await?;
        ensure!(
            ran.ok && ran.stderr.contains("Client profile saved."),
            "Desktop enrollment failed: {}",
            ran.stderr
        );
        Ok(())
    }

    /// Claim an Eclipse identity from a link's token, as the plugin does.
    pub async fn eclipse_identity(&self, label: &str) -> Result<EclipseIdentity> {
        let link = self.issue_link("eclipse", label).await?;
        let token = link
            .split_once("&t=")
            .map(|(_, token)| token)
            .context("The link has no token.")?;
        let http = https::Client::new(tls(&self.ca, None)?);
        let response = http
            .post(format!("https://{}/claim", self.enrollment))
            .json(&json!({"token": token}))
            .send()
            .await?;
        ensure!(response.status().is_success(), "The claim was refused.");
        let bytes = response.bytes(BODY_LIMIT).await?;
        let claimed: Claimed = serde_json::from_slice(&bytes)?;
        Ok(EclipseIdentity {
            endpoint: fingerprint(&claimed.client_cert_pem)?,
            cert_pem: claimed.client_cert_pem,
            key_pem: claimed.client_key_pem,
        })
    }
}

/// Grant every desktop in `desktops` (fingerprints) the endpoint, read-only: `sap_get_source`
/// is allowed and `sap_set_source` is not. The relay reads the file again on every request.
pub fn grant(pki: &Path, desktops: &[String], endpoint: &str) -> Result<()> {
    let mut rules = serde_json::Map::new();
    let mut grants = serde_json::Map::new();
    for desktop in desktops {
        rules.insert(
            desktop.clone(),
            json!({"read_only": true, "actions": null, "packages": null}),
        );
        grants.insert(desktop.clone(), json!([endpoint]));
    }
    let document = json!({
        "global": {"read_only": false, "actions": null, "packages": null},
        "desktops": rules,
        "endpoint_grants": grants,
    });
    let mut file = tempfile::NamedTempFile::new_in(pki)?;
    file.write_all(&serde_json::to_vec(&document)?)?;
    file.persist(pki.join("policy.json"))?;
    Ok(())
}

/// A path as the `&str` the command line needs.
pub fn text(path: &Path) -> Result<&str> {
    path.to_str().context("The test path is not UTF-8.")
}

/// The outcome of a finished client command.
pub struct Ran {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `sap-adt-mcp-client` with `args` to the end, with no standard input.
pub async fn run_client(args: &[&str]) -> Result<Ran> {
    let output = rt::timeout(
        Duration::from_secs(90),
        process(DESKTOP).args(args).stdin(Stdio::null()).output(),
    )
    .await
    .context("The client command timed out.")??;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    ensure!(
        !stdout.contains("GW1-") && !stderr.contains("GW1-"),
        "The client wrote a token."
    );
    Ok(Ran {
        ok: output.status.success(),
        stdout,
        stderr,
    })
}
