//! Headless operation: links come from `issue-link` over loopback TLS, not from a terminal.

use std::{fs, net::SocketAddr, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use smol::Timer;
use trillium_client::Status;

use super::{Identity, ResponseExt, SERVER, enroll, http, process, tls};

/// Run `issue-link` and return its standard output. Only the link may appear there.
pub async fn issue(pki: &Path, enrollment: SocketAddr, role: &str, label: &str) -> Result<String> {
    let output = process(SERVER)
        .args(["issue-link", "--role", role, "--label", label, "--relay"])
        .arg(enrollment.to_string())
        .arg("--pki")
        .arg(pki)
        .output()
        .await?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    ensure!(output.status.success(), "issue-link failed: {stderr}");
    ensure!(
        !stderr.contains("GW1-") && !stderr.contains("sap-adt://"),
        "issue-link leaked the link on stderr."
    );
    let stdout = String::from_utf8(output.stdout)?;
    let mut lines = stdout.lines();
    let link = lines.next().context("issue-link printed nothing.")?;
    ensure!(
        lines.next().is_none() && link.starts_with("sap-adt://enroll?"),
        "issue-link printed more than the link."
    );
    Ok(link.to_owned())
}

fn token_of(link: &str) -> Result<&str> {
    link.split_once("&t=")
        .map(|(_, token)| token)
        .context("The link has no token.")
}

async fn expect_status(
    http: &crate::https::Client,
    url: &str,
    headers: &[(&'static str, String)],
    body: &Value,
    expected: Status,
) -> Result<()> {
    let mut request = http.post(url);
    for (name, value) in headers {
        request = request.header(*name, value.clone());
    }
    let status = request.json(body).send().await?.status();
    ensure!(
        status == expected,
        "{url} answered {status}, expected {expected}."
    );
    Ok(())
}

/// `POST /issue` accepts only a loopback peer with the operator secret and no `Origin`.
async fn check_issue_guards(pki: &Path, enrollment: SocketAddr, ca: &[u8]) -> Result<()> {
    let http = http(tls(ca, None)?);
    let issue_url = format!("https://{enrollment}/issue");
    let body = json!({"role": "desktop", "label": "Guarded"});
    let secret = fs::read_to_string(pki.join("issue.secret"))?;
    ensure!(
        secret.trim().len() == 64 && secret.trim().bytes().all(|b| b.is_ascii_hexdigit()),
        "issue.secret is not 32 bytes of hex."
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(pki.join("issue.secret"))?.permissions().mode();
        ensure!(mode & 0o077 == 0, "issue.secret is not owner-only.");
    }
    expect_status(&http, &issue_url, &[], &body, Status::Forbidden).await?;
    let wrong = format!("Bearer {}", "0".repeat(64));
    expect_status(
        &http,
        &issue_url,
        &[("authorization", wrong)],
        &body,
        Status::Forbidden,
    )
    .await?;
    let right = format!("Bearer {}", secret.trim());
    let browser = [
        ("authorization", right.clone()),
        ("origin", "https://example.org".to_owned()),
    ];
    expect_status(&http, &issue_url, &browser, &body, Status::Forbidden).await?;
    expect_status(
        &http,
        &issue_url,
        &[("authorization", right)],
        &json!({"role": "root", "label": "Guarded"}),
        Status::BadRequest,
    )
    .await?;
    // The request, approval and registration-window endpoints are gone.
    let request =
        json!({"id": "11111111111111111111111111111111", "role": "desktop", "label": "Old"});
    expect_status(
        &http,
        &format!("https://{enrollment}/request"),
        &[],
        &request,
        Status::NotFound,
    )
    .await?;
    expect_status(
        &http,
        &format!("https://{enrollment}/claim"),
        &[],
        &json!({"token": "GW1-NOTATOKEN"}),
        Status::Forbidden,
    )
    .await
}

/// Mint with `issue-link`, enroll a desktop and an Eclipse identity, and refuse a used and an
/// expired link. The server must have been started with a short link lifetime of `ttl`.
pub async fn exercise(
    pki: &Path,
    enrollment: SocketAddr,
    root: &Path,
    ca: &[u8],
    ttl: Duration,
) -> Result<()> {
    check_issue_guards(pki, enrollment, ca).await?;

    let link = issue(pki, enrollment, "desktop", "Headless Desk").await?;
    let profile = root.join("headless-desktop");
    let (ok, stderr) = enroll(&link, &profile).await?;
    ensure!(ok && stderr.contains("Client profile saved."), "{stderr}");
    let saved: Value = serde_json::from_slice(&fs::read(profile.join("credentials.json"))?)?;
    ensure!(
        saved["credentials"]["client_cert_pem"].is_string(),
        "Client identity was not persisted."
    );
    let (ok, stderr) = enroll(&link, &root.join("headless-again")).await?;
    ensure!(
        !ok && stderr.contains("already used, expired or cancelled"),
        "A link was accepted twice."
    );

    let eclipse = issue(pki, enrollment, "eclipse", "Headless Eclipse").await?;
    let http = http(tls(ca, None)?);
    let claim = format!("https://{enrollment}/claim");
    let grant = json!({"token": token_of(&eclipse)?});
    let identity: Identity = http
        .post(&claim)
        .json(&grant)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        identity.client_cert_pem.contains("BEGIN CERTIFICATE"),
        "No Eclipse certificate was issued."
    );
    ensure!(
        http.post(&claim).json(&grant).send().await?.status() == Status::Forbidden,
        "An Eclipse link was accepted twice."
    );

    let slow = issue(pki, enrollment, "desktop", "Too Slow").await?;
    Timer::after(ttl + Duration::from_millis(600)).await;
    let (ok, stderr) = enroll(&slow, &root.join("headless-late")).await?;
    ensure!(
        !ok && stderr.contains("already used, expired or cancelled")
            && !root.join("headless-late").exists(),
        "An expired link was accepted."
    );
    Ok(())
}
