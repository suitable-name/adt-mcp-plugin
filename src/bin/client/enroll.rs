use std::{
    fs,
    io::{self, BufRead, IsTerminal, Read},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use trillium_client::Status;
use zeroize::Zeroizing;

use super::transport::{
    Credentials, MAX_CREDENTIAL_BYTES, PROFILE_NAME, Profile, certificate, endpoint, https_client,
};
use crate::{bootstrap, https::Response, storage, token};

#[derive(Deserialize)]
struct Approval {
    id: String,
    ca_pem: String,
}

#[derive(Serialize)]
struct Claim<'a> {
    token: &'a str,
}

fn operator_token() -> Result<Zeroizing<String>> {
    eprintln!("Enter the enrollment token supplied by the server operator.");
    let token = if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::read_password()?)
    } else {
        let mut bytes = Zeroizing::new(Vec::new());
        io::stdin().lock().take(257).read_until(b'\n', &mut bytes)?;
        ensure!(bytes.len() <= 256, "The token exceeds the size limit.");
        Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| anyhow!("Invalid token encoding."))?
                .trim()
                .to_owned(),
        )
    };
    ensure!(
        token.len() <= 256 && !token.is_empty(),
        "Enter a valid enrollment token."
    );
    Ok(token)
}

/// Local wording for the relay's refusal codes (see `REFUSED_*` in `src/enrollment.rs`).
fn refusal(status: Status, body: &[u8]) -> String {
    match (status, body) {
        (Status::Forbidden, b"registration-closed") => {
            "Registration is closed on the relay. Ask the operator to open registration, then enroll again.".into()
        }
        (Status::Forbidden, b"request-denied") => {
            "The operator denied this request, or closed registration while it waited. Enroll again.".into()
        }
        _ => format!("Enrollment returned HTTP {status}."),
    }
}

async fn reply<T: DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes(256).await.unwrap_or_default();
        anyhow::bail!(refusal(status, &body));
    }
    let data = response.bytes(MAX_CREDENTIAL_BYTES).await?;
    serde_json::from_slice(&data).map_err(|_| anyhow!("Invalid enrollment response."))
}

async fn request_profile(server: &str, enrollment: &str, label: &str) -> Result<Profile> {
    endpoint(server, "/mcp")?;
    let request = endpoint(enrollment, "/request")?;
    let claim = endpoint(enrollment, "/claim")?;
    let mut random = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| anyhow!("Could not generate a request ID."))?;
    let id = hex::encode(random);
    eprintln!("Enrollment request ID: {id}");
    eprintln!("Role: desktop. Device label: {label}");
    eprintln!("Compare the full ID, role, and label with the server operator before approval.");
    let approval: Approval = reply(
        bootstrap::request(request, &id, label)
            .await
            .context("Could not request enrollment.")?,
    )
    .await?;
    ensure!(
        approval.id == id,
        "The operator approved a different request ID."
    );
    let ca = certificate(approval.ca_pem.as_bytes())?;
    let pin = digest::digest(&digest::SHA256, ca.as_ref());
    let grant = smol::unblock(operator_token).await?;
    let decoded =
        token::decode(&grant).context("The operator supplied an invalid enrollment token.")?;
    ensure!(
        &decoded[32..] == pin.as_ref(),
        "The enrollment token belongs to a different CA."
    );
    // A new TLS connection must prove possession of a certificate issued by this authenticated CA.
    let http = https_client(ca.clone(), None)?;
    let credentials: Credentials = reply(
        http.post(claim)
            .timeout(Duration::from_secs(30))
            .json(&Claim {
                token: grant.trim(),
            })
            .send()
            .await
            .context("Could not claim the enrollment.")?,
    )
    .await?;
    ensure!(
        certificate(credentials.ca.as_bytes())? == ca,
        "The claimed CA differs from the bootstrap CA."
    );
    let profile = Profile {
        server: server.to_owned(),
        credentials,
    };
    // Validate the issued private key, certificate, and certification path before saving.
    drop(profile.connection()?);
    Ok(profile)
}

pub async fn run(server: &str, enrollment: &str, label: &str, directory: &Path) -> Result<()> {
    ensure!(
        (1..=64).contains(&label.len())
            && !label.trim().is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' '),
        "Enter a printable ASCII client label of up to 64 characters."
    );
    storage::new_directory(directory)
        .context("Choose a new client profile directory in a trusted parent.")?;
    let result = async {
        let profile = request_profile(server, enrollment, label).await?;
        let bytes = Zeroizing::new(serde_json::to_vec(&profile)?);
        ensure!(
            bytes.len() <= MAX_CREDENTIAL_BYTES,
            "The issued profile exceeds the size limit."
        );
        storage::write_new(&directory.join(PROFILE_NAME), &bytes)?;
        Ok(())
    }
    .await;
    if result.is_err() {
        // Only remove the reserved directory if it is still empty.
        let _ = fs::remove_dir(directory);
    } else {
        eprintln!("Client profile saved.");
        eprintln!("{}", crate::endpoints::SELECT_HELP);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::refusal;
    use trillium_client::Status;

    #[test]
    fn refusal_codes_get_actionable_messages() {
        assert!(refusal(Status::Forbidden, b"registration-closed").contains("open registration"));
        assert!(refusal(Status::Forbidden, b"request-denied").contains("denied"));
        assert_eq!(
            refusal(Status::Forbidden, b"other"),
            "Enrollment returned HTTP 403 Forbidden."
        );
    }
}
