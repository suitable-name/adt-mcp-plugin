use std::{fs, path::Path, sync::atomic::Ordering, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::digest;
use serde::Serialize;
use trillium_client::Status;
use zeroize::Zeroizing;

use super::transport::{
    Credentials, MAX_CREDENTIAL_BYTES, PROFILE_NAME, Profile, certificate, endpoint,
};
use crate::{
    bootstrap,
    link::{EnrollLink, Role},
    storage, token,
};

#[derive(Serialize)]
struct Claim<'a> {
    token: &'a str,
}

/// The relay answers one generic 403 for a wrong, used, expired or cancelled link.
fn refusal(status: Status) -> String {
    match status {
        Status::Forbidden => "The relay refused this link. It is wrong, already used, expired or cancelled. Ask the operator for a new link.".into(),
        _ => format!("Enrollment returned HTTP {status}."),
    }
}

/// The CA fingerprint the link pins, once the link is known to be for a desktop.
fn pinned_ca(link: &EnrollLink) -> Result<[u8; 32]> {
    ensure!(
        link.role == Role::Desktop,
        "This link enrolls an Eclipse workspace, not a desktop. Paste it into the Eclipse Register dialog."
    );
    let decoded = token::decode(&link.token).context("The link's token is damaged.")?;
    <[u8; 32]>::try_from(&decoded[32..]).map_err(|_| anyhow!("The link's token is damaged."))
}

async fn claim(link: &EnrollLink) -> Result<Profile> {
    let pin = pinned_ca(link)?;
    let url = endpoint(&format!("https://{}", link.enrollment), "/claim")?;
    // The handshake fails unless the relay presents the CA the link names, so the secret
    // below is sent only to the right relay.
    let (http, mismatch) = bootstrap::pinned_client(pin)?;
    let sent = http
        .post(url)
        .timeout(Duration::from_secs(30))
        .json(&Claim { token: &link.token })
        .send()
        .await;
    let response = match sent {
        Ok(response) => response,
        Err(_) if mismatch.load(Ordering::Acquire) => {
            bail!(
                "The relay's CA does not match the link: wrong relay or attacker in the middle. Nothing was sent."
            );
        }
        Err(error) => return Err(error).context("Could not claim the enrollment."),
    };
    let status = response.status();
    ensure!(status.is_success(), "{}", refusal(status));
    let data = response.bytes(MAX_CREDENTIAL_BYTES).await?;
    let credentials: Credentials =
        serde_json::from_slice(&data).map_err(|_| anyhow!("Invalid enrollment response."))?;
    let ca = certificate(credentials.ca.as_bytes())?;
    ensure!(
        digest::digest(&digest::SHA256, ca.as_ref()).as_ref() == pin.as_slice(),
        "The issued CA differs from the CA in the link."
    );
    let profile = Profile {
        server: format!("https://{}", link.server),
        credentials,
    };
    // Validate the issued private key, certificate, and certification path before saving.
    drop(profile.connection()?);
    Ok(profile)
}

pub async fn run(link: &str, directory: &Path) -> Result<()> {
    let link = EnrollLink::parse(link)?;
    storage::new_directory(directory)
        .context("Choose a new client profile directory in a trusted parent.")?;
    let result = async {
        eprintln!("Enrolling this desktop with the relay {:?}.", link.name);
        let profile = claim(&link).await?;
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
    use super::*;

    /// A real token: secret bytes 0..32, CA fingerprint bytes 32..64.
    const TOKEN: &str = "GW1-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FJ089-24CJ2-A9H75-0MJMA-SC5MQ-2YC1H-68SK8-D9P6W-W3JEH-V7GYK-WFR";

    fn link(role: &str) -> EnrollLink {
        EnrollLink::parse(&format!(
            "sap-adt://enroll?v=1&r={role}&n=Test&s=127.0.0.1:1&e=127.0.0.1:2&t={TOKEN}"
        ))
        .unwrap()
    }

    #[test]
    fn the_link_pins_the_ca_fingerprint_from_its_token() {
        let pin = pinned_ca(&link("desktop")).unwrap();
        let expected: Vec<u8> = (32..64).collect();
        assert_eq!(pin.as_slice(), expected.as_slice());
    }

    #[test]
    fn an_eclipse_link_is_not_for_the_desktop_client() {
        let error = pinned_ca(&link("eclipse")).unwrap_err();
        assert!(error.to_string().contains("Eclipse"));
    }

    #[test]
    fn a_refused_claim_gets_the_generic_wording() {
        assert!(refusal(Status::Forbidden).contains("already used, expired or cancelled"));
        assert_eq!(
            refusal(Status::InternalServerError),
            "Enrollment returned HTTP 500 Internal Server Error."
        );
    }
}
