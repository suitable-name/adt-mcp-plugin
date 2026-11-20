use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use trillium_client::{Method, Status};

use crate::{
    storage,
    transport::{Profile, read_file},
};

const SELECTION_FILE: &str = "endpoint.json";
pub const SELECT_HELP: &str = "Run sap-adt-mcp-client endpoints --profile <dir> to list your assigned endpoints, then sap-adt-mcp-client --set-endpoint=<id-or-label> --profile <dir> and restart the MCP connection.";

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize, Serialize)]
struct Selection {
    endpoint: String,
}

pub fn read_selected(directory: &Path) -> Result<String> {
    let bytes = read_file(&directory.join(SELECTION_FILE))?;
    let selection: Selection = serde_json::from_slice(&bytes)?;
    ensure!(valid_id(&selection.endpoint), "Invalid endpoint ID.");
    Ok(selection.endpoint)
}

#[derive(Deserialize, Serialize)]
pub struct Endpoint {
    id: String,
    label: String,
    online: bool,
}

#[derive(Deserialize)]
struct Listing {
    endpoints: Vec<Endpoint>,
}

/// The endpoints the relay has granted this profile (`GET /endpoints`).
///
/// # Errors
/// The relay is unreachable or answers with an error or an invalid list.
pub async fn available(directory: &Path) -> Result<Vec<Endpoint>> {
    let (client, mut url) = Profile::load(directory)?.connection()?;
    url.set_path("/endpoints");
    let reply = client
        .request(Method::Get, &url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("Could not retrieve assigned endpoints over mutual TLS.")?;
    let status = reply.status();
    // The registration listener knows no `/endpoints`; a profile saved with the
    // enrollment URL as its server is the usual cause of a 404 here.
    ensure!(
        status != Status::NotFound,
        "The relay returned HTTP 404 for the endpoint list. Check that the profile's server URL ({}) is the relay's mutual-TLS port (default 8787, the same as the Eclipse bridge URL), not its enrollment port (default 8788). Enrolling again with a link from the relay operator sets it correctly.",
        url.origin().ascii_serialization()
    );
    ensure!(
        status.is_success(),
        "The relay returned HTTP {status} for the endpoint list."
    );
    let bytes = reply.bytes(4 * 1024 * 1024).await?;
    let list: Listing =
        serde_json::from_slice(&bytes).context("Invalid endpoint list from the relay.")?;
    ensure!(
        list.endpoints.iter().all(|entry| valid_id(&entry.id)
            && entry
                .label
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')),
        "Invalid endpoint ID or label in the relay response."
    );
    Ok(list.endpoints)
}

pub async fn list(directory: &Path) -> Result<()> {
    let endpoints = available(directory).await?;
    if endpoints.is_empty() {
        println!(
            "No endpoints are assigned to this profile. Ask the relay operator to grant access."
        );
    } else {
        let selected = read_selected(directory).ok();
        println!("Selected\tEndpoint ID\tStatus\tLabel");
        for endpoint in endpoints {
            let marker = if selected.as_deref() == Some(endpoint.id.as_str()) {
                "*"
            } else {
                ""
            };
            let status = if endpoint.online { "Online" } else { "Offline" };
            println!("{marker}\t{}\t{status}\t{}", endpoint.id, endpoint.label);
        }
    }
    Ok(())
}

fn resolve<'a>(choice: &str, granted: &'a [Endpoint]) -> Result<&'a str> {
    if choice.len() == 64 && choice.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return granted
            .iter()
            .find(|entry| entry.id.eq_ignore_ascii_case(choice))
            .map(|entry| entry.id.as_str())
            .context("The relay has not assigned this endpoint ID to your profile.");
    }
    let mut matches = granted.iter().filter(|entry| entry.label == choice);
    let entry = matches.next().context("No assigned endpoint has this exact label. Run the endpoints command to see available IDs and labels.")?;
    ensure!(
        matches.next().is_none(),
        "Multiple assigned endpoints have this label. Copy the full endpoint ID from the endpoints command."
    );
    Ok(&entry.id)
}

fn save<'a>(directory: &Path, choice: &str, granted: &'a [Endpoint]) -> Result<&'a str> {
    let id = resolve(choice, granted)?;
    let path = directory.join(SELECTION_FILE);
    let bytes = serde_json::to_vec(&Selection {
        endpoint: id.to_owned(),
    })?;
    storage::stage(&path, &bytes)?
        .persist(&path)
        .context("Could not save the selected endpoint.")?;
    Ok(id)
}

/// Saves the granted endpoint `id` as the selected one, without printing anything.
///
/// # Errors
/// The relay has not granted this endpoint to the profile, or the file cannot be written.
pub async fn select_id(directory: &Path, id: &str) -> Result<()> {
    let endpoints = available(directory).await?;
    save(directory, id, &endpoints)?;
    Ok(())
}

pub async fn select(directory: &Path, choice: &str) -> Result<()> {
    let endpoints = available(directory).await?;
    let id = save(directory, choice, &endpoints)?;
    println!("Selected endpoint {id}. Restart the MCP connection to use it.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offline_grant_can_be_selected_and_denied_updates_preserve_the_selection() {
        let directory = tempfile::tempdir().unwrap();
        let id = "a".repeat(64);
        let other = "b".repeat(64);
        let endpoints = [Endpoint {
            id: id.clone(),
            label: String::from("Workspace"),
            online: false,
        }];
        assert!(read_selected(directory.path()).is_err());
        save(directory.path(), "Workspace", &endpoints).unwrap();
        assert!(save(directory.path(), &other, &endpoints).is_err());
        assert_eq!(read_selected(directory.path()).unwrap(), id);
        assert!(!valid_id("../workspace"));
    }

    #[test]
    fn only_unique_assigned_labels_resolve_and_full_ids_take_precedence() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let third = "c".repeat(64);
        let endpoints = [
            Endpoint {
                id: first.clone(),
                label: String::from("DEV"),
                online: true,
            },
            Endpoint {
                id: second.clone(),
                label: String::from("DEV"),
                online: false,
            },
            Endpoint {
                id: third,
                label: first.clone(),
                online: true,
            },
        ];
        assert!(
            resolve("DEV", &endpoints)
                .unwrap_err()
                .to_string()
                .contains("full endpoint ID")
        );
        assert!(resolve("dev", &endpoints).is_err());
        assert!(resolve("Missing", &endpoints).is_err());
        assert_eq!(resolve(&first, &endpoints).unwrap(), first);
        assert_eq!(
            resolve(&second.to_ascii_uppercase(), &endpoints).unwrap(),
            second
        );
        assert!(resolve(&first, &endpoints[1..]).is_err());
    }
}
