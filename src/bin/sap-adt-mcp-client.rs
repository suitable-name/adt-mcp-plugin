#[path = "client/bootstrap.rs"]
mod bootstrap;
#[path = "client/channel.rs"]
mod channel;
#[path = "client/endpoints.rs"]
mod endpoints;
#[path = "client/enroll.rs"]
mod enroll;
#[path = "client/host.rs"]
mod host;
#[path = "client/pair.rs"]
mod pair;
#[path = "client/peers.rs"]
mod peers;
#[path = "client/stdio.rs"]
mod stdio;
#[cfg(test)]
#[path = "../test_plugin.rs"]
mod test_plugin;
#[path = "client/transport.rs"]
mod transport;
#[path = "client/tunnel.rs"]
mod tunnel;

use sap_adt_mcp_server_relay::{https, inner_tls, keys, link, rt, storage, token, tunnel_proto};
use std::{path::PathBuf, process::ExitCode};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Connect a local MCP application to the SAP ADT relay.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Save an assigned endpoint by full ID or exact, unique label.
    #[arg(long, value_name = "ID_OR_LABEL", requires = "profile")]
    set_endpoint: Option<String>,
    /// Enrolled desktop profile to update.
    #[arg(long, value_name = "DIR", requires = "set_endpoint")]
    profile: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Claim an enrollment link from the relay operator and create a new private profile.
    Enroll {
        /// The one-time `sap-adt://enroll?...` link. It works once and is a secret.
        #[arg(long)]
        link: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Pair this desktop with an Eclipse using a one-time link from Eclipse's Pair Desktop.
    /// Afterwards the endpoint is used end to end and the relay can no longer read it.
    Pair {
        /// The one-time `sap-adt://pair?...` link. Copy it on this machine; it is a secret.
        #[arg(long)]
        link: String,
        /// Enrolled desktop profile to pair.
        #[arg(long, value_name = "DIR")]
        profile: PathBuf,
    },
    /// Remove the pinned key of a paired endpoint from this profile.
    Unpair {
        /// Enrolled desktop profile.
        #[arg(long, value_name = "DIR")]
        profile: PathBuf,
        /// The paired endpoint, by full ID or exact, unique label.
        #[arg(long, value_name = "ID_OR_LABEL")]
        endpoint: String,
    },
    /// Serve newline-delimited MCP on stdin and stdout.
    Connect {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// List the Eclipse endpoints this desktop profile can use.
    Endpoints {
        #[arg(long)]
        profile: PathBuf,
    },
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Enroll { link, profile }) => enroll::run(&link, &profile).await,
        Some(Command::Pair { link, profile }) => pair::run(&profile, &link).await,
        Some(Command::Unpair { profile, endpoint }) => peers::unpair(&profile, &endpoint),
        Some(Command::Connect { profile }) => stdio::run(profile.as_deref()).await,
        Some(Command::Endpoints { profile }) => endpoints::list(&profile).await,
        None => match (cli.set_endpoint, cli.profile) {
            (Some(choice), Some(profile)) => endpoints::select(&profile, &choice).await,
            (None, None) => stdio::run(None).await,
            _ => bail!("Select an endpoint with --set-endpoint=<id-or-label> --profile <dir>."),
        },
    }
}

fn main() -> ExitCode {
    match smol::block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_commands_accept_the_documented_arguments() {
        let cli = Cli::try_parse_from(["client", "--set-endpoint=example", "--profile", "private"])
            .unwrap();
        assert_eq!(cli.set_endpoint.as_deref(), Some("example"));
        assert!(Cli::try_parse_from(["client", "--set-endpoint=example"]).is_err());
        assert!(Cli::try_parse_from(["client", "--profile", "private"]).is_err());
        let bare = Cli::try_parse_from(["client"]).unwrap();
        assert!(bare.command.is_none() && bare.profile.is_none() && bare.set_endpoint.is_none());
        for command in ["connect", "endpoints"] {
            assert!(Cli::try_parse_from(["client", command, "--profile", "private"]).is_ok());
        }
        assert!(Cli::try_parse_from(["client", "connect"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "client",
                "pair",
                "--profile",
                "private",
                "--link",
                "sap-adt://pair?v=1"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["client", "pair", "--profile", "private"]).is_err());
        assert!(
            Cli::try_parse_from([
                "client",
                "unpair",
                "--profile",
                "private",
                "--endpoint",
                "DEV"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["client", "unpair", "--profile", "private"]).is_err());
        assert!(matches!(Cli::try_parse_from(["client", "--help"]),
            Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp));
    }
}
