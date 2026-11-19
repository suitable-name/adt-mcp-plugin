#[path = "client/bootstrap.rs"]
mod bootstrap;
#[path = "client/endpoints.rs"]
mod endpoints;
#[path = "client/enroll.rs"]
mod enroll;
#[path = "client/stdio.rs"]
mod stdio;
#[path = "../security/storage.rs"]
mod storage;
#[path = "../security/token.rs"]
mod token;
#[path = "client/transport.rs"]
mod transport;

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
    /// Request operator approval and create a new private profile.
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long)]
        enrollment: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        profile: PathBuf,
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
        Some(Command::Enroll {
            server,
            enrollment,
            label,
            profile,
        }) => enroll::run(&server, &enrollment, &label, &profile).await,
        Some(Command::Connect { profile }) => stdio::run(profile.as_deref()).await,
        Some(Command::Endpoints { profile }) => endpoints::list(&profile).await,
        None => match (cli.set_endpoint, cli.profile) {
            (Some(choice), Some(profile)) => endpoints::select(&profile, &choice).await,
            (None, None) => stdio::run(None).await,
            _ => bail!("Select an endpoint with --set-endpoint=<id-or-label> --profile <dir>."),
        },
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
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
        assert!(matches!(Cli::try_parse_from(["client", "--help"]),
            Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp));
    }
}
