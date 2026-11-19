mod bridge;
mod console;
mod enrollment;
mod logs;
mod mcp;
mod policy;
mod security;
mod transport;
mod tui;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Extension, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use tokio::{net::TcpListener, time::timeout};
use tracing_subscriber::{EnvFilter, fmt::writer::BoxMakeWriter};

use bridge::Registry;
use policy::PolicyStore;
use security::Pki;
use transport::PeerCertificate;

#[derive(Parser)]
#[command(
    version,
    about = "SAP ADT MCP relay with operator-approved certificate enrollment"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new private CA and server identity for this DNS name.
    Init {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        dns: String,
    },
    /// Renew the relay's server certificate with its existing key and CA.
    RenewServer {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        dns: String,
    },
    /// Serve enrolled clients and open the local operator interface.
    Serve {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: SocketAddr,
        #[arg(long, default_value = "0.0.0.0:8788")]
        enrollment_listen: SocketAddr,
        /// Open registration on startup. Each request requires local operator approval.
        #[arg(long)]
        issue_token: bool,
        /// Show logs without the TUI. With --issue-token, prompt on the attached console.
        #[arg(long)]
        headless: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let logs = logs::Logs::default();
    let writer = if matches!(
        args.command,
        Command::Serve {
            headless: false,
            ..
        }
    ) {
        BoxMakeWriter::new(logs.clone())
    } else {
        BoxMakeWriter::new(std::io::stderr)
    };
    // Limit diagnostics to our own events. Dependency trace output can contain wire data.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(format!(
            "off,sap_adt_mcp_server_relay={level}"
        )))
        .with_ansi(false)
        .with_writer(writer)
        .with_target(false)
        .init();
    match args.command {
        Command::Init { pki, dns } => {
            Pki::init(&pki, &dns)?;
            tracing::info!(
                "Created the relay identity for {dns}. Protect this PKI directory and its backup."
            );
            Ok(())
        }
        Command::RenewServer { pki, dns } => {
            Pki::load(&pki)?.renew_server(&dns)?;
            tracing::info!(
                "Renewed the server certificate for {dns}. Restart the relay to load it."
            );
            Ok(())
        }
        Command::Serve {
            pki,
            listen,
            enrollment_listen,
            issue_token,
            headless,
        } => {
            let identity = Pki::load(&pki)?;
            let policy = Arc::new(policy::PolicyStore::load(&pki)?);
            let pki = Arc::new(identity);
            let tls = pki.data_tls()?;
            let router = data_routes(Arc::clone(&pki), Arc::clone(&policy));
            let enrollment = enrollment::Enrollment::new(Arc::clone(&pki), issue_token);
            let network_enrollment = enrollment.clone();
            let service = async move {
                let socket = TcpListener::bind(listen)
                    .await
                    .context("Binding the mTLS listener")?;
                tracing::info!(
                    "Serving MCP and Eclipse over mutual TLS on {}.",
                    socket.local_addr()?
                );
                if headless {
                    if issue_token {
                        tracing::info!(
                            "Headless mode. Registration requires approval on the attached console."
                        );
                    } else {
                        tracing::info!("Headless mode. Registration is closed.");
                    }
                }
                tokio::select! {
                    result = transport::listen(socket, tls, 128, router) => result,
                    result = enrollment::run(enrollment_listen, network_enrollment, !headless || issue_token) => result,
                    result = tokio::signal::ctrl_c() => {
                        result.context("Receiving the shutdown signal")?;
                        tracing::info!("Shutting down the relay.");
                        Ok(())
                    }
                }
            };
            match (headless, issue_token) {
                (false, _) => tui::run(enrollment, pki, policy, logs, service).await,
                (true, true) => console::run(enrollment, service).await,
                (true, false) => service.await,
            }
        }
    }
}

#[derive(Clone)]
struct Relay {
    registry: Registry,
    pki: Arc<Pki>,
    policy: Arc<PolicyStore>,
}

fn data_routes(pki: Arc<Pki>, policy: Arc<PolicyStore>) -> Router {
    let relay = Relay {
        registry: Registry::default(),
        pki: Arc::clone(&pki),
        policy,
    };
    Router::new()
        .route("/endpoints", get(mcp::endpoints))
        .route("/mcp", post(mcp::request).delete(mcp::end_session))
        .route(
            "/bridge",
            get(
                |State(relay): State<Relay>, Extension(cert), ws| async move {
                    bridge::upgrade(&relay.registry, relay.pki, cert, ws)
                },
            ),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .route_layer(middleware::from_fn_with_state(pki, authorize))
        .with_state(relay)
}

async fn authorize(
    State(pki): State<Arc<Pki>>,
    Extension(cert): Extension<PeerCertificate>,
    request: Request,
    next: Next,
) -> Response {
    if request.headers().contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let role = match request.uri().path() {
        "/mcp" | "/endpoints" => "desktop",
        "/bridge" => "eclipse",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if !pki.authorize(&cert.der, role) {
        return (
            StatusCode::FORBIDDEN,
            "This certificate is not enrolled for this endpoint.",
        )
            .into_response();
    }
    timeout(Duration::from_secs(615), next.run(request))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}
