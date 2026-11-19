mod bridge;
mod console;
mod enrollment;
mod logs;
mod mcp;
mod policy;
mod rt;
mod security;
mod transport;
mod tui;
mod web;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use smol::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt::writer::BoxMakeWriter};
use trillium_http::{KnownHeaderName, Method, Status};

use bridge::{Bridge, Registry};
use policy::PolicyStore;
use rt::timeout;
use security::Pki;
use transport::{Conn, Handoff, Peer, PeerCertificate, Service, Upgrade};
use web::Reply;

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

fn main() -> Result<()> {
    smol::block_on(async_main())
}

#[allow(clippy::too_many_lines)]
async fn async_main() -> Result<()> {
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
            let relay = Relay::new(Arc::clone(&pki), Arc::clone(&policy));
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
                let (stop, stopped) = smol::channel::bounded::<()>(1);
                ctrlc::set_handler(move || {
                    let _ = stop.try_send(());
                })
                .context("Receiving the shutdown signal")?;
                smol::future::race(
                    transport::listen(socket, tls, 128, relay),
                    smol::future::race(
                        enrollment::run(
                            enrollment_listen,
                            network_enrollment,
                            !headless || issue_token,
                        ),
                        async {
                            stopped
                                .recv()
                                .await
                                .context("Receiving the shutdown signal")?;
                            tracing::info!("Shutting down the relay.");
                            Ok::<(), anyhow::Error>(())
                        },
                    ),
                )
                .await
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

#[derive(Clone, Copy)]
enum Route {
    Endpoints,
    Mcp,
    Bridge,
}

impl Relay {
    fn new(pki: Arc<Pki>, policy: Arc<PolicyStore>) -> Self {
        Self {
            registry: Registry::default(),
            pki,
            policy,
        }
    }

    /// Authorize a request for a known path, then dispatch it on its method.
    async fn respond(&self, conn: &mut Conn, peer: &Peer, handoff: &Handoff<Bridge>) -> Reply {
        let (route, role) = match conn.path() {
            "/mcp" => (Route::Mcp, "desktop"),
            "/endpoints" => (Route::Endpoints, "desktop"),
            "/bridge" => (Route::Bridge, "eclipse"),
            _ => return Status::NotFound.into(),
        };
        // Only an authenticated TLS handshake yields a peer certificate.
        let Some(cert) = &peer.cert else {
            return Status::InternalServerError.into();
        };
        if conn.request_headers().has_header(KnownHeaderName::Origin) {
            return Status::Forbidden.into();
        }
        if !self.pki.authorize(&cert.der, role) {
            return Reply::text(
                Status::Forbidden,
                "This certificate is not enrolled for this endpoint.",
            );
        }
        timeout(
            Duration::from_secs(615),
            self.dispatch(conn, route, cert, handoff),
        )
        .await
        .unwrap_or_else(|_| Status::RequestTimeout.into())
    }

    async fn dispatch(
        &self,
        conn: &mut Conn,
        route: Route,
        cert: &PeerCertificate,
        handoff: &Handoff<Bridge>,
    ) -> Reply {
        match (route, conn.method()) {
            (Route::Endpoints, Method::Get) => mcp::endpoints(self, cert).await,
            (Route::Mcp, Method::Post) => mcp::request(self, cert, conn).await,
            (Route::Mcp, Method::Delete) => {
                mcp::end_session(self, cert, conn.request_headers()).await
            }
            (Route::Bridge, Method::Get) => {
                let (reply, bridge) = bridge::upgrade(&self.registry, conn.request_headers(), cert);
                if let Some(bridge) = bridge {
                    handoff.set(bridge);
                }
                reply
            }
            _ => Status::MethodNotAllowed.into(),
        }
    }
}

impl Service for Relay {
    type Pending = Bridge;

    async fn handle(&self, mut conn: Conn, peer: &Peer, handoff: &Handoff<Bridge>) -> Conn {
        let reply = self.respond(&mut conn, peer, handoff).await;
        reply.into_conn(conn)
    }

    async fn upgrade(&self, upgrade: Upgrade, peer: &Peer, pending: Option<Bridge>) {
        if let (Some(bridge), Some(cert)) = (pending, &peer.cert) {
            bridge::serve_upgraded(upgrade, bridge, &self.pki, cert).await;
        }
    }
}
