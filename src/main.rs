mod bridge;
mod enrollment;
mod logs;
mod mcp;
mod policy;
mod security;
mod transport;
mod tui;
mod tunnel;
mod web;

use sap_adt_mcp_server_relay::{https, link, rt, tunnel_proto};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
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
#[command(version, about = "SAP ADT MCP relay with one-time enrollment links")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(ClapArgs)]
struct ServeArgs {
    #[arg(long)]
    pki: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8787")]
    listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:8788")]
    enrollment_listen: SocketAddr,
    /// Display name written into enrollment links. Default: the DNS name of the PKI.
    #[arg(long)]
    name: Option<String>,
    /// Data (mutual TLS) address that enrollment links name, as host:port.
    /// Default: the DNS name of the PKI with the bound data port.
    #[arg(long, value_name = "HOST:PORT")]
    public_data: Option<String>,
    /// Enrollment address that enrollment links name, as host:port.
    /// Default: the DNS name of the PKI with the bound enrollment port.
    #[arg(long, value_name = "HOST:PORT")]
    public_enrollment: Option<String>,
    /// Show logs without the TUI. Mint enrollment links with `issue-link`.
    #[arg(long)]
    headless: bool,
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
    Serve(ServeArgs),
    /// Mint an enrollment link on the relay running on this machine and print it.
    IssueLink {
        /// The PKI directory the relay was started with.
        #[arg(long)]
        pki: PathBuf,
        #[arg(long, value_parser = ["desktop", "eclipse"])]
        role: String,
        /// Names the certificate in the Clients tab and in the logs.
        #[arg(long)]
        label: String,
        /// The enrollment listener of the relay, as host:port.
        #[arg(long, default_value = "127.0.0.1:8788")]
        relay: String,
    },
}

fn main() -> Result<()> {
    smol::block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();
    let logs = logs::Logs::default();
    let writer = if matches!(
        args.command,
        Command::Serve(ServeArgs {
            headless: false,
            ..
        })
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
        Command::Serve(serve_args) => serve(serve_args, logs).await,
        Command::IssueLink {
            pki,
            role,
            label,
            relay,
        } => {
            // Only the link goes to standard output.
            let link = enrollment::issue_link(&pki, &role, &label, &relay).await?;
            println!("{}", link.as_str());
            Ok(())
        }
    }
}

async fn serve(args: ServeArgs, logs: logs::Logs) -> Result<()> {
    let identity = Pki::load(&args.pki)?;
    let policy = Arc::new(PolicyStore::load(&args.pki)?);
    let pki = Arc::new(identity);
    let tls = pki.data_tls()?;
    let data_socket = TcpListener::bind(args.listen)
        .await
        .context("Binding the mTLS listener")?;
    let enrollment_socket = TcpListener::bind(args.enrollment_listen)
        .await
        .context("Binding the enrollment listener")?;
    let ports = (
        data_socket.local_addr()?.port(),
        enrollment_socket.local_addr()?.port(),
    );
    let addresses = enrollment::Addresses::resolve(
        &pki,
        args.name,
        args.public_data,
        args.public_enrollment,
        ports,
    )?;
    let secret = pki.create_issue_secret()?;
    let enrollment = enrollment::Enrollment::new(Arc::clone(&pki), addresses, secret);
    let network_enrollment = enrollment.clone();
    let relay = Relay::new(Arc::clone(&pki), Arc::clone(&policy));
    // The operator interface reads live bridges and sessions from the same registry.
    let registry = relay.registry.clone();
    let headless = args.headless;
    let service = async move {
        tracing::info!(
            "Serving MCP and Eclipse over mutual TLS on {}.",
            data_socket.local_addr()?
        );
        if headless {
            tracing::info!("Headless mode. Mint enrollment links with issue-link.");
        }
        let (stop, stopped) = smol::channel::bounded::<()>(1);
        ctrlc::set_handler(move || {
            let _ = stop.try_send(());
        })
        .context("Receiving the shutdown signal")?;
        smol::future::race(
            transport::listen(data_socket, tls, 128, relay),
            smol::future::race(
                enrollment::run(enrollment_socket, network_enrollment),
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
    if headless {
        service.await
    } else {
        tui::run(enrollment, pki, policy, registry, logs, service).await
    }
}

#[derive(Clone)]
struct Relay {
    registry: Registry,
    tunnels: tunnel::Tunnels,
    pki: Arc<Pki>,
    policy: Arc<PolicyStore>,
}

#[derive(Clone, Copy)]
enum Route {
    Endpoints,
    Mcp,
    Bridge,
    Tunnel,
}

/// What a request handler leaves for the WebSocket upgrade that follows its `101` answer.
pub enum Pending {
    Bridge(Bridge),
    Tunnel(tunnel::Tunnel),
}

impl Relay {
    fn new(pki: Arc<Pki>, policy: Arc<PolicyStore>) -> Self {
        Self {
            registry: Registry::default(),
            tunnels: tunnel::Tunnels::default(),
            pki,
            policy,
        }
    }

    /// Authorize a request for a known path, then dispatch it on its method.
    async fn respond(&self, conn: &mut Conn, peer: &Peer, handoff: &Handoff<Pending>) -> Reply {
        let (route, role) = match conn.path() {
            "/mcp" => (Route::Mcp, "desktop"),
            "/endpoints" => (Route::Endpoints, "desktop"),
            "/tunnel" => (Route::Tunnel, "desktop"),
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
            self.dispatch(conn, route, cert, peer.addr, handoff),
        )
        .await
        .unwrap_or_else(|_| Status::RequestTimeout.into())
    }

    async fn dispatch(
        &self,
        conn: &mut Conn,
        route: Route,
        cert: &PeerCertificate,
        addr: SocketAddr,
        handoff: &Handoff<Pending>,
    ) -> Reply {
        match (route, conn.method()) {
            (Route::Endpoints, Method::Get) => mcp::endpoints(self, cert).await,
            (Route::Mcp, Method::Post) => mcp::request(self, cert, conn, addr).await,
            (Route::Mcp, Method::Delete) => {
                mcp::end_session(self, cert, conn.request_headers()).await
            }
            (Route::Bridge, Method::Get) => {
                let (reply, bridge) =
                    bridge::upgrade(&self.registry, conn.request_headers(), cert, addr);
                if let Some(bridge) = bridge {
                    handoff.set(Pending::Bridge(bridge));
                }
                reply
            }
            (Route::Tunnel, Method::Get) => {
                let (reply, tunnel) = tunnel::upgrade(self, conn.request_headers(), cert);
                if let Some(tunnel) = tunnel {
                    handoff.set(Pending::Tunnel(tunnel));
                }
                reply
            }
            _ => Status::MethodNotAllowed.into(),
        }
    }
}

impl Service for Relay {
    type Pending = Pending;

    async fn handle(&self, mut conn: Conn, peer: &Peer, handoff: &Handoff<Pending>) -> Conn {
        let reply = self.respond(&mut conn, peer, handoff).await;
        reply.into_conn(conn)
    }

    async fn upgrade(&self, upgrade: Upgrade, peer: &Peer, pending: Option<Pending>) {
        let Some(cert) = &peer.cert else {
            return;
        };
        match pending {
            Some(Pending::Bridge(bridge)) => {
                bridge::serve_upgraded(upgrade, bridge, &self.pki, cert).await;
            }
            Some(Pending::Tunnel(tunnel)) => {
                tunnel::serve_upgraded(upgrade, tunnel, self, cert, peer.addr).await;
            }
            None => {}
        }
    }
}
