//! Rust and Java inner-TLS interop (`docs/plan-e2e-envelope.md` §2, §9).
//!
//! The desktop client's inner TLS (`src/inner_tls.rs`) talks over a
//! loopback TCP socket to the plugin's real `InnerChannel`, run by `InteropServer.java`. The test
//! runs only with `SAP_ADT_INTEROP=1` and needs a JDK in `JAVA_HOME`; otherwise it returns at once.
//!
//! The client side comes from the shared library (`inner_tls`, `keys`, `tunnel_proto`), so the
//! test exercises exactly the code the desktop client runs.

use std::{
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::AtomicBool, mpsc},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use rustls::{CipherSuite, ClientConnection, ProtocolVersion};
use sap_adt_mcp_server_relay::{
    inner_tls::{self, InnerTls, SERVER_NAME},
    keys::{InnerKey, spki_fingerprint, spki_of},
    tunnel_proto::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES},
};
use serde_json::{Value, json};

/// A fresh desktop key. It is created in a temporary profile directory that is removed again;
/// the key itself stays in memory.
fn new_key() -> Result<InnerKey> {
    let directory = tempfile::tempdir()?;
    InnerKey::load_or_create(directory.path())
}

const SERVER_CLASS: &str = "com.sap.adt.mcp.server.e2e.InteropServer";
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// The JDK tool `name` from `JAVA_HOME` (`.exe` on Windows).
fn jdk_tool(name: &str) -> Result<PathBuf> {
    let home = std::env::var_os("JAVA_HOME").ok_or_else(|| anyhow!("JAVA_HOME is not set."))?;
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    Ok(Path::new(&home).join("bin").join(file))
}

/// The plugin's source root and its bundled Gson jar.
fn plugin_paths() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("java-plugin/sap-adt-mcp-server");
    let plugin = project.join("com.sap.adt.mcp.server.plugin");
    let gson = std::fs::read_dir(&plugin)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("gson-"))
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("jar"))
        })
        .ok_or_else(|| anyhow!("No gson jar in the plugin directory."))?;
    Ok((
        plugin.join("src"),
        gson,
        project.join("tests/InteropServer.java"),
    ))
}

/// Compiles the harness and the plugin classes it uses into `output`.
fn compile(output: &Path) -> Result<PathBuf> {
    let (sources, gson, harness) = plugin_paths()?;
    let status = Command::new(jdk_tool("javac")?)
        .args(["--release", "17", "-encoding", "UTF-8", "-cp"])
        .arg(&gson)
        .arg("-sourcepath")
        .arg(&sources)
        .arg("-d")
        .arg(output)
        .arg(&harness)
        .status()
        .context("Could not start javac.")?;
    ensure!(status.success(), "javac failed: {status}");
    Ok(gson)
}

/// The Java server process; killed when dropped.
struct JavaServer {
    child: Child,
    port: u16,
    pin: [u8; 32],
}

impl JavaServer {
    /// Starts the server for `client_pin` (64 hex digits or `any`) and reads its banner.
    fn start(classes: &Path, gson: &Path, client_pin: &str) -> Result<Self> {
        let class_path = std::env::join_paths([classes, gson])?;
        let child = Command::new(jdk_tool("java")?)
            .arg("-ea")
            .arg("-cp")
            .arg(class_path)
            .args([SERVER_CLASS, "0", client_pin])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Could not start java.")?;
        let mut server = Self {
            child,
            port: 0,
            pin: [0; 32],
        };
        server.read_banner()?;
        Ok(server)
    }

    /// Reads the `PORT` and `PIN` lines the server prints first.
    fn read_banner(&mut self) -> Result<()> {
        let stdout = self.child.stdout.take().context("No server output.")?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let (mut port, mut pin) = (None, None);
        while port.is_none() || pin.is_none() {
            let line = receiver
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| anyhow!("The Java server printed no PORT and PIN line in time."))?;
            if let Some(value) = line.strip_prefix("PORT ") {
                port = Some(value.trim().parse::<u16>()?);
            } else if let Some(value) = line.strip_prefix("PIN ") {
                pin = Some(parse_pin(value.trim())?);
            }
        }
        self.port = port.context("No PORT line.")?;
        self.pin = pin.context("No PIN line.")?;
        Ok(())
    }

    fn connect(&self) -> Result<TcpStream> {
        let stream = TcpStream::connect(("127.0.0.1", self.port))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

impl Drop for JavaServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse_pin(hex_text: &str) -> Result<[u8; 32]> {
    hex::decode(hex_text)?
        .try_into()
        .map_err(|_| anyhow!("A pin must be 32 bytes."))
}

/// Whether `error` is a socket timeout (the server hung) rather than a refusal.
fn is_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| matches!(io.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut))
    })
}

fn send(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if !bytes.is_empty() {
        stream.write_all(bytes)?;
    }
    Ok(())
}

/// Reads once from the server and feeds the bytes to `tls`.
fn pump(stream: &mut TcpStream, tls: &mut InnerTls) -> Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    let count = stream.read(&mut buffer)?;
    ensure!(count > 0, "The server closed the connection.");
    tls.feed(&buffer[..count])?;
    Ok(())
}

/// Runs the handshake until the client side considers it finished.
fn handshake(stream: &mut TcpStream, tls: &mut InnerTls) -> Result<()> {
    loop {
        send(stream, &tls.take_output()?)?;
        if !tls.handshaking() {
            return Ok(());
        }
        pump(stream, tls)?;
    }
}

/// Sends one inner message and waits for the next inner message back.
fn exchange(stream: &mut TcpStream, tls: &mut InnerTls, message: &[u8]) -> Result<Vec<u8>> {
    send(stream, &tls.seal(message, MAX_REQUEST_BYTES)?)?;
    loop {
        if let Some(reply) = tls.next_message(MAX_RESPONSE_BYTES)? {
            return Ok(reply);
        }
        pump(stream, tls)?;
        send(stream, &tls.take_output()?)?;
    }
}

/// A full session: handshake, then two JSON-RPC messages whose echoes are checked.
fn echo_session(server: &JavaServer, key: &InnerKey, pin: [u8; 32]) -> Result<()> {
    let mut stream = server.connect()?;
    let mut tls = InnerTls::new(key, pin)?;
    handshake(&mut stream, &mut tls)?;
    let big = "gem \u{00e4}\u{20ac} ".repeat(20_000);
    let params = [
        json!({"name": "sap_get_source", "arguments": {"object": "ZCL_TEST"}}),
        json!({"name": "sap_set_source", "arguments": {"text": big}}),
    ];
    for (id, params) in (1_u32..).zip(params) {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params});
        let reply = exchange(&mut stream, &mut tls, request.to_string().as_bytes())?;
        let reply: Value = serde_json::from_slice(&reply)?;
        let expected = json!({"jsonrpc": "2.0", "id": id, "result": {"echo": params}});
        ensure!(reply == expected, "The echo of message {id} differs.");
    }
    Ok(())
}

/// A bare client connection with the client's own [`inner_tls::config`]; returns what was
/// negotiated, which `InnerTls` does not expose.
fn negotiated(
    server: &JavaServer,
    key: &InnerKey,
) -> Result<(ProtocolVersion, CipherSuite, [u8; 32])> {
    let config = inner_tls::config(key, server.pin, Arc::new(AtomicBool::new(false)))?;
    let name = rustls::pki_types::ServerName::try_from(SERVER_NAME)
        .map_err(|_| anyhow!("Invalid placeholder server name."))?;
    let mut connection = ClientConnection::new(config, name)?;
    let mut stream = server.connect()?;
    while connection.is_handshaking() {
        while connection.wants_write() {
            connection.write_tls(&mut stream)?;
        }
        let mut buffer = [0_u8; 16 * 1024];
        let count = stream.read(&mut buffer)?;
        ensure!(count > 0, "The server closed the connection.");
        let mut input = &buffer[..count];
        while !input.is_empty() {
            connection.read_tls(&mut input)?;
            connection.process_new_packets()?;
        }
    }
    while connection.wants_write() {
        connection.write_tls(&mut stream)?;
    }
    let version = connection
        .protocol_version()
        .context("No protocol version.")?;
    let suite = connection
        .negotiated_cipher_suite()
        .context("No cipher suite.")?
        .suite();
    let certificate = connection
        .peer_certificates()
        .and_then(<[_]>::first)
        .context("The server sent no certificate.")?;
    let found = spki_fingerprint(&spki_of(certificate)?);
    Ok((version, suite, found))
}

/// The server pinned to `desktop`: echoes, negotiated parameters, and a refused stranger.
fn pinned_server(classes: &Path, gson: &Path, desktop: &InnerKey) -> Result<()> {
    let server = JavaServer::start(classes, gson, &desktop.fingerprint_hex())?;
    echo_session(&server, desktop, server.pin).context("pinned client, pinned server")?;

    let (version, suite, found) = negotiated(&server, desktop)?;
    ensure!(
        version == ProtocolVersion::TLSv1_3,
        "Not TLS 1.3: {version:?}"
    );
    ensure!(
        suite == CipherSuite::TLS13_AES_256_GCM_SHA384,
        "Wrong suite: {suite:?}"
    );
    ensure!(
        found == server.pin,
        "The server key differs from its PIN line."
    );

    // A client whose key the server has not pinned: the server must refuse it. TLS 1.3 clients
    // finish their handshake before the server's verdict, so the refusal shows on the first
    // exchange (alert or close), never as a timeout and never as an echo.
    let stranger = new_key()?;
    let outcome = echo_session(&server, &stranger, server.pin);
    let error = outcome.expect_err("an unpinned client key must be refused");
    ensure!(
        !is_timeout(&error),
        "The server hung instead of refusing: {error:#}"
    );
    Ok(())
}

/// The server in pairing mode (any client key): an unknown client works, a wrong server pin fails.
fn open_server(classes: &Path, gson: &Path) -> Result<()> {
    let server = JavaServer::start(classes, gson, "any")?;
    echo_session(&server, &new_key()?, server.pin).context("unknown key, open gate")?;

    let key = new_key()?;
    let mut stream = server.connect()?;
    let mut tls = InnerTls::new(&key, [0x42; 32])?;
    let error = handshake(&mut stream, &mut tls).expect_err("a wrong server pin must fail");
    ensure!(
        tls.pin_mismatch(),
        "The failure was not flagged as a pin mismatch: {error:#}"
    );
    Ok(())
}

#[test]
fn the_rust_client_and_the_java_plugin_agree_on_the_inner_tls() {
    if std::env::var("SAP_ADT_INTEROP").as_deref() != Ok("1") {
        eprintln!("SAP_ADT_INTEROP is not 1: skipping the Rust/Java interop check.");
        return;
    }
    let classes = tempfile::tempdir().unwrap();
    let gson = compile(classes.path()).unwrap();
    let desktop = new_key().unwrap();
    pinned_server(classes.path(), &gson, &desktop).unwrap();
    open_server(classes.path(), &gson).unwrap();
}
