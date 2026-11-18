use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use portable_pty::{Child, CommandBuilder, PtyPair, PtySize, native_pty_system};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::{io::AsyncBufReadExt, time::{sleep, timeout}};

use super::{DESKTOP, SERVER, address, http, input, matching_log, process, terminal::Terminal, tls};

const ROOT: &str = "SAP_ADT_TEST_CONSOLE_DIRECTORY";
const ATTACHED: &str = "SAP_ADT_TEST_CONSOLE_ATTACHED";
const FIXTURE: &str = "headless_console::redirected_server_fixture";

// Run inside portable-pty's new terminal session. On both Unix and Windows
// the server inherits that session while its regular standard streams are
// redirected, as they would be by a log collector. No shell is involved.
#[test]
#[ignore = "subprocess fixture for the headless enrollment integration test"]
fn redirected_server_fixture() -> Result<()> {
    let Some(root) = std::env::var_os(ROOT).map(PathBuf::from) else { return Ok(()) };
    let mut command = Command::new(SERVER);
    #[cfg(windows)]
    if std::env::var_os(ATTACHED).is_none() {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS prevents inheritance of the wrapper's ConPTY.
        command.creation_flags(0x0000_0008);
    }
    let mut server = command
        .args(["serve", "--headless", "--issue-token", "--listen", "127.0.0.1:0",
            "--enrollment-listen", "127.0.0.1:0", "--pki"])
        .arg(root.join("pki")).stdin(Stdio::null())
        .stdout(fs::File::create(root.join("stdout.log"))?)
        .stderr(fs::File::create(root.join("stderr.log"))?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = server.try_wait()? {
            ensure!(status.success(), "Server exited unsuccessfully.");
            return Ok(());
        }
        if root.join("stop").exists() || Instant::now() >= deadline {
            server.kill()?;
            server.wait()?;
            anyhow::bail!("Server fixture stopped.");
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

struct Console {
    child: Box<dyn Child + Send + Sync>,
    pty: Option<PtyPair>,
    terminal: Terminal,
    root: PathBuf,
}

impl Console {
    fn launch(root: &Path, attached: bool) -> Result<Self> {
        let size = PtySize { rows: 80, cols: 180, pixel_width: 0, pixel_height: 0 };
        let pty = native_pty_system().openpty(size)?;
        let mut command = CommandBuilder::new(std::env::current_exe()?);
        command.args(["--exact", FIXTURE, "--ignored", "--nocapture"]);
        command.env(ROOT, root);
        command.env("RUST_LOG", "debug");
        command.env("TERM", "xterm-256color");
        command.set_controlling_tty(attached);
        if attached { command.env(ATTACHED, "1"); } else { command.env_remove(ATTACHED); }
        let terminal = Terminal::attach(&*pty.master, size)?;
        let child = pty.slave.spawn_command(command)?;
        Ok(Self { child, pty: Some(pty), terminal, root: root.to_owned() })
    }

    async fn visible(&mut self, marker: &str) -> Result<()> {
        timeout(Duration::from_secs(30), self.terminal.screen.wait_for(|screen| screen.contains(marker)))
            .await.with_context(|| format!("Timed out waiting for console message {marker:?}."))??;
        Ok(())
    }

    async fn request_number(&mut self, id: &str, label: &str) -> Result<u64> {
        let prefix = format!("Pending {id} role=desktop label=\"{label}\" peer=");
        let number = |screen: &str| {
            screen.lines().find_map(|line| {
                let peer_and_number = line.trim().strip_prefix(&prefix)?;
                let (_, number) = peer_and_number.rsplit_once(" number=")?;
                number.parse::<u64>().ok()
            })
        };
        let screen = timeout(Duration::from_secs(30), self.terminal.screen.wait_for(|screen| number(screen).is_some()))
            .await.with_context(|| format!("The console did not show the request number for {label:?}."))??;
        number(&screen).context("Missing the displayed local request number.")
    }

    fn enter(&self, command: &str) -> Result<()> {
        self.terminal.keys(format!("{command}\r").as_bytes())
    }

    async fn grant(&mut self) -> Result<String> {
        fn token_line(screen: &str) -> Option<&str> {
            screen.lines().map(str::trim).find(|line| line.starts_with("GW1-") && line.len() == 127)
        }
        let screen = timeout(Duration::from_secs(30), self.terminal.screen.wait_for(|s| token_line(s).is_some()))
            .await.context("The console did not show the approved token.")??;
        let token = token_line(&screen).map(str::to_owned);
        drop(screen);
        token.context("Expected a complete token on the local terminal.")
    }

    async fn exit(&mut self) -> Result<bool> {
        loop {
            if let Some(status) = self.child.try_wait()? { return Ok(status.success()); }
            sleep(Duration::from_millis(30)).await;
        }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // Ask the wrapper to reap the real child even on assertion failure.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let stop = self.root.join("stop");
            let _ = fs::write(&stop, []);
            let deadline = Instant::now() + Duration::from_secs(3);
            while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(30));
            }
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                let _ = fs::remove_file(stop);
            } else {
                let _ = self.child.kill();
            }
        }
        // ClosePseudoConsole can wait for a terminal reply even during teardown.
        // Keep native ClosePseudoConsole off the test runtime's thread.
        if let Some(pty) = self.pty.take() {
            std::thread::spawn(move || drop(pty));
        }
    }
}

async fn listener_addresses(root: &Path) -> Result<(std::net::SocketAddr, std::net::SocketAddr)> {
    loop {
        let log = fs::read_to_string(root.join("stderr.log"))?;
        if log.contains("mutual TLS on") && log.contains("Enrollment listening on") {
            return Ok((address(&log, "mutual TLS on")?, address(&log, "Enrollment listening on")?));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

fn check_redirected_output(root: &Path) -> Result<String> {
    let stdout = fs::read(root.join("stdout.log"))?;
    let stderr = fs::read_to_string(root.join("stderr.log"))?;
    ensure!(stdout.is_empty(), "The headless server wrote to stdout.");
    ensure!(!stderr.contains("GW1-") && !stderr.contains("PRIVATE KEY"), "Enrollment secrets appeared in stderr.");
    Ok(stderr)
}

async fn headless_scenario() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let pki = root.join("pki");
    let status = process(SERVER).args(["init", "--dns", "127.0.0.1", "--pki"]).arg(&pki).status().await?;
    ensure!(status.success(), "Could not initialize the test server.");

    let mut detached = Console::launch(root, false)?;
    ensure!(!detached.exit().await?, "Token issuance started without a controlling console.");
    let log = check_redirected_output(root)?;
    ensure!(log.contains("controlling terminal"), "Server did not diagnose the missing controlling terminal.");
    drop(detached);

    let mut console = Console::launch(root, true)?;
    console.visible("Enrollment approval console ready.").await?;
    let (data, enrollment) = listener_addresses(root).await?;
    let ca = fs::read(pki.join("ca.pem"))?;
    let client = http(tls(&ca, None)?)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let request = |label: &str| {
        let post = client.post(format!("https://{enrollment}/request"))
            .json(&json!({"id": id, "role": "desktop", "label": label}));
        tokio::spawn(async move { post.send().await })
    };
    let denied = request("Deny this device");
    let first = console.request_number(&id, "Deny this device").await?;
    console.enter(&format!("deny {first}"))?;
    ensure!(denied.await??.status() == StatusCode::FORBIDDEN, "Denied device received approval.");
    console.visible("Request denied.").await?;

    let replacement = request("Reused public ID");
    let second = console.request_number(&id, "Reused public ID").await?;
    ensure!(first != second, "A reused public ID received a stale approval number.");
    console.enter(&format!("approve {first}"))?;
    console.visible("No displayed request has that number.").await?;
    console.enter(&format!("deny {second}"))?;
    ensure!(replacement.await??.status() == StatusCode::FORBIDDEN, "A stale approval authorized another applicant.");

    let profile = root.join("client");
    let mut desktop = process(DESKTOP).args(["enroll", "--server", &format!("https://{data}"),
        "--enrollment", &format!("https://{enrollment}"), "--label", "Approved desktop", "--profile"])
        .arg(&profile).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut logs = tokio::io::BufReader::new(desktop.stderr.take().context("Missing client diagnostic stream.")?).lines();
    let request = matching_log(&mut logs, "Enrollment request ID: ").await?;
    let id = request.strip_prefix("Enrollment request ID: ").context("Missing client request ID.")?;
    let number = console.request_number(id, "Approved desktop").await?;
    ensure!(!console.terminal.screen.borrow().contains("GW1-"), "A token appeared before the first valid approval.");
    check_redirected_output(root)?;
    console.enter(&format!("approve {number}"))?;
    let token = console.grant().await?;
    input(desktop.stdin.as_mut().context("Missing client's token input.")?, &token).await?;
    matching_log(&mut logs, "Client profile saved.").await?;
    ensure!(desktop.wait().await?.success(), "The real desktop client failed its pinned claim.");
    let saved: Value = serde_json::from_slice(&fs::read(profile.join("credentials.json"))?)?;
    ensure!(saved["credentials"]["client_cert_pem"].is_string(), "Client identity was not persisted.");
    let replay = client.post(format!("https://{enrollment}/claim")).json(&json!({"token": token})).send().await?;
    ensure!(replay.status() == StatusCode::FORBIDDEN, "A consumed token was accepted twice.");

    console.enter("quit")?;
    ensure!(console.exit().await?, "Headless server failed to stop cleanly.");
    let logs = check_redirected_output(root)?;
    ensure!(logs.contains("Enrollment listening on"), "Expected operational logs on stderr.");
    Ok(())
}

#[tokio::test]
async fn headless_grants_use_only_the_controlling_console() -> Result<()> {
    timeout(Duration::from_secs(150), headless_scenario()).await
        .context("Timed out exercising headless enrollment.")?
}
