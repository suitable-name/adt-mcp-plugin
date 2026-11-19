use std::{path::Path, time::Duration};

use super::terminal::Terminal;
use anyhow::{Context, Result};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::time::timeout;

/// Operate the same local terminal as a human. The test has no privileged network endpoint.
pub struct Operator {
    child: Box<dyn Child + Send + Sync>,
    _terminal: Box<dyn MasterPty + Send>,
    terminal: Terminal,
}

impl Operator {
    pub fn start(binary: &str, pki: &Path) -> Result<Self> {
        let size = PtySize {
            rows: 48,
            cols: 160,
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = native_pty_system().openpty(size)?;
        let mut cmd = CommandBuilder::new(binary);
        cmd.args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--enrollment-listen",
            "127.0.0.1:0",
            "--pki",
        ]);
        cmd.arg(pki);
        cmd.env("RUST_LOG", "info");
        cmd.env("TERM", "xterm-256color");
        let terminal = Terminal::attach(pair.master.as_ref(), size)?;
        let child = pair.slave.spawn_command(cmd)?;
        Ok(Self {
            child,
            _terminal: pair.master,
            terminal,
        })
    }

    pub fn keys(&self, keys: &[u8]) -> Result<()> {
        self.terminal.keys(keys)
    }

    async fn wait_for(
        &mut self,
        phase: &'static str,
        ready: impl FnMut(&String) -> bool,
    ) -> Result<String> {
        let screen = timeout(
            Duration::from_secs(15),
            self.terminal.screen.wait_for(ready),
        )
        .await
        .with_context(|| format!("Operator terminal timed out waiting for {phase:?}."))?
        .with_context(|| format!("Operator terminal closed while waiting for {phase:?}."))?;
        Ok(screen.clone())
    }

    pub async fn visible(&mut self, marker: &'static str) -> Result<String> {
        self.wait_for(marker, |screen| screen.contains(marker))
            .await
    }

    pub async fn approve(&mut self, id: &str) -> Result<String> {
        self.wait_for("the pending enrollment request", |s| s.contains(id))
            .await?;
        self.keys(b"a")?;
        self.wait_for("the approval dialog for the selected request", |s| {
            s.contains("Approve Enrollment") && s.contains(id)
        })
        .await?;
        self.keys(b"\r")?;
        let screen = self
            .wait_for("the complete enrollment token", |s| token(s).is_some())
            .await?;
        let grant = token(&screen)
            .context("Missing token from the local terminal.")?
            .to_owned();
        self.keys(b"\x1b")?;
        self.wait_for("dismissal of the enrollment token", |s| !s.contains("GW1-"))
            .await?;
        Ok(grant)
    }
}

fn token(screen: &str) -> Option<&str> {
    let start = screen.find("GW1-")?;
    let grant = screen.get(start..start + 127)?;
    grant
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        .then_some(grant)
}

impl Drop for Operator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
