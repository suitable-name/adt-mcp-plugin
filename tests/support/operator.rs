use std::{path::Path, sync::Mutex, time::Duration};

use super::terminal::Terminal;
use anyhow::{Context, Result};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

use crate::rt::timeout;

/// Operate the same local terminal as a human. The test has no privileged network endpoint.
pub struct Operator {
    child: Box<dyn Child + Send + Sync>,
    // Only kept alive. The mutex makes `Operator: Sync`, so `&Operator` futures are `Send`.
    _terminal: Mutex<Box<dyn MasterPty + Send>>,
    terminal: Terminal,
}

impl Operator {
    pub fn start(binary: &str, pki: &Path) -> Result<Self> {
        let size = PtySize {
            rows: 48,
            // Wide enough to show a whole link on one row.
            cols: 320,
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
            _terminal: Mutex::new(pair.master),
            terminal,
        })
    }

    pub fn keys(&self, keys: &[u8]) -> Result<()> {
        self.terminal.keys(keys)
    }

    async fn wait_for(
        &self,
        phase: &'static str,
        ready: impl FnMut(&str) -> bool + Send,
    ) -> Result<String> {
        timeout(
            Duration::from_secs(15),
            self.terminal.screen.wait_for(ready),
        )
        .await
        .with_context(|| format!("Operator terminal timed out waiting for {phase:?}."))?
        .with_context(|| format!("Operator terminal closed while waiting for {phase:?}."))
    }

    pub async fn visible(&self, marker: &'static str) -> Result<String> {
        self.wait_for(marker, |screen| screen.contains(marker))
            .await
    }

    /// Press N on the Enrollment tab, choose the role, type the label and read the link
    /// from the screen. The dialog is dismissed again and the test checks that the link
    /// is gone from the screen.
    pub async fn new_link(&self, eclipse: bool, label: &str) -> Result<String> {
        self.keys(b"n")?;
        self.wait_for("the New Enrollment Link dialog", |s| {
            s.contains("New Enrollment Link")
        })
        .await?;
        if eclipse {
            self.keys(b"\x1b[C")?;
            self.wait_for("the eclipse role", |s| s.contains("\u{25c0} eclipse"))
                .await?;
        }
        self.keys(label.as_bytes())?;
        self.wait_for("the typed label", |s| s.contains(label))
            .await?;
        self.keys(b"\r")?;
        let screen = self
            .wait_for("the complete enrollment link", |s| link(s).is_some())
            .await?;
        let text = link(&screen)
            .context("Missing link from the local terminal.")?
            .to_owned();
        self.keys(b"\x1b")?;
        self.wait_for("dismissal of the enrollment link", |s| {
            !s.contains("sap-adt://")
        })
        .await?;
        Ok(text)
    }

    /// Cancel the selected (first) outstanding link with X.
    pub async fn cancel_first_link(&self) -> Result<()> {
        self.keys(b"x")?;
        self.visible("Link cancelled.").await?;
        Ok(())
    }
}

/// The link on the screen once all of its token is there.
fn link(screen: &str) -> Option<&str> {
    let start = screen.find("sap-adt://enroll?")?;
    let text = screen[start..].split_whitespace().next()?;
    let (_, token) = text.split_once("&t=")?;
    (token.len() == 127
        && token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'))
    .then_some(text)
}

impl Drop for Operator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
