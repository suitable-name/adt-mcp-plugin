//! The MCP host side of the end-to-end test: `sap-adt-mcp-client connect` on stdio.

use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use serde_json::{Value, json};
use smol::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout},
};

use crate::{
    rt,
    setup::{DESKTOP, LogBuffer, process},
};

pub struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr: LogBuffer,
}

impl Host {
    pub fn start(profile: &Path) -> Result<Self> {
        let mut child = process(DESKTOP)
            .args(["connect", "--profile"])
            .arg(profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().context("Missing MCP input.")?;
        let stdout = BufReader::new(child.stdout.take().context("Missing MCP output.")?).lines();
        let stderr = LogBuffer::capture(child.stderr.take().context("Missing client logs.")?);
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr,
        })
    }

    async fn write_line(&mut self, message: &Value) -> Result<()> {
        let stdin = self.stdin.as_mut().context("The input is closed.")?;
        stdin.write_all(message.to_string().as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }

    pub async fn notify(&mut self, method: &str) -> Result<()> {
        self.write_line(&json!({"jsonrpc": "2.0", "method": method}))
            .await
    }

    /// Send a request and return the host's answer for it.
    pub async fn call(&mut self, id: u64, method: &str, params: &Value) -> Result<Value> {
        self.write_line(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        let line = rt::timeout(Duration::from_secs(60), self.stdout.next())
            .await
            .context("Timed out waiting for the desktop's answer.")?
            .context("The desktop closed its output.")??;
        let reply: Value = serde_json::from_str(&line)?;
        ensure!(reply["id"] == id, "Answer for another request: {reply}");
        Ok(reply)
    }

    /// Close the input, wait for the client to exit and return everything it logged.
    pub async fn finish(mut self) -> Result<String> {
        drop(self.stdin.take());
        let status = rt::timeout(Duration::from_secs(30), self.child.status())
            .await
            .context("The desktop did not exit.")??;
        ensure!(status.success(), "The desktop client failed: {status}.");
        // The collector task reads the last lines a moment after the process is gone.
        smol::Timer::after(Duration::from_millis(250)).await;
        Ok(self.stderr.text())
    }
}
