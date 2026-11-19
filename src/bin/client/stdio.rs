use std::{
    io::{self, Stdout},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use smol::{
    Task, Unblock,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    lock::Mutex,
};
use trillium_client::{HeaderValue, KnownHeaderName, Method, Status, Url};

use crate::{
    endpoints,
    https::{Client, RequestBuilder},
    rt,
    transport::Profile,
};

const MAX_REQUEST: usize = 4 * 1024 * 1024;
const MAX_RESPONSE: usize = 9 * 1024 * 1024;
const MAX_CONCURRENT: usize = 16;
const SESSION_ID: &str = "mcp-session-id";
const VERSION: &str = "mcp-protocol-version";
type Output = Arc<Mutex<Unblock<Stdout>>>;
type Jobs = Vec<Task<Result<()>>>;

#[derive(Clone)]
struct Remote {
    http: Client,
    url: Url,
    endpoint: HeaderValue,
}

impl Remote {
    fn open(directory: Option<&Path>) -> Result<Self> {
        let directory = directory.with_context(|| format!(
            "No desktop profile was configured. Set the MCP host arguments to connect --profile <dir>, using your enrolled profile directory. For enrollment instructions run sap-adt-mcp-client enroll --help. {}",
            endpoints::SELECT_HELP
        ))?;
        let profile = Profile::load(directory).with_context(|| format!(
            "Cannot load the desktop profile at {}. Check the MCP host's --profile argument or enroll a new profile with sap-adt-mcp-client enroll --help.",
            directory.display()
        ))?;
        let (http, url) = profile.connection()
            .context("Cannot use the profile's relay URL or credentials. Check the profile or enroll a new one with sap-adt-mcp-client enroll --help.")?;
        let selection = endpoints::read_selected(directory).with_context(|| {
            format!(
                "No valid Eclipse endpoint is selected for profile {}. {}",
                directory.display(),
                endpoints::SELECT_HELP
            )
        })?;
        Ok(Self {
            http,
            url,
            endpoint: HeaderValue::from(selection),
        })
    }

    fn request(&self, method: Method) -> RequestBuilder {
        self.http
            .request(method, &self.url)
            .header("x-sap-adt-endpoint", self.endpoint.clone())
    }
}

#[derive(Clone)]
struct Session {
    id: HeaderValue,
    version: HeaderValue,
    expired: Arc<AtomicBool>,
}

impl Session {
    fn headers(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .header(SESSION_ID, self.id.clone())
            .header(VERSION, self.version.clone())
    }

    async fn close(&self, target: &Remote) {
        let request = self
            .headers(target.request(Method::Delete))
            .timeout(Duration::from_secs(5));
        match request.send().await {
            Ok(response)
                if response.status().is_success() || response.status() == Status::NotFound => {}
            _ => eprintln!("Could not close the remote MCP session."),
        }
    }
}

async fn write(output: &Output, message: &Value) -> Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    let mut stdout = output.lock().await;
    stdout.write_all(&line).await?;
    stdout.flush().await?;
    drop(stdout);
    Ok(())
}

fn rpc_error(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

struct Reply {
    body: Option<Value>,
    new_session: Option<Session>,
}

async fn post(
    remote: &Remote,
    session: Option<&Session>,
    bytes: Vec<u8>,
    id: Option<&Value>,
    initialize: bool,
) -> Result<Reply> {
    let request = remote
        .request(Method::Post)
        .header(
            KnownHeaderName::Accept,
            "application/json, text/event-stream",
        )
        .header(KnownHeaderName::ContentType, "application/json")
        .body(bytes);
    let request = match session {
        Some(active) => active.headers(request),
        None => request,
    };
    let response = request
        .send()
        .await
        .context("Could not reach the relay over mutual TLS.")?;
    let status = response.status();
    if let Some(session) = session
        && status == Status::NotFound
    {
        session.expired.store(true, Ordering::Release);
    }
    let Some(id) = id else {
        ensure!(
            status == Status::Accepted,
            "The relay rejected a notification (HTTP {status})."
        );
        return Ok(Reply {
            body: None,
            new_session: None,
        });
    };
    let session_id = response.header(SESSION_ID).map(str::to_owned);
    ensure!(
        response
            .header(KnownHeaderName::ContentType)
            .and_then(|header| header.split(';').next())
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json")),
        "The relay returned an unexpected content type (HTTP {status})."
    );
    let bytes = response.bytes(MAX_RESPONSE).await?;
    let message: Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid JSON from the relay."))?;
    ensure!(
        message["jsonrpc"] == "2.0"
            && message.get("id") == Some(id)
            && (message.get("error").is_some() ^ message.get("result").is_some())
            && message.get("method").is_none(),
        "Invalid JSON-RPC response from the relay."
    );
    ensure!(
        status.is_success() || message.get("error").is_some(),
        "The relay returned HTTP {status}."
    );
    let new_session = if initialize && message.get("result").is_some() {
        let assigned_id = session_id.context("The relay did not issue a session ID.")?;
        ensure!(
            !assigned_id.is_empty(),
            "The relay issued an empty session ID."
        );
        let version = message["result"]["protocolVersion"]
            .as_str()
            .context("The relay did not negotiate a protocol version.")?
            .to_owned();
        let session = Session {
            id: HeaderValue::from(assigned_id),
            version: HeaderValue::from(version),
            expired: Arc::new(AtomicBool::new(false)),
        };
        let confirmed = message["result"]["_meta"]["com.sap.adt.mcp/endpoint"].as_str();
        if confirmed != remote.endpoint.as_str() {
            session.close(remote).await;
            let error = rpc_error(
                id,
                -32_002,
                "The relay did not confirm the selected Eclipse endpoint. Check the relay version and the desktop profile.",
            );
            return Ok(Reply {
                body: Some(error),
                new_session: None,
            });
        }
        Some(session)
    } else {
        None
    };
    Ok(Reply {
        body: Some(message),
        new_session,
    })
}

async fn exchange(
    remote: &Remote,
    session: Option<&Session>,
    bytes: Vec<u8>,
    message: &Value,
    output: &Output,
) -> Result<Option<Session>> {
    let id = message.get("id");
    let initialize = message["method"] == "initialize";
    match post(remote, session, bytes, id, initialize).await {
        Ok(reply) => {
            if let Some(body) = reply.body {
                write(output, &body).await?;
            }
            Ok(reply.new_session)
        }
        Err(error) => {
            eprintln!("Relay request failed: {error:#}");
            if let Some(id) = id {
                let text = if message["method"] == "tools/call" {
                    "The relay response is unavailable. The tool may have completed. Check its outcome before retrying."
                } else {
                    "The relay response is unavailable. Check the relay connection."
                };
                write(output, &rpc_error(id, -32_000, text)).await?;
            }
            Ok(None)
        }
    }
}

/// Await the jobs that have already finished so their errors surface promptly.
async fn reap(jobs: &mut Jobs) -> Result<()> {
    let mut index = 0;
    while index < jobs.len() {
        if jobs[index].is_finished() {
            jobs.swap_remove(index).await?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

async fn messages(
    connection: Result<&Remote, &str>,
    session: &mut Option<Session>,
    jobs: &mut Jobs,
) -> Result<()> {
    let output = Arc::new(Mutex::new(Unblock::new(io::stdout())));
    let mut input = BufReader::new(Unblock::new(io::stdin()));
    loop {
        reap(jobs).await?;
        let mut bytes = Vec::new();
        let length = (&mut input)
            .take(MAX_REQUEST as u64 + 2)
            .read_until(b'\n', &mut bytes)
            .await?;
        if length == 0 {
            return Ok(());
        }
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        ensure!(
            bytes.len() <= MAX_REQUEST,
            "Standard input exceeded the MCP request size limit."
        );
        let Ok(message) = serde_json::from_slice::<Value>(&bytes) else {
            write(&output, &rpc_error(&Value::Null, -32700, "Invalid JSON.")).await?;
            continue;
        };
        let id = message.get("id");
        if message["jsonrpc"] != "2.0"
            || !message["method"].is_string()
            || id.is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64()))
        {
            write(
                &output,
                &rpc_error(&Value::Null, -32600, "Invalid JSON-RPC request."),
            )
            .await?;
            continue;
        }
        let initialize = message["method"] == "initialize" && id.is_some();
        let remote = match connection {
            Ok(remote) => remote,
            Err(reason) => {
                if let Some(id) = id {
                    write(&output, &rpc_error(id, -32_002, reason)).await?;
                }
                continue;
            }
        };
        if session
            .as_ref()
            .is_some_and(|s| s.expired.load(Ordering::Acquire))
        {
            *session = None;
        }
        if initialize && session.is_none() {
            *session = exchange(remote, None, bytes, &message, &output).await?;
            continue;
        }
        let Some(current) = session.as_ref() else {
            if let Some(id) = id {
                write(
                    &output,
                    &rpc_error(id, -32_000, "Initialize a new relay session first."),
                )
                .await?;
            }
            continue;
        };
        if initialize {
            write(
                &output,
                &rpc_error(
                    &message["id"],
                    -32600,
                    "The session is already initialized.",
                ),
            )
            .await?;
        } else if id.is_none() {
            let _ = exchange(remote, Some(current), bytes, &message, &output).await?;
        } else if jobs.len() >= MAX_CONCURRENT {
            write(
                &output,
                &rpc_error(&message["id"], -32_000, "Too many concurrent requests."),
            )
            .await?;
        } else {
            let (target, active, sink) = (remote.clone(), current.clone(), output.clone());
            jobs.push(rt::spawn(async move {
                let _ = exchange(&target, Some(&active), bytes, &message, &sink).await?;
                Ok(())
            }));
        }
    }
}

pub async fn run(directory: Option<&Path>) -> Result<()> {
    let remote = Remote::open(directory).map_err(|err| err.to_string());
    let connection = remote.as_ref().map_err(String::as_str);
    if let Err(reason) = connection {
        eprintln!("{reason}");
    }
    let mut jobs = Jobs::new();
    let mut session = None;
    let mut outcome = messages(connection, &mut session, &mut jobs).await;
    for job in jobs {
        let result = job.await;
        if outcome.is_ok() {
            outcome = result;
        }
    }
    if let (Some(session), Ok(target)) = (session, connection) {
        session.close(target).await;
    }
    if let Err(error) = &outcome
        && error
            .downcast_ref::<io::Error>()
            .is_some_and(|err| err.kind() == io::ErrorKind::BrokenPipe)
    {
        return Ok(());
    }
    outcome
}
