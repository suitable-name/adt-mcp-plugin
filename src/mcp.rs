use axum::{
    Extension, Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::Relay;
use crate::bridge::{Client, Outcome, error};
use crate::policy::{Effective, PolicyStore};
use crate::security::{Pki, valid_fingerprint};
use crate::transport::PeerCertificate;

const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
const VERSION: &str = "2025-11-25";
const ENDPOINT_HEADER: &str = "x-sap-adt-endpoint";
const ENDPOINT_TOOL: &str = "relay_list_endpoints";
const SELECT_ENDPOINT: &str = "Run sap-adt-mcp-client endpoints --profile <dir>, then sap-adt-mcp-client --set-endpoint=<id> --profile <dir> and reconnect.";

#[derive(Serialize)]
struct Endpoint {
    id: String,
    label: String,
    online: bool,
}

async fn read_access<T: Send + 'static>(
    relay: &Relay,
    cert: &PeerCertificate,
    read: impl FnOnce(&PolicyStore, &Pki, &[u8; 32]) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, StatusCode> {
    let policy = Arc::clone(&relay.policy);
    let pki = Arc::clone(&relay.pki);
    let cert = cert.clone();
    tokio::task::spawn_blocking(move || {
        // Request bodies can arrive slowly after TLS and the initial route authorization.
        if !pki.authorize(&cert.der, "desktop") {
            return Ok(None);
        }
        read(&policy, &pki, &cert.fingerprint).map(Some)
    })
    .await
    .map_err(anyhow::Error::from)
    .flatten()
    .map_err(|cause| {
        tracing::error!(%cause, "Could not read endpoint access.");
        StatusCode::SERVICE_UNAVAILABLE
    })?
    .ok_or(StatusCode::FORBIDDEN)
}

async fn catalog(relay: &Relay, cert: &PeerCertificate) -> Result<Vec<Endpoint>, StatusCode> {
    let grants = read_access(relay, cert, |policy, pki, owner| {
        let mut enrolled = Vec::new();
        for id in policy.endpoint_grants(owner)? {
            if let Some(label) = pki.eclipse_label(&id)? {
                enrolled.push((id, label));
            }
        }
        Ok(enrolled)
    })
    .await?;
    let mut endpoints: Vec<_> = grants
        .into_iter()
        .map(|(id, label)| Endpoint {
            online: relay.registry.online(&id),
            id,
            label,
        })
        .collect();
    endpoints.sort_unstable_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    Ok(endpoints)
}

pub async fn endpoints(
    State(relay): State<Relay>,
    Extension(cert): Extension<PeerCertificate>,
) -> Result<Response, StatusCode> {
    let result = Json(json!({"endpoints":catalog(&relay, &cert).await?}));
    Ok(([(header::CACHE_CONTROL, "no-store")], result).into_response())
}

async fn endpoint_policy(
    relay: &Relay,
    cert: &PeerCertificate,
    endpoint: &str,
) -> Result<Effective, StatusCode> {
    let endpoint = endpoint.to_owned();
    read_access(relay, cert, move |policy, pki, owner| {
        Ok(policy
            .effective_for_endpoint(owner, &endpoint)?
            .filter(|_| pki.eclipse_enrolled(&endpoint)))
    })
    .await?
    .ok_or(StatusCode::FORBIDDEN)
}

fn rpc_error(status: StatusCode, id: &Value, cause: Value) -> Response {
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply["error"] = cause;
    (status, Json(reply)).into_response()
}

fn rpc_result(id: &Value, result: Value) -> Response {
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply["result"] = result;
    Json(reply).into_response()
}

fn session_id(headers: &HeaderMap) -> Result<Uuid, StatusCode> {
    let value = headers.get(SESSION_HEADER).ok_or(StatusCode::BAD_REQUEST)?;
    value
        .to_str()
        .ok()
        .and_then(|text| Uuid::parse_str(text).ok())
        .ok_or(StatusCode::NOT_FOUND)
}

fn selector(headers: &HeaderMap) -> Result<Option<&str>, StatusCode> {
    let mut values = headers.get_all(ENDPOINT_HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    first
        .to_str()
        .ok()
        .filter(|id| valid_fingerprint(id))
        .map(Some)
        .ok_or(StatusCode::BAD_REQUEST)
}

async fn lookup(
    relay: &Relay,
    headers: &HeaderMap,
    cert: &PeerCertificate,
) -> Result<(Uuid, Client, Effective), StatusCode> {
    let id = session_id(headers)?;
    let (client, version) = relay
        .registry
        .session(selector(headers)?, id, &cert.fingerprint)?;
    if headers
        .get(VERSION_HEADER)
        .is_some_and(|field| field.as_bytes() != version.as_bytes())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let policy = match endpoint_policy(relay, cert, &client.endpoint).await {
        Ok(policy) => policy,
        Err(status) => {
            if status == StatusCode::FORBIDDEN {
                relay.registry.remove(&client.endpoint, id);
            }
            return Err(status);
        }
    };
    relay.registry.refresh(&client, id, &cert.fingerprint)?;
    Ok((id, client, policy))
}

pub async fn end_session(
    State(relay): State<Relay>,
    Extension(cert): Extension<PeerCertificate>,
    headers: HeaderMap,
) -> StatusCode {
    match lookup(&relay, &headers, &cert).await {
        Ok((id, client, _)) => {
            relay.registry.remove(&client.endpoint, id);
            StatusCode::NO_CONTENT
        }
        Err(status) => status,
    }
}

async fn initialize(
    relay: &Relay,
    headers: &HeaderMap,
    params: &Value,
    id: &Value,
    cert: &PeerCertificate,
) -> Response {
    let Some(requested) = params["protocolVersion"].as_str() else {
        return rpc_error(
            StatusCode::OK,
            id,
            error(-32602, "Missing protocol version."),
        );
    };
    let version = match requested {
        "2024-11-05" => "2024-11-05",
        "2025-03-26" => "2025-03-26",
        "2025-06-18" => "2025-06-18",
        _ => VERSION,
    };
    let Ok(Some(endpoint)) = selector(headers) else {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            id,
            error(
                -32602,
                &format!("Select an Eclipse endpoint. {SELECT_ENDPOINT}"),
            ),
        );
    };
    if let Err(status) = endpoint_policy(relay, cert, endpoint).await {
        return access_error(status, id);
    }
    let session = match relay
        .registry
        .initialize(endpoint, version, cert.fingerprint)
    {
        Ok(session) => session,
        Err(StatusCode::SERVICE_UNAVAILABLE) => {
            return rpc_error(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                error(
                    -32_000,
                    "The selected Eclipse endpoint is offline. Connect that Eclipse workspace and retry.",
                ),
            );
        }
        Err(status) => {
            return rpc_error(
                status,
                id,
                error(-32_000, "The MCP session limit was reached."),
            );
        }
    };
    let result = json!({
        "protocolVersion": version, "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "sap-adt-relay", "version": env!("CARGO_PKG_VERSION")},
        "_meta": {"com.sap.adt.mcp/endpoint":endpoint},
        "instructions": format!("SAP tools use Eclipse endpoint {endpoint}. Use {ENDPOINT_TOOL} to see its label and your permitted endpoints. {SELECT_ENDPOINT}")
    });
    (
        [(SESSION_HEADER, session.to_string())],
        rpc_result(id, result),
    )
        .into_response()
}

fn validate(message: &Value) -> bool {
    let id = message.get("id");
    message["jsonrpc"] == "2.0"
        && message["method"].is_string()
        && message.get("params").is_none_or(Value::is_object)
        && id.is_none_or(|id| id.is_string() || id.is_i64() || id.is_u64())
        && message.get("result").is_none()
        && message.get("error").is_none()
}

fn access_error(status: StatusCode, id: &Value) -> Response {
    let message = match status {
        StatusCode::FORBIDDEN => {
            format!("This endpoint is unavailable to this desktop. {SELECT_ENDPOINT}")
        }
        StatusCode::SERVICE_UNAVAILABLE => "The access policy is unavailable.".to_owned(),
        _ => "A valid MCP session for this endpoint is required.".to_owned(),
    };
    rpc_error(status, id, error(-32_000, &message))
}

pub async fn request(
    State(relay): State<Relay>,
    Extension(cert): Extension<PeerCertificate>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Ok(mut message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            error(-32700, "Invalid JSON."),
        );
    };
    if !validate(&message) {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            error(-32600, "Invalid JSON-RPC message."),
        );
    }
    let params = message
        .as_object_mut()
        .and_then(|object| object.remove("params"))
        .unwrap_or(Value::Null);
    let method = message["method"].as_str().unwrap_or_default();
    if method == "initialize" && message.get("id").is_some() {
        if headers.contains_key(SESSION_HEADER) {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                &message["id"],
                error(-32600, "Initialize without a session ID."),
            );
        }
        return initialize(&relay, &headers, &params, &message["id"], &cert).await;
    }
    let (client, policy) = match lookup(&relay, &headers, &cert).await {
        Ok((_, client, policy)) => (client, policy),
        Err(status) => return access_error(status, &message["id"]),
    };
    let Some(id) = message.get("id") else {
        return StatusCode::ACCEPTED.into_response();
    };
    if method == "tools/call" && params["name"].as_str() == Some(ENDPOINT_TOOL) {
        if params
            .get("arguments")
            .is_some_and(|args| args.as_object().is_none_or(|fields| !fields.is_empty()))
        {
            return rpc_error(
                StatusCode::OK,
                id,
                error(-32602, "This tool takes no arguments."),
            );
        }
        return match catalog(&relay, &cert).await {
            Ok(endpoints) => {
                let data = json!({"selected":client.endpoint.as_ref(), "endpoints":endpoints});
                rpc_result(
                    id,
                    json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data}),
                )
            }
            Err(status) => access_error(status, id),
        };
    }
    match dispatch(&client, method, params, &policy, cert.fingerprint).await {
        Ok(result) => rpc_result(id, result),
        Err(cause) => rpc_error(StatusCode::OK, id, cause),
    }
}

async fn dispatch(
    client: &Client,
    method: &str,
    params: Value,
    policy: &Effective,
    owner: [u8; 32],
) -> Outcome {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => {
            let mut result = client.call("tools/list", params).await?;
            let tools = result["tools"]
                .as_array_mut()
                .ok_or_else(|| error(-32603, "Invalid tool list from Eclipse."))?;
            tools.retain(|tool| {
                tool["name"]
                    .as_str()
                    .is_some_and(|name| policy.allows(name))
            });
            tools.push(json!({
                "name":ENDPOINT_TOOL,
                "description":"List Eclipse endpoints available to this desktop and show the endpoint selected for this session.",
                "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
                "annotations":{"readOnlyHint":true}
            }));
            Ok(result)
        }
        "tools/call" => {
            let name = params["name"]
                .as_str()
                .ok_or_else(|| error(-32602, "A tool name is required."))?;
            let desktop = hex::encode(owner);
            if !policy.allows(name) {
                tracing::warn!(%desktop, "Denied a tool call under the current access policy.");
                return Err(error(
                    -32_001,
                    "The current access policy does not allow this tool.",
                ));
            }
            tracing::info!(%desktop, tool = name, "Admitted a tool call.");
            // Construct this envelope from scratch. Package constraints belong to the relay.
            let mut call = json!({"name":name, "relayPackageScopes":policy.package_scopes()});
            if let Some(arguments) = params.get("arguments") {
                call["arguments"] = arguments.clone();
            }
            client.call("tools/call", call).await
        }
        _ => Err(error(-32601, "Unknown MCP method.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn policy_applies_to_sap_discovery_and_direct_calls() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1; 32];
        let store = crate::policy::PolicyStore::load(dir.path()).unwrap();
        let endpoint = hex::encode([2; 32]);
        assert!(
            store
                .effective_for_endpoint(&owner, &endpoint)
                .unwrap()
                .is_none()
        );
        store
            .set_endpoint_grants(
                &store.snapshot().unwrap().revision,
                &hex::encode(owner),
                vec![endpoint.clone()],
            )
            .unwrap();
        let policy = store
            .effective_for_endpoint(&owner, &endpoint)
            .unwrap()
            .unwrap();
        let tools = json!({"tools": [{"name": "sap_set_source"}, {"name": "sap_search_object"}]});
        let (client, list_call) = Client::expecting("tools/list", Value::Null, tools);
        let listed = dispatch(&client, "tools/list", Value::Null, &policy, owner)
            .await
            .unwrap();
        let names: Vec<_> = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["sap_search_object", ENDPOINT_TOOL]);
        list_call.await.unwrap();

        let write = json!({"name":"sap_set_source", "relayPackageScopes":[]});
        assert_eq!(
            dispatch(&client, "tools/call", write, &policy, owner)
                .await
                .unwrap_err()["code"],
            -32_001
        );
        let params = json!({"name":"sap_search_object", "arguments":{"query":"Z*"}, "relayPackageScopes":[["*"]]});
        let forwarded = json!({"name":"sap_search_object", "arguments":{"query":"Z*"}, "relayPackageScopes":[]});
        let result = json!({"content": [{"type": "text", "text": "found"}], "isError": false});
        let (client, search_call) = Client::expecting("tools/call", forwarded, result.clone());
        assert_eq!(
            dispatch(&client, "tools/call", params, &policy, owner).await,
            Ok(result)
        );
        search_call.await.unwrap();
    }
}
