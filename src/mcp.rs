use serde::Serialize;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use trillium_http::{Headers, KnownHeaderName, Status};
use uuid::Uuid;

use crate::Relay;
use crate::bridge::{Client, Outcome, activity, error};
use crate::policy::{Effective, PolicyStore, TOOLS};
use crate::security::{Pki, valid_fingerprint};
use crate::transport::{Conn, PeerCertificate};
use crate::web::{Reply, is_json};

/// Request bodies larger than this are refused with 413.
const MAX_BODY: u64 = 4 * 1024 * 1024;
const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
const VERSION: &str = "2025-11-25";
const ENDPOINT_HEADER: &str = "x-sap-adt-endpoint";
const ENDPOINT_TOOL: &str = "relay_list_endpoints";
const SELECT_ENDPOINT: &str = "Run sap-adt-mcp-client endpoints --profile <dir>, then sap-adt-mcp-client --set-endpoint=<id> --profile <dir> and reconnect.";

const REQUIRE_E2E: &str = "This Eclipse endpoint requires end-to-end encryption. Pair this desktop with sap-adt-mcp-client pair --link <link from Eclipse> and reconnect.";

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
) -> Result<T, Status> {
    let policy = Arc::clone(&relay.policy);
    let pki = Arc::clone(&relay.pki);
    let cert = cert.clone();
    smol::unblock(move || {
        // Request bodies can arrive slowly after TLS and the initial route authorization.
        if !pki.authorize(&cert.der, "desktop") {
            return Ok(None);
        }
        read(&policy, &pki, &cert.fingerprint).map(Some)
    })
    .await
    .map_err(|cause| {
        tracing::error!(%cause, "Could not read endpoint access.");
        Status::ServiceUnavailable
    })?
    .ok_or(Status::Forbidden)
}

async fn catalog(relay: &Relay, cert: &PeerCertificate) -> Result<Vec<Endpoint>, Status> {
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

pub async fn endpoints(relay: &Relay, cert: &PeerCertificate) -> Reply {
    match catalog(relay, cert).await {
        Ok(list) => Reply::json(Status::Ok, &json!({"endpoints": list}))
            .with_header(KnownHeaderName::CacheControl, "no-store"),
        Err(status) => status.into(),
    }
}

pub async fn endpoint_policy(
    relay: &Relay,
    cert: &PeerCertificate,
    endpoint: &str,
) -> Result<Effective, Status> {
    let endpoint = endpoint.to_owned();
    read_access(relay, cert, move |policy, pki, owner| {
        Ok(policy
            .effective_for_endpoint(owner, &endpoint)?
            .filter(|_| pki.eclipse_enrolled(&endpoint)))
    })
    .await?
    .ok_or(Status::Forbidden)
}

fn rpc_error(status: Status, id: &Value, cause: Value) -> Reply {
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply["error"] = cause;
    Reply::json(status, &reply)
}

fn rpc_result(id: &Value, result: Value) -> Reply {
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply["result"] = result;
    Reply::json(Status::Ok, &reply)
}

fn session_id(headers: &Headers) -> Result<Uuid, Status> {
    if !headers.has_header(SESSION_HEADER) {
        return Err(Status::BadRequest);
    }
    headers
        .get_str(SESSION_HEADER)
        .and_then(|text| Uuid::parse_str(text).ok())
        .ok_or(Status::NotFound)
}

fn selector(headers: &Headers) -> Result<Option<&str>, Status> {
    let Some(values) = headers.get_values(ENDPOINT_HEADER) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(Status::BadRequest);
    }
    values
        .as_str()
        .filter(|id| valid_fingerprint(id))
        .map(Some)
        .ok_or(Status::BadRequest)
}

async fn lookup(
    relay: &Relay,
    headers: &Headers,
    cert: &PeerCertificate,
) -> Result<(Uuid, Client, Effective), Status> {
    let id = session_id(headers)?;
    let (client, version) = relay
        .registry
        .session(selector(headers)?, id, &cert.fingerprint)?;
    if headers.has_header(VERSION_HEADER) && headers.get_str(VERSION_HEADER) != Some(version) {
        return Err(Status::BadRequest);
    }
    let policy = match endpoint_policy(relay, cert, &client.endpoint).await {
        Ok(policy) if policy.e2e_required() => {
            // The endpoint became encrypted-only: this unencrypted session ends here.
            relay.registry.remove(&client.endpoint, id);
            return Err(Status::UpgradeRequired);
        }
        Ok(policy) => policy,
        Err(status) => {
            if status == Status::Forbidden {
                relay.registry.remove(&client.endpoint, id);
            }
            return Err(status);
        }
    };
    relay.registry.refresh(&client, id, &cert.fingerprint)?;
    Ok((id, client, policy))
}

pub async fn end_session(relay: &Relay, cert: &PeerCertificate, headers: &Headers) -> Reply {
    match lookup(relay, headers, cert).await {
        Ok((id, client, _)) => {
            relay.registry.remove(&client.endpoint, id);
            Status::NoContent.into()
        }
        Err(status) => status.into(),
    }
}

async fn initialize(
    relay: &Relay,
    headers: &Headers,
    params: &Value,
    id: &Value,
    cert: &PeerCertificate,
    peer: SocketAddr,
) -> Reply {
    let Some(requested) = params["protocolVersion"].as_str() else {
        return rpc_error(Status::Ok, id, error(-32602, "Missing protocol version."));
    };
    let version = match requested {
        "2024-11-05" => "2024-11-05",
        "2025-03-26" => "2025-03-26",
        "2025-06-18" => "2025-06-18",
        _ => VERSION,
    };
    let Ok(Some(endpoint)) = selector(headers) else {
        return rpc_error(
            Status::BadRequest,
            id,
            error(
                -32602,
                &format!("Select an Eclipse endpoint. {SELECT_ENDPOINT}"),
            ),
        );
    };
    match endpoint_policy(relay, cert, endpoint).await {
        Ok(policy) if policy.e2e_required() => {
            return access_error(Status::UpgradeRequired, id);
        }
        Ok(_) => {}
        Err(status) => return access_error(status, id),
    }
    let session = match relay
        .registry
        .initialize(endpoint, version, cert.fingerprint, peer)
    {
        Ok(session) => session,
        Err(Status::ServiceUnavailable) => {
            return rpc_error(
                Status::ServiceUnavailable,
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
    rpc_result(id, result).with_header(SESSION_HEADER, session.to_string())
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

fn access_message(status: Status) -> String {
    match status {
        Status::UpgradeRequired => REQUIRE_E2E.to_owned(),
        Status::Forbidden => {
            format!("This endpoint is unavailable to this desktop. {SELECT_ENDPOINT}")
        }
        Status::ServiceUnavailable => "The access policy is unavailable.".to_owned(),
        _ => "A valid MCP session for this endpoint is required.".to_owned(),
    }
}

fn access_error(status: Status, id: &Value) -> Reply {
    rpc_error(status, id, error(-32_000, &access_message(status)))
}

pub async fn request(
    relay: &Relay,
    cert: &PeerCertificate,
    conn: &mut Conn,
    peer: SocketAddr,
) -> Reply {
    // The body is read at most up to MAX_BODY bytes: trillium checks the
    // declared length up front and counts chunked bytes as they arrive.
    let Ok(body) = conn
        .request_body()
        .with_max_len(MAX_BODY)
        .read_bytes()
        .await
    else {
        return Status::PayloadTooLarge.into();
    };
    let headers = conn.request_headers();
    if !is_json(headers) {
        return Status::UnsupportedMediaType.into();
    }
    let Ok(mut message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(
            Status::BadRequest,
            &Value::Null,
            error(-32700, "Invalid JSON."),
        );
    };
    if !validate(&message) {
        return rpc_error(
            Status::BadRequest,
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
        if headers.has_header(SESSION_HEADER) {
            return rpc_error(
                Status::BadRequest,
                &message["id"],
                error(-32600, "Initialize without a session ID."),
            );
        }
        return initialize(relay, headers, &params, &message["id"], cert, peer).await;
    }
    let (client, policy) = match lookup(relay, headers, cert).await {
        Ok((session, client, policy)) => {
            let activity = activity(method, &params);
            relay
                .registry
                .note_request(&client, session, peer, &activity);
            (client, policy)
        }
        Err(status) => return access_error(status, &message["id"]),
    };
    let Some(id) = message.get("id") else {
        return Status::Accepted.into();
    };
    if method == "tools/call" && params["name"].as_str() == Some(ENDPOINT_TOOL) {
        if params
            .get("arguments")
            .is_some_and(|args| args.as_object().is_none_or(|fields| !fields.is_empty()))
        {
            return rpc_error(
                Status::Ok,
                id,
                error(-32602, "This tool takes no arguments."),
            );
        }
        return match catalog(relay, cert).await {
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
        Err(cause) => rpc_error(Status::Ok, id, cause),
    }
}

/// The tool names this relay allows the desktop, sent to Eclipse with each call.
fn allowed_tools(policy: &Effective) -> Vec<&'static str> {
    TOOLS
        .iter()
        .copied()
        .filter(|tool| policy.allows(tool))
        .collect()
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
            // The plugin is the authority: it lists only tools in this set that its own permissions allow.
            let request = json!({"relayAllowedTools": allowed_tools(policy)});
            let mut result = client.call("tools/list", request).await?;
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
            let mut call = json!({
                "name":name,
                "relayPackageScopes":policy.package_scopes(),
                "relayAllowedTools":allowed_tools(policy),
            });
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

    #[test]
    fn policy_applies_to_sap_discovery_and_direct_calls() {
        smol::block_on(policy_applies_to_sap_discovery_and_direct_calls_async());
    }

    async fn policy_applies_to_sap_discovery_and_direct_calls_async() {
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
        let allowed = allowed_tools(&policy);
        assert!(allowed.contains(&"sap_search_object") && !allowed.contains(&"sap_set_source"));
        let list_request = json!({"relayAllowedTools": allowed});
        let (client, list_call) = Client::expecting("tools/list", list_request, tools);
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
        list_call.await;

        let write = json!({"name":"sap_set_source", "relayPackageScopes":[]});
        assert_eq!(
            dispatch(&client, "tools/call", write, &policy, owner)
                .await
                .unwrap_err()["code"],
            -32_001
        );
        let params = json!({"name":"sap_search_object", "arguments":{"query":"Z*"}, "relayPackageScopes":[["*"]]});
        let forwarded = json!({"name":"sap_search_object", "arguments":{"query":"Z*"}, "relayPackageScopes":[], "relayAllowedTools":allowed_tools(&policy)});
        let result = json!({"content": [{"type": "text", "text": "found"}], "isError": false});
        let (client, search_call) = Client::expecting("tools/call", forwarded, result.clone());
        assert_eq!(
            dispatch(&client, "tools/call", params, &policy, owner).await,
            Ok(result)
        );
        search_call.await;
    }

    #[test]
    fn required_e2e_refuses_unencrypted_sessions_with_the_pairing_hint() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1; 32];
        let store = crate::policy::PolicyStore::load(dir.path()).unwrap();
        let endpoint = hex::encode([2; 32]);
        store
            .set_endpoint_grants(
                &store.snapshot().unwrap().revision,
                &hex::encode(owner),
                vec![endpoint.clone()],
            )
            .unwrap();
        let allowed = |store: &PolicyStore| {
            !store
                .effective_for_endpoint(&owner, &endpoint)
                .unwrap()
                .unwrap()
                .e2e_required()
        };
        assert!(allowed(&store));
        assert!(store.toggle_endpoint_e2e(&endpoint).unwrap());
        assert!(!allowed(&store));
        let message = access_message(Status::UpgradeRequired);
        assert!(message.contains("requires end-to-end encryption"));
        assert!(message.contains("sap-adt-mcp-client pair --link"));
        assert_ne!(message, access_message(Status::NotFound));
    }
}
