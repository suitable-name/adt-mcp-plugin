# Developer Guide

The relay routes each desktop MCP session to its selected, authorized Eclipse workspace. Rust owns transport authentication, endpoint grants, session routing, and desktop policy. The plugin owns tool schemas, tool execution, and verification of a target object's SAP package. SAP ADT owns the selected project's connection settings and authentication.

```mermaid
sequenceDiagram
    participant H as MCP host
    participant C as Rust desktop client
    participant R as Rust relay
    participant E as Eclipse plugin
    participant S as SAP
    E->>R: Open outbound mTLS WebSocket
    R->>E: relay/hello
    E-->>R: policyVersion 2
    H->>C: initialize on stdio
    C->>R: POST /mcp over mTLS
    R-->>C: Server info and session ID
    C-->>H: MCP initialize result
    H->>C: tools/call
    C->>R: Request with session ID
    R->>E: Authorized tool call with package scopes
    E->>S: Verify target and execute via ADT
    S-->>E: SAP result
    E-->>R: JSON-RPC result for bridge ID
    R-->>C: JSON-RPC result for host ID
    C-->>H: One response line
```

## Source Map

| Entry point | Responsibility |
| --- | --- |
| [Server main](../src/main.rs) and [TLS transport](../src/transport.rs) | CLI modes, listener setup, peer certificate extraction, request authentication and limits |
| [MCP endpoint](../src/mcp.rs) and [bridge](../src/bridge.rs) | MCP lifecycle, tool authorization, socket ownership, deadlines, and request correlation |
| [Policy store](../src/policy.rs) | Known-action catalog, rule validation, global and desktop intersection, durable edits |
| [PKI](../src/security.rs) and [enrollment](../src/enrollment.rs) | Issuance, role pins, revocation, `issue.secret`, the one-time link store, and claims. [Link format](../src/link.rs) |
| [TUI](../src/tui.rs), [rule editor](../src/tui/rules.rs), and [logs](../src/logs.rs) | Local operator actions, terminal lifecycle, bounded diagnostic history |
| [Desktop client](../src/bin/sap-adt-mcp-client.rs) and [client modules](../src/bin/client) | Profile enrollment from a link, CA-pinning verifier, pinned TLS, stdio framing and session headers |
| [Java server package](../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/src/com/sap/adt/mcp/server) | Relay identity, encrypted workspace profile, outbound WebSocket, JSON-RPC validation, and scoped execution |
| [Java SAP tools](../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/src/com/sap/adt/mcp/tools) and [SAP transport](../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/src/com/sap/adt/mcp/sap) | ADT requests, tool schemas, object addressing, package metadata parsing, and SAP session state |
| [Java UI](../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/src/com/sap/adt/mcp/ui) and [Tycho build](../java-plugin/sap-adt-mcp-server/pom.xml) | Registration and connection UI, plugin lifecycle, feature and p2 site assembly |

## Enrollment and Trust

1. `init` generates a dedicated CA and server identity in a new private directory. Both TLS listeners use the server leaf and CA chain. The enrollment listener permits initial connections without a client certificate. The data listener requires TLS 1.3 client authentication.
2. The operator mints a one-time link: **N** in the TUI Enrollment tab, or `issue-link`, which sends `POST /issue` `{"role":"desktop","label":"Anna desktop"}` to the enrollment listener. `/issue` is accepted only from a loopback peer, without an `Origin` header, with `Authorization: Bearer <secret>` where the secret is the 64 hex characters of `<pki>/issue.secret` (created at every `serve` start, owner-only, compared in constant time). The relay generates a CSPRNG secret, stores only its SHA-256 with the role, label and expiry (10 minutes, single use, at most 16 outstanding), and returns the link as plain text. Minting is the approval; nothing is confirmed on claim.
3. The link is `sap-adt://enroll?v=1&r=<role>&n=<name>&s=<data host:port>&e=<enrollment host:port>[&l=<label>]&t=<GW1 token>`, built and parsed by [`src/link.rs`](../src/link.rs) (shared by relay and client; the pairing link `sap-adt://pair?...` of the pairing phase lives there too). The shared vectors in `java-plugin/sap-adt-mcp-server/tests/link-vectors.json` fix the grammar and error codes for Rust and Java; the relay's tests regenerate their tokens so the file cannot drift. The token is the GW1 encoding: 32 secret bytes followed by SHA-256 of the CA DER, 103 Crockford Base32 symbols in groups of five after the `GW1-` prefix.
4. The client parses the link and opens a TLS connection to `e` whose verifier takes the CA the relay presents (the last certificate of the chain) and refuses the handshake unless SHA-256 of that CA equals the fingerprint in the token, so the secret is never sent to another relay. Only then it sends `POST /claim` with `{"token":"<GW1 token>"}`. The server checks the CA pin first (no entry is consumed on a mismatch), then compares the hash in constant time, consumes the link once, and returns `ca_pem`, `client_cert_pem`, and `client_key_pem` for the stored role and label. Every wrong, used, expired or cancelled link gets the same bare 403. The desktop saves `server = https://<s>`.
5. The signed client common name carries the role prefix. The server records SHA-256 of the issued leaf DER under that role. The PKI checks both signed role and current fingerprint membership. The desktop saves its profile under OS account permissions. Eclipse saves an AES-GCM-encrypted workspace profile with a wrapping key in Eclipse secure preferences.

The link store is memory-only and bounded to 16 outstanding links. Restarting drops it. The enrollment listener always runs, headless too, and accepts only `/claim` for stored links and loopback `/issue`; anything else is 404, 403 or 405. Each link has a number so that the TUI can cancel exactly the selected one. The link text is never stored or logged: it exists in the TUI dialog (zeroized when it closes) and in the output of `issue-link`. The test-only environment variable `SAP_ADT_RELAY_TEST_LINK_TTL_MS` can only shorten the lifetime, never extend it.

The relay's addresses in links come from `serve --name`, `--public-data` and `--public-enrollment`; the defaults are the DNS name read from the server certificate and the bound ports.

## Data Protocol

| Endpoint | Contract |
| --- | --- |
| `GET /endpoints` | Requires an enrolled desktop certificate. Returns `{"endpoints":[{"id":"…","label":"…","online":true}]}` with enrolled Eclipse identities granted to this desktop. Works before selection and includes offline workspaces |
| `POST /mcp` | One JSON-RPC object in an `application/json` body. Supports `initialize`, `ping`, `tools/list`, and `tools/call`. Valid notifications return HTTP 202 without a tool response |
| `DELETE /mcp` | Releases the session identified by the session header after checking the desktop certificate and protocol version |
| `GET /bridge` | WebSocket upgrade with an authorized Eclipse certificate. One UTF-8 JSON-RPC object per text message. With an `e2e` plugin, also tunnel control and data frames (see [Tunnel and Streams](#tunnel-and-streams)) |
| `GET /tunnel` | WebSocket upgrade with an authorized desktop certificate (same certificate and `Origin` checks as `/mcp`). One tunnel per desktop client process carries many end-to-end streams |

The desktop helper sends the selected Eclipse certificate's lowercase SHA-256 fingerprint in the `X-Sap-Adt-Endpoint` header. Initialization checks the grant and live bridge, then binds the session to that desktop identity and connection. The helper retains the negotiated `MCP-Protocol-Version` and `Mcp-Session-Id`. Every subsequent request checks session ownership and endpoint access. The relay answers `relay_list_endpoints` locally, returning the selected ID and the caller's authorized catalog. The host sees newline-delimited JSON-RPC on stdio. Diagnostics go to stderr. A browser-provided `Origin` is refused.

Rust sends `relay/hello` with `{"policyVersion": 2}` on a new bridge and requires an object containing numeric `policyVersion` 1 or 2 before allowing a session to initialize. With version 2, every `tools/list` and `tools/call` carries `relayAllowedTools`, and the plugin refuses a tool outside that list and its own local permissions; a version-2 plugin accepts a missing list only from a relay that never announced version 2. Rust then sends `ping`, `tools/list`, and `tools/call` using its own positive integer IDs. Eclipse replies with the same bridge ID and exactly one result or error. The relay preserves the desktop's original MCP request ID independently. A malformed reply, mismatched ID, unexpected message, or timeout closes that bridge.

Rust constructs the call sent to Eclipse from the authorized tool name, original tool arguments, and effective package constraints. The following is an internal bridge message.

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "sap_search_object",
    "arguments": {"query": "ZFIN*", "max": 10},
    "relayPackageScopes": [["ZFIN*", "/ACME/*"], ["/ACME/FIN*"]]
  }
}
```

An outer empty array represents unrestricted packages. Each inner list is a disjunction. A verified target must satisfy every inner list. An empty inner list permits no target. Client-supplied policy fields have no authority. Eclipse validates the envelope, tool arguments, and scope patterns before dispatch.

## Tunnel and Streams

The relay side of the end-to-end tunnel (`docs/plan-e2e-envelope.md`). The wire format is in [`src/tunnel_proto.rs`](../src/tunnel_proto.rs), shared with the client; the Java plugin implements the same format. The relay never reads stream payload bytes. It forwards control frames and data frames, enforces its rules on clear-text envelopes, and measures traffic.

| Module | Responsibility |
| --- | --- |
| [`src/tunnel.rs`](../src/tunnel.rs) | `GET /tunnel` upgrade, one session per desktop tunnel (frame loop, 1 s timer, policy re-check every 5 s, ping every 30 s), tunnel limits (4 per desktop, 256 in total) |
| [`src/tunnel/hub.rs`](../src/tunnel/hub.rs) | The streams of one bridge: bridge-side ID allocation and translation, limits, policy fingerprint, statistics (`StreamRow`, `Registry::stream_snapshot`) |
| [`src/tunnel/admission.rs`](../src/tunnel/admission.rs) | Pre-admission state machine of one stream |
| [`src/bridge.rs`](../src/bridge.rs) | Bridge connection: writer, reader and legacy driver, see below |

**Bridge capability.** The plugin's `relay/hello` reply may contain `"e2e": 1`. Only then does the hub accept streams. Legacy JSON-RPC calls (`/mcp`) keep working on the same bridge in this version.

**Bridge connection.** One task races three futures. The *writer* drains one bounded queue of WebSocket messages (legacy requests, stream control frames and data frames, in queue order). The *reader* routes what the plugin sends: control frames (a text frame that decodes as a `Control`, which has a top-level `type`) and data frames go to the hub, any other text frame is a legacy reply. The *driver* runs `relay/hello`, the legacy calls and the heartbeat exactly as before: one call at a time (the `Semaphore` of `Client`), the same deadlines and errors, and any malformed, mismatched or unsolicited legacy reply closes the bridge. A legacy reply is accepted only while an exchange waits for it. The reader never waits on the bridge queue (it uses `try_send`, or a detached task for a `Close`), so a slow bridge cannot deadlock it.

**Stream lifecycle.** `Open {stream, endpoint}` from the desktop is checked like `/mcp` initialization (`mcp::endpoint_policy`: grant and enrolled Eclipse), then against the bridge (ready, `e2e`) and the limits: 128 streams per bridge, 16 per desktop and endpoint. The relay allocates a bridge-side ID and sends `Open {stream, endpoint, desktop, label}` to the plugin, or answers the desktop with `Close` and a plain reason. The first `Admit` counts as the end of the inner handshake; a stream without one within 30 s is closed. Data frames are forwarded in order with translated IDs. `Close` from either side ends both legs; losing the tunnel or the bridge ends all its streams with a reason. Streams without traffic for eight hours are closed.

**Admission.** Each `Admit` carries the envelope of the request that will follow. The relay refuses it (`Denied`, code `-32001`, nothing changes) when `seq` is not exactly one more than the last admitted one (the first is 1), or for `tools/call` when the tool is unknown, its class differs from the shared tool table, or the effective policy does not allow it. Other methods are always admitted. An admitted envelope waits 30 s (up to eight at once). The `Request` must carry exactly the admitted envelope, oldest first; the relay adds the policy (`allowedTools`, `packageScopes`) and forwards it. A request without admission, with a different envelope, or after the deadline closes the stream, and so does an admission whose request never comes. The relay does not evaluate policy again at `Request`, because dropping bytes would break the inner TLS.

**Policy changes.** Each stream remembers the `RelayPolicy` (allowed tools and package scopes) it opened with. The relay reads the effective policy again on every `Admit` and every five seconds for each tunnel, and closes a stream with "The access rules changed." when the value differs or the grant is gone. It never drops single requests.

**Statistics.** The hub records, per stream, the request count, last method, tool and status, bytes in each direction, whether the first `Admit` arrived (the inner handshake is done), and the admit-to-response time that the relay measured. `Registry::stream_snapshot` returns `StreamRow` values for the Connections tab. Logs carry endpoint, desktop fingerprint prefix, tool, class and decision, never payload bytes.

## Client: Keys, Pairing and the Encrypted Path

The desktop client side of the tunnel lives in [`src/bin/client`](../src/bin/client) and shares [`src/tunnel_proto.rs`](../src/tunnel_proto.rs) with the relay.

| Module | Responsibility |
| --- | --- |
| `keys.rs` | `inner_key.pem` and `inner_cert.pem` (ECDSA P-256, self-signed, owner-only); the pin is SHA-256 of the SPKI DER; short form is 16 hex characters in groups of four |
| `peers.rs` | `peers.json` (endpoint ID to key, label, `pairedAt`), atomic replace, the `Route` decision (a pin means tunnel, never `/mcp`), `unpair` |
| `tunnel.rs` | One `wss://…/tunnel` socket per process (mTLS from the profile); reader and writer tasks; client-chosen stream IDs; `Stream` events |
| `inner_tls.rs` | rustls sans-IO client: TLS 1.3, `TLS_AES_256_GCM_SHA384`, x25519 and secp256r1, client certificate = inner key, no resumption, SPKI-pinned server verifier |
| `channel.rs` | Handshake, then per message `Admit`, `Admitted`, `Request` plus data, `Response` plus data; `tools.json` copy for the envelope class |
| `host.rs` | stdio host for a paired endpoint; local `relay_list_endpoints`; no `/mcp` fallback |
| `pair.rs` | `pair --link`: pinned handshake, `pair/claim` inside the session, then `peers.json` and the endpoint selection |

A denial happens before encryption, so it advances neither `seq` nor the TLS stream: the next message reuses the same `seq`. Any other failure marks the channel broken, and the host must initialize a new session (a new stream). A damaged `peers.json` is an error, never "unpaired".

## Authorization

The PKI directory contains `policy.json` and a persistent `policy.lock`. The `endpoint_grants` map associates a desktop certificate fingerprint with its permitted Eclipse fingerprints. An absent map, absent entry, or empty grant list permits no workspace access. Re-enrollment creates a new identity. A label is display data. Independently, global and desktop rules each contain `read_only`, `actions`, and `packages`. A JSON `null` action or package list is unrestricted, while an empty array permits none. A missing desktop rule override means read-only with unrestricted lists. Global rules default to all recognized SAP actions.

Discovery filters Eclipse's schemas using effective access. Direct invocation independently loads effective rules before dispatch. A malformed, missing, oversized, or ambiguous policy fails closed. Saving stages a private file, checks the revision under an exclusive lock, and atomically replaces the document. Operator edits use a revision derived from the bytes the editor opened. Keep the lock file with policy backups so deletion of an initialized document is detected.

| Classification | Tools |
| --- | --- |
| Read-only, support package constraints | `sap_search_object`, `sap_get_source`, `sap_object_structure` |
| Read-only, require unrestricted packages | `sap_inactive_objects`, `sap_usage_references`, `sap_abap_docu` |
| Require write-enabled rules, support package constraints | `sap_create_object`, `sap_lock`, `sap_unlock`, `sap_set_source`, `sap_activate` |
| Require write-enabled rules and unrestricted packages | `sap_sql_query`, `sap_syntax_check`, `sap_run_unit_test`, `sap_atc_run` |

A source write also requires permission for lock, unlock, and activate in both rule layers. Classify new tool names explicitly. The relay rejects unknown tools even under unrestricted action lists.

The table above is derived from one file, [`resources/tools.json`](../java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.plugin/resources/tools.json), the single source for tool names, action class, package awareness, and component actions. Each entry has `name`, `class` (`read`, `execute`, or `write`), `packageAware`, and `components` (extra tools that must also be permitted; `sap_set_source` lists `sap_lock`, `sap_unlock`, and `sap_activate`). The relay embeds the file with `include_str!` in `src/policy.rs` (`tool_class`, observational and package checks, component rule). The plugin bundles it as a resource and `ToolCatalog` loads it. Every `McpTool` declares `toolClass()`, and `ToolCatalog.verify` fails at startup when a registered tool is missing from the file or declares another class. To add or reclassify a tool, edit the file, the `TOOLS` constant, and the Java tool together; the `policy` unit tests and `ToolCatalogRegression` fail when they diverge.

Package patterns are canonicalized to uppercase. Exact names and a single trailing wildcard are supported, including `$TMP`, `ZFI*`, and `/ACME/*`. Each layer supports up to 64 patterns and the literal portion of a pattern is at most 30 characters. In the operator package editor, entering a lone `*` saves unrestricted access. In the wire format, a pattern `"*"` inside a layer still requires a verified package.

In the plugin, scoped search filters hits by verified ownership. For existing objects, scoped calls resolve supported object type and name and verify the corresponding SAP metadata. Missing metadata or conflicting identity fails closed. Structure reads use the verified metadata response. Source reads recheck ownership after retrieval, and source writes verify again while acquiring the lock. Scoped unlock requires the handle recorded for that target in the active SAP session. Creation checks the destination package written into the create request. A scoped policy constrains operation targets. It does not inspect the semantics of ABAP source code.

## Concurrency and Failure Handling

* Each Eclipse certificate can reserve one active bridge. The relay accepts up to 128 pending or active bridges from distinct Eclipse certificates. Sessions and the request channel belong to the exact bridge connection. Disconnecting it invalidates its own sessions. A replacement connection requires fresh initialization.
* Each session also belongs to the desktop certificate that initialized it. Reusing another desktop's session ID fails. Each endpoint allows 128 sessions and expires idle sessions after eight hours. Desktop revocation takes effect at the HTTP boundary. The relay rechecks the Eclipse pin before dispatch and on idle heartbeats.
* Each Eclipse SAP client is stateful, including locks. Each bridge admits one call at a time. Overlapping calls on that bridge receive a busy error. Calls on different bridges are independent. Idle heartbeat interval and deadline are 20 seconds. Bridge calls have a ten-minute deadline. A disconnected or timed-out mutation has an uncertain SAP outcome. Preserve that error to the host and avoid automatic replay.
* The data listener accepts at most 128 concurrent TLS/HTTP connection slots and enrollment uses a separate budget of 32. Both constrain TLS handshake and header read time. The desktop request and Java incoming request limits are 4 MiB. The bridge accepts a response up to 8 MiB. The stdio client bounds concurrency and response size.
* Logging can include the authorized tool name, desktop fingerprint, and connection or policy events. Exclude request bodies, SAP results, enrollment links, token strings, and private keys. Interactive logs are bounded in memory. Headless logging uses stderr. TUI link copy uses an explicit OSC 52 clipboard request.

## ADT Project Connection

The Eclipse view's **Select ABAP Project** action uses public Eclipse APIs to list existing ADT workspace projects and requests ADT's normal login flow when necessary. ADT's own project-picker implementation is restricted to its declared friend bundles; this plugin uses a standard Eclipse selection dialog. Tool transport is bound to the explicitly chosen project. Selecting another editor tab or Project Explorer item must never alter that binding. A connected relay must be disconnected before the operator can select a different project. A new bridge connection requires fresh MCP initialization.

`AdtRestClient` is the transport-neutral tool boundary. Its ADT implementation uses the selected project's connection and a dedicated ADT session for the relay's stateful operations. The plugin does not collect SAP URL, username, password, client, or language settings. Shared ADT connection management supplies those details and authentication. Calls fail if the selected project becomes unavailable, loses its authenticated state, or changes its destination identity. Invalidation retires the adapter and clears the selected project, requiring explicit selection again. Background tool requests never select another project or open an interactive login dialog.

Retiring the adapter on relay disconnect, view disposal, or replacement clears its explicit lock bookkeeping and releases its dedicated session. It must preserve the shared ADT project's authentication and unrelated editor sessions. **Connect Relay** binds a fresh adapter to a still-valid selected project. After identity invalidation, **Select ABAP Project** establishes a new selection and uses native login if needed. An interrupted write still requires checking SAP for its actual outcome; clearing local lock bookkeeping does not establish that a mutation was rolled back.

## Extending a Tool

1. Add or update the Java tool implementation and its `McpTool` schema. Verify existing and new argument combinations, SAP URL construction, SAP session requirements, and failure results. Register it in the Eclipse tool list used by the relay.
2. Classify the action in the Rust catalog. Determine whether it writes data, takes a lock, starts a run, or invokes other actions internally. Account for every component permission. An advertised schema alone cannot grant access.
3. For package-scoped access, define how Eclipse can prove the exact target using trusted SAP metadata or the validated creation destination. Include existing-object identity, URL aliases, user-supplied handles, competing updates, and unverified search rows. Leave the action unavailable under package restrictions until enforcement exists on both sides.
4. Add regression coverage for discovery and direct admission, narrowed policies, denied targets, and lifecycle failures relevant to the change. If the bridge's security contract changes incompatibly, version the capability handshake and test rejection of older plugins.
5. Update the operator documentation, tool table, and acceptance procedure when behavior or defaults change.

## Contributor Verification

Follow the [implementation guide](../IMPLEMENTATION.md). Run the commands below from the repository root in PowerShell 7.

```powershell
cargo +1.95.0 check --workspace --all-targets
cargo +1.95.0 test --locked --workspace --all-targets && cargo +1.95.0 clippy --locked --workspace --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery
cargo +1.95.0 build --locked --workspace --bins
```

Build the Eclipse modules with Maven 3.10.0, JDK 21, and the parent POM's Tycho 5.0.4. The plugin targets Java 17. The build resolves ADT APIs from SAP's public 2024-03 p2 repository alongside the Eclipse target. SAP ADT must also be installed in the runtime Eclipse environment. Keep the bundled Gson JAR at the plugin root. The [Eclipse build and harness commands](verification.md#eclipse-plugin-build) cover both Java checks. Use the [update site guide](eclipse-update-site.md) to install the result or host it on GitHub Pages.

The reactor's checked-in [`.mvn/maven.config`](../java-plugin/sap-adt-mcp-server/.mvn/maven.config) temporarily sets `-Dmaven.resolver.validation=MILD`. Tycho 5.0.4 assigns SAP's nested JAR paths as Maven classifiers, triggering Maven 3.10.0 coordinate validation. [Tycho issue 6399](https://github.com/eclipse-tycho/tycho/issues/6399) documents this failure and workaround. The [fix in pull request 6400](https://github.com/eclipse-tycho/tycho/pull/6400) is merged but absent from the pinned release; upgrade to a released version containing it and remove this setting together.

`MILD` relaxes coordinate validation to checking uninterpolated placeholders, so this build does not receive Maven's full coordinate safety checks. The setting applies to this reactor's Maven invocation and does not alter runtime TLS, certificate verification, or relay policy. Keep it out of user-wide Maven settings. Include the hidden `.mvn/maven.config` file in CI checkouts and source archives, and use the documented reactor command. [Maven 3.10.0 release notes](https://maven.apache.org/docs/3.10.0/release-notes.html)

The first check resolves a lockfile when needed. Keep the tested resolution for the subsequent locked commands. Use one workspace-wide run per additional supported feature set. The Rust integration tests can exercise the binaries with a simulated Eclipse peer. Live Eclipse, SAP authorization, package metadata, and visual inspection need the environment and screenshots described in the [verification checklist](verification.md). Inspect logs for a running server and obtain the owner's confirmation of a quiet machine before benchmark or timing work.

After verification and visual checks, the owner formats the workspace.

```powershell
cargo +nightly fmt --all
```
