# SAP ADT MCP Relay

A desktop MCP host launches `sap-adt-mcp-client` over stdio. The client connects to the Rust relay using its enrolled certificate. Eclipse opens an outbound WebSocket to the same relay using a separately enrolled Eclipse certificate. SAP access uses the selected Eclipse ADT project's connection and authentication. The relay sees the tool arguments and results.

One relay can serve multiple Eclipse workspaces. Each user enrolls a desktop profile, and the operator assigns that profile the Eclipse endpoints it may use. New desktops have no endpoint grants and default to read-only tool access. Each call runs under the SAP account connected in the selected workspace, subject to the relay's action and package rules.

| If You Are… | Start Here |
| --- | --- |
| Installing or operating the relay | [Operator manual](docs/operator-manual.md) |
| Installing the Eclipse feature or hosting its update site | [Eclipse update site guide](docs/eclipse-update-site.md) |
| Modifying the Rust server, desktop client, or Eclipse plugin | [Developer guide](docs/developer-guide.md) and [implementation rules](IMPLEMENTATION.md) |
| Accepting a build or diagnosing a failed connection | [Verification and troubleshooting](docs/verification.md) |

```text
Desktop MCP host ──stdio──► portable Rust client ──HTTPS + mTLS──► relay
                                                                  ▲
SAP system ◄──HTTPS── Eclipse workspace ─────outbound WSS + mTLS───┘
```

## Build

The Rust package declares Rust 1.95 as its minimum version, edition 2024, and workspace resolver 3. Run the following commands from the repository root in PowerShell 7 with Rust 1.95.0. The first Cargo command generates `Cargo.lock` if this checkout has no lockfile. Keep the resolved lockfile with the tested build.

```powershell
cargo +1.95.0 check --workspace --all-targets
cargo +1.95.0 test --locked --workspace --all-targets && cargo +1.95.0 clippy --locked --workspace --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery
cargo +1.95.0 build --locked --workspace --bins
```

The Rust executables are in `target/debug`. Build for each intended platform.

Build the Eclipse update site with Maven 3.10.0 and JDK 21. Tycho 5.0.4 compiles the plugin for Java 17 and resolves SAP ADT dependencies from SAP's public 2024-03 p2 repository. Install locally from the generated ZIP or repository directory into Eclipse with SAP ADT installed. [Local build and harness instructions](docs/verification.md#eclipse-plugin-build)

To publish the plugin on GitHub Pages, enable Pages with **GitHub Actions** as the source and trigger the Eclipse update site workflow from the **Actions** tab. It builds the plugin and runs the Java package-policy harness before deployment. [Publishing and installation instructions](docs/eclipse-update-site.md#publish-with-the-manual-workflow)

## Start the Server

Run these commands on the company server. Choose a fresh PKI directory under a trusted parent owned by the service account. Replace the example DNS name with the actual hostname clients use.

```powershell
.\target\debug\sap-adt-mcp-server-relay.exe init --pki C:\Relay\pki --dns adt-relay.company.example
.\target\debug\sap-adt-mcp-server-relay.exe serve --pki C:\Relay\pki --listen 0.0.0.0:8787 --enrollment-listen 0.0.0.0:8788
```

This opens the operator TUI with registration closed. Add `--issue-token` to start with registration open. The operator can toggle registration in the TUI in either case. Each requester still needs individual approval.

For unattended operation, use `serve --pki C:\Relay\pki --headless`. The server uses saved identities and policies, writes logs to stderr, and leaves the enrollment socket unbound.

For enrollment from a line-oriented operator console, run this command in an attached terminal.

```powershell
.\sap-adt-mcp-server-relay.exe serve --pki C:\Relay\pki --headless --issue-token
```

Registration starts open. Compare the full request ID, role, and label with the requester. Enter `approve <number>` or `deny <number>` using the number on the matching console row. That command applies immediately. Approval displays the single-use token directly on the attached terminal. Stdout and stderr can both be redirected. Logs still use stderr. Startup fails if the process cannot open the operator terminal. [Operator manual](docs/operator-manual.md)

Keep the PKI directory across restarts. Restrict it and its backups to the service account. It holds the CA signing key, server key, enrolled certificate fingerprints, and access policies. The server generates client credentials only when an approved token is claimed.

| Port | Purpose | Authentication |
| --- | --- | --- |
| 8787 | Desktop MCP requests on `/mcp` and Eclipse WebSocket upgrades on `/bridge` | TLS 1.3 with a client certificate and the matching role fingerprint |
| 8788 | Enrollment requests and single-use claims | TLS 1.3, local operator approval, then a CA-pinned claim |

Allow the workstations to reach both ports. For a corporate gateway, use TCP/TLS passthrough to the same relay instance. The relay must see the actual client certificate. The earlier setup that terminated TLS at an HTTP reverse proxy and forwarded bearer headers is incompatible. Choose a gateway timeout longer than ten minutes for long-running SAP calls and keep the Eclipse connection open for WebSocket traffic.

## Enroll a Workstation

Repeat this process once for each Eclipse workspace and desktop client profile. A fresh client needs the company server address. It receives its CA and private identity during enrollment.

1. In the server's **Enrollment** tab, open registration. While open, the server accepts requests from any reachable network address.
2. On the **requesting workstation**, enter a descriptive label and start enrollment. The client generates a random request ID and displays it locally. Only the public request ID, role, and label are sent at this stage. Use a label suitable for disclosure during initial contact.
3. On the **server**, compare the request’s full ID, role, and label with the requester through a trusted channel. Approve or deny the request in the TUI or the headless approval console. On approval, give the displayed one-time `GW1-` token to the verified requester over the trusted channel.
4. On the **workstation**, enter the token when prompted. The client checks the public CA against the fingerprint inside the token, then opens a fresh TLS connection that verifies the server hostname and that CA before sending the claim. The server consumes the token, issues a role-specific identity, and records its leaf fingerprint. The client saves its private profile. A pending request and an approved token each have their own three-minute lifetime.
5. Close registration in **Enrollment** after both identities have been claimed. Closing discards outstanding requests and grants. Existing enrolled clients can connect while registration is closed.

The token follows the `diagram_loader` GW1 format, which combines a random 256-bit secret with the SHA-256 fingerprint of the CA. The initial TLS handshake presents public certificates. Client identity is established only after approval and the pinned claim. No client certificate, shared password, or CA file needs to be provisioned on a new workstation in advance.

### Eclipse

Open **Window → Show View → Other → SAP ADT MCP → SAP ADT Relay**. Register the workspace using `https://adt-relay.company.example:8788` for enrollment and `wss://adt-relay.company.example:8787/bridge` for the bridge. Complete the approval flow above. Click **Select ABAP Project** and choose the intended existing ADT workspace project in the Eclipse selector. The plugin uses that project's existing connection; ADT opens its normal login dialog if authentication is needed. Click **Connect Relay**. SAP connection settings and authentication are managed by ADT. The relay profile supplies trust for the relay connection.

The bridge stays bound to the explicitly selected project when you switch editor tabs or Project Explorer selections. Disconnect the relay before selecting another project, then reconnect the desktop MCP host. Disconnecting the relay or closing its view releases the plugin's session while preserving the shared ADT login. A normal reconnect uses the selected project. If the project closes, loses authentication, or changes its destination identity, the plugin clears the selection; explicitly select the intended project again and reconnect.

### Desktop Client

Place the portable client binary where the MCP host can execute it. It uses stdin and stdout and opens an outbound TLS connection. Run enrollment interactively once using the same OS account that will run the desktop host. Choose a **new** profile directory inside an existing private parent.

```powershell
& 'C:\Tools\sap-adt-mcp-client.exe' enroll --server https://adt-relay.company.example:8787 --enrollment https://adt-relay.company.example:8788 --label 'Anna desktop' --profile "$env:LOCALAPPDATA\sap-adt-profile"
```

In the server's **Access Rules** tab, highlight the enrolled desktop, press **E**, mark the allowed Eclipse workspaces with **Space**, then press **S** to save. On the workstation, list the available endpoints and save the ID of the intended workspace.

```powershell
$client = 'C:\Tools\sap-adt-mcp-client.exe'
$profile = "$env:LOCALAPPDATA\sap-adt-profile"
& $client endpoints --profile $profile
$endpoint = Read-Host 'Paste the endpoint ID'
& $client "--set-endpoint=$endpoint" --profile $profile
```

An exact, unique endpoint label such as `--set-endpoint=DEV` also works. The MCP host starts `connect --profile <absolute-directory>`. It reports setup instructions during initialization if the enrollment or selection is missing. After changing the selection, reconnect the MCP host. Ask the model “Which SAP endpoint am I using, and which others can I access?” It can call `relay_list_endpoints` to report the current ID and the workspaces granted to this profile.

**Upgrading an existing relay:** enrollment certificates remain usable. Assign endpoint grants and set a selection on every desktop profile before reconnecting. Each separately enrolled device needs its own grants.

## Configure the Desktop Host

For Claude Desktop, merge this entry into `claude_desktop_config.json`. Antigravity accepts the same entry in `mcp_config.json`. Replace both paths with the absolute paths on the workstation. Restart or reload the host after saving. [Claude Desktop stdio configuration](https://py.sdk.modelcontextprotocol.io/get-started/real-host/) · [Antigravity MCP configuration](https://antigravity.google/docs/mcp)

```json
{
  "mcpServers": {
    "sap-adt": {
      "command": "C:/Tools/sap-adt-mcp-client.exe",
      "args": ["connect", "--profile", "C:/Users/Anna/AppData/Local/sap-adt-profile"]
    }
  }
}
```

For Codex or Claude Code, run the matching command in PowerShell. The host config contains the executable and profile paths. [OpenAI Docs for MCP](https://developers.openai.com/codex/mcp/) · [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)

```powershell
codex mcp add sap-adt -- 'C:\Tools\sap-adt-mcp-client.exe' connect --profile "$env:LOCALAPPDATA\sap-adt-profile"
claude mcp add --transport stdio sap-adt -- 'C:\Tools\sap-adt-mcp-client.exe' connect --profile "$env:LOCALAPPDATA\sap-adt-profile"
```

## Control Access

In **Access Rules**, select **Global Rules** or select a desktop by label and certificate fingerprint. A person's separately enrolled devices have separate policies. Save changes to apply them to the next discovery or tool request, including on existing sessions. Some desktop hosts cache tool lists and need to reconnect to refresh what they display. The server checks direct calls independently. An operation already admitted can finish.

| Control | Effect |
| --- | --- |
| Read-only | Allows search, get source, object structure, inactive objects, where-used references, and ABAP documentation, subject to other filters. Writing, locking, activation, SQL, checks, and execution require write-enabled access. |
| Actions | Both the global and desktop allowlists must permit an action. Writing source also needs lock, unlock, and activate because the Eclipse tool performs all three. Unknown tools are denied. |
| SAP packages | Use an exact package such as `$TMP`, or a trailing wildcard such as `ZFIN*` or `/ACME/*`. Names are case-insensitive. These patterns match technical package names; an unrelated name under the same SAP package hierarchy needs an explicit rule. |

Within a package list, any matching pattern is enough. When the global and desktop policies both specify packages, the target must match both lists. A restricted list with zero entries grants nothing. Scoped tools cover search, source, object structure, creation, locks, unlocks, and activation. Eclipse checks scope against SAP package metadata for existing targets and the target package on creation. Search omits unverified rows. SQL, test runs, and other operations without an enforceable package boundary are unavailable under a package restriction. The policy controls the SAP object an action targets. Source code in an allowed object can reference other packages.

## Operations and Verification

Use **Clients** to inspect or revoke an enrolled fingerprint. After credential loss or expiry, revoke the old fingerprint and enroll a fresh profile. Use **Logs** for recent relay events. In headless mode, direct stderr to the service's log collector. Set `RUST_LOG` to a level such as `info` or `debug` when starting the server. Enrollment tokens, tool arguments, and source code are excluded from relay logs.

Client certificates are issued for one year and the server leaf for 825 days. Before the server leaf expires, run the following command with the service account and restart the relay. This uses the existing CA and preserves enrolled profiles. Replacing the CA requires a new PKI and fresh enrollment for every identity.

```powershell
.\target\debug\sap-adt-mcp-server-relay.exe renew-server --pki C:\Relay\pki --dns adt-relay.company.example
```

Connect the selected Eclipse workspace before initializing the desktop MCP session. Each session belongs to its desktop certificate and that specific Eclipse connection. A bridge drop invalidates its sessions. Other workspaces keep serving their own sessions. If a call lost its reply, check the object, lock, and activation state in SAP before retrying.

For the owner-run acceptance check:

1. Verify startup with registration closed, open it in the TUI, deny one request, then enroll one desktop and one Eclipse identity. Check both forms of `--issue-token`, including human approval with redirected logs in headless mode.
2. Connect both clients. Compare a known source object with Eclipse. Verify a read-only user cannot discover or directly call `sap_set_source`.
3. Change the desktop policy live. Allow a development package and verify both an allowed object and a known object in another package. Try search, a direct source request, and a source write against designated development fixtures. Disable activation and verify source writes are denied immediately.
4. Restart in headless mode, reconnect both clients, and verify saved restrictions and logs. Return to the TUI and revoke the desktop fingerprint. Its next call must fail.
5. Capture **Enrollment**, **Clients**, **Access Rules**, and **Logs**, plus Eclipse registration and connected states, for visual review. Redact tokens and identifying company data.

Run formatting last, after the checks and manual verification.

```powershell
cargo +nightly fmt --all
```

See the [implementation guide](IMPLEMENTATION.md) for repository working rules.
