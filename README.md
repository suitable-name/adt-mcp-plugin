# SAP ADT MCP Relay

A desktop MCP host launches `sap-adt-mcp-client` over stdio. The client connects to the Rust relay using its enrolled certificate. Eclipse opens an outbound WebSocket to the same relay using a separately enrolled Eclipse certificate. SAP access uses the selected Eclipse ADT project's connection and authentication. For a desktop that is not paired with its Eclipse, the relay sees the tool arguments and results; for a paired desktop it sees only metadata and the tool name. See the [security model](docs/security-model.md).

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

The Rust package declares Rust 1.99 as its minimum version (Trillium needs it), edition 2024, and workspace resolver 3. Run the following commands from the repository root in PowerShell 7 with Rust 1.99. The first Cargo command generates `Cargo.lock` if this checkout has no lockfile. Keep the resolved lockfile with the tested build.

```powershell
cargo +1.99 check --workspace --all-targets
cargo +1.99 test --locked --workspace --all-targets && cargo +1.99 clippy --locked --workspace --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery
cargo +1.99 build --locked --workspace --bins
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

This opens the operator TUI. The enrollment listener always runs; it accepts a claim only for a link the operator minted. Links name the relay by its DNS name from the PKI and the bound ports. Behind a gateway or NAT, set the addresses clients must use with `--public-data <host:port>` and `--public-enrollment <host:port>`, and the relay's display name with `--name <text>`.

For unattended operation, use `serve --pki C:\Relay\pki --headless`. The server uses saved identities and policies and writes logs to stderr. Mint enrollment links on that machine with `issue-link` (see below). [Operator manual](docs/operator-manual.md)

Keep the PKI directory across restarts. Restrict it and its backups to the service account. It holds the CA signing key, server key, enrolled certificate fingerprints, access policies and `issue.secret` (the operator secret `issue-link` presents). The server generates client credentials only when a link is claimed.

| Port | Purpose | Authentication |
| --- | --- | --- |
| 8787 | Desktop MCP requests on `/mcp` and Eclipse WebSocket upgrades on `/bridge` | TLS 1.3 with a client certificate and the matching role fingerprint |
| 8788 | Single-use claims (`/claim`) and link minting (`/issue`, loopback only) | TLS 1.3; a claim needs a minted, unexpired link whose token pins the CA; `/issue` needs the operator secret |

Allow the workstations to reach both ports. For a corporate gateway, use TCP/TLS passthrough to the same relay instance. The relay must see the actual client certificate. The earlier setup that terminated TLS at an HTTP reverse proxy and forwarded bearer headers is incompatible. Choose a gateway timeout longer than ten minutes for long-running SAP calls and keep the Eclipse connection open for WebSocket traffic.

## Enroll a Workstation

Repeat this process once for each Eclipse workspace and desktop client profile. A fresh client needs the company server address. It receives its CA and private identity during enrollment.

1. **The operator mints a link.** In the server's **Enrollment** tab press **N**, choose the role (`desktop` or `eclipse`) and type a label, then press **Enter**. The relay shows a link such as `sap-adt://enroll?v=1&r=desktop&n=Company+Relay&s=adt-relay.company.example:8787&e=adt-relay.company.example:8788&t=GW1-...` with **C Copy** (terminal clipboard). Headless, run `sap-adt-mcp-server-relay issue-link --pki C:\Relay\pki --role desktop --label "Anna desktop"` on the relay's machine (`--relay <host:port>` names the enrollment listener, default `127.0.0.1:8788`); it prints only the link on standard output. Minting the link is the approval.
2. **The operator gives the link to the person.** The link is a password until it is used: single use, valid for 10 minutes, at most 16 outstanding. Cancel an unused link with **X** in the Enrollment tab. The link is shown once and hidden again when the dialog closes.
3. **The workstation claims it.** The client reads the relay's addresses from the link, checks that the CA the relay presents matches the fingerprint inside the link's token (and stops with "wrong relay or attacker in the middle" otherwise) and only then sends the secret over that CA-pinned TLS connection. The relay consumes the link, issues the identity for the link's role and label, and answers any wrong, used, expired or cancelled link with one generic refusal. The client saves its private profile.
4. The Enrollment tab and the log show "Anna desktop (desktop) enrolled from 203.0.113.7". A newly enrolled desktop is read-only and has no endpoint grants until the operator assigns them.

The token follows the `diagram_loader` GW1 format, which combines a random 256-bit secret with the SHA-256 fingerprint of the CA. No client certificate, shared password, or CA file needs to be provisioned on a new workstation in advance. Links are only pasted; the `sap-adt://` scheme is not registered with the operating system. Do not send a link through a channel the relay itself carries.

### Eclipse

Open **Window → Show View → Other → SAP ADT MCP → SAP ADT Relay**. Register the workspace by pasting an **Eclipse** enrollment link (role `eclipse`) from the operator; the enrollment and bridge addresses come from the link. Click **Select ABAP Project** and choose the intended existing ADT workspace project in the Eclipse selector. The plugin uses that project's existing connection; ADT opens its normal login dialog if authentication is needed. Click **Connect Relay**. SAP connection settings and authentication are managed by ADT. The relay profile supplies trust for the relay connection.

The bridge stays bound to the explicitly selected project when you switch editor tabs or Project Explorer selections. Disconnect the relay before selecting another project, then reconnect the desktop MCP host. Disconnecting the relay or closing its view releases the plugin's session while preserving the shared ADT login. A normal reconnect uses the selected project. If the project closes, loses authentication, or changes its destination identity, the plugin clears the selection; explicitly select the intended project again and reconnect.

To let a desktop use this Eclipse over an end-to-end encrypted stream, connect the relay and click **Pair Desktop**. Copy the one-time link (valid 5 minutes, one outstanding) on this machine and paste it into the desktop client's `pair` command. Eclipse then asks **Pair <label>?** with the desktop key's short fingerprint; compare it with the one the client printed and click **Pair**. The view lists paired desktops with **Remove**, and **Preferences → MCP Relay → Permissions** can restrict each paired desktop further than the global permissions. [Pairing and per-desktop permissions](docs/operator-manual.md#pairing-desktops-encrypted-streams)

#### Eclipse setup in order

1. **Enroll** with the operator's Eclipse link (**Register Eclipse**), select the ABAP project and click **Connect Relay**.
2. **Pair Desktop** for every desktop that should use this Eclipse, as described above.
3. **Optionally turn off unencrypted calls.** Open **Preferences → MCP Relay → Permissions** and clear **Allow unencrypted relay calls**. This Eclipse then answers only encrypted requests from paired desktops, and refuses the relay's clear-text `tools/list` and `tools/call` with error `-32002`. The setting applies to the next call without a restart. The default in this version is on, so existing desktops keep working until they are paired. The encryption protections against a compromised relay hold only once this is off and the desktops are paired.

An administrator can preset the switch for all users in `plugin_customization.ini` and lock it together with the permissions (the value then comes from the administrator layers only):

```properties
com.sap.adt.mcp.server.plugin/relay.allowUnencrypted=false
com.sap.adt.mcp.server.plugin/permissions.locked=true
```

The MCP view shows "Unencrypted relay calls: allowed" or "blocked" next to the local-permissions line and logs each refused clear-text call. Threat model, what the relay still sees, key storage, revocation and the migration steps are in the [security model](docs/security-model.md).

### Desktop Client

Place the portable client binary where the MCP host can execute it. It uses stdin and stdout and opens an outbound TLS connection. Run enrollment once using the same OS account that will run the desktop host. Choose a **new** profile directory inside an existing private parent. Paste the **desktop** link from the operator. The link is a secret, so avoid shell histories you do not control.

```powershell
& 'C:\Tools\sap-adt-mcp-client.exe' enroll --link 'sap-adt://enroll?v=1&r=desktop&...' --profile "$env:LOCALAPPDATA\sap-adt-profile"
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

#### Pair the Desktop with Eclipse (end-to-end encryption)

An endpoint that is not paired is served through the relay's `/mcp` path, and the relay can read its traffic. `connect` prints one warning on stderr for such an endpoint. Pairing makes the desktop and the Eclipse plugin talk through an inner TLS 1.3 session whose keys only the two ends know. The relay then forwards ciphertext plus a small readable envelope (method, tool name and action class) and still enforces its access rules on that envelope.

1. The operator must already have granted the endpoint to this desktop (**Access Rules**, **E**).
2. In Eclipse, open the MCP view and choose **Pair Desktop**. Copy the `sap-adt://pair?...` link. It works once, for five minutes, and is a secret. Copy it on this machine and never send it through the relay.
3. On the desktop, run the following with the enrolled profile.

```powershell
& 'C:\Tools\sap-adt-mcp-client.exe' pair --profile "$env:LOCALAPPDATA\sap-adt-profile" --link 'sap-adt://pair?v=1&p=...'
```

The client checks Eclipse's key against the fingerprint in the link before it sends anything. A different key stops with “wrong Eclipse or attacker in the middle”. While it waits, it prints this desktop's short key fingerprint. Eclipse shows a **Pair <label>?** dialog with the same fingerprint; compare them and confirm. On success the Eclipse key is pinned in `peers.json` in the profile and this endpoint becomes the selected one. A wrong, expired or used link, or a refusal in Eclipse, prints “The link was wrong, expired, already used, or the pairing was refused in Eclipse.”

The profile gains `inner_key.pem` (this desktop's P-256 identity key), `inner_cert.pem` and `peers.json`. Keep them as private as `credentials.json`. `unpair --profile <dir> --endpoint <id-or-label>` removes the pin; remove the desktop in Eclipse's MCP view as well.

**No downgrade once paired.** While `peers.json` pins the selected endpoint, `connect` uses only the end-to-end path and never `/mcp`, whatever the relay answers. If the tunnel or the encrypted session fails, the request fails. A damaged `peers.json` stops the connection instead of reading as “unpaired”. To go back to the relay-readable path, run `unpair`.

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

Use **Clients** to inspect or revoke an enrolled fingerprint. After credential loss or expiry, revoke the old fingerprint and enroll a fresh profile. Use **Logs** for recent relay events. In headless mode, direct stderr to the service's log collector. Set `RUST_LOG` to a level such as `info` or `debug` when starting the server. Enrollment links and tokens, tool arguments, and source code are excluded from relay logs.

Client certificates are issued for one year and the server leaf for 825 days. Before the server leaf expires, run the following command with the service account and restart the relay. This uses the existing CA and preserves enrolled profiles. Replacing the CA requires a new PKI and fresh enrollment for every identity.

```powershell
.\target\debug\sap-adt-mcp-server-relay.exe renew-server --pki C:\Relay\pki --dns adt-relay.company.example
```

Connect the selected Eclipse workspace before initializing the desktop MCP session. Each session belongs to its desktop certificate and that specific Eclipse connection. A bridge drop invalidates its sessions. Other workspaces keep serving their own sessions. If a call lost its reply, check the object, lock, and activation state in SAP before retrying.

For the owner-run acceptance check:

1. Verify startup, mint a desktop link and an Eclipse link in the TUI, and enroll one desktop and one Eclipse identity. Check that a used, cancelled or expired link is refused and that a link pointing at another relay fails the CA pin. In headless mode, mint a link with `issue-link` and enroll with it.
2. Connect both clients. Compare a known source object with Eclipse. Verify a read-only user cannot discover or directly call `sap_set_source`.
3. Change the desktop policy live. Allow a development package and verify both an allowed object and a known object in another package. Try search, a direct source request, and a source write against designated development fixtures. Disable activation and verify source writes are denied immediately.
4. Restart in headless mode, reconnect both clients, and verify saved restrictions and logs. Return to the TUI and revoke the desktop fingerprint. Its next call must fail.
5. Capture **Enrollment**, **Clients**, **Access Rules**, and **Logs**, plus Eclipse registration and connected states, for visual review. Redact tokens and identifying company data.

Run formatting last, after the checks and manual verification.

```powershell
cargo +nightly fmt --all
```

See the [implementation guide](IMPLEMENTATION.md) for repository working rules.
