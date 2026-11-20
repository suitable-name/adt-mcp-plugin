# Operator Manual

Use this manual to deploy one relay, connect an Eclipse workspace and MCP host, set access rules, and recover the service. Commands use PowerShell 7 and example paths. Substitute your company DNS name, service account, and approved installation paths. The [verification checklist](verification.md) covers acceptance testing.

## Deployment Layout

| Location | Software | Connections |
| --- | --- | --- |
| Company server | `sap-adt-mcp-server-relay`, private PKI directory | Accepts TLS connections on the data and enrollment ports |
| SAP workstation | Eclipse with SAP ADT and the rebuilt SAP ADT Relay feature | Opens an outbound WebSocket to the relay and uses the selected ADT project's SAP connection |
| MCP workstation | Existing MCP host and approved portable `sap-adt-mcp-client` executable | The host launches the executable over stdio. The executable opens outbound HTTPS connections to the relay |

The two workstation roles may share a computer and enroll separately. One relay accepts connections from several Eclipse workspaces. Each workspace has a distinct enrollment certificate. The operator grants individual desktops access to selected workspaces. SAP requests run using the SAP login active in the selected workspace.

Choose a stable DNS name reachable from both workstations. The server certificate covers the DNS name or IP address passed to `init`. Allow outbound workstation traffic to the corresponding server addresses. For a company gateway, forward raw TCP so that certificate authentication terminates in Rust. Both ports can use company-approved external port numbers. Supply the actual reachable addresses separately to each client. Allow idle WebSockets and a timeout above ten minutes for long SAP calls.

## Install and Initialize

1. Build the two Rust binaries for their destination operating systems and the Eclipse update site with the commands in the [verification checklist](verification.md). Deploy the relay binary on the server and the client binary in a location the desktop host can execute. This procedure requires permission to run the portable helper and install the modified Eclipse feature.
2. In an Eclipse installation with SAP ADT, open **Help → Install New Software → Add**. Enter your team's hosted update site URL, choose **Archive** for the built ZIP, or choose **Local** for the generated `repository` directory. Install the feature from this checkout to get the bridge and package-policy support, then restart Eclipse. SAP ADT is required at runtime. [Eclipse update site guide](eclipse-update-site.md)
3. On the server, create a trusted parent directory under the service account. Choose a new child path for the PKI. Run the commands below from the directory containing the relay executable.

```powershell
.\sap-adt-mcp-server-relay.exe init --pki C:\Relay\pki --dns adt-relay.company.example
.\sap-adt-mcp-server-relay.exe serve --pki C:\Relay\pki --listen 0.0.0.0:8787 --enrollment-listen 0.0.0.0:8788
```

The TUI requires a terminal on stdin and stdout. Use at least 54 columns by 18 rows and expand it to inspect long fingerprints. The default addresses listen on all IPv4 interfaces. Use `--listen` and `--enrollment-listen` to bind specific interfaces.

| Startup mode | Enrollment behavior | Operator interface |
| --- | --- | --- |
| `serve --pki <dir>` | Binds the enrollment port. It accepts `/claim` for links the operator minted and loopback `/issue` | Local TUI (**N** mints a link) |
| `serve --pki <dir> --headless` | Same, plus serves enrolled clients on the data port | Logs on stderr. Mint links with `issue-link` |

The enrollment listener always runs, headless too; it is never "open" to anyone without a minted link. `serve` creates `<pki>\issue.secret` (32 random bytes as hex, owner-only like the CA key) at every start. `issue-link` and nothing else needs it.

Links name the relay's display name (`--name`, default the DNS name of the PKI), its data address (`--public-data <host:port>`) and its enrollment address (`--public-enrollment <host:port>`). The defaults are the DNS name the PKI was initialized with plus the bound ports. Set the public addresses when clients reach the relay through a gateway, a NAT or another port. The enrollment host must be a name the server certificate covers, because the client verifies it.

To switch between the TUI and headless mode, stop the active relay and restart under the same account with the same PKI. Coordinate the restart with SAP users because live sessions end. Use the TUI for policy edits and certificate revocation.

### Headless Links

On the relay's machine, with the same account and PKI directory as `serve`:

```powershell
.\sap-adt-mcp-server-relay.exe issue-link --pki C:\Relay\pki --role desktop --label "Anna Laptop"
```

`--role` is `desktop` or `eclipse`. `--relay <host:port>` names the enrollment listener (default `127.0.0.1:8788`). The command calls `POST /issue` over TLS to that listener, pinning the relay CA from the PKI directory. The relay accepts `/issue` only from a loopback peer that presents the secret from `issue.secret`, sends no `Origin` header and uses constant-time comparison. Only the link is printed on standard output; capture it from there and keep it out of logs and tickets.

## Enroll the Two Roles

Enrollment needs an independent trusted channel between the operator and the person enrolling. A link is a password until it is used: single use, valid for 10 minutes, at most 16 outstanding. Minting the link is the approval; the relay asks for nothing more when it is claimed.

1. In the TUI, select **Enrollment** and press `n`. Choose the role with the left and right arrow keys and type a label of 1–64 printable ASCII characters that identifies the device (it names the certificate in **Clients** and in the log). Press Enter. Headless, run `issue-link` as above.
2. The link appears once, in the **Enrollment Link** dialog. Press `c` for clipboard copy on terminals that support OSC 52, then Esc to dismiss; the link is hidden again. Keep it out of tickets, logs, and screenshots.
3. Give the link to the person through the trusted channel. The Enrollment tab lists outstanding links (label, role, time left). Select one and press `x` to cancel it.
4. On the device, paste the link (below). The client checks that the CA the relay presents matches the fingerprint in the link's token, stops with "wrong relay or attacker in the middle" otherwise, and only then sends the secret. A successful claim issues one role-specific certificate for the stored label. A wrong, used, expired or cancelled link gets the same generic refusal.
5. The Enrollment tab and the log show "Anna Laptop (desktop) enrolled from 203.0.113.7", and the tab keeps the latest enrollments. Repeat with a second link for the second role. A newly enrolled desktop is read-only with no endpoint grants. The TUI's **Clients** tab lists enrolled fingerprints.

### Eclipse Workspace

Open **Window → Show View → Other → SAP ADT MCP → SAP ADT Relay**. Click **Register Eclipse** and paste an **Eclipse** enrollment link into **Enrollment link**. The plugin derives the enrollment and bridge addresses from it.

Click **Select ABAP Project** to open the Eclipse selector listing existing ADT workspace projects. Choose the project for the intended system and account. The plugin uses its existing ADT connection, and ADT opens its normal login dialog if the project needs authentication. Configure SAP connection settings, trust, and login through ADT. Click **Connect Relay** and keep the view and workspace open for tool requests.

The chosen project is fixed for that relay connection. Opening another editor tab or changing the Project Explorer selection does not redirect requests. Disconnect the relay before choosing a different project, reconnect it, and reinitialize the desktop host's MCP connection. Closing the relay view or disconnecting releases the plugin's own session and lock bookkeeping while retaining the ADT project's shared login. A normal **Connect Relay** reconnect uses the selected project. If the project is closed or deleted, its authentication is lost, or its destination identity changes, requests are rejected and the selection is cleared. Restore the intended project, use **Select ABAP Project** again, and reconnect. ADT opens its login dialog if the new selection needs authentication.

The plugin stores its enrolled identity in the workspace's encrypted `relay-profile.enc` with a wrapping key in Eclipse secure storage. A moved workspace or unavailable secure-storage key may require **Register Again**. Revoke the superseded certificate in **Clients**.

#### Local Permissions

**Window → Preferences → MCP Relay** limits what any relay may do in this Eclipse, in addition to the relay's own rules. The stricter of the two always wins, and the local settings can only restrict. The next relay call uses a saved change, without reconnecting.

| Setting | Meaning |
| --- | --- |
| **Read-only** | Only tools that read from SAP are listed and run. |
| **Allow all tools** / tool list | Uncheck **Allow all tools** and tick the tools to enable. A composite tool such as `sap_set_source` also needs the tools it uses (lock, unlock, activate). |
| **Package patterns** | Up to 64 patterns in the relay's syntax (`Z*`, `/NS/*`, `ZAPP`; case is ignored). A package-aware tool's target must match a pattern here and the relay's scopes. With patterns set, tools that cannot be limited to a package (for example SQL or test runs) are refused. Empty means no local package restriction. |

The relay also sends the tool names it allows with every request, and the plugin runs a tool only if both the relay's list and the local settings allow it. A relay that does not advertise policy version 2 in its hello (an older relay) sends no list. The plugin accepts that only until a relay has advertised version 2; update the relay to close this gap.

An administrator can preset the values in `plugin_customization.ini` and lock them:

```ini
com.sap.adt.mcp.server.plugin/permissions.readOnly=true
com.sap.adt.mcp.server.plugin/permissions.allowedTools=sap_get_source,sap_search_object
com.sap.adt.mcp.server.plugin/permissions.packagePatterns=Z*,/NS/*
com.sap.adt.mcp.server.plugin/permissions.locked=true
```

With `permissions.locked=true` the page shows the values read-only with "Locked by your administrator", and the user's own saved values are ignored. `permissions.allowedTools` is `*` (all) or a comma-separated list. The SAP ADT Relay view shows the effective local policy in one line. Its log names the layer that refused a call: "relay layer" or "this Eclipse's permissions". A local refusal returns JSON-RPC error `-32002` ("Denied by this Eclipse's permissions: ..."). A relay-layer refusal uses `-32001`.

#### Pairing Desktops (Encrypted Streams)

Once the relay is connected, **Pair Desktop** in the SAP ADT Relay view creates a one-time pairing link and shows it with a **Copy** button and its remaining lifetime. A link works once and expires after 5 minutes, and only one link is outstanding: creating a new one cancels the previous one. Copy the link on this machine and paste it into the desktop client's `pair` command. Never send it through the relay or a chat.

The desktop connects through the relay, checks this Eclipse's key against the link, and claims the link inside the encrypted session. This Eclipse then asks **Pair <label>?** in a non-blocking dialog. The label comes from the relay and is not verified. Compare the short key fingerprint (first 16 hex characters in groups of four) with the one the desktop client printed, and click **Pair** or **Refuse**. No answer within 2 minutes counts as a refusal. A wrong, used or expired secret, a refusal, or an unanswered dialog all give the desktop the same generic "Pairing refused." error; the reason is written to the view's log only.

The **Paired desktops** list shows each pinned desktop (label, short key fingerprint, paired since). **Remove** unpairs it; it must pair again before it can use this Eclipse.

**Per-desktop permissions.** In the **SAP ADT Relay** view, the **Paired desktops** table has one row per paired desktop, and its **Permissions** column shows "Same as global" or what that desktop is restricted to. Right-click a desktop and choose **Permissions...** (or double-click it, or select it and click **Permissions...**) to set the same three settings for that desktop (read-only, tools, package patterns); the change is saved when you click **OK**. **Global Permissions...** opens **Preferences → MCP Relay**. Each setting defaults to "same as global". A call from an encrypted stream is checked against the global permissions and that desktop's settings together, so the desktop can only be restricted further. The administrator keys are `permissions.desktop.<key fingerprint>.readOnly`, `.allowedTools` and `.packagePatterns` (the 64-hex-character fingerprint of the desktop's inner key), and `permissions.locked=true` covers them too. Unencrypted relay calls use the global permissions only.

### Desktop MCP Host

Run enrollment once under the OS account that runs the host. The profile argument must be a new directory under an existing trusted parent. Paste the **desktop** link the operator gave you; the relay addresses and the CA pin come from it, and the profile saves the data address as its server. The link is a secret: it appears in the process list and shell history while the command runs.

```powershell
& 'C:\Tools\sap-adt-mcp-client.exe' enroll --link 'sap-adt://enroll?v=1&r=desktop&...' --profile "$env:LOCALAPPDATA\sap-adt-profile"
```

### Assign and Select an Endpoint

1. In **Access Rules**, select the user's enrolled desktop. Check its label and certificate fingerprint, then press **E**. Select the Eclipse workspaces that user may access, using **Space** to toggle each one. Press **S** to save. You can grant the same endpoint to several desktops. Each separately enrolled desktop starts with an empty grant list, including profiles upgraded from the single-workspace relay.
2. On the workstation run `sap-adt-mcp-client.exe endpoints --profile <directory>`. The list includes the endpoint ID, workspace label, and connection status for the caller's grants. The ID is the Eclipse certificate fingerprint. Separate workspaces may have the same label.
3. Run `sap-adt-mcp-client.exe --set-endpoint=<id> --profile <directory>` with the full ID from the list. You can also use an exact, unique label such as `--set-endpoint=DEV`. If two assigned workspaces have the same label, use the intended ID. The client saves the verified ID. An assigned offline workspace can be selected in advance. Connect that workspace before starting the MCP session.
4. Configure the host to execute `sap-adt-mcp-client.exe connect --profile <directory>`, using absolute paths. The private profile holds the client key, certificate, CA, relay address, and saved selection. Restrict the directory to the host account. Reload the host's MCP connection when changing the selection.

The host receives a setup error if the profile or its selection is missing. With an initialized connection, the model can use `relay_list_endpoints` to report the selected endpoint and this desktop's available endpoints. Switching workspaces requires saving a new selection locally. Removing a grant blocks further requests to that endpoint. An operation already admitted may finish. Re-enrolling an Eclipse workspace issues a new endpoint ID. Grant and select that ID explicitly.

For Claude Code in PowerShell, register the executable in the project where you intend to use SAP. Start Eclipse's relay connection before opening the host's MCP session.

```powershell
claude mcp add --transport stdio sap-adt -- 'C:\Tools\sap-adt-mcp-client.exe' connect --profile "$env:LOCALAPPDATA\sap-adt-profile"
claude mcp get sap-adt
```

The [README](../README.md) includes the equivalent stdio configuration for other hosts. Check the connection with a known development object using `sap_search_object` and compare its name, type, and URI with Eclipse.

## Use the Operator TUI

Use Tab and Shift+Tab to switch sections. Arrow keys move the selection. Use lowercase letter keys for the commands shown in the footer. Esc cancels a dialog. Press `q` on a dashboard or Ctrl+C to shut down the interactive server.

| Tab | Actions |
| --- | --- |
| **Enrollment** | `n` mints a link (role, label, then Enter; `c` copies it, Esc hides it), `x` cancels the selected outstanding link. The tab also lists the latest enrollments |
| **Clients** | Inspect role, label, and fingerprint. `r` opens revocation for the selected certificate. Enter confirms. F5 refreshes |
| **Access Rules** | Select a desktop and press `e` for endpoint assignments. Enter opens the action and package editor. F5 refreshes enrolled identities |
| **Connections** | Live view, refreshed continuously. Each connected Eclipse bridge shows its label, address, connection age, state (handshake, ready, or busy while Eclipse processes a call), `e2e` or `legacy only` (whether the plugin announced end-to-end support), whether encryption is required for it, the number of forwarded calls, and the last tool. The first line lists the desktops that still use unencrypted sessions. Below each bridge are its **encrypted** streams (desktop label, address, stream ID prefix, age, idle time, request count, last method and tool, last status `ok`, `error` or `denied`, bytes in and out, last admit-to-response time measured by the relay) and its **unencrypted** `/mcp` sessions (desktop label, address of the latest request, session ID prefix, age, idle time, request count, last tool or method). The relay knows only envelope metadata for encrypted streams. Up/Down select a bridge (the view follows), Page Up/Page Down scroll, Home returns to the top, `e` requires or allows encryption for the selected endpoint, F5 reloads the labels |
| **Logs** | Up/Down scroll through history, Page Up/Page Down move ten entries, Left/Right pan long lines, End returns to the latest events |

### Require End-to-End Encryption

`require_e2e` is stored in `policy.json` as a global flag (`require_e2e`) and per-endpoint overrides (`require_e2e_endpoints`, endpoint ID to true or false). Files without these fields load as off, and it is **off by default in this version**. Set the global flag with `e` in the **Global Rules** editor, or toggle one endpoint with `e` on its row in **Connections**. The endpoint override wins over the global flag. Every change is logged at info level.

When encryption is required for an endpoint, `initialize` on `/mcp` for it is refused with the error "This Eclipse endpoint requires end-to-end encryption. Pair this desktop with sap-adt-mcp-client pair --link <link from Eclipse> and reconnect." Existing unencrypted sessions of that endpoint end at their next request with the same message. Encrypted streams are unaffected.

Migration advice: leave it off while desktops are being paired. The first line of the **Connections** tab names the desktops that still use unencrypted sessions. Turn it on per endpoint once every desktop that uses that endpoint is paired, and use the global flag only when all endpoints are ready. A desktop that is not paired is locked out of a required endpoint until it pairs.

The relay's flag cannot protect against the relay itself, because a compromised relay could ignore it and send clear-text calls. The Eclipse plugin therefore has its own preference, **Allow unencrypted relay calls** (key `relay.allowUnencrypted`, default on). When it is off, legacy `tools/list` and `tools/call` get the JSON-RPC error -32002 "This Eclipse accepts only end-to-end encrypted calls. Pair this desktop with Pair Desktop in the MCP view."; `relay/hello` and ping still work. An administrator can preset it in `plugin_customization.ini`. With `permissions.locked`, the user value is ignored. Protection against a compromised relay holds only when this switch is off. See [security-model.md](security-model.md) for the full threat model.

### Set Access Rules

Global restrictions apply to every desktop. Each newly enrolled desktop defaults to read-only. The desktop rule row identifies a certificate fingerprint, so two profiles with the same label can have different permissions.

| Editor operation | Keys |
| --- | --- |
| Toggle **Read-Only Mode** | `r` on the editor summary |
| Toggle **Require end-to-end encryption** (global editor only) | `e` on the editor summary |
| Set **Allowed Actions** | `a`, arrow keys and Space to toggle. `*` selects unrestricted, `0` clears the allowlist. Enter applies to the editor |
| Set **Allowed Packages** | `p`, type comma-separated patterns. Ctrl+U clears the field. A lone `*` selects unrestricted access. An empty field permits no packages. Enter applies to the editor |
| Commit edits | `s` on the summary. If someone saved a different revision, press `l` to reload, reapply changes, and save |
| Remove a desktop override | `x` on its summary, then Enter. The read-only desktop default takes effect immediately |

Each action must pass both the global and desktop rules. A checked action can still be blocked by read-only mode or package restrictions. Read-only permits ABAP documentation, get source, inactive objects, object structure, search, and usage references. SQL, syntax checks, test runs, ATC, creation, source writing, activation, locks, and unlocks require write-enabled rules.

For example, to grant a developer source editing in finance development packages only, first verify that **Global Rules** permits that work. Open the developer's desktop rule. Turn read-only off, choose `sap_search_object`, `sap_get_source`, `sap_set_source`, `sap_lock`, `sap_unlock`, and `sap_activate`, then enter `ZFIN*, /ACME/FIN*` as the package list and save. Source writing requires all four write-related permissions even when a call supplies its own options. Verify the result with designated development fixtures before allowing changes to business objects.

Package patterns match SAP technical package names case-insensitively. Exact names such as `$TMP` and trailing wildcards such as `/ACME/*` are supported. Multiple entries in one list are alternatives. If both rule layers specify packages, a target must match a pattern in each. Package scoping limits available tools to search, source retrieval, object structure, create, lock, unlock, activate, and set source. Eclipse verifies ownership for existing typed targets and checks the destination package for creation. Use object type and object name for scoped requests. Search can omit hits whose package cannot be verified.

Changes apply to future calls in existing sessions. Some hosts cache discovery results. Reconnect the host to refresh its displayed tools. An operation admitted before a rule change may still complete.

## Credentials, Recovery, and Logs

* **Back up the PKI.** Stop the relay and back up the entire directory with its access controls. It contains `ca.pem`, `ca.key`, `server.pem`, `server.key`, the `desktop` and `eclipse` pin directories, and the `policy.json` and `policy.lock` files created on first serve. Encrypt or otherwise protect the backup as signing-key material. Preserve a record of later enrollments, revocations, and policy changes.
* **Restore service.** Restore to a protected directory owned by the service account. Start the same binary and PKI in an isolated environment, check **Clients** and **Access Rules**, and reconcile any changes since the backup before opening the production data port. Restoring an old backup can reinstate a revoked fingerprint or older permission. Reconnect Eclipse and reinitialize the desktop host.
* **Revoke or replace a client.** In **Clients**, compare the full fingerprint and revoke it. Requests already admitted may complete. Enroll the replacement workspace or a fresh desktop profile. Apply the intended desktop rules to its new fingerprint. Client certificates last 365 days. Copying a profile also copies its identity and permissions.
* **Renew the server leaf.** The server certificate lasts 825 days. Use the existing CA and server key with the command below and restart the process. Keep the hostname used by the workstations. The CA has a ten-year lifetime. CA replacement requires a new trust domain and fresh enrollments.

```powershell
.\sap-adt-mcp-server-relay.exe renew-server --pki C:\Relay\pki --dns adt-relay.company.example
```

The interactive **Logs** tab keeps up to 512 recent entries in memory. Headless mode sends diagnostics to stderr. At startup, `RUST_LOG` accepts a single tracing level such as `info` or `debug`. Access events can identify a tool and desktop fingerprint. Keep the link dialog, the output of `issue-link`, `issue.secret`, and profile files out of diagnostic captures. The relay never logs a link or token. To diagnose a running process, read its log.

| Symptom | What to check |
| --- | --- |
| Enrollment refuses or cannot connect | The client reports one generic refusal for a wrong, used, expired or cancelled link: mint a new link (10-minute lifetime, single use). If it cannot connect, verify port 8788 or the `--public-enrollment` address in the link, firewall reachability, and that the enrollment host is covered by the server certificate. Check that the Enrollment tab still lists the link as outstanding |
| `issue-link` is refused or cannot connect | Run it on the relay's machine with the PKI directory `serve` was started with (`issue.secret` is recreated at every start). Pass `--relay <host:port>` if the enrollment listener is not on `127.0.0.1:8788`. At most 16 links can be outstanding |
| "Wrong relay or attacker in the middle" | The CA the relay presented does not match the link. The secret was not sent. Verify the company hostname and that the link came from this relay's operator, then mint a new link |
| TLS or authorization failure on the data port | Verify the DNS name, clock, certificate lifetime, correct role, and matching enrolled fingerprint. The gateway must preserve end-to-end TLS |
| Eclipse already connected | A bridge using the same Eclipse certificate is already connected. Enroll each independent workspace separately |
| Endpoint list empty or selected ID denied | In **Access Rules**, select this desktop fingerprint, press **E**, and check its saved grants. Run the desktop's `endpoints` command again |
| No endpoint selected | Save an ID from `endpoints` using `--set-endpoint=<id>` with the profile passed by the MCP host, then reconnect |
| MCP initialization reports Eclipse unavailable | Use **Select ABAP Project** to choose and authenticate the intended ADT project, connect the relay, and wait for the Eclipse bridge-connected log. Use the rebuilt plugin with package-policy support |
| Busy relay or expired MCP session | Let the active operation finish. Reconnect the workspace if needed, then reinitialize the host. Sessions expire after eight idle hours or bridge loss |
| Missing tool or package-denied call | Check both sets of rules, SAP authorization, technical package name, and typed target. Confirm the host has refreshed its catalog |
| Lost reply during a write or activation | Inspect SAP source, locks, and activation state before retrying. A transport error can follow a completed SAP mutation |
