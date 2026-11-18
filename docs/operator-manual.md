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
| `serve --pki <dir>` | Binds the enrollment port with registration closed | Local TUI |
| `serve --pki <dir> --issue-token` | Binds the enrollment port with registration open. Each request still requires approval | Local TUI |
| `serve --pki <dir> --headless` | Serves previously enrolled clients on the data port. Leaves the enrollment port unbound | Logs on stderr |
| `serve --pki <dir> --headless --issue-token` | Binds both ports with registration open. Requires an attached terminal and approval for each request | Line-oriented approval console on the terminal. Logs on stderr |

Use plain `--headless` for an unattended service. To switch startup modes, stop the active relay and restart under the same account with the same PKI. Coordinate the restart with SAP users because live sessions end. Use the TUI for policy edits and certificate revocation.

### Headless Approval Console

Launch `serve --pki <dir> --headless --issue-token` from a session with an attached operator terminal. The server opens `/dev/tty` on Unix or the console devices `CONIN$` and `CONOUT$` on Windows. You can redirect stdout and stderr to files or a log collector. The enrollment prompts, operator input, and issued tokens use the terminal directly. If the terminal cannot be opened, startup fails before the listeners begin serving.

1. Start enrollment on the workstation. On the server terminal, compare the full pending request ID, role, and label with the requester over an independent trusted channel. Use `pending` to list outstanding requests.
2. Read `number=<n>` on the verified console row. Enter `approve <number>` or `deny <number>`, substituting that number. The decision applies immediately. Each displayed request has its own number for the life of this console, including a replacement with the same requester ID. If the request changed or expired, compare the replacement’s details with its requester. Approval displays the one-time `GW1-` token on the terminal. Give the token to the verified requester over the trusted channel.
3. Enter `close` to close registration and invalidate outstanding requests and unused grants. Use `open` to accept new requests later, `help` to list commands, or `quit` to stop the relay. The data listener continues serving enrolled clients while registration is closed.

## Enroll the Two Roles

Enrollment needs the server address and an independent trusted channel between the operator and requester. It creates the CA trust and private client credentials on the workstation.

1. In the TUI, select **Enrollment** and press `o` if registration is closed. For a headless server started with `--issue-token`, use the approval console procedure above. On the workstation, start the applicable request below. Choose a label of 1–64 printable ASCII characters that identifies the device and is suitable for disclosure during initial contact.
2. The requester sees a random 32-character hexadecimal ID. Independently compare the complete ID, role, and label with the pending request on the server terminal. The peer address helps identify a connection through a gateway but a shared address can represent multiple devices.
3. In the TUI, select the request with the arrow keys, press `a`, inspect the confirmation screen, and press Enter. Use `d` and Enter to deny an unexpected request. The approval console accepts the equivalent `approve` and `deny` commands. An unanswered request expires after 180 seconds.
4. Deliver the entire displayed `GW1-` token through the trusted channel. In the TUI’s **Enrollment Token** dialog, press `c` for clipboard copy on terminals that support OSC 52, then Esc to dismiss. In the headless approval console, copy the token from the terminal. Keep it out of tickets, logs, and screenshots.
5. On the requesting device, submit the token. The client matches its CA fingerprint, then verifies TLS and the requested hostname on a fresh claim connection. A successful claim issues one role-specific certificate. The token is single-use and has its own 180-second lifetime from approval.
6. Repeat for the second role. Press `o` in the TUI or enter `close` in the approval console once both have enrolled. Closing invalidates pending requests and unclaimed tokens. The TUI’s **Clients** tab lists enrolled fingerprints.

### Eclipse Workspace

Open **Window → Show View → Other → SAP ADT MCP → SAP ADT Relay**. Click **Register Eclipse**. Enter the device label, **Registration URL** such as `https://adt-relay.company.example:8788`, and **Bridge URL** such as `wss://adt-relay.company.example:8787/bridge`. Click **Request Registration** and follow the approval steps.

Click **Select ABAP Project** to open the Eclipse selector listing existing ADT workspace projects. Choose the project for the intended system and account. The plugin uses its existing ADT connection, and ADT opens its normal login dialog if the project needs authentication. Configure SAP connection settings, trust, and login through ADT. Click **Connect Relay** and keep the view and workspace open for tool requests.

The chosen project is fixed for that relay connection. Opening another editor tab or changing the Project Explorer selection does not redirect requests. Disconnect the relay before choosing a different project, reconnect it, and reinitialize the desktop host's MCP connection. Closing the relay view or disconnecting releases the plugin's own session and lock bookkeeping while retaining the ADT project's shared login. A normal **Connect Relay** reconnect uses the selected project. If the project is closed or deleted, its authentication is lost, or its destination identity changes, requests are rejected and the selection is cleared. Restore the intended project, use **Select ABAP Project** again, and reconnect. ADT opens its login dialog if the new selection needs authentication.

The plugin stores its enrolled identity in the workspace's encrypted `relay-profile.enc` with a wrapping key in Eclipse secure storage. A moved workspace or unavailable secure-storage key may require **Register Again**. Revoke the superseded certificate in **Clients**.

### Desktop MCP Host

Run enrollment once under the OS account that runs the host. The profile argument must be a new directory under an existing trusted parent. Both URL arguments below are HTTPS origins.

```powershell
& 'C:\Tools\sap-adt-mcp-client.exe' enroll --server https://adt-relay.company.example:8787 --enrollment https://adt-relay.company.example:8788 --label 'Anna desktop' --profile "$env:LOCALAPPDATA\sap-adt-profile"
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
| **Enrollment** | `o` opens or closes registration, `a` approves a selected request, `d` denies it. Confirm with Enter |
| **Clients** | Inspect role, label, and fingerprint. `r` opens revocation for the selected certificate. Enter confirms. F5 refreshes |
| **Access Rules** | Select a desktop and press `e` for endpoint assignments. Enter opens the action and package editor. F5 refreshes enrolled identities |
| **Logs** | Up/Down scroll through history, Page Up/Page Down move ten entries, Left/Right pan long lines, End returns to the latest events |

### Set Access Rules

Global restrictions apply to every desktop. Each newly enrolled desktop defaults to read-only. The desktop rule row identifies a certificate fingerprint, so two profiles with the same label can have different permissions.

| Editor operation | Keys |
| --- | --- |
| Toggle **Read-Only Mode** | `r` on the editor summary |
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

The interactive **Logs** tab keeps up to 512 recent entries in memory. Both headless modes send diagnostics to stderr. At startup, `RUST_LOG` accepts a single tracing level such as `info` or `debug`. Access events can identify a tool and desktop fingerprint. Keep the local token dialog, approval terminal, and profile files out of diagnostic captures. To diagnose a running process, read its log.

| Symptom | What to check |
| --- | --- |
| Enrollment refuses or cannot connect | Verify interactive mode, port 8788 or its configured replacement, firewall reachability, and **Enrollment · Open**. Start a new request after expiry |
| Token or CA mismatch | Stop the attempt. Verify the company hostname and request ID independently. Obtain a new approval for the correct device |
| TLS or authorization failure on the data port | Verify the DNS name, clock, certificate lifetime, correct role, and matching enrolled fingerprint. The gateway must preserve end-to-end TLS |
| Eclipse already connected | A bridge using the same Eclipse certificate is already connected. Enroll each independent workspace separately |
| Endpoint list empty or selected ID denied | In **Access Rules**, select this desktop fingerprint, press **E**, and check its saved grants. Run the desktop's `endpoints` command again |
| No endpoint selected | Save an ID from `endpoints` using `--set-endpoint=<id>` with the profile passed by the MCP host, then reconnect |
| MCP initialization reports Eclipse unavailable | Use **Select ABAP Project** to choose and authenticate the intended ADT project, connect the relay, and wait for the Eclipse bridge-connected log. Use the rebuilt plugin with package-policy support |
| Busy relay or expired MCP session | Let the active operation finish. Reconnect the workspace if needed, then reinitialize the host. Sessions expire after eight idle hours or bridge loss |
| Missing tool or package-denied call | Check both sets of rules, SAP authorization, technical package name, and typed target. Confirm the host has refreshed its catalog |
| Lost reply during a write or activation | Inspect SAP source, locks, and activation state before retrying. A transport error can follow a completed SAP mutation |
