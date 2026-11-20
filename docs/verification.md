# Verification and Troubleshooting

Use a development SAP system, two packages with known objects, a disposable writable object, a test desktop profile, and an Eclipse workspace with SAP ADT and the rebuilt plugin. The relay uses the SAP identity of the explicitly selected ADT project. Record the SAP release and ADT object types used when accepting a deployment. A mock Eclipse bridge can check the wire protocol. Only a real SAP system can confirm the project authentication, session lifecycle, package metadata, and write behavior available on that release. The manual checks below are acceptance procedures, not a record of completed live SAP validation.

## Build and Automated Checks

Run from the checkout root in PowerShell 7. The first Cargo command resolves a lockfile for a fresh checkout. Once it exists, use the same lockfile for all acceptance runs.

```powershell
cargo +1.99 check --workspace --all-targets
cargo +1.99 test --locked --workspace --all-targets --all-features && cargo +1.99 clippy --locked --workspace --all-targets --all-features -- -D warnings -D clippy::pedantic -D clippy::nursery
cargo +1.99 build --locked --workspace --bins
```

The workspace tests exercise certificate and token handling, policy intersections, session ownership, and the desktop stdio path. The link parser is checked against the shared `link-vectors.json`. The desktop integration test uses a local pseudo-terminal for the operator (it mints links with **N**), `enroll --link` for desktops, `/claim` with the link's token for Eclipse identities, `issue-link` for the headless server, and loopback TLS with a mock Eclipse bridge. Allow the test process to start child processes and bind loopback ports.

### Eclipse Plugin Build

The Eclipse build uses Maven 3.10.0, Tycho 5.0.4, and JDK 21. The plugin targets Java 17. These PowerShell commands select the Maven and JDK installations directly on the development workstation. Adjust the two installation paths if yours differ. The first run needs access to Maven Central, the Eclipse target repository, and SAP's public 2024-03 p2 repository for ADT dependencies. Install the result into Eclipse with SAP ADT available.

Keep the checked-in `java-plugin/sap-adt-mcp-server/.mvn/maven.config` in local and CI checkouts, including source archives that might otherwise omit hidden directories. It supplies the temporary `-Dmaven.resolver.validation=MILD` workaround for Tycho 5.0.4's nested JAR classifiers. The normal command below reads that reactor configuration. Remove the workaround when upgrading to a released Tycho containing the merged fix. [Tycho issue 6399](https://github.com/eclipse-tycho/tycho/issues/6399), [fix 6400](https://github.com/eclipse-tycho/tycho/pull/6400)

This build setting reduces coordinate validation to checking uninterpolated placeholders. It is scoped to the Eclipse Maven reactor; runtime TLS and relay authorization are unaffected. Use the configured build dependencies and keep the setting out of global Maven configuration. [Maven 3.10.0 release notes](https://maven.apache.org/docs/3.10.0/release-notes.html)

```powershell
$env:JAVA_HOME = Join-Path $env:USERPROFILE '.jdks/jbr-21.0.11'
$maven = Join-Path $env:LOCALAPPDATA 'Programs/apache-maven-3.10.0/bin/mvn.cmd'
$eclipseProject = 'java-plugin/sap-adt-mcp-server'
& $maven --version
& $maven -f "$eclipseProject/pom.xml" clean verify
```

Check the version banner for Maven 3.10.0 and your chosen JDK. A successful reactor build creates the update site in `com.sap.adt.mcp.server.site/target/repository` under the Eclipse project and a ZIP in the adjacent `target` directory. Install the site in the acceptance workspace before running the manual checks. [Eclipse update site guide](eclipse-update-site.md)

Tycho 5.0.4 may report that SAP JCo artifacts cannot be mapped to Maven Central coordinates. These dependencies resolve from SAP's p2 repository; a successful reactor build confirms their availability. This upstream mapping warning is separate from Java compilation warnings. Tycho's mapping configuration is not exposed in this release. [Tycho issue 6145](https://github.com/eclipse-tycho/tycho/issues/6145)

### Java Package-Policy Harness

Run this block in the same PowerShell session. The standalone harness uses an in-memory SAP client to exercise scope parsing, object identity, search filtering, rejection of unverified targets, and isolation and clearing of explicit lock ownership. Each run compiles into a fresh temporary directory with the selected JDK and bundled Gson. Successful completion produces exit code zero. This harness does not exercise the live ADT connection adapter or native login dialog.

```powershell
$plugin = Join-Path $eclipseProject 'com.sap.adt.mcp.server.plugin'
$gson = Join-Path $plugin 'gson-2.11.0.jar'
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-policy-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/PackagePolicyRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.PackagePolicyRegression
if ($LASTEXITCODE -ne 0) { throw "The package-policy harness failed with exit code $LASTEXITCODE." }
```

### Java Local-Permissions Harness

Run this block from the checkout root in the same PowerShell session. It exercises the local Eclipse permissions and the plugin's role as the authority with in-memory SAP responses: a local read-only policy blocks a write the relay allows, a tool missing from `relayAllowedTools` is refused even when the relay forwarded it, local package patterns intersect with the relay's scopes, the lock flag makes the store read-only, and `RelayRequests` verifies the shared tool table when it is built. This harness and the package-policy harness read the table from `resources/tools.json` in the source tree (override with `-Dtools.json=<path>`) and need no Eclipse jars.

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-local-policy-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/LocalPolicyRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.LocalPolicyRegression
if ($LASTEXITCODE -ne 0) { throw "The local-permissions harness failed with exit code $LASTEXITCODE." }
```

### Java Legacy-Switch Harness

Run this block from the checkout root in the same PowerShell session. It exercises the preference **Allow unencrypted relay calls** (`relay.allowUnencrypted`): with the switch off, a legacy `tools/list` and `tools/call` are refused with `-32002` and the text "This Eclipse accepts only end-to-end encrypted calls. Pair this desktop with Pair Desktop in the MCP view.", the refusal is logged with the layer "this Eclipse's encryption setting", and `relay/hello` and `ping` still answer; with it on, behaviour is unchanged; a change applies to the next call; a locked administrator value wins over the user's value; an unreadable value counts as off. It needs no Eclipse jars.

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-legacy-switch-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/LegacySwitchRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.LegacySwitchRegression
if ($LASTEXITCODE -ne 0) { throw "The legacy-switch harness failed with exit code $LASTEXITCODE." }
```

### Java Link Harness

The link parser must agree with the Rust parser, so this harness reads the shared vectors in `link-vectors.json`: every valid vector must parse to exactly the listed fields and round-trip through build and parse, and every invalid vector must fail with exactly the listed error code. Run it in the same PowerShell session.

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-link-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/RelayLinkRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.RelayLinkRegression "$eclipseProject/tests/link-vectors.json"
if ($LASTEXITCODE -ne 0) { throw "The link harness failed with exit code $LASTEXITCODE." }
```

### Java Enrollment Harness

This harness checks that the enrollment trust manager accepts a chain only when it contains the CA pinned by the link's token (and the pinned CA issued the leaf), refuses any other chain before a secret could be sent, and maps an eclipse enrollment link to the bridge URL and registration origin. It uses fixed test certificates and needs no network.

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-enroll-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/RelayEnrollmentRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.RelayEnrollmentRegression
if ($LASTEXITCODE -ne 0) { throw "The enrollment harness failed with exit code $LASTEXITCODE." }
```

### Java Pairing Harness

Run this block in the same PowerShell session. It exercises the plugin side of pairing with an injected clock and confirmation dialog: a link is single use and expires after 5 minutes, a new link cancels the previous one, a wrong secret is refused (and five wrong secrets burn the link), a refused or unanswered dialog refuses and burns the secret, the token's second half equals the plugin's inner-key fingerprint, labels from the relay are cleaned, and no secret reaches the log. It needs no network and no Eclipse jars.

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-pairing-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/PairingRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.PairingRegression
if ($LASTEXITCODE -ne 0) { throw "The pairing harness failed with exit code $LASTEXITCODE." }
```

### Java Stream-Requests Harness

Run this block from the checkout root in the same PowerShell session. It drives the encrypted-stream MCP session with an in-memory SAP client: `initialize`, then `tools/list` and `tools/call` through the execution path the legacy bridge shares, calls before `initialize` refused, a per-desktop restriction (read-only, tool list, package patterns) applying to its own key fingerprint only, the relay's allowed tools and package scopes still applying, and an unpinned peer limited to `pair/claim` with one generic refusal. It reads the tool table like the local-permissions harness (override with `-Dtools.json=<path>`).

```powershell
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-streams-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/StreamRequestsRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.StreamRequestsRegression
if ($LASTEXITCODE -ne 0) { throw "The stream-requests harness failed with exit code $LASTEXITCODE." }
```

### Java Tool-Catalog Harness

Run this block in the same session as the previous one. The harness instantiates all 15 tools, compares each declared class with `resources/tools.json`, checks the package-awareness and component entries, and confirms that `ToolCatalog.verify` rejects a mismatching or unlisted tool. The plugin root is on the class path so the bundled `/resources/tools.json` resolves. The Rust side is covered by the `policy` unit tests in `cargo test`.

```powershell
$tools = Join-Path $plugin 'resources/tools.json'
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-tools-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/ToolCatalogRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson;$plugin" com.sap.adt.mcp.tools.ToolCatalogRegression $tools
if ($LASTEXITCODE -ne 0) { throw "The tool-catalog harness failed with exit code $LASTEXITCODE." }
```

### Java Tunnel Harnesses

Three harnesses cover the end-to-end tunnel in the plugin (package `com.sap.adt.mcp.server.e2e`). `TunnelProtocolRegression` round-trips the golden control frames copied from `src/tunnel_proto.rs` byte for byte and checks the envelope rules, data-frame and message-reader limits and seeded random input. `InnerKeysRegression` checks that the hand-written DER certificate parses with `CertificateFactory`, verifies, and keeps a stable SPKI fingerprint, and that the key storage never silently rotates a damaged identity. `InnerChannelRegression` runs a JDK `SSLEngine` client (TLS 1.3, its own key) against the plugin's inner channel: a pinned key is accepted, an unpinned key and another cipher suite are refused, an open pairing gate admits an unknown key that may then only send `pair/claim`, and through the stream table a changed envelope, a wrong `seq`, an unannounced message and a relay identity change all close the stream, while each response carries the status `ok`, `error` or `denied`. The last harness reads the shared tool table from the source tree, so run all three from the checkout root in the same PowerShell session (override the table with `-Dtools.json=<path>`).

```powershell
foreach ($name in 'TunnelProtocolRegression', 'InnerKeysRegression', 'InnerChannelRegression') {
    $classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-$name-$([guid]::NewGuid())")
    & "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/$name.java"
    if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
    & "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" "com.sap.adt.mcp.server.e2e.$name"
    if ($LASTEXITCODE -ne 0) { throw "The $name harness failed with exit code $LASTEXITCODE." }
}
```

### Rust and Java TLS interop

The Rust client's inner TLS (`src/inner_tls.rs` in the shared library, the same code the desktop client runs) connects over loopback TCP to the plugin's real `InnerChannel`, served by `java-plugin/sap-adt-mcp-server/tests/InteropServer.java`. The test checks that the handshake completes with TLS 1.3 and `TLS_AES_256_GCM_SHA384`, that the key the client sees equals the server's `PIN` line, that two length-prefixed JSON-RPC messages (one of about 180 KB) are echoed unchanged, that a client key the server has not pinned is refused, that a pairing-mode server (`any`) accepts an unknown client key, and that a client with a wrong server pin fails with the mismatch flag set.

Prerequisites: `JAVA_HOME` points at a JDK 17 or newer (`javac` and `java`), the plugin directory holds its bundled `gson-*.jar`, and loopback TCP is available. The test compiles the harness and the plugin classes it uses into a temporary directory and kills the Java process when it ends. Without `SAP_ADT_INTEROP=1` it prints a note and passes, so a plain `cargo test` needs no Java.

```powershell
$env:JAVA_HOME = Join-Path $env:USERPROFILE '.jdks/jbr-21.0.11'
$env:SAP_ADT_INTEROP = '1'
cargo test --test interop -- --nocapture
if ($LASTEXITCODE -ne 0) { throw "The interop test failed with exit code $LASTEXITCODE." }
Remove-Item Env:SAP_ADT_INTEROP
```

On Linux run `SAP_ADT_INTEROP=1 JAVA_HOME=/path/to/jdk cargo test --test interop -- --nocapture`.

### Real plugin end-to-end

`tests/e2e_relay.rs` normally runs the relay and the desktop client against a Rust stand-in for the plugin. With `SAP_ADT_INTEROP=1` it also runs the **real Java plugin bridge** (`RelayBridge`, the stream handler and the pairing, started headless by `java-plugin/sap-adt-mcp-server/tests/PluginHost.java` with in-memory keys and a fake SAP client, no Eclipse) against the real relay and the real `sap-adt-mcp-client`:

1. Alice pairs with a link the plugin minted (`allowUnencrypted=false`) and calls `sap_get_source` through `connect`. The fake SAP received the arguments intact, the result arrives, and the relay's whole stderr holds the tool name but neither the argument nor the result marker.
2. Bob never paired, so his `connect` uses the legacy `/mcp` path. His `tools/call` fails with `-32002` ("accepts only end-to-end encrypted calls") and nothing reaches SAP.
3. The plugin restarts with `allowUnencrypted=true` (its keys and pins are in memory, so Alice pairs again). Bob's legacy call now succeeds, which proves the switch and not a broken path.
4. A **rogue relay** that holds the real relay's server certificate (the plugin pins the CA, so it passes the plugin's check) speaks the bridge protocol to a third plugin. It pairs Alice's key, then: a clear-text `tools/call` is refused with `-32002`; a request whose envelope says `sap_get_source` but whose encrypted message calls `sap_set_source` makes the plugin close the stream without a result; a request with a wrong `seq` closes the stream. No SAP call happens.

Prerequisites: `JAVA_HOME` points at a JDK 17 or newer (`javac` and `java`), the plugin directory holds its bundled `gson-*.jar`, and loopback TCP is available. The test compiles `PluginHost.java` and the plugin classes it uses into a temporary directory and kills the Java processes when it ends. Without `SAP_ADT_INTEROP=1` it prints a note and passes.

```powershell
$env:JAVA_HOME = Join-Path $env:USERPROFILE '.jdks/jbr-21.0.11'
$env:SAP_ADT_INTEROP = '1'
cargo test --test e2e_relay -- --nocapture
if ($LASTEXITCODE -ne 0) { throw "The real plugin end-to-end test failed with exit code $LASTEXITCODE." }
Remove-Item Env:SAP_ADT_INTEROP
```

## Acceptance Matrix

| Check | Procedure | Expected Result |
| --- | --- | --- |
| No link, no enrollment | Start `serve` and post a `/claim` with a made-up token, or run `enroll --link` with a link that was never minted. Also request the removed `/request` endpoint. | One generic refusal (403) for the claim and 404 for `/request`. No row appears and nothing is issued. |
| Mint and enroll | Press **N** in Enrollment, choose `desktop`, type a label, copy the link with **C**, and run `enroll --link` on a workstation. Repeat with an `eclipse` link and the Eclipse **Enrollment link** field. | Each link issues exactly one profile for its role and label. The tab and log show "label (role) enrolled from peer". The dialog hides the link on Esc. The operator can identify both certificates in Clients. |
| Link lifetime and reuse | Claim a link twice, let a link run past its 10 minutes, and cancel another with **X** before it is claimed. | The first claim works, and every later attempt gets the generic refusal. The cancelled and expired links issue nothing. |
| Pinned CA | Edit a link so its `e` address points at another TLS server (a different CA), or change a symbol of its token after the first 90 characters. | The client stops with "wrong relay or attacker in the middle" before any secret is sent. The relay still has the link outstanding. |
| Outstanding limit | Mint 16 links without claiming them, then try a 17th in the TUI and with `issue-link`. | Both refuse with the limit message. Cancelling one frees a slot. |
| Unattended headless | Stop the TUI, restart with `--headless` and the same PKI. Reconnect existing clients and mint a fresh link with `issue-link`. | Logs go to stderr, the enrollment port stays open for minted links, and existing clients use the saved policy. |
| Headless `issue-link` | On the relay's machine run `issue-link --pki <dir> --role desktop --label "Anna Laptop"` with stdout and stderr redirected to separate files, then enroll with the printed link. Try `POST /issue` without the secret, with a wrong secret, and with an `Origin` header. | Standard output holds only the link and stderr no link or token. Enrollment succeeds once. Every unauthorized `/issue` call gets 403. `issue.secret` is owner-only. |
| Existing ADT project | Authenticate a development ABAP project through ADT, open **Select ABAP Project**, choose it from the Eclipse selector, and connect the relay. Read a known object through the desktop host. Repeat with a project that needs login. | The existing authenticated connection is usable. ADT presents its normal login dialog only when needed, and tool results match the chosen project. |
| Canceled project selection or login | Cancel the project selector, then repeat and cancel a required native login dialog. | No new relay connection is created and no partially authenticated adapter replaces a usable selection. The view remains usable for a later explicit selection. |
| Project binding | While the relay is connected, open an editor and select a Project Explorer item belonging to another ABAP project. Request an object that distinguishes the systems. | Requests continue to use the explicitly selected project. The operator must disconnect before changing that selection. |
| Project closure or authentication loss | Close the selected project or end its SAP login through ADT. Attempt a tool call, then reopen the project, explicitly select it again, and connect the relay. | The unavailable project cannot serve requests and the plugin clears its selection. **Connect Relay** cannot proceed until the operator reselects a project. Native login appears when needed, and the desktop needs a fresh MCP session. |
| Changed project destination | In a disposable test project, change the destination identity while its relay adapter exists, then attempt another call. Explicitly select the intended project again and reconnect. | The old adapter rejects the changed identity and the selection is cleared. Calls resume only through a new adapter bound to the explicitly selected destination. |
| Relay session retirement | Keep an authenticated ADT editor open. Disconnect the relay, reconnect it, then close and reopen the relay view. Select the project again if needed and reconnect. | Each retired adapter discards its own state. The existing ADT editor remains usable without a relay-induced logout. A new relay connection can use the project again. |
| Read-only | List tools from a new desktop. Send a direct `tools/call` for `sap_set_source` even if the host hides it. | Read operations appear. The relay refuses the write before Eclipse receives it. |
| Live action changes | In Access Rules remove search globally. Request discovery and invoke search again using the existing desktop session. Restore the global rule. | The next listing and call honor the saved change. The desktop cannot override a global denial. |
| Package boundary | Set the global allowlist to a prefix and a desktop rule to one exact package within it. Search across both packages. Read a known object inside and outside the intersection. Try changing the package field or sending your own `relayPackageScopes` in a raw call. | Only verified matching rows and object targets are available. Client-supplied scope does not change the server's decision. |
| Scoped write | On the disposable object grant write access and enable source, lock, unlock, and activate. Try the same edit in the excluded package. Disable activation and try the source tool again. | The permitted object changes. The excluded object stays intact. Disabling activation also suppresses the composite source writer. |
| Broad operations | Keep the package filter and request SQL or a test run. | The relay denies operations that cannot enforce the package boundary, even with the individual action enabled. |
| Private endpoints | Enroll Alice's and Bob's desktops and Eclipse workspaces. In **Access Rules**, assign each desktop its own endpoint. List endpoints and set the local selection on both desktops. Ask each host which endpoint it uses and retrieve a known object from that workspace. | Each desktop lists only its own grant, and each tool call reaches the selected workspace. Supplying the other endpoint's fingerprint fails. Read-only rules still apply. |
| Missing selection and live removal | Start an MCP host with a fresh or unconfigured profile. Configure a valid selection, reconnect, then remove its grant during the session. | Initialization reports setup instructions when configuration is missing. The next call after removal fails, and the endpoint disappears from the desktop CLI listing. |
| Bridge replacement | Disconnect Alice's Eclipse during a request while Bob's workspace is active. Reconnect Alice's Eclipse and try the old session. | Alice must initialize a new session. Bob can continue using his workspace. Check SAP directly for the outcome of any interrupted write. |
| Revocation | Revoke the test desktop, then the test Eclipse certificate. Try to reconnect each. | Subsequent desktop requests or bridge authentication fail. A connected bridge loses access on its next call or heartbeat. |
| Persistence | Restart normally with the same PKI after changing policies and revoking a certificate. | Revocations and saved access controls survive. Pending applications and unused grants do not. |

Collect screenshots of the Enrollment list, Clients, the Access Rules editor, Logs, and the Eclipse registration and connection views, including the ABAP project selector and selected-project status. Inspect the native ADT login dialog visually without recording credentials. Include a small terminal and a normal-size terminal. Redact enrollment tokens, profile contents, fingerprints, request metadata, and company-specific values before sharing. Record which checks ran, which succeeded, the first failure, and the exact toolchain used.

## Troubleshooting

| Symptom | Where to Look |
| --- | --- |
| `issue-link` fails | Run it on the relay's machine with the PKI directory `serve` was started with, and pass `--relay <host:port>` if the enrollment listener is not on `127.0.0.1:8788`. `issue.secret` is recreated at every `serve` start. |
| Startup fails to bind | Check the configured addresses, port conflicts, and service permissions. The data and enrollment listeners need distinct ports. |
| Link refused | The client prints one generic refusal for a wrong, used, expired or cancelled link. Check **Enrollment** in the TUI for the outstanding link, then mint a new one. |
| Enrollment reports a wrong relay, wrong CA, or hostname | "Wrong relay or attacker in the middle" means the CA the relay presented differs from the link's token: check the link's origin and the `--public-enrollment` address. For a hostname error, verify the enrollment host in the link against the DNS or IP in the server certificate. |
| Identity rejected after restart | Check the service account and PKI directory, leaf expiration, role, and fingerprint in Clients. A desktop identity accesses `/mcp`; an Eclipse identity uses `/bridge`. |
| No tools or fewer tools than expected | Select an available ADT project in the updated Eclipse plugin and connect the relay, then inspect global and desktop policy. A restricted empty list allows nothing. Reconnect a host that caches its discovery results. |
| Scoped lookup returns no result | Compare the object's owning package with both allowlists. Missing or ambiguous SAP ownership metadata prevents a scoped result. Package prefixes match names rather than the SAP package hierarchy. |
| Host reports invalid stdio JSON | Confirm it launches the portable client with `connect --profile`, using absolute paths, directly in its MCP configuration. Enrollment and server startup are separate commands. |
| SAP rejects the request | Check the selected ADT project's connection, login, SAP authorizations, object state, and transport requirements. If the project selection was invalidated, restore the connection through ADT, select the intended project again, and reconnect the relay. Relay policy grants cannot expand the SAP account's rights. |
| Lost reply during a write | Inspect SAP for changed source, activation, and outstanding locks. Reconcile the object before deciding to repeat the request. |

Use the server's **Logs** tab or the service's stderr stream. Keep workstation and SAP diagnostics associated with the same request and time. Never paste a private key, an enrollment token, profile JSON, or a SAP password into a defect report.

## Final Formatting

After the owner completes checks and visual verification, run formatting as the final step.

```powershell
cargo +nightly fmt --all
```
