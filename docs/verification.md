# Verification and Troubleshooting

Use a development SAP system, two packages with known objects, a disposable writable object, a test desktop profile, and an Eclipse workspace with the rebuilt plugin. The relay uses the SAP identity signed into that workspace. Record the SAP release and ADT object types used when accepting a deployment. A mock Eclipse bridge can check the wire protocol. Only a real SAP system can confirm the package metadata and write behavior available on that release.

## Build and Automated Checks

Run from the checkout root in PowerShell 7. The first Cargo command resolves a lockfile for a fresh checkout. Once it exists, use the same lockfile for all acceptance runs.

```powershell
cargo +1.95.0 check --workspace --all-targets
cargo +1.95.0 test --locked --workspace --all-targets && cargo +1.95.0 clippy --locked --workspace --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery
cargo +1.95.0 build --locked --workspace --bins
```

The workspace tests exercise certificate and token handling, policy intersections, session ownership, and the desktop stdio path. The desktop integration test uses a local pseudo-terminal for operator input and loopback TLS with a mock Eclipse bridge. Allow the test process to start child processes and bind loopback ports.

### Eclipse Plugin Build

The Eclipse build uses Maven 3.10.0, Tycho 5.0.4, and JDK 21. The plugin targets Java 17. These PowerShell commands select the Maven and JDK installations directly on the development workstation. Adjust the two installation paths if yours differ. The first run needs access to Maven Central and the Eclipse target repository.

```powershell
$env:JAVA_HOME = Join-Path $env:USERPROFILE '.jdks/jbr-21.0.11'
$maven = Join-Path $env:LOCALAPPDATA 'Programs/apache-maven-3.10.0/bin/mvn.cmd'
$eclipseProject = 'java-plugin/sap-adt-mcp-server'
& $maven --version
& $maven -f "$eclipseProject/pom.xml" clean verify
```

Check the version banner for Maven 3.10.0 and your chosen JDK. A successful reactor build creates the update site in `com.sap.adt.mcp.server.site/target/repository` under the Eclipse project and a ZIP in the adjacent `target` directory. Install the site in the acceptance workspace before running the manual checks. [Eclipse update site guide](eclipse-update-site.md)

### Java Package-Policy Harness

Run this block in the same PowerShell session. The standalone harness uses an in-memory SAP client to exercise scope parsing, object identity, search filtering, and rejection of unverified targets. Each run compiles into a fresh temporary directory with the selected JDK and bundled Gson. Successful completion produces exit code zero.

```powershell
$plugin = Join-Path $eclipseProject 'com.sap.adt.mcp.server.plugin'
$gson = Join-Path $plugin 'gson-2.11.0.jar'
$classes = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "sap-adt-policy-$([guid]::NewGuid())")
& "$env:JAVA_HOME/bin/javac.exe" --release 17 -cp $gson -sourcepath "$plugin/src" -d $classes.FullName "$eclipseProject/tests/PackagePolicyRegression.java"
if ($LASTEXITCODE -ne 0) { throw "Harness compilation failed with exit code $LASTEXITCODE." }
& "$env:JAVA_HOME/bin/java.exe" -ea -cp "$($classes.FullName);$gson" com.sap.adt.mcp.server.PackagePolicyRegression
if ($LASTEXITCODE -ne 0) { throw "The package-policy harness failed with exit code $LASTEXITCODE." }
```

## Acceptance Matrix

| Check | Procedure | Expected Result |
| --- | --- | --- |
| Registration closed | Start `serve` without flags. Attempt a new desktop enrollment. | Enrollment stays closed. No pending row or token appears. |
| Operator toggle | Press **O** in Enrollment, submit a request from another workstation, compare the displayed full ID and role, then deny it. | The request disappears and the workstation receives no identity. |
| Initial open state | Restart interactively with `--issue-token`. | Enrollment starts open. **O** closes it. A later restart without the flag starts closed again. |
| Two-party enrollment | Approve one Eclipse and one desktop request. Enter each operator-issued token at its respective workstation. Try an expired or already claimed token. | Only the valid single-use claim issues a profile. The operator can identify both certificates in Clients. |
| Unattended headless | Stop the TUI, restart with `--headless` and the same PKI. Reconnect existing clients and try a fresh enrollment. | Logs go to stderr, the enrollment port stays closed, and existing clients use the saved policy. |
| Headless operator console | From an attached terminal, start `serve --pki <dir> --headless --issue-token` with stdout and stderr redirected to separate files. Deny one request. Compare another requester’s full ID, role, and label, then enter `approve <number>` using the matching console row. Claim the displayed token. | The prompt and token appear on the operator terminal. Neither capture contains the token. Normal diagnostics appear in the stderr capture. The denied requester receives no identity, and the approved requester can connect. |
| Missing operator terminal | Launch the combined flags in a service or CI session without a controlling terminal. | Startup fails before either listener accepts connections. Plain `--headless` can still serve existing identities in that environment. |
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

Collect screenshots of the Enrollment list, Clients, the Access Rules editor, Logs, and the Eclipse registration and connection views. Include a small terminal and a normal-size terminal. Redact enrollment tokens, profile contents, fingerprints, request metadata, and company-specific values before sharing. Record which checks ran, which succeeded, the first failure, and the exact toolchain used.

## Troubleshooting

| Symptom | Where to Look |
| --- | --- |
| Operator terminal unavailable | Use plain `--headless` for an unattended service. For headless enrollment, launch the combined flags in a session with a usable operator terminal under the same service identity. |
| Startup fails to bind | Check the configured addresses, port conflicts, and service permissions. The TUI and the headless approval console use distinct data and enrollment ports. |
| Request missing | Check registration state, reachability of the enrollment port, and the registration URL. Use **Enrollment** in the TUI or `pending` on the approval console. Plain `--headless` leaves this port unbound. |
| Enrollment reports a wrong CA, invalid token, or hostname | Compare the full local request ID and issued token over the trusted channel. Verify the enrollment hostname and the DNS or IP in the server certificate. Reapply and approve a new request if the grant expired. |
| Identity rejected after restart | Check the service account and PKI directory, leaf expiration, role, and fingerprint in Clients. A desktop identity accesses `/mcp`; an Eclipse identity uses `/bridge`. |
| No tools or fewer tools than expected | Connect the updated Eclipse plugin and SAP session, then inspect global and desktop policy. A restricted empty list allows nothing. Reconnect a host that caches its discovery results. |
| Scoped lookup returns no result | Compare the object's owning package with both allowlists. Missing or ambiguous SAP ownership metadata prevents a scoped result. Package prefixes match names rather than the SAP package hierarchy. |
| Host reports invalid stdio JSON | Confirm it launches the portable client with `connect --profile`, using absolute paths, directly in its MCP configuration. Enrollment and server startup are separate commands. |
| SAP rejects the request | Check the Eclipse-to-SAP HTTPS trust, SAP login, SAP authorizations, object state, and transport requirements. Relay policy grants cannot expand the SAP account's rights. |
| Lost reply during a write | Inspect SAP for changed source, activation, and outstanding locks. Reconcile the object before deciding to repeat the request. |

Use the server's **Logs** tab or the service's stderr stream. Keep workstation and SAP diagnostics associated with the same request and time. Never paste a private key, an enrollment token, profile JSON, or a SAP password into a defect report.

## Final Formatting

After the owner completes checks and visual verification, run formatting as the final step.

```powershell
cargo +nightly fmt --all
```
