# Security model

This document says what the relay, the desktop client and the Eclipse plugin protect, against whom, and which settings must be in place for that protection to hold. The design is in [plan-e2e-envelope.md](plan-e2e-envelope.md).

## What is protected

Tool arguments and results (source code, SQL, object data) travel between the desktop client and the Eclipse plugin inside a TLS 1.3 session that only those two ends can read. The relay forwards the encrypted bytes and a small readable **envelope** per request: the method, the tool name and the action class (`read`, `execute`, `write`). The relay enforces its rules on the envelope. The plugin rebuilds the envelope from the decrypted request and refuses any difference, and it applies its own **local permissions**. The stricter side always wins.

## Threat model

| Attacker | Without the measures below | With the measures in place |
| --- | --- | --- |
| Compromised relay reads source code, SQL, arguments or results | Possible: the relay terminates both outer TLS connections | Prevented for paired desktops: payloads are encrypted between keys that the two ends pinned when they paired |
| Compromised relay sends its own tool calls to Eclipse | Possible | Prevented: it cannot produce a valid encrypted request, and the plugin refuses clear-text calls once the plugin switch is off |
| Compromised relay alters a request in transit | Possible | Prevented: any envelope mismatch or decryption failure is refused and closes the stream |
| Compromised relay downgrades to the clear-text path | Possible | Prevented only when **Allow unencrypted relay calls** is off in Eclipse **and** the client holds a pin for the endpoint |
| Compromised relay loosens its own rules | Effective | Limited by this Eclipse's local permissions, which can only restrict |
| Desktop, or the model behind it, exceeds its permissions | Stopped by the relay | Stopped by the relay (envelope) and by the plugin (envelope check and local permissions) |
| Enrollment or pairing link leaks to a third party before use | Possible | Single use and short lifetime (10 minutes for enrollment, 5 for pairing); a new desktop has no grants; pairing also needs a confirmation click in Eclipse that shows the desktop key's fingerprint |
| Relay observes who talks to whom, when, which tool, and sizes | Yes | Yes, by design (see below) |
| Relay blocks or delays traffic | Yes | Yes (availability is out of scope) |
| Attacker on the desktop or Eclipse machine itself | Out of scope | Out of scope |

### What was built

- **Enrollment links** (`sap-adt://enroll?...`): the operator mints a one-time link; the client checks the relay's CA against the fingerprint in the link before it sends the secret.
- **Pairing links** (`sap-adt://pair?...`) with confirmation: minted by the plugin, copied on the same machine, claimed through the relay inside a session pinned to the plugin's key. Eclipse asks "Pair <label>?" and shows the desktop key's short fingerprint; no answer within 2 minutes counts as refusal.
- **Inner TLS 1.3** between client and plugin: ECDSA P-256 keys, one cipher suite, client certificate required, no resumption. Each side trusts only the key it pinned.
- **Envelope check** in the plugin: method, tool, action class and sequence number are derived from the decrypted request and compared with the relay's envelope.
- **Local permissions** in Eclipse (**Preferences → MCP Relay → Permissions**): read-only, a tool list and package patterns, globally and per paired desktop. An administrator can preset and lock them.
- **`require_e2e`** on the relay (global, and per endpoint): when on, the relay refuses `/mcp` sessions and accepts only tunnel streams. It cannot protect against the relay itself.
- **The plugin switch** **Allow unencrypted relay calls** (`relay.allowUnencrypted`): when off, this Eclipse refuses legacy clear-text `tools/list` and `tools/call` from the relay.
- **No downgrade once paired**: when `peers.json` pins the selected endpoint, the client never uses `/mcp`.

### Caveat: the compromised-relay protections depend on the plugin switch

A relay that is compromised can ignore its own `require_e2e` setting and send a clear-text `tools/call` over the legacy bridge path. Only this Eclipse can stop that. The protections against a compromised relay in the table therefore hold **only once**:

1. the desktop is paired with the Eclipse (so the client has a pin and never falls back), and
2. **Allow unencrypted relay calls** is off in that Eclipse.

In the current version the switch is **on** by default, so a freshly installed Eclipse still answers clear-text calls. Until the switch is off, a compromised relay can read what passes over the legacy path and send tool calls within this Eclipse's local permissions. The switch is lockable: with `permissions.locked=true` set by the administrator, the value comes from the administrator layers only (`plugin_customization.ini` or the configuration scope), and a user value is ignored.

When the switch is off, the plugin answers legacy `tools/list` and `tools/call` with error `-32002` and the text "This Eclipse accepts only end-to-end encrypted calls. Pair this desktop with Pair Desktop in the MCP view." `relay/hello` and `ping` still work, so the relay keeps the bridge connection. Encrypted streams are not affected. The MCP view shows "Unencrypted relay calls: allowed" or "blocked" and logs each refusal with the layer "this Eclipse's encryption setting". The setting is read on every call; no restart is needed.

The compromised-relay claims above (no payload in the relay's logs, a forged envelope or wrong `seq` closes the stream, clear-text calls refused with the switch off) are exercised against the real Java plugin bridge, the real relay and a rogue relay by the opt-in test described under "Real plugin end-to-end" in [verification.md](verification.md) (`SAP_ADT_INTEROP=1`, `cargo test --test e2e_relay`).

## What the relay still sees

- The identity (certificate fingerprint and label) of each desktop and Eclipse, peer addresses, and connection times.
- For every request: the method, the tool name, the action class, the sequence number, and message sizes in both directions.
- Whether an inner handshake completed (a stream's state), but not which keys were pinned.
- Its own measured response time.

Object names, package names, source, SQL text, arguments and results are not in the envelope and are not visible to the relay on an encrypted stream. On the legacy path and for unpaired desktops the relay sees everything, as before.

The relay can still word its own refusals, so on an encrypted stream the desktop client passes on only the fixed texts the relay is known to send (`tunnel_proto::close` and `tunnel_proto::deny`). Any other close or denial text is replaced by a generic message before the MCP application sees it, so a compromised relay cannot put instructions of its own in front of the model. When the relay closes a stream before a request was sent, the client also says that the tool did not run.

## Out of scope

- Hiding metadata and traffic analysis.
- A compromised desktop or Eclipse machine, or malware running as the same user.
- Availability: a relay can drop, delay or refuse traffic.
- A link that leaks and is used before its legitimate holder uses it (limited by single use, short lifetime and the pairing confirmation, not prevented).
- Sending a pairing link through the relay itself. Copy it on the local machine.
- The security of the SAP system and of the ADT login, which the Eclipse project owns.

## Keys and where they are stored

| Key or secret | Where | Notes |
| --- | --- | --- |
| Relay CA private key, `issue.secret` | Relay PKI directory | Owner-only files; `issue.secret` is recreated at every start |
| Desktop relay identity (mTLS certificate and key) | Client profile directory (`credentials.json`) | Created at enrollment; certificates last 365 days |
| Eclipse relay identity | Workspace file `relay-profile.enc`, wrapping key in Eclipse secure storage | Per workspace |
| Desktop inner identity key (ECDSA P-256) | Client profile: `inner_key.pem`, `inner_cert.pem` | Keep as private as `credentials.json` |
| Pinned Eclipse keys | Client profile: `peers.json` | One pin per paired endpoint |
| Eclipse inner identity key (ECDSA P-256) | Eclipse secure storage, scoped to the workspace | Blob `innerKey` |
| Pinned desktop keys | Eclipse secure storage, scoped to the workspace | Blob `innerPins`; keyed by the desktop's inner-key fingerprint |
| Local permissions and the plugin switch | Eclipse instance-scope preferences; administrator presets in `plugin_customization.ini` | Keys: `permissions.readOnly`, `permissions.allowedTools`, `permissions.packagePatterns`, `permissions.locked`, `relay.allowUnencrypted` |

The pin is the SHA-256 of the key's SubjectPublicKeyInfo, not of a certificate. The relay's CA plays no role in the inner session.

Administrator preset example:

```properties
com.sap.adt.mcp.server.plugin/relay.allowUnencrypted=false
com.sap.adt.mcp.server.plugin/permissions.locked=true
```

## Rotate and revoke

- **Unpair a desktop.** On the desktop run `sap-adt-mcp-client unpair --profile <dir> --endpoint <id-or-label>`, and remove the desktop in Eclipse's MCP view (this also removes its per-desktop permissions). Do both: either side alone stops the encrypted path, but a stale pin on the other side stays.
- **Remove a pin.** Removing the Eclipse's pin in the client or the desktop's pin in the plugin ends trust for that key. Pair again to create a fresh one.
- **Replace a lost or copied profile.** Revoke the old certificate in the relay's **Clients** tab, enroll a new profile, and pair again. Copying a profile copies its identity and its pins.
- **Revoke the relay certificate.** In **Clients**, compare the full fingerprint and revoke it. Requests already admitted may complete. Revoking a certificate stops the outer connection; it does not change the pinned inner keys.
- **Rotate the inner key.** Remove the pin on both sides and delete the key (`inner_key.pem` and `inner_cert.pem` in the client profile, or re-create the Eclipse workspace's secure-storage entry by resetting the Eclipse plugin state), then pair again. All peers must pair again.
- **Lost secure storage.** A moved workspace or lost secure-storage key loses the Eclipse's inner key and pins. Re-pair every desktop.

## Migration

The new path runs beside the old one, is switchable, and the old one is removed after one version.

| Version | Relay | Plugin | Client |
| --- | --- | --- | --- |
| N (this version) | Tunnel available; `require_e2e` off; `/mcp` still served | **Allow unencrypted relay calls** on (default) | Uses the tunnel when a pin exists for the selected endpoint; otherwise `/mcp` with a warning on stderr |
| N+1 | `require_e2e` on by default | **Allow unencrypted relay calls** off by default | Same |
| N+2 | `/mcp` and legacy bridge calls removed | Preference removed | `/mcp` code removed |

Steps for each Eclipse and desktop, in version N:

1. Enroll the desktop and the Eclipse with enrollment links.
2. The operator grants the Eclipse endpoint to the desktop.
3. Pair each desktop with **Pair Desktop**.
4. Turn off **Allow unencrypted relay calls** in the Eclipse (or lock it by `plugin_customization.ini`).
5. Turn on `require_e2e` on the relay, per endpoint first, once the TUI shows no desktop still on the old path.

Turning on `require_e2e` or the plugin switch before every desktop is paired locks the unpaired desktops out; they get an error until they pair. Both settings are reversible.
