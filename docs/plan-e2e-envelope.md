# Plan: end-to-end encryption with a policy envelope

Status: plan only, nothing implemented. All decisions are made (see [Decisions](#decisions), D1–D12, decided 2026-11-20 after a code review of relay, client and plugin).

Both trust steps, enrolling with the relay (§0) and pairing desktop with Eclipse (§1), use **one-time links**, the pattern Pleochroma already uses (`pleochroma-net`: `pairing` for the link, `token` for `GW1-` encoding, `enroll::claim` for the pinned claim). The side that grants access mints a link. The other side pastes it, checks the pinned key from the link before sending anything, and claims once. There is no request/approve/code ping-pong.

## Goal

The desktop client and the Eclipse plugin talk to each other through the relay, but the relay can no longer read the tool arguments or results, and it can no longer create or change requests. The relay keeps enforcing its access rules, because each request carries a small readable **envelope** (method, tool, action class). The plugin derives the same envelope from the decrypted request and refuses any difference, and it also applies its own **local permissions** from the Eclipse settings. The stricter of the two always wins.

### Threat model

| Attacker | Today | After this plan |
| --- | --- | --- |
| Compromised relay reads source code, SQL, arguments, results | Possible (the relay terminates both TLS connections) | Prevented: payloads are encrypted between keys the two ends pinned at pairing |
| Compromised relay sends its own tool calls to Eclipse | Possible | Prevented: it cannot produce a valid encrypted request |
| Compromised relay alters a request in transit | Possible | Prevented: the plugin refuses any envelope mismatch or decryption failure |
| Compromised relay downgrades to the old clear-text path | Possible | Prevented once the plugin's "Allow unencrypted relay calls" is off and the client has a pin for the endpoint (§7) |
| Compromised relay loosens its own policy | Effective | Limited by the plugin's local permissions |
| Desktop (or the model behind it) exceeds its permissions | Stopped by the relay | Stopped by the relay (envelope) and the plugin (envelope check and local policy) |
| Relay sees who talks to whom, when, which tool, message sizes | Yes | Yes (deliberate: needed for policy and monitoring) |
| Relay blocks or delays traffic | Yes | Yes (out of scope: availability) |
| Attacker on the desktop or Eclipse machine itself | Out of scope | Out of scope |

The compromised-relay rows hold only once the plugin refuses unencrypted relay calls (N+1 default, §7); `docs/security-model.md` must say so.

Non-goals: hiding metadata (traffic analysis), protecting against a compromised endpoint machine, protecting against an enrollment or pairing link that leaks to someone else before it is used (single use, short lifetime, D10; pairing also needs a click in Eclipse, D12).

## Target architecture

```
Desktop host ──stdio── sap-adt-mcp-client ══ outer mTLS (relay PKI) ══ relay ══ outer mTLS (relay PKI) ══ Eclipse plugin ── ADT ── SAP
                              │                                          │                                     │
                              └──────────── inner TLS 1.3, pinned keys (pairing) ──────────────────────────────┘
                                         envelope (readable)  +  payload (inner TLS byte stream)
```

- **Outer layer (unchanged PKI):** relay-issued certificates authenticate both ends *to the relay*. This is access control only: which desktop may open a stream to which endpoint (today's endpoint grants).
- **Inner layer (new):** a TLS 1.3 session per stream between the client (TLS client) and the plugin (TLS server), ECDSA P-256 keys (D1). Each side trusts only the peer key it pinned during pairing. The relay CA plays no role here.
- **Envelope:** a small JSON object sent in clear with each request. The relay enforces its rules on it; the plugin derives it from the decrypted request and compares.

## 0. Enrollment links (replace request, approval and token typing)

Today registering a desktop or Eclipse takes four steps: the client sends `/request` and waits up to 180 s, the operator compares the request ID and approves in the TUI, the TUI shows a `GW1-` token, and the user types it into the client, which claims it. The relay's token already has Pleochroma's format (32-byte secret plus the CA fingerprint, Crockford Base32, `GW1-` prefix, see `enrollment.rs` `encode`), so only the flow around it changes.

### New flow
1. **The operator mints a link.**
   - TUI, Enrollment tab: **N New link**, choose the role (`desktop` or `eclipse`) and a label.
   - Headless: `sap-adt-mcp-server-relay issue-link --pki <dir> --role desktop --label "Anna Laptop"`. This is `POST /issue` on the enrollment listener, accepted only from a loopback peer that presents the operator secret from `<pki>/issue.secret` (owner-only file, constant-time compare) and sends no `Origin` header, like Pleochroma's `IssueAuthorized`.
   - The relay stores a hash of the secret with role, label and expiry. Single use, 10 minutes, at most 16 outstanding links (today's `WINDOW_CAP`) (D10).
2. **The relay shows the link** with **C Copy** (OSC 52, as for tokens today). Copy and paste only, no QR code (D8):
   ```text
   sap-adt://enroll?v=1&r=desktop&n=Gussek+Relay&s=relay.gussek.at:8787&e=relay.gussek.at:8788&t=GW1-...
   ```
   | Key | Meaning |
   | --- | --- |
   | `v` | link version (`1`) |
   | `r` | role the link grants: `desktop` or `eclipse` |
   | `n` | relay display name |
   | `s` | data (mTLS) address, `host:port`, DNS names allowed |
   | `e` | enrollment address, `host:port` |
   | `l` | label the certificate gets (optional; the relay's stored label wins) |
   | `t` | the `GW1-` token: secret plus CA fingerprint. A secret. |

   The `sap-adt://` scheme is never registered as an operating-system handler; links are only pasted.
3. **The client claims.**
   - Desktop: `sap-adt-mcp-client enroll --link "<link>" --profile <dir>`. The old `--server/--enrollment/--label` flags go.
   - Eclipse: the Register dialog gets one field, **Enrollment link**, instead of label, registration URL and bridge URL. The bridge URL is derived from `s`.
   - Both pin the CA from the token **before** sending the secret, and refuse on mismatch with wording like Pleochroma's `CaFingerprintMismatch` ("wrong relay or attacker in the middle"). In Java this needs a trust manager that checks the presented chain's CA (`chain[chain.length - 1]`, which the enrollment listener already sends) against the fingerprint during the handshake; today `PresentedAuthority` trusts provisionally and compares afterwards (`RelayEnrollment.java`, lines 73–86).
   - They send the secret over `/claim`, and store the bundle and the `s` address in the profile.
4. **The relay confirms** by consuming the token and issuing the certificate for the stored role and label. The Enrollment tab and log show "Anna Laptop (desktop) enrolled from 62.47.170.42". `/claim` answers one generic 403 for a wrong, used, expired or cancelled link.

There is no operator confirmation on claim and no setting for it (D11): minting the link is the approval. A stolen link gains little, because a new desktop starts read-only with no endpoint grants (`Rules::desktop_default()`, empty `endpoint_grants`), and a rogue Eclipse is unreachable until the operator grants it.

### Consequences
- **Registration is never "open" to anyone anymore.** `/request`, the registration window, `--issue-token`, the headless console prompt, the refused-while-closed counter and the request-ID comparison all go. The enrollment listener always runs, but only accepts `/claim` for minted, unexpired links and loopback `/issue`.
- **The link is a bearer secret until used:** whoever has it within the lifetime gets that role. The relay never logs it, errors never echo it, and the TUI hides it again after copying.
- **Wrong-port mistakes go away**, because the link carries both addresses.
- Certificate lifetime, revocation and the `GW1-` format stay the same. Unused links can be listed and cancelled in the TUI (**X Cancel link**).
- **Java:** a link parser with the same rules as Pleochroma's `PairingLink::parse`. The existing `RelayEnrollment.tokenFingerprint` already decodes `GW1-`.

## 1. Keys and pairing

### Keys
- Each client profile and each Eclipse workspace gets one long-term **inner identity key**, ECDSA P-256 (D1), separate from its relay certificate. The pin is the SHA-256 of the key's SubjectPublicKeyInfo DER, not of the certificate.
- **Client:** `inner_key.pem` (private, `storage::write_new` rules as for credentials) and `peers.json` (pinned endpoint keys, by endpoint ID) in the profile directory. Its self-signed certificate comes from rcgen, already a dependency.
- **Plugin:** private key in Eclipse secure storage next to the existing relay identity (`RelayProfileStore`). Pins are keyed by the **desktop's inner-key fingerprint** (the identity proven in the inner handshake); the desktop's relay fingerprint and label are stored as attributes only. A later stream whose relay fingerprint differs from the stored one for that key is refused with "pair again", because the relay fingerprint in `open` is only asserted by the relay.
- **Plugin certificate:** the JDK has no public X.509 builder and the bundle ships only gson, so the plugin writes a minimal self-signed DER certificate itself (fixed template, P-256 key, `SHA256withECDSA` signature). No BouncyCastle. It is served through a custom `X509ExtendedKeyManager`, and peers are checked by an `X509ExtendedTrustManager` that compares the key fingerprint. Validity dates and names are ignored; only the pinned key matters.

### Pairing link (once per desktop profile and endpoint)
The same link pattern as §0, but minted by **the plugin**, carried **outside the relay** (clipboard; Eclipse and the desktop host usually run on the same machine), and claimed **through** the relay inside a pinned inner TLS session. The relay forwards the bytes but can't read them, and it can't impersonate the plugin because the link pins the plugin's key.

The operator must already have granted this endpoint to the desktop: the pairing stream's `open` goes through the normal grant check.

1. In Eclipse, the MCP view's **Pair Desktop** creates a one-time pairing secret (32 bytes, single use, 5 minutes, one outstanding: a new link cancels the previous one, D10) and shows the link with **Copy**:
   ```text
   sap-adt://pair?v=1&p=<endpoint id>&n=EclipseLaptop&t=GW1-...
   ```
   `p` is the endpoint ID (the plugin's relay fingerprint), `n` its label. `t` is a `GW1-` token whose two halves are the **pairing secret** and the **SHA-256 fingerprint of the plugin's inner key** (in place of the CA fingerprint in §0).
2. On the desktop: `sap-adt-mcp-client pair --profile <dir> --link "<link>"`. The client:
   - opens a stream to endpoint `p` through the relay;
   - runs the inner TLS handshake with its own inner key as the client certificate, and accepts the plugin only if its key matches the fingerprint in the link (Pleochroma's `PinnedCaVerifier` pattern, refusing with "wrong Eclipse or attacker in the middle");
   - sends `pair/claim {secret}` **inside** the encrypted session, and prints the short fingerprint of its own inner key on stderr while it waits.
3. The plugin accepts an unknown client key only while a pairing link is outstanding, and such a stream may carry only `pair/claim`. It checks the secret (constant-time compare, unused, not expired), then shows a non-blocking dialog (D12): **"Pair <label>?"** with the relay-supplied label (marked as coming from the relay) and the short fingerprint of the desktop's inner key. No answer within 2 minutes counts as refused.
4. On confirmation the plugin pins the key, answers `pair/ok`, and burns the secret. The client stores the plugin's key in `peers.json` and saves this endpoint as the selected one.
5. **Unpair:** `sap-adt-mcp-client unpair --endpoint …` removes the pin locally; the plugin's MCP view lists paired desktops (label, key fingerprint, paired since) with a remove button.

Why this is enough against a relay in the middle: the relay never sees the link, so it doesn't know the plugin's key fingerprint ahead of the user, and it can't complete a handshake that matches it. Nor can it learn the secret, which only travels inside the pinned session. One paste plus one click replaces a code comparison and a commitment exchange. The click with the comparable fingerprint also covers a link that leaked. Failed claims (wrong key, wrong or used secret, refused click) are logged on both ends with the same generic refusal wording as Pleochroma's `ClaimFailed`, so a prober learns nothing.

## 2. Wire protocol

### Outer transport
- **Desktop to relay:** today one HTTPS POST per MCP message to `/mcp`. New: one persistent WebSocket `GET /tunnel` (mTLS, data port) per client process; it carries any number of streams. The client still uses `/endpoints` over plain HTTPS for the endpoint list.
- **Relay to plugin:** the existing `/bridge` WebSocket. The plugin announces support in `relay/hello` (`policyVersion: 2`, `e2e: 1`).
- Frame format: a JSON control text frame, or a binary data frame `[u32 stream][u8 kind][bytes]` of at most 64 KiB.

### Inner TLS (D2)
- TLS 1.3 only, cipher suite `TLS_AES_256_GCM_SHA384` only, key-exchange groups x25519 and secp256r1, signature scheme `ecdsa_secp256r1_sha256`, client certificate required, no session resumption, no 0-RTT.
- Rust uses rustls sans-IO (`read_tls`/`write_tls`), so no async runtime is involved; Java uses `SSLEngine`.
- **The inner TLS is an opaque byte stream per direction.** The JDK may emit records that belong to no request (session tickets, key updates), so the relay never assumes that records line up with messages; it forwards all data frames of a stream, in order.
- Inside TLS, each JSON-RPC message carries a 4-byte big-endian length prefix. Limits follow today's: 4 MiB per request (`mcp.rs` `MAX_BODY`), 8 MiB per response (`RelayRequests.MAX_RESPONSE_BYTES`).
- The inner handshake must finish within 30 s of `open`, or the stream is closed.

### Frames (per stream)
| Frame | Direction | Content |
| --- | --- | --- |
| `open` | client → relay → plugin | stream ID (assigned by the relay), desktop relay fingerprint; the relay adds the desktop label |
| `admit` | client → relay | the envelope; the relay answers `admitted {seq}` or `denied {code, message}` |
| `request` | client → relay → plugin | control frame `{stream, seq, envelope, policy, len}` (policy added by the relay), followed by data frames totalling `len` ciphertext bytes |
| `response` | plugin → relay → client | control frame `{stream, seq, status, len}` (`ok`, `error`, `denied`), followed by data frames |
| `notify` | client → relay → plugin | as `request`, for a JSON-RPC notification (still admitted first) |
| data | both | inner TLS bytes not tied to a request: handshake, tickets, alerts |
| `close` | both | reason |

### Pre-admission
Inner TLS is a stream with sequence numbers: if the relay dropped a denied request's bytes, everything after it on that stream would fail to decrypt. So:
1. The client sends the envelope in `admit`, and only encrypts and sends the payload after `admitted {seq}`. That costs one client–relay round trip per request, not a round trip to Eclipse.
2. **The admission is binding for 30 s.** The relay checks that the `request` envelope equals the admitted one, but does not evaluate policy again at that point, because a late denial would have to drop bytes and break the stream.
3. If the policy becomes stricter or a grant is revoked, the relay **closes** affected streams instead of dropping individual requests. An admitted `seq` with no `request` within 30 s also closes the stream.

### Envelope (schema v1)
```json
{"v": 1, "seq": 17, "method": "tools/call", "tool": "sap_set_source", "class": "write"}
```
- Exactly these fields; unknown fields are refused (D3: no object names, no reserved field).
- `method`: `initialize`, `tools/list`, `tools/call`, `ping`, `notifications/*`, `pair/claim`.
- `tool` and `class`: only for `tools/call`. `class` is `read`, `execute` or `write` from the shared tool table (§4); the relay **recomputes** it from the tool name and refuses a mismatch.
- `pair/claim` has no tool or class and is always admitted on a granted stream; the plugin decides whether it is valid (§1).

### Binding the envelope to the payload
The inner plaintext is the plain JSON-RPC message; no envelope copy travels inside. The plugin **derives** the expected envelope itself and compares it field by field with the one the relay forwarded:
1. `method` from the decrypted message, and for `tools/call` `tool` from `params.name`;
2. `class` from the plugin's own copy of the tool table;
3. `seq` from its own per-stream counter (previous plus one).

Any difference is refused (`-32_003`, logged as a binding failure) and closes the stream: either the relay or the client is misbehaving. This gives the same guarantee as an inner copy, without byte-identical JSON across Rust and Java.

## 3. Responsibilities after the change

### Client (`src/bin/client/`)
- Hosts the MCP session itself: `initialize` is answered end to end by the plugin, through the tunnel.
- Opens one stream per MCP session, runs the inner TLS client with the pinned key, sends `admit`, then `request`.
- Implements `relay_list_endpoints` locally, using `/endpoints`, and adds it to the `tools/list` result it gets from the plugin.
- Keeps today's stdio behaviour, size limits, concurrency limit and error texts.

### Relay
- Authenticates both ends (unchanged), checks the endpoint grant on `open`, and enforces `Rules` (read-only, actions) on each envelope at `admit`.
- Attaches its policy to each forwarded `request` (allowed tools and package scopes, today's `relayPackageScopes`).
- Never sees argument or result content. Logs and the Connections tab use envelope fields only.
- Stream limits (D7): at most 128 streams per bridge (`MAX_SESSIONS` renamed), at most 16 streams per desktop per endpoint, 8-hour idle close (`SESSION_IDLE`), 30 s for the inner handshake. Calls stay serialised per bridge (`Semaphore::new(1)` in `bridge.rs`).
- Removes MCP session handling (`Registry` sessions become streams) once the old path is retired (§7).

### Plugin (`java-plugin/…/server/`)
- New: stream handling, the inner TLS server (`SSLEngine`) with the pinned-key managers from §1, envelope derivation and comparison, and an MCP session per stream.
- Enforces the same stream limits as the relay itself.
- Applies the **effective policy** = relay policy ∩ local policy, to `tools/list` (filtering) and to every `tools/call`. Package checks keep using `RelayPackageScopes`/`ScopedSapCall`. Local package patterns are a **separate** `RelayPackageScopes` instance checked in addition; they never ride in the relay's array, which `RelayPackageScopes.parse` caps at two layers.
- Answers `initialize`, `ping`, `tools/list`, `tools/call`, `pair/claim` (today `RelayRequests` answers only the bridge methods).
- Has the preference **Allow unencrypted relay calls** (§7).

## 4. Shared tool table

Both the relay and the plugin need the same tool names, action class and package awareness. Today they are duplicated: `TOOLS`, `observational()` and `package_aware()` in `src/policy.rs`, and the tool classes in Java.

- Add `tools.json` to the repository as the single source: name, class (`read`/`execute`/`write`), package-aware, and component actions (for example `sap_set_source` needing lock, set and unlock).
- The relay embeds it at build time (`include_str!` plus a parse test). The plugin bundles it as a resource and checks at startup that every registered `McpTool` is listed with the class its implementation declares.
- A conformance test in each language fails when code and table diverge.

## 5. Local Eclipse permissions

- A preference page, **MCP Relay → Permissions**, with the same shape as the relay's rules:
  - **Read-only:** only `read` tools allowed.
  - **Tools:** a checkbox list, or all.
  - **Package patterns:** the same syntax and limits as the relay (`MAX_PATTERNS`, case rules).
- **Per-desktop overrides** (D4): one row per paired desktop, keyed by its pinned inner-key fingerprint. Delivered with P5, because before pairing the plugin has no trustworthy desktop identity (a relay-asserted one is worthless against a compromised relay). P1 ships the global local policy only.
- Stored as instance-scope preferences. An administrator can preset them in `plugin_customization.ini` and **lock** them (`permissions.locked=true` disables the page).
- The MCP view shows the effective policy (relay ∩ local) per connected desktop, and every denial says which layer refused it ("Denied by this Eclipse's permissions" vs "Denied by the relay").
- Rule: the local policy can only restrict, never extend what the relay allows.

The global part is independent of the encryption and can ship first (phase P1).

## 6. Statistics and monitoring

The Connections tab keeps its current content, built from outer metadata only:
- **Per bridge:** unchanged (peer, since, state, calls, last tool from the envelope).
- **Per stream** (replaces "session"): desktop label, peer address, stream ID prefix, opened, last activity, request count, last method and tool, last status (`ok`/`error`/`denied`), bytes in and out, and the relay's own measured admit-to-response time.
- **New:** a "paired / unpaired" indicator. The relay knows when a stream completes its inner handshake, but not which keys were pinned.
- No telemetry from the plugin (D5): self-reported numbers would add a clear-text channel for little value.

## 7. Compatibility and migration

Following the engine-replacement rule: the new path runs beside the old one, is switchable, becomes the default when proven, and the old one stays one version, then is removed (D6).

| Version | Relay | Plugin | Client |
| --- | --- | --- | --- |
| N | Tunnel ships; `require_e2e` off; `/mcp` still served | "Allow unencrypted relay calls" **on** | Tunnel when a pin exists for the selected endpoint, otherwise `/mcp` with a stderr warning |
| N+1 | `require_e2e` **on** by default | "Allow unencrypted relay calls" **off** by default | Same |
| N+2 | `/mcp` and legacy bridge calls removed | Preference removed | `/mcp` code removed |

- `relay/hello` advertises `e2e: 1`.
- **Relay `require_e2e`** (global, and per endpoint in the TUI): when on, the relay refuses `/mcp` sessions for that endpoint and only accepts tunnel streams.
- **Plugin switch:** the relay's `require_e2e` cannot protect against the relay itself; a compromised relay could just send a legacy clear-text `tools/call`. So the plugin has its own Eclipse preference **Allow unencrypted relay calls**, lockable like the permissions. Only when it is off do the compromised-relay rows of the threat model hold.
- **No downgrade once paired:** if `peers.json` holds a pin for the selected endpoint, the client never falls back to `/mcp`, whatever the relay claims. Fallback with a warning applies only to unpaired endpoints.
- Docs: README (enrollment link and pairing in setup), operator manual (links, Connections, `require_e2e`), and a new `docs/security-model.md` with the threat model table and the plugin-switch caveat.

## 8. Phases

Each phase ends compilable, with clippy (pedantic plus nursery) clean, tests green, and docs updated.

| Phase | Scope | Main files | Done when |
| --- | --- | --- | --- |
| **PE** Enrollment links (§0) | Loopback `POST /issue` and `issue-link`, TUI **New link**/**Cancel link**, single-use hashed link store (10 min, 16 outstanding), `enroll --link`, Eclipse **Enrollment link** field with a pinning trust manager, link parser in Rust and Java; `/request`, `--issue-token`, the registration window and the headless approval prompt removed | `enrollment.rs`, `console.rs`, `tui.rs`, `main.rs`, `bin/client/enroll.rs`, `RelayEnrollment.java`, `RelayIdentity.java`, `RelayRegistrationDialog.java` | One paste enrolls a desktop and an Eclipse; a used, expired or cancelled link gets the generic 403; a link from another relay fails the CA pin before the secret is sent |
| **P0** Shared tool table | `tools.json`, Rust embedding, Java resource, conformance tests in both | `policy.rs`, `tools/*.java`, new `tools.json` | Changing a tool's class in one place breaks a test |
| **P1** Local Eclipse permissions (global) | Preference page, storage and lock, enforcement in `RelayRequests` (list and call), separate local `RelayPackageScopes`, effective-policy display, denial attribution | `preferences/`, `server/RelayRequests.java`, `ScopedSapCall.java`, `RelayPackageScopes.java`, `ui/McpServerView.java` | Java tests: local read-only blocks a write that the relay allows; patterns intersect; a locked page can't be edited |
| **P2** Plugin as the authority | The relay sends its allowed tools with each call; the plugin rejects tools outside relay ∩ local even if the relay forwarded them | `mcp.rs` (call envelope), `RelayRequests.java` | Test with a "compromised relay" stub that forwards a denied tool: the plugin refuses |
| **P3** Keys and pairing | Inner P-256 keys and storage; Java DER certificate writer and pinned key/trust managers; the plugin's **Pair Desktop** link (5 min, one outstanding); `pair --link` and `unpair`; `pair/claim` inside the pinned inner session; confirmation dialog with key fingerprint (lands with or after P4 and P5, which it needs) | `bin/client/pair.rs`, `server/Pairing.java`, `server/InnerKeys.java` | One paste and one click pair; a test relay that answers with its own key fails the pin; a reused or expired secret and an unanswered dialog are refused; pins persist and are removable |
| **P4** Tunnel transport | Client `/tunnel` WebSocket, relay stream multiplexing over `/bridge`, control and data frames on both sides, stream limits (D7) | `bin/client/tunnel.rs`, relay `tunnel.rs`, `server/RelayStreams.java` | Loopback integration test opens, uses and closes streams; per-desktop and per-bridge caps hold |
| **P5** Inner TLS, envelope and admission | rustls sans-IO client with pinned verifier; `SSLEngine` server; length-prefixed messages; `admit`/`request`/`response` with binding 30 s admissions; envelope derivation and comparison in the plugin; MCP session in the plugin; local `relay_list_endpoints`; per-desktop local permissions (D4) | `bin/client/stdio.rs`, relay `tunnel.rs`, `server/InnerChannel.java`, `preferences/` | Integration test: the relay's stderr never contains a secret argument marker; a changed envelope or reordered bytes are refused; a denied request leaves the stream usable; a policy change closes affected streams |
| **P6** Monitoring | Stream rows in the Connections tab, statistics from envelopes, relay-measured response time, paired indicator | `bridge.rs`/`tunnel.rs`, `tui/render.rs` | TUI integration test shows a stream with tool name and status |
| **P7** Migration and hardening | `require_e2e`; the plugin's **Allow unencrypted relay calls** (lockable); no client fallback once paired; docs and `security-model.md`; Java↔Rust TLS interop test in CI | `main.rs`, `tui/`, `RelayRequests.java`, `preferences/`, `bin/client/stdio.rs`, `docs/` | With `require_e2e` on, `/mcp` is refused; with the plugin switch off, a legacy clear-text call is refused; a paired client never uses `/mcp`; the interop test passes on Windows and Linux |

PE, P1 and P2 are useful without the encryption and can ship first; PE also introduces the link format and parser that P3 reuses. P3 to P5 belong together; release them only together with P7's switches.

## 9. Tests

- **Rust unit tests:** link build and parse (versions, repeated or missing parts, bad token, length cap, the secret never in `Debug` or error text, as in Pleochroma's `pairing/tests.rs`); link store (single use, lifetime, cancel, outstanding cap, constant-time compare); class recomputation; admission (allowed, denied, class mismatch, 30 s expiry, close on policy change); frame codec limits.
- **Seeded random-input tests** in the normal `cargo test` for the frame codec, link parser and envelope parser, so both Windows and Linux get regression coverage (D9). `cargo fuzz` targets live in `fuzz/` and run locally on Linux only.
- **Java tests:** the same link vectors as Rust (one shared `link-vectors.json`); envelope derivation and mismatch (wrong `seq`, method, tool, class); effective-policy intersection with the separate local scopes; the pinned-key trust manager rejects any other key; the DER certificate writer produces a certificate the JDK and rustls accept; pairing secret single use, lifetime and the 2-minute dialog timeout.
- **Integration (`tests/desktop_relay.rs`):** enrollment by link for desktop and Eclipse (replacing today's request/approve/token steps), pairing by link, then a tool call end to end. Assertions:
  - the relay log and stderr contain the tool name but never the argument marker or the result marker;
  - a test-only relay mode that rewrites the envelope makes the plugin refuse;
  - a denied tool leaves the stream usable for the next request;
  - a test-only relay that sends a legacy clear-text call is refused once the plugin switch is off.
- **Interop:** a CI job runs the Rust client side against a Java `SSLEngine` server harness (and the reverse), on Windows and Linux.

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| An enrollment or pairing link is pasted into a chat or ticket and used by someone else | Single use and short lifetime (10 or 5 minutes); cancel in the TUI or MCP view; the "enrolled" notice names label and peer; a new desktop has no grants until the operator adds them; pairing needs a click with a comparable fingerprint |
| A pairing link is sent through the relay (for example via a relay-hosted chat), which defeats the pin | Docs and UI say "copy on this machine"; links are never transported by the relay itself |
| A compromised relay downgrades to the clear-text path during migration | Plugin switch off by default in N+1; paired clients never fall back |
| TLS-in-tunnel interop issues (rustls vs JDK `SSLEngine`) | Interop test early in P5; one cipher suite, one key type, no resumption |
| Extra round trip from pre-admission | Only client to relay; measure only when asked |
| Two policy tables drifting | P0 shared table plus conformance tests |
| Lost pins (new machine, reset Eclipse workspace) | Re-pairing is cheap; both sides list pins; documented recovery |
| Migration lockout when `require_e2e` is turned on too early | Off in N; the TUI shows which endpoints and desktops are still on the old path |

## Decisions

All decided 2026-11-20.

| ID | Decision | Reason |
| --- | --- | --- |
| D1 | **ECDSA P-256 only**, no fallback; signature scheme `ecdsa_secp256r1_sha256`; pin = SHA-256 of the SubjectPublicKeyInfo DER | Every key in the system is already P-256 (rcgen's default `KeyPair::generate()` in `security.rs`), and the plugin already runs TLS 1.3 with such keys (`RelayIdentity.java`). Ed25519 with a fallback would mean two key types. |
| D2 | **TLS 1.3 in the tunnel with pre-admission**: `TLS_AES_256_GCM_SHA384` only, groups x25519 and secp256r1, client certificate required, no resumption or 0-RTT; rustls sans-IO in Rust, `SSLEngine` in Java | Noise needs a third-party library on both sides; rustls and rcgen are already dependencies and sans-IO rustls needs no async runtime. JDK 17 (the plugin's `JavaSE-17`) has no TLS exporter API, so "TLS handshake plus own per-message encryption" is not available either. |
| D3 | **No object type or name in the envelope**, no reserved field; envelope v1 is exactly `v, seq, method, tool, class`, unknown fields refused | The relay never looks at objects today (`mcp.rs` `dispatch` only checks `policy.allows(name)`); packages are enforced in the plugin by `ScopedSapCall`. Nothing is lost and names stay hidden. |
| D4 | **Per-desktop local permissions: yes, keyed by the pinned inner-key fingerprint, delivered with P5**; P1 ships the global local policy only; local package patterns are a separate `RelayPackageScopes` instance | Before pairing the plugin has no trustworthy desktop identity (`RelayRequests.call` receives only name, arguments and `relayPackageScopes`). `RelayPackageScopes.parse` caps the relay's layers at two. |
| D5 | **No plugin telemetry**; the relay shows its own measured admit-to-response time | Self-reported numbers add a clear-text channel for little value; the relay can time what it forwards. |
| D6 | **N:** tunnel ships, `require_e2e` off, `/mcp` served. **N+1:** `require_e2e` on by default, plugin's unencrypted calls off. **N+2:** `/mcp` and legacy bridge calls removed. Plus the plugin switch and no client fallback once paired (§7) | The engine-replacement rule; a relay-only switch cannot protect against the relay itself. |
| D7 | **Several desktops per Eclipse stay allowed**: 128 streams per bridge, 16 per desktop per endpoint, 8-hour idle close, 30 s inner handshake, calls serialised per bridge; the plugin enforces the same caps | `bridge.rs` has no per-owner cap, so one desktop could take all slots, and each stream now costs an `SSLEngine`. Calls are already serialised (`Semaphore::new(1)`, single-thread executor in `RelayBridge.java`, `synchronized (sapSession)`). |
| D8 | **`sap-adt://enroll?…` and `sap-adt://pair?…`, copy and paste only, no QR code**, scheme never registered as an OS handler | Both consumers are paste targets (the `enroll --link` CLI and an Eclipse text field); nothing scans. QR would add a dependency on both sides (the bundle ships only gson). |
| D9 | **No cargo-fuzz in CI**; fuzz targets run locally on Linux; seeded random-input tests in the normal `cargo test` | cargo-fuzz needs nightly and libFuzzer and is awkward on Windows; the seeded tests cover both platforms. |
| D10 | **Enrollment link: 10 minutes, single use, at most 16 outstanding. Pairing link: 5 minutes, single use, one outstanding** | Enrollment links travel between people; 16 is today's `WINDOW_CAP`. Pairing links are pasted on the same machine with the user present. |
| D11 | **No operator confirmation on claim, and no setting**; minting is the approval; `--issue-token`, the headless prompt and `/request` are removed and the enrollment listener always runs | A stolen link gains little: a new desktop starts read-only with no endpoint grants (`Rules::desktop_default()`, empty `endpoint_grants`), and a rogue Eclipse is unreachable until granted. Headless `issue-link` has nobody to confirm anyway. |
| D12 | **Pairing confirmation on, always, no setting**: a non-blocking "Pair <label>?" dialog with the relay-supplied label (marked as such) and the desktop key's short fingerprint, refused after 2 minutes; the client prints the same fingerprint | Pairing lets a desktop drive this Eclipse's SAP session, and the label comes from the relay, which may be compromised. One click covers a leaked link. |
