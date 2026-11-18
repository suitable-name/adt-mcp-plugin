# Implementation Guide

## Who Runs What

1. The repository owner runs builds, `cargo check`, Clippy, tests, harness runs, release builds, and PGO builds and pastes the results. Read the code to fix failures and give the owner the exact commands to run next.
2. Format last. After everything else, the owner runs `cargo +nightly fmt --all`.
3. Run tests once across the whole workspace and Clippy once across the whole workspace. Give each additional feature set its own workspace-wide run. Do not loop over crates.
4. Wait for the owner to confirm that the machine is quiet before running benchmarks or taking timing measurements. Label existing numbers as provisional.
5. Do not run Git commands.
6. The owner handles publishing, version bumps, and package sizes. Release checks cover code and documentation only.

## Agents and Delegation

7. Assign implementation work to Codex agents using the session's default model. Use a model override only at the owner's explicit request.
8. Agents run no Cargo commands and re-read their edits by eye.
9. Instruct agents to make all edits first, then verify once. Agents must not spawn subagents or perform bulk sed or regex rewrites.
10. Give parallel agents separate files. Ask them to report any line they need changed outside their assignment.
11. Verify agent reports against the code before accepting them.
12. During multi-agent rounds, report only the final result. Omit per-agent progress updates.

## Code Quality

13. Fix every lint finding in the code. Do not suppress findings with `allow` or `expect`.
14. Enable the Clippy pedantic and nursery groups in `[workspace.lints.clippy]`. Every member inherits them through `[lints]` with `workspace = true`.
15. Fix every review finding. Use severity to decide the order.
16. Use targeted search tools. Never run shell `find`, `fd`, or recursive directory walks.
17. When a test pin moves, re-pin it from the values the owner pastes. Do not rerun the test to obtain those values.

## User-Facing Text

18. Use US spelling in user-facing text. Preserve the existing spelling of code identifiers and serialized keys.
19. Use Title Case for labels and sentence case for notes, tooltips, and messages.
20. Include notes in user-facing output only where they help the reader.

## UI

21. Inspect screenshots when verifying UI changes. Clippy and tests alone do not verify the UI.

## Process

22. While waiting on a build or server, read its log. Do not poll file timestamps.

## Relay Compatibility

Bind each desktop MCP session to its initiating certificate and the selected Eclipse connection. Enforce endpoint grants on the server, including on direct calls and existing sessions. An unassigned desktop, a disconnected endpoint, and a missing client selection must all fail closed. Changes to the local selection take effect on the next MCP connection.

Keep the minimum Rust version at 1.95, the edition at 2024, and the workspace resolver at 3. Run the workspace checks with the minimum toolchain and retain its dependency lockfile. Keep the desktop client's stdout exclusively for MCP messages in `connect` mode. Serve with a TUI by default. Display issued tokens in the local TUI dialog or on the attached headless approval terminal. Route diagnostics to the Logs tab or headless stderr and exclude tokens, keys, tool arguments, and SAP payloads.

Both Eclipse and desktop identities must use the same request, human approval, single-use claim, and mutual TLS sequence. The TUI starts with registration closed unless `--issue-token` is present. Plain `--headless` serves enrolled identities with the enrollment port unbound. For `--headless --issue-token`, require a usable operator terminal before serving. Read approval commands and write prompts and tokens directly through that terminal, including when standard streams are redirected. Every issuance requires a human decision on a specific pending request. A headless operator compares the full ID, role, and label, then approves using the console’s unique request number. Both operator interfaces can open and close registration.

The data listener requires role-authorized client certificates. Apply the intersection of global and desktop policies to discovery and every call. Check existing-object package ownership against SAP metadata and fail closed when ownership cannot be established. Keep request IDs, certificate ownership, tool definitions, and SAP mutation outcomes intact when updating either transport.
