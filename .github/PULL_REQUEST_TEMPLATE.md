<!-- Thanks for contributing! A short summary and the checklist below help review go fast. -->

## Summary

<!-- What does this PR change, and why? Link related issues: Fixes #123 -->

## How the new tests were shown to fail

<!--
Required for any new or changed test. Name the defect you injected, and what
went red. "A test you have not seen fail is a test you have not written" is
enforced here, not aspirational — see CONTRIBUTING.md.
Write "no test changes" if that's the case.
-->

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --no-fail-fast` passes
- [ ] If the tool surface changed: `./scripts/mcp-smoke.sh` passes, and its checks were extended to cover the change (it is the only thing that drives the real JSON-RPC wire)
- [ ] Every new positive assertion has the negative that separates it from the degenerate case — a constant, an empty response, a hardcoded default
- [ ] If a tool was added or removed: `tools.rs`'s router test, `tests/schema.rs`'s `TOOLS` list and annotation table, and the MCP server's `instructions` string are all updated
- [ ] If an advertised number changed (a byte cap, a default, a threshold): the constant and the schema description it appears in moved together
- [ ] If anything platform-gated changed: clippy is clean for `--target x86_64-pc-windows-gnu`
- [ ] If this changes what Holdfast claims to support: `README.md`, `CHANGELOG.md`, and — for anything touching detection, signals, secrets, or output — `SECURITY.md` are updated
