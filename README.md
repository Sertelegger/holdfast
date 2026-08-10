# CLASP — Claude's Live Agent Shell Proxy

An MCP server that gives AI agents persistent, PTY-backed shell sessions.

> **Status: 0.0.1 — early development.** Four tools, stdio only, Unix only.
> Sessions die with the MCP process. Output is returned **raw and
> unredacted**. Not yet suitable for real use; see the milestone plan in
> `docs/superpowers/specs/2026-05-01-clasp-design.md` §23.

## What works today

- `start_session` — spawn a shell or program on a real PTY
- `send_input` — type into it
- `read_output` — read what it printed, using a cursor you carry between calls
- `terminate` — stop it, killing the whole process group

## Build and try it

```bash
cargo build --workspace
./scripts/mcp-smoke.sh                  # raw JSON-RPC smoke test
claude mcp add --scope user clasp -- "$(pwd)/target/debug/clasp" mcp
```

## Development

```bash
cargo test --workspace       # unit + integration tests (spawns real PTYs)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## Documentation

- Design specification: `docs/superpowers/specs/2026-05-01-clasp-design.md`
- Implementation plans: `docs/superpowers/plans/`
