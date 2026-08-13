# CLASP — Claude's Live Agent Shell Proxy

An MCP server that gives AI agents persistent, PTY-backed shell sessions.

> **Status: milestone 0.0.2 — early development.** Seven tools, stdio
> only, Unix only. Sessions die with the MCP process. Output is returned
> **raw and unredacted**. Not yet suitable for real use.

## What works today (0.0.2)

- `start_session` — spawn a shell or program on a real PTY
- `send_input` — type into it
- `read_output` — read what it printed, using a cursor you carry between calls
- `terminate` — stop it, killing the whole process group
- `status` — what one session is doing right now
- `list_sessions` — every session this server knows about, live or exited
- `get_command_history` — per-command exit codes and output spans, for
  integrated shells

Sessions report **what the program is doing**, not a guess:

- `interaction_mode`: `AtPrompt` | `Executing` | `AwaitingSecret` |
  `Fullscreen` | `Exited`
- `detection_tier`: `semantic` (OSC 133) | `terminal_mode` (bracketed
  paste / alternate screen / termios `ECHO`) | `heuristic` (output
  quiescence × prompt patterns)

`detection_tier` is there so an agent can tell a measurement from a
guess. Every tool also ships an `outputSchema`, so a client can validate
what it gets back.

### Shell integration

When the session command is `bash`, `zsh` or `fish`, CLASP types a
one-line OSC 133 snippet at the first prompt, so the shell marks its own
prompt, command and exit-code boundaries and detection runs at the
`semantic` tier. The snippet wraps whatever `PS1` the shell ended up with
instead of replacing it, does nothing when your configuration already
emits OSC 133, and is not exported — a nested shell is integrated in its
own right. Pass `shell_integration: false` to `start_session` to skip it.

It is **typed into the session, never installed**: there is nothing to add
to an rc file, and `crates/clasp-core/src/detect/shell.rs` holds the only
copy of each snippet. Anything else — `dash`, `sh`, a REPL, a plain
program — degrades silently to `terminal_mode` or `heuristic`, with no
configuration and no error.

Output is still returned **raw and unredacted**; redaction and ANSI
stripping arrive in 0.0.3.

## Build and try it

```bash
cargo build --workspace
./scripts/mcp-smoke.sh                  # raw JSON-RPC smoke test (needs jq)
claude mcp add --scope user clasp -- "$(pwd)/target/debug/clasp" mcp
```

## Development

```bash
cargo test --workspace       # unit + integration tests (spawns real PTYs)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

`scripts/mcp-smoke.sh` is the only check that drives the real JSON-RPC
surface; everything else asserts against in-process objects. Run it after
any change to the tool surface, and read its header before adding a check
to it.

## Documentation

The design specification and the per-milestone implementation plans are kept
as the author's working documents and are not part of this repository. The
code is meant to stand on its own: every module carries a doc comment
explaining what it does and why, and the tests name the behaviour they pin.
