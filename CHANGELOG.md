# Changelog

All notable changes to CLASP are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Direction and
upcoming work live in [ROADMAP.md](./ROADMAP.md).

## [Unreleased]

**Nothing has been released yet.** The workspace version is `0.0.2` and has not
tracked the milestone number since; it is a placeholder rather than a published
artifact, and there is no tag, nothing on crates.io, and no distributed binary.
Everything below has landed on `main` and will be folded into the first
release's notes.

Every milestone here was built task by task from self-contained briefs, each
task reviewed against its brief and then again as a whole branch — which is why
the "Fixed" section names classes of defect rather than issue numbers.

**This file is behind the tree.** Milestones 0.0.3 (output processing and
redaction) and 0.0.4 (screen state, resize, interrupt) are merged and have no
sections of their own; README and ROADMAP describe what they added. The gap is
recorded here rather than guessed at.

### Added

#### Milestone 0.0.1 — skeleton and PTY

- **A working stdio MCP server** (`rmcp`) with four tools: `start_session`,
  `read_output`, `send_input`, `terminate`. Single Cargo workspace —
  `clasp-core` (library) and `clasp` (binary, subcommands `mcp` and `version`).
- **`InProcessPty`**, a `portable-pty`-backed PTY behind a `PtyBackend` trait,
  with `setsid()` and the PTY as controlling terminal so the child's process
  group, session id and PID coincide. The trait exists so later milestones can
  vary the isolation model without touching session logic; `MockPty` implements
  it for tests.
- **`OutputBuffer`** with absolute-offset cursors, so an agent can carry a
  cursor between `read_output` calls and know exactly what it has and has not
  seen, including when the ring has evicted the bytes it asked for.
- **`Session` and `SessionRegistry`** — a dedicated reader thread per session so
  blocking PTY reads never occupy a tokio worker, live-name uniqueness (an
  exited session releases its name but keeps its id and its output buffer), a
  concurrency cap of 8 live sessions, and a 1 MiB buffer each.
- **`scripts/mcp-smoke.sh`** — an end-to-end smoke test that drives raw JSON-RPC
  through the real server and asserts on shell-evaluated output. It is the only
  check in the project that exercises the wire format.

#### Milestone 0.0.2 — deterministic prompt detection

- **Sessions now report what the program is doing, with the evidence.** Every
  prompt-bearing response carries an `interaction_mode` — `AtPrompt`,
  `Executing`, `AwaitingSecret`, `Fullscreen`, `Exited` — and a
  `detection_tier` saying how that was reached: `semantic` (OSC 133 markers),
  `terminal_mode` (bracketed paste, alternate screen, termios `ECHO`), or
  `heuristic` (output quiescence combined with a prompt-pattern score). The tier
  is there so an agent can tell a measurement from a guess.
- **A tier-A byte scanner** — a bounded state machine over the raw PTY stream
  tracking bracketed paste, the alternate screen, the window title and OSC 133
  markers. It allocates no grid and keeps no history beyond a 512-byte tail
  line, so it runs unconditionally on every chunk, and it resynchronises on
  malformed sequences rather than letting one swallow the session.
- **Termios `ECHO` sampled through `PtyBackend`**, read from the master with
  `tcgetattr`, which is what makes a genuine secret prompt distinguishable from
  ordinary output that happens to end in `Password:`.
- **A 22-row tier-3 prompt-pattern table**, nine rows carrying head guards
  derived from measuring the table against 65 lines of ordinary build, test,
  `git`, package-manager and `--help` output. Sessions may extend or replace it
  via `start_session(prompt_patterns:)`.
- **OSC 133 shell integration for bash, zsh and fish** — a one-line snippet
  **typed into the session at the first prompt, never installed**. There is
  nothing to add to an rc file; the snippet wraps whatever `PS1` the shell ended
  up with rather than replacing it, does nothing when the user's configuration
  already emits OSC 133, and is not exported, so a nested shell is integrated in
  its own right. Anything else — `dash`, a REPL, a plain program — degrades
  silently to `terminal_mode` or `heuristic`. `shell_integration: false` skips
  it.
- **A command-history ring** built from those markers, recording each command's
  exit code, start time, duration, and the byte span of its output, addressed in
  the same cursor space `read_output` uses.
- **Three new tools** — `status` (what one session is doing now),
  `list_sessions` (every session, live or exited), and `get_command_history`.
  The tool set is seven.
- **An `outputSchema` on every tool**, and the MCP 2025-06-18 annotations
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`) on
  each, so a client can validate what it gets back and reason about what a call
  will do before making it.
- **Session options on `start_session`**: `cwd` (validated and canonicalised),
  `env`, `cols`/`rows`, `prompt_patterns`, `prompt_patterns_replace`,
  `settle_threshold_ms`, `shell_integration`.

#### Milestone 0.0.5 — the daemon and the control protocol

- **Sessions no longer die with the MCP client.** `clasp mcp` is now a thin
  shim: on first use it auto-spawns a background `clasp daemon`, and afterwards
  it reconnects to the one already running. The daemon owns the PTYs, so
  quitting and restarting Claude Code leaves every session alive, at the same
  prompt, with its output buffer intact. `clasp mcp --no-daemon` keeps the old
  single-process behaviour, and is the shape the Windows build will reuse.
- **A versioned control protocol** over a Unix socket — length-prefixed CBOR
  frames with a 16 MiB cap, a `clasp/handshake` that both peers check, and the
  §18.3 error catalogue. Mismatched protocol majors refuse to connect from
  *either* side, so a protocol break cannot be papered over by one end being
  lenient.
- **The daemon never opens a TCP listener.** The socket is Unix-domain only,
  its directory is `0700` and verified after creation, and every connection's
  peer credentials are read with `SO_PEERCRED` and compared to the daemon's own
  uid *before a single frame is parsed*. A credential that cannot be read fails
  closed.
- **New CLI subcommands** — `clasp daemon run|start|stop|status`, `clasp list`,
  and `clasp logs <session> [--tail N] [--raw]`, with §18.8's exit codes and
  §3.2's idempotence contracts (`daemon start` on a running daemon and
  `daemon stop` on a dead one both succeed and say so).
- **The §9.4 caller is derived from the connection, never from the request.**
  A read that disables redaction records two facts: `tool`, the mechanism, and
  `client_kind`, the accountable party — taken from the uid-checked handshake,
  so `clasp logs --raw` is logged as `cli` and an agent's
  `read_output(redact: false)` as `shim`. There is deliberately no argument an
  agent could set to label itself as a human. `client_kind` is attribution
  only; nothing in the read path branches on it.

### Fixed

Corrections that were measured rather than assumed. Each names a class rather
than a one-off:

- **A single `killpg()` does not reach a shell's background jobs.** Job control
  puts each in its own process group, so `terminate` swept the leader and left
  orphans. Measured against real PTYs; `terminate` now enumerates and signals
  every process group in the child's session, and interrupts target the
  terminal's foreground group.
- **`send_input`'s blocking write could wedge the entire server.** A raw-mode
  child that stopped reading parked a tokio worker uncancellably, and each retry
  took another — a handful of calls took down the whole MCP server, including
  `terminate`, the only way out. The write now runs on the blocking pool under a
  deadline with a 64 KiB payload cap, and the binary bounds its runtime shutdown
  because Linux does not wake a parked pty-master writer when the slave closes.
- **`read_output` reported truncation that had not happened** — on both of its
  branches, at different times and for different reasons.
- **A stale `ECHO` sample reported `AwaitingSecret` for ordinary commands.** The
  50 ms cache paired a readline prompt's echo-off with the bracketed-paste-off
  of the command just submitted, which is the exact signature of a secret
  prompt: 0.95 confidence, and the documented response is to interrupt a human
  for a password. For `sleep 5`. Measured at 267 spurious samples under load, 0
  after. Fixed where the bad value was produced — the cache deleted, the sample
  taken under the detector lock — rather than guarded downstream, because the
  tempting guard (require a non-empty tail line) is a false negative on bash's
  `read -s`, a genuine secret prompt that prints nothing.
- **One concept had two spellings, twice.** The alternate screen was a second,
  wider spelling of "terminal-mode tier available": a single alt-screen toggle
  marked a session available for life, so a `dash` prompt reported `Executing`
  at a live prompt with nothing able to clear it. The same shape then turned up
  in the semantic dimension, where the OSC 133 flag was unpinned against
  unmodelled subcommands. One concept, one spelling.
- **The escape-sequence ceiling was a forgery guard that could not be one.** At
  the trip point a huge well-formed sequence and a truncated one share a
  byte-identical prefix, so no online rule can distinguish them. It is now
  documented as a *blindness budget*, raised to 1 MiB so a routine sixel frame
  no longer trips it, with its residual asserted at its real reach — including
  an ESC-free sixel, which disproved the claim that accidental forgery needs an
  `ESC`.
- **A head guard silently zeroed recall for every numbered-host prompt** while
  the corpus stayed green, because the corpus had `hostname% ` and no
  `build01% `. Pattern rows are now pinned from both sides of the boundary they
  draw, and the first sweep to do that passed for the wrong reason — witnessed
  by an accepted false positive rather than by a real prompt — so it was redone.
- **`scripts/mcp-smoke.sh` failed red on correct code.** `grep -q` under
  `pipefail` exits early, `printf` dies of `SIGPIPE`, and the pipeline reports
  141 — three to six runs in twenty under load, latent since 0.0.1.
- **The MCP server's own `instructions` string described a four-tool surface**
  for the whole of 0.0.2, so an agent that trusted it never learned that
  `status`, `list_sessions` or `get_command_history` existed. The smoke script
  now asserts every tool name appears there.
- **Sixteen tests that could not fail** were found and fixed across 0.0.2, and
  ten across 0.0.1. Several of the 0.0.1 ones matched the PTY's echo of their
  own command line, and so passed against a session running `sleep 300` instead
  of a shell. Injecting the defect and confirming the test goes red is now
  standard practice; see [CONTRIBUTING.md](./CONTRIBUTING.md).

### Security

- **`start_session` no longer echoes `portable-pty`'s raw spawn error**, which
  embeds the entire `$PATH` and would otherwise land in the conversation
  transcript on every failed spawn.
- **`cwd` is validated and canonicalised.** `portable-pty` silently *discards* a
  cwd that is not an existing directory and falls back to `$HOME`, so an
  unvalidated `cwd` told the agent `ok` while running the command somewhere else
  entirely.
- **Signals are refused once the child has exited.** A reaped PID can be
  recycled, and the `/proc` sweep would then target a stranger's session. Every
  candidate group is also filtered on `pgid > 0`, because `kill(-0, sig)`
  signals CLASP's own process group.
- **Caller-supplied inputs are bounded**: at most 64 prompt patterns, each
  compiled under a 64 KiB size limit, with rejected patterns clipped to 120
  characters in the error message; `send_input` payloads at 64 KiB;
  `read_output` at 32 KiB by default and 256 KiB hard. Unbounded, 5000 patterns
  were accepted and put every tool call at milliseconds, and a 200 KB regex
  produced a 200 KB error that then sat in the transcript for the rest of the
  conversation.
- **Truncated escape sequences can no longer forge terminal modes.** A CSI cut
  at the parameter cap could end in `;2004` and set the bracketed-paste flag,
  and an abandoned sequence used to hand the rest of its payload to the state
  machine as ordinary text — measured, a 9 KiB OSC 52 clipboard write ending
  `\r\nroot@prod:/etc# ` produced exactly that as the detector's last line, which
  the pattern table scores at the act threshold.

See [SECURITY.md](./SECURITY.md) for what is and is not in scope, including the
residuals that are known and accepted.

### Known limitations

Stated because they are easy to mistake for bugs:

- **Output is returned raw and unredacted.** No secret redaction, no ANSI
  stripping. A token printed by a command is read by the agent and lands in the
  transcript.
- **stdio transport only, and sessions die with the MCP process.** There is no
  daemon and no attach; closing the client kills every session.
- **Unix only.** The tree is kept compiling and clippy-clean for
  `x86_64-pc-windows-gnu`, but signalling returns an error there and there is no
  process-group handling.
- **Seven tools.** No `interrupt`, `resize`, `wait_for_pattern`,
  `precheck_command` or `request_secret_input` yet — the backend supports
  signalling and resizing, but neither is exposed as a tool.
- **`get_command_history`'s `command` field is best-effort**, reconstructed from
  the terminal's echo: a command longer than the terminal width is captured
  truncated to its tail with no ellipsis and no error, and non-ASCII bytes are
  recorded as Latin-1.
- **On Unix without `/proc`**, the process-group sweep degrades to the child's
  group plus the terminal's foreground group, so a background job in a third
  group can survive `terminate`.

[Unreleased]: https://github.com/Sertelegger/clasp/commits/main
