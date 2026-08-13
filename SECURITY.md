# Security Policy

## Supported versions

**CLASP is pre-release. There is no released version.** The workspace is at
`0.0.2`, which is a milestone marker rather than a published artifact: nothing
is tagged, nothing is on crates.io, and no binaries are distributed. Fixes land
on `main`, and there is nothing to backport them to.

| Version | Supported |
| ------- | --------- |
| `main` (0.0.x, pre-release) | ✅ best effort |
| any tagged release | none exist yet |

This table becomes a real support statement at the first release. Until then,
"supported" means the fix goes on `main`.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private vulnerability reporting: go to the
[Security tab](https://github.com/Sertelegger/clasp/security) → **Report a
vulnerability**.

This is a personal open-source project, so response times are best-effort —
expect an acknowledgment within a week.

## The thing to understand before reporting

**CLASP exists to run commands on your machine on an AI agent's behalf.** It
spawns a real shell on a real PTY and lets an agent type into it. That is the
product, not a flaw in it. So:

- **"The agent ran a command I didn't want" is not a vulnerability.** It is
  CLASP working. Failures of the *safety machinery around* command execution
  are what this policy is about.
- **CLASP applies no sandbox, no allow-list, and no privilege reduction.** The
  child inherits the environment, working directory, and privileges of the
  process running `clasp mcp`. Run it as a user you are willing to let an agent
  be.
- **The program inside a session is inside the trust boundary.** A child that
  wants to print bytes that look like a shell prompt can do so directly, at any
  length, and CLASP cannot tell those bytes from a real shell's. See
  "Documented residuals" below.

What *is* in scope is everything CLASP claims to do about that execution:
whether the agent is told the truth about what a session is doing, whether a
`terminate` really terminates, and — once it ships — whether the redactor holds.

## In scope

### Secrets crossing the MCP wire

The design routes secret input **client → daemon → PTY**, so a secret never
appears in a tool argument or a tool result, and a redactor runs at every
output boundary including the audit log.

**None of that exists in 0.0.2, and the current behaviour is the opposite.**
Stated plainly, because a security policy that implies shipped protection is
worse than none:

- **`read_output` returns the session's bytes raw.** No redaction, no ANSI
  stripping. If a command prints a token, an API key, or a password, the agent
  reads it and it lands in the conversation transcript. This is said in
  `README.md`, in the MCP server `instructions` string
  (`crates/clasp-core/src/mcp/mod.rs`), and in `read_output` itself
  (`crates/clasp-core/src/mcp/tools.rs`). It is a known gap on the roadmap, not
  a vulnerability report.
- **There is no secret input channel.** `send_input` writes whatever the agent
  sends, over the MCP wire. The out-of-band `request_secret_input` path is a
  later milestone.
- **`start_session(env:)` values cross the MCP boundary** and the argument
  documents that ("Do not pass secrets"). Putting a credential there puts it in
  the transcript.

What is in scope **today** is CLASP putting sensitive material somewhere the
caller did not ask for. One fix of exactly this shape has already shipped:
`portable-pty`'s spawn error embeds the entire `$PATH`, so `start_session`
reports a clipped `envelope::brief(&e)` rather than the raw error, which would
otherwise have landed in the transcript on every failed spawn.

Once redaction lands, **a bypass of the redactor at any output boundary is
squarely in scope** — including the paths that are easy to forget, such as
error strings, the audit log, and bulk output delivered as a resource rather
than inline.

### Prompt and interaction-state detection

`crates/clasp-core/src/detect/` — `scanner.rs`, `detector.rs`, `patterns.rs`.

Detection is what the agent believes. Every prompt-bearing response carries an
`interaction_mode` (`AtPrompt` / `Executing` / `AwaitingSecret` / `Fullscreen`
/ `Exited`) and a `detection_tier` (`semantic` from OSC 133, `terminal_mode`
from bracketed paste / alternate screen / termios `ECHO`, `heuristic` from
output quiescence and the tier-3 pattern table). **A forged or mis-detected
state is a real bug class, and each direction has its own consequence:**

- a false `AtPrompt` tells the agent to type into a program that is still
  running;
- a false `AwaitingSecret` tells the agent to interrupt a human for a password
  no program asked for;
- a missed `AwaitingSecret` means the agent answers a password prompt as if it
  were ordinary input.

Cases of this class that have already been found and fixed, so you can see what
a good report looks like:

- **An abandoned escape sequence used to promote its own payload to terminal
  text.** When a sequence exceeded the byte ceiling the scanner returned
  straight to `Ground`, so the remainder of a *correctly terminated* payload
  became ordinary output — measured, a 9 KiB BEL-terminated OSC 52 clipboard
  write whose payload ended `\r\nroot@prod:/etc# ` produced exactly that as the
  detector's last line, which the tier-3 table scores at 0.85, the act
  threshold. The scanner now discards to the next newline and clears its tail
  line (`ModeScanner::give_up`).
- **A stale `ECHO` sample forged `AwaitingSecret`.** The termios sample was
  cached for 50 ms; paired with a *current* bracketed-paste-off it is the exact
  signature of a secret prompt, and reported `AwaitingSecret` at 0.95 for
  `sleep 5` roughly one run in ten. The cache is gone and the sample is now
  taken with the detector lock held, so no chunk can be classified between the
  sample and the classification.
- **Truncated sequence parameters forged terminal modes.** A CSI cut at the
  parameter cap could end in `;2004` and set the bracketed-paste flag, and
  unmodelled OSC 133 subcommands could set the flag that gates the `semantic`
  tier. Both flags are sticky and decide which rungs may answer for the rest of
  the session.

**Documented residuals — please read these before reporting.** Each is known,
recorded in the code, and accepted:

- **A hostile or merely careless program in the session can print any of these
  bytes directly.** OSC 133 markers, `\x1b[?2004h`, a prompt-shaped line — all
  of them, at any length, with no ceiling involved. CLASP cannot distinguish
  them from a shell's, by construction.
- **`SEQUENCE_MAX` (1 MiB, `scanner.rs`) is a blindness budget, not a forgery
  guard, and does not close.** At the trip point a huge well-formed sequence
  and a truncated one share a byte-identical prefix, so no online rule can act
  differently on them. The discard-to-newline rule leaves a residual: a payload
  carrying a newline hands everything after it to the state machine. This is
  documented at its real reach in `give_up`'s doc comment.
- **0.0.2 has no ANSI stripper**, so the tier-3 table matches raw bytes:
  coloured prompts score 0 and the table's false-positive surface is wider than
  it is designed to be. `patterns.rs` says so and pins it.

A report that demonstrates one of these residuals is already known. A report
showing a **new** path to a forged state, or one that materially lowers the
cost of reaching an existing one, is valuable.

### Process-group signal handling

`crates/clasp-core/src/pty/in_process.rs`. `terminate` must kill everything it
owns and **nothing it does not**. Both directions are bugs:

- **Orphans.** The child is spawned with `setsid()` and the PTY as its
  controlling terminal, so PGID == SID == PID. A single `killpg(pgid)` is not
  enough: shell job control puts each background job in its own process group,
  so `terminate` enumerates every process group in the child's session (via
  `/proc` on Linux) and signals each one, re-enumerating on every sweep.
- **Over-reach.** `kill(-0, sig)` signals *CLASP's own* process group, which is
  why every group is filtered on `pgid > 0`. A reaped PID can be recycled, so
  `signal` refuses to deliver anything once the child has exited — otherwise a
  `/proc` sweep could target a stranger's session. `InProcessPty::signal_deliveries()`
  is public, and not `#[cfg(test)]`, precisely so a test can assert that no
  signal left the process at all.

Known limitation, not a report: on Unix platforms **without** `/proc` the sweep
degrades to (the child's group, the terminal's foreground group), so a
background job in a third group can survive `terminate` there. Full enumeration
needs `sysctl(KERN_PROC_SESSION)` and is not implemented.

### Resource exhaustion

The only caller is an MCP client, but that client is a language model, so
unbounded inputs matter. Existing bounds, each of which was added after
measuring the failure it prevents:

- **`send_input` caps a payload at 64 KiB** and performs the write on the
  blocking pool under a 5 s deadline. Before that, a raw-mode child that had
  stopped reading its terminal parked one tokio worker per call, uncancellably;
  a handful of calls took the entire MCP server down — including `terminate`,
  the only way out.
- **`read_output` defaults to 32 KiB and hard-caps at 256 KiB**, and rejects
  `max_bytes: 0`, which can never make forward progress.
- **Caller-supplied `prompt_patterns` are capped at 64**, each compiled with a
  64 KiB size limit, and rejected patterns are clipped to 120 characters in the
  error. Unbounded, 5000 patterns were accepted and put every tool call at
  milliseconds; `(?:(?:a{50}){50}){50}` compiled to 125 000 repetitions; a
  200 KB regex produced a 200 KB error message that then sat in the transcript
  for the rest of the conversation. (Catastrophic backtracking is *not* the
  risk here — the `regex` crate is automaton-based and `(a+)+$` was measured
  linear. Compilation cost is.)
- **The registry caps live sessions at 8** and each session's output buffer at
  1 MiB.

A way past any of these caps, or an input path that has no cap at all, is in
scope.

## Out of scope

- **Command safety.** There is no preflight, no dangerous-command classifier,
  and no confirmation flow in 0.0.2. They are on the roadmap; their absence is
  not a vulnerability.
- **Secrets in output.** No redactor has shipped. See above.
- **A program inside a session forging its own detection signals.** It is
  inside the trust boundary.
- **Anything that requires an attacker who already runs as the user running
  `clasp mcp`.** At that point they can start the shell themselves.
- **Windows.** 0.0.2 is Unix-only. The workspace is kept compiling and
  clippy-clean for `x86_64-pc-windows-gnu`, but signalling returns an error
  there, there is no process-group handling, and `ECHO` is not sampled. Windows
  is unimplemented, not broken.
- **`docs/`.** The design specification and implementation plans are the
  author's local working documents and are deliberately absent from this
  repository and its history. The `§`-numbered references throughout the code
  point into them.
