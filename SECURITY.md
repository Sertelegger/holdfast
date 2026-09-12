# Security Policy

## Supported versions

**Holdfast is pre-release.** `v0.0.5` was the first tag, `v0.0.7` is the
newest, and the workspace version tracks it. Fixes land on `main` and are not
backported: a tag here marks a milestone, not a support commitment.

**Things are published under this name, and none of them is a Holdfast anyone
can run.** A GitHub Release per tag, carrying that version's changelog section
and **no binary assets** — `release.yml` creates the release and uploads
nothing. And two `0.0.0` **name reservations** on crates.io, `holdfast` and
`holdfast-core`, both published 2026-08-20, whose `lib.rs` says *"this version
contains no usable code"*; `cargo install holdfast` answers *"there is nothing
to install in `holdfast v0.0.0`, because it has no binaries"*. They were
published by hand and no workflow can repeat it — `ci-hygiene.sh` denies
`cargo publish` outside a release workflow, and the release workflow has no
such step.

This section said "nothing is tagged, nothing is on crates.io, and no binaries
are distributed" from 0.0.3 until now. Only the third clause was still true.

| Version | Supported |
| ------- | --------- |
| `main` (0.0.x, pre-release) | ✅ best effort |
| `v0.0.5` – `v0.0.7` | none — the fix goes on `main` |

This table becomes a real support statement at the first release anyone is
expected to install. Until then, "supported" means the fix goes on `main`.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private vulnerability reporting: go to the
[Security tab](https://github.com/Sertelegger/holdfast/security) → **Report a
vulnerability**.

This is a personal open-source project, so response times are best-effort —
expect an acknowledgment within a week.

## The thing to understand before reporting

**Holdfast exists to run commands on your machine on an AI agent's behalf.** It
spawns a real shell on a real PTY and lets an agent type into it. That is the
product, not a flaw in it. So:

- **"The agent ran a command I didn't want" is not a vulnerability.** It is
  Holdfast working. Failures of the *safety machinery around* command execution
  are what this policy is about.
- **Holdfast applies no sandbox, no allow-list, and no privilege reduction.** The
  child inherits the environment, working directory, and privileges of the
  process running `holdfast mcp`. Run it as a user you are willing to let an agent
  be.
- **The program inside a session is inside the trust boundary.** A child that
  wants to print bytes that look like a shell prompt can do so directly, at any
  length, and Holdfast cannot tell those bytes from a real shell's. See
  "Documented residuals" below.

What *is* in scope is everything Holdfast claims to do about that execution:
whether the agent is told the truth about what a session is doing, whether a
`terminate` really terminates, and whether the redactor holds.

## In scope

### Secrets crossing the MCP wire

The design routes secret input **client → daemon → PTY**, so a secret never
appears in a tool argument or a tool result, and a redactor runs at every
output boundary including the audit log.

**Both halves ship as of 0.0.7, and neither is finished. Where each one stops,
stated plainly, because a security policy that implies shipped protection is
worse than none:**

- **The redactor ships and runs on every surface that reports a session to
  somebody** — `read_output`, `wait_for_pattern`, `send_input(wait_for:)`,
  the `holdfast://session/…/buffer` resource, `get_screen_state`, `status`,
  `list_sessions`, `get_command_history`, `holdfast logs`, a `holdfast watch`
  stream, and the audit log. A match against the vendored rule set is replaced
  with a `[REDACTED:<kind>]` marker before the bytes leave the process. **One
  boundary deliberately has no redactor, and it is not an oversight:** an
  *interactive* `holdfast attach` connection gets the bytes raw
  (`AttachRole::Interactive`, `attach/conn.rs`), because that client **is** the
  terminal rather than a report about it — it has to render the escape
  sequences a marker would replace. `holdfast watch` connects as
  `AttachRole::Observer` instead, and that role is redacted.
- **Those surfaces are not equally strong, and this file used to average them
  into one sentence.** The cursor-read path — `read_output`,
  `wait_for_pattern`, `send_input(wait_for:)` and the buffer resource — is
  the strong one: matching runs over an expanded window, 512 bytes behind the
  request and 8192 past its cap, so a secret straddling a cursor boundary is
  caught from both sides, and over *every byte stream that read could emit*
  rather than the raw bytes alone — stripped, `lossy_printable`, and the
  8-bit C1 axis where Holdfast's own emulator and a real terminal disagree
  (GH #125, #138, #139). An attached `watch` stream gets that same union and
  the same lookbehind, and no lookahead, having no cap to read past. `status`,
  `list_sessions` and `get_command_history` redact the string they are handed:
  no window, no union. A defence one surface has is not a defence all of them
  have, and a secret that reaches the weaker ones is worth reporting.
- **A secret still *arriving* is held back — unless a control byte has landed
  inside it, and then it is not.** The in-flight test asks whether every byte
  from an indexed prefix to the end of the region could still belong to a
  value, and answers with `0x21..=0x7e` (`is_value_byte`,
  `output/prefix_index.rs`); `ESC` and `BEL` are outside that range, so an
  escape spliced into a token that has not finished arriving ends the run and
  disarms the holdback. Measured on `main` through `read_output` itself,
  `line one\nghp_` with 39 of a GitHub token's 40 characters and a `\x1b[0m`
  inside them: `earliest_partial` answers `None`, `holdback_boundary` returns
  the head it was given, and the read returns those 39 characters with
  `held_back: false` and `redactions: {}`. The **default** path is the worse
  one, because stripping then deletes the escape and hands the agent the 39
  characters contiguous. The same buffer without the escape holds correctly —
  the boundary lands on the token's first byte and the read returns
  `line one\n` with `held_back: true` — which is what this file claimed,
  minus the exception. What escapes is bounded by the matching rule's own
  minimum length less one byte: 39 for a GitHub token, at most 110 across the
  shipped rules (`discord-webhook-url`). Nothing warns the caller. That is
  **GH #142, open**, and the same hole is recorded at `watch`'s observer
  stream, where it caps at the same (rule minimum − 1) but is reached more
  often, the unit there being one PTY read rather than an 8 KiB lookahead
  (GH #135).
- **Every string written to the audit log is redacted unconditionally** —
  including map keys, at any depth — and `[security] redaction_enabled =
  false` is a load error rather than a switch. It is not quite *the same*
  redactor the reads run, and saying so is wrong in both directions: no
  window, no stream union and no holdback, but always the full built-in rule
  set, so an operator's `disabled_redaction_rules` narrows what a client sees
  and never what the trail records.
- **`read_output(redact: false)` is a real escape hatch and returns raw
  bytes.** It exists because a withheld partial has to be reachable somehow.
  Each such read writes a `redaction_disabled` entry to the audit log naming
  the tool and the calling surface. That is by design, not a bypass.
- **The redactor is a pattern matcher, and patterns miss.** It catches
  secret-*shaped* values — the vendored rules cover the common token formats
  — and it cannot catch a password like `correct horse battery staple`, which
  matches no rule. Treat it as defence in depth, not as a guarantee that no
  credential reaches the transcript.
- **The out-of-band secret channel ships as of 0.0.7.** This file called it "a
  later milestone", which was true when it was written at 0.0.3 and has been
  false since `request_secret_input` landed as the twelfth tool. The agent
  calls it; every attached client is told; a human or an operator-declared
  provider answers; the tool returns a status and a byte count — never the
  value, and never a handle that could be exchanged for one. The value travels
  client → daemon → PTY and appears in no tool argument and no tool result.
  It needs a daemon and an attached client, so it is refused as
  `not_supported_on_platform` on Windows, and with nobody attached it waits
  out its `timeout_secs` and answers `secret_cancelled`.
- **That channel refuses to write into a terminal that is still echoing — on
  `main`, and in no tag yet, so a `v0.0.7` install does not have it**
  (GH #137). `request_secret_input` raises `AwaitingSecret` the moment the
  agent calls it, without consulting the child, so an agent that asks before
  its child reaches a password prompt could get a human to type a real
  credential into an echoing terminal — from which the line discipline put it
  in the buffer and `read_output`, the default and redacted path, handed it
  back to that same agent in the clear, an arbitrary password matching no
  rule. The write is now gated on the child's line discipline, sampled
  against the tty one statement before the write rather than against a cache
  of it, and a refused submission is zeroed without reaching the PTY.
  `holdfast attach --allow-echo` is the exemption, for programs that ask for
  a code without ever clearing echo: it is a human's decision at an attached
  terminal, it reaches no tool argument, and it is `false` when absent so a
  client that predates it fails closed. Under it the value is still masked on
  the human's own terminal and still lands in the session's output.
- **`send_input` is not that channel and never was.** It writes whatever the
  agent sends, over the MCP wire, where the argument stays in the transcript.
- **`start_session(env:)` values cross the MCP boundary** and the argument
  documents that ("Do not pass secrets"). Putting a credential there puts it in
  the transcript.

What is in scope **today** is Holdfast putting sensitive material somewhere the
caller did not ask for. One fix of exactly this shape has already shipped:
`portable-pty`'s spawn error embeds the entire `$PATH`, so `start_session`
reports a clipped `envelope::brief(&e)` rather than the raw error, which would
otherwise have landed in the transcript on every failed spawn.

**A bypass of the redactor at any output boundary is squarely in scope** —
including the paths that are easy to forget, such as error strings, the audit
log, and bulk output delivered as a resource rather than inline — which has
landed, and redacts by default like the rest. A secret reaching an MCP
response through a surface that did not run the redactor is a report worth
making; a secret the rule set simply does not match is the documented limit
above.

### Prompt and interaction-state detection

`crates/holdfast-core/src/detect/` — `scanner.rs`, `detector.rs`, `patterns.rs`.

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
  of them, at any length, with no ceiling involved. Holdfast cannot distinguish
  them from a shell's, by construction.
- **`SEQUENCE_MAX` (1 MiB, `scanner.rs`) is a blindness budget, not a forgery
  guard, and does not close.** At the trip point a huge well-formed sequence
  and a truncated one share a byte-identical prefix, so no online rule can act
  differently on them. The discard-to-newline rule leaves a residual: a payload
  carrying a newline hands everything after it to the state machine. This is
  documented at its real reach in `give_up`'s doc comment.
- **The tier-3 pattern table matches raw bytes**, so coloured prompts score 0
  and the table's false-positive surface is wider than it is designed to be.
  0.0.3's ANSI stripper did *not* close this: it runs on the read path
  (`read_output`, `wait_for_pattern`), not ahead of this table. `patterns.rs`
  says so and pins it.

A report that demonstrates one of these residuals is already known. A report
showing a **new** path to a forged state, or one that materially lowers the
cost of reaching an existing one, is valuable.

### Process-group signal handling

`crates/holdfast-core/src/pty/in_process.rs`. `terminate` must kill everything it
owns and **nothing it does not**. Both directions are bugs:

- **Orphans.** The child is spawned with `setsid()` and the PTY as its
  controlling terminal, so PGID == SID == PID. A single `killpg(pgid)` is not
  enough: shell job control puts each background job in its own process group,
  so `terminate` enumerates every process group in the child's session (via
  `/proc` on Linux) and signals each one, re-enumerating on every sweep.
- **Over-reach.** `kill(-0, sig)` signals *Holdfast's own* process group, which is
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
  and no confirmation flow in 0.0.3. They are on the roadmap; their absence is
  not a vulnerability.
- **A secret the rule set does not match.** The redactor recognises
  secret-shaped values; a passphrase in prose matches nothing and is returned.
  A *new pattern* is a welcome contribution rather than a vulnerability
  report. A secret reaching the agent through a path that skipped the redactor
  entirely is in scope — see above.
- **A program inside a session forging its own detection signals.** It is
  inside the trust boundary.
- **Anything that requires an attacker who already runs as the user running
  `holdfast mcp`.** At that point they can start the shell themselves.
- **Windows.** 0.0.3 is Unix-only. The workspace is kept compiling and
  clippy-clean for `x86_64-pc-windows-gnu`, but signalling returns an error
  there, there is no process-group handling, and `ECHO` is not sampled. Windows
  is unimplemented, not broken.
- **`docs/`.** The design specification and implementation plans are the
  author's local working documents and are deliberately absent from this
  repository and its history. The `§`-numbered references throughout the code
  point into them.
