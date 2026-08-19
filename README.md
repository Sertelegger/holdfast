# HOLDFAST — Human-Observable Long-lived Daemon For Agent Shell Terminals

An MCP server that gives AI agents persistent, PTY-backed shell sessions.

The **Human-Observable** in that name is a shipped property from 0.0.6:
`holdfast attach` and `holdfast watch` let a human look at — and take
over — a live session from any terminal. The web UI is still to come; see
[ROADMAP.md](./ROADMAP.md).

> **Status: milestone 0.0.6 — early development.** Eleven tools, hybrid
> mode on Linux/macOS/WSL, Unix only. Sessions live in a background
> daemon and survive the MCP client, so a Claude Code restart no longer
> takes them with it. Output is ANSI-stripped and secret-redacted by
> default. Not yet suitable for real use; see [ROADMAP.md](./ROADMAP.md)
> for what is and is not there.

## What works today (0.0.6)

- `start_session` — spawn a shell or program on a real PTY
- `send_input` — type into it
- `read_output` — read what it printed, using a cursor you carry between
  calls; escape sequences stripped and secrets replaced with
  `[REDACTED:<kind>]` markers by default
- `wait_for_pattern` — block until a regex matches new output, so an
  agent can wait for a command to finish or a prompt to appear instead of
  polling; `send_input(wait_for:)` does the same after a write
- `terminate` — stop it, killing the whole process group
- `status` — what one session is doing right now
- `list_sessions` — every session this server knows about, live or exited
- `get_command_history` — per-command exit codes and output spans, for
  integrated shells
- `get_screen_state` — read the rendered terminal grid of a full-screen
  program, with `diff_from` for incremental updates. VT100 emulation is
  adaptive: it is off for ordinary line-oriented sessions and turns on
  only when something needs the rendered screen
- `resize` — change a session's terminal dimensions. The child gets
  `SIGWINCH`, and the tracked grid reflows so the rendered screen is not
  still clipped at the old width
- `interrupt` — send Ctrl+C to the foreground process group, stopping the
  command that is running without killing the shell hosting it
- `holdfast daemon start|stop|status|run` — manage the background daemon
- `holdfast list` / `holdfast logs <session> [--tail N] [--raw]` — inspect
  sessions from any terminal
- `holdfast attach <session>` — your terminal *becomes* the session. Full
  colour, full TUIs, full keyboard. Detach with **Ctrl-B then d**; the
  session keeps running.
- `holdfast watch <session>` — the same view, read-only and **redacted**.
  Detach with Ctrl+C.

Multiple clients can attach at once: output goes to all of them, and input from
any of them reaches the PTY. When a program asks for a password, every attached
client is told and any of them can answer — without the value ever reaching the
agent. `request_secret_input`, the tool an agent calls to *ask* for that
password, arrives in 0.0.7.

Sessions outlive the MCP client: `holdfast mcp` auto-spawns a daemon on
first use and reconnects to it afterwards. `holdfast mcp --no-daemon` runs
everything in-process instead.

Sessions report **what the program is doing**, not a guess:

- `interaction_mode`: `AtPrompt` | `Executing` | `AwaitingSecret` |
  `Fullscreen` | `Exited`
- `detection_tier`: `semantic` (OSC 133) | `terminal_mode` (bracketed
  paste / alternate screen / termios `ECHO`) | `heuristic` (output
  quiescence × the stronger of prompt patterns and cursor position)

`detection_tier` is there so an agent can tell a measurement from a
guess. Every tool also ships an `outputSchema`, so a client can validate
what it gets back.

### Full-screen programs

VT100 emulation is **adaptive**, and off is the ordinary case: a
line-oriented `bash` session reports `screen_tracking: "off"` from start
to exit and pays nothing for a screen nobody is rendering. It turns on
when the child does something that only makes sense against a rendered
screen — the alternate screen buffer, cursor addressing — and
`get_screen_state` then answers with the grid, the cursor, `alt_screen`
and the window title. Pass `diff_from: <screen_revision>` and the reply
is the escape sequence that turns the screen you last saw into the
current one, instead of the whole grid again.

Tracking is also where the heuristic tier gets its third signal: where
the cursor is sitting relative to a prompt character on the rendered
line. The cursor term is 0 whenever tracking is off, so it can only add
recall, never take it away.

Holdfast answers exactly one terminal query — Primary Device Attributes,
replying `\x1b[?6c` with no optional parameter, so it claims no
capability it does not have. A PTY master is not a terminal, so a shell
that *waits* on a query stalls until its own timeout: measured, `fish`
takes 10.04 s to reach its first prompt with no reply and 0.02 s with
this one answered. The reply is rate-limited, is never recorded as a
`send_input`, and deliberately does **not** count as session activity —
otherwise a child querying in a loop would be immortal. Pass
`terminal_queries: false` to `start_session` to write nothing at all
into the child and accept the stall.

### Shell integration

When the session command is `bash`, `zsh` or `fish`, Holdfast types a
one-line OSC 133 snippet at the first prompt, so the shell marks its own
prompt, command and exit-code boundaries and detection runs at the
`semantic` tier. The snippet wraps whatever `PS1` the shell ended up with
instead of replacing it, does nothing when your configuration already
emits OSC 133, and is not exported — a nested shell is integrated in its
own right. Pass `shell_integration: false` to `start_session` to skip it.

It is **typed into the session, never installed**: there is nothing to add
to an rc file, and `crates/holdfast-core/src/detect/shell.rs` holds the only
copy of each snippet. Anything else — `dash`, `sh`, a REPL, a plain
program — degrades silently to `terminal_mode` or `heuristic`, with no
configuration and no error.

Output is ANSI-stripped and secret-redacted by default: secrets are
replaced with `[REDACTED:<kind>]` markers, and `read_output` with
`redact: false` returns the raw bytes and is recorded in the audit log.
`status` and `list_sessions` redact `command`, `args` and
`prompt.last_line` on the way out, and every string written to the audit
log goes through the redactor first — so a session's own trail cannot
carry the secret whose disclosure it is recording.

The rendered screen is held to the same rule, and is **masked rather
than truncated**: while the redactor is withholding bytes that may turn
out to be the start of a secret, the cells those bytes would have
written read `[REDACTED:unresolved]` and the response carries
`held_back: true`. The exemption that lets a tail read see those bytes
is licensed by `read_output`'s own `tail_lines` / `tail_bytes` argument
— a per-call opt-in `get_screen_state` does not have.

## Build and try it

```bash
cargo build --workspace
./scripts/mcp-smoke.sh                  # raw JSON-RPC smoke test (needs jq)
claude mcp add --scope user holdfast -- "$(pwd)/target/debug/holdfast" mcp
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

## Continuous integration

Workflows live in `.github/workflows/`. Every push to `main` and every pull
request runs:

| Job | What it runs |
|---|---|
| `hygiene` | `scripts/ci-hygiene.sh` — asserts the workflows have not grown a publish step, a `continue-on-error`, a retry action, a `secrets.` reference, an unpinned action, a missing job timeout, or a checkout that leaves a pushable credential behind |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `windows-cross` | The same clippy invocation against `x86_64-pc-windows-gnu`. A **cross-compilation check, not a test run** — it proves Holdfast still *compiles* for Windows; it is not evidence that it *works* there |
| `probe` | `scripts/ci-probe.sh` — toolchain version, pseudoterminal allocation, and every shell and interpreter the suite spawns by name. Ten of `tests/detection.rs`'s 23 tests skip *and report as passing* when their program is absent, so this gate is part of what makes the test job's green mean something |
| `test` | `scripts/ci-skip-census.sh --self-test` (the census's own gates, deleted one at a time against fixtures), then `cargo test --workspace --locked --no-fail-fast -- --test-threads=4 --show-output`, then `scripts/ci-skip-census.sh` over the captured log — which fails on any skipped row the pipeline has not agreed to, on any *assertion* gated off inside a row that ran without an agreed entry, **and on an agreed one of either kind that stopped happening** |
| `package` | `cargo build --release --locked`, the MCP smoke script against the *release* binary, and a downloadable artifact + SHA-256. It `needs:` a green `test`, so the build that gets installed is the build that was tested |

Scheduled: a nightly flake hunt (the suite 20× at 4× oversubscribed
parallelism) and a weekly `cargo mutants` sweep.

**No job here is blocking, and that is a platform limit rather than a
choice.** Required status checks are configured only through branch
protection rules or rulesets, and both are gated to public repositories on
GitHub Free — so on a *private* repository under that plan no check can be
made required at all. **This pipeline observes; it does not gate.** A red job
does not stop a merge; someone has to look. That changes when the repository
goes public, and no check should be made required before it has been
observed red.

**Read the job, not the run.** `gh run list` reports the *run* conclusion, and
a job carrying `continue-on-error` records `failure` while its run records
`success`. That is measured here rather than hypothetical: the weekly
mutation sweep carries a dated calibration exemption (`continue-on-error:
true`, self-expiring 2026-09-09) and has already shown a **green** tick in
`gh run list` for a sweep that tested zero mutants. Until that key is gone:

```bash
gh api repos/Sertelegger/clasp/actions/runs/<id>/jobs \
  --jq '.jobs[] | .name + ": " + .conclusion'
```

**There are no retries.** A retried test hides the class of race this project
has already shipped twice. GitHub's "Re-run failed jobs" button cannot be
disabled, so this one is a commitment rather than a control: **capture the
failing test name and the panic text before you click it.** A test that flakes
gets quarantined with a name and a date, never a retry.

**A schedule that stops firing leaves no red mark**, which is the same failure
mode as a job that cannot fail. GitHub disables scheduled workflows in
repositories that go inactive — documented at 60 days for *public*
repositories and not documented at all for private ones, so treat the private
case as unknown rather than exempt:

```bash
gh workflow list                                # both scheduled workflows must read `active`
gh run list --workflow nightly.yml --limit 5    # newest run younger than a day?
gh run list --workflow mutants.yml --limit 5    # younger than a week?
gh workflow enable nightly.yml
```

Reproduce any job locally — every job body is a command, not YAML logic:

```bash
./scripts/ci-probe.sh
./scripts/ci-hygiene.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-gnu -- -D warnings
./scripts/ci-skip-census.sh --self-test
cargo test --workspace --locked --no-fail-fast -- --test-threads=4 --show-output 2>&1 | tee test-output.log
./scripts/ci-skip-census.sh test-output.log
taskset -c 0,1 env TEST_THREADS=4 ./scripts/ci-flake-hunt.sh 20
```

The `taskset` on the last line is not decoration. What exposes these races is
the ratio of *runnable* threads to available cores, not the thread count:
measured, a race the nightly caught on `main` reproduces on iteration 1 of 20
when pinned to two cores, and did not reproduce in five iterations run bare on
an idle 48-core box. Running the hunt bare on a workstation is a much weaker test than
its `--test-threads=192` banner suggests.

## Platform support — how each platform is verified

| Platform | Verified by |
|---|---|
| Linux x86_64 | **CI** — the full suite on every push and pull request |
| Windows x86_64 | **Cross-compilation check only** — `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu`. Nothing executes. There is no Windows runner and no Windows test job, so runtime behaviour on Windows is unverified. Milestone 0.0.11 |
| macOS (x86_64 / aarch64) | **Owner-run local execution.** GitHub offers macOS runners; not using one is a deliberate decision rather than a constraint. The suite is run on the owner's machine before a release — a documented verification route, not an absent one |
| WSL | Covered indirectly via Linux. GitHub-hosted runners offer no WSL image, so a dedicated runner is post-v0.1.0 |

### What CI does not verify

**`fish` shell integration is unverified at runtime.** `fish` is deliberately
not installed on the runner, so `tests/detection.rs`'s fish row skips — and
installing it would not fix that. Measured 2026-08-13 on the `ubuntu-24.04`
runner image, at both fish versions obtainable on it:

- **fish 3.7.0** (noble's own archive) — the snippet installs and marks
  correctly, and the row still fails on its last command. `(exit 42)` is a
  subshell in `bash` and `zsh` and a *command substitution* in `fish`, which
  rejects it outright, so the shared assertion helper's expected marker stream
  never arrives.
- **any fish ≥ 4.0** — a marker collision. Fish emits OSC 133 natively from
  4.0 onward, and Holdfast's snippet now injects unconditionally: the guard that
  used to decline was deleted, because declining left a session with **no `B`
  marker at all** on 4.0–4.2 (which emit none of their own), so `command` was
  empty forever. Holdfast tags its markers `holdfast=1` and yields **per letter**,
  which is the correct behaviour and is verified — a live fish 4.0.2 session
  driven through the MCP surface reports three commands, exit codes
  `[0, 1, 42]`, `osc133_source: "mixed"`, and no entry for the install line.
  The row still fails because it asserts the *no-collision* marker stream.

So the gap is real, and it is **explicit rather than silent**:
`scripts/ci-skip-census.sh` asserts the set of skipped rows is exactly the one
named row, and fails both on an unexpected skip and on that expected skip
disappearing.

**Spec §11.4's control-path p99 is never asserted in CI.**
`crates/holdfast-core/tests/stress_write_path.rs` asserts it only where
`available_parallelism()` reports at least 8 cores, and GitHub's standard
hosted runners are 2-core on a private repository — so the row runs, guards
its other two assertions (`parsed == 0`, and the produced-bytes floor that
stops the run passing vacuously) on every host, and *reports the p99 instead
of asserting it*. That is deliberate: measured on 2 cores, the sampling loop
gets 13 turns in three seconds instead of ~590, `percentile(0.99)` of
thirteen samples **is** the maximum, and the number describes the Linux
scheduler rather than Holdfast — a real 2-core run of this suite answers
p99 = 1.11 s against a 500 ms budget, where 48 cores answer 731 µs.

It is **explicit rather than silent** the same way the fish row is. The test
prints a `not-asserted: <id> cores=… min_cores=…` line, `ci-skip-census.sh`
censuses those lines against an agreed list exactly as it censuses skips, and
the entry fails the job the day it stops being true — when the runner grows,
or when `P99_MIN_CORES` moves under it. Locally, on a machine with 8 cores or
more, the assertion simply runs and the census says so.

## Documentation

- [CHANGELOG.md](./CHANGELOG.md) — what has landed, and the known limitations
  that are easy to mistake for bugs
- [ROADMAP.md](./ROADMAP.md) — where this is going, as ordered scope groupings
  rather than a schedule
- [CONTRIBUTING.md](./CONTRIBUTING.md) — the checks, and the two testing
  standards this project actually enforces
- [SECURITY.md](./SECURITY.md) — what is in scope. Holdfast runs commands on your
  machine by design, so the interesting surface is the machinery around that:
  detection, signals, and the redactor that now runs at every output boundary.

The design specification and the per-milestone implementation plans are kept
as the author's working documents and are not part of this repository. The
code is meant to stand on its own: every module carries a doc comment
explaining what it does and why, and the tests name the behaviour they pin.

## License

MIT — see [LICENSE](./LICENSE).
