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

## Continuous integration

Workflows live in `.github/workflows/`. Every push to `main` and every pull
request runs:

| Job | What it runs |
|---|---|
| `hygiene` | `scripts/ci-hygiene.sh` — asserts the workflows have not grown a publish step, a `continue-on-error`, a retry action, a `secrets.` reference, an unpinned action, a missing job timeout, or a checkout that leaves a pushable credential behind |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `windows-cross` | The same clippy invocation against `x86_64-pc-windows-gnu`. A **cross-compilation check, not a test run** — it proves CLASP still *compiles* for Windows; it is not evidence that it *works* there |
| `probe` | `scripts/ci-probe.sh` — toolchain version, pseudoterminal allocation, and every shell and interpreter the suite spawns by name. Eight of `tests/detection.rs`'s 21 tests skip *and report as passing* when their program is absent, so this gate is part of what makes the test job's green mean something |
| `test` | `cargo test --workspace --locked --no-fail-fast -- --test-threads=4 --show-output`, then `scripts/ci-skip-census.sh` over the captured log — which fails on any skipped row the pipeline has not agreed to, **and on an agreed one that stopped happening** |
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
- **fish 4.8.1** (the maintainers' PPA, the only route to a fish ≥ 4 here) —
  zero markers: CLASP's own snippet guard declines to inject, because it probes
  `status test-feature no-mark-prompt` while the feature is *named*
  `mark-prompt`, so the probe answers "unrecognised" on every fish.

So the gap is real, and it is **explicit rather than silent**:
`scripts/ci-skip-census.sh` asserts the set of skipped rows is exactly the one
named row, and fails both on an unexpected skip and on that expected skip
disappearing.

## Documentation

- [CHANGELOG.md](./CHANGELOG.md) — what has landed, and the known limitations
  that are easy to mistake for bugs
- [ROADMAP.md](./ROADMAP.md) — where this is going, as ordered scope groupings
  rather than a schedule
- [CONTRIBUTING.md](./CONTRIBUTING.md) — the checks, and the two testing
  standards this project actually enforces
- [SECURITY.md](./SECURITY.md) — what is in scope. CLASP runs commands on your
  machine by design, so the interesting surface is the machinery around that:
  detection, signals, and the redaction that has not shipped yet.

The design specification and the per-milestone implementation plans are kept
as the author's working documents and are not part of this repository. The
code is meant to stand on its own: every module carries a doc comment
explaining what it does and why, and the tests name the behaviour they pin.

## License

MIT — see [LICENSE](./LICENSE).
