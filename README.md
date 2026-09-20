# HOLDFAST — Human-Observable Long-lived Daemon For Agent Shell Terminals

An MCP server that gives AI agents persistent, PTY-backed shell sessions.

The **Human-Observable** in that name is a shipped property from 0.0.6:
`holdfast attach` and `holdfast watch` let a human look at — and take
over — a live session from any terminal. The web UI is still to come; see
[ROADMAP.md](https://github.com/Sertelegger/holdfast/blob/main/ROADMAP.md).

> **Status: `v0.0.7` is the newest tag — early development.** Twelve
> tools, hybrid mode on Linux/macOS/WSL. Sessions live in a background
> daemon and survive the MCP client, so a Claude Code restart no longer
> takes them with it. On Windows there is no daemon: `holdfast mcp`
> serves stdio in-process and sessions end with it — see the
> platform-support table below for what is verified there. Output is ANSI-stripped and secret-redacted by
> default. Not yet suitable for real use; see [ROADMAP.md](https://github.com/Sertelegger/holdfast/blob/main/ROADMAP.md)
> for what is and is not there.

## What works today (`v0.0.7`)

- `start_session` — spawn a shell or program on a real PTY
- `send_input` — type into it
- `request_secret_input` — ask for a password without ever holding one. The
  value is typed by an attached human or resolved by a configured provider
  and goes straight to the PTY; the agent gets back a status and a byte
  count, never the secret
- `read_output` — read what it printed, using a cursor you carry between
  calls; escape sequences stripped and secrets replaced with
  `[REDACTED:<kind>]` markers by default
- `wait_for_pattern` — block until the session stops executing, or until a
  regex matches new output, instead of polling; `send_input(wait_for:)` does
  the same after a write. **The pattern is optional, and for "has the command
  finished?" you want it omitted**: a regex for the *shell's* prompt is a guess
  about the operator's `$PS1`, and against a customised one it never matches, so
  the call reports a timeout for a command that finished long ago. Supply a
  pattern for a **program's** prompt — `Password:`, `(gdb)`, `>>>` — which is
  text no detector knows about
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
- `holdfast attach <session> [--allow-echo]` — your terminal *becomes* the
  session. Full colour, full TUIs, full keyboard. Detach with **Ctrl-B then
  d**; the session keeps running. That works at a password prompt too, and
  **Ctrl+C** there abandons the prompt rather than answering it.
  `--allow-echo` submits secrets even to a program that has not turned
  terminal echo off — see the password note below for what that costs.
- `holdfast watch <session>` — the same view, read-only and **redacted**.
  Detach with Ctrl+C.

Multiple clients can attach at once: output goes to all of them, and input from
any of them reaches the PTY. **One terminal hosts one interactive client per
session, though** — a second `holdfast attach` from a terminal that already has
one is refused with `terminal_busy`, because two processes reading one keyboard
are handed alternate keystrokes by the kernel and neither reliably sees a
detach. Attach from another window instead. The session's size is the smallest
attached writer's, so another client's window can narrow what a program sees. When a program asks for a password, every attached
client is told and any of them can answer — without the value ever reaching the
agent, **provided the program turned terminal echo off**, as `sudo`, `ssh` and
`gpg` do. If it did not, the terminal echoes what it is given straight into the
session's output, where the agent reads it; so Holdfast refuses that write and
tells you why rather than delivering it. `holdfast attach --allow-echo` sends it
anyway, for the programs that ask for a code or an API key without ever clearing
echo — the value is still masked on your own terminal, and it will still appear
in the session's output. `request_secret_input`, the tool an agent calls to *ask* for that
password, ships in 0.0.7 and is one of the twelve above. It was not: this
sentence said twelve while the list above it enumerated eleven, and
`request_secret_input` — the tool the sentence is about — was the one it
left out.

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
— a per-call opt-in `get_screen_state` does not have, and neither does
`holdfast logs --tail`, which asks for the tail inside the holdback.

## Build and try it

```bash
cargo build --workspace
./scripts/mcp-smoke.sh                  # raw JSON-RPC smoke test (needs jq)
claude mcp add --scope user holdfast -- "$(pwd)/target/debug/holdfast" mcp
```

**Those commands assume a git checkout, and that is the only way in
today.** `cargo install holdfast` resolves the `0.0.0` name reservation on
crates.io and errors with "there is nothing to install"; the shipped
GitHub Releases carry no binary assets. Publishing either is this
project's *first external distribution* — a decision it has not taken, and
one that changes what several in-tree escapes are allowed to do (see
[CONTRIBUTING.md](https://github.com/Sertelegger/holdfast/blob/main/CONTRIBUTING.md#no-binary-assets)).
When it is taken, releases are the channel and crates.io the source-build
fallback beside it.

### As a Claude Code plugin

This repository doubles as its own plugin marketplace, so the install is two
lines:

```
/plugin marketplace add Sertelegger/holdfast
/plugin install holdfast@holdfast
```

**That path does not work yet, and the missing piece is named rather than
implied**: the plugin's bootstrap downloads a prebuilt binary from the GitHub
Release matching `plugin/version.txt`. `release.yml` now builds and attaches
the five §12.1 assets and a `SHA256SUMS.txt` — but to a **draft** release, and
a draft's assets are not served from `releases/download/vX.Y.Z/` at all. The
bootstrap therefore still finds nothing to fetch until a human promotes a
draft, which is the first-external-distribution decision and is deliberately
not automated. Until then the two lines above install a plugin whose MCP
server fails to start with a message naming the manual install.
`plugin/README.md` documents that fallback, the safe-extraction rules the
bootstrap enforces on what it downloads, and the one thing about the Windows
entrypoint that is still unverified.

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
| `hygiene` | `scripts/ci-hygiene.sh` — asserts the workflows have not grown a `continue-on-error`, a retry action, an unpinned action, a missing job timeout, or a checkout that leaves a pushable credential behind. The publishing rules — a `secrets.` reference, `cargo publish`, `gh`, a write permission — are **scoped rather than absolute**, and `release.yml` is the one file they do not apply to: it declares itself a release workflow and the script verifies that claim by requiring its `on:` block to name `tags:` and to name none of `branches:`, `pull_request` or `schedule` before granting the exemption |
| `actionlint` | `actionlint` 1.7.12, installed against its published checksums, over `.github/workflows/*.yml`. It runs `shellcheck --version` first and fails if that is absent: actionlint shells out to shellcheck to lint the shell inside every `run:` block, and with it missing skips that silently and still exits 0 — so the check most likely to find a real defect would be the one that quietly did not run. `dev/workflows/verify.md` listed this under *"CI's own gate, which must pass"* from the day it was written, and CI did not run it |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `windows-cross` | The same clippy invocation against `x86_64-pc-windows-gnu`, on a Linux runner. A **cross-compilation check, not a test run** — it proves Holdfast still *compiles* for Windows, against the GNU ABI, in about two minutes. It was red on `main` from before 0.0.6 until #19 |
| `windows-native` | `windows-2022`. Native **MSVC** clippy over `--all-targets` (the ABI a Windows user actually installs, which `windows-cross` does not check), `tests/source_guards.rs`, a **filtered `--lib`**, and the `#[cfg(windows)]` CLI arms executed: the daemon-backed subcommands must exit 64 and name the reason, `daemon stop` must exit 0 (§3.2 is idempotent). The `--lib` filter names only the modules whose Windows arm differs from its Unix one, and it is load-bearing: it is the only gate anywhere that kills the `.append(true)` → `.truncate(true)` mutation, which would zero the §9.4 audit trail on every start. This row said "`--lib` is not run" — read that as the **full** `--lib`, which is not: 55 of its tests spawn a real shell — measured 721 passed / 55 failed natively — and gating those is 0.0.11's |
| `macos-native` | `macos-14` — **the third platform, and the one this project develops on.** The full suite on a BSD kernel under `cargo-nextest` at a pinned digest, plus the shells the detection rows spawn and a check that the GH #96 exclusion is still earning its place. It exists because the defects it catches are runtime and kernel-shaped — pty buffering, accept ordering, line discipline — and a cross-compile cannot see any of them: a `#[cfg]` split that deleted the arm for every BSD compiled cleanly on both platforms anyone had tested. Free while this repository is public, and the first job to revisit if it ever is not |
| `plugin` | The plugin and marketplace layer: `scripts/plugin-manifest-check.py` and its twelve breakage fixtures, shellcheck plus `dash -n`/`sh -n` over every shell file the plugin ships, and the bootstrap's safe-extraction rules against a generated corpus of 19 hostile tar archives and 12 hostile zips. **Four cells here and a fifth on `macos-native`**: dash + GNU tar unprivileged; bash with GNU tar and again with bsdtar, which together are what macOS `/bin/sh` and macOS `tar` are; busybox ash + busybox tar as root in a digest-pinned Alpine container; and the PowerShell extractor under `pwsh`. The cells are not repeats of each other — the bash cells exist because a bomb cap written in `ulimit -f` blocks is twice as large under bash as under dash, and every Linux cell used to be dash or busybox. Each check is deleted in turn and the corpus must go red; the post-extraction check is invisible outside the busybox-as-root cell, and every rejection is matched against the message of the check the case was written to provoke rather than against a non-zero status alone — which is itself what makes the mode check load-bearing in the busybox cell, where a bare exit-status assertion let a later check cover for its deletion. Then the download path itself, against a fabricated release served over loopback HTTP, because `release.yml` attaches its binaries to a *draft* and a draft's assets are not served from `releases/download/` — so there is no real release to point this at, and there will not be one until a human promotes a draft |
| `probe` | `scripts/ci-probe.sh` — toolchain version, pseudoterminal allocation, and every shell and interpreter the suite spawns by name. Host-dependent rows of `tests/detection.rs` skip *and report as passing* when their program is absent, so this gate is part of what makes the test job's green mean something. The exact set is pinned by `scripts/ci-skip-census.sh` rather than counted here (GH #74) |
| `test` | `scripts/ci-skip-census.sh --self-test` (the census's own gates, deleted one at a time against fixtures), then `cargo nextest run --workspace --locked --no-fail-fast -j 4 --success-output immediate --no-output-indent`, then `cargo test --workspace --locked --doc` because nextest runs no doctests, then `scripts/ci-skip-census.sh` over the captured log — which fails on any skipped row the pipeline has not agreed to, on any *assertion* gated off inside a row that ran without an agreed entry, **and on an agreed one of either kind that stopped happening** |
| `fish-req-ts-008` | `ubuntu-24.04` with fish 4.x from `ppa:fish-shell/release-4`, running REQ-TS-008's three-arm row and nothing else — the measurement §4.5.1's decision to write unsolicited bytes into a child's stdin rests on, which had executed nowhere in this pipeline until 0.0.4. It gets its own job because installing fish in `test` takes `tests/detection.rs`'s fish row red for a defect that is not the pipeline's; the `detection` binary is never invoked here, so that row's agreed skip is untouched. Not gated on `probe` — fish is deliberately not among the shells the probe asserts |
| `package` | `cargo build --release --locked`, the MCP smoke script against the *release* binary, and a downloadable artifact + SHA-256. It `needs:` a green `test`, so the build that gets installed is the build that was tested |

Not in the table above, because the table enumerates `ci.yml`: **`release
rehearsal`** (`release-rehearsal.yml`) builds, packs, checksums, verifies and
safely extracts all five §12.1 release assets on every pull request, on
`ubuntu-24.04`, `macos-15`, `macos-15-intel` and `windows-2022`. It exists
because `release.yml` is tag-triggered and holds a write token, so the only
other way to find out whether it works is to cut a tag and hope. It publishes
nothing and holds no token; the one command it cannot exercise —
`gh release create` — is named as the residual in `release.yml`'s own header.
**It is not a required status check**, and it is the larger half of that gap.
Eighteen contexts report on a commit and **eleven** gate it; the seven that do
not are this workflow's `assemble` job, its five `pack` matrix cells, and
`ci.yml`'s own `plugin` job below. An earlier draft of this sentence said
"exactly two such gaps" — it had counted workflows, where the unit branch
protection uses is contexts, and a matrix job is one entry that becomes five.
Count them rather than trusting the number:

```bash
comm -13 \
  <(gh api repos/Sertelegger/holdfast/branches/main/protection \
      --jq '.required_status_checks.contexts[]' | sort) \
  <(gh api "repos/Sertelegger/holdfast/commits/main/check-runs?per_page=100" \
      --jq '.check_runs[].name' | sort -u)
```

Add them alongside the eleven, or they are gates that can go red unnoticed.

Scheduled: a **weekly** flake hunt (Sundays — the suite 100× at 4×
oversubscribed parallelism) and a **monthly** `cargo mutants` sweep (the 1st).
Both were cut back from nightly/weekly while this repository was private, when
the account's 2000-minute Actions free tier ran out mid-month — **and that is
no longer the reason.** Standard runners on a public repository do not draw on
the free tier at all, which is the same fact that made `paths-ignore` pointless
to keep. The reduced cadence stays as a deliberate choice resting on runtime
rather than billing: `nightly.yml`'s own measurement puts the 100-iteration
hunt at ~54 min against its `timeout-minutes: 180`, where the cadence it
replaced reached the cap, and the sample count given up is recorded there as a
knowing trade. `nightly.yml` keeps its name because REQ-TST-004's tier-4 work
belongs there, not because it runs nightly.

**Eleven of these twelve jobs gate `main`, and this paragraph said for
months that none did.** Classic branch protection is live: a pull request is
required, all eleven contexts must be green, `strict` forces the branch up to
date with `main` before merge, conversations must be resolved, force-push and
deletion are blocked, and `enforce_admins` is on — so the owner has no bypass
either. The eleven are `actionlint`, `clippy`, `fish-req-ts-008`, `fmt`,
`hygiene`, `macos-native`, `package`, `probe`, `test`, `windows-cross` and
`windows-native`. Read them off the API rather than off this list:

```bash
gh api repos/Sertelegger/holdfast/branches/main/protection \
  --jq '.required_status_checks.contexts'
```

That became possible only when the repository went public on **2026-09-02**:
branch protection and rulesets are gated to public repositories on GitHub
Free. (That date read 2026-09-01, which is the `v0.0.7` tag's date and not
this repository's: going public was done by deleting and recreating the
repository, so the object's own `created_at` — `2026-09-02T07:06:34Z`, matching
its `PublicEvent`, and *after* the tag it now holds — is the event.
`gh api repos/Sertelegger/holdfast --jq .created_at` is the check.)

**The twelfth job, `plugin`, is not required**, and that is the gap worth
naming: it is the only gate on `scripts/plugin-manifest-check.py`, which holds
`plugin/version.txt` and `plugin/.claude-plugin/plugin.json` in lockstep with
the workspace version. The guard on the release version bump can therefore go
red without stopping the merge that broke it — the same hole `release
rehearsal` has, for the change most likely to trip it.

Turning them on took one prerequisite and one rule, and both are now
history rather than plan. The prerequisite was `paths-ignore`: a workflow
filtered out at the `on:` level posts no check at all, so a required check
would have left every docs-only PR pending forever. That filter was deleted
first. The rule is the CI plan's — **do not require a check until it has been
observed red** — which is why `windows-cross` could not have been required
before #19, and why each of the eleven was added only after a run of it had
actually failed. `plugin` and `release rehearsal` get the same treatment
whenever they are added.

**Read the job, not the run.** `gh run list` reports the *run* conclusion, and
a job carrying `continue-on-error` records `failure` while its run records
`success`. That was measured here rather than hypothetical: the mutation
sweep carried a dated calibration exemption and showed a **green** tick for a
sweep that tested zero mutants. **That key is now gone** — a surviving mutant
fails the job — so this is the general technique rather than a live
workaround, and it still matters for reading any run whose jobs disagree:

```bash
gh api repos/Sertelegger/holdfast/actions/runs/<id>/jobs \
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
gh run list --workflow nightly.yml --limit 5    # newest run younger than a week?
gh run list --workflow mutants.yml --limit 5    # younger than a month?
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
cargo nextest run --workspace --locked --no-fail-fast -j 4 --success-output immediate --no-output-indent 2>&1 | tee test-output.log
cargo test --workspace --locked --doc   # nextest does not run doctests
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
| Windows x86_64 | **CI on two jobs, one of them a real runner** — this row read "Nothing executes. There is no Windows runner and no Windows test job" while the CI table above it listed `windows-native` on `windows-2022`, so the same file contradicted itself. `windows-cross` cross-compiles for the GNU ABI on Linux; `windows-native` runs natively: MSVC clippy over `--all-targets`, `tests/source_guards.rs`, a filtered `--lib` over the modules whose Windows arm differs from its Unix one, and the `#[cfg(windows)]` CLI arms *executed* — exit-64 refusals with their reasons for the daemon-backed subcommands, and `daemon stop`'s idempotent 0. What Windows does at run time: `holdfast mcp` serves MCP over stdio in-process and writes the §9.4 audit trail (there is no daemon, so sessions end with the process), and `version` works. What is **still** unverified there is everything that needs a shell or a PTY — the 55 shell-spawning lib tests and the four shell-spawning integration targets do not run on Windows, so session behaviour on the platform rests on no test. Milestone 0.0.11 |
| macOS aarch64 | **CI** — `macos-native` on `macos-14` (arm64) runs the full suite under `cargo-nextest` on every push and pull request, and it is a required check. This row read "Owner-run local execution … GitHub offers macOS runners; not using one is a deliberate decision rather than a constraint" while the CI table above it already listed the job: the same self-contradiction `windows-native` had, in the same file, one table apart |
| macOS x86_64 | **Not tested.** `release-rehearsal.yml` builds, packs, checksums and extracts the `macos-x86_64` asset natively on `macos-15-intel`, but that is a packaging rehearsal and runs no test. Nothing anywhere executes the suite on Intel macOS — do not read the aarch64 row as covering it |
| WSL | Covered indirectly via Linux. GitHub-hosted runners offer no WSL image, so a dedicated runner is post-v0.1.0 |

### What CI does not verify

**`fish` shell integration is unverified BY CI at runtime** — which since
GH #217 / #98 is a statement about the runner's package list and no longer a
statement about the row. `fish` is not installed on the runner, so
`tests/detection.rs`'s fish row skips there. It does **not** skip on a
developer box that has fish, and on noble's own fish it **passes**:

- **fish 3.7.0** (noble's own archive) — **the row passes.** It used to fail
  on its own last command: `(exit 42)` is a subshell in `bash` and `zsh` and a
  *command substitution* in `fish`, which rejects it outright, so nothing ran
  and the shared assertion helper's expected marker stream never arrived. The
  bash-ism was in that helper, not in the fish integration; it now sends
  `sh -c 'exit 42'`, which is one external command in all three shells.
  Installing `fish` on the runner would now turn the skip into a green row.
- **any fish ≥ 4.0** — a marker collision. Fish emits OSC 133 natively from
  4.0 onward, and Holdfast's snippet now injects unconditionally: the guard that
  used to decline was deleted, because declining left a session with **no `B`
  marker at all** on 4.0–4.2 (which emit none of their own), so `command` was
  empty forever. Holdfast tags its markers `holdfast=1` and yields **per letter**,
  which is the correct behaviour and is verified — a live fish 4.0.2 session
  driven through the MCP surface reports three commands, exit codes
  `[0, 1, 42]`, `osc133_source: "mixed"`, and no entry for the install line.
  The row still fails because it asserts the *no-collision* marker stream.

So the gap is real — a fish >= 4 still fails the row, and CI installs no fish
at all — and it is **explicit rather than silent**: `scripts/ci-skip-census.sh`
carries one record per skipped row, keyed on the libtest row name, and fails
both on an unexpected skip and on an expected skip disappearing. That file is
also where the retirement is written down, including which half of it is a
decision and which half is still blocked.

**Spec §11.4's control-path p99 is never asserted in CI.**
`crates/holdfast-core/tests/stress_write_path.rs` asserts it only where
`available_parallelism()` reports at least 8 cores (`P99_MIN_CORES`), and
GitHub's standard hosted Linux runners are 4-core on a public repository — so
the row runs, guards its other two assertions (`parsed == 0`, and the
produced-bytes floor that stops the run passing vacuously) on every host, and
*reports the p99 instead of asserting it*. This clause read "2-core on a
private repository", which was the right number for the wrong repository:
going public on 2026-09-02 doubled the runner and **changed nothing**, because
the gate demands 8 either way. `scripts/ci-skip-census.sh` carries the same
correction in its own header.

Holding the assertion behind that gate is deliberate, and the measurement
behind it is a historical one, taken on the 2-core runner this repository had
while it was private: the sampling loop got 13 turns in three seconds instead
of ~590, `percentile(0.99)` of thirteen samples **is** the maximum, and the
number describes the Linux scheduler rather than Holdfast — that 2-core run
answered p99 = 1.11 s against a 500 ms budget, where 48 cores answer 731 µs.

It is **explicit rather than silent** the same way the fish row is. The test
prints a `not-asserted: <id> cores=… min_cores=…` line, `ci-skip-census.sh`
censuses those lines against an agreed list exactly as it censuses skips, and
the entry fails the job the day it stops being true — when the runner grows,
or when `P99_MIN_CORES` moves under it. Locally, on a machine with 8 cores or
more, the assertion simply runs and the census says so.

## Documentation

- [CHANGELOG.md](https://github.com/Sertelegger/holdfast/blob/main/CHANGELOG.md) — what has landed, and the known limitations
  that are easy to mistake for bugs
- [ROADMAP.md](https://github.com/Sertelegger/holdfast/blob/main/ROADMAP.md) — where this is going, as ordered scope groupings
  rather than a schedule
- [CONTRIBUTING.md](https://github.com/Sertelegger/holdfast/blob/main/CONTRIBUTING.md) — the checks, and the two testing
  standards this project actually enforces
- [SECURITY.md](https://github.com/Sertelegger/holdfast/blob/main/SECURITY.md) — what is in scope. Holdfast runs commands on your
  machine by design, so the interesting surface is the machinery around that:
  detection, signals, and the redactor that now runs at every output boundary.

The design specification and the per-milestone implementation plans are kept
as the author's working documents and are not part of this repository. The
code is meant to stand on its own: every module carries a doc comment
explaining what it does and why, and the tests name the behaviour they pin.

## License

MIT — see [LICENSE](https://github.com/Sertelegger/holdfast/blob/main/LICENSE).
