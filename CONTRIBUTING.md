# Contributing to Holdfast

Thanks for your interest. This document covers the local setup, the checks that
have to pass, and the two testing standards this project actually enforces —
they are unusual enough that they trip people up, and they are the reason the
suite is worth anything.

Holdfast is **early**. Milestones 0.0.1 through 0.0.5 have landed on `main`,
nothing is released, and the surface moves. [ROADMAP.md](./ROADMAP.md) shows
what is being built next; opening an issue before a large change is
appreciated.

## Development setup

Requirements: a Unix host (Linux or macOS; WSL counts), the toolchain pinned in
`rust-toolchain.toml` — Rust 1.97 with `rustfmt` and `clippy`, which `rustup`
installs for you on first build — and `jq` for the smoke script.

```bash
git clone https://github.com/Sertelegger/holdfast.git
cd holdfast
cargo build --workspace
```

To point Claude Code at your build:

```bash
claude mcp add --scope user holdfast -- "$(pwd)/target/debug/holdfast" mcp
```

`holdfast mcp [--no-daemon]` speaks MCP over stdio. By default it runs in
**hybrid mode**: it auto-spawns a background `holdfast daemon` that owns the
sessions, so they outlive the MCP client that started them. `holdfast daemon
run|start|stop [--force]|status [--json]`, `holdfast list [--json]`, `holdfast logs
<session> [--tail N] [--raw]`, and `holdfast version` are all live subcommands.
`holdfast attach`, `watch`, `ui`, `confirm`, and the dangerous-command preflight
are later milestones — see [ROADMAP.md](./ROADMAP.md).

## The checks

All four must pass before a change is ready.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo build --workspace && ./scripts/mcp-smoke.sh
```

CI runs all four on every push and pull request (see
[README.md](./README.md#continuous-integration)), but **it cannot block a
merge**: required status checks need branch protection or a ruleset, and both
are gated to public repositories on GitHub Free. Until this repository goes
public, running these locally is still the actual gate and a red job is
something a human has to notice.

`cargo test --workspace` was 890 tests at the `v0.0.5` tag: 669 unit (666 in
`holdfast-core`'s lib, 3 in `holdfast`'s bin), 23 in `tests/detection.rs`, 71 in
`tests/integration.rs`, 42 in `tests/schema.rs`, 19 in `tests/screen.rs`, 1 in
`tests/stress_write_path.rs`, 1 in `tests/source_guards.rs`, 39 in
`tests/control_protocol.rs`, and 25 in `crates/holdfast/tests/daemon_cli.rs`.
**Treat that count as already stale, not just as a tripwire.** It moved five
times in the course of one milestone review and its own fix: wrong when a
review first measured it, wronger while that review's own fix was being
written two whole suites short, off by two more when a sibling change landed
mid-fix, off by one *again* — a different suite, the `holdfast-core` lib —
between two re-measurements of *this very paragraph* taken minutes apart in
an isolated worktree, and then by nine more when the re-review's own four
fixes landed, one of which added a whole test file. No check in this repository currently fails when this
paragraph goes stale, so do not trust it: run `cargo test -p <crate> --test
<name> -- --list` per target (or `--lib` for the two unit targets) and read
the `N tests` line it prints — that is the only number worth acting on. If
you add a *new* test file, add its row here too, but do not expect the
addition to survive; the durable fix is a check wired into CI the way
`scripts/ci-skip-census.sh` guards skipped tests, and nothing here is that
check yet. Many of the tests spawn real PTYs and real
shells, so they are not hermetic and they are not fast — and two of the
suites are *supposed* to be slow. `tests/screen.rs` and
`tests/stress_write_path.rs` are dominated by real waiting (a 3 s grace
window and a 3 s stress run), so a materially faster result there means the
scenario did not happen, not that the machine is quick.

`scripts/mcp-smoke.sh` (the script counts and prints its own total at the end
of every run, `SMOKE OK (N checks)` or `SMOKE FAILED: F of N check(s) did not
pass`, and **that printed total is the only place the number lives** — a
literal copied into this paragraph went stale five times and nothing went red
when it did, so it is not written here any more) is **the only thing that
drives the real JSON-RPC surface**. Every Rust test asserts against in-process
objects, so a bug that lives in serialisation — a tool whose `outputSchema`
never reaches the wire, a doc comment the router drops, an enum serialised
outside its declared vocabulary — is invisible to all of them and visible only
here. Run it after any change to the tool surface, and **read its header
comment before adding a check to it**; it states two rules that the rest of
this file's testing section generalises.

Clippy is also expected to be clean cross-compiled to Windows
(`cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings`)
if you touch anything platform-gated. Windows is not supported at runtime, but
the tree is kept compiling for it.

## Testing standards

These two are non-negotiable, and both exist because this project measured what
happens without them.

### 1. Every test must be capable of failing

Write the test, then **inject the defect it targets, watch it go red, and
restore the code.** A test you have not seen fail is a test you have not
written; you have written a green line.

This is not a hypothetical. Sixteen tests that could not fail were found and
fixed during milestone 0.0.2, and ten during 0.0.1 — several of the 0.0.1 ones
matched the PTY's echo of their own command line, and so passed against a
session running `sleep 300` instead of a shell. The recurring class has a name
here: **a test whose assertion is weaker than its name.**

The smoke script is held to the same standard: **every check it counts fails
when it is pointed at `/bin/true`**, so the script itself is known to be
capable of failing. That is a check you can run, not a claim to take on trust —
`./scripts/mcp-smoke.sh /bin/true` must report `SMOKE FAILED: N of N check(s)
did not pass` with the same `N` the passing run prints, and an `F of N` where
`F` is less than `N`, or an `N` lower than the passing run's `SMOKE OK (N
checks)`, is a check that went green against a server that never started.

**The invariant is `F == N`, and it carries no number on purpose.** Stating it
as "all 38" made it a fact about a count, and the count moved five times
without the sentence moving with it — 0.0.6 shipped 47 checks of which four
stayed green against `/bin/true` while this paragraph still said 38. `F == N`
is true of any number of checks, so adding a check cannot make it stale.
Two consequences when you add one:

- **A check that asserts the script's own setup is a precondition, not a
  check.** It cannot fail under any server, so counting it makes `F == N`
  false by construction. Make it an `exit`, the way the
  `HOLDFAST_RUNTIME_DIR` guard in the 0.0.6 phase is.
- **A check that drives a `holdfast` subcommand other than `mcp` is still
  substituted** — `$BIN` is the whole binary, so `/bin/true attach …` runs
  in place of the real client. Asserting only its exit status is degenerate,
  because `/bin/true` exits 0. Pair it with output only a live run can
  produce, exactly as `absent` takes a witness.

CI runs the negative control, so this is enforced rather than remembered.

### 2. Pair every positive assertion with the negative that separates it from the degenerate case

An assertion that a correct implementation satisfies is only half a test. Ask
what *else* satisfies it — a constant, an empty response, a hardcoded default —
and add the assertion that rules that out.

Worked examples from the tree:

- `interaction_mode == "AtPrompt"` alone passes against a classifier that
  always says `AtPrompt`, so the same run also drives the session into
  `AwaitingSecret`.
- `exit_code == 0` alone passes against a parser that always says zero, so the
  same run also runs `(exit 42)`.
- `truncated_at_tail == true` needs a case that is *not* truncated beside it, or
  the flag tells every agent that every history has holes.
- A head guard added to a prompt pattern must be pinned from **both** sides: the
  ordinary-output line it was added to reject, *and* a real prompt on the near
  side of that same line. A `%` guard silently zeroed recall for every
  numbered-host prompt for eight spec revisions while the corpus stayed green,
  because the corpus had `hostname% ` and no `build01% `.

Grep the value, not the key. `"outputSchema"` being present says nothing.

### Other testing notes

- Do not mock the PTY when the behaviour under test is about the PTY. `MockPty`
  exists for session and detection plumbing; anything about signals, termios,
  or process groups belongs against a real PTY.
- Anything derived from the detector or the command history must **wait on the
  detector's own state**, not on the buffer's. The reader appends to the buffer
  before it feeds the detector, so "the bytes arrived" is not "the bytes were
  classified" — measured, that window is lost about one run in forty, not one
  in a million.
- Never add a retry loop to make a check pass. A smoke check that is allowed a
  second attempt is a smoke check that cannot go red. If a check flakes on a
  slow machine, lengthen the wait once and fix the synchronisation properly
  after that.

## Code conventions

- **Every module carries a doc comment saying what it does and why.** The design
  spec is not in this repository (see below), so the code has to stand on its
  own. Where a decision was made against an alternative, or corrected after
  measurement, the comment says which — that is why several of them are long.
- Numbers that reach the agent (byte caps, defaults, thresholds) are advertised
  in a tool's schema description *and* defined as a constant. Those two have to
  move together; there is a test that pins each one against its own description,
  because a default that drifts from its documentation is a silently short read
  and looks to the agent exactly like a child that stopped talking.
- A caller's mistake is a **protocol error** (`ErrorData::invalid_params`); an
  operational outcome is a **status envelope**. Do not route one through the
  other.
- The `§`-numbered references in comments (`§8.3`, `§5.4`, …) point into the
  design specification, which is deliberately git-ignored and local to the
  author's machine. If you are working in a clone without `docs/`, say so
  rather than guessing at what a section required.
- `scripts/orphan-req-check.py` and `scripts/artifact-deletion-check.py` are
  author-local tools, not a CI gate: both read the `docs/` spec and plans,
  both exit 3 with a message rather than 0 when `docs/` is absent, and
  neither is invoked from anywhere in this repository. Run them by hand if
  you have `docs/`; on a clone without it they cannot run at all.

## Commits and pull requests

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  scoped by milestone where it applies: `feat(0.0.3): …`, `fix(0.0.2): …`,
  `test(0.0.2): …`, `docs: …`, `chore: …`.
- Open PRs against `main`.
- Small, focused PRs are easier to review. For anything larger than a bug fix,
  open an issue first — the milestone sequence in [ROADMAP.md](./ROADMAP.md) is
  ordered, and work that lands out of order usually has to be redone.
- Say in the PR which of the four checks you ran, and — for a new test — which
  defect you injected to watch it fail.
