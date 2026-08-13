# Contributing to CLASP

Thanks for your interest. This document covers the local setup, the checks that
have to pass, and the two testing standards this project actually enforces —
they are unusual enough that they trip people up, and they are the reason the
suite is worth anything.

CLASP is **early**. Milestones 0.0.1 and 0.0.2 are merged, nothing is released,
and the surface moves. [ROADMAP.md](./ROADMAP.md) shows what is being built
next; opening an issue before a large change is appreciated.

## Development setup

Requirements: a Unix host (Linux or macOS; WSL counts), the toolchain pinned in
`rust-toolchain.toml` — Rust 1.97 with `rustfmt` and `clippy`, which `rustup`
installs for you on first build — and `jq` for the smoke script.

```bash
git clone https://github.com/Sertelegger/clasp.git
cd clasp
cargo build --workspace
```

To point Claude Code at your build:

```bash
claude mcp add --scope user clasp -- "$(pwd)/target/debug/clasp" mcp
```

`clasp mcp` speaks MCP over stdio and is the only subcommand that does anything
(`clasp version` prints the version). The daemon, `attach`, and the rest of the
CLI are later milestones.

## The checks

All four must pass before a change is ready. There is no CI yet, so running
them locally is the whole gate.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo build --workspace && ./scripts/mcp-smoke.sh
```

`cargo test --workspace` is 272 tests today: 189 unit, 19 in
`tests/detection.rs`, 35 in `tests/integration.rs`, 29 in `tests/schema.rs`.
Many of them spawn real PTYs and real shells, so they are not hermetic and they
are not fast.

`scripts/mcp-smoke.sh` (30 checks) is **the only thing that drives the real
JSON-RPC surface**. Every Rust test asserts against in-process objects, so a
bug that lives in serialisation — a tool whose `outputSchema` never reaches the
wire, a doc comment the router drops, an enum serialised outside its declared
vocabulary — is invisible to all of them and visible only here. Run it after
any change to the tool surface, and **read its header comment before adding a
check to it**; it states two rules that the rest of this file's testing section
generalises.

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

The smoke script is held to the same standard: it fails all 30 of its checks
when pointed at `/bin/true`, so the script itself is known to be capable of
failing.

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
