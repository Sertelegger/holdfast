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
`rust-toolchain.toml` with `rustfmt` and `clippy`, and `jq` for the smoke
script.

```bash
git clone https://github.com/Sertelegger/holdfast.git
cd holdfast
./scripts/preflight.sh
cargo build --workspace
```

`rustup` fetches the pinned toolchain on first build **provided `rustup` itself
is current**. An older `rustup` cannot, and it does not say so: the build fails
somewhere inside cargo, with a message about an edition or a feature, and
nothing points at the installer. That is what `scripts/preflight.sh` is for. It
installs nothing and writes nothing — it reads the pin from
`rust-toolchain.toml` and the MSRV from `Cargo.toml`, checks what you have
against them, and prints the exact command for anything missing. If it reports
a version older than the MSRV, the fix is almost always `rustup self update`
first and the toolchain install second, in that order.

To point Claude Code at your build:

```bash
claude mcp add --scope user holdfast -- "$(pwd)/target/debug/holdfast" mcp
```

`holdfast mcp [--no-daemon]` speaks MCP over stdio. By default it runs in
**hybrid mode**: it auto-spawns a background `holdfast daemon` that owns the
sessions, so they outlive the MCP client that started them. `holdfast daemon
run|start|stop [--force]|status [--json]`, `holdfast list [--json]`, `holdfast logs
<session> [--tail N] [--raw]`, `holdfast attach <session> [--allow-echo]`, `holdfast watch
<session>`, and `holdfast version` are all live subcommands: **`attach` and
`watch` shipped in 0.0.6**, which this paragraph listed as later milestones
until it was checked against the CHANGELOG. `holdfast ui`, `holdfast confirm`
and the dangerous-command preflight still are — see
[ROADMAP.md](./ROADMAP.md).

## The checks

All four must pass before a change is ready.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo build --workspace && ./scripts/mcp-smoke.sh
```

CI runs all four on every push and pull request (see
[README.md](./README.md#continuous-integration)), but **no check is required
yet**, so a red job does not block a merge and someone has to notice. That is
now a choice rather than a limit — required status checks need branch
protection or a ruleset, both of which are available on a public repository
under GitHub Free, and this one has been public since **2026-09-02** — the
repository object's own `created_at`, since going public was done by deleting
and recreating the repository. This read 2026-09-01, which is the `v0.0.7`
tag's date and therefore predates the object that holds the tag. Until a
check is actually marked required, running these locally is still the gate.

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
if you touch anything platform-gated — and CI now checks the **other** ABI
natively as well, on a `windows-2022` runner, so an arm that cross-compiles
clean for the GNU target can still fail the MSVC job.

"Windows is not supported at runtime", which this paragraph said, is no longer
the right shape. `holdfast mcp` serves MCP over stdio in-process there and
writes its audit trail, `version` works, and the daemon-backed subcommands
refuse by name because the design gives that platform no daemon rather than
because nothing works. What is genuinely unsupported is anything needing a shell or a
PTY, which is why the Windows job runs the source guards, the `#[cfg(windows)]`
CLI arms and a *filtered* `--lib` rather than the suite. The README's
platform-support table is the current account of what is verified there.

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
- `scripts/orphan-req-check.py`, `scripts/artifact-deletion-check.py` and
  `scripts/spec-enum-check.py` read the `docs/` spec and plans, and all three
  exit 3 with a message rather than 0 when `docs/` is absent. Run them by
  hand if you have `docs/`; on a clone without it they cannot run at all. The
  first two are invoked from nowhere in this repository. `spec-enum-check.py`
  is the exception in one direction only: its **`--self-test` runs in the
  `hygiene` job**, because that arm is fixture-driven and needs no document,
  and a parser whose own tests never run is a parser on trust. Its real
  invocation is still author-local, and it finds the spec from a git
  worktree — where `docs/` is not materialised — by falling back to the main
  checkout, so a reviewer can run it where reviewers actually work.

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

## Releases

`CHANGELOG.md` is the release. A GitHub Release is a pointer to it: the body is
that version's section verbatim, and nothing that matters about a release lives
only in the GitHub object — release prose is not in the repository, is not
reviewed with the code, and does not survive the repository being recreated.

Cutting one is therefore:

1. Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD`.
2. Add the matching link definition at the foot of the file, and repoint
   `[Unreleased]` at the new tag's compare range. **Every version needs a
   definition** — a missing one is why `[0.0.5]` and `[0.0.6]` rendered with
   visible brackets for two releases while `[0.0.7]` did not.
3. Open a fresh empty `## [Unreleased]`.
4. Bump the version to match in **four files and six literals**, and
   commit. **This step said "three files and four literals" until `Cargo.lock`
   was measured against it.** The count is restated rather than softened to
   "the version files": a procedure that names a number is one a reader can
   check themselves against, and this one was wrong for as long as it was
   uncheckable. Two of the six are in
   the root `Cargo.toml`: `[workspace.package] version` is the obvious one,
   and `holdfast-core = { path = "crates/holdfast-core", version = "X.Y.Z" }`
   under `[workspace.dependencies]` is the second. That one exists because
   crates.io rejects a path-only dependency and there is no
   `version.workspace` to inherit inside a dependency spec. **A stale second
   literal fails no build and no test** — the workspace still resolves it by
   path — and surfaces only as a *published* `holdfast` bound to an older
   `holdfast-core`, which is a wrong permanent artifact rather than a red
   check. The two are declared six lines apart so that one edit sees both.

   Two more are `plugin/version.txt` and
   `plugin/.claude-plugin/plugin.json`. The design spec names only
   `Cargo.toml` and `version.txt`, and the third file is the one that matters
   most to an installed user — the plugin install cache is keyed
   `cache/<marketplace>/<plugin>/<version>/` from `plugin.json`, so a release
   that bumps the other two ships a plugin that never updates itself.
   `scripts/plugin-manifest-check.py` fails if the three files disagree, and
   the `plugin` CI job runs it — **but `plugin` is the one `ci.yml` job that
   is not a required status check**, so that guard does not block a merge.
   Run the script yourself rather than waiting to be told.

   **The last two are in `Cargo.lock`, and forgetting them breaks every
   build.** It records a version for each workspace member —
   `[[package]] name = "holdfast"` and `[[package]] name = "holdfast-core"`,
   two `version = "X.Y.Z"` lines about sixteen apart — and **every check in
   this repository passes `--locked`**, including the release build. Bump
   `Cargo.toml` without relocking and each of them stops dead with

   ```
   error: cannot update the lock file /…/Cargo.lock because --locked was passed to prevent this
   ```

   A bare `cargo build` does **not**: with no `--locked` it relocks silently
   and succeeds, which is how this reaches a pull request feeling fine and
   fails in CI. Do not hand-edit the lock; run:

   ```bash
   cargo update --workspace --offline
   ```

   `--workspace` restricts it to the members, `--offline` guarantees it
   reaches no network, and together they are a two-line diff: measured on a
   `0.0.7` → `0.0.8` bump it printed `Locking 2 packages to latest compatible
   versions`, named the two members, and changed exactly those two `version`
   lines out of a thousand — the other 34 dependencies were untouched. Commit
   `Cargo.lock` with `Cargo.toml` in the same commit; they are one edit.

   **If you bump only one of `Cargo.toml`'s two literals, the error is a
   different one and never mentions the lock file**, which sends you the
   wrong way. Measured:

   ```
   error: failed to select a version for the requirement `holdfast-core = "^0.0.7"`
   candidate versions found which didn't match: 0.0.8
   ```

   That is the six-literal count failing, not the relock. Fix step 4 first.
5. **Update the version references in the prose.** None of these fails a
   check, and each one is read as fact:

   - `SECURITY.md` — "`v0.0.7` is the newest" in the first paragraph, the
     `` `v0.0.5` – `v0.0.7` `` row of the support table, and the
     out-of-band-secret bullet saying that echo gating is "on `main`, and in
     no tag yet, so a `v0.0.7` install does not have it" (that one becomes
     *wrong*, not merely stale, the moment the tag exists).
   - `README.md` — the status line and the `## What works today (vX.Y.Z)`
     heading near the top.
   - `CLAUDE.md` — the "Project Status" paragraph, which pins the newest tag,
     quotes that version's `CHANGELOG.md` heading verbatim, and states the
     workspace version; and the paragraph after it, which names
     `git log vX.Y.Z..main`.

   `grep -rn "0\.0\.7" --include='*.md' .` finds them plus anything added
   since this list was written, which is the point of running it rather than
   trusting the list. Most of its hits are in `CHANGELOG.md` and are
   **history** — a released section names its own version forever. Change
   only the claims about what is *newest*, *current* or *not yet tagged*.
6. Tag `vX.Y.Z` and push the tag. That triggers
   `.github/workflows/release.yml`, which checks that the tag, the crate
   version and a changelog section with actual content in it all agree, then
   publishes the release with that section as the body and the name derived
   from its heading. **The codename must be on the heading before the tag is
   pushed**, or the release ships without it.

   The changelog half of that check is `scripts/release-notes.sh`, and it is
   worth knowing what it used to do: the guard was written inline and ran
   *after* the step had appended every link definition to the file it was
   testing, so it could not fire. A tag pushed with step 1 skipped — easy,
   because steps 4 and 6 alone are self-consistent — would have published a
   release whose entire body was 47 bare link definitions. It now refuses,
   and `ci.yml`'s `hygiene` job runs the script's fixtures so that it keeps
   refusing.
7. **The release is a DRAFT.** `release.yml` attaches five platform binaries
   and a `SHA256SUMS.txt`, and a draft's assets are not served from
   `releases/download/vX.Y.Z/`. Before promoting, `curl -I` an asset URL
   unauthenticated and confirm it 404s, then re-read what the workflow prints:
   promoting is *first external distribution*, and several deliberate escapes
   in this tree are conditioned on that not having happened.

### crates.io

`release.yml` carries a second job, `crates-io`. It `needs:` the GitHub
Release above — crates.io goes last because a version, once uploaded, can be
yanked but never reused or replaced, while a GitHub Release can be deleted
and recreated — and then runs `cargo publish --workspace --locked`.

**Today that job does nothing, and cutting a release is unchanged by it.**
It is gated on a `CARGO_REGISTRY_TOKEN` repository secret that does not
exist. With the secret absent its first step records `publish=false`, every
later step is `if:`-ed off, and the job is one shell command that prints why
it stopped and exits green. Nothing is uploaded. The gate is written that
way, rather than as an `if:` on `secrets.*`, because `secrets` is not an
available context in either a job-level or a step-level `if:` — there the
expression is empty, and a job gated on an empty string runs
unconditionally.

Two things about it are worth knowing before it is switched on:

- **It publishes `holdfast-core` first, and must.** `holdfast` cannot
  resolve until core is on the index, and `--workspace` is what orders the
  members and waits for each upload to appear there. If a run half-succeeds
  — core uploaded, the binary crate not — a re-run does not recover it: core
  is already uploaded and cargo refuses. Recovery is a manual
  `cargo publish -p holdfast`.
- **Its version check is behind the same gate.** The step that compares the
  tag against both `Cargo.toml` literals only runs when the token is
  present, so with no token nothing in this repository catches a stale
  dependency literal. Step 4 above is the entire defence until then.

**Adding that secret is a decision, not a configuration step.** It is done
in the GitHub UI: no diff, no PR, no review, and no record here — the
repository records that the job *reads* the secret, never whether it is set.
What it changes is that the next tag uploads a permanent, unreplaceable
artifact, and that is **first external distribution**: the event the note
below says binds this project's compatibility promises, and that several
deliberate in-tree escapes are conditioned on not having happened. Decide it
deliberately, and record here when it was decided.

### Naming

**`holdfast X.Y.Z (Codename)`.** No `v` prefix, and no descriptive suffix —
the codename is the only thing after the number. The tag keeps its `v`
(`v0.0.7`); the release *name* does not.

Three releases shipped before this was settled and still read
`holdfast 0.0.5`, `holdfast 0.0.6 — the attach protocol` and
`holdfast v0.0.7` — three conventions in three releases. Renaming them is
outstanding.

**Nothing types this by hand.** `release.yml` reads the version off the tag
and the codename off that version's `CHANGELOG.md` heading — the one place it
is already recorded beside its version, so there is no second file to update
and no way for the two to disagree. A version whose heading carries no
codename is named `holdfast X.Y.Z`: the convention minus an optional part,
rather than a different convention.

### Codenames

Fasteners and rigging hardware, alphabetically, one per release in order.
A holdfast is itself a fastener, so the category names the project rather
than decorating it.

| | | | |
|---|---|---|---|
| A Anchor | B Bolt | C Carabiner | D Dowel |
| E Eyebolt | F Ferrule | G Grommet | H Hasp |
| I Insert | J Jig | K Keeper | L Latch |
| M Mandrel | N Nut | O O-ring | P Pin |
| Q Quicklink | R Rivet | S Shackle | T Turnbuckle |
| U U-bolt | V Vise | W Washer | X — |
| Y Yoke | Z Zip-tie | | |

Assigned so far: **0.0.5 Anchor**, **0.0.6 Bolt**, **0.0.7 Carabiner**. None of
the three release objects carries its codename yet; see the renaming note
above.

**X is deliberately unfilled.** No fastener or rigging term starts with it,
and inventing one would break the only rule the list has. It is twenty
releases away; decide it then, and record what was decided here rather than
leaving the next person to rediscover the problem.

### Binary assets, and the draft that keeps them a decision

**Releases now carry the five §12.1 assets and `SHA256SUMS.txt`, and they are
created as drafts.** The three shipped releases carry none, which is why
Holdfast could not be installed by anybody: measured, the only install path was
building from source, and nothing in the repository said so.

This section used to say *"no binary assets"*, and the argument it made is
still the right one — it just decides the `--draft`, not the upload. The event
that binds this project's compatibility promises is **first external
distribution**, and several deliberate escapes are conditioned on it not having
happened: `crates/holdfast-core/tests/wire_shape.rs` rewrites its `1.0.golden`
record in place on the ground that there is no peer in the world speaking 1.0,
and `crates/holdfast-core/src/protocol/method.rs` says in as many words that
*"the latitude ends at the first published binary."* A draft's assets are not
served from `releases/download/<tag>/<asset>`, so building and attaching them
is automation and **promoting the draft is the decision** — one act, taken by
a person, that ends both escapes.

So, cutting a release, after the tag: the `Release` workflow builds all five
targets, assembles `SHA256SUMS.txt` over exactly those five, verifies each
archive against it under §13.3's safe-archive rules, and creates the draft.
Then, by hand:

1. `curl -I` an asset URL **unauthenticated** — it must 404 while the release
   is a draft. That is the measurement that the event has not happened yet.
2. Re-read the two escapes above. Promoting ends them.
3. `gh release edit vX.Y.Z --draft=false`.
