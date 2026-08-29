---
description: Adversarial pre-PR review — parallel reviewers on disjoint dimensions, in isolated worktrees
argument-hint: "[base ref, default main]"
allowed-tools: Bash(git:*), Bash(cargo:*), Bash(./scripts/:*), Bash(gh:*), Task
---

Review the current branch against `$1` (default `main`) **before** it becomes a
pull request. This is a gate, not a formality: the round that produced it found
**twelve confirmed defects in three commits that had already passed the full
local gate twice**, including two that would have shipped.

## Why it is parallel, and why the lanes are disjoint

One reviewer reads a diff and forms one theory of it. Several reading for
*different failure modes* do not, and the overlap is the signal — in the round
this command comes from, **three of four independently found the same keying
hole**, which is a stronger result than any one of them reporting it.

Pick the lanes from the diff rather than from this list, but these are the ones
that have earned their place here:

- **Concurrency, locking, lifetimes, resource release.** Lock ordering, guards
  held across `.await`, what leaks on the paths that return early.
- **Wire protocol and compatibility.** Version bumps, the golden record, and
  the full skew matrix — old client/new daemon *and* the reverse.
- **Behavioural correctness of the feature itself**, including how it interacts
  with surfaces the author was not thinking about (the MCP tool surface is the
  one that keeps getting missed).
- **Test quality**, which is the highest-yield lane and the one to keep if you
  only run one. See below.

**Each reviewer gets its own git worktree.** `git worktree add --detach
/tmp/<tag>-N HEAD`, removed with `git worktree remove --force` at the end. The
win is build isolation as much as file isolation: reviewers running tests in the
shared tree serialise against each other on the build lock, which is what the
parallelism was for. Tell each one to run **targeted tests only** — a reviewer
running `--workspace` starves the others.

Tell them `docs/` is a git-ignored symlink that is **absent from a worktree**,
so spec claims cannot be checked there. A reviewer that says so is doing it
right; one that infers spec content has invented it.

## What to demand of each reviewer

- **Refute before reporting.** Every finding gets an attempt to disprove it
  first, and the ones that survive say so. A refutation reported is worth as
  much as a finding — it is how "I checked and it is fine" becomes evidence.
- **CONFIRMED vs PLAUSIBLE**, explicitly. CONFIRMED means traced end to end or
  measured, not "read and it looks wrong."
- **A concrete failure scenario**: inputs or interleaving, then the wrong
  outcome. "This could race" is not a finding; "A folds, B applies, A applies
  stale, session sits at a departed client's geometry" is.
- **A cap on findings** (6–8) ranked most severe first, and permission to
  report nothing. Padding is worse than silence because it costs the reader's
  attention on the real ones.

## The test-quality lane, in detail

It finds the most because a green suite is the thing everyone else trusts.
Require **mutation experiments, not opinions**: apply a plausible wrong
implementation, rebuild, run the targeted test, record CAUGHT or SURVIVED,
restore.

**Every mutation must assert that it applied.** A string replacement that
silently matches nothing looks exactly like a survivor, and it has produced a
false finding here twice — once in a reviewer's ledger and once in my own hands
minutes later. In Python: `assert new != old`.

A survivor is the finding. Report the mutation, which test should have caught
it, and what shipping that wrong implementation would do to a user.

Things this lane has actually caught, as a prompt for what to look for:

- A function with **no test at all**, because every other row hand-built its
  input as a literal and never called it.
- An assertion that **cannot fire** — a predicate satisfied by every input it
  was meant to reject, so the test failed elsewhere and looked like it worked.
- A test that passes **for the wrong reason**: the setup never reaches the
  state under test, so the mechanism is untested and the row is green.
- A test that is **probabilistic** where it reads as deterministic: red 40 runs
  in 41.
- A scenario **set up perfectly and then never asserted on**.

## Then

Fix what is confirmed, and **re-run the affected mutations** to prove the fix.
Findings that are judgement calls rather than defects go to the user, not into
a silent decision.

Report as: the lanes run, the count of confirmed findings, the ones that would
have shipped, and what remains open. Say plainly if a reviewer found nothing —
that is a result, and this gate is not scored on how much it finds.
