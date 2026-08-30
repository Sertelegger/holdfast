# Development workflows

Procedures for working **on** Holdfast. They are prose, not slash commands,
and that is deliberate: this repository doubles as its own Claude Code plugin
marketplace, so anything under `.claude/commands/` reads as part of the
product's command surface. A gate that only means something with the source
tree checked out is not part of the product.

- [`verify.md`](./verify.md) — the full local gate: fmt, clippy across every
  installed target, the suite, the smoke script against the real JSON-RPC wire,
  and the harness-falsification run. What CI does, plus the cross-platform part
  CI structurally cannot do, since every workflow runs `ubuntu-24.04`.
- [`review.md`](./review.md) — the adversarial pre-PR review: parallel
  reviewers on disjoint failure modes, each in its own worktree.

**They live here rather than in the private docs repo because they name things
in this tree** — `scripts/ci-hygiene.sh`, specific target triples, invariants
that move when the code moves. Separated from the code they reference, they
would drift silently, which is the failure this project keeps finding in its
own documentation.

`.claude/commands/holdfast/` keeps `doctor` and `sessions`, which diagnose and
inspect a *running* install and are useful to someone using Holdfast rather
than developing it.
