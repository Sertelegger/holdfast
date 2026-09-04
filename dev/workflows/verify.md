Run the checks that decide whether this tree is shippable, and report a single
verdict with the numbers. Run them all even when one fails — a run that stops
at the first red tells you one thing when it could have told you five.

**CI's own gate**, which must pass:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo test --workspace --no-fail-fast`
4. `./scripts/ci-hygiene.sh`
5. `actionlint .github/workflows/*.yml`
6. `./scripts/mcp-smoke.sh` — the only check that drives the real JSON-RPC wire

**Step 5 needs two tools, and it was listed here for months with neither
installed** — a step nobody could run, which is worth exactly as much as no
step. Neither is packaged in this repo; both are single static binaries from
their own releases:

```
gh release download "v$VER" --repo rhysd/actionlint \
  -p "actionlint_${VER}_linux_amd64.tar.gz" -p "actionlint_${VER}_checksums.txt"
gh release download v0.11.0 --repo koalaman/shellcheck \
  -p 'shellcheck-v0.11.0.linux.x86_64.tar.xz'
```

actionlint publishes a `checksums.txt` — verify against it. **shellcheck
publishes none**, so there is nothing to verify against and the most that can
be done is to record what was fetched: the 0.11.0 linux x86_64 tarball used
here was `8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198`.

**shellcheck is not optional, and this is the trap.** actionlint shells out to
it to lint the shell inside every `run:` block, and when it is missing it
**skips that silently and still exits 0** — so the check most likely to catch
a real defect in this repo's workflows is the one that quietly does not run.
`ci.yml` is mostly `run:` blocks. Confirm `shellcheck --version` answers
before believing a green from step 5.

**Then the part CI structurally cannot do.** Every workflow runs
`ubuntu-24.04`, so a break confined to another platform reaches `main`
unnoticed. Add, for each of `x86_64-unknown-linux-gnu`,
`x86_64-unknown-freebsd` and `aarch64-apple-darwin` that is installed:

```
cargo clippy -p holdfast-core --all-targets --locked --target <triple> -- -D warnings
```

Skip a triple that is not installed and **say you skipped it** — do not offer
to `rustup target add` unless asked, and never let a skipped target read as a
passed one. These are not decorative: the BSD arm of `session_pgids` has been
deleted once already, and it compiled fine on the two platforms anyone tested.

**Also worth running when the smoke script or its harness changed**, because a
pass count means nothing if the harness cannot fail:

```
./scripts/mcp-smoke.sh /usr/bin/true      # every check must FAIL
```

Report as: one line per check with the numbers **that run emitted** — quote the
`test result:` line and the smoke script's own `SMOKE OK (N checks)` rather than
a count from this file. A literal here goes stale silently: `mcp-smoke.sh`
records that its own "all 38 checks" drifted five times with nothing going red,
which is why it now prints its total instead of asserting one. Then the verdict. Quote what you measured, not what you
expected. If a check could not run, that is a third outcome and belongs in the
report as itself — not as a pass and not as a failure.
