Run the checks that decide whether this tree is shippable, and report a single
verdict with the numbers. Run them all even when one fails — a run that stops
at the first red tells you one thing when it could have told you five.

**CI's own gate**, which must pass:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo nextest run --workspace --locked --no-fail-fast --success-output immediate --no-output-indent 2>&1 | tee test-output.log`,
   then `cargo test --workspace --locked --doc`
4. `./scripts/ci-hygiene.sh`
5. `actionlint .github/workflows/*.yml`
6. `./scripts/mcp-smoke.sh` — the only check that drives the real JSON-RPC wire

**Step 3 needs a tool that is not `cargo test`, and the reason is one word:
attribution.** `cargo test` has no per-test timeout, so a wedged test runs
until something outside kills it — locally, until you notice; in CI, until the
job's `timeout-minutes`. Either way the log names nobody. `cargo nextest`
prints `SLOW`, then `TERMINATING`, then `TIMEOUT`, names the test in each,
keeps what that test printed before it hung, and exits 100. The thresholds
(a warning at 60s, a kill at 300s) are in `.config/nextest.toml` and apply to
this local run exactly as they do to CI's.

`--success-output immediate`, `--no-output-indent` and the `2>&1` are all
three mandatory and none of them looks it. The first is what makes a passing
test's `skipping: …` notice appear at all; the second is what keeps it at
column 0 where `ci-skip-census.sh`'s anchored greps can see it — drop either
and the census reports a clean sweep on a log full of skips. The third is not
tidiness: nextest writes its **entire** stream to stderr and leaves stdout
empty, so without it the `tee` produces a zero-byte file.

The doctest run is a second command because **nextest does not run doctests**
— not a flag, a gap. Both of this workspace's doctests are `ignored`, so it
measures nothing today; it is there so the capability does not disappear
silently.

Then feed the log to the census, which is the rest of what CI's `test` job
does:

```
./scripts/ci-skip-census.sh --self-test
./scripts/ci-skip-census.sh test-output.log
```

**Steps 3 and 5 need three tools, and step 5's two were listed here for months
with neither installed** — a step nobody could run, which is worth exactly as
much as no step. None is packaged in this repo; all three are single static
binaries from their own releases:

```
curl -fsSL https://get.nexte.st/0.9.143/linux -o cargo-nextest.tar.gz
echo "66786b9abe23920d022a182d1416b1bbc8130dd4872a9553d76985a1708dcd1e  cargo-nextest.tar.gz" \
  | sha256sum -c -
tar xzf cargo-nextest.tar.gz -C "$HOME/.cargo/bin" cargo-nextest
```

**Pin the version.** `https://get.nexte.st/latest/linux` moves silently, which
is the whole failure mode this file keeps recording. nextest publishes no
checksums file — same as shellcheck below — so there is nothing to verify
*against* and the most that can be done is to record what was fetched; the
digest above is the 0.9.143 linux tarball, and it is duplicated from `ci.yml`
on purpose, because a pin only CI can read is a pin a developer's local run
does not have.

Step 5's two:

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

Report as: one line per check with the numbers **that run emitted** — quote
nextest's own `Summary [ … ] N tests run: N passed, N skipped` line, the
census's `SKIP CENSUS OK: …`, and the smoke script's own `SMOKE OK (N checks)`
rather than a count from this file. A literal here goes stale silently:
`mcp-smoke.sh` records that its own "all 38 checks" drifted five times with
nothing going red, which is why it now prints its total instead of asserting
one. Then the verdict. Quote what you measured, not what you expected. If a
check could not run, that is a third outcome and belongs in the report as
itself — not as a pass and not as a failure.
