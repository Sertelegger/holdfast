#!/usr/bin/env bash
# Assert the EXACT set of rows that skipped in a test log.
#
# Eight rows of crates/clasp-core/tests/detection.rs early-`return` when
# their host requirement is unmet. libtest reports every one of them as
# `ok` and swallows the explanation unless `--show-output` is passed, so a
# suite that measured half of what its name promises still prints a green
# pass count. That is the defect this file exists to end.
#
# Two guards already exist and neither closes it:
#
#   * `the_pty_matrix_runs_every_host_dependent_row_but_the_two_it_names`
#     (in the suite) fails on any skip OUTSIDE its allowlist. The two rows
#     INSIDE the allowlist may still skip silently, forever, on any host.
#   * `CLASP_REQUIRE_ALL_SHELLS=1` turns every skip into a failure and
#     would supersede this script entirely. It is not set yet, and the
#     reason is measured and written down in ci.yml above the `test` job:
#     the fish row cannot pass on any fish available today.
#
# So this is the gate for the allowlisted rows while that holds: the set of
# skips is asserted to be EXACTLY the set named below. A new skip fails.
# An expected skip that stops happening ALSO fails — a stale exemption is
# how a gate rots into a comment, and the day fish becomes runnable is the
# day this file and CLASP_REQUIRE_ALL_SHELLS should both change.
#
# Run it locally exactly as CI does:
#
#   cargo test --workspace --locked --no-fail-fast -- \
#     --test-threads=4 --show-output 2>&1 | tee test-output.log
#   ./scripts/ci-skip-census.sh test-output.log
#
# `--show-output` is not optional: without it libtest captures the
# `skipping: …` notices and this script reads a log that cannot contain
# what it is looking for.
set -uo pipefail

log="${1:-}"
if [ -z "$log" ]; then
  echo "usage: $0 <test-log>   (the log of a cargo test run made with --show-output)" >&2
  exit 2
fi
if [ ! -f "$log" ]; then
  echo "SKIP CENSUS FAILED: no such log file: $log" >&2
  exit 1
fi

# Every skip this pipeline tolerates, as a literal line PREFIX, one per
# entry, each with the reason it is tolerated and the condition that
# retires it. Adding an entry here is a deliberate, reviewable act; a row
# that starts skipping without one turns this job red.
#
#   fish — measured 2026-08-13, in containers on the ubuntu-24.04 base
#   image, at both fish versions obtainable there:
#     * fish 3.7.0 (noble's own archive): the snippet installs and marks
#       correctly, and the row still fails, because the shared assertion
#       helper sends `(exit 42)` — a SUBSHELL in bash and zsh, a command
#       SUBSTITUTION in fish, which fish rejects with "command
#       substitutions not allowed here" before running anything.
#     * fish 4.8.1 (the fish maintainers' PPA): CLASP's own guard declines
#       to inject, so the session records zero markers.
#   Neither is CI's to fix and neither is a reason to stop running the
#   other twenty rows. See .superpowers/sdd/2026-08-12-clasp-ci-and-
#   verification-harness/census-flip-report.md for the full measurement.
EXPECTED=(
  "skipping: fish not installed"
)

# --- anti-vacuity: a log that never ran the rows cannot certify them -----
#
# Without this, an empty file, a log from a build failure, or a log whose
# `--show-output` was dropped all produce zero observed skips — and the
# "unexpected skip" check below would pass on every one of them. The
# expected-skip check catches most of that by itself, but only while
# EXPECTED is non-empty, and this file's whole purpose is to shrink
# EXPECTED to nothing.
if ! grep -qE 'tests/detection\.rs' "$log"; then
  echo "SKIP CENSUS FAILED: $log never mentions tests/detection.rs, so it is not" >&2
  echo "a log of a run that could have skipped anything. Did the build fail?" >&2
  exit 1
fi
if ! grep -qE '^test result:' "$log"; then
  echo "SKIP CENSUS FAILED: $log contains no 'test result:' line — no test binary" >&2
  echo "reported a summary, so this log certifies nothing." >&2
  exit 1
fi

mapfile -t observed < <(grep -hE '^skipping: ' "$log" | sort -u)

echo "--- rows that skipped ---"
if [ "${#observed[@]}" -eq 0 ]; then
  echo "  (none)"
else
  printf '  %s\n' "${observed[@]}"
fi

fails=0

# 1. Every observed skip must be one this pipeline has agreed to tolerate.
for line in "${observed[@]:-}"; do
  [ -z "$line" ] && continue
  matched=0
  for want in "${EXPECTED[@]}"; do
    case "$line" in "$want"*) matched=1 ;; esac
  done
  if [ "$matched" -eq 0 ]; then
    echo "  UNEXPECTED SKIP: $line" >&2
    fails=$((fails + 1))
  fi
done

# 2. Every tolerated skip must still be happening. An exemption for a row
#    that now runs is a lie in a file people read to find out what is
#    covered, and it is the exact state this project keeps finding.
for want in "${EXPECTED[@]}"; do
  matched=0
  for line in "${observed[@]:-}"; do
    case "$line" in "$want"*) matched=1 ;; esac
  done
  if [ "$matched" -eq 0 ]; then
    echo "  STALE EXEMPTION: nothing skipped with the prefix '$want'." >&2
    echo "  If that row now runs, DELETE the entry — and check whether" >&2
    echo "  CLASP_REQUIRE_ALL_SHELLS=1 can be set in ci.yml and nightly.yml," >&2
    echo "  which supersedes this script entirely." >&2
    fails=$((fails + 1))
  fi
done

echo
if [ "$fails" -ne 0 ]; then
  echo "SKIP CENSUS FAILED: $fails finding(s)" >&2
  exit 1
fi

# Green here means "the shortfall is exactly the one we know about", which
# is not the same as "nothing was skipped" and must not read like it. Say
# so on the run summary page, every run, so the exemption is visible to
# someone who never opens the log — and say the OTHER thing on the day
# EXPECTED is empty, rather than carrying a sentence about fish into a run
# where fish ran.
if [ "${#observed[@]}" -gt 0 ]; then
  note="skip census: ${#observed[@]} tolerated skip(s), 0 unexpected — the row(s) above did NOT run"
else
  note="skip census: nothing skipped — every host-dependent row ran"
fi
echo "SKIP CENSUS OK: $note"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    printf '### Skip census\n\n'
    printf '%s\n\n' "$note"
    # Guarded, because the state this file exists to reach is EXPECTED
    # empty and nothing skipping, and `printf` with an empty array would
    # still emit one empty bullet — a summary that reports a skip that
    # does not exist.
    [ "${#observed[@]}" -gt 0 ] && printf -- '- `%s`\n' "${observed[@]}"
  } >> "$GITHUB_STEP_SUMMARY"
fi
# No annotation when nothing skipped: a warning on a run with full
# coverage trains people to ignore the warning that means something.
if [ "${#observed[@]}" -gt 0 ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
  printf '::warning::%s\n' "$note"
fi
