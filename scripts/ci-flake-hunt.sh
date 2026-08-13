#!/usr/bin/env bash
# Run the workspace suite N times under deliberately oversubscribed
# parallelism, and fail on the first failure.
#
# This is the inverse of a retry. A retry hides intermittency; this
# manufactures the load that exposes it, on a schedule, off the critical
# path, where a red result is information rather than an obstacle. The races
# this project has already shipped -- the push-before-feed ordering bug
# closed in a4dc498 among them -- are exactly the shape that a single green
# run misses and twenty contended runs catch.
#
# Usage: ./scripts/ci-flake-hunt.sh [iterations]   (default 20)
set -uo pipefail

iterations="${1:-20}"

# A hunt that runs zero times prints "0/0 green" and exits 0. That is a
# green check that asserted nothing -- this project's defining defect, in
# the one job nobody watches. `seq 1 0` is empty, so the loop below is
# silently skipped for any argument < 1, and `seq` accepts negatives and
# non-integers without complaint. Validate before trusting.
case "$iterations" in
  '' | *[!0-9]*)
    echo "flake hunt: iterations must be a positive integer, got '$iterations'" >&2
    exit 1
    ;;
esac
if [ "$iterations" -lt 1 ]; then
  echo "flake hunt: iterations must be >= 1, got $iterations" >&2
  echo "A hunt of zero iterations reports success without running anything." >&2
  exit 1
fi

# The parallelism the CI `test` job uses. This job is only worth running if
# it runs at MORE than that. On a 2-vCPU private runner `2 * nproc` would be
# 4 -- exactly the test job's value -- and this job would silently become a
# twentyfold repeat of a configuration already known to pass.
ci_test_threads="${TEST_THREADS:-4}"
cores="$(nproc)"
threads=$(( cores * 4 ))
if [ "$threads" -lt 8 ]; then threads=8; fi

if [ "$threads" -le "$ci_test_threads" ]; then
  echo "flake hunt is not oversubscribed: threads=$threads <= test job's $ci_test_threads" >&2
  echo "Raise the multiplier or the floor. A hunt at the test job's own" >&2
  echo "parallelism is twenty repeats of a passing configuration." >&2
  exit 1
fi

# A scheduled workflow that never fires looks exactly like one that fired
# and found nothing: both leave no red mark. Neither the log nor a green
# tick distinguishes them. So every verdict this script emits carries the
# UTC instant it was produced, and is echoed into the run summary when one
# exists -- so "last clean run" is a date a human can read off
# `gh run list --workflow nightly.yml` and compare against the cron, rather
# than an absence they have to notice.
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
verdict() { # verdict <line>
  printf '%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

echo "flake hunt: $iterations iterations at --test-threads=$threads"
echo "  (nproc=$cores, ci test job uses $ci_test_threads, started $started_at)"
cargo test --workspace --locked --no-run || exit 1

completed=0
for i in $(seq 1 "$iterations"); do
  start=$SECONDS
  if ! cargo test --workspace --locked --no-fail-fast -- --test-threads="$threads" --show-output; then
    echo
    verdict "FLAKE HUNT FAILED on iteration $i of $iterations (--test-threads=$threads, started $started_at)"
    echo "Capture the failing test NAME and the panic message before re-running." >&2
    echo "Do not add a retry, and do not just click Re-run. See the plan's flake policy." >&2
    exit 1
  fi
  completed=$((completed + 1))
  echo "  iteration $i/$iterations ok ($((SECONDS - start))s)"
done

# The counter is not decoration. It is the assertion that the loop above
# actually executed, rather than being skipped by an empty `seq` or an
# early `break` someone adds later. Without it, "OK" is a claim about a
# variable rather than about work performed.
if [ "$completed" -ne "$iterations" ]; then
  echo "FLAKE HUNT INTERNAL ERROR: ran $completed of $iterations iterations" >&2
  exit 1
fi

verdict "FLAKE HUNT OK: $completed/$iterations green at --test-threads=$threads (finished $(date -u +%Y-%m-%dT%H:%M:%SZ))"
