#!/usr/bin/env bash
# Holdfast CI capability probe. The `test` job `needs:` it.
#
# It asserts the three things the test suite silently assumes and that no
# assertion in the suite itself can check:
#
#   1. the pinned toolchain is the one running,
#   2. the kernel will hand us a pseudoterminal,
#   3. every shell the suite spawns by name is installed, and the one
#      requirement that is not a presence claim — a CPython >= 3.13, whose
#      REPL drives bracketed paste — is met by something on PATH.
#
# (3) is what HOLDFAST_REQUIRE_ALL_SHELLS=1 would cover from inside the suite,
# by turning every `have()` skip into a panic. **That variable is not set**
# — ci.yml says why, above the `test` job, and it is a measurement about
# fish rather than an oversight. Until it can be, this probe is the
# fail-fast half of the gate and scripts/ci-skip-census.sh is the other
# half: this one fails in ~20 seconds with a one-line diagnosis and also
# covers the toolchain and the pty, which the variable cannot see; the
# census reads the suite's own skip notices and so catches a `have()`
# guard added tomorrow that this hardcoded list has never heard of.
#
# Run it locally exactly as CI does:  ./scripts/ci-probe.sh
set -uo pipefail

fails=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

echo "--- runner ---"
printf 'runner os     %s\n' "${RUNNER_OS:-<not running in CI>}"
printf 'runner arch   %s\n' "${RUNNER_ARCH:-<unknown>}"
printf 'image         %s %s\n' "${ImageOS:-<unknown>}" "${ImageVersion:-}"
printf 'kernel        %s\n' "$(uname -srmo)"
printf 'nproc         %s\n' "$(nproc)"
printf 'mem total     %s\n' "$(free -m 2>/dev/null | awk '/^Mem:/{print $2" MiB"}')"
printf 'disk free /   %s\n' "$(df -h / 2>/dev/null | awk 'NR==2{print $4}')"

echo
echo "--- toolchain (pinned by rust-toolchain.toml: channel 1.97; measured 2026-08-12: rustc 1.97.1) ---"
rustc --version
cargo --version
if rustc --version | grep -q '^rustc 1\.97\.'; then
  ok "rustc is on the pinned 1.97 channel"
else
  bad "rustc is NOT 1.97.x — rust-toolchain.toml pins channel \"1.97\""
fi
cargo clippy --version >/dev/null 2>&1 && ok "clippy present" || bad "clippy missing (rustup component add clippy)"
cargo fmt --version    >/dev/null 2>&1 && ok "rustfmt present" || bad "rustfmt missing (rustup component add rustfmt)"

echo
echo "--- shells and helpers the test suite spawns by name ---"
# Host-dependent rows of tests/detection.rs early-`return` when their
# program is missing, and libtest reports that as `ok` with the explanation
# swallowed. This list is what stops a slim image from certifying a suite
# that skipped its most valuable half.
#
# **No counts here, deliberately** (GH #74). This comment used to say "8 of
# 19" while README.md said "Ten of 23" and the file held 23 — two restated
# totals that disagreed with each other and with the tree, and nothing that
# could go red. `scripts/ci-skip-census.sh` is what actually pins the set:
# it asserts the exact rows that skipped, by name, and fails on a new one
# *and* on an agreed one that stopped happening. A number here would be a
# third copy of something already enforced somewhere else. Same reasoning
# `mcp-smoke.sh` applies to its own check total, and for the same measured
# reason — that one drifted five times with nothing going red.
#   bash zsh dash sh -> OSC 133 marker streams and the T3 degradation rows (§8.5)
#   dash + less      -> an_alt_screen_episode_leaves_a_dash_prompt_on_the_
#                       heuristic_tier — the only PTY-level test of REQ-PD-011/015
#   less             -> the alternate-screen / Fullscreen row. NOT listed in the
#                       ubuntu-24.04 image manifest, so this one is load-bearing
#   python3          -> both getpass()/REPL rows of §8.7, and the pty probe below
#   jq               -> scripts/mcp-smoke.sh, a hard requirement not a soft skip
# `fish` is deliberately NOT in this list; see the note printed after the
# loop, which is a measurement rather than an omission.
for prog in bash zsh dash sh python3 less jq; do
  path="$(command -v "$prog" 2>/dev/null)"
  if [ -n "$path" ]; then
    ver="$("$prog" --version 2>&1 | head -1)"
    printf '  ok    %-8s %-24s %s\n' "$prog" "$path" "$ver"
  else
    bad "$prog is not installed — its tests will SKIP and still report as passing"
  fi
done

# fish is the one gated program this pipeline does not require, and the
# shortfall is printed on every run rather than left to a comment nobody
# opens. Measured 2026-08-13 on the ubuntu-24.04 base image, at both fish
# versions obtainable there: 3.7.0 (noble's archive) fails the row on
# `(exit 42)`, which is a subshell in bash and zsh and a rejected command
# substitution in fish; 4.8.1 (the maintainers' PPA) fails it because
# Holdfast's own snippet guard declines to inject. Installing either would
# turn a silent skip into a red row that says nothing about CI. See
# ci.yml above the `test` job.
if command -v fish >/dev/null 2>&1; then
  printf '  note  %-8s %-24s %s\n' "fish" "$(command -v fish)" "$(fish --version 2>&1 | head -1)"
  printf '  note  fish is PRESENT, so its row will RUN — and is expected to FAIL until\n'
  printf '  note  the row and the snippet guard are fixed. That failure is a finding, not CI.\n'
else
  printf '  note  %-8s %s\n' "fish" "not installed — fish_integration_… will SKIP and the fish snippet stays UNVERIFIED at runtime"
fi

echo
echo "--- a CPython >= 3.13 (PyREPL) for the §8.7 REPL row ---"
# `Need::PyreplPython` in tests/detection.rs. The row
# matrix_row_the_python_repl_is_at_prompt_with_no_repl_specific_config
# needs an interpreter whose REPL drives bracketed paste with NO
# configuration, which is a VERSION claim and not a presence one: PyREPL
# landed in 3.13 and enables bracketed paste itself, while a pre-3.13
# readline REPL leaves it to the readline build and to inputrc, and
# ubuntu-24.04's own 3.12.3 emits none — measured on three runner VMs.
# Without the paste the row reaches §8.3's echo rung instead and answers
# `AwaitingSecret` at 0.95 for an ordinary `>>> ` prompt.
#
# Asked of each interpreter rather than parsed out of its file name, and
# scanned the same way the row scans: a `python3.13` on PATH may be a
# wrapper, a symlink to something else, or not executable at all.
if [ -n "${PYTHON_BASIC_REPL:-}" ]; then
  bad "PYTHON_BASIC_REPL is set in the environment — it turns PyREPL off on EVERY interpreter here, so even a 3.14 stops satisfying the row"
fi
names="$(
  IFS=:
  for dir in $PATH; do
    for cand in "$dir"/python3 "$dir"/python3.[0-9] "$dir"/python3.[0-9][0-9]; do
      [ -f "$cand" ] && basename "$cand"
    done
  done | sort -u
)"
best=""; best_major=0; best_minor=0
for name in $names; do
  read -r impl major minor <<<"$("$name" -c 'import sys; print(sys.implementation.name, sys.version_info[0], sys.version_info[1])' 2>/dev/null)"
  if [ "${impl:-}" != "cpython" ]; then
    printf '  scan  %-12s reported no CPython version\n' "$name"
    continue
  fi
  printf '  scan  %-12s CPython %s.%s\n' "$name" "$major" "$minor"
  if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 13 ]; }; then
    if [ "$major" -gt "$best_major" ] || { [ "$major" -eq "$best_major" ] && [ "$minor" -gt "$best_minor" ]; }; then
      best="$name"; best_major="$major"; best_minor="$minor"
    fi
  fi
done
if [ -n "$best" ]; then
  ok "$best is CPython $best_major.$best_minor — the REPL row can run"
else
  bad "no CPython >= 3.13 on PATH — matrix_row_the_python_repl_… will SKIP and still report as passing (CI installs one with actions/setup-python, python-version 3.13)"
fi

echo
echo "--- pseudoterminal allocation ---"
# The job's own stdout is NOT a tty and must never be assumed to be. What the
# suite needs is the ability to create its own pty pair: /dev/ptmx plus a
# mounted devpts. Anything else is the wrong question.
[ -c /dev/ptmx ]  && ok "/dev/ptmx is a character device" || bad "/dev/ptmx missing or not a char device"
[ -d /dev/pts ]   && ok "/dev/pts is mounted"             || bad "/dev/pts not mounted"

if command -v python3 >/dev/null 2>&1; then
  if python3 - <<'PY'
import os, pty, select, sys
pid, fd = pty.fork()
if pid == 0:
    os.execvp("/bin/sh", ["/bin/sh", "-c", "echo PTY_OK_$((6*7))"])
buf = b""
while True:
    r, _, _ = select.select([fd], [], [], 10)
    if not r:
        break
    try:
        chunk = os.read(fd, 1024)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
    if b"PTY_OK_42" in buf:
        break
# PTY_OK_42 can only be produced by a shell that *evaluated* $((6*7)); the
# echo of the command line carries the literal expression, so this cannot be
# satisfied by the terminal echoing back what we typed.
sys.exit(0 if b"PTY_OK_42" in buf else 1)
PY
  then ok "forkpty + shell round-trip works"
  else bad "forkpty round-trip FAILED — this runner cannot host Holdfast's tests"
  fi
else
  bad "python3 missing; cannot probe pty allocation"
fi

echo
if [ "$fails" -ne 0 ]; then
  echo "PROBE FAILED: $fails check(s) did not pass" >&2
  exit 1
fi
echo "PROBE OK"
