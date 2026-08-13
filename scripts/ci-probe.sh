#!/usr/bin/env bash
# CLASP CI capability probe. The `test` job `needs:` it.
#
# It asserts the three things the test suite silently assumes and that no
# assertion in the suite itself can check:
#
#   1. the pinned toolchain is the one running,
#   2. the kernel will hand us a pseudoterminal,
#   3. every shell the suite spawns by name is installed.
#
# (3) overlaps with CLASP_REQUIRE_ALL_SHELLS=1, which the test job also
# sets and which panics from inside the suite when a gated program is
# missing. The overlap is deliberate and neither is redundant: this probe
# fails in ~20 seconds with a one-line diagnosis and also covers the
# toolchain and the pty, which the variable cannot see; the variable
# covers a `have()` guard added tomorrow that this hardcoded list has
# never heard of.
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
# 8 of tests/detection.rs's 19 tests early-`return` when their program is
# missing, and libtest reports that as `ok` with the explanation swallowed.
# This list is what stops a slim image from certifying a suite that skipped
# its most valuable half.
#   bash zsh dash sh -> OSC 133 marker streams and the T3 degradation rows (§8.5)
#   dash + less      -> an_alt_screen_episode_leaves_a_dash_prompt_on_the_
#                       heuristic_tier — the only PTY-level test of REQ-PD-011/015
#   less             -> the alternate-screen / Fullscreen row. NOT listed in the
#                       ubuntu-24.04 image manifest, so this one is load-bearing
#   python3          -> both getpass()/REPL rows of §8.7, and the pty probe below
#   jq               -> scripts/mcp-smoke.sh, a hard requirement not a soft skip
# Add `fish` to this list in the same change that adds it to the apt line —
# see plan Task 1 Step 4. It is deliberately absent until then.
for prog in bash zsh dash sh python3 less jq; do
  path="$(command -v "$prog" 2>/dev/null)"
  if [ -n "$path" ]; then
    ver="$("$prog" --version 2>&1 | head -1)"
    printf '  ok    %-8s %-24s %s\n' "$prog" "$path" "$ver"
  else
    bad "$prog is not installed — its tests will SKIP and still report as passing"
  fi
done

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
  else bad "forkpty round-trip FAILED — this runner cannot host CLASP's tests"
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
