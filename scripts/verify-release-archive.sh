#!/usr/bin/env bash
# The consuming half of a release asset: verify an archive against
# SHA256SUMS.txt and extract it under §13.3's safe-archive rules.
#
# **This is the half that a release workflow otherwise never has**, and it is
# the half that matters. Producing an archive proves the build; it proves
# nothing about whether the thing the bootstrap will be handed is a thing the
# bootstrap can accept. §13.3 step 5 states that contract:
#
#   "Fetch `https://github.com/<owner>/holdfast/releases/download/vX.Y.Z/
#    SHA256SUMS.txt` over TLS. … Verify the archive against the
#    freshly-fetched `SHA256SUMS.txt`. Extract into a fresh temp directory
#    with safe-archive rules: reject absolute paths, `..` path components,
#    symlinks, hardlinks, device files, and archives that do not contain
#    exactly the expected `holdfast` executable for the target."
#
# Every clause of that is a check below, run against the real archives on
# every pull request by `.github/workflows/release-rehearsal.yml` and against
# synthetic violations by `--self-test`.
#
# **What this is NOT: the bootstrap's own parser.** `plugin/bootstrap.sh` does
# not exist yet (§13.2's whole plugin layer is separately scoped), so this
# asserts that the archives have the shape §13.3 describes, not that the
# launcher agrees. When that launcher lands it must be run against these same
# fixtures, or the two agree only by luck.
#
# Usage:
#   scripts/verify-release-archive.sh [--extract-to DIR] <sums-file> <archive>
#   scripts/verify-release-archive.sh --self-test
set -euo pipefail

# Resolved rather than assumed: the Python half sits beside this file, and
# `$0` is whatever spelling the caller used.
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
inspect="$here/verify-release-archive.py"
[ -f "$inspect" ] || { printf 'missing %s\n' "$inspect" >&2; exit 2; }

fails=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s: %s\n' "$1" "$2"; fails=$((fails + 1)); }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# **The sums line is parsed HERE, in shell, deliberately.** The file is
# written by `scripts/package-release.sh` and could have been checked with
# `sha256sum -c`, but then the producer and the checker would be one
# implementation agreeing with itself. §13.3 has a POSIX-sh launcher read
# this file with no `sha256sum -c` available on every platform it runs on, so
# what needs proving is that the format survives being read by four lines of
# `grep`/`cut` — which is what these are.
verify_one() { # verify_one <sums-file> <archive> <extract-dir-or-empty>
  local sums="$1" archive="$2" extract_to="${3:-}"
  local base line recorded actual member

  base="$(basename "$archive")"
  case "$base" in
    holdfast-windows-*.zip)  member=holdfast.exe ;;
    holdfast-*.tar.gz)       member=holdfast ;;
    *) bad asset-name "$base is not holdfast-<target>.<tar.gz|zip> — §13.3 step 5 composes exactly that name"
       return 1 ;;
  esac

  [ -f "$sums" ]    || { bad missing-sums "$sums"; return 1; }
  [ -f "$archive" ] || { bad missing-archive "$archive"; return 1; }

  # Exactly one line, matched on the WHOLE name: an unanchored match would
  # let `holdfast-linux-x86_64.tar.gz` be verified against the line for
  # `holdfast-linux-x86_64.tar.gz.sha256` if one were ever concatenated in.
  line="$(awk -v n="$base" '$2 == n { print; c++ } END { if (c != 1) exit 1 }' "$sums")" || {
    bad no-sum-line "$sums has no single line naming $base"
    return 1
  }
  recorded="$(printf '%s' "$line" | cut -d' ' -f1)"
  case "$recorded" in
    *[!0-9a-f]* | "" ) bad malformed-sum-line "not 64 lowercase hex: '$line'"; return 1 ;;
  esac
  [ "${#recorded}" -eq 64 ] || { bad malformed-sum-line "digest is ${#recorded} chars, not 64"; return 1; }
  ok "SHA256SUMS.txt names $base once, as 64 lowercase hex"

  actual="$(sha256_of "$archive")"
  if [ "$actual" = "$recorded" ]; then
    ok "$base matches its recorded digest"
  else
    bad checksum-mismatch "$base is $actual, SHA256SUMS.txt says $recorded"
    return 1
  fi

  # Inspection and extraction are python3's because the checks §13.3 names
  # are about ENTRY TYPE — symlink, hardlink, device — and `tar -tvf`'s
  # output format is not the same on GNU tar and bsdtar, both of which this
  # runs under. `tarfile`/`zipfile` answer the question directly. python3 is
  # already load-bearing in this pipeline (ci.yml's hygiene job runs
  # `scripts/spec-enum-check.py`), so this adds no dependency.
  local out rc=0
  out="$(python3 "$inspect" "$archive" "$member" "$extract_to" 2>&1)" || rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -ne 0 ]; then
    fails=$((fails + 1))
    return 1
  fi
  return 0
}

self_test() {
  local tmp t_fails=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  python3 "$inspect" --fixtures "$tmp" || { echo "fixture generation failed" >&2; return 1; }

  # <archive> <expected-token>, where `-` means "must be accepted".
  while read -r name want; do
    [ -n "$name" ] || continue
    local got rc=0 out
    out="$(verify_one "$tmp/SHA256SUMS.txt" "$tmp/$name" "" 2>&1)" || rc=$?
    if [ "$want" = "-" ]; then
      if [ "$rc" -eq 0 ]; then
        printf '  ok    %-44s accepted\n' "$name"
      else
        printf '  FAIL  %-44s should have been ACCEPTED\n' "$name"
        printf '%s\n' "$out" | sed 's/^/          /'
        t_fails=$((t_fails + 1))
      fi
    else
      got="$(printf '%s\n' "$out" | sed -n 's/^  FAIL  \([a-z-]*\):.*/\1/p' | head -1)"
      if [ "$rc" -ne 0 ] && [ "$got" = "$want" ]; then
        printf '  ok    %-44s rejected: %s\n' "$name" "$want"
      else
        printf '  FAIL  %-44s wanted %s, got %s (rc=%s)\n' "$name" "$want" "${got:-<none>}" "$rc"
        printf '%s\n' "$out" | sed 's/^/          /'
        t_fails=$((t_fails + 1))
      fi
    fi
  done < "$tmp/EXPECTED.txt"

  echo
  if [ "$t_fails" -eq 0 ]; then
    echo "VERIFY-ARCHIVE SELF-TEST PASSED"
    return 0
  fi
  printf 'VERIFY-ARCHIVE SELF-TEST FAILED: %s case(s)\n' "$t_fails"
  return 1
}

extract_to=""
if [ "${1:-}" = "--extract-to" ]; then
  extract_to="${2:?--extract-to needs a directory}"
  shift 2
fi

case "${1:-}" in
  --self-test)
    self_test
    exit $?
    ;;
  '' | -*)
    sed -n '/^# Usage:/,/--self-test$/p' "$0" >&2
    exit 2
    ;;
esac

[ $# -eq 2 ] || { sed -n '/^# Usage:/,/--self-test$/p' "$0" >&2; exit 2; }
verify_one "$1" "$2" "$extract_to" || true

echo
if [ "$fails" -eq 0 ]; then
  echo "ARCHIVE OK"
  exit 0
fi
printf 'ARCHIVE FAILED: %s finding(s)\n' "$fails"
exit 1
