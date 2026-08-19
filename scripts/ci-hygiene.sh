#!/usr/bin/env bash
# Fails if .github/workflows/ has grown a capability this project's CI is
# not allowed to have, or has lost a pin it is required to keep.
#
# Constraints erode by accretion, one plausible line at a time. This script
# is how "no publishing, no retries, everything pinned" survives contact
# with a future maintainer who has a good reason. If one of these is ever
# genuinely wanted, the change is to delete the rule here in the same
# commit -- deliberately, and visibly in the diff -- not to slip past it.
set -uo pipefail

# --------------------------------------------------------------------------
# Self-test: the runner-image rule had never fired, and could not have
# --------------------------------------------------------------------------
#
# The rule below used to read `runs-on:.*ubuntu-latest`. Every job in this
# repository is an Ubuntu job, so the rule and the tree agreed by accident and
# the rule had never once fired -- and `windows-latest`, which is the same
# mutable pointer the rule exists to forbid, went straight through it.
# Milestone 0.0.11 adds the first Windows job. A guard that permits the exact
# thing it names is this project's founding defect wearing the guard's badge.
#
# Widening it is half the fix. The other half is the fixture pair here,
# because "deny anything that looks like a runner image" and "deny the right
# ones" produce the same result on a tree with no Windows job: an alias must
# be REJECTED and a PINNED image must be ACCEPTED, and the second case is what
# stops the widening from becoming a rule that fails 0.0.11's correct
# `windows-2022`.
#
# The fixtures are complete, hygienic workflows that satisfy every other rule
# in this file, so the only variable across the cases is the runner image. One
# of them is a matrix, because that is how a second platform is actually
# added: `runs-on: ${{ matrix.os }}` names no image at all, and a rule anchored
# to `runs-on:` cannot see the alias sitting in the `os:` list.
self_test() {
  local me tmp out rc failures=0
  me="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  tmp="$(mktemp -d)"
  # Expanded NOW, not at EXIT: `tmp` is local and out of scope by the time
  # the trap runs, and under `set -u` a deferred `$tmp` aborts the cleanup
  # with an unbound-variable error after the results have printed.
  # shellcheck disable=SC2064
  trap "rm -rf -- '$tmp'" EXIT

  mkdir -p "$tmp/.github/workflows" "$tmp/scripts"
  printf '#!/bin/sh\nexit 0\n' > "$tmp/scripts/fixture-probe.sh"
  chmod +x "$tmp/scripts/fixture-probe.sh"

  fixture() { # fixture <the job's runner lines, indented>
    { cat <<'YAML'
name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
YAML
      printf '%s\n' "$1"
      cat <<'YAML'
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh
YAML
    } > "$tmp/.github/workflows/fixture.yml"
  }

  # An accepted case must exit 0. A rejected one must exit non-zero AND name
  # the runner rule: a fixture that tripped some other rule would "pass" a
  # bare exit-code test while proving nothing about this one.
  want_ok() { # want_ok <label> <runner lines>
    fixture "$2"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want exit 0, got %d\n' "$1" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
  }

  want_denied() { # want_denied <label> <runner lines>
    fixture "$2"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'FORBIDDEN: a `-latest` runner image'; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want the runner rule to fire; exit %d\n' "$1" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
  }

  echo "ci-hygiene self-test — the runner-image rule, both directions"
  echo

  # THE NEGATIVE CONTROLS. Without these the widened rule could be `deny .`
  # and every positive case below would still pass. The second is the one
  # 0.0.11 depends on: a pinned Windows image is correct and must not be
  # rejected by a rule aimed at the alias.
  want_ok     "a pinned ubuntu-24.04 job is accepted (and the whole script \
comes back clean, so the rejections below are not vacuous)" \
              "    runs-on: ubuntu-24.04"
  want_ok     "a pinned windows-2022 job is accepted — the widened rule must \
not reject 0.0.11's correct Windows job" \
              "    runs-on: windows-2022"
  want_ok     "a matrix of two pinned images is accepted" \
              "    strategy:
      matrix:
        os: [ubuntu-24.04, windows-2022]
    runs-on: \${{ matrix.os }}"

  # THE POSITIVES. The first is what the rule always claimed to do; the
  # second is what it silently permitted; the third is the shape a second
  # platform is actually added in.
  want_denied "runs-on: ubuntu-latest is rejected" \
              "    runs-on: ubuntu-latest"
  want_denied "runs-on: windows-latest is rejected (the case the rule named \
but did not match)" \
              "    runs-on: windows-latest"
  want_denied "runs-on: macos-latest is rejected" \
              "    runs-on: macos-latest"
  want_denied "an alias in a matrix os: list is rejected, where runs-on: \
names no image at all" \
              "    strategy:
      matrix:
        os: [ubuntu-24.04, windows-latest]
    runs-on: \${{ matrix.os }}"

  echo
  if [ "$failures" -ne 0 ]; then
    printf 'SELF-TEST FAILED: %d case(s)\n' "$failures" >&2
    return 1
  fi
  echo "SELF-TEST PASSED — an alias is rejected and a pinned image is not."
  return 0
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  "") ;;
  *) printf 'usage: %s [--self-test]\n' "$0" >&2; exit 2 ;;
esac

dir=".github/workflows"
fails=0

# Without this guard, an empty or missing directory makes every `grep`
# below return "no match" and the script reports a clean bill of health for
# a pipeline that does not exist. That is the exact defect class this repo
# keeps finding in its tests, and the previous version of this script had
# it. The COUNT is the guard; a `[ -d ]` test is not enough, because an
# empty directory passes it.
mapfile -t files < <(find "$dir" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
if [ "${#files[@]}" -eq 0 ]; then
  echo "HYGIENE FAILED: no workflow files under $dir/ (run from the repository root)" >&2
  exit 1
fi

# One narrow, DATED exemption: the mutation sweep's calibration window needs
# `continue-on-error`, which is otherwise banned. It expires by itself --
# after the marker's date the file is checked like every other, so a
# forgotten continue-on-error turns this job red without anyone remembering.
today="$(date -u +%F)"
kept=()
for f in "${files[@]}"; do
  until_date="$(grep -oE 'CALIBRATION-EXEMPT-UNTIL:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$f" 2>/dev/null \
                | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)"
  if [ -n "$until_date" ] && [[ "$today" < "$until_date" ]]; then
    printf 'note  %s is calibration-exempt until %s\n' "$f" "$until_date"
  else
    kept+=("$f")
  fi
done
# If EVERY workflow claimed the exemption we would again be checking
# nothing -- the same vacuous-pass defect, one layer up.
if [ "${#kept[@]}" -eq 0 ]; then
  echo "HYGIENE FAILED: every workflow is calibration-exempt — not a state this repo may be in" >&2
  exit 1
fi
files=("${kept[@]}")

# Every content check below runs against a COMMENT-BLANKED copy, never the
# original. Without this, each workflow's own header comment -- which
# describes the very constraints being enforced -- matches the deny rules,
# and the script fails on its own documentation. This is not hypothetical:
# it was MEASURED failing that way while this plan was written, on eight
# rules at once. Comments are blanked rather than deleted so reported line
# numbers still refer to the real file.
#
# Residual, stated rather than papered over: a YAML scalar containing " #"
# would be truncated. None of these workflows has one, and a new one would
# surface as a rule that stopped matching -- visible -- rather than as a
# silent pass.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stripped=()
for i in "${!files[@]}"; do
  s="$work/$i.yml"
  sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*#.*$//' "${files[$i]}" > "$s"
  stripped+=("$s")
done

printf 'checking %d workflow file(s):\n' "${#files[@]}"
printf '  %s\n' "${files[@]}"

echo
echo "--- forbidden capabilities ---"
deny() { # deny <extended-regex> <why>
  local re="$1" why="$2" out="" i m
  for i in "${!files[@]}"; do
    m="$(grep -nE -- "$re" "${stripped[$i]}" 2>/dev/null)" || true
    if [ -n "$m" ]; then
      out+="$(printf '%s\n' "$m" | sed "s|^|  ${files[$i]}:|")"$'\n'
    fi
  done
  if [ -n "$out" ]; then
    printf '%s' "$out"
    printf '  FORBIDDEN: %s\n' "$why"
    fails=$((fails + 1))
  else
    printf '  ok    absent: %s\n' "$why"
  fi
}

deny 'continue-on-error'                          'continue-on-error — a job that cannot fail; the Actions equivalent of retry:, and worse'
deny 'uses:[^#]*(retry|wretry)'                   'a retry action — a retried PTY test hides the race it exists to catch'
deny 'secrets\.'                                  'a secrets context reference — this pipeline authenticates to nothing'
deny 'uses:[^#]*(action-gh-release|create-release|release-action|actions-gh-pages)' 'a release/publish action — release automation is milestone 0.0.12'
deny 'cargo[[:space:]]+(publish|owner|login)'     'crates.io publishing'
deny 'docker[[:space:]]+(push|login)'             'container registry push'
deny '(^|[[:space:]])(gh|glab)[[:space:]]'        'a CLI that can publish or authenticate'
deny 'git[[:space:]]+push'                        'writing to a remote'
deny 'pull_request_target'                        'pull_request_target — runs untrusted code with a writable token'
deny 'permissions:[[:space:]]*write-all'          'permissions: write-all'
deny '(contents|packages|id-token|actions|deployments):[[:space:]]*write' 'a write permission'
# Not anchored to `runs-on:`, deliberately: `runs-on: ${{ matrix.os }}` names
# no image, and an anchored rule cannot see the alias in the `os:` list. These
# three names are runner images and nothing else. Comments are blanked before
# this runs, so each workflow's own header may go on saying "never
# ubuntu-latest" without tripping it. See `self_test` for the pair that proves
# both directions.
deny '(ubuntu|windows|macos)-latest'              'a `-latest` runner image — a mutable pointer; pin the version (ubuntu-24.04, windows-2022, macos-14)'

echo
echo "--- required pins and hardening ---"
count() { # count <regex> -> total matching lines across the stripped copies
  local re="$1" i n total=0
  for i in "${!stripped[@]}"; do
    n="$(grep -cE -- "$re" "${stripped[$i]}" 2>/dev/null)" || n=0
    total=$((total + n))
  done
  printf '%s' "$total"
}

# Every action must be pinned to a 40-hex commit SHA. A tag is a mutable
# pointer a maintainer can move under us between two runs of the same commit.
unpinned=""
for i in "${!files[@]}"; do
  m="$(grep -nE '^[[:space:]]*-?[[:space:]]*uses:' "${stripped[$i]}" \
       | grep -vE '@[0-9a-f]{40}[[:space:]]*$' || true)"
  [ -n "$m" ] && unpinned+="$(printf '%s\n' "$m" | sed "s|^|  ${files[$i]}:|")"$'\n'
done
if [ -n "$unpinned" ]; then
  printf '%s' "$unpinned"
  printf '  FORBIDDEN: %s\n' 'a `uses:` not pinned to a 40-hex commit SHA'
  fails=$((fails + 1))
else
  printf '  ok    every `uses:` is pinned to a 40-hex commit SHA\n'
fi

# actions/checkout defaults persist-credentials to TRUE, which writes a
# pushable token into .git/config. Removing the capability beats declining
# to use it. Count, don't just grep: one checkout without the line is the
# whole defect.
checkouts="$(count 'uses:[[:space:]]*actions/checkout@')"
persist_false="$(count 'persist-credentials:[[:space:]]*false')"
if [ "$checkouts" -gt 0 ] && [ "$checkouts" -eq "$persist_false" ]; then
  printf '  ok    all %s checkout step(s) set persist-credentials: false\n' "$checkouts"
else
  printf '  FAIL  %s checkout step(s) but %s persist-credentials: false\n' "$checkouts" "$persist_false"
  fails=$((fails + 1))
fi

# A workflow with no explicit permissions block inherits the enterprise /
# org / repository default, which is a security property living outside the
# diff.
for i in "${!files[@]}"; do
  if grep -qE '^permissions:' "${stripped[$i]}"; then
    printf '  ok    %s declares workflow-level permissions\n' "${files[$i]}"
  else
    printf '  FAIL  %s has no workflow-level `permissions:` block\n' "${files[$i]}"
    fails=$((fails + 1))
  fi
done

# The Actions default job timeout is 360 minutes. On a private repo that is
# 360 billed minutes for one hung PTY test. `runs-on:` is an EXACT proxy for
# the job count -- every job has exactly one, and nothing else has one -- so
# this is a count, not a heuristic, and the comparison is equality.
# (An earlier version counted two-space-indented top-level keys and
# mis-counted `push:`/`pull_request:`/`schedule:` under `on:`, producing a
# FALSE RED against a correct workflow. Measured. Do not go back to it.)
jobs_declared="$(count '^[[:space:]]+runs-on:')"
timeouts="$(count '^[[:space:]]+timeout-minutes:')"
if [ "$jobs_declared" -gt 0 ] && [ "$timeouts" -eq "$jobs_declared" ]; then
  printf '  ok    %s job(s), %s timeout-minutes declaration(s)\n' "$jobs_declared" "$timeouts"
else
  printf '  FAIL  %s job(s) but %s timeout-minutes declaration(s)\n' "$jobs_declared" "$timeouts"
  fails=$((fails + 1))
fi

echo
echo "--- invoked scripts are executable ---"
# DERIVED from the workflows rather than hardcoded. The plan's text lists
# four script paths literally, including scripts/ci-flake-hunt.sh, which is
# created by plan Task 5 and does not exist while only Tasks 1-3 have
# landed -- a hardcoded list would therefore report a FALSE RED against a
# correct tree, which this script's own history says is the one failure
# mode that gets a rule deleted. Deriving it from the (comment-blanked)
# workflow bodies is strictly stronger: it cannot go stale, and it picks up
# ci-flake-hunt.sh automatically on the day nightly.yml invokes it.
#
# Comment-blanked copies are used deliberately: a script named only in a
# header comment is documentation, not an invocation.
mapfile -t invoked < <(grep -hoE '(\./)?scripts/[A-Za-z0-9_.-]+\.sh' "${stripped[@]}" 2>/dev/null \
                       | sed 's|^\./||' | sort -u)
# Same vacuous-pass guard as above, one layer down: if the derivation ever
# matches nothing -- a renamed directory, an invocation spelled some other
# way -- this section would silently check zero files and report clean.
if [ "${#invoked[@]}" -eq 0 ]; then
  printf '  FAIL  no scripts/*.sh invocation found in any workflow — the derivation matched nothing\n'
  fails=$((fails + 1))
else
  for s in "${invoked[@]}"; do
    if [ -x "$s" ]; then
      printf '  ok    %s\n' "$s"
    else
      printf '  FAIL  %s is invoked by a workflow but is not an executable file\n' "$s"
      fails=$((fails + 1))
    fi
  done
fi

echo
if [ "$fails" -ne 0 ]; then
  echo "HYGIENE FAILED: $fails finding(s)" >&2
  exit 1
fi
echo "HYGIENE OK"
