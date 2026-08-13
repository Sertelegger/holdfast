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
deny 'runs-on:.*ubuntu-latest'                    'runs-on: ubuntu-latest — a mutable pointer; pin ubuntu-24.04'

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
