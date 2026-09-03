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
  # **The fixture needs the files the *other* rules read**, or every
  # `want_ok` fails on a rule it was not testing. That is not hypothetical:
  # the tool-count rule was added after these fixtures were written, and
  # from then on all three accepted cases failed on a missing
  # `scripts/mcp-smoke.sh`. Unnoticed, because CI runs this script but never
  # `--self-test` — though not for long: `git log -S` puts the rule at
  # 2026-08-27 and this fixture's repair at 2026-08-29, so the window was
  # TWO DAYS, not the "months" this comment claimed on the strength of
  # nobody checking. A self-test that cannot pass is a guard nobody is
  # guarding either way; the exaggeration was the same kind of unmeasured
  # claim the rest of this file exists to stop.
  printf '%s\n' 'tools=["a","b","c","d","e","f","g","h","i","j","k","l"]' \
    > "$tmp/scripts/mcp-smoke.sh"
  chmod +x "$tmp/scripts/mcp-smoke.sh"
  printf 'twelve MCP tools\n' > "$tmp/CLAUDE.md"

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

  # A whole-file fixture, for rules about the `on:` block rather than a job.
  whole() { printf '%s\n' "$1" > "$tmp/.github/workflows/fixture.yml"; }

  # The calibration cases need TWO files. A lone exempt workflow leaves
  # `kept` empty and trips the "every workflow is calibration-exempt" guard,
  # so the exempt fixture is paired with a clean one and the run asserts the
  # exemption rather than that guard.
  #
  # One copy of the clean body, held in a variable rather than written out at
  # each site: the cap case below needs a THIRD file, and three
  # hand-maintained copies of a workflow that has to satisfy every other rule
  # in this file is how a fixture quietly stops testing what its label says.
  local clean_body='name: Second
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh'

  pair() { # pair <fixture.yml body>
    printf '%s\n' "$1" > "$tmp/.github/workflows/fixture.yml"
    printf '%s\n' "$clean_body" > "$tmp/.github/workflows/second.yml"
  }
  unpair() { rm -f "$tmp/.github/workflows/second.yml" "$tmp/.github/workflows/third.yml"; }

  want_pair_ok() { # want_pair_ok <label> <fixture.yml body>
    pair "$2"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'is calibration-exempt until'; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want exit 0 AND an exemption note; exit %d\n' "$1" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
    unpair
  }

  # THREE files, two of them claiming the exemption and one clean. The guard
  # this exercises is the CAP, not the every-workflow backstop: `kept` is
  # non-empty here, so under the old rule this tree reported HYGIENE OK with
  # two of three workflows checked against nothing. Measured on the previous
  # version of this script.
  want_cap_denied() { # want_cap_denied <label>
    local marked="# CALIBRATION-EXEMPT-UNTIL: 2099-01-01
$clean_body"
    pair "$marked"
    printf '%s\n' "$marked" > "$tmp/.github/workflows/second.yml"
    printf '%s\n' "$clean_body" > "$tmp/.github/workflows/third.yml"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF 'granted to at most one'; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want the cap to fire; exit %d\n' "$1" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
    unpair
  }

  want_pair_denied() { # want_pair_denied <label> <expected text> <fixture.yml body>
    pair "$3"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$2"; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want %s; exit %d\n' "$1" "$2" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
    unpair
  }

  want_file_ok() { # want_file_ok <label> <whole file>
    whole "$2"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want exit 0, got %d\n' "$1" "$rc"
      printf '%s\n' "$out" | sed 's/^/          /'
      failures=$((failures + 1))
    fi
  }

  want_file_denied() { # want_file_denied <label> <expected FORBIDDEN text> <whole file>
    whole "$3"
    out="$(cd "$tmp" && "$me" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$2"; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s — want %s; exit %d\n' "$1" "$2" "$rc"
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
  # second is what it silently permitted; the fourth is the shape a second
  # platform is actually added in.
  #
  # These four sat SPLIT until 2026-09-03 — two here and two after the
  # calibration block below, where they had been stranded by an insertion —
  # so `macos-latest is rejected` and the matrix case printed under the
  # heading "the calibration exemption, all three directions". The cases were
  # right and the transcript lied about which rule had been exercised, which
  # in a self-test is most of what the output is for.
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
  echo "ci-hygiene self-test — the release gate, all three directions"
  echo

  # Publishing is allowed only where the trigger cannot fire by accident.
  want_file_ok "a tag-triggered release workflow may use secrets and publish" \
"# RELEASE-WORKFLOW: tag-triggered publishing
name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh
      - run: gh release create \"\$TAG\" --notes-file NOTES.md
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}"

  # The marker is checked, not believed. Without this the gate would be an
  # opt-out anybody could write on any file.
  want_file_denied "a release marker on a branch-triggered workflow is rejected" \
    'the marker is checked, not believed' \
"# RELEASE-WORKFLOW: tag-triggered publishing
name: NotReallyRelease
on:
  push:
    branches: [main]
    tags: ['v*']
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh
      - run: echo publish"

  # And an ordinary workflow still cannot authenticate. This is the rule the
  # widening must not have deleted.
  want_file_denied "an unmarked workflow may not reference secrets" \
    'FORBIDDEN: a secrets context reference' \
"name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh
      - run: echo \${{ secrets.GITHUB_TOKEN }}"
  echo
  echo "ci-hygiene self-test — the calibration exemption, six directions"
  echo

  # THE MECHANISM STILL WORKS. Nothing in the tree claims this exemption any
  # more, so without this case the whole dated-exemption path is dead code
  # that no run exercises -- which is how it came to carry the anchoring bugs
  # the next two cases are about. The marker is at COLUMN 0, in the header,
  # because that is the only place it counts now.
  want_pair_ok "a COLUMN-0 header marker, dated ahead, grants the exemption" \
"# CALIBRATION-EXEMPT-UNTIL: 2099-01-01
name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    continue-on-error: true
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh"

  # THE SECOND REGRESSION, and the reason the anchor moved to column 0. A
  # `run: |` body is full of whole comment lines at an indent; they are SHELL
  # comments, the marker grep reads the unstripped file, and under the
  # `^[[:space:]]*#` anchor it could not tell them from YAML ones. This
  # fixture is PR #87's own new step, and on the previous version of this
  # script it printed `note  … is calibration-exempt until 2099-01-01` and
  # then `HYGIENE OK` with the `continue-on-error: true` below still in
  # place. Three lines in a step body switched off every rule in this file
  # for that workflow.
  want_pair_denied "a marker inside a \`run:\` BLOCK BODY does not grant it, \
and the job's violation is still caught" \
    'FORBIDDEN: continue-on-error' \
"name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    continue-on-error: true
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: The Windows refusal arms, exercised rather than compiled
        shell: bash
        run: |
          # CALIBRATION-EXEMPT-UNTIL: 2099-01-01 (historic note)
          set +e
          ./scripts/fixture-probe.sh"

  # AND THE SHAPE THE OLD ANCHOR WAS RELAXED FOR is now refused too, which is
  # a deliberate behaviour change and not a side effect: an INDENTED marker
  # beside the job it exempts is a genuine YAML comment, it reads as a local
  # grant, and it is indistinguishable from the case above. The exemption is
  # file-scoped either way, so it goes in the header where its size is
  # legible.
  want_pair_denied "an INDENTED job-level marker no longer grants it" \
    'FORBIDDEN: continue-on-error' \
"name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    # CALIBRATION-EXEMPT-UNTIL: 2099-01-01
    continue-on-error: true
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh"

  # THE FIRST REGRESSION, and it is not hypothetical either: the commit that
  # retired the real exemption quoted the marker inside its own prose, the
  # unanchored grep matched the quotation, and mutants.yml stayed exempt from
  # every rule in this file with a re-added `continue-on-error` going
  # undetected.
  want_pair_denied "a marker merely QUOTED inside prose does not grant it" \
    'FORBIDDEN: continue-on-error' \
"# it used to carry a CALIBRATION-EXEMPT-UNTIL: 2099-01-01 marker
name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    continue-on-error: true
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh"

  # IT EXPIRES BY ITSELF. That is the entire argument for allowing a dated
  # hole in a deny rule, and it is worth one fixture.
  want_pair_denied "an EXPIRED marker stops granting it" \
    'FORBIDDEN: continue-on-error' \
"# CALIBRATION-EXEMPT-UNTIL: 2000-01-01
name: Fixture
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    continue-on-error: true
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: ./scripts/fixture-probe.sh"

  # AND ONE FILE AT A TIME. The backstop this replaces only fired when EVERY
  # workflow claimed the exemption, so three of four -- ci.yml, nightly.yml
  # and release.yml all unchecked -- passed it in silence.
  want_cap_denied "two workflows claiming the exemption is refused, not just \
all of them"

  echo
  if [ "$failures" -ne 0 ]; then
    printf 'SELF-TEST FAILED: %d case(s)\n' "$failures" >&2
    return 1
  fi
  # Says what was covered, not a count -- the count is what went stale last
  # time. The banner read "an alias is rejected and a pinned image is not"
  # while two thirds of the cases below it were about the two markers.
  echo "SELF-TEST PASSED — a runner alias is rejected and a pinned image is not;"
  echo "the release marker is checked rather than believed; and the calibration"
  echo "marker cannot be claimed from inside a \`run:\` body, from prose, after its"
  echo "date, or by a second workflow."
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
#
# **ANCHORED TO COLUMN 0, and it must be, because the exemption drops the
# file from EVERY rule below** -- not just the continue-on-error ban but the
# SHA pinning, `persist-credentials: false`, the `-latest` ban, the
# timeout-per-job count and the secrets ban. It is the largest single grant
# in this file and the cheapest thing in it to write.
#
# Two hazards, and the second is the one that cost a release:
#
#   1. A MARKER QUOTED IN PROSE. The commit that RETIRED this exemption named
#      the marker inside its own explanatory comment, the then-unanchored grep
#      matched the quotation, and mutants.yml stayed exempt from every rule
#      here with a re-added `continue-on-error` going undetected. Measured by
#      planting one.
#
#   2. A MARKER INSIDE A `run:` BLOCK SCALAR, which is what the first fix got
#      wrong. It anchored to `^[[:space:]]*#` -- "the whole of a comment line
#      at any indent" -- and its note claimed this was *"the same fix the
#      RELEASE-WORKFLOW marker below already carries, for the same reason."*
#      **That claim was false, and the difference between the two anchors was
#      the entire remaining defect.** RELEASE-WORKFLOW anchors at `^#`; this
#      one deliberately relaxed to `^[[:space:]]*#` "because the real marker
#      is indented inside a job block" -- and a `run: |` body is full of
#      indented whole comment lines that are SHELL comments, not YAML ones.
#      This grep reads the unstripped file and cannot tell them apart. So
#      three lines inside any step turned the whole guard off for that file:
#
#        - shell: bash
#          run: |
#            # CALIBRATION-EXEMPT-UNTIL: 2099-01-01 (historic note)
#
#      Reproduced on PR #87's own new step, with a `continue-on-error: true`
#      on the job: `note  … is calibration-exempt until 2099-01-01` followed
#      by `HYGIENE OK`. RELEASE-WORKFLOW was verified IMMUNE to the identical
#      trick, which is what identified the anchor as the difference.
#
# So: `^#`, parity with RELEASE-WORKFLOW for real this time. A GitHub
# workflow nests `run:` at least four levels deep, so nothing inside a block
# scalar can reach column 0; a column-0 `#` in a YAML file is a YAML comment
# and can be nothing else. The marker therefore lives in the FILE HEADER,
# which is also the more honest place for it: the grant is file-scoped, so a
# marker sitting beside one job's `continue-on-error` always understated what
# it switched off.
today="$(date -u +%F)"
kept=()
exempt=()
for f in "${files[@]}"; do
  until_date="$(grep -oE '^#[[:space:]]*CALIBRATION-EXEMPT-UNTIL:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$f" 2>/dev/null \
                | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)"
  if [ -n "$until_date" ] && [[ "$today" < "$until_date" ]]; then
    printf 'note  %s is calibration-exempt until %s\n' "$f" "$until_date"
    exempt+=("$f")
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
# **AT MOST ONE**, because the guard above is not the guard it reads as. It
# fires only when ALL FOUR workflow files claim the exemption, so three of
# four -- ci.yml, nightly.yml and release.yml all unchecked, with `mutants.yml`
# alone still carrying the rules -- passed it silently. "Not every workflow"
# is not the property wanted; "one narrow exemption", which is what the
# paragraph above promises, is. A second one is a different argument and gets
# made here, in the diff, the way this file's opening comment asks.
if [ "${#exempt[@]}" -gt 1 ]; then
  printf '  %s\n' "${exempt[@]}" >&2
  echo "HYGIENE FAILED: ${#exempt[@]} workflows claim the calibration exemption; it is granted to at most one" >&2
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

# **Publishing is allowed, in exactly one shape.** The rule here used to be
# "this pipeline authenticates to nothing", which forbade release automation
# outright. That is more hygiene than the risk warrants: the danger is not
# that a workflow *can* publish, it is that one publishes when nobody asked.
# A trigger is what separates those, so the capability is gated on the
# trigger rather than banned.
#
# A file may opt in with a `RELEASE-WORKFLOW:` marker, and the marker is
# **verified rather than trusted** — same shape as the calibration exemption
# above. `release_gate_ok` requires the `on:` block to name `tags:` and to
# name none of `branches:`, `pull_request`, `pull_request_target` or
# `schedule`. So a release workflow cannot fire from a branch push, a pull
# request, or a timer; the only thing that starts it is somebody tagging a
# commit on purpose. A marker on a file that does not meet that is a
# failure, not a pass — otherwise the marker would be the whole security
# model.
release_ok=()
for i in "${!files[@]}"; do
  release_ok[$i]=0
  # **Anchored to COLUMN 0**, and read from the unstripped file because a
  # marker *is* a comment. Unanchored, this file's own header — which has to
  # name the marker to document it — declared itself a release workflow, and
  # `ci.yml` failed on the first run. Same class as the `-latest` rule's
  # comment hazard, which is why that one is matched against the stripped
  # copy; a marker cannot be.
  #
  # `^#` and not `^[[:space:]]*#`, and that turned out to be load-bearing
  # rather than incidental: a reviewer planted this marker inside a `run: |`
  # body and this grep did not see it, while the calibration marker — which
  # had relaxed the same anchor to allow an indented marker — granted its
  # far larger exemption to the same plant. See the note on that one.
  grep -qE '^#[[:space:]]*RELEASE-WORKFLOW:' "${files[$i]}" || continue
  # The `on:` block: from a line starting `on:` to the next top-level key.
  on_block="$(awk '/^on:/{f=1;next} f&&/^[a-zA-Z_]+:/{exit} f{print}' "${stripped[$i]}")"
  if printf '%s' "$on_block" | grep -qE '^[[:space:]]+tags:' \
     && ! printf '%s' "$on_block" | grep -qE '^[[:space:]]+(branches|schedule):' \
     && ! printf '%s' "$on_block" | grep -qE '^[[:space:]]*pull_request(_target)?:'; then
    release_ok[$i]=1
    printf 'note  %s is a release workflow: tag-triggered, publishing allowed\n' "${files[$i]}"
  else
    printf '  %s: RELEASE-WORKFLOW marker on a workflow that is not tag-only\n' "${files[$i]}"
    printf '  FORBIDDEN: %s\n' 'a release marker whose `on:` block is not tags-only — the marker is checked, not believed'
    fails=$((fails + 1))
  fi
done

# `deny_unless_release` skips files that cleared the gate above; `deny`
# still applies everywhere, including to release workflows.
deny_unless_release() { # deny_unless_release <extended-regex> <why>
  local re="$1" why="$2" out="" i m
  for i in "${!files[@]}"; do
    [ "${release_ok[$i]}" = "1" ] && continue
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
    printf '  ok    absent outside a release workflow: %s\n' "$why"
  fi
}

# Dangerous whatever the trigger. `continue-on-error` and retries hide the
# races this suite exists to catch; `pull_request_target` runs untrusted code
# with a writable token; `write-all` and `-latest` are unbounded grants.
deny 'continue-on-error'                          'continue-on-error — a job that cannot fail; the Actions equivalent of retry:, and worse'
deny 'uses:[^#]*(retry|wretry)'                   'a retry action — a retried PTY test hides the race it exists to catch'
deny 'pull_request_target'                        'pull_request_target — runs untrusted code with a writable token'
deny 'permissions:[[:space:]]*write-all'          'permissions: write-all — name the scopes you need'

# Publishing capabilities: fine in a tag-triggered release workflow, never
# anywhere else. A `contents: write` on the CI workflow is how a test job
# grows the ability to move a tag; on the release workflow it is the point.
deny_unless_release 'secrets\.'                                  'a secrets context reference'
deny_unless_release 'uses:[^#]*(action-gh-release|create-release|release-action|actions-gh-pages)' 'a release/publish action'
deny_unless_release 'cargo[[:space:]]+(publish|owner|login)'     'crates.io publishing'
deny_unless_release 'docker[[:space:]]+(push|login)'             'container registry push'
deny_unless_release '(^|[[:space:]])(gh|glab)[[:space:]]'        'a CLI that can publish or authenticate'
deny_unless_release 'git[[:space:]]+push'                        'writing to a remote'
deny_unless_release '(contents|packages|id-token|actions|deployments):[[:space:]]*write' 'a write permission'
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
# --------------------------------------------------------------------------
# A tool count written in prose must match the list mcp-smoke.sh pins
# --------------------------------------------------------------------------
#
# `CLAUDE.md` said "11 MCP tools" and `ROADMAP.md` "Eleven MCP tools" while
# twelve were advertised. CLAUDE.md is loaded into every agent session, so a
# wrong count there is read as fact and propagated: a review of the 0.0.7
# branch proposed adding "a twelfth tool" that would have been the
# thirteenth, sourced straight from that line.
#
# The count is pinned once already, by mcp-smoke.sh's jcheck array. This makes
# every prose restatement derive from that array instead of from memory --
# the `F == N` move applied to documentation.
#
# **Only three phrasings are checked**, and they are listed below rather than
# inferred, because a rule that scans free prose for "<word> tools" matches
# ordinary sentences and fails on a correct tree. A count written any other
# way is NOT checked and this rule will not see it. Widen the pattern in the
# same commit that introduces a fourth phrasing.
#
# **A count tied to a version is skipped**, because it is a claim about scope
# and not about the tree: "13 MCP tools at v0.1.0 -- 12 implemented today" is
# correct prose that this rule would otherwise fail. The pinned list can
# adjudicate what exists; it cannot adjudicate what is planned. The skip is
# keyed on a `v0.N` marker on the same line, so a scope sentence has to say
# which release it is scoping in order to earn the exemption.
echo
echo "--- tool count in prose matches the pinned list ---"

tool_json="$(grep -oE '\["[a-z_]+"(,"[a-z_]+")*\]' scripts/mcp-smoke.sh | head -1)"
if [ -z "$tool_json" ]; then
  printf '  FAIL  no pinned tool array found in scripts/mcp-smoke.sh\n'
  fails=$((fails + 1))
else
  # `grep -c .` and not `wc -l`: the last field carries no trailing newline.
  pinned=$(printf '%s' "$tool_json" | tr ',' '\n' | grep -c .)
  case "$pinned" in
    10) word=ten ;;      11) word=eleven ;;   12) word=twelve ;;
    13) word=thirteen ;; 14) word=fourteen ;; 15) word=fifteen ;;
    *)  word="__unspelled__" ;;
  esac
  printf '  ok    mcp-smoke.sh pins %s tools\n' "$pinned"

  for f in CLAUDE.md ROADMAP.md README.md scripts/mcp-smoke.sh; do
    [ -f "$f" ] || continue
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      if [ "$n" = "$pinned" ] || [ "$n" = "$word" ]; then
        printf '  ok    %s: "%s" agrees\n' "$f" "$n"
      else
        printf '  FAIL  %s claims "%s" tools; mcp-smoke.sh pins %s (%s)\n' \
          "$f" "$n" "$pinned" "$word"
        fails=$((fails + 1))
      fi
    done <<EOF
$(grep -vE 'v0\.[0-9]' "$f" | sed -nE \
    -e 's/.*\b([0-9]+|[A-Za-z]+)[[:space:]]+MCP[[:space:]]+tools\b.*/\1/p' \
    -e 's/.*exactly the[[:space:]]+([0-9]+|[A-Za-z]+)[[:space:]]+tools\b.*/\1/p' \
    -e 's/.*\b([0-9]+|[A-Za-z]+)[[:space:]]+tools exist\b.*/\1/p' \
    | tr 'A-Z' 'a-z')
EOF
  done
fi

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
