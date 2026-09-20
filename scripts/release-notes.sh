#!/usr/bin/env bash
# Compose a GitHub Release body from CHANGELOG.md, and refuse to compose an
# empty one.
#
# **This exists because the check it carries used to be unable to fail.** The
# logic lived inline in `.github/workflows/release.yml`, in this order:
#
#     awk ... CHANGELOG.md > release-notes.md   # the version's section
#     printf '\n'          >> release-notes.md  # <- 1 byte
#     grep '^\[..\]: http' >> release-notes.md  # <- ~2.6 KB of link defs
#     if [ ! -s release-notes.md ]; then ... exit 1; fi
#
# `-s` is "exists and has a size greater than zero", and by the time it ran
# the file could not have a size of zero: the `printf` alone guaranteed a
# byte, and every link definition in the file had been appended on top of it.
# The guard was three lines below the two lines that made it unreachable, and
# it had been that way since it was written, so it had never once fired.
#
# What it was supposed to catch is a real and easy mistake, and the reason
# this file is not just a reordering: a `vX.Y.Z` tag pushed after the version
# bump but before `## [Unreleased]` is renamed passes the tag/Cargo.toml
# comparison — both say X.Y.Z — reaches here, extracts nothing, and publishes
# a release whose entire body is 47 bare link definitions. Measured against
# this repository's own CHANGELOG at `v0.0.8`: 2779 bytes, 48 lines, zero of
# them prose.
#
# So the check now runs on the EXTRACTED SECTION, BEFORE anything is
# appended, and it asks for a non-blank line rather than a byte — a section
# holding one newline is as empty as a section holding none, and `-s` calls
# the first one content.
#
# **And it is falsifiable, which is the other half.** `--self-test` runs it
# against fixtures in both directions: sections that must be refused and
# sections that must be accepted. The refusal fixtures all carry link
# definitions, deliberately — every one of them is a case the pre-fix guard
# accepted, so the self-test fails against the old code and passes against
# this one. It also runs the extractor over this repository's real
# CHANGELOG.md, which is what would catch the heading format drifting away
# from what the extractor matches.
#
# `hygiene` in `ci.yml` runs `--self-test`, not `release-rehearsal.yml`:
# the rehearsal is not among the required status checks and `hygiene` is,
# and these fixtures need no build and no runner matrix. That is the same
# argument, and the same placement, as `verify-release-archive.sh`.
#
# Usage:
#   scripts/release-notes.sh <version> [changelog] [output]
#   scripts/release-notes.sh --self-test
set -euo pipefail

fails=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s: %s\n' "$1" "$2"; fails=$((fails + 1)); }

# **"Has content" means a line that is not blank, not a link definition and
# not a heading.** Each exclusion is a section that renders as nothing, and
# each was found by trying to get an empty release past the rule rather than
# by reasoning about it:
#
#   * **Blank.** `-s` -- the test this file replaced -- counts a lone newline
#     as content.
#   * **A link definition.** The extractor below stops at the next `## `
#     heading, so every section but the LAST is bounded by one; the last runs
#     to the foot of the file, where the reference-style definitions live. A
#     trailing section with nothing under it therefore extracts ~2.6 KB of
#     `[#45]: https://...` and is non-blank. That is the same empty body the
#     broken guard would have shipped, reached by a different route.
#   * **A heading.** Keep a Changelog sections are `### Added` / `### Fixed`
#     over bullets, and this project's `## [Unreleased]` is written that way.
#     Rename it a version and delete the entries -- or open the new section
#     with the skeleton and never fill it -- and the section is two
#     subheadings and nothing else. Measured: that passed a
#     not-blank-and-not-a-link-definition rule, and the release body was
#     literally "### Added\n\n### Fixed". No real release body is headings
#     alone, so there is no false positive here to trade against.
#
# One `awk`, not `grep -v ... | grep -q ...`: under `pipefail` the second grep
# exits early on a match, the first takes SIGPIPE, and the pipeline reports
# 141 -- rejecting a section that is perfectly good.
has_prose() { # has_prose <file>
  awk '
    /^\[[^]]+\]: https?:\/\// { next }   # a link definition
    /^[ \t]*#{1,6}[ \t]/      { next }   # a heading
    /[^ \t]/                  { found = 1; exit }
    END                       { exit(found ? 0 : 1) }
  ' "$1"
}

# --------------------------------------------------------------------------
# The extraction and the guard
# --------------------------------------------------------------------------
#
# Writes the release body for <version> to <output>. Exits non-zero, with the
# reason and the fix, if there is nothing to publish.
compose() { # compose <version> <changelog> <output>
  local version="$1" changelog="$2" out="$3"

  [ -f "$changelog" ] || {
    printf 'no such changelog: %s\n' "$changelog" >&2
    return 1
  }

  # The section for exactly this version, up to the next heading. `index(...)
  # == 1` rather than a regex because a version is full of dots; the END
  # status distinguishes "no such heading" from "heading with nothing under
  # it", which are different mistakes with different fixes and used to share
  # one message.
  local heading
  if awk -v v="## [$version]" '
        index($0, v) == 1 { on = 1; found = 1; next }
        on && /^## /      { exit }
        on                { print }
        END               { exit(found ? 0 : 1) }
      ' "$changelog" > "$out"
  then heading=1
  else heading=0
  fi

  if [ "$heading" -eq 0 ]; then
    printf '%s has no "## [%s]" heading.\n' "$changelog" "$version" >&2
    printf 'Cutting a release is: rename [Unreleased] to the version with\n' >&2
    printf 'its date, add its link definition, commit, then tag. The notes\n' >&2
    printf 'are the section.\n' >&2
    return 1
  fi

  # **A line of prose, not a byte.** This is the check the `-s` test was meant
  # to be, in the position it was meant to be in: before the append below, on
  # the section alone.
  if ! has_prose "$out"; then
    printf '%s has a "## [%s]" heading with nothing under it.\n' \
      "$changelog" "$version" >&2
    printf 'A release body is that section; an empty section is an empty\n' >&2
    printf 'release. Write the entries, or do not cut the tag.\n' >&2
    return 1
  fi

  # **The definitions, or every `[#45]` renders as literal text.**
  # Reference-style links are defined once at the foot of the file, after
  # every version section, so the extractor above cannot reach them — it
  # stops at the next `## `. A body carrying `[#45]` with no matching
  # definition shows the brackets, which is precisely the defect the
  # changelog rewrite existed to fix, reintroduced one surface over.
  # Appending every definition is safe: Markdown ignores ones nothing
  # references.
  printf '\n' >> "$out"
  if ! grep -E '^\[[^]]+\]: https?://' "$changelog" >> "$out"; then
    # Under `set -e` this was previously a bare non-zero `grep` aborting the
    # step with no message at all. It is a real failure — a changelog with no
    # definitions renders every issue reference as brackets — so it keeps the
    # exit and gains the sentence.
    printf '%s carries no reference-style link definitions.\n' "$changelog" >&2
    printf 'Every issue reference in the body would render as literal\n' >&2
    printf 'brackets. Add the definitions at the foot of the file.\n' >&2
    return 1
  fi

  printf 'notes: %s lines from "## [%s]" plus %s link definitions\n' \
    "$(awk 'END { print NR }' "$out")" "$version" \
    "$(grep -cE '^\[[^]]+\]: https?://' "$changelog")"
}

# --------------------------------------------------------------------------
# --self-test
# --------------------------------------------------------------------------
#
# Fixture pairs, in both directions. A guard tested only against inputs it
# accepts is the guard this file replaced.
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # $tmp is expanded now on purpose
  trap "rm -rf '$tmp'" EXIT

  # Every fixture below ends with these, so that each REJECT case is also a
  # case the pre-fix `[ ! -s ]` guard accepted. Without them the fixtures
  # would pass against the old code too and prove nothing.
  local defs
  defs='
[Unreleased]: https://example.invalid/compare/v0.0.7...main
[0.0.7]: https://example.invalid/releases/tag/v0.0.7
[#45]: https://example.invalid/issues/45'

  case_run() { # case_run <label> <accept|reject> <version> <changelog body>
    local label="$1" want="$2" version="$3" body="$4"
    local cl="$tmp/CHANGELOG.md" out="$tmp/out.md" rc=0 log
    printf '%s\n%s\n' "$body" "$defs" > "$cl"
    rm -f "$out"
    log="$(compose "$version" "$cl" "$out" 2>&1)" || rc=$?
    case "$want" in
      accept)
        if [ "$rc" -ne 0 ]; then
          bad "$label" "refused a section that has content (rc=$rc): $log"
        elif ! grep -q '[^[:space:]]' "$out"; then
          bad "$label" "accepted but wrote nothing"
        elif ! grep -q '^\[#45\]: ' "$out"; then
          bad "$label" "accepted but did not append the link definitions"
        else
          ok "$label"
        fi ;;
      reject)
        if [ "$rc" -eq 0 ]; then
          # The whole point. Print what would have shipped.
          # Counted with the SAME exclusions `has_prose` applies, or the
          # diagnostic contradicts the rule it is reporting on.
          bad "$label" "accepted it — body would be $(wc -c < "$out") bytes, \
$(grep -cvE '^\[[^]]+\]: https?://|^[[:space:]]*$|^[[:space:]]*#{1,6}[[:space:]]' "$out") of them prose lines"
        elif [ "$(grep -c '^\[#45\]: ' "$out" 2>/dev/null || true)" -gt 1 ]; then
          # **Refused, but only after appending** — which is the defect this
          # file exists to fix, surviving into the fix. The check has to run
          # before the append or it is checking its own output.
          bad "$label" "refused, but had already appended the link definitions"
        else
          ok "$label"
        fi ;;
    esac
  }

  echo
  echo "release-notes self-test — the section decides, and it can say no"

  # The exact scenario: version bumped, tag pushed, [Unreleased] not renamed.
  case_run "a version with no heading at all is refused" reject "0.0.8" \
'# Changelog

## [Unreleased]

- something real that has not been released

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # A heading with the next heading directly under it.
  case_run "a heading with nothing under it is refused" reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20
## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # A heading followed by blank lines only. `-s` calls this content; it is
  # not, and this is the case that makes "non-blank line" rather than
  # "reordered `-s`" the fix.
  case_run "a heading followed by blank lines only is refused" reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20



## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # **The end of the file rather than the next heading**, which is the case a
  # reordered `-s` would still have got wrong: the extractor runs to EOF, so
  # this section "contains" every link definition at the foot of the file and
  # is non-empty by any test that counts bytes or non-blank lines.
  case_run "a trailing heading, whose section is only link definitions, is refused" \
    reject "0.0.9" \
'# Changelog

## [0.0.9] — 2026-09-20'

  # **The Keep a Changelog skeleton with the entries missing.** This is the
  # one that got past the first version of this guard: `## [Unreleased]` in
  # this repository is `### Added` over bullets, so renaming it and losing
  # the bullets -- or opening the new section with the skeleton and never
  # filling it -- leaves two subheadings that render as nothing.
  case_run "a section of bare \`###\` skeleton headings is refused" reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20

### Added

### Fixed

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  case_run "a section with content is accepted, definitions and all" accept "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20 (Dowel)

### Fixed

- the thing ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # The heading format this repository actually uses, em-dash and codename,
  # matched by `index(...) == 1` on the bracketed version alone.
  case_run "the codename and date on the heading do not affect the match" accept \
    "0.0.7" \
'# Changelog

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing

## [0.0.6] — 2026-08-19 (Bolt)

- the older thing'

  # A changelog with no definitions used to abort with no message.
  local cl="$tmp/nodefs.md" out="$tmp/nodefs-out.md" rc=0 log
  printf '# Changelog\n\n## [0.0.8]\n\n- a real entry\n' > "$cl"
  log="$(compose 0.0.8 "$cl" "$out" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "a changelog with no link definitions is refused" "accepted it"
  elif ! printf '%s' "$log" | grep -q 'no reference-style link definitions'; then
    bad "a changelog with no link definitions is refused" \
      "refused, but said '$log' rather than naming the cause"
  else
    ok "a changelog with no link definitions is refused"
  fi

  # --- the real file, which is what catches the heading format drifting ---
  #
  # Derived from CHANGELOG.md rather than hardcoded: every released version
  # it declares must extract to something. A hardcoded list would go stale at
  # the next release, which is the failure mode this whole file is about.
  local repo_cl versions v seen=0
  repo_cl="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)/CHANGELOG.md"
  if [ -f "$repo_cl" ]; then
    versions="$(sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' "$repo_cl")"
    for v in $versions; do
      seen=$((seen + 1))
      if compose "$v" "$repo_cl" "$tmp/real.md" >/dev/null 2>&1; then
        ok "CHANGELOG.md's own [$v] section extracts"
      else
        bad "CHANGELOG.md's own [$v] section extracts" "it did not"
      fi
    done
    # A derivation that matches nothing would report clean having checked
    # zero versions — the vacuous pass this repository's other guards each
    # grew a case for.
    if [ "$seen" -eq 0 ]; then
      bad "CHANGELOG.md declares at least one released version" \
        "the heading derivation matched nothing; this section checked nothing"
    fi
    if compose 99.99.99 "$repo_cl" "$tmp/real.md" >/dev/null 2>&1; then
      bad "a version CHANGELOG.md does not declare is refused" "accepted 99.99.99"
    else
      ok "a version CHANGELOG.md does not declare is refused"
    fi
  else
    bad "CHANGELOG.md is readable from the script's own directory" \
      "not found at $repo_cl"
  fi

  echo
  if [ "$fails" -ne 0 ]; then
    echo "release-notes SELF-TEST FAILED ($fails)"
    return 1
  fi
  echo "release-notes SELF-TEST OK — an empty section is refused before"
  echo "anything is appended to it, and a real one still composes."
}

usage() { sed -n '/^# Usage:/,/--self-test$/p' "$0" >&2; exit 2; }

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  -h|--help|'') usage ;;
esac

if [ $# -lt 1 ] || [ $# -gt 3 ]; then
  usage
fi
compose "$1" "${2:-CHANGELOG.md}" "${3:-release-notes.md}"
