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
# appended, and it asks for a line that would RENDER AS SOMETHING rather than
# for a byte. That predicate started as "non-blank" and grew every time
# somebody got an empty release past it: a section holding one newline is as
# empty as one holding none, and so is a section of bare `###` skeleton
# headings, or of link definitions, or of an HTML comment, or of a `---`.
# `prose_count` below is the list and each exclusion names the case that
# bought it.
#
# **And it is falsifiable, which is the other half.** `--self-test` runs
# fixtures in both directions: sections that must be refused and sections
# that must be accepted, with the refusal fixtures carrying link definitions
# deliberately so that each is a case the pre-fix guard accepted. **Both
# directions matter and the accept side is the one that was wrong**: it once
# asserted only that the output was non-blank and carried a `[#45]:` line,
# which the APPENDED definitions satisfy by themselves — so deleting the
# extraction outright left this file green while it composed the very body
# the whole exercise exists to refuse. It now compares bytes against an
# independently recomputed extraction. The self-test also runs the extractor
# over this repository's real CHANGELOG.md, which is what would catch the
# heading format drifting away from what the extractor matches.
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
#   * **An HTML comment or a thematic break.** Both render as nothing, and a
#     placeholder comment is a plausible thing to leave in a section opened
#     early.
#
# One `awk`, not `grep -v ... | grep -q ...`: under `pipefail` the second grep
# exits early on a match, the first takes SIGPIPE, and the pipeline reports
# 141 -- rejecting a section that is perfectly good.
#
# **`#+` and not `#{1,6}`.** mawk 1.3.4 is ubuntu-24.04's `/usr/bin/awk` and
# handles ERE intervals, but mawk 1.3.3 and the BSD awk on macOS -- which is
# what `dev/workflows/verify.md` runs on -- treat `{1,6}` as literal
# characters. That would not error; it would silently stop matching headings
# and reopen the hole above, on the platform where nobody would see it.
# CLAUDE.md's standing warning is that BSD tools fail silently, and an ERE
# interval is one of the ways.
#
# The link-definition pattern tests `]:` rather than a `https?://` scheme, and
# tolerates leading spaces, because CommonMark accepts `  [#45]: <https://x>`,
# `[spec]: ./doc.md` and `[#45]:https://x` and each of those is a definition
# that renders as nothing. A line matching `^\s*[...]:` in a release body is
# not prose. All four forms were measured getting an empty body past the
# scheme-anchored version of this rule.
# **One rule list, two callers.** `has_prose` decides and the self-test's
# failure diagnostic counts, and they used to be separate patterns with a
# comment claiming they were the same. They were not, so a diagnostic could
# contradict the rule it was reporting on. `prose_count` is the rule list;
# both go through it.
#
# `LINKDEF` is the `grep` half of the link-definition rule, used by the APPEND
# below. It and `prose_count`'s awk half were once a scheme-anchored pattern
# and a `]:` one: the predicate was widened and the append was not, so a
# changelog written in any of the forms this file advertises got a body whose
# `[#99]` references were silently never defined -- the exact defect the
# append exists to prevent, reintroduced by the fix to a different one.
LINKDEF='^[ \t]*\[[^]]+\][ \t]*:'

# **The awk copy is a LITERAL regex, not `-v linkdef=...`, and that is not a
# style choice.** A string passed with `-v` becomes a *dynamic* regex, so awk
# runs string-escape processing over it first: `\[` collapses to `[` and the
# pattern silently becomes `^[ \t]*[[^]]+][ \t]*:`, which matches nothing like
# the same set. mawk and gawk disagree about it, so the shared-variable
# version passed under `/usr/bin/awk` and failed under gawk, busybox awk,
# original-awk and `gawk --posix` alike -- a portability break introduced by
# the fix for the two patterns having drifted apart.
#
# So they are two spellings again, and the honest guard is behavioural rather
# than textual: `--self-test` feeds a corpus of definition forms through BOTH
# and fails if they ever classify one differently. "Same behaviour, asserted"
# is stronger than "same string, assumed" -- and it is what the drift they
# came from actually needed.
prose_count() { # prose_count <file> -- lines that would render as something
  awk '
    # **Strip CR first, on every line.** `/[^ \t]/` treats a lone carriage
    # return as a printing character, so ONE stray `\r` line anywhere in a
    # section made the whole section "prose" -- including the `### Added` /
    # `### Fixed` skeleton this rule was written to refuse. Measured: the
    # same fixture passed with a CR and was refused with it stripped. There
    # is no `.gitattributes` here and nothing else guards line endings.
    { gsub(/\r/, "") }
    /^[ \t]*\[[^]]+\][ \t]*:/            { next }  # a link definition
    /^[ \t]*#+[ \t]/                     { next }  # an ATX heading
    # **A comment BLOCK, not a comment line.** Skipping lines that start with
    # `<!--` refused the one-line form and accepted the multi-line one --
    # which is the natural spelling of the placeholder the rule exists for.
    /^[ \t]*<!--/                        { if ($0 !~ /-->/) inc = 1; next }
    inc                                  { if ($0 ~ /-->/) inc = 0; next }
    /^[ \t]*(---+|\*\*\*+|___+)[ \t]*$/  { next }  # a thematic break
    /[^ \t]/                             { n++ }
    END                                  { print n + 0 }
  ' "$1"
}

has_prose() { # has_prose <file>
  [ "$(prose_count "$1")" -gt 0 ]
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
  #
  # **Fenced blocks are tracked**, because `## ` inside one is not a heading
  # and truncating a section there is silent: the release publishes fine,
  # short, with `rc=0`. `CHANGELOG.md` has no fences today; `CONTRIBUTING.md`
  # has twelve, so this project does write them, and a changelog entry that
  # quotes a Markdown heading is one edit away. Four lines and two fixtures
  # against a truncation nobody would see until the release was out.
  local heading
  if awk -v v="## [$version]" '
        { gsub(/\r/, "") }
        /^[ \t]*(```|~~~)/ { fence = !fence }
        !fence && index($0, v) == 1 { on = 1; found = 1; next }
        !fence && on && /^## /      { exit }
        on                          { print }
        END                         { exit(found ? 0 : 1) }
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
  #
  # **The same `LINKDEF` the predicate uses.** These two drifted apart once
  # already and the failure was silent in both directions: a changelog using
  # the non-canonical forms got a body whose references were never defined,
  # and an all-non-canonical one was refused at tag time for having "no link
  # definitions" while having 47.
  printf '\n' >> "$out"
  if ! grep -E "$LINKDEF" "$changelog" >> "$out"; then
    # Under `set -e` this was previously a bare non-zero `grep` aborting the
    # step with no message at all. It is a real failure — a changelog with no
    # definitions renders every issue reference as brackets — so it keeps the
    # exit and gains the sentence.
    printf '%s carries no reference-style link definitions.\n' "$changelog" >&2
    printf 'Every issue reference in the body would render as literal\n' >&2
    printf 'brackets. Add the definitions at the foot of the file.\n' >&2
    return 1
  fi

  # **Phrased so the numbers add up.** This read "N lines … plus M link
  # definitions" where N was the total INCLUDING the M, so 171 and 47 read as
  # 218. The counts are now stated as the breakdown they are.
  local total defs section
  total="$(awk 'END { print NR + 0 }' "$out")"
  defs="$(grep -cE "$LINKDEF" "$changelog")"
  section=$((total - defs - 1))
  printf 'notes: %s lines total = %s from "## [%s]" + 1 blank + %s link definitions\n' \
    "$total" "$section" "$version" "$defs"

  # **A body has an upper bound and nothing here knew it.** GitHub's release
  # body limit is documented as 125,000 characters. A real
  # `[Unreleased]` → `[0.0.8]` rename composes 95,809 bytes / 95,253
  # characters as of 2026-09-20 — 24% of headroom left, and it was 85,637
  # bytes earlier the same evening, so this is not a slow drift. The failure
  # lands on `gh release create`, after five platform builds, on the one
  # workflow that gets no second attempt.
  #
  # Thresholded on BYTES against a limit stated in CHARACTERS, deliberately:
  # a UTF-8 byte count is never smaller than the character count (here by 556,
  # the em-dashes), so the warning fires early rather than late. Measure the
  # real limit before turning either number into a hard failure.
  #
  # **A warning and not an error, deliberately.** The limit is taken from
  # GitHub's documentation and has not been measured here; failing a correct
  # release on an unverified number would be the worse mistake of the two,
  # and it is the mistake this file exists to stop making. So it says so
  # loudly and lets the release proceed. Make it an error once somebody has
  # seen the API reject one.
  local bytes
  bytes="$(wc -c < "$out")"
  if [ "$bytes" -gt 100000 ]; then
    printf 'WARNING: the release body is %s bytes.\n' "$bytes" >&2
    printf "GitHub's documented limit is 125,000 characters and this is not\n" >&2
    printf 'far off it. If the release create step rejects the body, that is why.\n' >&2
  fi
}

# --------------------------------------------------------------------------
# --self-test
# --------------------------------------------------------------------------
#
# Fixture pairs, in both directions. A guard tested only against inputs it
# accepts is the guard this file replaced.
self_test() {
  # **`tmp` is global and the trap is single-quoted.** The double-quoted form
  # interpolated the path into the trap body, so a `TMPDIR` containing an
  # apostrophe made the trap a syntax error: `SELF-TEST OK`, exit 2, tempdir
  # leaked. `verify-release-archive.sh` -- the script this one is modelled on
  # -- already had the right form. Global rather than `local` because the
  # trap fires after this function has returned.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Every fixture below ends with these, so that each REJECT case is also a
  # case the pre-fix `[ ! -s ]` guard accepted. Without them the fixtures
  # would pass against the old code too and prove nothing.
  local defs
  defs='
[Unreleased]: https://example.invalid/compare/v0.0.7...main
[0.0.7]: https://example.invalid/releases/tag/v0.0.7
[#45]: https://example.invalid/issues/45'

  # case_run <label> <accept|reject> <version> <changelog body> [expected msg]
  #
  # The fifth argument is a fragment the refusal must print. **Both primary
  # messages were unasserted**: swapping them survived the whole self-test, so
  # a releaser whose changelog had no heading at all could be told "heading
  # with nothing under it" -- and telling those two apart is the improvement
  # this file claims over the guard it replaced.
  case_run() {
    local label="$1" want="$2" version="$3" body="$4" expect="${5:-}"
    local cl="$tmp/CHANGELOG.md" out="$tmp/out.md" rc=0 log
    printf '%s\n%s\n' "$body" "$defs" > "$cl"
    rm -f "$out"
    # **The extraction, recomputed here rather than taken from `compose`.**
    # A test that asks the implementation what the right answer is cannot
    # catch the implementation being wrong. Both branches below compare
    # `$out` against this.
    #
    # Known limit, stated rather than implied: this is a COPY of `compose`'s
    # awk, so a mutation applied to both survives. It catches the guard being
    # reordered, which is what it is for; it does not catch the extractor
    # being wrong in the same way twice.
    awk -v v="## [$version]" '
      { gsub(/\r/, "") }
      /^[ \t]*(```|~~~)/ { fence = !fence }
      !fence && index($0, v) == 1 { on = 1; next }
      !fence && on && /^## /      { exit }
      on                          { print }
    ' "$cl" > "$tmp/extracted.md"
    log="$(compose "$version" "$cl" "$out" 2>&1)" || rc=$?
    case "$want" in
      accept)
        # **`$out` must BEGIN with the extracted section.** This branch used
        # to assert only "not all whitespace" and "contains a `[#45]:` line"
        # -- both of which the APPENDED definitions satisfy on their own. So
        # deleting the extraction entirely (`: > "$out"` before the append)
        # left the self-test green while the script shipped a 48-line body of
        # bare link definitions: byte for byte the original defect, passing
        # the guard written to catch it. Measured, and it is why this compares
        # bytes rather than counting them.
        local n
        n="$(wc -c < "$tmp/extracted.md")"
        if [ "$rc" -ne 0 ]; then
          bad "$label" "refused a section that has content (rc=$rc): $log"
        elif ! head -c "$n" "$out" | cmp -s - "$tmp/extracted.md"; then
          bad "$label" "accepted, but the body does not start with the \
extracted section ($n bytes expected)"
        elif ! grep -q '^\[#45\]: ' "$out"; then
          bad "$label" "accepted but did not append the link definitions"
        else
          ok "$label"
        fi ;;
      reject)
        if [ "$rc" -eq 0 ]; then
          # The whole point. Print what would have shipped — counted through
          # `prose_count`, which IS the rule, rather than through a second
          # pattern that claimed to be it and was not.
          bad "$label" "accepted it — body would be $(wc -c < "$out") bytes, \
$(prose_count "$out") of them prose lines"
        elif [ -n "$expect" ] && ! printf '%s' "$log" | grep -qF "$expect"; then
          bad "$label" "refused, but said \"$(printf '%s' "$log" | head -1)\" \
rather than naming: $expect"
        elif ! cmp -s "$out" "$tmp/extracted.md"; then
          # **Refused, but only after appending** — which is the defect this
          # file exists to fix, surviving into the fix. The check has to run
          # before the append or it is checking its own output.
          #
          # Asserted by recomputing the extraction INDEPENDENTLY (above) and
          # demanding `$out` still equal it byte for byte. The first spelling
          # of this counted `[#45]` lines and asked for `-gt 1`, which could
          # only ever fire for the one trailing fixture whose section already
          # contains the definitions: moving `has_prose` back after the
          # append turned exactly 1 of 5 reject cases red instead of 5. A
          # regression check that catches the regression in one fifth of the
          # cases it is written over is the failure this whole file is about,
          # reproduced inside its own test.
          bad "$label" "refused, but \$out is no longer the extracted section \
($(wc -c < "$tmp/extracted.md") bytes extracted, $(wc -c < "$out") written)"
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

- the released thing' \
    'has no "## [0.0.8]" heading'

  # A heading with the next heading directly under it.
  case_run "a heading with nothing under it is refused" reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20
## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    'heading with nothing under it'

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

  # **The same skeleton with one stray carriage return in it.** `/[^ \t]/`
  # counts a lone CR as a printing character, so before the `gsub` above this
  # exact fixture passed -- one invisible byte turning the case the guard was
  # written for back into an accept. There is no `.gitattributes` here.
  case_run "a stray carriage return does not turn an empty section into prose" \
    reject "0.0.8" \
"# Changelog

## [0.0.8] — 2026-09-20

### Added
$(printf '\r')
### Fixed

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing" \
    'heading with nothing under it'

  # **A MULTI-line HTML comment**, which is the natural spelling of the
  # placeholder this exclusion exists for. The one-line form was refused and
  # this one was accepted, which is the wrong way round.
  case_run "a section that is only a multi-line HTML comment is refused" \
    reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20

<!--
  entries go here
-->

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # A thematic break renders as a rule and nothing else. Also the case that
  # shows 4 was the fixture set size and not a ceiling: any reject fixture
  # bounded by a heading catches the append-before-check reorder.
  case_run "a section that is only a thematic break is refused" reject "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20

---

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # **`## ` inside a fenced block is not a heading.** Without fence tracking
  # the extractor stops at the fenced line and the release publishes short,
  # green, with nobody told. `CHANGELOG.md` has no fences today;
  # `CONTRIBUTING.md` has twelve.
  case_run "a fenced \`## \` does not truncate the section" accept "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20 (Dowel)

- the extractor used to stop inside this block:

```markdown
## [0.0.7] — not a heading, it is a fence body
```

- and this line was silently dropped from the release ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # The other direction: a fence must not swallow a REAL following heading.
  case_run "a closed fence still ends the section at the next heading" accept \
    "0.0.8" \
'# Changelog

## [0.0.8] — 2026-09-20 (Dowel)

```text
some output
```

- a real entry ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing must not appear in 0.0.8'

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

  # --- the two link-definition spellings must agree, line for line -------
  #
  # `prose_count`'s awk regex and `LINKDEF` (which `grep` uses for the
  # append) are separate spellings of one rule, because awk cannot safely
  # take the shell's copy -- see the note above `prose_count`. Textual
  # identity is therefore off the table, so this asserts the property that
  # actually matters: for every form below, the two must make the SAME call.
  # When they drifted apart before, the damage went both ways -- a body whose
  # references were never defined, and a false "no link definitions" refusal
  # at tag time on a changelog that had 47.
  local lines i line g_match a_prose
  lines='[#45]: https://x/45
[#45]: <https://x/45>
  [#45]: https://x/45
[#45]:https://x/45
[spec]: ./docs/SPEC.md
[Unreleased]: https://x/compare/v0.0.7...main'
  i=0
  while IFS= read -r line; do
    i=$((i + 1))
    printf '%s\n' "$line" > "$tmp/one.md"
    g_match=0; printf '%s\n' "$line" | grep -qE "$LINKDEF" && g_match=1
    a_prose="$(prose_count "$tmp/one.md")"
    # A definition: grep must match it, and awk must NOT count it as prose.
    if [ "$g_match" -eq 1 ] && [ "$a_prose" -eq 0 ]; then
      ok "both spellings call form $i a link definition"
    else
      bad "both spellings call form $i a link definition" \
        "grep matched=$g_match, prose_count=$a_prose for: $line"
    fi
  done <<EOF
$lines
EOF
  # And the other direction, or a rule that called EVERYTHING a definition
  # would pass every case above.
  for line in '- a real entry ([#45])' 'Plain prose.' '  indented prose'; do
    printf '%s\n' "$line" > "$tmp/one.md"
    g_match=0; printf '%s\n' "$line" | grep -qE "$LINKDEF" && g_match=1
    a_prose="$(prose_count "$tmp/one.md")"
    if [ "$g_match" -eq 0 ] && [ "$a_prose" -eq 1 ]; then
      ok "both spellings call \"$line\" prose"
    else
      bad "both spellings call \"$line\" prose" \
        "grep matched=$g_match, prose_count=$a_prose"
    fi
  done

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
