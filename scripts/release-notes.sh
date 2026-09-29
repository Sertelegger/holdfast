#!/usr/bin/env bash
# Compose a GitHub Release body from CHANGELOG.md, and refuse to compose an
# empty one or one over GitHub's size limit. `--self-test` also holds every
# `[Unreleased]` entry to `ENTRY_CAP` lines.
#
# **This exists because the check it carries used to be unable to fail.** The
# logic lived inline in `.github/workflows/release.yml`, in this order:
#
#     awk ... CHANGELOG.md > release-notes.md   # the version's section
#     printf '\n'          >> release-notes.md  # <- 1 byte
#     grep '^\[..\]: http' >> release-notes.md  # <- every link definition
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
# a release whose entire body is every link definition in the file and no
# prose at all.
#
# **No byte or line count is quoted for that, deliberately.** Three were, and
# all three were stale before this paragraph was finished: the figures move
# with every merged `[Unreleased]` entry, and one set described a commit
# three merges before this branch's own base. The number that matters does
# not move -- zero prose lines -- and the rest is
# `grep -c '^\[[^]]*\]:' CHANGELOG.md` for anyone who wants it today.
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

# The largest release body `compose` will write, in characters (see the
# check at the end of `compose`).
BODY_LIMIT=120000
# The most non-blank lines an `[Unreleased]` entry may carry (`entry_cap`).
# The issue and the PR carry the detail.
ENTRY_CAP=3

fails=0
passes=0
refusals=0
# `refusals` counts the cases whose subject is the guard saying no, which is
# the number worth knowing: a suite that only proves acceptance is the suite
# this file replaced.
# `ok <label> [refusal]` -- the second argument is passed by the branches
# whose subject is the guard saying NO. Counted at the call site rather than
# matched out of the label: a `case` over label text is a hand-maintained
# list wearing a derivation's clothes, and this file exists to stop writing
# those.
ok()  {
  printf '  ok    %s\n' "$1"
  passes=$((passes + 1))
  [ "${2:-}" = refusal ] && refusals=$((refusals + 1))
  return 0
}
bad() { printf '  FAIL  %s: %s\n' "$1" "$2"; fails=$((fails + 1)); }

# **"Has content" means a line that RENDERS as something** -- not blank, not
# a link definition, not a heading, not an HTML comment and not a thematic
# break. This lead said "three" while the list under it ran to five, which is
# the self-contradiction this whole branch keeps finding elsewhere. The rule
# is `prose_count`; the list is below it; neither is a summary of the other.
# Each exclusion was bought by a case that got an empty release past the rule
# rather than by reasoning about it:
#
#   * **Blank.** `-s` -- the test this file replaced -- counts a lone newline
#     as content.
#   * **A link definition.** The extractor below stops at the next `## `
#     heading, so every section but the LAST is bounded by one; the last runs
#     to the foot of the file, where the reference-style definitions live. A
#     trailing section with nothing under it therefore extracts every
#     `[#45]: https://...` in the file and is non-blank. That is the same
#     empty body the broken guard would have shipped, by a different route.
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
#
# **There is now ONE spelling of that rule, and it is awk's.** It was two --
# an awk regex for the predicate and a `grep -E` for the append -- and the
# pair went wrong three separate ways:
#
#   * they drifted, so the predicate called a form a definition and the
#     append did not collect it, producing a body whose `[#99]` rendered as
#     brackets;
#   * sharing the pattern through `awk -v` made it a *dynamic* regex, where
#     string-escape processing collapses `\[` to `[` -- mawk tolerated it and
#     gawk, `--posix`, `--traditional`, original-awk and busybox awk all
#     matched nothing (gawk says so: `escape sequence '\[' treated as plain
#     '['`);
#   * and they disagree on a TAB-indented definition even when both are
#     "correct", because busybox and BSD `grep` read `[ \t]` as the set
#     {space, backslash, t} while every awk reads it as a tab. Not live on
#     GNU `grep`, and the nine-case equivalence corpus could not see it
#     because it had no tab form.
#
# A behavioural equivalence test was the right answer to the first two and no
# answer at all to the third. Deleting one of the two spellings answers all
# three, so the append is `awk` now and `grep` is gone from this rule.
#
# **And the append is fence-aware, which `grep` could not be.** The extractor
# honours fenced blocks; the append did not, so a link definition shown as an
# EXAMPLE inside a code fence was collected and emitted as a real definition.
# Both now run over the same scanner below.

# --------------------------------------------------------------------------
# AWK_SCAN -- the shared fence/comment state machine
# --------------------------------------------------------------------------
#
# Prepended to every awk program that reads the changelog, so that "is this
# line structural Markdown or content?" is answered in exactly one place. It
# sets `skip` for any line inside (or delimiting) a fenced block or an HTML
# comment, and leaves `infence` / `incomment` readable at END.
#
# **The fence toggle is marker-aware, and the bare `fence = !fence` it
# replaced was wrong four ways** -- each measured, each silently producing a
# WRONG release body at `rc=0`, which is the failure mode fence tracking was
# added to prevent:
#
#   * a nested fence (4-backtick outer, 3-backtick inner) closed the outer on
#     the inner's opener, and the entry after the block vanished;
#   * a `~~~` closed a fence a ``` had opened, leaking a previous release's
#     entries into the body;
#   * `## [0.0.7]` inside an HTML comment ended the section, because the
#     extractor tracked fences and not comments while `prose_count` tracked
#     comments and not fences -- two state machines, blind to each other;
#   * and an unterminated fence swallowed the rest of the file.
#
# CommonMark's rule is the one implemented: a closer is the same character as
# the opener, at least as long, and followed by nothing but whitespace.
#
# No ERE intervals anywhere -- `{3,}` is literal under mawk 1.3.3 and BSD awk,
# which would silently stop recognising fences on the platform
# `dev/workflows/verify.md` runs on. The run length is counted by hand.
# shellcheck disable=SC2016  # awk program text; `$0` is awk's
AWK_SCAN='
function fence_run(str,   c, n) {
  c = substr(str, 1, 1)
  if (c != "`" && c != "~") return 0
  n = 0
  while (substr(str, n + 1, 1) == c) n++
  if (n < 3) return 0
  runchar = c
  return n
}
{
  gsub(/\r/, "")
  stripped = $0
  sub(/^[ \t]+/, "", stripped)
  run = fence_run(stripped)
  # **`incomment` is tested FIRST, and that order is the whole of this
  # branch.** `<!--` opens an HTML block whose contents are raw until `-->`,
  # so a ``` inside one is not a fence opener. With the fence arm evaluated
  # first it opened one, and the file then "ended inside an unterminated
  # fence" -- a refusal, so it failed closed and no wrong body shipped, but
  # the message told a release engineer to close a fence that was never open
  # and was already closed. At tag time, one attempt, that sends somebody
  # editing a correct changelog.
  #
  # It is the defect the shared scanner was built to remove, inverted: one
  # state machine now, but the comment did not mask the fence. The two are
  # mutually exclusive -- whichever opened first runs to its own closer --
  # so the arms below are ordered, not nested, and the reverse case (a
  # `<!--` inside a fence, which must stay raw) falls into the `infence` arm
  # and is ignored exactly as it should be.
  if (incomment) {
    skip = 1
    if (stripped ~ /-->/) incomment = 0
  } else if (infence) {
    skip = 1
    if (run && runchar == openchar && run >= openlen \
        && substr(stripped, run + 1) ~ /^[ \t]*$/) infence = 0
  } else if (run) {
    infence = 1; openchar = runchar; openlen = run; skip = 1
  } else if (stripped ~ /^<!--/) {
    skip = 1
    if (stripped !~ /-->/) incomment = 1
  } else {
    skip = 0
  }
}
'

# **A changelog that ends inside a fence or a comment is refused outright.**
# There is no correct extraction from one: every `## ` after the unterminated
# opener is invisible, so the section runs to EOF and takes every earlier
# release with it. Silently publishing that is strictly worse than not
# publishing.
wellformed() { # wellformed <changelog>
  awk "$AWK_SCAN"'
    END {
      if (infence)   { print "fence";   exit 1 }
      if (incomment) { print "comment"; exit 1 }
    }
  ' "$1"
}

# Every reference-style link definition, in file order, skipping any shown
# inside a fence or a comment.
link_defs() { # link_defs <changelog>
  awk "$AWK_SCAN"'
    !skip && /^[ \t]*\[[^]]+\][ \t]*:/ { print }
  ' "$1"
}

prose_count() { # prose_count <file> -- lines that would render as something
  awk "$AWK_SCAN"'
    # **Strip CR first, on every line.** `/[^ \t]/` treats a lone carriage
    # return as a printing character, so ONE stray `\r` line anywhere in a
    # section made the whole section "prose" -- including the `### Added` /
    # `### Fixed` skeleton this rule was written to refuse. Measured: the
    # same fixture passed with a CR and was refused with it stripped. There
    # is no `.gitattributes` here and nothing else guards line endings.
    # **A fenced block IS prose**, unlike everywhere else in this file: it
    # renders as a code block, so a section containing one is not empty. That
    # is why `prose_count` runs the shared scanner and then *inverts* its
    # verdict for fences -- `skip` means "structural" to the extractor and
    # "still renders" here for a fence, "renders as nothing" for a comment.
    # The two used to have separate, partial state machines: this one tracked
    # comments and not fences, the extractor fences and not comments, and a
    # `## ` inside a comment therefore ended a section the predicate had
    # already read past.
    skip && (infence || run)             { n++; next }
    skip                                 { next }  # an HTML comment
    /^[ \t]*\[[^]]+\][ \t]*:/            { next }  # a link definition
    /^[ \t]*#+[ \t]/                     { next }  # an ATX heading
    /^[ \t]*(---+|\*\*\*+|___+)[ \t]*$/  { next }  # a thematic break
    /[^ \t]/                             { n++ }
    END                                  { print n + 0 }
  ' "$1"
}

has_prose() { # has_prose <file>
  [ "$(prose_count "$1")" -gt 0 ]
}

# **One line per `[Unreleased]` entry longer than `ENTRY_CAP` non-blank
# lines**, as `<count> lines: <the entry's first line>`, cut to 100 bytes.
# Exits 2 when the file has no `## [Unreleased]` heading, so a heading that
# drifted out of the match cannot read as a section of short entries.
#
# An entry is a block of the section, which runs from `## [Unreleased]` to
# the next `## ` outside a fence or comment:
#
#   * a top-level list item (`-`, `*`, `+`, `N.` or `N)` at column 0) opens
#     one, and runs until the next top-level item or heading;
#   * a column-0 line after a blank line opens one too -- a paragraph under
#     the section is capped like an entry, or the cap would not bind prose
#     written without a bullet;
#   * indented lines (continuations, sub-bullets, an item's later
#     paragraphs) and a column-0 line with no blank above it (a lazy
#     continuation) belong to the open entry, as do fence and comment lines;
#   * blank lines, headings, thematic breaks and link definitions are
#     structure and count toward nothing; a heading or a break closes the
#     open entry.
#
# Non-blank lines rather than rendered lines, because the file is where the
# length is written and read; blank lines are free so an entry's own spacing
# is not penalised.
entry_cap() { # entry_cap <changelog>
  awk -v cap="$ENTRY_CAP" "$AWK_SCAN"'
    function close_entry() {
      if (n > cap + 0) print n " lines: " substr(first, 1, 100)
      n = 0
    }
    function count() {
      if (n == 0) first = $0
      n++
      blank = 0
    }
    !skip && index($0, "## [Unreleased]") == 1 { on = 1; found = 1; next }
    !on                                         { next }
    !skip && /^## /                             { close_entry(); exit }
    skip {
      if ($0 ~ /[^ \t]/) count(); else blank = 1
      next
    }
    !/[^ \t]/                                   { blank = 1; next }
    /^[ \t]*#+[ \t]/                            { close_entry(); blank = 0; next }
    /^[ \t]*(---+|\*\*\*+|___+)[ \t]*$/         { close_entry(); blank = 0; next }
    /^[ \t]*\[[^]]+\][ \t]*:/                   { blank = 0; next }
    /^([-*+]|[0-9]+[.)])[ \t]/                  { close_entry(); count(); next }
    /^[^ \t]/ && blank                          { close_entry(); count(); next }
                                                { count() }
    END { close_entry(); exit(found ? 0 : 2) }
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

  # **Refuse a changelog that ends inside a fence or a comment**, before
  # reading anything out of it. Past an unterminated opener every `## ` is
  # invisible, so the section runs to EOF and carries every earlier release
  # with it -- silently, at rc=0. There is no correct extraction to fall back
  # on, so this is a refusal rather than a repair.
  local unterminated
  if unterminated="$(wellformed "$changelog")"; then :; else
    printf '%s ends inside an unterminated %s.\n' "$changelog" "$unterminated" >&2
    printf 'Every "## " after the opener is invisible to the extractor, so\n' >&2
    printf 'the section would run to the end of the file and publish earlier\n' >&2
    printf 'releases as part of this one. Close it.\n' >&2
    return 1
  fi

  # The section for exactly this version, up to the next heading. `index(...)
  # == 1` rather than a regex because a version is full of dots; the END
  # status distinguishes "no such heading" from "heading with nothing under
  # it", which are different mistakes with different fixes and used to share
  # one message.
  #
  # **Fenced blocks are tracked**, because `## ` inside one is not a heading
  # and truncating a section there is silent: the release publishes fine,
  # short, with `rc=0`. `CHANGELOG.md` has no fences today; `CONTRIBUTING.md`
  # has six, so this project does write them, and a changelog entry that
  # quotes a Markdown heading is one edit away. Four lines and two fixtures
  # against a truncation nobody would see until the release was out.
  local heading
  if awk -v v="## [$version]" "$AWK_SCAN"'
        !skip && index($0, v) == 1 { on = 1; found = 1; next }
        !skip && on && /^## /      { exit }
        on                         { print }
        END                        { exit(found ? 0 : 1) }
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
  # One spelling, and it is fence-aware: see `link_defs` above.
  #
  # **Counted with `awk END`, never `| grep -q .`.** `grep -q` exits on its
  # first match, `link_defs`'s awk takes SIGPIPE, and under `pipefail` the
  # pipeline reports 141 -- so the guard fired on a changelog that had 53
  # definitions. It surfaced only under busybox awk, which is precisely why
  # the six-interpreter matrix in `ci.yml` exists: one interpreter called it
  # fine. This is the same trap the note above `prose_count` describes, and
  # it was walked into three functions later.
  local ndefs
  ndefs="$(link_defs "$changelog" | awk 'END { print NR + 0 }')"
  printf '\n' >> "$out"
  if [ "$ndefs" -eq 0 ]; then
    # Under `set -e` this was previously a bare non-zero `grep` aborting the
    # step with no message at all. It is a real failure — a changelog with no
    # definitions renders every issue reference as brackets — so it keeps the
    # exit and gains the sentence.
    printf '%s carries no reference-style link definitions.\n' "$changelog" >&2
    printf 'Every issue reference in the body would render as literal\n' >&2
    printf 'brackets. Add the definitions at the foot of the file.\n' >&2
    return 1
  fi
  link_defs "$changelog" >> "$out"

  # **Phrased so the numbers add up.** This read "N lines … plus M link
  # definitions" where N was the total INCLUDING the M, so 171 and 47 read as
  # 218. The counts are now stated as the breakdown they are.
  local total section
  defs=
  total="$(awk 'END { print NR + 0 }' "$out")"
  defs="$ndefs"
  section=$((total - defs - 1))
  printf 'notes: %s lines total = %s from "## [%s]" + 1 blank + %s link definitions\n' \
    "$total" "$section" "$version" "$defs"

  # **A body over `BODY_LIMIT` characters is refused.** GitHub documents a
  # 125,000-character limit on a release body, and the step that would hit it
  # is `gh release create`, after five platform builds, on the one workflow
  # that gets no second attempt. Refused here, it fails with the reason and
  # before anything is created; and `--self-test` composes `[Unreleased]`
  # the same way, so a pull request meets the limit before a tag does. The
  # 5,000-character margin is for the version heading's rename and the link
  # definition a release adds.
  #
  # Characters, not bytes, because that is the limit's unit: this changelog's
  # `—` and `§` are three and two bytes each, so a byte count refuses bodies
  # GitHub would accept. They are counted as the bytes that are not UTF-8
  # continuation bytes, under `LC_ALL=C`, and not with `wc -m`, whose answer
  # depends on the runner's locale and is a byte count under `C`.
  local chars
  chars="$(LC_ALL=C tr -d '\200-\277' < "$out" | wc -c)"
  chars=$((chars))
  printf 'notes: %s characters, against a limit of %s\n' "$chars" "$BODY_LIMIT"
  if [ "$chars" -gt "$BODY_LIMIT" ]; then
    printf 'The release body is %s characters; the limit here is %s, under\n' \
      "$chars" "$BODY_LIMIT" >&2
    printf "GitHub's documented 125,000. Changelog entries are at most 3 lines,\n" >&2
    printf 'with the detail in the issue and the PR: condense the section.\n' >&2
    return 1
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
    # Known limit, stated rather than implied: this shares `AWK_SCAN` with
    # `compose`, so a mutation inside the scanner survives here too. It
    # catches the guard being reordered or the body growing a tail, which is
    # what it is for. **What covers the scanner instead is `case_body`
    # below**, which asserts on the text of the body rather than on a
    # recomputation of it -- the fence and comment fixtures name a line that
    # must appear and a line that must not, which no copy of the extractor
    # can satisfy by being wrong in the same way.
    #
    # Its own fence toggle was `fence = !fence` and therefore carried all
    # four of the defects that bug had; sharing the scanner was the fix.
    awk -v v="## [$version]" "$AWK_SCAN"'
      !skip && index($0, v) == 1 { on = 1; next }
      !skip && on && /^## /      { exit }
      on                         { print }
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
        # **The WHOLE file, not a prefix.** This compared only the leading
        # `wc -c` bytes against the extraction, so everything past that point
        # was unasserted: appending the entire changelog again
        # (`cat "$changelog" >> "$out"`) left all 26 cases green while the
        # body shipped with the changelog stapled to its end. That is round
        # 3's defect -- an assertion that cannot see what sits next to it --
        # moved from the head of the file to the tail. The body is exactly
        # the extraction, one blank line, and the definitions; so say that.
        cat "$tmp/extracted.md" > "$tmp/want.md"
        printf '\n' >> "$tmp/want.md"
        link_defs "$cl" >> "$tmp/want.md"
        if [ "$rc" -ne 0 ]; then
          bad "$label" "refused a section that has content (rc=$rc): $log"
        elif ! cmp -s "$out" "$tmp/want.md"; then
          bad "$label" "accepted, but the body is not \
extraction + blank + definitions ($(wc -c < "$tmp/want.md") bytes wanted, \
$(wc -c < "$out") written)"
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
          ok "$label" refusal
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
  # `CONTRIBUTING.md` has six (twelve marker lines).
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
    ok "a changelog with no link definitions is refused" refusal
  fi

  # --- the section boundary survives fences and comments -----------------
  #
  # **Asserted on the TEXT of the body**, not against a recomputed
  # extraction: every one of these was a silent `rc=0` wrong body, and the
  # thing that makes them wrong is which lines came out. `must` has to
  # appear, `must_not` has to be absent. A copy of a broken extractor cannot
  # pass these by agreeing with itself.
  case_body() { # case_body <label> <version> <body> <must> <must_not>
    local label="$1" version="$2" body="$3" must="$4" must_not="$5"
    local cl="$tmp/CHANGELOG.md" out="$tmp/out.md" rc=0 log
    printf '%s\n%s\n' "$body" "$defs" > "$cl"
    rm -f "$out"
    log="$(compose "$version" "$cl" "$out" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
      bad "$label" "refused: $log"
    elif ! grep -qF "$must" "$out"; then
      bad "$label" "body lost the line it had to keep: $must"
    elif grep -qF "$must_not" "$out"; then
      bad "$label" "body leaked a line from another release: $must_not"
    else
      ok "$label"
    fi
  }

  # A bare `fence = !fence` closed the outer fence on the inner opener, and
  # everything after the block vanished from the release.
  case_body "a nested fence does not end the section early" 0.0.8 \
'# Changelog

## [0.0.8] — 2026-09-20

````
outer, holding an example:
```
## [0.0.7] — not a heading
```
````

- KEEP-ME the entry after the block ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- LEAK-ME the previous release' \
    'KEEP-ME' 'LEAK-ME'

  # `~~~` closed a fence that ``` opened, so the section ran on past the
  # next heading and took the previous release with it.
  case_body "a mismatched fence marker does not close the fence" 0.0.8 \
'# Changelog

## [0.0.8] — 2026-09-20

```
code
~~~
still code
```

- KEEP-ME the entry after the block ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- LEAK-ME the previous release' \
    'KEEP-ME' 'LEAK-ME'

  # The extractor tracked fences and not comments while `prose_count`
  # tracked comments and not fences: two state machines, blind to each
  # other, so a `## ` inside a comment ended the section.
  case_body "a heading inside an HTML comment does not end the section" 0.0.8 \
'# Changelog

## [0.0.8] — 2026-09-20

<!--
## [0.0.7] — not a heading
-->

- KEEP-ME the entry after the comment ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- LEAK-ME the previous release' \
    'KEEP-ME' 'LEAK-ME'

  # **A fence marker inside a comment is not a fence**, and the pair is here
  # because a naive fix for one direction breaks the other. CommonMark: an
  # HTML block opened by `<!--` runs raw to `-->`, and a fenced block runs to
  # its own closer; whichever opened first wins, so neither may start inside
  # the other. The first of these refused with "ends inside an unterminated
  # fence" -- failing closed, but telling a release engineer to close a fence
  # that was never open, at tag time, with one attempt.
  case_body "a fence marker inside an HTML comment is not a fence" 0.0.8 \
'# Changelog

## [0.0.8] — 2026-09-20

<!--
```
-->

- KEEP-ME the entry after the comment ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- LEAK-ME the previous release' \
    'KEEP-ME' 'LEAK-ME'

  case_body "a comment marker inside a fence is not a comment" 0.0.8 \
'# Changelog

## [0.0.8] — 2026-09-20

```
<!--
```

- KEEP-ME the entry after the block ([#45])

## [0.0.7] — 2026-09-01 (Carabiner)

- LEAK-ME the previous release' \
    'KEEP-ME' 'LEAK-ME'

  # --- the link-definition rule classifies every form it advertises ------
  #
  # There is one spelling now (`link_defs`, and `prose_count`'s matching
  # clause), so the old test -- "do the awk and the grep agree?" -- no longer
  # has two things to compare. What replaced it is the property that test was
  # a proxy for: every form this file claims to handle must be COLLECTED for
  # the body and must NOT count as prose, and everything else must do the
  # opposite.
  #
  # **The tab form is here because the old corpus had no tab and the two
  # spellings disagreed on exactly it**: busybox and BSD `grep` read `[ \t]`
  # as {space, backslash, t} and every awk reads it as a tab, so a
  # tab-indented definition was classified one way and collected the other.
  # A corpus that cannot express the divergence cannot find it.
  local line defs_hit prose_hit n_forms=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    n_forms=$((n_forms + 1))
    printf '%s\n' "$line" > "$tmp/one.md"
    defs_hit="$(link_defs "$tmp/one.md" | awk 'END { print NR + 0 }')"
    prose_hit="$(prose_count "$tmp/one.md")"
    if [ "$defs_hit" -eq 1 ] && [ "$prose_hit" -eq 0 ]; then
      ok "collected as a link definition, not prose: $(printf '%s' "$line" | cat -A | head -c 46)"
    else
      bad "collected as a link definition, not prose: $line" \
        "link_defs=$defs_hit prose_count=$prose_hit"
    fi
  done <<EOF
[#45]: https://x/45
[#45]: <https://x/45>
  [#45]: https://x/45
$(printf '\t')[#45]: https://x/45
[#45]:https://x/45
[spec]: ./docs/SPEC.md
[Unreleased]: https://x/compare/v0.0.7...main
EOF
  # Seven forms is the claim this file makes; assert the loop saw them all,
  # or a heredoc that lost a line would shrink the corpus silently.
  if [ "$n_forms" -eq 7 ]; then
    ok "the link-definition corpus is all seven advertised forms"
  else
    bad "the link-definition corpus is all seven advertised forms" \
      "the loop saw $n_forms"
  fi

  # The other direction, or a rule calling EVERYTHING a definition would pass
  # every case above.
  for line in '- a real entry ([#45])' 'Plain prose.' '  indented prose'; do
    printf '%s\n' "$line" > "$tmp/one.md"
    defs_hit="$(link_defs "$tmp/one.md" | awk 'END { print NR + 0 }')"
    prose_hit="$(prose_count "$tmp/one.md")"
    if [ "$defs_hit" -eq 0 ] && [ "$prose_hit" -eq 1 ]; then
      ok "counted as prose, not collected: \"$line\""
    else
      bad "counted as prose, not collected: \"$line\"" \
        "link_defs=$defs_hit prose_count=$prose_hit"
    fi
  done

  # **A definition shown as an EXAMPLE inside a fence is not a definition.**
  # The extractor honoured fences and the `grep` append did not, so one got
  # collected and emitted into the body as real.
  # shellcheck disable=SC2016  # a literal fence, not a command substitution
  printf '```\n[#45]: https://x/45\n```\n' > "$tmp/one.md"
  defs_hit="$(link_defs "$tmp/one.md" | awk 'END { print NR + 0 }')"
  if [ "$defs_hit" -eq 0 ]; then
    ok "a link definition inside a fence is not collected"
  else
    bad "a link definition inside a fence is not collected" "collected $defs_hit"
  fi

  # --- a changelog that ends mid-fence or mid-comment is refused ----------
  #
  # Each of these leaves every later `## ` invisible, so the section runs to
  # EOF and takes earlier releases with it. Measured before the check: a body
  # carrying the previous release's entries, at rc=0.
  for kind in fence comment; do
    case "$kind" in
      fence)   printf '# C\n\n## [0.0.8]\n\n- a real entry\n\n```\n' > "$tmp/bad.md" ;;
      comment) printf '# C\n\n## [0.0.8]\n\n- a real entry\n\n<!-- oops\n' > "$tmp/bad.md" ;;
    esac
    printf '%s\n' "$defs" >> "$tmp/bad.md"
    rc=0; log="$(compose 0.0.8 "$tmp/bad.md" "$tmp/bad-out.md" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$log" | grep -q "unterminated"; then
      ok "a changelog ending inside a $kind is refused" refusal
    else
      bad "a changelog ending inside a $kind is refused" "rc=$rc log=$log"
    fi
  done

  # --- the body-size limit, at its boundary and in characters ------------
  #
  # `size_case <label> <accept|reject> <filler> <want-chars> [expect|min-bytes]`
  # writes a `## [0.0.8]` section holding the file <filler> and runs
  # `compose` over it. <want-chars> is the body's length worked out from how
  # the filler is built, not counted, so an accept also asserts that
  # `compose` counted exactly that: a count that is off by one, or counts
  # bytes, fails here. On an accept the fifth argument is a byte count the
  # body must exceed, which is what lets a case tell characters from bytes.
  #
  # The body is the section -- a blank line, the filler, a blank line -- then
  # the separating blank and the one definition (20 bytes): the filler plus
  # 23 characters.
  size_case() {
    local label="$1" want="$2" filler="$3" chars="$4" extra="${5:-}"
    local cl="$tmp/size.md" out="$tmp/size-out.md" rc=0 log bytes
    {
      printf '# Changelog\n\n## [0.0.8]\n\n'
      cat "$filler"
      printf '\n## [0.0.7]\n\n- the released thing\n\n[#45]: https://x/45\n'
    } > "$cl"
    rm -f "$out"
    log="$(compose 0.0.8 "$cl" "$out" 2>&1)" || rc=$?
    case "$want" in
      accept)
        if [ "$rc" -ne 0 ]; then
          bad "$label" "refused (rc=$rc): $log"
        elif ! printf '%s' "$log" | grep -qF "notes: $chars characters"; then
          bad "$label" "accepted, but did not count $chars characters: $log"
        else
          bytes="$(wc -c < "$out")"
          if [ -n "$extra" ] && [ "$((bytes))" -le "$extra" ]; then
            bad "$label" "the body is only $((bytes)) bytes, so the case \
cannot tell characters from bytes"
          else
            ok "$label"
          fi
        fi ;;
      reject)
        if [ "$rc" -eq 0 ]; then
          bad "$label" "accepted a body of $(wc -c < "$out") bytes"
        elif [ -n "$extra" ] && ! printf '%s' "$log" | grep -qF "$extra"; then
          bad "$label" "refused, but said \"$(printf '%s' "$log" | grep -v '^notes' | head -1)\" \
rather than naming: $extra"
        else
          ok "$label" refusal
        fi ;;
    esac
  }
  # `x` in lines of at most 100 bytes, <n> bytes in all; the last line may
  # be empty.
  size_filler() { # size_filler <n>
    awk -v n="$1" 'BEGIN {
      while (n > 0) {
        k = (n > 100) ? 100 : n
        s = ""
        for (i = 1; i < k; i++) s = s "x"
        print s
        n -= k
      }
    }'
  }
  size_filler $((BODY_LIMIT - 23)) > "$tmp/filler-at"
  size_filler $((BODY_LIMIT - 22)) > "$tmp/filler-over"
  # 2,000 lines of 50 `é` (two bytes each) and a newline: 102,000 characters
  # in 202,000 bytes, over the limit in bytes and under it in characters.
  awk -v u="$(printf '\303\251')" 'BEGIN {
    s = ""
    for (i = 1; i <= 50; i++) s = s u
    for (j = 1; j <= 2000; j++) print s
  }' > "$tmp/filler-multibyte"

  size_case "a body of exactly the limit in characters is accepted" accept \
    "$tmp/filler-at" "$BODY_LIMIT"
  size_case "a body one character over the limit is refused" reject \
    "$tmp/filler-over" "$((BODY_LIMIT + 1))" \
    "The release body is $((BODY_LIMIT + 1)) characters"
  size_case "the limit counts characters: a body over it in bytes only is accepted" \
    accept "$tmp/filler-multibyte" $((2000 * 51 + 23)) "$BODY_LIMIT"

  # --- the 3-line cap on [Unreleased] entries -----------------------------
  #
  # `cap_case <label> <accept|reject> <changelog body> [names] [flagged]`.
  # A refusal must name the entry by its first line, with its count, and
  # flag exactly <flagged> entries (default 1): a rule that flagged the
  # neighbours as well, or split one entry into two, is not the rule.
  cap_case() {
    local label="$1" want="$2" body="$3" names="${4:-}" nflag="${5:-1}"
    local got rc=0 n
    printf '%s\n%s\n' "$body" "$defs" > "$tmp/cap.md"
    got="$(entry_cap "$tmp/cap.md")" || rc=$?
    n="$(printf '%s' "$got" | awk 'END { print NR + 0 }')"
    case "$want" in
      accept)
        if [ "$rc" -eq 0 ] && [ -z "$got" ]; then
          ok "$label"
        else
          bad "$label" "rc=$rc, flagged: $got"
        fi ;;
      reject)
        if [ "$rc" -ne 0 ]; then
          bad "$label" "rc=$rc: found no [Unreleased] section"
        elif [ -z "$got" ]; then
          bad "$label" "accepted it"
        elif ! printf '%s\n' "$got" | grep -qF "$names"; then
          bad "$label" "flagged, but not as \"$names\": $got"
        elif [ "$n" -ne "$nflag" ]; then
          bad "$label" "flagged $n entries, not $nflag: $got"
        else
          ok "$label" refusal
        fi ;;
    esac
  }

  cap_case "a four-line entry is refused, by its first line" reject \
'# Changelog

## [Unreleased]

### Fixed

- a short neighbour ([#45])

- FLAG-ME the long one
  two
  three
  four

- another short neighbour

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    '4 lines: - FLAG-ME the long one'

  # A paragraph under the section is capped as an entry, or prose written
  # without a bullet would be exempt.
  cap_case "a four-line paragraph under [Unreleased] is refused" reject \
'# Changelog

## [Unreleased]

- a short entry

FLAG-ME a paragraph
two
three
four

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    '4 lines: FLAG-ME a paragraph'

  cap_case "sub-bullets count toward their entry" reject \
'# Changelog

## [Unreleased]

- FLAG-ME a bullet
  over two lines
  - with a sub-bullet
  - and another

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    '4 lines: - FLAG-ME a bullet'

  # A blank line inside an item does not end it: the indented paragraph
  # after it is the same entry.
  cap_case "an entry's later paragraph counts toward it" reject \
'# Changelog

## [Unreleased]

- FLAG-ME two lines
  and a second

  then a paragraph
  of two more

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    '4 lines: - FLAG-ME two lines'

  # A `## ` inside a fence is not the end of the section, so the fence's
  # lines stay in the entry around them.
  cap_case "a fenced \`## \` neither ends the section nor the entry" reject \
'# Changelog

## [Unreleased]

- FLAG-ME a fence

  ```text
## [0.0.7] — not a heading
  ```

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing' \
    '4 lines: - FLAG-ME a fence'

  # The last section in the file ends at EOF, not at a heading.
  cap_case "a long entry at the end of the file is refused" reject \
'# Changelog

## [Unreleased]

- a short entry

- FLAG-ME the last one
lazy two
lazy three
lazy four' \
    '4 lines: - FLAG-ME the last one'

  cap_case "three lines with blank lines around them are accepted" accept \
'# Changelog

## [Unreleased]


- one
  two
  three


- one
  two
  three

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # Headings and the definitions at the foot of the file are structure: a
  # `### ` directly under a three-line entry, and four definitions in a run
  # after the last one, belong to no entry.
  cap_case "headings and link definitions are not counted" accept \
'# Changelog

## [Unreleased]

### Added
- one
  two
  three
### Fixed
- one
  two
  three

[#1]: https://x/1
[#2]: https://x/2
[#3]: https://x/3
[#4]: https://x/4'

  cap_case "a long entry in a released section is not counted" accept \
'# Changelog

## [Unreleased]

- a short entry

## [0.0.7] — 2026-09-01 (Carabiner)

- a released entry
  that ran
  to five
  lines
  long'

  cap_case "an empty [Unreleased] is accepted" accept \
'# Changelog

## [Unreleased]

## [0.0.7] — 2026-09-01 (Carabiner)

- the released thing'

  # No heading is not a clean section: the cap would have checked nothing.
  printf '# Changelog\n\n## [0.0.7]\n\n- one\n  two\n  three\n  four\n' > "$tmp/cap.md"
  rc=0; entry_cap "$tmp/cap.md" >/dev/null || rc=$?
  if [ "$rc" -eq 2 ]; then
    ok "a changelog with no [Unreleased] heading is reported, not passed" refusal
  else
    bad "a changelog with no [Unreleased] heading is reported, not passed" \
      "rc=$rc"
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
      # **`rc == 0` is not enough, and these three proved it**: under the
      # mutation that deleted the extraction they all stayed green while
      # composing a bare-definition body from the project's real changelog.
      # So the body is compared against the same
      # extraction + blank + definitions the fixtures use.
      awk -v vv="## [$v]" "$AWK_SCAN"'
        !skip && index($0, vv) == 1 { on = 1; next }
        !skip && on && /^## /       { exit }
        on                          { print }
      ' "$repo_cl" > "$tmp/real-want.md"
      printf '\n' >> "$tmp/real-want.md"
      link_defs "$repo_cl" >> "$tmp/real-want.md"
      if ! compose "$v" "$repo_cl" "$tmp/real.md" >/dev/null 2>&1; then
        bad "CHANGELOG.md's own [$v] section composes" "it did not"
      elif ! cmp -s "$tmp/real.md" "$tmp/real-want.md"; then
        bad "CHANGELOG.md's own [$v] section composes" \
          "body is not extraction + blank + definitions"
      else
        ok "CHANGELOG.md's own [$v] section composes"
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
      ok "a version CHANGELOG.md does not declare is refused" refusal
    fi
    # The body `[Unreleased]` would publish as, sized now so that the limit
    # fails a pull request rather than a tag's publish job. Straight after a
    # release cut the section is empty, and there is no body to size.
    local ulog urc=0
    ulog="$(compose Unreleased "$repo_cl" "$tmp/unreleased.md" 2>&1)" || urc=$?
    if [ "$urc" -eq 0 ]; then
      ok "CHANGELOG.md's [Unreleased] composes within $BODY_LIMIT characters"
    elif printf '%s' "$ulog" | grep -q 'heading with nothing under it'; then
      ok "CHANGELOG.md's [Unreleased] is empty, so there is no body to size"
    else
      bad "CHANGELOG.md's [Unreleased] composes within $BODY_LIMIT characters" \
        "$(printf '%s' "$ulog" | grep -v '^notes' | head -1)"
    fi
    # The cap, on the one section still being written: each entry over it
    # is its own failure, named by its first line.
    local over flagged
    if over="$(entry_cap "$repo_cl")"; then
      if [ -z "$over" ]; then
        ok "every [Unreleased] entry in CHANGELOG.md is at most $ENTRY_CAP lines"
      else
        while IFS= read -r flagged; do
          bad "an [Unreleased] entry in CHANGELOG.md is at most $ENTRY_CAP lines" \
            "$flagged"
        done <<EOF
$over
EOF
      fi
    else
      bad "CHANGELOG.md has a \"## [Unreleased]\" heading" \
        "entry_cap found none, so the cap checked nothing"
    fi
  else
    bad "CHANGELOG.md is readable from the script's own directory" \
      "not found at $repo_cl"
  fi

  # **The totals are printed, not asserted anywhere.** `mcp-smoke.sh` records
  # that its own "all 38 checks" drifted five times with nothing going red,
  # which is why it prints its total instead; the same applies here, and more
  # sharply, because one of these cases is derived from each of
  # `CHANGELOG.md`'s released-version headings, and every release cut adds
  # one. Any comment naming a fixed number here is stale-by-construction at
  # the next release.
  echo
  if [ "$fails" -ne 0 ]; then
    echo "release-notes SELF-TEST FAILED ($fails of $((passes + fails)))"
    return 1
  fi
  printf 'release-notes SELF-TEST OK (%s cases, %s of them refusals, %s\n' \
    "$passes" "$refusals" "$seen"
  echo "derived from CHANGELOG.md's released versions) — an empty section is"
  echo "refused before anything is appended to it, and a real one composes."
  echo "A body over $BODY_LIMIT characters, and an [Unreleased] entry over"
  echo "$ENTRY_CAP lines, are refused."
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
