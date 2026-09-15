#!/usr/bin/env python3
# Assert the spec's ENUMERATIONS against the tree.
#
# `orphan-req-check.py` already answers "does this cited REQ id exist?" — 124
# of 255 cited, zero dangling. What nothing checked is the *members* of an
# enumeration: a numbered list in the spec whose elements are supposed to
# correspond one-for-one with something in `crates/`. An audit found four
# such drifts in under a minute of grepping, which is the tell that the
# answer wants to be mechanical rather than periodic.
#
# ==========================================================================
# WHAT THIS COVERS, AND WHAT IT DELIBERATELY DOES NOT
# ==========================================================================
#
# This is NOT a general spec parser, and the next reader should not mistake
# it for one. A general parser over a 5,600-line design document is a trap:
# it is confidently wrong on the sections whose formatting is prose, and its
# confidence is the damage. Two enumerations are covered because their
# format is regular enough to parse without guessing and the payoff is high.
#
#   COVERED
#
#   1. §9.4's audit-kind table (21 kinds). Column 1 of a pipe table is one
#      backticked snake_case identifier and nothing else, for every row, with
#      no gaps. Parsing it is exact.
#
#   2. §12.6's v0.1.0 ship-list of MCP tools (16). One bullet, one line,
#      comma-separated backticked ids. It needs one filter to be exact —
#      see PARENTHETICALS below — and after that filter it is.
#
#   NOT COVERED, each for a stated reason
#
#   * §7.5's frame set. Four separate constructs in three formats: a fenced
#     code block (which is where `Attach` lives, and it is absent from the
#     client bullet list), two bullet lists, and — the killer — indented
#     continuation paragraphs *inside* the client list, so the bullets are
#     non-contiguous and a "read until blank line" parser reports 2 client
#     frames where there are 7. `Detach` carries no `{ }` so a brace-anchored
#     regex misses it, and `ProtocolError`/`AwaitingSecret`/
#     `SecretRequestClosed` are named in surrounding prose, so a
#     backtick-scan over-collects. On the code side `ServerFrame` carries an
#     `Unknown` decoder sentinel that is not a wire frame and has no spec
#     row. Every one of those is a special case, and a check that is all
#     special cases is a transcription with extra steps.
#
#   * §4.2's `Configurable` column. Column 1 (the setting name) is as clean
#     as §9.4's, but column 3 is free prose with no closed vocabulary: one
#     row is two sentences with bold, a GH issue reference, backticked keys
#     and a § cross-ref; another expresses the negative case ("**fixed in
#     v0.1.0** (not configurable; …)") in prose. Two rows contain escaped
#     pipes, so even the field split is wrong. And the useful half is
#     already covered: `crates/holdfast-core/tests/config_surface.rs`
#     enumerates every config key FROM THE STRUCTS and classifies each
#     effective or inert, which is a stronger statement than this document
#     makes. Adding a second, weaker answer beside it would be the drift.
#
#   * §10.2's example config — GH #53. That check must EXTRACT the TOML from
#     the section and LOAD it through `Config`, because #53's whole point is
#     that a count is what went stale and a second count would go stale the
#     same way. Loading it needs the Rust type, so it is a Rust-side check
#     and cannot live here. This script is the document-side half —
#     enumerations comparable as sets of NAMES — and #53 is the half that
#     needs the loader. Named here so the next reader does not add a
#     §10.2 word-count to this file and call the issue closed.
#
#   * README's CI-job table against `.github/workflows/ci.yml`. Shell-shaped
#     and needs no spec, so it belongs in `scripts/ci-hygiene.sh`, which
#     runs in CI on every pull request — where this script, needing a
#     document CI does not check out, cannot.
#
# ==========================================================================
# THE JUDGEMENTS, STATED RATHER THAN IMPLIED
# ==========================================================================
#
# 1. A LEDGER, NOT A WAIVER — and the difference is that it fails both ways.
#    §9.4 lists 21 kinds; the tree writes fewer, because kinds belonging to
#    unbuilt v0.1.0 features (preflight, confirmations, the web-UI bridge,
#    file transfer, recording) have no call site yet and are SUPPOSED not
#    to. So "every kind has a writer" is not the invariant and asserting it
#    would produce a check that is red for correct reasons — which is a
#    check that gets deleted. The invariant is set EQUALITY against a
#    ledger, which is red in three useful cases:
#      - a kind gains a writer and the ledger is not updated (drift);
#      - a kind LOSES its writer (an event silently stops being audited —
#        a security regression, and the case a "has a writer" check in
#        either direction would miss);
#      - a new kind is added to the spec and implemented by nobody.
#    That is the same shape `prefix_index.rs`'s blind-rule ledger uses and
#    the opposite of the hand-kept count GH #53 watched go stale.
#
#    WHAT MAY GO IN `KNOWN_UNWRITTEN`, AND WHAT MAY NOT. Only a kind whose
#    FEATURE is unbuilt. A kind belonging to a feature that SHIPS and is
#    simply not writing its entry is a defect, not a deferral, and waiving
#    it would be the P5 failure this file exists to oppose — a guard
#    holding a stale sentence in place. Such a kind stays a finding and
#    this check stays red until someone writes the call site.
#
#    THE SECOND LEDGER IS NOT A SECOND WAIVER. `KNOWN_UNAUDITED` lists the
#    shipped-but-unaudited kinds and every one of them is STILL A FINDING;
#    nothing is suppressed. It exists because a finding alone does not pin
#    the spec row it is about. With both ledgers plus the set of kinds the
#    tree actually writes, EVERY row of §9.4's table is claimed by name, so
#    deleting any row from the document fires a membership check. Without
#    it the only anti-vacuity here was a numeric floor, and a floor is weak:
#    two realistic editorial reformats took the table from 21 rows to 19
#    with byte-identical findings and the same exit code.
#
# 2. A WRITER IS A `.record(` FIRST ARGUMENT. Not a substring of the tree.
#    The two are not close: `send_input`'s only surviving production
#    occurrence is an MCP tool-dispatch arm on the tool's NAME, so a
#    substring rule cleared the kind that records the bytes an agent types
#    into a shell, on a tree with no `.record("send_input"` in it. And a
#    kind can LOSE its only writer invisibly when its literal is also a
#    JSON field name, which `truncated_at_tail` is five times over. The
#    ledger section above claims both cases; only this definition of
#    "written" delivers them. See the note at the forward check.
#
# 3. PARENTHETICALS ARE NOT MEMBERS. §12.6 annotates entries inline —
#    `read_output` (with `ansi`/`text_encoding`/`redact`/`max_bytes`) — so a
#    naive backtick scan returns 20 spans for a list of 16. Parenthetical
#    groups are stripped BEFORE ids are extracted, and the count is then
#    cross-checked against the numeral the sentence writes out ("All 16 MCP
#    tools"). Those two disagreeing is itself a finding: it is precisely
#    how §10.2 drifted in GH #53 — a list and a count of it, maintained by
#    hand, in the same sentence.
#
# ==========================================================================
# WHAT CAN STILL SLIP PAST — the false-negative surface, stated on purpose
# ==========================================================================
#
# * §9.4: "written" means the kind is the first argument of a `.record(`
#   call in production Rust. It does NOT mean the call site is reachable,
#   correct, on the right path, or that its `Extra fields` match the spec's
#   second column. A writer behind an `if false` counts. The second column
#   is not read at all.
# * §9.4: a writer whose kind is NOT a string literal — a `const`, a
#   variable, a value threaded in from a caller — reads as no writer at all.
#   No such call site exists today (`AuditLog::record` is the one write
#   primitive and its five wrappers all pass literals), and the failure is
#   in the red direction, which is the direction a guard may be wrong in.
# * §9.4: test code is stripped by a HEURISTIC — a column-zero
#   `#[cfg(test)]` or `#[cfg(all(test, ...))]` through the end of the item
#   it gates, found by counting brackets over a string- and comment-masked
#   copy of the file. A test gate on an INDENTED item would still leave test
#   literals in the production set and mark an unbuilt kind as written; this
#   workspace has none (measured: 79 column-zero gates, no indented one).
#   The SHAPES it must handle were measured rather than assumed, because the
#   previous terminator — "the next line that is exactly `}`" — assumed one:
#   67 of the 79 gate a braced `mod tests`, 10 a column-zero `struct`/`enum`/
#   `impl` whose brace happens to land in the same place, and 2 a BRACELESS
#   item, where the old rule ran on for 99 lines of live production Rust.
# * §9.4: the masker is a Rust lexer only to the depth bracket counting
#   needs — line and nested block comments, ordinary/raw/byte strings, char
#   literals distinguished from lifetimes. It does not know about macros
#   that emit unbalanced token trees, and Rust does not permit those, which
#   is the reason counting is exact here rather than lucky. (Naive counting
#   is NOT: `config.rs:2264` is `&["{host"],`, one unbalanced brace inside a
#   string, and a counter that cannot see it walks off the end of the file.)
# * §9.4 reverse direction (a kind written but absent from the table) GATES.
#   It did not, on the stated ground that `.record(` has other meanings in
#   this tree — but the one unrelated `record` (`mcp/mod.rs:167`,
#   `fn record(&mut self, site: ArmSite)`) takes no string literal, so this
#   regex has never matched it, and on this tree it yields ten names that
#   are all `AuditLog` writes. The `.record("before" | "after", …)` calls
#   that argument named are six sites in `daemon/server.rs` and
#   `daemon/paths.rs`, all inside test modules the blanking correctly
#   strips: this script emits ZERO such warnings and always has.
# * §12.6: this asserts the shipped tools are a SUBSET of the ship-list and
#   that the list is self-consistent. It cannot tell you the ship-list is
#   the right list, nor that a tool named there will behave as §5 says.
# * Neither check reads any other section. A drift in §5, §8, §11 or §20 is
#   invisible here, and §20 is `orphan-req-check.py`'s job, not this one's.
# * Both checks compare NAMES. A member renamed in the spec and the tree in
#   the same commit passes, correctly; a member whose *meaning* changed
#   under an unchanged name passes, incorrectly.
#
# ==========================================================================
# WHERE THIS RUNS
# ==========================================================================
#
# Not in CI's real invocation, for the same reason `orphan-req-check.py` is
# not: `docs/` is git-ignored and lives in a separate repository, so the
# spec is absent from whatever CI checks out and every run would find no
# document. `--self-test` runs against fixtures, needs no spec, and IS
# wired into the `hygiene` job — because a guard whose own guard never runs
# is a guard on trust.
#
# THE REAL ARM RUNS FROM `dev/workflows/verify.md`, AND THAT IS NOT A
# CONSOLATION PRIZE — IT IS THE ONLY OPTION AND THE REPOSITORY HAS THE
# RECEIPT. Gating `hygiene` on the real check is not a decision anyone gets
# to make: CI's checkout has no `docs/`, so the real run exits 3 there on
# every push forever. What the question really asks is where else it runs,
# and the answer this project has already lived through is `af0e06a` —
# "actionlint was named in the gate for months and never run". `verify.md`
# listed actionlint under *"CI's own gate, which must pass"*, CI did not run
# it, and the tool was not installed on the machine of anyone who tried to
# follow the file. The fix was to EXECUTE it, not to delete it, and it is a
# required context today. Nothing in this repository has ever been deleted
# for being unrun: three of nine scripts are wired to no automation and all
# three survive — but each of the other two has `--install-hook`, and
# `preflight.sh` is a quoted command in CONTRIBUTING's getting-started
# block. Every orphan has SOMETHING that puts it in front of a human. This
# script's document arm had nothing, and `verify.md` — which `CLAUDE.md`
# calls "the full local gate" — is where that goes.
#
# It is listed there under "also worth running" rather than in the numbered
# list, because that list is titled "CI's own gate, which must pass" and
# this is a check CI cannot run. Putting it in the numbered list would make
# that heading false, which is the exact defect `af0e06a` was fixing.
#
# WHY IT SHIPS RED, AND WHY THAT IS NOT DECORATION. Four kinds are findings
# and GH #173 tracks all four; `KNOWN_UNAUDITED` names them so the red says
# what to do about it and so their spec rows cannot vanish unnoticed. The
# repo's stated theory of check-death is FALSE reds — "a check that is red
# for correct reasons is a check that gets deleted" is about a check red on
# a CORRECT tree. This one is red on an INCORRECT tree, which is a check
# doing its job. There is no expiry date on those rows on purpose:
# `mutants.yml` retired its `CALIBRATION-EXEMPT-UNTIL` marker early with the
# reason "a dated fuse is a dated surprise", and a fuse here would do
# nothing on any day but one.
#
# Absence of the spec exits 3 with a message saying nothing was checked. It
# never exits 0 on a tree it could not read: a silent pass is how a check
# becomes decoration, and the failure mode this whole script exists to
# oppose is a stale sentence nobody re-measured.
#
# IT RUNS FROM A GIT WORKTREE. `docs/` is an ABSOLUTE symlink, and while the
# link itself is not materialised in a worktree its target is reachable from
# anywhere. `find_spec()` therefore falls back to the main checkout, located
# via `git rev-parse --git-common-dir`, before giving up. The belief that
# spec claims cannot be checked from a worktree cost this project months
# (see `dev/workflows/review.md`), and a spec-reading script that skipped in
# exactly the place reviewers work would have re-taught it.
#
# Usage:
#   scripts/spec-enum-check.py [--repo-root DIR] [--spec FILE] [--json]
#   scripts/spec-enum-check.py --self-test
#
# The spec is located in this order: --spec, $HOLDFAST_SPEC,
# <root>/docs/superpowers/specs/*-holdfast-design.md, then the same path
# under the main checkout when <root> is a worktree.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_CANNOT_RUN = 3

# --------------------------------------------------------------------------
# §9.4 — the kinds with no production writer today.
#
# Each row is (kind, why). These belong to v0.1.0 features that are not
# built, so their absence is correct and the ledger records the decision
# rather than hiding it. Adding a writer means deleting the row; deleting a
# writer means the check goes red before the missing audit trail does.
# --------------------------------------------------------------------------
KNOWN_UNWRITTEN = [
    ("preflight_match", "argv-aware dangerous-command preflight is unbuilt (§5.4)"),
    ("confirmation_redeem", "strict_confirmation / `holdfast confirm` is unbuilt"),
    ("confirmation_abandoned", "strict_confirmation / `holdfast confirm` is unbuilt"),
    ("bridge_register", "the `holdfast ui` TCP bridge is unbuilt (§7.6.1)"),
    ("bridge_revoke", "the `holdfast ui` TCP bridge is unbuilt (§7.6.1)"),
    ("file_transfer", "send_file / fetch_file are unbuilt (§5.7)"),
    ("recording_started", "session recording is unbuilt (§5.8.1)"),
]

# --------------------------------------------------------------------------
# §9.4 — the kinds whose FEATURE SHIPS and which are audited by nobody.
#
# THIS IS NOT A WAIVER, and the distinction from `KNOWN_UNWRITTEN` above is
# the whole point: every row here is STILL A FINDING and this check stays
# red while any of them stands. What the row buys is two things a bare
# finding does not.
#
#   1. It names the tracker, so the red says what to do about it.
#   2. It PINS THE SPEC ROW. Between this list, `KNOWN_UNWRITTEN` and the
#      set of kinds the tree actually writes, every row of §9.4's table is
#      accounted for by NAME. Delete any row from the document and one of
#      the three membership checks fires. That is the anti-vacuity this
#      half was missing: the floor below is a coarse format-moved tripwire,
#      and a floor alone let two realistic editorial reformats take the
#      table from 21 rows to 19 with byte-identical output.
#
# NO EXPIRY DATE, deliberately, and the repository has the worked example:
# `mutants.yml` carried a `CALIBRATION-EXEMPT-UNTIL` marker and retired it
# early with the reason "a dated fuse is a dated surprise". A date here
# would do nothing on any day but one, and on that day it would turn a
# check that is already red a different colour. The finding is the pressure.
KNOWN_UNAUDITED = [
    ("daemon_start", "GH #173 — the daemon ships and does not audit its own start"),
    ("daemon_stop", "GH #173 — the daemon ships and does not audit its own stop"),
    ("send_input", "GH #173 — REQ-SEC-011 is conjunctive (warning AND audit-logged); "
                   "REQ-T-003 is a Tier-2 verification over this row"),
    ("panic", "GH #173 — `diag.rs`'s hook writes the diagnostic log, not audit.log"),
]

H3_RE = re.compile(r"^### (\d+\.\d+)\b")
TABLE_SEP_RE = re.compile(r"^\|\s*-+")
KIND_ROW_RE = re.compile(r"^\|\s*`([a-z_][a-z0-9_]*)`\s*\|")
SHIPLIST_RE = re.compile(r"^- All (\d+) MCP tools\b")
BACKTICK_ID_RE = re.compile(r"`([a-z_][a-z0-9_]*)`")
TOOLS_CONST_RE = re.compile(r"const TOOLS:\s*\[&(?:'static )?str;\s*(\d+)\]\s*=\s*\[(.*?)\]", re.S)
RECORD_CALL_RE = re.compile(r"\.record\(\s*\n?\s*\"([a-z_][a-z0-9_]*)\"")


def section_lines(lines, number):
    """The lines of `### <number>`, up to the next heading of any level.

    Bounding matters: §9.4's prose below the table names five of its own
    kinds in backticks, and those are references rather than definitions.
    `orphan-req-check.py` makes the same distinction for §20.
    """
    start = None
    for i, line in enumerate(lines):
        m = H3_RE.match(line)
        if m and m.group(1) == number:
            start = i
            break
    if start is None:
        return None, None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("#"):
            end = i
            break
    return start, end


def parse_audit_kinds(lines):
    """Column 1 of §9.4's pipe table: one backticked id per row."""
    start, end = section_lines(lines, "9.4")
    if start is None:
        return None
    kinds, sep = [], None
    for i in range(start, end):
        line = lines[i]
        if sep is None:
            if TABLE_SEP_RE.match(line.strip()):
                sep = i
            continue
        if not line.startswith("|"):
            break  # the table ended; prose below is references, not rows
        m = KIND_ROW_RE.match(line)
        if m:
            kinds.append(m.group(1))
    return kinds


def parse_shiplist_tools(lines):
    """§12.6's `All N MCP tools` bullet: (numeral, [ids])."""
    start, end = section_lines(lines, "12.6")
    if start is None:
        return None, None
    for i in range(start, end):
        m = SHIPLIST_RE.match(lines[i])
        if not m:
            continue
        # Judgement 2: strip parenthetical annotations first. `read_output`
        # is followed by four backticked argument names that are not tools.
        stripped = re.sub(r"\([^)]*\)", "", lines[i])
        return int(m.group(1)), BACKTICK_ID_RE.findall(stripped)
    return None, None


# Column-zero test gates. Anchored to the two literal cfg forms rather than a
# `\btest\b` search inside the cfg, because that would also match a
# `#[cfg(feature = "test-util")]` the day someone adds one and silently blank
# a production module.
#
# The SHAPE of the gated item is a separate question from the spelling of the
# cfg, and conflating the two is what the previous revision of this file got
# wrong: it terminated the blank at "the next line that is exactly `}`", which
# is right for `mod tests { ... }` and wrong for every braceless item. This
# tree has both — `secret/provider.rs:72` is `#[cfg(test)] use
# std::path::PathBuf;` — and there the old rule ran on to the close of `pub
# enum ResolveError` a hundred lines below, blanking live production Rust in
# between. That direction of error is silent: a kind whose only writer sits in
# the blanked span reads as unwritten, and a kind whose literal survives in
# test code reads as written.
CFG_TEST_RE = re.compile(r"^#\[cfg\((?:test\)|all\(test[,)])")

# A raw string opener (`r"`, `r#"`, `br##"` …) and a char literal, including
# the `'\u{7d}'` form. The char-literal pattern deliberately does NOT match a
# lifetime: `'a` has no closing quote in the next two characters, so `&'a str`
# is left alone while `'}'` is masked — which matters, because an unmasked
# `'}'` moves the depth counter below.
RAW_STR_RE = re.compile(r"b?r(#*)\"")
CHAR_LIT_RE = re.compile(r"'(?:\\u\{[0-9a-fA-F_]+\}|\\.|[^'\\\n])'")


def _mask_line(line, state):
    """Replace string, char-literal and comment content with spaces.

    `state` carries a nested-block-comment depth, an open ordinary string and
    an open raw string's hash count ACROSS lines, because all three can span
    them in this tree. Masking is what makes the bracket counting in
    `_item_end` exact rather than another heuristic: `crates/` is full of
    `"{}"` format strings, `'}'` char literals and doc comments containing
    braces, and every one of them would move a naive counter.
    """
    out = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if state["block"] > 0:
            if line.startswith("/*", i):
                state["block"] += 1
                out.append("  ")
                i += 2
                continue
            if line.startswith("*/", i):
                state["block"] -= 1
                out.append("  ")
                i += 2
                continue
            out.append(" ")
            i += 1
            continue
        if state["raw"] is not None:
            close = '"' + "#" * state["raw"]
            if line.startswith(close, i):
                state["raw"] = None
                out.append(" " * len(close))
                i += len(close)
                continue
            out.append(" ")
            i += 1
            continue
        if state["str"]:
            if ch == "\\":
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                state["str"] = False
                out.append(" ")
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        # Ordinary code.
        if line.startswith("//", i):
            out.append(" " * (n - i))
            break
        if line.startswith("/*", i):
            state["block"] = 1
            out.append("  ")
            i += 2
            continue
        prev_is_ident = i > 0 and (line[i - 1].isalnum() or line[i - 1] == "_")
        m = RAW_STR_RE.match(line, i) if not prev_is_ident else None
        if m:
            state["raw"] = len(m.group(1))
            out.append(" " * (m.end() - i))
            i = m.end()
            continue
        if ch == '"':
            state["str"] = True
            out.append(" ")
            i += 1
            continue
        if ch == "'":
            m = CHAR_LIT_RE.match(line, i)
            if m:
                out.append(" " * (m.end() - i))
                i = m.end()
                continue
            out.append("'")  # a lifetime, not a literal
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _item_end(masked, start):
    """Index of the LAST line of the item introduced at `masked[start]`.

    Two shapes, both exact once strings and comments are masked:

      * a BRACED item (`mod tests { … }`, `impl … { … }`) ends on the line
        where the depth opened by its first `{` returns to zero;
      * a BRACELESS one (`use …;`, `const … = …;`, `mod tests;`) ends at the
        first `;` seen at depth zero before any `{`.

    Depth counts `(`, `[` and `{` alike, and only `{` arms the braced case.
    That is not decoration: `static X: [&str; 2] = [ … ];` carries a `;`
    inside brackets, and terminating there would leave the rest of a test
    fixture in the production set — the false-GREEN direction, which is the
    one this whole script exists to refuse.

    An item that never closes blanks to EOF. That is the safe direction:
    over-blanking loses a writer and turns the check red, under-blanking
    keeps test literals and turns it green.
    """
    depth = 0
    seen_brace = False
    for j in range(start, len(masked)):
        for ch in masked[j]:
            if ch in "([{":
                depth += 1
                if ch == "{":
                    seen_brace = True
            elif ch in ")]}":
                depth -= 1
                if ch == "}" and seen_brace and depth <= 0:
                    return j
            elif ch == ";" and depth == 0 and not seen_brace:
                return j
    return len(masked) - 1


def strip_test_modules(src):
    """Blank out test-gated items anchored at column zero.

    Lines are blanked rather than deleted so any line number we report still
    matches the file.
    """
    lines = src.split("\n")
    state = {"block": 0, "raw": None, "str": False}
    masked = [_mask_line(line, state) for line in lines]

    out = list(lines)
    i = 0
    while i < len(lines):
        if CFG_TEST_RE.match(masked[i]):
            end = _item_end(masked, i)
            for j in range(i, end + 1):
                out[j] = ""
            i = end + 1
            continue
        i += 1
    return "\n".join(out)


def production_rust(root):
    """Every `crates/*/src/**.rs` with test modules blanked out."""
    files = {}
    crates = root / "crates"
    if not crates.is_dir():
        return files
    for path in sorted(crates.glob("*/src/**/*.rs")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files[path] = strip_test_modules(text)
    return files


def parse_shipped_tools(root):
    """`tests/schema.rs::TOOLS` — the tree's own flat pin of the surface."""
    path = root / "crates" / "holdfast-core" / "tests" / "schema.rs"
    if not path.is_file():
        return None, None
    m = TOOLS_CONST_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    if not m:
        return None, None
    return int(m.group(1)), re.findall(r'"([a-z_][a-z0-9_]*)"', m.group(2))


def build_report(spec_path, root):
    lines = spec_path.read_text(encoding="utf-8", errors="replace").split("\n")
    report = {
        "spec": str(spec_path),
        "root": str(root),
        "findings": [],
        # Empty today, and kept as a channel rather than deleted: the
        # reverse §9.4 direction used to live here and now gates, so a
        # self-test case asserts it is NOT reported as a warning. A rule
        # that wants to report without gating has somewhere to go; nothing
        # currently does.
        "warnings": [],
    }

    prod = production_rust(root)
    if not prod:
        return None, "no crates/*/src/**.rs under {} — refusing to report every kind as unwritten".format(root)
    blob = "\n".join(prod.values())

    # ---------------------------------------------------------------- §9.4
    kinds = parse_audit_kinds(lines)
    if kinds is None:
        return None, "§9.4 not found in the spec"
    # Coarse format-moved tripwire only. The REAL anti-vacuity for this half
    # is the by-name accounting below: every row is claimed by the emitted
    # set, by `KNOWN_UNWRITTEN` or by `KNOWN_UNAUDITED`, so deleting any one
    # of them fires a membership finding. A floor alone did not do that job —
    # two realistic editorial reformats took the table from 21 rows to 19
    # with byte-identical findings and the same exit code, and `< 10` never
    # came close. 18 is the sibling guard's ratio (`rules.len() >= 40`
    # against 51, 78%) applied to 21, rounded up, and it is a backstop for
    # the case where the by-name accounting cannot run because the parse
    # collapsed.
    if len(kinds) < 18:
        return None, "§9.4's table parsed to only {} kinds — the format moved".format(len(kinds))
    report["audit_kinds"] = kinds

    # A KIND IS "WRITTEN" WHEN IT IS THE FIRST ARGUMENT OF A `.record(` CALL,
    # and not merely when its string appears somewhere in production Rust.
    #
    # The difference is not academic; it was the defect. `send_input`'s only
    # surviving production occurrence is `mcp/passthrough.rs`'s MCP
    # tool-dispatch arm — `"send_input" => run!(send_input, SendInputArgs)` —
    # which is the tool's NAME, not an audit write. Under the old substring
    # rule the one kind recording the bytes an agent types into a shell read
    # as audited, on a tree where `git grep` finds no `.record("send_input"`
    # at all, while GH #173 lists it in bold among the four kinds nothing
    # writes. The check reported a false green on the exact failure class it
    # exists to catch, and it under-reported its own tracking issue by 25%.
    #
    # The same root has a worse direction that was latent: DELETING an audit
    # write was invisible. `truncated_at_tail` is written once, at
    # `audit.rs:273`, and the same literal appears five more times as a JSON
    # RESPONSE-FIELD name in `mcp/resources.rs` and `mcp/tools.rs` — so
    # removing the only writer left this script's output byte-identical.
    # That is precisely the case the LEDGER section above claims to catch
    # ("a kind LOSES its writer … the case a 'has a writer' check in either
    # direction would miss"), and the forward half was not delivering it.
    #
    # `AuditLog::record` (audit.rs:187) is the single write primitive: the
    # five convenience wrappers beside it all call `self.record("literal",
    # …)`, so this extraction is a complete accounting of the writes rather
    # than a sample of them. A future call site that passes a `const` or a
    # variable instead of a literal reads as unwritten — red, not green,
    # which is the direction a guard is allowed to be wrong in.
    emitted = set()
    for text in prod.values():
        emitted.update(RECORD_CALL_RE.findall(text))
    report["audit_emitted"] = sorted(emitted)

    written = [k for k in kinds if k in emitted]
    unwritten = [k for k in kinds if k not in emitted]
    report["audit_written"] = written
    report["audit_unwritten"] = unwritten

    # Kinds whose literal IS in production Rust but never as a `.record(`
    # first argument. Reported on the finding itself, because "no writer"
    # and "no writer, and here is the non-audit use that looked like one"
    # are very different things to hand a reader.
    literal_only = [k for k in unwritten if '"{}"'.format(k) in blob]
    report["audit_literal_but_not_recorded"] = literal_only

    deferred = sorted(k for k, _ in KNOWN_UNWRITTEN)
    defects = sorted(k for k, _ in KNOWN_UNAUDITED)
    why = dict(KNOWN_UNWRITTEN)
    why.update(dict(KNOWN_UNAUDITED))
    report["audit_deferred"] = deferred
    report["audit_shipped_unaudited"] = defects

    both = sorted(set(deferred) & set(defects))
    for kind in both:
        report["findings"].append(
            "§9.4 `{}` is in BOTH ledgers. A kind is either waiting on an unbuilt "
            "feature or is a shipped feature that does not audit; it cannot be "
            "both, and the two rows would hide each other.".format(kind)
        )

    for kind in deferred + defects:
        if kind not in kinds:
            report["findings"].append(
                "§9.4 ledger names `{}`, which is not a row in the table any more: "
                "drop the row rather than leaving it to match nothing".format(kind)
            )

    unaccounted = sorted(set(unwritten) - set(deferred) - set(defects))
    report["audit_unaccounted"] = unaccounted
    for kind in unaccounted:
        extra = ""
        if kind in literal_only:
            extra = (" The literal `\"{}\"` DOES appear in production Rust, but never "
                     "as the first argument of `.record(` — so whatever that "
                     "occurrence is, it is not an audit write.".format(kind))
        report["findings"].append(
            "§9.4 `{}` has NO production writer and is in neither ledger. Either an "
            "event stopped being audited, or a kind was specified and never "
            "implemented. Add a writer, or add it to KNOWN_UNWRITTEN with the "
            "feature it waits on, or to KNOWN_UNAUDITED with its issue.{}".format(kind, extra)
        )

    # `& set(kinds)` on both: a ledger row the TABLE dropped is already
    # reported above, and without the intersection it is not in `unwritten`
    # either — so it would be reported a second time as "now has a writer",
    # which is false and sends the reader to the wrong file. The previous
    # revision had this and the self-test did not see it, because the case
    # asserted the first finding was present and nothing about the rest.
    for kind in sorted((set(deferred) & set(kinds)) - set(unwritten)):
        report["findings"].append(
            "§9.4 `{}` now HAS a production writer but is still in the unbuilt-feature "
            "ledger ({}). Delete its row.".format(kind, why[kind])
        )
    for kind in sorted((set(defects) & set(kinds)) - set(unwritten)):
        report["findings"].append(
            "§9.4 `{}` now HAS a production writer but is still in the "
            "shipped-but-unaudited ledger ({}). Delete its row — and that issue "
            "has one fewer item.".format(kind, why[kind])
        )
    for kind in sorted(set(defects) & set(unwritten)):
        report["findings"].append(
            "§9.4 `{}` is specified, its feature SHIPS, and no production code "
            "writes it: {}. Ledgered so the row cannot vanish from the "
            "document unnoticed — NOT waived. This check is red until the call "
            "site exists.".format(kind, why[kind])
        )

    # Reverse direction: a kind the code writes that §9.4 never named. This
    # GATES, and the header used to say it did not.
    #
    # The stated reason it did not — that `.record(` has other meanings in
    # this tree — does not survive measurement. The one unrelated `record`
    # (`mcp/mod.rs:167`, `fn record(&mut self, site: ArmSite)`) takes no
    # string literal, so `RECORD_CALL_RE` has never matched it; on this tree
    # the regex yields ten names and all ten are `AuditLog` writes. And the
    # argument is now self-defeating: the FORWARD direction gates on exactly
    # this extraction, so calling it too heuristic to gate in reverse would
    # be holding one direction to a standard the other is already trusted
    # with. A `.record("x", …)` whose `x` §9.4 does not list is an audit
    # record with no specified shape, which is the drift, not a curiosity.
    stray = sorted(k for k in emitted if k not in kinds)
    report["audit_emitted_not_in_spec"] = stray
    for kind in stray:
        report["findings"].append(
            "`.record(\"{}\", …)` is called in production Rust and `{}` is not a "
            "row in §9.4's table. Either the table lost a row or the tree "
            "writes an audit record the document does not specify.".format(kind, kind)
        )

    # --------------------------------------------------------------- §12.6
    numeral, tools = parse_shiplist_tools(lines)
    if numeral is None:
        return None, "§12.6's `All N MCP tools` bullet not found"
    report["shiplist_numeral"] = numeral
    report["shiplist_tools"] = tools
    if numeral != len(tools):
        report["findings"].append(
            "§12.6 says `All {} MCP tools` and then lists {}: {}. A list and a "
            "count of it maintained by hand in one sentence is exactly how "
            "§10.2 drifted (GH #53).".format(numeral, len(tools), ", ".join(tools))
        )

    declared, shipped = parse_shipped_tools(root)
    if shipped is None:
        return None, "could not read tests/schema.rs::TOOLS — the pin moved"
    if len(shipped) < 5:
        # Anti-vacuity, and the self-test found it: a `TOOLS` that parsed to
        # nothing makes the subset rule below trivially satisfied, so the
        # §12.6 half would report OK having compared no tools at all.
        return None, (
            "tests/schema.rs::TOOLS parsed to only {} name(s) — the pin moved, and "
            "the ship-list subset rule would be vacuously satisfied".format(len(shipped))
        )
    report["shipped_tools"] = shipped
    if declared != len(shipped):
        report["findings"].append(
            "tests/schema.rs::TOOLS is declared `[&str; {}]` but holds {} names".format(
                declared, len(shipped)
            )
        )
    for tool in sorted(set(shipped) - set(tools)):
        report["findings"].append(
            "`{}` is an MCP tool the tree ships (tests/schema.rs::TOOLS) and "
            "§12.6's v0.1.0 ship-list does not name it.".format(tool)
        )
    report["shiplist_not_shipped"] = sorted(set(tools) - set(shipped))

    return report, None


def render(report):
    out = []
    out.append("Holdfast spec-enumeration check")
    out.append("=" * 66)
    out.append("spec:  {}".format(report["spec"]))
    out.append("tree:  {}".format(report["root"]))
    out.append("")
    out.append("  §9.4 audit kinds in the table ..... {}".format(len(report["audit_kinds"])))
    out.append("      with a production writer ...... {}".format(len(report["audit_written"])))
    out.append("      unwritten, feature unbuilt .... {}".format(
        len(set(report["audit_unwritten"]) & set(report["audit_deferred"]))))
    out.append("      unwritten, feature SHIPS ...... {}".format(
        len(set(report["audit_unwritten"]) & set(report["audit_shipped_unaudited"]))))
    out.append("      unwritten, in neither ledger .. {}".format(len(report["audit_unaccounted"])))
    out.append("  §12.6 ship-list tools ............. {}  (numeral says {})".format(
        len(report["shiplist_tools"]), report["shiplist_numeral"]))
    out.append("      shipped today ................. {}".format(len(report["shipped_tools"])))
    out.append("      planned, not built ............ {}".format(len(report["shiplist_not_shipped"])))
    out.append("")
    if report["shiplist_not_shipped"]:
        out.append("planned for v0.1.0, not built today (not a finding)")
        out.append("-" * 66)
        for t in report["shiplist_not_shipped"]:
            out.append("  {}".format(t))
        out.append("")
    # Only the unbuilt-feature ledger prints here. The previous revision
    # iterated ALL of `audit_unwritten` under this heading, so the three
    # kinds that were findings printed once with a BLANK reason column and
    # again six lines below under FINDINGS, while the summary counted all
    # ten as "ledgered" when seven were. A report that contradicts itself
    # teaches the reader to skim the part that was right.
    deferred_here = [k for k in report["audit_unwritten"] if k in set(report["audit_deferred"])]
    if deferred_here:
        out.append("§9.4 kinds whose feature is unbuilt (ledgered; not a finding)")
        out.append("-" * 66)
        why = dict(KNOWN_UNWRITTEN)
        for k in deferred_here:
            out.append("  {:<24} {}".format(k, why[k]))
        out.append("")
    for w in report["warnings"]:
        out.append("WARNING: {}".format(w))
    if report["warnings"]:
        out.append("")
    if report["findings"]:
        out.append("FINDINGS")
        out.append("-" * 66)
        for f in report["findings"]:
            out.append("  {}".format(f))
        out.append("")
        out.append("SPEC-ENUM FAILED: {} finding(s)".format(len(report["findings"])))
    else:
        # The count is READ, not remembered. A hand-kept numeral in the banner
        # of the file whose stated purpose is ending hand-kept numerals is the
        # joke writing itself; §12.6's half already cross-checks the document's
        # own numeral against the document's own list, and this line was the
        # §9.4 half doing neither.
        out.append("SPEC-ENUM OK — §9.4's {} kinds and §12.6's ship-list agree with the tree".format(
            len(report["audit_kinds"])))
    return "\n".join(out)


def find_spec(root, explicit):
    """--spec, then $HOLDFAST_SPEC, then <root>/docs, then the main checkout.

    The last hop is what makes this runnable from a git worktree, where the
    git-ignored `docs/` symlink is not materialised but its absolute target
    is still reachable.
    """
    if explicit:
        p = Path(explicit).expanduser()
        return (p, None) if p.is_file() else (None, "--spec {} is not a file".format(p))
    env = os.environ.get("HOLDFAST_SPEC")
    if env:
        p = Path(env).expanduser()
        return (p, None) if p.is_file() else (None, "$HOLDFAST_SPEC {} is not a file".format(p))

    candidates = [root]
    try:
        common = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True, text=True, timeout=10,
        )
        if common.returncode == 0:
            main = Path(common.stdout.strip()).parent
            if main != root:
                candidates.append(main)
    except (OSError, subprocess.SubprocessError):
        pass

    tried = []
    for base in candidates:
        specs_dir = base / "docs" / "superpowers" / "specs"
        tried.append(str(specs_dir))
        if not specs_dir.is_dir():
            continue
        found = sorted(specs_dir.glob("*-holdfast-design.md"))
        if len(found) != 1:
            return None, "expected exactly one *-holdfast-design.md in {}, found {}".format(
                specs_dir, len(found))
        return found[0], None
    return None, "no spec at any of: {}".format(", ".join(tried))


# --------------------------------------------------------------------------
# Self-test.
#
# Every case runs `build_report` or `find_spec` — the production paths —
# against a fixture tree, so a case cannot pass by testing a copy of the
# logic. Each rule gets a positive AND a negative: "no findings" and "this
# rule cannot produce a finding" print the same word, which is the whole
# reason the negatives are here. The mutation cases edit a fixture and assert
# the ANSWER CHANGES; a check that reports the same thing either way is not
# reading the document.
#
# THE CASES ARE CHOSEN BY WHAT SURVIVES MUTATION OF *THIS FILE*, not by what
# is easy to fixture. An earlier revision of this self-test was the only arm
# wired into CI and it constrained almost none of the heuristics that decide
# the real answer: four separate mutations of this script passed it with exit
# 0 while breaking the real check —
#
#   * deleting `find_spec`'s `git rev-parse --git-common-dir` fallback, which
#     is this script's headline capability and the reason a reviewer can run
#     it from a worktree at all. All three `find_spec` cases called
#     `find_spec(Path(tmp), None)` on a directory that was not a git worktree,
#     so none of them entered the branch — while the coverage summary printed
#     that they did;
#   * narrowing the source glob from `*/src/**/*.rs` to `*/src/*.rs`. Every
#     fixture writer lived in `src/lib.rs`, so the `**` was never load-bearing;
#   * breaking the test-module blanking terminator. `SELF_TEST_SRC` contained
#     exactly one `#[cfg(test)]`, on a textbook `mod tests { … }` — the one
#     shape the heuristic already handled, and not the shape it got wrong in
#     the real tree;
#   * deleting the `--spec` and `$HOLDFAST_SPEC` branches of `find_spec`, for
#     which there was no case at all.
#
# Each of those now has a case that dies on the mutation, and the fixtures
# below are shaped accordingly: writers live in a NESTED directory, the
# blanking fixture carries every item shape this workspace actually has, and
# `find_spec` is driven through a real `git worktree`.
#
# AND IT IS HERMETIC. `find_spec` reads `$HOLDFAST_SPEC` from the process
# environment, so a developer who had exported it — the documented way to
# point the real check at a spec — got three red `find_spec` cases that said
# nothing about what they had changed. CI never saw it, because the variable
# is unset there, which makes it a human-only false red: the direction that
# gets a check dismissed rather than fixed. `self_test` scrubs the variable
# for its own duration and the one case that wants it sets it explicitly.

SELF_TEST_SPEC = """# Design

### 9.4 Audit logging

- Preamble prose naming `session_start` in backticks, which is a reference.

| `kind` | Extra fields |
|---|---|
| `daemon_start` | `pid, version` |
| `daemon_stop` | `reason: "explicit" \\| "sigterm"` |
| `session_start` | `command, args` |
| `session_terminate` | `reason, exit_code` |
| `send_input` | `byte_count` |
| `redaction_disabled` | `tool, client_kind` |
| `attach_connect` | `peer_uid` |
| `attach_disconnect` | `reason, duration_secs` |
| `panic` | `module, message` |
| `truncated_at_tail` | `tool, since_cursor` |
| `secret_input_request` | `request_id` |
| `secret_input_resolved` | `request_id, outcome` |
| `binding_resolved` | `binding_name` |
| `binding_approval` | `approval_id` |
| `preflight_match` | `rule_kind` |
| `confirmation_redeem` | `confirmation_id` |
| `confirmation_abandoned` | `confirmation_id` |
| `bridge_register` | `port` |
| `bridge_revoke` | `reason` |
| `file_transfer` | `direction, bytes` |
| `recording_started` | `path` |

Prose below the table naming `session_start` and `panic` again.

### 10.1 Something else

| `kind` | Extra fields |
|---|---|
| `not_an_audit_kind` | `x` |

### 12.6 v0.1.0 ship-list

- All 7 MCP tools from §5: `start_session`, `read_output` (with \
`ansi`/`redact`), `send_input`, `terminate`, `status`, `list_sessions`, \
`precheck_command`
- Another bullet entirely.
"""

SELF_TEST_SCHEMA = """
const TOOLS: [&str; 6] = [
    "start_session",
    "read_output",
    "send_input",
    "terminate",
    "status",
    "list_sessions",
];
"""

# `crates/holdfast-core/src/lib.rs`.
#
# Shaped after the real tree rather than after what is convenient, because
# the blanking heuristic is decided by SHAPES and the previous fixture had
# exactly one — `mod tests { … }`, the shape that already worked:
#
#   * a braceless `#[cfg(test)] use …;`, which is `secret/provider.rs:72` and
#     where the old "blank to the next line that is exactly `}`" terminator
#     ate 99 lines of live production Rust, including the writers below it;
#   * a `{` inside a STRING literal (`config.rs:2264` is `&["{host"],`), which
#     is what makes naive brace counting walk off the end of the file;
#   * a `'}'` CHAR literal beside a `'a` lifetime, which a masker that cannot
#     tell them apart gets wrong in one direction or the other;
#   * a raw string containing a lone brace and an embedded quote;
#   * a column-zero `#[cfg(all(test, unix))]` on a tuple struct and a
#     `#[cfg(test)]` on an `impl`, which is 10 of this workspace's 12
#     non-`mod` gates;
#   * `"send_input"` as an MCP DISPATCH ARM — the literal in production Rust
#     that is not an audit write, which is the false green this file shipped.
SELF_TEST_SRC = """
pub const BRACE_IN_A_STRING: &[&str] = &["{host"];
pub const BRACE_CHAR: char = '}';
pub const RAW: &str = r#"a raw string with a lone } and an embedded "quote""#;

pub fn borrow<'a>(s: &'a str) -> &'a str {
    s // `'a` is a lifetime, not a char literal
}

#[cfg(test)]
use std::path::PathBuf;

pub fn go(log: &AuditLog) {
    log.record("daemon_start", None, json!({}));
    log.record("daemon_stop", None, json!({}));
    log.record("session_start", None, json!({}));
    log.record("send_input", None, json!({}));
    log.record("attach_connect", None, json!({}));
    log.record("panic", None, json!({}));
    log.record("truncated_at_tail", None, json!({}));
}

pub fn dispatch(name: &str) -> bool {
    matches!(name, "send_input" | "start_session")
}

pub fn respond() -> Value {
    json!({ "truncated_at_tail": true })
}

#[cfg(all(test, unix))]
pub(crate) struct Forced(u32);

#[cfg(test)]
impl Forced {
    fn t(&self, log: &AuditLog) {
        log.record("confirmation_redeem", None, json!({}));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        log.record("preflight_match", None, json!({}));
        log.record("bridge_register", None, json!({}));
        log.record("bridge_revoke", None, json!({}));
        log.record("confirmation_abandoned", None, json!({}));
        log.record("file_transfer", None, json!({}));
        log.record("recording_started", None, json!({}));
    }
}
"""

# `crates/holdfast-core/src/mcp/tools.rs` — a NESTED directory, and the only
# home of these five writers. Narrow the glob's `**` to a single `*` and they
# vanish, which is the mutation that used to survive.
SELF_TEST_NESTED = """
pub fn more(log: &AuditLog) {
    log.record("session_terminate", None, json!({}));
    log.record("redaction_disabled", None, json!({}));
    log.record("attach_disconnect", None, json!({}));
    log.record("secret_input_request", None, json!({}));
    log.record("secret_input_resolved", None, json!({}));
    log.record("binding_resolved", None, json!({}));
    log.record("binding_approval", None, json!({}));
}
"""

NESTED_ONLY = [
    "session_terminate", "redaction_disabled", "attach_disconnect",
    "secret_input_request", "secret_input_resolved", "binding_resolved",
    "binding_approval",
]


def _fixture(tmp, spec=SELF_TEST_SPEC, schema=SELF_TEST_SCHEMA, src=SELF_TEST_SRC,
             nested=SELF_TEST_NESTED):
    root = Path(tmp)
    (root / "crates" / "holdfast-core" / "src" / "mcp").mkdir(parents=True, exist_ok=True)
    (root / "crates" / "holdfast-core" / "tests").mkdir(parents=True, exist_ok=True)
    (root / "crates" / "holdfast-core" / "src" / "lib.rs").write_text(src)
    (root / "crates" / "holdfast-core" / "src" / "mcp" / "tools.rs").write_text(nested)
    (root / "crates" / "holdfast-core" / "tests" / "schema.rs").write_text(schema)
    spec_path = root / "spec.md"
    spec_path.write_text(spec)
    return spec_path, root


def self_test():
    # Hermeticity: see the header above. `$HOLDFAST_SPEC` is scrubbed for the
    # whole run, and the one case that wants it sets it itself.
    saved_env = os.environ.pop("HOLDFAST_SPEC", None)
    try:
        return _self_test_body()
    finally:
        if saved_env is not None:
            os.environ["HOLDFAST_SPEC"] = saved_env


def _self_test_body():
    state = {"failures": 0}
    deferred = ["preflight_match", "confirmation_redeem", "confirmation_abandoned",
                "bridge_register", "bridge_revoke", "file_transfer", "recording_started"]

    def chk(name, got, want):
        if got == want:
            print("  PASS  {} -> {!r}".format(name, got))
        else:
            print("  FAIL  {}\n          got  {!r}\n          want {!r}".format(name, got, want))
            state["failures"] += 1

    def run(defects=(), **kw):
        with tempfile.TemporaryDirectory() as tmp:
            spec_path, root = _fixture(tmp, **kw)
            saved_u, saved_a = list(KNOWN_UNWRITTEN), list(KNOWN_UNAUDITED)
            KNOWN_UNWRITTEN[:] = [(k, "fixture") for k in deferred]
            KNOWN_UNAUDITED[:] = [(k, "fixture issue") for k in defects]
            try:
                return build_report(spec_path, root)
            finally:
                KNOWN_UNWRITTEN[:] = saved_u
                KNOWN_UNAUDITED[:] = saved_a

    print("spec-enum-check self-test")
    print("-" * 66)

    print("\n§9.4 — table parsing")
    rep, err = run()
    chk("the baseline fixture reports no findings", (rep and rep["findings"], err), ([], None))
    chk("column 1 of the table is parsed, and only the table", len(rep["audit_kinds"]), 21)
    chk("an escaped pipe in column 2 does not break the row",
        "daemon_stop" in rep["audit_kinds"], True)
    chk("a later section's table is NOT collected",
        "not_an_audit_kind" in rep["audit_kinds"], False)
    chk("test-module writers do not count as production writers",
        sorted(rep["audit_unwritten"]), sorted(["preflight_match", "confirmation_redeem",
                                                "confirmation_abandoned", "bridge_register",
                                                "bridge_revoke", "file_transfer",
                                                "recording_started"]))
    chk("every row of the table is accounted for by name", rep["audit_unaccounted"], [])

    print("\n§9.4 — a writer is a `.record(` FIRST ARGUMENT, not a substring")
    chk("writers in a NESTED src/ directory are seen (the glob's `**` is load-bearing)",
        [k for k in NESTED_ONLY if k not in rep["audit_written"]], [])
    chk("a dispatch arm naming the kind is not itself a writer",
        (rep["audit_literal_but_not_recorded"], "send_input" in rep["audit_written"]),
        ([], True))
    rep_disp, _ = run(src=SELF_TEST_SRC.replace(
        '    log.record("send_input", None, json!({}));\n', ""))
    chk("MUTATION: delete the audit write, leave the MCP dispatch arm -> a finding",
        (any("`send_input` has NO production writer" in f for f in rep_disp["findings"]),
         rep_disp["audit_literal_but_not_recorded"]),
        (True, ["send_input"]))
    chk("...and the finding SAYS the surviving literal is not an audit write",
        any("not an audit write" in f and "send_input" in f for f in rep_disp["findings"]), True)
    chk("...and `send_input` is no longer reported as written",
        "send_input" in rep_disp["audit_written"], False)
    rep_json, _ = run(src=SELF_TEST_SRC.replace(
        '    log.record("truncated_at_tail", None, json!({}));\n', ""))
    chk("MUTATION: delete the only audit write whose literal is also a JSON field name",
        (any("`truncated_at_tail` has NO production writer" in f for f in rep_json["findings"]),
         rep_json["audit_literal_but_not_recorded"]),
        (True, ["truncated_at_tail"]))
    chk("...and the answer CHANGED (the substring rule left it byte-identical)",
        rep_json["findings"] != rep["findings"], True)

    print("\n§9.4 — test-module blanking, by ITEM SHAPE")
    stripped = strip_test_modules(SELF_TEST_SRC)
    # Production items, every one of which the OLD terminator destroyed or
    # would destroy on the next edit: `pub fn go` sits between a braceless
    # `#[cfg(test)] use …;` and the next column-zero `}`.
    survives = ["BRACE_IN_A_STRING", "BRACE_CHAR", "RAW", "pub fn borrow",
                "pub fn go", "pub fn dispatch", "pub fn respond"]
    blanked = ["std::path::PathBuf", "pub(crate) struct Forced", "impl Forced",
               "mod tests", "confirmation_redeem", "preflight_match"]
    chk("every production item survives blanking", [x for x in survives if x not in stripped], [])
    chk("every test-gated item is blanked", [x for x in blanked if x in stripped], [])
    chk("a braceless `#[cfg(test)] use …;` does not take the writers below it",
        [k for k in ("daemon_start", "session_start", "panic") if k not in rep["audit_written"]],
        [])
    chk("a `{` in a string, a `'}'` char literal and a raw brace do not move the depth counter",
        [x for x in ("BRACE_IN_A_STRING", "BRACE_CHAR", "RAW") if x not in stripped], [])
    chk("`'a` is a lifetime and not a char literal", "pub fn borrow" in stripped, True)
    chk("blanking preserves line numbering",
        len(stripped.split("\n")), len(SELF_TEST_SRC.split("\n")))

    print("\n§9.4 — MUTATION: a writer disappears (an event stops being audited)")
    rep2, _ = run(src=SELF_TEST_SRC.replace(
        '    log.record("attach_connect", None, json!({}));\n', ""))
    chk("the lost writer is a finding",
        any("`attach_connect` has NO production writer" in f for f in rep2["findings"]), True)
    chk("...and the answer CHANGED from the baseline", rep2["findings"] != rep["findings"], True)

    print("\n§9.4 — MUTATION: a ledgered kind gains a writer")
    rep3, _ = run(src=SELF_TEST_SRC.replace(
        '    log.record("send_input", None, json!({}));',
        '    log.record("send_input", None, json!({}));\n'
        '    log.record("preflight_match", None, json!({}));'))
    chk("a stale ledger row is a finding",
        any("`preflight_match` now HAS a production writer" in f for f in rep3["findings"]), True)

    print("\n§9.4 — MUTATION: the ledger names a kind the table dropped")
    rep4, _ = run(spec=SELF_TEST_SPEC.replace("| `bridge_register` | `port` |\n", ""))
    chk("a ledger row matching no table row is a finding",
        any("not a row in the table any more" in f for f in rep4["findings"]), True)

    print("\n§9.4 — the reverse direction GATES")
    rep5, _ = run(spec=SELF_TEST_SPEC.replace("| `attach_connect` | `peer_uid` |\n", ""))
    chk("a kind written but unspecified is a finding, not a warning",
        (any("`attach_connect` is not a row" in f for f in rep5["findings"]),
         rep5["warnings"]), (True, []))

    print("\n§9.4 — every row is pinned by NAME, so an editorial reformat cannot shrink it")
    for row, label in (("| `session_start` | `command, args` |\n", "a WRITTEN row"),
                       ("| `file_transfer` | `direction, bytes` |\n", "a DEFERRED row")):
        repx, errx = run(spec=SELF_TEST_SPEC.replace(row, ""))
        chk("dropping {} from the table is caught (20 rows, above the floor)".format(label),
            (errx, len(repx["audit_kinds"]), repx["findings"] != []), (None, 20, True))

    print("\n§9.4 — the shipped-but-unaudited ledger PINS a row without waiving it")
    rep6, _ = run(defects=["daemon_start"],
                  src=SELF_TEST_SRC.replace(
                      '    log.record("daemon_start", None, json!({}));\n', ""))
    chk("a ledgered shipped-but-unaudited kind is STILL a finding",
        any("its feature SHIPS, and no production code writes it" in f
            and "daemon_start" in f for f in rep6["findings"]), True)
    chk("...and the row is pinned, so it is not 'unaccounted for' either",
        (rep6["audit_unaccounted"], rep6["audit_shipped_unaudited"]), ([], ["daemon_start"]))
    rep7, _ = run(defects=["daemon_start"])
    chk("a defect-ledger row whose writer arrived is a finding (the ledger cannot rot)",
        any("still in the shipped-but-unaudited ledger" in f for f in rep7["findings"]), True)
    rep8, _ = run(defects=["preflight_match"])
    chk("a kind in BOTH ledgers is a finding",
        any("is in BOTH ledgers" in f for f in rep8["findings"]), True)
    rep8b, _ = run(defects=["daemon_start"],
                   spec=SELF_TEST_SPEC.replace("| `daemon_start` | `pid, version` |\n", ""))
    chk("a defect-ledger row the table dropped is a finding (this is the F9 pin)",
        any("not a row in the table any more" in f and "daemon_start" in f
            for f in rep8b["findings"]), True)
    chk("...and it is NOT also reported as having gained a writer",
        any("now HAS a production writer" in f for f in rep8b["findings"]), False)
    rep8c, _ = run(spec=SELF_TEST_SPEC.replace("| `file_transfer` | `direction, bytes` |\n", ""))
    chk("the same holds for the unbuilt-feature ledger",
        (any("not a row in the table any more" in f and "file_transfer" in f
             for f in rep8c["findings"]),
         any("now HAS a production writer" in f for f in rep8c["findings"])),
        (True, False))

    print("\n§12.6 — parenthetical filter and the numeral cross-check")
    chk("parentheticals are stripped before ids are taken",
        rep["shiplist_tools"],
        ["start_session", "read_output", "send_input", "terminate", "status",
         "list_sessions", "precheck_command"])
    chk("`ansi` and `redact` are NOT collected as tools",
        [t for t in rep["shiplist_tools"] if t in ("ansi", "redact")], [])
    chk("the shipped set is reported", rep["shipped_tools"],
        ["start_session", "read_output", "send_input", "terminate", "status",
         "list_sessions"])
    chk("planned-but-unbuilt is a census, not a finding",
        (rep["shiplist_not_shipped"], [f for f in rep["findings"] if "precheck_command" in f]),
        (["precheck_command"], []))

    print("\n§12.6 — MUTATION: the numeral disagrees with its own list")
    rep9, _ = run(spec=SELF_TEST_SPEC.replace("All 7 MCP tools", "All 8 MCP tools"))
    chk("numeral vs list is a finding",
        any("says `All 8 MCP tools` and then lists 7" in f for f in rep9["findings"]), True)

    print("\n§12.6 — MUTATION: a shipped tool is missing from the ship-list")
    rep10, _ = run(spec=SELF_TEST_SPEC.replace("`send_input`, `terminate`", "`terminate`")
                   .replace("All 7 MCP tools", "All 6 MCP tools"))
    chk("a shipped tool absent from §12.6 is a finding",
        any("`send_input` is an MCP tool the tree ships" in f for f in rep10["findings"]), True)

    print("\nanti-vacuity — a tree or document it cannot read is never a pass")
    with tempfile.TemporaryDirectory() as tmp:
        spec_path, root = _fixture(tmp)
        (root / "crates" / "holdfast-core" / "src" / "lib.rs").unlink()
        (root / "crates" / "holdfast-core" / "src" / "mcp" / "tools.rs").unlink()
        rep11, err11 = build_report(spec_path, root)
    chk("no production Rust -> error, not 'every kind unwritten'",
        (rep11 is None, "refusing to report every kind as unwritten" in (err11 or "")), (True, True))
    shrunk = SELF_TEST_SPEC
    for row in ("| `file_transfer` | `direction, bytes` |\n",
                "| `recording_started` | `path` |\n",
                "| `bridge_revoke` | `reason` |\n",
                "| `binding_approval` | `approval_id` |\n"):
        shrunk = shrunk.replace(row, "")
    rep_small, err_small = run(spec=shrunk)
    chk("a table that parsed to 17 rows -> error, not a short green run",
        (rep_small is None, "the format moved" in (err_small or "")), (True, True))
    rep12, err12 = run(spec="# Design\n\n### 12.6 ship-list\n\n- nothing\n")
    chk("§9.4 absent -> error, not a green run", (rep12 is None, err12),
        (True, "§9.4 not found in the spec"))
    rep13, err13 = run(spec=SELF_TEST_SPEC.replace("### 12.6 v0.1.0 ship-list", "### 12.7 elsewhere"))
    chk("§12.6 absent -> error, not a green run",
        (rep13 is None, "§12.6" in (err13 or "")), (True, True))
    rep14, err14 = run(schema="const TOOLS: [&str; 0] = [];\nlet x = 1;\n")
    chk("an EMPTY schema.rs pin -> error, not a vacuously satisfied subset rule",
        (rep14 is None, "vacuously satisfied" in (err14 or "")), (True, True))
    rep15, err15 = run(schema="const NOT_TOOLS: [&str; 2] = [\"a\", \"b\"];\n")
    chk("the schema.rs pin being RENAMED -> error, not a silent skip",
        (rep15 is None, "the pin moved" in (err15 or "")), (True, True))

    print("\nfind_spec — every branch of the chain, including the worktree fallback")
    chk("the environment is scrubbed for this section",
        os.environ.get("HOLDFAST_SPEC"), None)
    with tempfile.TemporaryDirectory() as tmp:
        explicit = Path(tmp) / "given.md"
        explicit.write_text("x")
        got, ferr = find_spec(Path(tmp), str(explicit))
        chk("--spec names a file -> that file, and no search happens", (got, ferr),
            (explicit, None))
        got, ferr = find_spec(Path(tmp), str(Path(tmp) / "absent.md"))
        chk("--spec names a non-file -> error, not a fallback to the search",
            (got, "--spec" in (ferr or "")), (None, True))
        os.environ["HOLDFAST_SPEC"] = str(explicit)
        try:
            got, ferr = find_spec(Path(tmp), None)
            chk("$HOLDFAST_SPEC is consulted when --spec is absent", (got, ferr), (explicit, None))
            os.environ["HOLDFAST_SPEC"] = str(Path(tmp) / "absent.md")
            got, ferr = find_spec(Path(tmp), None)
            chk("$HOLDFAST_SPEC naming a non-file -> error, not a silent fallback",
                (got, "$HOLDFAST_SPEC" in (ferr or "")), (None, True))
        finally:
            os.environ.pop("HOLDFAST_SPEC", None)
    with tempfile.TemporaryDirectory() as tmp:
        got, ferr = find_spec(Path(tmp), None)
        chk("a tree with no docs/ and no git -> cannot run, with the paths tried",
            (got, "no spec at any of" in (ferr or "")), (None, True))
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "docs" / "superpowers" / "specs"
        d.mkdir(parents=True)
        (d / "0000-00-00-holdfast-design.md").write_text("x")
        got, ferr = find_spec(Path(tmp), None)
        chk("docs/ present -> the spec is found", (got.name, ferr),
            ("0000-00-00-holdfast-design.md", None))
        (d / "0001-01-01-holdfast-design.md").write_text("x")
        got, ferr = find_spec(Path(tmp), None)
        chk("two candidate specs -> error, not an arbitrary pick",
            (got, "expected exactly one" in (ferr or "")), (None, True))
    _worktree_case(chk)

    print("\n" + "-" * 66)
    # What was covered, rather than how many cases ran: the count is the
    # thing that goes stale, which is the defect this whole file is about.
    print("covered: §9.4's table parsed and bounded away from its own prose")
    print("and from a later section's table; a writer defined as a `.record(`")
    print("first argument, with a dispatch arm and a JSON field name proved")
    print("NOT to be one; the blanking heuristic driven through every item")
    print("shape this workspace has, with a brace in a string, a `'}'` char")
    print("literal and a raw string; writers in a nested src/ directory; the")
    print("ledger red in both directions and when it names a dropped row; the")
    print("shipped-but-unaudited ledger pinning a row without waiving it; the")
    print("reverse direction gating; every table row pinned by name against")
    print("an editorial deletion; §12.6's parenthetical filter, its")
    print("numeral-vs-list cross-check and the shipped-subset rule; refusal")
    print("on an unreadable tree, a shrunken table, a missing §9.4 or §12.6,")
    print("and an empty or renamed schema.rs pin; and find_spec's --spec /")
    print("$HOLDFAST_SPEC / docs / real-git-worktree chain.")
    if state["failures"]:
        print("SELF-TEST FAILED: {} case(s)".format(state["failures"]))
        return EXIT_FINDINGS
    print("SELF-TEST OK")
    return EXIT_OK


def _worktree_case(chk):
    """`find_spec` from a REAL `git worktree`, which is the headline capability.

    Driven through `git` rather than simulated, because the branch under test
    is `git rev-parse --path-format=absolute --git-common-dir` and a fake of
    it would be a second implementation of the thing being checked. `docs/` is
    created AFTER the commit and never added, so the worktree genuinely does
    not have it — which is the real condition, not a staged one.
    """
    git = shutil.which("git")
    if git is None:
        chk("git is on PATH for the worktree case", False, True)
        return
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "spec-enum-check",
        "GIT_AUTHOR_EMAIL": "spec-enum-check@example.invalid",
        "GIT_COMMITTER_NAME": "spec-enum-check",
        "GIT_COMMITTER_EMAIL": "spec-enum-check@example.invalid",
    })
    with tempfile.TemporaryDirectory() as tmp:
        main = Path(tmp) / "main"
        main.mkdir()

        def g(*args):
            return subprocess.run([git, "-C", str(main)] + list(args), env=env,
                                  capture_output=True, text=True, timeout=30)

        if g("init", "-q").returncode != 0:
            chk("git init succeeds for the worktree case", False, True)
            return
        (main / "README").write_text("x")
        g("add", "-A")
        if g("commit", "-qm", "init").returncode != 0:
            chk("git commit succeeds for the worktree case", False, True)
            return
        specs = main / "docs" / "superpowers" / "specs"
        specs.mkdir(parents=True)
        (specs / "0000-00-00-holdfast-design.md").write_text("x")
        wt = Path(tmp) / "wt"
        if g("worktree", "add", "--detach", "-q", str(wt), "HEAD").returncode != 0:
            chk("git worktree add succeeds for the worktree case", False, True)
            return
        chk("the worktree genuinely has no docs/ (the case is not staged)",
            (wt / "docs").exists(), False)
        got, ferr = find_spec(wt, None)
        chk("a git WORKTREE with no docs/ finds the spec in the main checkout",
            (got.name if got else None, ferr), ("0000-00-00-holdfast-design.md", None))
        g("worktree", "remove", "--force", str(wt))


def main():
    ap = argparse.ArgumentParser(description="Assert the spec's enumerations against the tree.")
    ap.add_argument("--repo-root")
    ap.add_argument("--spec")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    root = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parent.parent

    spec_path, err = find_spec(root, args.spec)
    if spec_path is None:
        print(
            "CANNOT RUN: {}.\n"
            "\n"
            "`docs/` is git-ignored in this repository and lives in a separate\n"
            "git repo, so a clone -- including whatever CI checks out -- does\n"
            "not have it. This is not a pass: nothing was checked. Run this\n"
            "where the docs repo is present, pass --spec, or set $HOLDFAST_SPEC.".format(err),
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    report, err = build_report(spec_path, root)
    if report is None:
        print("error: {}".format(err), file=sys.stderr)
        return EXIT_ERROR

    print(json.dumps(report, indent=2) if args.json else render(report))
    return EXIT_FINDINGS if report["findings"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
