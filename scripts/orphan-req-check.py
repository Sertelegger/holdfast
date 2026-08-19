#!/usr/bin/env python3
# Find §20 requirements that no implementation plan owns.
#
# Spec §23.3 (rev. 42) makes this a gate obligation rather than a chore:
# "a requirement no plan names is outside every plan-driven sweep by
# construction, so checking that each §20 row in the changed area has an
# owning plan is part of this gate rather than adjacent to it." The worked
# example in that same paragraph is REQ-PD-018 — implemented, its test
# shipped, and named by no plan across the whole set, so no plan's
# re-verification pass could ever reach it.
#
# WHY THIS IS NOT A PERIODIC MANUAL SWEEP. A sweep measures a document that
# keeps growing. Rev. 36 added seven in-range REQs and no plan cited any of
# the seven; rev. 38 added three that were orphaned at one day old; rev. 39
# added two more; rev. 40 two more. The count moves every revision, so the
# answer has to be cheap enough to recompute on every revision.
#
# WHY IT STARTS AT THE SPEC AND NOT AT THE PLANS. Asking each plan "what do
# you cite?" cannot see a requirement no plan mentions — the whole class
# REQ-PD-018 belongs to is invisible from that direction. The universe here
# is the set of ids the §20 tables *define*; plans are read only to strike
# ids off it.
#
# FIVE JUDGEMENTS, STATED RATHER THAN IMPLIED:
#
#   1. RANGE NOTATION IS NOT A CITATION. A plan writing `REQ-SEC-012..017`
#      has named a count, not six requirements. Ranges are expanded and the
#      ids they cover are reported in their own class (`range-only`), which
#      counts as unowned. This is not pedantry: the one such span in the
#      current plan set sits in a line reading "Deliberately not covered
#      here", so scoring it as ownership is wrong twice over. Range spans
#      are blanked out of the text *before* literal ids are scanned —
#      otherwise `REQ-SEC-012..017` donates a literal citation to its own
#      first endpoint and only the other five look uncited, which is the
#      exact shape that produced a wrong answer by hand.
#
#   2. SCOPE IS READ FROM THE TABLE, NOT FROM A HARDCODED SECTION LIST.
#      §20's preamble defines the convention: deferred sections carry
#      "post-v0.1.0" in the heading and "use a `Verification` column rather
#      than `Tests`". So a section is in scope iff its table is a Tests
#      table and neither it nor its parent heading is marked deferred.
#      Hardcoding "20.1 through 20.15" would silently mis-scope the next
#      section anybody adds, in whichever direction the numbering fell.
#      A numeric cross-check runs anyway and warns if the two disagree.
#
#   3. "Owned" means a plan names the id. A requirement whose behaviour is
#      implemented by a task that never writes the id down is reported as
#      unowned, and that is the intended answer — the id is the only handle
#      a re-verification pass has.
#
#   4. NAMING AN ID IS NOT CLAIMING IT. A plan cites an id for two opposite
#      reasons — "this is mine" and "this is NOT mine, 0.0.10 owns it" — and
#      until the deferral gate existed both scored as ownership, so the
#      headline number meant "every requirement is mentioned somewhere",
#      which is weaker than what it reads as. A citation under a heading
#      that hands work away (`Deliberately not covered here`,
#      `Re-asserted here, owned elsewhere`, `Scope boundaries — deliberately
#      NOT in 0.0.7`) is collected as DEFERRED-ONLY, a third unowned class.
#      Measured on this corpus: 112 citations were deferrals, and with the
#      four plans that own what 0.0.7 hands away withheld — the state this
#      was found in — owned falls from 186 to 172 and the nine REQ-W ids
#      plus five REQ-DM ids are reported for the first time. The discount is
#      per CITATION, so a plan deferring an id cannot take it from the plan
#      that claims it, and it is read from HEADINGS only: see
#      `DEFERRAL_HEADING_RE` for why the sentence is not enough and why the
#      pattern is a phrase list rather than the word "deferred".
#
#   5. DEFERRAL IS A STATUS, NOT A LOCATION (§23.3a, rev. 50). Judgement 2
#      reads a section HEADING, which is a proxy for the rule the spec
#      actually states -- "deferred requirements do not count" -- and §23.3a
#      is explicit that rev. 50 is the case where the proxy and the rule
#      disagree: "One carve-out, and it is the only one: REQ-SPTY-001..005
#      (§20.17.1) count." Their item became milestone 0.0.10a, so they are
#      owed at v0.1.0 while sitting under a heading that says otherwise. They
#      were deliberately NOT moved into §20.1-§20.15, because every citation
#      of them resolves where they are. REQ-SPTY-006 is in the same table and
#      is still deferred -- which is exactly what makes this a ROW-level fact
#      that no section-level answer can express.
#
#      So: a row inside a deferred section is carved back IN iff its own
#      Status cell names a MILESTONE rather than a roadmap tier. Read from the
#      table, for judgement 2's reason -- a hardcoded `REQ-SPTY-001..005` list
#      would be a second enumeration that goes stale in silence, and the
#      Status column is already the per-row statement of precisely this fact.
#      A whole-section answer read off the heading is what the carve-out
#      exists to defeat; so is a whole-section exception, which would silence
#      the twelve genuinely-deferred rows' neighbours along with them.
#
#      SELF-LIMITING THREE WAYS, because the only exemption that gets removed
#      is one nobody has to remember to remove:
#        * It expires by being SATISFIED. A carved-in row joins the universe,
#          so it reads UNOWNED until a 0.0.10a plan names it. §23.3a: "that is
#          the check working, not breaking". When that plan lands the row goes
#          green with no edit here.
#        * It expires by being RETIRED. Ship the milestone, or move the rows
#          into §20.1-§20.15, and the Status cell stops naming a milestone --
#          the carve-in stops firing on its own. Nothing below says "SPTY".
#        * It cannot expire by ACCIDENT. If a deferred section's prose claims
#          the carve-out and no row's Status backs it up -- or the reverse --
#          that is a warning rather than a silent green. §23.3a names this
#          failure mode directly: "the rule lives only in this paragraph and
#          the automated answer quietly disagrees with it."
#
# WHERE THIS RUNS. Not in CI, deliberately. `docs/` is git-ignored in this
# repository and lives in a separate git repo, so the spec and the plans are
# not in the tree CI checks out; a workflow calling this would find no spec
# on every run. This project has already shipped a config file at a path
# nothing read, so an unrunnable check is a known failure mode here, not a
# hypothetical one. Run it by hand, or install the post-commit hook into the
# docs repo (`--install-hook`) so it fires on the event that causes the
# drift — a spec revision. Absence of `docs/` exits 3 with a message saying
# the check could not run; it never exits 0 on a tree it could not read.
#
# Usage:
#   scripts/orphan-req-check.py                 # report, exit 1 if unowned
#   scripts/orphan-req-check.py --json          # machine-readable
#   scripts/orphan-req-check.py --self-test     # prove the check can fail
#   scripts/orphan-req-check.py --install-hook  # post-commit hook in docs/

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# A requirement id: REQ-<AREA>-<NNN> with an optional letter suffix
# (REQ-T-006a, REQ-SEC-010a are real).
REQ_ID = r"REQ-[A-Z]+-[0-9]+[a-z]?"

# The id column of a §20 table row, tolerating a struck-through id.
ROW_ID_RE = re.compile(rf"^\|\s*(?:~~)?({REQ_ID})(?:~~)?\s*\|")

# Range notation. Endpoint may repeat the prefix (`REQ-X-001..REQ-X-006`) or
# not (`REQ-X-001..006`); `..` or `...`.
RANGE_RE = re.compile(
    r"(REQ-([A-Z]+)-)([0-9]+)([a-z]?)\s*\.\.\.?\s*(?:REQ-\2-)?([0-9]+)([a-z]?)"
)

LITERAL_RE = re.compile(REQ_ID)

# A range wider than this is a typo, not an enumeration.
MAX_RANGE_SPAN = 200

# ---- deferral vs ownership ----------------------------------------------
#
# A plan cites an id for two opposite reasons, and until this existed the
# check could not tell them apart: to say "this is mine" and to say "this is
# NOT mine, it belongs to 0.0.10". The second is the more careful thing a plan
# author can do -- the 0.0.7 plan's own words are "named one by one, so that a
# mechanical sweep for an uncited requirement finds this list rather than a
# gap" -- and the sweep rewarded it by scoring the id discharged. Measured:
# every one of the nine REQ-W ids read as owned by 0.0.7 from before the plan
# that actually owns them existed, and an early 0.0.11 draft naming
# REQ-CFG-006 while explaining it is 0.0.8's took the orphan count from 1 to 0
# on the spot.
#
# READ FROM THE HEADING, not from the sentence. The heading is a structural
# fact a plan author declares once and a reviewer can see; a sentence is
# prose, and "not covered here" appears in argument as often as in
# declaration. The existing self-test fixture has a *prose* line reading
# "Deliberately not covered here: REQ-ZZA-003..005" and it is deliberately
# NOT discounted, which is what pins that distinction.
#
# PRECISION MATTERS MORE THAN RECALL here, because a false discount
# manufactures an orphan that no plan can close: there is a real heading in
# this corpus reading "Two items 0.0.1 deferred to this milestone — decided",
# which is an OWNERSHIP heading containing the word "deferred". Matching on
# that word alone would score two owned requirements as orphans. Each pattern
# below is a phrase this corpus actually uses to hand work away.
PLAN_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
PLAN_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")

DEFERRAL_HEADING_RE = re.compile(
    r"deliberately\s+not\b"                      # "deliberately NOT in 0.0.7"
    r"|\bnot\s+covered\s+here\b"                 # "Deliberately not covered here"
    r"|\bowned\s+elsewhere\b"                    # "Re-asserted here, owned elsewhere"
    r"|\bscope\s+boundaries\b"                   # "Scope boundaries — ..."
    r"|\bexcluded\s+from\s+the\s+completeness\s+check\b",
    re.I,
)

# ---- the row-level carve-out: deferral is a status, not a location -------
#
# §23.3a, rev. 50; judgement 5 in the header. A row in a deferred section
# counts anyway iff its own Status cell names a milestone.
#
# WHY "THREE-PART VERSION *AND NOT* A TIER" rather than matching "0.0.10a".
# A bare three-part match is not enough on the real corpus: REQ-RTD-007's
# Status is "§14.3, §9.3.2", and the section reference §9.3.2 is three-part.
# The tier guard is what makes the rule mean "names a milestone" instead of
# "contains a dotted number". Matching the literal string "0.0.10a" would be
# the hardcoded id list wearing a different hat -- it would not notice the
# next scheduled roadmap item, and it would keep firing after this one ships.
#
# It FAILS SAFE in the direction that matters: a Status this cannot classify
# is not carved in, so an unreadable table gives the pre-rev.-50 answer
# rather than a new and confident wrong one. The prose cross-check below is
# what stops that silence from being mistaken for agreement.
MILESTONE_STATUS_RE = re.compile(r"\b[0-9]+\.[0-9]+\.[0-9]+[a-z]?\b")

DEFERRED_TIER_RE = re.compile(
    r"\bv[0-9]+\.[0-9]+"          # "v0.2 (§14.1)", "v0.3–v0.5 (§14.2)"
    r"|\bspeculative\b"           # "speculative (§14.3)"
    r"|§\s*14\.[0-9]",            # "§14.3, §9.3.2" — a §14 roadmap tier
    re.I,
)

# The prose half of the same claim. §20.17.1 states the carve-out in its
# blockquote -- "they count in the §23.3a completeness check" -- and this is
# read ONLY to cross-check it against the Status cells. Neither one is
# allowed to be the answer on its own: if they disagree, say so.
CARVE_IN_PROSE_RE = re.compile(
    r"count\s+in\s+the\s+§?\s*23\.3a\s+completeness\s+check", re.I)


def status_is_owed(status: str) -> bool:
    """True iff a deferred row's Status names a milestone, not a roadmap tier."""
    if not status:
        return False
    return bool(MILESTONE_STATUS_RE.search(status)) and not DEFERRED_TIER_RE.search(status)


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_CANNOT_RUN = 3


# --------------------------------------------------------------------------
# Spec parsing: the universe of requirements
# --------------------------------------------------------------------------


class Section:
    def __init__(self, number: str, title: str, level: int, line: int):
        self.number = number
        self.title = title
        self.level = level
        self.line = line
        self.deferred_heading = "post-v0.1.0" in title.lower()
        self.has_status_column = False
        self.saw_table = False
        # (id, Status cell). The Status cell is empty for an in-scope section,
        # which carries a Tests column instead — that difference IS the §20
        # convention, and §23.3a's carve-out is read straight off it.
        self.rows: list[tuple[str, str]] = []
        # Set when this section's own prose states the §23.3a carve-out.
        self.carve_in_prose = False

    @property
    def req_ids(self) -> list[str]:
        return [rid for rid, _ in self.rows]

    @property
    def in_scope(self) -> bool:
        return self.saw_table and not self.deferred_heading and not self.has_status_column

    @property
    def carved_rows(self) -> list[str]:
        """Rows this deferred section owes anyway — §23.3a's row-level carve-out.

        Empty for an in-scope section, whose rows are already counted, and for
        a deferred section whose every row names a roadmap tier — which is all
        of them but §20.17.1 today, and that is the point: the answer is per
        row, so the five owed rows and the one speculative row in that single
        table come out on opposite sides.
        """
        if self.in_scope or not self.saw_table:
            return []
        return [rid for rid, status in self.rows if status_is_owed(status)]


HEADING_RE = re.compile(r"^(#{2,4})\s+(20(?:\.[0-9]+[a-z]?)*)\.?\s+(.*)$")
ANY_H2_RE = re.compile(r"^##\s+(\d+)\.")


def parse_spec(spec_path: Path) -> tuple[list[Section], list[str]]:
    """Return (§20 subsections, warnings).

    Only the §20 block is read. Requirement ids are taken from the *first
    column* of each table: ids also appear inside requirement prose (rows
    cross-reference each other constantly) and those are references, not
    definitions.
    """
    warnings: list[str] = []
    lines = spec_path.read_text(encoding="utf-8").splitlines()

    start = end = None
    for i, line in enumerate(lines):
        m = ANY_H2_RE.match(line)
        if not m:
            continue
        if m.group(1) == "20" and start is None:
            start = i
        elif start is not None and m.group(1) != "20":
            end = i
            break
    if start is None:
        raise SystemExit(f"{spec_path}: no '## 20.' heading found — spec shape changed")
    if end is None:
        end = len(lines)

    sections: list[Section] = []
    current: Section | None = None
    parent_deferred = False
    status_idx: int | None = None

    def cells_of(row: str) -> list[str]:
        return [c.strip() for c in row.strip().strip("|").split("|")]

    for offset, line in enumerate(lines[start:end]):
        lineno = start + offset + 1

        m = HEADING_RE.match(line)
        if m:
            status_idx = None
            hashes, number, title = m.groups()
            level = len(hashes)
            if level == 2:
                # The "## 20. Numbered Requirements" heading itself.
                continue
            sec = Section(number, title, level, lineno)
            if level == 3:
                parent_deferred = sec.deferred_heading
            elif level >= 4:
                # A #### under a deferred ### inherits the deferral: the
                # §20.17.x subsections carry no marker of their own.
                sec.deferred_heading = sec.deferred_heading or parent_deferred
            sections.append(sec)
            current = sec
            continue

        if current is None:
            continue

        if line.startswith("| ID |"):
            current.saw_table = True
            header = cells_of(line)
            status_idx = header.index("Status") if "Status" in header else None
            current.has_status_column = status_idx is not None
            continue

        rm = ROW_ID_RE.match(line)
        if rm:
            status = ""
            if status_idx is not None:
                row = cells_of(line)
                # A row that does not split into the header's shape (a literal
                # or escaped pipe inside a cell) yields no Status, and a row
                # with no Status is never carved in. Fail safe: the answer
                # stays the pre-carve-out one rather than becoming a guess.
                if len(row) > status_idx:
                    status = row[status_idx]
            current.rows.append((rm.group(1), status))
            continue

        if CARVE_IN_PROSE_RE.search(line):
            current.carve_in_prose = True

    # Cross-check the structural verdict against the numbering §23.3a
    # states today, and warn rather than silently trusting either one.
    for sec in sections:
        if not sec.saw_table:
            continue
        parts = sec.number.split(".")
        try:
            minor = int(re.sub(r"[a-z]$", "", parts[1]))
        except (IndexError, ValueError):
            continue
        numerically_in_scope = minor <= 15
        if numerically_in_scope != sec.in_scope:
            warnings.append(
                f"§{sec.number} ({sec.title[:60]}) is "
                f"{'IN' if sec.in_scope else 'OUT of'} scope by the structural rule "
                f"(heading marker / Status column) but "
                f"{'IN' if numerically_in_scope else 'OUT of'} scope by §23.3a's "
                f"§20.1–§20.15 numbering. §20's preamble says the marker wins; "
                f"if that is wrong here, the section is mislabelled."
            )

    # §23.3a's own named failure mode: "the rule lives only in this paragraph
    # and the automated answer quietly disagrees with it." The carve-out is
    # stated twice in the spec — once in §20.17.1's prose, once in each row's
    # Status cell — and this check refuses to let either one be the answer
    # alone. Reformat the Status column and the carve-in silently stops
    # firing; that is the shape of every check in this project that could not
    # fail, so it is a warning rather than a green run.
    for sec in sections:
        if sec.in_scope or not sec.saw_table:
            continue
        carved = sec.carved_rows
        if sec.carve_in_prose and not carved:
            warnings.append(
                f"§{sec.number} ({sec.title[:60]}) says in prose that rows here "
                f"count in the §23.3a completeness check, but no row's Status "
                f"cell names a milestone, so none was carved in. Either the "
                f"Status column was reformatted or the carve-out was retired "
                f"without deleting the sentence — the count just moved and "
                f"nothing said so."
            )
        elif carved and not sec.carve_in_prose:
            warnings.append(
                f"§{sec.number} ({sec.title[:60]}) has {len(carved)} row(s) whose "
                f"Status names a milestone ({', '.join(carved)}), so they are "
                f"counted against the ship-list, but this section's prose does "
                f"not state the §23.3a carve-out. Either a Status cell was "
                f"typo'd into scope or a real carve-out is undocumented."
            )

    dupes = {}
    for sec in sections:
        for rid in sec.req_ids:
            dupes.setdefault(rid, []).append(sec.number)
    for rid, where in sorted(dupes.items()):
        if len(where) > 1:
            warnings.append(f"{rid} is defined in more than one section: {', '.join(where)}")

    return sections, warnings


# --------------------------------------------------------------------------
# Plan parsing: who cites what
# --------------------------------------------------------------------------


def expand_range(m: re.Match) -> list[str]:
    prefix, _area, lo_s, _lo_sfx, hi_s, hi_sfx = m.groups()
    width = len(lo_s)
    lo, hi = int(lo_s), int(hi_s)
    if hi < lo or (hi - lo) > MAX_RANGE_SPAN:
        return []
    out = [f"{prefix}{n:0{width}d}" for n in range(lo, hi + 1)]
    if hi_sfx:
        out.append(f"{prefix}{hi:0{width}d}{hi_sfx}")
    return out


def scan_plan(text: str) -> tuple[set[str], set[str], set[str]]:
    """Return (ids cited as owned, ids named only via a range, ids deferred).

    Two things happen per line, and both are about not mistaking a mention
    for a claim:

      * Range spans are blanked before literal ids are scanned, so a range
        never donates a literal citation to its own endpoints.

      * Every citation carries the heading stack it sits under, and one made
        under a heading that hands work away is collected as DEFERRED rather
        than as ownership. An id deferred here and cited normally there is
        owned: the discount is per citation, not per id, so one plan handing
        a requirement to another cannot take it away from the plan that has
        it.

    Fenced blocks are skipped when tracking headings and only then. A shell
    comment reading `# rebuild the fixture` is not an h1, and letting it
    become one would silently end the enclosing section -- which, under a
    deferral heading, means every citation after the block reads as
    ownership again. Ids INSIDE a fence are still scanned: a requirement
    named in a code comment has still been named.
    """
    owned: set[str] = set()
    ranged: set[str] = set()
    deferred: set[str] = set()

    stack: list[tuple[int, str]] = []
    fence: str | None = None
    span: list[str] = []

    def blank(m: re.Match) -> str:
        span.extend(expand_range(m))
        return " " * len(m.group(0))

    for line in text.splitlines():
        fm = PLAN_FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)[0]
            if fence is None:
                fence = tok
            elif tok == fence:
                fence = None
            continue
        if fence is None:
            hm = PLAN_HEADING_RE.match(line)
            if hm:
                level = len(hm.group(1))
                stack = [h for h in stack if h[0] < level] + [(level, hm.group(2))]
                continue

        span.clear()
        literal = set(LITERAL_RE.findall(RANGE_RE.sub(blank, line)))
        if not literal and not span:
            continue
        if any(DEFERRAL_HEADING_RE.search(h) for _, h in stack):
            # A range under a deferral heading is not a span somebody owns
            # either, so it joins the deferred set rather than the ranged one.
            deferred |= literal | set(span)
        else:
            owned |= literal
            ranged |= set(span)

    return owned, ranged, deferred


def scan_plans(plan_paths: list[Path]) -> tuple[dict[str, set[str]],
                                                dict[str, set[str]],
                                                dict[str, set[str]]]:
    literal: dict[str, set[str]] = {}
    ranged: dict[str, set[str]] = {}
    deferred: dict[str, set[str]] = {}
    for p in plan_paths:
        lit, rng, dfr = scan_plan(p.read_text(encoding="utf-8"))
        for rid in lit:
            literal.setdefault(rid, set()).add(p.name)
        for rid in rng:
            ranged.setdefault(rid, set()).add(p.name)
        for rid in dfr:
            deferred.setdefault(rid, set()).add(p.name)
    return literal, ranged, deferred


def scan_crates(root: Path) -> set[str]:
    """Requirement ids named anywhere under crates/.

    A weak signal, and labelled as one everywhere it is reported: it means
    "the id is written down in the source tree", not "the requirement is
    implemented". Its value is in one direction only — an id that is
    *unowned by every plan* and *present in the code* is the REQ-PD-018
    shape, built with no plan carrying its id.
    """
    crates = root / "crates"
    if not crates.is_dir():
        return set()
    found: set[str] = set()
    for path in crates.rglob("*"):
        if not path.is_file() or path.suffix not in {".rs", ".toml", ".md"}:
            continue
        try:
            found.update(LITERAL_RE.findall(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return found


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def build_report(spec_path: Path, plan_paths: list[Path], root: Path) -> dict:
    sections, warnings = parse_spec(spec_path)
    literal, ranged, deferred = scan_plans(plan_paths)
    in_code = scan_crates(root)

    in_scope_sections = [s for s in sections if s.in_scope]
    deferred_sections = [s for s in sections if s.saw_table and not s.in_scope]

    universe: list[tuple[str, str]] = []
    for sec in in_scope_sections:
        for rid in sec.req_ids:
            universe.append((rid, sec.number))

    # §23.3a's row-level carve-out. These rows sit in a section the heading
    # excludes, and they count anyway because their own Status says they are
    # owed. Their neighbours in the same table do not come with them —
    # judgement 5 in the header.
    carved_in: list[dict] = []
    for sec in deferred_sections:
        for rid in sec.carved_rows:
            universe.append((rid, sec.number))
            carved_in.append({"id": rid, "section": sec.number})

    orphans, range_only, deferred_only, owned = [], [], [], []
    for rid, sec_no in universe:
        entry = {
            "id": rid,
            "section": sec_no,
            "cited_by": sorted(literal.get(rid, ())),
            "ranged_by": sorted(ranged.get(rid, ())),
            "deferred_by": sorted(deferred.get(rid, ())),
            "in_crates": rid in in_code,
        }
        # `cited_by` first, and it is the whole of the ownership test: an id
        # deferred by one plan and claimed by another is owned. `range_only`
        # keeps its precedence over `deferred_only` because a plan writing
        # `A..B` was at least attempting to cover the span, where a deferral
        # citation is an explicit statement that somebody else covers it.
        if entry["cited_by"]:
            owned.append(entry)
        elif entry["ranged_by"]:
            range_only.append(entry)
        elif entry["deferred_by"]:
            deferred_only.append(entry)
        else:
            orphans.append(entry)

    # Per-area coverage. This is the cheap half of "unowned vs
    # owned-but-unimplemented". A REQ->milestone map would be the precise
    # answer, but §23.3a forbids building one from §23.2's Contents column
    # ("not a completeness check and must not become a second enumeration"),
    # and nothing else in the spec carries the mapping. Area coverage is
    # what is available without inventing that second enumeration: an area
    # at 0/N has no plan written yet, so its rows are unowned but expected;
    # an area with holes is a plan that shipped without them.
    areas: dict[str, dict] = {}
    for rid, _ in universe:
        area = rid.rsplit("-", 1)[0]
        a = areas.setdefault(area, {"total": 0, "owned": 0, "unowned": 0})
        a["total"] += 1
        if literal.get(rid):
            a["owned"] += 1
        else:
            a["unowned"] += 1

    return {
        "spec": str(spec_path),
        "plans": [p.name for p in plan_paths],
        "areas": areas,
        "sections_in_scope": [s.number for s in in_scope_sections],
        "sections_excluded": [s.number for s in deferred_sections],
        "rows_carved_in": carved_in,
        "warnings": warnings,
        "counts": {
            "requirements_in_scope": len(universe),
            "owned": len(owned),
            "unowned": len(orphans) + len(range_only) + len(deferred_only),
            "orphan": len(orphans),
            "range_only": len(range_only),
            "deferred_only": len(deferred_only),
            "orphan_but_in_crates": sum(1 for e in orphans if e["in_crates"]),
            "owned_not_in_crates": sum(1 for e in owned if not e["in_crates"]),
        },
        "orphans": orphans,
        "range_only": range_only,
        "deferred_only": deferred_only,
    }


def render(report: dict) -> str:
    c = report["counts"]
    out: list[str] = []
    w = out.append

    w("Holdfast orphan-requirement check")
    w("=" * 66)
    w(f"spec:     {report['spec']}")
    w(f"plans:    {len(report['plans'])}")
    w(f"in scope: §{', §'.join(report['sections_in_scope'])}")
    w(f"excluded: §{', §'.join(report['sections_excluded'])}  (post-v0.1.0, per §20 preamble)")
    if report["rows_carved_in"]:
        secs = sorted({e["section"] for e in report["rows_carved_in"]})
        w(f"carved in: {', '.join(e['id'] for e in report['rows_carved_in'])}")
        w(f"           — rows in §{', §'.join(secs)} whose own Status names a")
        w( "             milestone. §23.3a: deferral is a status, not a location.")
        w( "             Every OTHER row in those sections stays excluded.")
    w("")
    w(f"  requirements in scope ....... {c['requirements_in_scope']}")
    w(f"  owned by >=1 plan ........... {c['owned']}")
    w(f"  UNOWNED ..................... {c['unowned']}")
    w(f"      named by no plan ........ {c['orphan']}")
    w(f"      named only in a range ... {c['range_only']}")
    w(f"      named only to defer it .. {c['deferred_only']}")
    w("")
    w(f"  of the unowned, already named in crates/: {c['orphan_but_in_crates']}")
    w(f"  of the owned, not named in crates/:       {c['owned_not_in_crates']}"
      "   (owned-but-unbuilt; not a finding)")

    for warn in report["warnings"]:
        w("")
        w(f"WARNING: {warn}")

    if report["orphans"]:
        w("")
        w("ORPHANED — named by no plan")
        w("-" * 66)
        for e in report["orphans"]:
            tag = "  [id present in crates/]" if e["in_crates"] else ""
            w(f"  {e['id']:<16} §{e['section']}{tag}")

    if report["range_only"]:
        w("")
        w("RANGE-ONLY — covered by a plan's `A..B` span, named individually by none")
        w("-" * 66)
        for e in report["range_only"]:
            tag = "  [id present in crates/]" if e["in_crates"] else ""
            w(f"  {e['id']:<16} §{e['section']}  via {', '.join(e['ranged_by'])}{tag}")

    if report["deferred_only"]:
        w("")
        w("DEFERRED-ONLY — every plan that names this id names it under a heading")
        w("that hands the work away, so no plan has claimed it. This is the most")
        w("actionable class of the three: the id is known, its owner is named in")
        w("prose, and no plan carries it.")
        w("-" * 66)
        for e in report["deferred_only"]:
            tag = "  [id present in crates/]" if e["in_crates"] else ""
            w(f"  {e['id']:<16} §{e['section']}  deferred by "
              f"{', '.join(e['deferred_by'])}{tag}")

    if not (report["orphans"] or report["range_only"] or report["deferred_only"]):
        w("")
        w("Every in-scope requirement is named by at least one plan.")

    w("")
    w("BY AREA — an area at 0 owned has no plan written yet (unowned but")
    w("expected); an area with holes is a plan that shipped without them.")
    w("-" * 66)
    for area, a in sorted(report["areas"].items(), key=lambda kv: -kv[1]["unowned"]):
        if not a["unowned"]:
            continue
        note = "  <- no plan covers this area at all" if a["owned"] == 0 else ""
        w(f"  {area:<10} {a['owned']:>3}/{a['total']:<3} owned, "
          f"{a['unowned']:>2} unowned{note}")

    return "\n".join(out)


# --------------------------------------------------------------------------
# Self-test: the check has to be able to fail
# --------------------------------------------------------------------------


SELF_TEST_SPEC = """\
# Fake spec

## 19. Something Else

## 20. Numbered Requirements

Deferred sections use a `Verification` column rather than `Tests`.

### 20.1 Alpha (REQ-ZZA)

| ID | Requirement | Spec | Tests |
|---|---|---|---|
| REQ-ZZA-001 | a plan names this one outright | §1 | unit |
| REQ-ZZA-002 | nothing names this at all | §1 | unit |
| REQ-ZZA-003 | named only as a range endpoint | §1 | unit |
| REQ-ZZA-004 | named only inside a range | §1 | unit |
| REQ-ZZA-005 | named only inside a range | §1 | unit |

### 20.2 Beta (REQ-ZZB)

| ID | Requirement | Spec | Tests |
|---|---|---|---|
| REQ-ZZB-001 | mentioned in another row's prose, see REQ-ZZA-002 | §1 | unit |

### 20.3 Gamma (REQ-ZZC)

| ID | Requirement | Spec | Tests |
|---|---|---|---|
| REQ-ZZC-001 | named only under "Deliberately not covered here" | §1 | unit |
| REQ-ZZC-002 | named only under "Re-asserted here, owned elsewhere" | §1 | unit |
| REQ-ZZC-003 | named only under a "Scope boundaries" heading | §1 | unit |
| REQ-ZZC-004 | deferred in one place and claimed in another, same plan | §1 | unit |
| REQ-ZZC-005 | named under an OWNERSHIP heading containing "deferred" | §1 | unit |
| REQ-ZZC-006 | deferred, after a fenced block holding a `#` comment | §1 | unit |
| REQ-ZZC-007 | deferred by one plan and owned by another | §1 | unit |
| REQ-ZZC-008 | deferred by an ANCESTOR heading, not the innermost one | §1 | unit |
| REQ-ZZC-009 | claimed in a section that OPENS after a deferral one closes | §1 | unit |

### 20.16 Deferred things (REQ-ZZS) — post-v0.1.0

> Excluded from the v0.1.0 completeness check.

| ID | Requirement | Spec | Status | Verification |
|---|---|---|---|---|
| REQ-ZZS-001 | must never be reported as an orphan | §1 | v0.2 | manual |
| REQ-ZZS-002 | must never be reported as an orphan | §1 | v0.2 | manual |

### 20.17 Roadmap requirements (REQ-ZZT, REQ-ZZR) — post-v0.1.0

#### 20.17.1 One scheduled item and one that is not (REQ-ZZT)

> **REQ-ZZT-001..002 are the one part of §20.17 that is not deferred.** Their
> item became a milestone, so they count in the §23.3a completeness check.
> REQ-ZZT-003 is unaffected and stays speculative.

| ID | Requirement | Spec | Status | Verification |
|---|---|---|---|---|
| REQ-ZZT-001 | OWED: Status names a milestone, and no plan names it | §1 | **0.0.10a** (§23.2) | integration |
| REQ-ZZT-002 | OWED: Status names a milestone, and a plan does name it | §1 | **0.0.10a** (§23.2) | integration |
| REQ-ZZT-003 | NOT owed: speculative, in the SAME table as the two above | §1 | speculative (§14.3) | manual |
| REQ-ZZT-004 | NOT owed: a §14 tier whose cell contains a 3-part § ref | §1 | §14.3, §9.3.2 | manual |

#### 20.17.2 Ordinary deferred things (REQ-ZZR)

| ID | Requirement | Spec | Status | Verification |
|---|---|---|---|---|
| REQ-ZZR-001 | must never be reported: a sibling's carve-out is not ours | §1 | v0.2 (§14.1) | manual |
| REQ-ZZR-002 | must never be reported: a sibling's carve-out is not ours | §1 | v0.3–v0.5 (§14.2) | manual |

## 21. Rollout
"""

SELF_TEST_PLAN = """\
# Fake plan

Task 1 implements REQ-ZZA-001 and asserts it.

Deliberately not covered here: REQ-ZZA-003..005 (a later milestone owns them).

Task 2 quotes the spec's REQ-ZZB-001 row.

## Requirements covered

### Primary — this plan is the owner

| REQ | Covered by |
|---|---|
| REQ-ZZC-004 | Task 1, and it is claimed here as well as deferred below |

### Two items 0.0.1 deferred to this milestone — decided

An OWNERSHIP heading that contains the word "deferred", because that is what
happened: 0.0.1 deferred REQ-ZZC-005 and this plan picked it up. A pattern
matching the bare word turns this row into an orphan no plan can close.

### Re-asserted here, owned elsewhere

| REQ | Owner |
|---|---|
| REQ-ZZC-002 | some other plan |
| REQ-ZZC-004 | some other plan, but Task 1 above claims it too |

### Deliberately not covered here

- **Another milestone:** REQ-ZZC-001, REQ-ZZC-007.

The fence below holds a line that looks like an h1. If it ended this section,
every citation after it would read as ownership again:

```sh
# rebuild the fixture
grep -c REQ- spec.md
```

- **Also another milestone:** REQ-ZZC-006.

## Scope boundaries — deliberately NOT in this plan

REQ-ZZC-003 belongs to a later milestone.

### Later milestones, one by one

REQ-ZZC-008 is a Windows one. The heading directly above this line says
nothing about deferral — the section that defers it is its PARENT — so a
gate reading only the innermost heading calls this ownership.

## Decisions taken where the spec was silent

REQ-ZZC-009 is claimed here, in a section that opens after two deferral
sections have closed. A gate that never pops the heading stack has this
plan deferring everything from its first deferral heading to the end of
the file, which is most of a real plan.
"""

# The other half of the real shape: 0.0.7 defers REQ-W-001 and 0.0.10 owns
# it, so the id is owned. The discount is per CITATION -- one plan handing a
# requirement away cannot take it from the plan that has it.
SELF_TEST_PLAN_OWNER = """\
# Fake owning plan

## Requirements covered

| REQ | Covered by |
|---|---|
| REQ-ZZC-007 | Task 1 |
| REQ-ZZT-002 | Task 2 — a carved-in row that IS owned |
"""

# Everything named literally, under no heading at all: the negative control
# for the whole check, kept in its own file because appending to the plan
# above would land the ids under its last (deferral) heading.
SELF_TEST_PLAN_ALL = """\
# Fake exhaustive plan

REQ-ZZA-002 REQ-ZZA-003 REQ-ZZA-004 REQ-ZZA-005 REQ-ZZB-001
REQ-ZZC-001 REQ-ZZC-002 REQ-ZZC-003 REQ-ZZC-006 REQ-ZZC-007 REQ-ZZC-008
REQ-ZZT-001
"""


def self_test() -> int:
    failures: list[str] = []

    def check(name: str, got, want):
        if got == want:
            print(f"  PASS  {name}")
            print(f"          got {got!r}")
        else:
            print(f"  FAIL  {name}")
            print(f"          want {want!r}")
            print(f"          got  {got!r}")
            failures.append(name)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        specs = root / "docs" / "superpowers" / "specs"
        plans = root / "docs" / "superpowers" / "plans"
        specs.mkdir(parents=True)
        plans.mkdir(parents=True)
        spec = specs / "0000-00-00-holdfast-design.md"
        spec.write_text(SELF_TEST_SPEC, encoding="utf-8")
        (plans / "fake-plan.md").write_text(SELF_TEST_PLAN, encoding="utf-8")
        (plans / "owner-plan.md").write_text(SELF_TEST_PLAN_OWNER, encoding="utf-8")

        rep = build_report(spec, sorted(plans.glob("*.md")), root)
        orphan_ids = [e["id"] for e in rep["orphans"]]
        range_ids = [e["id"] for e in rep["range_only"]]
        deferred_ids = [e["id"] for e in rep["deferred_only"]]
        reported = set(orphan_ids) | set(range_ids) | set(deferred_ids)

        print("Self-test — synthetic spec and plan\n")

        check("an uncited requirement is reported as ORPHAN (REQ-ZZA-002 in "
              "scope by heading, REQ-ZZT-001 by §23.3a's row-level carve-out)",
              sorted(orphan_ids), ["REQ-ZZA-002", "REQ-ZZT-001"])

        check("a literally-cited requirement is NOT reported",
              "REQ-ZZA-001" in reported, False)

        check("a requirement the plan names inside a quoted spec row still "
              "counts as owned (REQ-ZZB-001)",
              "REQ-ZZB-001" in reported, False)

        # §20 rows cross-reference each other constantly: REQ-ZZB-001's
        # requirement text names REQ-ZZA-002. If prose ids were read as
        # definitions, REQ-ZZA-002 would be "defined" in both §20.1 and
        # §20.2 and the duplicate-definition warning would fire. A silent
        # warning list is the assertion that only the id column is read.
        check("ids in another row's prose are not definitions "
              "(no duplicate-definition warning)",
              rep["warnings"], [])

        # The load-bearing one. `REQ-ZZA-003..005` contains the literal
        # substring `REQ-ZZA-003`; if range spans were not blanked before
        # the literal scan, 003 would come back "owned" and only 004/005
        # would be reported. Asserting the *class* is what makes this
        # sensitive to that bug rather than to mere presence.
        check("all three ids in `REQ-ZZA-003..005` are RANGE-ONLY, "
              "including the first endpoint",
              sorted(range_ids), ["REQ-ZZA-003", "REQ-ZZA-004", "REQ-ZZA-005"])

        # ------------------------------------------------------------------
        # DEFERRAL vs OWNERSHIP. A plan cites an id both to claim it and to
        # hand it away, and scoring the second as the first is what made
        # "191 of 192 owned" mean "every requirement is mentioned somewhere".
        # ------------------------------------------------------------------

        check("an id named only under \"Deliberately not covered here\" is "
              "DEFERRED-ONLY, not owned",
              ("REQ-ZZC-001" in set(deferred_ids), "REQ-ZZC-001" in reported),
              (True, True))

        check("an id named only under \"Re-asserted here, owned elsewhere\" "
              "is DEFERRED-ONLY",
              "REQ-ZZC-002" in set(deferred_ids), True)

        check("an id named only under a \"Scope boundaries\" heading is "
              "DEFERRED-ONLY, and that heading's scope runs to the next "
              "same-level heading",
              "REQ-ZZC-003" in set(deferred_ids), True)

        # THE NEGATIVE CONTROLS. Without these the fix could discount every
        # citation in the corpus and every assertion above would still pass.
        check("an id claimed under an ownership heading AND deferred under "
              "another in the same plan is OWNED (the discount is per "
              "citation, not per id)",
              "REQ-ZZC-004" in reported, False)

        # The precision control, and the reason the pattern is a phrase list
        # rather than the word "deferred": this corpus really does have a
        # heading reading "Two items 0.0.1 deferred to this milestone —
        # decided", which is a statement of ownership.
        check("an ownership heading that happens to contain the word "
              "\"deferred\" does NOT discount its citations",
              "REQ-ZZC-005" in reported, False)

        check("an id deferred by one plan and claimed by another is OWNED",
              "REQ-ZZC-007" in reported, False)

        # THE STACK, both ends of it. A deferral heading defers its whole
        # subtree, and it stops at the next same-or-higher heading. Both are
        # shapes a real plan has: 0.0.7's `Deliberately not covered here` is
        # followed by `## Decisions taken where the spec was silent`, which
        # cites requirements it does own.
        check("an id under a SUBHEADING of a deferral section is deferred "
              "(the whole stack is consulted, not just the innermost heading)",
              "REQ-ZZC-008" in set(deferred_ids), True)

        check("an id in a section that OPENS after a deferral section closes "
              "is OWNED (a deferral heading's scope ends)",
              "REQ-ZZC-009" in reported, False)

        # THE FENCE. A `# rebuild the fixture` line inside a shell block is
        # not an h1. If it ended the enclosing deferral section, every
        # citation after the block would read as ownership -- and a plan's
        # deferral list routinely has code in it.
        check("a `#` comment inside a fenced block does not end the "
              "enclosing deferral section",
              "REQ-ZZC-006" in set(deferred_ids), True)

        # ...and the sentence/heading line. This fixture's prose says
        # "Deliberately not covered here: REQ-ZZA-003..005" in a paragraph,
        # and it is NOT discounted: the signal read is a heading, which an
        # author declares once and a reviewer can see, not a sentence, which
        # appears in argument as often as in declaration.
        check("the same words in PROSE rather than in a heading do not "
              "discount (REQ-ZZA-003..005 stays RANGE-ONLY)",
              sorted(deferred_ids), ["REQ-ZZC-001", "REQ-ZZC-002",
                                     "REQ-ZZC-003", "REQ-ZZC-006",
                                     "REQ-ZZC-008"])

        check("no post-v0.1.0 (§20.16) row is reported",
              [i for i in reported if i.startswith("REQ-ZZS")], [])

        check("§20.16 is recognised as excluded, and so are the §20.17.x "
              "subsections that inherit the marker from their parent",
              rep["sections_excluded"], ["20.16", "20.17.1", "20.17.2"])

        check("counts are reported, not just names",
              (rep["counts"]["requirements_in_scope"],
               rep["counts"]["owned"],
               rep["counts"]["unowned"],
               rep["counts"]["orphan"],
               rep["counts"]["range_only"],
               rep["counts"]["deferred_only"]),
              (17, 7, 10, 2, 3, 5))

        # ------------------------------------------------------------------
        # §23.3a'S ROW-LEVEL CARVE-OUT (rev. 50). The heading over §20.17.1
        # says deferred and for two rows out of four it is right; the other
        # two rows' Status says otherwise, and the Status wins, because
        # "deferral is a status, not a location". A section-level answer
        # cannot express this in either direction -- which is the point. A
        # carve-out that dragged its neighbours in, or one that silenced
        # them, would be a section rule wearing a row-level costume.
        # ------------------------------------------------------------------

        check("a row in a deferred section whose Status names a MILESTONE is "
              "carved in, and is reported when no plan names it",
              "REQ-ZZT-001" in set(orphan_ids), True)

        check("the carve-in is ROW-level: a speculative row in the SAME table "
              "stays excluded, and so does one whose tier cell happens to "
              "contain a three-part § reference",
              sorted(i for i in reported if i.startswith("REQ-ZZT")
                     and i not in {"REQ-ZZT-001", "REQ-ZZT-002"}),
              [])

        check("a sibling deferred subsection is not dragged in by §20.17.1's "
              "carve-out",
              [i for i in reported if i.startswith("REQ-ZZR")], [])

        check("the carve-in is reported explicitly — exactly which rows it "
              "promoted, and out of where",
              sorted((e["id"], e["section"]) for e in rep["rows_carved_in"]),
              [("REQ-ZZT-001", "20.17.1"), ("REQ-ZZT-002", "20.17.1")])

        check("a carved-in row that a plan DOES name is owned, not reported "
              "(the carve-out puts rows in scope; it does not fail them)",
              "REQ-ZZT-002" in reported, False)

        # Mutation: delete the deferred marker from the excluded section and
        # its rows must become findings. A check that reports the same thing
        # either way is not reading the marker.
        mutated = SELF_TEST_SPEC.replace(
            "### 20.16 Deferred things (REQ-ZZS) — post-v0.1.0",
            "### 20.16 Deferred things (REQ-ZZS)",
        ).replace(
            "| ID | Requirement | Spec | Status | Verification |\n|---|---|---|---|---|",
            "| ID | Requirement | Spec | Tests |\n|---|---|---|---|",
            1,  # §20.16's table comes first; the §20.17 tables share this
                # header and are not what this mutation is about.
        )
        spec.write_text(mutated, encoding="utf-8")
        mrep = build_report(spec, sorted(plans.glob("*.md")), root)
        mut_ids = {e["id"] for e in mrep["orphans"]}
        check("MUTATION — with the deferred marker and Status column removed, "
              "the same rows DO get reported (the exclusion is load-bearing)",
              sorted(i for i in mut_ids if i.startswith("REQ-ZZS")),
              ["REQ-ZZS-001", "REQ-ZZS-002"])

        # Mutation: the STATUS CELL is the carve-in's gate. Retier the two
        # milestone rows, change nothing else, and they must leave the
        # universe entirely. Without this, a carve-in hardcoded to a literal
        # id list would pass every carve-out assertion above and would go on
        # firing forever after the milestone shipped -- which is the "an
        # exemption with no expiry becomes permanent" failure, and it is the
        # one a checker fix is most likely to introduce.
        spec.write_text(
            SELF_TEST_SPEC.replace("**0.0.10a** (§23.2)", "v0.9 (§14.1)"),
            encoding="utf-8")
        srep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — with the milestone Status retiered, the carved rows "
              "leave scope (the Status cell is the gate, not a hardcoded list)",
              (srep["rows_carved_in"],
               [e["id"] for e in srep["orphans"] if e["id"].startswith("REQ-ZZT")]),
              ([], []))

        # ...and that retirement must not be SILENT. §23.3a's named failure
        # mode is the prose and the tooling quietly disagreeing; here the
        # blockquote still claims the carve-out and no row backs it up.
        check("MUTATION — a silently-retired carve-out is a WARNING, not a "
              "quiet green: §20.17.1's prose and its Status column disagree",
              [w for w in srep["warnings"]
               if "20.17.1" in w and "23.3a completeness check" in w] != [],
              True)

        # Mutation: the carve-out expires by being SATISFIED, with no edit to
        # this script. This is the whole of the "until a 0.0.10a plan exists"
        # expiry -- nothing has to remember to delete an exemption, because
        # there is no exemption: the row is in scope and simply becomes owned.
        spec.write_text(SELF_TEST_SPEC, encoding="utf-8")
        (plans / "milestone-plan.md").write_text(
            "# Fake milestone plan\n\n## Requirements covered\n\n"
            "| REQ | Covered by |\n|---|---|\n| REQ-ZZT-001 | Task 1 |\n",
            encoding="utf-8")
        prep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — a plan naming the carved-in id closes it with no "
              "change here (the carve-out expires by being satisfied, and the "
              "row stays in scope afterwards rather than vanishing)",
              ([e["id"] for e in prep["orphans"]],
               sorted(e["id"] for e in prep["rows_carved_in"])),
              (["REQ-ZZA-002"], ["REQ-ZZT-001", "REQ-ZZT-002"]))
        (plans / "milestone-plan.md").unlink()

        # Mutation: the deferral headings are the gate. Retitle them as
        # ordinary section headings, change nothing else, and every id they
        # cover must come back OWNED. A check that reported the same either
        # way would not be reading them.
        spec.write_text(SELF_TEST_SPEC, encoding="utf-8")
        (plans / "fake-plan.md").write_text(
            SELF_TEST_PLAN
            .replace("### Deliberately not covered here", "### Also covered")
            .replace("### Re-asserted here, owned elsewhere", "### Also mine")
            .replace("## Scope boundaries — deliberately NOT in this plan",
                     "## More of it"),
            encoding="utf-8")
        drep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — with the deferral headings retitled as ordinary "
              "sections, their ids come back OWNED (the headings are the gate)",
              (drep["counts"]["deferred_only"],
               sorted(e["id"] for e in drep["orphans"] + drep["range_only"]
                      + drep["deferred_only"] if e["id"].startswith("REQ-ZZC"))),
              (0, []))

        # Mutation: the other direction, and the real shape — 0.0.7 defers
        # REQ-W-001 and 0.0.10 owns it. Withdraw the owning plan and the id
        # must fall to DEFERRED-ONLY rather than staying discharged by the
        # plan that gave it away. This is the corpus case in miniature: the
        # nine REQ-W ids read as owned from before the plan that owns them
        # existed.
        (plans / "fake-plan.md").write_text(SELF_TEST_PLAN, encoding="utf-8")
        (plans / "owner-plan.md").unlink()
        wrep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — with the OWNING plan withdrawn, the id it owned "
              "falls to DEFERRED-ONLY instead of staying owned by the plan "
              "that handed it away",
              sorted(e["id"] for e in wrep["deferred_only"]),
              ["REQ-ZZC-001", "REQ-ZZC-002", "REQ-ZZC-003", "REQ-ZZC-006",
               "REQ-ZZC-007", "REQ-ZZC-008"])

        # Mutation: a plan that names everything must leave nothing behind.
        # In its own file, under no heading: appending to the plan above
        # would land the ids under its last section, which is a deferral one.
        (plans / "owner-plan.md").write_text(SELF_TEST_PLAN_OWNER,
                                             encoding="utf-8")
        (plans / "all-ids.md").write_text(SELF_TEST_PLAN_ALL, encoding="utf-8")
        crep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — when every id is named literally, the check is clean "
              "(it is not reporting unconditionally)",
              (crep["counts"]["unowned"], crep["orphans"], crep["range_only"],
               crep["deferred_only"]),
              (0, [], [], []))

    print()
    if failures:
        print(f"SELF-TEST FAILED: {len(failures)} of the above")
        return EXIT_ERROR
    print("SELF-TEST PASSED — the check discriminates in both directions")
    return EXIT_OK


# --------------------------------------------------------------------------
# Hook installation
# --------------------------------------------------------------------------


HOOK_BODY = """\
#!/bin/sh
# Installed by holdfast/scripts/orphan-req-check.py --install-hook
#
# The spec lives in this repository, not in the one CI checks out, so this
# is the only place the drift event -- a spec revision -- is observable.
# Non-blocking on purpose: a transient orphan is normal mid-revision. The
# number is the point.
exec "%(script)s" --repo-root "%(root)s" || true
"""


def install_hook(root: Path, script: Path) -> int:
    docs_git = root / "docs" / ".git"
    if not docs_git.exists():
        print(f"error: no git repository at {root / 'docs'}", file=sys.stderr)
        return EXIT_ERROR
    hooks = docs_git / "hooks" if docs_git.is_dir() else None
    if hooks is None:
        print(f"error: {docs_git} is not a directory (worktree/submodule?)", file=sys.stderr)
        return EXIT_ERROR
    hooks.mkdir(exist_ok=True)
    hook = hooks / "post-commit"
    if hook.exists():
        print(f"error: {hook} already exists; not overwriting. Merge by hand.", file=sys.stderr)
        return EXIT_ERROR
    hook.write_text(HOOK_BODY % {"script": script.resolve(), "root": root.resolve()},
                    encoding="utf-8")
    hook.chmod(0o755)
    print(f"installed {hook}")
    print("It runs after every commit in the docs repo and never blocks one.")
    return EXIT_OK


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Report §20 requirements that no implementation plan owns.")
    ap.add_argument("--repo-root", type=Path, default=None,
                    help="holdfast checkout (default: this script's parent repo)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true",
                    help="run the check against synthetic fixtures with known answers")
    ap.add_argument("--install-hook", action="store_true",
                    help="install a post-commit hook into the docs repo")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    script = Path(__file__).resolve()
    root = (args.repo_root or script.parent.parent).resolve()

    if args.install_hook:
        return install_hook(root, script)

    specs_dir = root / "docs" / "superpowers" / "specs"
    plans_dir = root / "docs" / "superpowers" / "plans"

    if not specs_dir.is_dir() or not plans_dir.is_dir():
        print(
            f"CANNOT RUN: no spec at {specs_dir}.\n"
            "\n"
            "`docs/` is git-ignored in this repository and lives in a separate\n"
            "git repo, so a clone -- including whatever CI checks out -- does\n"
            "not have it. This is not a pass: nothing was checked. Run this\n"
            "where the docs repo is present, or `git clone` it into ./docs.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    specs = sorted(specs_dir.glob("*-holdfast-design.md"))
    if len(specs) != 1:
        print(f"error: expected exactly one *-holdfast-design.md in {specs_dir}, "
              f"found {len(specs)}: {[p.name for p in specs]}", file=sys.stderr)
        return EXIT_ERROR

    plans = sorted(plans_dir.glob("*.md"))
    if not plans:
        print(f"error: no plans in {plans_dir} — refusing to report every "
              f"requirement as an orphan", file=sys.stderr)
        return EXIT_ERROR

    report = build_report(specs[0], plans, root)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render(report))

    return EXIT_FINDINGS if report["counts"]["unowned"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
