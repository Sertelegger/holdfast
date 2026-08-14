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
# THREE JUDGEMENTS, STATED RATHER THAN IMPLIED:
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
        self.req_ids: list[str] = []

    @property
    def in_scope(self) -> bool:
        return self.saw_table and not self.deferred_heading and not self.has_status_column


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

    for offset, line in enumerate(lines[start:end]):
        lineno = start + offset + 1

        m = HEADING_RE.match(line)
        if m:
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
            if "| Status |" in line:
                current.has_status_column = True
            continue

        rm = ROW_ID_RE.match(line)
        if rm:
            current.req_ids.append(rm.group(1))

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


def scan_plan(text: str) -> tuple[set[str], set[str]]:
    """Return (literally cited ids, ids named only via range notation).

    Range spans are removed from the text before literal ids are scanned,
    so a range never donates a literal citation to its own endpoints.
    """
    ranged: set[str] = set()

    def blank(m: re.Match) -> str:
        ranged.update(expand_range(m))
        return " " * len(m.group(0))

    stripped = RANGE_RE.sub(blank, text)
    literal = set(LITERAL_RE.findall(stripped))
    return literal, ranged


def scan_plans(plan_paths: list[Path]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    literal: dict[str, set[str]] = {}
    ranged: dict[str, set[str]] = {}
    for p in plan_paths:
        lit, rng = scan_plan(p.read_text(encoding="utf-8"))
        for rid in lit:
            literal.setdefault(rid, set()).add(p.name)
        for rid in rng:
            ranged.setdefault(rid, set()).add(p.name)
    return literal, ranged


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
    literal, ranged = scan_plans(plan_paths)
    in_code = scan_crates(root)

    in_scope_sections = [s for s in sections if s.in_scope]
    deferred_sections = [s for s in sections if s.saw_table and not s.in_scope]

    universe: list[tuple[str, str]] = []
    for sec in in_scope_sections:
        for rid in sec.req_ids:
            universe.append((rid, sec.number))

    orphans, range_only, owned = [], [], []
    for rid, sec_no in universe:
        entry = {
            "id": rid,
            "section": sec_no,
            "cited_by": sorted(literal.get(rid, ())),
            "ranged_by": sorted(ranged.get(rid, ())),
            "in_crates": rid in in_code,
        }
        if entry["cited_by"]:
            owned.append(entry)
        elif entry["ranged_by"]:
            range_only.append(entry)
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
        "warnings": warnings,
        "counts": {
            "requirements_in_scope": len(universe),
            "owned": len(owned),
            "unowned": len(orphans) + len(range_only),
            "orphan": len(orphans),
            "range_only": len(range_only),
            "orphan_but_in_crates": sum(1 for e in orphans if e["in_crates"]),
            "owned_not_in_crates": sum(1 for e in owned if not e["in_crates"]),
        },
        "orphans": orphans,
        "range_only": range_only,
    }


def render(report: dict) -> str:
    c = report["counts"]
    out: list[str] = []
    w = out.append

    w("CLASP orphan-requirement check")
    w("=" * 66)
    w(f"spec:     {report['spec']}")
    w(f"plans:    {len(report['plans'])}")
    w(f"in scope: §{', §'.join(report['sections_in_scope'])}")
    w(f"excluded: §{', §'.join(report['sections_excluded'])}  (post-v0.1.0, per §20 preamble)")
    w("")
    w(f"  requirements in scope ....... {c['requirements_in_scope']}")
    w(f"  owned by >=1 plan ........... {c['owned']}")
    w(f"  UNOWNED ..................... {c['unowned']}")
    w(f"      named by no plan ........ {c['orphan']}")
    w(f"      named only in a range ... {c['range_only']}")
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

    if not report["orphans"] and not report["range_only"]:
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

### 20.16 Deferred things (REQ-ZZS) — post-v0.1.0

> Excluded from the v0.1.0 completeness check.

| ID | Requirement | Spec | Status | Verification |
|---|---|---|---|---|
| REQ-ZZS-001 | must never be reported as an orphan | §1 | v0.2 | manual |
| REQ-ZZS-002 | must never be reported as an orphan | §1 | v0.2 | manual |

## 21. Rollout
"""

SELF_TEST_PLAN = """\
# Fake plan

Task 1 implements REQ-ZZA-001 and asserts it.

Deliberately not covered here: REQ-ZZA-003..005 (a later milestone owns them).

Task 2 quotes the spec's REQ-ZZB-001 row.
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
        spec = specs / "0000-00-00-clasp-design.md"
        spec.write_text(SELF_TEST_SPEC, encoding="utf-8")
        (plans / "fake-plan.md").write_text(SELF_TEST_PLAN, encoding="utf-8")

        rep = build_report(spec, sorted(plans.glob("*.md")), root)
        orphan_ids = [e["id"] for e in rep["orphans"]]
        range_ids = [e["id"] for e in rep["range_only"]]
        reported = set(orphan_ids) | set(range_ids)

        print("Self-test — synthetic spec and plan\n")

        check("an uncited requirement is reported as ORPHAN",
              orphan_ids, ["REQ-ZZA-002"])

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

        check("no post-v0.1.0 (§20.16) row is reported",
              [i for i in reported if i.startswith("REQ-ZZS")], [])

        check("§20.16 is recognised as excluded",
              rep["sections_excluded"], ["20.16"])

        check("counts are reported, not just names",
              (rep["counts"]["requirements_in_scope"],
               rep["counts"]["unowned"],
               rep["counts"]["orphan"],
               rep["counts"]["range_only"]),
              (6, 4, 1, 3))

        # Mutation: delete the deferred marker from the excluded section and
        # its rows must become findings. A check that reports the same thing
        # either way is not reading the marker.
        mutated = SELF_TEST_SPEC.replace(
            "### 20.16 Deferred things (REQ-ZZS) — post-v0.1.0",
            "### 20.16 Deferred things (REQ-ZZS)",
        ).replace(
            "| ID | Requirement | Spec | Status | Verification |\n|---|---|---|---|---|",
            "| ID | Requirement | Spec | Tests |\n|---|---|---|---|",
        )
        spec.write_text(mutated, encoding="utf-8")
        mrep = build_report(spec, sorted(plans.glob("*.md")), root)
        mut_ids = {e["id"] for e in mrep["orphans"]}
        check("MUTATION — with the deferred marker and Status column removed, "
              "the same rows DO get reported (the exclusion is load-bearing)",
              sorted(i for i in mut_ids if i.startswith("REQ-ZZS")),
              ["REQ-ZZS-001", "REQ-ZZS-002"])

        # Mutation: a plan that names everything must leave nothing behind.
        spec.write_text(SELF_TEST_SPEC, encoding="utf-8")
        (plans / "fake-plan.md").write_text(
            SELF_TEST_PLAN + "\nAlso: REQ-ZZA-002 REQ-ZZA-003 REQ-ZZA-004 "
            "REQ-ZZA-005 REQ-ZZB-001\n",
            encoding="utf-8",
        )
        crep = build_report(spec, sorted(plans.glob("*.md")), root)
        check("MUTATION — when every id is named literally, the check is clean "
              "(it is not reporting unconditionally)",
              (crep["counts"]["unowned"], crep["orphans"], crep["range_only"]),
              (0, [], []))

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
# Installed by clasp/scripts/orphan-req-check.py --install-hook
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
                    help="clasp checkout (default: this script's parent repo)")
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

    specs = sorted(specs_dir.glob("*-clasp-design.md"))
    if len(specs) != 1:
        print(f"error: expected exactly one *-clasp-design.md in {specs_dir}, "
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
