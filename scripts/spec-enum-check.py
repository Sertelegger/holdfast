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
# THE TWO JUDGEMENTS, STATED RATHER THAN IMPLIED
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
#    WHAT MAY GO IN THE LEDGER, AND WHAT MAY NOT. Only a kind whose FEATURE
#    is unbuilt. A kind belonging to a feature that SHIPS and is simply not
#    writing its entry is a defect, not a deferral, and ledgering it would
#    be the P5 failure this file exists to oppose — a guard holding a stale
#    sentence in place. Such a kind stays a finding and this check stays
#    red until someone writes the call site or files the issue and records
#    it here with the real reason. That is affordable precisely because the
#    real run is not a CI gate (see WHERE THIS RUNS); only `--self-test`
#    is, and it is green.
#
# 2. PARENTHETICALS ARE NOT MEMBERS. §12.6 annotates entries inline —
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
# * §9.4: "written" means the kind's string literal appears in production
#   Rust. It does NOT mean the call site is reachable, correct, on the right
#   path, or that its `Extra fields` match the spec's second column. A
#   writer behind an `if false` counts. The second column is not read at all.
# * §9.4: test code is stripped by a HEURISTIC — a column-zero `#[cfg(test)]`
#   or `#[cfg(all(test, ...))]` through the next line that is exactly `}`.
#   That is this codebase's universal shape (measured: 72 and 7 occurrences,
#   no third form), but a test gate on an INDENTED item, or a test module
#   whose closing brace is indented, would leave test literals in the
#   production set and mark an unbuilt kind as written. The two
#   `.record("before" | "after", …)` warnings this emits are exactly that
#   case and are why the reverse direction does not gate.
# * §9.4 reverse direction (a kind written but absent from the table) is a
#   WARNING, not a failure. Extracting the first argument of `.record(`
#   is heuristic — `mcp/mod.rs` has an unrelated `record(site)` on a
#   different type — so it is reported for a human rather than gating.
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


# Column-zero test gates. Measured across `crates/*/src/`: 72 `#[cfg(test)]`
# and 7 `#[cfg(all(test, unix))]`, and nothing else. Anchored to the two
# literal forms rather than a `\btest\b` search inside the cfg, because that
# would also match a `#[cfg(feature = "test-util")]` the day someone adds one
# and silently blank a production module.
CFG_TEST_RE = re.compile(r"^#\[cfg\((?:test\)|all\(test[,)])")


def strip_test_modules(src):
    """Blank out test-gated items anchored at column zero.

    Heuristic, and the limits are in the header: from a column-zero test
    `cfg` through the next line that is exactly `}`. Every test module in
    this workspace has that shape. Lines are blanked rather than deleted so
    any line number we report still matches the file.
    """
    out, skipping = [], False
    for line in src.split("\n"):
        if not skipping and CFG_TEST_RE.match(line):
            skipping = True
            out.append("")
            continue
        if skipping:
            out.append("")
            if line == "}":
                skipping = False
            continue
        out.append(line)
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
    if len(kinds) < 10:
        return None, "§9.4's table parsed to only {} kinds — the format moved".format(len(kinds))
    report["audit_kinds"] = kinds

    written, unwritten = [], []
    for kind in kinds:
        if '"{}"'.format(kind) in blob:
            written.append(kind)
        else:
            unwritten.append(kind)
    report["audit_written"] = written
    report["audit_unwritten"] = unwritten

    ledger = sorted(k for k, _ in KNOWN_UNWRITTEN)
    why = dict(KNOWN_UNWRITTEN)
    for kind in ledger:
        if kind not in kinds:
            report["findings"].append(
                "§9.4 ledger names `{}`, which is not a row in the table any more: "
                "drop the row rather than leaving it to match nothing".format(kind)
            )
    for kind in sorted(set(unwritten) - set(ledger)):
        report["findings"].append(
            "§9.4 `{}` has NO production writer and is not in the ledger. Either an "
            "event stopped being audited, or a kind was specified and never "
            "implemented. Add a writer, or add it to KNOWN_UNWRITTEN with the "
            "feature it waits on.".format(kind)
        )
    for kind in sorted(set(ledger) - set(unwritten)):
        report["findings"].append(
            "§9.4 `{}` now HAS a production writer but is still in the ledger "
            "({}). Delete its row.".format(kind, why[kind])
        )

    # Reverse direction: a kind the code writes that §9.4 never named. A
    # warning, not a finding — see the false-negative surface.
    emitted = set()
    for text in prod.values():
        emitted.update(RECORD_CALL_RE.findall(text))
    stray = sorted(k for k in emitted if k not in kinds)
    report["audit_emitted_not_in_spec"] = stray
    for kind in stray:
        report["warnings"].append(
            "`.record(\"{}\", …)` is called in production Rust but `{}` is not a "
            "row in §9.4's table (heuristic: `.record(` has other meanings in "
            "this tree, so check before acting)".format(kind, kind)
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
    out.append("      unwritten (ledgered) .......... {}".format(len(report["audit_unwritten"])))
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
    if report["audit_unwritten"]:
        out.append("§9.4 kinds with no production writer (ledgered; not a finding)")
        out.append("-" * 66)
        why = dict(KNOWN_UNWRITTEN)
        for k in report["audit_unwritten"]:
            out.append("  {:<24} {}".format(k, why.get(k, "")))
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
        out.append("SPEC-ENUM OK — §9.4's 21 kinds and §12.6's ship-list agree with the tree")
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
# Every case runs `build_report` — the production path — against a fixture
# tree, so a case cannot pass by testing a copy of the logic. Each rule gets
# a positive AND a negative: "no findings" and "this rule cannot produce a
# finding" print the same word, which is the whole reason the negatives are
# here. The mutation cases edit a fixture and assert the ANSWER CHANGES; a
# check that reports the same thing either way is not reading the document.
# --------------------------------------------------------------------------

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
| `preflight_match` | `rule_kind` |
| `bridge_register` | `port` |

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

SELF_TEST_SRC = """
pub fn go(log: &AuditLog) {
    log.record("daemon_start", None, json!({}));
    log.record("daemon_stop", None, json!({}));
    log.record("session_start", None, json!({}));
    log.record("session_terminate", None, json!({}));
    log.record("send_input", None, json!({}));
    log.record("redaction_disabled", None, json!({}));
    log.record("attach_connect", None, json!({}));
    log.record("attach_disconnect", None, json!({}));
    log.record("panic", None, json!({}));
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        log.record("preflight_match", None, json!({}));
        log.record("bridge_register", None, json!({}));
    }
}
"""


def _fixture(tmp, spec=SELF_TEST_SPEC, schema=SELF_TEST_SCHEMA, src=SELF_TEST_SRC):
    root = Path(tmp)
    (root / "crates" / "holdfast-core" / "src").mkdir(parents=True, exist_ok=True)
    (root / "crates" / "holdfast-core" / "tests").mkdir(parents=True, exist_ok=True)
    (root / "crates" / "holdfast-core" / "src" / "lib.rs").write_text(src)
    (root / "crates" / "holdfast-core" / "tests" / "schema.rs").write_text(schema)
    spec_path = root / "spec.md"
    spec_path.write_text(spec)
    return spec_path, root


def self_test():
    failures = 0
    ledger = ["preflight_match", "bridge_register"]

    def check(name, got, want):
        nonlocal failures
        if got == want:
            print("  PASS  {} -> {!r}".format(name, got))
        else:
            print("  FAIL  {}\n          got  {!r}\n          want {!r}".format(name, got, want))
            failures += 1

    def run(**kw):
        with tempfile.TemporaryDirectory() as tmp:
            spec_path, root = _fixture(tmp, **kw)
            saved = list(KNOWN_UNWRITTEN)
            KNOWN_UNWRITTEN[:] = [(k, "fixture") for k in ledger]
            try:
                return build_report(spec_path, root)
            finally:
                KNOWN_UNWRITTEN[:] = saved

    print("spec-enum-check self-test")
    print("-" * 66)

    print("\n§9.4 — table parsing")
    rep, err = run()
    check("the baseline fixture reports no findings", (rep and rep["findings"], err), ([], None))
    check("column 1 of the table is parsed, and only the table",
          rep["audit_kinds"],
          ["daemon_start", "daemon_stop", "session_start", "session_terminate",
           "send_input", "redaction_disabled", "attach_connect", "attach_disconnect",
           "panic", "preflight_match", "bridge_register"])
    check("an escaped pipe in column 2 does not break the row",
          "daemon_stop" in rep["audit_kinds"], True)
    check("a later section's table is NOT collected", "not_an_audit_kind" in rep["audit_kinds"], False)
    check("test-module writers do not count as production writers",
          sorted(rep["audit_unwritten"]), ["bridge_register", "preflight_match"])

    print("\n§9.4 — MUTATION: a writer disappears (an event stops being audited)")
    rep2, _ = run(src=SELF_TEST_SRC.replace('log.record("attach_connect", None, json!({}));', ""))
    check("the lost writer is a finding",
          any("`attach_connect` has NO production writer" in f for f in rep2["findings"]), True)
    check("...and the answer CHANGED from the baseline", rep2["findings"] != rep["findings"], True)

    print("\n§9.4 — MUTATION: a ledgered kind gains a writer")
    rep3, _ = run(src=SELF_TEST_SRC.replace(
        'log.record("send_input", None, json!({}));',
        'log.record("send_input", None, json!({}));\n    log.record("preflight_match", None, json!({}));'))
    check("a stale ledger row is a finding",
          any("`preflight_match` now HAS a production writer" in f for f in rep3["findings"]), True)

    print("\n§9.4 — MUTATION: the ledger names a kind the table dropped")
    rep4, _ = run(spec=SELF_TEST_SPEC.replace("| `bridge_register` | `port` |\n", ""))
    check("a ledger row matching no table row is a finding",
          any("not a row in the table any more" in f for f in rep4["findings"]), True)

    print("\n§9.4 — reverse direction is a WARNING, not a finding")
    rep5, _ = run(spec=SELF_TEST_SPEC.replace("| `attach_connect` | `peer_uid` |\n", ""))
    check("a kind written but unspecified warns",
          any("attach_connect" in w for w in rep5["warnings"]), True)
    check("...and does not gate",
          any("attach_connect" in f for f in rep5["findings"]), False)

    print("\n§12.6 — parenthetical filter and the numeral cross-check")
    check("parentheticals are stripped before ids are taken",
          rep["shiplist_tools"],
          ["start_session", "read_output", "send_input", "terminate", "status",
           "list_sessions", "precheck_command"])
    check("`ansi` and `redact` are NOT collected as tools",
          [t for t in rep["shiplist_tools"] if t in ("ansi", "redact")], [])
    check("the shipped set is reported", rep["shipped_tools"],
          ["start_session", "read_output", "send_input", "terminate", "status",
           "list_sessions"])
    check("planned-but-unbuilt is a census, not a finding",
          (rep["shiplist_not_shipped"], [f for f in rep["findings"] if "precheck_command" in f]),
          (["precheck_command"], []))

    print("\n§12.6 — MUTATION: the numeral disagrees with its own list")
    rep6, _ = run(spec=SELF_TEST_SPEC.replace("All 7 MCP tools", "All 8 MCP tools"))
    check("numeral vs list is a finding",
          any("says `All 8 MCP tools` and then lists 7" in f for f in rep6["findings"]), True)

    print("\n§12.6 — MUTATION: a shipped tool is missing from the ship-list")
    rep7, _ = run(spec=SELF_TEST_SPEC.replace("`send_input`, `terminate`", "`terminate`")
                  .replace("All 7 MCP tools", "All 6 MCP tools"))
    check("a shipped tool absent from §12.6 is a finding",
          any("`send_input` is an MCP tool the tree ships" in f for f in rep7["findings"]), True)

    print("\nanti-vacuity — a tree or document it cannot read is never a pass")
    with tempfile.TemporaryDirectory() as tmp:
        spec_path, root = _fixture(tmp)
        for p in (root / "crates" / "holdfast-core" / "src" / "lib.rs",):
            p.unlink()
        rep8, err8 = build_report(spec_path, root)
    check("no production Rust -> error, not 'every kind unwritten'",
          (rep8 is None, "refusing to report every kind as unwritten" in (err8 or "")), (True, True))
    rep_small, err_small = run(spec=SELF_TEST_SPEC.replace(
        "| `session_terminate` | `reason, exit_code` |\n", "")
        .replace("| `redaction_disabled` | `tool, client_kind` |\n", "")
        .replace("| `attach_disconnect` | `reason, duration_secs` |\n", ""))
    check("a table that parsed to too few rows -> error, not a short green run",
          (rep_small is None, "the format moved" in (err_small or "")), (True, True))
    rep9, err9 = run(spec="# Design\n\n### 12.6 ship-list\n\n- nothing\n")
    check("§9.4 absent -> error, not a green run", (rep9 is None, err9), (True, "§9.4 not found in the spec"))
    rep10, err10 = run(spec=SELF_TEST_SPEC.replace("### 12.6 v0.1.0 ship-list", "### 12.7 elsewhere"))
    check("§12.6 absent -> error, not a green run",
          (rep10 is None, "§12.6" in (err10 or "")), (True, True))
    rep11, err11 = run(schema="const TOOLS: [&str; 0] = [];\nlet x = 1;\n")
    check("an EMPTY schema.rs pin -> error, not a vacuously satisfied subset rule",
          (rep11 is None, "vacuously satisfied" in (err11 or "")), (True, True))
    rep12, err12 = run(schema="const NOT_TOOLS: [&str; 2] = [\"a\", \"b\"];\n")
    check("the schema.rs pin being RENAMED -> error, not a silent skip",
          (rep12 is None, "the pin moved" in (err12 or "")), (True, True))

    print("\nfind_spec — the worktree fallback")
    with tempfile.TemporaryDirectory() as tmp:
        got, ferr = find_spec(Path(tmp), None)
        check("a tree with no docs/ and no git -> cannot run, with the paths tried",
              (got, "no spec at any of" in (ferr or "")), (None, True))
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "docs" / "superpowers" / "specs"
        d.mkdir(parents=True)
        (d / "0000-00-00-holdfast-design.md").write_text("x")
        got, ferr = find_spec(Path(tmp), None)
        check("docs/ present -> the spec is found", (got.name, ferr),
              ("0000-00-00-holdfast-design.md", None))
        (d / "0001-01-01-holdfast-design.md").write_text("x")
        got, ferr = find_spec(Path(tmp), None)
        check("two candidate specs -> error, not an arbitrary pick",
              (got, "expected exactly one" in (ferr or "")), (None, True))

    print("\n" + "-" * 66)
    # What was covered, rather than how many cases ran: the count is the
    # thing that goes stale, which is the defect this whole file is about.
    print("covered: §9.4's table parsed and bounded away from its own prose")
    print("and from a later section's table; the ledger red in both")
    print("directions and when it names a dropped row; a writer disappearing;")
    print("the reverse direction warning without gating; §12.6's parenthetical")
    print("filter, its numeral-vs-list cross-check and the shipped-subset")
    print("rule; refusal on an unreadable tree, a shrunken table, a missing")
    print("§9.4 or §12.6, and an empty or renamed schema.rs pin; and")
    print("find_spec's --spec / $HOLDFAST_SPEC / docs / worktree chain.")
    if failures:
        print("SELF-TEST FAILED: {} case(s)".format(failures))
        return EXIT_FINDINGS
    print("SELF-TEST OK")
    return EXIT_OK


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
