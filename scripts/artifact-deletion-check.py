#!/usr/bin/env python3
# Find plan steps that hand over the whole of an artifact that has since grown.
#
# THE DEFECT. A plan step gives the complete new content of an artifact --
# "Replace `crates/clasp-core/src/lib.rs` with:", "Write
# `.github/workflows/ci.yml`", "Create `scripts/ci-probe.sh`:" -- and was
# written when that artifact was smaller. Applied to today's tree it silently
# deletes everything added since. Every such step reads as correct and
# complete in isolation; the defect exists only in the relationship between
# the plan's age and the tree's growth, so no amount of reading the step
# finds it. Found by hand three times in this repository before this check
# existed:
#
#   * 0.0.5 Task 1 Step 4 -- a seven-module `lib.rs` against a tree whose
#     list had grown to eleven. Four modules deleted, `detect` (6 026 lines)
#     among them, which is a crate-wide unresolved-module failure.
#   * 0.0.5 Task 12 Step 2 -- "the module list becomes", four of seven.
#   * The CI plan -- six whole-file Create steps, all six artifacts grown
#     since it executed; re-applying `ci.yml` deletes the skip-census gate
#     and orphans `scripts/ci-skip-census.sh`, which no plan names.
#
# WHY NOT A PHRASE GREP. Measured before this was written: grepping for the
# phrases that introduce such a block gives 31 candidate sites and 8 real
# findings, and misses the two worst -- 0.0.5 says only "Replace ... with",
# the CI plan says only "Create". Those verbs are too common to grep for and
# too weak to score. The discriminator is not the prose. It is the disk: a
# block that claims to be a whole artifact either accounts for what is at
# that path today or it does not, and that question has an exact answer.
# A phrase grep decays as the plans are reworded; this gets *stronger* as the
# tree grows, because growth is the thing it measures.
#
# HOW IT DECIDES. Three gates, in this order, and the third is the one that
# carries the weight:
#
#   1. SHAPE, from the block itself, not from the prose around it. A fenced
#      block is a whole-artifact block when its own content says so: a
#      shebang, a `//!` inner doc comment (legal only at the top of a Rust
#      file), a YAML document with `name:`/`on:`/`jobs:` at column 0, a TOML
#      document with `[package]`, or a TOML block opening on a `[table]`
#      header. Shape first is deliberate: it is what catches the CI plan,
#      whose introducing verb is the single word "Create".
#
#   2. PATH, from the backticked path nearest above the fence, with the
#      extension required to agree with the shape. Disagreement means the
#      path was picked up from an unrelated sentence, and the block is
#      dropped rather than diffed against the wrong file.
#
#   3. DELETION, against the file on disk. Significant lines (blank and
#      comment lines excluded) are compared as SETS, so re-indentation and
#      reordering are not deletions. A finding is a line that exists at that
#      path today and appears nowhere in the block.
#
# WHAT IT CANNOT DO, said plainly rather than papered over. "Looks like a
# whole artifact" is answerable for a file and for a TOML table. It is not
# answerable for a Rust fragment: a `use` block, an `enum`, a `match` arm
# list or a `const` array has no delimiter in the block saying where it ends
# in the file, so there is no set of disk lines to compare it against without
# parsing Rust. Those go undetected and are listed as such in the summary --
# a check that guessed at their extent would report deletions of everything
# else in the file and be switched off within the week. The one fragment
# shape that IS decidable is a module-declaration list (every significant
# line is `mod x;` or `pub mod x;`), because the disk side is exactly the
# module declarations of that file; it is checked as a second tier, and
# suppressed when the prose says "add"/"insert", because a two-line addition
# and a four-line replacement are the same bytes and only the prose tells
# them apart. That tier is the only place a word is read, and it can only
# ever suppress, never accuse.
#
# BLOCKING vs RECORD. An executed plan is a historical record, and its
# whole-file Create steps are *supposed* to describe the file as it was
# built, not as it is now. The distinction is not derivable from the block --
# 0.0.2's stale `Create crates/clasp-core/src/mcp/schema.rs` block and the CI
# plan's stale `Create .github/workflows/ci.yml` block are the same
# phenomenon down to the shape of the diff -- so it is read from the one
# signal the corpus carries: a plan whose header blockquote says **EXECUTED**
# is a record, and its findings are reported as RECORD (shown with --all,
# never blocking). Everything else is a plan somebody is going to run, and
# its findings BLOCK. That makes the header stamp load-bearing rather than
# decorative: stamping a plan is how a finding is closed without rewriting
# the step, and un-stamping one turns its findings red again. The `--all`
# listing is what keeps the stamp honest.
#
# WHERE THIS RUNS. Not in CI. `docs/` is git-ignored in this repository and
# lives in a separate git repo, so the plans are not in the tree CI checks
# out; a workflow calling this would find no plans on every run and report
# nothing, forever. Same delivery problem, same answer, as
# `scripts/orphan-req-check.py`: run it by hand, or install the post-commit
# hook into the docs repo (`--install-hook`) so it fires on the event that
# causes the drift -- a plan edit. Absence of `docs/` exits 3 with a message
# saying the check could not run; it never exits 0 on a tree it could not
# read.
#
# Usage:
#   scripts/artifact-deletion-check.py                # report, exit 1 on blocking
#   scripts/artifact-deletion-check.py --all          # include RECORD findings
#   scripts/artifact-deletion-check.py --json
#   scripts/artifact-deletion-check.py --self-test    # prove the check can fail
#   scripts/artifact-deletion-check.py --install-hook # post-commit hook in docs/
#   scripts/artifact-deletion-check.py --plans-dir DIR  # audit an arbitrary set

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_CANNOT_RUN = 3

# How far above a fence the introducing path may sit. Steps in this corpus
# name the path on the line directly above, or in the step heading two or
# three lines up with a sentence between.
LOOKBACK = 14

FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([A-Za-z0-9+_-]*)\s*$")
BACKTICK_RE = re.compile(r"`([^`\n]+)`")
PATH_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*\.[A-Za-z0-9]+$")

WRITE_VERB_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\[[ xX]\]\s*)?\**\s*"
    r"(?:Replace|Create|Write|Rewrite|Modify|Update|Overwrite)\b", re.I)

TASK_RE = re.compile(r"^#{2,4}\s+(Task\s+[0-9]+[a-z]?)\b[:.]?\s*(.*)$", re.I)
STEP_RE = re.compile(r"^\s*[-*]\s*\[[ xX]\]\s*\*\*(Step\s+[0-9]+[a-z]?)\b[:.]?\s*(.*?)\*\*")

# A plan that says this in its header blockquote is a record of what was
# written, not a description of what is there now.
EXECUTED_RE = re.compile(r"^>\s*\*\*EXECUTED\b", re.M)
EXECUTED_SCAN_LINES = 60

# Tier 2 only. These words mean the block is a delta, not a replacement, and
# the module-list tier must stay silent. They can only suppress.
ADDITION_RE = re.compile(
    r"\b(add|adds|adding|insert|inserts|inserting|append|appends|appending|"
    r"beneath|after|alongside)\b",
    re.I,
)
MOD_DECL_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;$")

# A block whose only introduction is the bare word "Find:" or "Replace with:"
# is one half of an anchored edit pair. It claims nothing about the whole of
# anything -- it is a needle and a thread -- and an anchor that no longer
# matches fails loudly instead of deleting silently. That is what makes the
# Find/Replace form structurally immune to this defect, and it is why the
# 0.0.2 plans, which use it throughout for modifications, are clean. Matched
# against the LAST non-blank line above the fence only: "Replace
# `crates/clasp-core/src/lib.rs` with:" names a path and is not this.
ANCHORED_EDIT_RE = re.compile(
    r"^\**\s*(?:Find|Replace(?:\s+with)?|With|Becomes)\s*:?\s*\**$", re.I)

COMMENT_PREFIX = {
    "rust-file": "//",
    "mod-list": "//",
    "script": "#",
    "yaml-file": "#",
    "toml-file": "#",
    "toml-table": "#",
}

# The extension a block of each shape must be paired with. A mismatch means
# the nearest backticked path belongs to some other sentence.
EXT_FOR_KIND = {
    "script": (".sh", ".py"),
    "rust-file": (".rs",),
    "mod-list": (".rs",),
    "yaml-file": (".yml", ".yaml"),
    "toml-file": (".toml",),
    "toml-table": (".toml",),
}

KIND_LABEL = {
    "rust-file": "whole Rust file",
    "mod-list": "module-declaration list",
    "script": "whole shell/python script",
    "yaml-file": "whole YAML workflow",
    "toml-file": "whole TOML manifest",
    "toml-table": "TOML table",
}


# --------------------------------------------------------------------------
# Markdown: fenced blocks, and where in the plan they sit
# --------------------------------------------------------------------------


class Block:
    def __init__(self, plan: Path, line: int, lang: str, body: list[str],
                 context: list[str], where: str):
        self.plan = plan
        self.line = line          # 1-based line of the opening fence
        self.lang = lang
        self.body = body
        self.context = context    # the LOOKBACK lines above the fence
        self.where = where        # "Task 1 / Step 4", best effort


def iter_blocks(plan: Path):
    """Yield every fenced block, with the lines above it and its Task/Step.

    A closing fence is a fence line with no info string, of the same
    character and at least the opening length; that is CommonMark's rule and
    it keeps a nested ```` block from ending its parent early.
    """
    lines = plan.read_text(encoding="utf-8").splitlines()
    task = step = ""
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            tm = TASK_RE.match(lines[i])
            if tm:
                task, step = tm.group(1), ""
            else:
                sm = STEP_RE.match(lines[i])
                if sm:
                    step = sm.group(1)
            i += 1
            continue

        _, tok, lang = m.groups()
        j = i + 1
        while j < len(lines):
            m2 = FENCE_RE.match(lines[j])
            if (m2 and m2.group(2)[0] == tok[0]
                    and len(m2.group(2)) >= len(tok) and not m2.group(3)):
                break
            j += 1
        where = " / ".join(x for x in (task, step) if x) or "(no task/step heading)"
        yield Block(plan, i + 1, lang, lines[i + 1:j],
                    lines[max(0, i - LOOKBACK):i], where)
        i = j + 1


def is_executed_record(plan: Path) -> bool:
    head = "\n".join(plan.read_text(encoding="utf-8").splitlines()[:EXECUTED_SCAN_LINES])
    return bool(EXECUTED_RE.search(head))


# --------------------------------------------------------------------------
# Gate 1: shape
# --------------------------------------------------------------------------


def classify(body: list[str]) -> str | None:
    """What whole artifact, if any, does this block claim to be?

    Read from the block's own content. Nothing here consults the prose: the
    CI plan's introducing verb is the single word "Create", which is not a
    signal, and its `ci.yml` block is unmistakable from the inside.
    """
    significant = [l for l in body if l.strip()]
    if not significant:
        return None
    first = significant[0].strip()

    if first.startswith("#!"):
        return "script"

    # `//!` is an inner doc comment: legal only at the top of a file or a
    # `mod { }` body, and plans do not paste inline module bodies.
    if first.startswith("//!"):
        return "rust-file"

    col0 = [l for l in body if l[:1] not in (" ", "\t", "")]
    top_keys = {l.split(":", 1)[0] for l in col0 if ":" in l}
    if {"name", "on", "jobs"} <= top_keys:
        return "yaml-file"

    if any(l.strip() == "[package]" for l in body):
        return "toml-file"
    if re.match(r"^\[[^\[\]]+\]$", first):
        return "toml-table"

    # Tier 2: a module-declaration list. Decidable because the disk side is
    # exactly the `mod`/`pub mod` lines of the file -- unlike a `use` block,
    # an `enum` or a `match`, whose extent in the file the block never states.
    decls = [l.strip() for l in significant if not l.strip().startswith("//")]
    if len(decls) >= 2 and all(MOD_DECL_RE.match(d) for d in decls):
        return "mod-list"

    return None


# --------------------------------------------------------------------------
# Gate 2: path
# --------------------------------------------------------------------------


def paths_on(line: str) -> list[str]:
    out = []
    for tok in BACKTICK_RE.findall(line):
        tok = tok.strip()
        if " " in tok or tok.endswith("/"):
            continue
        if PATH_RE.match(tok):
            out.append(tok)
    return out


def resolve_path(context: list[str]) -> str | None:
    """The artifact this block claims to be, taken from the lines above it.

    The nearest line that names EXACTLY ONE path wins. Nearest, because
    "Replace `[dependencies]` in `crates/clasp/Cargo.toml` with:" names the
    table before the file. Exactly one, because a line naming several is
    prose, not a step: 0.0.5's rewritten Task 1 Step 4 explains itself with
    "...imported by `mcp/tools.rs`, `mcp/detection.rs`, `session/mod.rs` and
    `tests/detection.rs`", and a plain nearest-wins rule takes the last of
    those and then diffs a module list against a test file. Such a line is
    stepped over rather than treated as an answer.

    A line that OPENS with a writing verb is the exception: it is a step
    heading, its first path is its object, and any others are asides
    ("Replace `x` with the following — it is imported by `y` and `z`").
    This is the only place a word is read to pick a path, and it can only
    ever choose between paths — never decide that a block is a whole
    artifact, which is settled by shape alone before this is called.
    """
    for line in reversed(context):
        found = paths_on(line)
        if not found:
            continue
        if len(found) == 1:
            return found[0]
        if WRITE_VERB_RE.match(line):
            return found[0]
    return None


# --------------------------------------------------------------------------
# Gate 3: what applying the block would delete
# --------------------------------------------------------------------------


def significant(kind: str, lines: list[str]) -> list[str]:
    prefix = COMMENT_PREFIX[kind]
    out = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith(prefix):
            continue
        out.append(s)
    return out


def toml_table_lines(lines: list[str], header: str) -> list[str]:
    out, inside = [], False
    for line in lines:
        s = line.strip()
        if re.match(r"^\[+[^\[\]]+\]+$", s):
            inside = (s == header)
            continue
        if inside:
            out.append(line)
    return out


def mod_decl_lines(lines: list[str]) -> list[str]:
    return [l.strip() for l in lines if MOD_DECL_RE.match(l.strip())]


def disk_view(kind: str, disk_lines: list[str], body: list[str]) -> list[str]:
    """The part of the file this block claims to be the whole of."""
    if kind == "toml-table":
        header = [l.strip() for l in body if l.strip()][0]
        return toml_table_lines(disk_lines, header)
    if kind == "mod-list":
        return mod_decl_lines(disk_lines)
    return disk_lines


def name_deletions(kind: str, deleted: list[str]) -> list[str]:
    """A short handle for each deleted line, for the headline."""
    named = []
    for d in deleted:
        m = MOD_DECL_RE.match(d)
        if m:
            named.append(f"module `{m.group(1)}`")
            continue
        m = re.match(r"^-?\s*(?:run|uses):\s*(.+)$", d)
        if m:
            named.append(f"step `{m.group(1)[:60]}`")
            continue
        m = re.match(r"^pub\s+use\s+(.+?)[;{]", d)
        if m:
            named.append(f"re-export `{m.group(1).strip()}`")
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*=", d)
        if m:
            named.append(f"key `{m.group(1)}`")
            continue
        m = re.match(r"^(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)", d)
        if m:
            named.append(f"fn `{m.group(1)}`")
    # Preserve order, drop repeats.
    return list(dict.fromkeys(named))


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------


def scan(plans: list[Path], root: Path) -> dict:
    raw: list[dict] = []
    stats = {
        "blocks": 0,
        "whole_artifact_blocks": 0,
        "unresolved_path": 0,
        "path_absent": 0,
        "superseded": 0,
        "clean": 0,
        "anchored_edit": 0,
        "fragments_undecidable": 0,
    }

    for plan in plans:
        record = is_executed_record(plan)
        for blk in iter_blocks(plan):
            stats["blocks"] += 1
            kind = classify(blk.body)
            if kind is None:
                stats["fragments_undecidable"] += 1
                continue

            nearest = next((l for l in reversed(blk.context) if l.strip()), "")
            if ANCHORED_EDIT_RE.match(nearest.strip()):
                stats["anchored_edit"] += 1
                continue

            if kind == "mod-list":
                # Tier 2 may only ever be suppressed by prose, never raised
                # by it: "add two lines" and "the list becomes" are the same
                # bytes, and only the sentence distinguishes them.
                near = " ".join(blk.context[-6:])
                if ADDITION_RE.search(near):
                    stats["fragments_undecidable"] += 1
                    continue

            stats["whole_artifact_blocks"] += 1

            rel = resolve_path(blk.context)
            if rel is None or Path(rel).suffix not in EXT_FOR_KIND[kind]:
                stats["unresolved_path"] += 1
                continue

            target = root / rel
            if not target.is_file():
                # The legitimate case: a whole-artifact block for a file the
                # plan itself creates, which does not exist yet. Nothing to
                # delete, nothing to say.
                stats["path_absent"] += 1
                continue

            disk_all = target.read_text(encoding="utf-8", errors="replace").splitlines()
            disk_sig = significant(kind, disk_view(kind, disk_all, blk.body))
            block_sig = significant(kind, blk.body)
            block_set = set(block_sig)

            deleted = [l for l in dict.fromkeys(disk_sig) if l not in block_set]
            added = [l for l in dict.fromkeys(block_sig) if l not in set(disk_sig)]

            raw.append({
                "plan": plan.name,
                "line": blk.line,
                "where": blk.where,
                "kind": kind,
                "path": rel,
                "executed_record": record,
                "disk_significant": len(set(disk_sig)),
                "block_significant": len(block_set),
                "deleted": deleted,
                "added_not_on_disk": len(added),
                "names": name_deletions(kind, deleted),
            })

    # A plan that writes the same path several times is building it up across
    # its own tasks; only the last such block claims to be the end state.
    # Diffing an intermediate stage against today's file measures the plan's
    # own remaining tasks, not drift.
    last_for: dict[tuple[str, str, str], int] = {}
    for idx, f in enumerate(raw):
        last_for[(f["plan"], f["path"], f["kind"])] = idx
    kept = []
    for idx, f in enumerate(raw):
        if last_for[(f["plan"], f["path"], f["kind"])] != idx:
            f["superseded_by_later_block"] = True
            stats["superseded"] += 1
            continue
        if not f["deleted"]:
            stats["clean"] += 1
            continue
        kept.append(f)

    blocking = [f for f in kept if not f["executed_record"]]
    record = [f for f in kept if f["executed_record"]]

    return {
        "root": str(root),
        "plans": [p.name for p in plans],
        "plans_marked_executed": sorted(p.name for p in plans if is_executed_record(p)),
        "stats": stats,
        "counts": {"blocking": len(blocking), "record": len(record)},
        "blocking": blocking,
        "record": record,
    }


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def render_finding(f: dict, cap: int = 12) -> list[str]:
    out = []
    out.append(f"  {f['plan']}:{f['line']}  {f['where']}")
    out.append(f"      block claims to be: {KIND_LABEL[f['kind']]}  ->  {f['path']}")
    out.append(f"      applying it deletes {len(f['deleted'])} of the "
               f"{f['disk_significant']} significant lines at that path")
    if f["names"]:
        out.append(f"      deletes: {', '.join(f['names'][:6])}"
                   + (f" (+{len(f['names']) - 6} more)" if len(f["names"]) > 6 else ""))
    for d in f["deleted"][:cap]:
        out.append(f"        - {d[:100]}")
    if len(f["deleted"]) > cap:
        out.append(f"        ... and {len(f['deleted']) - cap} more")
    if f["added_not_on_disk"]:
        out.append(f"      ({f['added_not_on_disk']} line(s) in the block are not on "
                   f"disk at all — the block is also out of date in the other direction)")
    return out


def render(report: dict, show_record: bool) -> str:
    s, c = report["stats"], report["counts"]
    out: list[str] = []
    w = out.append

    w("CLASP whole-artifact deletion check")
    w("=" * 72)
    w(f"root:   {report['root']}")
    w(f"plans:  {len(report['plans'])}  "
      f"({len(report['plans_marked_executed'])} marked EXECUTED)")
    w("")
    w(f"  fenced blocks read ................... {s['blocks']}")
    w(f"  half of a Find/Replace pair (immune) . {s['anchored_edit']}")
    w(f"  claim to be a whole artifact ......... {s['whole_artifact_blocks']}")
    w(f"      path not resolvable .............. {s['unresolved_path']}")
    w(f"      path absent on disk (legitimate) . {s['path_absent']}")
    w(f"      superseded by a later block ...... {s['superseded']}")
    w(f"      account for the file as it is .... {s['clean']}")
    w(f"  BLOCKING findings .................... {c['blocking']}")
    w(f"  RECORD findings (plan marked EXECUTED) {c['record']}"
      + ("" if show_record else "   [--all to list]"))
    w("")
    w(f"  fragments no whole-artifact test can decide: {s['fragments_undecidable']}"
      " (see header)")

    if report["blocking"]:
        w("")
        w("BLOCKING — a plan nobody has marked EXECUTED hands over the whole of an")
        w("artifact that has grown since. Applying the step as written deletes this.")
        w("-" * 72)
        for f in report["blocking"]:
            w("")
            out.extend(render_finding(f))
    else:
        w("")
        w("No blocking findings: every whole-artifact block in an unexecuted plan")
        w("accounts for what is at its path today.")

    if show_record and report["record"]:
        w("")
        w("RECORD — the plan's header says EXECUTED, so these blocks are a historical")
        w("record by declaration. Listed to keep that declaration honest: if a plan")
        w("here is not actually a record, remove the stamp and these turn BLOCKING.")
        w("-" * 72)
        for f in report["record"]:
            w("")
            out.extend(render_finding(f, cap=4))

    return "\n".join(out)


# --------------------------------------------------------------------------
# Self-test: the check has to be able to fail
# --------------------------------------------------------------------------

# Fixture disk files. Each is what the tree holds TODAY; the plans below were
# written when they were smaller.
FIX_LIB_RS = """\
//! Fake core.

pub mod alpha;
pub mod detect;
pub mod error;

pub use error::Result;
"""

FIX_WORKFLOW = """\
# Fake CI.
name: CI

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: cargo test
      - run: ./scripts/fixture-skip-census.sh test-output.log
"""

FIX_MANIFEST = """\
[dependencies]
anyhow = "1"
regex = "1"
"""

FIX_MODS_RS = """\
//! Fake module root.

pub mod one;
pub mod three;
pub mod two;
"""

FIX_OTHER_RS = """\
//! Fake other root.

pub mod aye;
pub mod bee;
"""

# A plan nobody has marked EXECUTED: its steps are going to be run.
PLAN_LIVE = """\
# Fake live plan

## Task 1: Scaffolding

- [ ] **Step 4: Declare the new module**

Replace `src/lib.rs` with:

```rust
//! Fake core.

pub mod alpha;
pub mod error;
pub mod newthing;

pub use error::Result;
```

- [ ] **Step 5: Create a file this plan owns**

Create `src/brand_new.rs`:

```rust
//! Nothing at this path yet.

pub mod nothing;
```

- [ ] **Step 6: A fragment, not a whole artifact**

In `src/lib.rs`, the imports become:

```rust
use std::collections::HashMap;
use std::sync::Arc;
```

- [ ] **Step 7: A block that is still accurate**

Replace `src/mods.rs` with:

```rust
//! Fake module root.

pub mod one;
pub mod two;
pub mod three;
```

- [ ] **Step 8: An addition, spelled as one**

In `Cargo.toml`, add one line to `[dependencies]`:

```toml
serde = "1"
```

- [ ] **Step 9: A step whose explanation names other files**

Replace `src/other.rs` with the following — it is imported by `src/lib.rs`,
`src/mods.rs` and `src/brand_new.rs`, so do not rename it:

```rust
//! Fake other root.

pub mod aye;
```
"""

# The 0.0.2 shape: modifications expressed as Find/Replace pairs. Structurally
# immune -- an anchor that no longer matches fails loudly instead of deleting.
PLAN_FIND_REPLACE = """\
# Fake find/replace plan

## Task 1: Edit two files

- [ ] **Step 1: Widen the module list**

In `src/lib.rs`:

**Find:**

```rust
pub mod alpha;
```

**Replace with:**

```rust
pub mod alpha;
pub mod added_by_this_plan;
```
"""

# The CI-plan shape: whole-file Create steps in a plan that has already run.
PLAN_CI = """\
# Fake CI plan

> **EXECUTED — a record of what was written, not of what is there now.**

## Task 3: The push workflow

- [ ] **Step 2: Write `.github/workflows/fixture.yml`**

```yaml
# Fake CI.
name: CI

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: cargo test
```
"""

# Same file, written twice in one plan: the first is an intermediate stage.
PLAN_STAGED = """\
# Fake staged plan

## Task 1: Start the module root

- [ ] **Step 1: Create it**

Create `src/mods.rs`:

```rust
//! Fake module root.

pub mod one;
```

## Task 2: Finish the module root

- [ ] **Step 1: Fill it in**

Replace `src/mods.rs` with:

```rust
//! Fake module root.

pub mod one;
pub mod two;
pub mod three;
```
"""

# Tier 2: a bare module list presented as the new list, no `//!` header.
PLAN_MOD_LIST = """\
# Fake mod-list plan

## Task 12: Declare the module

- [ ] **Step 2: The module list**

In `src/mods.rs`, the module list becomes:

```rust
pub mod one;
pub mod two;
```
"""

# Tier 2 suppression: the same bytes, introduced as an addition.
PLAN_MOD_ADD = """\
# Fake mod-add plan

## Task 12: Declare the module

- [ ] **Step 2: The module list**

In `src/mods.rs`, add one line, keeping the list alphabetical:

```rust
pub mod one;
pub mod two;
```
"""


def _fixture_tree(td: Path) -> tuple[Path, Path]:
    root = td / "repo"
    plans = root / "docs" / "superpowers" / "plans"
    (root / "src").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    plans.mkdir(parents=True)
    (root / "src" / "lib.rs").write_text(FIX_LIB_RS, encoding="utf-8")
    (root / "src" / "mods.rs").write_text(FIX_MODS_RS, encoding="utf-8")
    (root / "src" / "other.rs").write_text(FIX_OTHER_RS, encoding="utf-8")
    (root / "Cargo.toml").write_text(FIX_MANIFEST, encoding="utf-8")
    (root / ".github" / "workflows" / "fixture.yml").write_text(FIX_WORKFLOW, encoding="utf-8")
    return root, plans


def _run(plans_dir: Path, root: Path) -> dict:
    return scan(sorted(plans_dir.glob("*.md")), root)


def _find(report: dict, bucket: str, plan_frag: str, path: str):
    for f in report[bucket]:
        if plan_frag in f["plan"] and f["path"] == path:
            return f
    return None


def self_test(corpus_root: Path | None) -> int:
    failures: list[str] = []

    def check(name, got, want):
        if got == want:
            print(f"  PASS  {name}")
            print(f"          got {got!r}")
        else:
            print(f"  FAIL  {name}")
            print(f"          want {want!r}")
            print(f"          got  {got!r}")
            failures.append(name)

    print("Self-test tier 1 — synthetic tree with known answers\n")

    with tempfile.TemporaryDirectory() as td:
        root, plans = _fixture_tree(Path(td))
        (plans / "live.md").write_text(PLAN_LIVE, encoding="utf-8")
        (plans / "findrepl.md").write_text(PLAN_FIND_REPLACE, encoding="utf-8")
        (plans / "ci.md").write_text(PLAN_CI, encoding="utf-8")
        (plans / "staged.md").write_text(PLAN_STAGED, encoding="utf-8")
        (plans / "modlist.md").write_text(PLAN_MOD_LIST, encoding="utf-8")
        (plans / "modadd.md").write_text(PLAN_MOD_ADD, encoding="utf-8")

        rep = _run(plans, root)

        # THE FLAGSHIP SHAPE. A `//!`-headed whole-file block, written when
        # the list was shorter, against a file that has since grown.
        f = _find(rep, "blocking", "live", "src/lib.rs")
        check("a stale whole-file `lib.rs` block is BLOCKING, and the module it "
              "drops is NAMED",
              (f is not None and f["deleted"], f and f["names"]),
              (["pub mod detect;"], ["module `detect`"]))

        # THE CI SHAPE. A workflow whose introducing verb is only "Write",
        # in a plan that has run, against a file that has grown.
        f = _find(rep, "record", "ci", ".github/workflows/fixture.yml")
        check("a stale whole-workflow block names the deleted step",
              (f is not None and f["deleted"], f and f["names"]),
              (["- run: ./scripts/fixture-skip-census.sh test-output.log"],
               ["step `./scripts/fixture-skip-census.sh test-output.log`"]))

        check("...and it is RECORD, not BLOCKING, because that plan says EXECUTED",
              [(x["plan"], x["path"]) for x in rep["blocking"] if x["plan"] == "ci.md"],
              [])

        # The legitimate case the brief calls out by name.
        check("a whole-artifact block for a path that does not exist is not reported",
              [x for x in rep["blocking"] + rep["record"] if x["path"] == "src/brand_new.rs"],
              [])

        # A `use` block is a fragment. Reporting it would mean claiming its
        # extent in the file, which the block never states -- and would
        # "delete" every other line of lib.rs.
        check("a bare `use` fragment is not treated as a whole artifact",
              [x for x in rep["blocking"] + rep["record"]
               if x["plan"] == "live.md" and x["kind"] != "rust-file"],
              [])

        # Find/Replace pairs are structurally immune: the block is a
        # fragment, so no path is ever claimed.
        check("a Find/Replace plan produces nothing (it is structurally immune)",
              [x for x in rep["blocking"] + rep["record"] if x["plan"] == "findrepl.md"],
              [])

        # Not unconditional: an accurate block, and a real addition, are both
        # silent.
        check("a whole-file block that still accounts for the file is silent",
              [x for x in rep["blocking"] + rep["record"]
               if x["plan"] == "live.md" and x["path"] == "src/mods.rs"],
              [])
        check("a one-key `[dependencies]` addition is not read as a replacement",
              [x for x in rep["blocking"] + rep["record"] if x["path"] == "Cargo.toml"],
              [])

        check("a path written twice in one plan is judged on the LAST block only",
              [x for x in rep["blocking"] + rep["record"] if x["plan"] == "staged.md"],
              [])

        # Nearest-path-wins alone gets this wrong: the explanatory clause ends
        # on `src/brand_new.rs`, and the block would be diffed against a file
        # it says nothing about.
        f = _find(rep, "blocking", "live", "src/other.rs")
        check("a step whose explanation lists several paths still resolves to the "
              "one path its intro names",
              f is not None and f["names"], ["module `bee`"])

        # Tier 2, both directions.
        f = _find(rep, "blocking", "modlist", "src/mods.rs")
        check("TIER 2 — a bare module list presented as the new list is reported",
              f is not None and f["names"], ["module `three`"])
        check("TIER 2 — the same bytes introduced with \"add\" are NOT reported",
              [x for x in rep["blocking"] + rep["record"] if x["plan"] == "modadd.md"],
              [])

        check("exit code would be non-zero", rep["counts"]["blocking"] > 0, True)

        # MUTATION 1: the check must read the DISK, not the plan. Shrink the
        # tree back to what the plan describes and the finding must vanish.
        (root / "src" / "lib.rs").write_text(
            FIX_LIB_RS.replace("pub mod detect;\n", "").replace(
                "pub mod alpha;", "pub mod alpha;\npub mod newthing;"),
            encoding="utf-8")
        mrep = _run(plans, root)
        check("MUTATION — with the tree shrunk to match the plan, the lib.rs "
              "finding disappears (the check reads disk, not prose)",
              [x for x in mrep["blocking"] if x["path"] == "src/lib.rs"], [])
        (root / "src" / "lib.rs").write_text(FIX_LIB_RS, encoding="utf-8")

        # MUTATION 2: the EXECUTED stamp is load-bearing, not decoration.
        (plans / "ci.md").write_text(
            PLAN_CI.replace(
                "> **EXECUTED — a record of what was written, not of what is there now.**\n\n",
                ""),
            encoding="utf-8")
        mrep = _run(plans, root)
        f = _find(mrep, "blocking", "ci", ".github/workflows/fixture.yml")
        check("MUTATION — with the EXECUTED stamp removed, the same block turns "
              "BLOCKING (the stamp is load-bearing)",
              f is not None and f["names"],
              ["step `./scripts/fixture-skip-census.sh test-output.log`"])
        (plans / "ci.md").write_text(PLAN_CI, encoding="utf-8")

        # MUTATION 3: a check that cannot come back clean is not a check.
        for name in list(plans.glob("*.md")):
            name.unlink()
        (plans / "findrepl.md").write_text(PLAN_FIND_REPLACE, encoding="utf-8")
        crep = _run(plans, root)
        check("MUTATION — a corpus with no whole-artifact block is CLEAN, and the "
              "clean run is not vacuous (blocks were still read)",
              (crep["counts"], crep["stats"]["blocks"] > 0),
              ({"blocking": 0, "record": 0}, True))

    print()
    print("Self-test tier 2 — the real plan corpus\n")
    if corpus_root is None:
        print("  SKIPPED — no docs/superpowers/plans in this tree.")
        print()
        print("  This is NOT a pass. Tier 1 proves the mechanism against fixtures;")
        print("  tier 2 is what proves it against the documents it exists for, and")
        print("  it did not run. Exiting 3.")
        return EXIT_CANNOT_RUN

    plans_dir = corpus_root / "docs" / "superpowers" / "plans"
    rep = _run(plans_dir, corpus_root)

    check("the corpus was actually read (blocks, whole-artifact blocks, and at "
          "least one resolved path)",
          (rep["stats"]["blocks"] > 100,
           rep["stats"]["whole_artifact_blocks"] > 10,
           rep["stats"]["path_absent"] > 0),
          (True, True, True))

    # The negative half of the brief's acceptance set. These four plans are
    # clean and a check that flags them is over-firing.
    for frag in ("0.0.2-deterministic", "0.0.3-output", "0.0.6-attach",
                 "0.0.2-followup"):
        hits = [x["path"] for x in rep["blocking"] if frag in x["plan"]]
        check(f"no BLOCKING finding in {frag}", hits, [])

    every = rep["blocking"] + rep["record"]
    check("every finding names a path that exists on disk",
          all((corpus_root / x["path"]).is_file() for x in every), True)
    check("no BLOCKING finding sits in a plan marked EXECUTED",
          [x["plan"] for x in rep["blocking"] if x["executed_record"]], [])

    print()
    if failures:
        print(f"SELF-TEST FAILED: {len(failures)} of the above")
        return EXIT_ERROR
    print("SELF-TEST PASSED — the check discriminates in both directions, on")
    print("fixtures and on the real corpus.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Hook installation
# --------------------------------------------------------------------------


HOOK_HEADER = """\
#!/bin/sh
# Post-commit hooks for the CLASP docs repo.
#
# The plans and the spec live in THIS repository, not in the one CI checks
# out, so this is the only place the drift events -- a spec revision, a plan
# edit -- are observable. Non-blocking on purpose: a transient finding is
# normal mid-revision. The number is the point.
"""

HOOK_LINE = '"%(script)s" --repo-root "%(root)s" || true\n'


def install_hook(root: Path, script: Path) -> int:
    docs_git = root / "docs" / ".git"
    if not docs_git.is_dir():
        print(f"error: no git repository at {root / 'docs'}", file=sys.stderr)
        return EXIT_ERROR
    hooks = docs_git / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "post-commit"
    line = HOOK_LINE % {"script": script.resolve(), "root": root.resolve()}

    if not hook.exists():
        hook.write_text(HOOK_HEADER + "\n" + line, encoding="utf-8")
        hook.chmod(0o755)
        print(f"installed {hook}")
        return EXIT_OK

    existing = hook.read_text(encoding="utf-8")
    if script.name in existing:
        print(f"{hook} already runs {script.name}; nothing to do.")
        return EXIT_OK

    # scripts/orphan-req-check.py installs an `exec`-terminated hook. Anything
    # appended after that never runs, so the two are merged rather than
    # concatenated. Only that exact shape is handled: an unrecognised hook is
    # somebody else's and gets instructions, not an edit.
    if "orphan-req-check.py" in existing and re.search(r"^exec\s", existing, re.M):
        merged = re.sub(r"^exec\s+", "", existing, count=1, flags=re.M) + line
        hook.write_text(merged, encoding="utf-8")
        hook.chmod(0o755)
        print(f"merged into {hook}")
        print("  (dropped the `exec` from the orphan-req-check line so both run)")
        return EXIT_OK

    print(f"error: {hook} exists and is not a hook this script recognises.\n"
          f"Add this line to it by hand:\n\n  {line}", file=sys.stderr)
    return EXIT_ERROR


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Report plan steps that hand over the whole of an artifact "
                    "that has grown since the step was written.")
    ap.add_argument("--repo-root", type=Path, default=None,
                    help="clasp checkout (default: this script's parent repo)")
    ap.add_argument("--plans-dir", type=Path, default=None,
                    help="audit an arbitrary directory of plans instead of docs/")
    ap.add_argument("--all", action="store_true",
                    help="also list RECORD findings (plans marked EXECUTED)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true",
                    help="run the check against fixtures with known answers")
    ap.add_argument("--install-hook", action="store_true",
                    help="install a post-commit hook into the docs repo")
    args = ap.parse_args()

    script = Path(__file__).resolve()
    root = (args.repo_root or script.parent.parent).resolve()

    if args.self_test:
        corpus = root if (root / "docs" / "superpowers" / "plans").is_dir() else None
        return self_test(corpus)

    if args.install_hook:
        return install_hook(root, script)

    plans_dir = args.plans_dir or (root / "docs" / "superpowers" / "plans")
    if not plans_dir.is_dir():
        print(
            f"CANNOT RUN: no plans at {plans_dir}.\n"
            "\n"
            "`docs/` is git-ignored in this repository and lives in a separate\n"
            "git repo, so a clone -- including whatever CI checks out -- does\n"
            "not have it. This is not a pass: nothing was checked. Run this\n"
            "where the docs repo is present, `git clone` it into ./docs, or\n"
            "point --plans-dir at the plans.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    plans = sorted(plans_dir.glob("*.md"))
    if not plans:
        print(f"error: no plans in {plans_dir} — a clean result would be vacuous",
              file=sys.stderr)
        return EXIT_ERROR

    report = scan(plans, root)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render(report, show_record=args.all))

    return EXIT_FINDINGS if report["counts"]["blocking"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
