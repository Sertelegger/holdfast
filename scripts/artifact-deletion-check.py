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
# THE SAME DEFECT ONE TIER DOWN, which is where plans actually operate.
# Measured after the file tier shipped: 0.0.4's re-verification found seven
# Blocking and FOUR of them were item-level, with this tool reporting zero
# and being right to by its own rules. A `use` block that deleted four
# imports added since; a function body that deleted two calls in favour of a
# method that does not exist; a six-element array against a file holding
# seven; a loop body that dropped a fan-out. 0.0.3 and 0.0.8 each replace
# `pub struct ClaspServer` and its `impl`, and 0.0.8's drops the `processor`
# field every read path reads. None of these is a whole file.
#
# So there is a THIRD TIER, on the same shape as the first -- resolve what
# the block claims to be, find that item in the named file, diff its members,
# report deletions -- and the whole difficulty is in the first step. It is
# harder here than at file level, so the tier is deliberately narrow:
#
#   1. SHAPE. The block must parse, from its own bytes, into a sequence of
#      COMPLETE top-level Rust items (or be a single bracketed array
#      literal). "Complete" is the load-bearing word and it is what keeps
#      illustrative snippets out: a bare statement sequence, a signature with
#      no body, a `match` arm quoted on its own, a body with a `// …`
#      elision in it -- none of these parses, and each is counted and
#      reported as undecidable rather than guessed at.
#
#   2. IDENTITY, from the item's own opener: `use`, `pub struct NAME`,
#      `enum NAME`, `impl NAME`, `fn NAME`, `const NAME: [T; N]`. The kind
#      and the name come out of the block; nothing is inferred from prose.
#
#   3. PATH, and this is the part that is genuinely harder than at file
#      level, because the path is often not adjacent -- 0.0.4's
#      `fn detection` block sits under two paragraphs that name a different
#      file. So the path is not guessed: every path named in the lines above
#      AND every path in the enclosing task's `Files:` list is a candidate,
#      and the tier proceeds only when EXACTLY ONE candidate actually
#      contains the item. Disk arbitrates, not prose. Zero candidates or two
#      is an undecidable, counted and reported.
#
#   4. MEMBERSHIP, which differs by kind and is the only thing compared: a
#      `use` block's members are its imported leaf paths, a struct's its
#      fields, an enum's its variants, an inherent `impl`'s its methods, a
#      function's its body statements, an array's its elements. A deletion
#      is a member the file has today that the block accounts for nowhere.
#
# WHAT THIS TIER STILL CANNOT DO, said plainly rather than papered over,
# with the measured cost of each:
#
#   * A BARE BODY. 0.0.4 Task 6 Step 4 -- one of the four cases this tier was
#     built for -- is a statement sequence introduced by "Make it:", and
#     nothing in its bytes says which loop it is the whole of. It is NOT
#     found, and that is the honest answer rather than a guess. Same for a
#     `match` arm list, which has neither name nor opener.
#   * A `use` BLOCK INSIDE `mod tests`. The anchor reads the file's
#     module-level imports, so a test module's import list never matches.
#     0.0.4 Task 6 Step 6 is one of these.
#   * A `use` BLOCK WHOSE FIRST STATEMENT WAS WIDENED since. The anchor is
#     exact statement equality, so a name added inside the first `use`'s
#     brace list makes the whole block unanchorable. Narrower than it could
#     be, and deliberately: a prefix match would anchor on the wrong file.
#   * A `#[test]` FUNCTION. Measured on this corpus: every block of test
#     functions is a block being appended, so the plan's copy is the older
#     one by construction and diffing it reports the implementer's own
#     improvements as deletions. That was 25 of 33 `fn` findings in the first
#     run and none of them was a deletion risk.
#   * A `trait`, a `type` alias, a tuple struct. No members this tier knows
#     how to compare.
#   * A WHOLE-FILE BLOCK THAT OPENS ON `use` OR `mod`. It is a whole-file
#     replacement, so it is tier 1's question -- but tier 1's shape test
#     looks for `//!`, a shebang or a TOML/YAML document and cannot see it,
#     and diffing its functions one at a time reports a deliberate rewrite as
#     a pile of deletions. Declined here, COUNTED, and each one named in the
#     summary. It is the one known hole in the pair of tiers.
#
# Every decline above is counted and the summary prints the numbers: a tier
# that guessed at these would report deletions of everything else in the file
# and be switched off within the week.
#
# The one word this tier reads is the same one the module-list tier reads,
# for the same reason and in the same direction: an import block introduced
# by "add"/"insert" is a delta, and "add two lines" and "the list becomes"
# are the same bytes. It can only ever suppress, never accuse. A `use` block
# additionally has to ANCHOR: its first statement must be the file's first
# module-level `use`. An "add these three imports" block almost never opens
# on the file's first import, and one that does is suppressed by the word.
#
# NO DOUBLE COUNTING. Tier 1 sees every block first. The item tier is
# offered only blocks tier 1 declined, so no block is ever reported twice and
# the two tiers' counts add rather than overlap.
#
# WHAT NO TIER CAN DO. "Looks like a whole artifact" is answerable for a
# file, for a TOML table and -- with the four gates above -- for a named Rust
# item. It is not answerable for an anonymous fragment. The one fragment
# shape that is decidable without any of that machinery is a
# module-declaration list (every significant line is `mod x;` or
# `pub mod x;`), because the disk side is exactly the module declarations of
# that file; it is checked as a second tier, and suppressed when the prose
# says "add"/"insert", for the reason given above.
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
#
# Exit codes: 0 clean, 1 blocking findings, 2 self-test failure or bad usage,
# 3 could not run (no plans).

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

# ---- tier 3 (item level) -------------------------------------------------
#
# A wider lookback than tier 1's, because an item block's path is routinely
# two paragraphs and one code block further up than a whole-file block's.
# Widening it is safe here only because the path is not trusted on its own:
# the item has to be FOUND at it (see `resolve_item_path`).
ITEM_LOOKBACK = 34

# Below this an import block is an addition however it is worded.
MIN_USE_STATEMENTS = 3

# A bare array literal is located in the file by its first element. Short
# elements are not identifying, and a two-element array is a tuple by another
# name; both floors exist to keep the search from landing on a coincidence.
MIN_ARRAY_ELEMENTS = 3
MIN_ARRAY_FIRST_ELEM_CHARS = 8

# A block with any of these in it is quoting an item in part. It is not a
# replacement and its "missing" members are missing on purpose.
ELISION_LINE_RE = re.compile(r"^(?:(?://+|#|/\*)\s*)?(?:\.\.\.|…)[\s.*/]*$")
ELISION_WORD_RE = re.compile(
    r"\b(unchanged|snip|elided|omitted|as before|rest of|remainder|"
    r"abridged|truncated|and so on|etc)\b", re.I)

# `crates/x/src/y.rs:245` in a backtick names `crates/x/src/y.rs`. Tier 1
# does not strip this because a whole-file block is never introduced with a
# line number; an item block routinely is, because the line number is how the
# step tells you where the item sits.
LINE_SUFFIX_RE = re.compile(r":\d+(?:[-:]\d+)?$")

# The `Files:` list at the head of a task. Its paths are candidates for every
# item block in that task, which is what rescues the blocks whose own
# paragraph names a different file.
TASK_FILE_RE = re.compile(
    r"^\s*[-*]\s*\**\s*(?:Modify|Create|Delete|New|Add|Edit|Rewrite|Update|"
    r"Touch|Read)\b", re.I)

_VIS = r"(?:pub(?:\s*\([^)]*\))?\s+)?"
ITEM_OPENERS = [
    ("use", re.compile(_VIS + r"use\s+(?P<name>[^;{]*)")),
    ("fn", re.compile(
        _VIS + r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("struct", re.compile(_VIS + r"struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("enum", re.compile(_VIS + r"enum\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("trait", re.compile(_VIS + r"(?:unsafe\s+)?trait\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("impl", re.compile(r"impl\b(?P<name>.*)")),
    ("const", re.compile(_VIS + r"const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:")),
    ("static", re.compile(_VIS + r"static\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:")),
    ("type", re.compile(_VIS + r"type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("mod", re.compile(_VIS + r"mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
]

# The kinds whose membership this tier knows how to compare. `trait`, `type`
# and `mod` parse but are not checked: a trait's members are signatures whose
# disk form differs by whitespace more often than by content, `type` has no
# members, and `mod` is tier 2's.
CHECKABLE_ITEM_KINDS = {"struct", "enum", "impl", "fn", "const", "static"}

ITEM_MEMBER_NOUN = {
    "use-block": "import",
    "struct": "field",
    "enum": "variant",
    "impl": "item",
    "fn": "statement",
    "const": "element",
    "static": "element",
    "array": "element",
}

STRUCT_FIELD_RE = re.compile(_VIS + r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:")
ENUM_VARIANT_RE = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:[({=,]|$)")
IMPL_MEMBER_RE = re.compile(
    _VIS + r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?(?P<what>fn|const|type)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)")

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
                 context: list[str], where: str,
                 prose: list[str] | None = None,
                 task_files: list[str] | None = None,
                 item_context: list[str] | None = None):
        self.plan = plan
        self.line = line          # 1-based line of the opening fence
        self.lang = lang
        self.body = body
        self.context = context    # the LOOKBACK lines above the fence
        self.where = where        # "Task 1 / Step 4", best effort
        # The prose since the PREVIOUS fence closed. Tier 3's suppressor
        # reads this rather than `context`, because three code blocks in one
        # step are routine and a fixed line count reaches over them into a
        # sentence belonging to a different block.
        self.prose = prose or []
        # The paths in the enclosing task's `Files:` list.
        self.task_files = task_files or []
        # Tier 3 looks further up than tier 1 for a path, because an item
        # block's path is routinely a paragraph and a code block further
        # away than a whole-file block's. Safe only because the path is not
        # trusted on its own: the item has to be FOUND at it.
        self.item_context = item_context or self.context


def iter_blocks(plan: Path):
    """Yield every fenced block, with the lines above it and its Task/Step.

    A closing fence is a fence line with no info string, of the same
    character and at least the opening length; that is CommonMark's rule and
    it keeps a nested ```` block from ending its parent early.
    """
    lines = plan.read_text(encoding="utf-8").splitlines()
    task = step = ""
    task_files: list[str] = []
    prev_end = 0              # index just after the last closing fence
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            tm = TASK_RE.match(lines[i])
            if tm:
                task, step = tm.group(1), ""
                task_files = []
            else:
                sm = STEP_RE.match(lines[i])
                if sm:
                    step = sm.group(1)
                elif TASK_FILE_RE.match(lines[i]):
                    for p in paths_on_relaxed(lines[i]):
                        if p not in task_files:
                            task_files.append(p)
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
                    lines[max(0, i - LOOKBACK):i], where,
                    prose=lines[max(prev_end, i - LOOKBACK):i],
                    task_files=list(task_files),
                    item_context=lines[max(0, i - ITEM_LOOKBACK):i])
        i = j + 1
        prev_end = i


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
# Tier 3: item-level replacement
#
# Enough Rust to answer one question -- "does this block consist entirely of
# complete items, and if so which ones" -- and no more. Everything it cannot
# answer it declines, and every decline is counted.
# --------------------------------------------------------------------------


def mask_rust(lines: list[str]) -> list[str]:
    """Blank out comments, strings and char literals, keeping columns.

    Everything below counts braces, and a brace inside `"{"` or after `//`
    is not a brace. String state carries across lines on purpose: this
    codebase's `instructions` literal is one `\\`-continued string sixty
    lines long, and a scanner that reset at each newline would read its
    prose as code.
    """
    out: list[str] = []
    in_block = 0
    in_str: tuple | None = None
    for line in lines:
        buf: list[str] = []
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if in_block:
                if c == "/" and nxt == "*":
                    in_block += 1
                    buf.append("  ")
                    i += 2
                    continue
                if c == "*" and nxt == "/":
                    in_block -= 1
                    buf.append("  ")
                    i += 2
                    continue
                buf.append(" ")
                i += 1
                continue
            if in_str is not None:
                if in_str[0] == '"':
                    if c == "\\":
                        buf.append("  ")
                        i += 2
                        continue
                    if c == '"':
                        in_str = None
                    buf.append(" ")
                    i += 1
                    continue
                h = in_str[1]
                if c == '"' and line[i + 1:i + 1 + h] == "#" * h:
                    in_str = None
                    buf.append(" " * (1 + h))
                    i += 1 + h
                    continue
                buf.append(" ")
                i += 1
                continue
            if c == "/" and nxt == "/":
                buf.append(" " * (n - i))
                break
            if c == "/" and nxt == "*":
                in_block = 1
                buf.append("  ")
                i += 2
                continue
            if c == '"':
                in_str = ('"',)
                buf.append(" ")
                i += 1
                continue
            if (c == "r" and nxt in ('"', "#")
                    and (i == 0 or not (line[i - 1].isalnum() or line[i - 1] == "_"))):
                j, h = i + 1, 0
                while j < n and line[j] == "#":
                    h += 1
                    j += 1
                if j < n and line[j] == '"':
                    in_str = ("r", h)
                    buf.append(" " * (j - i + 1))
                    i = j + 1
                    continue
            if c == "'":
                m = re.match(r"'(?:\\.|[^\\'])'", line[i:])
                if m:
                    buf.append(" " * m.end())
                    i += m.end()
                    continue
            buf.append(c)
            i += 1
        out.append("".join(buf))
    return out


def _delta(code: str) -> int:
    return (code.count("{") - code.count("}")
            + code.count("(") - code.count(")")
            + code.count("[") - code.count("]"))


def dedent(lines: list[str]) -> list[str]:
    pad = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return [l[pad:] if l.strip() else "" for l in lines]


def has_elision(body: list[str]) -> bool:
    """Is this block quoting an item in part rather than handing it over?"""
    for line in body:
        s = line.strip()
        if not s:
            continue
        if ELISION_LINE_RE.match(s):
            return True
        if s.startswith("//") or s.startswith("#") or s.startswith("/*"):
            if ELISION_WORD_RE.search(s) or "…" in s:
                return True
    return False


class RItem:
    def __init__(self, kind: str, name: str, lines: list[str], masked: list[str],
                 attrs: list[str] | None = None):
        self.kind = kind
        self.name = name
        self.lines = lines
        self.masked = masked
        self.attrs = attrs or []

    @property
    def is_test(self) -> bool:
        return any(re.search(r"\btest\b", a) for a in self.attrs)

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<RItem {self.kind} {self.name!r} {len(self.lines)}L>"


def item_end(lines: list[str], masked: list[str], start: int) -> int | None:
    """Index of the last line of the item opening at `start`, or None.

    None means the item does not close inside `lines` -- a signature with no
    body, a body cut off mid-brace. That is the decline that keeps snippets
    out, so it is a real answer rather than a failure.
    """
    depth = 0
    opened = False
    for j in range(start, len(lines)):
        code = masked[j]
        depth += _delta(code)
        if any(ch in code for ch in "{(["):
            opened = True
        if depth < 0:
            return None
        if depth == 0:
            s = code.rstrip()
            if s.endswith(";") or (opened and (s.endswith("}") or s.endswith("},"))):
                return j
    return None


def split_items(lines: list[str]) -> list[RItem] | None:
    """Split a dedented block into complete top-level items, or decline.

    Declines -- returns None -- the moment it meets anything that is not an
    item: a bare statement, a `match` arm, an unterminated signature. That is
    the gate. Everything this tier reports has passed it.
    """
    masked = mask_rust(lines)
    items: list[RItem] = []
    attrs: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        s = lines[i].strip()
        if not s or s.startswith("//"):
            i += 1
            continue
        if s.startswith("#[") or s.startswith("#!["):
            j, depth = i, 0
            while j < n:
                depth += masked[j].count("[") - masked[j].count("]")
                if depth <= 0:
                    break
                j += 1
            attrs.append(" ".join(l.strip() for l in lines[i:j + 1]))
            i = j + 1
            continue
        kind = name = None
        for k, rx in ITEM_OPENERS:
            m = rx.match(s)
            if m:
                kind = k
                name = (m.group("name") or "").strip()
                break
        if kind is None:
            return None
        end = item_end(lines, masked, i)
        if end is None:
            return None
        if kind == "impl":
            name = re.sub(r"\s*\{\s*$", "", lines[i].strip())
            name = re.sub(r"\s+", " ", name)
        items.append(RItem(kind, name, lines[i:end + 1], masked[i:end + 1], attrs))
        attrs = []
        i = end + 1
    return items or None


def top_level_ids(lines: list[str], masked: list[str]) -> set[tuple[str, str]]:
    """Every top-level item of a Rust FILE, as (kind, name).

    Lenient where `split_items` is strict: a real file has macros, `#![...]`
    and shapes this scanner does not model, and skipping them is right here.
    It exists for one question -- is a block the whole of this file? -- and a
    scanner that gave up on the first oddity could never answer it.
    """
    ids: set[tuple[str, str]] = set()
    i, n = 0, len(lines)
    depth = 0
    while i < n:
        if depth == 0:
            s = lines[i].strip()
            hit = None
            for k, rx in ITEM_OPENERS:
                m = rx.match(s)
                if m:
                    hit = (k, (m.group("name") or "").strip())
                    break
            if hit:
                end = item_end(lines, masked, i)
                if end is not None:
                    kind, name = hit
                    if kind == "use":
                        ids.add(("use", ""))
                    elif kind == "impl":
                        ids.add(("impl", re.sub(
                            r"\s+", " ", re.sub(r"\s*\{\s*$", "", s))))
                    else:
                        ids.add((kind, name))
                    for j in range(i, end + 1):
                        depth += _delta(masked[j])
                    i = end + 1
                    continue
        depth += _delta(masked[i])
        i += 1
    return ids


def logical_statements(lines: list[str], masked: list[str]) -> list[str]:
    """A function body as statements rather than as physical lines.

    Physical lines are the wrong unit here and measurably so: a rustfmt'd
    call wraps into `.expect("x");` and `);` and `.as_u64()`, and a set
    comparison over those reports six deletions for one changed call and is
    unreadable. Joining continuations gives one member per statement, which
    is the unit a reader can act on.
    """
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for line, code in zip(lines, masked):
        if not code.strip():
            continue                       # blank, or comment-only
        cur.append(line.strip())
        depth += _delta(code)
        s = code.rstrip()
        if depth <= 0 and (s.endswith(";") or s.endswith("}")
                           or s.endswith("},") or s.endswith(",")):
            out.append(re.sub(r"\s+", " ", " ".join(cur)))
            cur = []
            depth = 0
    if cur:
        out.append(re.sub(r"\s+", " ", " ".join(cur)))
    return out


# ---- membership, by kind -------------------------------------------------


def use_statements(lines: list[str], masked: list[str]) -> list[str]:
    """Every module-level `use` statement, normalised to one line each."""
    out: list[str] = []
    i, n = 0, len(lines)
    depth = 0
    while i < n:
        s = lines[i].strip()
        if depth == 0 and re.match(r"^use\s", s):
            end = item_end(lines, masked, i)
            if end is None:
                return out
            stmt = " ".join(l.strip() for l in lines[i:end + 1])
            out.append(normalise_use(stmt))
            depth += sum(_delta(masked[j]) for j in range(i, end + 1))
            i = end + 1
            continue
        depth += _delta(masked[i])
        i += 1
    return out


def normalise_use(stmt: str) -> str:
    s = re.sub(r"\s+", " ", stmt.strip()).rstrip(";").strip()
    s = s.replace("{ ", "{").replace(" }", "}").replace(" ,", ",")
    s = re.sub(r",\s*}", "}", s)
    return s


def use_leaves(stmt: str) -> list[str]:
    """`use a::{b, c::{d, e}};` -> ['a::b', 'a::c::d', 'a::c::e']."""
    s = normalise_use(stmt)
    s = re.sub(r"^use\s+", "", s)

    def expand(text: str) -> list[str]:
        k = text.find("{")
        if k < 0:
            return [text.strip()]
        prefix = text[:k]
        depth, parts, cur = 0, [], []
        for ch in text[k:]:
            if ch == "{":
                depth += 1
                if depth == 1:
                    continue
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    if "".join(cur).strip():
                        parts.append("".join(cur).strip())
                    cur = []
                    continue
            elif ch == "," and depth == 1:
                if "".join(cur).strip():
                    parts.append("".join(cur).strip())
                cur = []
                continue
            cur.append(ch)
        out: list[str] = []
        for p in parts:
            out.extend(prefix + q for q in expand(p))
        return out

    return [re.sub(r"\s+", " ", x).strip() for x in expand(s) if x.strip()]


def body_span(item: RItem) -> tuple[int, int] | None:
    """The lines strictly inside the item's outermost `{ ... }`."""
    for i, code in enumerate(item.masked):
        if "{" in code:
            return i + 1, len(item.lines) - 1
    return None


def members_at_top_of_body(item: RItem):
    """Yield (index, stripped_line) for lines at depth 0 inside the body."""
    span = body_span(item)
    if span is None:
        return
    start, end = span
    # Depth left over on the opening line after its first `{`.
    open_code = item.masked[start - 1]
    depth = _delta(open_code[open_code.index("{"):])
    for j in range(start, end):
        code = item.masked[j]
        if depth == 1 and code.strip():
            yield j, item.lines[j].strip()
        depth += _delta(code)


def item_members(item: RItem) -> list[str] | None:
    if item.kind == "struct":
        if "{" not in "".join(item.masked):
            return None                      # unit or tuple struct
        out = []
        for _, s in members_at_top_of_body(item):
            if s.startswith("//") or s.startswith("#["):
                continue
            m = STRUCT_FIELD_RE.match(s)
            if m:
                out.append(m.group("name"))
        return out or None
    if item.kind == "enum":
        out = []
        for _, s in members_at_top_of_body(item):
            if s.startswith("//") or s.startswith("#["):
                continue
            m = ENUM_VARIANT_RE.match(s)
            if m:
                out.append(m.group("name"))
        return out or None
    if item.kind == "impl":
        out = []
        for _, s in members_at_top_of_body(item):
            m = IMPL_MEMBER_RE.match(s)
            if m:
                out.append(f"{m.group('what')} {m.group('name')}")
        return out or None
    if item.kind == "fn":
        span = body_span(item)
        if span is None:
            return None
        start, end = span
        out = logical_statements(item.lines[start:end], item.masked[start:end])
        return out or None
    if item.kind in ("const", "static"):
        joined = " ".join(l.strip() for l in item.lines)
        k = joined.find("=")
        if k < 0:
            return None
        parsed = parse_array(joined[k + 1:].strip())
        if parsed is None:
            return None
        elems = parsed[0]
        return elems if len(elems) >= MIN_ARRAY_ELEMENTS else None
    return None


# ---- array literals ------------------------------------------------------


def parse_array(text: str) -> tuple[list[str], int] | None:
    """Top-level elements of the `[...]` starting at text[0], and its end."""
    if not text.startswith("["):
        return None
    depth, elems, cur = 0, [], []
    in_s = None
    prev = ""
    for i, c in enumerate(text):
        if in_s:
            cur.append(c)
            if c == in_s and prev != "\\":
                in_s = None
            prev = c
            continue
        if c in "\"'":
            in_s = c
            cur.append(c)
            prev = c
            continue
        if c in "[({":
            depth += 1
            if depth > 1:
                cur.append(c)
            prev = c
            continue
        if c in "])}":
            depth -= 1
            if depth == 0:
                if "".join(cur).strip():
                    elems.append(re.sub(r"\s+", " ", "".join(cur)).strip())
                return elems, i
            cur.append(c)
            prev = c
            continue
        if c == "," and depth == 1:
            if "".join(cur).strip():
                elems.append(re.sub(r"\s+", " ", "".join(cur)).strip())
            cur = []
            prev = c
            continue
        cur.append(c)
        prev = c
    return None


def as_array_literal(body: list[str]) -> list[str] | None:
    """A block that is nothing but one bracketed array literal."""
    text = "\n".join(l for l in body if l.strip()).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1].strip()
    if not text.startswith("["):
        return None
    parsed = parse_array(text)
    if parsed is None or parsed[1] != len(text) - 1:
        return None
    elems = parsed[0]
    if len(elems) < MIN_ARRAY_ELEMENTS:
        return None
    if len(elems[0]) < MIN_ARRAY_FIRST_ELEM_CHARS:
        return None
    return elems


def find_arrays_by_first_element(disk_text: str, first: str) -> list[list[str]]:
    """Every array literal in the file whose first element is exactly `first`.

    The search key is the element as the block spells it, and the character
    before it has to be the array's own `[`. That is what makes this a
    location rather than a guess: a match means the file holds an array that
    starts the same way, and anything else means it does not.
    """
    hits, start = [], 0
    while True:
        k = disk_text.find(first, start)
        if k < 0:
            return hits
        # The `[` test only skips a parse; `parse_array` refuses anything
        # that does not open on one, so the two agree by construction.
        if k > 0 and disk_text[k - 1] == "[":
            parsed = parse_array(disk_text[k - 1:])
            if parsed and parsed[0] and parsed[0][0] == first:
                hits.append(parsed[0])
        start = k + 1


# ---- locating an item in a file ------------------------------------------


def item_locator(item: RItem) -> re.Pattern | None:
    n = re.escape(item.name)
    if item.kind == "struct":
        return re.compile(r"^\s*" + _VIS + r"struct\s+" + n + r"\b")
    if item.kind == "enum":
        return re.compile(r"^\s*" + _VIS + r"enum\s+" + n + r"\b")
    if item.kind == "fn":
        return re.compile(r"^\s*" + _VIS + r"(?:default\s+)?(?:const\s+)?"
                          r"(?:async\s+)?(?:unsafe\s+)?"
                          r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+" + n + r"\s*[(<]")
    if item.kind in ("const", "static"):
        return re.compile(r"^\s*" + _VIS + item.kind + r"\s+(?:mut\s+)?" + n + r"\s*:")
    if item.kind == "impl":
        return None                          # matched on the whole header
    return None


def locate_in_file(item: RItem, disk_lines: list[str],
                   disk_masked: list[str]) -> RItem | None:
    """The one item of this kind and name in the file, or None.

    None also means "more than one", deliberately: two `fn feed` in a file
    and this tier does not know which the block is, so it says so instead of
    picking.
    """
    starts: list[int] = []
    if item.kind == "impl":
        for j, line in enumerate(disk_lines):
            if not disk_masked[j].strip():
                continue
            head = re.sub(r"\s*\{\s*$", "", line.strip())
            if re.sub(r"\s+", " ", head) == item.name:
                starts.append(j)
    else:
        rx = item_locator(item)
        if rx is None:
            return None
        for j, line in enumerate(disk_lines):
            if disk_masked[j].strip() and rx.match(line):
                starts.append(j)
    if len(starts) != 1:
        return None
    j = starts[0]
    end = item_end(disk_lines, disk_masked, j)
    if end is None:
        return None
    return RItem(item.kind, item.name,
                 dedent(disk_lines[j:end + 1]),
                 dedent(disk_masked[j:end + 1]))


# ---- classification, path resolution, and the diff -----------------------


class ItemClaim:
    """What a block claims to be, at item level."""

    def __init__(self, kind: str, name: str, members: list[str],
                 anchor: str | None = None, extra: dict | None = None):
        self.kind = kind            # 'use-block' | 'array' | a Rust item kind
        self.name = name
        self.members = members
        self.anchor = anchor
        self.extra = extra or {}


def classify_item(body: list[str]) -> tuple[list[ItemClaim] | None, str]:
    """The item(s) this block hands over, or (None, why-not)."""
    if not [l for l in body if l.strip()]:
        return None, "empty"
    if has_elision(body):
        return None, "elided"

    elems = as_array_literal(body)
    if elems is not None:
        return [ItemClaim("array", "array literal", elems,
                          anchor=elems[0])], ""

    lines = dedent(body)
    items = split_items(lines)
    if items is None:
        return None, "not-whole-items"

    if all(i.kind == "use" for i in items):
        if len(items) < MIN_USE_STATEMENTS:
            return None, "too-few-imports"
        stmts = [normalise_use(" ".join(l.strip() for l in i.lines)) for i in items]
        leaves: list[str] = []
        for s in stmts:
            leaves.extend(use_leaves(s))
        return [ItemClaim("use-block", "the module-level `use` block", leaves,
                          anchor=stmts[0], extra={"statements": stmts})], ""

    claims: list[ItemClaim] = []
    for it in items:
        if it.kind not in CHECKABLE_ITEM_KINDS:
            continue
        # A `#[test]` function is not judged, and the reason is measured
        # rather than aesthetic. Across this corpus every block of test
        # functions is a block being APPENDED to a test module -- "add these
        # three tests at the end" -- so the plan's copy is the older, smaller
        # one by construction and diffing it against the file reports the
        # implementer's own improvements as deletions. That was 25 of the 33
        # `fn` findings in the first run of this tier and none of them was a
        # deletion risk. A test that is genuinely being REPLACED is expressed
        # as a Find/Replace pair in every plan here, which this tier already
        # declines for a stronger reason.
        if it.kind == "fn" and it.is_test:
            continue
        members = item_members(it)
        if members is None:
            continue
        claims.append(ItemClaim(it.kind, it.name, members,
                                extra={"item": it}))
    if not claims:
        return None, "no-checkable-item"
    ids: set[tuple[str, str]] = set()
    for it in items:
        if it.kind == "use":
            ids.add(("use", ""))
        else:
            ids.add((it.kind, it.name))
    for c in claims:
        c.extra["block_ids"] = ids
    return claims, ""


def paths_on_relaxed(line: str) -> list[str]:
    out = []
    for tok in BACKTICK_RE.findall(line):
        tok = LINE_SUFFIX_RE.sub("", tok.strip())
        if " " in tok or tok.endswith("/"):
            continue
        if PATH_RE.match(tok):
            out.append(tok)
    return out


def item_path_candidates(blk) -> list[str]:
    cands: list[str] = []
    for line in reversed(blk.item_context):
        for p in paths_on_relaxed(line):
            if p not in cands:
                cands.append(p)
    for p in blk.task_files:
        if p not in cands:
            cands.append(p)
    return cands


def disk_claim_members(claim: ItemClaim, disk_text: str, disk_lines: list[str],
                       disk_masked: list[str]) -> tuple[list[str], list[str]] | None:
    """The members the file holds for what this claim says it is, or None.

    Returns `(members, disk_statements)`; the second is empty except for a
    `use` block, where the headline needs to name a whole deleted statement
    rather than each of its six imported paths.
    """
    if claim.kind == "array":
        hits = find_arrays_by_first_element(disk_text, claim.anchor)
        return (hits[0], []) if len(hits) == 1 else None
    if claim.kind == "use-block":
        stmts = use_statements(disk_lines, disk_masked)
        # THE ANCHOR. A file's import block is identified by its first
        # module-level `use`, and a block that does not open on it is not
        # claiming to be the whole of this file's imports -- it is three
        # lines somebody is adding. This is what keeps the tier off every
        # illustrative `use` snippet in the corpus, and it is a disk fact
        # rather than a reading of the prose.
        if not stmts or stmts[0] != claim.anchor:
            return None
        leaves: list[str] = []
        for s in stmts:
            leaves.extend(use_leaves(s))
        return leaves, stmts
    found = locate_in_file(claim.extra["item"], disk_lines, disk_masked)
    if found is None:
        return None
    members = item_members(found)
    return None if members is None else (members, [])


def check_item_block(blk, root: Path, plan: Path, record: bool,
                     stats: dict) -> list[dict]:
    """Tier 3 on one block. Appends to `stats` for every decline."""
    claims, why = classify_item(blk.body)
    if claims is None:
        # "elided" and "no-checkable-item" are blocks that DID hand over an
        # item and that this tier declined; the rest were never items at all.
        # The two are reported separately because only the first is a gap.
        if why in ("elided", "no-checkable-item"):
            stats["item_undecidable"] += 1
            stats.setdefault("item_undecidable_why", {})
            stats["item_undecidable_why"][why] = \
                stats["item_undecidable_why"].get(why, 0) + 1
        return []

    stats["item_blocks"] += 1
    stats["item_claims"] += len(claims)

    # The one word this tier reads, in the one direction it may read it.
    prose = " ".join(blk.prose)
    suppress_use = bool(ADDITION_RE.search(prose))

    out: list[dict] = []
    for claim in claims:
        if claim.kind == "use-block" and suppress_use:
            stats["item_addition_suppressed"] += 1
            continue

        resolved = []
        for rel in item_path_candidates(blk):
            target = root / rel
            if not target.is_file():
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            masked = mask_rust(lines)
            got = disk_claim_members(claim, text, lines, masked)
            if got is not None:
                resolved.append((rel, got[0], got[1]))
        # EXACTLY ONE. Zero means the item is nowhere the step could plausibly
        # mean -- usually because the plan is creating it. Two means this tier
        # does not know which file the block is about, and a tier that picked
        # would diff a struct against its namesake in another module.
        if len(resolved) != 1:
            stats["item_unresolved"] += 1
            continue

        rel, disk_members, disk_stmts = resolved[0]

        # THE WHOLE FILE IS NOT AN ITEM. A block that accounts for every
        # top-level item the file has is a whole-file replacement, which is
        # tier 1's question and not this one's -- and diffing its functions
        # one at a time reports a deliberate rewrite as a pile of deletions.
        # 0.0.5 Task 13 Step 2 ("Replace `crates/clasp/src/main.rs` with:")
        # is exactly this and produced two such findings before the gate.
        # Declined, counted, and named in the summary rather than dropped:
        # tier 1's shape test cannot see these blocks (no `//!`, no
        # shebang), so this number is a real hole and printing it is how it
        # stays visible.
        if claim.kind not in ("array",):
            file_ids = top_level_ids(
                (root / rel).read_text(encoding="utf-8",
                                       errors="replace").splitlines(),
                mask_rust((root / rel).read_text(encoding="utf-8",
                                                 errors="replace").splitlines()))
            if file_ids and file_ids <= claim.extra.get("block_ids", set()):
                # Counted per BLOCK, not per item in it, so the number and
                # the list below it agree.
                stats.setdefault("item_whole_file_where", [])
                if [plan.name, blk.line, rel] not in stats["item_whole_file_where"]:
                    stats["item_whole_file_where"].append([plan.name, blk.line, rel])
                    stats["item_whole_file"] += 1
                continue

        claim.extra["disk_statements"] = disk_stmts
        block_set = set(claim.members)
        deleted = [m for m in dict.fromkeys(disk_members) if m not in block_set]
        added = [m for m in dict.fromkeys(claim.members)
                 if m not in set(disk_members)]

        # NAMESAKE GUARD. Two items with the same name in different modules
        # look identical from the block, and `fn foreground_group` has three
        # definitions in this tree -- the trait default and two impls. If the
        # block and the file share no member at all they are not the same
        # item, and reporting a 100% deletion would be reporting a
        # mislocation. Measured: this is what the first run of this tier did
        # to `PtyBackend::foreground_group`.
        if deleted and not (block_set & set(disk_members)):
            stats["item_no_overlap"] += 1
            continue
        out.append({
            "tier": "item",
            "plan": plan.name,
            "line": blk.line,
            "where": blk.where,
            "kind": claim.kind,
            "item": claim.name,
            "path": rel,
            "executed_record": record,
            "disk_significant": len(set(disk_members)),
            "block_significant": len(block_set),
            "deleted": deleted,
            "added_not_on_disk": len(added),
            "names": item_names(claim, deleted, disk_members),
        })
    return out


def item_names(claim: ItemClaim, deleted: list[str],
               disk_members: list[str]) -> list[str]:
    noun = ITEM_MEMBER_NOUN.get(claim.kind, "member")
    if claim.kind == "use-block":
        # A statement all of whose leaves are gone is named as a statement:
        # "the whole `crate::output::{…}` statement" is what a reader has to
        # look for, not six separate paths.
        return group_use_deletions(claim, deleted)
    return [f"{noun} `{d[:70]}`" for d in deleted[:12]]


def group_use_deletions(claim: ItemClaim, deleted: list[str]) -> list[str]:
    gone = set(deleted)
    named: list[str] = []
    claimed: set[str] = set()
    for stmt in claim.extra.get("disk_statements", []):
        leaves = use_leaves(stmt)
        if leaves and all(l in gone for l in leaves):
            head = re.sub(r"^use\s+", "", stmt)
            named.append(f"the whole `{head}` statement")
            claimed.update(leaves)
    for d in deleted:
        if d not in claimed:
            named.append(f"import `{d}`")
    return named


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------


def scan(plans: list[Path], root: Path) -> dict:
    raw: list[dict] = []
    items: list[dict] = []
    stats = {
        "blocks": 0,
        "whole_artifact_blocks": 0,
        "unresolved_path": 0,
        "path_absent": 0,
        "superseded": 0,
        "clean": 0,
        "anchored_edit": 0,
        "fragments_undecidable": 0,
        # Tier 3.
        "item_blocks": 0,
        "item_claims": 0,
        "item_unresolved": 0,
        "item_undecidable": 0,
        "item_addition_suppressed": 0,
        "item_clean": 0,
        "item_superseded": 0,
        "item_anchored_edit": 0,
        "item_whole_file": 0,
        "item_no_overlap": 0,
    }

    for plan in plans:
        record = is_executed_record(plan)
        for blk in iter_blocks(plan):
            stats["blocks"] += 1
            kind = classify(blk.body)
            nearest = next((l for l in reversed(blk.context) if l.strip()), "")
            anchored = bool(ANCHORED_EDIT_RE.match(nearest.strip()))

            if kind is None:
                # NO DOUBLE COUNTING. Tier 3 is offered only what tier 1
                # declined, so a block is judged by exactly one tier.
                stats["fragments_undecidable"] += 1
                if anchored:
                    stats["item_anchored_edit"] += 1
                else:
                    items.extend(check_item_block(blk, root, plan, record, stats))
                continue

            if anchored:
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
        f.setdefault("tier", "file")
        if last_for[(f["plan"], f["path"], f["kind"])] != idx:
            f["superseded_by_later_block"] = True
            stats["superseded"] += 1
            continue
        if not f["deleted"]:
            stats["clean"] += 1
            continue
        kept.append(f)

    # Tier 3, on the same rule and for the same reason: a plan that hands over
    # the same item twice is building it up across its own steps, and only the
    # last block claims to be the end state.
    item_last: dict[tuple, int] = {}
    for idx, f in enumerate(items):
        item_last[(f["plan"], f["path"], f["kind"], f["item"])] = idx
    for idx, f in enumerate(items):
        if item_last[(f["plan"], f["path"], f["kind"], f["item"])] != idx:
            f["superseded_by_later_block"] = True
            stats["item_superseded"] += 1
            continue
        if not f["deleted"]:
            stats["item_clean"] += 1
            continue
        kept.append(f)

    blocking = [f for f in kept if not f["executed_record"]]
    record = [f for f in kept if f["executed_record"]]

    return {
        "root": str(root),
        "plans": [p.name for p in plans],
        "plans_marked_executed": sorted(p.name for p in plans if is_executed_record(p)),
        "stats": stats,
        "counts": {
            "blocking": len(blocking),
            "record": len(record),
            "blocking_file": len([f for f in blocking if f["tier"] == "file"]),
            "blocking_item": len([f for f in blocking if f["tier"] == "item"]),
            "record_file": len([f for f in record if f["tier"] == "file"]),
            "record_item": len([f for f in record if f["tier"] == "item"]),
        },
        "blocking": blocking,
        "record": record,
    }


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def finding_claim(f: dict) -> str:
    if f.get("tier") != "item":
        return KIND_LABEL[f["kind"]]
    if f["kind"] == "use-block":
        return "the whole module-level `use` block"
    if f["kind"] == "array":
        return "the whole of an array literal"
    return f"the whole of `{f['kind']} {f['item']}`" if f["kind"] != "impl" \
        else f"the whole of `{f['item']}`"


def render_finding(f: dict, cap: int = 12) -> list[str]:
    out = []
    tier = f.get("tier", "file")
    out.append(f"  {f['plan']}:{f['line']}  {f['where']}"
               + ("   [item level]" if tier == "item" else ""))
    out.append(f"      block claims to be: {finding_claim(f)}  ->  {f['path']}")
    unit = (ITEM_MEMBER_NOUN.get(f["kind"], "member") + "s") if tier == "item" \
        else "significant lines"
    out.append(f"      applying it deletes {len(f['deleted'])} of the "
               f"{f['disk_significant']} {unit} at that path")
    if f["names"]:
        out.append(f"      deletes: {', '.join(f['names'][:6])}"
                   + (f" (+{len(f['names']) - 6} more)" if len(f["names"]) > 6 else ""))
    for d in f["deleted"][:cap]:
        out.append(f"        - {d[:100]}")
    if len(f["deleted"]) > cap:
        out.append(f"        ... and {len(f['deleted']) - cap} more")
    if f["added_not_on_disk"]:
        noun = unit[:-1] if tier == "item" else "line"
        out.append(f"      ({f['added_not_on_disk']} {noun}(s) in the block are not "
                   f"on disk at all — the block is also out of date in the other "
                   f"direction)")
    return out


def render(report: dict, show_record: bool) -> str:
    s, c = report["stats"], report["counts"]
    out: list[str] = []
    w = out.append

    w("CLASP artifact deletion check — whole file, and whole item")
    w("=" * 72)
    w(f"root:   {report['root']}")
    w(f"plans:  {len(report['plans'])}  "
      f"({len(report['plans_marked_executed'])} marked EXECUTED)")
    w("")
    w(f"  fenced blocks read ................... {s['blocks']}")
    w("")
    w("  TIER 1/2 — a block that is a whole file, workflow, script, manifest,")
    w("  TOML table or module list:")
    w(f"      half of a Find/Replace pair ...... {s['anchored_edit']}")
    w(f"      claim to be a whole artifact ..... {s['whole_artifact_blocks']}")
    w(f"          path not resolvable .......... {s['unresolved_path']}")
    w(f"          path absent (legitimate) ..... {s['path_absent']}")
    w(f"          superseded by a later block .. {s['superseded']}")
    w(f"          account for the file as it is  {s['clean']}")
    w(f"      findings ......................... "
      f"{c['blocking_file']} blocking, {c['record_file']} record")
    w("")
    w("  TIER 3 — a block that is the whole of one named item inside an")
    w("  otherwise untouched file (a `use` block, a struct, an enum, an impl,")
    w("  a function, an array):")
    w(f"      half of a Find/Replace pair ...... {s['item_anchored_edit']}")
    w(f"      blocks claiming a whole item ..... {s['item_blocks']}"
      f"  ({s['item_claims']} items in them)")
    w(f"          introduced as an addition .... {s['item_addition_suppressed']}")
    w(f"          item not found at exactly one")
    w(f"            candidate path ............. {s['item_unresolved']}")
    w(f"          the whole file, not an item .. {s['item_whole_file']}")
    w(f"          namesake: no member in common  {s['item_no_overlap']}")
    w(f"          superseded by a later block .. {s['item_superseded']}")
    w(f"          account for the item as it is  {s['item_clean']}")
    w(f"      findings ......................... "
      f"{c['blocking_item']} blocking, {c['record_item']} record")
    w("")
    w(f"  BLOCKING findings, both tiers ........ {c['blocking']}")
    w(f"  RECORD findings (plan marked EXECUTED) {c['record']}"
      + ("" if show_record else "   [--all to list]"))
    w("")
    w("  WHAT NEITHER TIER COULD DECIDE, said out loud rather than counted as a")
    w("  pass — every one of these is a block this check did not judge:")
    w(f"      blocks that are neither a whole artifact nor a whole item: "
      f"{s['fragments_undecidable'] - s['item_anchored_edit'] - s['item_blocks'] - s['item_undecidable']}")
    w(f"      blocks that claimed an item this tier cannot decide: "
      f"{s['item_undecidable']}")
    w("      (a `match` arm list, a bare loop or function body, a `use` block")
    w("      inside `mod tests`, an item quoted with a `// …` elision — see")
    w("      the header for why each is declined rather than guessed at)")
    if s.get("item_whole_file_where"):
        w("")
        w("      A KNOWN HOLE, not a pass. These blocks account for every top-level")
        w("      item of the file they name, so they ARE whole-file replacements —")
        w("      but they open on `mod`/`use` rather than on `//!`, so tier 1's")
        w("      shape test does not see them and the item tier declines them:")
        for plan, line, rel in s["item_whole_file_where"]:
            w(f"        {plan}:{line}  ->  {rel}")

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

# ---- tier 3 fixtures -----------------------------------------------------

FIX_ITEM_RS = """\
//! Fake item file.

use crate::alpha::{Aye, Bee};
use crate::beta::{Delta, Gamma};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct Widget {
    pub name: String,
    // `count` is a counter, not an index. See `impl Widget {` below.
    pub count: usize,
    pub tags: BTreeMap<String, String>,
}

impl Widget {
    /// Build one.
    pub fn new(name: String) -> Self {
        Self::with_count(name, 0)
    }

    pub fn with_count(name: String, count: usize) -> Self {
        Self {
            name,
            count,
            tags: BTreeMap::new(),
        }
    }
}

pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    let tail = w.count.to_string();
    let extra = w
        .tags
        .len()
        .to_string();
    format!("{head}:{tail}:{extra}")
}

pub fn summarise(w: &Widget) -> String {
    let head = w.name.clone();
    let tail = w.count.to_string();
    format!("{head}:{tail}")
}

#[test]
fn a_widget_round_trips() {
    let w = Widget::new("x".to_string());
    assert_eq!(w.count, 0);
    assert!(w.tags.is_empty());
}
"""

# A second definition of `describe`, so "found in exactly one candidate" has
# something to fail on.
FIX_TWIN_RS = """\
//! Fake twin file.

pub const TWIN_TAG: &str = "twin";

pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    let tail = w.count.to_string();
    let extra = w.tags.len().to_string();
    format!("{head}/{tail}/{extra}")
}
"""

# A trait default. A block giving the *implementation* of the same method
# shares no statement with it, which is how a namesake is caught.
FIX_NAMESAKE_RS = """\
//! Fake trait file.

pub trait Probe {
    fn probe(&self) -> Option<i32> {
        None
    }
}
"""

# No `//!`, so tier 1's shape test cannot see a whole-file block for it.
FIX_SMALL_RS = """\
use std::fmt;

pub fn tiny() -> u8 {
    let base = 1;
    base + 1
}
"""

FIX_VOCAB_SH = """\
#!/bin/sh
# Fake vocabulary check.
expect_vocab \\
  '[["ok","timeout","spawn_failed"],["AtPrompt","Executing"],["off","on"],["clasp","external"]]'
expect_pair '[["off","on"],["strip","raw"]]'
expect_short '["a","b","c","d"]'
"""

FIX_VOCAB2_SH = """\
#!/bin/sh
# Fake second vocabulary check.
expect_vocab \\
  '[["yes","no","maybe_so"],["AtPrompt","Executing"],["off","on"]]'
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


# Tier 3, both directions, in one plan nobody has marked EXECUTED. Every
# step here is a shape measured off the real corpus.
PLAN_ITEM = """\
# Fake item plan

## Task 3: Item-level edits

**Files:**
- Modify: `src/item.rs`
- Modify: `src/namesake.rs`
- Modify: `src/small.rs`

- [ ] **Step 1: The import block, handed over whole**

The block now reads, in rustfmt's order:

```rust
use crate::alpha::{Aye, Bee};
use crate::beta::Gamma;
use std::sync::Arc;
```

- [ ] **Step 2: The same bytes, introduced as an addition**

In `src/item.rs`, add one line to the import block, giving:

```rust
use crate::alpha::{Aye, Bee};
use crate::beta::Gamma;
use std::sync::Arc;
```

- [ ] **Step 3: Imports that are not this file's import block**

The test module's imports:

```rust
use super::*;
use crate::beta::Gamma;
use std::sync::Arc;
```

- [ ] **Step 4: Rewrite the widget and its impl**

In `src/item.rs`, replace the struct and its inherent `impl`:

```rust
pub struct Widget {
    pub name: String,
    pub count: usize,
}

impl Widget {
    /// Build one.
    pub fn new(name: String) -> Self {
        Self::with_count(name, 0)
    }
}
```

- [ ] **Step 5: The whole of `describe`**

In `src/item.rs`:

```rust
pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    let tail = w.count.to_string();
    format!("{head}:{tail}")
}
```

- [ ] **Step 6: A test, one assertion short**

```rust
#[test]
fn a_widget_round_trips() {
    let w = Widget::new("x".to_string());
    assert_eq!(w.count, 0);
}
```

- [ ] **Step 7: The same function, quoted with an elision**

```rust
pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    // …
    format!("{head}:{tail}:{extra}")
}
```

- [ ] **Step 8: A loop body, which is nobody's whole item**

Make it:

```rust
        let base = compute();
        buffer.push(base);
        drop(buffer);
```

- [ ] **Step 9: A signature with no body**

```rust
    pub fn describe(w: &Widget) -> String {
        format!("{}", w.name)
    }

    pub fn describe_at(
        w: &Widget,
        now: Instant,
    ) -> String {
```

- [ ] **Step 10: The vocabulary literal**

`scripts/fixture-vocab.sh:3`, the vocabulary check. The whole expected value
then reads:

```
'[["ok","timeout","spawn_failed"],["AtPrompt","Executing"],["off","on"]]'
```

- [ ] **Step 11: A literal that still accounts for the file**

`scripts/fixture-vocab2.sh:3`:

```
'[["yes","no","maybe_so"],["AtPrompt","Executing"],["off","on"]]'
```

- [ ] **Step 12: A namesake in another module**

In `src/namesake.rs`, on the implementing type:

```rust
    fn probe(&self) -> Option<i32> {
        match self.inner.lock().leader() {
            Some(g) if g > 0 => Some(g),
            _ => None,
        }
    }
```

- [ ] **Step 13: A whole file that opens on `use`, not on `//!`**

Replace `src/small.rs` with:

```rust
use std::fmt;

pub fn tiny() -> u8 {
    1
}
```

- [ ] **Step 14: A struct this plan creates**

In `src/item.rs`:

```rust
pub struct BrandNew {
    pub a: u8,
    pub b: u8,
}
```

## Task 4: The same function name in two files

**Files:**
- Modify: `src/item.rs`
- Modify: `src/twin.rs`

- [ ] **Step 1: Which `describe` is this?**

```rust
pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    format!("{head}")
}
```
"""

# Each of the three below lives in its own plan on purpose. Put in `item.md`
# they would share a (plan, path, kind) key with a block already there, and
# the supersede rule would hide them -- so the check would pass whether the
# gate it tests works or not. Measured: two of these were written inside
# `item.md` first and survived a mutation that removed the gate.

# The ANCHOR. Nothing in this block's prose says "add"; the only thing
# keeping the tier off it is that it does not open on the file's first
# module-level `use`.
PLAN_ITEM_TESTUSE = """\
# Fake test-imports plan

## Task 1: The test module

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: The test module's imports**

They read:

```rust
use super::*;
use crate::beta::Gamma;
use std::sync::Arc;
```
"""

# The SUPPRESSOR. These bytes are exactly the file's import block minus one
# statement; only the word "add" says they are an addition.
PLAN_ITEM_ADD = """\
# Fake import-addition plan

## Task 1: One more import

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: Add one import**

In `src/item.rs`, add one line to the import block, giving:

```rust
use crate::alpha::{Aye, Bee};
use crate::beta::Gamma;
use std::sync::Arc;
```
"""

# COMPLETENESS. The first function is complete and would be a finding on its
# own; the second is a signature with no body, which makes the block a
# fragment and the whole block undecidable.
PLAN_ITEM_SIG = """\
# Fake signature plan

## Task 1: Signatures

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: A complete function and a signature**

```rust
pub fn summarise(w: &Widget) -> String {
    let head = w.name.clone();
    format!("{head}")
}

pub fn summarise_at(
    w: &Widget,
    now: Instant,
) -> String {
```
"""

# AMBIGUITY. `describe` is defined in `src/item.rs` AND `src/twin.rs`, and
# this task's `Files:` list names both. Its own plan, so that whichever file
# a broken resolver picked, the finding cannot be mistaken for Step 5's.
PLAN_ITEM_TWIN = """\
# Fake twin plan

## Task 1: Which `describe`?

**Files:**
- Modify: `src/item.rs`
- Modify: `src/twin.rs`

- [ ] **Step 1: The whole of `describe`**

```rust
pub fn describe(w: &Widget) -> String {
    let head = w.name.clone();
    format!("{head}")
}
```
"""

# THE FLOOR. These two statements ARE the file's first two imports, so the
# anchor accepts them and no word says "add": only the statement floor keeps
# this from being read as the whole import block.
PLAN_ITEM_TWO_IMPORTS = """\
# Fake two-import plan

## Task 1: Two imports

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: The two `crate::` imports**

They read:

```rust
use crate::alpha::{Aye, Bee};
use crate::beta::Gamma;
```
"""

# SUPERSEDE. The same item handed over twice as the plan builds it up. The
# first block is an intermediate stage and diffing it against the finished
# file measures the plan's own remaining steps.
PLAN_ITEM_STAGED = """\
# Fake staged item plan

## Task 1: Build the widget up

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: First cut**

In `src/item.rs`:

```rust
pub struct Widget {
    pub name: String,
}
```

- [ ] **Step 2: Finish it**

In `src/item.rs`:

```rust
pub struct Widget {
    pub name: String,
    pub count: usize,
    pub tags: BTreeMap<String, String>,
}
```
"""

# THE `Files:` LIST. Nothing within this block's lookback names a path -- the
# preamble is long and names no file, which is the ordinary case -- so the
# only way to site `summarise` is the task's own `Files:` list. Measured:
# without it, three of the four cases this tier was built for go unfound.
PLAN_ITEM_DISTANT = """\
# Fake distant-files plan

## Task 1: A step whose paragraph names no file

**Files:**
- Modify: `src/item.rs`

Paragraph 1 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 2 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 3 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 4 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 5 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 6 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 7 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 8 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 9 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 10 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 11 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 12 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 13 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 14 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 15 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 16 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 17 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 18 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 19 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 20 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 21 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 22 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 23 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 24 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 25 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 26 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 27 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 28 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 29 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 30 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 31 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 32 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 33 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 34 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 35 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 36 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 37 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 38 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 39 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.
Paragraph 40 of the preamble. It explains why the step below is written the way it is and names no file at all, which is the ordinary case in this corpus.

- [ ] **Step 1: The whole of `summarise`**

```rust
pub fn summarise(w: &Widget) -> String {
    let head = w.name.clone();
    format!("{head}")
}
```
"""

# THE PROSE WINDOW. Two blocks in one step: the first is the insertion, the
# second is the resulting whole. Only the second is a replacement, and the
# only thing separating them is that the suppressor reads the prose since the
# PREVIOUS fence rather than a fixed number of lines. This is 0.0.4 Task 6
# Step 1 in miniature, and the fixed-window version misses it.
PLAN_ITEM_TWOBLOCK = """\
# Fake two-block plan

## Task 1: Extend the imports

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: Extend the imports**

In `src/item.rs`, add one `use` line — do not retype the block:

```rust
use std::sync::Arc;
```

giving, in rustfmt's order:

```rust
use crate::alpha::{Aye, Bee};
use crate::beta::{Delta, Gamma};
use std::sync::Arc;
```
"""

# THE WIDER LOOKBACK. No `Files:` list here at all, and the only mention of
# the path is a sentence more than tier 1's fourteen lines above the fence.
PLAN_ITEM_FAR = """\
# Fake far-path plan

## Task 1: A task with no Files list

The step below edits `src/item.rs`, which is named here and nowhere nearer.

Line 1 of a preamble that names no file.
Line 2 of a preamble that names no file.
Line 3 of a preamble that names no file.
Line 4 of a preamble that names no file.
Line 5 of a preamble that names no file.
Line 6 of a preamble that names no file.
Line 7 of a preamble that names no file.
Line 8 of a preamble that names no file.
Line 9 of a preamble that names no file.
Line 10 of a preamble that names no file.
Line 11 of a preamble that names no file.
Line 12 of a preamble that names no file.
Line 13 of a preamble that names no file.
Line 14 of a preamble that names no file.
Line 15 of a preamble that names no file.
Line 16 of a preamble that names no file.
Line 17 of a preamble that names no file.
Line 18 of a preamble that names no file.
Line 19 of a preamble that names no file.
Line 20 of a preamble that names no file.

- [ ] **Step 1: The whole of `summarise`**

```rust
pub fn summarise(w: &Widget) -> String {
    let head = w.name.clone();
    format!("{head}")
}
```
"""

# THE ARRAY FLOORS. Both of these blocks would locate a real array in
# `scripts/fixture-vocab.sh` and report a deletion; both are too small to be
# claiming to be the whole of anything. A two-element array is a pair, and a
# first element of `"a"` identifies nothing.
PLAN_ITEM_SMALL_ARRAY = """\
# Fake small-array plan

## Task 1: Two literals that identify nothing

**Files:**
- Modify: `scripts/fixture-vocab.sh`

- [ ] **Step 1: The pair check**

`scripts/fixture-vocab.sh:5`, whose expected value reads:

```
'[["off","on"]]'
```

- [ ] **Step 2: The short check**

`scripts/fixture-vocab.sh:6`, whose expected value reads:

```
'["a","b","c"]'
```
"""

# The RECORD half of tier 3: the same shape in a plan that has run.
PLAN_ITEM_RECORD = """\
# Fake executed item plan

> **EXECUTED — a record of what was written, not of what is there now.**

## Task 1: The widget

**Files:**
- Modify: `src/item.rs`

- [ ] **Step 1: The struct as it was built**

```rust
pub struct Widget {
    pub name: String,
    pub count: usize,
}
```
"""


def _fixture_tree(td: Path) -> tuple[Path, Path]:
    root = td / "repo"
    plans = root / "docs" / "superpowers" / "plans"
    (root / "src").mkdir(parents=True)
    (root / "scripts").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    plans.mkdir(parents=True)
    (root / "src" / "lib.rs").write_text(FIX_LIB_RS, encoding="utf-8")
    (root / "src" / "mods.rs").write_text(FIX_MODS_RS, encoding="utf-8")
    (root / "src" / "other.rs").write_text(FIX_OTHER_RS, encoding="utf-8")
    (root / "src" / "item.rs").write_text(FIX_ITEM_RS, encoding="utf-8")
    (root / "src" / "twin.rs").write_text(FIX_TWIN_RS, encoding="utf-8")
    (root / "src" / "namesake.rs").write_text(FIX_NAMESAKE_RS, encoding="utf-8")
    (root / "src" / "small.rs").write_text(FIX_SMALL_RS, encoding="utf-8")
    (root / "scripts" / "fixture-vocab.sh").write_text(FIX_VOCAB_SH, encoding="utf-8")
    (root / "scripts" / "fixture-vocab2.sh").write_text(FIX_VOCAB2_SH, encoding="utf-8")
    (root / "Cargo.toml").write_text(FIX_MANIFEST, encoding="utf-8")
    (root / ".github" / "workflows" / "fixture.yml").write_text(FIX_WORKFLOW, encoding="utf-8")
    return root, plans


def _run(plans_dir: Path, root: Path) -> dict:
    return scan(sorted(plans_dir.glob("*.md")), root)


def _fixture_block(plan_text: str, marker: str) -> list[str]:
    """The first fenced block after `marker` in a fixture plan."""
    lines = plan_text.splitlines()
    i = next(k for k, l in enumerate(lines) if marker in l)
    while not lines[i].startswith("```"):
        i += 1
    j = i + 1
    while not lines[j].startswith("```"):
        j += 1
    return lines[i + 1:j]


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
        (plans / "item.md").write_text(PLAN_ITEM, encoding="utf-8")
        (plans / "itemrec.md").write_text(PLAN_ITEM_RECORD, encoding="utf-8")
        (plans / "itemtestuse.md").write_text(PLAN_ITEM_TESTUSE, encoding="utf-8")
        (plans / "itemadd.md").write_text(PLAN_ITEM_ADD, encoding="utf-8")
        (plans / "itemsig.md").write_text(PLAN_ITEM_SIG, encoding="utf-8")
        (plans / "itemtwin.md").write_text(PLAN_ITEM_TWIN, encoding="utf-8")
        (plans / "itemtwo.md").write_text(PLAN_ITEM_TWO_IMPORTS, encoding="utf-8")
        (plans / "itemstaged.md").write_text(PLAN_ITEM_STAGED, encoding="utf-8")
        (plans / "itemdistant.md").write_text(PLAN_ITEM_DISTANT, encoding="utf-8")
        (plans / "itemsecond.md").write_text(PLAN_ITEM_TWOBLOCK, encoding="utf-8")
        (plans / "itemfar.md").write_text(PLAN_ITEM_FAR, encoding="utf-8")
        (plans / "itemsmall.md").write_text(PLAN_ITEM_SMALL_ARRAY, encoding="utf-8")

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

        # ------------------------------------------------------------------
        # TIER 3 — item level. Same fixture tree; the plan hands over items
        # rather than files.
        # ------------------------------------------------------------------

        def item(bucket, plan_frag, kind, name):
            for f in rep[bucket]:
                if (f.get("tier") == "item" and plan_frag in f["plan"]
                        and f["kind"] == kind and f["item"] == name):
                    return f
            return None

        def item_hits(plan_frag):
            return [(f["kind"], f["item"]) for f in rep["blocking"] + rep["record"]
                    if f.get("tier") == "item" and plan_frag in f["plan"]]

        # THE FLAGSHIP ITEM SHAPE, and the one the brief measured: a `use`
        # block handed over whole, written when the file's import list was
        # shorter. This is 0.0.4 Task 6 Step 1 in miniature.
        f = item("blocking", "item", "use-block", "the module-level `use` block")
        check("TIER 3 — a stale whole-`use`-block is BLOCKING; a whole dropped "
              "statement and a dropped name inside a brace list are both NAMED",
              (f is not None and f["deleted"], f and f["path"], f and f["names"]),
              (["crate::beta::Delta", "std::collections::BTreeMap"], "src/item.rs",
               ["the whole `std::collections::BTreeMap` statement",
                "import `crate::beta::Delta`"]))

        # The same bytes, introduced as an addition, in a plan of its own so
        # the supersede rule cannot pass this check for the wrong reason.
        check("TIER 3 — the same import block introduced with \"add\" is NOT "
              "reported",
              item_hits("itemadd"), [])

        # THE ANCHOR, which is what keeps this tier off illustrative `use`
        # snippets: a block that does not open on the file's first
        # module-level import is not claiming to be the whole of it. Nothing
        # in this plan's prose says "add", so the anchor is the only thing
        # that can decline it.
        check("TIER 3 — a `use super::*;` test-module block is not treated as "
              "the file's import block (no addition word involved)",
              item_hits("itemtestuse"), [])

        f = item("blocking", "item", "struct", "Widget")
        check("TIER 3 — a struct handed over whole names the dropped field",
              (f is not None and f["deleted"], f and f["names"]),
              (["tags"], ["field `tags`"]))

        f = item("blocking", "item", "impl", "impl Widget")
        check("TIER 3 — its `impl`, in the same block, names the dropped method",
              (f is not None and f["deleted"], f and f["names"]),
              (["fn with_count"], ["item `fn with_count`"]))

        f = item("blocking", "item", "fn", "describe")
        check("TIER 3 — a function body handed over whole names the dropped "
              "statements",
              f is not None and f["deleted"],
              ["let extra = w .tags .len() .to_string();",
               'format!("{head}:{tail}:{extra}")'])

        f = item("blocking", "item", "array", "array literal")
        check("TIER 3 — a three-element array against a file holding four names "
              "the missing element (path resolved through a `file.sh:3` "
              "reference)",
              (f is not None and f["deleted"], f and f["path"]),
              (['["clasp","external"]'], "scripts/fixture-vocab.sh"))

        # The negative half. The three SHAPE declines are asserted directly
        # against `classify_item`, because an end-to-end "no finding appeared"
        # can be satisfied by any later gate and would still pass with the
        # shape test deleted. Ask the gate itself what it decided.
        check("TIER 3 — a bare loop body claims no item (shape gate)",
              classify_item(_fixture_block(PLAN_ITEM, "Step 8:"))[1],
              "not-whole-items")
        check("TIER 3 — a function quoted with a `// …` elision claims no item "
              "(shape gate)",
              classify_item(_fixture_block(PLAN_ITEM, "Step 7:"))[1], "elided")
        check("TIER 3 — a `#[test]` function is not a checkable item (shape gate)",
              classify_item(_fixture_block(PLAN_ITEM, "Step 6:"))[1],
              "no-checkable-item")
        check("TIER 3 — a complete function followed by a signature with no body "
              "makes the whole block a fragment, end to end",
              (classify_item(_fixture_block(PLAN_ITEM_SIG, "Step 1:"))[1],
               item_hits("itemsig")),
              ("not-whole-items", []))

        check("TIER 3 — a two-element array and one whose first element is `\"a\"` "
              "are both below the floor at which a literal identifies an array",
              item_hits("itemsmall"), [])
        check("TIER 3 — an array that still accounts for the file is silent",
              [x for x in rep["blocking"] + rep["record"]
               if x["path"] == "scripts/fixture-vocab2.sh"], [])
        check("TIER 3 — a namesake with no member in common is declined, not "
              "reported as a 100% deletion",
              [x for x in item_hits("item") if x[1] == "probe"], [])
        check("TIER 3 — an item the plan itself creates is not reported",
              [x for x in item_hits("item") if x[1] == "BrandNew"], [])
        # `fn describe` exists in src/item.rs AND src/twin.rs, and this plan's
        # `Files:` list names both. A finding either way would mean the tier
        # picked a candidate instead of requiring exactly one.
        check("TIER 3 — a function name found in two candidate files is declined",
              item_hits("itemtwin"), [])
        check("TIER 3 — two imports that ARE the file's first two are still below "
              "the floor at which a block claims to be the whole import list",
              item_hits("itemtwo"), [])
        check("TIER 3 — an item handed over twice in one plan is judged on the "
              "LAST block only",
              item_hits("itemstaged"), [])

        # The path came from the task's `Files:` list and from nowhere else:
        # the block's own preamble is fourteen paragraphs and names no file.
        f = item("blocking", "itemdistant", "fn", "summarise")
        check("TIER 3 — a block whose preamble names no file is still sited, "
              "from the enclosing task's `Files:` list",
              (f is not None and f["path"], f and f["deleted"]),
              ("src/item.rs",
               ["let tail = w.count.to_string();", 'format!("{head}:{tail}")']))

        f = item("blocking", "itemfar", "fn", "summarise")
        check("TIER 3 — a path named further up than tier 1 looks, in a task "
              "with no `Files:` list, is still found",
              f is not None and f["path"], "src/item.rs")

        # Two blocks in one step: the insertion, then the resulting whole.
        # The suppressor must read only the prose since the previous fence.
        f = item("blocking", "itemsecond", "use-block",
                 "the module-level `use` block")
        check("TIER 3 — in a step whose FIRST block is an insertion, the SECOND "
              "block (the resulting whole) is still judged",
              f is not None and f["deleted"], ["std::collections::BTreeMap"])

        # The whole file is tier 1's question. This block opens on `use`, so
        # tier 1 cannot see it either -- which is why the number is printed.
        check("TIER 3 — a block accounting for every top-level item of a file is "
              "declined as a whole-file block, and COUNTED",
              (rep["stats"]["item_whole_file"] >= 1,
               ["item.md", 0, "src/small.rs"][2] in
               [w[2] for w in rep["stats"].get("item_whole_file_where", [])]),
              (True, True))

        check("TIER 3 — no block is judged by both tiers",
              [k for k, v in
               {(f["plan"], f["line"]): set()
                for f in rep["blocking"] + rep["record"]}.items()
               if len({g["tier"] for g in rep["blocking"] + rep["record"]
                       if (g["plan"], g["line"]) == k}) > 1],
              [])

        f = item("record", "itemrec", "struct", "Widget")
        check("TIER 3 — the same shape in a plan marked EXECUTED is RECORD",
              (f is not None and f["deleted"],
               [x for x in rep["blocking"] if x["plan"] == "itemrec.md"]),
              (["tags"], []))

        check("exit code would be non-zero", rep["counts"]["blocking"] > 0, True)

        # MUTATION 4: tier 3 must read the DISK too. Drop the field the plan
        # does not mention and its finding has to vanish.
        (root / "src" / "item.rs").write_text(
            FIX_ITEM_RS.replace("    pub tags: BTreeMap<String, String>,\n", ""),
            encoding="utf-8")
        mrep = _run(plans, root)
        check("MUTATION — with the field removed from the tree, the struct "
              "finding disappears (tier 3 reads disk, not prose)",
              [x for x in mrep["blocking"]
               if x.get("tier") == "item" and x["kind"] == "struct"], [])
        (root / "src" / "item.rs").write_text(FIX_ITEM_RS, encoding="utf-8")

        # MUTATION 5: the EXECUTED stamp is load-bearing for tier 3 as well.
        (plans / "itemrec.md").write_text(
            PLAN_ITEM_RECORD.replace(
                "> **EXECUTED — a record of what was written, not of what is there now.**\n\n",
                ""),
            encoding="utf-8")
        mrep = _run(plans, root)
        check("MUTATION — with the EXECUTED stamp removed, the item finding "
              "turns BLOCKING",
              [x["names"] for x in mrep["blocking"] if x["plan"] == "itemrec.md"],
              [["field `tags`"]])
        (plans / "itemrec.md").write_text(PLAN_ITEM_RECORD, encoding="utf-8")

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
              ((crep["counts"]["blocking"], crep["counts"]["record"]),
               crep["stats"]["blocks"] > 0),
              ((0, 0), True))

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

    # ---- tier 3 against the real corpus ---------------------------------

    check("TIER 3 was actually exercised on the corpus (blocks claimed items, "
          "items were located, and some accounted for the file exactly)",
          (rep["stats"]["item_blocks"] > 20,
           rep["stats"]["item_claims"] > 50,
           rep["stats"]["item_clean"] > 10),
          (True, True, True))

    check("TIER 3 — no corpus block is judged by both tiers",
          sorted({(f["plan"], f["line"]) for f in every
                  if len({g["tier"] for g in every
                          if (g["plan"], g["line"]) == (f["plan"], f["line"])}) > 1}),
          [])

    # THE REAL-CORPUS ACCEPTANCE CASE. 0.0.8 Task 7 Step 1 hands over
    # `pub struct ClaspServer` and its inherent `impl` as they were before
    # 0.0.3 put a processor on them, and its own prose says the replacement
    # is safe "because the struct really does still have exactly one field".
    # It has two, and `start_session` reads the second on every call.
    got = sorted(
        (f["kind"], f["item"], tuple(f["deleted"]))
        for f in rep["blocking"]
        if f.get("tier") == "item" and "0.0.8" in f["plan"]
        and f["path"] == "crates/clasp-core/src/mcp/mod.rs")
    check("TIER 3 — 0.0.8 Task 7 Step 1's `ClaspServer` replacement is reported, "
          "naming the dropped field and the dropped constructor",
          got,
          [("impl", "impl ClaspServer", ("fn with_audit_path",)),
           ("struct", "ClaspServer", ("processor",))])

    # ...and the separator. 0.0.3 Task 9 Step 1 replaces the SAME two items
    # with the same shape of block, and today it accounts for both of them
    # exactly. A tier that flagged every struct-plus-impl block would report
    # this one too.
    check("TIER 3 — 0.0.3 Task 9 Step 1's `ClaspServer` block, the same shape "
          "against the same file, is silent because it still accounts for it",
          [(f["kind"], f["item"]) for f in every
           if f.get("tier") == "item" and "0.0.3" in f["plan"]
           and f["path"] == "crates/clasp-core/src/mcp/mod.rs"],
          [])

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
