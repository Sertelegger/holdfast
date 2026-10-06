#!/bin/sh
# The plugin's mod, checked by Claude Code itself:
#
#   1. `claude plugin validate --strict --json plugin/` must pass, and the
#      hooks, mods API calls and environment reads it reports for the hooks
#      module must equal plugin-tests/validate-notes.txt line for line. A new
#      call -- `$.mcp.call`, `$.prompt.submit`, `$.store.set`, a `tool.check`
#      hook -- is a diff against that file, so it is a decision in review
#      rather than a side effect of an edit.
#   2. `claude plugin test` runs plugin-tests/*.test.ts against the mod.
#
# The tests live outside plugin/ so that they do not ship in every install.
# `claude plugin test` runs the tests under one mod folder, so a scratch copy
# of plugin/ gets them added under tests/ and is run there.
#
# CLAUDE names the claude binary (default: `claude` on PATH). Every run gets
# a scratch HOME and CLAUDE_CONFIG_DIR and no network it does not need, so
# the caller's Claude Code configuration is neither read nor written.
#
# Usage:  plugin-mod-tests.sh [--self-test]
#   --self-test  breaks a scratch copy of the mod in ways each check must
#                catch, and fails if one is not caught.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
claude_bin=${CLAUDE:-claude}
work=$(mktemp -d "${TMPDIR:-/tmp}/hf-mod-tests.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/home" "$work/config"

# The Claude Code version CI installs, from the lockfile CI installs it from.
pinned=$(sed -n 's/.*"@anthropic-ai\/claude-code": *"\([0-9.]*\)".*/\1/p' \
  "$root/plugin-tests/claude-code/package.json" | head -n 1)

cc() {
  env -i PATH="$PATH" HOME="$work/home" CLAUDE_CONFIG_DIR="$work/config" TERM=dumb \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 \
    "$claude_bin" "$@"
}

# validate <plugin-dir>: 0 when the report passes and matches the pin.
validate() {
  set +e
  cc plugin validate --strict --json "$1" > "$work/validate.json"
  rc=$?
  set -e
  python3 - "$work/validate.json" "$root/plugin-tests/validate-notes.txt" "$rc" <<'PY'
import json, re, sys
report_path, pin_path, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    report = json.load(open(report_path))
except ValueError as e:
    print("  FAIL  claude plugin validate printed no JSON (%s), exit %d" % (e, rc))
    sys.exit(1)
fails = []
if rc != 0 or not report.get("success"):
    fails.append("claude plugin validate --strict failed (exit %d)" % rc)
items = [report.get("manifest", {})] + list(report.get("contents", []))
for item in items:
    for level in ("errors", "warnings"):
        for msg in item.get(level, []):
            fails.append("%s: %s" % (level, msg.get("message", msg)))
# The `(via helper)` annotations name the module's own functions, not calls,
# so they are dropped on both sides: renaming a helper is not a new call.
def calls_only(line):
    return re.sub(r" \(via [^)]*\)", "", line)
hooks = [c for c in report.get("contents", []) if c.get("type") == "hooks"]
got = [calls_only(n) for c in hooks for n in c.get("notes", [])]
want = [calls_only(l) for l in open(pin_path).read().splitlines() if l and not l.startswith("#")]
if got != want:
    fails.append("the hooks module's report differs from %s" % pin_path)
    for l in want:
        if l not in got:
            print("  -  %s" % l)
    for l in got:
        if l not in want:
            print("  +  %s" % l)
for f in fails:
    print("  FAIL  %s" % f)
if fails:
    sys.exit(1)
print("  ok    validate --strict passes; %d report line(s) match the pin" % len(got))
PY
}

# assemble <plugin-dir> <dest>: the mod folder `claude plugin test` runs.
assemble() {
  rm -rf "$2"
  cp -R "$1" "$2"
  mkdir -p "$2/tests"
  cp "$root"/plugin-tests/*.ts "$2/tests/"
}

# mod_tests <mod-folder>: 0 when every test passes.
mod_tests() {
  cc plugin test "$1"
}

version=$(cc --version 2>/dev/null | sed -n '1s/^\([0-9][0-9.]*\).*/\1/p')
if [ "$version" != "$pinned" ]; then
  if [ -n "${CI:-}" ]; then
    echo "FAIL  $claude_bin is Claude Code ${version:-unknown}; CI pins $pinned" >&2
    exit 1
  fi
  echo "note  $claude_bin is Claude Code ${version:-unknown}; the pin and CI use $pinned, so the report may differ"
fi

if [ "${1:-}" = "--self-test" ]; then
  fails=0
  # Each case breaks a scratch copy in one way and must turn a check red.
  for case in new-call new-mcp-call new-hook failing-test; do
    rm -rf "$work/plugin"
    cp -R "$root/plugin" "$work/plugin"
    mod="$work/plugin/hooks/register.js"
    case $case in
      new-call|new-mcp-call|new-hook)
        python3 - "$mod" "$case" <<'PY'
import sys
path, case = sys.argv[1], sys.argv[2]
text = open(path).read()
if case in ("new-call", "new-mcp-call"):
    # Inside the tool.call hook, where it would run.
    anchor = "    const going = next(e)\n"
    if case == "new-call":
        planted = anchor + "    await $.prompt.submit({ text: 'planted' })\n"
    else:
        # The status read the band made before a mod's MCP call was
        # measured to be permission-checked.
        planted = anchor + "    await $.mcp.call('plugin:holdfast:holdfast', 'status', { session: e.session })\n"
else:
    anchor = "export function register(on, options) {\n"
    planted = anchor + "  on('tool.check', async ($, e, next) => next(e))\n"
assert anchor in text, "the anchor for %s is gone from register.js" % case
open(path, "w").write(text.replace(anchor, planted, 1))
PY
        ;;
    esac
    # What the red run must say, so a case cannot pass by failing for some
    # other reason.
    case $case in
      new-call) reason='^  [+]  .*calls: .*[$][.]prompt[.]submit' ;;
      new-mcp-call) reason='^  [+]  .*calls: .*[$][.]mcp[.]call' ;;
      new-hook) reason='^  [+]  .*hooks: .*tool[.]check' ;;
      failing-test) reason='planted failure' ;;
    esac
    if [ "$case" = failing-test ]; then
      assemble "$work/plugin" "$work/mod"
      printf '%s\n' "import { expect, test } from 'claude-code/testing'" \
        "test('planted failure', () => { expect(1).toBe(2) })" > "$work/mod/tests/zz-planted.test.ts"
      if mod_tests "$work/mod" > "$work/out.txt" 2>&1; then caught=no; else caught=yes; fi
    else
      if validate "$work/plugin" > "$work/out.txt" 2>&1; then caught=no; else caught=yes; fi
    fi
    if [ "$caught" = no ]; then
      echo "  FAIL  NOT caught: $case"; fails=$((fails + 1))
    elif ! grep -qE "$reason" "$work/out.txt"; then
      echo "  FAIL  caught for another reason: $case"; sed 's/^/        /' "$work/out.txt"; fails=$((fails + 1))
    else
      echo "  ok    caught: $case"
    fi
  done
  echo "self-test: 4 case(s), $fails not caught"
  [ "$fails" -eq 0 ]
  exit
fi

echo "--- claude plugin validate --strict, pinned ---"
validate "$root/plugin"
echo "--- claude plugin test ---"
assemble "$root/plugin" "$work/mod"
mod_tests "$work/mod"
