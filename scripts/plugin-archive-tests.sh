#!/bin/sh
# The plugin bootstrap's safe-extraction rules, asserted against a corpus of
# hostile archives.
#
# **POSIX sh, because this file is itself part of the test.** It runs under
# dash on the Ubuntu cell and under busybox ash in the Alpine cell, and a
# bash-ism here would mean the shell under test is not the shell that ran.
#
# Usage:
#   plugin-archive-tests.sh --tar                  run the tar corpus
#   plugin-archive-tests.sh --mutations <cell>     delete each check, assert red
#   plugin-archive-tests.sh --zip                  run the zip corpus under pwsh
#   plugin-archive-tests.sh --all <cell>           all three
#
# <cell> is one of: gnu-nonroot, busybox-root. The mutation table below is
# keyed by it and is checked in BOTH directions -- a mutation that stops being
# caught fails, and so does one that starts being caught. That is deliberate:
# two of the four checks are invisible in any single cell, and a table that
# only said "at least one went red" would let the other two rot into dead code
# that a later reader deletes as unreachable.
set -u

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
LIB="$ROOT/plugin/lib-safe-extract.sh"
GEN="$ROOT/scripts/plugin-archive-corpus.py"
TARBIN=${HOLDFAST_TAR:-tar}
pass=0
fail=0

note()  { printf '%s\n' "$*"; }
ok()    { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
bad()   { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }

hf_die() { echo "safe-extract: $*" >&2; exit 1; }

[ -r "$LIB" ] || { echo "missing $LIB" >&2; exit 2; }
[ -r "$GEN" ] || { echo "missing $GEN" >&2; exit 2; }

SANDBOX=${HOLDFAST_ARCHIVE_SANDBOX:-}
if [ -z "$SANDBOX" ]; then
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/hf-arc.XXXXXX") || exit 2
    trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM
fi
# HOLDFAST_ARCHIVE_CORPUS reuses a corpus generated elsewhere. The Alpine
# cell needs it: busybox has no python3, and `apk add` in a test would make
# the cell depend on a mutable package index. The corpus is generated once on
# the host -- where the generator IS under test -- and piped in.
#
# **Reusing is not the same as trusting**: the row count is re-derived here,
# so a corpus that arrived truncated fails rather than passing on nine cases.
if [ -n "${HOLDFAST_ARCHIVE_CORPUS:-}" ]; then
    CORPUS=$HOLDFAST_ARCHIVE_CORPUS
    [ -r "$CORPUS/MANIFEST" ] || { echo "HOLDFAST_ARCHIVE_CORPUS=$CORPUS has no MANIFEST" >&2; exit 2; }
    note "corpus: reused from $CORPUS ($(grep -c . "$CORPUS/MANIFEST") case(s))"
else
    CORPUS="$SANDBOX/corpus"
    python3 "$GEN" "$CORPUS" > "$SANDBOX/gen.log" 2>&1 || {
        cat "$SANDBOX/gen.log" >&2
        echo "corpus generation failed" >&2
        exit 2
    }
    note "corpus: $(tail -1 "$SANDBOX/gen.log")"
fi

# Extraction destinations live four levels down, so a `../../../` escape
# lands inside the sandbox where `escaped` can see it rather than somewhere
# this script would have to trust itself not to have missed.
DEEP="$SANDBOX/a/b/c"
mkdir -p "$DEEP" || exit 2

escaped() {
    # Anything a case wrote outside its destination. Both roots: shallow
    # traversals land in the sandbox, the 40-level one reaches /tmp.
    find "$SANDBOX" -name 'HF_PWN_*' 2> /dev/null
    find /tmp -maxdepth 1 -name 'HF_PWN_*' 2> /dev/null
}

clean_escapes() {
    find "$SANDBOX" -name 'HF_PWN_*' -exec rm -rf {} + 2> /dev/null
    find /tmp -maxdepth 1 -name 'HF_PWN_*' -exec rm -rf {} + 2> /dev/null
    return 0
}

# run_tar_corpus <lib-to-source> ; prints "<pass> <fail>" and returns nonzero
# if any case disagreed with MANIFEST. Runs in a subshell so a mutated
# library never contaminates the next run.
run_tar_corpus() {
    _lib=$1
    _quiet=${2:-}
    _p=0
    _f=0
    # shellcheck source=plugin/lib-safe-extract.sh
    . "$_lib"
    # shellcheck disable=SC2034
    # `why` is read to consume the rest of the MANIFEST line; it is the
    # human-readable reason and this loop has no use for it.
    while read -r kind name verdict why; do
        [ "$kind" = tar ] || continue
        clean_escapes
        _d="$DEEP/dest.$name"
        rm -rf "$_d"
        mkdir -p "$_d"
        chmod 700 "$_d"
        _out=$( (hf_safe_extract_tar "$CORPUS/tar/$name" "$_d" holdfast) 2>&1 )
        _rc=$?
        _esc=$(escaped)
        if [ "$verdict" = ACCEPT ]; then
            [ "$_rc" -eq 0 ] && _v=ok || _v=BAD
        else
            [ "$_rc" -ne 0 ] && _v=ok || _v=BAD
        fi
        # A case that "rejected" only after writing outside its destination
        # is a failure, whatever it returned.
        [ -n "$_esc" ] && _v=BAD-ESCAPED
        if [ "$_v" = ok ]; then
            _p=$((_p + 1))
        else
            _f=$((_f + 1))
            # Detail to stderr: stdout is the "<pass> <fail>" line the
            # caller parses, and mixing the two made `set --` read a
            # failure message as the counts.
            [ -n "$_quiet" ] || printf '    %-13s %-30s want=%-6s rc=%s %s\n' \
                "$_v" "$name" "$verdict" "$_rc" "$(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-90)" >&2
        fi
        rm -rf "$_d"
        clean_escapes
    done < "$CORPUS/MANIFEST"
    printf '%s %s\n' "$_p" "$_f"
    [ "$_f" -eq 0 ]
}

do_tar() {
    note ""
    note "--- tar corpus: shell=$(shell_name) tar=$("$TARBIN" --version 2>&1 | head -1) uid=$(id -u) ---"
    _res=$(run_tar_corpus "$LIB")
    _rc=$?
    # shellcheck disable=SC2086
    set -- $_res
    if [ "$_rc" -eq 0 ]; then
        ok "$1 case(s) matched MANIFEST, 0 disagreed"
    else
        bad "$2 of $(($1 + $2)) case(s) disagreed with MANIFEST"
    fi
    # Anti-vacuity: an unreadable MANIFEST or a `[ "$kind" = tar ]` that
    # matches nothing would make the loop run zero times and report clean.
    _n=$(grep -c '^tar ' "$CORPUS/MANIFEST")
    if [ "$(($1 + $2))" -eq "$_n" ] && [ "$_n" -gt 10 ]; then
        ok "all $_n tar case(s) in MANIFEST were actually executed"
    else
        bad "MANIFEST holds $_n tar case(s) but $(($1 + $2)) ran"
    fi
}

shell_name() {
    if [ -n "${BASH_VERSION:-}" ]; then echo "bash"
    elif case "$(readlink /proc/$$/exe 2> /dev/null)" in *busybox*) true ;; *) false ;; esac; then echo "busybox ash"
    else echo "${HOLDFAST_TEST_SHELL:-sh/dash}"; fi
}

# --- mutation controls -----------------------------------------------------
# Each check is removed from a COPY of the library and the corpus is re-run.
# The mutation switch deliberately does not live in the shipped script: a
# production file carrying an env var that disables a security check is one
# typo in a CI job away from being the production behaviour.
mutate() { # mutate <name> <dest>
    case "$1" in
        listing) sed '/# >>> CHECK listing$/,/# <<< CHECK listing$/d' "$LIB" > "$2" ;;
        type)    sed '/# >>> CHECK type$/,/# <<< CHECK type$/d' "$LIB" > "$2" ;;
        landed)  sed '/# >>> CHECK landed$/,/# <<< CHECK landed$/d' "$LIB" > "$2" ;;
        # The extraction lives inside the `limit` block, so deleting the block
        # deletes the thing under test. Only the ulimit line is removed.
        limit)   sed '/ulimit -f 262144/d' "$LIB" > "$2" ;;
        *) return 1 ;;
    esac
    # A sed that matched nothing would produce an identical file, the corpus
    # would stay green, and the mutation would read as "this check is not
    # needed". Refuse to draw a conclusion from a mutation that did not mutate.
    if cmp -s "$LIB" "$2"; then
        bad "mutation '$1' changed nothing -- the sentinel comments moved"
        return 1
    fi
    return 0
}

do_mutations() {
    _cell=$1
    case "$_cell" in
        gnu-nonroot)  _expect="listing type limit" ;;
        busybox-root) _expect="listing limit landed" ;;
        *) echo "unknown cell '$_cell' (want gnu-nonroot or busybox-root)" >&2; exit 2 ;;
    esac
    note ""
    note "--- mutation controls, cell=$_cell (expect red: $_expect) ---"
    _got=
    for m in listing type limit landed; do
        _mlib="$SANDBOX/lib.$m.sh"
        mutate "$m" "$_mlib" || continue
        _res=$( (run_tar_corpus "$_mlib" quiet) )
        _rc=$?
        # shellcheck disable=SC2086
        set -- $_res
        if [ "$_rc" -ne 0 ]; then
            _got="$_got $m"
            printf '    red   deleting the %s check breaks %s case(s)\n' "$m" "$2"
        else
            printf '    green deleting the %s check breaks nothing in this cell\n' "$m"
        fi
    done
    _got=$(printf '%s' "$_got" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ' | sed 's/ $//')
    _exp=$(printf '%s' "$_expect" | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$_got" = "$_exp" ]; then
        ok "exactly the expected checks are load-bearing here: $_got"
    else
        bad "load-bearing checks in this cell are [$_got], the table says [$_exp]"
    fi
}

# --- zip corpus ------------------------------------------------------------
do_zip() {
    note ""
    if ! command -v pwsh > /dev/null 2>&1; then
        bad "pwsh is not on PATH -- the Windows extractor's corpus did not run, and a silent skip is how a rule stops being one"
        return
    fi
    note "--- zip corpus: pwsh $(pwsh -NoProfile -Command "\$PSVersionTable.PSVersion.ToString()" 2> /dev/null) ---"
    if pwsh -NoProfile -File "$ROOT/scripts/plugin-zip-tests.ps1" \
        -Lib "$ROOT/plugin/lib-safe-extract.ps1" -Corpus "$CORPUS"; then
        ok "zip corpus matched MANIFEST"
    else
        bad "zip corpus disagreed with MANIFEST"
    fi
}

mode=${1:---all}
case "$mode" in
    --tar)       do_tar ;;
    --mutations) do_mutations "${2:-gnu-nonroot}" ;;
    --zip)       do_zip ;;
    --all)       do_tar; do_mutations "${2:-gnu-nonroot}"; do_zip ;;
    *) echo "usage: $0 [--tar|--mutations <cell>|--zip|--all <cell>]" >&2; exit 2 ;;
esac

note ""
note "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
