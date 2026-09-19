#!/bin/sh
# The plugin bootstrap's safe-extraction rules, asserted against a corpus of
# hostile archives.
#
# **POSIX sh, because this file is itself part of the test.** It runs under
# dash on the Ubuntu cell and under busybox ash in the Alpine cell, and a
# bash-ism here would mean the shell under test is not the shell that ran.
#
# Usage:
#   plugin-archive-tests.sh --tar                  the write cap, then the
#                                                  tar corpus
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

# reason_ok <token[|token...]> <captured message>
#
# True when the refusal carries the message of one of the named checks. The
# match is a SUBSTRING of prose that is stable across shells, not a whole-line
# compare: the messages embed archive-supplied names, and `$(...)` over a name
# with an embedded newline renders differently under dash and under bash
# (measured: case 09 prints `holdfast ../..` under dash and `holdfast\n../..`
# under bash). A whole-message assertion would be a test of the shell.
#
# An unknown token is a FAILURE, not a skip. The corpus generator holds the
# authoritative token list; if it grows one this table has no pattern for, the
# alternative to failing is silently asserting nothing.
reason_ok() {
    _want_r=$1
    _msg=$2
    _hit=1
    for _t in $(printf '%s' "$_want_r" | tr '|' ' '); do
        case "$_t" in
            listing)  _pat='does not contain exactly' ;;
            type)     _pat='is not a regular file (mode' ;;
            setuid)   _pat='carries a setuid/setgid bit' ;;
            hardlink) _pat='it is a hardlink to a file that was already on disk' ;;
            limit)    _pat="extraction of " ;;
            size)     _pat='-byte bound' ;;
            *)        bad "MANIFEST names reason '$_t', which this harness has no pattern for"
                      return 1 ;;
        esac
        case "$_msg" in
            *"$_pat"*) _hit=0 ;;
        esac
    done
    return $_hit
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
    # human-readable prose and this loop has no use for it. `reason` is the
    # token this loop very much does have a use for -- see reason_ok.
    while read -r kind name verdict reason why; do
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
        elif [ "$_rc" -eq 0 ]; then
            _v=BAD
        elif reason_ok "$reason" "$_out"; then
            _v=ok
        else
            # Rejected, but by something other than the check this case was
            # written to provoke. That is not a pass: it means the case has
            # stopped testing what its name says, and the check it was aimed
            # at is now asserted by nothing.
            _v=BAD-REASON
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
            [ -n "$_quiet" ] || printf '    %-13s %-30s want=%-6s/%-9s rc=%s %s\n' \
                "$_v" "$name" "$verdict" "$reason" "$_rc" \
                "$(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-90)" >&2
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

# --- the bomb bound, asserted in bytes rather than in the shell's blocks ----
#
# **This is the assertion the macOS failure needed and did not have.** The
# library caps tar with `ulimit -f`, whose argument is in blocks, and whose
# block size is 512 under dash and 1024 under bash -- so a fixed block count
# meant 128 MiB on the cells CI ran and 256 MiB under macOS `/bin/sh`, which
# IS bash. The 200 MiB corpus bomb fitted under the doubled cap and was
# installed. Nothing about the tar implementation was involved: GNU tar 1.35
# and bsdtar 3.7.2 both accept it under bash and both refuse it under dash.
#
# So: ask the kernel what the cap came out as, in bytes, in whatever shell is
# running. `seek` makes it a one-byte write at the far offset -- RLIMIT_FSIZE
# is checked against the offset, so this costs no disk and no time and still
# asks the exact question the bomb asks.
#
# Both directions, because a cap that is too SMALL silently stops shipping the
# real 13.5 MB binary, and "refused everything" is not a passing guard either.
do_bound() {
    note ""
    # shellcheck source=plugin/lib-safe-extract.sh
    . "$LIB"
    note "--- the write cap, shell=$(shell_name) HF_MAX_BYTES=$HF_MAX_BYTES HF_MAX_BLOCKS=$HF_MAX_BLOCKS ---"
    _pr=$SANDBOX/bound-probe

    # The `{ ...; } 2>/dev/null` is around the WHOLE test and not just the
    # subshell: SIGXFSZ kills the `dd`, and the notice ("File size limit
    # exceeded") is printed by the shell that reaps it, which is this one.
    # A redirection inside the subshell does not reach it, and a CI log that
    # says "File size limit exceeded" immediately above a green tick reads
    # like a failure to everyone who has not read this function.
    rm -f "$_pr"
    _capped=yes
    { ( ulimit -f "$HF_MAX_BLOCKS" 2>/dev/null
        dd if=/dev/zero of="$_pr" bs=1 count=1 seek="$HF_MAX_BYTES"
      ) > /dev/null 2>&1 && _capped=no
    } 2>/dev/null
    if [ "$_capped" = no ]; then
        bad "a write at offset $HF_MAX_BYTES succeeded under 'ulimit -f $HF_MAX_BLOCKS' -- this shell's block size makes the cap LARGER than HF_MAX_BYTES"
    else
        ok "the cap this shell derives from HF_MAX_BLOCKS is at most HF_MAX_BYTES"
    fi

    # 16 MiB: comfortably above the real binary, comfortably below the bound.
    rm -f "$_pr"
    _admits=no
    { ( ulimit -f "$HF_MAX_BLOCKS" 2>/dev/null
        dd if=/dev/zero of="$_pr" bs=1 count=1 seek=16777216
      ) > /dev/null 2>&1 && _admits=yes
    } 2>/dev/null
    if [ "$_admits" = yes ]; then
        ok "the cap still admits a 16 MiB write, so it has not been tightened onto the real binary"
    else
        bad "a 16 MiB write was refused under 'ulimit -f $HF_MAX_BLOCKS' -- the cap is too small for the binary this bootstrap installs"
    fi
    rm -f "$_pr"
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
        size)    sed '/# >>> CHECK size$/,/# <<< CHECK size$/d' "$LIB" > "$2" ;;
        # The extraction lives inside the `limit` block, so deleting the block
        # deletes the thing under test. Only the ulimit line is removed. The
        # comments above it name `ulimit -f` too, hence the anchor.
        limit)   sed '/^ *ulimit -f /d' "$LIB" > "$2" ;;
        # The one compound mutation, and the reason it exists: `limit` and
        # `size` are the same bound in two currencies, so each alone is
        # masked by the other. Only removing both lets the bomb land.
        limit+size)
                 sed -e '/^ *ulimit -f /d' \
                     -e '/# >>> CHECK size$/,/# <<< CHECK size$/d' "$LIB" > "$2" ;;
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
    # **`limit` and `size` are deliberately absent from both lists.** They
    # are the same bomb bound expressed twice -- one capping what tar may
    # write, one measuring what arrived -- so deleting either alone changes
    # nothing the corpus can see, and `limit+size` is the row that proves the
    # pair is load-bearing. Because the table is checked in BOTH directions,
    # this is not a hole: delete the `size` block from the library for real
    # and `limit` starts going red, `_got` gains a member the table does not
    # have, and this assertion fails. Redundancy asserted, not assumed.
    #
    # **`type` is red in BOTH cells now, and it was green in busybox-root
    # until the reason assertion landed.** With only the exit status asserted,
    # deleting `type` in this cell changed nothing visible: `landed` caught
    # the symlink, the device and the setuid archive on the way out and the
    # cases still "passed". They passed as the wrong test. Asserting the
    # reason is what turned a check that was invisible in one cell into a
    # check that is load-bearing in both, which is the direction that should
    # be welcome.
    case "$_cell" in
        gnu-nonroot)  _expect="listing type limit+size" ;;
        busybox-root) _expect="listing type landed limit+size" ;;
        *) echo "unknown cell '$_cell' (want gnu-nonroot or busybox-root)" >&2; exit 2 ;;
    esac
    note ""
    note "--- mutation controls, cell=$_cell (expect red: $_expect) ---"
    _got=
    for m in listing type limit size landed limit+size; do
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
    --tar)       do_bound; do_tar ;;
    --mutations) do_mutations "${2:-gnu-nonroot}" ;;
    --zip)       do_zip ;;
    --all)       do_bound; do_tar; do_mutations "${2:-gnu-nonroot}"; do_zip ;;
    *) echo "usage: $0 [--tar|--mutations <cell>|--zip|--all <cell>]" >&2; exit 2 ;;
esac

note ""
note "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
