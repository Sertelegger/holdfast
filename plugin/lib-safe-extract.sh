#!/bin/sh
# Safe single-member archive extraction for the Holdfast bootstrap (spec
# §13.3 step 5). Sourced by `plugin/bootstrap`; also sourced directly by
# scripts/plugin-archive-tests.sh, which is the only reason it is a separate
# file rather than inlined.
#
# POSIX sh. No bash-isms: no `[[ ]]`, no arrays, no `local`, no `$'...'`,
# no `${x//y}`, no `pipefail`, no `+=`.
#
# ---------------------------------------------------------------------------
# WHY THIS IS A WHITELIST AND NOT THE BLACKLIST §13.3 ASKS FOR
# ---------------------------------------------------------------------------
# §13.3 words the rule as "reject absolute paths, `..` path components,
# symlinks, hardlinks, device files". Measured, that rule cannot be written
# over a tar listing, because busybox tar sanitises names BEFORE it prints
# them: an entry stored as `../../../tmp/HF_PWN` lists as `tmp/HF_PWN` under
# busybox 1.36.1 and as `../../../tmp/HF_PWN` under GNU tar 1.35 and bsdtar
# 3.8.3. A check that greps the listing for `..` therefore never fires on the
# one implementation §13.3 was written for — while the archive still extracts
# a file the maintainer never shipped.
#
# The rule that is implementable everywhere is the clause the same sentence
# ends with: "archives that do not contain exactly the expected holdfast
# executable". That is a whitelist, and it is what this file enforces.
#
# ---------------------------------------------------------------------------
# FIVE CHECKS, AND WHAT EACH ONE IS THE ONLY THING TO CATCH
# ---------------------------------------------------------------------------
# scripts/plugin-archive-tests.sh deletes each block below from a copy of this
# file and asserts the corpus goes red. Measured results of that mutation run:
#
#   delete `listing`     -> two-entry and duplicate-name archives accepted, both cells
#   delete `type`        -> setuid archive accepted in the GNU/non-root cell;
#                           under busybox it is `landed` that catches the
#                           symlink, device and setuid cases instead, which
#                           the reason assertion counts as a failure and the
#                           bare exit status did not
#   delete `landed`      -> hardlink-to-/etc/passwd installed, busybox/root cell only
#   delete `limit`       -> nothing; `size` still refuses the bomb, 200 MiB hits disk first
#   delete `size`        -> nothing; `limit` still refuses the bomb
#   delete BOTH of those -> 200 MiB decompression bomb installed as `holdfast`
#
# `landed` is invisible in the GNU-tar / non-root cell. A one-cell test matrix
# makes it look like dead code and invites its deletion, which is why the CI
# job runs busybox-as-root as a separate cell.
#
# `limit` and `size` are the one deliberately redundant pair here, and the
# mutation table asserts the redundancy in both directions: if either is ever
# deleted from this file, the *other* one's mutation starts going red, the
# measured table stops matching, and the harness fails. Redundant is not the
# same as unasserted.
#
# ---------------------------------------------------------------------------
# WHY THE BOMB BOUND IS ENFORCED TWICE, IN TWO DIFFERENT CURRENCIES
# ---------------------------------------------------------------------------
# It was enforced once, by `ulimit -f`, with a block count that assumed the
# POSIX 512-byte unit -- and that shipped a guard whose strength depended on
# which shell `/bin/sh` is:
#
#   dash          `ulimit -f 262144` -> RLIMIT_FSIZE 134217728  (128 MiB)
#   bash          `ulimit -f 262144` -> RLIMIT_FSIZE 268435456  (256 MiB)
#   bash --posix  `ulimit -f 262144` -> RLIMIT_FSIZE 134217728  (128 MiB)
#
# (measured, Linux 6.12, bash 5.2.21 / dash 0.5.12: this file's own test does
# the same measurement on whatever shell it runs under, and asserts the
# result). bash counts 1024-byte blocks unless it is in posix mode.
#
# macOS `/bin/sh` is bash, and the corpus header printed `shell=bash` on the
# `macos-native` job that found this -- where the 200 MiB bomb was ACCEPTED,
# which is only possible if the cap there came out above 200 MiB, i.e. if
# those were 1024-byte blocks. That is a deduction from the observed failure
# rather than a measurement on a macOS box, and the bash version there (3.2,
# which predates the posix-mode concession above) is the likely reason posix
# mode did not save it.
#
# The failure was NOT a tar difference: GNU tar 1.35 and bsdtar 3.7.2 both
# accept the bomb under bash and both refuse it under dash. CI never saw it
# because every Linux cell ran the corpus under `dash` or `busybox sh`.
#
# So the bound is now stated once, in bytes, and enforced twice:
#
#   `limit` caps what tar may WRITE. It keeps a bomb off the disk, it is
#           kernel-enforced rather than parsed out of any tar's diagnostics,
#           and it is computed against the largest block size any shell uses
#           so that it is <= HF_MAX_BYTES under every unit convention.
#   `size`  is the VERDICT. It measures what actually arrived and compares it
#           to the byte constant directly. It asks no shell to have meant the
#           right unit, no kernel to have delivered a signal, and no tar to
#           have reported anything -- which is what the `ulimit` line, with
#           its errors sent to /dev/null, quietly depended on.
# ---------------------------------------------------------------------------

# The bomb bound, in BYTES and in exactly one place. The real binary is
# ~13.5 MB, so this is ~10x headroom. lib-safe-extract.ps1 carries the same
# number as its $MaxBytes default, and the zip corpus asserts it there.
HF_MAX_BYTES=134217728

# The same bound in the only currency `ulimit -f` accepts. Divided by the
# LARGEST block size any shell uses (bash's 1024) so that the resulting cap
# can never come out ABOVE HF_MAX_BYTES -- which is the direction the old
# code got wrong. A 512-byte-block shell therefore caps tar at 64 MiB and a
# 1024-byte-block one at 128 MiB; both are >4x the real binary.
#
# It is a variable rather than an expression inline so that
# scripts/plugin-archive-tests.sh can assert the resulting cap in BYTES
# against this same file, instead of restating the arithmetic and asserting
# its own copy of the bug.
HF_MAX_BLOCKS=$((HF_MAX_BYTES / 1024))

# hf_safe_extract_tar <archive> <empty 0700 dest dir> <expected member name>
#
# Uses $HOLDFAST_TAR as the tar implementation (default `tar`). The SAME
# binary must do the listing and the extraction: `tar` and `bsdtar` disagree
# about whether `./holdfast` matches `holdfast`, and listing with one and
# extracting with the other reintroduces a tool-of-check/tool-of-use gap that
# list-then-extract otherwise does not have.
hf_safe_extract_tar() {
    _arc=$1
    _dst=$2
    _want=$3
    _tar=${HOLDFAST_TAR:-tar}

    # >>> CHECK listing
    # The listing must be EXACTLY the one member we expect, with nothing
    # before or after it. `$(...)` strips the trailing newline, so a second
    # entry, an embedded-newline name, a `./` prefix and a directory prefix
    # all make the string unequal. This is the check that does not care what
    # the tar implementation did to the name first.
    _list=$("$_tar" -tzf "$_arc" 2>/dev/null) || {
        hf_die "cannot read archive $_arc (not a gzip tar?)"
    }
    if [ "$_list" != "$_want" ]; then
        hf_die "archive does not contain exactly '$_want' -- refusing it (listing: $(printf '%s' "$_list" | tr '\n' ' '))"
    fi
    # <<< CHECK listing

    # >>> CHECK type
    # First character of the 10-char mode string from `-tv`. Rejects symlink,
    # directory, device and fifo entries on GNU tar and bsdtar. busybox
    # reports a HARDLINK entry as `-`, so this is defence in depth rather
    # than the decision; `CHECK landed` is what settles that case.
    #
    # The s/S test is not theoretical: tar restores setuid when it runs as
    # root, agents in containers routinely are root, and no Holdfast release
    # archive has ever carried the bit.
    _mode=$("$_tar" -tvzf "$_arc" 2>/dev/null | head -1 | cut -c1-10)
    case "$_mode" in
        -*) ;;
        *)  hf_die "archive member '$_want' is not a regular file (mode '$_mode')" ;;
    esac
    case "$_mode" in
        *s* | *S*) hf_die "archive member '$_want' carries a setuid/setgid bit ($_mode)" ;;
    esac
    # <<< CHECK type

    # >>> CHECK limit
    # `ulimit -f` is POSIX, is inherited by the tar child, and caps what tar
    # may write: a declared-size bomb dies on SIGXFSZ instead of filling the
    # user's home filesystem.
    #
    # **Its argument is in blocks, and the block size is not portable** -- see
    # the measurements and HF_MAX_BLOCKS at the top of this file. A third,
    # larger unit than the two measured there would make the cap too small and
    # reject the real binary loudly. That is the safe way round for a guess
    # about a unit to be wrong, and it is not the way round this was wrong.
    (
        ulimit -f "$HF_MAX_BLOCKS" 2>/dev/null
        "$_tar" -xzf "$_arc" -C "$_dst" "$_want"
    ) || hf_die "extraction of '$_want' failed"
    # <<< CHECK limit
    # The extraction above is inside the `limit` block on purpose: deleting
    # the block deletes the extraction with it, and a mutation that removes
    # the thing under test proves nothing. The harness therefore replaces
    # this block rather than deleting it -- see its `mutate` function.

    _f=$_dst/$_want

    # >>> CHECK landed
    # Validate what is on disk. This is the only check that depends on no
    # tar's self-description, and it is the one that catches the busybox
    # hardlink case -- where the listing said `-` (regular file) and busybox
    # then materialised a second link to /etc/passwd named `holdfast`.
    _got=$(ls -A "$_dst")
    if [ "$_got" != "$_want" ]; then
        hf_die "extracted tree is not exactly '$_want' (got: $(printf '%s' "$_got" | tr '\n' ' '))"
    fi
    if [ -h "$_f" ]; then hf_die "'$_want' extracted as a symlink"; fi
    if [ -d "$_f" ]; then hf_die "'$_want' extracted as a directory"; fi
    if [ -b "$_f" ] || [ -c "$_f" ]; then hf_die "'$_want' extracted as a device node"; fi
    if [ -p "$_f" ] || [ -S "$_f" ]; then hf_die "'$_want' extracted as a fifo or socket"; fi
    if [ ! -f "$_f" ]; then hf_die "'$_want' is not a regular file"; fi
    if [ ! -s "$_f" ]; then hf_die "'$_want' is empty"; fi
    # Link count is field 2 of POSIX `ls -l`. Greater than 1 means the
    # archive aliased a file that already existed on this disk.
    _ls=$(ls -ldn "$_f")
    # shellcheck disable=SC2086
    # Deliberate word splitting: `set --` over an unquoted `ls -ldn` line is
    # the POSIX way to get at fields 1 and 2 without awk or cut -f.
    set -- $_ls
    if [ "$2" != "1" ]; then
        hf_die "'$_want' has $2 links -- it is a hardlink to a file that was already on disk"
    fi
    case "$1" in
        *s* | *S*) hf_die "'$_want' landed with a setuid/setgid bit ($1)" ;;
    esac
    # <<< CHECK landed

    # >>> CHECK size
    # The bomb verdict. It runs AFTER `landed` on purpose: `landed` has by
    # now established that $_f is a regular file, so this cannot block on a
    # fifo or read a device forever.
    #
    # `wc -c` rather than a field of `ls -l`, deliberately. The size column's
    # index moves between implementations -- GNU prints `user/group`, bsdtar
    # prints uid and gid as two fields, busybox prints `uid/gid` -- and a size
    # read by field index is the classic way to get a silent zero from the
    # other tool and a bound that always passes.
    #
    # BSD `wc` pads its output with leading blanks and GNU's does not, so the
    # blanks come off before the comparison: `[ "  209715200" -gt ... ]` is
    # not portably an integer comparison.
    _bytes=$(wc -c < "$_f" 2>/dev/null | tr -d ' ')
    case "$_bytes" in
        '' | *[!0-9]*) hf_die "cannot measure '$_want' (got '$_bytes')" ;;
    esac
    if [ "$_bytes" -gt "$HF_MAX_BYTES" ]; then
        hf_die "'$_want' is $_bytes bytes, over the $HF_MAX_BYTES-byte bound -- refusing it"
    fi
    # <<< CHECK size

    chmod 700 "$_f" || hf_die "cannot chmod '$_f'"
    return 0
}
