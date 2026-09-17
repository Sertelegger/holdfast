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
# FOUR CHECKS, AND EACH ONE IS THE ONLY THING THAT CATCHES SOMETHING
# ---------------------------------------------------------------------------
# scripts/plugin-archive-tests.sh deletes each block below from a copy of this
# file and asserts the corpus goes red. Measured results of that mutation run:
#
#   delete `listing`  -> two-entry and duplicate-name archives accepted, both cells
#   delete `type`     -> setuid archive accepted, GNU/non-root cell only
#   delete `limit`    -> 200 MiB decompression bomb written to disk
#   delete `landed`   -> hardlink-to-/etc/passwd installed, busybox/root cell only
#
# Two of the four are invisible in the GNU-tar / non-root cell. A one-cell
# test matrix makes them look like dead code and invites their deletion,
# which is why the CI job runs busybox-as-root as a separate cell.
# ---------------------------------------------------------------------------

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
    # `ulimit -f` is POSIX, is inherited by the tar child, and is in 512-byte
    # blocks. A declared-size bomb dies on SIGXFSZ instead of filling the
    # user's home filesystem. 262144 blocks = 128 MiB; the real binary is
    # 13.5 MB, so the headroom is ~10x.
    (
        ulimit -f 262144 2>/dev/null
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

    chmod 700 "$_f" || hf_die "cannot chmod '$_f'"
    return 0
}
