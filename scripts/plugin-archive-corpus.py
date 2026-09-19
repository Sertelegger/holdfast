#!/usr/bin/env python3
"""Generate the hostile-archive corpus the plugin bootstrap is tested against.

**Generated at test time, never committed.** A fixture committed as a blob can
be quietly deleted, or quietly repaired, and the test that depended on it goes
green either way. Everything here is built from this file on every run, so
disabling a case means deleting a line that shows up in a diff.

Usage:  plugin-archive-corpus.py <outdir>

Writes <outdir>/tar/, <outdir>/zip/ and <outdir>/MANIFEST. MANIFEST is
`<kind> <filename> <ACCEPT|REJECT> <reason-token> <one-line prose>`, and it is
the harness's only source of expected verdicts -- so a case cannot be added
here and left unasserted, or asserted here and not generated.

`<reason-token>` is `-` for ACCEPT rows and otherwise one of TAR_REASONS /
ZIP_REASONS below, `|`-separated where implementations legitimately disagree
about which check catches a case. It exists because "rc != 0" is not the same
claim as "refused for the reason this case was written to provoke": a case
that starts being caught by an earlier check has stopped testing what its name
says, and without this column nothing would notice.

Every REJECT case that writes outside its destination names its escape
`HF_PWN_*`, which is what the harness greps the filesystem for: a case that
"passed" because the extractor errored *after* writing the file is a fail.
"""

import gzip
import io
import os
import shutil
import stat
import sys
import tarfile
import zipfile

# The reason tokens a REJECT row may name, and the check each one stands for.
# The harnesses hold the message substring each token must match --
# scripts/plugin-archive-tests.sh for tar, scripts/plugin-zip-tests.ps1 for
# zip -- and both fail on a token they have no pattern for, so this list and
# those tables cannot drift apart in silence.
TAR_REASONS = {
    "listing",   # CHECK listing: the member set is not exactly {holdfast}
    "type",      # CHECK type: the listed mode is not a regular file
    "setuid",    # CHECK type: setuid/setgid declared in the archive
    "hardlink",  # CHECK landed: it arrived as a link to a file already here
    "limit",     # CHECK limit: tar was killed by RLIMIT_FSIZE mid-write
    "size",      # CHECK size: what landed is over HF_MAX_BYTES
}
ZIP_REASONS = {
    "count",     # not exactly one entry
    "name",      # the entry is not named exactly holdfast.exe
    "type",      # declared Unix mode is not S_IFREG
    "setuid",    # setuid/setgid declared in the zip's external attributes
    "size",      # declared length is outside (0, MaxBytes]
}

BIN = b"#!/bin/sh\necho REAL-HOLDFAST\n"
WANT = "holdfast"
WANT_EXE = "holdfast.exe"
ZBIN = b"MZ-fake-holdfast-exe-payload"


def _reg(tf, name, data=BIN, mode=0o755):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    ti.type = tarfile.REGTYPE
    tf.addfile(ti, io.BytesIO(data))


def _sym(tf, name, target):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = target
    ti.mode = 0o777
    tf.addfile(ti)


def _hard(tf, name, target):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.LNKTYPE
    ti.linkname = target
    ti.mode = 0o644
    tf.addfile(ti)


def _dev(tf, name):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.CHRTYPE
    ti.devmajor, ti.devminor = 1, 3
    ti.mode = 0o666
    tf.addfile(ti)


def _dir(tf, name):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    tf.addfile(ti)


def build_tars(d, manifest):
    def new(name, fmt=tarfile.GNU_FORMAT):
        return tarfile.open(os.path.join(d, name), "w:gz", format=fmt)

    def case(name, verdict, reason, why):
        manifest.append(("tar", name, verdict, reason, why))

    with new("00-good.tar.gz") as t:
        _reg(t, WANT)
    case("00-good.tar.gz", "ACCEPT", "-", "exactly one regular file named holdfast")

    with new("01-traversal.tar.gz") as t:
        _reg(t, "../../../tmp/HF_PWN_TRAVERSAL")
    case("01-traversal.tar.gz", "REJECT", "listing", "'..' components -- and busybox tar strips them before listing them")

    with new("02-absolute.tar.gz") as t:
        _reg(t, "/tmp/HF_PWN_ABSOLUTE")
    case("02-absolute.tar.gz", "REJECT", "listing", "absolute member path")

    with new("03-symlink-out.tar.gz") as t:
        _sym(t, WANT, "/tmp/HF_PWN_SYMTARGET")
    case("03-symlink-out.tar.gz", "REJECT", "type", "the expected name is a symlink out of the tree")

    with new("04-symlink-escape.tar.gz") as t:
        _sym(t, "esc", "/tmp")
        _reg(t, "esc/HF_PWN_VIASYMLINK")
    case("04-symlink-escape.tar.gz", "REJECT", "listing", "symlink then write through it")

    with new("05-two-entries.tar.gz") as t:
        _reg(t, WANT)
        _reg(t, "README.md", b"hi\n", 0o644)
    case("05-two-entries.tar.gz", "REJECT", "listing", "an extra entry beside the expected one")

    with new("06-device.tar.gz") as t:
        _dev(t, WANT)
    case("06-device.tar.gz", "REJECT", "type", "character device named holdfast (only reachable as root)")

    with new("07-hardlink-out.tar.gz") as t:
        _hard(t, WANT, "/etc/passwd")
    case("07-hardlink-out.tar.gz", "REJECT", "type|hardlink", "hardlink to a file already on disk -- busybox calls this a regular file")

    with new("08-setuid.tar.gz") as t:
        _reg(t, WANT, BIN, 0o4755)
    case("08-setuid.tar.gz", "REJECT", "setuid", "setuid bit, which tar restores when run as root")

    with new("09-newline-name.tar.gz") as t:
        _reg(t, "holdfast\n../../../tmp/HF_PWN_NEWLINE")
    case("09-newline-name.tar.gz", "REJECT", "listing", "embedded newline, so a line-oriented check sees 'holdfast'")

    with new("10-dupname.tar.gz") as t:
        _reg(t, WANT)
        _reg(t, WANT, b"#!/bin/sh\necho EVIL\n")
    case("10-dupname.tar.gz", "REJECT", "listing", "the name twice -- the second payload is what lands")

    with new("11-pax-path.tar.gz", tarfile.PAX_FORMAT) as t:
        ti = tarfile.TarInfo(WANT)
        ti.size = len(BIN)
        ti.mode = 0o755
        ti.pax_headers = {"path": "../../../tmp/HF_PWN_PAX"}
        t.addfile(ti, io.BytesIO(BIN))
    case("11-pax-path.tar.gz", "REJECT", "listing", "pax 'path' override disagrees with the ustar header")

    with new("12-longname.tar.gz") as t:
        _reg(t, "../" * 40 + "tmp/HF_PWN_LONGNAME")
    case("12-longname.tar.gz", "REJECT", "listing", "GNU longname traversal")

    with new("13-nested-dir.tar.gz") as t:
        _dir(t, "holdfast-0.1.0-linux-x86_64")
        _reg(t, "holdfast-0.1.0-linux-x86_64/holdfast")
    case("13-nested-dir.tar.gz", "REJECT", "listing", "the release tarball shape we did NOT agree to -- a directory prefix")

    with new("14-dotslash.tar.gz") as t:
        _reg(t, "./holdfast")
    case("14-dotslash.tar.gz", "REJECT", "listing", "'./' prefix: bsdtar matches it, GNU and busybox do not -- a macOS/Linux split")

    a = io.BytesIO()
    with tarfile.open(fileobj=a, mode="w") as t:
        _reg(t, WANT)
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        _reg(t, "../../../tmp/HF_PWN_CONCAT")
    with open(os.path.join(d, "15-concat.tar.gz"), "wb") as f:
        f.write(gzip.compress(a.getvalue()))
        f.write(gzip.compress(b.getvalue()))
    case("15-concat.tar.gz", "ACCEPT", "-", "two gzip members: list and extract must agree to stop at the first EOF marker")

    with open(os.path.join(d, "16-tarconcat.tar.gz"), "wb") as f:
        f.write(gzip.compress(a.getvalue() + b.getvalue()))
    case("16-tarconcat.tar.gz", "ACCEPT", "-", "two tar archives in one gzip stream: same list/extract agreement")

    with new("17-dir-named-holdfast.tar.gz") as t:
        _dir(t, WANT)
    case("17-dir-named-holdfast.tar.gz", "REJECT", "listing", "a directory carrying the expected name")

    with new("18-bomb.tar.gz") as t:
        _reg(t, WANT, b"\0" * (200 * 1024 * 1024))
    case("18-bomb.tar.gz", "REJECT", "limit|size", "200 MiB of zeros in a 200 KiB archive")


def build_zips(d, manifest):
    def case(name, verdict, reason, why):
        manifest.append(("zip", name, verdict, reason, why))

    def z(name):
        return zipfile.ZipFile(os.path.join(d, name), "w")

    with z("00-good.zip") as f:
        f.writestr(WANT_EXE, ZBIN)
    case("00-good.zip", "ACCEPT", "-", "exactly one entry named holdfast.exe, no Unix type bits (what a Windows zip looks like)")

    with z("01-good-unix-mode.zip") as f:
        zi = zipfile.ZipInfo(WANT_EXE)
        zi.create_system = 3
        zi.external_attr = (stat.S_IFREG | 0o755) << 16
        f.writestr(zi, ZBIN)
    case("01-good-unix-mode.zip", "ACCEPT", "-", "a zip built on Unix with real S_IFREG bits -- the case an over-strict mode check rejects")

    with z("02-traversal.zip") as f:
        f.writestr("../../../HF_PWN_ZIP_TRAV", ZBIN)
    case("02-traversal.zip", "REJECT", "name", "'..' components")

    with z("03-absolute.zip") as f:
        f.writestr("/tmp/HF_PWN_ZIP_ABS", ZBIN)
    case("03-absolute.zip", "REJECT", "name", "absolute member path")

    with z("04-backslash.zip") as f:
        f.writestr("..\\..\\..\\HF_PWN_ZIP_BS", ZBIN)
    case("04-backslash.zip", "REJECT", "name", "backslash traversal, which a forward-slash-only check misses on Windows")

    with z("05-two-entries.zip") as f:
        f.writestr(WANT_EXE, ZBIN)
        f.writestr("evil.cmd", b"@echo pwn\n")
    case("05-two-entries.zip", "REJECT", "count", "an extra entry beside the expected one")

    with z("06-symlink.zip") as f:
        zi = zipfile.ZipInfo(WANT_EXE)
        zi.create_system = 3
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        f.writestr(zi, "/etc/passwd")
    case("06-symlink.zip", "REJECT", "type", "symlink entry -- Expand-Archive writes this out as a file containing the target")

    with z("07-nested.zip") as f:
        f.writestr("holdfast-0.1.0-windows-x86_64/holdfast.exe", ZBIN)
    case("07-nested.zip", "REJECT", "name", "a directory prefix")

    with z("08-dupname.zip") as f:
        f.writestr(WANT_EXE, ZBIN)
        f.writestr(WANT_EXE, b"EVIL")
    case("08-dupname.zip", "REJECT", "count", "the name twice")

    with z("09-setuid.zip") as f:
        zi = zipfile.ZipInfo(WANT_EXE)
        zi.create_system = 3
        zi.external_attr = (stat.S_IFREG | stat.S_ISUID | 0o755) << 16
        f.writestr(zi, ZBIN)
    case("09-setuid.zip", "REJECT", "setuid", "setuid bit")

    with z("10-empty.zip") as f:
        f.writestr(WANT_EXE, b"")
    case("10-empty.zip", "REJECT", "size", "zero-length member")

    # The UPPER bound, which had no case at all. `10-empty` only ever
    # exercised the `-le 0` half of the same `if`, so the half that refuses a
    # bomb was asserted by nothing on the Windows side -- while the tar side
    # had `18-bomb` for exactly this. Written in chunks rather than as one
    # 200 MiB bytes object: the generator runs inside every CI cell.
    with z("11-bomb.zip") as f:
        zi = zipfile.ZipInfo(WANT_EXE)
        zi.compress_type = zipfile.ZIP_DEFLATED
        with f.open(zi, "w") as h:
            chunk = b"\0" * (1024 * 1024)
            for _ in range(200):
                h.write(chunk)
    case("11-bomb.zip", "REJECT", "size", "200 MiB of zeros in a ~200 KiB archive")


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: plugin-archive-corpus.py <outdir>\n")
        return 2
    out = sys.argv[1]
    shutil.rmtree(out, ignore_errors=True)
    tar_dir = os.path.join(out, "tar")
    zip_dir = os.path.join(out, "zip")
    os.makedirs(tar_dir)
    os.makedirs(zip_dir)
    manifest = []
    build_tars(tar_dir, manifest)
    build_zips(zip_dir, manifest)

    # Anti-vacuity, generator side. If a refactor ever stops emitting a whole
    # family, the harness would happily assert over what is left and report
    # clean. Both kinds, and both verdicts, must be present.
    kinds = {m[0] for m in manifest}
    if kinds != {"tar", "zip"}:
        sys.stderr.write("corpus generator emitted kinds %r, expected tar and zip\n" % (sorted(kinds),))
        return 1
    for kind in ("tar", "zip"):
        got = [m for m in manifest if m[0] == kind]
        if not any(m[2] == "ACCEPT" for m in got):
            sys.stderr.write("no ACCEPT case for %s -- the harness could not tell rejection from breakage\n" % kind)
            return 1
        if sum(1 for m in got if m[2] == "REJECT") < 5:
            sys.stderr.write("fewer than five REJECT cases for %s\n" % kind)
            return 1

    # The `reason` column is what stops a REJECT row passing for the wrong
    # reason. Rejection was asserted as "rc != 0" alone until a bomb that the
    # bound had stopped catching would still have been a pass had anything
    # else refused it first -- so the token names WHICH refusal is expected,
    # and the harnesses match it against the message. `|` lists the
    # alternatives where implementations legitimately differ: busybox tar
    # calls a hardlink a regular file, so `07` is caught by a different check
    # there than under GNU tar.
    for kind, name, verdict, reason, _why in manifest:
        known = TAR_REASONS if kind == "tar" else ZIP_REASONS
        if verdict == "ACCEPT":
            if reason != "-":
                sys.stderr.write("%s/%s is ACCEPT but names reason %r\n" % (kind, name, reason))
                return 1
            continue
        if not reason or reason == "-":
            sys.stderr.write("%s/%s is REJECT with no reason token\n" % (kind, name))
            return 1
        for tok in reason.split("|"):
            if tok not in known:
                sys.stderr.write("%s/%s names reason %r, not one of %r\n"
                                 % (kind, name, tok, sorted(known)))
                return 1

    with open(os.path.join(out, "MANIFEST"), "w") as f:
        for kind, name, verdict, reason, why in manifest:
            path = os.path.join(out, kind, name)
            if not os.path.exists(path):
                sys.stderr.write("MANIFEST names %s/%s, which was not generated\n" % (kind, name))
                return 1
            f.write("%s %s %s %s %s\n" % (kind, name, verdict, reason, why))
    print("%d cases (%d tar, %d zip) in %s"
          % (len(manifest),
             sum(1 for m in manifest if m[0] == "tar"),
             sum(1 for m in manifest if m[0] == "zip"),
             out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
