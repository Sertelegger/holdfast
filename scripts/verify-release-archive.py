#!/usr/bin/env python3
"""Archive inspection and safe extraction for scripts/verify-release-archive.sh.

Why this is Python and not more shell: the checks §13.3 step 5 names are about
ENTRY TYPE — "reject absolute paths, `..` path components, symlinks, hardlinks,
device files" — and the only portable shell answer is parsing `tar -tvf`, whose
output format differs between GNU tar and bsdtar. This release pipeline runs
under both. `tarfile` and `zipfile` answer the question directly instead of by
scraping a listing, and python3 is already load-bearing here: ci.yml's hygiene
job runs `scripts/spec-enum-check.py`.

Two modes:

    verify-release-archive.py <archive> <expected-member> [extract-dir]
    verify-release-archive.py --fixtures <dir>

The second writes the adversarial fixture set the shell's `--self-test` drives.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tarfile
import tempfile
import zipfile

FAILS = 0


def ok(msg: str) -> None:
    print(f"  ok    {msg}")


def bad(token: str, detail: str) -> None:
    global FAILS
    FAILS += 1
    print(f"  FAIL  {token}: {detail}")


class Entry:
    """One archive member, normalised across tar and zip."""

    def __init__(self, name, kind, size, mode, read):
        self.name = name
        self.kind = kind  # 'file' | 'dir' | 'symlink' | 'hardlink' | 'device' | 'other'
        self.size = size
        self.mode = mode  # None where the format does not carry one
        self.read = read


def _tar_entries(path):
    tf = tarfile.open(path, "r:gz")
    out = []
    for m in tf.getmembers():
        if m.isreg():
            kind = "file"
        elif m.isdir():
            kind = "dir"
        elif m.issym():
            kind = "symlink"
        elif m.islnk():
            kind = "hardlink"
        elif m.ischr() or m.isblk() or m.isfifo():
            kind = "device"
        else:
            kind = "other"
        out.append(
            Entry(
                m.name,
                kind,
                m.size,
                m.mode,
                (lambda mm=m: tf.extractfile(mm).read()) if m.isreg() else (lambda: b""),
            )
        )
    return tf, out


def _zip_entries(path):
    zf = zipfile.ZipFile(path)
    out = []
    for i in zf.infolist():
        hi = i.external_attr >> 16
        fmt = stat.S_IFMT(hi) if hi else 0
        if fmt == stat.S_IFLNK:
            kind = "symlink"
        elif fmt in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO):
            kind = "device"
        elif i.is_dir():
            kind = "dir"
        else:
            kind = "file"
        # A zip written on Windows carries no Unix mode at all, so `None`
        # here is the honest answer and the executable-bit check below is
        # reported as a named skip rather than silently passing.
        mode = stat.S_IMODE(hi) if hi else None
        out.append(Entry(i.filename, kind, i.file_size, mode, (lambda ii=i: zf.read(ii))))
    return zf, out


def verify(archive: str, member: str, extract_dir: str) -> int:
    is_zip = archive.endswith(".zip")
    try:
        handle, entries = (_zip_entries if is_zip else _tar_entries)(archive)
    except Exception as exc:  # noqa: BLE001 — any unreadable archive is one failure
        bad("unreadable-archive", f"{os.path.basename(archive)}: {exc}")
        return 1

    with handle:
        # §13.3: "archives that do not contain exactly the expected `holdfast`
        # executable for the target". Exactly one entry, and it is that one.
        if len(entries) != 1:
            bad("member-count", f"{len(entries)} entries, expected exactly 1: {[e.name for e in entries]}")
            return 1
        e = entries[0]

        # One check covers absolute paths, `..` components and any directory
        # prefix, because all three make the name something other than the
        # bare expected one. Stating them separately would be three ways to
        # spell the same comparison.
        if e.name != member:
            bad("member-name", f"member is {e.name!r}, expected {member!r} (absolute, `..` and nested names all land here)")
            return 1
        ok(f"one member, named exactly {member!r}")

        if e.kind != "file":
            bad("member-type", f"{e.name!r} is a {e.kind}; §13.3 rejects symlinks, hardlinks, directories and device files")
            return 1
        ok(f"{member!r} is a regular file")

        if e.size <= 0:
            bad("empty-member", f"{e.name!r} is {e.size} bytes")
            return 1

        if e.mode is None:
            print("  skip  no Unix mode in this archive format — executable bit unchecked")
        elif not (e.mode & 0o111):
            bad("not-executable", f"{e.name!r} has mode {e.mode:04o}; nothing would be able to run it")
            return 1
        else:
            ok(f"{member!r} carries an executable bit ({e.mode:04o})")

        # **Written out by name rather than extracted by the library.** The
        # checks above are what makes this safe, so the extraction must not
        # reintroduce the hazard by letting the archive choose a path: the
        # destination is composed here from a name this code already proved
        # equal to a constant.
        own_tmp = None
        if not extract_dir:
            own_tmp = tempfile.mkdtemp(prefix="holdfast-verify-")
            extract_dir = own_tmp
        os.makedirs(extract_dir, exist_ok=True)
        dest = os.path.join(extract_dir, member)
        data = e.read()
        with open(dest, "wb") as fh:
            fh.write(data)
        os.chmod(dest, 0o755)

        st = os.lstat(dest)
        if not stat.S_ISREG(st.st_mode) or st.st_size != e.size:
            bad("extract-shape", f"{dest} is {st.st_size} bytes, archive said {e.size}")
            return 1
        ok(f"extracted to {dest} ({st.st_size} bytes, mode 0755)")
        if own_tmp:
            os.remove(dest)
            os.rmdir(own_tmp)
    return 0


# --------------------------------------------------------------------------
# Fixtures: one archive per clause of §13.3 step 5, plus the SHA256SUMS.txt
# failures the shell half parses for.
# --------------------------------------------------------------------------

BIN = b"\x7fELF" + b"holdfast fixture payload" * 8


def _tar(path, build):
    with tarfile.open(path, "w:gz") as tf:
        build(tf)


def _reg(name, mode=0o755, data=BIN):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.REGTYPE
    ti.mode = mode
    ti.size = len(data)
    return ti, data


def fixtures(outdir: str) -> int:
    os.makedirs(outdir, exist_ok=True)
    cases = []  # (filename, expected-token-or-'-', sum-override)

    def tar_case(name, token, build, sum_override=None):
        _tar(os.path.join(outdir, name), build)
        cases.append((name, token, sum_override))

    def add_reg(tf, name, mode=0o755, data=BIN):
        ti, d = _reg(name, mode, data)
        tf.addfile(ti, __import__("io").BytesIO(d))

    def special(tf, name, ttype, mode=0o755, linkname=""):
        ti = tarfile.TarInfo(name)
        ti.type = ttype
        ti.mode = mode
        ti.linkname = linkname
        tf.addfile(ti)

    tar_case("holdfast-linux-x86_64.tar.gz", "-", lambda tf: add_reg(tf, "holdfast"))
    tar_case("holdfast-fixture-badsum.tar.gz", "checksum-mismatch",
             lambda tf: add_reg(tf, "holdfast"), sum_override="0" * 64)
    tar_case("holdfast-fixture-shortdigest.tar.gz", "malformed-sum-line",
             lambda tf: add_reg(tf, "holdfast"), sum_override="deadbeef")
    tar_case("holdfast-fixture-unlisted.tar.gz", "no-sum-line",
             lambda tf: add_reg(tf, "holdfast"), sum_override="__omit__")
    tar_case("holdfast-fixture-duplicated.tar.gz", "no-sum-line",
             lambda tf: add_reg(tf, "holdfast"), sum_override="__twice__")
    tar_case("holdfast-fixture-two-members.tar.gz", "member-count",
             lambda tf: (add_reg(tf, "holdfast"), add_reg(tf, "README")))
    tar_case("holdfast-fixture-nested.tar.gz", "member-name",
             lambda tf: add_reg(tf, "bin/holdfast"))
    tar_case("holdfast-fixture-absolute.tar.gz", "member-name",
             lambda tf: add_reg(tf, "/holdfast"))
    tar_case("holdfast-fixture-dotdot.tar.gz", "member-name",
             lambda tf: add_reg(tf, "../holdfast"))
    tar_case("holdfast-fixture-misnamed.tar.gz", "member-name",
             lambda tf: add_reg(tf, "holdfastd"))
    tar_case("holdfast-fixture-symlink.tar.gz", "member-type",
             lambda tf: special(tf, "holdfast", tarfile.SYMTYPE, linkname="/bin/sh"))
    tar_case("holdfast-fixture-hardlink.tar.gz", "member-type",
             lambda tf: special(tf, "holdfast", tarfile.LNKTYPE, linkname="/etc/passwd"))
    tar_case("holdfast-fixture-dir.tar.gz", "member-type",
             lambda tf: special(tf, "holdfast", tarfile.DIRTYPE))
    tar_case("holdfast-fixture-chardev.tar.gz", "member-type",
             lambda tf: special(tf, "holdfast", tarfile.CHRTYPE))
    tar_case("holdfast-fixture-fifo.tar.gz", "member-type",
             lambda tf: special(tf, "holdfast", tarfile.FIFOTYPE))
    tar_case("holdfast-fixture-empty.tar.gz", "empty-member",
             lambda tf: add_reg(tf, "holdfast", data=b""))
    tar_case("holdfast-fixture-noexec.tar.gz", "not-executable",
             lambda tf: add_reg(tf, "holdfast", mode=0o644))
    tar_case("notholdfast-linux-x86_64.tar.gz", "asset-name",
             lambda tf: add_reg(tf, "holdfast"))

    def zip_case(name, token, entries):
        p = os.path.join(outdir, name)
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
            for mname, attr, data in entries:
                zi = zipfile.ZipInfo(mname, (1980, 1, 1, 0, 0, 0))
                zi.external_attr = attr << 16
                zf.writestr(zi, data)
        cases.append((name, token, None))

    zip_case("holdfast-windows-x86_64.zip", "-", [("holdfast.exe", 0o100755, BIN)])
    zip_case("holdfast-windows-fixture-symlink.zip", "member-type",
             [("holdfast.exe", 0o120777, b"/bin/sh")])
    zip_case("holdfast-windows-fixture-misnamed.zip", "member-name",
             [("holdfast", 0o100755, BIN)])

    sums = []
    expected = []
    for name, token, override in cases:
        digest = hashlib.sha256(open(os.path.join(outdir, name), "rb").read()).hexdigest()
        if override == "__omit__":
            pass
        elif override == "__twice__":
            sums.append(f"{digest}  {name}")
            sums.append(f"{digest}  {name}")
        elif override:
            sums.append(f"{override}  {name}")
        else:
            sums.append(f"{digest}  {name}")
        expected.append(f"{name} {token}")

    with open(os.path.join(outdir, "SHA256SUMS.txt"), "w") as fh:
        fh.write("\n".join(sums) + "\n")
    with open(os.path.join(outdir, "EXPECTED.txt"), "w") as fh:
        fh.write("\n".join(expected) + "\n")
    print(f"{len(cases)} fixtures in {outdir}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--fixtures":
        sys.exit(fixtures(sys.argv[2]))
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    rc = verify(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    sys.exit(1 if (rc or FAILS) else 0)
