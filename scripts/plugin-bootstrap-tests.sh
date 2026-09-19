#!/bin/sh
# The plugin bootstrap's download path, against a fabricated GitHub Release
# served over loopback HTTP.
#
# **This is the permanent answer, not a stand-in for a real release.**
# `release.yml` attaches no binary assets on purpose -- doing so IS the
# spec section 12.3 first-external-distribution event -- so there is nothing
# to point a "download the real thing" test at, and there will not be until
# somebody decides to publish. A test that skipped when no release was found
# would be a test that has never run.
#
# POSIX sh. Every assertion is on an observable the code had to produce -- a
# file in the cache, a request count in the server log, a phrase in the error
# -- and never on an exit status alone, and never through a pipe: piping a run
# into `head` makes the harness read head's status and report 0 for a run that
# died. Both of those produced a green test for broken code during this
# harness's own development.
set -u

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
pass=0
fail=0
chk() { # chk <label> <got> <want>
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
        printf '  ok    %-46s %s\n' "$1" "$2"
    else
        fail=$((fail + 1))
        printf '  FAIL  %-46s got[%s] want[%s]\n' "$1" "$2" "$3"
    fi
}
yn() { [ "$1" -ne 0 ] && echo yes || echo no; }

command -v python3 > /dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
command -v curl > /dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

S=$(mktemp -d "${TMPDIR:-/tmp}/hf-boot.XXXXXX") || exit 2
SRV=""
cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2> /dev/null
    rm -rf "$S"
}
trap cleanup EXIT HUP INT TERM

# --- a plugin tree we may edit (version.txt is bumped per case) ------------
PLUG="$S/plugin"
mkdir -p "$PLUG"
cp "$ROOT/plugin/bootstrap" "$ROOT/plugin/lib-safe-extract.sh" "$PLUG/"
chmod +x "$PLUG/bootstrap"
printf '0.1.0\n' > "$PLUG/version.txt"

# --- fabricate the release ------------------------------------------------
REL="$S/release/v0.1.0"
mkdir -p "$REL"
W="$S/work"
mkdir -p "$W"
{
    printf '#!/bin/sh\n'
    printf 'echo "HOLDFAST-FAKE-BINARY argv=[$*]"\n'
    printf 'exit 0\n'
    printf '# '
} > "$W/holdfast"
# 4 MiB of padding. The disk-full case CANNOT FAIL against a 60-byte stub --
# measured: it passed trivially until the fixture was bigger than the
# filesystem it is written to. The real binary is ~13 MB.
head -c 4194304 /dev/zero | tr '\0' '#' >> "$W/holdfast"
chmod 755 "$W/holdfast"
# The archive shape the bootstrap requires, and the shape the release build
# must therefore produce: exactly one entry, a regular file, named literally
# `holdfast`, no `./` prefix and no directory prefix.
tar -czf "$REL/holdfast-linux-x86_64.tar.gz" -C "$W" holdfast
( cd "$REL" && sha256sum holdfast-linux-x86_64.tar.gz > SHA256SUMS.txt )
# A decoy whose name CONTAINS the real one, so a substring lookup picks the
# wrong line and this harness says so.
cp "$REL/holdfast-linux-x86_64.tar.gz" "$REL/holdfast-linux-x86_64-musl.tar.gz"
( cd "$REL" && sha256sum holdfast-linux-x86_64-musl.tar.gz >> SHA256SUMS.txt )
cp "$REL/holdfast-linux-x86_64.tar.gz" "$S/orig.tgz"
cp "$REL/SHA256SUMS.txt" "$S/orig.sums"

PORT=${HOLDFAST_TEST_PORT:-8731}
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$S/release" > "$S/http.log" 2>&1 &
SRV=$!
i=0
while [ "$i" -lt 100 ]; do
    curl -sf "http://127.0.0.1:$PORT/" > /dev/null 2>&1 && break
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 100 ] || { echo "fixture server never came up on $PORT" >&2; exit 2; }
BASE="http://127.0.0.1:$PORT"
CACHE="$S/data"
BIN="$CACHE/bin/holdfast-v0.1.0-linux-x86_64"
SUMS="$CACHE/bin/SHA256SUMS-v0.1.0.txt"

run() { # run <args...>; stdout+stderr combined, never piped by the caller
    env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        /bin/sh "$PLUG/bootstrap" "$@" 2>&1
}
reqs() { grep -c 'GET /' "$S/http.log" 2> /dev/null || echo 0; }
# `find`, not `ls | grep`: the names here are ours and either would work,
# but shellcheck is right that the pattern does not generalise.
count_matching() { find "$1" -maxdepth 1 -name "$2" 2> /dev/null | grep -c . || true; }
cached_bins() { count_matching "$CACHE/bin" 'holdfast-v*'; }

echo "--- T1 happy path ---"
out=$(run mcp --flag); rc=$?
chk "T1 exit 0"              "$rc" 0
chk "T1 the binary ran"      "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY')" 1
chk "T1 argv forwarded"      "$(printf '%s' "$out" | grep -c 'argv=\[mcp --flag\]')" 1
chk "T1 binary cached"       "$([ -x "$BIN" ] && echo yes || echo no)" yes
chk "T1 manifest cached"     "$([ -r "$SUMS" ] && echo yes || echo no)" yes
chk "T1 no temp dir left"    "$(count_matching "$CACHE/bin" '.dl.*')" 0
n1=$(reqs)

echo "--- T2 second run must not touch the network ---"
out=$(run version); rc=$?
chk "T2 exit 0"              "$rc" 0
chk "T2 requests served"     "$(( $(reqs) - n1 ))" 0

echo "--- T3 corrupted archive: fail closed, nothing cached ---"
rm -rf "$CACHE"
printf 'X' | dd of="$REL/holdfast-linux-x86_64.tar.gz" bs=1 seek=60 conv=notrunc 2> /dev/null
out=$(run mcp); rc=$?
chk "T3 exit nonzero"        "$(yn $rc)" yes
chk "T3 names the mismatch"  "$(printf '%s' "$out" | grep -c 'checksum mismatch')" 1
chk "T3 nothing cached"      "$(cached_bins)" 0
cp "$S/orig.tgz" "$REL/holdfast-linux-x86_64.tar.gz"

echo "--- T4 release not published (404) -- the air-gapped message ---"
rm -rf "$CACHE"
printf '9.9.9\n' > "$PLUG/version.txt"
out=$(run mcp); rc=$?
chk "T4 exit nonzero"        "$(yn $rc)" yes
chk "T4 asks if published"   "$(printf '%s' "$out" | grep -c 'is the release published')" 1
chk "T4 names manual URL"    "$(printf '%s' "$out" | grep -c 'github.com/Sertelegger/holdfast/releases')" 1
chk "T4 names the placement" "$(printf '%s' "$out" | grep -c 'holdfast-v9.9.9-linux-x86_64')" 1
printf '0.1.0\n' > "$PLUG/version.txt"

echo "--- T5 manifest has no line for this target ---"
rm -rf "$CACHE"
grep -v ' holdfast-linux-x86_64.tar.gz$' "$S/orig.sums" > "$REL/SHA256SUMS.txt"
out=$(run mcp); rc=$?
chk "T5 exit nonzero"        "$(yn $rc)" yes
chk "T5 no substring match"  "$(printf '%s' "$out" | grep -c 'no single well-formed entry')" 1
chk "T5 nothing cached"      "$(cached_bins)" 0
cp "$S/orig.sums" "$REL/SHA256SUMS.txt"

echo "--- T6 hostile archives carrying a CORRECT checksum (compromised release) ---"
CORP="$S/corpus"
python3 "$ROOT/scripts/plugin-archive-corpus.py" "$CORP" > /dev/null 2>&1 \
    || { echo "corpus generation failed" >&2; exit 2; }
for m in 01-traversal 03-symlink-out 05-two-entries 06-device 07-hardlink-out 13-nested-dir 17-dir-named-holdfast; do
    rm -rf "$CACHE"
    cp "$CORP/tar/$m.tar.gz" "$REL/holdfast-linux-x86_64.tar.gz"
    ( cd "$REL" && sha256sum holdfast-linux-x86_64.tar.gz > SHA256SUMS.txt )
    out=$(run mcp); rc=$?
    chk "T6 $m refused"      "$(yn $rc)" yes
    chk "T6 $m not cached"   "$(cached_bins)" 0
done
chk "T6 no escape on disk"   "$(find /tmp -maxdepth 1 -name 'HF_PWN_*' 2>/dev/null | grep -c . || true)" 0
cp "$S/orig.tgz" "$REL/holdfast-linux-x86_64.tar.gz"
cp "$S/orig.sums" "$REL/SHA256SUMS.txt"

echo "--- T7 the test hook cannot weaken production ---"
rm -rf "$CACHE"
out=$(env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" /bin/sh "$PLUG/bootstrap" mcp 2>&1); rc=$?
chk "T7 refuses plain http"  "$(printf '%s' "$out" | grep -c 'refusing a non-TLS URL')" 1
chk "T7 exit nonzero"        "$(yn $rc)" yes
chk "T7 nothing cached"      "$(cached_bins)" 0

echo "--- T8 the \$PATH exec is off unless asked for ---"
rm -rf "$CACHE"
mkdir -p "$S/evilpath"
{
    printf '#!/bin/sh\n'
    # shellcheck disable=SC2016
    # Literal: this is the body of the decoy script, not this shell's $1.
    printf '[ "$1" = version ] && { echo "holdfast 0.1.0"; exit 0; }\n'
    printf 'echo HIJACKED\n'
} > "$S/evilpath/holdfast"
chmod 755 "$S/evilpath/holdfast"
out=$(env -i PATH="$S/evilpath:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    /bin/sh "$PLUG/bootstrap" mcp 2>&1)
chk "T8 default ignores \$PATH" "$(printf '%s' "$out" | grep -c HIJACKED)" 0
chk "T8 downloaded instead"     "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY')" 1
rm -rf "$CACHE"
out=$(env -i PATH="$S/evilpath:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 /bin/sh "$PLUG/bootstrap" mcp 2>&1)
chk "T8 opt-in honours \$PATH"  "$(printf '%s' "$out" | grep -c HIJACKED)" 1

echo "--- T9 read-only cache directory ---"
rm -rf "$CACHE"
mkdir -p "$CACHE/bin"
chmod 500 "$CACHE/bin"
out=$(run mcp); rc=$?
chk "T9 exit nonzero"        "$(yn $rc)" yes
chk "T9 actionable message"   "$(printf '%s' "$out" | grep -c 'install holdfast manually\|not writable\|cannot create')" 1
chmod 700 "$CACHE/bin"

echo "--- T10 no room to write the binary ---"
rm -rf "$CACHE"
out=$( (ulimit -f 200; run mcp) 2>&1 ); rc=$?
chk "T10 exit nonzero"       "$(yn $rc)" yes
chk "T10 no half binary"     "$(cached_bins)" 0

echo "--- T11 a version.txt that is not a version ---"
rm -rf "$CACHE"
printf 'main\n' > "$PLUG/version.txt"
out=$(run mcp); rc=$?
chk "T11 exit nonzero"       "$(yn $rc)" yes
chk "T11 names the file"     "$(printf '%s' "$out" | grep -c 'version.txt does not hold a version')" 1
printf '0.1.0\n' > "$PLUG/version.txt"

echo ""
echo "pass=$pass fail=$fail   http requests served=$(reqs)"
[ "$fail" -eq 0 ]
