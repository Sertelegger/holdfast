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
SRV2=""
cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2> /dev/null
    [ -n "$SRV2" ] && kill "$SRV2" 2> /dev/null
    rm -rf "$S"
}
trap cleanup EXIT HUP INT TERM

# --- a plugin tree we may edit (version.txt is bumped per case) ------------
PLUG="$S/plugin"
mkdir -p "$PLUG"
cp "$ROOT/plugin/bootstrap" "$ROOT/plugin/lib-safe-extract.sh" \
    "$ROOT/plugin/bootstrap.ps1" "$ROOT/plugin/lib-safe-extract.ps1" "$PLUG/"
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

# **A second server for the answers the first cannot give.** `http.server`
# serves 200, 404 and a directory's 301, and nothing else -- so the bootstrap's
# "answered HTTP <other>" arm had no row that reached it, and "the LAST status
# of a redirect chain is the answer" had none either. Under `/to404/` every
# path is a 302 to the same path under `/gone/`, which is a 404; under
# `/drop/` the connection is closed with no answer at all; everything else is
# a 503.
PORT2=$((PORT + 1))
python3 - "$PORT2" > "$S/http2.log" 2>&1 <<'EOF' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/to404/"):
            self.send_response(302)
            self.send_header("Location", "/gone/" + self.path[len("/to404/"):])
        elif self.path.startswith("/gone/"):
            self.send_response(404)
        elif self.path.startswith("/drop/"):
            return
        else:
            self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
SRV2=$!
i=0
while [ "$i" -lt 100 ]; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT2/" 2> /dev/null)" = 503 ] && break
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 100 ] || { echo "second fixture server never came up on $PORT2" >&2; exit 2; }
BASE503="http://127.0.0.1:$PORT2"
BASE302="http://127.0.0.1:$PORT2/to404"
BASEDROP="http://127.0.0.1:$PORT2/drop"
CACHE="$S/data"
BIN="$CACHE/bin/holdfast-v0.1.0-linux-x86_64"
SUMS="$CACHE/bin/SHA256SUMS-v0.1.0.txt"

# stdin is /dev/null, and that is load-bearing since GH #237: under `mcp` a
# dying bootstrap reads one JSON-RPC request from stdin to answer it, and an
# inherited stdin would make every row below depend on how the harness was
# launched. T12 is where stdin carries a request, deliberately.
run() { # run <args...>; stdout+stderr combined, never piped by the caller
    env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="${RUN_BASE:-$BASE}" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        /bin/sh "$PLUG/bootstrap" "$@" 2>&1 < /dev/null
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

# **Two rows where there was one, because there are two failures.** T4 used
# to assert that a 404 sent the user to download the assets by hand -- the
# exact dead end GH #237 reported, since a release that 404s has no assets to
# download. A 404 is "not published" and gets the from-source route; only a
# host that reaches no server at all (T4b) gets the air-gapped placement.
echo "--- T4 release not published (404): build it, do not download it ---"
rm -rf "$CACHE"
printf '9.9.9\n' > "$PLUG/version.txt"
out=$(run mcp); rc=$?
chk "T4 exit nonzero"        "$(yn $rc)" yes
chk "T4 says not published"  "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1
chk "T4 names the build"     "$(printf '%s' "$out" | grep -c "cargo install --locked --git https://github.com/Sertelegger/holdfast --tag v9.9.9 holdfast")" 1
chk "T4 names BOOTSTRAP_BIN" "$(printf '%s' "$out" | grep -c 'set HOLDFAST_BOOTSTRAP_BIN to')" 1
chk "T4 no manual placement" "$(printf '%s' "$out" | grep -c 'place the extracted binary')" 0
chk "T4 nothing cached"      "$(cached_bins)" 0

echo "--- T4b no server answers at all: the air-gapped message ---"
rm -rf "$CACHE"
# Port 1 on loopback: nothing listens there, so curl gets a refusal and no
# HTTP status -- which is the discriminator, not the port.
out=$(RUN_BASE=http://127.0.0.1:1 run mcp); rc=$?
chk "T4b exit nonzero"       "$(yn $rc)" yes
chk "T4b says unreachable"   "$(printf '%s' "$out" | grep -c 'cannot reach http://127.0.0.1:1/v9.9.9/SHA256SUMS.txt')" 1
chk "T4b names the tag page" "$(printf '%s' "$out" | grep -c 'github.com/Sertelegger/holdfast/releases/tag/v9.9.9')" 1
chk "T4b places the binary"  "$(printf '%s' "$out" | grep -c 'place the extracted binary at [^ ]*/holdfast-v9.9.9-linux-x86_64 ')" 1
# The half the old message left out: a binary without its manifest is a
# cache miss (step 1), so following the old advice re-downloaded forever.
chk "T4b places the manifest" "$(printf '%s' "$out" | grep -c 'beside it as [^ ]*/SHA256SUMS-v9.9.9.txt')" 1
chk "T4b names BOOTSTRAP_BIN" "$(printf '%s' "$out" | grep -c 'set HOLDFAST_BOOTSTRAP_BIN to')" 1

# The third arm: a server answered, and not with 404. It is neither "not
# published" nor "cannot reach", and says neither.
echo "--- T4c a server that answers something else, and a 404 at the end of a redirect ---"
rm -rf "$CACHE"
out=$(RUN_BASE=$BASE503 run mcp); rc=$?
chk "T4c 503 exit nonzero"       "$(yn $rc)" yes
chk "T4c 503 is said as such"    "$(printf '%s' "$out" | grep -c 'SHA256SUMS.txt answered HTTP 503 -- retry later, or build it')" 1
chk "T4c 503 is not 'not published'" "$(printf '%s' "$out" | grep -c 'binary to download')" 0
chk "T4c 503 is not 'cannot reach'"  "$(printf '%s' "$out" | grep -c 'cannot reach')" 0
# A release asset is a redirect on GitHub; the answer is the last hop's.
out=$(RUN_BASE=$BASE302 run mcp)
chk "T4c 302 then 404: not published" "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1
out=$(RUN_BASE=$BASEDROP run mcp)
chk "T4c no answer: cannot reach" "$(printf '%s' "$out" | grep -c 'cannot reach http://127.0.0.1:[0-9]*/drop/v9.9.9/SHA256SUMS.txt')" 1
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
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null); rc=$?
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
    /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
chk "T8 default ignores \$PATH" "$(printf '%s' "$out" | grep -c HIJACKED)" 0
chk "T8 downloaded instead"     "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY')" 1
rm -rf "$CACHE"
out=$(env -i PATH="$S/evilpath:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
chk "T8 opt-in honours \$PATH"  "$(printf '%s' "$out" | grep -c HIJACKED)" 1
# **The version is compared whole.** The old test was `grep -q 0.1.0` over
# the version line: a regex, unanchored, which `holdfast 0.1.00` satisfies.
mkdir -p "$S/nearpath"
{
    printf '#!/bin/sh\n'
    # shellcheck disable=SC2016
    printf '[ "$1" = version ] && { echo "holdfast 0.1.00 (build x) protocol 1.4"; exit 0; }\n'
    printf 'echo NEAR-MISS-EXECED\n'
} > "$S/nearpath/holdfast"
chmod 755 "$S/nearpath/holdfast"
rm -rf "$CACHE"
out=$(env -i PATH="$S/nearpath:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
chk "T8 0.1.00 is not 0.1.0"      "$(printf '%s' "$out" | grep -c NEAR-MISS-EXECED)" 0
chk "T8 ...and it downloaded"     "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY')" 1
# **And a refusal is said.** It used to fall back in silence.
chk "T8 the refusal is said"      "$(printf '%s' "$out" | grep -c "reports 'holdfast 0.1.00 (build x) protocol 1.4', not holdfast 0.1.0; falling back")" 1
# The same reason rides on a later failure's message, because that message
# is the one line Claude Code shows (T12).
rm -rf "$CACHE"
printf '9.9.9\n' > "$PLUG/version.txt"
out=$(env -i PATH="$S/nearpath:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
chk "T8 the 404 carries the why"  "$(printf '%s' "$out" | grep -c "binary to download.*(HOLDFAST_BOOTSTRAP_ALLOW_PATH is set but .*reports 'holdfast 0.1.00")" 1
printf '0.1.0\n' > "$PLUG/version.txt"
# And with no holdfast on $PATH at all. A PATH built from exactly the tools
# the bootstrap uses, because the host's own PATH may well hold a holdfast --
# the owner's does, once they have followed the README.
mkdir -p "$S/minpath"
for t in tr sed uname curl mkdir mktemp chmod rm cut sha256sum tar gzip head ls wc mv dirname sleep; do
    tp=$(command -v "$t") || { echo "the minimal PATH needs $t" >&2; exit 2; }
    ln -sf "$tp" "$S/minpath/$t"
done
rm -rf "$CACHE"
out=$(env -i PATH="$S/minpath" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
# shellcheck disable=SC2016
# Literal: the message names the variable, it does not expand it.
chk "T8 no PATH holdfast is said" "$(printf '%s' "$out" | grep -c 'ALLOW_PATH is set but there is no holdfast on \$PATH; falling back')" 1
chk "T8 ...and it downloaded"     "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY')" 1

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

# --- helpers for the rows that read stdout on its own ---------------------
# jfield <file> <python expression over `j`>: one JSON line, parsed. python3
# rather than a grep, because "the reply is well-formed JSON-RPC that Claude
# Code will accept" is the claim, and a grep for a substring would pass a
# reply with an unescaped quote in it.
jfield() {
    python3 -c 'import json,sys
lines=open(sys.argv[1]).read().splitlines()
if len(lines)!=1: print("LINES=%d" % len(lines)); sys.exit(0)
j=json.loads(lines[0])
print(eval(sys.argv[2]))' "$1" "$2" 2>&1
}
INIT='{"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"claude-code","version":"2.1.280"}},"jsonrpc":"2.0","id":0}'

echo "--- T12 a failure under mcp answers initialize, so Claude Code shows it ---"
# Measured with Claude Code 2.1.280: a server that exits before answering
# shows as `CONNECTION_CLOSED`; one that answers `initialize` with a
# JSON-RPC error shows as `-32603: <message>`. The request is Claude Code's
# own first line, verbatim apart from trimmed clientInfo.
rm -rf "$CACHE"
printf '9.9.9\n' > "$PLUG/version.txt"
printf '%s\n' "$INIT" | env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    /bin/sh "$PLUG/bootstrap" mcp > "$S/t12.out" 2> "$S/t12.err"; rc=$?
chk "T12 exit nonzero"           "$(yn $rc)" yes
chk "T12 one JSON-RPC line"      "$(jfield "$S/t12.out" 'j["jsonrpc"]')" 2.0
chk "T12 answers id 0"           "$(jfield "$S/t12.out" 'repr(j["id"])')" 0
chk "T12 is an error"            "$(jfield "$S/t12.out" 'j["error"]["code"]')" -32603
chk "T12 no result member"       "$(jfield "$S/t12.out" '"result" in j')" False
# The message IS the stderr diagnosis -- the whole line, not a paraphrase.
chk "T12 message == stderr line" "$(jfield "$S/t12.out" 'j["error"]["message"] == open(sys.argv[1][:-4]+".err").read().splitlines()[-1]')" True
chk "T12 message says why"       "$(jfield "$S/t12.out" '"no holdfast v9.9.9 binary to download" in j["error"]["message"]')" True
# `claude mcp list` prints `-32603: ` and then cuts the line at 500
# characters with an ellipsis (measured, 2.1.280). This is the message every
# install sees until a release is promoted, so all of it -- the link at the
# end included -- has to be inside what is shown.
chk "T12 fits the 500 shown"     "$(jfield "$S/t12.out" 'len("-32603: " + j["error"]["message"]) <= 500')" True
# A string id comes back as the same string.
printf '%s\n' '{"jsonrpc":"2.0","id":"req-7","method":"initialize","params":{}}' \
    | env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        /bin/sh "$PLUG/bootstrap" mcp > "$S/t12s.out" 2> /dev/null
chk "T12 string id echoed"       "$(jfield "$S/t12s.out" 'repr(j["id"])')" "'req-7'"
# **A stdin that never speaks must not hang the failure.** Claude Code
# writes `initialize` at once, but not every caller that passes `mcp` is
# Claude Code -- this harness hung on its own inherited stdin while it was
# being written. A watchdog bounds the wait; the diagnosis is on stderr
# before it starts, so nothing is lost when it fires.
# A FIFO whose only writer sleeps, rather than `sleep 30 |`: a pipeline
# lasts as long as its slowest member, so that would time the sleep.
mkfifo "$S/quiet"
sleep 60 > "$S/quiet" &
quiet=$!
t0=$(date +%s)
env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    /bin/sh "$PLUG/bootstrap" mcp < "$S/quiet" > "$S/t12q.out" 2> "$S/t12q.err"
t1=$(date +%s)
kill "$quiet" 2> /dev/null
chk "T12 silent stdin: bounded"  "$([ $((t1 - t0)) -lt 20 ] && echo yes || echo "no, $((t1 - t0))s")" yes
chk "T12 silent stdin: said why" "$(grep -c 'no holdfast v9.9.9 binary to download' "$S/t12q.err")" 1
chk "T12 silent stdin: no reply" "$(wc -c < "$S/t12q.out" | tr -d ' ')" 0
chk "T12 silent stdin: no temp dir" "$(count_matching "$CACHE/bin" '.dl.*')" 0
# **And under bash**, which is /bin/sh on macOS and which, unlike dash,
# resumes a `read` after running a trap -- so a watchdog signal the download
# phase traps (it was TERM) bounded the wait everywhere but there.
if command -v bash > /dev/null 2>&1; then
    rm -rf "$CACHE"
    sleep 60 > "$S/quiet" &
    quiet=$!
    t0=$(date +%s)
    env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        bash "$PLUG/bootstrap" mcp < "$S/quiet" > /dev/null 2> "$S/t12b.err"
    t1=$(date +%s)
    kill "$quiet" 2> /dev/null
    chk "T12 silent stdin, bash: bounded" "$([ $((t1 - t0)) -lt 20 ] && echo yes || echo "no, $((t1 - t0))s")" yes
    chk "T12 silent stdin, bash: said why" "$(grep -c 'no holdfast v9.9.9 binary to download' "$S/t12b.err")" 1
else
    echo "  skip  T12 silent stdin under bash -- no bash on this host"
fi
# Only under `mcp`: `bootstrap version` run by a person must not print JSON.
printf '%s\n' "$INIT" | env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
    /bin/sh "$PLUG/bootstrap" version > "$S/t12v.out" 2> /dev/null
chk "T12 not under 'version'"    "$(wc -c < "$S/t12v.out" | tr -d ' ')" 0
# Escaping. A relative HOLDFAST_BOOTSTRAP_BIN carrying a quote, a backslash
# and a tab is echoed into the message, so the reply must survive it.
printf '%s\n' "$INIT" | env -i PATH="$PATH" HOME="$S/fakehome" \
    HOLDFAST_BOOTSTRAP_BIN="$(printf 'q"b\\s\tt')" \
    /bin/sh "$PLUG/bootstrap" mcp > "$S/t12e.out" 2> /dev/null
# `q"b\s t` after JSON decoding: the tab became a space, the rest is intact.
chk "T12 quote+backslash survive" "$(jfield "$S/t12e.out" 'chr(113)+chr(34)+chr(98)+chr(92)+chr(115)+chr(32)+chr(116) in j["error"]["message"]')" True
printf '0.1.0\n' > "$PLUG/version.txt"

echo "--- T13 HOLDFAST_BOOTSTRAP_BIN: exactly that binary, or a refusal ---"
# A binary that proves what it was handed: its argv, and the request line on
# its stdin -- the success path must not consume the request T12's failure
# path reads.
mkdir -p "$S/own"
{
    printf '#!/bin/sh\n'
    printf 'IFS= read -r l\n'
    # shellcheck disable=SC2016
    printf 'echo "OWN-BINARY argv=[$*] stdin=[$l]"\n'
} > "$S/own/holdfast"
chmod 755 "$S/own/holdfast"
own() { # own <BIN value> <args...>; stdin from /dev/null unless piped
    _b=$1; shift
    env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        HOLDFAST_BOOTSTRAP_BIN="$_b" /bin/sh "$PLUG/bootstrap" "$@" 2>&1
}
rm -rf "$CACHE"
n0=$(reqs)
out=$(printf '%s\n' '{"id":0}' | own "$S/own/holdfast" mcp --flag); rc=$?
chk "T13 exit 0"                 "$rc" 0
chk "T13 argv forwarded"         "$(printf '%s' "$out" | grep -c 'OWN-BINARY argv=\[mcp --flag\]')" 1
chk "T13 stdin untouched"        "$(printf '%s' "$out" | grep -c 'stdin=\[{"id":0}\]')" 1
chk "T13 no request made"        "$(( $(reqs) - n0 ))" 0
chk "T13 no cache created"       "$([ -e "$CACHE" ] && echo yes || echo no)" no
# Relative: refused, and nothing downloaded in its place.
out=$( (cd "$S/own" && own holdfast mcp < /dev/null) ); rc=$?
chk "T13 relative refused"       "$(printf '%s' "$out" | grep -c 'must be an absolute path')" 1
chk "T13 relative did not run"   "$(printf '%s' "$out" | grep -c OWN-BINARY)" 0
chk "T13 relative exit nonzero"  "$(yn $rc)" yes
# A tilde is the likeliest relative path of all, because Claude Code's
# settings.json does not expand it. The refusal names that, and the fix.
# shellcheck disable=SC2088
# Literal on purpose: an unexpanded tilde is the case under test.
out=$(own '~/.cargo/bin/holdfast' mcp < /dev/null)
chk "T13 tilde named as such"    "$(printf '%s' "$out" | grep -c "nothing expands ~ .*such as $S/fakehome/.cargo/bin/holdfast")" 1
# Missing, a directory, not executable: each refused, none downloads.
chmod 644 "$S/own/holdfast"
for bad in "$S/own/absent" "$S/own" "$S/own/holdfast"; do
    out=$(own "$bad" mcp < /dev/null); rc=$?
    chk "T13 refused: ${bad#"$S"/}" "$(printf '%s' "$out" | grep -c 'which is not an executable file -- nothing was downloaded')" 1
    chk "T13 exit nonzero: ${bad#"$S"/}" "$(yn $rc)" yes
done
chk "T13 still no request"       "$(( $(reqs) - n0 ))" 0
chmod 755 "$S/own/holdfast"
# It wins over HOLDFAST_BOOTSTRAP_ALLOW_PATH: the stricter spelling.
out=$(printf '\n' | env -i PATH="$S/evilpath:$PATH" HOME="$S/fakehome" \
    HOLDFAST_BOOTSTRAP_ALLOW_PATH=1 HOLDFAST_BOOTSTRAP_BIN="$S/own/holdfast" \
    /bin/sh "$PLUG/bootstrap" mcp 2>&1)
chk "T13 beats ALLOW_PATH"       "$(printf '%s' "$out" | grep -c 'OWN-BINARY')" 1
chk "T13 decoy not run"          "$(printf '%s' "$out" | grep -c HIJACKED)" 0
# It needs nothing the download needs. A platform with no prebuilt -- a fake
# `uname` saying FreeBSD -- and a version.txt that is not a version.
mkdir -p "$S/bsd"
# shellcheck disable=SC2016
# Literal: the body of the fake `uname`, not this shell's $1.
printf '#!/bin/sh\ncase "$1" in -s) echo FreeBSD ;; *) echo amd64 ;; esac\n' > "$S/bsd/uname"
chmod 755 "$S/bsd/uname"
out=$(env -i PATH="$S/bsd:$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
    /bin/sh "$PLUG/bootstrap" mcp 2>&1 < /dev/null)
# The control first: without the variable, the fake uname does bite.
chk "T13 control: FreeBSD dies"  "$(printf '%s' "$out" | grep -c "no prebuilt binary for 'FreeBSD'.*HOLDFAST_BOOTSTRAP_BIN")" 1
out=$(printf '\n' | env -i PATH="$S/bsd:$PATH" HOME="$S/fakehome" \
    HOLDFAST_BOOTSTRAP_BIN="$S/own/holdfast" /bin/sh "$PLUG/bootstrap" mcp 2>&1)
chk "T13 runs on FreeBSD"        "$(printf '%s' "$out" | grep -c OWN-BINARY)" 1
printf 'main\n' > "$PLUG/version.txt"
out=$(printf '\n' | own "$S/own/holdfast" mcp)
chk "T13 runs past version.txt"  "$(printf '%s' "$out" | grep -c OWN-BINARY)" 1
printf '0.1.0\n' > "$PLUG/version.txt"

echo "--- T14 bootstrap.ps1, the Windows half, under pwsh ---"
# pwsh on Linux runs the same script Windows would, minus bootstrap.cmd. It
# covers the HOLDFAST_BOOTSTRAP_BIN arm and the 404 / unreachable split,
# which is all of GH #237's change to that file; nothing else executes
# bootstrap.ps1 anywhere. CI's `plugin` job asserts pwsh exists, so there a
# missing one is a failure rather than a skip.
PWSH=${HOLDFAST_PWSH:-$(command -v pwsh 2> /dev/null || true)}
skipped=0
if [ -z "$PWSH" ]; then
    if [ -n "${CI:-}" ]; then
        chk "T14 pwsh is available in CI" no yes
    else
        skipped=1
        echo "  skip  T14 -- no pwsh (set HOLDFAST_PWSH to one); bootstrap.ps1 was NOT exercised"
    fi
else
    ps() { # ps <extra env...> -- <args...>
        _e=
        while [ "$1" != -- ]; do _e="$_e $1"; shift; done
        shift
        # shellcheck disable=SC2086
        env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
            PROCESSOR_ARCHITECTURE=AMD64 HOLDFAST_BOOTSTRAP_INSECURE=1 $_e \
            "$PWSH" -NoProfile -NonInteractive -File "$PLUG/bootstrap.ps1" "$@" 2>&1 < /dev/null
    }
    out=$(ps HOLDFAST_BOOTSTRAP_BIN="$S/own/holdfast" -- mcp --flag); rc=$?
    chk "T14 BIN exit 0"             "$rc" 0
    chk "T14 BIN argv forwarded"     "$(printf '%s' "$out" | grep -c 'OWN-BINARY argv=\[mcp --flag\]')" 1
    out=$(ps HOLDFAST_BOOTSTRAP_BIN=holdfast -- mcp); rc=$?
    chk "T14 relative refused"       "$(printf '%s' "$out" | grep -c 'must be an absolute path')" 1
    chk "T14 relative exit nonzero"  "$(yn $rc)" yes
    out=$(ps HOLDFAST_BOOTSTRAP_BIN="$S/own/absent" -- mcp)
    chk "T14 missing refused"        "$(printf '%s' "$out" | grep -c 'which is not a file -- nothing was downloaded')" 1
    rm -rf "$CACHE"
    printf '9.9.9\n' > "$PLUG/version.txt"
    out=$(ps HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp); rc=$?
    chk "T14 404 exit nonzero"       "$(yn $rc)" yes
    chk "T14 404 says not published" "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1
    chk "T14 404 names the build"    "$(printf '%s' "$out" | grep -c 'set HOLDFAST_BOOTSTRAP_BIN to')" 1
    chk "T14 404 no manual placement" "$(printf '%s' "$out" | grep -c 'place the extracted binary')" 0
    out=$(ps HOLDFAST_BOOTSTRAP_BASE_URL=http://127.0.0.1:1 -- mcp)
    chk "T14 unreachable says so"    "$(printf '%s' "$out" | grep -c 'cannot reach http://127.0.0.1:1/v9.9.9/SHA256SUMS.txt')" 1
    chk "T14 unreachable places both" "$(printf '%s' "$out" | grep -c 'holdfast-v9.9.9-windows-x86_64.exe with SHA256SUMS.txt beside it as [^ ]*SHA256SUMS-v9.9.9.txt')" 1
    out=$(ps HOLDFAST_BOOTSTRAP_BASE_URL="$BASE503" -- mcp)
    chk "T14 503 is said as such"    "$(printf '%s' "$out" | grep -c 'SHA256SUMS.txt answered HTTP 503 -- retry later, or build it')" 1
    out=$(ps HOLDFAST_BOOTSTRAP_BASE_URL="$BASE302" -- mcp)
    chk "T14 302 then 404: not published" "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1

    # **The initialize answer, as T12 checks it for `bootstrap`.** It is what
    # makes CHANGELOG's "says why in Claude Code" true of this file at all;
    # before, it said so of the Unix half only and read as both.
    psio() { # psio <extra env...> -- <args...>; stdio is the caller's
        _e=
        while [ "$1" != -- ]; do _e="$_e $1"; shift; done
        shift
        # shellcheck disable=SC2086
        env -i PATH="$PATH" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
            PROCESSOR_ARCHITECTURE=AMD64 HOLDFAST_BOOTSTRAP_INSECURE=1 $_e \
            "$PWSH" -NoProfile -NonInteractive -File "$PLUG/bootstrap.ps1" "$@"
    }
    printf '%s\n' "$INIT" | psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp \
        > "$S/t14.out" 2> "$S/t14.err"; rc=$?
    chk "T14 init: exit nonzero"     "$(yn $rc)" yes
    chk "T14 init: one JSON-RPC line" "$(jfield "$S/t14.out" 'j["jsonrpc"]')" 2.0
    chk "T14 init: answers id 0"     "$(jfield "$S/t14.out" 'repr(j["id"])')" 0
    chk "T14 init: is an error"      "$(jfield "$S/t14.out" 'j["error"]["code"]')" -32603
    chk "T14 init: message == stderr line" "$(jfield "$S/t14.out" 'j["error"]["message"] == open(sys.argv[1][:-4]+".err").read().splitlines()[-1]')" True
    chk "T14 init: message says why" "$(jfield "$S/t14.out" '"no holdfast v9.9.9 binary to download" in j["error"]["message"]')" True
    printf '%s\n' '{"jsonrpc":"2.0","id":"req-7","method":"initialize","params":{}}' \
        | psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp > "$S/t14s.out" 2> /dev/null
    chk "T14 init: string id echoed" "$(jfield "$S/t14s.out" 'repr(j["id"])')" "'req-7'"
    printf '%s\n' 'not json' \
        | psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp > "$S/t14n.out" 2> /dev/null
    chk "T14 init: unreadable id is null" "$(jfield "$S/t14n.out" 'repr(j["id"])')" None
    printf '%s\n' "$INIT" | psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- version \
        > "$S/t14v.out" 2> /dev/null
    chk "T14 init: not under 'version'" "$(wc -c < "$S/t14v.out" | tr -d ' ')" 0
    psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp < /dev/null > "$S/t14z.out" 2> /dev/null
    chk "T14 init: no request, no reply" "$(wc -c < "$S/t14z.out" | tr -d ' ')" 0
    # Quote, backslash, tab and a non-ASCII letter, echoed from a relative
    # HOLDFAST_BOOTSTRAP_BIN into the message: the reply must parse, and say
    # `q"b\s té` -- the tab a space, the rest intact.
    # Not through psio, which word-splits its env arguments -- on the tab.
    printf '%s\n' "$INIT" | env -i PATH="$PATH" HOME="$S/fakehome" \
        HOLDFAST_BOOTSTRAP_BIN="$(printf 'q"b\\s\tt\303\251')" \
        "$PWSH" -NoProfile -NonInteractive -File "$PLUG/bootstrap.ps1" mcp \
        > "$S/t14e.out" 2> /dev/null
    chk "T14 init: escaping survives" "$(jfield "$S/t14e.out" '"q\"b\\s té" in j["error"]["message"]')" True
    chk "T14 init: reply is ASCII"   "$(LC_ALL=C grep -c '[^ -~]' "$S/t14e.out")" 0
    sleep 60 > "$S/quiet" &
    quiet=$!
    t0=$(date +%s)
    psio HOLDFAST_BOOTSTRAP_BASE_URL="$BASE" -- mcp < "$S/quiet" > "$S/t14q.out" 2> "$S/t14q.err"
    t1=$(date +%s)
    kill "$quiet" 2> /dev/null
    chk "T14 init: silent stdin bounded" "$([ $((t1 - t0)) -lt 20 ] && echo yes || echo "no, $((t1 - t0))s")" yes
    chk "T14 init: silent stdin said why" "$(grep -c 'no holdfast v9.9.9 binary to download' "$S/t14q.err")" 1
    chk "T14 init: silent stdin no reply" "$(wc -c < "$S/t14q.out" | tr -d ' ')" 0
    printf '0.1.0\n' > "$PLUG/version.txt"
fi

echo "--- T15 wget as the only fetcher: the same answers as curl ---"
# Every row above runs curl, which the bootstrap prefers. A host without it
# -- a slim container, Alpine -- falls back to wget, and the two wgets there
# report a failure differently from curl and from each other: busybox
# exits 1 for a 404 and for a refused connection alike, GNU wget exits 8 for
# a 404 and a 503 alike. Before GH #237's review this path read only the
# exit status, and a 404 under busybox got the "cannot reach" advice -- the
# dead end the issue is about. Each wget runs here on a $PATH that has it
# and no curl, the real binary under the name `wget`, as Alpine installs it.
wget_path() { # wget_path <dir> <binary to call wget>
    mkdir -p "$1"
    # `sleep` because the initialize watchdog needs it: without it the ALRM
    # comes at once, and races the read it is meant to bound.
    for t in tr sed uname mkdir mktemp chmod rm cut sha256sum tar gzip head ls wc mv dirname sleep; do
        ln -sf "$(command -v "$t")" "$1/$t"
    done
    ln -sf "$2" "$1/wget"
}
wrun() { # wrun <PATH> <base url> <args...>
    _p=$1; _b=$2; shift 2
    env -i PATH="$_p" HOME="$S/fakehome" CLAUDE_PLUGIN_DATA="$CACHE" \
        HOLDFAST_BOOTSTRAP_BASE_URL="$_b" HOLDFAST_BOOTSTRAP_INSECURE=1 \
        /bin/sh "$PLUG/bootstrap" "$@" 2>&1 < /dev/null
}
FLAVOURS=
gnu_wget=$(command -v wget 2> /dev/null || true)
if [ -n "$gnu_wget" ] && "$gnu_wget" --version 2> /dev/null | head -n 1 | grep -q '^GNU Wget'; then
    wget_path "$S/wget-gnu" "$gnu_wget"
    FLAVOURS="$FLAVOURS gnu"
elif [ -n "${CI:-}" ]; then
    chk "T15 GNU wget is available in CI" no yes
else
    skipped=$((skipped + 1))
    echo "  skip  T15 GNU wget -- none on this host; that wget path was NOT exercised"
fi
bb=$(command -v busybox 2> /dev/null || true)
if [ -n "$bb" ] && "$bb" --list 2> /dev/null | grep -qx wget; then
    wget_path "$S/wget-busybox" "$bb"
    FLAVOURS="$FLAVOURS busybox"
elif [ -n "${CI:-}" ]; then
    chk "T15 busybox is available in CI" no yes
else
    skipped=$((skipped + 1))
    echo "  skip  T15 busybox wget -- no busybox on this host; that wget path was NOT exercised"
fi
for f in $FLAVOURS; do
    P="$S/wget-$f"
    rm -rf "$CACHE"
    out=$(wrun "$P" "$BASE" mcp --flag); rc=$?
    chk "T15 $f: downloads and runs"  "$(printf '%s' "$out" | grep -c 'HOLDFAST-FAKE-BINARY argv=\[mcp --flag\]')" 1
    chk "T15 $f: binary cached"       "$([ -x "$BIN" ] && echo yes || echo no)" yes
    chk "T15 $f: exit 0"              "$rc" 0
    printf '9.9.9\n' > "$PLUG/version.txt"
    rm -rf "$CACHE"
    out=$(wrun "$P" "$BASE" mcp)
    chk "T15 $f: 404 is not published" "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1
    chk "T15 $f: 404 is not 'cannot reach'" "$(printf '%s' "$out" | grep -c 'cannot reach')" 0
    # wget's own words pass through to stderr as curl's do; the header lines
    # `-S` adds do not.
    chk "T15 $f: no header lines"     "$(printf '%s\n' "$out" | grep -c '^ *HTTP/')" 0
    out=$(wrun "$P" "$BASE302" mcp)
    chk "T15 $f: 302 then 404 is not published" "$(printf '%s' "$out" | grep -c 'no holdfast v9.9.9 binary to download.*answered 404')" 1
    out=$(wrun "$P" "$BASE503" mcp)
    chk "T15 $f: 503 is said as such" "$(printf '%s' "$out" | grep -c 'SHA256SUMS.txt answered HTTP 503 -- retry later, or build it')" 1
    # A connection closed with no answer: GNU wget's default is to retry
    # that twenty times with a growing wait, minutes in all.
    t0=$(date +%s)
    out=$(wrun "$P" "$BASEDROP" mcp)
    t1=$(date +%s)
    chk "T15 $f: no answer is 'cannot reach'" "$(printf '%s' "$out" | grep -c 'cannot reach http://127.0.0.1:[0-9]*/drop/v9.9.9/SHA256SUMS.txt')" 1
    chk "T15 $f: no answer is not retried" "$([ $((t1 - t0)) -lt 20 ] && echo yes || echo "no, $((t1 - t0))s")" yes
    out=$(wrun "$P" http://127.0.0.1:1 mcp)
    chk "T15 $f: unreachable says so" "$(printf '%s' "$out" | grep -c 'cannot reach http://127.0.0.1:1/v9.9.9/SHA256SUMS.txt')" 1
    printf '0.1.0\n' > "$PLUG/version.txt"
done
# **A wget that says it did not check the certificate is refused.** busybox
# with no `openssl` on $PATH -- as here -- uses its own TLS, which validates
# nothing and says so before the handshake. An https URL at the plain-HTTP
# fixture is enough to make it say so; nothing it fetches may be used.
case "$FLAVOURS" in
    *busybox*)
        # The control first: that this busybox says so at all. One built to
        # hand TLS to a validating helper -- Alpine's is -- does not, and
        # there the row has nothing to test.
        said=$(env -i PATH="$S/wget-busybox" "$S/wget-busybox/wget" -q -O /dev/null "https://127.0.0.1:$PORT/" 2>&1 < /dev/null \
            | grep -c 'certificate validation not implemented')
        if [ "$said" -ge 1 ]; then
            rm -rf "$CACHE"
            out=$(wrun "$S/wget-busybox" "https://127.0.0.1:$PORT" mcp); rc=$?
            chk "T15 busybox TLS: refused"    "$(printf '%s' "$out" | grep -c 'does not verify TLS certificates')" 1
            # The whole line inside the 500 characters `claude mcp list`
            # shows after `-32603: ` (T12), build route and link included.
            chk "T15 busybox TLS: fits the 500 shown" "$(printf '%s\n' "$out" | grep 'does not verify TLS' | awk '{ print (length("-32603: " $0) <= 500) ? "yes" : "no, " length("-32603: " $0) }')" yes
            chk "T15 busybox TLS: exit nonzero" "$(yn $rc)" yes
            chk "T15 busybox TLS: nothing cached" "$(cached_bins)" 0
            chk "T15 busybox TLS: no temp dir" "$(count_matching "$CACHE/bin" '.dl.*')" 0
        else
            echo "  skip  T15 busybox TLS -- this busybox does not say it skips validation, so there is nothing to refuse"
        fi
        ;;
esac

echo ""
echo "pass=$pass fail=$fail skipped-sections=$skipped   http requests served=$(reqs)"
[ "$fail" -eq 0 ]
