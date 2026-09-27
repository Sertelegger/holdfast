#!/usr/bin/env bash
# Single-quoted `$(...)` and backticks throughout are literal on purpose:
# shell text for a session to run, and Python expressions over a response.
# shellcheck disable=SC2016
# The upgrade window between two releases, driven with real builds of both:
# an old daemon under new clients, and a new daemon under an old shim.
#
#   scripts/upgrade-skew-check.sh [--old-tag v0.0.7] [--new <holdfast>] [--workdir <dir>]
#
# Run by hand before a release, not by CI: it builds a whole second tree
# (minutes, and a target directory of its own), and what it measures is the
# pair a user has on the day they upgrade, which CI cannot hold still.
#
# What it checks, and why each is here: until 0.0.8 a client read only the
# daemon's protocol MAJOR, so across the 0.0.7 (protocol 1.1) -> 0.0.8
# (protocol 1.5) boundary a new shim's `start_session` ran in the old
# daemon's directory and environment, a new `holdfast logs --tail` printed a
# still-arriving token in the clear, and a misspelt argument was served --
# all without a word. Every row below is one of those, now refused or read
# safely, plus the controls that prove the probe would have caught it.
#
# Everything runs isolated: HOME, the XDG directories and
# HOLDFAST_RUNTIME_DIR point under the work directory, every daemon started
# here is stopped here, and the old tree's worktree and target directory
# are removed on exit. Fake secrets only.
set -uo pipefail

old_tag=v0.0.7
new_bin=
workdir=
while [ $# -gt 0 ]; do
  case "$1" in
    --old-tag) old_tag="$2"; shift 2 ;;
    --new) new_bin="$2"; shift 2 ;;
    --workdir) workdir="$2"; shift 2 ;;
    -h|--help) sed -n '/^# The upgrade window/,/Fake secrets only/p' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
done

repo="$(git rev-parse --show-toplevel)" || exit 2
own_workdir=0
if [ -z "$workdir" ]; then
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/holdfast-skew.XXXXXX")" || exit 2
  own_workdir=1
fi
mkdir -p "$workdir"
workdir="$(cd "$workdir" && pwd)"
old_tree="$workdir/old-tree"
old_target="$workdir/old-target"
iso="$workdir/iso"
# Every daemon this run starts lives here, and only here. Spelt out on
# each command that stops one rather than inherited, because the builds
# below run with the caller's own HOME (cargo's registry is under it) and
# an exit during them -- a mistyped tag, a failed build, Ctrl-C -- runs
# `cleanup` with that environment still in force.
iso_env=(HOME="$iso/home" XDG_CONFIG_HOME="$iso/cfg" XDG_DATA_HOME="$iso/data"
  XDG_STATE_HOME="$iso/state" XDG_RUNTIME_DIR="$iso/run" HOLDFAST_RUNTIME_DIR="$iso/hf")
isolated=0

cleanup() {
  # Stop whatever this run started, with both binaries: either may be the
  # one a daemon was started from. Only once isolated, since no daemon is
  # started before, and never under the caller's environment: a `daemon
  # stop --force` there ends the caller's real daemon and every session
  # in it.
  if [ "$isolated" = 1 ]; then
    for b in "${new_bin:-}" "${old_bin:-}"; do
      [ -n "$b" ] && [ -x "$b" ] && env "${iso_env[@]}" "$b" daemon stop --force >/dev/null 2>&1
    done
  fi
  git -C "$repo" worktree remove --force "$old_tree" >/dev/null 2>&1
  rm -rf -- "$old_target"
  if [ "$own_workdir" = 1 ]; then
    rm -rf -- "$workdir"
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------ the two builds
if [ -z "$new_bin" ]; then
  echo "== building this tree"
  (cd "$repo" && cargo build --locked --bin holdfast) || exit 2
  target="$(cd "$repo" && cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')" || exit 2
  new_bin="$target/debug/holdfast"
fi
# Absolute, because every client below runs from a directory of its own.
new_bin="$(cd "$(dirname "$new_bin")" && pwd)/$(basename "$new_bin")"
[ -x "$new_bin" ] || { printf 'not an executable: %s\n' "$new_bin" >&2; exit 2; }
echo "== building $old_tag in a detached worktree under $workdir"
git -C "$repo" worktree add --detach "$old_tree" "$old_tag" >/dev/null || exit 2
CARGO_TARGET_DIR="$old_target" cargo build --locked --bin holdfast \
  --manifest-path "$old_tree/Cargo.toml" || exit 2
old_bin="$old_target/debug/holdfast"

# ------------------------------------------------------------- isolation
mkdir -p "$iso"/{home,cfg,data,state,run,hf,daemon-cwd,client-cwd}
chmod 700 "$iso/run" "$iso/hf"
export "${iso_env[@]}"
isolated=1
unset HF_PROBE
daemon_cwd="$iso/daemon-cwd"
client_cwd="$iso/client-cwd"

echo "== old: $("$old_bin" version)"
echo "== new: $("$new_bin" version)"

# ------------------------------------------------ a minimal MCP stdio driver
# usage: mcp.py <binary> <cwd> <calls-json>. Runs `<binary> mcp` in <cwd>,
# initialises, sends each [method, params] in turn and prints the answers
# as one JSON array. The string "$SID" in params is the session id the last
# `start_session` returned. Every wait is bounded.
cat > "$workdir/mcp.py" <<'PY'
import json, os, select, subprocess, sys, time
binary, cwd, calls = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
p = subprocess.Popen([binary, "mcp"], cwd=cwd, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
buf, nid, sid = b"", 0, None
def send(o):
    p.stdin.write((json.dumps(o) + "\n").encode()); p.stdin.flush()
def recv(i, timeout=30):
    global buf
    end = time.time() + timeout
    while time.time() < end:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                m = json.loads(line)
                if m.get("id") == i:
                    return m
        r, _, _ = select.select([p.stdout], [], [], 0.2)
        if r:
            c = os.read(p.stdout.fileno(), 65536)
            if not c:
                break
            buf += c
    return {"timeout": i}
def call(method, params):
    global nid
    nid += 1
    send({"jsonrpc": "2.0", "id": nid, "method": method, "params": params})
    return recv(nid)
call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "upgrade-skew-check", "version": "0"}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
out = []
for method, params in calls:
    if method == "sleep":
        time.sleep(params); continue
    params = json.loads(json.dumps(params).replace("$SID", sid or "none"))
    r = call(method, params)
    sc = (r.get("result") or {}).get("structuredContent") or {}
    if (sc.get("data") or {}).get("session_id"):
        sid = sc["data"]["session_id"]
    out.append(r)
p.stdin.close()
try:
    p.wait(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
print(json.dumps(out))
PY

mcp() { (cd "$2" && python3 "$workdir/mcp.py" "$1" "$2" "$3"); }
# `[method, params]` for a start_session running `sh -c <script>`, quoted
# by a JSON encoder rather than by hand.
start_call() {
  python3 -c 'import json, sys; print(json.dumps(["tools/call", {"name": "start_session",
    "arguments": {"command": "/bin/sh", "args": ["-c", sys.argv[1]]}}]))' "$1"
}
# jq-free field reads, so the script needs only python3 besides the builds.
# The expression evaluated is always one written in this file, never data:
# the JSON it reads arrives as `d`, a parsed value.
field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d, "json": json}))' "$1"; }

failures=0
check() { # check <label> <python-truthy-expression over d> <json>
  if printf '%s' "$3" | field "bool($2)" | grep -qx True; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s\n        %s\n' "$1" "$(printf '%s' "$3" | head -c 1500)"
    failures=$((failures + 1))
  fi
}
check_cmd() { # check_cmd <label> <condition-exit-status> <output shown on failure>
  if [ "$2" = 0 ]; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s\n        %s\n' "$1" "$(printf '%s' "$3" | head -c 1500)"
    failures=$((failures + 1))
  fi
}

start="$(start_call 'echo "CWD=$(pwd -P) PROBE=${HF_PROBE:-unset}"; sleep 20')"
# ghp_ and 30 of the 36 characters a classic PAT has: a candidate still
# arriving at the tail. Entirely made up.
partial="$(start_call "printf 'line one\\ntoken ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfa'; sleep 60")"
# A line of prose naming a key block's opening marker, with no end and
# 300 KB after it: a daemon from before GH #195 freezes its cursor there,
# so a drain stops 300 KB short of the end however often it retries.
keyblock="$(start_call 'i=0; while [ $i -lt 1000 ]; do echo "before line $i ................................"; i=$((i+1)); done
echo "prose that names -----BEGIN RSA PRIVATE KEY----- and never ends it"
i=0; while [ $i -lt 6000 ]; do echo "after line $i ................................................."; i=$((i+1)); done
echo LAST-LINE-MARKER; sleep 60')"

# ======================================== A: the old daemon, new clients
echo "== A: $old_tag daemon, this tree's clients"
(cd "$daemon_cwd" && "$old_bin" daemon start >/dev/null) || { echo "old daemon did not start"; exit 2; }

r="$(HF_PROBE=client-fake mcp "$new_bin" "$client_cwd" "[$start]")"
check "new shim: start_session refused, not run in the daemon's directory" \
  'd[0].get("error", {}).get("data", {}).get("reason") == "daemon_too_old"
   and "(protocol 1.1)" in d[0]["error"]["message"]
   and "holdfast daemon stop" in d[0]["error"]["message"]' "$r"

r="$(mcp "$new_bin" "$client_cwd" '[
  ["tools/call", {"name": "send_input", "arguments": {"session": "sess_none", "data": "x", "apend_newline": false}}],
  ["tools/call", {"name": "read_output", "arguments": {"session": "sess_none", "tail_lines": 3, "apply_holdback": true}}],
  ["tools/call", {"name": "list_sessions", "arguments": {}}],
  ["tools/call", {"name": "start_session", "arguments": {"command": "/bin/sh", "profile": null}}]]')"
check "new shim: a misspelt argument is refused by name, not dropped" \
  '"unknown field `apend_newline`" in d[0].get("error", {}).get("message", "")' "$r"
check "new shim: apply_holdback on a tail is refused, cursor read offered first" \
  'd[1].get("error", {}).get("data", {}).get("reason") == "daemon_too_old"
   and 0 <= d[1]["error"]["message"].find("since_cursor") < d[1]["error"]["message"].find("holdfast daemon stop")' "$r"
check "new shim: the old daemon's sessions stay reachable" \
  'd[2].get("result", {}).get("structuredContent", {}).get("status") == "ok"' "$r"
check "new shim: profile: null is no profile, and is refused" \
  'd[3].get("error", {}).get("data", {}).get("reason") == "daemon_too_old"' "$r"

# A session ending in a still-arriving fake token, started the only way the
# old daemon now can be: through its own shim.
r="$(mcp "$old_bin" "$daemon_cwd" "[$partial]")"
sid="$(printf '%s' "$r" | field 'd[0]["result"]["structuredContent"]["data"]["session_id"]' 2>/dev/null)"
check "control: the old shim starts a session on the old daemon" '"sess_" in d[0]["result"]["structuredContent"]["data"]["session_id"]' "$r"
sleep 2
old_tail="$("$old_bin" logs "$sid" --tail 3 2>&1)"
printf '%s' "$old_tail" | grep -q 'ghp_FAKE'
check_cmd "control: the old CLI's --tail releases the partial token (the leak is real)" $? "$old_tail"
new_tail="$("$new_bin" logs "$sid" --tail 3 2>&1)"; rc=$?
! printf '%s' "$new_tail" | grep -q 'ghp_FAKE' && [ "$rc" = 0 ] && printf '%s' "$new_tail" | grep -q 'line one'
check_cmd "new CLI: logs --tail withholds it and still prints the lines before it" $? "rc=$rc $new_tail"
new_all="$("$new_bin" logs "$sid" 2>&1)"
! printf '%s' "$new_all" | grep -q 'ghp_FAKE'
check_cmd "new CLI: logs (the drain) withholds it" $? "$new_all"
r="$(mcp "$new_bin" "$client_cwd" "[[\"tools/call\", {\"name\": \"read_output\", \"arguments\": {\"session\": \"$sid\", \"since_cursor\": 0, \"apply_holdback\": true}}]]")"
check "new shim: apply_holdback on a cursor read is forwarded, and the read withholds the token" \
  '"line one" in d[0]["result"]["structuredContent"]["data"]["output"]
   and "ghp_FAKE" not in json.dumps(d[0])' "$r"

r="$(mcp "$old_bin" "$daemon_cwd" "[$keyblock]")"
kid="$(printf '%s' "$r" | field 'd[0]["result"]["structuredContent"]["data"]["session_id"]' 2>/dev/null)"
sleep 3
old_tail="$("$old_bin" logs "$kid" --tail 3 2>&1)"
printf '%s' "$old_tail" | grep -q 'LAST-LINE-MARKER'
check_cmd "control: the session's last line is there to be read (the old CLI's tail read prints it)" $? "$old_tail"
new_tail="$("$new_bin" logs "$kid" --tail 3 2>&1)"
printf '%s' "$new_tail" | grep -q 'not the last of the' && printf '%s' "$new_tail" | grep -q 'GH #195'
check_cmd "new CLI: --tail stopped short by the old daemon says so, and not as the tail" $? "$new_tail"

st="$("$new_bin" daemon status 2>&1)"; rc=$?
[ "$rc" = 0 ] && printf '%s' "$st" | grep -q 'older than this holdfast'
check_cmd "new CLI: daemon status works and says the daemon is older" $? "rc=$rc $st"
out="$("$new_bin" list 2>&1)"; rc=$?
check_cmd "new CLI: list works" "$rc" "$out"
out="$("$new_bin" daemon stop 2>&1)"; rc=$?
check_cmd "new CLI: daemon stop stops the old daemon" "$rc" "$out"
"$old_bin" daemon status >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ]
check_cmd "the old daemon is gone" $? "old daemon status rc=$rc"

# ======================================== B: the new daemon, an old shim
echo "== B: this tree's daemon, a stale $old_tag shim"
(cd "$daemon_cwd" && "$new_bin" daemon start >/dev/null) || { echo "new daemon did not start"; exit 2; }
r="$(HF_PROBE=client-fake mcp "$old_bin" "$client_cwd" "[$start, [\"tools/call\", {\"name\": \"list_sessions\", \"arguments\": {}}]]")"
check "old shim: start_session refused with the advice to restart the MCP client" \
  'd[0].get("error", {}).get("code") == -32603
   and "restart the MCP client" in d[0]["error"]["message"]' "$r"
check "old shim: everything else is still served" \
  'd[1].get("result", {}).get("structuredContent", {}).get("status") == "ok"' "$r"

r="$(HF_PROBE=client-fake mcp "$new_bin" "$client_cwd" "[$start, [\"sleep\", 1.5], [\"tools/call\", {\"name\": \"read_output\", \"arguments\": {\"session\": \"\$SID\", \"since_cursor\": 0}}]]")"
check "control: a new shim on the new daemon starts in its own directory and environment" \
  '"CWD='"$client_cwd"' PROBE=client-fake" in d[1]["result"]["structuredContent"]["data"]["output"]' "$r"
out="$("$new_bin" daemon stop 2>&1)"; rc=$?
check_cmd "new CLI: daemon stop" "$rc" "$out"

if [ "$failures" = 0 ]; then
  echo "SKEW CHECK OK"
else
  echo "SKEW CHECK FAILED: $failures check(s)"
  exit 1
fi
