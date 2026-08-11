#!/usr/bin/env bash
# Drive `clasp mcp` over stdio with raw JSON-RPC and CHECK the responses.
# Verifies initialize -> tools/list -> start_session -> send_input ->
# read_output -> terminate end to end.
#
# This script asserts. An earlier version only printed the responses, so
# it exited 0 even if `tools/list` came back empty or the shell never ran
# the command -- the definition of done was satisfied by human eyeballing
# rather than by the exit code. Every DoD bullet below is now a check.
set -uo pipefail

BIN="${1:-./target/debug/clasp}"
if [ ! -x "$BIN" ]; then
  echo "build first: cargo build --workspace" >&2
  exit 1
fi

req() { printf '%s\n' "$1"; }

OUT="$(
  {
    req '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
    req '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    req '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    req '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_session","arguments":{"command":"bash","args":["--norc","--noprofile"],"name":"smoke"}}}'
    sleep 0.5
    # `SMOKE_$((6*7))` is echoed by the terminal verbatim; only a shell
    # that *ran* it prints SMOKE_42. Checking for a literal marker would
    # match the echo and pass against a server that never reached a shell.
    # (The `''` trick used in the Rust tests cannot be used here: inside a
    # single-quoted shell string `''` closes and reopens the quote and
    # vanishes before the JSON is ever formed.)
    req '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"echo SMOKE_$((6*7))"}}}'
    sleep 1
    req '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","since_cursor":0}}}'
    req '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"terminate","arguments":{"session":"smoke","force":true}}}'
    sleep 0.3
  } | "$BIN" mcp
)"
SERVER_STATUS=$?

printf '%s\n' "$OUT"
echo
echo "--- checks ---"

fails=0
check() { # check <description> <pattern>
  if printf '%s' "$OUT" | grep -q -- "$2"; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    echo "        (no match for: $2)"
    fails=$((fails + 1))
  fi
}

if [ "$SERVER_STATUS" -ne 0 ]; then
  echo "  FAIL  server exited $SERVER_STATUS"
  fails=$((fails + 1))
else
  echo "  ok    server exited 0"
fi

check "initialize advertises tool capability" '"capabilities":{"tools":'
for tool in start_session read_output send_input terminate; do
  check "tools/list contains $tool" "\"name\":\"$tool\""
done
# The whole point of the arithmetic marker: SMOKE_42 can only come from a
# shell that evaluated $((6*7)). The echoed command line contains
# SMOKE_$((6*7)) literally, so this cannot be satisfied by the PTY echo.
check "read_output shows shell-evaluated output" 'SMOKE_42'
check "terminate reports ok" '"already_exited":false'

echo
if [ "$fails" -ne 0 ]; then
  echo "SMOKE FAILED: $fails check(s) did not pass" >&2
  exit 1
fi
echo "SMOKE OK"
