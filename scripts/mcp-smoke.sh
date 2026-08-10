#!/usr/bin/env bash
# Drive `clasp mcp` over stdio with raw JSON-RPC and print the responses.
# Verifies initialize -> tools/list -> start_session -> send_input ->
# read_output -> terminate end to end.
set -uo pipefail

BIN="${1:-./target/debug/clasp}"
if [ ! -x "$BIN" ]; then
  echo "build first: cargo build --workspace" >&2
  exit 1
fi

req() { printf '%s\n' "$1"; }

{
  req '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
  req '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  req '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  req '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_session","arguments":{"command":"bash","args":["--norc","--noprofile"],"name":"smoke"}}}'
  sleep 0.5
  # `SMOKE_$((6*7))` is echoed by the terminal verbatim; only a shell that
  # *ran* it prints SMOKE_42. Checking for a literal marker would match
  # the echo and pass against a server that never reached a shell.
  # (The `''` trick used in the Rust tests cannot be used here: inside a
  # single-quoted shell string `''` closes and reopens the quote and
  # vanishes before the JSON is ever formed.)
  req '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"echo SMOKE_$((6*7))"}}}'
  sleep 1
  req '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","since_cursor":0}}}'
  req '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"terminate","arguments":{"session":"smoke","force":true}}}'
  sleep 0.3
} | "$BIN" mcp
