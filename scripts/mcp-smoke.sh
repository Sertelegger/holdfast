#!/usr/bin/env bash
# Drive `clasp mcp` over stdio with raw JSON-RPC and CHECK the responses.
#
# This is the only thing in the project that exercises the real JSON-RPC
# surface end to end: every Rust test asserts against in-process objects,
# so a bug that lives in serialisation -- a tool whose `outputSchema`
# never reaches the wire, a doc comment the router drops, an enum
# serialised outside its declared vocabulary -- is invisible to all of
# them and visible here.
#
# This script asserts. An earlier version only printed the responses, so
# it exited 0 even if `tools/list` came back empty or the shell never ran
# the command -- the definition of done was satisfied by human eyeballing
# rather than by the exit code. Every DoD bullet below is now a check.
#
# Two rules for anyone extending it:
#
#   1. Grep (or match) the *value*, not the key. `"outputSchema"` being
#      present says nothing; `"outputSchema".properties.data.$ref` being
#      `#/$defs/SendInput` on `send_input` and nothing else does.
#   2. Every positive needs the negative that separates it from the
#      degenerate case. `interaction_mode: "AtPrompt"` alone passes
#      against a constant, so the same run also drives the session into
#      `AwaitingSecret`; `exit_code: 0` alone passes against a parser
#      that always says zero, so the same run also runs `(exit 42)`.
#
# The requests are written into the server's stdin ahead of time with
# fixed `sleep`s between them; there is no reading of responses as they
# arrive. If a check flakes on a slow machine the fix is a longer sleep
# once, and after that a coprocess rewrite -- drive the server through a
# bidirectional pipe and read until each response arrives or a deadline
# passes. Never a retry loop: a smoke check that is allowed a second
# attempt is a smoke check that cannot go red.
set -uo pipefail

# Called with no argument, this script builds what it is about to test.
#
# It used not to, and against a stale `target/debug/holdfast` it fails two
# checks with `osc133_source: null` -- which reads exactly like a 0.0.2
# regression and cost one milestone's implementer a bisect against a
# baseline worktree to disprove. A check that fails misleadingly costs
# almost as much as one that cannot fail, and "remember to build first"
# is not a property of the artifact.
#
# Only on the default path. An explicit argument names a binary the
# caller has already produced -- CI passes `./target/release/holdfast` after
# its own `cargo build --release`, and `./scripts/mcp-smoke.sh /bin/true`
# is the negative control that must fail all 38 checks -- so building in
# that case would either be wrong or a no-op.
if [ "$#" -eq 0 ]; then
  if ! cargo build --workspace >&2; then
    echo "mcp-smoke: cargo build --workspace failed; nothing to smoke" >&2
    exit 1
  fi
fi

# The default path must resolve to the binary the build above *produced*,
# not to a hardcoded `./target`. `CARGO_TARGET_DIR` is honoured by cargo
# and was not honoured here, so with one set the script built one binary
# and smoked another. Measured: a stale `./target/debug/holdfast` 23 minutes
# older than the fresh build, different hashes, `SMOKE OK` reported. That
# is worse than the staleness this self-build was added to prevent -- a
# false pass rather than a misleading failure.
BIN="${1:-${CARGO_TARGET_DIR:-./target}/debug/holdfast}"
if [ ! -x "$BIN" ]; then
  echo "build first: cargo build --workspace" >&2
  exit 1
fi
# Hard requirement, not a soft skip. Half these checks are structural
# assertions about the advertised tool surface, and a skipped structural
# check is a green line that proves nothing -- the exact failure this
# script exists to stop.
if ! command -v jq >/dev/null 2>&1; then
  echo "mcp-smoke needs jq to assert on the tool surface (apt install jq)" >&2
  exit 1
fi

# A private CLASP instance for this run, and the teardown that goes with
# it. From 0.0.5 on, `"$BIN" mcp` is hybrid mode: it AUTO-SPAWNS a daemon
# and leaves it running when the transcript block ends. Without this
# export that daemon lands in the invoking user's default runtime
# directory, and two deterministic failures follow.
#
#   1. The headline check goes red on the SECOND run. `list_sessions`
#      maps over the whole registry with no filter and the registry
#      retains exited sessions, so a surviving daemon still holds the
#      previous run's terminated `smoke` session -- `data(13).sessions |
#      length` is then 2, and `.[0]` over a `HashMap` is not even
#      deterministically the new one.
#   2. It re-opens the false pass this file's self-build was added to
#      close. A daemon surviving from a previous BUILD serves that older
#      binary's behaviour, and `cargo build` cannot reach a process that
#      is already running -- the same shape as the stale-binary `SMOKE
#      OK` measured above, and just as green.
#
# `--no-daemon` is deliberately NOT the fix: it would retreat the only
# real-JSON-RPC check in the project onto the non-default transport at
# the exact milestone that makes hybrid mode the default, leaving the
# transport most agents actually use smoked by nothing.
#
# `mktemp` rather than `/tmp/clasp-smoke-$$`: two runs can collide on a
# recycled pid, and the second would then adopt the first's daemon --
# which is the bug this isolation exists to close. Short, under `/tmp`,
# for the `sun_path` reason: a socket under the workspace `target/`
# overruns the ~100-byte budget.
export CLASP_RUNTIME_DIR="$(mktemp -d /tmp/clasp-smoke-XXXXXX)"
# EXACTLY ONE `EXIT` trap, and it must stay that way: bash keeps one, so
# a second `trap ... EXIT` anywhere in this file replaces this one
# silently and leaks both the daemon and the directory. Installed after
# `BIN` resolves and before the transcript runs, so a failed check still
# tears down. `daemon stop` with no daemon exits 0 by §3.2, so the trap
# is idempotent and its status is ignored.
trap '"$BIN" daemon stop >/dev/null 2>&1; rm -rf "$CLASP_RUNTIME_DIR"' EXIT

req() { printf '%s\n' "$1"; }

OUT="$(
  {
    req '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
    req '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    req '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    req '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_session","arguments":{"command":"bash","args":["--norc","--noprofile"],"name":"smoke"}}}'
    # Long enough for the §8.5 integration snippet to have been typed AND
    # run. While it runs, readline holds ECHO off with bracketed paste
    # disabled, which §8.3 classifies as `AwaitingSecret` -- a write
    # landing in that window is flagged, and `send_input does not flag an
    # ordinary write` below would fail for a reason unrelated to what it
    # tests.
    sleep 2
    # `SMOKE_$((6*7))` is echoed by the terminal verbatim; only a shell
    # that *ran* it prints SMOKE_42. Checking for a literal marker would
    # match the echo and pass against a server that never reached a shell.
    # (The `''` trick used in the Rust tests cannot be used here: inside a
    # single-quoted shell string `''` closes and reopens the quote and
    # vanishes before the JSON is ever formed.)
    req '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"echo SMOKE_$((6*7))"}}}'
    sleep 2
    req '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","since_cursor":0}}}'
    # A second command with a distinctive non-zero exit code. `exit_code:
    # 0` on its own is the value a broken `D;<code>` parser produces by
    # default, so it proves nothing without this beside it.
    req '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"(exit 42)"}}}'
    sleep 2
    # `read -s` drops termios ECHO with bracketed paste already off, which
    # is the §8.3 signature of a password prompt (§8.7 row 4). It is what
    # makes `interaction_mode` and `detection_tier` provably not constants
    # in this transcript, and it drives REQ-SEC-011's warning for real.
    req '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"read -s -p SMOKEPW: pw"}}}'
    # Sampled twice. `read` blocks until something is typed, so the
    # echo-off state is *stable* between these two probes -- this is not a
    # retry, it is two readings of one steady state, and the check below
    # requires every reading that saw `AwaitingSecret` to agree on how it
    # got there. One probe was measured going red about once in six runs on
    # a loaded box: sometimes the shell had not reached the `read` yet, and
    # sometimes it had reached it but had not yet printed the prompt, so
    # the classification was right and `prompt.last_line` was still empty.
    sleep 2
    req '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","tail_bytes":512}}}'
    sleep 1
    req '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","tail_bytes":512}}}'
    req '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"hunter2"}}}'
    sleep 2
    # The milestone's headline behaviour, on the only surface that drives
    # real JSON-RPC. A GitHub-shaped token is TYPED INTO THE SHELL, so it
    # reaches three places at once: the terminal's echo of the line (which
    # `read_output` must redact), the OSC 133 command capture (which
    # `get_command_history` must redact -- it did not, and shell
    # integration is on by default, so that was the default
    # configuration), and the shell's own environment. The token is a
    # fixture, not a credential: it is the `github-token` rule's own
    # `positive` example from `redaction_default.toml`.
    req '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"send_input","arguments":{"session":"smoke","data":"export GH_TOKEN=ghp_0123456789abcdefghijABCDEFGHIJ012345"}}}'
    sleep 2
    req '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"read_output","arguments":{"session":"smoke","since_cursor":0}}}'
    req '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"list_sessions","arguments":{}}}'
    req '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_command_history","arguments":{"session":"smoke"}}}'
    req '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"status","arguments":{"session":"smoke"}}}'
    # The one place in this transcript where ORDER, not elapsed time, is
    # what the sleep buys. Everything above is a read; `terminate` is the
    # single mutation, and it ends the session's claim on the name
    # `smoke` -- so any read that lands after it answers
    # `session_not_found`.
    #
    # Requests are written ahead of time and responses are never read, so
    # the only thing separating two requests is a sleep. That was
    # survivable while the tools ran in-process and finished in arrival
    # order; from 0.0.5 each one is a socket round-trip through the shim,
    # rmcp dispatches a task per request, and completion order is
    # whatever the runtime picks. Measured without this line: responses
    # came back `... 16 13 6 7 8` -- `terminate` overtook the two
    # requests written before it, and `get_command_history` and `status`
    # both answered `session_not_found` about a session that had been
    # alive when they were sent. Four checks red, none of them about
    # anything that was broken.
    sleep 1
    req '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"terminate","arguments":{"session":"smoke","force":true}}}'
    sleep 0.3
  } | "$BIN" mcp
)"
SERVER_STATUS=$?

printf '%s\n' "$OUT"
echo
echo "--- checks ---"

fails=0
# Counted rather than transcribed: the total below is what `check`,
# `absent` and `jcheck` actually ran, printed at the end of every run in
# both directions. `CONTRIBUTING.md`'s "N checks" is a copy of this
# number as last measured -- if the two disagree, this one is right,
# because it comes from the run that just happened rather than from
# memory. Two stale-count reviews in one milestone is why this is here
# instead of a comment asking a future editor to remember.
total=0

# `check <description> <literal substring>` -- a byte-level assertion on
# the transcript. `-F` on purpose: every pattern here is a literal, and
# BRE would silently give `$`, `*` and `[` a second meaning inside JSON.
#
# `>/dev/null` rather than `grep -q`, and that is not a style choice.
# `-q` makes grep exit at the first match, which closes the pipe while
# `printf` still has tens of kilobytes of transcript to write; `printf`
# then dies of SIGPIPE, and `set -o pipefail` turns the whole pipeline
# into status 141 -- a **false red** on a pattern that is present.
# Measured on this file at 3-6 runs in 20 under load, always on a pattern
# that matches near the start of the transcript (the `capabilities`
# object is the first thing the server writes) because that is when grep exits
# earliest. Without `-q`, grep reads to EOF and the race does not exist.
check() {
  total=$((total + 1))
  if printf '%s' "$OUT" | grep -F -- "$2" >/dev/null; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    echo "        (no match for: $2)"
    fails=$((fails + 1))
  fi
}

# `absent <description> <forbidden substring> <witness substring>`
#
# The same assertion inverted, over the WHOLE transcript rather than over
# one response. That scope is the point: a field-by-field check covers
# only the fields whoever wrote it thought of, which is how a secret
# shipped in `prompt.last_line` while four other fields of the same
# response were being asserted redacted. Every byte the server wrote is
# inside this one -- `details` strings, the `content[0]` text mirror, and
# every response added later.
#
# The **witness** is not decoration. An absence check passes against an
# empty transcript, so without it this would be the one line in the file
# that stays green against `/bin/true` -- and rule 2 of this script says
# every positive needs the negative that separates it from the degenerate
# case. `[REDACTED:github]` can only appear if the redactor ran on real
# session content, so the pair says "the secret is gone AND something
# removed it" rather than "nothing came back".
absent() {
  total=$((total + 1))
  if printf '%s' "$OUT" | grep -F -- "$2" >/dev/null; then
    echo "  FAIL  $1"
    echo "        (the transcript contains: $2)"
    fails=$((fails + 1))
  elif ! printf '%s' "$OUT" | grep -F -- "$3" >/dev/null; then
    echo "  FAIL  $1"
    echo "        (nothing to prove it: no match for: $3)"
    fails=$((fails + 1))
  else
    echo "  ok    $1"
  fi
}

# jq helpers. `-s` slurps the transcript into an array of responses, so a
# filter can address one response by id instead of grepping the whole
# blob -- which is what makes "`get_command_history` says X" an assertion
# about `get_command_history` rather than about the transcript.
JQ_HELPERS='
def resp($id): map(select(.id? == $id)) | first;
def data($id): resp($id).result.structuredContent.data;
def tools: resp(2).result.tools;
def tool($n): tools | map(select(.name == $n)) | first;
'

# `jcheck <description> <jq filter> <expected compact JSON>`
#
# The expected value is always a concrete non-null JSON literal, so a
# filter that addresses nothing (`null`), a response that never arrived,
# or a jq syntax error all fail rather than quietly agreeing.
jcheck() {
  total=$((total + 1))
  local got
  got="$(printf '%s\n' "$OUT" | jq -c -s "$JQ_HELPERS $2" 2>&1)"
  if [ "$got" = "$3" ]; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    echo "        expected: $3"
    echo "        got:      $got"
    fails=$((fails + 1))
  fi
}

total=$((total + 1))
if [ "$SERVER_STATUS" -ne 0 ]; then
  echo "  FAIL  server exited $SERVER_STATUS"
  fails=$((fails + 1))
else
  echo "  ok    server exited 0"
fi

# ---------------------------------------------------------- the handshake

# Order-independent, because it is not: 0.0.5 added the `resources`
# capability (§5.5) and the serialised object no longer opens with
# `"tools"`. A substring check on `{"tools":` asserted a field *order*
# rmcp chooses, which is not a contract this project owns.
jcheck "initialize advertises the tools capability" \
  'resp(1).result.capabilities.tools != null' 'true'
# §5.5's `resources` capability, present on this transport and
# **without** `listChanged`, which it cannot deliver -- one `jcheck` over
# both clauses, not two. It used to be two: presence, then
# absence-of-listChanged. Splitting them was itself a bug, found by
# running the negative control rather than by reading the diff:
# `.capabilities.resources.listChanged` on a wholly *absent*
# `capabilities.resources` is also `null` in jq, so the listChanged half
# passed against a server that never started -- against `/bin/true` it
# was the one check in this file (of 39) that stayed green. Anding
# `resources != null` back in closes it, because that clause is false in
# exactly the case that let the other one through, and the pair also
# collapses two `jcheck`s into one, which is why the total below is 38.
#
# This check read `.listChanged == true` at one point and was green for
# the wrong reason: it asserted the advertisement, and nothing anywhere
# asserted the delivery. The forwarder that turns a
# `resource_list_changed` pulse into an MCP notification is
# `ClaspServer::on_initialized`, which needs the MCP peer; this script
# runs the DEFAULT transport, where that object lives in the daemon and
# the pulse goes into a broadcast channel with zero receivers. §7.4.1's
# streaming frames are reserved and unused in v0.1.0, so nothing carries
# it across. Deferred to the milestone that adds a server->client frame;
# see `mcp::shim_capabilities`.
#
# `null`, not `false`, for the second clause: `ResourcesCapability` is
# `#[non_exhaustive]`, so an explicit `false` cannot be built from
# outside `rmcp`, and the field is `skip_serializing_if =
# "Option::is_none"`.
jcheck "initialize advertises resources without listChanged on the daemon transport" \
  '[resp(1).result.capabilities.resources != null,
    resp(1).result.capabilities.resources.listChanged]' \
  '[true,null]'
# The `instructions` string is the first thing an agent reads about this
# server, and it described a four-tool 0.0.1 surface for the whole of
# 0.0.2. Asserting the names rather than the prose keeps it honest
# without pinning wording.
jcheck "initialize's instructions name every tool" \
  'resp(1).result.instructions as $i
   | ["start_session","send_input","read_output","wait_for_pattern","terminate",
      "status","list_sessions","get_command_history","get_screen_state",
      "resize","interrupt"]
   | map(. as $n | select(($i | contains($n)) | not))' \
  '[]'

# ------------------------------------------------- the advertised surface

for tool in start_session read_output send_input terminate status list_sessions \
            get_command_history wait_for_pattern get_screen_state resize \
            interrupt; do
  check "tools/list contains $tool" "\"name\":\"$tool\""
done
# The loop above cannot see an *extra* tool, and "every tool has X" is
# only a claim about the eleven if eleven is all there is.
jcheck "tools/list advertises exactly the eleven tools" \
  'tools | map(.name) | sort' \
  '["get_command_history","get_screen_state","interrupt","list_sessions","read_output","resize","send_input","start_session","status","terminate","wait_for_pattern"]'

# REQ-T-014. Four same-typed booleans per tool: a transposition
# serialises perfectly and passes any check that greps for the word
# `annotations`, or for `"readOnlyHint":true` somewhere in the blob. The
# whole table is pinned instead, tool by tool, and the read-only
# tools share one hint combination so the *title* is what separates them.
# This is the wire-side half of `tests/schema.rs::
# every_tool_declares_the_annotations_5_3_assigns_it`.
jcheck "tools carry MCP annotations" \
  'tools | sort_by(.name)
   | map([.name, .annotations.title, .annotations.readOnlyHint,
          .annotations.destructiveHint, .annotations.idempotentHint,
          .annotations.openWorldHint])' \
  '[["get_command_history","List commands run, with exit codes",true,null,null,false],["get_screen_state","Read the rendered terminal screen",true,null,null,false],["interrupt","Send Ctrl+C to a session'"'"'s process group",false,true,false,true],["list_sessions","List all sessions",true,null,null,false],["read_output","Read session output",true,null,null,false],["resize","Resize a session'"'"'s terminal",false,false,true,false],["send_input","Send keystrokes to a session",false,true,false,true],["start_session","Start a PTY-backed shell session",false,true,false,true],["status","Get detailed session status",true,null,null,false],["terminate","Terminate a session",false,true,true,false],["wait_for_pattern","Wait for a regex to match output",true,null,null,false]]'

# REQ-T-013, on the wire rather than in Rust. The `$ref` column is the
# load-bearing one: it is what distinguishes eleven tools that each
# advertise an `outputSchema` from eleven tools that advertise the *same*
# `outputSchema`, which is the shape a copy-paste error takes here and
# which a presence check cannot see.
jcheck "tools declare an outputSchema" \
  'tools | sort_by(.name)
   | map([.name, .outputSchema.type, .outputSchema.required,
          .outputSchema.properties.data["$ref"]])' \
  '[["get_command_history","object",["status","data","details"],"#/$defs/CommandHistory"],["get_screen_state","object",["status","data","details"],"#/$defs/GetScreenState"],["interrupt","object",["status","data","details"],"#/$defs/Interrupt"],["list_sessions","object",["status","data","details"],"#/$defs/ListSessions"],["read_output","object",["status","data","details"],"#/$defs/ReadOutput"],["resize","object",["status","data","details"],"#/$defs/Resize"],["send_input","object",["status","data","details"],"#/$defs/SendInput"],["start_session","object",["status","data","details"],"#/$defs/StartSession"],["status","object",["status","data","details"],"#/$defs/SessionRecord"],["terminate","object",["status","data","details"],"#/$defs/Terminate"],["wait_for_pattern","object",["status","data","details"],"#/$defs/WaitForPattern"]]'

# A `$ref` that resolves to nothing describes nothing. `additionalProperties:
# false` is separately load-bearing: without it a schema that merely omitted
# a field would validate every response, and `tests/schema.rs` could never
# go red.
jcheck "each tool's data schema resolves to a closed object" \
  'tools | sort_by(.name)
   | map(.outputSchema
         | (.properties.data["$ref"] | ltrimstr("#/$defs/")) as $d
         | [.["$defs"][$d].type, .["$defs"][$d].additionalProperties])' \
  '[["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false]]'

# `$defs` only appears in a schemars-generated schema, so this cannot be
# satisfied by a hand-written stub that says `{"type":"object"}`.
check "outputSchema reaches the wire as schemars JSON" '"outputSchema":{"$defs"'

# The §18.2a vocabularies the agent is told to branch on. A field
# declared as a bare string accepts `state: "banana"` and
# `detection_tier: "terminal-mode"`, and a *type* check cannot see it;
# only the enumeration can. Both directions matter -- a value the tools
# emit and the schema omits is a response that fails its own schema, and
# a value declared but never emitted is vocabulary the agent waits for
# and never sees.
jcheck "the §18.2a vocabularies reach the wire" \
  '[tool("read_output").outputSchema["$defs"]
    | .Status.enum, .InteractionMode.enum, .DetectionTier.enum,
      .ScreenTracking.enum, .SessionState.enum]
   + [tool("status").outputSchema["$defs"].ShellIntegration.enum,
      tool("status").outputSchema["$defs"].Osc133Source.enum]' \
  '[["ok","timeout","session_died","session_not_found","name_taken","limit_reached","spawn_failed","unavailable"],["AtPrompt","Executing","AwaitingSecret","Fullscreen","Exited"],["semantic","terminal_mode","heuristic"],["off","on"],["Starting","Running","Exited","Dead"],["bash","zsh","fish"],["holdfast","external","mixed"]]'

# The caveats have to be in the text the AGENT reads, and scoped to the
# tool that carries them rather than to the transcript. `80 columns` and
# `Latin-1` are here for the same reason `tests/schema.rs` has them:
# deleting the quantification while keeping the phrase `truncated to its
# tail` is the reword that survives a bare-substring check, and those two
# are what tell the agent *how* wrong `command` gets.
jcheck "get_command_history warns about nested shells" \
  'tool("get_command_history").description as $d
   | ["nested integrated shell"]
   | map(. as $n | select(($d | contains($n)) | not))' \
  '[]'
jcheck "get_command_history warns that command is truncated" \
  'tool("get_command_history").description as $d
   | ["truncated to its tail","80 columns","Latin-1"]
   | map(. as $n | select(($d | contains($n)) | not))' \
  '[]'

# ------------------------------------------------------ real behaviour

# `shell_integration` is what tells the agent whether `get_command_history`
# can work at all, and it is decided by `detect_shell` from the command
# line rather than echoed back from the request. `cwd` is asserted as a
# *string* because §5.2 says it is the effective directory the child was
# spawned in: `portable-pty` silently falls back to $HOME for a bad cwd,
# and null here would mean the tool answered without knowing where it ran.
jcheck "start_session reports the shell it integrated" \
  'data(3) | [.name, .shell_integration, (.pid > 0), (.cwd | type)]' \
  '["smoke","bash",true,"string"]'

# The whole point of the arithmetic marker: SMOKE_42 can only come from a
# shell that evaluated $((6*7)). The echoed command line contains
# SMOKE_$((6*7)) literally, so this cannot be satisfied by the PTY echo.
check "read_output shows shell-evaluated output" 'SMOKE_42'

# The §5.4 block on every prompt-bearing response, and the session
# observed at an OSC 133 prompt.
#
# The count is the strict half: eight tool calls in this transcript are
# prompt-bearing (four `send_input`, three `read_output`, one `status`),
# and dropping `with_detection` from any one of them changes it.
# `list_sessions` is deliberately not among them -- it carries the block
# on each *entry*, not on `data` -- so this also pins that shape.
#
# The membership half is written over the transcript rather than over one
# response id on purpose. Pinning `data(5)` was measured going red once in
# twenty-five runs under load, with the shell mid-`echo` and the detector
# correctly answering `Executing`; that is the fixed-sleep design failing,
# not the classifier. Three separate settled instants are sampled here and
# all three would have to miss for this to pass wrongly -- which is
# exactly what happens when the §8.5 snippet never runs.
#
# Rev. 37's scoped availability does *not* move this, and the reason is
# worth recording so the next reader need not re-derive it:
# `AtPrompt`/`semantic` comes from the T1 prompt-marker rung, and `A`/`B`
# being the last marker means no `C` has arrived, means no command is
# running, means the emitting shell is itself the foreground program. The
# owner and the holder are the same group there by construction.
jcheck "responses carry interaction_mode" \
  '[.[] | .result.structuredContent.data
        | select(.interaction_mode? != null)
        | [.interaction_mode, .detection_tier]] as $seen
   | [($seen | any(. == ["AtPrompt","semantic"])), ($seen | length)]' \
  '[true,10]'

# `semantic` is only reachable if the injected OSC 133 snippet was typed
# into a real shell and that shell ran it -- it cannot be faked by the
# PTY echo, which carries the snippet's *text* and no markers.
#
# Written over the transcript rather than over `data(5)` since rev. 37:
# availability is scoped to the foreground program, so a read landing
# while an external command runs correctly reports `heuristic`, and
# pinning one response id makes this a race. At least one prompt-bearing
# response must have caught the shell itself at the terminal, which is
# what `semantic` means and what an empty list would not satisfy.
jcheck "shell integration reached tier 1" \
  '[.[] | .result.structuredContent.data
        | select(.detection_tier? == "semantic")] | length > 0' \
  'true'

# The separator for the two above: a hardcoded `AtPrompt`/`semantic`
# passes both. §8.7 row 4 is a different mode reached through a different
# tier, in the same session, in the same transcript.
#
# Written over every prompt-bearing response rather than over one id, so
# it does not depend on *which* sample caught the steady state -- but it
# is not weaker for it. Two things are asserted, and both are needed:
#
#   * `unique` collapsing to a single row means every response in the
#     transcript that reported `AwaitingSecret` reported it through the
#     terminal-mode tier at 0.95. An empty list -- nothing ever reached
#     the state -- is not the expected value either, so this cannot pass
#     vacuously.
#   * at least one of those readings was sitting on `read -s`'s own
#     prompt, which is what makes this an assertion about the password
#     prompt rather than about whatever the session was passing through.
#     It is a separate clause because `last_line` is legitimately empty
#     for the instant between the shell clearing the line and `read`
#     printing its prompt -- measured, once in twenty runs under load.
jcheck "a real password prompt is AwaitingSecret via the terminal-mode tier" \
  '[.[] | .result.structuredContent.data
        | select(.interaction_mode? == "AwaitingSecret")] as $seen
   | [($seen | map([.interaction_mode, .detection_tier, .prompt.confidence])
             | unique),
      ($seen | any(.prompt.last_line == "SMOKEPW:"))]' \
  '[[["AwaitingSecret","terminal_mode",0.95]],true]'

# REQ-SEC-011, and its own negative. An ordinary write at an ordinary
# prompt must not be flagged, or the warning is noise an agent learns to
# ignore. Anchored on request 9 rather than request 4: request 5 asserts
# the session is at a semantic prompt, nothing is written between 5 and 9,
# and `send_input` samples the flag *before* its own write -- so this one
# is not a race. (Request 4 can legitimately land while the §8.5 snippet
# is still running, which is echo-off and correctly flagged.)
#
# `bytes_written` rides along because the expected `warning` is `null`,
# and `null` is also what a filter that addressed *nothing* returns:
# measured against `/bin/true`, this check was the one line that stayed
# green on an empty transcript. `(exit 42)` plus the appended newline is
# ten bytes, so the pair can only be produced by a response that exists.
jcheck "send_input does not flag an ordinary write" \
  'data(9) | [.warning, .bytes_written]' '[null,10]'
jcheck "send_input flags a write to an echo-off session" \
  'data(12).warning' '"session_awaiting_secret"'

# ------------------------------------------------------------ redaction
#
# 0.0.3's headline behaviour, and it was absent from this file entirely --
# the one place that drives the real JSON-RPC surface had no check for the
# milestone's whole subject. `get_command_history` returned the command
# line unredacted for the length of the milestone, and this is the surface
# that bug lived on.

absent "no response carries the token typed into the shell" \
  'ghp_0123456789abcdefghijABCDEFGHIJ012345' '[REDACTED:github]'

# The two companions, per tool, because the line above passes just as well
# against a server that returned nothing at all. Each pins the SURROUNDING
# text as well as the marker, so a redactor that ate the line fails them.
jcheck "read_output redacts the terminal's echo of the token" \
  'data(16).output | contains("export GH_TOKEN=[REDACTED:github]")' 'true'
jcheck "get_command_history redacts the command line" \
  'data(7).entries[3] | [.command, .exit_code]' \
  '["export GH_TOKEN=[REDACTED:github]",0]'

# `index` is emitted only by get_command_history, and the exit code
# beside it came from an OSC 133 `D;<code>` marker. Entry 0's `0` is the
# value a broken parser defaults to; entry 1's `42` is not, and the two
# together are what prove the code is read per command rather than
# assumed. `command` is asserted alongside so an entry cannot be matched
# to the wrong command line.
jcheck "command history recorded an exit code" \
  'data(7).entries[0] | [.index, .command, .exit_code]' \
  '[0,"echo SMOKE_$((6*7))",0]'
jcheck "command history reports each command its own exit code" \
  'data(7) | [(.entries[1] | [.index, .command, .exit_code]), .total, .truncated_at_tail]' \
  '[[1,"(exit 42)",42],4,false]'

# `list_sessions` and `status` must answer about the session
# `start_session` created, by the id it handed back -- not about "the
# first session in the registry", which is indistinguishable while there
# is only one.
jcheck "list_sessions returns the session start_session created" \
  'data(3).session_id as $id
   | data(13).sessions | [length, (.[0] | [.id == $id, .name, .state])]' \
  '[1,[true,"smoke","Running"]]'
# `osc133_source` rides here rather than in its own check: the smoke shell
# is a CLASP-integrated bash with no foreign emitter, so `holdfast` is the
# only correct answer and it is only reachable if the snippet ran, was
# tagged, and was not discarded. `null` means no marker ever arrived --
# which the tier-1 check above already contradicts, so a disagreement
# between them localises the defect.
jcheck "status answers about the named session" \
  'data(3).session_id as $id
   | data(8) | [.id == $id, .name, .command, .state, .shell_integration,
                .osc133_source, .command_count]' \
  '[true,"smoke","bash","Running","bash","holdfast",4]'

check "terminate reports ok" '"already_exited":false'

echo
if [ "$fails" -ne 0 ]; then
  echo "SMOKE FAILED: $fails of $total check(s) did not pass" >&2
  exit 1
fi
echo "SMOKE OK ($total checks)"
