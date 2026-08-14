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
# It used not to, and against a stale `target/debug/clasp` it fails two
# checks with `osc133_source: null` -- which reads exactly like a 0.0.2
# regression and cost one milestone's implementer a bisect against a
# baseline worktree to disprove. A check that fails misleadingly costs
# almost as much as one that cannot fail, and "remember to build first"
# is not a property of the artifact.
#
# Only on the default path. An explicit argument names a binary the
# caller has already produced -- CI passes `./target/release/clasp` after
# its own `cargo build --release`, and `./scripts/mcp-smoke.sh /bin/true`
# is the negative control that must fail all 30 checks -- so building in
# that case would either be wrong or a no-op.
if [ "$#" -eq 0 ]; then
  if ! cargo build --workspace >&2; then
    echo "mcp-smoke: cargo build --workspace failed; nothing to smoke" >&2
    exit 1
  fi
fi

BIN="${1:-./target/debug/clasp}"
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
    req '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"list_sessions","arguments":{}}}'
    req '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_command_history","arguments":{"session":"smoke"}}}'
    req '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"status","arguments":{"session":"smoke"}}}'
    req '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"terminate","arguments":{"session":"smoke","force":true}}}'
    sleep 0.3
  } | "$BIN" mcp
)"
SERVER_STATUS=$?

printf '%s\n' "$OUT"
echo
echo "--- checks ---"

fails=0

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
# that matches near the start of the transcript (`"capabilities":{"tools":`
# is the first thing the server writes) because that is when grep exits
# earliest. Without `-q`, grep reads to EOF and the race does not exist.
check() {
  if printf '%s' "$OUT" | grep -F -- "$2" >/dev/null; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    echo "        (no match for: $2)"
    fails=$((fails + 1))
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

if [ "$SERVER_STATUS" -ne 0 ]; then
  echo "  FAIL  server exited $SERVER_STATUS"
  fails=$((fails + 1))
else
  echo "  ok    server exited 0"
fi

# ---------------------------------------------------------- the handshake

check "initialize advertises tool capability" '"capabilities":{"tools":'
# The `instructions` string is the first thing an agent reads about this
# server, and it described a four-tool 0.0.1 surface for the whole of
# 0.0.2. Asserting the names rather than the prose keeps it honest
# without pinning wording.
jcheck "initialize's instructions name every 0.0.3 tool" \
  'resp(1).result.instructions as $i
   | ["start_session","send_input","read_output","wait_for_pattern","terminate",
      "status","list_sessions","get_command_history"]
   | map(. as $n | select(($i | contains($n)) | not))' \
  '[]'

# ------------------------------------------------- the advertised surface

for tool in start_session read_output send_input terminate status list_sessions \
            get_command_history wait_for_pattern; do
  check "tools/list contains $tool" "\"name\":\"$tool\""
done
# The loop above cannot see an *extra* tool, and "every tool has X" is
# only a claim about the eight if eight is all there is.
jcheck "tools/list advertises exactly the eight 0.0.3 tools" \
  'tools | map(.name) | sort' \
  '["get_command_history","list_sessions","read_output","send_input","start_session","status","terminate","wait_for_pattern"]'

# REQ-T-014. Four same-typed booleans per tool: a transposition
# serialises perfectly and passes any check that greps for the word
# `annotations`, or for `"readOnlyHint":true` somewhere in the blob. The
# whole table is pinned instead, tool by tool, and the three read-only
# tools share a hint combination so the *title* is what separates them.
# This is the wire-side half of `tests/schema.rs::
# every_tool_declares_the_annotations_5_3_assigns_it`.
jcheck "tools carry MCP annotations" \
  'tools | sort_by(.name)
   | map([.name, .annotations.title, .annotations.readOnlyHint,
          .annotations.destructiveHint, .annotations.idempotentHint,
          .annotations.openWorldHint])' \
  '[["get_command_history","List commands run, with exit codes",true,null,null,false],["list_sessions","List all sessions",true,null,null,false],["read_output","Read session output",true,null,null,false],["send_input","Send keystrokes to a session",false,true,false,true],["start_session","Start a PTY-backed shell session",false,true,false,true],["status","Get detailed session status",true,null,null,false],["terminate","Terminate a session",false,true,true,false],["wait_for_pattern","Wait for a regex to match output",true,null,null,false]]'

# REQ-T-013, on the wire rather than in Rust. The `$ref` column is the
# load-bearing one: it is what distinguishes eight tools that each
# advertise an `outputSchema` from eight tools that advertise the *same*
# `outputSchema`, which is the shape a copy-paste error takes here and
# which a presence check cannot see.
jcheck "tools declare an outputSchema" \
  'tools | sort_by(.name)
   | map([.name, .outputSchema.type, .outputSchema.required,
          .outputSchema.properties.data["$ref"]])' \
  '[["get_command_history","object",["status","data","details"],"#/$defs/CommandHistory"],["list_sessions","object",["status","data","details"],"#/$defs/ListSessions"],["read_output","object",["status","data","details"],"#/$defs/ReadOutput"],["send_input","object",["status","data","details"],"#/$defs/SendInput"],["start_session","object",["status","data","details"],"#/$defs/StartSession"],["status","object",["status","data","details"],"#/$defs/SessionRecord"],["terminate","object",["status","data","details"],"#/$defs/Terminate"],["wait_for_pattern","object",["status","data","details"],"#/$defs/WaitForPattern"]]'

# A `$ref` that resolves to nothing describes nothing. `additionalProperties:
# false` is separately load-bearing: without it a schema that merely omitted
# a field would validate every response, and `tests/schema.rs` could never
# go red.
jcheck "each tool's data schema resolves to a closed object" \
  'tools | sort_by(.name)
   | map(.outputSchema
         | (.properties.data["$ref"] | ltrimstr("#/$defs/")) as $d
         | [.["$defs"][$d].type, .["$defs"][$d].additionalProperties])' \
  '[["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false],["object",false]]'

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
  '[["ok","timeout","session_died","session_not_found","name_taken","limit_reached","spawn_failed","unavailable"],["AtPrompt","Executing","AwaitingSecret","Fullscreen","Exited"],["semantic","terminal_mode","heuristic"],["off"],["Starting","Running","Exited","Dead"],["bash","zsh","fish"],["clasp","external","mixed"]]'

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
  '[true,8]'

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
  '[[1,"(exit 42)",42],3,false]'

# `list_sessions` and `status` must answer about the session
# `start_session` created, by the id it handed back -- not about "the
# first session in the registry", which is indistinguishable while there
# is only one.
jcheck "list_sessions returns the session start_session created" \
  'data(3).session_id as $id
   | data(13).sessions | [length, (.[0] | [.id == $id, .name, .state])]' \
  '[1,[true,"smoke","Running"]]'
# `osc133_source` rides here rather than in its own check: the smoke shell
# is a CLASP-integrated bash with no foreign emitter, so `clasp` is the
# only correct answer and it is only reachable if the snippet ran, was
# tagged, and was not discarded. `null` means no marker ever arrived --
# which the tier-1 check above already contradicts, so a disagreement
# between them localises the defect.
jcheck "status answers about the named session" \
  'data(3).session_id as $id
   | data(8) | [.id == $id, .name, .command, .state, .shell_integration,
                .osc133_source, .command_count]' \
  '[true,"smoke","bash","Running","bash","clasp",3]'

check "terminate reports ok" '"already_exited":false'

echo
if [ "$fails" -ne 0 ]; then
  echo "SMOKE FAILED: $fails check(s) did not pass" >&2
  exit 1
fi
echo "SMOKE OK"
