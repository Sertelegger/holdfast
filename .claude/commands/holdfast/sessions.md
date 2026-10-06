---
description: Show every Holdfast session as one compact table
argument-hint: "[name or id substring to filter by]"
allowed-tools: Bash(holdfast:*), Bash(./target/debug/holdfast:*), Bash(command -v holdfast), Bash(printenv HOLDFAST_BOOTSTRAP_BIN), mcp__plugin_holdfast_holdfast__list_sessions, mcp__holdfast__list_sessions
---

List the Holdfast sessions and render them as a single table. Filter to those
whose name or id contains `$1` when it is given.

**Read them with `holdfast list --json`.** It prints the same records the
`list_sessions` tool returns, under `sessions`, detection state included:
`interaction_mode`, `detection_tier`, `command_capture`. Only the plain
`holdfast list` table leaves that out. The CLI is also the read that cannot
start a daemon: with none running it exits 2 and says why on stderr, which is
a different fact from "no sessions" and has a different fix.

Find the binary first, because a plugin install puts none on `PATH`:
- `command -v holdfast`;
- else `printenv HOLDFAST_BOOTSTRAP_BIN`, and run the path it names;
- else `./target/debug/holdfast`, a build in this checkout, if it exists.

**Fall back to the MCP `list_sessions` tool only when none of those answers**,
and say which source you used. Its name depends on how Holdfast was
installed, so use whichever this session has:
- `mcp__plugin_holdfast_holdfast__list_sessions` under the plugin;
- `mcp__holdfast__list_sessions` under `claude mcp add holdfast`.

Its result text is a JSON envelope with the records under `data.sessions`.
**Unlike the CLI, an MCP call starts a daemon when its own has gone.** The
call then lists no sessions, and its `details` begins "The Holdfast daemon had
stopped". When it does, report that the daemon was down and this call started
a new, empty one, not "no sessions".

Render exactly these columns, one row per session, nothing else:

`id` (first 8 chars) · `name` · `state` · `interaction_mode` · `detection_tier` · `pid` · `idle`

`idle` is the time since `last_activity_unix_ms`.

Then, and only when there is something to say:

- **Flag any session whose `detection_tier` is `heuristic`.** That tier is
  guessed from output quiescence and a prompt-pattern table rather than
  measured from OSC 133 or a terminal mode, so `interaction_mode` on that row
  is a good guess and not a fact. A reader deciding whether to act on
  "AtPrompt" needs to know which one they have.
- **Flag any session whose `command_capture` is `missing`.** Its newest
  command history entry has no command text (`command: null`): that
  command's OSC 133 `C` marker had no `B` marker in front of it. Usually a
  prompt framework such as starship is regenerating the prompt over the
  markers; exit codes and output spans are still exact, and what was typed
  is not in the history. It can also mean a program printed a `C` marker in
  its own output, after which the history can stop recording commands at
  all (GH #265). The field describes the last command recorded and cannot
  predict the next.
- **Flag `AwaitingSecret`.** That session is blocked on a password prompt.
  The secret is typed in `holdfast attach <id>`. An agent asks for it with
  `request_secret_input`, never with `send_input`, which would put it in the
  transcript.
- **Flag sessions in `Exited`/`Dead` state that are still retained**, with
  their exit code — they hold a buffer and a registry slot until reaped.

Do not start, terminate or write to any session. This command reads.

If there are no sessions, say so in one line — do not print an empty table.
