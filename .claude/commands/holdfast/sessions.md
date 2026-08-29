---
description: Show every Holdfast session as one compact table
argument-hint: "[name or id substring to filter by]"
allowed-tools: Bash(./target/debug/holdfast:*), Bash(holdfast:*), mcp__holdfast__list_sessions, mcp__holdfast__status
---

List the Holdfast sessions and render them as a single table. Filter to those
whose name or id contains `$1` when it is given.

**Prefer the MCP `list_sessions` tool** — it reports detection state the CLI
does not. Fall back to `holdfast list --json` only if the Holdfast MCP server
is not connected this session, and say which source you used.

Render exactly these columns, one row per session, nothing else:

`id` (first 8 chars) · `name` · `state` · `interaction_mode` · `detection_tier` · `pid` · `idle`

Then, and only when there is something to say:

- **Flag any session whose `detection_tier` is `heuristic`.** That tier is
  guessed from output quiescence and a prompt-pattern table rather than
  measured from OSC 133 or a terminal mode, so `interaction_mode` on that row
  is a good guess and not a fact. A reader deciding whether to act on
  "AtPrompt" needs to know which one they have.
- **Flag `AwaitingSecret`.** That session is blocked on a password prompt and
  must be answered with `request_secret_input`, never `send_input`.
- **Flag sessions in `Exited`/`Dead` state that are still retained**, with
  their exit code — they hold a buffer and a registry slot until reaped.

Do not start, terminate or write to any session. This command reads.

If there are no sessions, say so in one line — do not print an empty table. If
the daemon is not running, say that instead, since it is a different fact from
"no sessions" and the fix is different.
