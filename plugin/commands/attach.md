---
description: Explain how to watch or drive a Holdfast session from your own terminal
argument-hint: "[session name or id substring]"
allowed-tools: Bash(holdfast:*), Bash(tmux:*)
---

Help the user get eyes on a Holdfast session from *their* terminal. Filter to
sessions whose name or id contains `$1` when it is given.

`holdfast` here is the binary the plugin's bootstrap cached, which is on the
user's `$PATH` only if they installed it some other way. **Check that first**
(`command -v holdfast`) and, if it is absent, point at `/holdfast:install`
rather than printing commands that will not run.

Two subcommands, and the difference is the whole point:

- **`holdfast watch <id>`** is read-only. It mirrors the live PTY and sends
  nothing. This is the right default, and it is what to suggest when the user
  says "let me see what it is doing".
- **`holdfast attach <id>`** is read-write. Keystrokes reach the child, so the
  human and the agent are both driving one terminal. Say so before suggesting
  it, and say how to leave: detach, do not `Ctrl-C` — `Ctrl-C` reaches the
  child and kills whatever the agent was running.

If the user is in tmux, a split pane is the shape that works: the agent keeps
its pane, the session gets its own, and neither redraws over the other.

**Do not wait on a shell prompt with a regex** if you are scripting around
this. It is a guess about the operator's `$PS1` and it silently never matches
a customised one. `interaction_mode` says whether a command finished;
`get_command_history` says whether it succeeded.

**A session nobody reads from can stall its shell**, and on macOS it reliably
does: the pty's output buffer is far smaller than on Linux, and a full buffer
blocks the child mid-write. That is a reason to attach, not a reason not to —
but it is also why "I attached and nothing was happening" is not evidence that
the session is dead.

Report what you did in a few lines. Do not start, terminate or write to a
session on the user's behalf from this command.
