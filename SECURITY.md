# Security Policy

## Supported versions

**Holdfast is pre-release.** `v0.0.5` was the first tag, `v0.0.8` is the
newest, and the workspace version tracks it. Fixes land on `main` and are not
backported: a tag here marks a milestone, not a support commitment.

**Things are published under this name, and none of them is a Holdfast anyone
can run.** Three GitHub Releases — `v0.0.5`, `v0.0.6` and `v0.0.7` — each
carrying that version's changelog section and **no binary assets**, because
the workflow that produced them uploaded none. And two `0.0.0` **name
reservations** on crates.io, `holdfast` and `holdfast-core`, both published
2026-08-20, whose `lib.rs` says *"this version contains no usable code"*;
`cargo install holdfast` answers *"there is nothing to install in `holdfast
v0.0.0`, because it has no binaries"*. Those two were published by hand.

**The paragraph above used to describe the workflow rather than the
artifacts, and two of those descriptions are now false.** It said
"`release.yml` creates the release and uploads nothing" and "no workflow can
repeat it — the release workflow has no such step". Both were true when GH #161
wrote them on 2026-09-14. Two consecutive merges four days later took out one
clause each:

- **`release.yml` builds five platform binaries and a `SHA256SUMS.txt` and
  attaches them** (GH #198). It attaches them to a **draft**, and a draft's
  assets are not served from `releases/download/vX.Y.Z/` — so nothing has
  reached anyone, but the *reason* has changed. It is no longer that nothing
  is built; it is that promoting a draft is a human running
  `gh release edit vX.Y.Z --draft=false`, deliberately, and nobody has.
  `v0.0.8` is the first tag to run that path, and its draft is the one
  sitting there unpromoted; `v0.0.7` and older predate it, which is why the
  three releases above carry no assets.
- **`release.yml` carries a `cargo publish --workspace --locked`** in a
  `crates-io` job (GH #197). It is gated on a `CARGO_REGISTRY_TOKEN` repository
  secret that does not exist, so today it prints why it stopped and exits
  green, and nothing is uploaded. But the barrier moved from *no code path
  exists* to *a secret is unset* — and a secret is set in the GitHub UI, with
  no diff, no pull request and no review. `ci-hygiene.sh` still refuses
  `cargo publish` in any workflow that is not the tag-triggered release one;
  what it never refused was the release workflow having the step.

**So "nothing installable has reached anyone" is still true, and it is now a
statement about two human decisions rather than about absent machinery.** The
event this project treats as binding is *first external distribution* — the
moment a build reaches somebody other than the author — and it is defined by
who receives a build, not by the state of a release object. The draft, and
the promotion step, are how `release.yml` keeps that moment an act somebody
takes; its header carries the argument in full.

This section said "nothing is tagged, nothing is on crates.io, and no binaries
are distributed" from 0.0.3 until GH #161. Only the third clause was still true
by then — and GH #161's replacement for it was false four days later. Both
rewrites went wrong the same way, by describing the machinery instead of the
artifacts, which is why this paragraph now says what exists and leaves what
`release.yml` does to `release.yml`. `CONTRIBUTING.md`'s release procedure
names this file's version-pinned claims as a step, for the ones a tag
invalidates rather than a merge.

| Version | Supported |
| ------- | --------- |
| `main` (0.0.x, pre-release) | ✅ best effort |
| `v0.0.5` – `v0.0.8` | none — the fix goes on `main` |

This table becomes a real support statement at the first release anyone is
expected to install. Until then, "supported" means the fix goes on `main`.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private vulnerability reporting: go to the
[Security tab](https://github.com/Sertelegger/holdfast/security) → **Report a
vulnerability**.

This is a personal open-source project, so response times are best-effort —
expect an acknowledgment within a week.

## The thing to understand before reporting

**Holdfast exists to run commands on your machine on an AI agent's behalf.** It
spawns a real shell on a real PTY and lets an agent type into it. That is the
product, not a flaw in it. So:

- **"The agent ran a command I didn't want" is not a vulnerability.** It is
  Holdfast working. Failures of the *safety machinery around* command execution
  are what this policy is about.
- **Holdfast applies no sandbox, no allow-list, and no privilege reduction.** The
  child inherits the environment, working directory, and privileges of the
  process running `holdfast mcp`. Run it as a user you are willing to let an agent
  be.
- **The program inside a session is inside the trust boundary.** A child that
  wants to print bytes that look like a shell prompt can do so directly, at any
  length, and Holdfast cannot tell those bytes from a real shell's. See
  "Documented residuals" below.

What *is* in scope is everything Holdfast claims to do about that execution:
whether the agent is told the truth about what a session is doing, whether a
`terminate` really terminates, and whether the redactor holds.

**A Claude Code mod can call Holdfast with every permission the session has
granted.** A *mod* is code a plugin runs inside Claude Code. Through
`$.mcp.call` it can call any tool on any MCP server the session has connected,
another plugin's included. Claude Code 2.1.291 was measured checking such a
call as it checks the agent's: in default permission mode it asks, naming the
plugin, and under `claude -p`, where nobody can be asked, it refuses the call;
`deny` and `ask` rules apply. What a mod inherits is every standing grant. A
Holdfast tool you have always allowed, or any Holdfast tool under auto mode,
can be called by any installed plugin's mod with nobody asked. That was
measured from a second plugin's mod: an allowed `list_sessions` in default
mode, and `send_input` and `read_output(redact: false)` in auto mode.

- **A mod can also approve the agent's own calls.** A `tool.check` hook
  answers before the permission prompt appears. Claude Code's admin guide
  documents that its approval overrides an `ask` rule and, in auto mode, the
  classifier, and that a `deny` rule still holds where Claude Code's built-in
  guard loads (managed settings, or a Team or Enterprise sign-in). This is not
  measured here.
- **It is no new capability.** A process running as your user can already
  connect to the daemon's `control.sock`, which admits any process with the
  daemon's uid. That puts it under the same-user rule in Out of scope.
- **It is a hole in an assumption.** An always-allow you give the agent for a
  Holdfast tool is given to every installed plugin's mod too. Claude Code's
  permission prompt is the human gate in front of Holdfast only as far as you
  trust those plugins.
- **Holdfast cannot tell such a call from the agent's.** It arrives through
  the same `holdfast mcp` process, so where the audit log names the kind of
  client, it names the one it names for the agent's own calls: `shim` under
  the daemon. A mod's `read_output(redact: false)` was measured landing in a
  `redaction_disabled` entry that way. That field is attribution only; it
  decides no redaction and grants nothing.
- **What was not measured.** The auto-mode run had no model access, so
  whether auto mode's classifier reviews a mod's call is unknown. The mod
  API's own types say such a call raises no prompt at all; 2.1.291 does not
  behave that way, and a later version may.

Install plugins that carry mods only from marketplaces you trust. `claude
plugin validate <dir>` shows both reaches before you install: `$.mcp.call` on
its `calls:` line, and `tool.check` on its `hooks:` line.

The `holdfast` plugin's own mod makes no Holdfast calls and never accepts a
secret. It draws its band from the agent's own `request_secret_input` call as
that passes, takes the id that goes with a session's name from the agent's own
`start_session`, `list_sessions` and `status` results, and points you at
`holdfast attach`, where the secret is typed. It keeps nothing beyond the
running module's memory. `scripts/plugin-manifest-check.py` fails the build if
the mod's source, or the pinned report of what it calls, reaches an MCP
server.

## In scope

### Secrets and output redaction

Holdfast is designed so that a secret a human types travels **client →
daemon → PTY** and never appears in a tool argument or a tool result, and so
that a redactor stands between the session's output and anyone who reads it.
This section says exactly how much of that holds today. A security policy
that implies protection that has not shipped is worse than none, so each
clause below carries its status, and a clause marked *not built* is a goal,
not a protection.

#### Terms

- **Surface**: any way a session's output leaves Holdfast. That includes an
  MCP tool result, the `holdfast://session/…/buffer` resource, `holdfast
  logs`, a `holdfast watch` stream, the audit log, and the daemon's own log.
- **Rule**: one entry in the vendored rule set
  (`crates/holdfast-core/data/redaction_default.toml`, 55 rules), describing
  one secret shape. A match is replaced with `[REDACTED:<kind>]`, where
  `<kind>` names the rule.
- **Label-keyed rule**: a rule that finds a value by the label or flag in
  front of it (`password=…`, `API_KEY: …`, `mysql -p…`), rather than by the
  value's own shape. The two broadest, `generic-secret-assignment` and
  `secret-key-assignment`, need a value of at least 8 bytes. The others set
  lengths of their own, down to a single byte for `mysql-cli-password` and
  `registry-login-password`.
- **The redactor**: the code that applies the rules to output before a
  surface emits it.
- **In flight**: text at the end of the output so far that could still become
  a match once more bytes arrive, such as `ghp_` followed by half a token.
- **Withholding**: a cursor read stops before in-flight text, and reports
  `held_back: true` with `held_back_cause: "in_flight_secret"`. The next read
  from `next_cursor` resumes there.
- **`[REDACTED:unresolved]`**: a mask over bytes a read could not decide.
  That means something that began like a secret whose end the read could not
  see, or private-key material it could not tie to a whole key. It can hide a
  real secret, and a later read may show the same bytes in the clear.

#### The contract: guarantees and best effort

**Tier 1: what Holdfast is built to guarantee.** Today only G1 holds, and
only with the raw paths it names. G3 holds in part, G2 and G4 are not built,
and G5 is not claimed. Each row states its status.

| Clause | What it promises | Status today |
|---|---|---|
| **G1. Routing** | Every byte that reaches an agent or an observer comes from the redactor, except through the raw paths named below. | **Holds**, with the raw paths listed under G1. |
| **G2. Known values** | A secret whose exact value Holdfast knows is masked wherever it appears, within a published scope. | **Not built.** Known gap: `printenv`. |
| **G3. Write gate** | Holdfast writes a secret into a session only at a real secret prompt, or on a human's explicit override. | **Partial.** The gate refuses a shell sitting at its own prompt when the shell's OSC 133 markers show it. It still admits a REPL's prompt and a line-editing shell with no markers, because both have echo off (GH #262). |
| **G4. One verdict per byte** | Once Holdfast has decided whether a byte is shown or masked, every surface and every later read give the same answer. | **Not built.** Each read decides on its own. |
| **G5. Bounded withholding** | Nothing is withheld indefinitely. | **Not claimed.** One indefinite hold is known. |

**Tier 2: best effort.** The pattern rules protect against *accidental*
disclosure of secret-shaped values. They are not a guarantee that no
credential reaches an agent's transcript.

The [residual register](#residual-register) lists every known case in which
output leaks past the redactor or is masked when it should not be.

#### G1. Routing: holds, with named raw paths

**What is redacted.** Every surface that reports a session passes the text it
takes from the session through the redactor. That covers:
- every MCP tool result;
- the buffer resource;
- `holdfast logs`;
- a `holdfast watch` stream;
- the audit log;
- the daemon's own log.

The routing points are few. Every tool call reaches the same handlers,
whether through the daemon or in-process. Every byte-stream read goes through
one function. The attach protocol builds output frames in two places, and
both pass through one function, which redacts for every role but
`Interactive`.

The surfaces do not apply the redactor equally:

- **Byte-stream reads.** `read_output`, the `holdfast://session/…/buffer`
  resource, `holdfast logs`, and the text that `wait_for_pattern` and
  `send_input(wait_for:)` return all share one pipeline
  (`Session::read_processed`).
  - **The window.** Matching runs over a window from 512 bytes before the
    requested range to 8192 bytes past its cap. Those are the defaults of
    `redaction_lookbehind_bytes` and `redaction_lookahead_bytes` in the
    `[limits]` config section. The window covers the raw bytes and every
    text stream the read can emit.
  - **Straddling secrets.** A secret that straddles the start of a page is
    found if it begins within the lookbehind. One that straddles the end is
    found if it ends within the lookahead. A token longer than the
    lookbehind, such as a 1 KB JWT, is missed by a read that begins more
    than the lookbehind into it (R18).
  - **The lookbehind is not checked to be nonzero.** Set to 0, a read finds
    no secret that straddles the start of its page (GH #171).
  - **Private keys** are kilobytes long, so they get a longer reach. A
    complete key whose header lies up to 16 KiB (`UNVOUCHED_CARRY_BYTES`, a
    constant) before the first requested byte is found as well.
  - **Outside the reach.** A longer match, or one that opens further back, is
    outside it; see the [register](#residual-register).
  - **Withholding.** A cursor read also withholds in-flight text at the end of
    the output.
- **The observer stream** behind `holdfast watch` (attach role `Observer`).
  - It runs the same rules over the same set of text streams, with the same
    lookbehind (512 bytes by default).
  - After a private-key header whose block did not close, it keeps that
    header for up to 16 KiB, to recognise key-body lines that follow it.
  - It holds back in-flight text, carrying up to 8 KiB between PTY reads.
    If more than that is still unresolved at the end of a read, it sends one
    `[REDACTED:unresolved]` and drops what it held. It then drops all output
    until a PTY read ends with nothing in flight in the last 16 KiB, and
    drops that read too (R17). Dropped output is never sent to the viewer;
    it stays in the session's buffer for a cursor read.
  - At the end of a session it sends what it still holds, up to 8 KiB, with
    complete matches masked. An unfinished private key is masked; any other
    partial secret is sent in the clear (R6).
  - A viewer that joins part way through is seeded from up to 16 KiB before
    its join point (less if the session's buffer no longer holds it), so it
    judges the stream much as a viewer that had watched from the start
    would.
  - Its opening picture is the masked screen.
- **`get_screen_state`** masks the rendered grid:
  - complete matches over the joined rows;
  - private-key material;
  - cells written by bytes a cursor read would withhold, as
    `[REDACTED:unresolved]`.

  A token whose first characters have scrolled above the top row is not
  matched. Only private keys are followed off screen.
- **Metadata** is redacted as a string: complete matches only, with no
  window. This covers `prompt.last_line`, the window title,
  `get_command_history`'s commands, the `command` and `args` that `status`
  and `list_sessions` report, and the prompt text shown to a human asked for
  a secret.
  - `prompt.last_line` is emptied while a read would withhold.
  - A partial token in a window title is not caught (GH #142).
- **The audit log and the daemon log** redact every string, map keys
  included.
  - They always use the full built-in rule set. An operator's
    `disabled_redaction_rules` narrows what a client sees, never what the log
    records.
  - Matches must be complete.
  - Neither log records session output.
  - `[security] redaction_enabled = false` is refused at load; it is not a
    switch.

**Raw paths.** Each of these hands out session output without the redactor,
or reveals something about output the redactor masked:

1. **Interactive `holdfast attach`.**
   - An attach connection in the `Interactive` role receives every byte the
     PTY produces from the moment it joins, raw. That client *is* the
     terminal, and it has to render the escape sequences a marker would
     replace. Only its opening picture is masked.
   - Only the daemon's own user can connect: the socket is mode `0600`, and
     the peer's uid is checked.
   - Every connection is recorded in the audit log.
   - `holdfast watch` connects as an `Observer` instead, and that role is
     redacted.
2. **`redact: false`.** It is accepted by `read_output`, by
   `get_screen_state` and by the buffer resource (`?redact=false`).
   `holdfast logs --raw` is `read_output` with `redact: false`.
   - It turns off every mask and the in-flight withhold, and returns any
     secret in the text.
   - Each call writes a `redaction_disabled` audit entry naming the session,
     the tool and the kind of client, with a running count. The entry records
     no range and no content.
   - The daemon does not start without its audit log. `holdfast mcp
     --no-daemon` starts without one if it cannot open it, and then records
     nothing. On either, a write that fails later is reported once as a
     diagnostic, and the read goes ahead.
   - It is audited, not gated.
   - A withheld partial has to be reachable somehow. This is one way; a tail
     read is the other.
3. **`tail_bytes` and `tail_lines` reads skip the in-flight withhold.**
   - A tail read returns in-flight text that starts in the last 512 bytes
     (the default of `partial_secret_scan_bytes`) as far as it has arrived.
   - Every complete match that begins within the lookbehind before the
     read's start, and every other mask, still applies. A token longer than
     the lookbehind, which began further back, comes back in part (R18).
   - A tail read that passes `apply_holdback: true` keeps the withhold.
     `holdfast logs --tail` always passes it. Against a daemon too old to
     honour it (protocol below 1.4, which a `v0.0.7` daemon still running
     after an upgrade is), it reads through cursor reads instead, which
     keep the in-flight withhold, and says where they stopped if they end
     short of the head.
4. **`wait_for_pattern` and `send_input(wait_for:)` match the agent's
   regular expression against unredacted bytes**: the raw stream, and a copy
   with escape sequences removed.
   - The text they return is redacted, but `matched` and `match.offset` are
     not.
   - So an agent can learn whether masked output matches a pattern of its
     choosing, and where, one guess per call.
   - Unlike `redact: false`, this is not audited.
   - Measured: by matching one character class at a time, an agent recovered
     a masked 40-character token in about two hundred calls.
   - A token longer than the lookbehind takes one call. `match.text` is
     redacted over a window of its own, which starts one lookbehind before
     the match. So a match that begins further than that into the token
     returns that part of it raw, while the same response's
     `output_since_start` masks it (R18).
   - Redaction guards against accidental disclosure. It is no barrier to an
     agent that sets out to read a secret, which `redact: false` would hand
     over anyway.
5. **`start_session(prompt_patterns:)`** scores the agent's own regular
   expressions against the unredacted last line of output. The score comes
   back as `prompt.pattern_score`, and through `confidence` and
   `interaction_mode`. It is a second guess-per-call oracle of the same kind.
6. **Session metadata that is not redacted.** This is the caller's own words,
   or the operator's for a profile session, rather than output:
   - `start_session`'s result echoes the command it started and the working
     directory;
   - its `spawn_failed` error echoes the command;
   - `resources/list` labels each session with its command (GH #175);
   - a session's `name` is shown verbatim everywhere.
7. **Raw offsets.** `cursor`, `next_cursor`, `bytes_returned`,
   `match.offset` and `get_command_history`'s output spans count raw bytes.
   Set beside the text a read returns, they disclose how long each masked
   region is.

**Outside Holdfast.** Holdfast redacts only what an agent reads *through
Holdfast*:
- An agent that also has another way to run commands can run any command
  without Holdfast. Claude Code's own Bash tool is one such way. Nothing
  Holdfast does redacts that tool's output.
- What the agent itself sends is in its transcript already, because the agent
  wrote it. That includes `send_input`'s `data`, `start_session`'s `env`,
  and a regular expression it waits on.

#### G2. Known values: not built

**Nothing masks a value because Holdfast knows it.** Redaction today is by
rule only.
- A secret Holdfast handles itself, such as a value a human submits through
  `request_secret_input` or one a provider resolves, is protected by never
  being placed where a surface reads.
- It travels in a type that cannot be serialised or copied, is zeroed when
  dropped, and reaches nothing but the PTY write. Some transient copies on
  the way in are not zeroed yet (GH #82 to GH #86).
- If the child then prints it, only the pattern rules stand between it and
  the agent.

**Known gap: `printenv`.** A session's environment is not registered
anywhere.
- A session the daemon starts for an MCP client starts from that client's
  **whole** environment: the one the client launched `holdfast mcp` with.
- A `--no-daemon` session inherits the server's own environment. A profile
  session starts from the daemon's.
- MCP clients can put credentials in the environment of the servers they
  launch.
- `printenv NAME` prints the value of any variable in that environment. A
  value with no recognisable shape comes back in the clear with
  `redactions: {}`, even when the variable's name says it is a secret, as in
  `MY_SERVICE_TOKEN`.
- Measured with a 32-character random value in `MY_SERVICE_TOKEN`:
  `printenv MY_SERVICE_TOKEN` and `echo "$MY_SERVICE_TOKEN"` return it in the
  clear. `env | grep MY_SERVICE_TOKEN` is masked, because a label rule sees
  `NAME=value`.
- This is not fixed yet (GH #253).

**Planned, not shipped.** The scope planned for this clause is:
- **What is registered:**
  - values Holdfast wrote into a session, or resolved for one, of at least 6
    bytes;
  - values of environment variables whose names mark them as secrets
    (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_PAT`,
    `*_CREDENTIALS`), of at least 8 bytes and neither a boolean nor all
    digits.
- **Which spellings are masked:** raw, ANSI-stripped, base64 at each of the
  three alignments, URL-encoded and JSON-escaped.
- **When:** registered at session start, or before the write. Registering
  re-judges the output Holdfast still holds, but bytes already returned
  cannot be recalled.
- **Not covered:** a value the terminal wrapped at its right margin while
  echoing it, any other transformation, and shorter values.

It also means keeping written values in memory for the life of the session.
Today they are discarded as soon as they are written.

#### G3. The write gate: partial

**What exists.** Holdfast writes a credential into a session only when two
tests pass. This applies to both production paths that write one:
- a human's answer to `request_secret_input` from an attached client;
- a value that an operator-configured secret provider resolves.

Both tests run on the writer thread one statement before the write
(`write_secret_if_unread`, `crates/holdfast-core/src/session/mod.rs`). The
terminal's state is sampled once at that moment, not read from a cache.
The shell's markers are read as the output reader has scanned them by
then. A refused value is zeroed without reaching the PTY.
1. **The child's terminal has echo turned off.** A backend that cannot
   report the terminal's state is refused in the same way.
2. **The session's shell is not sitting at its own prompt** (GH #262). The
   shell reports this with its OSC 133 markers: Holdfast's own integration
   for bash, zsh and fish, or an integration the shell already carries.
   The write is refused when all of these hold:
   - no command has started since the shell's last prompt marker;
   - the shell still holds the terminal;
   - the terminal is not in the shape of a secret line read, which is echo
     off with canonical (line-at-a-time) input on. No line editor reads
     that way, and a shell's own `read -s` does. This exception lets
     `read -s` through where the markers never say a command started:
     bash older than 4.4, such as macOS's `/bin/bash` 3.2, and an
     integration that marks only the prompt.

`request_secret_input` asks the second question before it asks anyone. At
an idle shell prompt it answers `secret_cancelled` with reason
`at_shell_prompt`. No human is asked to type, no provider runs, and nothing
is audited, because nothing was requested. It asks again just before it
raises the request, after any provider has run. If the shell returns to
its prompt later, for example because the command that asked has ended,
the writer refuses the answer with the same reason, while the request is
still open. Once it has closed, `holdfast attach` discards what its human
goes on typing, up to Enter, rather than send it to the session as
keystrokes, which a shell at its prompt would draw, run and save.

**Why the second test is needed.** Echo off is not the same thing as a
password prompt. Line editors such as bash's readline and zsh's zle turn
echo off and draw the characters typed at them themselves. Before the
second test, a secret submitted while a shell sat idle at its prompt
passed the gate. Then:
1. the line editor drew it, so it reached the session's output and the
   attached human's own terminal;
2. it ran as a command when the newline that Holdfast appends by default
   arrived;
3. it could be saved to the shell's history.

GH #262 measured this end to end for bash, zsh and the Python REPL, on both
write paths. On the provider path, with a binding that asks for no
confirmation, no human took part at all. One ordinary agent mistake is
enough to get there: bash's `read -s -p` fails in zsh and leaves the
session at its prompt.

**What it still admits.** The second test is an interim guard, and it sees
only a shell whose markers arrive. These still pass on echo alone:
- **a REPL**: Python, Node, a database client, or any other line editor
  that is not a shell;
- **a line-editing shell whose integration is off**: a session started
  with `shell_integration: false`, a shell Holdfast does not integrate
  (`ksh`, `mksh`, `tcsh`), a nested shell started inside the session, or
  one reached with `exec`, and a session whose rc makes `PS1` or `PS0`
  readonly (the snippet then installs nothing) or reads the terminal at
  start-up (H12). `sh` and `dash` echo at their prompt, so the echo test
  refuses them unless a human sends `--allow-echo`;
- **a shell whose markers stop at its prompt**: an rc that assigns
  `PROMPT_COMMAND` and is sourced again in the session, or makes it
  readonly and regenerates `PS1` from it. Each leaves the idle prompt with
  no `A`, `B` or `D` after the last `C` (measured, bash 5.2; GH #281);
- **a remote shell under `ssh`**, unless the remote shell emits the
  markers itself;
- **a prompt the reader has not scanned yet**, for as long as the reader
  takes to see the markers the shell has just printed.

A secret submitted at any of those idle prompts is still drawn, run and
saved as above. Two more cases are admitted with a different outcome:
- **a shell with no line editor whose terminal a program left with echo
  off**, such as `bash --noediting` after an interrupted `stty -echo`. Its
  prompt reads exactly like a secret line read. The value is not drawn,
  but it is run as a command and saved to history;
- **a full-screen program with echo off**, such as an editor. The value
  goes into that program's own input, for example a vim buffer in insert
  mode, which `get_screen_state` shows.

**What it refuses that it should not.**
- **A secret prompt from a remote shell under `ssh -t` whose integration
  marks only the prompt.** `ssh` holds the local terminal in raw mode, so
  the secret-line-read exception cannot see the remote read, and the
  remote shell's prompt marker is still the last one. No override reaches
  it.
- **A request made in the same instant as the command that asks for the
  secret.** Until the shell has read the command line, it is still at its
  prompt. Measured: 2 of 3 calls made with no gap were refused, and none
  with a gap of 5 ms or more. The refusal tells the agent to wait for the
  password prompt and call again, and that call succeeds.

**What it does not refuse.** A command that is reading the secret:
- `read -s`;
- `sudo` and `getpass`;
- a program running in the foreground in its own process group, such as
  `ssh -t` at a remote password prompt when the remote shell emits no
  markers or all of them.

They read after the shell's "command started" marker, or while another
program holds the terminal, or, for the shell's own `read -s`, as a secret
line read.

**The planned fix** makes the gate use the classifier's own predicate.
That predicate is what reports `interaction_mode: AwaitingSecret`: echo
off, the terminal still in canonical mode, and no bracketed paste
(`crates/holdfast-core/src/detect/detector.rs`). It needs a per-submission
override for the human, because on its own it refuses real password
prompts that run in raw mode, such as `ssh -t` (GH #262).

**The human override.** `holdfast attach --allow-echo` skips the echo test
for that connection:
- It is a human's decision at an attached terminal, and it reaches no tool
  argument.
- It is `false` when absent, so a client that predates it fails closed.
- It exists for programs that ask for a code without ever clearing echo.
- Under it, the value is still masked on the human's own terminal. It
  still lands in the session's output, where only the pattern rules can
  catch it.
- **It does not skip the shell-prompt test.** It accepts that a secret
  prompt echoes, and an idle shell is not a secret prompt: the value would
  be run and saved to history, not only shown.

**Open issues.** Three leave gaps between the gate's check and the child's
read:
- bytes already queued ahead of the credential and not yet read by the child
  (GH #43);
- a `send_input` write that does not go through the writer's queue (GH #47);
- a terminal auto-reply that the autofill's write counter does not see
  (GH #158).

#### G4. One verdict per byte: not built

**Each surface decides what to show on its own**, every time it is asked,
over its own window of the output, and nothing records a decision once it is
made. So:
- **Surfaces can disagree about the same bytes at the same moment.** A
  `read_output` page, the grid and a `watch` stream each judge a window of
  their own.
- **The answer can depend on how the bytes are read.** The same bytes can be
  shown or masked depending on where a read starts and how large its
  `max_bytes` is.
- **A mask can lift later.** A region masked `[REDACTED:unresolved]` on one
  read can come back in the clear on a later one, once more output shows it
  was not a secret. That is by design.

The register lists the measured cases. A design in which each byte is judged
once, and every surface renders that single verdict, would close them by
construction. Whether to build it, or to go on fixing cases one at a time, is
an open question in [ROADMAP.md](./ROADMAP.md).

#### G5. Bounded withholding: not claimed

**Neither quiet nor the child's exit releases a withheld read.**
- A program that stops after text that could begin a secret leaves every
  cursor read held at that point until more output arrives. After the child
  exits, no more will.
- The text stays reachable through the audited `redact: false`, and through
  a `tail_*` read (see G1).
- `holdfast watch` does the opposite at the end of a session: it releases
  what it was still holding (R6 in the register).

A bound is planned and not built: mask such text once the session has been
quiet for a set time, and at exit.

**Known indefinite hold.** A prompt that ends in a secret label with no value
after it, printed by a program waiting on input, is held.
- In bash, `printf 'Enter password:'; read -r x` leaves every cursor read
  stopped at `password:` (the read ends at `Enter `), for as long as the
  program waits, with:
  - `held_back: true`;
  - `prompt.last_line` empty;
  - `interaction_mode: Executing`.
- `Password:` and `API_KEY=` behave the same. With a trailing space
  (`Password: `), nothing is held.
- The planned fix starts a label rule's hold at the first byte of the value,
  not at the label.
- See R14 in the register (GH #255).

#### Tier 2: the pattern rules (best effort)

The rules recognise *secret-shaped* values:
- token formats with a distinctive prefix (`ghp_`, `sk-ant-`, `xoxb-`, `AKIA`);
- private-key blocks;
- JWTs;
- passwords inside connection strings, URLs and authorization headers;
- values after secret-named labels.

A read matches them over every text stream it can emit: the raw bytes, the
ANSI-stripped text, and each of those with control characters dropped.
Matches are mapped back to raw offsets. So an ordinary colour change that
lands inside a secret, as `grep --color` produces, does not hide it.
Withholding in-flight text is best effort in the same way.

This tier guards against **accidental** disclosure. It is defence in depth,
not a guarantee that no credential reaches an agent's transcript. It does not
claim to catch:

- **A secret with no recognisable shape and no label.** Examples are a
  passphrase such as `correct horse battery staple`, or a password printed on
  its own.
- **A value shorter than 8 bytes after a generic label** (`PASSWORD=hunter2`).
  The two broadest label rules have that floor because without it ordinary
  text such as `token: default` and `password: example` would be masked.
- **An escape sequence deliberately planted inside a secret** to break the
  match (GH #51). A program in the session is inside the trust boundary.
- **A label spelled with a Unicode character that case-folds to an ASCII
  letter**, such as U+017F (`ſ`, which folds to `s`) or U+212A (the Kelvin
  sign, which folds to `k`).
- **A terminal that acts on 8-bit C1 control codes (bytes `0x80`–`0x9F`)
  inside UTF-8 text.** Holdfast handles those bytes conservatively, but
  claims nothing for such a terminal.
- **The payload of an operating-system command (OSC) sequence**, such as a
  clipboard write, which a terminal does not show as text.

#### Residual register

This table, with the list after it, covers every known case in which output
gets past the redactor through something other than a raw path named under
G1, and every known case in which the redactor masks or drops output that is
not a secret.

- Each row was measured on the tree this file describes.
- Every repro uses generated values. Never test with a real credential.
- A *key* below means a PEM private-key block (`-----BEGIN RSA PRIVATE
  KEY-----`, random base64 lines of 64 characters, `-----END …`). The largest
  standard key, RSA-16384, is about 12.6 KB of PEM.
- Row numbers are stable. A fixed row stays in the table, marked fixed, so a
  reference to it keeps its meaning.

| ID | Leaks or over-masks | Trigger | Repro sketch | Status | Can a targeted fix close it? |
|---|---|---|---|---|---|
| R1 | Both: a document's masking depended on the page size it was read at | Paging the same output at different `max_bytes` | `cat` a long document that mentions a private-key header in prose; page it at 4 KiB, 32 KiB and 256 KiB | **Fixed for prose** (GH #242). A header in prose starts a candidate that ends at the first character that cannot be part of a key, so the mention itself masks nothing. This repository's `CHANGELOG.md` now masks the same lines at every page size, all of them rule matches on credential-shaped examples. Lines after such a header can still be over-masked: R19. Keys longer than 16 KiB still depend on page size: R2–R4 | Done for prose. For long keys, see R2–R4 |
| R2 | **Leaks** the later lines of a complete key, with `redactions: {}` | A single key block longer than somewhere between 24 KiB and 16 KiB + `max_bytes` + 8 KiB, depending on where the pages fall, paged with cursor reads; or a tail read that starts more than 16 KiB after the header of a key longer than 16 KiB. On `holdfast watch`, any complete key longer than about 16 KiB | Generate a 500-line key, `cat` it, and page from before the `cat` at `max_bytes: 4096`: 249 of body lines 248–499 come back raw, counting lines from 0; the lines that straddle a page seam are masked. A 1,000-line key leaks 750 lines at the default 32 KiB | **Narrowed** (GH #243): every standard key size is masked at every page size, and so are blocks up to 26 KB at 4 KiB and 8 KiB pages. Longer blocks: open, GH #259 | Partly. A longer reach moves the bound; no fixed reach removes it |
| R3 | **Leaks** key body more than 16 KiB past the header | A key block with no END line, longer than 16 KiB, followed by other output | Print a header and 300 body lines with no END, then `echo done`; page from before at 4 KiB or 32 KiB: body lines 248–299 come back raw | **Narrowed** (GH #242), from 114 lines at 4 KiB and all 300 at 32 KiB. Open, GH #259 | Partly. The 16 KiB reach bounds what a header whose block never closes can mask, so a longer reach moves the bound without removing it |
| R4 | **Leaks** a whole key still arriving, `held_back: false`, `redactions: {}` | A read at the end of the output while a key's header is more than 16 KiB behind it | `cat` a 260-line key with no END, then `sleep 25`; read during the sleep: all 260 body lines raw, and 12 raw rows on the grid. At 245 lines (16.2 KB) every surface masks it | **Open**, GH #259. GH #166's own reproduction, a key of up to 50 lines, is masked now. The 16 KiB bound is deliberate: an unbounded search on every read is quadratic in output an agent controls | Only with an unbounded search at the end of the output on every read |
| R5 | **Leaks** a token glued to a word character in front of it, on every surface | A prefix rule's leading `\b` does not match after a letter, digit or `_`, with or without a colour change between them. So whether the token is masked depends on where a read's text starts | `printf 'x\033[31mghp_%s\033[0m done\n' <36 random alphanumerics>`: a cursor read from before it, a `tail_bytes` read, the grid and `watch` all show the token clear, and `read_output` reports `redactions: {}`. Plain `xghp_…`, `_ghp_…` and `9ghp_…` do the same. A read whose page starts exactly at the escape or at `ghp_` masks it. With a space instead of `x`, every read masks it | **Open**, GH #254 | The dependence on where a page starts, yes. Whether `xghp_…` should match at all is a rule decision, because the `\b` keeps rules from matching inside longer identifiers |
| R6 | **Leaks** on `holdfast watch` a partial secret still carried when the session ends | The child exits with a partial token unfinished at the end of its output, while a `watch` that saw it arrive is attached | With `watch` attached first, run `sh -c 'sleep 3; printf "deploy with ghp_0123456789abcdefghij"; sleep 2'`. While it runs, `watch` shows `deploy with `; at exit it prints the partial token raw, with no marker. A `watch` that joins after the `printf` prints neither. `read_output` goes on withholding it after the exit | **Open**, GH #256. A partial private key is masked at exit (GH #242). Bounded by what the stream still carries, at most 8 KiB | Yes |
| R7 | **Leaked** key body on the `get_screen_state` grid | A completed key whose header had scrolled off the screen, or a key still arriving | `cat` a 50-line key in a 40-row session, then `get_screen_state` | **Fixed** (GH #224). 0 raw rows for 50- and 200-line keys, after scrolling, at 40 to 80 columns, and while a key streams, up to 16 KiB. Beyond that, see R4 | Done |
| R8 | **Over-masked**: `watch` dropped about 30% of prose | A private-key header mentioned in prose held the observer stream | `holdfast watch` a session, then `cat CHANGELOG.md` | **Fixed** (GH #242). `watch` now receives every line `read_output` does, with no gap notice. For the drop after a long key, see R17 | Done |
| R9 | Both: surfaces disagreed about the same bytes at the same moment | Any output that one surface judges differently from another | Stream an 8-line key with no END, then `sleep 10`. Compare `read_output`, `watch`, `get_screen_state` and `status` within 0.1 s | **Narrowed** (GH #224, GH #242). All four now mask that key; the grid used to show 8 raw lines, and `prompt.last_line` a raw body line. A grep hit naming a key header, followed by a failing test log, now shows the failure on every default read with the secrets masked. Still open: R6, R16 | Surface by surface only, without G4 |
| R10 | **Leaks** a key painted one colour per character | `grep --color=always -n . key.pem` (or `--color=auto`, which colours on a PTY), `lolcat`. No `-----BEGIN` survives in the raw bytes, and the key grows about twenty-fold | Colour a 40-line key that way: the first default page carries 27 raw body lines with `redactions: {}`, and paging carries all 40. The grid shows 16 raw rows, or 38 with `start_session(screen_tracking: "on")`. A read of 64 KiB or more masks it. A 26-line key is masked | **Registered, not fixed** | Yes: look for key candidates in the ANSI-stripped text as well as in the raw bytes |
| R11 | **Leaks** a quoted label-keyed value that contains a `;` | A label-keyed value ends at `;`, and fewer than 8 bytes come before it | `echo "DB_PASS='Xk9;mP2qLzAB'"` comes back whole, with `redactions: {}`. With 8 or more bytes before the `;` (`'Xk9mP2qL;zAB'`), the part after the `;` is shown | **Registered, not fixed.** The 8-byte value floor is kept | Yes, by making the two broadest label rules read a quoted value to its closing quote. That is a larger change to those rules |
| R12 | **Over-masks** a type name after a secret-named label | A CamelCase value after `secret`, `token`, `api_key` and the like, as in Rust signatures and struct fields | `rg -n secret crates/holdfast-core/src/session \| head -60` masks 6 of 60 lines, all of them `secret: SecretBytes`. `token: TokenKind`, `api_key: ApiKey256`, `let token = uuid::Uuid::new_v4(` and digit-bearing types are masked too | **Registered, not fixed**; GH #245 stays open. For Rust-heavy work an operator can list `generic-secret-assignment` in `[security] disabled_redaction_rules` | Not without a cost. Nothing in the value tells `SecretBytes` from a capitalised passphrase with no separator. Keying on the byte after the value would stop masking `password=Hunter2hunter, user=bob`, and a stoplist of type suffixes would stop masking `JWT_SECRET=MySuperSecretKey` |
| R13 | **Leaks** the value of a secret-named environment variable | `printenv NAME` or `echo "$NAME"`, where the value has no recognisable shape | `start_session` with `env: {"MY_SERVICE_TOKEN": "<32 random lowercase alphanumerics>"}`, then `printenv MY_SERVICE_TOKEN`: the value comes back clear, with `redactions: {}`. The same happens when the variable is only in the environment of the client that launched `holdfast mcp`. `env \| grep MY_SERVICE_TOKEN` is masked by a label rule | **Open**, GH #253. See G2 | Yes: G2's environment-name registration |
| R14 | **Withholds indefinitely** a prompt a program is waiting at | A secret label ending in `:` or `=` with no trailing space, printed by a program waiting on input: `Enter password:`, `Password:`, `API_KEY=` | In bash, `printf 'Enter password:'; read -r x`. Cursor reads stop at `password:` (the read ends at `Enter `) with `held_back: true` and `held_back_cause: "in_flight_secret"`; `prompt.last_line` is `""` and `interaction_mode` is `Executing`, for as long as the program waits. A `tail_bytes` read shows the prompt. `Password: `, with a trailing space, is not held | **Open**, GH #255 | Yes: start a label rule's hold at the first byte of the value, not at the label |
| R15 | **Leaks** part of a credential that arrives with an escape sequence inside it | The in-flight test reads raw bytes, and an escape ends the run it is testing | `printf 'ghp_%s\033[0m%s' <17 alphanumerics> <18 alphanumerics>` (39 of a GitHub token's 40 characters), then a cursor read: the default, ANSI-stripped read returns all 39 characters together, with `held_back: false` and `redactions: {}`. On `watch` a token split across two PTY reads with an escape inside it does the same, and that happens more often, because the unit is one PTY read | **Open**, GH #142 and GH #160. The grid masks this case. At most one character short of the rule's minimum length: 39 for a GitHub token | Needs a sharper in-flight test. The form that has been tried withholds ordinary output indefinitely |
| R16 | **Leaks** one line of key body in `prompt.last_line`, and goes on leaking it after the command ends | A key still arriving whose last body line has no line break yet | Print a header and 7 body lines with no END, then an eighth body line with no `\n`, then `sleep 10`. `status`, `list_sessions` and the `prompt` block of every response that carries one (`read_output`, `wait_for_pattern`, `send_input`, `interrupt`, `request_secret_input`) report that line raw. Once the shell prints its prompt, `last_line` is that line followed by the prompt. If the child then asks for a secret, the prompt text sent to attached clients is built from the same line, with only complete matches masked. Every byte-stream surface and the grid mask it | **Open**, GH #257 | Yes: report no last line while a read masks the region it lies in |
| R17 | **Over-masks**: `watch` silently drops output that follows a long key | Output that arrives in the same PTY read as the END of a key, once `watch` has begun dropping output because more than 8 KiB of the key was unresolved at the end of an earlier read. How the output splits into PTY reads decides that, so it is timing-dependent | `printf 'before\n'; cat key.pem after.txt` with a 200-line key, a 30-line `after.txt` and `watch` attached: in 2 runs of 2, `watch` received 3 and 0 of the 30 lines, with no gap notice, while `read_output` showed all 30. As two commands, `cat key.pem; cat after.txt`, it dropped lines in 2 runs of 6. No run with a key under 8 KiB dropped anything | **Open**, GH #258 | Yes: emit the rest of the read once the key has been judged |
| R18 | **Leaks** the tail of a token longer than 512 bytes, such as a JWT | Every rule but the private-key rule is judged over a window that reaches only the lookbehind (512 bytes by default) behind a read's start. So a read that begins more than that into a long token misses it: a `tail_bytes` read, `wait_for_pattern`'s `match.text`, a read from an arbitrary `since_cursor`, or the cursor read after one that saw the token partly arrived | `cat` a generated 1,027-byte JWT, then `read_output(tail_bytes: 400)`: the last 310 characters of the signature come back raw, with `redactions: {}`, with or without `apply_holdback: true`. `tail_bytes: 600` masks them. `wait_for_pattern(pattern: "[A-Za-z0-9_-]{300}\r\n")` returns 300 signature characters raw in `match.text` in one call, while the same response's `output_since_start` masks them. Print 600 bytes of the token, pause, then print the rest: the first cursor read masks what has arrived as `[REDACTED:unresolved]`, and the next returns the rest of the token raw. With 300 bytes before the pause, the token is held and then masked | **Open**, GH #261 | Yes: give token rules the backward search that private keys have |
| R19 | **Over-masks** hex digests and base64 lines after a mention of a private-key header | A line that names a whole `…PRIVATE KEY-----` header without being a key, such as a `grep` hit, a code literal or a test fixture's name. Up to 16 KiB past the header, every line with a run of 48 or more base64-alphabet characters (letters, digits, `+`, `/`, `=`) is masked as `[REDACTED:unresolved]`: SHA-256 hex digests, the base64 part of a `sha512-` integrity string, base64 blobs. A 40-digit git object id is too short to qualify | `grep` a file for `-----BEGIN RSA PRIVATE KEY-----`, then run `sha256sum` over twelve files: all 12 digest lines are masked on the default cursor read, on a 1 KiB page and on the grid. Only `redact: false` shows them, and it also shows every real secret in the window | **Open**, GH #260 | Partly. Refusing hex-only runs and `sha256-`, `sha384-` and `sha512-` prefixes closes digests and integrity strings. A base64 blob has the alphabet of key body, and stays masked |
| R20 | **Leaks** the tail of a recalled command in `get_command_history`, reported as complete | A line editor that answers a carriage return by moving the cursor forward past the prompt, which resumes inside the command, as bash does for history recall and fish does while typing. The capture discards the row, and the entry keeps only what was written after the resume, with `truncated: false`. A secret whose label or prefix sat before that column comes back as a bare tail that no rule matches | In bash, run `echo short`, then press Up, Up, Down, Enter: the entry reads `short` with `truncated: false`. fish typing `echo hello world` key by key records `d` | **Open**, GH #271 | Yes: treat the motion as resuming inside the command, or report `truncated: true` whenever a carriage return discards text no later write replaced |
| R21 | **Leaks** a token that zsh's wrap redraw splits, on `read_output`; and records a long command as `[REDACTED:unresolved]` or as a tail reported as complete in `get_command_history` | A command line wider than the terminal under zsh, which redraws it at the right margin with ` \r\e[K<char>\r`. That puts a space and two carriage returns inside a token straddling the margin, and the history capture reads the `\r` after the autowrap as a return to the start of the line. At the default 120 columns this is an ordinary long command | In zsh, type a fake `AKIAIOSFODNN7EXAMPLE` so that `AKIAIOSF` ends the first row: `read_output` returns both halves raw with `redactions: {}`, where bash returns `{aws: 1}` and fish `{aws: 2}`; `get_screen_state` masks it. A 112-character pipeline or a 115-character `echo` at 120 columns, under `zsh -f` or an empty `.zshrc`, is recorded as `[REDACTED:unresolved]` with the right exit code. When the second row is at least as long as the dropped front, the tail passes the truncation check and is reported as the whole command | **Open**, GH #276. Not a regression: v0.0.7 does the same | Yes: pass the session's columns to the scanner, so a `\r` past the width returns only to the current row, which fixes the history entry; and normalise the same redraw in the redactor's input, which fixes the split token |

**Known, filed, and not yet a row.** Each of these is a leak:
- **A partial token in a window title.** Metadata is matched for complete
  secrets only, so a title of `deploy ghp_` and 20 more characters of a token
  is reported raw by `status` (GH #142). A complete token in a title is
  masked.
- **A token whose first characters have scrolled above the top row of
  `get_screen_state`'s grid** is not matched there. Only private keys are
  followed off screen.
- **Two rules are never withheld in flight:** `telegram-bot-token`, which
  has no prefix to hold on (GH #170), and the `api-` form of
  `launchdarkly-key`, which its declared prefixes leave out (GH #189). A
  cursor read returns either one as far as it has arrived.
- **`redaction_lookbehind_bytes = 0` is accepted at load** (GH #171). A read
  then matches nothing that began before its range, so a secret that
  straddles the start of a page comes back raw, with `redactions: {}`.

#### Shell history

**By default, a session's shell writes nothing to the history files under
`$HOME` (GH #252).** Without a policy, the agent's commands, a secret typed
at a readline prompt, and Holdfast's own integration snippet all reached
the operator's history. That happened on `exit`, on EOF, on the hangup that
a graceful `terminate`, `holdfast daemon stop` or a daemon crash delivers,
and after every command under common bash and zsh configurations. Four
mechanisms prevent it:

- **The environment.** Every session starts with these variables:
  - `HISTFILE=/dev/null`;
  - an empty `fish_history`;
  - a zsh `HISTORY_IGNORE` that matches the line Holdfast types;
  - the history files of common REPLs and database clients switched off:
    `PYTHON_HISTORY=/dev/null`, `NODE_REPL_HISTORY=` (empty),
    `TS_NODE_HISTORY=` (one space), `PSQL_HISTORY=/dev/null`,
    `MYSQL_HISTFILE=/dev/null`, `MARIADB_HISTFILE=/dev/null` and
    `SQLITE_HISTORY=` (empty). On Windows `PYTHON_HISTORY` and
    `PSQL_HISTORY` are `nul`, because a native program opens `/dev/null`
    as `\dev\null` on the current drive;
  - `SHELL_SESSIONS_DISABLE=1`, for macOS Terminal's per-window zsh
    history;
  - for a bash or zsh session with shell integration,
    `HOLDFAST_BASH_INTEGRATION` or `HOLDFAST_ZSH_INTEGRATION`, which
    carries the integration snippet to the line Holdfast types and is
    unset by that line; a call's `env` cannot replace it. It fails to
    reach the shell when an rc re-execs it through `env -i` or `env -u`
    or defines its own `eval` function or alias, and is expected to for
    WSL's `bash.exe` started from native Windows (not measured), and such
    a session gets neither integration nor the snippet's half of this
    policy. An rc that reads the whole line at start-up (H12) leaves the
    variable set for everything the session starts.

  A call's own `env` overrides any of them but the last. `SQLITE_HISTORY`
  is empty rather than `/dev/null` because libedit `fchmod`s the history
  file it saves to `0600`, which as root would change `/dev/null` itself.
  node's value is empty rather than `/dev/null` because node 24 and later
  print *Could not open history file* at every REPL start when it is a
  device. ts-node treats an empty value as its default file, so it gets a
  space, which node trims to empty. MariaDB 11 reads `MARIADB_HISTFILE`
  before `MYSQL_HISTFILE`, and 10.x reads only the second, so both are
  set.
- **The integration snippet**, for bash and zsh. It begins with a space
  and runs after the rc files, and sets `HISTFILE` again. The value is
  `/dev/null`, or a `HISTFILE` the call set itself, which the snippet
  carries past the rc files in `HOLDFAST_HISTFILE`. It assigns
  `/dev/null` and does not unset the variable, for two reasons:
  oh-my-zsh and prezto re-arm an empty `HISTFILE` when the rc is sourced
  again, and a nested shell or `exec` does not inherit an unset one.
  In zsh it then cuts the history the shell has already read from the
  file the rc names to one entry, the line Holdfast typed (GH #274; see
  H10), and reads back only a file the session's own `HISTFILE` names. It
  cuts only where the rc appends to its file (`append_history`,
  `inc_append_history` or `share_history`): a zsh that saves by rewriting
  its file from the list would, once the agent sources the rc again,
  replace the operator's file with the session's commands. In bash it
  leaves the list the rc loaded whole. Emptied, that list is what an rc
  that runs `history -w`, sourced again, writes over the operator's file,
  and nothing the snippet can read at start-up finds every such rc. When
  `HISTFILE` is readonly, or in zsh `SAVEHIST` or `HISTSIZE`, it leaves
  the history variables and the list alone (see H1).
  In zsh it also sets `SAVEHIST=0` and unsets `hist_save_by_copy`. With
  `SAVEHIST` set by an rc, zsh saves at exit and locks first by creating
  `/dev/null.LOCK`. As any user but root that fails, and *zsh: locking
  failed for /dev/null: permission denied* appeared in the session's
  output at every `exit`, EOF and `exec zsh`. As root the lock succeeds,
  and under `unsetopt append_history` zsh wrote `/dev/null.new` and
  renamed it over `/dev/null`, leaving a regular `0666` file of the
  agent's commands (simulated as uid 0 in a user namespace).
- **fish's init command.** A fish that Holdfast starts runs a `-C` command
  after config.fish. It empties `fish_history`, and keeps it empty when
  configuration later re-points it or erases it. An erased `fish_history`
  is fish's default session, which reads the operator's history file and
  on fish 3.7 rewrites it. The command also exports `fish_private_mode` at
  the first prompt, so any fish started inside the session saves nothing.
  It is not applied if the call's `env` sets a non-empty `fish_history`.
  That fish starts as a plain fish with the call's value, and a
  config.fish that sets `fish_history` overrides it. An empty value from
  the call is Holdfast's own default, and gets the init command.
- **No hangup for tcsh and csh.** A tcsh that receives a hangup saves its
  history, and no environment variable reaches its `savehist`. So
  `terminate` and `daemon stop` send tcsh and csh `SIGTERM`, which an
  interactive tcsh ignores, and then `SIGKILL` after the grace period.

**`[terminal] shell_history_file = "per_session"` keeps a record of what
the agent ran.** Each bash and zsh session appends every command to
`<log dir>/history/<session_id>.history`.
- The file is `0600`, and is always created new. It is never written
  through an existing file or link.
- It lives in a `0700` directory. The daemon refuses the directory if it
  is a symlink or belongs to another user.
- Holdfast never rotates or deletes these files, and **does not redact
  them**.

The record is kept for convenience; it is not an audit trail:
- The call's `env` can point `HISTFILE` somewhere else.
- The rc's own options decide what is recorded. For example, Debian's
  `HISTCONTROL=ignoreboth` and zsh's `hist_ignore_space` drop commands
  that begin with a space.
- zsh records a command when it is entered, not when it finishes.
- Anything in the list below that re-points `HISTFILE` takes the rest of
  the session's commands with it.
- An rc sourced again that sets `HISTFILESIZE`, or an rc that makes it
  `readonly`, which the snippet then cannot unset, truncates the file to
  that size when bash exits (measured for both: `HISTFILESIZE=3` left
  three lines).
- A `PROMPT_COMMAND` replaced mid-session removes the per-command append.
  Commands after that reach the file only if bash saves at exit or on a
  hangup, and then only the last `HISTSIZE` of them. `histappend`, which
  the snippet sets, is what keeps that save from rewriting the file and
  losing everything recorded before.

fish sessions keep nothing on disk in either mode, and get no per-session
file.

**What still reaches disk.** Unless marked otherwise, each item was
measured on bash 5.2, zsh 5.9, fish 3.7.0 and 4.9.3, tcsh 6.24, mksh R59c
and Python 3.12.

- **H1. A `HISTFILE` set after the snippet has run.** The snippet runs
  once, at the first prompt, and cannot follow a shell that changes the
  variable later. That happens when:
  - an rc that hard-sets `HISTFILE` is sourced again;
  - `exec bash` or a nested bash starts under such an rc;
  - `PROMPT_COMMAND` assigns `HISTFILE`;
  - `HISTFILE` is `readonly`, in bash or zsh, as audit-hardened rc files
    and every `rbash` make it, or in zsh `SAVEHIST` or `HISTSIZE` is. The
    snippet then leaves the history variables alone, so the rc's settings
    decide what is saved and where, and it leaves the history the shell
    read in memory (H10). The integration is unaffected: markers, exit
    codes and `get_command_history` work, and nothing is printed.
    Measured on bash 5.2 and 5.3 and zsh 5.9. A bash older than 4.4
    cannot test for it, and there the snippet's assignment still fails
    and takes the integration with it (not measured).

  The first case adds the session's commands to the operator's file. Where
  the rc rewrites that file from the shell's list, it keeps every entry the
  file held, because bash keeps the list its rc loaded (H10). Measured
  through Holdfast on bash 5.2 and 5.3, both modes, by `exit` and by
  hangup, sourced after another command, under `history -w` at the prompt,
  the `history -n; history -w; history -c; history -r` sync recipe, the
  `historymerge` function with its `EXIT` trap, an `EXIT` trap alone, and
  an rc that sets `history -w` only once it is sourced again: all five of
  the operator's entries survived every row. Emptying the list instead
  loses every entry under that last rc, and no reading of the shell at
  start-up can find it. What still loses entries:
  - on bash 4.3 and older, whose `history -n` counts the lines already in
    the list rather than those read from the file, the sync recipe and
    `historymerge` sourced again in `none` mode, whose prompt empties the
    list itself by reading back `/dev/null`: the operator's oldest entry
    after another command, and every entry as the session's first command
    (measured, bash 3.2.57, macOS's `/bin/bash`; 4.2 and 4.3 by their
    source; GH #282);
  - bash's own save at exit appends, unless the session has run more
    commands than `HISTSIZE` holds, when it rewrites the file from a list
    that holds only the newest of them.

  zsh's equivalent, an rc that saves by rewriting its history file, is
  left whole for the same reason (H10).
- **H2. A zsh started inside a session, or by `exec zsh`, under an rc that
  sets `HISTFILE` unconditionally.** macOS's `/etc/zshrc` sets one for
  every zsh, so on a Mac any nested or exec'd zsh writes `~/.zsh_history`,
  and a per-session record stops at that point.
- **H3. mksh under an rc that sets `HISTFILE`.** mksh has no Holdfast
  snippet, so only the environment reaches it. ksh93 honours
  `HISTFILE=/dev/null`, and mksh keeps no history file unless one is set.
- **H4. tcsh and csh ending by `exit`, EOF or a daemon crash.** Under an
  rc that sets `savehist`, as FreeBSD's default `.cshrc` does, tcsh
  writes `~/.history` in three cases: when it exits on its own, at EOF,
  and when the kernel hangs it up because the daemon died. This predates
  GH #252.
- **H5. A fish that Holdfast did not start.** This covers a fish started
  inside a bash or zsh session, and a fish started through a wrapper such
  as `env fish`, when its config.fish sets `fish_history`. Only the empty
  `fish_history` in the environment reaches that fish, and config.fish
  overrides it. A fish nested inside a fish that Holdfast started saves
  nothing, but see H10. The same holds for a fish whose call set a
  non-empty `fish_history`.
- **H6. The line Holdfast types, under a user-set zsh `HISTORY_IGNORE`.**
  The user's value replaces Holdfast's. So under `inc_append_history` or
  `share_history`, without `hist_ignore_space`, the line Holdfast types
  reaches the history file that the rc names. The agent's commands do
  not.
- **H7. REPLs that the environment does not reach.**
  - Python 3.12 and older ignore `PYTHON_HISTORY`, so their REPL writes
    `~/.python_history`. An empty `PYTHON_HISTORY` does not help either,
    because 3.13 treats empty as unset.
  - As root, a Python 3.13 basic REPL linked against libedit saves its
    history to `PYTHON_HISTORY=/dev/null` through libedit, which
    `fchmod`s it to `0600`, leaving `/dev/null` unwritable by every other
    user. Homebrew builds Python 3.13 on macOS against libedit
    (`--with-readline=editline`). There is no empty value to use instead.
    Reasoned from libedit's source; Linux's libedit made the same change
    to a pty device this uid owned. PyREPL, 3.13's default REPL, writes
    the file itself and changes no mode.
  - A `.psqlrc` that runs `\set HISTFILE` overrides `PSQL_HISTORY`,
    because psql reads the variable first. Read from psql's source.
  - PowerShell's PSReadLine keeps `ConsoleHost_history.txt` and reads no
    variable Holdfast sets. Not measured.
  - Any other program with its own history file that is not listed above
    keeps writing it. sqlite3 finds its default file through the password
    database, not `$HOME`, so only `SQLITE_HISTORY` keeps it off disk.
- **H8. macOS Terminal session history (not measured on a Mac).** Since
  GH #229, a session inherits `TERM_PROGRAM=Apple_Terminal` and
  `TERM_SESSION_ID` from a client started in Terminal.
  `/etc/zshrc_Apple_Terminal` then saves per-window history under
  `~/.zsh_sessions/`, whatever `HISTFILE` says.
  `SHELL_SESSIONS_DISABLE=1` is Apple's documented off switch for it, and
  every session gets it; nobody has confirmed on a Mac that it takes
  effect. `/etc/bashrc_Apple_Terminal`, which a login bash sources, does
  the same under `~/.bash_sessions/`, and it ignores the variable: only a
  `~/.bash_sessions_disable` file turns it off. Both files need
  `TERM_SESSION_ID`. Dropping that variable belongs with the other
  terminal-identity variables a session inherits from its client.
- **H9. zsh's `SAVEHIST` restored after the snippet has run.** The snippet sets `SAVEHIST=0` once.
  `source ~/.zshrc`, `exec zsh` and a nested zsh each run an rc that sets
  it again, and `HISTFILE` is still `/dev/null`, as with oh-my-zsh's and
  prezto's conditional line. As any user but root, zsh then prints
  *zsh: locking failed for /dev/null: permission denied* at exit and saves
  nothing. As root:
  - after `source ~/.zshrc`, `hist_save_by_copy` stays off, so zsh writes
    into `/dev/null` itself, which is harmless;
  - a zsh started by `exec zsh` or inside the session starts with zsh's
    default `hist_save_by_copy`. Under an rc that unsets
    `append_history`, it writes `/dev/null.new` and renames it over
    `/dev/null`. That leaves a regular `0666` file holding its commands,
    readable and writable by every user.

  So does any zsh started with `shell_integration: false`, which gets no
  snippet. Simulated as uid 0 in a user namespace with a regular file
  standing in for `/dev/null`: the exec'd and nested shells replaced it
  (new inode, the commands inside), and the re-sourced shell wrote into
  it in place.
- **H10. Reading the operator's history.** bash and zsh load the history
  file that an rc names as they start, before the snippet runs, and the
  session runs as the operator, so `cat ~/.bash_history` works as it
  always did. In zsh the snippet then cuts that list to one entry, the
  line Holdfast typed, so `fc -l`, up-arrow and `!!` offer only what was
  typed after it (GH #274; measured on zsh 5.9, in both history modes,
  under rc files that name a filled history file). What still offers the
  operator's history:
  - **every bash session.** The snippet leaves bash's list as the rc
    loaded it, so `history`, `fc -l`, up-arrow and `!!` offer the
    operator's entries, followed by the line Holdfast typed unless
    `HISTCONTROL` ignores a leading space. Emptied, that list is what an
    rc that runs `history -w`, sourced again, would write over the
    operator's file (H1). In `per_session` mode the session's file begins
    with the typed line, and a prompt or `EXIT` trap that runs `history
    -w` writes the whole list into it, the operator's entries included;
    an rc that only appends with `history -a`, or runs no history command
    at all, puts none of them there (measured, bash 5.2 and 5.3);
  - a bash or zsh started inside a session, or by `exec`, which loads the
    file its own rc names, where the agent can list and recall it;
  - a zsh whose rc turns off `append_history`, `inc_append_history` and
    `share_history`. Such a zsh saves by rewriting its file from the
    list, so after `source ~/.zshrc` a cut list replaced the operator's
    file with the session's commands (measured, zsh 5.9), and the snippet
    leaves its list whole instead;
  - a zsh whose `HISTFILE`, `SAVEHIST` or `HISTSIZE` is readonly (H1), a
    zsh with `shell_integration: false`, one the snippet's carrier does
    not reach, and one whose rc reads the terminal at start-up (H12),
    none of which get the cut.

  A fish nested inside a Holdfast fish session reads the history file its
  own config.fish names in the same way. It offers the lines as
  autosuggestions and lists them in `history`, and it can create an empty
  file where there was none. Measured on fish 3.7.0, 4.0.2 and 4.9.3. A
  fish that Holdfast starts reads nothing.
- **H11. A history recorder that an rc installs as a hook (GH #277).** atuin,
  zsh-histdb, mcfly and loggers built on bash-preexec run from a shell
  hook, such as a `preexec` function or zsh's `zshaddhistory`, and write
  each command to a store of their own as it runs. Nothing the
  environment or the snippet sets reaches that store, so every command
  the agent runs is recorded there, in either history mode and with
  `shell_integration: false`. Measured with bash-preexec 0.5.0, 0.6.0 and
  its master branch: a logger hooked through it wrote every agent command
  to a file under `$HOME`, whatever `HISTFILE` said. atuin itself was not
  measured.
- **H12. An rc file that reads the terminal at start-up (GH #278).**
  Holdfast writes its integration line as the session spawns, and the
  shell reads it as its first input. A `read` in `.zshrc`, oh-my-zsh's
  update question or zsh's new-user menu takes the line as its answer,
  and the snippet, with its half of the history policy, never runs.
  Measured on zsh 5.9 with `HISTFILE` and `SAVEHIST` set in `.zshrc`
  followed by a `read`: the agent's commands were written to
  `~/.zsh_history` on `exit`. bash 5.2 under the same `read` saved
  nothing. In bash and zsh the variable carrying the snippet is then
  never unset, and everything the session starts inherits it (measured,
  bash 5.2 and 5.3, zsh 5.9). fish's policy runs from `-C` and was not
  measured under an rc-time prompt. Such a session also keeps the
  history the shell read (H10).

#### The out-of-band secret channel

**`request_secret_input` asks for a secret without the agent ever holding
it.** It shipped in 0.0.7.
1. The agent calls it, and every attached client is told.
2. A human, or an operator-declared provider, answers.
3. The tool returns a status and a byte count: never the value, and never a
   handle that could be exchanged for one. The byte count is the number of
   bytes written, so it does disclose the value's length.

The value travels client → daemon → PTY, and it appears in no tool argument
and no tool result. That is a statement about the tool, not about the
session's output. Written at an idle REPL prompt, or at a shell prompt
Holdfast cannot see, the value is drawn into the output, where only the
pattern rules stand between it and the agent. A shell prompt it can see is
refused (G3, GH #262).

The channel needs a daemon and an attached client:
- On Windows it is refused as `not_supported_on_platform`.
- With nobody attached, it waits out its `timeout_secs` and answers
  `secret_cancelled`.

**Its echo test (G3) is in `v0.0.8` and later, so a `v0.0.7` install does
not have it** (GH #137). A `v0.0.7` install writes the value whatever
the terminal's echo state. An agent that asks before its child reaches a
password prompt could get a human to type a real credential into an echoing
terminal.
The line discipline would then put it in the output, and the default,
redacted `read_output` would hand it back to that same agent in the clear. An
arbitrary password matches no rule. A newer `holdfast attach` does not rely
on that daemon. Joined to a daemon older than the echo test (protocol below
1.3, which a `v0.0.7` daemon still running after an upgrade is), it collects
a secret masked, discards it unless `--allow-echo` was given, and says so at
the prompt before anything is typed.

Such a daemon has no shell-prompt test (G3) either. Against one, this
release's MCP server refuses `request_secret_input` (`daemon_too_old`), and
`holdfast attach` warns under the prompt that a secret it sends with
`--allow-echo` reaches whatever holds the terminal. A request that an older
MCP server still running beside it raises at an idle prompt is written
there once answered, and drawn, run and saved to history, until the daemon
is restarted.

**Other input channels:**
- **`send_input` is not that channel and never was.** It writes whatever the
  agent sends, over the MCP wire, and the argument stays in the transcript.
- **`start_session(env:)` values cross the MCP boundary**, and the argument's
  own description says so ("Do not pass secrets"). Putting a credential there
  puts it in the transcript.

#### What to report

**A report is in scope if Holdfast puts sensitive material somewhere the
caller did not ask for it to go.** One fix of exactly this shape has already
shipped. `portable-pty`'s spawn error embeds the entire `$PATH`, so
`start_session` reports a clipped summary of the error rather than the raw
error, which would otherwise have landed in the transcript on every failed
spawn.

**A way around the redactor is squarely in scope.** That includes:
- a secret reaching an agent or an observer through a surface that did not
  run the redactor, other than the raw paths named under G1;
- a leak that the residual register does not list;
- a leak that a register row understates;
- a path that is easy to forget, such as an error string, the audit log, or
  bulk output delivered as a resource.

A secret-shaped value the rules simply do not match is tier 2's documented
limit. For that, a new rule is the right contribution.

### Prompt and interaction-state detection

`crates/holdfast-core/src/detect/` — `scanner.rs`, `detector.rs`, `patterns.rs`.

Detection is what the agent believes. Every prompt-bearing response carries an
`interaction_mode` (`AtPrompt` / `Executing` / `AwaitingSecret` / `Fullscreen`
/ `Exited`) and a `detection_tier` (`semantic` from OSC 133, `terminal_mode`
from bracketed paste / alternate screen / termios `ECHO`, `heuristic` from
output quiescence and the tier-3 pattern table). **A forged or mis-detected
state is a real bug class, and each direction has its own consequence:**

- a false `AtPrompt` tells the agent to type into a program that is still
  running;
- a false `AwaitingSecret` tells the agent to interrupt a human for a password
  no program asked for;
- a missed `AwaitingSecret` means the agent answers a password prompt as if it
  were ordinary input.

Cases of this class that have already been found and fixed, so you can see what
a good report looks like:

- **An abandoned escape sequence used to promote its own payload to terminal
  text.** When a sequence exceeded the byte ceiling the scanner returned
  straight to `Ground`, so the remainder of a *correctly terminated* payload
  became ordinary output — measured, a 9 KiB BEL-terminated OSC 52 clipboard
  write whose payload ended `\r\nroot@prod:/etc# ` produced exactly that as the
  detector's last line, which the tier-3 table scores at 0.85, the act
  threshold. The scanner now discards to the next newline and clears its tail
  line (`ModeScanner::give_up`).
- **A stale `ECHO` sample forged `AwaitingSecret`.** The termios sample was
  cached for 50 ms; paired with a *current* bracketed-paste-off it is the exact
  signature of a secret prompt, and reported `AwaitingSecret` at 0.95 for
  `sleep 5` roughly one run in ten. The cache is gone and the sample is now
  taken with the detector lock held, so no chunk can be classified between the
  sample and the classification.
- **Truncated sequence parameters forged terminal modes.** A CSI cut at the
  parameter cap could end in `;2004` and set the bracketed-paste flag, and
  unmodelled OSC 133 subcommands could set the flag that gates the `semantic`
  tier. Both flags are sticky and decide which rungs may answer for the rest of
  the session.

**Documented residuals — please read these before reporting.** Each is known,
recorded in the code, and accepted:

- **A hostile or merely careless program in the session can print any of these
  bytes directly.** OSC 133 markers, `\x1b[?2004h`, a prompt-shaped line — all
  of them, at any length, with no ceiling involved. Holdfast cannot distinguish
  them from a shell's, by construction.
- **`SEQUENCE_MAX` (1 MiB, `scanner.rs`) is a blindness budget, not a forgery
  guard, and does not close.** At the trip point a huge well-formed sequence
  and a truncated one share a byte-identical prefix, so no online rule can act
  differently on them. The discard-to-newline rule leaves a residual: a payload
  carrying a newline hands everything after it to the state machine. This is
  documented at its real reach in `give_up`'s doc comment.
- **The tier-3 pattern table matches raw bytes**, so coloured prompts score 0
  and the table's false-positive surface is wider than it is designed to be.
  0.0.3's ANSI stripper did *not* close this: it runs on the read path
  (`read_output`, `wait_for_pattern`), not ahead of this table. `patterns.rs`
  says so and pins it.

A report that demonstrates one of these residuals is already known. A report
showing a **new** path to a forged state, or one that materially lowers the
cost of reaching an existing one, is valuable.

### Process-group signal handling

`crates/holdfast-core/src/pty/in_process.rs`. `terminate` must kill everything it
owns and **nothing it does not**. Both directions are bugs:

- **Orphans.** The child is spawned with `setsid()` and the PTY as its
  controlling terminal, so PGID == SID == PID. A single `killpg(pgid)` is not
  enough: shell job control puts each background job in its own process group,
  so `terminate` enumerates every process group in the child's session (via
  `/proc` on Linux) and signals each one, re-enumerating on every sweep.
- **Over-reach.** `kill(-0, sig)` signals *Holdfast's own* process group, which is
  why every group is filtered on `pgid > 0`. A reaped PID can be recycled, so
  `signal` refuses to deliver anything once the child has exited — otherwise a
  `/proc` sweep could target a stranger's session. `InProcessPty::signal_deliveries()`
  is public, and not `#[cfg(test)]`, precisely so a test can assert that no
  signal left the process at all.

Known limitation, not a report: on Unix platforms **without** `/proc` the sweep
degrades to (the child's group, the terminal's foreground group), so a
background job in a third group can survive `terminate` there. Full enumeration
needs `sysctl(KERN_PROC_SESSION)` and is not implemented.

### Resource exhaustion

The only caller is an MCP client, but that client is a language model, so
unbounded inputs matter. Existing bounds, each of which was added after
measuring the failure it prevents:

- **`send_input` caps a payload at 64 KiB** and performs the write on the
  blocking pool under a 5 s deadline. Before that, a raw-mode child that had
  stopped reading its terminal parked one tokio worker per call, uncancellably;
  a handful of calls took the entire MCP server down — including `terminate`,
  the only way out.
- **`read_output` defaults to 32 KiB and hard-caps at 256 KiB**, and rejects
  `max_bytes: 0`, which can never make forward progress.
- **Caller-supplied `prompt_patterns` are capped at 64**, each compiled with a
  64 KiB size limit, and rejected patterns are clipped to 120 characters in the
  error. Unbounded, 5000 patterns were accepted and put every tool call at
  milliseconds; `(?:(?:a{50}){50}){50}` compiled to 125 000 repetitions; a
  200 KB regex produced a 200 KB error message that then sat in the transcript
  for the rest of the conversation. (Catastrophic backtracking is *not* the
  risk here — the `regex` crate is automaton-based and `(a+)+$` was measured
  linear. Compilation cost is.)
- **The registry caps live sessions at 8** and each session's output buffer at
  1 MiB.

A way past any of these caps, or an input path that has no cap at all, is in
scope.

## Out of scope

- **Command safety.** There is no preflight, no dangerous-command classifier,
  and no confirmation flow. They are on the roadmap; their absence is not a
  vulnerability.
- **A secret the rule set does not match.** The redactor recognises
  secret-shaped values; a passphrase in prose matches nothing and is returned.
  A *new pattern* is a welcome contribution rather than a vulnerability
  report. A secret reaching the agent through a path that skipped the redactor
  entirely, other than the raw paths named under G1, is in scope — see above.
- **The raw paths named under G1**, and the residuals already in the register,
  unless a report shows one reaching further than its row says.
- **A program inside a session forging its own detection signals.** It is
  inside the trust boundary.
- **Anything that requires an attacker who already runs as the user running
  `holdfast mcp`.** At that point they can start the shell themselves.
- **Windows.** `holdfast mcp` serves MCP in-process there, with no daemon, so
  there is no `attach`, no `watch` and no `request_secret_input`. Signalling
  returns an error, there is no process-group handling, and `ECHO` is not
  sampled. Nothing that spawns a shell is exercised by a test on Windows.
  Windows is unimplemented, not broken.
- **`docs/`.** The design specification and implementation plans are the
  author's local working documents and are deliberately absent from this
  repository and its history. The `§`-numbered references throughout the code
  point into them.
