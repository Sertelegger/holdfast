# Changelog

All notable changes to Holdfast are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with **one stated
addition**: a `Known limitations` section, for behaviour that is easy to
mistake for a bug.

Direction and upcoming work live in [ROADMAP.md](./ROADMAP.md). How a release
is cut, named and published is in
[CONTRIBUTING.md](./CONTRIBUTING.md#releases).

## [Unreleased]

**Upgrading:** run `holdfast daemon stop` after installing (it ends every
session), then restart Claude Code. Until both, each side refuses a
`start_session` the other would misplace, and says which to restart ([#229]).

### Added

- A Claude Code plugin and marketplace (`/plugin install holdfast@holdfast`),
  and release binaries for five targets with a `SHA256SUMS.txt` that the
  plugin checks. A release is a draft until a maintainer promotes it ([#237]).
- `HOLDFAST_BOOTSTRAP_BIN=/absolute/path` runs the plugin on a source build
  (`cargo install --locked --git … --tag vX.Y.Z holdfast`) until then, and a
  bootstrap that cannot start the server says why in `claude mcp list` ([#237]).
- `[security] disabled_redaction_rules` switches named built-in rules off on
  every client-facing surface, and a name no rule has is a load error. Audit
  rows count the active rules and name the disabled ones ([#128]).
- An MCP `notifications/cancelled` cancels the daemon-side work: a cancelled
  `request_secret_input` frees its slot at once and ends `caller_cancelled`
  ([#127], [#105]).
- `[terminal] shell_history_file = "per_session"` keeps each bash and zsh
  session's commands in a `0600` file of its own, unredacted ([#252]).

### Changed

- **Breaking:** every tool refuses an argument it does not declare, and names
  it: JSON-RPC `-32602` through the daemon, an `isError` result under
  `--no-daemon`. Each `inputSchema` says `additionalProperties: false` ([#219]).
- **Breaking:** control and attach protocol **1.5** (0.0.7 spoke 1.1). Across
  the skew, a shim or daemon refuses a `start_session` (or argument) the other
  side would misplace or drop silently, and says which to restart ([#229]).
- **Breaking:** a history entry whose text was not captured is `command: null`,
  not `""`, and `status`/`list_sessions` gain `command_capture`. A prompt that
  regenerates `PS1`, such as starship's, no longer loses the text ([#220]).
- **Breaking:** the CLI refuses a flag it does not have (exit 64, with usage)
  where it ran without it. `--help`, `-h`, `help`, `--version` and `-V` work,
  and `holdfast version` names the commit it was built from ([#233], [#178]).
- **Breaking:** `config.toml` refuses `redaction_enabled = false` (it disabled
  nothing; audit rows drop it), a now-live `output_broadcast_capacity` over its
  ceiling and `resource_read_max_bytes` below the ring ([#128], [#210], [#203]).
- `holdfast attach` and `watch` open on the session's current screen, masked as
  `get_screen_state` masks it; the secret prompt says whose words it quotes and
  no longer repeats the child's own prompt ([#235], [#236]).
- `watch` and `attach` survive bursts: a lagging viewer resumes from the ring
  buffer and is detached only after 30 s of reading nothing, when `attach` holds
  the terminal. A view that missed output exits 3, not 0 ([#200], [#210]).
- Under `ansi: "strip"` a progress bar that erases the line it redraws (`\e[K`
  after a `\r`, as cargo's does) reads back as its last frame; one that only
  overwrites after a `\r` (tqdm, wget) still reads back every frame ([#247]).
- While a command runs, `detection_tier` is `heuristic` (reason `no
  deterministic signal`) where 0.0.7 said `semantic`: a shell's markers no
  longer vouch for a program it started. The mode is unchanged ([#240]).
- One non-ASCII byte no longer slows redaction 456-fold, a slow read no longer
  stalls other clients, and finished sessions are capped at 64 records and
  16 MiB of output ([#194], [#163], [#201], [#129]).
- On Windows, `holdfast-core` builds, `holdfast mcp` serves in-process and finds
  its config through `USERPROFILE`, and the daemon-backed subcommands exit 64
  with one message saying so ([#19]).

### Security

- New rules for URL userinfo, `Authorization: Basic`, `mysql -p` and `docker
  login -p`, more database URL schemes, and `_PASS`, `_PWD`, `PASSPHRASE` and
  `APP_KEY` labels; most are held back while still arriving ([#244]).
- A private key's body is masked on a read that starts inside it, on the grid
  after its header scrolls off, in titles, on a late `watch` and when cut short.
  A header quoted in prose masks nothing ([#243], [#224], [#235], [#242]).
- Redaction judges every view a read can emit and the page it returns, so an
  escape or C1 byte spliced into a token, as in coloured output, no longer hides
  it, nor does the grid show one arriving ([#125], [#138], [#139], [#142]).
- `read_output`'s paging loop always progresses: a region the window cannot
  vouch for is one `[REDACTED:unresolved]`, where it froze the cursor or, at the
  buffer head, went out raw ([#195], [#14]).
- `request_secret_input` writes a credential only once the child's terminal has
  stopped echoing, and says `not_echo_off` otherwise; `holdfast attach
  --allow-echo` is the opt-out. Refused submissions are zeroed ([#137], [#57]).
- `request_secret_input` refuses a shell idle at its own prompt by its markers
  (`at_shell_prompt`), where a secret was shown, run and saved to history, even
  with `--allow-echo`. A REPL still passes; the full fix is open ([#262]).
- `holdfast logs --tail` no longer bypasses the holdback: it sends the new
  `read_output` argument `apply_holdback: true`, and every read says why it is
  held back in `held_back_cause` ([#169], [#160], [#195]).
- Against a 0.0.7 daemon, `holdfast logs --tail` withholds a token still
  arriving and says where that daemon stops short, and `holdfast attach` sends
  a secret only with `--allow-echo` ([#169], [#195], [#137]).
- Against a 0.0.7 daemon, which asks even at an idle shell prompt, the server
  refuses `request_secret_input`, and `holdfast attach` warns under the prompt
  before `--allow-echo` sends a secret there ([#262]).
- `holdfast attach` discards what is typed up to Enter after a secret request
  closes mid-entry (a timeout, the agent's `interrupt`), where the rest of the
  password went to the shell as keystrokes and ran as a command.
- Sessions no longer write the agent's commands into your shell, REPL or
  database-client history files ([#252]), but hook-based recorders such as
  atuin, zsh-histdb, mcfly and bash-preexec loggers still do (SECURITY.md, H11).
- A bash or zsh session no longer lists or recalls your own shell history: the
  snippet empties the list the shell read from your rc's history file, except
  where SECURITY.md's H10 says it cannot safely ([#274]).
- `SECURITY.md` states a two-tier redaction contract and each guarantee's status
  today, and keeps a residual register of known leaks ([#253], [#254], [#255],
  [#256], [#257], [#258], [#259]).

### Fixed

- The label-keyed rules stop masking code (`label::path`, field accesses,
  digit-free values with brackets or backticks) and the word after a trailing
  `password:`; OpenSSH `sk-ecdsa-…` names are not OpenAI keys ([#202], [#245]).
- `read_output` never splits a UTF-8 character across two pages, and a
  `tail_bytes` above `max_bytes` reports `truncated_for_size` ([#241], [#246]).
- Waits match coloured output by its text, and a pattern-less wait no longer
  answers before `less` reads a key, holds `Executing` at a `[Y/n] ` prompt or
  says `session_died` over real output ([#238], [#248], [#240], [#42]).
- A shim whose daemon stopped starts a new one; a call that may already have run
  is answered `daemon_restarted` rather than sent twice ([#231]).
- Sessions start in the calling client's directory and environment, not the
  shared daemon's (`profile` sessions keep the daemon's), with the pagers set to
  `cat` so `git log` does not sit in `less` ([#229], [#239]).
- `terminate` and `daemon stop` hang up an idle shell rather than wait out their
  grace (not tcsh or csh, which save history on a hangup), and `daemon stop`
  returns once the daemon has exited ([#234], [#20], [#252]).
- The server instructions fit Claude Code's 2,048-character budget and lead with
  the password-prompt rule; `read_output` explains `[REDACTED:unresolved]`
  ([#230], [#242]).
- A secret requested before the child read it reaches the child whole, autofill
  no longer misses an early prompt, and a secret provider is held to its
  deadline and size limit ([#236], [#106], [#105], [#126]).
- `holdfast logs` drains the whole buffer, not the oldest 256 KiB ([#232]); a
  CLI piped into `head` dies of `SIGPIPE` like `cat` instead of panicking
  ([#218]); `attach` to a session that has exited exits 0 ([#39]).
- `holdfast watch | head` ends once `head` exits even on a quiet session, on
  macOS as well; a socket or named FIFO there still waits for the next write
  ([#218]).
- Under bash 5.3, a command typed key by key at a multibyte or multi-row prompt,
  such as starship's, is recorded whole, not from its last redraw on ([#220]).
- `get_command_history` returns a non-ASCII command as typed, not as its UTF-8
  bytes read one to a character (`echo hÃ©llo`) ([#270]).
- A session no longer ends at the first `false && true` under an rc's
  `set -e` (zsh `err_exit`), and a readonly `PROMPT_COMMAND` or `PS1` no
  longer prints an error into it or, under `set -e`, ends it at start-up.
- `start_session` for a program that is not installed says it was not found
  on PATH; the message used to stop at `because:`.
- Most tool descriptions and schemas no longer cite spec sections or name
  internal functions, and `get_command_history`'s says how bash, zsh and fish
  record a command wider than the terminal ([#276]).

### Known limitations

- Label-keyed rules miss a value on the line after a `:`, a digit-free value
  shaped like code (`Hello::World`) and one starting with `:`; the new rules
  mask some ordinary text, such as `find / -name mysql -prune` ([#245], [#244]).
- Some credentials are not held back while arriving: a URL password behind an
  ordinary username, a context rule's value after a space ([#152]), and up to
  three bytes of `Basic` on a header spelling the rule does not index ([#244]).
- `read_output` can still release the front of a credential that arrives with
  an escape inside it, up to one byte short of the rule's minimum ([#142]).
- A viewer is detached after 30 s without progress, and on Linux progress comes
  in socket-buffer steps. Joining a session switches on its VT100 tracking, as
  `get_screen_state` does ([#210], [#235]).
- The plugin's Windows entrypoint is unverified on Windows, and there the
  runtime directory, logs and `config.toml` keep their inherited ACL, with a
  warning rather than a check.
- Under zsh, a command line wider than the terminal can split a token past the
  redactor on `read_output`, and is recorded as `[REDACTED:unresolved]` or an
  unmarked tail; fish repeats part of such a command in front of it ([#276]).
- An rc file that reads the terminal at start-up (a `read`, oh-my-zsh's update
  question, zsh's new-user menu) takes the integration line as its answer: the
  session starts without it, and zsh saves to the history file the rc names.
- A bash rc that sets `HISTFILE` and runs `history -w` from `PROMPT_COMMAND`,
  sourced again in a session, overwrites that file with the session's commands
  alone, since the session no longer holds your history ([#274]).

## [0.0.7] — 2026-09-01 (Carabiner)

### Added

- **`request_secret_input`**, the twelfth MCP tool. It blocks until an attached
  human answers, a configured provider resolves the value, the child stops
  asking, or `timeout_secs` elapses, and returns a status and a byte count —
  never the value and never a handle that could be exchanged for one.
- **Operator-declared session profiles** (`[[security.profiles]]`) and
  `start_session(profile:, vars:)`: the operator writes the program, the
  argument template, the environment and the working directory, and the agent
  supplies values into named slots ([#46]).
- **`profile` on the session record and on `session_start`**, so `status`,
  `list_sessions` and the audit log say where a session's command line came
  from. It is `null` for a `command`/`args` session, carries the name and
  nothing more, and is the one string on the record that is not redacted.
- **Keychain autofill from operator-declared bindings**
  (`[[security.secret_bindings]]`), naming a profile, an optional prompt
  pattern, a provider (`secret-service`, `security`, `pass`, `op`) and a
  reference. Every way a binding fails to resolve falls through silently to the
  human prompt, so the agent cannot enumerate what exists.
- **`require_confirm` on a binding**, with the `BindingApprovalRequired` and
  `ApproveBinding` frames to go with it. The credential is resolved after the
  human approves and never before.
- **A notice in the session buffer when a secret is wanted and nobody is
  attached**, so an agent reading `read_output` can see why its child stopped.
  It reaches the buffer only — not the child, not the reported prompt, not the
  idle deadline.
- **`not_supported_on_platform`**, for a build whose platform has no
  out-of-band secret entry.
- **A terminal hosts one interactive client per session.** `holdfast attach`
  declares which terminal device its keyboard is, and a second `ReadWrite`
  client on a terminal that already has one is refused with `terminal_busy`.
  Attaching from another terminal is unaffected, and `holdfast watch` never
  contends.
- **Protocol `1.1`**, with a new `tests/wire-shape/1.1.golden`: `Attach` gains
  an optional `terminal` and `AttachReject.reason` gains `terminal_busy`. Both
  are additive and unreachable for a peer that did not opt in.

### Changed

- **The macOS runtime directory moves** from
  `~/Library/Application Support/holdfast` to `~/.holdfast`, so every platform
  without `XDG_RUNTIME_DIR` uses one path. **Stop the daemon before
  upgrading**: there is no migration, a 0.0.6 daemon is invisible to 0.0.7, and
  `holdfast daemon stop` can no longer reach it — recovery is `pkill holdfast`
  ([#73]).
- **`wait_for_pattern`'s `pattern` is optional.** Omitted, the call waits until
  the session stops executing and answers `reached`; the regex form is for a
  *program's* prompt and never for the shell's own, which is a guess about the
  operator's `$PS1`. A wait that expires against a session already at a
  measured prompt now says so in `warning` ([#62]).
- **The session is sized to the smallest attached writer**, not to whichever
  client resized last, and a departing writer gives its columns back;
  last-writer-wins does not converge between two clients dragging at once
  ([#66]).
- **A resize notice is coalesced rather than printed per frame** in both
  `attach` and `watch`, and a diagnostic is written in a single `write_all`, so
  two clients sharing a terminal cannot shred each other's output mid-word
  ([#66]).
- **Two config shapes that loaded at 0.0.6 now stop the daemon**, with the
  offending key named: `security.autofill_on_echo_off = true` alongside
  `security.secret_provider = "prompt"`, which reads *on* and behaves *off*;
  and a `[[security.secret_bindings]]` entry whose `match_prompt` is not a
  valid regex or whose `profile` names no `[[security.profiles]]` entry.
- **Every `[[security.secret_bindings]]` entry an operator has written stops
  loading.** `match_command` and `match_example` are gone and `profile` is
  required, so a binding carrying either fails the unknown-key rule; declare a
  profile for the command line the binding was for ([#46]).
- **`start_session`'s `inputSchema` no longer marks `command` required**, and a
  call omitting both `command` and `profile` returns JSON-RPC `-32602` instead
  of a tool result. The two are mutually exclusive — a `oneOf` no schema here
  can express — so the constraint moved into the tool body, and the two
  property descriptions now carry the whole contract.
- **`AwaitingSecret.prompt_text` strips control characters before redacting**
  rather than redacting the raw line, closing the case where a control byte
  split a credential past the redactor. Dropping a byte can join the text on
  either side of it into a token that matches a rule neither side matched, so a
  prompt label may newly over-redact.

### Security

- **The operator writes the command line and the agent fills named slots in
  it** ([#46], closing [#45]). This retires the bypass class rather than
  mitigating it: `match_command`, `match_example` and the load-time corpus that
  judged one against the other are gone. Substitution happens within one argv
  element, so a value containing spaces, quotes, `;`, `&&` or a leading `-`
  stays a single argument and cannot become a second one.
- **Each profile rule is a load error naming the key.** `program`, `env` (keys
  and values) and `cwd` are literals and admit no `{…}`; every `{name}` in
  `args` has a `vars` entry and every `vars` entry is used by a slot; each var
  pattern compiles wrapped exactly as the renderer wraps it; profile names are
  unique; and a binding naming an unknown profile is refused.
- **`env` and `cwd` are mutually exclusive with `profile`**, so the agent
  chooses no part of the process. `env: {PATH: …}` repointed a profile whose
  literal `program` was `ssh` at the agent's own binary, and
  `env: {LD_PRELOAD: …}` captured the credential out of an absolute-path
  program running the operator's own argv ([#55]).
- **A session started with `command`/`args` can never receive a keychain
  credential.** That is the safety property and it is also a real capability
  loss: an operator who forgets a profile finds out when a legitimate workflow
  stops autofilling.
- **`match_prompt` is unchanged, and is still not a security control.** It is a
  conjunct that can only remove candidates a selection already made. It matches
  the unredacted prompt line deliberately, so the redactor cannot switch an
  operator's binding off — matching the redacted line "for safety" would
  reintroduce exactly that.
- **`BindingApprovalRequired` carries the session's command line**, redacted
  element-wise and then stripped of every control, directional-override and
  zero-width character, so an argument cannot rewrite the line the operator is
  deciding from. The text itself stays, so a forged line reads longer and
  stranger and never shorter and innocent.
- **`require_confirm` now defaults to `true`**, so a binding that omits the key
  resolves only after a human has seen the command line. `autofill_on_echo_off`
  still defaults to `false`.
- **What this does not close, stated plainly.** A profile bounds which command
  line a credential can reach and which credential an agent can obtain; it says
  nothing about the credential's effect. What these rules take away is theft of
  the bytes, for replay elsewhere and beyond the session's lifetime.
- **Every tool's `outputSchema` advertises eleven statuses where it advertised
  eight.** `secret_provided` and `secret_cancelled` join after `session_died`
  and `not_supported_on_platform` after `spawn_failed`, inserted at their
  catalogue positions because that array's order is a wire fact.

## [0.0.6] — 2026-08-19 (Bolt)

### Added

- **`holdfast attach <session>`** — a raw-mode view of a live session with
  tmux-style detach (`Ctrl-B d`). What the agent sees, you see, and you can
  type into the same shell.
- **`holdfast watch <session>`** — the same stream read-only. It cannot send a
  write frame at all: the refusal is a server-side frame-kind table, not a
  client-side politeness.
- **A per-connection redaction role.** An observer's stream is redacted, an
  interactive client's is not, and the decision reads the connection's role and
  never `client_kind`, which is audit attribution only.
- **Streaming redaction**, which withholds an unterminated match rather than
  emitting it — making it stronger than the read path over the first ~24 KiB.
- **`SecretInput`** — a password typed into an attached client reaches the
  child's PTY without crossing the MCP wire, entering another client's stream,
  or appearing in an audit entry. The prompt is detected from termios `ECHO`,
  not from matching the word `Password:`.
- **`SessionExited`, `Detached` and `AwaitingSecret` frames**, so a client is
  told why a stream ended rather than discovering it by silence.

### Changed

- **The GitHub repository is now `Sertelegger/holdfast`.** Old URLs redirect,
  but `Cargo.toml`'s `repository` field does not benefit from a redirect, so it
  moved too.
- **Renamed from CLASP to Holdfast** — *HOLDFAST, Human-Observable Long-lived
  Daemon For Agent Shell Terminals*. This shipped inside the `v0.0.5` tag and
  nothing was ever released under the old name. Everything below changes
  behaviour, and there is no migration shim:
  - `clasp-core` → `holdfast-core`, `clasp` → `holdfast`; re-register with
    `claude mcp add --scope user holdfast -- <path>/holdfast mcp`.
  - `serverInfo.name` is now `holdfast`.
  - `clasp://session/…` → `holdfast://session/…`, and the response `_meta`
    namespace key `clasp` → `holdfast`.
  - `clasp/handshake` → `holdfast/handshake`; a daemon and a shim from
    different sides of the rename will not speak.
  - OSC 133 markers carry `;holdfast=1`, the injected shell functions are
    `__holdfast_*`, and `osc133_source` reports `holdfast`.
  - `~/.clasp` → `~/.holdfast`, `$XDG_RUNTIME_DIR/clasp` → `.../holdfast`,
    `~/Library/Application Support/clasp` → `.../holdfast`, and
    `clasp.pid`/`clasp.lock` → `holdfast.pid`/`holdfast.lock`. A stale
    `~/.clasp` is orphaned, not moved.
  - `$XDG_CONFIG_HOME/clasp/config.toml` → `.../holdfast/config.toml`
    (likewise `~/.config/clasp` → `~/.config/holdfast`); an existing config is
    not read from the old path.
  - `CLASP_RUNTIME_DIR`, `CLASP_BUILD_SHA` and `CLASP_SHELL_INTEGRATION` →
    `HOLDFAST_*`; the old names are not read as a fallback.
  - Unchanged on purpose: the protocol version numbers, the socket filenames
    (`control.sock`, `attach.sock`, `http.sock`), the log filenames, the
    `sess_` session-id prefix, and every MCP tool name.

### Fixed

- **Four smoke checks passed against a server that never started**, and 0.0.5's
  fix for the same class did not hold — reporting the total does nothing about
  the transcribed copies, and the attach phase shipped 47 checks while the
  script's header and `CONTRIBUTING.md` both still said 38. The invariant no
  longer carries a number (`F == N`), and CI runs the negative control.

## [0.0.5] — 2026-08-19 (Anchor)

**The first tagged release.** Milestones 0.0.1 through 0.0.5 are all in it;
there was no earlier tag, nothing on crates.io and no distributed binary. The
workspace version had sat at `0.0.2` and now tracks the milestone number.
`Added` is grouped by milestone because that is how the work was built and
reviewed, and `Fixed` names classes of defect rather than issue numbers because
each was found by reviewing a task against its brief.

### Added

#### Milestone 0.0.1 — skeleton and PTY

- **A working stdio MCP server** (`rmcp`) with four tools — `start_session`,
  `read_output`, `send_input`, `terminate` — in a single workspace of
  `holdfast-core` and `holdfast` (subcommands `mcp` and `version`).
- **`InProcessPty`**, a `portable-pty` backend behind a `PtyBackend` trait,
  with `setsid()` and the PTY as controlling terminal so the child's process
  group, session id and PID coincide. `MockPty` implements the trait for tests.
- **`OutputBuffer`** with absolute-offset cursors, so an agent can carry a
  cursor between `read_output` calls and know exactly what it has and has not
  seen, including when the ring has evicted it.
- **`Session` and `SessionRegistry`** — a dedicated reader thread per session,
  live-name uniqueness, a cap of 8 live sessions, and a 1 MiB buffer each.
- **`scripts/mcp-smoke.sh`**, an end-to-end smoke test over raw JSON-RPC and
  the only check in the project that exercises the wire format.

#### Milestone 0.0.2 — deterministic prompt detection

- **Sessions report what the program is doing, with the evidence.** Every
  prompt-bearing response carries an `interaction_mode` (`AtPrompt`,
  `Executing`, `AwaitingSecret`, `Fullscreen`, `Exited`) and a `detection_tier`
  (`semantic`, `terminal_mode`, `heuristic`), so an agent can tell a
  measurement from a guess.
- **A tier-A byte scanner** over the raw PTY stream — bracketed paste, the
  alternate screen, the window title and OSC 133 markers — allocating no grid,
  keeping a 512-byte tail line, and resynchronising on malformed sequences.
- **Termios `ECHO` sampled through `PtyBackend`** with `tcgetattr` on the
  master, which is what makes a genuine secret prompt distinguishable from
  output that happens to end in `Password:`.
- **A 22-row tier-3 prompt-pattern table**, nine rows carrying head guards
  measured against 65 lines of ordinary build, test, `git`, package-manager and
  `--help` output. Sessions may extend or replace it via
  `start_session(prompt_patterns:)`.
- **OSC 133 shell integration for bash, zsh and fish** — a one-line snippet
  typed into the session at the first prompt, never installed, wrapping
  whatever `PS1` the shell ended up with. Anything else degrades silently to
  `terminal_mode` or `heuristic`; `shell_integration: false` skips it.
- **A command-history ring** built from those markers, recording each command's
  exit code, start time, duration and output span in the cursor space
  `read_output` uses.
- **`status`, `list_sessions` and `get_command_history`**, bringing the tool
  set to seven.
- **An `outputSchema` on every tool**, and the MCP 2025-06-18 annotations
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`).
- **Session options on `start_session`**: `cwd` (validated and canonicalised),
  `env`, `cols`/`rows`, `prompt_patterns`, `prompt_patterns_replace`,
  `settle_threshold_ms`, `shell_integration`.

#### Milestone 0.0.3 — output processing and redaction

- **Secrets are removed from output by default.** A 51-rule set derived from
  Gitleaks replaces each match with a `[REDACTED:<kind>]` marker naming the
  rule; every rule carries positive *and* negative examples, and the loader
  rejects one that has neither.
- **A secret split across two reads is withheld rather than leaked in halves.**
  A prefix index scans the trailing region, the read stops short and reports
  `held_back: true`, and `tail_lines`/`tail_bytes` reads opt out by argument.
- **ANSI stripping with a boundary rule**, so a sequence cut across a chunk
  boundary is not half-emitted as text, and **`text_encoding` modes** for
  callers that need the bytes rather than the rendering.
- **An audit trail with mandatory redaction.** Every string handed to the log
  passes through the redactor first; `read_output(redact: false)` returns the
  raw bytes and writes an entry saying so.
- **`status` and `list_sessions` redact on the way out** — `command`, `args`
  and `prompt.last_line` — and sessions gained `exited_at_unix_secs`.
- **`wait_for_pattern`, and `send_input(wait_for:)`**, bringing the tool set to
  eight.

#### Milestone 0.0.4 — screen state, resize, interrupt

- **`get_screen_state`** renders what a full-screen program is actually
  showing, whole or as a `diff_from` delta against a revision the caller holds.
- **Tracking is adaptive, not always-on.** A Tier-A probe watches for the
  alternate screen, bracketed paste or a cursor-position report and only then
  starts the parser, so a line-oriented shell session pays nothing.
- **`resize` and `interrupt`**, bringing the set to eleven. `resize` reports
  the geometry read back *after* the `ioctl`, so a resize that did not take
  effect cannot report success.
- **A cursor-position prompt sub-signal (T3c)**, combined as
  `quiescent × max(pattern, cursor)`.
- **Primary Device Attributes are answered** (`\x1b[?6c`, byte-exact), taking a
  `fish` startup stall from 10.04 s to 0.02 s. Replies are rate-limited, are
  never a `send_input` audit event, and do not count as session activity.

#### Milestone 0.0.5 — the daemon and the control protocol

- **Sessions no longer die with the MCP client.** `holdfast mcp` is a thin shim
  that auto-spawns a background `holdfast daemon` and afterwards reconnects to
  it, so quitting and restarting Claude Code leaves every session alive at the
  same prompt. `--no-daemon` keeps the single-process behaviour.
- **A versioned control protocol** over a Unix socket — length-prefixed CBOR
  with a 16 MiB cap, a `holdfast/handshake` both peers check, and an error
  catalogue. Mismatched protocol majors refuse to connect from *either* side.
- **The daemon never opens a TCP listener.** The socket is Unix-domain only,
  its directory is `0700` and verified after creation, and every connection's
  `SO_PEERCRED` uid is compared to the daemon's own before a single frame is
  parsed. A credential that cannot be read fails closed.
- **New CLI subcommands** — `holdfast daemon run|start|stop|status`,
  `holdfast list`, and `holdfast logs <session> [--tail N] [--raw]` — with
  documented exit codes and idempotent `daemon start`/`daemon stop`.
- **The audit caller is derived from the connection, never from the request.**
  `tool` records the mechanism and `client_kind` the accountable party, taken
  from the uid-checked handshake; there is deliberately no argument an agent
  could set to label itself as a human, and nothing in the read path branches
  on it.

### Fixed

- **A single `killpg()` does not reach a shell's background jobs.** `terminate`
  now enumerates and signals every process group in the child's session, and
  interrupts target the terminal's foreground group.
- **`send_input`'s blocking write could wedge the entire server.** A raw-mode
  child that stopped reading parked a tokio worker uncancellably, and each
  retry took another. The write now runs on the blocking pool under a deadline
  with a 64 KiB payload cap.
- **`read_output` reported truncation that had not happened** — on both of its
  branches, at different times and for different reasons.
- **A stale `ECHO` sample reported `AwaitingSecret` for ordinary commands**,
  measured at 267 spurious samples under load and 0 after. Fixed where the bad
  value was produced — the 50 ms cache deleted, the sample taken under the
  detector lock — rather than guarded downstream.
- **One concept had two spellings, twice.** A single alt-screen toggle marked a
  session terminal-mode-available for life, and the same shape then turned up
  in the semantic dimension with the OSC 133 flag unpinned.
- **The escape-sequence ceiling was a forgery guard that could not be one**, and
  is now documented as a *blindness budget*, raised to 1 MiB so a routine sixel
  frame no longer trips it.
- **A head guard silently zeroed recall for every numbered-host prompt** while
  the corpus stayed green, because it had `hostname% ` and no `build01% `.
  Pattern rows are now pinned from both sides of the boundary they draw.
- **`scripts/mcp-smoke.sh` failed red on correct code.** `grep -q` under
  `pipefail` exits early, `printf` dies of `SIGPIPE`, and the pipeline reports
  141 — three to six runs in twenty under load, latent since 0.0.1.
- **The MCP server's own `instructions` string described a four-tool surface**
  for the whole of 0.0.2, so an agent that trusted it never learned `status`,
  `list_sessions` or `get_command_history` existed. The smoke script now
  asserts every tool name appears there.
- **Sixteen tests that could not fail** were found and fixed across 0.0.2, and
  ten across 0.0.1. Injecting the defect and confirming the test goes red is
  now standard practice — see [CONTRIBUTING.md](./CONTRIBUTING.md).
- **The exit cleanup asked who *holds* the socket, not whose it *is*.** An
  inherited descriptor in a forked child made a dead listener answer a
  `connect()` probe, failing roughly half of all default-parallel test runs.
  Identity replaced liveness, held as an inert `O_PATH` descriptor rather than
  a recorded `(dev, ino)`, which ext4 recycles in 500 of 500 measured trials.
- **A `wait_for_pattern` blocked the `interrupt` that would have ended it.** One
  `Arc<ControlClient>`, a mutex held across both write and read, and a
  sequential per-connection loop composed into a transport where one
  outstanding call blocked every tool on every session. `--no-daemon` had
  dispatched concurrently all along.
- **A permission check refused ordinary installs.** Any `~/.holdfast/logs`
  created before 0.0.5 is `0775` under the umask 002 that Debian, Ubuntu and
  RHEL ship, and both remedies the error suggested were wrong.
- **Auto-spawn quietly moved the logs onto tmpfs**, writing `audit.log` and
  `daemon.log` under `$XDG_RUNTIME_DIR` where they are destroyed at logout —
  in the configuration every install actually uses.
- **`holdfast mcp --no-daemon` ran the entire tool surface on
  `Config::default()`**, ignoring the operator's configuration completely. It
  now refuses a config the daemon would also refuse.
- **A smoke check passed against a server that never started.** Splitting one
  assertion left the "no `listChanged`" half comparing `null` to `null` in
  `jq`, which holds whether or not a server is there; it was the lone survivor
  of 39 checks against `/bin/true`.

### Security

- **`start_session` no longer echoes `portable-pty`'s raw spawn error**, which
  embeds the entire `$PATH` and would otherwise land in the conversation
  transcript on every failed spawn.
- **`cwd` is validated and canonicalised.** `portable-pty` silently *discards* a
  cwd that is not an existing directory and falls back to `$HOME`, so an
  unvalidated `cwd` told the agent `ok` while running the command elsewhere.
- **Signals are refused once the child has exited**, because a reaped PID can be
  recycled. Every candidate group is also filtered on `pgid > 0`, since
  `kill(-0, sig)` signals Holdfast's own process group.
- **Caller-supplied inputs are bounded**: at most 64 prompt patterns, each
  compiled under a 64 KiB size limit; `send_input` payloads at 64 KiB;
  `read_output` at 32 KiB by default and 256 KiB hard.
- **Truncated escape sequences can no longer forge terminal modes.** A CSI cut
  at the parameter cap could end in `;2004` and set the bracketed-paste flag,
  and an abandoned sequence handed the rest of its payload to the state machine
  as ordinary text.
- **A size-capped read returned a cursor inside the secret it had just
  redacted**, so the following chunk matched nothing and returned raw key
  material with an empty `redactions` map and no audit entry. The cursor now
  advances past the end of any span it would land inside; the 512-byte
  lookbehind was deliberately *not* enlarged, because any bound is exceeded by
  one more byte.
- **The audit trail failed open, and one output boundary had no redactor at
  all.** A daemon that could not write its audit log served anyway;
  `daemon.log` was written raw with no panic hook; a config parse error echoed
  the offending line, which for a config file may *be* the credential; and
  `session_start` recorded `redaction_enabled: true` as a constant.
- **The config file was trusted on nothing but its path.** It is now checked
  through the open descriptor — regular file, owned by the caller or root, not
  world-writable — so there is no second lookup to race. Symlinks stay accepted,
  because refusing them would break every `stow`, `chezmoi` and `yadm` install.

See [SECURITY.md](./SECURITY.md) for what is and is not in scope, including the
residuals that are known and accepted.

### Known limitations

- **No attach, watch or web UI.** Sessions outlive the MCP client, but a human
  cannot yet look at or type into a session the agent is driving. *(Shipped in
  0.0.6.)*
- **Unix only.** Signalling returns an error on Windows and there is no
  process-group handling. This release claimed the tree was "kept compiling and
  clippy-clean" for `x86_64-pc-windows-gnu`; it was not ([#19]).
- **Eleven tools.** No `precheck_command`, `request_secret_input`, `send_file`,
  `fetch_file` or `wait_for_any` yet.
- **`get_command_history`'s `command` field is best-effort**, reconstructed
  from the terminal's echo: a command longer than the terminal width is
  captured truncated to its *tail* with no ellipsis and no error, and non-ASCII
  bytes are recorded as Latin-1. The truncation runs upstream of the redactor
  ([#7]).
- **`fish` shell integration is unverified at runtime**, and the Primary Device
  Attributes measurements it rests on were taken by hand rather than in CI —
  `fish` is deliberately absent from the runner.
- **On Unix without `/proc`**, the process-group sweep degrades to the child's
  group plus the terminal's foreground group, so a background job in a third
  group can survive `terminate`.

[Unreleased]: https://github.com/Sertelegger/holdfast/compare/v0.0.7...main
[0.0.7]: https://github.com/Sertelegger/holdfast/releases/tag/v0.0.7
[0.0.6]: https://github.com/Sertelegger/holdfast/releases/tag/v0.0.6
[0.0.5]: https://github.com/Sertelegger/holdfast/releases/tag/v0.0.5

[#7]: https://github.com/Sertelegger/holdfast/issues/7
[#14]: https://github.com/Sertelegger/holdfast/issues/14
[#19]: https://github.com/Sertelegger/holdfast/issues/19
[#39]: https://github.com/Sertelegger/holdfast/issues/39
[#42]: https://github.com/Sertelegger/holdfast/issues/42
[#45]: https://github.com/Sertelegger/holdfast/issues/45
[#46]: https://github.com/Sertelegger/holdfast/issues/46
[#55]: https://github.com/Sertelegger/holdfast/issues/55
[#57]: https://github.com/Sertelegger/holdfast/issues/57
[#62]: https://github.com/Sertelegger/holdfast/issues/62
[#66]: https://github.com/Sertelegger/holdfast/issues/66
[#73]: https://github.com/Sertelegger/holdfast/issues/73
[#105]: https://github.com/Sertelegger/holdfast/issues/105
[#106]: https://github.com/Sertelegger/holdfast/issues/106
[#125]: https://github.com/Sertelegger/holdfast/issues/125
[#126]: https://github.com/Sertelegger/holdfast/issues/126
[#127]: https://github.com/Sertelegger/holdfast/issues/127
[#128]: https://github.com/Sertelegger/holdfast/issues/128
[#129]: https://github.com/Sertelegger/holdfast/issues/129
[#137]: https://github.com/Sertelegger/holdfast/issues/137
[#138]: https://github.com/Sertelegger/holdfast/issues/138
[#139]: https://github.com/Sertelegger/holdfast/issues/139
[#142]: https://github.com/Sertelegger/holdfast/issues/142
[#169]: https://github.com/Sertelegger/holdfast/issues/169
[#163]: https://github.com/Sertelegger/holdfast/issues/163
[#200]: https://github.com/Sertelegger/holdfast/issues/200
[#210]: https://github.com/Sertelegger/holdfast/issues/210
[#235]: https://github.com/Sertelegger/holdfast/issues/235
[#236]: https://github.com/Sertelegger/holdfast/issues/236
[#194]: https://github.com/Sertelegger/holdfast/issues/194

[#201]: https://github.com/Sertelegger/holdfast/issues/201
[#152]: https://github.com/Sertelegger/holdfast/issues/152
[#195]: https://github.com/Sertelegger/holdfast/issues/195
[#160]: https://github.com/Sertelegger/holdfast/issues/160
[#203]: https://github.com/Sertelegger/holdfast/issues/203
[#202]: https://github.com/Sertelegger/holdfast/issues/202
[#245]: https://github.com/Sertelegger/holdfast/issues/245
[#244]: https://github.com/Sertelegger/holdfast/issues/244
[#241]: https://github.com/Sertelegger/holdfast/issues/241
[#246]: https://github.com/Sertelegger/holdfast/issues/246
[#243]: https://github.com/Sertelegger/holdfast/issues/243
[#224]: https://github.com/Sertelegger/holdfast/issues/224
[#242]: https://github.com/Sertelegger/holdfast/issues/242
[#247]: https://github.com/Sertelegger/holdfast/issues/247
[#220]: https://github.com/Sertelegger/holdfast/issues/220
[#240]: https://github.com/Sertelegger/holdfast/issues/240
[#238]: https://github.com/Sertelegger/holdfast/issues/238
[#248]: https://github.com/Sertelegger/holdfast/issues/248
[#229]: https://github.com/Sertelegger/holdfast/issues/229
[#239]: https://github.com/Sertelegger/holdfast/issues/239
[#234]: https://github.com/Sertelegger/holdfast/issues/234
[#231]: https://github.com/Sertelegger/holdfast/issues/231
[#20]: https://github.com/Sertelegger/holdfast/issues/20
[#178]: https://github.com/Sertelegger/holdfast/issues/178
[#218]: https://github.com/Sertelegger/holdfast/issues/218
[#232]: https://github.com/Sertelegger/holdfast/issues/232
[#233]: https://github.com/Sertelegger/holdfast/issues/233
[#237]: https://github.com/Sertelegger/holdfast/issues/237
[#219]: https://github.com/Sertelegger/holdfast/issues/219
[#230]: https://github.com/Sertelegger/holdfast/issues/230
[#253]: https://github.com/Sertelegger/holdfast/issues/253
[#254]: https://github.com/Sertelegger/holdfast/issues/254
[#255]: https://github.com/Sertelegger/holdfast/issues/255
[#256]: https://github.com/Sertelegger/holdfast/issues/256
[#257]: https://github.com/Sertelegger/holdfast/issues/257
[#258]: https://github.com/Sertelegger/holdfast/issues/258
[#259]: https://github.com/Sertelegger/holdfast/issues/259
[#252]: https://github.com/Sertelegger/holdfast/issues/252
[#270]: https://github.com/Sertelegger/holdfast/issues/270
[#262]: https://github.com/Sertelegger/holdfast/issues/262
[#274]: https://github.com/Sertelegger/holdfast/issues/274
[#276]: https://github.com/Sertelegger/holdfast/issues/276
