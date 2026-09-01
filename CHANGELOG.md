# Changelog

All notable changes to Holdfast are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Direction and
upcoming work live in [ROADMAP.md](./ROADMAP.md).

**This file is the release, and a GitHub Release is a pointer to it.** A
release's notes are the section below bearing its version; the tag marks the
commit. Nothing that matters about a release lives only in the GitHub object —
release prose, unlike this file, is not in the repository, is not reviewed with
the code, and does not survive the repository being recreated. Cutting a release
is therefore: rename `[Unreleased]` to the version with its date, tag, and let
the release body quote this section.

For the same reason releases carry **no binary assets**. §12.3's binding event
is first external distribution, and several deliberate escapes — the protocol
shape record's in-place corrections most of all — are conditioned on it not
having happened. A downloadable binary is that event, and it is not one to
trigger as a side effect of writing release notes.

## [Unreleased]

Nothing yet.

## [0.0.7] — 2026-09-01

### Upgrading to 0.0.7 on macOS

**Stop the daemon before upgrading.** 0.0.7 moves the macOS runtime directory
from `~/Library/Application Support/holdfast` to `~/.holdfast`, so every
platform without `XDG_RUNTIME_DIR` now uses one path. There is no migration and
none is planned (GH #73).

A 0.0.6 daemon left running is **invisible to 0.0.7**, which will start a second
one at the new path. The old daemon keeps its live PTY sessions and
`holdfast daemon stop` can no longer reach it, because the new binary computes a
different socket path; recovery is `pkill holdfast`, which drops whatever those
sessions were holding. No privilege boundary is crossed — the old socket stays
`0600` inside a `0700` directory — it is an orphan, not a hole. The old
directory can be deleted once nothing is running from it.

**A terminal now hosts one interactive client per session.**
`holdfast attach` declares which terminal device its keyboard is, and a second
`ReadWrite` client on a terminal that already has one is refused with
`terminal_busy` rather than admitted. Attaching from *another* terminal is
unaffected — multi-client attach is a feature and is untouched — and
`holdfast watch` never contends, in either order.

The refusal exists because the alternative is silent: two processes reading one
terminal are handed alternate bytes by the kernel, so an operator's `Ctrl-B d`
is split between them and whichever misses it keeps running. Measured exactly
that way, one client exiting 0 while the other survived. tmux never needs this
guard because a foreground client owns the terminal and job control stops a
backgrounded one with `SIGTTIN` the moment it reads; `holdfast attach` has no
such protection and has to state the constraint itself.

**The session is sized to the smallest attached writer**, not to whichever
resized last (GH #66). Last-writer-wins does not converge: two clients dragging
their windows at once alternate between their own readings for as long as either
keeps moving, which was reported as a resize flood whose sizes oscillated
rather than settling. A departing writer gives its columns back. This is a
semantics change on a §23.3-gated surface and was taken through that gate
deliberately.

Alongside it, **a resize notice is coalesced rather than printed per frame** in
both `attach` and `watch` — the notice now names where a drag landed, once —
and a diagnostic is written in a single `write_all`, so two clients sharing a
terminal can no longer shred each other's output mid-word.

`PROTOCOL_MAJOR.PROTOCOL_MINOR` moves to **1.1**, with a new
`tests/wire-shape/1.1.golden`. `Attach` gains an optional `terminal` and
`AttachReject.reason` gains `terminal_busy`; both are additive, and the new
token is unreachable for any peer that did not opt in by sending the field.

**`wait_for_pattern`'s `pattern` is optional.** Omitted, the call waits until
the session stops executing and answers `reached` instead of `matched` (GH #62).
The regex form is for a *program's* prompt — `Password:`, `(gdb)`, `>>>` — and
never for the shell's own, which is a guess about the operator's `$PS1` that no
agent is in a position to make: against a customised prompt it simply never
matches, and the call reports a timeout for a command that finished long ago. A
wait that expires against a session already at a measured prompt now says so in
`warning`.

**The agent can ask for a credential it is never allowed to see.**
`request_secret_input` blocks the calling tool while a human — or, where an
operator has configured one, a credential store — supplies a value that goes
from the client straight to the child's PTY. It enters no MCP response, no log
and no broadcast to other attached clients, so there is no boundary at which a
redactor could run on it, which is the point: the value is *absent* from those
surfaces rather than redacted on them.

### Added

- **`request_secret_input`**, the twelfth MCP tool. It blocks until an attached
  human answers, a configured provider resolves the value, the child stops
  asking, or the call's own `timeout_secs` elapses. What the agent gets back is
  a status and a **byte count** — never the value, and never a handle it could
  exchange for one.
- **Operator-declared session profiles** (`[[security.profiles]]`) and
  `start_session(profile:, vars:)`. The operator writes the **process** — the
  program, the argument template, the environment and the working directory —
  and the agent supplies values into named slots. See **Security** for the
  whole of it.
- **`profile` on the session record and on `session_start`.** `status`,
  `list_sessions` and the audit log now say **where a session's command line
  came from** — the name of the `[[security.profiles]]` entry it was started
  from, or `null` for one started with `command`/`args`.

  It is there because `command` and `args` cannot say it. A profile-started
  session and an agent-authored one that produced the same argv were otherwise
  **byte-identical** on both surfaces, and only the first can ever receive a
  keychain credential — so an operator reading the trail could not tell which
  they were looking at. `null` is affirmative rather than an absent key,
  because *"this session could not have received a credential"* is the fact
  being looked for and a missing field cannot be told from a forgotten one.

  It carries the **name and nothing more**, on `binding_resolved`'s rule: not
  the operator's argument template, and not the `vars` the agent supplied. It
  is the one string on the record that is **not** redacted, and deliberately:
  it comes out of the operator's own config file, and running a built-in rule
  over it would let the redactor blank out a name the operator chose.
- **Keychain autofill from operator-declared bindings** (`[[security.secret_bindings]]`).
  A binding names a **profile**, an optional prompt pattern, a provider
  (`secret-service`, `security`, `pass`, `op`) and a reference in that provider.
  The agent supplies no part of the lookup and cannot enumerate what exists:
  every way a binding fails to resolve falls through silently to the human
  prompt, so *"your binding is exhausted"* is indistinguishable from *"you have
  no binding"*.

  **What it *can* do, said plainly rather than overstated:** naming a profile
  is naming a binding, so an agent with three credentialed profiles available
  to it chooses among three credentials. The bound is that the operator wrote
  the set, not that the agent is absent from the choice. Earlier drafts of
  §9.6 said the agent had *"no input into which entry is selected"*; that was
  false then and is false now, and this section has already been bitten once by
  a §9.6 sentence that read as protective and was load-bearing the other way.
- **`require_confirm` on a binding**, with the approval round trip to go with
  it: a new `BindingApprovalRequired` server frame and `ApproveBinding` client
  frame. The credential is resolved **after** the human approves and not
  before — a value fetched speculatively and discarded on denial is a
  credential read out of a store nobody agreed to read.
- **A notice in the session buffer when a secret is wanted and nobody is
  attached**, so an agent reading `read_output` can see why its child stopped.
  It reaches the buffer only: not the child, not the prompt the detector
  reports, and not the idle deadline.
- **`not_supported_on_platform`**, for a build whose platform has no
  out-of-band secret entry.

### Changed

- **Two config shapes that loaded at 0.0.6 now stop the daemon.** Both keys were
  documented *"Unread — 0.0.7"* before this milestone, so an operator who set
  them ahead of time had a config that loaded and did nothing; after upgrade the
  daemon binds no socket and prints the offending key. Both refusals are
  deliberate, and the error names what to change:

  - `security.autofill_on_echo_off = true` with `security.secret_provider =
    "prompt"` (which is the default). Autofill resolves from a credential store
    and `prompt` has none, so the pair reads *"on"* and behaves *"off"* — for
    the single most consequential switch in the file. Set `secret_provider` to
    `"keychain"` or `"both"`, or leave autofill off.
  - A `[[security.secret_bindings]]` entry whose `match_prompt` is not a valid
    regex, or whose `profile` names no `[[security.profiles]]` entry. The whole
    block was unread at 0.0.6, so a typo'd pattern was inert; it is now a load
    error, because a binding that never matches is indistinguishable from a
    credential store that is down.

  §10.2's published example is unaffected: it ships `autofill_on_echo_off =
  false` alongside `secret_provider = "prompt"`, which passes the new rule.

- **Every `[[security.secret_bindings]]` entry an operator has written stops
  loading, and the error names the key.** `match_command` and `match_example`
  are gone and `profile` is required, so a binding carrying either fails
  §10.1's unknown-key rule. Declare a `[[security.profiles]]` for the command
  line the binding was for and point the binding at it; see **Security** for
  why a deprecation window on those two keys would have been a deprecation
  window on the bypass class.

- **`start_session`'s `inputSchema` no longer marks `command` required, and a
  call that omits it now returns a JSON-RPC error instead of a tool result.**
  A 0.0.6-facing difference that is not a behaviour change, and it is on the
  wire. (The entry below it is the other one.)

  | | 0.0.6 | 0.0.7 |
  |---|---|---|
  | `inputSchema.required` | `["command"]` | **absent** |
  | `inputSchema.properties.command` | `{"type":"string"}` | `{"type":["string","null"],"default":null}` |
  | `start_session {"args":["x"]}` | `result.isError: true`, text *"failed to deserialize parameters: missing field `command`"* | `error.code: -32602`, *"start_session needs either `command` or `profile`"* |

  **Why.** `command` and `profile` are mutually exclusive and exactly one must
  be supplied. That is a `oneOf`, and there is no way to derive one — so
  `command` became `Option<String>`, the `required` array lost its only entry,
  and the constraint moved into the tool body, which refuses the
  neither-supplied and both-supplied cases by name.

  **What it costs a client.** The *schema* no longer tells a caller — or a
  model reading `tools/list` — that a command is needed. What is left is the
  prose on the properties: `command`'s description says *"Mutually exclusive
  with `profile`; supply exactly one"* and `profile`'s says *"Mutually
  exclusive with `command`/`args`"*. Those two sentences now carry the whole
  contract, so `tests/schema.rs::start_session_advertises_profile_and_vars_and_no_required_command`
  pins both phrases by name — dropping a word there is a silent contract
  change with nothing else to catch it.

  And a client that branches on `result.isError` takes its transport-error
  path for this one input instead. Not a new class — a bad `cwd` or a bad
  `screen_tracking` was already `invalid_params` at 0.0.6 — but `command`
  moved into it.

- **`AwaitingSecret.prompt_text` can now be redacted where 0.0.6 left it
  intact.** `Session::prompt_last_line_redacted` moved from `redact_str` to
  `redact_for_display`, which **strips control characters before** redacting
  rather than redacting the raw line. `AwaitingSecret` is 0.0.6's frame (§7.5)
  and its field is unchanged in shape; what it carries can differ. (The
  function's other consumer, `BindingApprovalRequired.prompt_text`, is new in
  0.0.7 and has no 0.0.6 behaviour to differ from.)

  Intended, and the reason for the change: a control byte between a label and
  a credential let a prompt line reassemble on a human's screen into something
  the redactor never saw as one token. Stripping first closes that.

  **It is a control-character filter and not an ANSI-sequence stripper**, and
  that distinction is the whole of the paragraph below: `one_line_for_display`
  drops the ESC byte and leaves the `[2K` that followed it. The module's real
  sequence stripper is `ansi::strip` — the `AnsiStripper` state machine — and
  it is a different function that is not on this path.

  The part worth writing down is a **side effect nobody would predict from
  either change alone**. Dropping a control byte joins the text on each side
  of it, and the joined token can match a rule that neither side matched:

  ```
  0.0.6:  "Password: \x1b[2K\rholdfast attach: all clear"   (unchanged)
  0.0.7:  "Password: [REDACTED:generic] attach: all clear"
  ```

  Dropping the `\x1b` **and the `\r`** glues `[2K` onto `holdfast`, and a
  **pre-existing, unchanged** generic rule then matches the result. The
  mechanism, since "a rule started matching" is not an explanation:
  `generic-secret-assignment` requires a value of eight characters or more
  after a `password`-ish label. In the raw line the `\r` ends the value after
  four (`\x1b[2K`), below the floor; once both control bytes are gone the
  value group is `[2Kholdfast`, eleven characters, and it matches. Confirmed
  by feeding the post-strip text to 0.0.6's own `redact_str`, which produces
  the identical marker, and by `git diff v0.0.6 HEAD -- data/redaction_default.toml`
  being empty. The rule did not change; the strip newly hands it a token that
  was not in the source.

  The direction is safe — a human-facing display field over-redacts, and
  over-redaction on a prompt label is not a leak — but it does qualify the
  property this strip is otherwise described by, *"the payload must stay
  visible; only its power to overwrite is removed"*: for a prompt where a
  stripped escape abuts adjacent text, some payload may not stay visible.

### Security

- **The operator writes the command line and the agent fills named slots in it**
  (GH #46). This is what closed GH #45, and it retires the bypass class rather
  than mitigating it: `match_command` and `match_example` are **gone**, along
  with the load-time corpus that judged one against the other.

  ```toml
  [[security.profiles]]
  name    = "prod-ssh"
  program = "ssh"                       # a literal; no {…}
  args    = ["{user}@{host}"]
  cwd     = "/srv/deploy"               # literal, optional

    [security.profiles.vars]
    user = "^[a-z][a-z0-9_-]{0,30}$"
    host = "^prod-0[12]$"

    [security.profiles.env]             # literal on both sides
    SSH_AUTH_SOCK = "/run/holdfast/agent.sock"

  [[security.secret_bindings]]
  name    = "prod-ssh-cred"
  profile = "prod-ssh"
  ```

  `start_session` gains `profile` and `vars`, mutually exclusive with
  `command`/`args` **and with `env`/`cwd`**. A `command`/`args` session
  *behaves* exactly as it did at 0.0.6, `env` and `cwd` included — nothing is
  at stake in a session that cannot receive a credential — but the tool's
  **advertised schema did change**, and a call that omits `command` now fails
  through a different channel. See *`start_session`'s `inputSchema` no longer
  marks `command` required* under **Changed**.

  **Why the shape changed rather than the check.** Four guard shapes over
  `match_command` were tried and each was defeated by someone who attacked it
  instead of reading it: anchoring (bypassed at the other end), a ~180-line
  syntactic scanner (20 accepted spellings), a 9-probe behavioural corpus (the
  whole insertion class missed), and a 51-probe corpus — where a review found 46
  bypasses and **the cheapest dodge fell from six characters to one**, `[^ ]*`,
  because all 51 probe texts contain a space. Widening the corpus made the dodge
  *cheaper*, not dearer: a larger probe set shares more structure, and a negated
  class excludes shared structure in a single stroke. That measurement is what
  ended the argument.

  **The asymmetry that makes a slot a different problem from a command line.** A
  slot is bounded — one value, matched whole, with no "rest of the line" to
  append to. Arguments come from the template, so the agent cannot *add* one.
  Therefore **a badly-written slot pattern is bounded damage**: `host = ".*"`
  lets the agent choose a hostname and it still cannot add a flag, where one
  sloppy `match_command` gave it unlimited extra arguments. `host = ".*"` is
  accepted for that reason, and `match_command = ".*"` was a load error for the
  other.

  **Substitution happens within one argv element.** `args` is an array of
  strings and exactly one output element is produced per template element, so a
  value containing spaces, quotes, `;`, `&&` or a leading `-` stays a single
  argument and cannot become a second one. There is no join, no split and no
  shell. GH #45's reproduction is therefore not merely refused through a profile
  — it is **not expressible**: `ssh prod-01 -o ProxyCommand=…` is a four-element
  argv, and `program = "ssh"` with `args = ["{user}@{host}"]` is two.

  **The rules, each a load error naming the key.** `program`, `env` (keys
  **and** values) and `cwd` are literals and admit no `{…}` — a slot in any of
  them lets the agent choose which binary actually runs, which no pattern over
  an *argument* can bound, and they are one rule because they are one hole.
  Every `{name}` in `args` has a `vars` entry and every `vars` entry is used by
  a slot: a slot with no pattern is unguarded, and a pattern with no slot is a
  typo the operator should learn at startup rather than at 3am. Each var
  pattern compiles wrapped exactly as the renderer wraps it (`\A(?:…)\z`, by
  the same function at both ends). Profile names are unique, and a binding
  naming an unknown profile is refused.

- **The operator writes the *process*, not only the command line** (GH #55).
  Profiles stopped the agent authoring the command line and left it authoring
  the process: `start_session` took `env` and `cwd` from the agent on every
  arm. **Driven twice.** `env: {PATH: …}` repointed a profile whose literal
  `program` was `ssh` at the agent's own binary — the credential came back out
  of `read_output` in cleartext, `redactions: {}`. `env: {LD_PRELOAD: …}`, with
  `program` an **absolute path** and therefore the obvious fix for the first,
  captured the credential out of the operator's binary running the operator's
  argv.

  **`require_confirm` is no mitigation.** The human is shown
  `command_line: "ssh prod-01"` — the legitimate line, because it *is* the
  legitimate line. The redirection lives in the environment, which the approval
  frame does not carry; and with `autofill_on_echo_off = true` there is no tool
  call and no human at all.

  **The class is the whole environment, not a list of dangerous names.**
  `LD_PRELOAD`, `BASH_ENV`, `ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `SSH_ASKPASS`
  and `LESSOPEN` are members of it and not the list of it, so an allowlist or a
  blocklist of variables is the wrong shape here for exactly the reason the
  `match_command` scanner was: it enumerates the ways an adversary can
  influence a process, and there is no complete list. So **`env` and `cwd` are
  mutually exclusive with `profile`**, and a profile declares its own.

  **Operators upgrading:** `start_session(profile:, env:)` and `(profile:,
  cwd:)` are argument errors where both worked before. If a credentialed
  workflow genuinely needs an environment, write it into
  `[security.profiles.env]`, where the agent cannot reach it.

  **What this does not close, stated plainly.** A profile bounds *which* command
  line a credential can reach and *which* credential an agent can obtain. It
  says nothing about the credential's **effect**: an agent that reaches a
  profile-started session still obtains an interactive shell on the target once
  injection succeeds, which is the feature working. And a slot pattern is still
  the operator's to write.

- **A session started with `command`/`args` can never receive a keychain
  credential.** That is the safety property, and it is also a real capability
  loss — both halves are true and this entry says both. An agent can only run
  credentialed sessions the operator anticipated; an operator who forgets a
  profile finds out when a legitimate workflow stops autofilling.

- **`match_prompt` is unchanged, and is still not a security control.** It
  narrowed within a `match_command` and it narrows within a profile: a
  *conjunct*, so it can only remove candidates a selection already made. It gets
  no load-time check of its own for the same three reasons — it cannot produce a
  selection hole; `""` (the documented default) already means "does not select
  on the prompt", so `.*` means what a permitted value means; and there is no
  hostile-probe corpus to write, because **the agent chooses the child and
  therefore chooses the prompt**.

  What it is *for* is disambiguating between prompts inside a session that has
  already matched: "this credential is for the login prompt, not the sudo
  prompt".

  **One oddity is recorded and not fixed.** `match_prompt` matches the
  **unredacted** prompt line — deliberately, so the redactor cannot silently
  switch an operator's binding off — and resolution success is observable by the
  agent. An operator who wrote a `match_prompt` discriminating on *secret
  content* would turn resolve/no-resolve into a one-bit oracle over text the
  redactor exists to hide. It takes the operator to author it, so it is bounded;
  it is written down chiefly as a warning to anyone who later proposes matching
  the **redacted** line "for safety", which reintroduces the exact defect the
  unredacted match prevents.

- **`BindingApprovalRequired` carries the session's command line**, so a human
  approves *this command line receiving this credential* rather than a binding
  name. `prod-ssh` reads identically whether the session is `ssh prod-01` or
  `ssh prod-01 -o ProxyCommand=nc 127.0.0.1 2222`, and telling those apart is
  the whole of the decision being asked for. `holdfast attach` and `holdfast
  watch` both print it. The field is `command` and `args` joined with single
  spaces, **redacted element-wise before the join, and stripped of every
  character that could rewrite the line it is printed on** — the frame reaches
  every attached client and those two fields are the agent's own strings.

  The strip is not tidying. An argument containing `\x1b[2K` or `\r` lets the
  agent erase or overwrite the very line the operator is being asked to decide
  from, and forge the text around it — which defeats the field rather than
  weakening it. Every control character goes, and so do the directional-override
  and zero-width characters: U+202E reverses the rendering of everything after
  it, which is the same attack in another alphabet.

  **What is *not* removed is the text itself.** An escape sequence loses its
  `\x1b` and what remains — `[2K`, `]0; -o ProxyCommand=…` — stays on screen as
  the visible nonsense it is, so an operator sees a **longer, stranger** line
  and never a shorter innocent one. That distinction is the whole point and it
  was briefly the other way round: a first cut routed the field through the
  terminal-stream ANSI stripper, which *consumes* OSC/DCS/APC payloads, so
  `ssh prod-01\x1b]0; -o ProxyCommand=nc 1.2.3.4 22\x07` rendered as exactly
  `ssh prod-01` — an argument deleted outright, which is this feature inverted.

  The same treatment is applied to `AwaitingSecret.prompt_text` and
  `BindingApprovalRequired.prompt_text`, which are agent-authored too and reach
  a worse surface: `holdfast attach` writes that field to the terminal
  unmodified.

  This is mitigation and not a fix: it does nothing for
  `autofill_on_echo_off`, which is the unattended case, and it asks a person to
  read a long line. It is additive on the attach protocol. **It was recorded by
  correcting `1.0.golden` in place rather than by bumping the minor**, on the
  argument that nothing had been distributed speaking 1.0; that argument, and
  the fact that the protocol has since moved to 1.1 for an unrelated change, are
  both in `tests/wire_shape.rs`.

- **`require_confirm` now defaults to `true`.** It defaulted to `false`, which
  made silent resolution the shape an operator got by leaving a line out. A
  binding that omits the key now resolves only after a human has seen the
  command line; write `require_confirm = false` to get the old behaviour back.
  `autofill_on_echo_off` still defaults `false` and stays there — one key
  decides whether the credential store is consulted at all, the other whether a
  human sees the command line first, and both defaults are the position that
  requires somebody to have decided.

- **What this does not close, stated because the code must not claim more than
  it delivers.** An agent that can start the `prod-ssh` profile at all still
  obtains the credential's *effect* — an interactive shell on the target — once
  injection succeeds. What these rules take away is theft of the **bytes**, for
  replay elsewhere and beyond the session's lifetime.

  **The un-quoted-join straddle is gone with the join.** An earlier draft of
  this entry recorded that `start_session("ssh prod-01", [])` presented the same
  matching subject as `start_session("ssh", ["prod-01"])`, and named profiles as
  a later milestone that would retire it. Profiles landed in this same release,
  so nothing matches a joined command line any more and that residual is not a
  residual — it is unrepresentable. The join survives only as
  `BindingApprovalRequired.command_line`, which is a rendering shown to a human
  and is matched against by nothing.

- **Every tool's `outputSchema` advertises eleven statuses where it advertised
  eight.** `secret_provided` and `secret_cancelled` join after `session_died`,
  and `not_supported_on_platform` after `spawn_failed` — inserted at their
  catalogue positions rather than appended, because that array's order is a wire
  fact. Enum widening is backward-compatible for a validating client, but the
  schema is a surface MCP clients cache, and three of the eleven are statuses
  any given pre-0.0.7 tool can never return.

## [0.0.6] — 2026-08-19

**"Human-Observable" stops being an aspiration.** 0.0.5's changelog said the
attach and watch surfaces "that would make it true are still future work". This
is that work: a second Unix socket carrying a live terminal stream to human
clients, alongside the MCP surface the agent uses, on the same sessions at the
same time.

### Added

- **`holdfast attach <session>`** — a raw-mode view of a live session with
  tmux-style detach (`Ctrl-B d`). What the agent sees, you see, and you can
  type into the same shell.
- **`holdfast watch <session>`** — the same stream read-only. It cannot send a
  write frame at all: the refusal is a server-side frame-kind table checked
  before every arm, not a client-side politeness.
- **A per-connection redaction role.** An observer's stream is redacted; an
  interactive client's is not. The decision reads the connection's *role* and
  never `client_kind`, which is audit attribution only — a rule that was prose
  until this milestone and is now a test that dies under a carve-out in either
  direction.
- **Streaming redaction**, which had to solve a problem the batch redactor did
  not: a secret split across chunk boundaries in a stream that cannot be
  rewound. It withholds an unterminated match rather than emitting it, which
  makes it *stronger* than the read path over the first ~24 KiB.
- **`SecretInput`** — a password typed into an attached client reaches the
  child's PTY without crossing the MCP wire, without appearing in any other
  client's stream, and without an audit entry carrying its content. The prompt
  is detected from termios `ECHO`, not from matching the word `Password:`.
- **`SessionExited`, `Detached` and `AwaitingSecret` frames**, so a client is
  told why a stream ended rather than discovering it by silence.

### Changed

- **The GitHub repository is now `Sertelegger/holdfast`.** The v0.0.5 notes
  recorded the slug as deliberately unchanged; it changed immediately after
  that tag. Old URLs redirect, but `Cargo.toml`'s `repository` field does not
  benefit from a redirect, so it moved too.
- **Renamed from CLASP to Holdfast.** *This shipped inside the `v0.0.5` tag* —
  it is recorded here because the section was written after that tag was cut,
  and because nothing was ever released under the old name, so it is history
  rather than an upgrade step. The project was *CLASP — Claude's Live
  Agent Shell Proxy*; it is now **HOLDFAST — Human-Observable Long-lived Daemon
  For Agent Shell Terminals**.

  The rename is not only cosmetic. Everything below changes behaviour:

  - **Crates and binary.** `clasp-core` → `holdfast-core`, `clasp` →
    `holdfast`. The installed binary is `holdfast`; re-register it with
    `claude mcp add --scope user holdfast -- <path>/holdfast mcp`.
  - **MCP identity.** `serverInfo.name` is now `holdfast`.
  - **MCP resource URIs.** `clasp://session/…` → `holdfast://session/…`, and
    the response `_meta` namespace key `clasp` → `holdfast`.
  - **Control protocol.** The handshake method `clasp/handshake` →
    `holdfast/handshake`. `PROTOCOL_MAJOR`/`PROTOCOL_MINOR` are unchanged; a
    daemon and a shim from different sides of this rename will not speak, which
    is fine because nothing was released.
  - **OSC 133 marker tag.** Injected markers now carry `;holdfast=1` instead of
    `;clasp=1`, the injected shell functions are `__holdfast_*`, and the
    `osc133_source` value `clasp` is now `holdfast`.
  - **Runtime directory.** `~/.clasp` → `~/.holdfast`,
    `$XDG_RUNTIME_DIR/clasp` → `$XDG_RUNTIME_DIR/holdfast`,
    `~/Library/Application Support/clasp` → `.../holdfast`, `clasp.pid` →
    `holdfast.pid`, `clasp.lock` → `holdfast.lock`. **There is no migration
    shim.** A stale `~/.clasp` from a development build is orphaned, not moved:
    read anything you still want out of `~/.clasp/logs/audit.log` and delete
    the directory.
  - **Config file.** `$XDG_CONFIG_HOME/clasp/config.toml` →
    `.../holdfast/config.toml` (likewise `~/.config/clasp` →
    `~/.config/holdfast`). An existing config file is not read from the old
    path; move it.
  - **Environment variables.** `CLASP_RUNTIME_DIR` → `HOLDFAST_RUNTIME_DIR`,
    `CLASP_BUILD_SHA` → `HOLDFAST_BUILD_SHA`, `CLASP_SHELL_INTEGRATION` →
    `HOLDFAST_SHELL_INTEGRATION`. The old names are not read as a fallback.

  Unchanged on purpose: the protocol version numbers, the socket filenames
  (`control.sock`, `attach.sock`, `http.sock`), the log filenames, the
  `sess_` session-id prefix, every MCP tool name, and the GitHub repository
  slug.

### Fixed

- **Four smoke checks passed against a server that never started, and 0.0.5's
  fix for the same class did not hold.** 0.0.5 recorded that "the script now
  reports its own check count, so the number in the documentation cannot drift
  away from it again". It drifted again immediately: reporting the total does
  nothing about the *transcribed* copies, and the attach phase shipped 47
  checks while the script's own header and `CONTRIBUTING.md` both still said
  38. The four survivors were three different defects — one row asserted the
  script's own setup and could not fail under any server; one asserted the
  *absence* of `http.sock`, which an empty directory satisfies; and two
  asserted only that `holdfast attach` / `holdfast watch` exited 0, which
  `/bin/true` also does. Each is repaired in kind: a precondition became an
  `exit`, the absence gained the positive that witnesses it, and the two client
  rows now assert output only a live session can have produced. The durable
  part is that **the invariant no longer carries a number** — it is `F == N`,
  which no added check can make stale — and that CI now runs the negative
  control instead of a sentence claiming someone could.

## [0.0.5] — 2026-08-19

**The first tagged release.** Until now the workspace version sat at `0.0.2`
and had not tracked the milestone number since — a placeholder rather than a
published artifact — so a build would have reported `0.0.2` and written it into
`holdfast.pid`. The version and the milestone agree from here.

Milestones 0.0.1 through 0.0.5 are all in this release; there was no earlier
tag, nothing on crates.io, and no distributed binary. The sections below are
grouped by milestone because that is how the work was built and reviewed, not
because each shipped separately.

Every milestone here was built task by task from self-contained briefs, each
task reviewed against its brief and then again as a whole branch — which is why
the "Fixed" section names classes of defect rather than issue numbers.

Milestones 0.0.3 and 0.0.4 were merged before they had sections here; they were
backfilled from their commit history rather than reconstructed from memory.

### Added

#### Milestone 0.0.1 — skeleton and PTY

- **A working stdio MCP server** (`rmcp`) with four tools: `start_session`,
  `read_output`, `send_input`, `terminate`. Single Cargo workspace —
  `holdfast-core` (library) and `holdfast` (binary, subcommands `mcp` and `version`).
- **`InProcessPty`**, a `portable-pty`-backed PTY behind a `PtyBackend` trait,
  with `setsid()` and the PTY as controlling terminal so the child's process
  group, session id and PID coincide. The trait exists so later milestones can
  vary the isolation model without touching session logic; `MockPty` implements
  it for tests.
- **`OutputBuffer`** with absolute-offset cursors, so an agent can carry a
  cursor between `read_output` calls and know exactly what it has and has not
  seen, including when the ring has evicted the bytes it asked for.
- **`Session` and `SessionRegistry`** — a dedicated reader thread per session so
  blocking PTY reads never occupy a tokio worker, live-name uniqueness (an
  exited session releases its name but keeps its id and its output buffer), a
  concurrency cap of 8 live sessions, and a 1 MiB buffer each.
- **`scripts/mcp-smoke.sh`** — an end-to-end smoke test that drives raw JSON-RPC
  through the real server and asserts on shell-evaluated output. It is the only
  check in the project that exercises the wire format.

#### Milestone 0.0.2 — deterministic prompt detection

- **Sessions now report what the program is doing, with the evidence.** Every
  prompt-bearing response carries an `interaction_mode` — `AtPrompt`,
  `Executing`, `AwaitingSecret`, `Fullscreen`, `Exited` — and a
  `detection_tier` saying how that was reached: `semantic` (OSC 133 markers),
  `terminal_mode` (bracketed paste, alternate screen, termios `ECHO`), or
  `heuristic` (output quiescence combined with a prompt-pattern score). The tier
  is there so an agent can tell a measurement from a guess.
- **A tier-A byte scanner** — a bounded state machine over the raw PTY stream
  tracking bracketed paste, the alternate screen, the window title and OSC 133
  markers. It allocates no grid and keeps no history beyond a 512-byte tail
  line, so it runs unconditionally on every chunk, and it resynchronises on
  malformed sequences rather than letting one swallow the session.
- **Termios `ECHO` sampled through `PtyBackend`**, read from the master with
  `tcgetattr`, which is what makes a genuine secret prompt distinguishable from
  ordinary output that happens to end in `Password:`.
- **A 22-row tier-3 prompt-pattern table**, nine rows carrying head guards
  derived from measuring the table against 65 lines of ordinary build, test,
  `git`, package-manager and `--help` output. Sessions may extend or replace it
  via `start_session(prompt_patterns:)`.
- **OSC 133 shell integration for bash, zsh and fish** — a one-line snippet
  **typed into the session at the first prompt, never installed**. There is
  nothing to add to an rc file; the snippet wraps whatever `PS1` the shell ended
  up with rather than replacing it, does nothing when the user's configuration
  already emits OSC 133, and is not exported, so a nested shell is integrated in
  its own right. Anything else — `dash`, a REPL, a plain program — degrades
  silently to `terminal_mode` or `heuristic`. `shell_integration: false` skips
  it.
- **A command-history ring** built from those markers, recording each command's
  exit code, start time, duration, and the byte span of its output, addressed in
  the same cursor space `read_output` uses.
- **Three new tools** — `status` (what one session is doing now),
  `list_sessions` (every session, live or exited), and `get_command_history`.
  The tool set is seven.
- **An `outputSchema` on every tool**, and the MCP 2025-06-18 annotations
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`) on
  each, so a client can validate what it gets back and reason about what a call
  will do before making it.
- **Session options on `start_session`**: `cwd` (validated and canonicalised),
  `env`, `cols`/`rows`, `prompt_patterns`, `prompt_patterns_replace`,
  `settle_threshold_ms`, `shell_integration`.

#### Milestone 0.0.3 — output processing and redaction

- **Secrets are removed from output by default.** A 51-rule set derived from
  Gitleaks finds credentials in the byte stream and replaces each with a
  `[REDACTED:<kind>]` marker naming the rule that matched. Every rule carries
  positive *and* negative examples, and the loader rejects one that has neither
  — a pattern nobody has watched fail is a pattern nobody has tested.
- **A secret split across two reads is withheld rather than leaked in halves.**
  A prefix index scans the trailing region for the start of any rule, and while
  one is open the read stops short and reports `held_back: true`, resuming once
  the bytes either complete a match or prove not to be one. `tail_lines` and
  `tail_bytes` reads opt out of this by argument, and that per-call opt-in is
  the licence — not the shape of the read.
- **ANSI stripping with a boundary rule**, so a sequence cut across a chunk
  boundary is not half-emitted as text, and **`text_encoding` modes** for
  callers that need the bytes rather than the rendering.
- **An audit trail with mandatory redaction** (§9.4). Every string handed to the
  log passes through the redactor first, so a session's own record cannot carry
  the secret whose disclosure it is recording. `read_output(redact: false)`
  returns the raw bytes and writes an entry saying so.
- **`status` and `list_sessions` redact on the way out** — `command`, `args` and
  `prompt.last_line` — and sessions gained `exited_at_unix_secs`.
- **`wait_for_pattern`**, and `send_input(wait_for:)`, so an agent can block
  until a regex matches new output instead of polling. The tool set is eight.

#### Milestone 0.0.4 — screen state, resize, interrupt

- **`get_screen_state`** renders what a full-screen program is actually showing.
  A `vt100` parser maintains a grid seeded from the ring buffer, and the tool
  returns either the whole screen or a `diff_from` delta against a revision the
  caller already has.
- **Tracking is adaptive, not always-on.** A Tier-A probe watches for the
  signals that mean a program has taken over the screen — the alternate screen,
  bracketed paste, a cursor-position report — and only then does the parser
  start. A line-oriented shell session pays nothing, which §11.4 asserts under
  load as `parsed_bytes == 0`.
- **`resize` and `interrupt`** as tools, bringing the set to **eleven**. `resize`
  reports the geometry read back from the session *after* the `ioctl`, not the
  geometry requested, so a resize that did not take effect cannot report success.
- **A cursor-position prompt sub-signal (T3c).** Where the heuristic tier
  previously scored only the text of the last line, it now also scores where the
  cursor is sitting, combined as `quiescent × max(pattern, cursor)`.
- **Holdfast answers Primary Device Attributes** (`\x1b[?6c`, byte-exact, no
  optional parameters), which is what stops a `fish` session stalling ~10 s at
  startup waiting for a terminal that never replies. Measured: answering the
  other three common probes while withholding DA1 changes nothing; answering
  DA1 alone takes the stall from 10.04 s to 0.02 s. Replies are rate-limited,
  are never a `send_input` audit event, and deliberately do not count as session
  activity — otherwise a child querying in a loop would keep its session alive
  for ever.

#### Milestone 0.0.5 — the daemon and the control protocol

- **Sessions no longer die with the MCP client.** `holdfast mcp` is now a thin
  shim: on first use it auto-spawns a background `holdfast daemon`, and afterwards
  it reconnects to the one already running. The daemon owns the PTYs, so
  quitting and restarting Claude Code leaves every session alive, at the same
  prompt, with its output buffer intact. `holdfast mcp --no-daemon` keeps the old
  single-process behaviour, and is the shape the Windows build will reuse.
- **A versioned control protocol** over a Unix socket — length-prefixed CBOR
  frames with a 16 MiB cap, a `holdfast/handshake` that both peers check, and the
  §18.3 error catalogue. Mismatched protocol majors refuse to connect from
  *either* side, so a protocol break cannot be papered over by one end being
  lenient.
- **The daemon never opens a TCP listener.** The socket is Unix-domain only,
  its directory is `0700` and verified after creation, and every connection's
  peer credentials are read with `SO_PEERCRED` and compared to the daemon's own
  uid *before a single frame is parsed*. A credential that cannot be read fails
  closed.
- **New CLI subcommands** — `holdfast daemon run|start|stop|status`, `holdfast list`,
  and `holdfast logs <session> [--tail N] [--raw]`, with §18.8's exit codes and
  §3.2's idempotence contracts (`daemon start` on a running daemon and
  `daemon stop` on a dead one both succeed and say so).
- **The §9.4 caller is derived from the connection, never from the request.**
  A read that disables redaction records two facts: `tool`, the mechanism, and
  `client_kind`, the accountable party — taken from the uid-checked handshake,
  so `holdfast logs --raw` is logged as `cli` and an agent's
  `read_output(redact: false)` as `shim`. There is deliberately no argument an
  agent could set to label itself as a human. `client_kind` is attribution
  only; nothing in the read path branches on it.

### Fixed

Corrections that were measured rather than assumed. Each names a class rather
than a one-off:

- **A single `killpg()` does not reach a shell's background jobs.** Job control
  puts each in its own process group, so `terminate` swept the leader and left
  orphans. Measured against real PTYs; `terminate` now enumerates and signals
  every process group in the child's session, and interrupts target the
  terminal's foreground group.
- **`send_input`'s blocking write could wedge the entire server.** A raw-mode
  child that stopped reading parked a tokio worker uncancellably, and each retry
  took another — a handful of calls took down the whole MCP server, including
  `terminate`, the only way out. The write now runs on the blocking pool under a
  deadline with a 64 KiB payload cap, and the binary bounds its runtime shutdown
  because Linux does not wake a parked pty-master writer when the slave closes.
- **`read_output` reported truncation that had not happened** — on both of its
  branches, at different times and for different reasons.
- **A stale `ECHO` sample reported `AwaitingSecret` for ordinary commands.** The
  50 ms cache paired a readline prompt's echo-off with the bracketed-paste-off
  of the command just submitted, which is the exact signature of a secret
  prompt: 0.95 confidence, and the documented response is to interrupt a human
  for a password. For `sleep 5`. Measured at 267 spurious samples under load, 0
  after. Fixed where the bad value was produced — the cache deleted, the sample
  taken under the detector lock — rather than guarded downstream, because the
  tempting guard (require a non-empty tail line) is a false negative on bash's
  `read -s`, a genuine secret prompt that prints nothing.
- **One concept had two spellings, twice.** The alternate screen was a second,
  wider spelling of "terminal-mode tier available": a single alt-screen toggle
  marked a session available for life, so a `dash` prompt reported `Executing`
  at a live prompt with nothing able to clear it. The same shape then turned up
  in the semantic dimension, where the OSC 133 flag was unpinned against
  unmodelled subcommands. One concept, one spelling.
- **The escape-sequence ceiling was a forgery guard that could not be one.** At
  the trip point a huge well-formed sequence and a truncated one share a
  byte-identical prefix, so no online rule can distinguish them. It is now
  documented as a *blindness budget*, raised to 1 MiB so a routine sixel frame
  no longer trips it, with its residual asserted at its real reach — including
  an ESC-free sixel, which disproved the claim that accidental forgery needs an
  `ESC`.
- **A head guard silently zeroed recall for every numbered-host prompt** while
  the corpus stayed green, because the corpus had `hostname% ` and no
  `build01% `. Pattern rows are now pinned from both sides of the boundary they
  draw, and the first sweep to do that passed for the wrong reason — witnessed
  by an accepted false positive rather than by a real prompt — so it was redone.
- **`scripts/mcp-smoke.sh` failed red on correct code.** `grep -q` under
  `pipefail` exits early, `printf` dies of `SIGPIPE`, and the pipeline reports
  141 — three to six runs in twenty under load, latent since 0.0.1.
- **The MCP server's own `instructions` string described a four-tool surface**
  for the whole of 0.0.2, so an agent that trusted it never learned that
  `status`, `list_sessions` or `get_command_history` existed. The smoke script
  now asserts every tool name appears there.
- **Sixteen tests that could not fail** were found and fixed across 0.0.2, and
  ten across 0.0.1. Several of the 0.0.1 ones matched the PTY's echo of their
  own command line, and so passed against a session running `sleep 300` instead
  of a shell. Injecting the defect and confirming the test goes red is now
  standard practice; see [CONTRIBUTING.md](./CONTRIBUTING.md).
- **The exit cleanup asked who *holds* the socket, not whose it *is*.** A
  daemon's teardown probed `control.sock` with a `connect()` and unlinked it if
  nothing answered — but an AF_UNIX listener stays connectable while *any*
  descriptor references it, so a forked child holding an inherited fd made the
  probe report "live" about a listener nobody served. It failed roughly half of
  all default-parallel test runs. Identity replaced liveness, and the obvious
  form of that fix was itself wrong: on ext4 the successor is handed the
  predecessor's freed inode number in **500 of 500** measured trials (tmpfs
  0/500, monotonic counter), so comparing `(dev, ino)` would have silently
  restored the very bug it was closing. The daemon now holds an inert `O_PATH`
  descriptor and compares against an inode it still owns — not a number it
  wrote down. `O_PATH` rather than a duplicated listener, because a duplicate
  keeps the socket answering across teardown and converts a clean
  connect-refused-and-respawn into a reset that respawns nothing.
- **A `wait_for_pattern` blocked the `interrupt` that would have ended it.**
  One `Arc<ControlClient>`, a mutex held across both the write and the read,
  and a sequential per-connection loop composed into a transport where a single
  outstanding call — default 30 s, capped at 3600 — blocked `interrupt`,
  `terminate`, `read_output`, `status` and `list_sessions` on *every* session.
  Each of the three parts was correct alone. `--no-daemon` dispatched them
  concurrently all along, so the agent's documented escape from a hung wait
  worked on one transport and not the other.
- **A permission check refused ordinary installs.** Any `~/.holdfast/logs` created
  before 0.0.5 is `0775` under the umask 002 that Debian, Ubuntu and RHEL ship,
  and the daemon refused to start on it — reproduced on the author's own
  machine with no setup. Both remedies the error suggested were wrong: one
  deletes the audit trail, and the other names an instance-selection variable
  that has nothing to do with permissions. A check that rejects a normal
  install is a bug, not a hardening.
- **Auto-spawn quietly moved the logs onto tmpfs.** Reaching the default
  instance through `holdfast mcp` wrote `audit.log` and `daemon.log` under
  `$XDG_RUNTIME_DIR`, where they are destroyed at logout — making the retention
  windows unreachable in the configuration every install actually uses.
- **`holdfast mcp --no-daemon` ran the entire tool surface on `Config::default()`**,
  ignoring the operator's configuration completely. On Windows that is the only
  transport. It now refuses a config the daemon would also refuse, which is a
  new failure mode on that transport and an intended one.
- **A smoke check passed against a server that never started.** Splitting one
  assertion in two left the "no `listChanged`" half comparing `null` to `null`
  in `jq`, which holds whether or not a server is there. Run against `/bin/true`
  it was the lone survivor of 39 checks. The script now reports its own check
  count, so the number in the documentation cannot drift away from it again.

### Security

- **`start_session` no longer echoes `portable-pty`'s raw spawn error**, which
  embeds the entire `$PATH` and would otherwise land in the conversation
  transcript on every failed spawn.
- **`cwd` is validated and canonicalised.** `portable-pty` silently *discards* a
  cwd that is not an existing directory and falls back to `$HOME`, so an
  unvalidated `cwd` told the agent `ok` while running the command somewhere else
  entirely.
- **Signals are refused once the child has exited.** A reaped PID can be
  recycled, and the `/proc` sweep would then target a stranger's session. Every
  candidate group is also filtered on `pgid > 0`, because `kill(-0, sig)`
  signals Holdfast's own process group.
- **Caller-supplied inputs are bounded**: at most 64 prompt patterns, each
  compiled under a 64 KiB size limit, with rejected patterns clipped to 120
  characters in the error message; `send_input` payloads at 64 KiB;
  `read_output` at 32 KiB by default and 256 KiB hard. Unbounded, 5000 patterns
  were accepted and put every tool call at milliseconds, and a 200 KB regex
  produced a 200 KB error that then sat in the transcript for the rest of the
  conversation.
- **Truncated escape sequences can no longer forge terminal modes.** A CSI cut
  at the parameter cap could end in `;2004` and set the bracketed-paste flag,
  and an abandoned sequence used to hand the rest of its payload to the state
  machine as ordinary text — measured, a 9 KiB OSC 52 clipboard write ending
  `\r\nroot@prod:/etc# ` produced exactly that as the detector's last line, which
  the pattern table scores at the act threshold.
- **A size-capped read returned a cursor inside the secret it had just
  redacted.** The chunk itself was correct — the whole secret was replaced by a
  marker — but the continuation offset landed mid-span, and the 512-byte
  lookbehind on the next read cannot reach back to a `-----BEGIN` anchor a
  kilobyte earlier. The following chunk therefore matched nothing and returned
  raw key material, with an empty `redactions` map and no audit entry, so it was
  indistinguishable from output that never held a secret. With `max_bytes` set
  to 1024 — an ordinary choice made to save tokens — a 1.7 KB PEM split that way
  every time, not occasionally. The cursor now advances past the end of any span
  it would otherwise land inside. The lookbehind was deliberately *not* enlarged:
  any bound is exceeded by one more byte, which fixes an instance instead of the
  class.
- **The audit trail failed open, and one output boundary had no redactor at
  all.** A daemon that could not write its audit log served anyway; `daemon.log`
  was written raw, with no panic hook, so a panic message carrying the values
  that caused it went to disk unredacted; a config parse error echoed the
  offending line verbatim, which for a config file is a line that may *be* the
  credential; and `session_start` recorded `redaction_enabled: true` as a
  constant rather than as something it had checked. The parse-error fix drops
  the underlying `toml` error rather than keeping it as a `source`, because a
  redacted `Display` over a raw source is the same disclosure one chain-walk
  away.
- **The config file was trusted on nothing but its path.** It is now checked
  through the open descriptor — regular file, owned by the caller or root, not
  world-writable — so there is no second lookup to race. Symlinks are
  deliberately still accepted: the checks judge what the link resolves to, and
  refusing them outright would break every `stow`, `chezmoi` and `yadm` install.

See [SECURITY.md](./SECURITY.md) for what is and is not in scope, including the
residuals that are known and accepted.

### Known limitations

Stated because they are easy to mistake for bugs:

- **No attach yet.** Sessions now outlive the MCP client (0.0.5), but there is
  no `holdfast attach` or `holdfast watch`, and no web UI — a human cannot yet look at
  or type into a session the agent is driving.
- **Unix only.** The tree is kept compiling and clippy-clean for
  `x86_64-pc-windows-gnu`, but signalling returns an error there and there is no
  process-group handling.
- **Eleven tools.** No `precheck_command`, `request_secret_input`, `send_file`,
  `fetch_file` or `wait_for_any` yet.
- **`get_command_history`'s `command` field is best-effort**, reconstructed from
  the terminal's echo: a command longer than the terminal width is captured
  truncated to its *tail* with no ellipsis and no error, and non-ASCII bytes are
  recorded as Latin-1. **The truncation runs upstream of the redactor**, so a
  credential whose leading token falls in the discarded front reaches the agent
  unredacted on a field otherwise documented as redacted. Known, tracked, and
  not yet fixed; the repair belongs where the front is discarded, not in the
  redactor.
- **`fish` shell integration is unverified at runtime**, and the Primary Device
  Attributes stall measurements it rests on were taken by hand rather than in
  CI — `fish` is deliberately absent from the runner. README's platform section
  explains why installing it would not close the gap.
- **On Unix without `/proc`**, the process-group sweep degrades to the child's
  group plus the terminal's foreground group, so a background job in a third
  group can survive `terminate`.

[Unreleased]: https://github.com/Sertelegger/holdfast/compare/v0.0.7...main
[0.0.7]: https://github.com/Sertelegger/holdfast/releases/tag/v0.0.7
