# Changelog

All notable changes to Holdfast are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with **one stated
addition**: a `Known limitations` section, for behaviour that is easy to
mistake for a bug.

Direction and upcoming work live in [ROADMAP.md](./ROADMAP.md). How a release
is cut, named and published is in
[CONTRIBUTING.md](./CONTRIBUTING.md#releases).

## [Unreleased]

### Added

- A `windows-2022` CI job: native MSVC clippy over `--all-targets`, the source
  guards, the `#[cfg(windows)]` CLI arms executed, and a filtered `--lib` over
  the modules whose Windows arm differs from its Unix one. The full `--lib` is
  still not run, because 55 of its tests spawn a real shell ([#91]).
- Control protocol **1.2**: a `holdfast/cancel` method and an optional
  `cancel_token` on every request, so an MCP `notifications/cancelled` reaches
  the daemon instead of stopping at the shim. Additive in both directions — a
  1.1 peer sends no token and is simply not cancellable, and a 1.2 client gets
  `unknown_method` from a 1.1 daemon, which is what happens today ([#127]).
- `secret_cancelled` gains a fifth reason, `caller_cancelled`, and §7.5's
  `SecretRequestClosed` a fourth outcome of the same name. A request the agent
  abandoned and a request the human or the child abandoned are different
  endings, and `cancelled` already meant the second ([#127], [#105]).
- `[security] disabled_redaction_rules`: a list of built-in §9.2 rule names to
  switch off, for the operator whose output a rule mangles. What it names
  leaves the set every client-facing boundary runs — `read_output`,
  `resources/read`, `get_screen_state` and an attached observer's stream — and
  the §4.1 prefix index is rebuilt from the reduced set with it. **A name no
  built-in rule has is a load error naming it**: a misspelling that switched
  off nothing would read as a decision about redaction that had been taken,
  which is what [#128] is about. Disabled rules are reported once at startup on
  stderr ([#128]).
- Attach protocol **1.3**: `SecretInput.allow_echo`, an optional `bool` that
  defaults to `false`. It is the deliberate opt-out from the echo gate above —
  *"I can see this terminal, I know it echoes, send it anyway"* — so children
  that legitimately never clear `ECHO` (a TOTP-code prompt, a REPL asking for
  an API key) stay reachable through the masked path rather than being pushed
  to `send_input`, which has no masking at all. Absent means `false`, so a
  client that predates the field fails **closed**; nothing an agent sends
  selects it. `holdfast attach --allow-echo` is the CLI spelling ([#137]).

- `read_output` gains `apply_holdback`, the way to ask for the last N lines
  **inside** §4.1's holdback. A bare `tail_lines`/`tail_bytes` is the per-call
  opt-in and still bypasses it, unchanged; `apply_holdback: true` declines that
  opt-in while keeping the tail. The daemon could not express "the last N lines,
  safely" before, which is why `holdfast logs --tail` reached for the bypass.
  Only `true` is accepted — `false` has exactly one meaning anyone could want,
  and putting a second, unaudited licence to bypass on the wire is the defect
  this argument exists to close ([#169]).

### Fixed

- **One byte >= 0x80 anywhere in a read window no longer costs the redaction
  prefilter its automaton ([#194]).** Forty-five of the fifty-one shipped rules
  carry a Unicode `\b`, the prefilter was built from the rule source verbatim,
  and a Unicode word boundary installs a quit set over every byte >= 0x80 — so
  a single `é`, em dash or emoji dropped the whole `RegexSet` onto the slow
  engine for the length of the window. Measured on this tree, release, on
  REQ-O-007's 41,472 B default read window (512 lookbehind + 32,768 + 8,192
  lookahead): **0.082 ms pure ASCII against 37.4 ms with one em dash at the
  midpoint, 456x**, and 0.09 ms after. A default `read_output` of this
  repository's own `CHANGELOG`+`README`+`ROADMAP` — 871 non-ASCII bytes out of
  108,501 — goes from 112 ms of span-finding to 11 ms.

  The prefilter's patterns now carry `(?-u:\b)` where the boundary's meaning
  provably survives the respelling, and carry no boundary at all where it does
  not. It is the rewrite [#142] made for the liveness DFA, with the premise
  read off the pattern text rather than off an indexed prefix, and with
  deletion instead of refusal as the fallback — a `RegexSet` is one automaton,
  so one surviving Unicode `\b` re-arms the quit set for the whole set.

  **A prefilter may over-report freely and may never under-report, because
  `find_spans` runs only the rules it names.** Both branches are
  superset-preserving and the argument is per-boundary: deleting an assertion
  can only enlarge a language, and `\b` -> `(?-u:\b)` holds wherever `\b`
  does when the pattern's own side of the boundary can only be an ASCII word
  byte. The two generic assignment rules can begin a match on `.` or `-` and
  get the deletion; so does any boundary next to `k`, `K`, `s` or `S`, the
  four ASCII letters whose `(?i)` expansion reaches U+212A and U+017F. A
  differential over the shipped rules, their positive examples with seven
  non-ASCII probes planted at the first byte, the midpoint and the last, and
  randomly generated rule sets finds **zero** divergences for what ships and
  **2,623** for an unconditional respelling.

- **The redaction prefilter is built with a 64 MiB lazy-DFA cache ceiling
  instead of the `regex` crate's 2 MiB default, so a large *pure-ASCII* read
  no longer falls off the automaton ([#194]).** This is the second of that
  issue's two cliffs and it has nothing to do with the first: no byte in the
  window is ≥ 0x80, and the collapse is the cache being cleared on every block
  once the fifty-one-rule automaton outgrows it. Measured on this tree,
  release, prefilter scan only, over the rule file's own examples with the
  non-ASCII bytes stripped — the densest near-miss corpus there is, and the
  one the new test uses — **256 KiB costs 10.33 ms at the default and 0.040 ms
  here**. Across six real corpora the sweep is 355 ms to 19 ms.

  **The number is a ceiling and not an allocation, which is the only reason it
  can be this large.** The cache grows to what a search needs and stops: at
  16 MiB it tops out at 10.4 MiB resident and 32 and 64 MiB measure the same,
  so the headroom buys nothing today and buys the cliff staying gone when
  §9.2's quarterly gitleaks refresh makes the set bigger. What it does cost is
  paid per thread concurrently running a redaction scan, because `regex` keeps
  a cache pool — 2.5 MiB/thread today against 5.9 MiB/thread here on the worst
  corpus, so twelve concurrent readers move 29 MiB to 69 MiB. There is one
  `RuleSet` per daemon, not one per session.

### Changed

- **`[security] redaction_enabled = false` is refused at load, and §9.4's
  `session_start` row no longer carries `redaction_enabled`.** The key disabled
  redaction nowhere: its only consumer was that row, so `false` bought an
  operator every rule still running *and* an audit trail asserting on every
  session that they were not. `true` and the default load exactly as before, so
  no working config breaks; the error on `false` names
  `disabled_redaction_rules`, which is the mechanism that does something. The
  row now carries `redaction_rules_active` (a count) and
  `redaction_rules_disabled` (the names), both read off the rule set the
  session's own reads run — a bool whose only accepted value is `true` carries
  no information, and `true` beside three disabled rules is the same wrong
  answer in a smaller size. Replacing a §9.4 field is §21.6's case and its
  binding event is first distribution, which has not happened ([#128]).
- **`read_output` can now return more redaction markers on colourised output,
  and this is a payload change rather than a free win.** A rule that matches
  the stripped text but not the raw bytes now fires: `\x1b[36mpassword\x1b[0m
  = \x1b[33mnot-set-yet\x1b[0m` returns `password = [REDACTED:generic]` where
  it returned `password = not-set-yet`. The plain form was always redacted —
  `generic-secret-assignment` matches on the *label* and does not inspect the
  value — so this is that rule reaching the stream the agent actually receives,
  but it means `grep --color` over a config file now returns markers where it
  returned placeholders ([#125]).
- On Windows native, seven daemon-backed subcommands — `daemon run`,
  `daemon start`, `daemon status`, `list`, `logs`, `attach`, `watch` — refuse
  with exit 64 from a single shared message; `list` and `logs` name the MCP
  tool that does answer there. `holdfast mcp` still serves, in-process.
- `daemon stop` on Windows exits 0 with "no daemon running", and
  `daemon status --json` still prints `{"running": false, "supported": false,
  "reason": …}` before exiting 64, so a `--json` consumer needs no Windows arm.
- Holdfast warns rather than refuses about Windows file permissions: the
  runtime directory, logs and `config.toml` are used with the ACL they inherit,
  and the config trust check does not run. An ACL-shaped answer is still owed.
- CI no longer skips itself on documentation-only changes — `paths-ignore` is
  gone from both of `ci.yml`'s triggers, because a workflow filtered out at the
  `on:` level posts no check run and a required check on it would leave every
  docs-only pull request pending forever.
- A surviving mutant now fails the mutation sweep; its dated
  `continue-on-error` calibration exemption is retired.
- The `test` job runs under `cargo nextest` (0.9.143, digest-pinned) at a 60 s
  `SLOW` warning and a 300 s per-test kill, so a hung test is named rather than
  only turning the job red. Doctests get their own `cargo test --doc` step,
  because nextest does not run them at all.
- For library consumers, `daemon::{server, spawn, peer, attach_server}`,
  `protocol::client` (with its `ClientError` / `ControlClient` re-exports) and
  `mcp::shim` are `#[cfg(unix)]`; `daemon::paths`, `protocol::{frame, handshake,
  method}` and the rest stay cross-platform. Nothing changes on Unix, and
  nothing is removed — `holdfast-core` did not compile for Windows at all
  before this release ([#19]).
- **`regex-automata` and `regex-syntax` are built with `opt-level = 3` in the
  dev profile.** Determinizing the fifty-one DFAs the [#142] entry below adds is
  the cost; `PrefixIndex::build` runs once per `OutputProcessor`, and a
  `holdfast-core` test builds one per row — so the unoptimized figure lands on
  every test and on every daemon a CLI test starts. Measured on this tree, with
  the override against without it: `PrefixIndex::build` 77 ms against 1.28 s,
  `cargo test -p holdfast-core --lib` 29 s against 145 s, and
  `--test redaction_sweep` 50 s against a run still going at 11 minutes when it
  was stopped. Nothing about the shipped binary changes; `--release` already
  optimized both.
- **§4.1's in-flight scan answers the same question about half as much work on
  ordinary output, and three orders of magnitude less on a hostile one.** Three
  changes to `PrefixIndex`, each exactly answer-preserving — nothing is
  withheld that was released, and nothing released that was withheld. The
  prefix index buckets into a 256-slot array rather than a `HashMap<u8, _>`,
  which removes one SipHash of one byte **per input byte of every read**. The
  two full-suffix walks — the `has_value_group` arm and `still_alive`'s
  no-automaton fallback — become one backward pass per call and an index
  comparison against it, which is exact rather than conservative because the
  predicate is upward-closed and that pass finds its least witness. And
  `unresolved_from`, whose answer is the `min` of that scan and the trailing
  value run, computes the run **first** and passes it in as a ceiling: an
  anchor at or after the run's start could only ever lose the `min`, so
  declining to look for one cannot move the answer. That ceiling is the one
  thing here that is not safe everywhere — it changes the scan's *own* answer —
  so it is a private parameter with one permitted caller and a source guard
  holding the line. Measured on this tree, before → after: a 41,472-byte read
  window of ordinary build output 1.58 → 0.65 ms; the same window of
  `-secret_key=` 326 → 0.97 ms; 270,336 bytes of it 24.2 s → 7.1 ms; and
  `unresolved_from` over 270,336 bytes of `-sk-` with no trailing delimiter
  22.3 s → 0.157 ms. **The half of that family that ends in a space is
  unchanged and that is deliberate** — its cost is in the liveness automaton,
  which none of this touches, and the merged multi-start sweep that would reach
  it is a much larger change held back for a separate decision. A
  `#[cfg(test)]` oracle keeps the pre-change scan and a differential test runs
  the two against each other over the shipped rule set, the adversarial user
  rules and 400 randomly generated ones — random sets because the arm the
  fallback lives in is dead code against the built-in fifty-one ([#163]).

### Security

- **`get_screen_state` no longer paints a credential that arrived with an
  escape sequence inside it, and the grid is the only surface this covers.**
  §4.1's holdback decides whether a secret is still arriving by scanning the
  **raw** trailing region, and a control byte is what *ends* the value run
  that test rests on — so `ghp_` with 39 of its 40 characters and a colour
  reset spliced inside matched nothing, the boundary stayed at `buffer.head`,
  and the grid, whose mask is a function of that boundary, rendered the token
  contiguously, because an emulator writes no cell for an escape. On a
  `readOnlyHint: true` tool, with `read_output` reporting `held_back: false`
  and `redactions: {}` in the same moment. §9.2 Subject 2 names the class in
  terms. The grid now masks on a **second** boundary, which asks §4.1's own
  question of every byte stream a consumer can derive from those bytes rather
  than of the raw bytes alone, and maps the answer back to raw offsets
  ([#142]).
- **What that does not cover, listed rather than implied.** Every other
  consumer of the §4.1 boundary *shortens* — it caps a read end and moves a
  cursor — and none of them takes the new one: `read_output`,
  `resources/read`, `wait_for_pattern`, `holdfast logs` and the `observer`
  attach stream behind `holdfast watch` are byte-identical to before. (This
  sentence read *"`holdfast logs` (whose `--tail` is outside the holdback to
  begin with)"* until [#169] put `--tail` **inside** §4.1's holdback; see that
  entry. What is byte-identical is this entry's own subject — the **new grid**
  boundary, which no read surface takes — and that is unchanged.) That is
  deliberate and it is measured: a shortened read cannot be revised, because
  the byte that would revise it — the space, the newline, the `ESC` — is the
  byte the view deleted, and the read consults no other stream. The same
  change made on `read_output` stranded ordinary output permanently at 2,570
  zero-byte second reads against `main`'s 258, and the two cases are not
  separable, because `use crate::re_exports` followed by a colour reset
  genuinely *is* the `resend-api-key` rule with seven of its twenty-four value
  bytes arrived. A mask is admissible where a shortening is not for one
  reason: it denies no range, moves no cursor, and is recomputed from the live
  grid on every call, so the next call revises it. §18.2 already gave the grid
  that spelling — *"a screen has no tail to cut"* — and the reason it gives is
  geometry, never principle ([#142]).
- `prompt.last_line` needed nothing and got nothing. It has run the in-flight
  test over the **rendered** line since 0.0.5, which is a view-driven denial
  by another route, and REQ-O-013 mandates it; measured on `main`, this
  issue's own fixture already returns `""` there. Worth stating because it
  means a view-driven denial had already shipped on one surface while the
  rule in `normalise.rs` still read as an unqualified ban ([#142]).
- **The cost, measured on three corpora and not zero.** The new boundary is
  open at moments §4.1's is not, and every such moment masks part of the
  grid. At each 512-byte read boundary: **+0.0000 pp** on 95 KB of this
  repository's prose, on 5.3 MB of its own Rust source, and on a real
  `cargo build` log captured through a pty (0.0510 % either way); **+0.0548
  pp** on a 2.4 MB `jq -C` blob, and **+0.2998 pp** on that source recoloured
  mid-word. `held_back` stays rare, which is the 0.0.3 plan's requirement for
  it. The one place this makes an existing defect *worse* rather than merely
  more frequent is the grid's documented eviction residual: on a session that
  has outlived its 1 MiB ring buffer, any open boundary masks the **whole**
  visible screen, and this boundary reaches that state at the rates above.
  Both arms are pinned by
  `an_evicted_front_masks_the_whole_screen_and_the_new_boundary_reaches_it_oftener`,
  whose other half is the leak being closed — on `main` that same moment
  returns the credential in the clear ([#142]).
- **One attacker-controlled byte can mask part of the grid, and the reach is
  bounded by the scan window.** A view that *consumes* rather than deletes
  joins an indexed prefix to the end of the region by itself: an unterminated
  8-bit OSC introducer (`\x9d`, [#139]'s byte) makes that view swallow
  everything after it, so the `re_` of an ordinary `use crate::re_exports`
  becomes a candidate and the cells from it onward are masked. The fixture is
  that line and no longer the `key-` of an npm warning, because the predicate
  below has to call the candidate *alive* for the primitive to exist at all,
  and `\bre_[A-Za-z0-9_]{24,}` is alive across ordinary identifier bytes where
  `\bkey-[a-f0-9]{32}` is not. Measured at 121 bytes of reach-back and four
  markers; **bounded at `partial_secret_scan_bytes` (512) structurally**,
  because the view is built from that window and offsets map back into it. A newline does not clear it —
  the consuming view swallows the newline too — so what clears it is the
  prefix scrolling out of that window, the same terminating rule an attached
  observer's stream already uses. No byte is denied on any surface, and §4.1's
  boundary is unmoved on the same fixture ([#142], [#139]).
- **`get_screen_state.title` is *not* covered, and it is this issue's other
  named shape.** The mask is defined over *cells* (REQ-O-011a: the cells where
  the live render differs from the render at the boundary), and a window title
  is set by an OSC sequence that paints no cell — so `\x1b]0;ghp_<39 of
  40>\x07` leaves the boundary open and still returns the partial credential
  verbatim in `title`, with `held_back: false`, because `redact_str` replaces
  only *complete* matches. Measured on this branch. Not closed here on
  purpose: the title is a reconstruction with no byte-to-position mapping, so
  the only available spellings are `prompt.last_line`'s — clip at the
  candidate, or report nothing — and unlike a last line a title is **sticky**,
  so either one denies the field until the child sets a new one. That is a
  separate decision about a different field and it should be taken as one
  rather than arrive inside this change ([#142]).
- **Still open on `read_output`, and this entry is not the fix for it.** A
  credential arriving with an escape inside it is still released
  half-emitted there, bounded at *(rule minimum − 1)* characters, and [#166]
  — an unbounded leak on the same two tools, reachable by `cat ~/.ssh/id_rsa`
  and needing no escape at all — is untouched ([#142]).

- **A credential is no longer written into a child whose terminal still
  echoes.** `request_secret_input` has no echo-state precondition — it raises
  and broadcasts `AwaitingSecret` the moment the agent calls it, without
  consulting the child — so an agent that called before its child reached a
  password prompt got a human to type a real credential into an echoing
  terminal. The line discipline put it in the ring buffer and `read_output`,
  the default and redacted path, handed it back to that agent in the clear; an
  arbitrary password matches no redaction rule, so nothing downstream removed
  it. The write is now gated on the child's line discipline, sampled on the
  writer thread one statement before the write and against the tty rather than
  a cache of it — the check §9.6's autofill has carried since 0.0.7. A refused
  submission is dropped and zeroed without reaching the PTY. Not a regression:
  reproduced identically at `v0.0.7` ([#137]).
- `secret_cancelled` gains a sixth reason, `not_echo_off`, and
  `SecretRequestClosed` a fifth outcome of the same name, so a human whose
  password was refused is told that rather than `cancelled` — which they would
  read as the child having given up ([#137]).
- A refused `SecretInput` submission is now zeroed: the `too_large` and
  `unknown_request_id` arms dropped the decoded credential as a plain
  `Vec<u8>`, whose `Drop` does not zero. Nothing read the value — what it broke
  was the zeroing discipline, on the two arms a hostile submission lands on
  ([#57]). Residuals filed from the same review: [#82], [#83], [#84], [#85],
  [#86].
- `ci-hygiene.sh`'s dated calibration exemption no longer applies to a workflow
  that merely mentions the marker inside a comment — it must *be* a comment
  line — so a file can no longer exempt itself from the bans on
  `continue-on-error`, unpinned actions and `secrets.` references.
- **`holdfast logs <session> --tail N` no longer releases a secret the same
  session's `read_output` is withholding.** The CLI sent `tail_lines`, which is
  §4.1's per-call bypass, so every tail-shaped read inherited an exemption the
  spec grants to two arguments on one tool — and names this surface a
  non-member of, twice. Measured on a live daemon in one instant:
  `read_output(since_cursor: 0)` answered `held_back: true` and
  `holdfast logs --tail 50` printed the credential in the clear. Unlike
  `--raw`, nothing recorded it. `--tail` now asks for the tail inside the
  holdback and stops at the boundary, saying so on stderr; with nothing in
  flight it returns byte-for-byte what it always did. The bypass predicate has
  moved off the read's *shape* and onto the request, where the licence
  actually is, and `ReadRequest` has no `Default`, so the next read surface is
  asked by the compiler rather than inheriting an answer. `--raw` is untouched:
  it is this surface's opt-in, it still returns the bytes, and it is still
  audited. No branch on `client_kind` — the CLI is held back for what it sends
  (REQ-SEC-018). §11.4's third arm is finally written, and it is one
  measurement rather than two tests that can drift ([#169]). Filed under
  `### Security` rather than `### Fixed` to sit with [#142] and [#137], the
  milestone's other two credential-release fixes; it was under `### Fixed`
  until review.
- **Two behaviour changes `holdfast logs` carries as a consequence, stated
  rather than left to be discovered.** (a) **A session that has exited can
  now withhold the tail of its own log, permanently.** §4.1 is explicit that
  this is correct — *"If a process stops mid-token, the partial stays
  withheld"* — and REQ-O-005 makes it normative, but before [#169] `--tail`
  bypassed the holdback and returned the bytes, so on `main` a completed
  session's last line comes back whole and here it may not. The withhold is
  kept and **is deliberately still reachable through `--raw`**, which is the
  recourse §4.1 names in the same sentence (*"may take the audited `redact:
  false` path"*) and §4.1:476 names as this surface's spelling of it; making
  it unreachable would invent a rule the spec does not have and strand the
  bytes entirely. (b) **The stderr note now says which of three things
  shortened the read.** `held_back` is `safety_end < cap_end`, and §4.1's
  holdback, REQ-O-008's unfinished trailing escape and [#14]'s
  `unresolved_from` bound all set it; one sentence described the first as if
  it were all three. It claimed a secret was in flight on `--raw`, where
  `redact: false` disarms that mechanism *before* the field is computed and
  the audit log says so, and it advised a retry that a dead child can never
  satisfy. The note is now chosen from `--raw` and the response's `state`.
  It is also flushed against stdout, so `holdfast logs X 2>&1 | tail` no
  longer splices it into the log text ([#169]).
- **Residual, not closed: under shim/daemon version skew an agent can ask for
  the safe tail read and silently get the bypassing one.** `mcp::shim`
  answers `list_tools` **locally** — its own module doc names this class and
  defers it — and `ReadOutputArgs` carries no `deny_unknown_fields`, so a
  newer shim in front of an older daemon advertises `apply_holdback`, forwards
  it, and the daemon drops it: the caller gets `held_back: false` and no
  error. A false affordance `main` does not have, since on `main` the argument
  does not exist. Closing it properly needs a manifest method on the control
  protocol (§7.4.1 defines none), which is the same protocol addition
  `shim.rs` already defers; **the protocol version is deliberately not bumped
  for it** — `PROTOCOL_MINOR` "cannot start refusing anybody"
  (`attach/handshake.rs`), so a bump would not make an older daemon apply a
  holdback it has no code for ([#169]).
- **`regex-automata` and `regex-syntax` are built with `opt-level = 3` in the
  dev profile.** Compiling fifty-one DFAs at startup (see the [#142] entry
  below) is the cost, `PrefixIndex::build` runs once per `OutputProcessor`, and
  a `holdfast-core` test builds one per row — so the unoptimized figure lands on
  every test and on every daemon a CLI test starts. Measured on this tree, with
  the override against without it: `PrefixIndex::build` 77 ms against 1.28 s,
  `cargo test -p holdfast-core --lib` 29 s against 145 s, and
  `--test redaction_sweep` 50 s against a run still going at 11 minutes when it
  was stopped. Nothing about the shipped binary changes; `--release` already
  optimized both.

### Fixed

- **The `binary` arm of the in-flight test asks the rule as well, so a
  certificate no longer pins the holdback for the rest of the session
  ([#166]'s precondition — on its own it closes no leak).**
  `earliest_partial`'s `binary` arm was an unconditional `true`.
  `private-key-block` is the whole of that class, a PEM body's newlines defeat
  `is_value_byte` at every line, and until [#142] there was nothing sharper to
  ask — but an unconditional `true` is not the conservative reading of *is this
  secret still arriving*, it is the absence of the question. Condition 3 then
  asks only *has this rule matched*, never *can it still match*, so
  `-----BEGIN CERTIFICATE-----` — which matches the rule's indexed prefix and
  is that rule's own shipped `negative` example — held `holdback_boundary` at
  its anchor for as long as those bytes stayed in the scan window, past
  `-----END CERTIFICATE-----` and past every ordinary line printed after it.
  The arm now asks the automaton, through a `binary`-specific predicate rather
  than `still_alive`, and keeps the unconditional hold where
  `PrefixIndex::build` refused the rule one: `is_value_byte` is not a usable
  fallback for a `binary` rule the way it is for every other one, because it
  calls a key dead on its second line.

  **A dead state is believed only when it was reached on bytes every emitted
  view reproduces verbatim, and that guard is not decoration.** Without it this
  change *releases key material*, measured: `-----BEGIN RSA PRIVATE KEY-----`,
  forty lines of body, **one `0x9b`** in the middle of it and no `-----END`
  yet — `earliest_partial` goes `Some(0)` to `None` and the body already
  arrived goes out in the clear. `[\s\S]` is a *codepoint* class, so a lone C1
  byte puts the automaton in a dead state; the same class keeps `rule.regex`
  from matching the raw bytes, so `find_spans` covers nothing either and there
  is no marker and no audit entry. What does cover those bytes is `all_spans`
  over the normalised views ([#135], [#139]) — and only once `-----END` lands.
  `holdback_boundary` reads the raw region and nothing else by design, which
  was harmless while this arm was a constant no raw byte could change and stops
  being harmless the moment a raw byte can release. An ANSI escape in the
  label, a tab the rendered grid expands into the spaces `[ A-Z]` accepts, and
  a `\r` that puts the rendered row in a different order are the same failure
  by three further routes. So the walk stops at the first byte outside
  printable ASCII and `\n` and answers *in flight*. A certificate is unaffected:
  it dies on the `-` after a plain-ASCII label, 27 bytes in, before any of that.

  **The narrowing is per anchor, not per region, which is what makes it safe.**
  A dead state is the statement *no arriving byte can produce a match from
  here*, about one rule at one offset. A combined PEM — the certificate
  followed by its key, which is what an haproxy bundle is — carries two
  anchors, and `earliest_partial` walks left to right and returns the first
  *qualifying* one: the certificate's bytes go out, and the boundary lands on
  the key's own `-----BEGIN`.

  **Measured, as the share of 512-byte read boundaries at which a candidate
  judged over the whole buffer holds, before → after:** a synthetic
  three-certificate bundle `100.0 % → 0.0 %`; a 3.3 KB RSA key still streaming
  `100.0 % → 100.0 %`, which is the half that must not move;
  this file plus `README.md` **as they stood before this entry was written**
  `0.7 % → 0.7 %` and an 853 KiB `cargo build -vv` log `0.0 % → 0.0 %`,
  neither containing a `-----BEGIN` at all, so neither reaches this arm;
  `holdfast-core/src/**/*.rs` `94.2 % → 52.0 %`. The qualification on the
  prose row is not pedantry — this entry put four `-----BEGIN` anchors into
  the file, and the corpus that results is held at **88.5 %** of its
  boundaries by the old arm and **87.3 %** by the new one, the difference
  being that the old one stops at the certificate and the new one stops 842
  bytes later at the private key.

  **A real certificate does not reach this today, and that is the point of
  landing it first.** At `partial_secret_scan_bytes`' 512 bytes the
  `-----BEGIN` anchor falls out of the scanned region long before
  `-----END CERTIFICATE-----` arrives, so the permanent hold is prevented by
  accident; [#166] is about widening that region for `binary` rules, which
  removes the accident. The rows added here are therefore asserted over
  regions far wider than 512, per §9.2: *"If the fixture fits inside one unit,
  it is not testing this rule."*

  **One release is a behaviour change rather than a narrowing, and it is
  stated rather than left to be found.** A PEM header this rule cannot match
  at all — `-----begin rsa private key-----`, which RFC 7468 does not permit
  and which `find_spans` would never have redacted, because the pattern is
  case-sensitive while the prefix index is not — was held for ever and is now
  released. Nothing the redactor could ever have covered changes hands: that
  hold was a strand and not a protection, and it would have ended at
  `read_output(redact: false)` in any case. A permanent hold on a key the rule
  *can* match is unchanged and deliberate — REQ-O-005: *"Quiescence does not
  release the holdback."*

- **The in-flight test the holdback rests on asks the rule, not a byte range
  ([#142] — narrowed, and *not* closed).** `earliest_partial`'s continuation
  test — *"every byte from the indexed prefix to the end of the region could
  still belong to the value"* — was decided by `is_value_byte`, a flat
  `0x21..=0x7e`. That is wrong in two directions at once: it holds runs no rule
  could ever complete, and it releases the moment a control byte lands inside a
  value that is genuinely still arriving. A rule now carries an anchored dense
  DFA built from its own pattern, and the predicate asks *could this rule still
  match if more bytes arrived*. **Not every rule, and the exceptions are
  checked rather than listed**: 49 of the 51 build one and keep it, two are
  refused for the reason in the paragraph below, and of the 49 keepers the
  seven remaining `has_value_group` context rules are never asked it — so the
  predicate decides 42 of the 51, the one `binary` rule among them by way of
  the [#166] entry below. A rule that is refused, or never asked, keeps the
  behaviour it has today.

  **What it buys is the false holds, and the honest summary is that it is a
  small number.** `parsing key-value`, `npm WARN @acme/key-manager` and
  `npm WARN @acme/sdk-gateway` are no longer secrets in flight, because
  `\bkey-[a-f0-9]{32}` can reach neither the `v` of `value` nor the `m` of
  `manager`, and `launchdarkly-key`'s `sdk-` wants a hex UUID and cannot reach
  the `g` of `gateway`. Measured over 20,000 lines of the repository's own
  source at the parent commit, as the share of line-final boundaries that hold:
  plain `0.885 %` → `0.860 %`, and unchanged at `0.060 %`, `0.040 %` and
  `0.060 %` for trailing `\x1b[K`, mid-line colour and a trailing `✔`. The
  price is at startup: `PrefixIndex::build` goes from ~0.19 ms to 77 ms and
  49 automata totalling 1.93 MiB by `DFA::memory_usage()`, once per
  `OutputProcessor`, which is one per daemon. (The before-figure is from the
  parent commit without the profile override above; it builds no automata, so
  that override is immaterial to it.)

  **It strands nothing, and that is the constraint this shape was chosen for
  rather than a happy result.** The predicate reads the raw stream, where the
  byte that revises its answer has already arrived — an escape ends a candidate
  no rule can take. `use crate::re_exports\x1b[0m` with no trailing newline
  still returns all 25 bytes with `held_back: false`, and
  `"$ cargo build\n   Compiling re_export\x1b[0m"` still reports
  `prompt.last_line = "   Compiling "`, both byte-identical to the parent
  commit.

  **[#142]'s leak is still open and this does not close it.** A credential
  still arriving *with an escape inside it* is still released half-emitted,
  because the raw stream is the only one the holdback reads. Closing it needs
  the emitted views asked as well, and **that view-driven withhold is under
  research rather than shipped**: measured, the form of it that was written
  strands ordinary output permanently — a session whose last output is
  `use crate::re_exports\x1b[0m` returns 11 of 25 bytes with `held_back: true`
  for ever, and blanks `prompt.last_line`, which is how an agent learns a
  password is being asked for. The open question is not *which* rules a view
  may withhold on; it is that a view has already deleted the byte that would
  have ended the withhold, so the decision is unrevisable in a way the raw
  stream's never is.

  **Two shipped rules get no automaton and keep the byte-class test**, by a
  check rather than by a list. `generic-secret-assignment` and
  `secret-key-assignment` declare prefixes their own match can begin *before*,
  so an automaton anchored at the prefix reports an ordinary
  `MY_APP_PASSWORD=hunter2hunter2` line DEAD while the rule matches the whole
  of it. Both are `has_value_group` rules that [#152] keeps on `is_value_byte`
  anyway, so nothing observable moves — the check exists so that #152's fix
  cannot land that false DEAD without noticing. A user rule from
  `extra_redaction_patterns` whose pattern carries a `\b` and whose prefix opens
  on punctuation is refused for the neighbouring reason: the ASCII rewrite of
  `\b` is only an over-approximation when the prefix's first byte is a word
  byte, and where it is not, the automaton releases a value the byte-class test
  held.

  **[#152] stays open, and for the reason it always had.** The nine context
  rules keep the byte-class test on the raw stream because their patterns
  legitimately admit whitespace between the label and the value: driven from
  the `P` of `"$ ssh dev@box\r\nPassword: "`, `generic-secret-assignment`'s
  automaton is ALIVE, and a candidate that can still grow never dies at the end
  of a region that has stopped growing — `earliest_partial` would go `None` to
  `Some(15)`, `read_output` would return only the first line with
  `held_back: true`, and `prompt.last_line` would become `""`, on the most
  common state this tool exists to handle. **What #152 needs is a sharper byte
  class, not a re-routing**, and the refusal above is why: those two rules now
  have no automaton to be re-routed onto, so removing the carve-out leaves them
  on `is_value_byte` regardless (measured on this tree:
  `still_alive(generic-secret-assignment, …, 15)` is `false`).

  Two behaviours are re-pinned deliberately: `ghp_abcsk-ant-xy` is no longer a
  boundary at all (a GitHub token cannot reach a `-`, and `sk-ant-` sits
  mid-word behind a `c` where its `\b` forbids a match), and
  `parsing key-value` moves from the documented residual to the list of
  holdbacks liveness retired.
- The secret **provider** path enforces the deadline and the size limit the
  caller declared. A helper process that inherits the provider's output pipe no
  longer outlives them: the bounded phase is pipe *collection* rather than the
  direct child's exit, which is what the unconditional reader joins ran past.
  Measured before the fix, against a 1 s budget with a grandchild holding the
  pipe for 4 s: resolved successfully after 4.02 s. A `max_secret_bytes` of 1
  accepted a 7-byte credential and wrote 8 with the newline; it is now refused
  where the bytes are read ([#126], the same descriptor-inheritance shape as
  [#52] and [#21]).
- Cancelling an MCP request now cancels the work it started. A cancelled
  `request_secret_input` closes its request, tells every attached client with
  its own outcome word, and frees the slot — a replacement used to be refused
  `concurrent_request_pending` for up to 120 s. A call whose future is dropped
  rather than cancelled frees the slot too ([#127]).
- `read_output` no longer reassembles a credential it declined to redact.
  Redaction searched the raw ring buffer while ANSI stripping ran afterwards,
  so a colour reset planted inside a token broke the rule's anchor at match
  time and was then removed on the way out: a complete, valid credential
  reached the agent on the **default** read path, reported as
  `redactions: {}`. Matching now runs over each byte stream the read pipeline
  derives from the window it judges — raw, stripped, and either of those under
  `lossy_printable`, which drops the C0 controls the stripper keeps — and maps
  every match back to raw buffer offsets, so cursors and `bytes_returned` are
  arithmetically unchanged. The **holdback is unchanged too, deliberately**:
  the in-flight predicate it rests on is load-bearing on the very control
  bytes those streams remove, so it still reads the raw region alone, and a
  credential straddling a read boundary with an escape inside it is still
  released half-emitted ([#142]). *That is still true of `read_output` and no
  longer true of `get_screen_state`; see the Security entry above.* `redact: false` and `--raw` are byte-identical
  released half-emitted ([#142]). **That predicate has since been replaced** —
  it asks the rule rather than a byte class now, see the [#142] entry above —
  and the sentence survives it: the rule's own automaton is load-bearing on
  those same control bytes, so the holdback still reads the raw region alone
  and the residual is unchanged. `redact: false` and `--raw` are byte-identical
  to before ([#125]).
  **This closed the matching side of #125 and not every class of the
  defect.** The range and grammar axes — [#138] (spans judged over the
  window while a sub-range is emitted) and [#139] (8-bit C1 introducers,
  which the stripper does not open a sequence on and the screen emulator
  discards as an unhandled control — the discard being what splices the
  token) — are now closed too; see the two entries below. The *withholding*
  side is still open **on every surface that shortens**: a credential still
  arriving with an escape inside it is released half-emitted by `read_output`
  ([#142] — the grid no longer does this), and a token split across reads
  with an escape inside it is still partly released ([#135]). Redaction is not
  closed as a class.
- **Redaction now judges the bytes that go out, not only the window they
  were drawn from ([#138]).** Spans were found over
  `[window_start, window_end)` while the read emits `[req_start, read_end)`,
  so a rule's `\b` could be decided by a lookbehind byte the caller never
  receives — and the token that reached the caller therefore went
  unredacted. The emitted page is now judged as well as the window.
  Measured over a 61-fixture sweep: **51 of 61 leaked on paged geometry
  before, 0 after.** The page pass adds markers only and cannot move the
  cursor, which is pinned by a test with a `redact: false` control.
- **An 8-bit C1 introducer planted inside a credential no longer survives
  every view ([#139]).** The view enumeration came from the ANSI stripper's
  grammar, which opens a sequence only on `0x1b`, so a token spliced with a
  C1 byte matched no rule on any stream while `get_screen_state` redacted
  the same line — the screen surface and the read surface disagreed about
  the same bytes. The enumeration now carries a C1 axis with **two**
  filters, not one: the emulator *discards* C1 as an unhandled control,
  which is what splices the token in the grid, while a real 8-bit terminal
  *consumes* it as a sequence introducer. Both streams are reachable and
  both are now matched. Measured: **47 of 61 fixtures leaked whole-read
  before, 0 after**; across all geometries, 4727 leaking rows → 0.
- A session that has finished no longer keeps the writer thread that only a
  running child needs. The registry now holds live sessions and completed
  records separately, and retiring a record drops the sending half of its write
  queue so the thread leaves. Retained history is unchanged — `list_sessions`,
  `status`, `read_output`, `holdfast logs`, the session resources and an attach
  arriving after the end all answer exactly as before — but it is now bounded
  at **64 records and 16 MiB of output**, oldest first, where it was previously
  unbounded in both. Measured before the fix with a live limit of 1 and 24
  further sessions created and completed: 24 parked threads and 24 MiB
  retained; after, none and 16 MiB ([#129]).
- Autofill no longer misses a credential prompt drawn before its listener was
  armed; the listener replays the current echo-off episode once, de-duplicated
  against a delivered edge, which also closes the lagged-receiver case
  ([#106]).
- A fulfilled secret request is no longer reported as `outcome: "cancelled"`
  when autofill answered the prompt before an attached client's raise ([#105]).
- The session reader drains the PTY once more after it observes the child die,
  instead of breaking on the death. `read` and `is_alive` are two separate lock
  acquisitions, so a backend that did *both* its last write and its exit in the
  gap between them left the reader abandoning those bytes — and then publishing
  `reader_finished`, which is the positive fact *"the buffer is final"* that
  [#42]'s guard entitles `wait_for_pattern` to trust. The waiter then did
  everything right over a buffer that was final and empty, and answered
  `session_died`. The exit condition is now *a read returned zero and the
  backend was already dead before that read*. This is [#42]'s symptom through a
  different mechanism, one layer down, so the fix is in the producer rather
  than the consumer.
  **No agent-visible behaviour changes on a shipped Unix session, and the entry
  says so rather than claiming a user-facing win it cannot support.** The hole
  is in the *non-blocking* reading of a zero-byte read that the reader's own
  contract allows; `InProcessPty` on Unix is blocking, and `portable-pty` maps
  the master's `EIO` onto `Ok(0)`, so a zero read there means every slave
  descriptor is closed and no byte can follow it. What the defect does reach is
  the test double — it is what reddened the `macos-native` job 3 times in 28
  runs — and the process-isolated `SubprocessPty` seam, which is the priority
  post-v0.1.0 backend and will be non-blocking. Measured with an 80 ms probe in
  that gap: 10 failures in 10 before and 0 in 10 after, while [#42]'s own
  deterministic row failed 0 in 5 under the identical probe — which is what
  makes them two windows and not one ([#149]).
- `wait_for_pattern` no longer reports `session_died` over output the child
  really produced; the final rescan waits on `Session::reader_finished()`
  rather than on `is_alive()` ([#42]).
- `interrupt` now documents that a signal can land on the shell before it has
  handed the terminal to the job, and that the remedy is to call again — the
  gap belongs to the product and is the one a real terminal has ([#112]).
- A `settle_threshold_ms` at or above the deadline no longer makes a
  pattern-less wait time out beside a true `AtPrompt`; the settle window is
  clamped against the time left from the first idle sample rather than from the
  call.
- `holdfast mcp` on Windows writes its audit trail again: `USERPROFILE` is the
  fallback where `HOME` and the `XDG_*` variables are unset, and an empty `HOME`
  now counts as no answer rather than as one. `config.toml` was ignored on the
  same machine for the same reason.
- `holdfast attach` no longer discards an ending it has already been sent: the
  unsolicited startup `Resize` is best effort and the reader names the ending,
  so attaching to an already-exited session exits 0 instead of 2 onto a blank
  terminal ([#39]).
- The "the daemon closed the connection" diagnostic is reachable again — the
  startup write returned before the frame loop ran, so a genuinely dead daemon
  and an exited session were indistinguishable to an operator ([#39]).
- The Windows build compiles again: 31 clippy errors on
  `x86_64-pc-windows-gnu`, 27 of them in the daemon subsystem and four in
  `config.rs` and `protocol/client.rs`, closed by compile-gating rather than by
  porting ([#19]).
- `a_connection_mid_handshake_holds_off_the_client_less_exit` half-closes with
  `shutdown(2)` instead of `close(2)`: a forked sibling's inherited copy of a
  connected descriptor keeps the socket open, so the daemon read no EOF. No
  product change ([#52], the same descriptor-inheritance window as [#21]).
- Five `screen.rs` rows wait on the rendered grid, `Session::screen_tracking`
  or `Session::cursor_signal` rather than on the ring buffer, which the reader
  publishes one step earlier. Test-only.
- `every_emitted_unix_field_is_a_number`,
  `every_nested_object_a_tool_returns_has_its_key_set_pinned` and the
  `exited_session` fixture wait on a closed command-history entry or on the
  reader's drain flag instead of on the output bytes. Test-only.
- `no_output_is_classified_between_the_echo_sample_and_the_answer` no longer
  reads the command count between the reader's two publications. Test-only.
- Three `secret::binding` rows synchronised on a signal that did not mean what
  their next line needed, and each now carries the delay that produced its
  figure. `buffer_until_count` was added alongside, and caught a
  `write_secret_if_unread` mutation that had passed all 54 rows in the module.

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
[#21]: https://github.com/Sertelegger/holdfast/issues/21
[#39]: https://github.com/Sertelegger/holdfast/issues/39
[#42]: https://github.com/Sertelegger/holdfast/issues/42
[#45]: https://github.com/Sertelegger/holdfast/issues/45
[#46]: https://github.com/Sertelegger/holdfast/issues/46
[#52]: https://github.com/Sertelegger/holdfast/issues/52
[#55]: https://github.com/Sertelegger/holdfast/issues/55
[#57]: https://github.com/Sertelegger/holdfast/issues/57
[#62]: https://github.com/Sertelegger/holdfast/issues/62
[#66]: https://github.com/Sertelegger/holdfast/issues/66
[#73]: https://github.com/Sertelegger/holdfast/issues/73
[#82]: https://github.com/Sertelegger/holdfast/issues/82
[#83]: https://github.com/Sertelegger/holdfast/issues/83
[#84]: https://github.com/Sertelegger/holdfast/issues/84
[#85]: https://github.com/Sertelegger/holdfast/issues/85
[#86]: https://github.com/Sertelegger/holdfast/issues/86
[#91]: https://github.com/Sertelegger/holdfast/issues/91
[#105]: https://github.com/Sertelegger/holdfast/issues/105
[#106]: https://github.com/Sertelegger/holdfast/issues/106
[#112]: https://github.com/Sertelegger/holdfast/issues/112
[#125]: https://github.com/Sertelegger/holdfast/issues/125
[#126]: https://github.com/Sertelegger/holdfast/issues/126
[#127]: https://github.com/Sertelegger/holdfast/issues/127
[#128]: https://github.com/Sertelegger/holdfast/issues/128
[#129]: https://github.com/Sertelegger/holdfast/issues/129
[#135]: https://github.com/Sertelegger/holdfast/issues/135
[#137]: https://github.com/Sertelegger/holdfast/issues/137
[#138]: https://github.com/Sertelegger/holdfast/issues/138
[#139]: https://github.com/Sertelegger/holdfast/issues/139
[#142]: https://github.com/Sertelegger/holdfast/issues/142
[#149]: https://github.com/Sertelegger/holdfast/issues/149
[#166]: https://github.com/Sertelegger/holdfast/issues/166
[#169]: https://github.com/Sertelegger/holdfast/issues/169
[#163]: https://github.com/Sertelegger/holdfast/issues/163
[#194]: https://github.com/Sertelegger/holdfast/issues/194
[#152]: https://github.com/Sertelegger/holdfast/issues/152
[#166]: https://github.com/Sertelegger/holdfast/issues/166
