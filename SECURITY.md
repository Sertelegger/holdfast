# Security Policy

## Supported versions

**Holdfast is pre-release.** `v0.0.5` was the first tag, `v0.0.7` is the
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
repeat it — the release workflow has no such step". Both were true when #161
wrote them on 2026-09-14. Two consecutive merges four days later took out one
clause each:

- **`release.yml` builds five platform binaries and a `SHA256SUMS.txt` and
  attaches them** (#198). It attaches them to a **draft**, and a draft's
  assets are not served from `releases/download/vX.Y.Z/` — so nothing has
  reached anyone, but the *reason* has changed. It is no longer that nothing
  is built; it is that promoting a draft is a human running
  `gh release edit vX.Y.Z --draft=false`, deliberately, and nobody has. No
  tag has run that path yet either: `v0.0.7` predates it, which is why the
  three releases above carry no assets and why there is no draft sitting
  there to promote.
- **`release.yml` carries a `cargo publish --workspace --locked`** in a
  `crates-io` job (#197). It is gated on a `CARGO_REGISTRY_TOKEN` repository
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
are distributed" from 0.0.3 until #161. Only the third clause was still true
by then — and #161's replacement for it was false four days later. Both
rewrites went wrong the same way, by describing the machinery instead of the
artifacts, which is why this paragraph now says what exists and leaves what
`release.yml` does to `release.yml`. `CONTRIBUTING.md`'s release procedure
names this file's version-pinned claims as a step, for the ones a tag
invalidates rather than a merge.

| Version | Supported |
| ------- | --------- |
| `main` (0.0.x, pre-release) | ✅ best effort |
| `v0.0.5` – `v0.0.7` | none — the fix goes on `main` |

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
  logs`, a `holdfast watch` stream, and the audit log.
- **Rule**: one entry in the vendored rule set
  (`crates/holdfast-core/data/redaction_default.toml`, 55 rules), describing
  one secret shape. A match is replaced with `[REDACTED:<kind>]`, where
  `<kind>` names the rule.
- **Label-keyed rule**: a rule that finds a value by the label in front of it
  (`password=…`, `API_KEY: …`), rather than by the value's own shape. These
  rules need a value of at least 8 bytes.
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

**Tier 1: guarantees.** Each is stated with its status today.

| Clause | What it promises | Status today |
|---|---|---|
| **G1. Routing** | Every byte that reaches an agent or an observer comes from the redactor, except through the raw paths named below. | **Holds**, with the raw paths listed under G1. |
| **G2. Known values** | A secret whose exact value Holdfast knows is masked wherever it appears, within a published scope. | **Not built.** Known gap: `printenv`. |
| **G3. Write gate** | Holdfast writes a secret into a session only at a real secret prompt, or on a human's explicit override. | **Partial.** The gate admits any terminal with echo off, which includes an idle shell prompt. |
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
    requested range to 8192 bytes past its cap. It covers the raw bytes and
    every text stream the read can emit.
  - **Straddling secrets.** A secret that straddles the start of a page is
    found if it begins within those 512 bytes. One that straddles the end is
    found if it ends within those 8192.
  - **Private keys** are kilobytes long, so they get a longer reach. A
    complete key that opens up to 16 KiB (`UNVOUCHED_CARRY_BYTES`) behind the
    window is found as well.
  - **Outside the reach.** A longer match, or one that opens further back, is
    outside it; see the [register](#residual-register).
  - **Withholding.** A cursor read also withholds in-flight text at the end of
    the output.
- **The observer stream** behind `holdfast watch` (attach role `Observer`).
  - It runs the same rules over the same set of text streams, with 512 bytes
    of lookbehind and up to 8 KiB carried between PTY reads.
  - It withholds in-flight text in the same way.
  - A viewer that joins part way through is seeded from the 16 KiB before its
    join point, so it judges the stream as a viewer that had watched from the
    start would.
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
   - It is audited, not gated.
   - A withheld partial has to be reachable somehow, and this is the way.
3. **`tail_bytes` and `tail_lines` reads skip the in-flight withhold.**
   - A tail read returns in-flight text from the last 512 bytes as far as it
     has arrived. Every complete match, and every other mask, still applies.
   - A tail read that passes `apply_holdback: true` keeps the withhold.
     `holdfast logs --tail` always passes it.
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
  dropped, and reaches nothing but the PTY write.
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
- This is not fixed yet (GH #TBD-printenv).

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

**What exists.** Holdfast refuses to write a credential into a session unless
the child's terminal has echo turned off. This applies to both production
paths that write one:
- a human's answer to `request_secret_input` from an attached client;
- a value that an operator-configured secret provider resolves.

The terminal is sampled on the writer thread one statement before the write,
not read from a cache. A refused value is zeroed without reaching the PTY
(`write_secret_if_unread`, `crates/holdfast-core/src/session/mod.rs`). A
backend that cannot report the terminal's state is refused in the same way.

**What it admits.** Echo off is not the same thing as a password prompt. Line
editors such as bash's readline and zsh's zle, and the Python and Node REPLs,
turn echo off and draw the characters typed at them themselves. So a secret
submitted while a shell sits idle at its prompt passes the gate. Then:
1. the line editor draws it, so it reaches the session's output;
2. it runs as a command when the newline that Holdfast appends by default
   arrives;
3. it can be saved to the shell's history.

The classifier that reports `interaction_mode: AwaitingSecret` already asks a
stricter question: echo off, the terminal still in canonical (line-at-a-time)
mode, and no bracketed paste (`crates/holdfast-core/src/detect/detector.rs`).
The write gate does not use it. Using the classifier's predicate, with a
per-submission override for the human, is proposed and not yet decided.

**The human override.** `holdfast attach --allow-echo` skips the echo test
for that connection:
- It is a human's decision at an attached terminal, and it reaches no tool
  argument.
- It is `false` when absent, so a client that predates it fails closed.
- It exists for programs that ask for a code without ever clearing echo.
- Under it, the value is still masked on the human's own terminal. It still
  lands in the session's output, where only the pattern rules can catch it.

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
once, and every surface renders that single verdict, is under consideration
and not decided.

#### G5. Bounded withholding: not claimed

**Neither quiet nor the child's exit releases a withheld read.**
- A program that stops after text that could begin a secret leaves every
  cursor read held at that point until more output arrives. After the child
  exits, no more will.
- The text stays reachable through the audited `redact: false`, and through
  a `tail_*` read (see G1).
- `holdfast watch` does the opposite at the end of a session: it releases
  what it was still holding (R6 in the register).

A bound for this is proposed and not built: mask such text once the session
has been quiet for a set time, and at exit.

**Known indefinite hold.** A prompt that ends in a secret label with no value
after it, printed by a program waiting on input, is held.
- In bash, `printf 'Enter password:'; read -r x` leaves every cursor read
  stopped before `Enter password:`, for as long as the program waits, with:
  - `held_back: true`;
  - `prompt.last_line` empty;
  - `interaction_mode: Executing`.
- `Password:` and `API_KEY=` behave the same. With a trailing space
  (`Password: `), nothing is held.
- The planned fix starts a label rule's hold at the first byte of the value,
  not at the label.
- See R14 in the register (GH #TBD-enter-password).

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
- **A label-keyed value shorter than 8 bytes** (`PASSWORD=hunter2`). The
  floor exists because without it ordinary text such as `token: default` and
  `password: example` would be masked.
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

This table lists every known case in which output gets past the redactor
through something other than a raw path named under G1, and every known case
in which the redactor masks or drops output that is not a secret.

- Each row was measured on the tree this file describes.
- Every repro uses generated values. Never test with a real credential.
- A *key* below means a PEM private-key block (`-----BEGIN RSA PRIVATE
  KEY-----`, random base64 lines of 64 characters, `-----END …`). The largest
  standard key, RSA-16384, is 12.4 KB of PEM.
- Row numbers are stable. A fixed row stays in the table, marked fixed, so a
  reference to it keeps its meaning.

| ID | Leaks or over-masks | Trigger | Repro sketch | Status | Can a targeted fix close it? |
|---|---|---|---|---|---|
| R1 | Both: a document's masking depended on the page size it was read at | Paging the same output at different `max_bytes` | `cat` a long document that mentions a private-key header in prose; page it at 4 KiB, 32 KiB and 256 KiB | **Fixed for prose** by `e80a631` (GH #242): a header in prose no longer starts a candidate. This repository's `CHANGELOG.md` now loses the same 10 of 2,842 lines at every page size, all of them rule matches on credential-shaped examples. Keys longer than 16 KiB still depend on page size: R2–R4 | Done for prose. For long keys, see R2–R4 |
| R2 | **Leaks** the later lines of a complete key, with `redactions: {}` | A single key block longer than about 16 KiB + `max_bytes` + 8 KiB, paged with cursor reads; or a tail read that starts more than 16 KiB after the header of a key longer than 16 KiB. On `holdfast watch`, any complete key longer than about 16 KiB | Generate a 500-line key, `cat` it, and page from before the `cat` at `max_bytes: 4096`: body lines 248–499 come back raw. A 1,000-line key leaks at the default 32 KiB | **Narrowed** by `e80a631` (GH #243): every standard key size is masked at every page size, and so are blocks up to 26 KB at 4 KiB and 8 KiB pages. Longer blocks: open, GH #TBD-c6 | Partly. A longer reach moves the bound; no fixed reach removes it |
| R3 | **Leaks** key body more than 16 KiB past the header | A key block with no END line, longer than 16 KiB, followed by other output | Print a header and 300 body lines with no END, then `echo done`; page from before at 4 KiB or 32 KiB: body lines 248–299 come back raw | **Narrowed** by `e80a631` (GH #242), from 114 lines at 4 KiB and all 300 at 32 KiB. Open: GH #166 | Partly. The 16 KiB reach bounds what a header whose block never closes can mask, so a longer reach moves the bound without removing it |
| R4 | **Leaks** a whole key still arriving, `held_back: false`, `redactions: {}` | A read at the end of the output while a key's header is more than 16 KiB behind it | `cat` a 260-line key with no END, then `sleep 25`; read during the sleep: all 260 body lines raw, and 12 raw rows on the grid. At 245 lines (16.2 KB) every surface masks it | **Open**, GH #166. The 16 KiB bound is deliberate: an unbounded search on every read is quadratic in output an agent controls | Only with an unbounded search at the end of the output on every read |
| R5 | **Leaks** a token glued to a word character in front of it | A prefix rule's leading `\b` does not match after a letter, digit or `_`, with or without a colour change between them | `printf 'x\033[31mghp_%s\033[0m done\n' <36 random alphanumerics>`; a read from before it returns the token clear with `redactions: {}`. A read whose page starts exactly at the escape or at the token masks it. With a space instead of `x`, every read masks it | **Open**, GH #TBD-c7 | The dependence on where a page starts, yes. Whether `xghp_…` should match at all is a rule decision, because the `\b` keeps rules from matching inside longer identifiers |
| R6 | **Leaks** on `holdfast watch` a partial secret still carried when the session ends | The child exits with a partial token unfinished at the end of its output | `sh -c 'printf "deploy with ghp_0123456789abcdefghij"; sleep 2'` with `watch` attached. While it runs, `watch` shows `deploy with `; at exit it prints the partial token raw, with no marker. `read_output` goes on withholding it after the exit | **Open**, GH #TBD-watch-eof. A partial private key is masked at exit (`600bab7`, GH #242). Bounded by what the stream still carries, at most 8 KiB | Yes |
| R7 | **Leaked** key body on the `get_screen_state` grid | A completed key whose header had scrolled off the screen, or a key still arriving | `cat` a 50-line key in a 40-row session, then `get_screen_state` | **Fixed** by `e80a631` and `8c77f22` (GH #224). 0 raw rows for 50- and 200-line keys, after scrolling, at 40 to 80 columns, and while a key streams, up to 16 KiB. Beyond that, see R4 | Done |
| R8 | **Over-masked**: `watch` dropped about 30% of prose | A private-key header mentioned in prose held the observer stream | `holdfast watch` a session, then `cat CHANGELOG.md` | **Fixed** by `e80a631` (GH #242). `watch` now receives every line `read_output` does, with no gap notice. For the drop after a long key, see R17 | Done |
| R9 | Both: surfaces disagreed about the same bytes at the same moment | Any output that one surface judges differently from another | Stream an 8-line key with no END, then `sleep 10`. Compare `read_output`, `watch`, `get_screen_state` and `status` within 0.1 s | **Narrowed** by `e80a631` and `8c77f22`. All four now mask that key; the grid used to show 8 raw lines, and `prompt.last_line` a raw body line. A grep hit naming a key header, followed by a failing test log, now shows the failure on every default read with the secrets masked. Still open: R6, R16 | Surface by surface only, without G4 |
| R10 | **Leaks** a key painted one colour per character | `grep --color=always -n . key.pem` (or `--color=auto`, which colours on a PTY), `lolcat`. No `-----BEGIN` survives in the raw bytes, and the key grows about twenty-fold | Colour a 40-line key that way: the first default page carries 27 raw body lines with `redactions: {}`, and paging carries all 40. The grid shows 16 raw rows, or 38 with `start_session(screen_tracking: "on")`. A read of 64 KiB or more masks it. A 26-line key is masked | **Registered, not fixed** | Yes: look for key candidates in the ANSI-stripped text as well as in the raw bytes |
| R11 | **Leaks** a quoted label-keyed value that contains a `;` | A label-keyed value ends at `;`, and fewer than 8 bytes come before it | `echo "DB_PASS='Xk9;mP2qLzAB'"` comes back whole, with `redactions: {}`. With 8 or more bytes before the `;` (`'Xk9mP2qL;zAB'`), the part after the `;` is shown | **Registered, not fixed.** The 8-byte value floor is kept | Yes, by making the two broadest label rules read a quoted value to its closing quote. That is a larger change to those rules |
| R12 | **Over-masks** a type name after a secret-named label | A CamelCase value after `secret`, `token`, `api_key` and the like, as in Rust signatures and struct fields | `rg -n secret crates/holdfast-core/src/session \| head -60` masks 6 of 60 lines, all of them `secret: SecretBytes`. `token: TokenKind`, `api_key: ApiKey256`, `let token = uuid::Uuid::new_v4(` and digit-bearing types are masked too | **Registered, not fixed**; GH #245 stays open. For Rust-heavy work an operator can list `generic-secret-assignment` in `[security] disabled_redaction_rules` | Not without a cost. Nothing in the value tells `SecretBytes` from a capitalised passphrase with no separator. Keying on the byte after the value would stop masking `password=Hunter2hunter, user=bob`, and a stoplist of type suffixes would stop masking `JWT_SECRET=MySuperSecretKey` |
| R13 | **Leaks** the value of a secret-named environment variable | `printenv NAME` or `echo "$NAME"`, where the value has no recognisable shape | `start_session` with `env: {"MY_SERVICE_TOKEN": "<32 random lowercase alphanumerics>"}`, then `printenv MY_SERVICE_TOKEN`: the value comes back clear, with `redactions: {}`. The same happens when the variable is only in the environment of the client that launched `holdfast mcp`. `env \| grep MY_SERVICE_TOKEN` is masked by a label rule | **Open**, GH #TBD-printenv. See G2 | Yes: G2's environment-name registration |
| R14 | **Withholds indefinitely** a prompt a program is waiting at | A secret label ending in `:` or `=` with no trailing space, printed by a program waiting on input: `Enter password:`, `Password:`, `API_KEY=` | In bash, `printf 'Enter password:'; read -r x`. Cursor reads stop before `Enter password:` with `held_back: true` and `held_back_cause: "in_flight_secret"`; `prompt.last_line` is `""` and `interaction_mode` is `Executing`, for as long as the program waits. A `tail_bytes` read shows the prompt. `Password: `, with a trailing space, is not held | **Open**, GH #TBD-enter-password | Yes: start a label rule's hold at the first byte of the value, not at the label |
| R15 | **Leaks** part of a credential that arrives with an escape sequence inside it | The in-flight test reads raw bytes, and an escape ends the run it is testing | `printf 'ghp_%s\033[0m%s' <17 alphanumerics> <18 alphanumerics>` (39 of a GitHub token's 40 characters), then a cursor read: the default, ANSI-stripped read returns all 39 characters together, with `held_back: false` and `redactions: {}`. On `watch` a token split across two PTY reads with an escape inside it does the same, and that happens more often, because the unit is one PTY read | **Open**, GH #142. The grid masks this case. At most one character short of the rule's minimum length: 39 for a GitHub token | Needs a sharper in-flight test. The form that has been tried withholds ordinary output indefinitely |
| R16 | **Leaks** one line of key body in `prompt.last_line` | A key still arriving whose last body line has no line break yet | Print a header and 7 body lines with no END, then an eighth body line with no `\n`, then `sleep 10`. `status`, `list_sessions` and the `prompt` block of `read_output` and `wait_for_pattern` report that line raw. Every byte-stream surface masks it | **Open**, GH #TBD-last-line | Yes: report no last line while a read masks the region it lies in |
| R17 | **Over-masks**: `watch` silently drops the output that follows a long key | Output that arrives in the same PTY read as the END of a key longer than 8 KiB | `printf 'before\n'; cat key.pem; cat after.txt` with a 200-line key and `watch` attached: none of `after.txt` reaches `watch`, with no gap notice, and `read_output` shows all of it | **Open**, GH #TBD-watch-drop | Yes: emit the rest of the read once the key has been judged |

#### Shell history

<!-- HISTORY-POLICY -->
What Holdfast does about the history files of the shells it starts is tracked
in GH #252.

#### The out-of-band secret channel

**`request_secret_input` asks for a secret without the agent ever holding
it.** It shipped in 0.0.7.
1. The agent calls it, and every attached client is told.
2. A human, or an operator-declared provider, answers.
3. The tool returns a status and a byte count: never the value, and never a
   handle that could be exchanged for one. The byte count is the number of
   bytes written, so it does disclose the value's length.

The value travels client → daemon → PTY, and it appears in no tool argument
and no tool result.

The channel needs a daemon and an attached client:
- On Windows it is refused as `not_supported_on_platform`.
- With nobody attached, it waits out its `timeout_secs` and answers
  `secret_cancelled`.

**Its echo test (G3) is on `main`, and in no tag yet, so a `v0.0.7` install
does not have it** (GH #137). A `v0.0.7` install writes the value whatever
the terminal's echo state. An agent that asks before its child reaches a
password prompt could get a human to type a real credential into an echoing
terminal.
The line discipline would then put it in the output, and the default,
redacted `read_output` would hand it back to that same agent in the clear. An
arbitrary password matches no rule.

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
