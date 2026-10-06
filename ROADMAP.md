# Roadmap

Where Holdfast is heading. Shipped work is in [CHANGELOG.md](./CHANGELOG.md).

**Read the numbers as scope groupings, not as a schedule.** `0.0.9`, `0.0.10`
and so on are working labels for coherent bundles of work in the order they are
being built. The version a bundle actually ships under is decided at release
time from what is in it, and no date, number, or delivery is promised here.
Each group gets its own design pass before implementation, and groups have been
resequenced before.

The end state this is walking toward is the framing the project is built on:
**Holdfast gives the agent a persistent shell environment, the way tmux gives a
developer one.** The shell, its persistence and the human's read-only and
interactive views into it have shipped. What is still ahead is making the
safety machinery say exactly what it guarantees and then keep to it, and the
first release anyone is expected to install.

## Where it is now

Twelve MCP tools in **hybrid mode on Unix**: a background `holdfast daemon`
owns the sessions and a `holdfast mcp` shim proxies to it over a Unix socket, so
sessions outlive the MCP client rather than dying with it. A human can follow a
session with `holdfast watch`, take it over with `holdfast attach`, and answer
a `request_secret_input` there without the value crossing the MCP wire.
Detection is real — sessions report `interaction_mode` with the
`detection_tier` that produced it. Neither the web UI nor the dangerous-command
preflight exists on any platform.

**Output is ANSI-stripped and secret-redacted by default, and the promise is
now stated in two tiers.** [SECURITY.md](./SECURITY.md) lists the hard
guarantees Holdfast aims for — every byte an agent or an observer reads routed
through the redactor, except on the raw paths it names; known secret values
masked within a published scope; secrets written only at a real secret prompt;
one verdict per byte across every surface; and nothing withheld indefinitely.
Only the routing holds today, the write gate holds in part, and the rest are
not built or not claimed. Below them sit the pattern rules, which are best
effort and say so. Every known way output gets past the redactor, or is masked
when it should not be, is in SECURITY.md's residual register with the issue it
is filed as. `read_output(redact: false)` and `holdfast logs --raw` are the
audited ways to raw bytes; SECURITY.md names the unaudited ones too.

**No published release carries binaries yet.** `v0.0.5` to `v0.0.7` were
published with source only. `v0.0.8` is the first tag with binaries, attached
to a draft, and a draft's assets are not served until it is promoted. The
plugin installs and then says so (see Distribution).

**On Windows the MCP server starts, and that is close to the whole of it.**
`holdfast mcp` serves MCP over stdio in-process and writes the §9.4 audit
trail, and `version` works. There is no daemon, so sessions end with the
process and the daemon-backed subcommands refuse by name rather than
half-working — `daemon stop` excepted, which exits 0 because §3.2 makes it
idempotent and on this platform that is its only case. The PTY layer itself is
still unported (ConPTY, below), so "the server serves" is a smaller claim than
"the tools work", and the Windows section is where the difference is listed.

## 0.0.8 "Dowel": tagged, not promoted

**The fixes from the September dogfood pass, integrated and gated as one
tree.** That pass drove `main` as a user would and filed what it found.
Among the changes:
- **Sessions start where the caller is.** A session gets the calling client's
  working directory and environment rather than whichever client happened to
  start the daemon ([#229](https://github.com/Sertelegger/holdfast/issues/229)).
- **The shells Holdfast starts write no history under `$HOME`.** An operator
  can keep one history file per session instead
  ([#252](https://github.com/Sertelegger/holdfast/issues/252)).
- **Private keys are masked on every read surface.** This includes the grid
  and a `watch` that joins partway through a key, within the limits
  SECURITY.md's register lists.
- **Tool arguments are closed.** An unknown argument is refused rather than
  ignored.
- **Bursts no longer detach viewers.**
- **Idle shells are hung up on `terminate`,** so it takes a fraction of a
  second instead of five.
- **Clients and daemons that disagree about the protocol say so.** A daemon
  outlives upgrades by design, so a call that an older daemon, or an older
  shim, would serve differently is refused with which side to restart.

The CHANGELOG has the list.

**0.0.8 is tagged as a draft and is not promoted.** The first release a user
can install is the first one that also carries the next group.

## Next: before the first promoted release

**Promoting a draft is the first external distribution, and some changes are
cheapest before it** — anything that breaks a config, a wire shape or an
agent's expectations costs nothing while nobody depends on the old behaviour.
This group is what has to be true before that step:

- **Known values are masked.** A secret-named environment variable's value is
  registered when the session starts, so `printenv GITHUB_TOKEN` returns a
  marker rather than the token
  ([#253](https://github.com/Sertelegger/holdfast/issues/253)). This is the
  first source of the "known values" guarantee, and its scope — which names,
  which values, which encodings, which surfaces — is published in SECURITY.md
  with it.
- **A narrower way past a mask than `redact: false`.** Today the only way to
  read text behind a mask that might not be a secret returns everything raw,
  including secrets the redactor had already caught. The plan is a
  `redact: "complete_only"` read that keeps complete secrets, known values and
  all private-key material masked and shows the rest. The tool descriptions
  also need to say what `held_back` and `[REDACTED:unresolved]` mean and what
  to try first.
- **The live leaks in the register that an agent reaches with ordinary
  commands.**
  - A token that a colour escape joins to the word before it
    ([#254](https://github.com/Sertelegger/holdfast/issues/254)).
  - Key body in `prompt.last_line`
    ([#257](https://github.com/Sertelegger/holdfast/issues/257)).
- **The daemon stops carrying the first client's environment** into sessions
  that do not take the caller's, such as a `profile` session.
- **Instruments.**
  - Property tests that judge every read surface against a whole-stream
    reference, so "does this change leak, over-mask, or make two surfaces
    disagree" is a test result rather than a review argument. The residual
    register is pinned by those tests.
  - A per-session statistics record in the audit log.
- **Config refusal and scope removals, if decided** (see Pending decisions).

**Also in this group, though promoting does not wait for it: a band in Claude
Code when an agent asks for a secret.** Today `request_secret_input` blocks the
agent's turn for its timeout, two minutes by default, while the human may not
know that a terminal is wanted, for which session, or what to run there. The
plugin draws a band above Claude Code's prompt naming the session, by name and
id. One key copies the `holdfast attach` command and, inside tmux, another
opens it in a split. The secret is still typed only in `holdfast attach`: the
band has no field for it, and it calls no Holdfast tool that writes. It needs
Claude Code 2.1.287 or later, which mods require in a terminal, and it draws
nothing in the VS Code chat panel, under `claude -p` or in a cloud session. It
is the first piece of the Session panel below.

## After that

- **Nothing withheld indefinitely.**
  - A label-keyed hold starts at the value, not the label.
  - An idle, unfinished candidate is committed as a mask after a quiet
    period, so a prompt such as `Enter password:` is shown
    ([#255](https://github.com/Sertelegger/holdfast/issues/255)).
  - Every surface commits what it holds when the session ends; `watch`
    currently does not ([#256](https://github.com/Sertelegger/holdfast/issues/256)).
  - Only once that commit ships on by default does the `tail_*` bypass of the
    holdback go.
- **The secret write gate uses the classifier's own test for a secret
  prompt,** with a per-submission human override. An interim guard in
  0.0.8 refuses a shell sitting at its own prompt by its markers. The gate
  still admits any other terminal with echo off, including a REPL prompt
  or a shell whose integration is off, where the secret is echoed, run as
  a command and saved to history
  ([#262](https://github.com/Sertelegger/holdfast/issues/262)). The override
  is what keeps prompts the stricter test would refuse, such as `ssh -t`,
  working.
- **The cheap performance fixes the measurements found:**
  - ASCII word boundaries in the two generic rules
    ([#206](https://github.com/Sertelegger/holdfast/issues/206));
  - the quadratic in-flight scan
    ([#163](https://github.com/Sertelegger/holdfast/issues/163));
  - UTF-8-aware C1 handling;
  - an O(1) ring buffer;
  - dropping a finished session's screen model;
  - moving the terminate and wait rescans off the async executor.
  None of these depends on a redesign.

## Pending decisions

These are open. The analysis for each exists; the owner has not chosen.

- **Scope for the first release.**
  - **The candidates:**
    - the dangerous-command preflight (Command safety, below);
    - keychain bindings, profiles, approval and autofill;
    - the web UI;
    - data movement: file transfer, waiting on several sessions, recording;
    - process-isolated PTYs;
    - native Windows beyond the stdio server;
    - the config keys that load and do nothing.
  - **The second question is what "cut" means:**
    - **deactivate**: the code stays and the feature is refused at config load;
    - **remove**: the code is deleted and kept on an archive branch.
  - Whatever is removed is removed before the first promoted release.
- **A field week.** A week of real agent work routed through Holdfast, with
  the questions and their thresholds written down beforehand. It asks:
  - how often agents choose Holdfast over their built-in shell tool;
  - how often a read carries `[REDACTED:unresolved]`;
  - how often an agent escalates to a raw read, and after what.

  Today every ranking behind this roadmap comes from constructed workloads.
- **A per-session verdict ledger, or targeted fixes.** Several register rows
  exist because each surface decides what to show over its own window. A
  ledger that judges each byte once and has every surface render from it
  would close those by construction. The other course is to keep fixing
  rows one at a time and accept the few no targeted fix can close — keys
  longer than 16 KiB, mostly — in the register. The choice waits for the
  field week.

## Command safety

**Preflight, and confirmation that an agent cannot self-approve.** An
argv-aware dangerous-command classifier — argv-aware because pattern-matching a
command *string* is the wrong shape and gets both directions wrong — exposed as
`precheck_command` and as a two-phase preflight on `start_session`. Plus an
optional strict mode in which the agent receives a token and only a trusted
client sees the code that authorises it, so approval is something a human does
rather than something the agent can arrange.

**Nothing of it is built, and it is a candidate for cutting** (Pending
decisions). The case against it is that Claude Code's own permission prompts
and `PreToolUse` hooks already see every `start_session` and `send_input`
call the agent makes, and a strict mode an agent can satisfy from a second
session is not the barrier it reads as. A call from a Claude Code mod skips
the prompt, which SECURITY.md names.

## Web UI

**The terminal, in a browser.** An `xterm.js` view of a live session, served by
a daemon that listens on a Unix socket only; a TCP bridge exists solely as an
explicit `holdfast ui` command, with bearer-token auth and `Origin`/`Host`
validation. The default has to stay "not reachable from the network", because a
web view of a shell an agent is typing into is exactly the thing that must not
be accidentally exposed.

**Deferred past the first release, pending the scope decision.** `attach` and
`watch` already give the human a view. The `[ui]` config keys load today and
do nothing.

## Session panel

**One place that answers "what needs me?"** A persistent rollup of every
session and the reason it is in the state it is in, rather than a grid of panes
a human has to read one at a time. The daemon already computes the answer —
`interaction_mode`, `detection_tier`, `confidence` and `reason` are on every
prompt-bearing response (§8.3, §18.2a) — and nothing puts them side by side.

**What it shows is the part worth arguing about, because the obvious design is
the wrong one.** A tiled terminal grid is a solved problem with mature
implementations, and holdfast would be a late entrant to it. The rows that earn
this panel are the ones only this daemon can produce: which sessions are
`AwaitingSecret` and how long they have been waiting, what has been redacted and
how often, which **profile** a session was launched from — or that it was
agent-authored `command`/`args` and therefore can never receive a credential
(§9.6) — and what is pending a strict-mode confirmation. Ranking sessions by
*needs a human* is a different product from tiling terminals, and it is the one
that follows from what holdfast already knows. Some of those rows depend on
features in the scope decision above.

**The surface is decided: a Claude Code mod first.** A mod is code a Claude
Code plugin runs inside Claude Code, and it can draw a pane, or a band above
the prompt, in the terminal the agent is already in. The secret-request band
in the group above comes first. The panel follows it only if the field week
(Pending decisions) shows Holdfast in enough use to need one. A `holdfast tui`
is built only if users outside Claude Code appear. A mod draws only in
`claude` in a terminal and in the Desktop app's Code tab, so `attach` and
`watch` stay the view everywhere else. Whatever draws it, the panel shows a
session's screen masked as the agent reads it, and it never takes a secret:
that is typed in `holdfast attach`.

## Windows

**Native Windows support.** ConPTY, job objects in place of process groups (the
signal semantics are genuinely different, not a port of `killpg`), and
stdio-only mode where the hybrid daemon does not apply.

**Whether the first release supports native Windows at all is part of the
scope decision.** The alternative is WSL only, with the Windows assets and
bootstrap refusing and pointing at WSL. What would be missing today is listed
below. Reading the code, a native session's `interrupt` and `terminate`
cannot signal its child, and no test starts one.

**The tree compiles and lints clean for Windows.** `windows-cross` — the
`x86_64-pc-windows-gnu` clippy job — was red on `main` from before 0.0.6
until [#19](https://github.com/Sertelegger/holdfast/issues/19) fixed it: 27 of
the 31 errors were in the daemon subsystem, which this section already says
does not exist on Windows, and the other four were the same `#[cfg(unix)]`
class in `config.rs` and `protocol/client.rs`. The tree now cross-compiles
clippy-clean, a `windows-2022` job runs native MSVC clippy and executes the
CLI's Windows arms, and `holdfast mcp` serves stdio in-process there with an
audit trail.

**What is actually left**, then, is the part that needs a Windows machine and
a port rather than a `#[cfg]`:

- **ConPTY** in place of `/dev/ptmx`, behind the existing `PtyBackend` trait.
- **Job objects** in place of process groups — `killpg`, `setsid` and
  `tcgetpgrp` have no port, only replacements with different semantics.
- **Console modes** (`GetConsoleMode`) in place of the termios `ECHO`/`ICANON`
  rung that §8.3's Tier 2 detection reads, without which `AwaitingSecret` is
  unreachable there.
- **An ACL-shaped trust check.** Windows has no mode bits, so §9.4's `0700`
  runtime directory and `0600` logs are currently the ACL they inherit and
  Holdfast says so in a warning rather than enforcing anything. `config.rs`
  asks for "an ACL-shaped answer, not a `#[cfg]` that returns trusted"; that
  debt is still owed.
- **The unit suite on Windows.** 55 of `holdfast-core`'s lib tests spawn a
  real shell (measured natively: 721 passed, 55 failed, in three modules), so
  the Windows job runs the source guards, the CLI arms, and a **filtered**
  `--lib` naming only the modules whose Windows arm differs from its Unix one
  — not the full `--lib`. Gating those shell fixtures buys the other 721 tests
  on the platform —
  [#91](https://github.com/Sertelegger/holdfast/issues/91).

## Distribution

**Something a user can install.** Prebuilt per-platform binaries on GitHub
Releases, and a Claude Code plugin marketplace with a bootstrap launcher that
fetches the right binary on demand. `cargo install` builds from source; the
README no longer recommends it as the way in.

**The plugin half exists and the binary half waits on one decision.**
`/plugin marketplace add Sertelegger/holdfast` then `/plugin install
holdfast@holdfast` installs, and the bootstrap it installs then fails with a
message naming the manual and from-source routes, because no *promoted*
release carries binaries or a `SHA256SUMS.txt`. `release.yml` builds five and
attaches them to a **draft**, and a draft's assets are not served from
`releases/download/`. Promoting that draft is the first-external-distribution
event, not a side effect of writing release notes. It happens for the first
release that carries the group above, not for 0.0.8. Once a release is
promoted, the marketplace listing is pinned to it. Windows is the one part of
the plugin whose entrypoint shape nobody has been able to run, which the
Windows decision above settles one way or the other.

## Beyond the first release

- **Process-isolated PTYs.** The `PtyBackend` trait exists so the isolation
  model can change without touching session logic; `InProcessPty` is the only
  implementation today. A `SubprocessPty` that puts each session in its own
  process would keep one session's pathology from becoming the whole server's
  (see the wedged-writer fix in the changelog). Its groundwork — the frame
  catalogue and a per-session worker socket — is in the tree. It predates
  several changes to the trait and to how a session's environment is built,
  so it resumes only after those reach the seam. Whether it stays in scope is
  tied to the Windows decision, because native Windows is what made it urgent.
- **Full process-group enumeration on the BSDs.** macOS is done — it enumerates
  via `proc_listallpids` plus `getsid(2)`, which yields the same predicate Linux
  reads out of `/proc/<pid>/stat`. It is **not** `sysctl(KERN_PROC_SESSION)`:
  XNU registers no such OID and answers `ENOENT`, `kinfo_proc`'s `e_sess` is
  NULL on every process, and libc does not declare `kinfo_proc` for Apple at
  all. On the remaining BSDs `terminate` can still leave a background job in a
  third process group behind.
- **Signed and notarized macOS builds, and an Authenticode-signed Windows
  binary.** The first release ships unsigned. The plugin's bootstrap downloads
  with `curl`, which sets no quarantine attribute, so the install path most
  people take is unaffected — but a binary fetched by hand from the Releases
  page in a browser *is* quarantined, and macOS refuses it with a message about
  an unverified developer. Until this lands, that path is documented rather
  than smooth. Note that sigstore/cosign signing, listed separately, does not
  substitute: it attests where an artifact came from, and the operating system
  does not consult it.

## Principles

- **Never claim protection that has not shipped.** Output is redacted by
  default, and SECURITY.md says clause by clause which guarantees hold today,
  which are partial and which are not built, with every known gap in its
  register. The README, the MCP server's own `instructions` string and
  SECURITY.md say the same thing. An overstated capability reads as a
  guarantee and is not one.
- **Tell the agent how it knows.** `detection_tier` exists so a measurement is
  distinguishable from a guess. Any new signal ships with the same honesty about
  its own confidence.
- **The human keeps a way in.** Attach, watch, and the UI are not conveniences
  layered on top; a shell an agent can drive and a human cannot observe is the
  thing this project is trying not to build.
- **Evidence before structure.** A redesign has to be justified by measured
  failures on real use, not by the count of edge cases a review can construct.
- **Design before build.** Each group gets its own design pass before it is
  built. This file tracks direction, not commitments.
