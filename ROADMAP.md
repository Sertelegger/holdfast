# Roadmap

Where Holdfast is heading. Shipped work is in [CHANGELOG.md](./CHANGELOG.md).

**Read the numbers as scope groupings, not as a schedule.** `0.0.3`, `0.0.4`
and so on are working labels for coherent bundles of work in the order they are
being built. The version a bundle actually ships under is decided at release
time from what is in it, and no date, number, or delivery is promised here.
Each group gets its own design pass before implementation, and groups have been
resequenced before.

The end state this is walking toward is the framing the project is built on:
**Holdfast gives the agent a persistent shell environment, the way tmux gives a
developer one.** Two milestones in, it gives the agent a shell; the persistence,
the safety machinery, and the human's view into what the agent is doing are all
still ahead.

## Where it is now

Eleven MCP tools, Unix only, in **hybrid mode**: a background `holdfast daemon`
owns the sessions and a `holdfast mcp` shim proxies to it over a Unix socket, so
sessions outlive the MCP client rather than dying with it. Output is
ANSI-stripped and **secret-redacted by default**, with `--raw` and
`read_output(redact: false)` as audited opt-outs. Detection is real — sessions
report `interaction_mode` with the `detection_tier` that produced it. Windows
is not there yet, and neither is attach, the web UI, or the dangerous-command
preflight. See the README for the accurate current surface and
[SECURITY.md](./SECURITY.md) for what that means in practice.

## Output processing

**Redaction, and the ANSI stripper.** The largest gap between what Holdfast is
designed to be and what it is. A gitleaks-derived redactor at **every** output
boundary — tool results, the audit log, and every later boundary as it is added
— plus a read-path ANSI stripper with holdback-aligned boundary rules and an
`ansi: "raw"` escape hatch for callers that want the bytes.

The stripper is a correctness fix as much as a cosmetic one: the tier-3 pattern
table is specified against stripped text, so until it lands a coloured prompt
scores 0 and the table's false-positive surface is wider than it is designed to
be. The audit log arrives in the same group, which is also what turns the
current Unix-seconds timestamps into RFC 3339.

## Terminal state

**Tier B: full VT100 emulation.** Today's scanner is deliberately bounded — a
state machine that allocates no grid and keeps a 512-byte tail line, so it can
run on every chunk. A real screen model answers questions the tail line cannot:
what the session *looks* like right now, where the cursor is, what a full-screen
program is showing. It is also the foundation for anything that has to render a
session to a human, so it comes before the attach and UI groups.

## Daemon and control protocol

**Sessions that outlive the MCP process.** A persistent Unix-socket daemon with
the stdio MCP server as a thin shim in front of it, so closing a client stops
being the same event as killing every session. This is the single change that
makes the tmux framing true rather than aspirational, and everything below
depends on it.

## Attach protocol and CLI clients

**A human can look.** `holdfast attach`, `watch`, `list`, and `logs` (with
`--raw`), talking the attach protocol to the daemon. The point is not
convenience: an agent driving a shell that no human can see is the failure mode
this project exists to avoid, and attach is what makes "what is the agent doing
in there" answerable without reading a transcript.

## Secrets

**Secret input that never crosses the MCP wire.** `request_secret_input`, with
the value routed **client → daemon → PTY** and never through a tool argument or
result: the agent learns that a secret was supplied, not what it was. Entry
happens out of band in an attached client — a `SecretInput` frame for CLI
attach, a masked field in the web UI.

This is the group the current `AwaitingSecret` detection exists to serve.
Detecting a password prompt and then having no way to answer it except
`send_input` is half a feature.

## Command safety

**Preflight, and confirmation that an agent cannot self-approve.** An
argv-aware dangerous-command classifier — argv-aware because pattern-matching a
command *string* is the wrong shape and gets both directions wrong — exposed as
`precheck_command` and as a two-phase preflight on `start_session`. Plus an
optional strict mode in which the agent receives a token and only a trusted
client sees the code that authorises it, so approval is something a human does
rather than something the agent can arrange.

## Data movement

**Bounded responses, and somewhere for bulk output to go.** A raw-byte budget on
`read_output` responses with bulk output delivered as MCP resources rather than
inline, so a chatty build cannot consume the agent's context, and the tools that
mean an agent no longer has to poll — `wait_for_pattern`, `interrupt`, `resize`.
The backend already signals and resizes; neither is exposed as a tool.

## Web UI

**The terminal, in a browser.** An `xterm.js` view of a live session, served by
a daemon that listens on a Unix socket only; a TCP bridge exists solely as an
explicit `holdfast ui` command, with bearer-token auth and `Origin`/`Host`
validation. The default has to stay "not reachable from the network", because a
web view of a shell an agent is typing into is exactly the thing that must not
be accidentally exposed.

## Windows

**Native Windows support.** ConPTY, job objects in place of process groups (the
signal semantics are genuinely different, not a port of `killpg`), and
stdio-only mode where the hybrid daemon does not apply. The tree is already kept
compiling and clippy-clean for `x86_64-pc-windows-gnu` so this does not start
from a red build.

## Distribution

**Something a user can install.** Prebuilt per-platform binaries on GitHub
Releases, `cargo install`, and a Claude Code plugin marketplace with a bootstrap
launcher that fetches the right binary on demand.

## Beyond the first release

- **Process-isolated PTYs.** The `PtyBackend` trait exists so the isolation
  model can change without touching session logic; `InProcessPty` is the only
  implementation today. A `SubprocessPty` that puts each session in its own
  process is the priority follow-up — an in-process PTY means one session's
  pathology is the whole server's, which is a lesson already paid for once (see
  the wedged-writer fix in the changelog).
- **Full process-group enumeration on Unix without `/proc`**, via
  `sysctl(KERN_PROC_SESSION)`. Until then, `terminate` on those platforms can
  leave a background job in a third process group behind.
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

- **Never claim protection that has not shipped.** Output is raw today and the
  README, the MCP server's own `instructions` string, and
  [SECURITY.md](./SECURITY.md) all say so. An overstated capability reads as a
  guarantee and is not one.
- **Tell the agent how it knows.** `detection_tier` exists so a measurement is
  distinguishable from a guess. Any new signal ships with the same honesty about
  its own confidence.
- **The human keeps a way in.** Attach, watch, and the UI are not conveniences
  layered on top; a shell an agent can drive and a human cannot observe is the
  thing this project is trying not to build.
- **Design before build.** Each group gets its own brainstorm/spec/plan cycle.
  This file tracks direction, not commitments.
