# Holdfast — Claude Code plugin

Holdfast gives an agent a persistent, PTY-backed shell environment, the way
tmux gives a developer one. This directory is the plugin half: the manifests
Claude Code reads, and the bootstrap that puts a `holdfast` binary on the
machine so the MCP server has something to run.

## Install

```
/plugin marketplace add Sertelegger/holdfast
/plugin install holdfast@holdfast
```

Then restart Claude Code. The first MCP call downloads the binary for the
release this plugin build is pinned to; every call after that is a
file-existence check.

**That download needs a promoted release.** A release is now created as a
draft, and a draft's assets are not served until a person promotes it
([CONTRIBUTING.md](../CONTRIBUTING.md#releases)); `v0.0.5` to `v0.0.7` were
published with no binaries at all. Against either, the server fails to start,
and `claude mcp list` says why in one line: *no holdfast vX.Y.Z
binary to download … To run Holdfast now, build it* (measured on Linux; on
Windows the entrypoint is [unverified](#the-windows-entrypoint-is-an-open-question)).
That line is the way in:
[Using a binary you built yourself](#using-a-binary-you-built-yourself).

`holdfast@holdfast` is `<plugin>@<marketplace>`. The right-hand `holdfast` is
this repository's `.claude-plugin/marketplace.json` `name` field — it is not
derived from the repository name, so renaming the repo does not change the
install line and renaming that field does.

## Using a binary you built yourself

For a build from source — the only way in before a release is promoted, the
way in on a platform with no prebuilt, and the way to run a checkout you are
working on — name the binary and the bootstrap runs it and nothing else.

1. **Install it somewhere that outlives your build directory.**

   ```bash
   # the release this plugin build is pinned to -- see version.txt
   cargo install --locked --git https://github.com/Sertelegger/holdfast --tag vX.Y.Z holdfast
   # or a checkout you are working on, from its root
   cargo install --locked --path crates/holdfast
   ```

   Both put the binary at `~/.cargo/bin/holdfast`. **`cargo install holdfast`
   does not work**: crates.io holds a `0.0.0` name reservation with no binary
   in it, and cargo answers *"there is nothing to install"*. Nor is
   `target/debug/holdfast` a good thing to name: `cargo clean` then breaks
   every Claude Code session at once.

2. **Name it in the `env` block of Claude Code's `settings.json`** —
   `~/.claude/settings.json`, or `settings.json` inside each
   `CLAUDE_CONFIG_DIR` you use, because every config directory is its own
   installation:

   ```json
   { "env": { "HOLDFAST_BOOTSTRAP_BIN": "/home/you/.cargo/bin/holdfast" } }
   ```

   **The full path, spelled out.** Claude Code passes these values literally
   — measured, `~` and `$HOME` arrive unexpanded — so the bootstrap refuses a
   leading `~` or `$` by name rather than guessing what was meant. It also
   refuses a relative path, since it runs in whichever project Claude Code was
   started in, and a path that is not an executable file. **It never
   downloads in place of a binary you named.**

3. **Restart Claude Code.** `claude mcp list` should show
   `plugin:holdfast:holdfast: … ✔ Connected`.

Upgrading is a rebuild and a daemon restart, and the daemon is the part that
is easy to miss: the top-level README's
[Build and try it](../README.md#build-and-try-it) says why, and what it costs.

**Working on the plugin itself.** `/plugin marketplace add /path/to/checkout`
— a local directory rather than `Sertelegger/holdfast` — loads the checkout's
`plugin/` in place: measured, the server command it registers is the
checkout's own `plugin/bootstrap`, so an edit takes effect at the next start.
`claude --plugin-dir /path/to/checkout/plugin` does the same for one session.
Once the listing is pinned to a promoted release ([Releasing](#releasing)), a
local-directory marketplace installs *that* release, and `--plugin-dir` is the
in-place route.

## The secret-request band

When the agent calls `request_secret_input`, its turn blocks until a human
types the secret into `holdfast attach`. The plugin's mod (`hooks/`) says so
where you are looking: a toast, and a band above the prompt.

```
 holdfast: deploy (sess_4f2c91aa07de) is waiting for a secret  at least 1:52 left
 agent says: "sudo password for deploy"
 Type it in holdfast attach, not here.
 1: open attach in tmux split (right)    2: copy attach command
```

- **The session** by name, and by id once a `start_session`,
  `list_sessions` or `status` result passing through Claude Code has paired
  that name with one; a session such a result shows exited gives its name
  up. Without an id the band says `session "deploy"`. The name is the
  agent's choice, so it is cut to 24 characters, which keeps the id on a
  narrow band, and anything in it that reads as an id is drawn as `sess_…`,
  so the only id on the band is the real one. "agent says" is the agent's
  `prompt_text`. Both are the agent's text, so they are drawn stripped of
  control, escape, bidi and invisible characters and labelled for what they
  are.
- **The time** is the least the request has left. The countdown starts as
  the agent's call reaches the mod, which is before Claude Code's own
  permission dialog for that call, if it asks; Holdfast's timeout starts
  only once you approve. So the request has the time shown and as long
  again as the dialog was up, and past zero the band says it *may time out
  at any moment*, not that it has: the band closes when the call does.
- **1** opens `holdfast attach --keep-size <id>` in a tmux pane to the right,
  without moving the focus out of Claude Code. It is drawn only in the
  terminal and only inside tmux. **2** copies the same command. Each runs only
  when pressed, which includes a `1` or `2` typed alone into an empty prompt,
  and both are harmless if that happens by accident.
- **The tmux pane** starts with the tmux server's environment, not Claude
  Code's, so the split hands it Claude Code's `HOLDFAST_RUNTIME_DIR` and
  `XDG_RUNTIME_DIR`, which choose the daemon that attach dials. The binary
  and the session reach tmux as separate arguments, so no shell parses them;
  that takes tmux 2.0 or later. If attach fails, the pane stays open showing
  why until you press Enter; if it failed because that `holdfast` predates
  `--keep-size` (exit 64), the pane says so. A copied command runs with the
  environment of the shell you paste it into.
- **When the call ends**, the band shows the outcome word for five seconds,
  as the daemon gave it: `secret_provided, 8 bytes written`, or
  `not sent: timeout`.

**The secret is never typed into the band.** It has no field, by design: a
mod's text field is not masked, and every other installed mod sees each key
typed into it. The band points you at `holdfast attach`, which is where the
secret goes.

**It makes no Holdfast call, so it asks no permission.** A mod's
`$.mcp.call` is checked against the session's permission mode like the
agent's own (measured on Claude Code 2.1.291): in default mode it raises a
dialog naming the plugin, and under `claude -p` it is refused. A band that
read the session first would put that dialog in front of the very request
it announces. So the hook passes the agent's call on before anything else,
draws from the call's own arguments, and watches the `start_session`,
`list_sessions` and `status` results that pass for the id that goes with a
name, returning every result untouched. A call another installed mod makes
passes the same hooks as the agent's, so it can raise the band or pair a
name with an id too; a mod is already trusted with more than that
([SECURITY.md](../SECURITY.md)). What it does call —
`$.env.get`, `$.fs.stat`, `$.process.run` — was measured under `claude -p`
in default mode, where `$.mcp.call` is refused, and none of them was. It
puts nothing in front of the model and never answers or approves the call.
"terminal shows" and "started by", which need a read, are left to the
session panel ([ROADMAP.md](../ROADMAP.md#session-panel)).

**The command names `HOLDFAST_BOOTSTRAP_BIN`** when it is an absolute path to
an executable file, as the bootstrap would run it; **else the first
executable `holdfast` in an absolute directory on Claude Code's `PATH`**.
Executable is `test -x`, run as a builtin of `/bin/sh` with the path as an
argument, so nothing is looked up on `PATH` to check it; the Desktop app has
no `$.process`, and there a regular file is taken as it stands. **With
neither, there are no buttons**: the band shows
`holdfast attach --keep-size '<id>'` and says `holdfast` is not on Claude
Code's `PATH`, pointing at `/holdfast:attach` and
[#280](https://github.com/Sertelegger/holdfast/issues/280). It never names
this plugin's `bootstrap`: run from a mod, without the `CLAUDE_PLUGIN_DATA`
of Claude Code's MCP start, that would download a release. With no id, the
command names the session by its name when `holdfast attach` can take it as
it stands — a letter or digit, then letters, digits, `.`, `_` or `-`, which
attach resolves as it resolves an id — and otherwise the band asks you to
find the id with `holdfast list`. `--keep-size` keeps the half-width split
from resizing the agent's session, and **it needs a `holdfast` from this
release or later**: an older one refuses the flag with exit 64, in a pasted
command and in the split alike. The split's pane then says to update
`holdfast`, or to run attach without the flag, which resizes the session to
that pane; it never does that by itself.

**It needs Claude Code 2.1.287 or later**, which is when mods arrived; it is
measured with 2.1.291. The plugin manifest has no field that declares a
minimum Claude Code version, so this sentence is the declaration. An older
Claude Code still loads the plugin and connects its MCP server, and runs no
mod, so the tools work and there is no band: measured on 2.1.285, where
`claude plugin validate` passes, `plugin:holdfast:holdfast` connects, and a
command a mod registers is not there (on 2.1.291 the same one runs).

Its tests live in `plugin-tests/`, outside what every install copies, and
`scripts/plugin-mod-tests.sh` runs them under `claude plugin test`, after
checking that what `claude plugin validate` reports the module hooks, calls
and reads still matches `plugin-tests/validate-notes.txt`, a pin that
`scripts/plugin-manifest-check.py` refuses if it lists any MCP call. A real
session is [the manual check below](#manual-check-the-band-in-a-real-session).

**To turn it off**, run `/plugin configure holdfast@holdfast`, or use its
row in `/config`, or set it in `settings.json`:

```json
{ "pluginConfigs": { "holdfast@holdfast": { "options": { "secret_band": false } } } }
```

Off, the mod registers nothing at all; it takes effect at the next session
start. Installing the plugin prints *1 userConfig option not yet set*: that
is this switch, and unset it is on.

**Where it does not draw:** `claude -p`, the Agent SDK and the VS Code chat
panel, where nothing draws and so nothing is looked up either; cloud
sessions; the Desktop app's WSL sessions, which get no plugins. In the
Desktop app's Code tab it draws without the tmux button, which needs a
terminal. On Windows native there is no daemon to attach to, and
`request_secret_input` is refused at once, so instead of the band a toast
says the request needs hybrid mode. An organisation's `disableAllHooks` or
`allowManagedModsOnly` removes the mod and keeps the MCP server, so
Holdfast's own text never promises the band.

## What the bootstrap does

`.mcp.json` registers one stdio server whose command is
`${CLAUDE_PLUGIN_ROOT}/bootstrap`. On every MCP start that script:

1. execs `HOLDFAST_BOOTSTRAP_BIN` if it is set, or refuses — see above;
2. reads `version.txt` next to itself — the version this plugin build is
   pinned to, bumped in the release PR;
3. if `HOLDFAST_BOOTSTRAP_ALLOW_PATH` is set, execs the `holdfast` on `$PATH`
   when `holdfast version` reports exactly that version, and otherwise says
   why on stderr and carries on;
4. execs the cached binary for that version and this target if it is there;
5. otherwise fetches `SHA256SUMS.txt` and `holdfast-<target>.tar.gz` from the
   matching GitHub Release over TLS, verifies the archive against the freshly
   fetched manifest, extracts exactly one member under the safe-extraction
   rules below, installs it into the cache and execs it. It fetches with
   curl, or with wget when there is no curl, and it refuses a wget that says
   it did not verify the certificate — busybox's, with no `openssl` on
   `$PATH` — because TLS is the only thing vouching for both files.

**When it cannot start the server, it says so where you are looking.** A
stdio server that exits before answering shows in Claude Code as
`Failed to connect — CONNECTION_CLOSED` and nothing else. So under `mcp` a
failing bootstrap answers the `initialize` request Claude Code has already
sent with a JSON-RPC error carrying its diagnosis, and `claude mcp list` shows
`Failed to connect — -32603: holdfast bootstrap: <the reason>` (both shapes
measured with Claude Code 2.1.280 on Linux, through `claude mcp list`; the
interactive `/mcp` panel was not checked). The same line is on stderr, which
Claude Code keeps in its MCP log, and
`HOLDFAST_BOOTSTRAP_DEBUG=1 "${CLAUDE_PLUGIN_ROOT}/bootstrap" version`
reproduces it by hand. Nothing is read from stdin on a success path.
`bootstrap.ps1` answers the same way, and `scripts/plugin-bootstrap-tests.sh`
runs that under `pwsh` on Linux — **but on Windows itself it is exactly as
unverified as the entrypoint that would reach it**
([below](#the-windows-entrypoint-is-an-open-question)), so there a failure
may still read `CONNECTION_CLOSED`.

**Cache location.** `$CLAUDE_PLUGIN_DATA/bin/` when the loader exports it —
which it does — else `$XDG_CACHE_HOME/holdfast/bin/`, else
`~/.cache/holdfast/bin/`. The plugin-data directory is preferred over the
`~/.cache` path the design spec names for two reasons: it is removed when the
plugin is uninstalled instead of being orphaned, and it is not a well-known
path a hostile local process can pre-create and pre-populate before your first
run.

**Trust root.** GitHub's TLS authenticates the release origin and
`SHA256SUMS.txt` fetched from that same release establishes archive integrity.
This is assumption A-4 in the design spec, and it is worth being precise about
what it does not cover: it is not protection against a compromised release or
a compromised maintainer account. Sigstore/cosign signing is the post-v0.1.0
answer to that.

## Air-gapped or firewalled

When the release **is** published and this host cannot reach it, the bootstrap
fails with *cannot reach …* and names the two paths below. (A release that is
not published fails differently — *no holdfast vX.Y.Z binary to download* —
and there is nothing to download by hand; build it instead, as above.) To
install by hand:

1. On a connected machine, download `holdfast-<target>.tar.gz` and
   `SHA256SUMS.txt` from the release page for the tag matching this plugin's
   `version.txt`, `https://github.com/Sertelegger/holdfast/releases/tag/vX.Y.Z`.
   `<target>` is one of `linux-x86_64`, `linux-aarch64`, `macos-x86_64`,
   `macos-aarch64`, `windows-x86_64`.
2. **Verify the checksum yourself.** `sha256sum -c SHA256SUMS.txt
   --ignore-missing`, or `shasum -a 256` and compare. Skipping this moves the
   trust root from GitHub's TLS onto whatever carried the file.
3. Extract the single `holdfast` binary and place it, mode 755, at
   `$CLAUDE_PLUGIN_DATA/bin/holdfast-v<version>-<target>`, with
   `SHA256SUMS.txt` beside it named `SHA256SUMS-v<version>.txt`. **Both files,
   or it is a cache miss**: a binary without its manifest is treated as absent
   and the bootstrap tries to download again.

A build from source with `HOLDFAST_BOOTSTRAP_BIN`, as above, needs no network
at MCP time either.

The `/holdfast:install` command walks a user through all of this and reads the
bootstrap's own diagnosis first.

## Environment

| Variable | Effect |
|---|---|
| `HOLDFAST_BOOTSTRAP_BIN` | Absolute path of a `holdfast` to exec instead of anything else. No search, no version comparison, no download; a relative, `~`-, `$`-led or non-executable value is refused, never worked around |
| `HOLDFAST_BOOTSTRAP_DEBUG` | Trace to stderr. Safe at any time; stdout stays the MCP transport |
| `HOLDFAST_BOOTSTRAP_ALLOW_PATH` | Exec whatever `holdfast` is on `$PATH` when `holdfast version` reports exactly the pinned version — the second field, compared whole. When it declines, it says why. **Off by default and that is a security decision** — see below |
| `HOLDFAST_BOOTSTRAP_BASE_URL` | Release base URL. For the test harness; a non-`https://` value is refused unless the next variable is also set |
| `HOLDFAST_BOOTSTRAP_INSECURE` | Permits a non-TLS base URL. For `scripts/plugin-bootstrap-tests.sh` only |
| `CLAUDE_PLUGIN_DATA` | Cache root, normally set by the loader |

### Why `$PATH` is not trusted by default

The design spec's step 2 says to exec whatever `holdfast` is on `$PATH`
whenever `holdfast version` agrees with `version.txt`. That is not shippable as
a default: **self-reported version output is not authentication.** Any writable
`$PATH` entry ahead of the real binary wins with a five-line shell script, and
the process this bootstrap execs inherits the agent's MCP stdio — every command
the agent runs, and every secret routed through `request_secret_input`. The
behaviour survives as an opt-in, where setting the variable *is* the
authorisation. `HOLDFAST_BOOTSTRAP_BIN` is the stricter spelling of the same
wish — one named file, nothing searched and no version to spoof — and wins
when both are set.

## The safe-extraction rules, and why they are a whitelist

The spec words them as a blacklist — reject absolute paths, `..` components,
symlinks, hardlinks, device files. Measured, that cannot be written over a tar
listing: **busybox tar sanitises names before it prints them**, so an entry
stored as `../../../tmp/PWNED` lists as `tmp/PWNED` and a check that greps the
listing for `..` never fires — on the one implementation the rule was written
for. The archive still extracts a file the maintainer never shipped.

`lib-safe-extract.sh` enforces the clause the same sentence ends with instead:
the archive must contain *exactly the expected `holdfast` executable*. Five
checks:

1. the listing is exactly the one expected name — nothing before, nothing after;
2. the `-tv` mode string is a regular file with no setuid/setgid bit;
3. extraction of that one member only, under `ulimit -f`;
4. **what actually landed on disk** is re-validated — one entry, regular file,
   not a symlink or directory or device, non-empty, link count 1, no setuid;
5. **and it is measured** — `wc -c` against the byte bound, which is where the
   decompression-bomb verdict now lives.

Check 4 is not defence in depth. busybox tar reports a hardlink entry as a
regular file and then happily materialises a second link to `/etc/passwd`
named `holdfast`; nothing in the listing says so.

**Check 5 is the one that is, and it is deliberate.** `ulimit -f` takes
*blocks*, and the block size is 512 under dash and 1024 under bash — so one
fixed block count is a 128 MiB cap under `/bin/sh` on Linux and a 256 MiB cap
under `/bin/sh` on macOS, where `/bin/sh` is bash. A 200 MiB bomb fits under
the second. The bound is now a byte constant; check 3 divides it by the larger
block size so the cap can only come out at or below it, and check 5 compares
the size of the file that actually arrived to the same constant, asking no
shell to have meant the right unit and no `tar` to have reported anything.

`scripts/plugin-archive-tests.sh` runs 19 hostile tar archives and 12 hostile
zips, deletes each check in turn to prove the corpus goes red, and matches
each rejection against the message of the check that case was written to
provoke — "it exited non-zero" is not the same claim. Check 4 is invisible outside
the busybox-as-root cell, and checks 3 and 5 mask each other, so they are
asserted as a pair. It also asks the kernel, in bytes,
what cap the running shell actually derived — the assertion the block-size
bug needed and did not have.

`lib-safe-extract.ps1` is the Windows half. It does **not** use
`Expand-Archive`: Windows PowerShell 5.1 ships
`Microsoft.PowerShell.Archive 1.0.1.0`, which predates even the traversal check
that PowerShell 7's 1.2.5 has — and 1.2.5 still accepts a two-entry archive, a
nested-directory archive, and writes a Unix symlink entry out as a file whose
content is the link target.

## The Windows entrypoint is an open question

**`.mcp.json` holds exactly one `command` string and has no platform
conditional.** There is no key in the current MCP server schema that names one
program on Unix and another on Windows, and the command is spawned directly
with no shell to branch in — so the spec's "registers `bootstrap.sh` on Unix
and `bootstrap.cmd` on Windows" cannot be expressed.

The shape here is the only one in which one string can be both: the command is
extensionless (`${CLAUDE_PLUGIN_ROOT}/bootstrap`), the POSIX sh script is the
file with no extension, and `bootstrap.cmd` sits beside it for Windows PATHEXT
resolution to find. **Whether the spawn path actually does PATHEXT resolution
is unverified** — no Windows host was available when this landed. It costs
nothing on Unix, where the resolution is by shebang and is measured working.

Two further things are unverified on Windows and would be settled by the same
CI step:

- whether a native child's stdout survives PowerShell's pipeline byte-for-byte.
  MCP is JSON-RPC over stdio; if PowerShell re-encodes it the server will
  appear to connect and then talk nonsense.
- whether `bootstrap.cmd` is reached at all.
- whether `bootstrap.ps1`'s answer to `initialize` on failure reaches Claude
  Code through `bootstrap.cmd`. It is exercised under `pwsh` on Linux only.

If PATHEXT does not resolve, the fallback is two MCP server entries with the
wrong-platform one failing closed. That is ugly enough to be worth recording
here rather than discovering twice.

## MANUAL CHECK: the band in a real session

CI drives the band through Claude Code's test kit. A real terminal drove
the rest once, on 2026-10-06 with Claude Code 2.1.291 in default permission
mode, with no login: a second plugin's command stood in for the agent and
made its `list_sessions` and `request_secret_input` calls, allowed by rule.
The band and the toast drew with the id beside the name, `1` alone in the
empty prompt opened attach in a split without taking the focus, the secret
typed there answered the call, `2` copied the command, and a timeout closed
with `not sent: timeout`. The session kept its own size, and the band raised
no permission dialog. A second run left `request_secret_input` unallowed:
Claude Code's dialog for it came up with the band's toast already drawn, the
band itself appeared only once the dialog was answered, reading the timeout
less the time the dialog had been up, and a `1` pressed while the dialog was
up answered the dialog. What neither run could have is a model turn, so this
check has one. It is the owner's to run for each Claude Code release the
band is claimed to work with. It needs a `holdfast` built with
`attach --keep-size`, tmux, and a Claude Code login.

1. **Isolate the daemon, Claude Code and tmux.** In a terminal at least 110
   columns wide, from the checkout's root:

   ```bash
   cargo build --release --locked -p holdfast
   CHECKOUT=$PWD
   HF="$CHECKOUT/target/release/holdfast"   # or under your CARGO_TARGET_DIR
   ISO=$(mktemp -d)
   mkdir -p -m 700 "$ISO/home" "$ISO/run" "$ISO/rt" "$ISO/xdg" "$ISO/claude"
   export HOME="$ISO/home" XDG_RUNTIME_DIR="$ISO/run" HOLDFAST_RUNTIME_DIR="$ISO/rt" \
          XDG_CONFIG_HOME="$ISO/xdg/config" XDG_DATA_HOME="$ISO/xdg/data" \
          XDG_STATE_HOME="$ISO/xdg/state" CLAUDE_CONFIG_DIR="$ISO/claude" \
          HOLDFAST_BOOTSTRAP_BIN="$HF"
   env -u TMUX tmux -L hf-band -f /dev/null new-session \
     claude --plugin-dir "$CHECKOUT/plugin" --permission-mode default
   ```

   The private tmux server starts with these exports, so every pane it opens
   has them; a pane of your usual tmux server would not, and its attach
   would dial your real daemon. If that terminal is itself a tmux pane, this
   one runs nested inside it: press the prefix twice to reach the inner one.
   The first time, `/login` inside that session: the config directory is a
   new installation.

2. **Ask for a secret.** Send:

   > Using only the holdfast tools: start a session named deploy running
   > bash, and in it run `read -r -s -p 'Password: ' pw; echo; echo got
   > ${#pw} bytes`. Wait until its interaction_mode is AwaitingSecret, then
   > call request_secret_input for it with prompt_text "test password for
   > deploy" and timeout_secs 120. Never send input to the session yourself.

3. **The band and the toast.** When the `request_secret_input` row appears
   you should see the toast *holdfast: deploy (sess_...) is waiting for a
   secret. Type it in holdfast attach, not here.* and, above the prompt, the
   band: the name with the id (the agent's own `start_session` gave it),
   "agent says" with the prompt text, *at least M:SS left* counting down, and
   the two buttons. **No permission dialog names the holdfast plugin**, at
   this step or any other: the only dialogs are Claude Code's for the agent's
   own calls, and none if you allowed them. If Claude Code asks you to
   approve the agent's `request_secret_input`, the toast is expected while
   its dialog is up and the band only after it, as in the run above: note
   whether that holds, wait about ten seconds, and approve with Enter on
   *Yes*. The band should then read about ten seconds less than the timeout,
   and the call should still be open for the whole timeout after you
   approved.

4. **Button 1, from an empty prompt.** With nothing typed, press `1` and
   pause. A pane opens on the right, and the cursor stays in Claude Code.
   The pane must show attach's own banner, *holdfast: attached to sess_...*;
   if it shows *holdfast attach exited N* instead, attach did not reach the
   daemon, and that line and the one above it are the report. Switch to the
   pane (`Ctrl-B o`), type any password and Enter. Within a second the call
   returns, and the band reads *holdfast: deploy (sess_...) - secret_provided,
   N bytes written* for about five seconds, then is gone.

5. **Button 2.** Ask the agent to run the `read` again and request another
   secret. Press `2` in the empty prompt: the toast shows the copied command.
   Paste it into a shell with the same exports; it attaches, and the secret
   typed there answers the call.

6. **A timeout.** Request once more with timeout_secs 20 and answer nothing:
   the closing line reads `not sent: timeout`.

7. **The switch.** Quit, add
   `"pluginConfigs": { "holdfast@inline": { "options": { "secret_band": false } } }`
   to `$ISO/claude/settings.json` (`holdfast@inline` is the plugin's id under
   `--plugin-dir`), start the private tmux again as in step 1 and repeat
   step 2: no toast, no band, and the call still waits for `holdfast attach`.

**Report**, for each step, whether it happened as written, the terminal
width, what step 3 saw while the permission dialog was up and what the band
read after it, any permission
dialog that names the holdfast plugin (there must be none), and any
transcript line naming the plugin, such as `ui.render (AbovePrompt) refused:
...` (a drawing Claude Code rejected and replaced with its own) or
`tool.call hook skipped: ...`. Then clean up with the same exports:
`"$HF" daemon stop`, `tmux -L hf-band kill-server`, and `rm -rf "$ISO"`.

## Releasing

The version is in four files and six literals, and all of them move
together; [CONTRIBUTING.md](../CONTRIBUTING.md#releases) step 4 lists them,
including the two `Cargo.lock` lines without which every `--locked` build
fails. Three of the four matter to the plugin: `Cargo.toml`,
`plugin/version.txt`, and `plugin/.claude-plugin/plugin.json`. The spec names
only the first two; the install cache is keyed
`cache/<marketplace>/<plugin>/<version>/` from **plugin.json**, so a release
that bumps `version.txt` alone ships a plugin that never updates.
`scripts/plugin-manifest-check.py` fails if those three disagree.

**Which tree an install gets is a separate question, and the answer moves
after promotion.** While `.claude-plugin/marketplace.json`'s `source` is
`"./plugin"`, an install reads this directory off `main` — which the release PR
has already bumped to a version whose release is still a draft, so every
install in that window fails to start. Once a release is promoted, the source
becomes a `git-subdir` pin of `plugin/` at that tag and its commit, and it
moves only after the next promotion.
[CONTRIBUTING.md](../CONTRIBUTING.md#releases) step 8 has the procedure;
`scripts/plugin-manifest-check.py` accepts `"./plugin"` or a pin of exactly that
shape and nothing else.
