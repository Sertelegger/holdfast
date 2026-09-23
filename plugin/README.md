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
binary to download … To run Holdfast now, build it*. That line is the way in:
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

## Releasing

Three files carry the version and all three must move together:
`Cargo.toml`, `plugin/version.txt`, and `plugin/.claude-plugin/plugin.json`.
The spec names only the first two; the install cache is keyed
`cache/<marketplace>/<plugin>/<version>/` from **plugin.json**, so a release
that bumps `version.txt` alone ships a plugin that never updates.
`scripts/plugin-manifest-check.py` fails if they disagree.

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
