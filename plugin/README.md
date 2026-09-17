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

Then restart Claude Code. The first MCP call downloads the binary; every call
after that is a file-existence check.

`holdfast@holdfast` is `<plugin>@<marketplace>`. The right-hand `holdfast` is
this repository's `.claude-plugin/marketplace.json` `name` field — it is not
derived from the repository name, so renaming the repo does not change the
install line and renaming that field does.

## What the bootstrap does

`.mcp.json` registers one stdio server whose command is
`${CLAUDE_PLUGIN_ROOT}/bootstrap`. On every MCP start that script:

1. reads `version.txt` next to itself — the version this plugin build is
   pinned to, bumped in the release PR;
2. execs the cached binary for that version and this target if it is there;
3. otherwise fetches `SHA256SUMS.txt` and `holdfast-<target>.tar.gz` from the
   matching GitHub Release over TLS, verifies the archive against the freshly
   fetched manifest, extracts exactly one member under the safe-extraction
   rules below, installs it into the cache and execs it.

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

## Air-gapped, firewalled, or the release simply is not published yet

The bootstrap fails with a message that names the URL and the exact path to
put the binary at. To install by hand:

1. On a connected machine, download `holdfast-<target>.tar.gz` and
   `SHA256SUMS.txt` from <https://github.com/Sertelegger/holdfast/releases>
   for the tag matching this plugin's `version.txt`. `<target>` is one of
   `linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64`,
   `windows-x86_64`.
2. **Verify the checksum yourself.** `sha256sum -c SHA256SUMS.txt
   --ignore-missing`, or `shasum -a 256` and compare. Skipping this moves the
   trust root from GitHub's TLS onto whatever carried the file.
3. Extract the single `holdfast` binary and place it, mode 755, at
   `$CLAUDE_PLUGIN_DATA/bin/holdfast-v<version>-<target>`, with
   `SHA256SUMS.txt` beside it named `SHA256SUMS-v<version>.txt`. **Both files,
   or it is a cache miss**: a binary without its manifest is treated as absent
   and the bootstrap tries to download again.

`cargo install holdfast` also works and needs no network at MCP time — but it
installs onto `$PATH`, not into the cache, so see `HOLDFAST_BOOTSTRAP_ALLOW_PATH`
below.

The `/holdfast:install` command walks a user through all of this and reads the
bootstrap's own diagnosis first.

## Environment

| Variable | Effect |
|---|---|
| `HOLDFAST_BOOTSTRAP_DEBUG` | Trace to stderr. Safe at any time; stdout stays the MCP transport |
| `HOLDFAST_BOOTSTRAP_ALLOW_PATH` | Exec whatever `holdfast` is on `$PATH` when it reports the pinned version. **Off by default and that is a security decision** — see below |
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
authorisation.

## The safe-extraction rules, and why they are a whitelist

The spec words them as a blacklist — reject absolute paths, `..` components,
symlinks, hardlinks, device files. Measured, that cannot be written over a tar
listing: **busybox tar sanitises names before it prints them**, so an entry
stored as `../../../tmp/PWNED` lists as `tmp/PWNED` and a check that greps the
listing for `..` never fires — on the one implementation the rule was written
for. The archive still extracts a file the maintainer never shipped.

`lib-safe-extract.sh` enforces the clause the same sentence ends with instead:
the archive must contain *exactly the expected `holdfast` executable*. Four
checks, each of which is the only thing that catches something:

1. the listing is exactly the one expected name — nothing before, nothing after;
2. the `-tv` mode string is a regular file with no setuid/setgid bit;
3. extraction of that one member only, under `ulimit -f`;
4. **what actually landed on disk** is re-validated — one entry, regular file,
   not a symlink or directory or device, non-empty, link count 1, no setuid.

Check 4 is not defence in depth. busybox tar reports a hardlink entry as a
regular file and then happily materialises a second link to `/etc/passwd`
named `holdfast`; nothing in the listing says so.

`scripts/plugin-archive-tests.sh` runs 19 hostile tar archives and 11 hostile
zips, and deletes each check in turn to prove the corpus goes red. Two of the
four are invisible outside the busybox-as-root cell, which is why CI runs that
cell separately.

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
