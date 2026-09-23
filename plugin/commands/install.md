---
description: Install or repair the Holdfast binary the plugin bootstrap runs
allowed-tools: Bash(command:*), Bash(uname:*), Bash(ls:*), Bash(sha256sum:*), Bash(shasum:*), Bash(cargo:*), Bash(printenv:*), Bash(holdfast:*)
---

Get the user a working `holdfast` binary. The plugin does not ship one: its
`.mcp.json` runs `bootstrap`, which execs the binary `HOLDFAST_BOOTSTRAP_BIN`
names if that is set, and otherwise downloads the binary matching
`plugin/version.txt` from the GitHub Release, verifies it against that
release's `SHA256SUMS.txt`, and caches it. **Find out which of those failed
before suggesting a fix.**

The reason is usually already on screen: `claude mcp list` and `/mcp` show a
failing bootstrap as `Failed to connect — -32603: holdfast bootstrap: <reason>`.
To reproduce it, run the bootstrap by hand — it names its own cause:

```sh
HOLDFAST_BOOTSTRAP_DEBUG=1 "${CLAUDE_PLUGIN_ROOT}/bootstrap" version
```

The failures it distinguishes, and what each one actually means:

- **"no holdfast vX.Y.Z binary to download"** — the release this plugin build
  is pinned to answered 404: it is not promoted yet (a draft serves nothing),
  or it was published without binaries, as `v0.0.5` to `v0.0.7` were. **There
  is nothing to download by hand**, so do not send the user to the releases
  page. The answer is a build from source — the route below.
- **"cannot reach …"** — no server answered: the host is offline, firewalled
  or air-gapped. The manual placement below is the answer, not a workaround.
- **"HOLDFAST_BOOTSTRAP_BIN …"** — the user named a binary and it is not
  usable: a relative path, a `~` or `$` that nothing expands (Claude Code
  passes `settings.json` values literally), or not an executable file. The
  bootstrap refuses rather than downloading something else. Fix the path.
- **"checksum mismatch"** — the download did not match the release manifest.
  Nothing was installed and nothing was cached. Retry once; if it repeats,
  stop and report it rather than working around it.
- **"archive does not contain exactly 'holdfast'"** and its neighbours — the
  archive was rejected by the safe-extraction rules. This is not a transfer
  fault; say so plainly and do not suggest extracting it by hand.
- **"cannot run it — is … on a noexec mount"** — the install succeeded and the
  cache directory forbids execution. Point `CLAUDE_PLUGIN_DATA` or
  `XDG_CACHE_HOME` at a filesystem mounted without `noexec`.

**A build from source** — the only route before a release is promoted, and
the route on a platform with no prebuilt:

1. `cargo install --locked --git https://github.com/Sertelegger/holdfast --tag
   vX.Y.Z holdfast`, with `X.Y.Z` from `${CLAUDE_PLUGIN_ROOT}/version.txt`. It
   needs a Rust toolchain and several minutes, and it puts the binary at
   `~/.cargo/bin/holdfast`. **Not `cargo install holdfast`**: crates.io holds
   only a `0.0.0` name reservation with no binary, and cargo refuses it with
   *"there is nothing to install"*.
2. The user adds `"HOLDFAST_BOOTSTRAP_BIN": "<absolute path>"` to the `env`
   block of Claude Code's `settings.json` — the full path, spelled out, because
   `~` and `$HOME` are not expanded there — and restarts Claude Code. **Give
   them the line; do not edit their settings yourself.** Every
   `CLAUDE_CONFIG_DIR` has its own `settings.json`.

**The air-gapped fallback**, for a published release this host cannot reach:

1. On a connected machine, fetch `holdfast-<target>.tar.gz` and
   `SHA256SUMS.txt` from
   `https://github.com/Sertelegger/holdfast/releases/tag/vX.Y.Z` for the tag
   matching `plugin/version.txt`. `<target>` is `linux-x86_64`,
   `linux-aarch64`, `macos-x86_64`, `macos-aarch64` or `windows-x86_64`.
2. **Verify the checksum yourself** — `sha256sum -c SHA256SUMS.txt
   --ignore-missing`, or `shasum -a 256` and compare by eye. Skipping this
   moves the whole trust root from GitHub's TLS to the USB stick.
3. Extract the single `holdfast` binary and place it at
   `$CLAUDE_PLUGIN_DATA/bin/holdfast-v<version>-<target>`, mode 755, with
   `SHA256SUMS.txt` beside it as `SHA256SUMS-v<version>.txt`. Both files must
   be there: the bootstrap treats a binary without its manifest as a cache
   miss and tries to download again.

**`HOLDFAST_BOOTSTRAP_ALLOW_PATH=1`** is a third route, with a real cost worth
stating rather than hiding: the bootstrap then execs whatever `holdfast` is on
`$PATH` when its reported version is exactly `version.txt`'s. Version output
is not authentication, so any writable `$PATH` entry ahead of the real binary
is then exec'd with the agent's MCP stdio attached. It is off by default for
that reason, and `HOLDFAST_BOOTSTRAP_BIN` does the same job for one named file
with nothing to spoof. Recommend it only to a user who asked for it and who
controls their `$PATH`.

Do not download anything yourself, and do not disable a check to make an
install succeed. Report the diagnosis and the option you recommend.
