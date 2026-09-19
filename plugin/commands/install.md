---
description: Install or repair the Holdfast binary the plugin bootstrap runs
allowed-tools: Bash(command:*), Bash(uname:*), Bash(ls:*), Bash(sha256sum:*), Bash(shasum:*), Bash(cargo:*), Bash(printenv:*), Bash(holdfast:*)
---

Get the user a working `holdfast` binary. The plugin does not ship one: its
`.mcp.json` runs `bootstrap`, which downloads the binary matching
`plugin/version.txt` from the GitHub Release, verifies it against that
release's `SHA256SUMS.txt`, and caches it. **Every failure this command exists
for is a failure of that download**, so find out which one before suggesting a
fix.

Run the bootstrap by hand and read what it says — it names its own cause:

```sh
HOLDFAST_BOOTSTRAP_DEBUG=1 "${CLAUDE_PLUGIN_ROOT}/bootstrap" version
```

The failures it distinguishes, and what each one actually means:

- **"is the release published"** — the version this plugin build is pinned to
  has no assets yet, or the host cannot reach `github.com`. On an air-gapped or
  firewalled host this is the expected message and the fallback below is the
  answer, not a workaround.
- **"checksum mismatch"** — the download did not match the release manifest.
  Nothing was installed and nothing was cached. Retry once; if it repeats, stop
  and report it rather than working around it.
- **"archive does not contain exactly 'holdfast'"** and its neighbours — the
  archive was rejected by the safe-extraction rules. This is not a transfer
  fault; say so plainly and do not suggest extracting it by hand.
- **"cannot run it — is … on a noexec mount"** — the install succeeded and the
  cache directory forbids execution. Point `CLAUDE_PLUGIN_DATA` or
  `XDG_CACHE_HOME` at a filesystem mounted without `noexec`.

**The air-gapped fallback**, which is also the manual repair:

1. On a connected machine, fetch `holdfast-<target>.tar.gz` and
   `SHA256SUMS.txt` from <https://github.com/Sertelegger/holdfast/releases> for
   the tag matching `plugin/version.txt`. `<target>` is `linux-x86_64`,
   `linux-aarch64`, `macos-x86_64`, `macos-aarch64` or `windows-x86_64`.
2. **Verify the checksum yourself** — `sha256sum -c SHA256SUMS.txt
   --ignore-missing`, or `shasum -a 256` and compare by eye. Skipping this
   moves the whole trust root from GitHub's TLS to the USB stick.
3. Extract the single `holdfast` binary and place it at
   `$CLAUDE_PLUGIN_DATA/bin/holdfast-v<version>-<target>`, mode 755, with
   `SHA256SUMS.txt` beside it as `SHA256SUMS-v<version>.txt`. Both files must
   be there: the bootstrap treats a binary without its manifest as a cache
   miss and tries to download again.

Two other routes, each with a real cost worth stating rather than hiding:

- **`cargo install holdfast`** builds from source on the user's machine. It
  needs a Rust toolchain and several minutes, and the result does **not** live
  in the plugin cache — so the bootstrap will still try to download unless
  `HOLDFAST_BOOTSTRAP_ALLOW_PATH=1` is set.
- **`HOLDFAST_BOOTSTRAP_ALLOW_PATH=1`** makes the bootstrap exec whatever
  `holdfast` is on `$PATH` when its reported version matches. **Say what that
  buys and what it costs**: version output is not authentication, so any
  writable `$PATH` entry ahead of the real binary is then exec'd with the
  agent's MCP stdio attached. It is off by default for that reason. Recommend
  it only to a user who asked for it and who controls their `$PATH`.

Do not download anything yourself, and do not disable a check to make an
install succeed. Report the diagnosis and the option you recommend.
