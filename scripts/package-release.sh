#!/usr/bin/env bash
# Build one release asset and lay it out the way §12.1 and §13.3 require.
#
# **This script is the one description of how a release asset is built**, and
# that is its whole point rather than a tidiness preference. A release
# workflow cannot be tested by releasing — the trigger is a tag, and a tag is
# not a thing to cut in order to find out whether the YAML parses. So the
# build-and-pack half lives here, where `release-rehearsal.yml` runs it on
# every pull request against all five targets and where a developer can run
# the identical command on a laptop. What `release.yml` adds that nothing
# else exercises is then exactly one line, `gh release create`, and that line
# stays in the workflow: `scripts/ci-hygiene.sh` reads `.github/workflows/`
# and nothing else, so a publish command moved into `scripts/` would evade the
# very gate that authorises it.
#
# Usage:
#   scripts/package-release.sh --assets          # the five §12.1 asset names
#   scripts/package-release.sh --target <asset>  # the Rust triple for one
#   scripts/package-release.sh --archive <asset> # the file name it produces
#   scripts/package-release.sh <asset> [outdir]  # build + archive (outdir=dist)
#   scripts/package-release.sh --sums <dir>      # assemble SHA256SUMS.txt
#
# §12.1 (spec:3793) names the assets, not the triples:
#
#   "**GitHub Releases** — prebuilt binaries for `linux-x86_64`,
#    `linux-aarch64`, `macos-x86_64`, `macos-aarch64`, `windows-x86_64`.
#    `.tar.gz` (Unix) / `.zip` (Windows) plus `SHA256SUMS.txt`."
#
# and §13.3 step 5 is why the spelling is load-bearing rather than cosmetic:
# the bootstrap fetches
# `releases/download/vX.Y.Z/holdfast-<target>.<tar.gz|zip>`, composing that
# name from §12.1's list. An asset named by Rust triple is an asset the
# bootstrap cannot find.
set -euo pipefail

# **musl, not gnu, for both Linux assets — and §13.3 is what decides it.**
# The spec names the asset `linux-x86_64` with no libc, so §12.1 alone does
# not settle the question; §13.3 does, by promising the bootstrap "runs under
# `dash`/`busybox sh` on minimal Alpine-style installs". A glibc binary
# cannot exec on Alpine at all, so a gnu asset would make the bootstrap's own
# stated environment one it cannot serve. The static musl build satisfies
# both readings, and measured it costs nothing: `scripts/mcp-smoke.sh`
# against the musl binary passes every counted check, PTYs and all.
#
# It also buys the cross-build. `x86_64-unknown-linux-musl` links on a stock
# `ubuntu-24.04` with no apt package at all, and `aarch64-unknown-linux-musl`
# links with the `rust-lld` override in `.cargo/config.toml` — so one Linux
# runner produces both Linux assets. The Apple and Windows targets are not
# cross-built here: they COMPILE from Linux (every crate, including the
# binary) and fail only at link, on a missing macOS SDK and a missing
# `link.exe` respectively. Those are native-runner problems with native-runner
# answers, and a native build is the more trustworthy one anyway.
assets=(linux-x86_64 linux-aarch64 macos-x86_64 macos-aarch64 windows-x86_64)

triple_for() {
  case "$1" in
    linux-x86_64)   printf 'x86_64-unknown-linux-musl\n' ;;
    linux-aarch64)  printf 'aarch64-unknown-linux-musl\n' ;;
    macos-x86_64)   printf 'x86_64-apple-darwin\n' ;;
    macos-aarch64)  printf 'aarch64-apple-darwin\n' ;;
    windows-x86_64) printf 'x86_64-pc-windows-msvc\n' ;;
    *) return 1 ;;
  esac
}

# `<asset>` -> the file the release carries and the bootstrap asks for.
archive_for() {
  case "$1" in
    windows-*) printf 'holdfast-%s.zip\n' "$1" ;;
    *)         printf 'holdfast-%s.tar.gz\n' "$1" ;;
  esac
}

case "${1:-}" in
  --assets)
    printf '%s\n' "${assets[@]}"
    exit 0
    ;;
  --target)
    triple_for "${2:?--target needs an asset name}" || {
      printf 'unknown asset %s; known: %s\n' "$2" "${assets[*]}" >&2
      exit 2
    }
    exit 0
    ;;
  --archive)
    # **A name, not a glob.** `ls dist/holdfast-linux-x86_64.*` also matches
    # `holdfast-linux-x86_64.tar.gz.sha256`, and a caller that assigned that
    # two-line result to a variable would build a broken path out of it. The
    # extension is a property of the asset and this is where that is decided,
    # so asking is cheaper than re-deriving it in two workflows.
    triple_for "${2:?--archive needs an asset name}" >/dev/null || {
      printf 'unknown asset %s; known: %s\n' "$2" "${assets[*]}" >&2
      exit 2
    }
    archive_for "$2"
    exit 0
    ;;
  --sums)
    # **The publish job and the rehearsal call this identical line**, which
    # is what makes the rehearsal a rehearsal: if the two assembled
    # `SHA256SUMS.txt` differently, a green pull request would prove nothing
    # about the file the bootstrap fetches.
    #
    # It is also the check that a matrix leg cannot vanish quietly. The set
    # is `$assets`, not "whatever is in the directory", so a build job that
    # was deleted, renamed or skipped fails here instead of producing a
    # four-asset release whose checksum file is internally consistent and
    # silently short.
    sums_dir="${2:?--sums needs a directory}"
    : > "$sums_dir/SHA256SUMS.txt"
    for a in "${assets[@]}"; do
      f="$(archive_for "$a")"
      if [ ! -f "$sums_dir/$f" ] || [ ! -f "$sums_dir/$f.sha256" ]; then
        printf 'missing %s or its .sha256 in %s — §12.1 names five assets and this is not five\n' \
          "$f" "$sums_dir" >&2
        exit 1
      fi
      cat "$sums_dir/$f.sha256" >> "$sums_dir/SHA256SUMS.txt"
    done
    # The per-asset files were the transport between five machines; the
    # release carries one file, so they do not ship.
    rm -f "$sums_dir"/*.sha256
    cat "$sums_dir/SHA256SUMS.txt"
    exit 0
    ;;
  ''|-*)
    sed -n '/^# Usage:/,/^# *scripts\/package-release.sh --sums/p' "$0" >&2
    exit 2
    ;;
esac

asset="$1"
outdir="${2:-dist}"
triple="$(triple_for "$asset")" || {
  printf 'unknown asset %s; known: %s\n' "$asset" "${assets[*]}" >&2
  exit 2
}

# `.exe` is a property of the TARGET, not of the machine doing the build.
archive="$(archive_for "$asset")"
case "$asset" in
  windows-*) member=holdfast.exe ;;
  *)         member=holdfast ;;
esac

# **Or every shipped binary reports `build unknown` in its handshake.**
# `crates/holdfast-core/src/protocol/handshake.rs` reads
# `option_env!("HOLDFAST_BUILD_SHA")` and its own doc comment says the value
# is "wired to a real git SHA by the release pipeline" — this is that
# pipeline. Derived from git when the caller did not supply it, so a local
# run of this script produces the same shape of artifact CI does rather than
# a differently-labelled one.
if [ -z "${HOLDFAST_BUILD_SHA:-}" ] && git rev-parse HEAD >/dev/null 2>&1; then
  HOLDFAST_BUILD_SHA="$(git rev-parse --short=12 HEAD)"
  export HOLDFAST_BUILD_SHA
fi

echo "asset:   $asset"
echo "triple:  $triple"
echo "build:   ${HOLDFAST_BUILD_SHA:-<unset — the binary will say 'build unknown'>}"

# `--locked` is §12.4's requirement verbatim: "releases built with
# `cargo build --release --locked`". `--workspace` matches what ci.yml's
# `package` job already builds, so the release build is the tested build's
# invocation and not a second one.
# Not swallowed with `|| true`: a target that will not install is a release
# asset that will not exist, and finding that out from a link error two
# minutes later reads as a different defect.
if command -v rustup >/dev/null 2>&1; then
  rustup target add "$triple"
fi
cargo build --release --locked --workspace --target "$triple"

built="target/${triple}/release/${member}"
[ -f "$built" ] || { printf 'cargo produced no %s\n' "$built" >&2; exit 1; }

# **Staged into a fresh directory so the archive member is a bare name.**
# §13.3 step 5 rejects "archives that do not contain exactly the expected
# `holdfast` executable for the target", so the archive holds one flat entry
# and no directory prefix, no `./`, and nothing else at all.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$built" "$stage/$member"
chmod 0755 "$stage/$member"

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"
rm -f "$outdir/$archive"

case "$archive" in
  *.tar.gz)
    # `gzip -n` drops the timestamp and the original filename from the gzip
    # header, so two packs of one binary differ in no byte gzip adds. That is
    # as far as this goes: the BINARY is not reproducible (no `-Zbuild-std`,
    # no pinned build paths), and §12.4's reproducibility promise is about
    # the source archive at the tag, which GitHub generates and this does not
    # touch. Claiming more here would be claiming something unmeasured.
    ( cd "$stage" && tar -cf - "$member" ) | gzip -9n > "$outdir/$archive"
    ;;
  *.zip)
    # **No single zip tool is present on all three runner images**, so the
    # probe is explicit and its failure is loud. `python3` is last rather
    # than absent because it is already load-bearing in this pipeline —
    # ci.yml's hygiene job runs `scripts/spec-enum-check.py` — and it is the
    # only one of the three guaranteed on every image this repository uses.
    if command -v 7z >/dev/null 2>&1; then
      ( cd "$stage" && 7z a -tzip -bso0 -bsp0 "$outdir/$archive" "$member" >/dev/null )
    elif command -v zip >/dev/null 2>&1; then
      ( cd "$stage" && zip -q -X "$outdir/$archive" "$member" )
    elif command -v python3 >/dev/null 2>&1; then
      ( cd "$stage" && python3 -c 'import sys,zipfile
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
i = zipfile.ZipInfo(sys.argv[2], (1980, 1, 1, 0, 0, 0))
i.external_attr = 0o100755 << 16
with open(sys.argv[2], "rb") as f:
    z.writestr(i, f.read())
z.close()' "$outdir/$archive" "$member" )
    else
      echo "no zip tool: tried 7z, zip, python3" >&2
      exit 1
    fi
    ;;
esac

# macOS has no `sha256sum`; Linux has no `shasum` guaranteed. Both are here
# rather than one, because the release matrix runs this script on both.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# **The line format is `sha256sum`'s, and that is a contract with the
# bootstrap**, not a convenience: §13.3 step 5 has the launcher fetch
# `SHA256SUMS.txt` from the release and "verify the archive against the
# freshly-fetched `SHA256SUMS.txt`". Sixty-four lowercase hex, two spaces,
# the bare asset name — parseable by `sha256sum -c`, by `shasum -a 256 -c`,
# and by four lines of POSIX sh, which is what §13.3 says `bootstrap.sh` has
# to be. One `.sha256` per asset is written here rather than the combined
# file because the matrix legs run on five different machines; the publish
# job concatenates them in a fixed order.
printf '%s  %s\n' "$(sha256_of "$outdir/$archive")" "$archive" > "$outdir/${archive}.sha256"

echo "packed:  $outdir/$archive"
cat "$outdir/${archive}.sha256"
