#!/bin/sh
# Build prerequisites, checked before `cargo build` rather than after it fails.
#
# The failure this exists for: CONTRIBUTING used to say the pinned toolchain is
# the one "`rustup` installs for you on first build". That is true only if
# `rustup` itself is new enough to fetch it. A stale `rustup` fails somewhere
# inside cargo instead, with a message about a feature or an edition, and the
# reader has no reason to suspect their installer rather than their checkout.
#
# **No version literal lives in this file.** The pin is read from
# `rust-toolchain.toml` and the MSRV from `Cargo.toml`, so bumping either one
# does not leave a second copy here to go stale -- the same reason
# `scripts/mcp-smoke.sh` retired its check count in favour of an invariant.
#
# Read-only: it installs nothing and writes nothing. Every failure prints the
# exact command to run. Exit 0 = ready to build, 1 = something to fix.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail=0

say_fix() {
    printf '  fix: %s\n' "$1"
    fail=1
}

# ---- the two pinned versions, read rather than remembered -----------------

pin=$(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$root/rust-toolchain.toml" | head -1)
msrv=$(sed -n 's/^ *rust-version *= *"\([^"]*\)".*/\1/p' "$root/Cargo.toml" | head -1)

if [ -z "$pin" ] || [ -z "$msrv" ]; then
    echo "preflight: could not read the toolchain pin or the MSRV."
    echo "  rust-toolchain.toml channel = '${pin:-<unreadable>}'"
    echo "  Cargo.toml rust-version     = '${msrv:-<unreadable>}'"
    echo "  This script is out of step with the files it reads; fix it rather than the environment."
    exit 1
fi

echo "preflight: toolchain pin ${pin}, MSRV ${msrv}"

# ---- rustup ---------------------------------------------------------------

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup: NOT FOUND"
    say_fix "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
else
    echo "rustup: $(rustup --version 2>/dev/null | head -1)"
    if ! rustup toolchain list 2>/dev/null | grep -q "^${pin}"; then
        echo "toolchain ${pin}: NOT INSTALLED"
        # Ordered deliberately: a rustup too old to fetch the pin is the case
        # that presents as a confusing cargo error rather than as a rustup one.
        say_fix "rustup self update && rustup toolchain install ${pin}"
    else
        echo "toolchain ${pin}: installed"
    fi
fi

# ---- the compiler that will actually run ----------------------------------
#
# Checked through `cargo`, not `rustc`, because cargo is what resolves the pin
# and is therefore what a build will really use.

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo: NOT FOUND"
    say_fix "install rustup (above), then re-run this script"
else
    have=$(cargo --version 2>/dev/null | awk '{print $2}')
    echo "cargo: ${have:-<unknown>}"
    if [ -n "$have" ]; then
        # sort -V puts the lower version first; if the MSRV is not first, the
        # installed cargo is older than the crate requires.
        lowest=$(printf '%s\n%s\n' "$msrv" "$have" | sort -V | head -1)
        if [ "$lowest" != "$msrv" ]; then
            echo "  cargo ${have} is older than the MSRV ${msrv}"
            say_fix "rustup self update && rustup toolchain install ${pin}"
        fi
    fi
fi

# ---- jq, which the smoke script needs and cargo does not -------------------

if ! command -v jq >/dev/null 2>&1; then
    echo "jq: NOT FOUND (scripts/mcp-smoke.sh needs it; cargo build does not)"
    say_fix "apt install jq  |  brew install jq  |  dnf install jq"
else
    echo "jq: $(jq --version 2>/dev/null)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "preflight: ready to build."
else
    echo "preflight: not ready -- run the fixes above, then re-run this script."
fi
exit "$fail"
