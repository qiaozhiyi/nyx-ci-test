#!/usr/bin/env bash
# Build the implant-win DLL on the dev host and verify it on the remote Windows
# server — the closed-loop "build locally, verify on Windows" pipeline.
#
# Why build on the dev host (not on Windows): the macOS host has brew's mingw
# (`x86_64-w64-mingw32-gcc`) + a nightly toolchain with the `x86_64-pc-windows-gnu`
# target and `rust-src`, so it cross-compiles the no_std PIC implant directly.
# The Windows server only needs to RUN the result (its toolchain is msvc-only,
# no git/python/mingw), so we SCP the fresh DLL there and drive the 8 selftest
# exports via rundll32 (scripts/remote_tests.py).
#
# Usage:   bash scripts/win_build.sh
# Exit:    0 if the build succeeded AND all 8 selftests hit their expected codes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DLL="crates/implant-win/target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll"

echo "==> [1/2] cross-building implant-win (nightly + build-std -> x86_64-pc-windows-gnu)"
cargo +nightly build -Z build-std=core,alloc,panic_abort \
    --manifest-path crates/implant-win/Cargo.toml \
    --target x86_64-pc-windows-gnu --release
[[ -f "$DLL" ]] || { echo "FAIL: build did not produce $DLL"; exit 1; }
echo "    fresh DLL: $(stat -f '%z bytes, built %Sm' "$DLL")"

echo "==> [2/2] deploying to the Windows server + running selftests"
exec python3 scripts/remote_tests.py
