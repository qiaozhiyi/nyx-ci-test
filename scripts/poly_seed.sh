#!/usr/bin/env bash
# Map NYX_BUILD_SEED → Cargo release profile export lines (polymorphism L1).
#
# Usage:
#   eval "$(bash scripts/poly_seed.sh "$NYX_BUILD_SEED")"
#   bash scripts/poly_seed.sh <seed>     # seed as $1
#   NYX_BUILD_SEED=<seed> bash scripts/poly_seed.sh
#
# Prints:
#   export CARGO_PROFILE_RELEASE_OPT_LEVEL={3|s|z}
#   export CARGO_PROFILE_RELEASE_CODEGEN_UNITS={16|1}
#
# Does NOT print or set CARGO_PROFILE_RELEASE_LTO. Fat LTO swallowed
# .nyx_cfg patches (commit b94a158) and produced dead implants that C2'd
# to 127.0.0.1. Allowed LTO values if ever touched: unset / thin / off.
# This script never touches LTO.
#
# Mapping MUST match crates/config/src/poly.rs::l1_release_flags (locked by
# nyx-config unit tests). Invalid seed → non-zero exit, no fallback.
#
# Gate: every new param combo MUST pass nyx_selftest_cfgstage before it is
# a supported template. Do not add a CI matrix of all combos here.
set -euo pipefail

if [[ $# -ge 1 ]]; then
    SEED_RAW="$1"
elif [[ ${NYX_BUILD_SEED+x} ]]; then
    SEED_RAW="$NYX_BUILD_SEED"
else
    echo "poly_seed.sh: missing seed (pass \$1 or NYX_BUILD_SEED)" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "poly_seed.sh: python3 is required to parse NYX_BUILD_SEED" >&2
    exit 1
fi

export _NYX_POLY_SEED_RAW="$SEED_RAW"
python3 - <<'PY'
import os
import sys

raw = os.environ.get("_NYX_POLY_SEED_RAW", "")


def parse_build_seed(s: str) -> int:
    s = s.strip()
    if not s:
        raise ValueError("NYX_BUILD_SEED is empty")
    if s[0] in "+-":
        raise ValueError("NYX_BUILD_SEED must be an unsigned integer")
    if s.startswith("0x") or s.startswith("0X"):
        h = s[2:]
        if not h or any(c not in "0123456789abcdefABCDEF" for c in h):
            raise ValueError("NYX_BUILD_SEED is invalid hex: %r" % s)
        val = int(h, 16)
    elif s.isdigit():
        val = int(s, 10)
    elif all(c in "0123456789abcdefABCDEF" for c in s):
        val = int(s, 16)
    else:
        raise ValueError("NYX_BUILD_SEED is invalid: %r" % s)
    if val > 2**64 - 1:
        raise ValueError("NYX_BUILD_SEED overflows u64: %r" % s)
    return val


try:
    seed = parse_build_seed(raw)
except ValueError as exc:
    print("poly_seed.sh: %s" % exc, file=sys.stderr)
    sys.exit(1)

opt = ["3", "s", "z"][seed % 3]
cgu = [16, 1][seed % 2]
print("export CARGO_PROFILE_RELEASE_OPT_LEVEL=%s" % opt)
print("export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=%s" % cgu)
PY
