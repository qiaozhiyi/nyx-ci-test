#!/usr/bin/env bash
# verify_implant_pub.sh — extract the server_pub baked into a Windows implant DLL
# and compare it against a reference (live server log, keyfile, or hex string).
#
# WHY THIS EXISTS:
#   `frame decryption failed` on a Windows implant is almost always a baked
#   server_pub that doesn't match the currently running server. The implant
#   stores server_pub at .nyx_cfg section bytes [54..86] (see
#   crates/implant-win/src/config_placeholder.rs:114-116 and the writer at
#   crates/server/src/implant_gen.rs:579). This script extracts those 32 bytes
#   and diffs them against whatever the running server reports, so you can
#   catch the mismatch BEFORE deploying to Windows.
#
#   NOTE: the pubkey you want to verify is the SERVER's long-term X25519 pub,
#   NOT the implant's own ephemeral pubkey. (Verifying the implant pubkey is
#   meaningless — it's regenerated on every check-in.)
#
# Usage:
#   ./scripts/verify_implant_pub.sh <implant.dll> <server.log>
#       Extract baked pub from the DLL, extract live pub from the server log,
#       compare.
#
#   ./scripts/verify_implant_pub.sh <implant.dll> --pub <hex>
#       Compare against an explicit hex pubkey.
#
#   ./scripts/verify_implant_pub.sh <implant.dll> --keyfile <path>
#       Derive the expected pub from a 32-byte keyfile (re-runs the server's
#       from_secret_bytes logic via Python cryptography).
#
# Exit 0 = MATCH, 1 = MISMATCH (or usage error).

set -uo pipefail

if [ $# -lt 2 ]; then
  cat <<USAGE
Usage:
  $0 <implant.dll> <server.log>
  $0 <implant.dll> --pub <hex>
  $0 <implant.dll> --keyfile <32-byte-keyfile>
USAGE
  exit 1
fi

IMPLANT="$1"; shift
[ -f "$IMPLANT" ] || { echo "❌ implant not found: $IMPLANT"; exit 1; }

# ── 1. Extract baked server_pub from the implant DLL ──────────────────────────
# Scan for the 0xDEADBEEF magic that marks a patched .nyx_cfg section, then read
# bytes [54..86] relative to it (section layout documented in config_placeholder.rs).
BAKED_PUB=$(python3 - "$IMPLANT" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
# 0xDEADBEEF as LE bytes: EF BE AD DE
magic = b"\xef\xbe\xad\xde"
idx = data.find(magic)
if idx < 0:
    print("ERROR_NOT_PATCHED", end="")
    sys.exit(0)
# Section layout (from implant_gen.rs:548-551):
#   [magic 4][keying 4][data_len 2][nonce 12][implant_priv 32][server_pub 32]...
# server_pub starts at offset 54 from magic.
pub_off = idx + 54
if pub_off + 32 > len(data):
    print("ERROR_SHORT", end="")
    sys.exit(0)
print(data[pub_off:pub_off+32].hex(), end="")
PY
)

if [ "$BAKED_PUB" = "ERROR_NOT_PATCHED" ]; then
  echo "❌ No 0xDEADBEEF magic found in $IMPLANT"
  echo "   This implant is UNPATCHED (uses compile-time config). Its server_pub"
  echo "   comes from build.rs env vars, not .nyx_cfg. You must either:"
  echo "     (a) generate the implant via the server's /api/implant/generate, or"
  echo "     (b) check NYX_SERVER_PUB at cross-compile time matches the running server."
  exit 1
fi
if [ "$BAKED_PUB" = "ERROR_SHORT" ]; then
  echo "❌ Found 0xDEADBEEF magic but section is truncated in $IMPLANT"
  exit 1
fi

echo "implant    : $IMPLANT"
echo "baked pub  : $BAKED_PUB  (from .nyx_cfg[54..86])"
echo ""

# ── 2. Determine the reference pubkey ──────────────────────────────────────────
case "$1" in
  --pub)
    REF="$2"
    echo "reference  : (explicit hex) $REF"
    ;;
  --keyfile)
    KF="$2"
    [ -f "$KF" ] || { echo "❌ keyfile not found: $KF"; exit 1; }
    SZ=$(wc -c < "$KF" | tr -d ' ')
    [ "$SZ" = "32" ] || { echo "❌ keyfile is $SZ bytes (expected 32)"; exit 1; }
    REF=$(python3 - "$KF" <<'PY'
import sys
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR_NO_CRYPTO", end=""); sys.exit(0)
kb = open(sys.argv[1], "rb").read()
# The keyfile is the raw 32-byte X25519 private scalar (server lib.rs:270-275
# feeds it straight into StaticSecret::from). Reconstruct and read the pub.
priv = X25519PrivateKey.from_private_bytes(kb)
pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)
print(pub.hex(), end="")
PY
)
    [ "$REF" = "ERROR_NO_CRYPTO" ] && { echo "❌ Python 'cryptography' not installed. Install: pip3 install cryptography"; exit 1; }
    echo "reference  : (from keyfile $KF) $REF"
    ;;
  *)
    LOG="$1"
    [ -f "$LOG" ] || { echo "❌ server log not found: $LOG"; exit 1; }
    REF=$(grep -o 'server_pub=[a-f0-9]*' "$LOG" | head -1 | cut -d= -f2)
    [ -n "$REF" ] || { echo "❌ no server_pub= line found in $LOG"; exit 1; }
    echo "reference  : (from $LOG) $REF"
    ;;
esac

echo ""
if [ "$BAKED_PUB" = "$REF" ]; then
  echo "✅ MATCH — implant will successfully check-in against this server."
  exit 0
else
  echo "❌ MISMATCH — this implant will fail with 'frame decryption failed'."
  echo ""
  echo "  Fix: regenerate the implant while the server runs with the SAME keyfile"
  echo "  that will be used at deployment time. The .nyx_cfg[54..86] bytes must"
  echo "  equal the running server's server_pub."
  exit 1
fi
