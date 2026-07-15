#!/usr/bin/env bash
# keyfile_check.sh — authoritative keyfile-mode bring-up.
#
# ROOT CAUSE THIS SCRIPT ELIMINATES (see docs/diagnostic 2026-07-14):
#   `frame decryption failed` on server / `400 Bad Request` (or EOF) on agent
#   is ALWAYS caused by a mismatched server_pub. derive_session_key() binds
#   server_pub into BOTH the HKDF-Extract salt AND the expand info, plus the
#   frame AAD, so any 1-bit mismatch fails the AEAD tag deterministically.
#
#   The dev-agent has NO keyfile path — it reads server_pub ONLY from the
#   NYX_SERVER_PUB env var (crates/agent-dev/src/main.rs:12). The single most
#   common mistake is launching the server with a keyfile and then handing the
#   agent a stale NYX_SERVER_PUB from a previous (ephemeral or different-keyfile)
#   server run. This script makes that mistake impossible: it always re-extracts
#   the live pubkey from the current server's log before starting the agent.
#
# Usage:
#   ./scripts/keyfile_check.sh                      # uses ~/.nyx/server.key, port 18455
#   KEYFILE=/path/k.key PORT=19455 ./scripts/keyfile_check.sh
#   SKIP_AGENT=1 ./scripts/keyfile_check.sh         # only mint keyfile + start server
#
# Exit 0 = agent registered; 1 = any failure.

set -uo pipefail
export MSYS2_ENV_CONV_EXCL='*'   # don't let MSYS2 mangle beacon URIs on Windows

PORT="${PORT:-18455}"
KEYFILE="${KEYFILE:-$HOME/.nyx/server.key}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SRV="$ROOT/target/debug/nyx-server"
AGT="$ROOT/target/debug/nyx-agent-dev"

[ -x "$SRV" ] && [ -x "$AGT" ] || cargo build -p nyx-server -p nyx-agent-dev

SLOG=$(mktemp -t nyx_srv.XXXX)
ALOG=$(mktemp -t nyx_agt.XXXX)
WD=$(mktemp -d -t nyx_wd.XXXX)
SPID=""; APID=""
cleanup() {
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null
  [ -n "$APID" ] && kill "$APID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WD"; rm -f "$SLOG" "$ALOG"
}
trap cleanup EXIT

mkdir -p "$(dirname "$KEYFILE")"

echo "=== keyfile: $KEYFILE ==="
if [ -f "$KEYFILE" ]; then
  SZ=$(wc -c < "$KEYFILE" | tr -d ' ')
  if [ "$SZ" != "32" ]; then
    echo "❌ keyfile exists but is $SZ bytes (expected 32). Aborting — this is a corruption/DRY-RUN risk."
    exit 1
  fi
  echo "    (existing keyfile, ${SZ}B — server_pub will be STABLE across restarts)"
else
  echo "    (no keyfile — server will create one on first boot; server_pub will then be STABLE)"
fi

echo "=== starting server on 127.0.0.1:$PORT with NYX_KEYFILE ==="
NYX_KEYFILE="$KEYFILE" RUST_LOG=info NYX_BIND=127.0.0.1:$PORT "$SRV" > "$SLOG" 2>&1 &
SPID=$!

# Wait for HTTP up.
up=0
for i in $(seq 1 40); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/api/sessions" && { up=1; break; }
  sleep 0.25
done
[ "$up" = 1 ] || { echo "❌ server failed to start:"; tail -15 "$SLOG"; exit 1; }

# CRITICAL: extract server_pub from THIS run's log.
PUB=""
for i in $(seq 1 40); do
  PUB=$(grep -o 'server_pub=[a-f0-9]*' "$SLOG" 2>/dev/null | head -1 | cut -d= -f2)
  [ -n "$PUB" ] && break
  sleep 0.25
done
[ -n "$PUB" ] || { echo "❌ server started but never logged server_pub:"; tail -15 "$SLOG"; exit 1; }

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  LIVE server_pub = $PUB"
echo "  (server PID $SPID, log $SLOG)"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  For dev-agent  : NYX_SERVER_PUB=\$PUB (this script does it for you)"
echo "  For PIC implant: bake this pub into .nyx_cfg at implant-gen time,"
echo "                   and verify with scripts/verify_implant_pub.sh"
echo ""

# Save pub to a file the operator can source / re-use without re-scraping logs.
PUBFILE="$KEYFILE.pub"
echo "$PUB" > "$PUBFILE"
echo "  (pubkey also written to $PUBFILE for downstream tooling)"
echo ""

[ "${SKIP_AGENT:-0}" = "1" ] && {
  echo "SKIP_AGENT=1 — server left running on PID $SPID. Kill with: kill $SPID"
  # Detach from cleanup trap so the server survives this script exiting.
  trap - EXIT
  exit 0
}

echo "=== starting dev-agent with live server_pub ==="
NYX_SERVER=http://127.0.0.1:$PORT NYX_SERVER_PUB=$PUB NYX_SLEEP=1 \
  NYX_WORKDIR="$WD" NYX_BEACON_URI=/beacon "$AGT" > "$ALOG" 2>&1 &
APID=$!

SID=""
for i in $(seq 1 40); do
  SID=$(curl -sf "http://127.0.0.1:$PORT/api/sessions" 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[-1]['id'] if d else '')" 2>/dev/null)
  [ -n "$SID" ] && break
  sleep 0.25
done

if [ -n "$SID" ]; then
  echo "✅ check-in SUCCESS — SID=${SID:0:12}"
  echo "   (server_pub was correctly live-extracted; keyfile mode works.)"
  exit 0
else
  echo "❌ check-in FAILED even with live server_pub — this is a REAL bug, not the known stale-pub issue."
  echo "   --- agent log (last 8) ---"; tail -8 "$ALOG"
  echo "   --- server log (last 8) ---"; tail -8 "$SLOG"
  exit 1
fi
