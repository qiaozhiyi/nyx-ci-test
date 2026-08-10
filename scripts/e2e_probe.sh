#!/usr/bin/env bash
# Self-contained end-to-end probe for the monitoring/collection commands.
#
# Unlike dev_test.sh (which is a manual 3-terminal bring-up for interactive
# TUI testing), this script is fully automatic: it starts a throwaway team
# server + dev agent on an ephemeral port, issues one of each monitoring
# command over the REST task API, and drains the results. Use it as a quick
# regression check that the operator→task→implant→result loop is intact and
# that screenshot/env/driveinfo/net/clipboard all still execute end-to-end.
#
# RBAC: the server rejects unauthenticated writes (task POST -> 401/403), so
# this script bootstraps a throwaway admin operator via NYX_BOOTSTRAP_OPERATOR
# (override with the env var of the same name) and sends `Authorization:
# Bearer name:secret` on every REST call. NYX_OPERATORS_FILE is pointed at a
# script-created temp file so a real ~/.nyx/operators.json can never leak in.
#
# Usage:   ./scripts/e2e_probe.sh
# Exits:   0 if all commands returned a result, 1 otherwise.
set -uo pipefail
# Prevent MSYS2 from converting env-var values that look like Unix paths
# (e.g. /beacon -> C:/Program Files/Git/beacon) when launching Windows binaries.
export MSYS2_ENV_CONV_EXCL='*'

PORT="${PORT:-18455}"
OP="${NYX_BOOTSTRAP_OPERATOR:-probe:e2e}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SRV="$ROOT/target/debug/nyx-server"
AGT="$ROOT/target/debug/nyx-agent-dev"
SLOG=$(mktemp -t nyx_srv.XXXXXX)
ALOG=$(mktemp -t nyx_agt.XXXXXX)
WD=$(mktemp -d -t nyx_wd.XXXXXX)
OPSFILE=$(mktemp -t nyx_ops.XXXXXX)
echo '[]' > "$OPSFILE"
APID=""
SPID=""
trap 'kill ${SPID:-} ${APID:-} 2>/dev/null; wait 2>/dev/null; rm -rf "$WD" "$SLOG" "$ALOG" "$OPSFILE"' EXIT

# Build if the binaries are missing.
[ -x "$SRV" ] && [ -x "$AGT" ] || cargo build -p nyx-server -p nyx-agent-dev

# --- server ---
RUST_LOG=info NYX_BIND=127.0.0.1:$PORT \
  NYX_BOOTSTRAP_OPERATOR="$OP" NYX_OPERATORS_FILE="$OPSFILE" \
  "$SRV" > "$SLOG" 2>&1 &
SPID=$!
AUTH="Authorization: Bearer $OP"
for i in $(seq 1 40); do curl -sf -o /dev/null -H "$AUTH" "http://127.0.0.1:$PORT/api/sessions" && break; sleep 0.25; done
PUB=$(grep -o 'server_pub=[a-f0-9]*' "$SLOG" | head -1 | cut -d= -f2)
[ -z "$PUB" ] && { echo "FAIL: server didn't start"; cat "$SLOG"; exit 1; }

# --- agent ---
NYX_SERVER=http://127.0.0.1:$PORT NYX_SERVER_PUB=$PUB NYX_SLEEP=1 \
  NYX_WORKDIR="$WD" NYX_BEACON_URI=/beacon "$AGT" > "$ALOG" 2>&1 &
APID=$!
SID=""
for i in $(seq 1 40); do
  # Sessions persist across server restarts (SQLite restore, marked stale=true
  # until a live check-in). Pick the youngest NON-stale session — `d[-1]` would
  # happily hand us a dead restored one and every task would vanish.
  SID=$(curl -sf -H "$AUTH" "http://127.0.0.1:$PORT/api/sessions" 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);live=[s for s in d if not s.get('stale')];live.sort(key=lambda s:s.get('age_secs',1<<30));print(live[0]['id'] if live else '')" 2>/dev/null)
  [ -n "$SID" ] && break; sleep 0.25
done
[ -z "$SID" ] && { echo "FAIL: agent didn't register"; cat "$ALOG"; exit 1; }
echo "agent registered, SID=${SID:0:12}"

# --- issue one of each monitoring command ---
B="http://127.0.0.1:$PORT/api/task"
declare -a NAMES=(screenshot env driveinfo net clipboard)
i=0
for body in \
  '{"type":"screenshot","monitor":0}' \
  '{"type":"env","name":"USER"}' \
  '{"type":"driveinfo"}' \
  '{"type":"net","query":""}' \
  '{"type":"clipboard"}'; do
  tid=$((i+1))
  if curl -sf -X POST $B -H "$AUTH" -H 'Content-Type: application/json' \
        -d "{\"session\":\"$SID\",\"command\":$body}" >/dev/null; then
    echo "  tasked $tid (${NAMES[$i]})"
  else
    echo "  task $tid (${NAMES[$i]}) POST FAILED"
  fi
  i=$((i+1))
done

# allow 2 beacon cycles (sleep=1) for execute + return
sleep 6
echo "--- results ---"
curl -sf -H "$AUTH" "http://127.0.0.1:$PORT/api/results?session=$SID" | python3 -c "
import sys,json
names={1:'screenshot',2:'env',3:'driveinfo',4:'net',5:'clipboard'}
try: rs=json.load(sys.stdin)
except Exception as e: print('  no results:',e); sys.exit(1)
for r in sorted(rs,key=lambda x:x['task_id']):
    n=names.get(r['task_id'],'?'); d=r.get('data_hex') or ''
    extra=f', {len(bytes.fromhex(d))}B raw' if d else ''
    print(f\"  [{n:10}] {r['kind']:6}: {r['text'][:55]}{extra}\")
got={r['task_id'] for r in rs}
miss=[names[k] for k in names if k not in got]
if miss: print(f'  MISSING: {miss}'); sys.exit(1)
print('  ALL 5 RETURNED')
"
