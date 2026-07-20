#!/usr/bin/env bash
# Disconnect-resilient full selftest run on the Windows server.
#
# Stability design (the whole point of this script):
#   * every ssh/scp call gets keepalive + ConnectTimeout options AND an
#     exponential-backoff retry wrapper — a dropped connection retries
#     instead of aborting the run;
#   * the test suite itself runs as a SYSTEM scheduled task ON the server
#     (proven pattern from win_deploy.sh), so even a total client-side
#     outage cannot kill the run — results land in C:\nyx files;
#   * the client only polls for a DONE marker and fetches result files,
#     so `run` is fully resumable: re-run it after a drop and it picks up
#     polling where it left off.
#
# Usage:
#   WIN_HOST=win ./scripts/win_remote_run.sh build   # cross-compile selftest DLL + scp
#   WIN_HOST=win ./scripts/win_remote_run.sh run     # deploy runner, start task, poll, fetch
#   WIN_HOST=win ./scripts/win_remote_run.sh fetch   # only fetch result files
#   WIN_HOST=win ./scripts/win_remote_run.sh all     # build + run
set -uo pipefail

WIN_HOST="${WIN_HOST:-win}"
REMOTE_DIR="C:\\nyx"
REMOTE_DIR_UNIX="C:/nyx"
TARGET="x86_64-pc-windows-gnu"
DLL="crates/implant-win/target/$TARGET/release/nyx_implant_win.dll"
TASK="nyx_selftest"
POLL_BUDGET_S=1800     # worst case ~50 exports * 20s timeout
PER_EXPORT_TIMEOUT=20

SSH_OPTS=(-o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3
          -o TCPKeepAlive=yes -o BatchMode=yes)

# retry <attempts> <cmd...> — exponential backoff 2,4,8,16,30,30,...
retry() {
    local max="$1"; shift
    local n=1 delay=2
    while true; do
        if "$@"; then return 0; fi
        if (( n >= max )); then
            echo "!! giving up after $n attempts: $*" >&2
            return 1
        fi
        echo "   (attempt $n failed, retrying in ${delay}s)" >&2
        sleep "$delay"
        (( n++, delay *= 2, delay > 30 && delay = 30 ))
    done
}

ssh_win() { ssh "${SSH_OPTS[@]}" "$WIN_HOST" "$@"; }
scp_win() { scp "${SSH_OPTS[@]}" "$@"; }

cmd_build() {
    echo "==> cross-compiling nyx-implant-win (selftest feature) -> $TARGET"
    (cd crates/implant-win && \
        RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
        cargo +nightly build --release --target "$TARGET" \
            -Zbuild-std=core,compiler_builtins,alloc --features selftest) || return 1
    [ -f "$DLL" ] || { echo "!! DLL missing at $DLL"; return 1; }
    echo "==> extracting export list (keeps server-side runner in sync)"
    x86_64-w64-mingw32-objdump -p "$DLL" | grep -oE 'nyx_selftest_[a-z_0-9]+' | sort -u > /tmp/nyx_exports.txt
    echo "    $(wc -l < /tmp/nyx_exports.txt | tr -d ' ') exports"
    echo "==> uploading DLL + runner scripts"
    retry 5 ssh_win "mkdir $REMOTE_DIR 2>nul & exit 0"
    retry 5 scp_win "$DLL" scripts/win_selftest_all.ps1 /tmp/nyx_exports.txt "$WIN_HOST:$REMOTE_DIR_UNIX/"
    retry 5 ssh_win "rename $REMOTE_DIR\\nyx_exports.txt exports.txt"
    echo "==> build + upload done"
}

# Write the server-side wrapper (runs the suite, writes DONE marker) via
# base64 to dodge cmd/ssh quoting hell.
deploy_runner() {
    local ps1 b64
    ps1='$ErrorActionPreference = '"'"'SilentlyContinue'"'"'
Remove-Item C:\nyx\selftest_done.txt -Force -EA SilentlyContinue
$out = & powershell -ExecutionPolicy Bypass -File C:\nyx\win_selftest_all.ps1 -Validate -Dll C:\nyx\nyx_implant_win.dll -Timeout '"$PER_EXPORT_TIMEOUT"' 2>&1
$out | Out-File -Encoding UTF8 C:\nyx\selftest_run.log
"exit=$LASTEXITCODE" | Out-File -Encoding ASCII C:\nyx\selftest_done.txt'
    b64=$(printf '%s' "$ps1" | base64)
    retry 5 ssh_win "powershell -Command \"[System.IO.File]::WriteAllBytes('$REMOTE_DIR\\runner_selftest.ps1', [System.Convert]::FromBase64String('$b64'))\""
}

cmd_run() {
    echo "==> deploying runner + resetting state"
    deploy_runner
    retry 5 ssh_win "del $REMOTE_DIR\\selftest_done.txt 2>nul & schtasks /End /TN $TASK 2>nul & schtasks /Delete /TN $TASK /F 2>nul & exit 0"

    echo "==> starting scheduled task '$TASK' (SYSTEM, survives SSH drops)"
    retry 5 ssh_win "schtasks /Create /TN $TASK /TR \"powershell -ExecutionPolicy Bypass -File $REMOTE_DIR\\runner_selftest.ps1\" /SC ONCE /ST 23:59 /RU SYSTEM /F"
    retry 5 ssh_win "schtasks /Run /TN $TASK"

    echo "==> polling for DONE marker (budget ${POLL_BUDGET_S}s, drop-tolerant)"
    local deadline=$((SECONDS + POLL_BUDGET_S)) done_out=""
    while (( SECONDS < deadline )); do
        done_out=$(ssh_win "type $REMOTE_DIR\\selftest_done.txt 2>nul" 2>/dev/null)
        if [ -n "$done_out" ]; then break; fi
        sleep 8
    done
    if [ -z "$done_out" ]; then
        echo "!! no DONE marker within budget — task may still be running server-side."
        echo "   re-run '$0 run' later to resume polling, or '$0 fetch' if it finished."
        return 1
    fi
    echo "==> run finished: $done_out"
    cmd_fetch
}

cmd_fetch() {
    local ts dest
    ts=$(date +%Y%m%d_%H%M%S)
    dest=".agents/orchestrator/win_run_$ts"
    mkdir -p "$dest"
    echo "==> fetching results -> $dest"
    retry 5 scp_win "$WIN_HOST:$REMOTE_DIR_UNIX/selftest_results.csv" "$WIN_HOST:$REMOTE_DIR_UNIX/selftest_run.log" "$dest/" || return 1
    retry 3 scp_win "$WIN_HOST:$REMOTE_DIR_UNIX/trex_report.txt" "$dest/" 2>/dev/null
    rm -f .agents/orchestrator/win_run_latest
    ln -s "win_run_$ts" .agents/orchestrator/win_run_latest

    echo "==> per-export results:"
    cat "$dest/selftest_results.csv"
    echo "==> validation summary:"
    grep -E 'MISMATCH|VALIDATION|PASS:|FAIL:|SUMMARY' "$dest/selftest_run.log" || true
    echo "==> done. Full log: $dest/selftest_run.log"
}

case "${1:-}" in
    build) cmd_build ;;
    run)   cmd_run ;;
    fetch) cmd_fetch ;;
    all)   cmd_build && cmd_run ;;
    *) echo "usage: WIN_HOST=win $0 {build|run|fetch|all}"; exit 1 ;;
esac
