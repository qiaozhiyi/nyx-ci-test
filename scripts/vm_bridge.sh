#!/usr/bin/env bash
# vm_bridge.sh — zero-touch remote exec into the Parallels "Windows 11" VM.
# Channel: prlctl exec (SYSTEM, single-token) + Parallels Shared Folders
# (\\Mac\Home = this repo's parent dirs) for job/result files. No SSH needed.
#
# Usage:
#   ./scripts/vm_bridge.sh exec '<bat commands>'     # sync run, prints output
#   ./scripts/vm_bridge.sh push <mac_file>           # stage file into share dir
set -uo pipefail

BRIDGE="tmp/vm-bridge"
RUNNER_UNC='\\Mac\Home\Desktop\pentest\NY\tmp\vm-bridge\runner.exe'
VM="Windows 11"

cmd_exec() {
    local cmds="$1"
    # CRLF every line (cmd batch parser is picky) — supports multi-line jobs,
    # which matters because %VAR% on a single &-joined line expands at parse
    # time, before the earlier commands have run.
    printf '%s\n' "$cmds" | sed $'s/\r$//; s/$/\r/' > "$BRIDGE/job.bat"
    rm -f "$BRIDGE/out.bin" "$BRIDGE/done.txt"
    prlctl exec "$VM" "$RUNNER_UNC" >/dev/null 2>&1
    local rc=$?
    if [ ! -f "$BRIDGE/done.txt" ]; then
        echo "!! bridge failed: no done.txt (runner did not run?)" >&2
        return 1
    fi
    # cmd output is GBK on zh-CN systems; tolerate decode failures
    iconv -f GBK -t UTF-8 "$BRIDGE/out.bin" 2>/dev/null || cat "$BRIDGE/out.bin"
    echo "== bridge exit: $(cat "$BRIDGE/done.txt") (prlctl rc=$rc)" >&2
}

cmd_push() {
    cp "$1" "$BRIDGE/" && echo "staged: $BRIDGE/$(basename "$1")"
}

case "${1:-}" in
    exec) shift; cmd_exec "$*" ;;
    push) shift; cmd_push "$1" ;;
    *) echo "usage: $0 {exec '<bat>'|push <file>}"; exit 1 ;;
esac
