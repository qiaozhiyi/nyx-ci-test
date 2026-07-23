#!/usr/bin/env bash
# Deploy nyx-server + nyx-agent-dev to a Windows host for capability testing.
#
# This is the topology "all on Windows" (design choice B): the team server runs
# on the Windows box (which is on a public IP), and one or more dev agents run
# alongside it, beaconing to the local server. The macOS/Linux operator drives
# everything over SSH + the server's REST API.
#
# Why this topology: in our environment the Windows host (resolved via the
# `$WIN_HOST` ssh alias, default "win") is on a
# public IP while the operator's macOS sits behind NAT with no inbound reach, so
# the server has to live on the Windows side. The dev agent is the cross-platform
# std build (not the stealth implant-win), good enough to exercise every Command
# variant (shell, fileop, screenshot, connect/socks, ...) on a real Windows host.
#
# Prereqs on the build host (macOS/Linux):
#   brew install mingw-w64                        # or apt install mingw-w64
#   rustup target add x86_64-pc-windows-gnu
#   (this repo's .cargo/config.toml already wires the linker)
#   ssh passwordless to the Windows box as administrator
#     (administrator's pubkey goes in
#      C:\ProgramData\ssh\administrators_authorized_keys with ACL = SYSTEM +
#      Administrators only, set via:
#        icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r \
#          /grant SYSTEM:F /grant BUILTIN\Administrators:F)
#
# Usage:
#   WIN_HOST=win ./scripts/win_deploy.sh build     # cross-compile + scp
#   WIN_HOST=win ./scripts/win_deploy.sh server    # start server on Windows
#   WIN_HOST=win ./scripts/win_deploy.sh agent N   # start agent #N (1,2,3..)
#   WIN_HOST=win ./scripts/win_deploy.sh status    # show sessions
#   WIN_HOST=win ./scripts/win_deploy.sh stop      # stop everything
#
# WIN_HOST defaults to the `win` ssh config alias.
set -euo pipefail

WIN_HOST="${WIN_HOST:-win}"
REMOTE_DIR="C:\\nyx"
TARGET="x86_64-pc-windows-gnu"
BIN_DIR="target/$TARGET/release"

ssh_win() { ssh "$WIN_HOST" "$@"; }

cmd_build() {
    echo "==> cross-compiling nyx-server + nyx-agent-dev -> $TARGET"
    cargo build -p nyx-server -p nyx-agent-dev --release --target "$TARGET"
    echo "==> scp to $WIN_HOST:$REMOTE_DIR"
    ssh_win "mkdir $REMOTE_DIR 2>nul" || true
    scp -q "$BIN_DIR/nyx-server.exe" "$BIN_DIR/nyx-agent-dev.exe" \
        "$WIN_HOST:$(echo "$REMOTE_DIR" | tr '\\' '/')/"
    ssh_win "dir $REMOTE_DIR\\*.exe"
}

# Start (or restart) the team server as a SYSTEM-level scheduled task so it
# survives the SSH session closing. Writes stdout to $REMOTE_DIR\srv.log.
cmd_server() {
    ssh_win 'schtasks /End /TN "nyx_server" 2>nul; schtasks /Delete /TN "nyx_server" /F 2>nul' || true
    ssh_win "schtasks /Create /TN nyx_server /TR \"cmd /c $REMOTE_DIR\\nyx-server.exe > $REMOTE_DIR\\srv.log 2>&1\" /SC ONCE /ST 23:59 /RU SYSTEM /F"
    ssh_win 'schtasks /Run /TN "nyx_server"'
    sleep 4
    echo "==> server log:"
    ssh_win "type $REMOTE_DIR\\srv.log" | sed 's/\x1b\[[0-9;]*m//g' | grep -iE 'listening|pubkey' | head -2
    echo "==> /api/sessions:"
    ssh_win 'curl.exe -s --max-time 8 http://127.0.0.1:8443/api/sessions'
    echo
    echo "==> grab the pubkey for the agents:"
    PUB=$(ssh_win "type $REMOTE_DIR\\srv.log" | grep -oE 'server_pub=[a-f0-9]+' | head -1 | cut -d= -f2)
    echo "    $PUB"
}

# Start agent #N. Needs the server pubkey (auto-read from srv.log) and the agent
# number for a distinct workdir + scheduled-task name.
cmd_agent() {
    local n="${1:?usage: agent N}"
    local pub
    pub=$(ssh_win "type $REMOTE_DIR\\srv.log" | grep -oE 'server_pub=[a-f0-9]+' | head -1 | cut -d= -f2)
    [ -z "$pub" ] && { echo "no pubkey in srv.log — start the server first"; exit 1; }
    echo "==> pubkey: ${pub:0:16}..."
    # base64-transport the .bat to dodge cmd quoting hell inside schtasks.
    local bat
    bat=$(printf 'set NYX_SERVER=http://127.0.0.1:8443\r\nset NYX_SERVER_PUB=%s\r\nset NYX_SLEEP=2\r\nset NYX_WORKDIR=%s\\wd%s\r\n%s\\nyx-agent-dev.exe\r\n' \
        "$pub" "$REMOTE_DIR" "$n" "$REMOTE_DIR" | base64)
    ssh_win "powershell -Command \"[System.IO.File]::WriteAllBytes('$REMOTE_DIR\\agent$n.bat', [System.Convert]::FromBase64String('$bat'))\""
    ssh_win "schtasks /Create /TN nyx_agent$n /TR \"$REMOTE_DIR\\agent$n.bat\" /SC ONCE /ST 23:59 /RU SYSTEM /F" >/dev/null
    ssh_win "schtasks /Run /TN nyx_agent$n"
    echo "==> agent$n started"
}

cmd_status() {
    echo "==> beacons:"
    ssh_win 'curl.exe -s --max-time 8 http://127.0.0.1:8443/api/sessions' \
        | python3 -c "import sys,json;[print(' ',s) for s in json.load(sys.stdin)]" 2>/dev/null \
        || ssh_win 'curl.exe -s http://127.0.0.1:8443/api/sessions'
}

cmd_stop() {
    ssh_win 'schtasks /End /TN nyx_server 2>nul; schtasks /End /TN nyx_agent1 2>nul; schtasks /End /TN nyx_agent2 2>nul; taskkill /F /IM nyx-server.exe /T 2>nul; taskkill /F /IM nyx-agent-dev.exe /T 2>nul' || true
    echo "stopped"
}

case "${1:-}" in
    build)  cmd_build ;;
    server) cmd_server ;;
    agent)  cmd_agent "${2:-1}" ;;
    status) cmd_status ;;
    stop)   cmd_stop ;;
    *) echo "usage: $0 {build|server|agent N|status|stop}"; exit 1 ;;
esac
