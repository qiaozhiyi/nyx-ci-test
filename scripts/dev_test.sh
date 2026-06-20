#!/usr/bin/env bash
# Nyx 端到端测试脚本：起 server + dev agent + TUI，自动串联。
#
# 用法：
#   ./scripts/dev_test.sh          # 全自动（三终端）
#   ./scripts/dev_test.sh server   # 只起 server
#   ./scripts/dev_test.sh agent    # 只起 agent（需先起 server）
#   ./scripts/dev_test.sh tui      # 只起 TUI
#
# 前提：cargo build 已完成（脚本会自动 build）。

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/target/debug"
SERVER="$BUILD_DIR/nyx-server"
AGENT="$BUILD_DIR/nyx-agent-dev"
TUI="$BUILD_DIR/nyx-cli"
PUBFILE="/tmp/nyx_server_pub.$$"

build() {
    echo "==> Building..."
    cargo build -p nyx-server -p nyx-agent-dev -p nyx-cli 2>&1 | tail -1
}

start_server() {
    echo "==> Starting team server (terminal 1)..."
    echo "    Log will show: bake server_pub=<hex>"
    echo ""
    # 用 script 捕获 server 输出，grep 出 pubkey 存文件
    # server 持续运行，Ctrl+C 停止
    RUST_LOG=info "$SERVER" 2>&1 | tee >(grep -o 'server_pub=[a-f0-9]*' | head -1 | cut -d= -f2 > "$PUBFILE")
}

start_agent() {
    # 等 server 输出 pubkey
    for i in $(seq 1 30); do
        if [ -s "$PUBFILE" ]; then break; fi
        sleep 0.5
    done
    if [ ! -s "$PUBFILE" ]; then
        echo "ERROR: server pubkey not found. Is the server running?"
        echo "       Start server first: ./scripts/dev_test.sh server"
        echo "       Then copy the server_pub=<hex> from its log."
        exit 1
    fi
    PUB=$(cat "$PUBFILE")
    echo "==> Starting dev agent with server_pub=${PUB:0:16}..."
    NYX_SERVER_PUB="$PUB" NYX_SLEEP=3 NYX_WORKDIR=/tmp/nyx-agent-workdir "$AGENT"
}

start_tui() {
    echo "==> Starting TUI..."
    echo "    Commands to try:"
    echo "      /sessions        — list beacons"
    echo "      /use <id>        — select a beacon"
    echo "      whoami           — run shell (just type it!)"
    echo "      /ls              — list files (parsed table)"
    echo "      /ps              — list processes"
    echo "      /help            — all commands"
    echo "      Ctrl+%           — split pane left/right"
    echo '      Ctrl+"           — split pane up/down'
    echo "      Ctrl+1..6        — switch pane view"
    echo "      Ctrl+h/j/k/f     — move focus"
    echo "      Ctrl+x           — close pane"
    echo "      Ctrl+C           — quit"
    echo ""
    "$TUI" --server http://127.0.0.1:8443
}

case "${1:-all}" in
    build) build ;;
    server) build; start_server ;;
    agent) build; start_agent ;;
    tui) build; start_tui ;;
    all)
        echo "Ny端到端测试需要 3 个终端。请分别在 3 个终端运行："
        echo ""
        echo "  终端1: ./scripts/dev_test.sh server"
        echo "  终端2: ./scripts/dev_test.sh agent   (等终端1打印 pubkey 后)"
        echo "  终端3: ./scripts/dev_test.sh tui"
        echo ""
        echo "或者手动按下面步骤操作。"
        echo ""
        echo "========================================"
        echo "手动步骤："
        echo "========================================"
        echo ""
        echo "1. 起 server（终端1）："
        echo "   cargo run -p nyx-server"
        echo "   → 看日志里的 server_pub=<hex>，复制那串 hex"
        echo ""
        echo "2. 起 agent（终端2）："
        echo "   NYX_SERVER_PUB=<粘贴hex> NYX_SLEEP=3 \\"
        echo "     NYX_WORKDIR=/tmp/nyx-agent-workdir \\"
        echo "     cargo run -p nyx-agent-dev"
        echo ""
        echo "3. 开 TUI（终端3）："
        echo "   cargo run -p nyx-cli"
        echo ""
        echo "4. TUI 里操作："
        echo "   /sessions   → 看到 1 个 beacon"
        echo "   /use <id>   → 选中它"
        echo "   whoami      → 直接打字就是 shell（看本机用户名）"
        echo "   /ls /tmp    → 文件列表弹面板"
        echo "   /ps         → 进程列表"
        echo "   /mkdir test → 建目录（agent 的 workdir 里）"
        echo "   Ctrl+%      → 左右分屏"
        echo "   Ctrl+2      → 切到 session 列表视图"
        echo "   Ctrl+h      → 焦点左移"
        ;;
    *)
        echo "Usage: $0 [build|server|agent|tui|all]"
        exit 1
        ;;
esac
