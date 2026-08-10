#!/usr/bin/env bash
# Nyx 开发调试拉起脚本：team server + dev agent + Web GUI，手动 3 终端。
#
# 用法：
#   ./scripts/dev_test.sh          # 打印三终端操作指引
#   ./scripts/dev_test.sh server   # 只起 server（终端 1）
#   ./scripts/dev_test.sh agent    # 只起 agent（需先起 server；终端 2）
#   ./scripts/dev_test.sh gui      # 只起 GUI（需先起 server；终端 3）
#   ./scripts/dev_test.sh build    # 只构建 server + agent
#
# 架构说明：旧版 nyx-cli TUI 已归档移除，操作端现为 crates/client-ui-web
# （Tauri 2 + React，见 README「快速上手」第 4 节）。RBAC 落地后 server
# 需要 operator 凭证才能下任务（空注册表 = 匿名 Viewer，写接口 403），
# 本脚本默认注入 NYX_BOOTSTRAP_OPERATOR=dev:dev 并将 NYX_OPERATORS_FILE
# 指向 /tmp 下的独立注册表（不读 ~/.nyx），两者均可用同名环境变量覆盖。
# GUI 连接页的 Bearer 填 name:secret（默认 dev:dev）。
#
# 前提：cargo build 已完成（脚本会自动 build）；GUI 首次运行会自动 npm install。

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/target/debug"
SERVER="$BUILD_DIR/nyx-server"
AGENT="$BUILD_DIR/nyx-agent-dev"
GUI_DIR="$ROOT/crates/client-ui-web"
PUBFILE="/tmp/nyx_server_pub.$$"
OP="${NYX_BOOTSTRAP_OPERATOR:-dev:dev}"
OPSFILE="${NYX_OPERATORS_FILE:-/tmp/nyx_dev_operators.json}"

build() {
    echo "==> Building server + agent..."
    cargo build -p nyx-server -p nyx-agent-dev 2>&1 | tail -1
}

start_server() {
    echo "==> Starting team server (terminal 1)..."
    echo "    Bind: 127.0.0.1:8443 (NYX_BIND 可覆盖)"
    echo "    Operator bearer: $OP  (operators file: $OPSFILE)"
    echo "    Log will show: bake server_pub=<hex>"
    echo ""
    # 独立空注册表（不存在则初始化为空 JSON 数组），避免读 ~/.nyx。
    [ -f "$OPSFILE" ] || echo '[]' > "$OPSFILE"
    # 用 script 捕获 server 输出，grep 出 pubkey 存文件
    # server 持续运行，Ctrl+C 停止
    NYX_BOOTSTRAP_OPERATOR="$OP" NYX_OPERATORS_FILE="$OPSFILE" \
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
    NYX_SERVER=http://127.0.0.1:8443 NYX_SERVER_PUB="$PUB" NYX_SLEEP=3 \
      NYX_WORKDIR=/tmp/nyx-agent-workdir NYX_BEACON_URI=/beacon "$AGENT"
}

start_gui() {
    echo "==> Starting operator GUI (crates/client-ui-web)..."
    echo "    连接页 Server 填 http://127.0.0.1:8443，Bearer 填 $OP"
    echo "    纯前端开发（不起 Tauri 外壳）: GUI_MODE=web ./scripts/dev_test.sh gui"
    echo ""
    cd "$GUI_DIR"
    [ -d node_modules ] || npm install
    if [ "${GUI_MODE:-tauri}" = "web" ]; then
        npm run dev
    else
        npm run tauri dev
    fi
}

case "${1:-all}" in
    build) build ;;
    server) build; start_server ;;
    agent) build; start_agent ;;
    gui) start_gui ;;
    all)
        echo "Nyx 开发调试需要 3 个终端。请分别在 3 个终端运行："
        echo ""
        echo "  终端1: ./scripts/dev_test.sh server"
        echo "  终端2: ./scripts/dev_test.sh agent   (等终端1打印 pubkey 后)"
        echo "  终端3: ./scripts/dev_test.sh gui"
        echo ""
        echo "或者手动按下面步骤操作。"
        echo ""
        echo "========================================"
        echo "手动步骤："
        echo "========================================"
        echo ""
        echo "1. 起 server（终端1）："
        echo "   NYX_BOOTSTRAP_OPERATOR=dev:dev \\"
        echo "     NYX_OPERATORS_FILE=/tmp/nyx_dev_operators.json \\"
        echo "     cargo run -p nyx-server"
        echo "   → 看日志里的 server_pub=<hex>，复制那串 hex"
        echo ""
        echo "2. 起 agent（终端2）："
        echo "   NYX_SERVER=http://127.0.0.1:8443 NYX_SERVER_PUB=<粘贴hex> \\"
        echo "     NYX_SLEEP=3 NYX_WORKDIR=/tmp/nyx-agent-workdir \\"
        echo "     NYX_BEACON_URI=/beacon cargo run -p nyx-agent-dev"
        echo ""
        echo "3. 开 GUI（终端3）："
        echo "   cd crates/client-ui-web"
        echo "   npm install          # 首次"
        echo "   npm run tauri dev    # 或纯前端: npm run dev"
        echo ""
        echo "4. GUI 里操作："
        echo "   连接页 Server 填 http://127.0.0.1:8443，Bearer 填 dev:dev"
        echo "   → session 列表应出现 1 个 beacon（agent-dev 每 3s 回连）"
        echo "   → 选中后可下发 shell/ls/ps/env 等任务，2s 轮询出结果"
        ;;
    *)
        echo "Usage: $0 [build|server|agent|gui|all]"
        exit 1
        ;;
esac
