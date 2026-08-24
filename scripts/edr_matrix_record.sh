#!/usr/bin/env bash
# edr_matrix_record.sh — EDR 量化矩阵记录器（WP-B）。
# 一次"技术 × EDR"实测追加一行 CSV，schema 见 docs/testing/edr-quant-matrix.md §1.1。
#
# 设计：与 win_remote_run.sh 同款的 keepalive + 重试 ssh 通道；告警计数经
# base64 部署的 collect_alerts.ps1 在目标机上采集（Get-MpThreatDetection +
# Get-MpThreat + AMProductVersion），绕开 ssh/cmd 多层引号问题。
#
# 用法见本文件末尾注释块。
set -uo pipefail

WIN_HOST="${WIN_HOST:-win}"
REMOTE_DIR="C:\\nyx"
CSV="${EDR_MATRIX_CSV:-.agents/orchestrator/edr_matrix.csv}"
COLLECT_PS1="collect_alerts.ps1"
SETTLE_S=5   # 触发后等待 Defender 遥测落库的秒数

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

# Deploy the alert-collector ps1 via base64 (dodges cmd/ssh quoting hell),
# same pattern as win_remote_run.sh deploy_runner().
deploy_collector() {
    local ps1 b64
    ps1='$ErrorActionPreference = '"'"'SilentlyContinue'"'"'
$d = @(Get-MpThreatDetection).Count
$t = @(Get-MpThreat).Count
$v = (Get-MpComputerStatus).AMProductVersion
"$d,$t,$v"'
    b64=$(printf '%s' "$ps1" | base64)
    retry 5 ssh_win "powershell -Command \"[System.IO.File]::WriteAllBytes('$REMOTE_DIR\\$COLLECT_PS1', [System.Convert]::FromBase64String('$b64'))\""
}

# Echoes "detections,threats,product_version" from the target host.
collect() {
    ssh_win "powershell -ExecutionPolicy Bypass -File $REMOTE_DIR\\$COLLECT_PS1" | tr -d '\r' | tail -1
}

# Quote a CSV field if it contains , or "
csvq() {
    local f="$1"
    if [[ "$f" == *,* || "$f" == *\"* ]]; then
        printf '"%s"' "${f//\"/\"\"}"
    else
        printf '%s' "$f"
    fi
}

cmd_record() {
    local technique="" edr_name="" edr_version="" context="" export="" alerts=""
    local samples="" successes="" env_limit="" evidence="" no_trigger=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --technique)   technique="$2"; shift 2 ;;
            --edr)         edr_name="$2"; shift 2 ;;
            --edr-version) edr_version="$2"; shift 2 ;;
            --context)     context="$2"; shift 2 ;;
            --export)      export="$2"; shift 2 ;;
            --no-trigger)  no_trigger=1; shift ;;
            --alerts)      alerts="$2"; shift 2 ;;
            --samples)     samples="$2"; shift 2 ;;
            --successes)   successes="$2"; shift 2 ;;
            --env-limit)   env_limit="$2"; shift 2 ;;
            --evidence)    evidence="$2"; shift 2 ;;
            *) echo "!! unknown flag: $1" >&2; return 1 ;;
        esac
    done
    [ -n "$technique" ] || { echo "!! --technique required" >&2; return 1; }
    [ -n "$edr_name" ]  || { echo "!! --edr required" >&2; return 1; }
    [ -n "$context" ]   || { echo "!! --context required (dll-sideload/exe/other)" >&2; return 1; }
    [ -n "$env_limit" ] || { echo "!! --env-limit required (无/Prism 仿真降级/无 CET/EDR 未装/Defender 已关闭/环境阻塞-其他) — 强制字段，见 edr-quant-matrix.md §2" >&2; return 1; }
    if [ "$no_trigger" = 1 ] && [ -z "$alerts" ]; then
        echo "!! --no-trigger 模式必须显式给 --alerts N（人工观察回填）" >&2; return 1
    fi

    echo "==> deploying alert collector"
    deploy_collector || return 1

    local before after b_d b_t b_v a_d a_t a_v
    if [ -n "$export" ]; then
        before=$(collect) || return 1
        b_d="${before%%,*}"; rest="${before#*,}"; b_t="${rest%%,*}"; b_v="${rest#*,}"
        echo "==> baseline: detections=$b_d threats=$b_t defender=$b_v"
        echo "==> triggering export: $export"
        retry 3 ssh_win "rundll32 $REMOTE_DIR\\nyx_implant_win.dll,$export"
        local rc=$?
        echo "    export exit code: $rc"
        sleep "$SETTLE_S"
        after=$(collect) || return 1
        a_d="${after%%,*}"; rest="${after#*,}"; a_t="${rest%%,*}"; a_v="${rest#*,}"
        echo "==> after:    detections=$a_d threats=$a_t"
        if [ -z "$alerts" ]; then
            alerts=$(( (a_d - b_d) + (a_t - b_t) ))
            if (( alerts < 0 )); then
                echo "!! negative alert delta ($alerts) — 告警历史疑似在实测期间被清理，如实记录，请人工复核" >&2
            fi
        fi
        [ -z "$edr_version" ] && edr_version="$a_v"
    else
        # no-trigger: 仍采一次版本号，告警数用 --alerts 回填值
        after=$(collect) || return 1
        a_v="${after##*,}"
        [ -z "$edr_version" ] && edr_version="$a_v"
    fi

    local rate=""
    if [ -n "$samples" ] && [ -n "$successes" ] && [ "$samples" -gt 0 ] 2>/dev/null; then
        rate=$(awk "BEGIN{printf \"%.1f%%\", $successes * 100.0 / $samples}")
    fi

    mkdir -p "$(dirname "$CSV")"
    if [ ! -f "$CSV" ]; then
        echo "date,technique,edr_name,edr_version,delivery_context,samples,successes,success_rate,alerts,env_limit,evidence" > "$CSV"
    fi
    local row="" f
    for f in "$(date +%F)" "$technique" "$edr_name" "$edr_version" "$context" \
             "$samples" "$successes" "$rate" "$alerts" "$env_limit" "$evidence"; do
        row+="$(csvq "$f"),"
    done
    echo "${row%,}" >> "$CSV"
    echo "==> appended to $CSV:"
    tail -1 "$CSV"
}

case "${1:-}" in
    record) shift; cmd_record "$@" ;;
    *) echo "usage: WIN_HOST=win $0 record [flags] — 见脚本文末注释"; exit 1 ;;
esac

# ============================================================================
# 用法（WP-B：docs/testing/edr-quant-matrix.md §6 同源）
#
# 前置：目标机已有 C:\nyx\nyx_implant_win.dll（win_remote_run.sh build 上传），
#       ssh 密钥认证已配好（vm_bootstrap.ps1），Defender 实时保护状态符合
#       本次实测设定（ON 或第二遍 OFF）。
#
# 1) selftest 导出驱动 —— 自动采集告警差值（推荐）：
#      WIN_HOST=win ./scripts/edr_matrix_record.sh record \
#        --technique fls_callback --edr "Microsoft Defender" \
#        --context exe --export nyx_selftest_inject_fls \
#        --samples 1 --successes 1 --env-limit "Prism 仿真降级" \
#        --evidence .agents/orchestrator/win_run_latest/selftest_run.log
#
# 2) operator 手动驱动（真 C2 会话里跑 inject/sleep 等命令）—— 人工观察
#    Get-MpThreatDetection 后回填告警数：
#      WIN_HOST=win ./scripts/edr_matrix_record.sh record \
#        --technique fluctuation --edr "Microsoft Defender" \
#        --context exe --no-trigger --alerts 0 \
#        --samples 1 --successes 1 --env-limit "Prism 仿真降级"
#
# 参数：
#   --technique T    技术名（module_stomp/threadless/pool_party/fls_callback/
#                    fluctuation/hwbp_blind/indirect_syscall）——必填
#   --edr NAME       EDR/AV 名称——必填
#   --edr-version V  EDR 版本（缺省自动采 Get-MpComputerStatus.AMProductVersion）
#   --context C      投递上下文：dll-sideload / exe / other——必填
#   --export E       selftest 导出名，经 rundll32 触发并自动算告警差值
#   --no-trigger     不触发技术（operator 已手动驱动）；必须配 --alerts N
#   --alerts N       告警数（给定时覆盖自动差值；--no-trigger 模式必填）
#   --samples N      样本数；--successes M 成功数（两者都给则自动算成功率）
#   --env-limit L    环境限制枚举——必填（强制口径：edr-quant-matrix.md §2，
#                    依据 docs/design/NYX_REMEDIATION_PROGRAM_2026Q3.md :44）
#   --evidence P     证据链接（回收日志/CSV 的相对路径）
#
# 环境变量：WIN_HOST（默认 win）、EDR_MATRIX_CSV（默认
# .agents/orchestrator/edr_matrix.csv）。
#
# 注意：alert 差值 = 前后 Get-MpThreatDetection + Get-MpThreat 计数差，
# 实测期间不要清理 Defender 历史，否则差值为负（脚本会警告并如实记录）。
# 未采集字段留空，不得填 0 冒充实测。
# ============================================================================
