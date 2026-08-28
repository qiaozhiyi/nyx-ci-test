# edr_matrix_hosted.ps1 — EDR 量化矩阵 hosted-runner 采集器（2026-08-24）。
#
# edr_matrix_record.sh 的 runner 内直跑版：runner 本身就是目标 Windows 机，
# 无需 ssh/rundll32 —— 技术触发改走 nyx-bof-isolated-probe.exe 控制台线束
# （LoadLibrary + 直接调导出，Session 0 安全，windows-ci.yml B3/B4 同款先例），
# 行语义与 edr-quant-matrix.md §1.1 schema 逐列一致（date,technique,edr_name,
# edr_version,delivery_context,samples,successes,success_rate,alerts,env_limit,
# evidence；success_rate 按 %.1f%%；空值留空不填 0）。
#
# 用法（在 runner 上，working-directory = repo 根）：
#   pwsh scripts/edr_matrix_hosted.ps1 `
#       -Technique fls_callback -Export nyx_selftest_inject_fls `
#       -PassCodes 7 -Probe target\release\nyx-bof-isolated-probe.exe `
#       -Dll crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win.dll `
#       -EnvLimit 无 -Csv out\edr_matrix.csv -Evidence <run-url> -LogDir out
#
# 退出码：0 = 行已追加（无论技术成败 —— 失败也是矩阵数据）；
#         3 = 用法/前置错误（probe/DLL 缺失），行不追加。
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Technique,
    [Parameter(Mandatory)][string]$Export,
    [Parameter(Mandatory)][int[]]$PassCodes,
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$Dll,
    [string]$EdrName = "Microsoft Defender",
    [string]$Context = "exe",
    [Parameter(Mandatory)][string]$EnvLimit,   # 强制字段：无 / Defender 已关闭 / …（§2 枚举）
    [Parameter(Mandatory)][string]$Csv,
    [string]$Evidence = "",
    [string]$LogDir = "",
    [int]$TimeoutSec = 60,
    [int]$SettleSec = 8
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Probe)) { Write-Host "::error::probe exe missing: $Probe"; exit 3 }
if (-not (Test-Path $Dll))   { Write-Host "::error::selftest DLL missing: $Dll"; exit 3 }

function Get-DefenderSnapshot {
    # Get-MpThreat* 在无 Defender/Server 上可能抛错 —— 如实降级为空计数并记录。
    $det = 0; $thr = 0; $ver = ""
    try { $d = Get-MpThreatDetection; if ($d) { $det = @($d).Count } } catch { $det = -1 }
    try { $t = Get-MpThreat;          if ($t) { $thr = @($t).Count } } catch { $thr = -1 }
    try { $ver = (Get-MpComputerStatus).AMProductVersion } catch { $ver = "" }
    return @{ Detections = $det; Threats = $thr; Version = $ver }
}

function Csv-Quote([string]$f) {
    if ($f.Contains(",") -or $f.Contains('"')) { return '"' + $f.Replace('"', '""') + '"' }
    return $f
}

$before = Get-DefenderSnapshot
Write-Host "==> baseline: detections=$($before.Detections) threats=$($before.Threats) defender=$($before.Version)"

# 反沙箱套件可能把 runner 判为 VM（windows-ci.yml B4 同款前置）。
$env:NYX_SKIP_SANDBOX = "1"
Remove-Item "nyx_matrix_$Technique.out.txt", "nyx_matrix_$Technique.err.txt" -Force -ErrorAction SilentlyContinue
Write-Host "==> triggering: $Export via probe (timeout ${TimeoutSec}s)"
$sp = @{
    FilePath               = $Probe
    ArgumentList           = @("`"$Dll`"", $Export)
    PassThru               = $true
    RedirectStandardOutput = "nyx_matrix_$Technique.out.txt"
    RedirectStandardError  = "nyx_matrix_$Technique.err.txt"
}
# -WindowStyle 仅 Windows 桌面版语义；PS Core 非 Windows 平台会拒绝该参数。
if ($IsWindows) { $sp.WindowStyle = "Hidden" }
$p = Start-Process @sp
$p.WaitForExit($TimeoutSec * 1000) | Out-Null
$timedOut = -not $p.HasExited
if ($timedOut) {
    $p.Kill()
    $code = -999
    Write-Host "::warning::$Export TIMEOUT (${TimeoutSec}s) — killed"
} else {
    $code = $p.ExitCode
}
Write-Host "==> exit: $code (pass set: $($PassCodes -join '/'))"

Start-Sleep -Seconds $SettleSec
$after = Get-DefenderSnapshot
Write-Host "==> after:    detections=$($after.Detections) threats=$($after.Threats)"

$alerts = ""
if ($before.Detections -ge 0 -and $after.Detections -ge 0) {
    $alerts = ($after.Detections - $before.Detections) + ($after.Threats - $before.Threats)
    if ($alerts -lt 0) {
        Write-Host "::warning::negative alert delta ($alerts) — 告警历史疑似被清理，如实记录"
    }
}

$success = if ($timedOut) { 0 } elseif ($PassCodes -contains $code) { 1 } else { 0 }
$samples = 1
$rate = "{0:N1}%" -f ($success * 100.0 / $samples)

# 自愈证据：selftest 持久化的原始响应（fls/pool 写 %TEMP%\nyx_g6_*.resp）随日志走。
if ($LogDir) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    foreach ($f in @("nyx_matrix_$Technique.out.txt", "nyx_matrix_$Technique.err.txt")) {
        if (Test-Path $f) { Move-Item $f $LogDir -Force }
    }
    Get-ChildItem "$env:TEMP\nyx_g6_*" -ErrorAction SilentlyContinue |
        Copy-Item -Destination $LogDir -Force
}

$csvDir = Split-Path $Csv -Parent
if ($csvDir) { New-Item -ItemType Directory -Force -Path $csvDir | Out-Null }
if (-not (Test-Path $Csv)) {
    "date,technique,edr_name,edr_version,delivery_context,samples,successes,success_rate,alerts,env_limit,evidence" |
        Out-File $Csv -Encoding utf8
}
$fields = @(
    (Get-Date -Format "yyyy-MM-dd"), $Technique, $EdrName, $after.Version, $Context,
    "$samples", "$success", $rate, "$alerts", $EnvLimit, $Evidence
)
$row = ($fields | ForEach-Object { Csv-Quote $_ }) -join ","
$row | Out-File $Csv -Encoding utf8 -Append
Write-Host "==> appended: $row"
exit 0
