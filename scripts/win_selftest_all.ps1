# win_selftest_all.ps1 — run ALL nyx_implant_win selftest exports via rundll32.
# Version/host-agnostic: DLL path from env NYX_DLL (default C:\nyx\nyx_implant_win.dll).
# Each export gets a per-export timeout (default 15s); hangs are killed + logged TIMEOUT.
# Results written to NYX_OUT (default C:\nyx\selftest_results.csv) for retrieval.
#
# With -Validate: compares each export's exit code against EXPECTED_CODES below
# and exits 1 if any mismatch. Without -Validate: records codes only (informational).
#
# Expected codes are derived from the `Bits:` doc comments in selftests.rs /
# envprobe.rs / hookchain.rs. Codes marked $null are "best-effort" (depend on
# host environment — e.g. pivot needs a closed port) and are not validated.
#
# Usage:  powershell -ExecutionPolicy Bypass -File win_selftest_all.ps1 -Validate
#         powershell -ExecutionPolicy Bypass -File win_selftest_all.ps1 -Dll C:\path\dll -Timeout 20
[CmdletBinding()]
param(
    [string]$Dll   = $(if ($env:NYX_DLL) { $env:NYX_DLL } else { "C:\nyx\nyx_implant_win.dll" }),
    [int]$Timeout  = 15,
    [string]$Out   = $(if ($env:NYX_OUT) { $env:NYX_OUT } else { "C:\nyx\selftest_results.csv" }),
    [string]$ExportsFile = $(if ($env:NYX_EXPORTS) { $env:NYX_EXPORTS } else { "C:\nyx\exports.txt" }),
    [switch]$Validate
)

$ErrorActionPreference = 'SilentlyContinue'

# ---- Expected exit codes (from selftests.rs / envprobe.rs Bits: doc comments) ----
# $null = best-effort (host-dependent, not validated). Int values are exact-match.
$EXPECTED_CODES = @{
    "nyx_selftest_calib42"        = 42      # calibration: exit code propagation
    "nyx_selftest_config"         = 3       # bits 0-1: decode + fields match
    "nyx_selftest_hostinfo"       = 15      # bits 0-3: hostname/user/pid/beacon_id
    "nyx_selftest_antidebug"      = 7       # bits 0-2: BeingDebugged/uptime/syscall
    "nyx_selftest_recon"          = 7       # bits 0-2: driveinfo/path/net
    "nyx_selftest_shell"          = 1       # bit 0: echo stdout capture
    "nyx_selftest_fs"             = 127     # bits 0-6: upload/download/mv/cp/mkdir/rm/syscall
    "nyx_selftest_bof"            = 1       # bit 0: BOF-PRINT-OK
    "nyx_selftest_env"            = 3       # bits 0-1
    "nyx_selftest_mem"            = 3       # bits 0-1
    "nyx_selftest_net"            = 15      # bits 0-3
    "nyx_selftest_postex"         = 15      # bits 0-3: token ops
    "nyx_selftest_keylog"         = 3       # bits 0-1
    "nyx_selftest_clipboard"      = 1       # bit 0
    "nyx_selftest_screenshot"     = 1       # bit 0: capture succeeded
    "nyx_selftest_portscan"       = 7       # bits 0-2
    "nyx_selftest_driveinfo"      = $null   # bitmask — host-dependent drive count
    "nyx_selftest_envprobe"       = $null   # 0xB0 Clean / 0xB1 AnalysisEnv — host-dependent
    "nyx_selftest_hashdump"       = 4       # bitmask: SAM hive parse
    "nyx_selftest_pivot"          = $null   # needs closed port — host-dependent
    "nyx_selftest_inject"         = $null   # depends on sacrificial spawn success
    "nyx_selftest_resolve_forwarder" = 7    # bits 0-2
    "nyx_selftest_syscall_rt"     = 3       # bits 0-1
    # The remaining exports (*_diag, *_probe, *_edge, *_full, *_armed variants)
    # are diagnostic/probe entries with host-dependent exit codes — $null.
    "nyx_selftest"                = $null   # aggregator
    "nyx_selftest_alloc_probe"    = 3
    "nyx_selftest_blind_nttrace"  = 15
    "nyx_selftest_blind_provider" = 1
    "nyx_selftest_bof_diag"       = 1
    "nyx_selftest_bof_marker"     = 1
    "nyx_selftest_evasion"        = $null   # aggregator
    # nyx_selftest_foliage / nyx_selftest_foliage_apc were removed (selftests.rs
    # commit) — the Foliage APC chain is dead code, superseded by Fluctuation.
    "nyx_selftest_fs_edge"        = 15
    "nyx_selftest_fs_probe"       = $null   # probe
    "nyx_selftest_gap_scan"       = 15
    "nyx_selftest_hashdump_diag"  = 1
    "nyx_selftest_hookchain"      = $null   # bitmask — SSN resolution host-dependent
    "nyx_selftest_hookchain_full" = $null
    "nyx_selftest_hwbp_blind"     = $null   # HWBP — needs specific config
    "nyx_selftest_inject_armed"   = $null
    "nyx_selftest_rt_probe"       = $null   # probe
    "nyx_selftest_rt_steps"       = $null
    "nyx_selftest_screenshot_diag"= 63      # bits 0-5
    "nyx_selftest_screenwatch"    = 0       # 0 = all frames captured
    "nyx_selftest_shell_edge"     = 3
    "nyx_selftest_swap_armed"     = 15
    "nyx_selftest_swap_decision"  = 3
    "nyx_selftest_transport"      = 1
    "nyx_selftest_rm_file"        = 1
    "nyx_selftest_rm_probe"       = 1
    # 2026-07-20 additions (PR #41 regression + G1 trex + 74c9663 replacements):
    "nyx_selftest_hive_guard"     = 63      # bits 0-5: hive guard blocks bypass inputs (PR #41)
    "nyx_selftest_trex"           = $null   # 0xE0+tier (0..4) / 0xFF — host posture dependent
    "nyx_selftest_cet_status"     = $null   # 1=CET on / 0=off-or-probe-failed — host dependent
    "nyx_selftest_display_count"  = $null   # monitor count / 0xFFFFFFFF probe-fail — session dependent
}

if (-not (Test-Path $Dll)) {
    Write-Output "ERROR: DLL not found at $Dll"
    exit 2
}

# Export enumeration order: (1) exports.txt shipped alongside the DLL by the
# build pipeline (always in sync, no tooling needed on the server), (2) mingw
# objdump if present, (3) dumpbin if present.
$exports = @()
if (Test-Path $ExportsFile) {
    $exports = Get-Content $ExportsFile | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^nyx_selftest' } | Sort-Object -Unique
}
if (-not $exports) {
    # Pick the FIRST objdump that actually resolves (PATH or known mingw dir).
    # Filtering by Get-Command resolution — not by string truthiness — so a PATH
    # install is reached even if the mingw dir differs across hosts.
    $objdump = @("objdump.exe", "C:\mingw64\bin\objdump.exe", "C:\mingw32\bin\objdump.exe") |
        Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
        Select-Object -First 1
    if ($objdump) {
        $exports = (& $objdump -p $Dll) | Select-String 'nyx_selftest' |
            ForEach-Object { ($_ -split '\s+') | Where-Object { $_ -match '^nyx_selftest' } } |
            Sort-Object -Unique
    }
}
if (-not $exports) {
    # Fallback: parse with dumpbin if present (VS toolchain), else fail loudly.
    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if ($dumpbin) {
        $exports = (& dumpbin /exports $Dll) | Select-String 'nyx_selftest' |
            ForEach-Object { ($_ -split '\s+') | Where-Object { $_ -match '^nyx_selftest' } } |
            Sort-Object -Unique
    }
}
if (-not $exports) {
    Write-Output "ERROR: could not enumerate exports (need exports.txt, objdump, or dumpbin)"
    exit 3
}

Write-Output ("Running {0} selftest exports from {1} (timeout {2}s each)" -f $exports.Count, $Dll, $Timeout)

$results = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($e in $exports) {
    $i++
    $code = -999
    $status = "UNKNOWN"
    try {
        $p = Start-Process rundll32.exe -ArgumentList "$Dll,$e" -PassThru -WindowStyle Hidden
        if ($p.WaitForExit($Timeout * 1000)) {
            $code = $p.ExitCode
            $status = "EXIT"
        } else {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
            $code = -1
            $status = "TIMEOUT"
        }
    } catch {
        $code = -998
        $status = "SPAWN_FAIL"
    }
    $results.Add([PSCustomObject]@{ export = $e; code = $code; status = $status })
    Write-Output ("[{0,2}/{1}] {2,-38} => {3} ({4})" -f $i, $exports.Count, $e, $code, $status)
}

# Write CSV for retrieval
$results | Export-Csv -Path $Out -NoTypeInformation -Encoding UTF8
Write-Output "---"
$ok    = ($results | Where-Object { $_.status -eq 'EXIT' }).Count
$hangs = ($results | Where-Object { $_.status -eq 'TIMEOUT' }).Count
$fail  = ($results | Where-Object { $_.status -ne 'EXIT' }).Count
Write-Output ("SUMMARY: {0} total, {1} exited, {2} timed-out, {3} non-exit" -f $results.Count, $ok, $hangs, $fail)
Write-Output "Results CSV: $Out"

# ---- Exit-code validation (gate mode) ----
if ($Validate) {
    $mismatches = 0
    $validated  = 0
    $skipped    = 0
    foreach ($r in $results) {
        $expected = $EXPECTED_CODES[$r.export]
        if ($null -eq $expected) {
            $skipped++
            continue   # best-effort: host-dependent, skip
        }
        $validated++
        if ($r.code -ne $expected) {
            $mismatches++
            Write-Output ("  MISMATCH: {0} => got {1}, expected {2}" -f $r.export, $r.code, $expected)
        }
    }
    Write-Output "---"
    Write-Output ("VALIDATION: {0} validated, {1} mismatches, {2} skipped (best-effort)" -f $validated, $mismatches, $skipped)
    if ($mismatches -gt 0) {
        Write-Output "FAIL: $mismatches selftest(s) returned unexpected exit codes"
        exit 1
    }
    Write-Output "PASS: all validated selftests matched expected exit codes"
}
