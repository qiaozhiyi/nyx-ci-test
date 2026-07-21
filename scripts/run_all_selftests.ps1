# Run every nyx_implant_win.dll selftest export, capture the real exit code via
# the Process API (cmd %ERRORLEVEL% doesn't propagate rundll32 ExitProcess codes).
# Times out after 30s per test (some tests hang by design, e.g. hashdump_diag on SAM).
# Authoritative bitmask matrix for the P2.1 runtime acceptance.

$ErrorActionPreference = 'SilentlyContinue'
$dllDir = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$dll = Join-Path $dllDir 'nyx_implant_win.dll'

# The full export list (from dumpbin /exports), excluding the entry points that
# would start a real beacon loop / oneshot (those need a live team server).
$tests = @(
    'nyx_selftest_calib42','nyx_selftest_alloc_probe','nyx_selftest_antidebug',
    'nyx_selftest_blind_nttrace','nyx_selftest_gap_scan','nyx_selftest_mem',
    'nyx_selftest_inject',
    'nyx_selftest_syscall_rt','nyx_selftest_rt_probe','nyx_selftest_rt_steps',
    'nyx_selftest_config','nyx_selftest_hostinfo','nyx_selftest_recon',
    'nyx_selftest_env','nyx_selftest_net','nyx_selftest_portscan',
    'nyx_selftest_clipboard','nyx_selftest_shell','nyx_selftest_shell_edge',
    'nyx_selftest_fs','nyx_selftest_fs_edge',
    'nyx_selftest_keylog','nyx_selftest_postex','nyx_selftest_pivot',
    'nyx_selftest_screenshot','nyx_selftest_screenshot_diag','nyx_selftest_screenwatch',
    'nyx_selftest_transport','nyx_selftest_evasion',
    'nyx_selftest_swap_decision',
    'nyx_selftest_bof','nyx_selftest_bof_marker','nyx_selftest_bof_diag',
    'nyx_selftest_hashdump','nyx_selftest_hashdump_diag',
    'nyx_selftest_rm_file','nyx_selftest_rm_probe','nyx_selftest_fs_probe'
)

$results = @()
foreach ($t in $tests) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'rundll32.exe'
    $psi.Arguments = "nyx_implant_win.dll,$t"
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $dllDir
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $exited = $p.WaitForExit(30000)
    if (-not $exited) {
        try { $p.Kill() } catch {}
        $code = 'TIMEOUT'
        $bin = 'TIMEOUT'
    } else {
        $code = $p.ExitCode
        if ($code -is [int]) { $bin = '0b{0}' -f [Convert]::ToString($code,2) } else { $bin = $code }
    }
    $results += [PSCustomObject]@{ Test=$t; Exit=$code; Bin=$bin }
    Write-Host ("{0,-32} exit={1,-12} {2}" -f $t, $code, $bin)
}

Write-Host ""
Write-Host "=== SUMMARY ==="
$pass = ($results | Where-Object { $_.Exit -is [int] -and $_.Exit -ne 0 }).Count
$zero = ($results | Where-Object { $_.Exit -eq 0 }).Count
$to    = ($results | Where-Object { $_.Exit -eq 'TIMEOUT' }).Count
Write-Host "nonzero-exit (ran+returned): $pass"
Write-Host "zero-exit:                   $zero  (note: calib42=42 expected nonzero; 0 may mean early exit or test's own 'nothing passed')"
Write-Host "TIMEOUT (hung by design?):   $to"
