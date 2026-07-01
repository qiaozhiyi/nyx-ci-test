# win_selftest_all.ps1 — run ALL nyx_implant_win selftest exports via rundll32.
# Version/host-agnostic: DLL path from env NYX_DLL (default C:\nyx\nyx_implant_win.dll).
# Each export gets a per-export timeout (default 15s); hangs are killed + logged TIMEOUT.
# Results written to NYX_OUT (default C:\nyx\selftest_results.csv) for retrieval.
# Usage:  powershell -ExecutionPolicy Bypass -File win_selftest_all.ps1
#         powershell -ExecutionPolicy Bypass -File win_selftest_all.ps1 -Dll C:\path\dll -Timeout 20
[CmdletBinding()]
param(
    [string]$Dll   = $(if ($env:NYX_DLL) { $env:NYX_DLL } else { "C:\nyx\nyx_implant_win.dll" }),
    [int]$Timeout  = 15,
    [string]$Out   = $(if ($env:NYX_OUT) { $env:NYX_OUT } else { "C:\nyx\selftest_results.csv" })
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $Dll)) {
    Write-Output "ERROR: DLL not found at $Dll"
    exit 2
}

# Dynamically enumerate exports from the DLL using mingw objdump if available,
# else fall back to a hardcoded-ish list read from the binary. Prefer dynamic.
$exports = @()
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
    Write-Output "ERROR: could not enumerate exports (need objdump or dumpbin on PATH)"
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
