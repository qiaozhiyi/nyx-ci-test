# Launch several implant carriers in parallel for a wider scan window, then
# PE-sieve each under SeDebugPrivilege. Carriers use nyx_selftest_evasion
# (full unhook+blind+SSN init) which exercises the indirect-syscall trampoline
# page + unhooked ntdll — exactly the surfaces PE-sieve inspects.
$ErrorActionPreference = 'SilentlyContinue'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$wrapper = "$env:TEMP\nyx_detectors\EnableDebug.exe"
$dllDir  = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$outDir  = "$env:TEMP\nyx_detectors\scan_multi"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

$carriers = @('nyx_selftest_evasion','nyx_selftest_screenwatch','nyx_selftest_postex')
$procs = @()
foreach ($c in $carriers) {
    $p = Start-Process rundll32.exe -ArgumentList "nyx_implant_win.dll,$c" -PassThru -WindowStyle Hidden -WorkingDirectory $dllDir
    $procs += [PSCustomObject]@{ P=$p; Name=$c }
    Write-Host "launched $c  PID=$($p.Id)"
}
Start-Sleep -Milliseconds 1200

$anyDumped = $false
foreach ($entry in $procs) {
    $p = $entry.P
    if ($p.HasExited) { Write-Host "[skip] $($entry.Name) PID=$($p.Id) already exited"; continue }
    Write-Host "--- PE-sieve scanning PID=$($p.Id) ($($entry.Name)) ---"
    $rep = & $wrapper $pesieve "/pid" "$($p.Id)" "/dir" "$outDir" 2>&1
    $rep | Out-File "$outDir\report_$($p.Id).txt"
    # Show the substantive lines (skip the help/banner boilerplate).
    $rep | Where-Object { $_ -match 'suspicious|dumped|implanted|unmapped|hook|patched|ERROR|\[.\]|report' } | ForEach-Object { Write-Host "  $_" }
    Write-Host "  exit=$LASTEXITCODE"
    try { if (-not $p.HasExited) { $p.Kill() } } catch {}
}

Write-Host ""
Write-Host "--- dumped artifacts (suspicious memory regions PE-sieve extracted) ---"
$art = Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(exe|shc|dll|bin)$' }
if ($art) { $art | Select-Object FullName, Length | Format-Table -AutoSize; $anyDumped = $true }
else { Write-Host "(no .exe/.shc dumped)" }
Write-Host ""
Write-Host "--- full reports ---"
Get-ChildItem "$outDir\report_*.txt" | ForEach-Object { Write-Host "=== $($_.Name) ==="; Get-Content $_.FullName }
