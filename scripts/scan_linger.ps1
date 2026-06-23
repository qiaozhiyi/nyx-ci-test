# Scan nyx_linger (30s live implant with full runtime up) with PE-sieve under
# SeDebugPrivilege. nyx_linger brings up: indirect-syscall table, RX trampoline
# page (RWX private commit), unhooked ntdll, NtTraceEvent patch, staged GapPool.
# This is the realistic in-memory surface a detector inspects.
$ErrorActionPreference = 'SilentlyContinue'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$wrapper = "$env:TEMP\nyx_detectors\EnableDebug.exe"
$dllDir  = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$outDir  = "$env:TEMP\nyx_detectors\scan_linger"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

$p = Start-Process rundll32.exe -ArgumentList 'nyx_implant_win.dll,nyx_linger' -PassThru -WindowStyle Hidden -WorkingDirectory $dllDir
$tpid = $p.Id
Write-Host "nyx_linger carrier PID = $tpid (30s live window, full runtime up)"
Start-Sleep -Milliseconds 2000   # let everything init (SSN scan + gap scan + trampoline)

Write-Host "--- PE-sieve /pid $tpid (SeDebug enabled) ---"
$rep = & $wrapper $pesieve "/pid" "$tpid" "/dir" "$outDir" 2>&1
$rep | Out-File "$outDir\report.txt"
Write-Host ("raw output lines: " + $rep.Count)
Write-Host "--- substantive report lines ---"
$rep | Where-Object { $_ -match 'suspicious|dumped|implanted|unmapped|hook|patched|ERROR|\[\*\]|\[-\]|\[\+\]|report|module|scanning|total' } | ForEach-Object { Write-Host "  $_" }
Write-Host "pe-sieve exit = $LASTEXITCODE"

Write-Host ""
Write-Host "--- dumped artifacts (.exe/.shc = suspicious regions extracted) ---"
$art = Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^report\.txt$' }
if ($art) { $art | Select-Object Name, Length | Format-Table -AutoSize }
else { Write-Host "(none dumped)" }

Write-Host ""
Write-Host "--- FULL REPORT (first 60 lines) ---"
Get-Content "$outDir\report.txt" | Select-Object -First 60

# cleanup
try { if (-not $p.HasExited) { $p.Kill() } } catch {}
