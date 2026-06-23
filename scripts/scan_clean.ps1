# Clean PE-sieve scan: PowerShell owns the carrier lifecycle, EnableDebug.exe
# wraps only pe-sieve (so pe-sieve inherits the enabled SeDebugPrivilege).
$ErrorActionPreference = 'SilentlyContinue'
$dllDir  = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$wrapper = "$env:TEMP\nyx_detectors\EnableDebug.exe"
$outDir  = "$env:TEMP\nyx_detectors\scan_final"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

# 1. Carrier: screenwatch stays alive ~3s with the indirect-syscall runtime up.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'rundll32.exe'
$psi.Arguments = 'nyx_implant_win.dll,nyx_selftest_screenwatch'
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $dllDir
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$tpid = $p.Id
Write-Host "carrier PID = $tpid (nyx_selftest_screenwatch — runtime + trampoline page up)"
Start-Sleep -Milliseconds 900   # let SSN table + RX trampoline page init

# 2. PE-sieve under EnableDebug (SeDebug enabled → can OpenProcess VM_READ).
Write-Host "--- pe-sieve /pid $tpid (SeDebug enabled via wrapper) ---"
& $wrapper $pesieve "/pid" "$tpid" "/dir" "$outDir" 2>&1 | Tee-Object -FilePath "$outDir\report.txt"
Write-Host "wrapper exit = $LASTEXITCODE"

$p.WaitForExit(4000) | Out-Null
try { if (-not $p.HasExited) { $p.Kill() } } catch {}

Write-Host ""
Write-Host "--- dumped artifacts (PE-sieve writes a .exe/.shc per suspicious region) ---"
$art = Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'report.txt' }
if ($art) { $art | Select-Object FullName, Length | Format-Table -AutoSize }
else { Write-Host "(no dumped artifacts — PE-sieve found nothing suspicious enough to dump)" }
