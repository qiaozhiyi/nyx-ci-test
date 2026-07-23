# Scan a running implant-loaded process with PE-sieve to verify P2.1 detection
# posture. Strategy: launch rundll32 on a selftest that stays alive ~3s
# (nyx_selftest_screenwatch), grab its PID, scan with pe-sieve64 /pid <pid>,
# capture the report. This is the native-Windows detector run (no WSL2/Docker).

$ErrorActionPreference = 'SilentlyContinue'
$dllDir = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$outDir  = "$env:TEMP\nyx_detectors\scan_out"

# 1. Launch the carrier (screenwatch runs 3 screenshot cycles — alive ~3s).
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'rundll32.exe'
$psi.Arguments = 'nyx_implant_win.dll,nyx_selftest_screenwatch'
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $dllDir
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$pid_target = $p.Id
Write-Host "carrier rundll32 PID = $pid_target (nyx_selftest_screenwatch)"

# Give it a moment to init the runtime (SSN table, trampoline page, etc.).
Start-Sleep -Milliseconds 600

# 2. Scan with PE-sieve. /pid target, dump suspicious to outDir, reflection off.
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
Write-Host "--- pe-sieve scan ---"
& $pesieve /pid $pid_target /dir "$outDir" 2>&1 | Tee-Object -FilePath "$outDir\pesieve_stdout.txt"
$pesieveExit = $LASTEXITCODE
Write-Host "pe-sieve exit code = $pesieveExit"

# 3. Let the carrier finish (don't orphan it).
$p.WaitForExit(5000) | Out-Null
try { if (-not $p.HasExited) { $p.Kill() } } catch {}

Write-Host ""
Write-Host "--- dumped artifacts (process / module list) ---"
Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue |
    Select-Object FullName, Length | Format-Table -AutoSize
Write-Host "DONE. Full stdout: $outDir\pesieve_stdout.txt"
