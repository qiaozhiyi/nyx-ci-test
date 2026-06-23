# PE-sieve scan with SeDebugPrivilege enabled (via the EnableDebug.exe wrapper).
# The wrapper enables SeDebug in its own token, then execs a cmd that both
# launches the carrier AND runs pe-sieve — both inherit the enabled privilege.

$ErrorActionPreference = 'SilentlyContinue'
$dllDir  = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$wrapper = "$env:TEMP\nyx_detectors\EnableDebug.exe"
$outDir  = "$env:TEMP\nyx_detectors\scan_v3"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

# Inner cmd: start carrier in background, wait, scan, report. All under SeDebug.
# Use start /b to launch rundll32 detached, then ping for delay, then pe-sieve.
$inner = @(
    "set DDL=$dllDir"
    "set DLL=$dllDir\nyx_implant_win.dll"
    "set PE=$pesieve"
    "set OUT=$outDir"
    "start `"carrier`" /b rundll32.exe `"%DDL%\nyx_implant_win.dll,nyx_selftest_screenwatch`""
    "ping -n 2 127.0.0.1 >nul"
    "for /f `"tokens=2`" %i in ('tasklist /fi `"imagename eq rundll32.exe`" /fo list ^| findstr PID') do set RPID=%i"
    "echo carrier PID=%RPID%"
    "%PE% /pid %RPID% /dir %OUT% /refl off"
    "echo PE_EXIT=%errorlevel%"
) -join " & "

Write-Host "--- running under EnableDebug.exe wrapper ---"
& $wrapper "cmd.exe" "/c" $inner 2>&1 | Tee-Object -FilePath "$outDir\full.txt"
Write-Host ""
Write-Host "--- scan_v3 artifacts ---"
Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize
