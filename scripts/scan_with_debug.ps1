# Enable SeDebugPrivilege in THIS process token, then run PE-sieve against a
# live implant-loaded process. SeDebugPrivilege is held (Administrator) but
# disabled by default — enabling it lets PE-sieve OpenProcess(PROCESS_VM_READ)
# on the target, otherwise it fails with Access Denied (Error 5).

Add-Type -Namespace Win32 -Name Priv -MemberDefinition @"
[System.Runtime.InteropServices.DllImport(\"advapi32.dll\", SetLastError=true)]
public static extern bool OpenProcessToken(System.IntPtr h, uint acc, out System.IntPtr phtok);
[System.Runtime.InteropServices.DllImport(\"advapi32.dll\", SetLastError=true)]
public static extern bool LookupPrivilegeValue(string sys, string name, ref long luid);
[System.Runtime.InteropServices.DllImport(\"advapi32.dll\", SetLastError=true)]
public static extern bool AdjustTokenPrivileges(System.IntPtr htok, bool disall, ref TOKEN_PRIVILEGES ns, int len, System.IntPtr prev, System.IntPtr relen);
[System.Runtime.InteropServices.DllImport(\"kernel32.dll\")]
public static extern System.IntPtr GetCurrentProcess();
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack=1)]
public struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attr; }
public static bool Enable(string priv) {
  System.IntPtr htok;
  if (!OpenProcessToken(GetCurrentProcess(), 0x0020, out htok)) return false;
  TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { Count = 1, Luid = 0, Attr = 2 };
  if (!LookupPrivilegeValue(null, priv, ref tp.Luid)) return false;
  return AdjustTokenPrivileges(htok, false, ref tp, 0, System.IntPtr.Zero, System.IntPtr.Zero);
}
"@

$enabled = [Win32.Priv]::Enable('SeDebugPrivilege')
Write-Host "SeDebugPrivilege enabled: $enabled"

$dllDir  = 'C:\Users\Administrator\Desktop\nyx\pentest\crates\implant-win\target\x86_64-pc-windows-msvc\release'
$pesieve = "$env:TEMP\nyx_detectors\pe-sieve64.exe"
$outDir  = "$env:TEMP\nyx_detectors\scan_out2"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

# Launch the carrier (screenwatch = ~3s alive window with the runtime up).
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'rundll32.exe'
$psi.Arguments = 'nyx_implant_win.dll,nyx_selftest_screenwatch'
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $dllDir
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$tpid = $p.Id
Write-Host "carrier PID = $tpid"
Start-Sleep -Milliseconds 800   # let the indirect-syscall runtime + trampoline init

Write-Host "--- pe-sieve scan (/refl off, full report) ---"
& $pesieve /pid $tpid /dir "$outDir" /refl off 2>&1 | Tee-Object -FilePath "$outDir\report.txt"
Write-Host "pe-sieve exit = $LASTEXITCODE"

$p.WaitForExit(4000) | Out-Null
try { if (-not $p.HasExited) { $p.Kill() } } catch {}

Write-Host ""
Write-Host "--- dumped artifacts ---"
Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue | Select-Object Name, Length
