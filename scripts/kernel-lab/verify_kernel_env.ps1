# verify_kernel_env.ps1 — report the kernel-research posture of the lab VM.
# Run elevated after bootstrap_kernel_lab.ps1 + reboot.
#
# Exit code 0 when VBS AND HVCI are running (the matrix-ready state),
# 1 otherwise — scriptable as a CI-style gate.
#
# Optional driver-load probe:  .\verify_kernel_env.ps1 -TestDriver C:\lab\test.sys
# Attempts sc.exe create/start and reports the exact failure code:
#   1275 = blocked by CI policy (HVCI/blocklist/testsigning off) — expected
#          for unsigned/test-signed code with enforcement ON,
#   0/running = driver loaded (posture allows it).

#Requires -RunAsAdministrator
param([string]$TestDriver)

$fail = 0

# --- VBS / HVCI state -------------------------------------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$vbsStatus = $dg.VirtualizationBasedSecurityStatus   # 0 off, 1 enabled-not-running, 2 running
$services  = @($dg.SecurityServicesRunning)          # 1 = Credential Guard, 2 = HVCI (memory integrity)

Write-Host ("VBS status            : {0} ({1})" -f $vbsStatus, @('off','enabled, not running','RUNNING')[$vbsStatus])
Write-Host ("HVCI (mem integrity)  : {0}" -f $(if ($services -contains 2) { 'RUNNING' } else { 'not running' }))
Write-Host ("Credential Guard      : {0}" -f $(if ($services -contains 1) { 'RUNNING' } else { 'not running' }))
Write-Host ("Secure Boot           : {0}" -f $(try { Confirm-SecureBootUEFI } catch { 'unknown' }))

if ($vbsStatus -ne 2)          { $fail = 1 }
if (-not ($services -contains 2)) { $fail = 1 }

# --- Environment facts for the matrix report ---------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host ""
Write-Host ("OS build              : {0}" -f $os.BuildNumber)
Write-Host ("Architecture          : {0}" -f $env:PROCESSOR_ARCHITECTURE)
Write-Host ("Hyper-V present       : {0}" -f $cs.HypervisorPresent)

# --- Optional driver-load probe ----------------------------------------------
if ($TestDriver) {
    Write-Host ""
    Write-Host "==> driver-load probe: $TestDriver"
    $name = 'nyxprobe'
    sc.exe delete $name | Out-Null
    sc.exe create $name binPath= $TestDriver type= kernel | Out-Null
    sc.exe start $name | Out-Null
    $rc = $LASTEXITCODE
    Write-Host ("start result          : exit {0}" -f $rc)
    if ($rc -eq 1275) { Write-Host '  -> blocked by Code Integrity policy (enforcement active)' }
    if ($rc -eq 0)    { Write-Host '  -> driver LOADED (posture permits this binary)' }
    sc.exe delete $name | Out-Null
}

exit $fail
