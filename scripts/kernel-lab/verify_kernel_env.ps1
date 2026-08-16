# verify_kernel_env.ps1 — report the kernel-research posture of the lab VM.
# Run elevated after bootstrap_kernel_lab.ps1 + reboot.
#
# Exit code 0 when VBS AND HVCI are running (the matrix-ready state),
# 1 otherwise — scriptable as a CI-style gate.
#
# -Json: additionally print ONE JSON line (prefix "POSTURE_JSON:") with the
# machine-readable posture — consumed by run_hvci_matrix.sh as evidence.
# The prefix keeps the line findable inside 'az vm run-command' output, which
# interleaves stdout/stderr.
#
# Optional driver-load probe:  .\verify_kernel_env.ps1 -TestDriver C:\lab\test.sys
# Attempts sc.exe create/start and reports the exact failure code:
#   1275 = blocked by CI policy (HVCI/blocklist/testsigning off) — expected
#          for unsigned/test-signed code with enforcement ON,
#   0/running = driver loaded (posture allows it).

#Requires -RunAsAdministrator
param(
    [string]$TestDriver,
    [switch]$Json
)

$fail = 0

# --- VBS / HVCI state -------------------------------------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$vbsStatus = $dg.VirtualizationBasedSecurityStatus   # 0 off, 1 enabled-not-running, 2 running
$services  = @($dg.SecurityServicesRunning)          # 1 = Credential Guard, 2 = HVCI (memory integrity)
$ciEnforced = ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2)

$vbsLabel = switch ($vbsStatus) { 0 {'off'} 1 {'enabled, not running'} 2 {'RUNNING'} default {"unknown ($vbsStatus)"} }
$hvciRunning = ($services -contains 2)
$cgRunning   = ($services -contains 1)
$secureBoot  = try { Confirm-SecureBootUEFI } catch { 'unknown' }

Write-Host ("VBS status            : {0} ({1})" -f $vbsStatus, $vbsLabel)
Write-Host ("HVCI (mem integrity)  : {0}" -f $(if ($hvciRunning) { 'RUNNING' } else { 'not running' }))
Write-Host ("Credential Guard      : {0}" -f $(if ($cgRunning) { 'RUNNING' } else { 'not running' }))
Write-Host ("Secure Boot           : {0}" -f $secureBoot)
Write-Host ("CI policy enforced    : {0}" -f $ciEnforced)

if ($vbsStatus -ne 2)  { $fail = 1 }
if (-not $hvciRunning) { $fail = 1 }

# --- Blocklist registry (KB5020779: on-by-default once HVCI is on) -----------
$bl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
Write-Host ("VulnDriverBlocklist   : {0}" -f $(if ($null -eq $bl) { 'unset' } else { $bl }))

# --- Test-signing state (bcdedit) ---------------------------------------------
$testsigning = $false
try { $testsigning = (bcdedit /enum '{current}' | Select-String -Quiet 'testsigning\s+Yes') } catch {}
Write-Host ("Test-signing          : {0}" -f $testsigning)

# --- Environment facts for the matrix report ---------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host ""
Write-Host ("OS build              : {0}" -f $os.BuildNumber)
Write-Host ("Architecture          : {0}" -f $env:PROCESSOR_ARCHITECTURE)
Write-Host ("Hyper-V present       : {0}" -f $cs.HypervisorPresent)

# --- Machine-readable posture line (for run_hvci_matrix.sh evidence) ----------
if ($Json) {
    $posture = [ordered]@{
        vbs_status         = $vbsStatus
        vbs_running        = ($vbsStatus -eq 2)
        hvci_running       = $hvciRunning
        credential_guard   = $cgRunning
        secure_boot        = ($secureBoot -eq $true)
        ci_enforced        = $ciEnforced
        blocklist_enable   = $(if ($null -eq $bl) { $null } else { [int]$bl })
        test_signing       = [bool]$testsigning
        os_build           = $os.BuildNumber
        os_caption         = $os.Caption
        arch               = $env:PROCESSOR_ARCHITECTURE
        hypervisor_present = [bool]$cs.HypervisorPresent
        matrix_ready       = ($fail -eq 0)
    }
    Write-Host ("POSTURE_JSON:" + ($posture | ConvertTo-Json -Compress))
}

# --- Optional driver-load probe ----------------------------------------------
if ($TestDriver) {
    Write-Host ""
    Write-Host "==> driver-load probe: $TestDriver"
    $name = 'nyxprobe'
    sc.exe delete $name | Out-Null
    sc.exe create $name binPath= "$TestDriver" type= kernel | Out-Null
    sc.exe start $name | Out-Null
    $rc = $LASTEXITCODE
    Write-Host ("start result          : exit {0}" -f $rc)
    if ($rc -eq 1275) { Write-Host '  -> blocked by Code Integrity policy (enforcement active)' }
    if ($rc -eq 0)    { Write-Host '  -> driver LOADED (posture permits this binary)' }
    sc.exe delete $name | Out-Null
}

exit $fail
