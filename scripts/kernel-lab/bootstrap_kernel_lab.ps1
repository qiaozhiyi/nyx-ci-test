# bootstrap_kernel_lab.ps1 — enable VBS + HVCI (memory integrity) inside the
# Azure Trusted Launch lab VM. Run elevated. Reboot required afterwards.
#
# Registry path per Microsoft Learn ("Enable virtualization-based protection
# of code integrity"): DeviceGuard + Scenarios\HypervisorEnforcedCodeIntegrity.
# The VM was created with plain Secure Boot (not "Secure Boot with DMA"),
# which is the SKU that supports memory integrity on Azure.

#Requires -RunAsAdministrator
param(
    # Also enable Credential Guard (VBS-protected LSASS isolation research).
    [switch]$WithCredentialGuard,
    # Disable the MS vulnerable-driver blocklist (VulnerableDriverBlocklistEnable=0).
    # Memory integrity turns the blocklist ON by default (KB5020779). The shipped
    # BYOVD drivers (WDTKernel / Shield) are NOT blocklisted and load with it ON;
    # this switch is only needed to test a blocklisted driver.
    # Headless equivalent of Windows Security -> Device security -> Core
    # isolation -> "Microsoft Vulnerable Driver Blocklist" toggle.
    # Requires the SAME reboot as the VBS/HVCI keys, so pass it up front.
    [switch]$DisableBlocklist
)

$ErrorActionPreference = 'Stop'

Write-Host "==> VBS: EnableVirtualizationBasedSecurity = 1"
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
    -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord

Write-Host "==> HVCI (memory integrity): HypervisorEnforcedCodeIntegrity.Enabled = 1"
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
    -Name Enabled -Value 1 -Type DWord

if ($WithCredentialGuard) {
    Write-Host "==> Credential Guard: LsaCfgFlags = 1 (with UEFI lock)"
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name LsaCfgFlags -Value 1 -Type DWord
}

if ($DisableBlocklist) {
    Write-Host "==> Vulnerable Driver Blocklist: VulnerableDriverBlocklistEnable = 0 (BYOVD research)"
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
        -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord
}

Write-Host ""
Write-Host "Done. REBOOT required:  shutdown /r /t 0"
Write-Host "After reboot verify with: .\verify_kernel_env.ps1"
Write-Host ""
if (-not $DisableBlocklist) {
    Write-Host "Reminder: memory integrity turns ON the Microsoft vulnerable driver"
    Write-Host "blocklist (KB5020779). For BYOVD experiments re-run this script with"
    Write-Host "-DisableBlocklist, or toggle it off in Windows Security -> Device"
    Write-Host "security -> Core isolation (reboot required either way)."
}
