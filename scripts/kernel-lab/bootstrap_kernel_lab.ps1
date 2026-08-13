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
    [switch]$WithCredentialGuard
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

Write-Host ""
Write-Host "Done. REBOOT required:  shutdown /r /t 0"
Write-Host "After reboot verify with: .\verify_kernel_env.ps1"
Write-Host ""
Write-Host "Reminder: memory integrity turns ON the Microsoft vulnerable driver"
Write-Host "blocklist (KB5020779). Toggle it off in Windows Security -> Device"
Write-Host "security -> Core isolation before BYOVD experiments."
