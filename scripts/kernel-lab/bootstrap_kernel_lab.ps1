# bootstrap_kernel_lab.ps1 — configure the Azure kernel-lab VM for driver
# research. Run elevated. Reboot required afterwards.
#
# Lab purpose (post-2026-08-16): plain x64 Windows kernel work — PatchGuard
# live KPCR dump (offset truth for kernelsdk `offsets.rs`), WFP kit e2e,
# BYOVD driver functional tests, test-signed probe driver (peekaboo-probe).
# The HVCI-on verification matrix is ABANDONED: the shipped BYOVD drivers
# (WDTKernel / Shield) are clean of the MS vulnerable-driver blocklist, so
# HVCI posture gates nothing we ship, and HVCI-on only BLOCKS lab scenarios
# (test-signed loads, blocklisted-driver research). This script therefore
# enables test-signing and leaves VBS/HVCI OFF.

#Requires -RunAsAdministrator
param(
    # Disable the MS vulnerable-driver blocklist (VulnerableDriverBlocklistEnable=0).
    # The shipped BYOVD drivers (WDTKernel / Shield) are NOT blocklisted and load
    # with it ON; this switch is only needed to test a blocklisted driver.
    # Headless equivalent of Windows Security -> Device security -> Core
    # isolation -> "Microsoft Vulnerable Driver Blocklist" toggle.
    [switch]$DisableBlocklist
)

$ErrorActionPreference = 'Stop'

Write-Host "==> Test-signing: bcdedit /set testsigning on (test-signed probe drivers)"
bcdedit /set testsigning on | Out-Host

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
Write-Host "Note: VBS/HVCI are intentionally left OFF. The HVCI-on matrix was"
Write-Host "abandoned 2026-08-16 — do not re-enable memory integrity on this lab;"
Write-Host "it only blocks the scenarios above."
