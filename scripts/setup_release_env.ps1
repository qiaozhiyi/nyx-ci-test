<#
.SYNOPSIS
    Configures Windows Defender on the Nyx release-build VPS for
    reproducible release artifact builds. Idempotent and safe to re-run.

.DESCRIPTION
    One-time (but re-runnable) setup of the build environment on the
    self-hosted Windows runner (hostname Cloud-Init-Win, Windows Server
    2019 build 17763). Makes three classes of change to Windows Defender:

      1. MAPSReporting       -> 0  (Disabled)
         SubmitSamplesConsent -> 2  (Never submit)
         so the red-team research server does not auto-upload payload
         samples to the Microsoft cloud during iteration.

      2. ExclusionPath for every crates/*/target directory and the
         C:\nyx\staging release-asset directory, so Defender does not
         quarantine compile artifacts between cargo invocations.

      3. ExclusionProcess for cargo.exe and rustc.exe, so Defender does
         not block the build tools from reading freshly-written artifacts.

    Defender realtime protection is NOT disabled by this script; the
    release pipeline relies on "Defender-on verification" (see
    docs/superpowers/specs/2026-07-21-release-pipeline-design.md section 2
    and docs/RELEASE_ENV.md). Every change is reversible; see the rollback
    section of docs/RELEASE_ENV.md.

    Requires Administrator and PowerShell 5.1 (Server 2019 ships 5.1).
    Uses only Set-MpPreference / Add-MpPreference / Get-MpPreference /
    Get-MpComputerStatus -- no pwsh-only cmdlets, no ternaries, no ??.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\nyx\scripts\setup_release_env.ps1

.EXAMPLE
    # From the macOS dev host over the existing SSH alias:
    ssh win "powershell -ExecutionPolicy Bypass -File C:\nyx\scripts\setup_release_env.ps1"

.NOTES
    Exit codes:
      0  all verifications passed
      1  not running as Administrator
      2  Defender module / Set-MpPreference unavailable (not Windows, or
         Defender feature removed)
      3  one or more post-change verifications did not match the expected
         values
#>

# ======================================================================
# SAFETY / RATIONALE -- read before editing this script.
# ----------------------------------------------------------------------
# Each Defender change below is deliberate and reversible (rollback
# steps in docs/RELEASE_ENV.md):
#
#   1. MAPS off (MAPSReporting=0, SubmitSamplesConsent=2):
#        This is an authorized red-team research server. Builds iterate
#        real payload bytes; auto-uploading those bytes to the Microsoft
#        threat-intel cloud would burn the toolchain and violate
#        engagement scope.
#
#   2. ExclusionPath for crates/*/target + C:\nyx\staging:
#        Defender realtime protection STAYS ON (the release spec wants
#        "Defender-on verification"), but it must not quarantine compile
#        artifacts mid-build. Without these exclusions, .rlib / .dll /
#        .pdb files get deleted between cargo invocations and the build
#        fails with "file not found".
#
#   3. ExclusionProcess for cargo.exe / rustc.exe:
#        cargo/rustc spawn many short-lived children that read freshly
#        written artifacts; the process exclusion prevents intermittent
#        open-file scan blocks that surface as linker input errors.
#
# This script does NOT disable realtime monitoring, does NOT stop the
# WinDefend service, and does NOT add ASR rules.
# ======================================================================

[CmdletBinding()]
param()

# Infra setup: surface every surprise loudly. Each Defender cmdlet call
# below is individually wrapped in try/catch so a failure reports which
# setting failed before exiting.
$ErrorActionPreference = 'Stop'

#region --- Admin check (Set-MpPreference / Add-MpPreference require elevation) ---
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: this script must be run as Administrator."
    Write-Output "Re-launch from an elevated PowerShell session. The self-hosted runner"
    Write-Output "agent already runs elevated, so CI invocation needs no change."
    exit 1
}
#endregion

#region --- Defender availability check ---
if (-not (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue)) {
    Write-Output "ERROR: Set-MpPreference not found on PATH."
    Write-Output "Defender module is unavailable (not Windows, or the Defender feature"
    Write-Output "was removed from this Server image). Nothing to configure."
    exit 2
}
#endregion

#region --- Target ExclusionPath / ExclusionProcess lists ---
# Mirror the crate layout verified live on 2026-07-21 (see RELEASE_ENV.md
# baseline table). Each crates/<name> has its own target/ because the
# standalone crates (implant-win) carry an empty [workspace] block and do
# not share the workspace-level target/.
#
# Two parallel working trees must be covered:
#   1. C:\nyx                        — manual SSH validation worktree (the
#                                      one win_remote_run.sh etc. operate on)
#   2. C:\actions-runner\_work\NY\NY — the GH Actions self-hosted runner
#                                      checkout root (verified 2026-07-21).
# Both get the same exclusion pattern; the runner path is what CI uses, the
# C:\nyx path is what manual testing uses.
$exclusionPaths = @(
    # C:\nyx manual worktree
    'C:\nyx\target',
    'C:\nyx\crates\implant-win\target',
    'C:\nyx\crates\server\target',
    'C:\nyx\crates\operator-kernel-cli\target',
    'C:\nyx\crates\offset-resolver\target',
    'C:\nyx\crates\nyx-loader\target',
    'C:\nyx\tools\loader_probe_dll\target',
    'C:\nyx\staging',
    # C:\actions-runner\_work\NY\NY self-hosted runner checkout
    'C:\actions-runner\_work\NY\NY\target',
    'C:\actions-runner\_work\NY\NY\crates\implant-win\target',
    'C:\actions-runner\_work\NY\NY\crates\server\target',
    'C:\actions-runner\_work\NY\NY\crates\operator-kernel-cli\target',
    'C:\actions-runner\_work\NY\NY\crates\offset-resolver\target',
    'C:\actions-runner\_work\NY\NY\crates\nyx-loader\target',
    'C:\actions-runner\_work\NY\NY\tools\loader_probe_dll\target',
    'C:\actions-runner\_work\NY\NY\staging',
    'C:\actions-runner\_work\NY\NY'   # belt-and-braces: whole checkout, since
                                       # staging/ + ad-hoc test files live here too
)

# Build-tool processes. clink is not added because it is not in the
# verified baseline; add it here if a future toolchain brings it in.
$exclusionProcesses = @(
    'C:\Users\Administrator\.cargo\bin\cargo.exe',
    'C:\Users\Administrator\.cargo\bin\rustc.exe'
)
#endregion

#region --- 1. MAPS off (do not feed MS threat intel) ---
Write-Output "[1/3] Disabling MAPS cloud sample upload..."
try {
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -SubmitSamplesConsent 2
} catch {
    Write-Output ("  FAIL: could not set MAPSReporting/SubmitSamplesConsent: {0}" -f $_.Exception.Message)
    exit 3
}
Write-Output "  OK: MAPSReporting=0, SubmitSamplesConsent=2"
#endregion

#region --- 2. ExclusionPath (build artifacts not deleted mid-build) ---
Write-Output "[2/3] Adding ExclusionPath entries..."
foreach ($p in $exclusionPaths) {
    try {
        # Add-MpPreference is idempotent: adding an already-present
        # exclusion is a no-op, so re-runs are safe.
        Add-MpPreference -ExclusionPath $p
    } catch {
        Write-Output ("  FAIL: {0} : {1}" -f $p, $_.Exception.Message)
        exit 3
    }
    Write-Output ("  OK:   {0}" -f $p)
}
#endregion

#region --- 3. ExclusionProcess (cargo/rustc not blocked on artifact reads) ---
Write-Output "[3/3] Adding ExclusionProcess entries..."
foreach ($exe in $exclusionProcesses) {
    try {
        Add-MpPreference -ExclusionProcess $exe
    } catch {
        Write-Output ("  FAIL: {0} : {1}" -f $exe, $_.Exception.Message)
        exit 3
    }
    Write-Output ("  OK:   {0}" -f $exe)
}
#endregion

#region --- Verification: re-read Get-MpPreference and assert each value ---
Write-Output ""
Write-Output "=== Verification (re-reading live Defender state) ==="

try {
    $pref = Get-MpPreference
} catch {
    Write-Output ("FAIL: Get-MpPreference threw after configuration: {0}" -f $_.Exception.Message)
    exit 3
}

$checks = [System.Collections.Generic.List[object]]::new()

# MAPSReporting -- expect 0 (Disabled). Guard against $null (which would
# otherwise coerce to 0 and false-pass).
$mapsRaw = $pref.MAPSReporting
$mapsPass = ($null -ne $mapsRaw) -and ([int]$mapsRaw -eq 0)
$mapsActual = if ($null -eq $mapsRaw) { '<null>' } else { "{0}" -f [int]$mapsRaw }
$checks.Add([PSCustomObject]@{
    Setting  = 'MAPSReporting'
    Expected = '0 (Disabled)'
    Actual   = $mapsActual
    Pass     = $mapsPass
})

# SubmitSamplesConsent -- expect 2 (Never submit).
$consentRaw = $pref.SubmitSamplesConsent
$consentPass = ($null -ne $consentRaw) -and ([int]$consentRaw -eq 2)
$consentActual = if ($null -eq $consentRaw) { '<null>' } else { "{0}" -f [int]$consentRaw }
$checks.Add([PSCustomObject]@{
    Setting  = 'SubmitSamplesConsent'
    Expected = '2 (Never submit)'
    Actual   = $consentActual
    Pass     = $consentPass
})

# ExclusionPath -- every required path must be present. Force array form
# so a $null / single-value preference still iterates correctly. PS
# string -contains is case-insensitive by default, matching Windows
# case-insensitive path semantics.
$currentPaths = @($pref.ExclusionPath)
foreach ($p in $exclusionPaths) {
    $present = $currentPaths -contains $p
    $checks.Add([PSCustomObject]@{
        Setting  = 'ExclusionPath'
        Expected = $p
        Actual   = $(if ($present) { 'present' } else { 'MISSING' })
        Pass     = $present
    })
}

# ExclusionProcess -- every required process must be present.
$currentProcs = @($pref.ExclusionProcess)
foreach ($exe in $exclusionProcesses) {
    $present = $currentProcs -contains $exe
    $checks.Add([PSCustomObject]@{
        Setting  = 'ExclusionProcess'
        Expected = $exe
        Actual   = $(if ($present) { 'present' } else { 'MISSING' })
        Pass     = $present
    })
}

# Print the verification table.
$checks | Format-Table Setting, Expected, Actual, Pass -AutoSize

# Defender service / realtime status -- informational only, NOT gated.
# The release spec wants Defender to STAY ON; if an operator has
# separately disabled realtime, that is their decision and not a failure
# of this script.
Write-Output ""
Write-Output "Defender runtime status (informational -- NOT gated by this script):"
try {
    $status = Get-MpComputerStatus
    $status | Select-Object `
        RealTimeProtectionEnabled,
        DisableRealtimeMonitoring,
        AntivirusEnabled,
        AMRunningMode,
        AntivirusSignatureAge |
        Format-List
} catch {
    Write-Output ("  (could not read Get-MpComputerStatus: {0})" -f $_.Exception.Message)
}
#endregion

#region --- Final pass/fail ---
$failed = @($checks | Where-Object { -not $_.Pass })
if ($failed.Count -gt 0) {
    Write-Output ""
    Write-Output ("FAIL: {0} verification check(s) did not match expected values." -f $failed.Count)
    Write-Output "Re-run the script (it is idempotent); if the failure persists, inspect"
    Write-Output "the rows above and the Defender event log (Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational')."
    exit 3
}

Write-Output ""
Write-Output "PASS: all Defender release-environment settings verified."
exit 0
#endregion
