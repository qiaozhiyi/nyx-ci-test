# vm_bootstrap.ps1 — one-shot prep for the Route-A local Windows VM (run IN the VM, elevated).
#
# What it does:
#   1. installs + starts the inbox OpenSSH Server (so the existing macOS-side
#      harness scripts/win_remote_run.sh works against the VM unchanged)
#   2. authorizes your macOS public key (administrators_authorized_keys, correct ACL)
#   3. opens firewall port 22, disables sleep, creates C:\nyx
#   4. prints the VM IPv4 address + a READY marker
#
# Usage (elevated PowerShell in the VM):
#   powershell -ExecutionPolicy Bypass -File vm_bootstrap.ps1 -PubKey "ssh-ed25519 AAAA... you@mac"
#   powershell -ExecutionPolicy Bypass -File vm_bootstrap.ps1 -PubKeyUrl "http://192.168.64.1:8899/id.pub"
#
# -PubKeyUrl is the fallback when clipboard sharing is not working yet: on the Mac
# run `python3 -m http.server 8899 --bind 0.0.0.0` in the folder holding the .pub file
# and pass its URL (192.168.64.1 = macOS host on UTM shared networking).
[CmdletBinding()]
param(
    [string]$PubKey = "",
    [string]$PubKeyUrl = "",
    [switch]$SkipSsh
)

$ErrorActionPreference = 'Stop'

function Step($msg) { Write-Output "==> $msg" }

# --- admin check ---
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: run this from an ELEVATED PowerShell (Run as administrator)"
    exit 1
}

Step "creating C:\nyx working dir"
New-Item -ItemType Directory -Path C:\nyx -Force | Out-Null

Step "disabling sleep / display timeout (AC)"
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

if (-not $SkipSsh) {
    Step "installing OpenSSH Server capability (idempotent)"
    $cap = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }

    Step "starting sshd + autostart"
    Set-Service sshd -StartupType Automatic
    Start-Service sshd

    Step "ensuring firewall rule for port 22"
    $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($rule) {
        Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'
    } else {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }

    # --- pubkey provisioning ---
    $key = $PubKey
    if (-not $key -and $PubKeyUrl) {
        Step "fetching pubkey from $PubKeyUrl"
        $key = (Invoke-WebRequest -UseBasicParsing -Uri $PubKeyUrl).Content.Trim()
    }
    if ($key) {
        Step "installing pubkey into administrators_authorized_keys"
        $akf = "C:\ProgramData\ssh\administrators_authorized_keys"
        # append only if not already present
        $existing = if (Test-Path $akf) { Get-Content $akf -Raw } else { "" }
        if ($existing -notmatch [regex]::Escape($key)) {
            Add-Content -Path $akf -Value $key -Encoding ascii
        }
        # required ACL: SYSTEM + Administrators only, or sshd ignores the file
        icacls $akf /inheritance:r | Out-Null
        icacls $akf /grant 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
    } else {
        Write-Output "NOTE: no -PubKey/-PubKeyUrl given — password auth still works, but"
        Write-Output "      scripts/win_remote_run.sh uses BatchMode=yes (key auth required)."
        Write-Output "      re-run with -PubKey later to enable it."
    }
}

Step "network interfaces (use the 192.168.64.x one for WIN_HOST)"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    ForEach-Object { Write-Output ("    {0}  ({1})" -f $_.IPAddress, $_.InterfaceAlias) }

$defender = Get-MpComputerStatus
Write-Output ("==> Defender: RealTimeProtection={0} AntivirusEnabled={1} (leave ON for the realistic pass)" -f
    $defender.RealTimeProtectionEnabled, $defender.AntivirusEnabled)

Write-Output ""
Write-Output "READY: VM bootstrap complete."
Write-Output "NEXT on the Mac:"
Write-Output "  1. ssh <user>@<vm-ip> hostname        # key auth sanity check"
Write-Output "  2. WIN_HOST=<vm-ip> ./scripts/win_remote_run.sh all"
