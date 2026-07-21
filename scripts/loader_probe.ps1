<#
.SYNOPSIS
    Driver for the reflective PIC blob loader probe (release-blocking gate).

.DESCRIPTION
    Builds the harness DLL (tools/loader_probe_dll), invokes it via rundll32
    with the wrapped PIC blob, polls for the result file, and parses the
    OK / FAIL line. Runs OUTSIDE the GH Actions runner agent process — a
    crash in the blob is caught by the harness DLL's Vectored Exception
    Handler and written to the result file before WER terminates the process.

    Invoked by: scripts/release/loader_probe_gate.ps1 -Blob <path>

    The blob is the output of scripts/release/wrap_blob.ps1 (a wrapped
    nyx-implant-win prod DLL via crates/nyx-loader/examples/wrap.rs).

    Result file contract (written by tools/loader_probe_dll/src/lib.rs):
      Location: $env:NYX_PROBE_RESULT, else C:\nyx\loader_probe_result.txt
      OK rv=0x<HEX>                        — stub returned cleanly
      FAIL stage=<stage> [code=0x<N> ...]  — harness or stub failed

.PARAMETER Blob
    Absolute or repo-relative path to the wrapped PIC blob (.bin).

.PARAMETER TimeoutSec
    Maximum seconds to wait for rundll32 + the blob to complete. The blob
    contains a reflective PE loader that calls DllMain then returns, so this
    should normally complete in under 2 seconds. Default 30s; bump if running
    under a debugger.

.EXAMPLE
    powershell -File scripts/loader_probe.ps1 -Blob staging/nyx_loader_blob.bin

.NOTES
    Exit codes:
      0  blob loaded + DllMain returned cleanly (result = OK)
      1  blob failed to load (result = FAIL, or harness crashed without result)
      2  arguments wrong
      3  harness DLL failed to build
      4  timeout waiting for result file
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Blob,

    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'

# ── Resolve paths ────────────────────────────────────────────────────────────

$repoRoot = (Get-Location).Path
$blobPath = if ([System.IO.Path]::IsPathRooted($Blob)) { $Blob } else { Join-Path $repoRoot $Blob }
$harnessDir = Join-Path $repoRoot 'tools\loader_probe_dll'
$harnessDll = Join-Path $harnessDir 'target\release\loader_probe.dll'
# Result file: prefer $env:NYX_PROBE_RESULT (lets CI point it inside the
# checkout's staging/ dir), else default to C:\nyx\loader_probe_result.txt
# (the manual SSH worktree, covered by setup_release_env.ps1 ExclusionPath).
$resultPath = if ($env:NYX_PROBE_RESULT) { $env:NYX_PROBE_RESULT } else { 'C:\nyx\loader_probe_result.txt' }

if (-not (Test-Path $blobPath)) {
    Write-Host "::error::blob not found: $blobPath"
    Write-Host '::error::Run scripts/release/wrap_blob.ps1 first.'
    exit 2
}

# ── Build harness DLL ────────────────────────────────────────────────────────

Write-Host '== loader_probe: building harness DLL =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see scripts/release/build_prod_dll.ps1.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
Push-Location $harnessDir
try {
    & cargo build --release 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "::error::harness DLL build failed (exit $LASTEXITCODE)."
        Write-Host '::error::Check the cargo output above for compile errors in tools/loader_probe_dll/src/lib.rs.'
        exit 3
    }
}
finally {
    $ErrorActionPreference = $prevEAP
    Pop-Location
}

if (-not (Test-Path $harnessDll)) {
    Write-Host "::error::cargo build reported success but $harnessDll is missing."
    exit 3
}
Write-Host "   harness DLL: $harnessDll ($((Get-Item $harnessDll).Length) bytes)"

# ── Reset state ──────────────────────────────────────────────────────────────

if (Test-Path $resultPath) {
    Remove-Item $resultPath -Force
}

# ── Invoke rundll32 in a fresh process ───────────────────────────────────────
#
# rundll32 convention: <dll_path>,<entrypoint> <arg>
# We do NOT wait synchronously — a bluescreen-inducing blob would hang the
# WaitForExit call and the runner. Instead we Start-Process with a timeout
# and poll the result file; even if the process is still "running" (hung in
# a fault handler), the result file is written before the process dies.

Write-Host "   invoking: rundll32.exe $harnessDll,nyx_probe_run `"$blobPath`""

$proc = Start-Process -FilePath 'rundll32.exe' `
    -ArgumentList "$harnessDll`,nyx_probe_run `"$blobPath`"" `
    -PassThru -WindowStyle Hidden -WorkingDirectory $repoRoot

Write-Host "   spawned rundll32 PID=$($proc.Id) — polling for result (timeout ${TimeoutSec}s)"

# ── Poll for result file ─────────────────────────────────────────────────────

$deadline = (Get-Date).AddSeconds($TimeoutSec)
$result = $null
while ((Get-Date) -lt $deadline) {
    if (Test-Path $resultPath) {
        $result = Get-Content $resultPath -Raw -ErrorAction SilentlyContinue
        if ($result) { break }
    }
    Start-Sleep -Milliseconds 250
}

# Reap the process (best-effort — may have already exited or crashed).
if (-not $proc.HasExited) {
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
}

# ── Parse result ─────────────────────────────────────────────────────────────

if (-not $result) {
    Write-Host "::error::no result file written within ${TimeoutSec}s — blob likely bluescreened or hung the harness."
    Write-Host '::error::Check Get-WinEvent System log + any WER crash dumps for rundll32.exe.'
    exit 4
}

$result = $result.Trim()
Write-Host "   result: $result"

if ($result -like 'OK *') {
    Write-Host '== loader_probe: PASS — reflective blob loaded + DllMain executed =='
    exit 0
}

# FAIL — extract the stage for actionable diagnostics.
if ($result -like 'FAIL stage=invoke *') {
    Write-Host '::error::blob crashed during execution (VEH caught the exception).'
    Write-Host '::error::This is expected during reflective loader iteration — inspect the failing stage below.'
}
elseif ($result -like 'FAIL stage=read *') {
    Write-Host '::error::harness could not read the blob file.'
}
elseif ($result -like 'FAIL stage=alloc *') {
    Write-Host '::error::harness VirtualAlloc(RWX) failed — likely system policy (e.g. ACG/CFG forced).'
}
elseif ($result -like 'FAIL stage=veh *') {
    Write-Host '::error::harness could not register vectored exception handler — proceeding would be unsafe.'
}

Write-Host "::error::loader probe FAILED: $result"
exit 1
