# loader_probe_gate.ps1 — release-blocking gate that verifies the reflective
# PIC blob actually loads + executes in a real (non-CI-agent) process.
#
# The actual probe logic lives in scripts/loader_probe.ps1 (spec §5.5):
#   1. Takes the wrapped blob (crates/nyx-loader/target/release/nyx_loader_blob.bin).
#   2. Spawns a short-lived harness process (rundll32 + tools/loader_probe_dll/)
#      that VirtualAlloc(RWX) + memcpy(blob) + jumps to the blob entry. Running
#      OUTSIDE the runner agent process means a crash is caught by the harness
#      DLL's Vectored Exception Handler, not by the runner.
#   3. Writes a result marker (OK rv=0x<HEX> | FAIL stage=<stage>) to the
#      result file ($env:NYX_PROBE_RESULT, else C:\nyx\loader_probe_result.txt).
#   4. Returns 0 on OK, nonzero on FAIL.
#
# FAIL-CLOSED CONTRACT (this gate must NEVER skip silently):
#   The release step FAILS if ANY of these hold:
#     * the probe script is missing,
#     * the blob is missing,
#     * the probe did not actually run (no exit code captured),
#     * the probe exited nonzero,
#     * the probe result file is missing after the run, or
#     * the result file content is not an `OK ...` line.
#   In particular the gate does NOT trust the probe's exit code alone: it
#   independently verifies the result file was written and parsed as OK, so a
#   tampered/skipped probe can never pass by exiting 0 without doing work.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

# ---- integration knobs ----
$PROBE_SCRIPT = 'scripts\loader_probe.ps1'
$BLOB_PATH    = 'crates\nyx-loader\target\release\nyx_loader_blob.bin'

# Result file contract — MUST match scripts/loader_probe.ps1 exactly.
# Location: $env:NYX_PROBE_RESULT, else C:\nyx\loader_probe_result.txt
$resultPath = if ($env:NYX_PROBE_RESULT) { $env:NYX_PROBE_RESULT } else { 'C:\nyx\loader_probe_result.txt' }

if (-not (Test-Path $PROBE_SCRIPT)) {
    Write-Host "::error::loader probe script not found: $PROBE_SCRIPT"
    Write-Host '::error::This is provided by the nyx-loader owner (crates/nyx-loader + scripts/loader_probe.ps1). See spec §5.5.'
    exit 1
}

if (-not (Test-Path $BLOB_PATH)) {
    Write-Host "::error::blob not found at $BLOB_PATH — run wrap_blob.ps1 first."
    exit 1
}

# ---- pre-run state: a stale result file must never satisfy this gate ----
# loader_probe.ps1 also removes it, but we remove it here so the gate's own
# post-run verification can only see a result THIS invocation produced.
if (Test-Path $resultPath) {
    Write-Host "   removing stale probe result file: $resultPath"
    Remove-Item $resultPath -Force
}

Write-Host '== loader_probe_gate: invoking scripts/loader_probe.ps1 =='
# Delegate. We pass the blob path as -Blob so the probe doesn't have to guess
# where wrap_blob.ps1 put it.
$probeExit = $null
& powershell -ExecutionPolicy Bypass -File $PROBE_SCRIPT -Blob $BLOB_PATH
$probeExit = $LASTEXITCODE

# ---- fail-closed checks (independent of each other; any failure blocks) ----

# 1. The probe must have actually run. $probeExit is $null when the child
#    process never executed (e.g. powershell not on PATH) — do not let a
#    stale/absent $LASTEXITCODE pass as success.
if ($null -eq $probeExit) {
    Write-Host '::error::loader probe did not run (no exit code captured from the child process).'
    Write-Host '::error::This is release-blocking: the reflective blob was NOT validated.'
    exit 1
}

# 2. The probe must have reported success.
if ($probeExit -ne 0) {
    Write-Host "::error::loader probe FAILED (exit $probeExit). The reflective blob did not load+execute cleanly."
    Write-Host '::error::This is release-blocking: a blob that fails to reflectively load is unusable on-target.'
    Write-Host '::error::Inspect the probe output above + any WER crash dump for the harness process.'
    exit 1
}

# 3. The result file must exist — an OK exit code with no result file means
#    the probe did not actually exercise the blob (silent skip).
if (-not (Test-Path $resultPath)) {
    Write-Host "::error::loader probe exited 0 but wrote no result file at $resultPath."
    Write-Host '::error::This is release-blocking: without a probe result the blob was NOT validated.'
    exit 1
}

# 4. The result content must be an OK line. Anything else (FAIL, garbage,
#    empty) is a failed probe — never a silent pass.
$result = (Get-Content $resultPath -Raw -ErrorAction Stop).Trim()
Write-Host "   probe result: $result"
if ($result -notlike 'OK *') {
    Write-Host "::error::loader probe result is not OK: '$result'"
    Write-Host '::error::This is release-blocking: the reflective blob did not load+execute cleanly.'
    exit 1
}

Write-Host '== loader_probe_gate OK: probe ran, result file verified, reflective blob loaded + DllMain executed =='
