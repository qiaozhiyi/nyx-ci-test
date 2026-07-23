# loader_probe_gate.ps1 — release-blocking gate that verifies the reflective
# PIC blob actually loads + executes in a real (non-CI-agent) process.
#
# DEPENDENCY ON T1 (crates/nyx-loader + scripts/loader_probe.ps1):
#   The actual probe logic is owned by T1 per spec §5.5 + §7 task table.
#   T1's scope is `crates/nyx-loader/**`. The probe driver script
#   `scripts/loader_probe.ps1` lives at the top level of scripts/ (NOT under
#   scripts/release/) and is ambiguous in the spec's task split — but it is
#   the artifact T1 produces to validate the loader it just wrote. This gate
#   is a thin STUB that delegates to scripts/loader_probe.ps1 and fails
#   clearly if T1 has not yet provided it.
#
#   Until T1 lands scripts/loader_probe.ps1, this gate fails with a clear
#   "file not found" error. Integration note: if T1 names the probe script
#   differently or moves it, update $PROBE_SCRIPT below.
#
# What the probe does (spec §5.5, T1's job to implement):
#   1. Takes the wrapped blob (staging/nyx_loader_blob.bin) and the prod DLL.
#   2. Spawns a short-lived harness process (rundll32 + tools/loader_probe_dll/
#      or a dedicated exe) that VirtualAlloc(RWX) + memcpy(blob) + jumps to the
#      blob entry. Running OUTSIDE the runner agent process means a crash is
#      caught by Windows Error Reporting, not by the runner.
#   3. Writes a result marker (OK <dllmain_rv> | FAIL <stage>).
#   4. Returns 0 on OK, nonzero on FAIL (the gate fails the release).
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

# ---- T1 integration knobs ----
$PROBE_SCRIPT = 'scripts\loader_probe.ps1'
$BLOB_PATH    = 'crates\nyx-loader\target\release\nyx_loader_blob.bin'

if (-not (Test-Path $PROBE_SCRIPT)) {
    Write-Host "::error::loader probe script not found: $PROBE_SCRIPT"
    Write-Host '::error::This is provided by T1 (crates/nyx-loader owner). See spec §5.5.'
    Write-Host '::error::Until T1 lands scripts/loader_probe.ps1, the loader probe gate cannot run.'
    exit 1
}

if (-not (Test-Path $BLOB_PATH)) {
    Write-Host "::error::blob not found at $BLOB_PATH — run wrap_blob.ps1 first."
    exit 1
}

Write-Host '== loader_probe_gate: invoking scripts/loader_probe.ps1 (T1) =='
# Delegate. We pass the blob path as -Blob so T1's script doesn't have to guess
# where wrap_blob.ps1 put it. (If T1's script uses a different param name, this
# is the integration point to adjust.)
& powershell -ExecutionPolicy Bypass -File $PROBE_SCRIPT -Blob $BLOB_PATH
$probeExit = $LASTEXITCODE
if ($probeExit -ne 0) {
    Write-Host "::error::loader probe FAILED (exit $probeExit). The reflective blob did not load+execute cleanly."
    Write-Host '::error::This is release-blocking: a blob that fails to reflectively load is unusable on-target.'
    Write-Host '::error::Inspect the probe output above + any WER crash dump for the harness process.'
    exit 1
}
Write-Host '== loader_probe_gate OK: reflective blob loaded + DllMain executed =='
