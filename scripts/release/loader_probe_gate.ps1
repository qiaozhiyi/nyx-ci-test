# loader_probe_gate.ps1 — release-blocking gate for the reflective PIC blob.
#
# Two legs, run in order:
#
#   LEG 1 (MANDATORY — always runs): Unicorn emulator probe
#     `python3 tools/loader-emu/loader_emu.py` executes the REAL Layer-1 bytes
#     (parsed straight out of crates/nyx-loader/src/on_target.rs — single
#     source of truth, zero drift) in a Unicorn x86-64 emulator and asserts the
#     magic-present handoff + magic-absent bail contracts. It is Windows-free —
#     it runs on any host, including the Session-0 GitHub hosted runners where
#     rundll32 hangs — so it is the authoritative loader gate in release.yml.
#     When the probe supports full-blob mode (`--blob <path>`), the wrapped
#     blob from wrap_blob.ps1 is also fed in so the decrypt+map+DllMain path is
#     validated end-to-end (exit 0 = all probes pass, 1 = any failure).
#
#   LEG 2 (OPTIONAL — -InteractiveProbe): rundll32 harness probe
#     `scripts/loader_probe.ps1` spawns a short-lived rundll32 +
#     tools/loader_probe_dll/ harness that VirtualAlloc(RWX) + memcpy(blob) +
#     jumps to the blob entry, and writes a result marker
#     (OK rv=0x<HEX> | FAIL stage=<stage>) to the result file
#     ($env:NYX_PROBE_RESULT, else C:\nyx\loader_probe_result.txt). It requires
#     an interactive Windows session (rundll32 hangs in Session 0 on hosted
#     runners), so it is opt-in and NEVER runs implicitly.
#
# FAIL-CLOSED CONTRACT (a leg that runs must NEVER pass silently):
#   * Leg 1 fails if the emu probe script is missing, python3 is unavailable,
#     the probe did not actually run (no exit code captured), or it exited
#     nonzero.
#   * Leg 2 fails if the probe script is missing, the blob is missing, the
#     probe did not actually run, it exited nonzero, the result file is
#     missing after the run, or the result file content is not an `OK rv=0x0`
#     line (rv must be 0 — the legacy bare-'OK *' check passed any return
#     value). In particular Leg 2 does NOT trust the probe's exit code alone:
#     it independently verifies the result file was written and parsed as a
#     clean zero return, so a tampered/skipped probe can never pass by exiting
#     0 without doing work.
#
# Assumes CWD = repo root. PowerShell 5.1.
param(
    # Run the interactive rundll32 leg after the emu leg passes. Requires an
    # interactive Windows session; hosted runners (Session 0) must not set it.
    [switch]$InteractiveProbe
)

$ErrorActionPreference = 'Stop'

# ---- integration knobs ----
$EMU_SCRIPT   = 'tools\loader-emu\loader_emu.py'
$PROBE_SCRIPT = 'scripts\loader_probe.ps1'
$BLOB_PATH    = 'crates\nyx-loader\target\release\nyx_loader_blob.bin'

# Result file contract — MUST match scripts/loader_probe.ps1 exactly.
# Location: $env:NYX_PROBE_RESULT, else C:\nyx\loader_probe_result.txt
$resultPath = if ($env:NYX_PROBE_RESULT) { $env:NYX_PROBE_RESULT } else { 'C:\nyx\loader_probe_result.txt' }

# ===========================================================================
# LEG 1 — Unicorn emulator probe (mandatory, Windows-free)
# ===========================================================================
if (-not (Test-Path $EMU_SCRIPT)) {
    Write-Host "::error::loader emu probe script not found: $EMU_SCRIPT"
    Write-Host '::error::This is provided by the nyx-loader owner (tools/loader-emu/loader_emu.py).'
    exit 1
}
$python3 = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python3) {
    Write-Host '::error::python3 not found on PATH — the Unicorn emu probe cannot run.'
    Write-Host '::error::This is release-blocking: the loader Layer-1 contracts were NOT validated.'
    exit 1
}

Write-Host '== loader_probe_gate: LEG 1 — Unicorn emu probe (tools/loader-emu/loader_emu.py) =='
# Full-blob mode is opt-in via `--blob <path>` (loader-probe contract). Pass
# the wrapped blob when the script supports it; otherwise run bare
# (Layer-1-only), which is the current contract.
$emuSupportsBlob = [bool](Select-String -Path $EMU_SCRIPT -Pattern '--blob' -Quiet)
$emuArgs = @($EMU_SCRIPT)
if ($emuSupportsBlob) {
    if (Test-Path $BLOB_PATH) {
        $emuArgs += @('--blob', $BLOB_PATH)
    } else {
        Write-Host "   ::notice::blob not found at $BLOB_PATH — full-blob emu probe skipped (Layer-1 tests still run)."
    }
}

$emuExit = $null
& python3 @emuArgs
$emuExit = $LASTEXITCODE

# 1. The emu probe must have actually run. $emuExit is $null when the child
#    process never executed (e.g. python3 not on PATH) — do not let a
#    stale/absent $LASTEXITCODE pass as success.
if ($null -eq $emuExit) {
    Write-Host '::error::loader emu probe did not run (no exit code captured from the child process).'
    Write-Host '::error::This is release-blocking: the loader Layer-1 contracts were NOT validated.'
    exit 1
}

# 2. The emu probe must have reported success (exit 0 = all probes pass).
if ($emuExit -ne 0) {
    Write-Host "::error::loader emu probe FAILED (exit $emuExit). Layer-1 handoff/bail contracts violated."
    Write-Host '::error::This is release-blocking: the reflective loader is not shippable.'
    Write-Host '::error::(missing python dependency? install with: python3 -m pip install --user unicorn)'
    exit 1
}
Write-Host '== loader_probe_gate: emu probe PASSED =='

# ===========================================================================
# LEG 2 — interactive rundll32 probe (OPTIONAL, -InteractiveProbe)
# ===========================================================================
if (-not $InteractiveProbe) {
    Write-Host '== loader_probe_gate: LEG 2 (rundll32 harness) SKIPPED — pass -InteractiveProbe on an interactive Windows session =='
} else {
    if (-not (Test-Path $PROBE_SCRIPT)) {
        Write-Host "::error::loader probe script not found: $PROBE_SCRIPT"
        Write-Host '::error::This is provided by the nyx-loader owner (scripts/loader_probe.ps1). See spec §5.5.'
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

    Write-Host '== loader_probe_gate: LEG 2 — invoking scripts/loader_probe.ps1 =='
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
    if ($result -notlike 'OK rv=0x*') {
        Write-Host "::error::loader probe result is not OK: '$result'"
        Write-Host '::error::This is release-blocking: the reflective blob did not load+execute cleanly.'
        exit 1
    }
    # STRICT: the blob entry must return 0 (clean DllMain → return path). The
    # legacy bare-'OK *' check passed ANY return value; the harness records
    # `OK rv=0x<N>` for every non-crash, so a nonzero N is a fail.
    if ($result -match '^OK rv=0x([0-9A-Fa-f]+)') {
        $rv = [Convert]::ToUInt64($matches[1], 16)
        if ($rv -ne 0) {
            Write-Host "::error::loader probe result rv=0x$($matches[1]) — expected 0. Reflective blob did not return cleanly."
            Write-Host '::error::This is release-blocking: a nonzero return means the blob entry did not complete its contract.'
            exit 1
        }
    } else {
        Write-Host "::error::loader probe result has no parseable rv field: '$result'"
        Write-Host '::error::This is release-blocking: cannot verify a clean return.'
        exit 1
    }
    Write-Host '== loader_probe_gate: interactive rundll32 probe PASSED =='
}

Write-Host '== loader_probe_gate OK: emu probe passed (interactive rundll32 probe passed when requested) =='
