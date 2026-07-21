# build_selftest_dll.ps1 — release build of the selftest nyx-implant-win DLL.
#
# Identical to build_prod_dll.ps1 PLUS --features selftest. The selftest feature
# (crates/implant-win/Cargo.toml) un-gates the ~50 #[no_mangle] nyx_selftest_*
# rundll32 exports; without it rundll32 reports "missing entry" and every test
# looks like it failed. selftest_gate.ps1 runs against THIS DLL.
#
# We rename the output to nyx_implant_win_selftest.dll so it does NOT clobber
# the prod DLL when both are staged side by side (stage_assets.ps1 ships both).
# This rename is local to the release pipeline — the build itself still emits
# nyx_implant_win.dll into the target/ dir (the rename happens after).
#
# Toolchain / target / manifest-path rationale: see build_prod_dll.ps1 header.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

Write-Host '== build_selftest_dll: ensure nightly + rust-src + msvc target =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see build_prod_dll.ps1 for full comment.
# TL;DR: EAP=Stop + native command writes stderr = RemoteException on first
# byte. Fix: relax EAP for the rustup/cargo block; restore in finally.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & rustup toolchain install nightly --component rust-src --no-self-update 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::rustup nightly install failed'; exit 1 }
    & rustup target add x86_64-pc-windows-msvc --toolchain nightly 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::rustup target add failed'; exit 1 }

    Write-Host '== build_selftest_dll: cargo +nightly build (release + selftest feature) =='
    & cargo +nightly build --release --features selftest --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-msvc 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::selftest implant DLL build failed'; exit 1 }
}
finally {
    $ErrorActionPreference = $prevEAP
}

$dll = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win.dll'
if (-not (Test-Path $dll)) {
    Write-Host "::error::expected output not found: $dll"
    exit 1
}

# Rename to a selftest-specific name in-place. The next stage_assets.ps1 will
# copy BOTH the prod DLL (nyx_implant_win_prod.dll) and this selftest DLL into
# staging/. Keeping them under distinct names avoids the clobber trap.
$selftestDll = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win_selftest.dll'
Copy-Item -Path $dll -Destination $selftestDll -Force
$size = (Get-Item $selftestDll).Length
Write-Host ("== build_selftest_dll OK: {0} ({1} bytes) ==" -f $selftestDll, $size)
