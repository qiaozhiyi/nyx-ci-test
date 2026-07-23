# build_prod_dll.ps1 — release build of the production nyx-implant-win DLL.
#
# Mirrors the "Build implant DLL (nightly)" step of .github/workflows/windows-ci.yml
# with ONE change: the --features selftest flag is dropped. Production builds must
# carry only the 4 operational exports (DllMain, nyx_entry, nyx_entry_noevasion,
# nyx_screenshot_session — see CHANGELOG 0.2.0 "Production DLL export surface
# reduced to 4 exports"). The selftest exports are an avoidable detection surface
# and are built separately into the selftest DLL by build_selftest_dll.ps1.
#
# Toolchain: nightly (implant-win is !no_std PIC, requires -Zbuild-std-family
# features the stable toolchain does not expose for the MSVC target).
# Target:    x86_64-pc-windows-msvc (matches windows-ci.yml; MSVC linker, not GNU).
# Manifest:  standalone crate (NOT a workspace member — see crates/implant-win/Cargo.toml
#            note + root Cargo.toml) so --manifest-path is mandatory.
#
# Output: crates/implant-win/target/x86_64-pc-windows-msvc/release/nyx_implant_win.dll
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

# Ensure the nightly toolchain + rust-src + the MSVC target are present. Same
# invocation as windows-ci.yml (collapsed into one rustup call so a missing
# toolchain doesn't fail mid-build on a freshly-registered runner).
Write-Host '== build_prod_dll: ensure nightly + rust-src + msvc target =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP: rustup writes progress ("info: syncing
# channel updates...") to stderr (standard Unix convention). PowerShell 5.1,
# under $ErrorActionPreference='Stop', throws a NativeCommandError
# RemoteException the moment the FIRST stderr line appears — BEFORE the
# command finishes, regardless of $LASTEXITCODE. `2>&1` does NOT fix this:
# PS intercepts the stderr stream before the redirect applies.
#
# The real fix is to temporarily relax EAP for the rustup/cargo calls so
# stderr writes don't escalate to terminating errors. We use a try/finally
# to guarantee EAP is restored even on exit/throw.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & rustup toolchain install nightly --component rust-src --no-self-update 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::rustup nightly install failed'; exit 1 }
    & rustup target add x86_64-pc-windows-msvc --toolchain nightly 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::rustup target add failed'; exit 1 }

    Write-Host '== build_prod_dll: cargo +nightly build (prod, NO selftest feature) =='
    & cargo +nightly build --release --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-msvc 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::prod implant DLL build failed'; exit 1 }
}
finally {
    $ErrorActionPreference = $prevEAP
}

$dll = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win.dll'
if (-not (Test-Path $dll)) {
    Write-Host "::error::expected output not found: $dll"
    exit 1
}
$size = (Get-Item $dll).Length
Write-Host ("== build_prod_dll OK: {0} ({1} bytes) ==" -f $dll, $size)
