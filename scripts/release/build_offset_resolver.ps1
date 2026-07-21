# build_offset_resolver.ps1 — release build of the offset-resolver
# (nyx-offset-resolver). Stable Rust, no special target.
#
# This crate is STANDALONE (own [workspace] in Cargo.toml — operator-side tool
# that downloads ntoskrnl.pdb from the MS symbol server and parses out the
# EPROCESS + ETW-TI offsets; kept decoupled from the root workspace's no_std
# implant members). So --manifest-path is mandatory.
#
# Binary name: nyx-offset-resolver (crates/offset-resolver/Cargo.toml [[bin]]
# stanza). Emitted to crates/offset-resolver/target/release/.
#
# Mirrors the offset-resolver half of windows-ci.yml's "Build operator CLI +
# offset-resolver (stable)" step. stage_assets.ps1 tars it into
# offset-resolver-windows.tar.gz.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

Write-Host '== build_offset_resolver: cargo build --release offset-resolver =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see build_prod_dll.ps1.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & cargo build --release --manifest-path crates/offset-resolver/Cargo.toml 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::offset-resolver build failed'; exit 1 }
}
finally {
    $ErrorActionPreference = $prevEAP
}

$binDir = 'crates\offset-resolver\target\release'
$resolverExe = Join-Path $binDir 'nyx-offset-resolver.exe'
if (-not (Test-Path $resolverExe)) {
    Write-Host "::error::nyx-offset-resolver.exe not found at $resolverExe"
    exit 1
}
$size = (Get-Item $resolverExe).Length
Write-Host ("== build_offset_resolver OK: {0} ({1} bytes) ==" -f $resolverExe, $size)
