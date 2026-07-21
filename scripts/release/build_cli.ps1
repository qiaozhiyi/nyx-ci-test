# build_cli.ps1 — release build of the operator-side kernel-tier CLI
# (nyx-operator-kernel-cli). Stable Rust, no special target.
#
# This crate is STANDALONE (own [workspace] in Cargo.toml — operator-kernel-cli
# pulls in operator-kernelsdk + minidump-assembler which are also standalone,
# decoupling it from the root workspace's no_std implant members). So
# --manifest-path is mandatory; `cargo build -p nyx-operator-kernel-cli` from the
# root would NOT work (the crate is invisible to the root workspace).
#
# Binary names (from crates/operator-kernel-cli/Cargo.toml [[bin]] stanzas):
#   nyx-kernel       (main operator CLI — bootstrap / resolve / assemble_tier)
#   cfg-write        (write per-engagement config blob)
#   probe-offsets    (offset-probe dev tool)
#   probe2           (secondary probe dev tool)
#   find-bitmap      (bitmap scan dev tool)
# All five are emitted to crates/operator-kernel-cli/target/release/.
#
# Mirrors the "Build operator CLI + offset-resolver (stable)" step in
# windows-ci.yml. Stage_assets.ps1 tars these *.exe into nyx-cli-windows.tar.gz.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

Write-Host '== build_cli: cargo build --release operator-kernel-cli =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see build_prod_dll.ps1. cargo writes
# compile progress to stderr; EAP=Stop would throw NativeCommandError on the
# first stderr byte. Relax EAP for the cargo call; restore in finally.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & cargo build --release --manifest-path crates/operator-kernel-cli/Cargo.toml 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::operator-kernel-cli build failed'; exit 1 }
}
finally {
    $ErrorActionPreference = $prevEAP
}

$binDir = 'crates\operator-kernel-cli\target\release'
if (-not (Test-Path $binDir)) {
    Write-Host "::error::build output dir not found: $binDir"
    exit 1
}

# Enumerate the freshly-built .exe files (and their PDBs). The [[bin]] stanzas
# list five binaries; we report whatever cargo actually emitted so a missing
# or extra binary is visible in the release log.
$exes = Get-ChildItem -Path $binDir -Filter '*.exe' -File
if ($exes.Count -eq 0) {
    Write-Host "::error::no .exe files produced in $binDir"
    exit 1
}
Write-Host 'Built executables:'
foreach ($e in $exes) {
    Write-Host ("  {0,-30} {1,10} bytes" -f $e.Name, $e.Length)
}
Write-Host ("== build_cli OK: {0} exe(s) ==" -f $exes.Count)
