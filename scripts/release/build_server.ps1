# build_server.ps1 — release build of the Nyx team server (nyx-server).
#
# Unlike implant-win / operator-kernel-cli / offset-resolver, nyx-server IS a
# root workspace member (see root Cargo.toml members list + crates/server/Cargo.toml
# `version.workspace = true`). This gives us a choice:
#   (a) `cargo build --release --manifest-path crates/server/Cargo.toml`, or
#   (b) `cargo build -p nyx-server --release` from the repo root.
#
# We pick (b): -p from the root workspace. Reasons:
#   1. It is the idiomatic way to build a single workspace member and keeps the
#      server's build outputs in the shared root target/ (which verify_env.ps1
#      excludes from Defender via the root 'target' ExclusionPath).
#   2. -p names the package unambiguously; --manifest-path would break if the
#      crate ever moves dirs.
#   3. -p resolves workspace deps (nyx-store, nyx-rest, nyx-transport, ...) via
#      the shared Cargo.lock, guaranteeing reproducibility across the matrix.
#
# Binary name: nyx-server (crates/server/Cargo.toml [[bin]] stanza). Emitted to
# the root target/release/. stage_assets.ps1 tars it into nyx-server-windows.tar.gz.
#
# Stable Rust, no special target.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

Write-Host '== build_server: cargo build -p nyx-server --release (workspace member) =='
# PS 5.1 NATIVE-COMMAND STDERR TRAP — see build_prod_dll.ps1.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & cargo build -p nyx-server --release 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host '::error::nyx-server build failed'; exit 1 }
}
finally {
    $ErrorActionPreference = $prevEAP
}

# The shared workspace target dir: root/target/release/. (Cargo respects the
# nearest workspace root [workspace] [profile.release] for output location.)
$binDir = 'target\release'
$serverExe = Join-Path $binDir 'nyx-server.exe'
if (-not (Test-Path $serverExe)) {
    # Defensive: if a future change moves the crate out of the workspace, fall
    # back to its own target/ dir. This surfaces the divergence loudly instead
    # of silently producing a tarball with no server binary.
    $fallback = 'crates\server\target\release\nyx-server.exe'
    if (Test-Path $fallback) {
        Write-Host "::warning::nyx-server.exe found at $fallback, not $serverExe — is the crate still a workspace member?"
        $serverExe = $fallback
        $binDir = Split-Path $fallback
    } else {
        Write-Host "::error::nyx-server.exe not found at $serverExe (or fallback $fallback)"
        exit 1
    }
}
$size = (Get-Item $serverExe).Length
Write-Host ("== build_server OK: {0} ({1} bytes) ==" -f $serverExe, $size)
