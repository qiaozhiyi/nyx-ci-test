# stage_assets.ps1 — collect every release artifact into staging/, package the
# EXE groups into tarballs, and emit staging/SHA256SUMS over the final set.
#
# Asset manifest (spec §6.4):
#   staging/nyx_implant_win_prod.dll        — from build_prod_dll.ps1
#   staging/nyx_implant_win_selftest.dll    — from build_selftest_dll.ps1
#   staging/nyx_loader_blob.bin             — from wrap_blob.ps1
#   staging/nyx-server-windows.tar.gz       — server exe (+ config templates if present)
#   staging/nyx-cli-windows.tar.gz          — operator-kernel-cli exes
#   staging/offset-resolver-windows.tar.gz  — offset-resolver exes
#   staging/SHA256SUMS                      — checksums of all of the above
#
# Tarball format: tar (bsdtar on Server 2019) -czf. We use tar rather than
# Compress-Archive so operators on Linux/macOS can extract natively; zip would
# also work but tar.gz is the convention for cross-platform Rust release assets.
# Server 2019 ships tar.exe in System32 (since 1809) — no extra dep needed.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

$staging = 'staging'
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# Tag for naming tarballs. We do NOT hardcode a version — derive from the GitHub
# ref (e.g. 'v0.3.0'). Falls back to 'untagged' for manual local runs.
$tag = $env:GITHUB_REF_NAME
if ([string]::IsNullOrEmpty($tag)) { $tag = 'untagged' }
Write-Host ("== stage_assets: tag={0} ==" -f $tag)

# ---- 1. Prod DLL ----
$prodDllSrc = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win.dll'
if (-not (Test-Path $prodDllSrc)) { Write-Host "::error::missing prod DLL: $prodDllSrc"; exit 1 }
Copy-Item $prodDllSrc (Join-Path $staging 'nyx_implant_win_prod.dll') -Force

# ---- 2. Selftest DLL ----
$selftestDllSrc = 'crates\implant-win\target\x86_64-pc-windows-msvc\release\nyx_implant_win_selftest.dll'
if (-not (Test-Path $selftestDllSrc)) { Write-Host "::error::missing selftest DLL: $selftestDllSrc"; exit 1 }
Copy-Item $selftestDllSrc (Join-Path $staging 'nyx_implant_win_selftest.dll') -Force

# ---- 3. Reflective blob ----
$blobSrc = 'crates\nyx-loader\target\release\nyx_loader_blob.bin'
if (-not (Test-Path $blobSrc)) { Write-Host "::error::missing blob: $blobSrc"; exit 1 }
Copy-Item $blobSrc (Join-Path $staging 'nyx_loader_blob.bin') -Force

# ---- helper: build a tar.gz from a list of files into staging ----
# Uses tar.exe (System32 on Server 2019+). We stage the inputs into a temp dir
# so the tarball contains clean relative paths (no repo-root prefixes).
function New-ReleaseTarball {
    param(
        [string]$Name,            # output filename in staging/
        [string[]]$Inputs         # absolute or relative paths to include
    )
    $tmp = Join-Path $env:TEMP "nyx_stage_$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        foreach ($f in $Inputs) {
            if (-not (Test-Path $f)) {
                Write-Host "::error::tarball input missing: $f"
                throw "missing input $f"
            }
            Copy-Item $f $tmp -Force
        }
        $out = Join-Path $staging $Name
        # -C changes dir so paths inside the tarball are flat. -czf = gzip.
        & tar.exe -C $tmp -czf $out *
        if ($LASTEXITCODE -ne 0) { Write-Host "::error::tar failed for $Name"; throw "tar failed" }
        Write-Host ("  staged {0} ({1} bytes)" -f $Name, (Get-Item $out).Length)
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# ---- 4. CLI tarball (all 5 exes + pdbs if present) ----
$cliDir = 'crates\operator-kernel-cli\target\release'
$cliInputs = Get-ChildItem -Path $cliDir -File | Where-Object { $_.Extension -in '.exe','.pdb' } | ForEach-Object { $_.FullName }
if ($cliInputs.Count -eq 0) { Write-Host "::error::no CLI exes in $cliDir"; exit 1 }
New-ReleaseTarball -Name 'nyx-cli-windows.tar.gz' -Inputs $cliInputs

# ---- 5. Server tarball (server exe + config templates if any) ----
# Server config templates: the spec §6.4 manifest lists "server + config
# templates". As of 2026-07-21 the server crate has no shipped config template
# files (crates/server has no config/ dir, .toml.example, or .yaml). The server
# reads config from env vars + CLI flags at runtime. We therefore tar just the
# exe today; if config templates are added later (e.g. crates/server/config/*.toml.example)
# they will be picked up automatically by the glob below.
$serverExe = 'target\release\nyx-server.exe'
$serverFallback = 'crates\server\target\release\nyx-server.exe'
$serverInputs = @()
if (Test-Path $serverExe) {
    $serverInputs += $serverExe
} elseif (Test-Path $serverFallback) {
    Write-Host "::warning::server exe at $serverFallback (crate not a workspace member?)"
    $serverInputs += $serverFallback
} else {
    Write-Host "::error::server exe not found at $serverExe or $serverFallback"
    exit 1
}
# Pick up any config templates under crates/server/config/ if/when they exist.
$configDir = 'crates\server\config'
if (Test-Path $configDir) {
    $cfgs = Get-ChildItem -Path $configDir -File -Recurse | ForEach-Object { $_.FullName }
    if ($cfgs) { $serverInputs += $cfgs }
} else {
    Write-Host "::notice::no crates/server/config/ dir — server tarball contains only the exe (config is env/flag-driven)."
}
New-ReleaseTarball -Name 'nyx-server-windows.tar.gz' -Inputs $serverInputs

# ---- 6. Offset-resolver tarball ----
$resolverDir = 'crates\offset-resolver\target\release'
$resolverInputs = Get-ChildItem -Path $resolverDir -File | Where-Object { $_.Extension -in '.exe','.pdb' } | ForEach-Object { $_.FullName }
if ($resolverInputs.Count -eq 0) { Write-Host "::error::no offset-resolver exes in $resolverDir"; exit 1 }
New-ReleaseTarball -Name 'offset-resolver-windows.tar.gz' -Inputs $resolverInputs

# ---- 7. SHA256SUMS over every file in staging EXCEPT SHA256SUMS itself ----
# Format matches the GNU coreutils sha256sum layout: "<hexhash>  <filename>".
# softprops/action-gh-release ships staging/SHA256SUMS as its own asset.
$sumsFile = Join-Path $staging 'SHA256SUMS'
$files = Get-ChildItem -Path $staging -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | Sort-Object Name
$lines = @()
foreach ($f in $files) {
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
    $lines += ("{0}  {1}" -f $hash, $f.Name)
}
$lines | Set-Content -Path $sumsFile -Encoding ASCII

# ---- manifest printout ----
Write-Host ''
Write-Host '== staged asset manifest =='
Get-ChildItem -Path $staging -File | Sort-Object Name | ForEach-Object {
    Write-Host ("  {0,-40} {1,12} bytes" -f $_.Name, $_.Length)
}
Write-Host ("== stage_assets OK: {0} files in {1}/ ==" -f (Get-ChildItem $staging -File).Count, $staging)
