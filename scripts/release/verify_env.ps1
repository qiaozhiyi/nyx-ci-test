# verify_env.ps1 — release-pipeline preflight: confirm the self-hosted runner
# (Win Server 2019, build 17763) is in the locked-down Defender posture the
# release spec requires before any artifact is built.
#
# Checks (from docs/superpowers/specs/2026-07-21-release-pipeline-design.md §2/§3):
#   1. MAPSReporting == 0   — no sample/metadata auto-upload to MS cloud during iteration
#   2. ExclusionPath contains every build output dir we are about to populate,
#      so Defender realtime does not quarantine the freshly-linked DLL/EXEs.
#
# These are set up by scripts/setup_release_env.ps1 (owned by T2). If this
# script fails the operator runs setup_release_env.ps1 once and re-pushes the tag.
#
# Assumes CWD = repo root. PowerShell 5.1 (Server 2019 built-in).
$ErrorActionPreference = 'Stop'

# Match the dir list scripts/setup_release_env.ps1 excludes. Keep these in sync
# with the workspace member layout (Cargo.toml root) plus the standalone crates
# that are built via --manifest-path (implant-win, operator-kernel-cli,
# offset-resolver) and the loader (nyx-loader is a workspace member but its
# target/ dir sits under crates/nyx-loader, which the glob below already covers).
$repoRoot = (Get-Location).Path
$requiredExclusions = @(
    (Join-Path $repoRoot 'target'),
    (Join-Path $repoRoot 'crates\*\target')
) | Sort-Object -Unique

Write-Host '== verify_env: release runner preflight =='

# ---- 1. MAPSReporting ----
# Get-MpPreference returns 0/1/2. 0 = disabled (locked down). Spec §3 locks this
# to 0 before any iteration so Defender does not auto-upload the implant to MS.
$maps = (Get-MpPreference).MAPSReporting
if ($null -eq $maps) {
    Write-Host '::error::Get-MpPreference returned $null for MAPSReporting — Defender cmdlets unavailable (not Server 2019?). Aborting release.'
    exit 1
}
Write-Host ("MAPSReporting = {0} (required: 0)" -f $maps)
if ($maps -ne 0) {
    Write-Host '::error::MAPSReporting is not 0. Defender would auto-upload build artifacts to the MS cloud during the release build.'
    Write-Host '::error::Run scripts/setup_release_env.ps1 on this runner first, then re-push the tag.'
    exit 1
}

# ---- 2. ExclusionPath coverage ----
# We collect the live exclusion list and expand the wildcard requirement
# ('crates\*\target') against the actual crate dirs present on disk. Any crate
# that has a target/ subdir (or will, once we build into it) must be covered.
$current = @()
try {
    $current = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath)
} catch {
    Write-Host '::error::Could not read ExclusionPath via Get-MpPreference.'
    Write-Host '::error::Run scripts/setup_release_env.ps1 first, then re-push the tag.'
    exit 1
}
# Normalize: strip trailing backslashes, uppercase for case-insensitive compare.
$currentNorm = $current | ForEach-Object { $_.TrimEnd('\').ToUpper() } | Sort-Object -Unique
Write-Host ("Current ExclusionPath entries: {0}" -f ($currentNorm.Count))

# Resolve the wildcard 'crates\*\target' into the concrete crate target dirs.
$crateTargetDirs = @()
foreach ($crate in (Get-ChildItem -Path (Join-Path $repoRoot 'crates') -Directory)) {
    # We require the exclusion for every crate dir we will build into. The
    # standalone crates (implant-win, operator-kernel-cli, offset-resolver) and
    # workspace members (server, nyx-loader) all emit to their own target/.
    $crateTargetDirs += (Join-Path $crate.FullName 'target')
}
$rootTarget = (Join-Path $repoRoot 'target')

$missing = @()
foreach ($dir in (@($rootTarget) + $crateTargetDirs)) {
    $norm = $dir.TrimEnd('\').ToUpper()
    if ($currentNorm -notcontains $norm) {
        $missing += $dir
    }
}

if ($missing.Count -gt 0) {
    Write-Host '::error::Missing Defender ExclusionPath entries. The following build dirs are NOT excluded:'
    foreach ($m in $missing) { Write-Host "  - $m" }
    Write-Host '::error::Without exclusions Defender realtime protection will quarantine the freshly-built DLL/EXE blobs mid-build.'
    Write-Host '::error::Run scripts/setup_release_env.ps1 on this runner first, then re-push the tag.'
    exit 1
}

Write-Host '== verify_env OK: MAPSReporting disabled and all build dirs excluded =='
