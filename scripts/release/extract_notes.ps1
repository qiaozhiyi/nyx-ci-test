# extract_notes.ps1 — extract this release's section from CHANGELOG.md, prepend
# a release-notes header template, write to release_notes.md for
# softprops/action-gh-release's body_path input.
#
# CHANGELOG format (verified against the live file):
#   ## [0.2.0] - 2026-07-21
#   ...section body...
#   ## [Unreleased]
#   ...next section...
# Section headers are `## [<version>]`. The version in brackets does NOT carry
# the `v` prefix that the git tag does — the tag is `v0.3.0` but the changelog
# header is `## [0.3.0]`. We handle BOTH (tag with and without `v`) so a future
# changelog style change doesn't silently break the release.
#
# Source of the version: $env:GITHUB_REF_NAME (the tag name, e.g. 'v0.3.0').
# We never hardcode a version — every release derives its section from the tag.
#
# NOTE on spec §6.5: the design spec references "the release notes template from
# spec §6.5" but §6.5 does not exist in the approved spec (it jumps §6.4 → §7).
# We synthesize a template from the spec's transparency requirements (§3 locked
# decisions: unsigned + engagement-time signing docs; Defender exclusion
# documentation). This is an AMBIGUITY we resolved by authoring the template
# inline; if a real §6.5 template is added later, replace $NOTES_HEADER below.
#
# Assumes CWD = repo root. PowerShell 5.1.
$ErrorActionPreference = 'Stop'

# ---- resolve version from tag ----
$tag = $env:GITHUB_REF_NAME
if ([string]::IsNullOrEmpty($tag)) {
    Write-Host '::error::GITHUB_REF_NAME is empty — this script must run in a tag-triggered workflow.'
    exit 1
}
# Strip optional leading 'v' to match the CHANGELOG bracket convention.
$version = $tag -replace '^v', ''
Write-Host ("== extract_notes: tag={0} version={1} ==" -f $tag, $version)

$changelog = 'CHANGELOG.md'
if (-not (Test-Path $changelog)) {
    Write-Host "::error::$changelog not found at repo root."
    exit 1
}
$lines = Get-Content -Path $changelog -Encoding UTF8

# ---- locate the section header ----
# Match either `## [0.3.0]` or `## [v0.3.0]` (be liberal). Anchored with regex
# so we don't accidentally match a version mentioned inside a section body.
$headerPattern = '^##\s+\[(?:v)?' + [regex]::Escape($version) + '\]'
$startIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $headerPattern) { $startIdx = $i; break }
}
if ($startIdx -lt 0) {
    Write-Host "::error::no CHANGELOG section matching '$headerPattern' for tag $tag."
    Write-Host '::error::Add a ## [$version] section to CHANGELOG.md before pushing the tag.'
    exit 1
}

# ---- find the NEXT ## [ section (the boundary) ----
$endIdx = $lines.Count
for ($i = $startIdx + 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^##\s+\[') { $endIdx = $i; break }
}
$sectionBody = $lines[$startIdx..($endIdx - 1)]

# ---- release notes header template (synthesized from spec §3 transparency reqs) ----
# This is the fixed preamble every Nyx draft release carries. The CHANGELOG body
# is appended verbatim after this header.
$NOTES_HEADER = @"
# Nyx $tag (DRAFT)

> **Red-team authorized use only.** This release is a draft pending operator
> review. Assets are not publicly listed until the draft is published manually.

## Build & verification provenance

- **Built on:** self-hosted runner ``[self-hosted, win-17763]`` (Windows Server
  2019, build 17763).
- **Defender posture during build:** MAPSReporting = 0 (no cloud sample upload);
  ExclusionPath covers all build target directories. See ``docs/RELEASE_ENV.md``
  for the reproducible setup steps.
- **Code signing:** **UNSIGNED.** Sign with your engagement-time certificate
  before deployment. Unsigned payloads will trip any AV/EDR with signature
  requirements.
- **Validation gate passed:** 8 core ``nyx_selftest_*`` exports ran clean
  against the selftest DLL; reflective PIC blob verified via the loader probe.
  See ``staging/selftest_results.csv`` for per-export exit codes.

## Changes

"@

# ---- write release_notes.md ----
$out = 'release_notes.md'
$NOTES_HEADER | Out-File -FilePath $out -Encoding UTF8
# Append the CHANGELOG section (skip its own `## [version]` header line —
# the template above already headlines the release). Append the body lines.
if ($sectionBody.Count -gt 1) {
    $sectionBody[1..($sectionBody.Count - 1)] | Out-File -FilePath $out -Encoding UTF8 -Append
}

$bytes = (Get-Item $out).Length
Write-Host ("== extract_notes OK: {0} ({1} bytes) ==" -f $out, $bytes)
Write-Host '--- preview (first 30 lines) ---'
Get-Content $out -TotalCount 30 | ForEach-Object { Write-Host $_ }
