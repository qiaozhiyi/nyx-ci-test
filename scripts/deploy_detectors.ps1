# deploy_detectors.ps1 — one-shot: download + compile all memory scanners
# for the real-machine validation pipeline. Run once per target.
#
# Tools deployed:
#   pe-sieve64.exe     — PE-sieve (hasherezade) — .text hash / unbacked / hook scan
#   EnableDebug.exe    — SeDebugPrivilege wrapper (compiled from scripts/EnableDebug.cs)
#   moneta64.exe       — Moneta (withzombies) — private-executable / unbacked scan
#   hsb.exe            — Hunt-Sleeping-Beacons — sleep-beacon detection
#
# After running this, use scan_linger.ps1 or scan_clean.ps1 to run the scans.

$ErrorActionPreference = 'Stop'
$detDir = "$env:TEMP\nyx_detectors"

if (Test-Path $detDir) { Remove-Item -Recurse -Force $detDir }
New-Item -ItemType Directory -Path $detDir | Out-Null
Write-Host "Deploying detectors to $detDir"

# ---- 1. PE-sieve (hasherezade/pe-sieve) ----
Write-Host "`n[1/4] Downloading PE-sieve..."
$peSieveZip = "$detDir\pe-sieve.zip"
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/hasherezade/pe-sieve/releases/latest" -UseBasicParsing
    $asset = $release.assets | Where-Object { $_.name -match 'pe.sieve.*\.zip' } | Select-Object -First 1
    if ($asset) {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $peSieveZip -UseBasicParsing
        Expand-Archive -Path $peSieveZip -DestinationPath $detDir -Force
        $found = Get-ChildItem -Recurse $detDir -Filter "pe-sieve64.exe" | Select-Object -First 1
        if ($found) {
            Move-Item $found.FullName "$detDir\pe-sieve64.exe" -Force
            Write-Host "  pe-sieve64.exe deployed ($([math]::Round((Get-Item "$detDir\pe-sieve64.exe").Length / 1KB))KB)"
        } else {
            Write-Warning "  pe-sieve64.exe not found in zip"
        }
    } else {
        Write-Warning "  No matching PE-sieve asset in latest release"
    }
} catch {
    Write-Warning "  PE-sieve download failed: $_"
    Write-Host "  Manual: https://github.com/hasherezade/pe-sieve/releases/latest"
}

# ---- 2. EnableDebug.exe (compile from source) ----
Write-Host "`n[2/4] Compiling EnableDebug.exe..."
$csSrc = Join-Path $PSScriptRoot "EnableDebug.cs"
$cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (Test-Path $csSrc) {
    if (Test-Path $cscPath) {
        & $cscPath /nologo /out:"$detDir\EnableDebug.exe" $csSrc 2>&1
        if (Test-Path "$detDir\EnableDebug.exe") {
            Write-Host "  EnableDebug.exe compiled"
        } else {
            Write-Warning "  EnableDebug.exe compilation failed"
        }
    } else {
        Write-Warning "  csc.exe not found at $cscPath"
    }
} else {
    Write-Warning "  EnableDebug.cs not found at $csSrc"
}

# ---- 3. Moneta (withzombies/Moneta) ----
Write-Host "`n[3/4] Downloading Moneta..."
try {
    $monetaRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/withzombies/Moneta/releases/latest" -UseBasicParsing
    $monetaAsset = $monetaRelease.assets | Where-Object { $_.name -match 'moneta64' } | Select-Object -First 1
    if ($monetaAsset) {
        Invoke-WebRequest -Uri $monetaAsset.browser_download_url -OutFile "$detDir\moneta64.exe" -UseBasicParsing
        Write-Host "  moneta64.exe deployed"
    } else {
        Write-Warning "  moneta64.exe not found in latest Moneta release"
        Write-Host "  Manual: https://github.com/withzombies/Moneta/releases/latest"
    }
} catch {
    Write-Warning "  Moneta download failed: $_"
    Write-Host "  Manual: https://github.com/withzombies/Moneta/releases/latest"
}

# ---- 4. Hunt-Sleeping-Beacons ----
Write-Host "`n[4/4] Downloading Hunt-Sleeping-Beacons..."
try {
    $hsbRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/hasherezade/Hunt-Sleeping-Beacons/releases/latest" -UseBasicParsing
    $hsbAsset = $hsbRelease.assets | Where-Object { $_.name -match '\.zip$' } | Select-Object -First 1
    if ($hsbAsset) {
        $hsbZip = "$detDir\hsb.zip"
        Invoke-WebRequest -Uri $hsbAsset.browser_download_url -OutFile $hsbZip -UseBasicParsing
        Expand-Archive -Path $hsbZip -DestinationPath "$detDir\hsb" -Force
        $hsbExe = Get-ChildItem -Recurse "$detDir\hsb" -Filter "*.exe" | Select-Object -First 1
        if ($hsbExe) {
            Move-Item $hsbExe.FullName "$detDir\hsb.exe" -Force
            Write-Host "  hsb.exe deployed"
        } else {
            Write-Warning "  No .exe found in HSB zip"
        }
    } else {
        Write-Warning "  No HSB asset found in latest release"
    }
} catch {
    Write-Warning "  HSB download failed: $_"
    Write-Host "  Manual: https://github.com/hasherezade/Hunt-Sleeping-Beacons/releases/latest"
}

# ---- Summary ----
Write-Host "`n=== Deployed to $detDir ==="
Get-ChildItem $detDir -File | ForEach-Object {
    Write-Host ("  {0,-30} {1,10:N0} bytes" -f $_.Name, $_.Length)
}

Write-Host "`nNext steps:"
Write-Host "  .\scripts\scan_linger.ps1          — PE-sieve scan of nyx_linger"
Write-Host "  .\scripts\scan_clean.ps1           — clean PE-sieve scan"
Write-Host "  moneta64.exe /pid <pid> /scan       — Moneta memory scan"
Write-Host "  hsb.exe <pid>                       — Hunt-Sleeping-Beacons scan"
