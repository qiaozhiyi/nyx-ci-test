# Release Build Environment (Windows VPS)

> Companion to [`docs/superpowers/specs/2026-07-21-release-pipeline-design.md`](superpowers/specs/2026-07-21-release-pipeline-design.md)
> (sections 2 and 4-S1). This page documents the **build-environment configuration
> of the self-hosted Windows runner** so that release artifacts are reproducible
> and consumers can audit exactly how the binaries were produced.
>
> Operator: [`scripts/setup_release_env.ps1`](../scripts/setup_release_env.ps1) is the
> idempotent script that applies every change on this page. Re-running it is a no-op.

---

## 1. Why this page exists (transparency)

Every release artifact produced by the v0.3.0+ pipeline is built on a single
self-hosted Windows Server 2019 VPS whose Windows Defender configuration differs
from the OS default in three ways (MAPS off, build-dir exclusions, build-process
exclusions). Those deviations are necessary for the build to complete and for the
research server to stay in scope, but they are also exactly the kind of thing a
consumer wants to see spelled out. This page is the canonical record; the same
facts are summarised in the release notes body for each tagged release.

Realtime protection is **left ON** on purpose — the release spec calls this
"Defender-on verification": a build that survives Defender scanning every
intermediate artifact is a stronger signal than a build on a Defenderless host.

---

## 2. Verified environment baseline

Every value below was probed live on 2026-07-21 over the existing SSH alias
`ssh win` (hostname `Cloud-Init-Win`). The runner label `win-17763` (used in
`.github/workflows/release.yml`) refers to this same host.

| Constraint | Value | Design impact |
|---|---|---|
| Hostname | `Cloud-Init-Win` | VPS, identical to the `win-17763` runner |
| OS | Windows Server 2019 build 17763.1339 | Matches `windows-ci.yml`; ships **PowerShell 5.1** (not 7) |
| Memory | 8 GB | Constrained; reflective loader iterated natively, no VM |
| Disk free | ~16 GB | Adequate; rules out a Hyper-V VM isolation path |
| Defender Realtime | **ON** (`RealTimeProtectionEnabled=True`, `DisableRealtimeMonitoring=False`) | "Defender-on verification" is achievable here |
| `WinDefend` service | Running | — |
| Signature age | 13 h | Healthy |
| `ExclusionPath` | empty (pre-setup) | Will add `C:\nyx\target`, `crates/*/target`, `C:\nyx\staging` |
| `ExclusionProcess` | empty (pre-setup) | Will add `cargo.exe`, `rustc.exe` |
| `ExclusionExtension` | empty | No extension-level exclusions |
| ASR rules | empty | No attack-surface-reduction rules added |
| `MAPSReporting` | 2 (Advanced — auto-uploads samples to MS cloud) | **Set to 0** by `setup_release_env.ps1` |
| `SubmitSamplesConsent` | (inherited) | **Set to 2 (Never submit)** |
| Hyper-V | unavailable (0x5 access denied + disk) | VM path rejected — build runs directly on the host |
| Rust toolchain | `cargo` / `rustc` at `C:\Users\Administrator\.cargo\bin` | No setup blocker |
| Git | `C:\Program Files\Git\cmd\git.exe` | No setup blocker |
| Repo checkout | `C:\nyx` (existing) | Build roots + exclusions are anchored here |
| Existing artifacts | `C:\nyx\nyx_implant_win.dll` (~349 KB selftest) + `nyx_implant_win_prod.dll` (~310 KB) | Prior build outputs present |

---

## 3. Why each Defender change is made

### 3.1 MAPS cloud sample upload disabled (`MAPSReporting=0`, `SubmitSamplesConsent=2`)

Out of the box, with `MAPSReporting=2` (Advanced membership), Defender forwards
files it finds suspicious to the Microsoft cloud for automated analysis. On a
research server that is iterating real payload bytes (DLLs, PIC blobs, BOFs),
that auto-upload would feed the very toolchain we are building into vendor
threat-intel feeds — both burning the research and violating the engagement's
data-handling scope. Setting both knobs off keeps telemetry local.

`SubmitSamplesConsent=2` is "Never submit" (the `Set-MpPreference` enum value 0
maps to a different label depending on locale; 2 is the stable, locale-free
"never submit" choice). `MAPSReporting=0` is "Disabled".

### 3.2 Build-directory exclusions (`ExclusionPath`)

cargo writes and rewrites large intermediate artifacts (`.rlib`, `.pdb`, `.dll`,
incremental compilation caches) under each crate's `target/` directory. With
realtime protection on, Defender scans each fresh write; under load this both
slowed the build materially and, more importantly, occasionally quarantined a
freshly-linked DLL mid-build — surfacing as a misleading "file not found" at the
next linker invocation. The exclusions below let the build complete without
disabling realtime scanning globally.

`C:\nyx\staging` is excluded for the same reason: it is where the release
workflow assembles the final asset set (DLLs, blob, tarballs, `SHA256SUMS`)
immediately before publishing, and a quarantine there would silently drop an
asset from the release.

The full list applied by the script:

| Path | Why |
|---|---|
| `C:\nyx\target` | Workspace-level build output (server, cli, offset-resolver, ...) |
| `C:\nyx\crates\implant-win\target` | Standalone `no_std` implant DLL (own empty `[workspace]`) |
| `C:\nyx\crates\server\target` | Team server |
| `C:\nyx\crates\operator-kernel-cli\target` | Operator CLI |
| `C:\nyx\crates\offset-resolver\target` | PDB offset resolver |
| `C:\nyx\crates\nyx-loader\target` | Reflective loader / PIC wrap |
| `C:\nyx\staging` | Release-asset staging dir |

### 3.3 Build-process exclusions (`ExclusionProcess`)

cargo and rustc spawn many short-lived child processes that open freshly-written
artifacts in `target/`. Even with the path exclusions above, a process-level
exclusion on the toolchain binaries removes a residual class of intermittent
"another process is using this file" scan races that surface as linker input
errors. Applied list:

| Process | Why |
|---|---|
| `C:\Users\Administrator\.cargo\bin\cargo.exe` | Driver of every build step |
| `C:\Users\Administrator\.cargo\bin\rustc.exe` | Per-crate compiler invocations |

`clink.exe` is **not** excluded: it is not part of the verified baseline
toolchain on this VPS, and adding an exclusion for a binary that is not present
would be misleading. If a future toolchain upgrade brings clink into the build,
add it to `$exclusionProcesses` in `scripts/setup_release_env.ps1`.

### 3.4 What is deliberately NOT changed

- **Realtime protection stays ON.** The release spec's "Defender-on verification"
  goal is that every artifact survives a realtime scan, not that scans are
  neutered. `setup_release_env.ps1` never calls `Set-MpPreference -DisableRealtimeMonitoring`.
- **The `WinDefend` service is not stopped.**
- **No ASR rules** are added.
- **No extension exclusions** (`ExclusionExtension`) are added — only the
  specific directories and processes above.

---

## 4. Running the setup script

The script is idempotent: `Add-MpPreference` treats "add an exclusion that
already exists" as a no-op, and `Set-MpPreference` overwrites with the same
value. Re-running it after a successful run produces identical output and exits 0.

### 4.1 From an interactive session on the VPS

```powershell
# Must be an elevated (Administrator) PowerShell window.
powershell -ExecutionPolicy Bypass -File C:\nyx\scripts\setup_release_env.ps1
```

### 4.2 From the macOS dev host (the operator's normal workflow)

The repo already ships an SSH alias `win` that resolves to the VPS:

```bash
ssh win "powershell -ExecutionPolicy Bypass -File C:\nyx\scripts\setup_release_env.ps1"
```

The self-hosted GitHub Actions runner agent on this host runs elevated, so the
release workflow can invoke the same command without any extra privilege
handling.

### 4.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | All Defender settings applied and verified |
| 1 | Not running as Administrator |
| 2 | `Set-MpPreference` not available (not Windows, or Defender feature removed) |
| 3 | One or more post-change verifications did not match expected values |

On exit 3, re-run the script (it is idempotent). If the failure persists, check
the Defender operational log:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 25 |
    Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
```

---

## 5. Verifying the configuration manually

Independent of the script's own verification block, any operator can confirm the
live state with two one-liners. These are also the commands the release notes
point consumers at.

### 5.1 The two scalar knobs

```powershell
Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent
```

Expected:

```
MAPSReporting SubmitSamplesConsent
------------- --------------------
            0                       2
```

### 5.2 The full exclusion lists

```powershell
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess
```

Expected: every entry listed in section 3.2 / 3.3, in any order. Path comparison
on Windows is case-insensitive, so differing drive-letter case is not a defect.

### 5.3 Defender runtime posture (informational)

```powershell
Get-MpComputerStatus | Select-Object `
    RealTimeProtectionEnabled, DisableRealtimeMonitoring,
    AntivirusEnabled, AMRunningMode, AntivirusSignatureAge
```

This should show realtime protection still enabled — the script never disables
it. If `RealTimeProtectionEnabled` is `False` here, **something else** on the host
changed it; that is outside this script's scope.

---

## 6. Rollback (engagement-end teardown)

Every change applied by `setup_release_env.ps1` is reversible. Run the commands
below from an elevated PowerShell session. None of them touch the build outputs
themselves; they only restore Defender to its default posture.

### 6.1 Re-enable MAPS cloud reporting and sample submission

```powershell
Set-MpPreference -MAPSReporting 2        # Advanced membership (OS default on Server 2019)
Set-MpPreference -SubmitSamplesConsent 0 # Safe/Default (prompt-free auto-submit per policy)
```

> `SubmitSamplesConsent` accepted values: `0` = Always prompt (maps to "Safe" in
> some locales), `1` = Prompt, `2` = Never submit, `3` = Send safe samples
> automatically. Pick the value that matches your post-engagement policy; the OS
> default on a clean Server 2019 install is `0`.

### 6.2 Remove the ExclusionPath entries

```powershell
Remove-MpPreference -ExclusionPath 'C:\nyx\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\crates\implant-win\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\crates\server\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\crates\operator-kernel-cli\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\crates\offset-resolver\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\crates\nyx-loader\target'
Remove-MpPreference -ExclusionPath 'C:\nyx\staging'
```

### 6.3 Remove the ExclusionProcess entries

```powershell
Remove-MpPreference -ExclusionProcess 'C:\Users\Administrator\.cargo\bin\cargo.exe'
Remove-MpPreference -ExclusionProcess 'C:\Users\Administrator\.cargo\bin\rustc.exe'
```

### 6.4 Confirm the rollback

```powershell
(Get-MpPreference).ExclusionPath        # -> empty
(Get-MpPreference).ExclusionProcess     # -> empty
Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent
```

`Remove-MpPreference` is a no-op if the entry is already absent, so the commands
above are safe to re-run.

### 6.5 Optional: trigger a signature refresh + full scan

Once MAPS reporting is re-enabled, bring signatures current and run a full scan
to make sure nothing from the engagement window slipped past the (still-on)
realtime engine:

```powershell
Update-MpSignature
Start-MpScan -ScanType FullScan
```

---

## 7. Provenance

- Design source: `docs/superpowers/specs/2026-07-21-release-pipeline-design.md`
  §2 (verified baseline) and §4-S1 (VPS environment prep).
- Implementation: `scripts/setup_release_env.ps1` (idempotent, PowerShell 5.1).
- Baseline probed live: 2026-07-21 via `ssh win`.
- This page is referenced verbatim from the release-notes template so every
  consumer of a v0.3.0+ draft release sees the same build-environment facts.
