# Release Pipeline + Reflective Loader Design

**Date**: 2026-07-21
**Status**: Approved (user instruction: parallel implementation)
**Scope**: Single spec covering all four release artifacts + reflective loader backfill.

---

## 1. Goal

Establish a tag-triggered release pipeline on the existing self-hosted runner
(VPS `Cloud-Init-Win`, Win Server 2019 build 17763, label `win-17763`) that
produces real Windows payloads — prod DLL, selftest DLL, reflective PIC blob,
team-server + operator CLI — with every artifact passing a selftest gate on
the runner, published as a **Draft GitHub Release**. Within the same spec,
backfill the reflective loader (`crates/nyx-loader`) whose `generate_loader_stub()`
is currently a `_config`-ignored stub and whose on-target Layer-2 (decrypt +
reflective PE map) is documented as "intentionally out of scope".

## 2. Verified Environment Baseline

All facts below were probed live on 2026-07-21 via SSH (`ssh win`):

| Constraint | Value | Design impact |
|---|---|---|
| Hostname | `Cloud-Init-Win` | VPS, identical to the `win-17763` runner |
| OS | Windows Server 2019 build 17763.1339 | Matches `windows-ci.yml` |
| Memory | 8 GB | Constrained; reflective loader iterated natively, no VM |
| Disk free | ~16 GB | Adequate; excludes Hyper-V VM path |
| Defender Realtime | **ON** (`RealTimeProtectionEnabled=True`, `DisableRealtimeMonitoring=False`) | "Defender-on verification" is achievable here |
| `WinDefend` service | Running | — |
| Signature age | 13 h | Healthy |
| `ExclusionPath` | empty | Will add `C:\nyx\target` + `crates/*/target` |
| `ExclusionProcess` | empty | — |
| `MAPSReporting` | 2 (Advanced membership, auto-upload to MS cloud) | **Will set to 0** before any iteration |
| Hyper-V | unavailable (0x5 access denied + disk) | VM path rejected |
| Rust toolchain | `cargo`/`rustc` installed at `C:\Users\Administrator\.cargo\bin` | No setup blocker |
| Git | installed | No setup blocker |
| Existing artifacts | `C:\nyx\nyx_implant_win.dll` (349 KB, selftest) + `nyx_implant_win_prod.dll` (310 KB) | Prior build outputs present |

## 3. User Decisions (locked)

| Decision | Choice |
|---|---|
| Execution channel | Reuse existing self-hosted runner (no new machine) |
| Artifacts | All four: prod DLL + selftest DLL + reflective blob + server/CLI |
| PIC blob gap handling | Backfill reflective loader **in this spec** (single spec) |
| Scope decomposition | Single spec, not split |
| Release trigger | `git tag v0.3.0` push |
| Release visibility | **Draft** (assets not publicly listed) |
| Code signing | Unsigned + engagement-time signing documentation in release notes |
| Defender iteration | Add ExclusionPath for build dirs, document transparently in release notes |
| MAPSReporting | **Set to 0** before any iteration |
| Version | **v0.3.0** (minor: reflective loader is new functionality) |

## 4. Subsystem Architecture

```
S1. VPS Environment Prep (one-time, idempotent)
  - Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2
  - Add-MpPreference -ExclusionPath for target/ dirs
  - scripts/setup_release_env.ps1 (re-runnable)
  - docs/RELEASE_ENV.md (reproducible)
        |
        v
S2. Reflective Loader Implementation (core new code)
  - crates/nyx-loader/src/stub.rs: generate_loader_stub() -> real
  - crates/nyx-loader/src/lib.rs: wrap_payload() -> real
  - New module crates/nyx-loader/src/on_target.rs:
      Layer-2 PIC shellcode (decrypt + reflective PE map)
  - Host-side tests in crates/nyx-loader/tests/:
      stub_layout.rs, roundtrip_decrypt.rs, payload_format.rs
  - VPS validation script: scripts/loader_probe.ps1
        |
        v
S3. Build Matrix (on runner)
  - nyx-implant-win (cdylib, prod):    MSVC + nightly, default
  - nyx-implant-win (cdylib, selftest): MSVC + nightly, +selftest
  - nyx-loader wrap:                   prod DLL -> reflective blob
  - operator-kernel-cli:               stable Rust
  - nyx-server:                        stable Rust
  - offset-resolver:                   stable Rust
        |
        v
S4. Validation Gate (release-blocking)
  - Selftest regression: 8 core nyx_selftest_* must pass
  - Loader probe: inject-and-execute verification
  - Asset checksums: SHA256SUMS for all artifacts
        |
        v
S5. Release
  - .github/workflows/release.yml (on: push: tags: ['v*'])
  - softprops/action-gh-release@v2 with draft: true
  - Assets: DLLx2, blob, CLI tarball, server tarball, SHA256SUMS
  - Body: extracted from CHANGELOG.md section for tag
```

## 5. Reflective Loader Design (S2 detail)

### 5.1 Payload layout (already documented in stub.rs)

```
[PIC_STUB (variable)][NYX2 magic (4B)][encrypted_len LE (4B)][nonce (12B)][ciphertext (N B)][tag (16B)]
```

The stub is at offset 0 (entry point). It self-locates via `call/pop`, walks
**forward** past its own code to find the `NYX2` magic marker, then reads
`encrypted_len`, `nonce`, and `ciphertext || tag`.

### 5.2 PIC stub structure (the new implementation)

Hand-written position-independent x86-64 assembly, emitted as raw bytes by
`generate_loader_stub()`. Steps:

1. **Self-locate** via `call next; next: pop rax`.
2. **Scan forward** for the 4-byte `NYX2` magic. Bound: `rax + 256`.
3. **Parse header**: encrypted_len (u32 LE @ +4), nonce (12B @ +8),
   ciphertext||tag (@ +20).
4. **PEB walk** to resolve `VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`.
5. **Allocate** RWX page for decrypted PE.
6. **ChaCha20-Poly1305 decrypt** with baked-in 32-byte key. Tag mismatch →
   zero buffer and return silently (no crash).
7. **Reflective PE load**: map sections, apply `IMAGE_REL_BASED_DIR64`
   relocations, resolve imports, call `DllMain(hModule, DLL_PROCESS_ATTACH, 0)`.

### 5.3 Why inline crypto

The `chacha20poly1305` crate requires `alloc` and pulls in the Rust panic
runtime — neither exists when the stub is executing as bare shellcode. The
inline port is ~600 bytes of x86-64. Unit-tested on host via disassembler
cross-check and known-answer test against the crate's output.

### 5.4 Host-side tests (must pass before VPS injection)

| Test | Verifies |
|---|---|
| `stub_layout.rs::stub_starts_with_call_pop` | First bytes are `E8 00 00 00 00 58` |
| `stub_layout.rs::stub_finds_magic_within_max_scan` | Scan loop terminates at NYX2 |
| `payload_format.rs::wrap_payload_emits_magic_and_lengths` | `wrap_payload()` output matches layout |
| `roundtrip_decrypt.rs::host_decrypt_matches_crate` | Host-side decrypt of wrapped payload == crate output |
| `roundtrip_decrypt.rs::tag_check_rejects_corruption` | Flipped ciphertext byte → tag fails |

### 5.5 VPS validation (scripts/loader_probe.ps1)

Runs in a **dedicated short-lived test process** (not the runner agent) so a
crash does not kill CI:

1. Build prod DLL.
2. `wrap_payload()` it into a blob with a test key.
3. Spawn `rundll32` with `tools/loader_probe_dll/` — a small harness DLL
   that `VirtualAlloc(RWX)` + `memcpy(blob)` + jumps to blob entry.
4. Harness writes `C:\nyx\loader_probe_result.txt` = `OK <dllmain_rv>` or
   `FAIL <stage>`.
5. Runner script polls and parses.

Process crash → Windows Error Reporting records it, runner agent survives.
VPS bluescreen → workflow timeout (25 min), no release created, diagnose
via `Get-WinEvent` after reboot.

## 6. Release Workflow (S5 detail)

### 6.1 Trigger

```yaml
on:
  push:
    tags: ['v*']
```

### 6.2 Single job, sequential steps (VPS has 8 GB RAM, one cargo = saturated)

```yaml
jobs:
  release:
    runs-on: [self-hosted, win-17763]
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Verify environment
        run: powershell -File scripts/release/verify_env.ps1
      - name: Build prod DLL
        run: powershell -File scripts/release/build_prod_dll.ps1
      - name: Build selftest DLL
        run: powershell -File scripts/release/build_selftest_dll.ps1
      - name: Build operator-kernel-cli
        run: powershell -File scripts/release/build_cli.ps1
      - name: Build team server
        run: powershell -File scripts/release/build_server.ps1
      - name: Build offset-resolver
        run: powershell -File scripts/release/build_offset_resolver.ps1
      - name: Wrap reflective blob
        run: powershell -File scripts/release/wrap_blob.ps1
      - name: Selftest gate
        run: powershell -File scripts/release/selftest_gate.ps1
      - name: Loader probe gate
        run: powershell -File scripts/release/loader_probe_gate.ps1
      - name: Stage assets + SHA256SUMS
        run: powershell -File scripts/release/stage_assets.ps1
      - name: Extract release notes from CHANGELOG
        run: powershell -File scripts/release/extract_notes.ps1
      - name: Create draft release
        uses: softprops/action-gh-release@v2
        with:
          draft: true
          body_path: release_notes.md
          files: |
            staging/*.dll
            staging/*.bin
            staging/*.tar.gz
            staging/SHA256SUMS
```

### 6.3 Failure semantics

Any step failure aborts. No draft release created. Tag remains in git;
operator deletes and re-pushes, or pushes a new tag.

### 6.4 Asset manifest

| File | Size (est.) | Source |
|---|---|---|
| `nyx_implant_win_prod.dll` | ~310 KB | implant-win target msvc release |
| `nyx_implant_win_selftest.dll` | ~350 KB | implant-win + `--features selftest` |
| `nyx_loader_blob.bin` | ~330 KB | wrap_payload() of prod DLL |
| `nyx-server-windows.tar.gz` | ~5 MB | server + config templates |
| `nyx-cli-windows.tar.gz` | ~3 MB | operator-kernel-cli exes |
| `offset-resolver-windows.tar.gz` | ~2 MB | offset-resolver exes |
| `SHA256SUMS` | <1 KB | checksums of all above |

### 6.5 Release notes template

Inlined verbatim in `scripts/release/extract_notes.ps1` as `$NOTES_HEADER`,
prepended to the CHANGELOG-extracted body for the tag. Template:

```markdown
# Nyx C2 v${TAG} (DRAFT)

⚠️ **UNAUTHORIZED USE PROHIBITED.** Authorized red team / penetration testing only.

## Build environment transparency
- Built on self-hosted Windows Server 2019 (build 17763) with Defender Realtime **ON**.
- Defender **ExclusionPath** active for `C:\nyx\target` and `crates/*/target` (build dirs).
- **MAPSReporting disabled** on build host (no sample upload to MS cloud).
- DLLs are **unsigned**. Engagement-time signing instructions: see docs/ENGAGEMENT_SIGNING.md.

## Verification
- Selftest gate: 8/8 core nyx_selftest_* exports passed.
- Loader probe: reflective blob injected + DllMain returned <RV>.

## Artifacts
| File | SHA256 |
|---|---|
| ... | ... |

## Known limits (inherited)
- Sleep obfuscation `fluctuation` not wired.
- 6 Transport channels have zero consumers.
- BOF compatibility surface is narrow.
```

`extract_notes.ps1` substitutes `${TAG}` and appends the per-tag CHANGELOG
section after the template's `## Artifacts` block (the artifacts table itself
is filled by `stage_assets.ps1` → `SHA256SUMS`).

## 7. Implementation Task Decomposition (parallel)

Three independent file-scoped tasks dispatched in parallel:

| Task | Files touched (exclusive) | Depends on |
|---|---|---|
| **T1. Reflective loader** | `crates/nyx-loader/**` only | nothing |
| **T2. VPS env prep** | `scripts/setup_release_env.ps1` (new) + `docs/RELEASE_ENV.md` (new) | nothing |
| **T3. Release workflow + build scripts** | `.github/workflows/release.yml` (new) + `scripts/release/**` (new) | nothing |

After T1-T3 return, sequential **T4** updates `CHANGELOG.md` with the v0.3.0
section summarizing all changes.

## 8. Testing Strategy

| Layer | Where | What |
|---|---|---|
| Host unit | macOS dev host, `cargo test -p nyx-loader` | stub layout, payload format, decrypt roundtrip |
| Cross-compile check | macOS dev host | `cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu` |
| VPS selftest | runner | 8 core `nyx_selftest_*` exports via rundll32 |
| VPS loader probe | runner | reflective blob inject-and-execute in dedicated process |
| Build matrix | runner | every artifact builds without error |
| Release gate | runner | all of the above must pass before draft release |

## 9. Error Handling

| Failure | Consequence | Recovery |
|---|---|---|
| Build fails | Workflow fails, no release | Fix code, re-push tag |
| Selftest fails | Workflow fails, no release | Inspect `selftest_results.csv` artifact |
| Loader probe crashes test proc | Probe reports `FAIL <stage>` | Fix loader, re-run |
| Loader probe bluescreens VPS | Workflow timeout (25 min) | Reboot VPS, `Get-WinEvent` for root cause |
| Defender deletes artifact outside exclusion | Build step fails (file missing) | Verify exclusions, re-run |
| softprops action fails | Workflow fails, no release | Manual `gh release create` fallback |

## 10. Out of Scope

- On-target evasion (sleep mask wiring, transport consumers) — README known limits.
- EV/OV code signing infrastructure.
- Per-engagement payload mutation (nyx-mutate is a separate runtime tool).
- Cross-platform builds (Linux server binaries, macOS operator UI).
- Public release promotion (this spec produces **draft** only; promotion is
  a manual operator decision outside CI).
