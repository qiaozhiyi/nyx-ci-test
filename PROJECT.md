# Project: Testing and Review Suite

## Architecture
This project implements a comprehensive testing and review suite for the **Nyx** C2 framework.
- **Operator Interface**: Makepad 2.0 native client (`crates/client-ui`) + ratatui TUI (`crates/client-cli`).
- **Team Server**: axum REST API / beacon loop handler (`crates/server`).
- **Cross-platform Agent**: std-based dev agent (`crates/agent-dev`).
- **Windows PIC Implant**: standalone nightly built PIC implant (`crates/implant-win`).
- **Bypass Module**: evasion SDK (`crates/evasionsdk`), implant evasion glue (`crates/implant-win` evasion modules), operator kernel SDK (`crates/operator-kernelsdk`).

## Code Layout
- `crates/` - Core Rust crates.
- `scripts/` - Helper and deployment scripts.
- `tools/` - Standalone tools (e.g., sRDI).
- `docs/` - **Authoritative status: `docs/STATUS.md`**. Live dev docs (capabilities, handoff, real-machine results). `docs/archive/` holds superseded audit/research docs (historical, not authoritative).

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1. Code Review Report | Audit codebase, generate `code_review_report.md` | None | DONE |
| 2 | M2. Visual UI Testing | Automated build & verification scripts for the Makepad client | None | DONE |
| 3 | M3. SSH Connection Automation | Parse `~/.ssh/config` to locate server & verify connection | None | DONE |
| 4 | M4. Remote Functional Testing | Execute tests on Windows server via SSH & output pass/fail report | M3 | DONE |
| 5 | M5. P2 Bypass Module | EDR evasion: userland kits + kernel tier | None | DONE (2026-06-26) |
| 6 | M6. Kernel Real-Machine | BYOVD load + ETW-TI + DKOM + Callback repurpose on Server 2019 | M5 | DONE (2026-06-26) |
| 7 | M7. Gap Closure + Real-Machine | Close gaps G1-G5 (postex/creds-audit/BOF-loader/MiniFilter/symserver); verify G1 on Server 2019 | M6 | DONE (2026-06-27) |
| 8 | M8. Win11 24H2 Real-Machine | Cross-version offset + CET verify on Win11 24H2/25H2 | M7, Win11 VM | 🔶 BLOCKED (no Win11 24H2 host in sshconfig) |

## Bypass Module Status (2026-06-27)

> **Authoritative detail: [`docs/STATUS.md`](docs/STATUS.md).** Numbers below are a summary.

**Overall completion: ~95%** (userland 98%, kernel algo 100%, wiring 100%, kernel real-machine 7/7 PASS). Gaps G1-G5 closed 2026-06-27; only G6 (Win11 24H2 real-machine) remains — hardware gap.

### Userland (implant-win) — all default ARMED
- ✅ Indirect syscalls (Hell/Halo/Tartarus SSN)
- ✅ HWBP patchless blind (zero `.text` modification) + byte-patch blind (NtTraceEvent)
- ✅ Foliage sleep mask (APC chain + RC4, masks `.text` AND heap regions)
- ✅ Module stomping inject + ThreadlessInject (HWBP) — `MODULESTOMP_ENABLED` default **ON**
- ✅ BYOUD-Gap RSP swap (CET-aware; `SPOOF_SWAP_ENABLED` default **OFF** until CET-safe)
- ✅ Memory region encryption (RC4) + heap slab tracking
- ✅ ntdll unhook (KnownDlls + disk fallback) + anti-debug
- ✅ **Post-ex token operations** (G1, wired 2026-06-27): `StealToken`/`MakeToken`/`Rev2Self`/`GetUid` — real-machine verified (`nyx_selftest_postex` exit=15)

### Kernel (operator-kernelsdk)
- ✅ BYOVD driver load (KslD dynamic `QueryDosDeviceW` → RTCore64 fallback chain)
- ✅ ETW-TI provider blind (IsEnabled=0, HVCI-safe)
- ✅ DKOM process hide (ActiveProcessLinks unlink/relink)
- ✅ Callback repurpose (DATA write, **selective slot targeting DONE** — range-based ntoskrnl skip + slot[0] fallback)
- ✅ PatchGuard windows — `TimingRepairWindow` + `RuntimePgBypassWindow` real; only legacy `PatchGuardWindow` is a skeleton
- 🔶 MiniFilter — algorithm in `telemetry.rs::MiniFilterUnlinker`, but `bootstrap_chain()` does NOT wire it (`flt_globals_kva=0`)

### Real-machine verification (Server 2019 17763.1339)
- ✅ Task G: BYOVD driver load + ntoskrnl base resolve
- ✅ Task H: ETW-TI IsEnabled zeroed
- ✅ Task I: DKOM process hide/restore
- ✅ Task J: Driver unload
- ✅ Task K: Callback repurpose (Sysmon silenced/restored)

## Interface Contracts
- **SSH Automation script**:
  - Input: reads `~/.ssh/config` for alias `win` (or customized target alias).
  - Output: Exit code 0 on successful connection and basic command execution.
- **Remote Functional Testing**:
  - Input: established SSH connection to remote Windows server.
  - Output: test logs and report `remote_tests_report.md` indicating pass/fail status.
