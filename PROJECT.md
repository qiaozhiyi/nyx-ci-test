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
- `docs/` - Development reports, capability matrices, research papers.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1. Code Review Report | Audit codebase, generate `code_review_report.md` | None | DONE |
| 2 | M2. Visual UI Testing | Automated build & verification scripts for the Makepad client | None | DONE |
| 3 | M3. SSH Connection Automation | Parse `~/.ssh/config` to locate server & verify connection | None | DONE |
| 4 | M4. Remote Functional Testing | Execute tests on Windows server via SSH & output pass/fail report | M3 | DONE |
| 5 | M5. P2 Bypass Module | EDR evasion: userland kits + kernel tier | None | DONE (2026-06-26) |
| 6 | M6. Kernel Real-Machine | BYOVD load + ETW-TI + DKOM + Callback repurpose on Server 2019 | M5 | DONE (2026-06-26) |

## Bypass Module Status (2026-06-26)

**Overall completion: ~87%** (userland 98%, kernel algo 100%, wiring 95%, kernel real-machine all pass)

### Userland (implant-win)
- ✅ Indirect syscalls (Hell/Halo/Tartarus SSN)
- ✅ HWBP patchless blind (zero `.text` modification)
- ✅ Byte-patch blind (NtTraceEvent)
- ✅ Foliage sleep mask (APC chain + RC4)
- ✅ Module stomping inject (gated)
- ✅ BYOUD-Gap RSP swap (gated, CET-aware)
- ✅ Memory region encryption (RC4)

### Kernel (operator-kernelsdk)
- ✅ BYOVD driver load (KslD → RTCore64 fallback chain)
- ✅ ETW-TI provider blind (IsEnabled=0, HVCI-safe)
- ✅ DKOM process hide (ActiveProcessLinks unlink/relink)
- 🔶 Callback repurpose (DATA write, 90% — needs selective slot targeting)
- 🔶 MiniFilter (code done, pending real-machine verify)

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
