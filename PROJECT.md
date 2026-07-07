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
- `docs/` - **Authoritative status: [`docs/STATUS.md`](docs/STATUS.md)** + **code-audited capability inventory: [`docs/CAPABILITY_AUDIT_2026-07-05.md`](docs/CAPABILITY_AUDIT_2026-07-05.md)**. Live dev docs (capabilities, handoff, real-machine results). `docs/archive/` holds superseded audit/research docs (historical, not authoritative).
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
| 8 | M8. Win11 24H2 Real-Machine | Cross-version offset + CET verify on Win11 24H2/25H2 | M7, Win11 VM | 🔶 PARTIAL (CI compiles on 26100, selftest blocked by HVCI on runners) |
| 8b | P6. Military-Grade Sleep + Stack Spoof + Kernel TUI | Fluctuation + LACUNA + IOC audit + BYOVD driver pack + kernel TUI wiring | M7 | ✅ DONE (2026-07-07, 54/54 selftest, workspace 0 errors) |
| 8c | **P7. V2 Evasion Countermeasures** | CFG user-mode bypass + DR sleep sanitization + caller-spoof stub scanner + VEH proxy gadget scanner — four countermeasures, zero kernel driver | M8b | ✅ DONE (2026-07-07, 54/54 selftest on 17763.1339) |
| 10 | M10. Lateral Movement V1 | LSASS dump + Kerberoasting + PtH + WMI/DCOM lateral | None | 🎯 PLANNED — §C5 |
| 11 | M11. Anti-Forensics V1 | Windows timestomp/USN/Prefetch/EventLog cleanup + memory-only path | None | 🎯 PLANNED — §C4 |
| 12 | M12. Cross-Platform V1 | `implant-core` trait + Linux production implant | None | 🎯 PLANNED — §C2 |
| 13 | M13. Delivery & Exploit V1 | stager + multi-stage loader + 1 N-day LPE chain + payload polymorphism | None | 🎯 PLANNED — §C3 |
| 14 | M14. Server Federation V1 | 3-node Raft + session migration + operator cooperative locks | None | 🎯 PLANNED — §C6 |
| 15 | M15. macOS Implant + Integration | Mach-O dylib implant + amfid/ES bypass + full-pillar integration | M12 | 🎯 PLANNED — §C2 |
## National-Tier Roadmap (2026-07-07)

> **详细计划:** [`docs/ROADMAP_2026-2027.md`](docs/ROADMAP_2026-2027.md) — 18-24 个月从当前 P7 到 Nyx 2.0 GA 的分阶段演进蓝图。
> **六根支柱:** 流量韧性(C1) · 跨平台(C2) · 交付链(C3) · 反取证(C4) · 横向移动(C5) · 服务器联邦(C6)。
> M9–M15 是分阶段里程碑，每阶段独立可验证。
> 范围外项目（0day 研发、移动端 0click、固件/OT）在路线图 §7 中列为外部依赖。


## Bypass Module Status (2026-06-27)

> **Authoritative detail: [`docs/STATUS.md`](docs/STATUS.md).** Numbers below are a summary.

**Overall completion: ~97%** (userland 99%, kernel algo 100%, wiring 100%). P6 Fluctuation+LACUNA+IOC audit closed 2026-07-07. All selftests pass on Server 2019 (17763.1339).

### Userland (implant-win) — all default ARMED
- ✅ Indirect syscalls (Hell/Halo/Tartarus SSN)
- ✅ HWBP patchless blind (zero `.text` modification, VEH chain probe) + byte-patch blind
- ✅ **Fluctuation sleep mask** (PAGE_NOACCESS oscillation, CFG/CET immune) — replaces Foliage
- ✅ **LACUNA ghost-frame scanner** (.pdata gap discovery + BYOUD-Gap stack injection)
- ✅ Module stomping + ThreadlessInject (HWBP) + **Pool Party section injection**
- ✅ BYOUD-Gap RSP swap (CET-aware; `SPOOF_SWAP_ENABLED` default **OFF**)
- ✅ Memory region encryption (RC4) + heap slab tracking
- ✅ ntdll unhook (KnownDlls + disk fallback) + anti-debug
- ✅ **Post-ex token operations**: `StealToken`/`MakeToken`/`Rev2Self`/`GetUid`

### Kernel (operator-kernelsdk)
- ✅ **Pluggable BYOVD driver pack** — Shield/Horizon (default, clean July 2026) + WDTKernel/Dell (HVCI-safe) + RTCore64 + IQVW64E; `NYX_BYOVD=<name>` build-time selection
- ✅ ETW-TI provider blind (IsEnabled=0, HVCI-safe)
- ✅ DKOM process hide (ActiveProcessLinks unlink/relink)
- ✅ Callback repurpose (DATA write, selective slot targeting)
- ✅ PatchGuard windows — TimingRepairWindow + RuntimePgBypassWindow
- ✅ MiniFilter — auto-resolves FltGlobals RVA via build table (17763/19041/22621/26100)
- ✅ **CFG bitmap kernel write** (cfg.rs) — marks NtContinue valid via kernel r/w
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
