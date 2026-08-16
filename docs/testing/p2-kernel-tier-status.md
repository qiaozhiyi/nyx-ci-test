# P2 Kernel Tier Architecture + Completion Status

> **更新:** 2026-06-27（H-K 全链路真机验证通过）
> **分支:** `p2-evasion-synced`
> **权威状态：** 详细能力清单 + gate 默认值 + 缺口见 [`STATUS.md`](STATUS.md)。本文是内核 tier 的架构速查。
>
> ⚠️ **2026-07-18 勘误：** 据独立审计 [`AUTHORITATIVE_FACTS`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)：
> (1) **PatchGuard 偏移未在真机验证**；(2) **WfpKit 永返 Err**（下表标 🔶 偏乐观，实际无可用调用路径）；
> (3) **WdtKernel 为 stub**；(4) 下表"真机 7/7 PASS"指 H–K 诊断链路，不等同于所有 kit 算法生产可用。
> ✅ **2026-08-14 更新：** (1) PG `0x190` 占位已经离线 PDB 证伪（`offsets.rs` 注释含证据，真值仍需 live-kernel dump）；(2) WfpKit 已实装 `ALE_APP_ID` 单条件过滤（不再永返 Err，Windows lab 端到端待验）；(3) WdtKernel phys 模式已接线（CR3 扫描 + MZ 门 + CLI `--wdt`，CI 真机验证待跑）。

---

## 架构

```
operator-kernelsdk/ (standalone crate, no_std, workspace green)
├── lib.rs          — KernelTier trait + no-op default
├── byovd.rs        — ByovdDriver (IOCTL seam) + VulnDriverIoctl trait（驱动包: Shield 默认 / WdtKernel phys）
├── etwti.rs        — EtwTiBlind (IsEnabled=0 via kernel write)
├── telemetry.rs    — CallbackKit + CallbackNeutralizer (repurpose/neutralize)
├── persistence.rs  — ProcessHider (DKOM) + PPL strip + PG windows
├── netsec.rs       — WFP rule gen + LSASS read framework
├── offsets.rs      — 14-build EPROCESS offset table + RuntimeOffsets
├── pattern_scan.rs — ntoskrnl byte-pattern scan
├── pagewalk.rs     — x64 4-level page walk VA→PA
└── win/
    ├── mod.rs          — bootstrap_chain() KslD→BYOVD + blind_etw_ti_full()
    ├── driver_load.rs  — NtLoadDriver registry bootstrap
    ├── kernel_base.rs  — ntoskrnl base via NtQuerySystemInformation
    ├── resolve.rs      — GetModuleHandleA + GetProcAddress + LoadLibraryA fallback
    ├── va_rw.rs        — VaKernelRw adapter (VA→PA→phys RW)
    ├── pagewalk.rs     — x64 page walk impl
    ├── ksld.rs         — KslD.sys Living-off-the-Defender KernelRw
    └── etw_deception.rs — ETW-TI provider disable orchestration
```

**驱动加载优先级链:**
```
bootstrap_chain() → Priority 1: KslD.sys (Living off the Defender)
                  → Priority 2: BYOVD fallback — 默认 Shield.sys（clean，VA memcpy）；
                    WDTKernel.sys phys 模式（--wdt，HVCI-safe）
```
（RTCore64 / iqvw64e 已于 2026-08-16 从驱动包删除——两者均在微软 Vulnerable
Driver Blocklist 上，hosted CI 实测 NtLoadDriver 0xC0000034。）

---

## Kit 完成度

| Kit | 算法 | 实现 | 真机 | 说明 |
|---|---|---|---|---|
| KernelRw (BYOVD) | ✅ | ✅ | ✅ 10MB 读 | 默认 Shield 单 IOCTL 双向 memcpy（历史真机验证用 RTCore64，已删） |
| ETW-TI Blind | ✅ | ✅ | ✅ IsEnabled→0 | 5 版本 offset 表 |
| ProcessHider (DKOM) | ✅ | ✅ | ✅ 1→0→1 | ActiveProcessLinks unlink |
| PPL Strip | ✅ | ✅ | 🔶 | offset 真机确认 |
| CallbackKit | ✅ | ✅ | ✅ EID1 SILENCED | repurpose DATA write, selective slot |
| PatchGuardKit | ✅ | ✅ | 🔴 占位已证伪 | TimingRepair + RuntimePgBypass；2026-08-14 离线 PDB 证伪 `+0x190`=`LastExceptionToRip`，真值需 live-kernel KPCR dump（门仍 OFF） |
| KslD | ✅ | ✅ | ✅ | QueryDosDeviceW enum, bootstrap_chain |
| WfpRuleSet | ✅ | ✅ | 🔶 待 lab 验证 | 2026-08-14 实装 ALE_APP_ID 单条件 block（FwpmGetAppIdFromFileName0，零条件不可能），tier 已接线；端到端待 Windows lab |
| LSASS Reader | ✅ | ✅ | 🔶 | 框架就绪 |
| PatternScan | ✅ | ✅ | 🔶 | 需真实 ntoskrnl image |

**真机验证总评:** 7/7 PASS (H-K), 所有 DATA 写 HVCI-safe, PG 未触发.

---

## 关键地址 (Server 2019 17763.1339)

| 项目 | KVA |
|---|---|
| ntoskrnl base | `0xfffff8057fa19000` |
| ntoskrnl size | 0xA70000 |
| ret gadget | `0xfffff8057fa1a7f0` (ntoskrnl+0x17F0, bytes=[c3 cc cc cc]) |
| EtwThreatIntProvRegHandle | `0xffffc30c32652c80` |
| PsActiveProcessHead | `0xfffff8057fe275c0` |
| ETW_THREAT_INT RVA | 0x40A6B0 |
| PSP_CPROCESS RVA | 0x4D9D70 |
| PS_ACTIVE_HEAD RVA | 0x40E5C0 |

---

## EPROCESS Offsets (跨版本)

| Build | PID offset | Links offset | Protection offset |
|---|---|---|---|
| 17763 (Server 2019) | 0x2e0 | 0x2e8 | 0x6ca |
| 18362 (Win10 1909) | 0x2e8 | 0x2f0 | 0x6fa |
| 19041-19045 (Win10 2004-22H2) | 0x440 | 0x448 | 0x878 |
| 20348/22000 | 0x440 | 0x448 | 0x87a |
| 22621/22631 (Win11) | 0x440 | 0x448 | 0x87a |
| 26100/26200 (Win11 24H2/25H2) | 0x1d0 | 0x1d8 | 0x5fa |
