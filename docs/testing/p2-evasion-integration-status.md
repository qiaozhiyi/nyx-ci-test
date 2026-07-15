# P2 Evasion Integration Status

> **更新:** 2026-06-27（内核 H-K 全链路真机验证完成）
> **分支:** `p2-evasion-synced`
> **授权:** 仅限授权红队 / 安全研究
> **权威状态：** 完整能力清单 + gate 默认值 + 已知缺口见 [`STATUS.md`](STATUS.md)。本文是集成进度的速查摘要。

---

## 总体完成度: ~95%

| 维度 | 完成度 | 说明 |
|---|---|---|
| 用户态 | 98% | 14 selftest 全通过，PE-sieve 0 implanted |
| 内核算法 | 100% | 全部 trait + mock test 通过 |
| 内核接线 | 100% | bootstrap_chain → KslD → BYOVD → ETW-TI → DKOM → callback |
| 内核真机 | 7/7 PASS | H→I→J→K 全链路 Server 2019 验证 |

---

## 2026-06-27 真机验证结果 (内核 H-K 全量)

| 任务 | 状态 | 关键结果 |
|------|------|----------|
| H BYOVD bootstrap | ✅ PASS | ntoskrnl=`0xfffff8057fa19000`, PE 校验, 10MB 读, 导出表 RVA |
| I ETW-TI blind | ✅ PASS | IsEnabled `0x000000ff00000001` → `0x0000000000000000` |
| J 进程隐藏 | ✅ PASS | notepad PID=7756, EPROCESS=`0xffffc30c40e83080`, tasklist 1→0→1, PG 未触发 |
| K-A probe_readonly | ✅ PASS | 10 slot 全量诊断, telemetry.rs 假设全部 PLAUSIBLE |
| K-B owner_map | ✅ PASS | slot[0]=ntoskrnl, slot[2]=WdFilter, slot[5]=SysmonDrv, slot[9]=KslD |
| K-C repurpose_test | ✅ PASS | SysmonDrv EID1 SILENCED + RESUMED (DATA write) |
| K-D neutralize_test | ❌ BSOD | 两次 triple fault, **生产禁用** |

---

## P1 任务完成状态 (全部 4 项, 2026-06-27)

| 任务 | 状态 | 说明 |
|---|---|---|
| B1 堆区域枚举 | ✅ | `ntalloc.rs` slab tracking + `mem::enumerate_beacon_heap_regions()` |
| B2 Foliage 堆掩码 | ✅ | `sleep.rs` helper RC4 遮蔽堆区域 |
| C1 KslD 动态设备 | ✅ | `QueryDosDeviceW` 枚举 MpKsl* 前缀, 3-path open |
| C2 PatchGuard windows | ✅ | `TimingRepairWindow` + `RuntimePgBypassWindow` (data-only, HVCI-safe) |

---

## P0 任务: selective slot targeting — 已完成

`CallbackNeutralizer::repurpose()` 已迁入库代码:
- Range-based ntoskrnl skip: routine 落在 `[ntoskrnl_base, base+size)` 的所有 slots 跳过
- Fallback slot[0] skip: bounds 未解析时退回只跳过 slot[0]
- DATA write (非 .text), HVCI-safe
- 真机验证: Sysmon EID1 SILENCED + RESUMED

---

## 剩余项

| 项 | 优先级 | 说明 |
|---|---|---|
| LSASS 凭据解析 | P2 | read_process_mem 框架就绪, drypt 解析未实现 |
| Win11 24H2 VM 验证 | P2 | 跨版本 offset 表 + CET 探测 |
| Pattern scan 兜底 | P3 | 未知 build 最后一道防线 |
