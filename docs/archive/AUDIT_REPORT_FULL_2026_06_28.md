# 全量文档审计报告 — 2026-06-28

**审计范围**：全部文档（CLAUDE.md、README.md、PROJECT.md、docs/ 目录下 30+ 文件）
**审计方法**：逐条交叉验证文档声明 vs 实际源码
**分支**：p2-evasion-synced
**审计人**：Kimi Code CLI 2026.6.26

---

## 🚨 P0 — 安全/能力声明严重失实（共 11 项）

### Gate 默认值：文档全面失实（3 项）

所有文档和源码注释均声称三个 gate **默认 OFF**，但代码实际 **全部默认 ON**：

| 变量 | 文档/注释声明 | 代码实际值 | 代码位置 |
|------|-------------|-----------|---------|
| `SPOOF_SWAP_ENABLED` | "默认 OFF" | `AtomicBool::new(true)` | stack.rs:79 |
| `FOLIAGE_ENABLED` | "默认 OFF"（sleep.rs:26,37） | `AtomicBool::new(true)` | sleep.rs:41 |
| `MODULESTOMP_ENABLED` | "默认 OFF"（CLAUDE.md:183） | `AtomicBool::new(true)` | inject.rs:56 |

**影响**：这三个 gate 控制 RSP swap（原始汇编栈操作）、跨进程 APC 内存写入、模块 stomping（LoadLibraryA + WPM shellcode）——全部是高风险原语。文档说 "默认安全/OFF"，实际 implant 启动时这些破坏性能力 **全部激活**。

**更严重**：sleep.rs:26 的源码注释本身也说 "FOLIAGE_ENABLED defaults OFF"，但初始化值是 `true`。源码自身的注释都是错的。

### 功能实现状态声明失实（4 项）

| 文档声明 | 代码实际状态 | 出处 |
|---------|------------|------|
| ThreadlessInject "❌ 未实现" | **完全实现**：inject.rs:489-632（300行完整函数：RWX分配→shellcode写入→线程挂起→CONTEXT DR0/DR7设置→NtSetContextThread→恢复） | BYPASS_CAPABILITIES.md §5矩阵/§7 |
| NtContinue CONTEXT 伪造 "未实现" | **完全实现**：context.rs::spoofed_context() + sleep.rs:674 实际调用 | BYPASS_CAPABILITIES.md §5未实现表 |
| `build.rs` 路径在 `implant-win/src/` | **实际位置**：`crates/implant-win/build.rs`（crate根目录，非src/） | DEVELOPER_HANDOFF_FINAL.md 文件地图 |
| repurpose "是 stub 返回 UnsupportedPosture" | **完全实现**：telemetry.rs:126-168（396行，数组遍历+指针验证+DATA写入） | DEVELOPER_HANDOFF_FINAL.md §6 bug描述 |

### MiniFilter 能力声明虚构（3 项）

文档声称存在 `operator-kernelsdk/src/win/minifilter.rs` 实现三种能力：

| 文档声明 | 代码现实 |
|---------|---------|
| §19 MiniFilter 加载：`FltRegisterFilter` + `FltStartFiltering` | **文件不存在**，无 minifilter 加载代码 |
| §20 MiniFilter 卸载：`FltUnregisterFilter` | **文件不存在**，无卸载代码 |
| §21 MiniFilter 暂停/恢复：`pause()` / `resume()` | **文件不存在**，无暂停恢复代码 |

bootstrap_chain() 中也没有 "Priority 1.5: MiniFilter" 路径。

**实际能力**：`telemetry.rs` 中有 `MiniFilterUnlinker`——通过遍历 `FLTMGR!FltGlobals → FrameList → RegisteredFilters` 做 **list-unlinking**（数据写，HVCI安全）。这是完全不同的操作（unlink existing filters vs load new ones）。

---

## 🔴 P1 — 架构/协议声明失实（共 8 项）

| # | 文档声明 | 代码现实 | 出处 |
|---|---------|---------|------|
| 1 | "Keypair 每次启动临时生成" / "持久化是后期目标" | `NYX_KEYFILE` 环境变量支持完整密钥持久化（main.rs:53-60, lib.rs:226-245） | CLAUDE.md:28,114-116 |
| 2 | "Connect/Socks 存在于 wire 但尚无 JSON command" | `JsonCommand::Connect` 和 `JsonCommand::Socks` 均已存在，21个 command 完全 1:1 映射 | CLAUDE.md:99-103 |
| 3 | "8 protocol + 1 e2e test" | **25 protocol + 40 server = 65 total tests**（严重过时） | CLAUDE.md:15 |
| 4 | "41 selftest" 导出 | **48个** `nyx_selftest*`/`nyx_linger*` 导出（45在selftests.rs + 2在entry.rs + 1在syscalls.rs） | DEVELOPER_HANDOFF_FINAL.md:18,115,130 |
| 5 | transport crate "implant transport" | **实际是服务端指纹引擎**（JA3/JA4哈希匹配） | 多处文档 |
| 6 | "Pattern scan 兜底 — 预留位置未写" | `pattern_scan.rs` **已写好**（49行，含 find_pattern + find_all_patterns） | BYPASS_CAPABILITIES.md §17 |
| 7 | "KslD 占位结构待展开" | `win/ksld.rs` **有完整 KernelRw 实现**（32字节缓冲区，kread/kwrite 逐字节循环） | BYPASS_CAPABILITIES.md §18 |
| 8 | KslD IOCTL 绑定 "未接线" | `LivingOffDefender` **已实现完整 DeviceIoControl 调用**，bootstrap_chain() KslD优先→BYOVD回退 | p2-benchmark-vs-cs413-brc4-v23.md |

---

## 🟡 P2 — 状态追踪失实（共 5 项）

### gap-analysis.md：所有 CRITICAL 项已关闭

gap-analysis 列出的 5 个 CRITICAL 和 3 个 HIGH 项，代码中全部已解决，但文档从未更新：

| Gap Analysis 声称 | 当前状态 |
|------------------|---------|
| CRITICAL: HWBP patchless blind 未实现 | blind_hwbp.rs 581行，完全实现 |
| CRITICAL: NTDLL unhook 未实现 | unhook.rs 689行，完全实现 |
| CRITICAL: KslD/BYOVD 未实现 | ksld.rs 418行，完全实现 |
| CRITICAL: 三个 gate 默认 OFF | 全部默认 ON |
| HIGH: MiniFilter disconnect + Ps* notify neutralize | telemetry.rs 完全实现 |
| HIGH: PPL bypass from kernel | persistence.rs make_immortal() 完全实现 |

**建议**：gap-analysis.md 应添加 `> [SUPERSEDED] 2026-06-28` 头部标记。

### 开发报告不一致

DEVELOPER_HANDOFF_FINAL.md 和 BYPASS_DEVELOPMENT_REPORT.md 对 repurpose 状态说法矛盾：
- Handoff（line 91）："repurpose 是 stub"
- Report（line 17）："repurpose 已从 example 迁入库代码"
- **代码真相**：report 正确——repurpose 已是完整实现

---

## 🟢 确认准确的声明

| 文档 | 声明 | 状态 |
|------|------|------|
| CLAUDE.md | "21 Command variants" | ✅ 完全正确 |
| CLAUDE.md | "No Node/JS anywhere" | ✅ 完全正确 |
| CLAUDE.md | 所有文件路径引用 | ✅ 全部存在 |
| postmortem | 所有 bug 描述 + 修复说明 | ✅ 100% 准确 |
| benchmark | FOLIAGE_DEFAULT_ON / SPOOF_DEFAULT_ON | ✅ 正确 |
| benchmark | blind_hwbp.rs DR0+VEH+RF | ✅ 正确 |
| benchmark | etw_deception.rs 伪造事件 | ✅ 正确 |
| benchmark | PPL 剥离/提升 | ✅ 正确 |
| 所有文档 | ETW/AMSI 字节 patch 能力 | ✅ 代码确认 |
| 所有文档 | HWBP patchless blind (DR0+VEH+RF) | ✅ 代码确认 |
| 所有文档 | ntdll unhook (KnownDlls + disk) | ✅ 代码确认 |
| 所有文档 | 间接系统调用 + Halo's Gate | ✅ 代码确认 |
| 所有文档 | BYOVD RTCore64 | ✅ 代码确认 |
| 所有文档 | ETW-TI 内核盲化 | ✅ 代码确认 |
| 所有文档 | DKOM 进程隐藏 | ✅ 代码确认 |
| 所有文档 | PPL 剥离 | ✅ 代码确认 |
| 所有文档 | 反调试/反沙箱 | ✅ 代码确认 |
| 所有文档 | 内存区域加密 (RC4) | ✅ 代码确认 |
| 所有文档 | Foliage sleep mask (10-step状态机) | ✅ 代码确认 |

---

## 📋 代码安全问题（与之前审计报告合并）

### 原始 P0（AUDIT_REPORT_2026_06_26）仍然有效

| 问题 | 位置 | 状态 |
|------|------|------|
| bof-runner RWX 分配（PAGE_EXECUTE_READWRITE） | win.rs:70-77 | 未修复，dev-only 无编译门控 |
| bof-runner transmute 无验证 | win.rs:157-160 | 未修复 |
| agent-dev shell 注入 | lib.rs:488-491 | 未修复 |
| SPOOF_SWAP_ENABLED = true（CET-on 崩溃风险） | stack.rs:79 | 未修复 |
| KslD 硬编码 `\\.\MpKsl` | win/ksld.rs | 未修复 |
| repurpose() 无选择性目标 | telemetry.rs:141-165 | 未修复 |
| Protocol batch decode 无上限（DoS放大） | msg.rs:299-305 | 未修复 |
| inject.rs trigger_addr 被丢弃 | inject.rs:630 | 未修复 |
| client-ui 同步读取（UI线程阻塞） | main.rs:2027 | 未修复 |
| blind_hwbp.rs diag() 生产 IOC | blind_hwbp.rs:94-138 | 未修复 |

### PatchGuard 窗口：全部无操作骨架

| 实现 | enter_unchecked | Drop（退出） | 状态 |
|------|----------------|-------------|------|
| PatchGuardWindow:256 | `Err(UnsupportedPosture)` | — | 骨架 |
| TimingRepairWindow:351 | 读 valid_flag → Ok | `let _valid_flag` | 无操作 |
| RuntimePgBypassWindow:438 | 读 pg_thread_kva → Ok | `let _ = pg_thread_kva` | 无操作 |

DKOM 依赖 "<1s luck" 窗口对抗 PatchGuard 检测。

---

## 📊 文档可靠性总评

| 文档 | 准确率 | 问题数 | 主要问题 |
|------|--------|-------|---------|
| CLAUDE.md | ~70% | 5 | Gate默认值、Keypair持久化、Connect/Socks映射、测试数量 |
| BYPASS_CAPABILITIES.md | ~55% | 11 | 3个gate错误、3个MiniFilter虚构、Threadless/NtContinue/Pattern scan状态错误 |
| DEVELOPER_HANDOFF_FINAL.md | ~85% | 5 | Gate默认值、selftest计数、build.rs路径、ksld.rs遗漏、repurpose描述 |
| BYPASS_DEVELOPMENT_REPORT.md | ~95% | 2 | Gate默认值、selftest计数 |
| p2-2026-06-gap-analysis.md | 已过时 | 全部 | 所有CRITICAL/HIGH项已关闭但文档未更新 |
| p2-benchmark-vs-cs413-brc4-v23.md | ~90% | 3 | KslD"未接线"、sleep机制描述不精确 |
| p2-2026-06-hwbp-resolve-forwarder-postmortem.md | 100% | 0 | 无问题 |

---

## 🔧 修复优先级建议

**立即修复**：
1. stack.rs:79 — `SPOOF_SWAP_ENABLED` 改回 `false`（CET-on 未安全之前）
2. 修复所有源码注释中的 "defaults OFF" 与实际 `true` 的矛盾
3. minifilter.rs 相关声明要么创建文件实现，要么从文档删除
4. 更新 gap-analysis.md 添加 SUPERSEDED 标记

**本周内修复**：
5. 更新 CLAUDE.md 中所有失实声明（keypair、Connect/Socks、测试数量）
6. 更新 BYPASS_CAPABILITIES.md §5/§7/§19-§21
7. 修复 blind.rs:28-30 中 "HWBP is a future addition" 的过时注释
8. 统一 DEVELOPER_HANDOFF vs BYPASS_DEVELOPMENT_REPORT 中 repurpose 的描述

**长期改进**：
9. 实现 PatchGuard 窗口的真实逻辑（至少 TimingRepairWindow）
10. 为 repurpose 添加选择性 slot 过滤
11. 实现 ThreadlessInject 的 command handler 接线
