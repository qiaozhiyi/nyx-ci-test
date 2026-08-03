# Nyx C2 框架 — 究极远见能力调查报告

> ⚠️ **设计/历史文档** — 本文档成文于 2026-07-10，能力状态可能已演进。
> 最新事实以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。

> **调查日期:** 2026-07-10
> **方法:** 全栈源码审查（25 crate / 77K 行）× 三轮审计交叉验证 × 2025–2026 年 C2/evasion 领域 SOTA（state-of-the-art）全量检索（exa + context7 + web reader，30+ 篇 2026 年技术文献）
> **工具链:** Exa search × 8 轮 · Context7 docs × 3 轮 · web reader × 3 篇全文 · 10 路并行子报告审计
> **授权语境:** 授权红队 / 安全研究工具改进。本报告不含可直接武器化的利用细节。

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [项目架构全景](#2-项目架构全景)
3. [远见能力逐域评估](#3-远见能力逐域评估)
   - 3.1 [语言选型与二进制指纹](#31-语言选型与二进制指纹)
   - 3.2 [Sleep Obfuscation 与内存波动](#32-sleep-obfuscation-与内存波动)
   - 3.3 [Syscall 执行架构](#33-syscall-执行架构)
   - 3.4 [调用栈伪装](#34-调用栈伪装)
   - 3.5 [AMSI/ETW 致盲](#35-amsietw-致盲)
   - 3.6 [进程注入与模块踩踏](#36-进程注入与模块踩踏)
   - 3.7 [内核层 BYOVD 与 callback 对抗](#37-内核层-byovd-与-callback-对抗)
   - 3.8 [传输层与多信道](#38-传输层与多信道)
   - 3.9 [加密核心与协议](#39-加密核心与协议)
   - 3.10 [MCP/LLM 信道——AI 流量伪装](#310-mcp-llm-信道-ai-流量伪装)
4. [检测方 2026 工具箱全景](#4-检测方-2026-工具箱全景)
5. [项目远见 vs 检测方能力对照矩阵](#5-项目远见-vs-检测方能力对照矩阵)
6. [盲区分析——被检测窗笼罩的技术点](#6-盲区分析-被检测窗笼罩的技术点)
7. [领先分析——超越同代的设计决策](#7-领先分析-超越同代的设计决策)
8. [远见修正路线图](#8-远见修正路线图)
9. [与同代 C2 框架对比](#9-与同代-c2-框架对比)
10. [结论](#10-结论)
11. [研究来源](#11-研究来源)

---

## 1. 执行摘要

本报告对 Nyx C2 框架的**技术远见能力**（foresight / vision）进行全量评估，核心问题是：**项目当前实现的规避（evasion）技术，在 2026 年 Q2–Q3 的攻防军备竞赛中，处于什么位置？哪些已经进入检测方的瞄准镜？哪些仍然领先？**

### 核心发现

1. **MCP/LLM 信道是项目最强的远见** — 在 arXiv 2025-11 论文正式定义 MCP-based C2 之前，Nyx 已完成工程实现并接线进 7 信道 TransportStack。这是公开 C2 项目中唯一覆盖 AI 流量伪装的。

2. **纯 Rust `no_std` PIC implant 是正确的结构性赌注** — Go 系 C2（Sliver）的二进制签名已被所有主流 EDR 收录；Rust `no_std` + `opt-level=z` + LTO 无运行时、无 Go signature、编译器设置微调即改变二进制。同时代的其他 Rust C2（Proteus、Kraken、CloakCat、Red-Cell-C2）仍在早期阶段。

3. **Sleep obfuscation（fluctuation PAGE_NOACCESS）是最关键的远见盲区** — 2023 Black Hat Asia 发表的 CFG-FindHiddenShellcode + EtwTi-FluctuationMonitor 已在 2026 被工程化为可用产品级检测。Nyx 的 RX→NOACCESS→RX 循环恰好是这两个检测器的目标模式。下一代技术 "flower"（JIT-mimicry / move-and-free）已开源，PIC implant 天然适合这条迁移路径。

4. **BYOVD 战略判断正确但 3/4 驱动包损坏** — 项目正确判断 HVCI 下 inline hook 已死 → 数据+时序策略，但审计发现 iqvw64e / WDTKernel / Shield 都走 RTCore64 字节循环，只有 RTCore64 正确工作。2026 年 MITRE ATT&CK v19 新增 "Impair Defenses" 战术，BYOVD 已成勒索软件标准前置。

5. **加密核心修复质量最高** — CSPRNG Result 传播、SessionKey zeroize+compiler_fence Drop、HKDF `server_pub` salt、`subtle::ConstantTimeEq` — 全部经人工逐行核验，零活跃 CRITICAL。

6. **ETW-TI 是不可绕过的 invariant** — 任何用户态技术都无法阻止内核态 `KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL` 事件。唯一消费端绕过：BYOVD 内核驱动操作 ETW-TI provider 注册——但 Microsoft 通常 1–2 个 servicing release 内修复。

### 远见能力总评

```
┌────────────────────────────┬──────┬──────────────────────────────────────────┐
│ 维度                        │ 评分 │ 核心判断                                  │
├────────────────────────────┼──────┼──────────────────────────────────────────┤
│ 语言/架构选型                │  S   │ 纯 Rust no_std PIC — 领先 Go 系           │
│ 信道前瞻（MCP/LLM）          │  S   │ 工程领先学术论文，同代唯一                 │
│ Sleep obfuscation           │  C+  │ PAGE_NOACCESS 设计已被 2026 POC 击穿       │
│ Syscall evasion             │  B-  │ indirect 对齐但缺 gadget diversity         │
│ 调用栈伪装 (LACUNA)          │  A   │ 原创性强，.pdata gap 思路超前               │
│ AMSI/ETW 致盲               │  A-  │ HWBP patchless 思路正确                    │
│ 进程注入 (Module stomp)      │  B   │ 实现对齐但 .text hash-mismatch 未解        │
│ 内核层 (BYOVD)              │  C   │ 战略对但 3/4 驱动损坏                      │
│ 网络指纹伪装                 │  C+  │ JA3/JA4 引擎有但 emission 未接线           │
│ 加密核心                    │  A+  │ 三轮审计验证，零活跃 CRITICAL              │
│ 工程纪律/可验证性            │  A   │ 三轮审计 + 53 真机 selftest                │
│ 路线图完整性                 │  B+  │ CNSA-2/QUIC/air-gap 都有设计文档           │
├────────────────────────────┼──────┼──────────────────────────────────────────┤
│ 综合                        │ B+   │ 同代公开项目中最前沿梯队之一               │
│                             │      │ 核心短板：sleep obfuscation 代差            │
└────────────────────────────┴──────┴──────────────────────────────────────────┘
```

---

## 2. 项目架构全景

### 2.1 规模

| 维度 | 数值 |
|---|---|
| 代码行数 | 69,509 行 Rust（审计调整为 ~77,000 行含修复 diff） |
| Crate 总数 | 25（20 workspace 成员 + 4 独立 + 1 已排除） |
| Windows PIC implant 模块 | 42 个 `#![no_std]` / `#![no_main]` 模块 |
| 内核 SDK 模块 | 24 个 |
| 真机 selftest | 53 个（Server 2019 17763.1339 全 pass） |
| Wire Command 变体 | 26 个 |
| 传输信道 | 7 个（HTTPS / DoH / Slack / LLM / MCP / WebTransport / SMB） |
| BYOVD 驱动 | 4 个（RTCore64 / iqvw64e / WDTKernel / Shield） |
| Windows 构建覆盖 | 17763 / 19041 / 20348 / 22621 / 26100 |

### 2.2 Crate 角色映射

```
┌──────────────────────────────────────────────────────────────────┐
│                     Nyx 架构拓扑                                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐           │
│  │ client-cli   │  │ client-ui   │  │ operator-kernel │           │
│  │ (TUI/REPL)   │  │ (Makepad)   │  │ -cli / -sdk     │           │
│  └──────┬───────┘  └──────┬──────┘  └────────┬────────┘           │
│         │    REST API JSON │                  │ kernel API         │
│  ───────┴──────────────────┴──────────────────┴──────────           │
│                          ┌────────┐                                 │
│                          │ server │ ← team server                   │
│                          │ (HTTP) │ ← /beacon (binary frame)         │
│                          └───┬────┘ ← /api/* (JSON control)         │
│                              │                                     │
│              ┌───────────────┼───────────────┐                     │
│              │               │               │                     │
│      ┌───────┴──────┐ ┌─────┴──────┐ ┌──────┴───────┐             │
│      │  protocol     │ │ transport  │ │  implant-win │             │
│      │ (crypto+wire) │ │ (7 channel)│ │ (no_std PIC) │             │
│      └──────────────┘ └────────────┘ └──────────────┘             │
│              │               │               │                     │
│      ┌───────┴──────┐ ┌─────┴──────┐ ┌──────┴───────┐             │
│      │ config/macros │ │ evasion    │ │ coff (BOF)   │             │
│      │ profile       │ │ (SSN+indir)│ │ store/script │             │
│      └──────────────┘ └────────────┘ └──────────────┘             │
│                                                                    │
│  agent-dev (std dev implant — proves loop, NOT production)         │
└──────────────────────────────────────────────────────────────────┘
```

### 2.3 三轮审计发现总览

| 维度 | 07-08 总数 | 已修复 | 部分修 | 仍在 | 新发现 | 活跃合计 |
|---|---|---|---|---|---|---|
| CRITICAL | 9 | 5 | 2 | 2 | 0 | **0 残留** |
| HIGH | 25 | 7 | 5 | 13 | +7 | **20** |
| MEDIUM | 39 | 1 | 0 | 38 | +12 | **50** |
| LOW | 39 | 0 | 0 | 39 | +~20 | **~59** |

**关键结论：** 全部 9 CRITICAL 已被修复或降级——当前零活跃 CRITICAL。加密核心修复质量最高。但修复 diff 本身引入了 7 个新 HIGH（ntalloc UAF 回归最危险）。

---

## 3. 远见能力逐域评估

### 3.1 语言选型与二进制指纹

#### 项目实现
- 纯 Rust，全栈无 C/Go/Python 运行时依赖（GUI 用 Makepad 纯 Rust）
- `implant-win`: `#![no_std]` + `#![no_main]`，nightly + `x86_64-pc-windows-gnu`
- Workspace `[profile.release]`: `opt-level = "z"`, `lto`, `panic = "abort"`, `strip`
- 手写 LE binary wire codec（非 protobuf）——刻意去依赖以减少静态指纹面
- 每次 build 通过 `config-macros` proc-macro 随机化配置密钥/布局

#### 行业 SOTA 对标（2026）

2026 年多篇 C2 框架研究明确指出 **Go 二进制签名已被全面收录**：

> "Sliver — Go binary signature is increasingly recognised by EDRs. Use it to learn C2 operations properly; for production engagements against hardened targets, profile it against your target's specific EDR first."  
> — securityelites.com, C2 Frameworks 2026

> "Go binaries carry a runtime, carry a recognizable binary signature, and run large. Rust can go all the way to no_std, minimizing both binary size and detection surface."  
> — CloakCat Red Team Labs (2026-03, Rust C2 架构评测)

多个 2026 年新出现的 Rust C2 项目验证了这个趋势：
- **Proteus** (2026-04): `no_std`/`no_main` Mythic agent, per-build function shuffle + ChaCha20 数据段加密
- **Kraken** (2026-04): OPSEC-first Rust C2, ~50KB implant
- **CloakCat** (2026-03): Rust C2，明确选择 Rust 是为了 "eliminate entire classes of memory bugs at compile time"
- **Red-Cell-C2** (2026-03): Havoc 的 Rust 重写，teamserver + client 全 Rust

#### 远见评级：**S 级**

Nyx 在 2026-07 已达到的 Rust `no_std` PIC 成熟度（42 模块、53 selftest、真机验证）远超上述 2026 年新项目。**语言选型的前瞻性已被行业验证**——但 Nyx 的领先优势正在缩小，因为其他 Rust C2 项目在快速跟进。

**Nyx 的独特优势：**
1. `no_std` hand-rolled wire codec（不是 protobuf）——Proteus/Kraken/CloakCat 都还没做到完全 `no_std` 的 wire 层
2. `config-macros` 的 per-build 随机化（不只是编译参数，是结构层随机化）
3. 53 个真机 selftest 的验证深度——其他项目最多有单元测试

**潜在风险：**
- Rust 二进制逆向工程工具不成熟（linky 项目指出 "harder to reverse than Go/Python — limited RE tooling for Rust binaries"），这目前是优势——但当 Rust C2 普及后，RE 工具会跟进

---

### 3.2 Sleep Obfuscation 与内存波动

#### 项目实现

**`fluctuation.rs`（P6 军事级）：**
- PAGE_NOACCESS 振荡：sleep 时 `.text` → PAGE_NOACCESS，wake 时 → RX
- 通过独立分配的 RX trampoline 页调用 `NtProtectVirtualMemory` + `NtDelayExecution`
- **CFG/CET 免疫**：无 APC、无线程劫持、无 `NtContinue` CONTEXT 链
- RAII `MaskGuard`/`DrGuard` 保证 unmask + DR 恢复在 early-exit 路径
- `mem.rs`: RC4 就地加密注册的数据区域（key 从 syscall runtime 派生，每次启动不同）
- `.text` 自加密被门控（RX→RW 是 code-integrity 信号）—— 只 mask 数据不 mask 运行代码

**审计发现问题：**
- CRIT-5 降级为 HIGH-8：fluctuation RAII 守卫不覆盖硬件异常——`.text` 为 NOACCESS 时 APC/异常 dispatch 触及 .text 地址 → 进程终止，Drop 不跑。`panic=abort` 下无 unwinder

#### 行业 SOTA（2026 Q1–Q2）——这是本项目最大的远见盲区

**2026 年的检测突破已经把传统的 fluctuation 技术击穿了。** 关键进展来自三个方向：

##### 检测突破 1：CFG-FindHiddenShellcode（Black Hat Asia 2023 → 2026 工程化）

> "The CFG bitmap, as an unintended side-effect, will record the location of every private memory region that are or were previously executable during the lifetime of the process."  
> — John Uhlmann, Black Hat Asia 2023

CFG bitmap 在区域被标记为 executable 时更新，但标记为 non-executable 时**不更新**。这意味着：
- **Nyx 的 RX→NOACCESS→RX 循环在 CFG bitmap 上留下永久足迹**
- 任何曾经 executable 过的 private memory 区域，即使当前是 NOACCESS，也会被 CFG bitmap 标记
- 检测成本极低（bitmap 遍历），假阳性极少

Binary Defense 2024-08 测试发现 CFG-FindHiddenShellcode 当时无法检测 Havoc 的 Ekko/FOLIAGE（因为 C2 已应用 bypass），但 **2026 年的实现已大幅改进**。

##### 检测突破 2：EtwTi-FluctuationMonitor（不可绕过的 invariant）

> "It is security best practice that, once a page is marked executable, it should be immutable."  
> — EtwTi-FluctuationMonitor (jdu2600)

利用 ETW-TI `KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL` 事件监控每次 `NtProtectVirtualMemory`：
- 事件由 `ntoskrnl.exe` 内核发射，**任何用户态技术都无法阻止**
- 只需 PPL-Antimalware 级别即可消费
- 检测逻辑：executable memory 被改为 non-executable 超过一次 → 告警
- **Nyx 的 RX→NOACCESS→RX 循环每次 sleep 都触发两次 PROTECTVM 事件**——完美的检测信号

这是 justruss.tech (2026-06-21) 确认的 **"survives the full evasion stack" 的唯一 invariant**：

> "The invariant that covers everything is page protection transitions logged by ETW, because it fires in kernel mode on every NtProtectVirtualMemory call and cannot be intercepted or suppressed by any user-mode technique."

##### 检测突破 3：HSB v2 (Hunt-Sleeping-Beacons) + PATRIOT

- HSB v2 检测 `KiUserApcDispatcher` + timer/callback 指向 `NtContinue`
- PATRIOT 检查 CONTEXT struct 的 `Rip` 是否指向 `*Protect` 函数
- EkkoMod (2026-01) 通过将 timer callback 指向 `NtContinue` 前 8 字节的 `nop` 区域绕过 HSB——但这是猫鼠游戏

##### 下一代规避：flower（JIT-mimicry / move-and-free）

sillywa.re 在 2026 年发表的 "flower" 技术是针对上述检测的解法：

> "By making our beacon move itself in memory we can simulate JIT behavior and slip through an honest gap in those detections."

flower 的核心：**停止 fluctuation（无限翻转保护），改为 JIT-mimicry（move-and-free）**
- 每次 sleep：分配新 RW 区域 → `memcpy` beacon 到新区域 → 新区域设 RX → sleep → free 旧区域
- 模拟合法 JIT 的 `Allocate(RW) → memcpy → Protect(RX) → execute → Free` 生命周期
- CFG bitmap 不会标记新区域（因为它从未被 executable 过然后改为 non-executable）
- ETW-TI 看到的是 `RW→memcpy→RX→FREE`——合法 JIT 行为

**关键：flower 论文明确指出 PIC implant 比 RDLL 更适合这条路径：**

> "It would be way better for the beacon to be fully PIC and not a RDLL due to the fact that the former will only require to be moved into another RX region whereas a RDLL will basically require to be remapped."

Nyx 是纯 PIC implant——**flower 迁移的技术基础已经具备**。

##### 2026-06 最新进展：StealthPalace / Kraken Mask

Maor Sabag (2026-06-06) 发表的 StealthPalace 实现了 CFG+CET 兼容的 sleep obfuscation：
- `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)` 注册所有 ROP gadget 为 CFG-valid target
- CET 兼容：只交换 TIB stack bounds（不修改 RIP），保留真实 RIP 一致性
- Kraken Mask 用 `NtQueueApcThread` 替代 timer，更安全地恢复 TIB

**Nyx 的 `cfg_user.rs` 已经实现了 `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)`** ——但这是用于 CFG 注册，不是用于 sleep chain。Nyx 的 fluctuation 不用 ROP/timer/APC（它用独立 trampoline 页直接调 `NtProtectVirtualMemory`），所以 CET 兼容性不是问题。**但 PAGE_NOACCESS 循环本身才是检测目标。**

#### 远见评级：**C+ 级**

**这是项目最大的远见盲区。** fluctuation 的设计在 2022–2023 年是前沿的（CFG/CET 免疫的独立 trampoline 思路有创意），但 2026 年的检测方已经把 **保护状态翻转** 作为核心 invariant 来检测。无论用什么机制（APC / timer / trampoline）来实现翻转，翻转本身就是信号。

**修正方向：** 研究 flower 式 JIT-mimicry 迁移。Nyx 的 PIC 特性 + ntalloc bump allocator + `mem.rs` 的 mask 机制为这条路径提供了天然基础。

---

### 3.3 Syscall 执行架构

#### 项目实现

- `syscalls.rs`: indirect-syscall runtime — SSN table + ntdll `syscall;ret` gadget + RX trampoline
- `syscall!` 宏 + global accessor
- SSN 解析通过 Hells/Halo/Tartarus Gate（逻辑在 `nyx-evasion` crate）
- `unhook.rs`: 从 `\KnownDlls\ntdll` 映射 fresh ntdll 拷贝恢复 pristine SSN + clean `syscall;ret` gadget；RAII unmap（KnownDlls 映射本身是 ETW-TI 签名）
- `resolve.rs`: PEB walk + djb2 hash；处理 PE forwarded exports（0xC0000005 postmortem bug 已修）

#### 行业 SOTA（2026）

**2026 年 syscall 检测已从"检测 stub 位置"进化到"检测调用模式"：**

##### Elastic 的行为规则（2026 活跃）

Elastic protections-artifacts 仓库中有三条直接针对 indirect/direct syscall 的规则：

1. **"Direct Syscall from Unsigned Module"**: 检测 `process.Ext.api.behaviors == "direct_syscall"` + call stack final user module 不是 trusted signed module
2. **"VirtualProtect via Indirect Random Syscall"**: 检测 VirtualProtect 调用但 call stack 中无 `NtProtectVirtualMemory`/`ZwProtectVirtualMemory` symbol，且 call stack summary 包含 `"ntdll.dll|Unbacked"` 或 final user module = `Unbacked`
3. **"Potential Library Load via ROP Gadgets"**: 检测敏感 DLL 加载但 call stack 缺少合法 `Ldr*`/`LoadLibrary` symbol

##### K2 检测引擎（2026-05，titansoftwork.com）

K2 是一个专用内核驱动级 syscall 检测引擎，实现了 **Frame0 + Frame1 双层验证**：

- **Frame0**（syscall-facing frame）：必须指向 `ntdll.dll` 或 `win32u.dll` 的正确 export
- **Frame1**（caller frame）：不能指向 executable private memory
- **严格 export 匹配**：如果事件期望 `NtOpenProcess`，但 Frame0 落在 `NtClose` 的 export 范围 → 标记为 indirect/spoofed

> "A stack spoof that only fixes the first frame is useless."  
> — K2 检测引擎设计

##### dcodezero 实战报告（2026-03）

> "Elastic's defense team documented that they scan for `jmp` instructions that target `syscall` gadgets in ntdll. If your implant has a bunch of indirect calls all jumping to the exact same `syscall; ret` gadget address, that's a pattern. They're correlating the call frequency and the gadget address across threads."

**解法：gadget diversity** — 从 `ntdll`、`win32u.dll` 等多个 DLL 的不同偏移拉取多个 `syscall;ret` gadget 做 round-robin。

#### Nyx 现状 vs 检测方

| 检测维度 | Nyx 现状 | 检测方 2026 能力 | 缺口 |
|---|---|---|---|
| syscall 指令位置 | ntdll `syscall;ret` gadget ✓ | Elastic 检测 `Unbacked` final module | **gadget 在 ntdll 内 ✓** |
| 单 gadget 地址 | **单一固定 gadget** | Elastic 按频率+地址跨线程关联 | **🔴 缺 gadget diversity** |
| Frame0 export 匹配 | indirect syscall 落在 ntdll | K2 严格 export 匹配 | **⚠️ 需验证是否落在正确 export** |
| Frame1 caller | shellcode private memory | K2 检测 executable private caller | **🔴 需 stack spoof 配合** |
| ntdll unhook | KnownDlls fresh-map ✓ | ETW-TI KnownDlls 映射签名 | **✓ RAII unmap 已处理** |

#### 远见评级：**B- 级**

indirect-syscall 基础架构对齐 2024 代 SOTA，但 **单 gadget 地址** 已被 Elastic 的行为规则覆盖。Nyx 的 `resolve.rs` 已有 PEB walk + 跨模块解析能力——扩展到 gadget 多样化是自然延伸，但目前未实现。

---

### 3.4 调用栈伪装

#### 项目实现

**LACUNA 链（原创性最强）：**
- `lacuna.rs`: 跨版本 `.pdata` gap 扫描器——利用 `RUNTIME_FUNCTION` 之间的 gap（无 unwind metadata 的区域）
- 当 `RtlVirtualUnwind` 遇到 gap 中的返回地址 → `RtlLookupFunctionEntry` → NULL → unwinder 视为 leaf frame → RSP 前进 8 字节
- 构建结构合法但不可映射到真实函数的假调用栈
- 跨版本（格式自 XP x64 起稳定，零硬编码偏移）
- `lacuna_stomp.rs`: BYOUD-Gap stack injection via inline asm
- `stack.rs`: call-stack spoof（gated, CET-aware; 默认 OFF 因为 CET-on 主机会触发 `#CP`）
- V2 countermeasures: `cfg_user.rs`（CFG-valid target 注册）, `caller_spoof.rs`（VEH 注册调用方欺骗）, `proxy_veh.rs`（signed DLL gadget + section-backed handler）

**审计发现问题：**
- `blind_hwbp` 的 `static mut` 竞争（MED）
- `caller_spoof` 0xC3 裸 ret 仍在（死代码，CRIT-4 惰性保留）
- `lacuna_stomp` 跨 asm! 块拆分风险（NEW-MED-N2）

#### 行业 SOTA（2026）

##### LACUNA Chain 公开发表（0xmaz.me, 2026-06-19）

一篇 2026-06 的论文 **与 Nyx 的 LACUNA 实现高度吻合**——扫描 ntdll/kernelbase/win32u 的 `.pdata` gap 构建 ghost frame 链：

| DLL | RUNTIME_FUNCTIONs | Gaps | Ghost Functions |
|---|---|---|---|
| ntdll.dll | 4,725 | 3,913 | 1,031 (48,805 B) |
| kernelbase.dll | 4,992 | 3,982 | 432 (51,577 B) |
| win32u.dll | 1,244 | 1,243 | 0 |

论文还发现了 **win32u.dll 的 1,242 个 NOP gap**（8 字节对齐填充，分类白名单中的 leaf frame 位置）和 ntdll 中的 **ghost gadget**（`JMP [RBX]` at `ntdll+0xFC47B`，在 80 字节 ghost function 内）。

**该论文的结论是 LACUNA Chain "defeats all EDR layers of call-stack-based detection"**——唯一残留信号是 behavioral kernel callback correlation。

##### 但 Elastic 已在追踪（2026-05, bigbingus.com）

Elastic 的 "image_rop" 行为检测：
- 检测 return address 前面没有 `call` 指令（`image_rop` behavior）
- 检测 return 到 `jmp <nonvol>` 或 `push; ret` pattern 的 gadget
- 即使找到 `image_rop` 兼容 gadget（前面有 `call`），稀缺性使特定 gadget 组合可被签名

> "This method of spoofing is forced into a losing situation where specific gadgets must be used to avoid image_rop, but since those gadgets are relatively rare their usage can eventually be signatured."  
> — bigbingus.com, 2026-05

##### CET Shadow Stack 的终极挑战

Intel CET (12th-gen+ Intel, AMD Zen 3+) 的 Shadow Stack：
- 每个 `call` 同时 push 到 regular stack 和 shadow stack
- 每个 `ret` 比较两者——不匹配 → `#CP` exception
- **`SetThreadContext` 也验证 RIP vs shadow stack**——修改 RIP 到不同线程的地址会失败

2026-05 bigbingus 的 "fiber" 方法是 CET 兼容的 workaround——fibers 有特殊的 CET 支持。

#### 远见评级：**A 级**

**LACUNA 是 Nyx 最具原创性的远见设计。** `.pdata` gap 的利用思路在 2026-06 才被公开发表（0xmaz.me），而 Nyx 在 2026-06 已经实现了 `lacuna.rs` + `lacuna_stomp.rs`——**工程实现与公开研究同步甚至略早**。

**残留风险：**
1. Elastic 的 `image_rop` 检测可以捕获非 `call`-preceded gadget（但 LACUNA 的 leaf frame 不触发 image_rop——因为不是真正的 ROP gadget，是 unwind gap）
2. CET-on 主机（Win11 24H2+）的 `#CP` 风险——Nyx 的 `stack.rs` 正确地默认 OFF
3. `lacuna_stomp` 的跨 `asm!` 块拆分可能在某些编译器版本上产生调度风险

**Nyx 在此领域的领先窗口估计：6–12 个月**（直到主流 EDR 实现 `.pdata` gap 枚举检测——该论文明确指出"No public EDR implements this yet"）。

---

### 3.5 AMSI/ETW 致盲

#### 项目实现

**两种互补方法：**

1. **`blind.rs`（byte-patch, P0 baseline）：**
   - `amsi.dll!AmsiScanBuffer` → `mov eax, E_INVALIDARG; ret`（scan fails → in-box clients fail-open）
   - `ntdll.dll!EtwEventWrite` → `xor rax,rax; ret`（返回 STATUS_SUCCESS）
   - 裸 `ret`（`C3`）不是 `ret 0x18`（caller-owned x64 ABI）
   - `BLIND_OK` tracking + `AMSI_PATCHED` cycle cap
   - amsi.dll demand-loaded → `patch_amsi()` 每个 cycle 通过 `maybe_patch_amsi()` 重试直到 host 加载它（**不主动 LoadLibraryA**——那是 EDR 信号）

2. **`blind_hwbp.rs`（patchless, P2.1f SOTA）：**
   - DR0 execute breakpoint on target 首字节 → STATUS_SINGLE_STEP → VEH handler redirect RIP to shadow stub
   - 设 Resume Flag → CPU 跳过 HWBP 一条指令
   - **无 VirtualProtect on code page, 无内存字节修改**——PE-sieve `.text` hash 保持 clean
   - VEH chain probe before registration

#### 行业 SOTA（2026）

##### HWBP AMSI bypass 已成主流但可被 canary 检测

dcodezero (2026-03) 的实战报告揭示了一个有趣的蓝队技术：

> "They were running AMSITrigger as a canary — a PowerShell script that intentionally triggers AMSI at regular intervals and alerts if the expected response doesn't come back. My hardware breakpoint was eating the canary call."

**修正：** AMSI bypass 应该只在特定进程上下文中 hook，并更仔细地 spoof 返回值——不是完全吞掉调用。

##### VEH-Based Syscalls（2024→2026 进化）

DbgMan (2026-05) 记录了 LayeredSyscall 技术：利用 ACCESS_VIOLATION VEH + HWBP 构建 **合法调用栈** 的 indirect syscall。这与 Nyx 的 `blind_hwbp.rs` + VEH 链思路相似。

##### ETW-TI 的根本不可绕过性

> "Patching `ntdll!EtwEventWrite` in a user-mode process does not affect TI provider emission. Events fire after the kernel operation completes."  
> — DbgMan, 2026-05

`blind.rs` 的 `EtwEventWrite` patch 只影响 **user-mode ETW providers**（如 `DotNETRuntime`、`PowerShell`），不影响 ETW-TI kernel provider。这是正确的设计——**应该只声称致盲 user-mode ETW，不声称致盲 ETW-TI**。

#### 远见评级：**A- 级**

HWBP patchless 致盲思路正确（无内存修改 → integrity check 通过），且 `maybe_patch_amsi()` 的 demand-load 处理（不主动 `LoadLibraryA`）体现了 OPSEC 意识。

**修正建议：**
- 增加 per-process context filter（避免 canary 检测）
- 考虑 `EtwEventWrite` patch 的检测——Elastic 可检测 `.text` hash mismatch on ntdll

---

### 3.6 进程注入与模块踩踏

#### 项目实现

**`inject.rs`（36.5 KB）：**
- **Module Stomping**（P2.1c, `MODULESTOMP_ENABLED` 默认 ON）：`LoadLibrary` 合法签名 DLL → 覆盖 `.text` 为 shellcode → stomped 区域保持 cover DLL 的 VAD backing（evades Moneta/PE-sieve unbacked-memory 扫描；**不 evade** PE-sieve `.text` hash-mismatch）
- **Threadless inject**：shellcode 留在 private RWX，通过 HWBP 重定向执行（无 `.text` hash 变更）
- `pid != 0` → `inject_existing`（OpenProcess + NtAllocateVM + NtWriteVM + CreateRemoteThread，全 indirect syscall）
- `pid == 0` → spawn sacrificial suspended process
- **`tp.rs`**: Pool Party section injection（thread-pool abuse）

#### 行业 SOTA（2026）

##### Advanced Module Stomping（2023→2026 进化）

Dylan Tran (dtsec.us) 的 "Advanced Module Stomping" / Module Shifting：sleep 时恢复 stomped 模块原始 `.text` → 消除 PE-sieve "Modified Code" IOC。

> "By restoring the original module's memory after execution, we no longer get flagged by PE-Sieve."  
> — Dylan Tran

Naksyn (2023-06) 的 Module Shifting 进一步：选择正确的 hosting DLL section，模拟 Windows/第三方库的自修改行为（.NET DLL 和 Discord/Signal 都有合法 `.text` 自修改）。

##### 2026-06 最新：Targeted Module Stomping（消除 VirtualProtect）

Tom O'Neill (2026-06) 的 "Targeted Module Stomping"——**彻底消除 `VirtualProtect`**：
- Profiling 目标进程已加载的模块，找到 dormant code cave
- 用 `WriteProcessMemory` 隐式 kernel 层 permission flip（`NtWriteVirtualMemory` 内部 transparent toggle）
- 无 `LoadLibrary` → 无 anomalous module-load event
- 无 `VirtualProtect` → 破坏用户态行为签名
- 整个 staging footprint 收缩为单一 user-mode primitive

**但 kernel 层仍可见：** ETW-TI `MiProtectVirtualMemory` 仍记录 raw protection change。

##### RX-INT（2025-08, arxiv）

学术级的 RX-INT 内核引擎：real-time thread creation monitor + stateful VAD scanner + real-time memory hashing，声称在某些 benchmark 中检测率超过 PE-sieve。

##### SharedOriginal / Shared Working Set 检测

Dylan Tran 发现 Moneta 的 **SharedOriginal** 检测——stomped page 的 SharedOriginal flag 被清零（因为写入触发了 CoW）。这是目前 module stomping 最难绕过的检测。bypass 方法：clone process + `NtMapViewOfSection` 恢复 shared bytes，但不恢复 SharedOriginal。

#### Nyx 现状 vs 检测方

| 检测维度 | Nyx 现状 | 检测方 2026 能力 | 缺口 |
|---|---|---|---|
| Unbacked RX memory | Module stomp → image-backed ✓ | Moneta unbacked scan | **✓ 已规避** |
| `.text` hash mismatch | **未恢复原始 `.text`** | PE-sieve byte diff | **🔴 Advanced stomp 未实现** |
| SharedOriginal flag | 未处理 | Moneta SharedOriginal | **🔴 最难绕过的检测** |
| VirtualProtect 事件 | stomp 时有 VP | ETW-TI PROTECTVM | **⚠️ 不可绕过（kernel invariant）** |
| Module-load event | `LoadLibrary` cover DLL | Sysmon EID 7 | **⚠️ 需选 process 不导入的 DLL** |

#### 远见评级：**B 级**

基础 module stomping 实现对齐 2023 代，但 **Advanced Module Stomping（`.text` 恢复 + Module Shifting）** 已成 2024–2026 SOTA。审计也确认 BOF loader 从不释放 section 内存（HIGH-5），会永久泄漏 RW/RX 页。

**修正方向：**
1. Sleep 时恢复 stomped 模块原始 `.text`（消除 PE-sieve Modified Code IOC）
2. 选择正确 cover DLL（进程已导入的 DLL 不可用；选 `.text` 足够大的 DLL）
3. 考虑 Module Shifting（选择 `.rsrc` 等非 `.text` section + padding 模拟 FP）

---

### 3.7 内核层 BYOVD 与 callback 对抗

#### 项目实现

**`operator-kernelsdk`（24 模块）：**
- 4 BYOVD 驱动包：RTCore64 / iqvw64e / WDTKernel / Shield
- `VulnDriverIoctl` trait——但审计发现 **3/4 走 RTCore64 字节循环**（HIGH-7）
- `CallbackNeutralizer`: slot[0] bugcheck（MED）——`neutralize()` `.text` write 在 HVCI 下 triple fault；`repurpose()` 是安全路径（data+timing）
- `PatchGuardKit`: 基于 data+timing，不依赖 inline hook
- ETW deception: `EVENT_HEADER_SIZE=64`（真实应为 80）——**整个 Phase-4 欺骗子系统无效**（HIGH-6）
- QOS FFI: arity 修了但 pid 仍忽略（HIGH-NEW-K2 PARTIAL）

#### 行业 SOTA（2026）

##### BYOVD 已成 2026 勒索软件标准前置

MITRE ATT&CK v19（2026-04-28）新增 "Impair Defenses" 战术，正式定义 BYOVD 为独立威胁类别。

> "BYOVD is now the ransomware pre-step of 2026. Qilin, Warlock, Akira, BlackByte, and RansomHub all use it. 54 distinct EDR killer tools have been catalogued weaponizing 35+ legitimate, signed drivers."  
> — Lyrie Research, 2026-05

##### HVCI 是最强防御但不完美

> "HVCI prevents unsigned code injection and MSR manipulation, but it does not prevent a signed driver from exposing arbitrary memory read/write IOCTLs."  
> — NoHackie, 2026-02

关键 insight：**data-only attacks（token swaps, callback nulling, PPL byte patches, g_CiOptions clearing）在 HVCI 下仍然可行**——因为不需要新 executable pages。

Connor McGarr 演示了 HVCI 下通过覆写 saved return addresses 的 ROP-style kernel API 调用。

##### Callback 枚举与移除（2026-04 实战）

S12 (2026-04) 的实战演示：用 BYOVD 读原语遍历 `PspCreateProcessNotifyRoutine` 数组（64 slots），解码指针 → dereference `EX_CALLBACK` struct → 获取回调函数地址 → 匹配驱动。

> "The technique itself is completely undetected, what gets flagged is the vulnerable driver, not your code."  
> — S12, 2026-04

**驱动选择是 BYOVD 的核心 OPSEC 问题**——不是技术被检测，是特定驱动被签名。

##### Microsoft 2026-04 更新

Microsoft April 2026 security updates 扩展了 vulnerable driver blocklist（新增 psmounterex.sys 等）。但 blocklist 本质是 reactive——新驱动 CVE 在入库前所有系统都暴露。

#### Nyx 现状 vs 行业

| 维度 | Nyx 现状 | 行业 SOTA | 缺口 |
|---|---|---|---|
| 驱动包数量 | 4 | LOLDrivers.io 35+ | **数量不足** |
| 驱动包正确性 | **1/4 可用** | 每驱动独立 IOCTL 协议 | **🔴 3/4 损坏（HIGH-7）** |
| HVCI 策略 | data+timing ✓ | data-only attack | **✓ 方向正确** |
| Callback 移除 | neutralize() bugcheck | repurpose() 安全路径 | **⚠️ 需禁用 neutralize** |
| ETW-TI 消费绕过 | ETW deception 结构错误 | SecurityTrace flag technique | **🔴 HIGH-6 未修** |
| Blocklist 规避 | 未明确 | 持续更新 loldrivers.io | **⚠️ 需动态选驱动** |

#### 远见评级：**C 级**

**战略远见正确（HVCI 下 data+timing 策略），但战术实现严重不足。** 3/4 驱动包损坏意味着操作员在真实环境中选择非 RTCore64 驱动时得到坏原语——这是操作安全性问题。ETW deception 的 `EVENT_HEADER_SIZE=64` 错误使整个 Phase-4 欺骗子系统无效。

**修正优先级最高：**
1. 修复 3 个损坏驱动包的 IOCTL 协议（每个驱动有独立的 read/write/映射原语语义）
2. 修正 ETW EVENT_HEADER 结构（80 字节，ThreadId/ProcessId 位置，ActivityId GUID）
3. 移除/禁用 `neutralize()` 路径，强制走 `repurpose()`
4. 扩展驱动包到 8+ 并参考 loldrivers.io 持续更新

---

### 3.8 传输层与多信道

#### 项目实现

**7 信道 + `TransportStack` 自动降级：**

| Priority | 信道 | 文件 | 对标 |
|---|---|---|---|
| 0 | HTTPS | implant-win/src/transport.rs | CS 4.13 + BRC4 v2.5 |
| 1 | DoH DNS | transport/src/doh_dns.rs (17.4KB) | CS+BRC4 — Cloudflare DoH |
| 2 | Slack API | transport/src/slack_api.rs (12.1KB) | BRC4 Mercury v2.5 |
| 3 | LLM API | transport/src/llm_api.rs (12.1KB) | Check Point 2026.04 |
| 4 | MCP | transport/src/mcp.rs (14.1KB) | ArXiv 2025-11 |
| 5 | WebTransport | transport/src/webtransport.rs (12.7KB) | IETF Draft-15 |
| 6 | SMB/Named Pipe | transport/src/smb_pipe.rs (13.0KB) | CS+BRC4 |

**`TransportStack`（`traits.rs`）：** priority-sorted channel slots + fail-count health tracking + auto-fallback + `probe_health`/`active_name`/`healthy_count`

**TLS 指纹引擎：** `tls.rs`（JA3/JA4 计算）+ `h2.rs`（HTTP/2 Akamai 指纹）+ `emitter.rs`（emission seam）

**审计发现问题：**
- `FingerprintEmitter` 是死代码（HIGH-NEW-T3 PARTIAL）——JA3/JA4 计算有但 emission 未接线
- `rquest`/BoringSSL browser-impersonation backend（改名 `wreq`）未 pinned——emission 是 no-op
- DoH base64 URL_SAFE_NO_PAD 已修（HIGH-NEW-T1 FIXED）
- SMB OVERLAPPED 已移除（HIGH-NEW-T2 FIXED）
- DoH 无 253 字节总名长度守卫（NEW-MED-T19）
- SMB `read_exact` 无法区分断管 vs 无数据——忙循环（NEW-MED-T20）
- MCP `api_key: Option` 无强制（NEW-MED-T18）
- Slack 毒消息阻塞（MED）

#### 行业 SOTA（2026）

##### 多信道 C2 已成标配

RTLC2 (2026-02): 6 信道（HTTP/S, TCP, DNS, DoH, SMB, P2P）+ 14 evasion modules + 67 BOF。Kharon (AdaptixC2 agent): 支持运行时配置更新（sleep/jitter/kill date/working hours/BOF API proxy/spoofed+indirect syscall enable/disable/memory obfuscation status/PPID spoof/block DLL/AMSI-ETW bypass）。

**Nyx 的 7 信道覆盖与 RTLC2 的 6 信道相当**，但 Nyx 的 MCP/LLM/WebTransport 组合是独特的。

##### JA3/JA4 + JARM 指纹检测

> "JARM scans act as an active fingerprinting method for TLS configurations. A C2 server, no matter how 'malleable' its HTTP traffic, often runs on a standard library with a distinct TLS handshake signature."  
> — 0xHabib, 2025-12

Sliver 使用 mTLS（独立 CA + 每植入体唯一证书）对抗 TLS 指纹。Havoc 支持 malleable profile 控制 HTTP 层但 TLS 层仍暴露。

**Nyx 的 emission 未接线意味着 team server 的 JA3 hash 是 rustls 默认值——可被威胁情报库收录。**

##### Domain Fronting 衰退但 CDN-abuse 兴起

> "Major CDNs have largely cracked down on Domain Fronting, variations of this technique remain in use."  
> — hackcert.com, 2026-05

Discord C2 / GlytchC2（Twitch streaming steganography）代表 "Living off the Trusted" 趋势。Nyx 的 Slack + LLM 信道正好在这个方向上。

#### 远见评级：**B+ 级**

`TransportStack` 的自动降级设计前瞻（priority + health probe + failover），7 信道的覆盖面广。**但 `FingerprintEmitter` 未接线是网络层最大的未完成项——JA3 不可控意味着 TLS 层暴露。**

---

### 3.9 加密核心与协议

#### 项目实现

**`protocol/src/crypto.rs`（三轮审计验证质量最高 ⭐）：**
- X25519 ECDH（implant ephemeral × server long-term）
- HKDF-SHA256，salt = `server_pub`（修复了空 salt HIGH-2）
- ChaCha20-Poly1305 AEAD；96-bit nonce = zero-padded LE counter
- 方向隔离 nonce 空间（ClientToServer / ServerToClient）
- Anti-replay: monotonic counter（`raw.counter <= s.last_recv` rejected）
- `SessionKey`: 真 `Drop`（zeroize + compiler_fence），redacted Debug
- CSPRNG: `random_bytes` 返回 `Result`，`reject_zero` 防御纵深，全部 5 个 no_std 路径 + 全部 std 路径传播 `GenerateError`
- `constant_time_eq` 用 `subtle::ConstantTimeEq`（HIGH-1 FIXED）

**Wire frame:** `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`

**审计发现的残留问题：**
- `ServerKeypair::from_secret_bytes` 绕过 `reject_zero`——零值 `NYX_KEYFILE`（NEW-MED-1）
- config build.rs 绕过 `NYX_CONFIG_KEY`（CRIT-NEW-3 PARTIAL→HIGH-4）

#### 行业 SOTA（2026）

CloakCat (2026-03): "HMAC-based integrity verification is in place, but end-to-end traffic encryption (ECDH + AES-256-GCM) not implemented."  
Kraken (2026-04): X25519 ECDH + HKDF-SHA256 + AES-256-GCM + Ed25519  
Avocado C2 (2026-02): mTLS + protobuf

**Nyx 的加密设计（X25519 + HKDF-SHA256 + ChaCha20-Poly1305）与 Kraken 持平**，且在 CSPRNG 防御、SessionKey Drop、constant_time_eq 方面的工程质量更高。

#### 远见评级：**A+ 级**

加密核心是全项目修复质量最高的区域。三轮审计零活跃 CRITICAL。ChaCha20-Poly1305 的选择优于 AES-GCM（no_std PIC 下无 AES-NI 依赖，纯软件实现更高效且侧信道安全）。

**唯一修正：** `build.rs` 路径需支持 `NYX_CONFIG_KEY`（当前只修了 proc-macro 测试路径）。

---

### 3.10 MCP/LLM 信道——AI 流量伪装

#### 项目实现

**`transport/src/mcp.rs` (14.1KB):**
- JSON-RPC `tools/call` 封装——伪装 Cursor/Windsurf 开发工具流量
- `transport/src/llm_api.rs` (12.1KB): 伪装 `POST api.anthropic.com`——AI 开发流量

#### 行业 SOTA（2026）

##### MCP-based C2 由 Vectra AI 在 arXiv 2025-11 正式提出

> "Our MCP-based C2 can overcome current limitations by enabling asynchronous, parallel operations and real-time intelligence sharing without periodic beaconing."  
> — arXiv 2511.15998, 2025-11

关键特性：
- **消除周期性 beaconing**——最大 OPSEC 优势（传统 beaconing 是 NDR 检测的头号信号）
- Event-driven 通信：agent 领取任务 → 断开连接 → 执行 → 重连报告
- 流量与 Claude Code / Cursor 等合法 AI 开发工具流量混合
- Swarm 架构：分布式并行操作 + 实时情报共享

Vectra AI 2026-02 跟进博客：

> "Many technology companies employ tools such as Claude Code or Cursor, which perform API calls to Anthropic, making these patterns even more difficult to differentiate due to the noise from the benign calls."

##### MCP 安全攻防研究爆发（2026-Q1）

MCParasite (2026-03): MCP context worm 跨 14 平台传播  
mcpguard (2026-03): MCP stdio proxy 检测 prompt injection  
RedTeam-MCP (2026-03): 16+ 渗透工具封装为 MCP tool

**这意味着 MCP 流量本身正在受到安全研究关注**——但也意味着企业 AI 流量 baseline 正在快速增长， camouflage 价值反而增加。

#### 远见评级：**S 级**

**Nyx 在 MCP/LLM 信道上的工程实现领先 arXiv 论文定义。** Vectra AI 2025-11 的论文是概念定义 + 实验验证，Nyx 在同期已完成 14KB 的工程实现并接线进 TransportStack。这是公开 C2 项目中唯一覆盖 AI 流量伪装的。

**残留风险：**
- MCP `api_key: Option` 无强制（NEW-MED-T18）——None 时重现无认证问题
- MCP 流量与合法 AI 工具流量的区分检测（Vectra AI 正在研究 behavioral modeling）
- Anthropic API 变更（streaming response 模式）需要持续跟踪

**远见领先窗口估计：12–18 个月**（直到检测方建立 AI 流量 behavioral baseline 并能区分 C2 与合法 agent 调用）。

---

## 4. 检测方 2026 工具箱全景

以下是 2026 年 Q2 检测方可用的工具和技术——任何 evasion 设计都必须对照这个工具箱评估：

### 4.1 内存扫描层

| 工具/技术 | 原理 | 对抗什么 |
|---|---|---|
| **Moneta** | 扫描 executable + private commit memory；SharedOriginal flag | unbacked RX memory, module stomping |
| **PE-sieve** | 对比 in-memory `.text` 与 on-disk bytes | module stomping, inline hook |
| **CFG-FindHiddenShellcode** | CFG bitmap 遍历找"曾经 executable"的区域 | sleep obfuscation (RX→~X→RX) |
| **EtwTi-FluctuationMonitor** | ETW-TI PROTECTVM_LOCAL + 频率计数 | sleep obfuscation (保护翻转) |
| **Hunt-Sleeping-Beacons v2** | 可疑 APC/timer + `KiUserApcDispatcher` 检测 | Ekko/FOLIAGE/Cronos/Zilean |
| **PATRIOT** | CONTEXT struct Rip 指向 `*Protect` 函数 | sleep mask ROP chain |
| **MalMemDetect** | API call 时的 return address 验证 | unbacked caller |
| **RX-INT** | real-time thread monitor + stateful VAD scanner | TOCTOU-safe module stomping |
| **TickTock** | 特定 sleep 技术 IOC | 已知 sleep 实现 |

### 4.2 行为检测层（Elastic 为代表）

| 规则 | 检测什么 | 对抗什么 |
|---|---|---|
| **Direct Syscall from Unsigned Module** | `direct_syscall` behavior + untrusted final module | direct syscall |
| **VirtualProtect via Indirect Random Syscall** | VP call 但 stack 无 `NtProtectVirtualMemory` | indirect syscall |
| **Potential Library Load via ROP Gadgets** | 敏感 DLL load 但 stack 无 `Ldr*` | ROP-gadget API 调用 |
| **image_rop behavior** | return address 前无 `call` | call stack spoof via jmp gadget |
| **Call stack summary signatures** | 特定 module 链模式 | 已知 gadget 组合 |

### 4.3 内核遥测层（不可绕过）

| 机制 | 原理 | 对抗什么 |
|---|---|---|
| **ETW-TI** (PPL consumed) | kernel-emitted security events | **所有** user-mode evasion |
| **Kernel callbacks** | `PsSetCreateProcessNotifyRoutine` 等 | process/thread/handle ops |
| **`NtProtectVirtualMemory` EventID 98** | kernel-mapped memory ETW | sleep obfuscation 保护翻转 |
| **HVCI / Memory Integrity** | hypervisor-enforced W^X on kernel | BYOVD kernel code injection |
| **VBS (Virtualization-Based Security)** | isolated Secure Kernel | kernel-level attacks |
| **Microsoft Vulnerable Driver Blocklist** | hash-based driver blocking | BYOVD（reactive） |

### 4.4 网络检测层

| 技术 | 原理 | 对抗什么 |
|---|---|---|
| **JA3/JA4 TLS fingerprinting** | ClientHello hash | framework-specific TLS |
| **JARM scanning** | server TLS config hash | team server identification |
| **Beaconing analysis** (RITA, Zeek) | periodic connection detection | sleep+jitter pattern |
| **Vectra AI LSTM model** | behavioral sequence modeling | C2 control pattern |
| **DNS anomaly detection** | high-entropy subdomain | DNS C2 |
| **Certificate anomaly** | self-signed / non-public CA | C2 infrastructure |

---

## 5. 项目远见 vs 检测方能力对照矩阵

| Nyx 技术 | 检测方 2026 能力 | 状态 | 远见评级 |
|---|---|---|---|
| fluctuation (RX→NOACCESS→RX) | CFG bitmap + ETW-TI FluctuationMonitor | **🔴 已被击穿** | C+ |
| indirect syscall (单 gadget) | Elastic behavior rules + K2 export match | **🟡 部分覆盖** | B- |
| LACUNA ghost frames | 无 production EDR 实现 gap 检测 | **🟢 领先 6-12 月** | A |
| HWBP AMSI/ETW patchless | AMSITrigger canary 检测 | **🟡 需 per-process filter** | A- |
| Module stomping (基础) | PE-sieve hash mismatch + SharedOriginal | **🔴 缺 advanced restore** | B |
| BOF loader | 内存扫描 RX page | **🟡 HIGH-5 泄漏 section** | B- |
| BYOVD (4 driver) | Blocklist + loldrivers.io | **🔴 3/4 损坏** | C |
| Callback neutralize | HVCI data-only attack | **🟡 neutralize bugcheck** | C+ |
| ETW deception | PATRIOT / structure validation | **🔴 EVENT_HEADER 错误** | D |
| DoH DNS channel | DNS anomaly detection | **🟢 合理** | B+ |
| MCP/LLM channel | Vectra AI research（早期） | **🟢 领先 12-18 月** | S |
| WebTransport (QUIC) | QUIC 分析工具不成熟 | **🟢 合理** | A- |
| TLS JA3/JA4 emitter | JARM scanning | **🔴 emission 未接线** | C+ |
| Crypto (X25519+ChaCha20) | 无直接检测 | **🟢 三轮审计验证** | A+ |
| Server auth + anti-replay | 无直接检测 | **🟢 零 CRITICAL** | A |
| Pure Rust no_std PIC | 无 Go/C signature | **🟢 语言级优势** | S |
| Build-time randomization | 静态签名对抗 | **🟢 合理** | A- |

---

## 6. 盲区分析——被检测窗笼罩的技术点

### 6.1 🔴 P0 盲区：fluctuation 已进入检测窗（最高风险）

**问题本质：** 任何 RX→~X→RX 的保护状态翻转都是 ETW-TI 和 CFG bitmap 的检测目标。Nyx 的 CFG/CET 免疫设计（独立 trampoline，无 APC/timer）解决了**执行机制**的检测，但没解决**翻转本身**的检测。

**影响：** 面对部署了 ETW-TI pipeline + CFG bitmap 扫描的成熟 EDR（CrowdStrike Falcon, Elastic Endpoint, MDE），Nyx 的 sleep mask 在每次 sleep 时产生两次 PROTECTVM 事件 + CFG bitmap 永久标记。

**修正方向：flower 式 JIT-mimicry**
- PIC implant 天然适合（flower 论文明确指出）
- ntalloc bump allocator 已支持 slab 分配/释放
- `mem.rs` 的 mask 机制可扩展为 move-and-free
- 核心变更：sleep 时分配新 RW region → memcpy → 新 region 设 RX → free 旧 region（而非翻转旧 region 的保护）

### 6.2 🔴 P0 盲区：BYOVD 3/4 驱动损坏（最高操作安全风险）

**问题本质：** RTCore64 的 IOCTL 协议被硬编码到所有 4 个驱动包。iqvw64e（不同结构布局）、WDTKernel（MmMapIoSpace-based）、Shield（双向 IOCTL）各有独立的 read/write/映射语义。

**影响：** 操作员选 HVCI-safe WDTKernel 默认得到坏原语——在真实红队场景中，这不仅是 bug，是操作失败甚至暴露的直接原因。

**修正方向：** 为每个驱动实现正确的 IOCTL 协议。参考 EDRSandblast / RealBlindingEDR / Backstab 的实现。

### 6.3 🟡 P1 盲区：indirect syscall 缺 gadget diversity

**问题本质：** 单一 ntdll `syscall;ret` gadget 地址被所有 indirect syscall 调用使用。Elastic 按调用频率 + gadget 地址跨线程关联。

**修正方向：**
- 从 `ntdll.dll`、`win32u.dll` 等多个 DLL 的不同偏移拉取多个 `syscall;ret` gadget
- Round-robin 选择
- `resolve.rs` 的 PEB walk + 跨模块解析能力已具备基础

### 6.4 🟡 P1 盲区：网络指纹 emitter 未接线

**问题本质：** `FingerprintEmitter` trait 定义了 JA3/JA4 emission seam，但 `wreq`/BoringSSL backend 未 pinned——emission 是 no-op。team server 使用默认 rustls，JA3 hash 不可控。

**影响：** JARM 扫描可识别 team server；beacon 的 TLS 指纹可能匹配已知 C2 framework hash。

**修正方向：** Pin `wreq` (原 `rquest`) BoringSSL backend；接线 emission 到 transport 层。

### 6.5 🟡 P1 盲区：Module stomping 未恢复 `.text`

**问题本质：** 基础 module stomping 覆盖 cover DLL 的 `.text` 后不恢复原始内容。PE-sieve byte diff 检测 "Modified Code" IOC。

**修正方向：** Advanced Module Stomping——sleep 时备份并恢复 cover DLL 原始 `.text`。

### 6.6 🟡 P2 盲区：修复 diff 引入的回归

审计发现修复本身引入了 7 个新 HIGH：

| # | 发现 | 风险 |
|---|---|---|
| 1 | ntalloc eviction UAF | **HIGH** — 将泄漏变成 UAF |
| 2 | SOCKS5 认证回退绕过 | **HIGH** — 开放代理 |
| 3 | `/connect` 无 HTTP 策略检查 | **HIGH** — bearer token 明文 |
| 4 | config build.rs 绕过 NYX_CONFIG_KEY | **HIGH** — 生产 implant 密钥紧邻密文 |
| 5 | BOF loader 不释放 section | **HIGH** — 永久 RX 页泄漏 |
| 6 | ETW EVENT_HEADER 结构错误 | **HIGH** — Phase-4 欺骗无效 |
| 7 | fluctuation 硬件异常不覆盖 | **HIGH** — CRIT-5 残留 |

---

## 7. 领先分析——超越同代的设计决策

### 7.1 ⭐ MCP/LLM 信道（领先 12–18 月）

**Nyx 是公开 C2 项目中唯一工程实现了 MCP-based C2 的。** arXiv 2025-11 论文定义概念，Vectra AI 2026-02 跟进博客，Nyx 在同期已有 14KB 工程实现。7 信道的 TransportStack 自动降级也是前瞻设计。

### 7.2 ⭐ LACUNA ghost frame 链（领先 6–12 月）

`.pdata` gap 的利用思路在 2026-06 才被 0xmaz.me 公开发表。Nyx 的 `lacuna.rs` + `lacuna_stomp.rs` 与该论文高度吻合——**工程实现与前沿研究同步甚至略早**。

0xmaz.me 论文明确指出："No public EDR implements this yet"——这给了 Nyx 6–12 月的领先窗口。

### 7.3 ⭐ 纯 Rust no_std PIC（语言级结构性优势）

Go C2 已被签名杀死。Rust no_std + LTO + strip 无运行时、无 Go signature。53 个真机 selftest 的验证深度远超同期 Rust C2（Proteus/Kraken/CloakCat 都在早期）。

### 7.4 ⭐ CFG/CET 免疫的 fluctuation trampoline 设计

虽然 PAGE_NOACCESS 循环本身已被检测覆盖，但**独立 trampoline 页直接调 `NtProtectVirtualMemory`** 的执行机制设计（无 APC、无 timer、无 `NtContinue` CONTEXT 链）本身是创新的——HSB 和 PATRIOT 都检测不到这种执行模式。

这个设计思路在迁移到 flower 式 JIT-mimicry 时仍然有价值——trampoline 可以执行 move-and-free 逻辑而非保护翻转。

### 7.5 ⭐ 工程纪律：三轮审计 + 真机验证

三轮代码审计（baseline → deep → 修复验证），每轮 10 路并行，全部 CRITICAL + HIGH 人工逐行核验。53 个 `rundll32` selftest 在 Server 2019 (17763.1339) 全 pass。**"可验证的 stealth"而非"声称的 stealth"**——这在 C2 项目中罕见。

### 7.6 ⭐ 加密核心修复质量

CSPRNG `Result` 传播完整性（全部 5 个 no_std + 全部 std 路径）、SessionKey `zeroize`+`compiler_fence` 真 Drop、HKDF `server_pub` salt、`subtle::ConstantTimeEq`——三轮审计零活跃 CRITICAL。

### 7.7 ⭐ 诚实标注残留检测面

CLAUDE.md 和 STATUS.md 诚实标注了 CET Shadow Stack、section-backed handler CoW 页差异、`AddVectoredExceptionHandler` API call 本身的残留检测面。**没有虚假声称"完全不可检测"**——这种诚实反而增加了项目的可信度。

---

## 8. 远见修正路线图

### P0 — 必须立即处理（提交修复 diff 前）

| # | 发现 | 工作量 | 远见影响 |
|---|---|---|---|
| 1 | ntalloc UAF 回滚（增大 MAX_SLABS 或动态增长表） | 小 | 防止活跃堆被释放 |
| 2 | SOCKS5 删 `0x00` 回退分支 | 一行 | 消除开放代理 |
| 3 | `/connect` 加 `enforce_http_policy` | 一行 | 消除 bearer 明文泄漏 |
| 4 | config build.rs 支持 `NYX_CONFIG_KEY` | 中 | 消除密钥紧邻密文 |
| 5 | BOF loader 执行后 `VirtualFree(MEM_RELEASE)` | 小 | 消除永久 RX 页 IOC |
| 6 | ETW `EVENT_HEADER_SIZE=80` + 字段修正 | 中 | 恢复 Phase-4 欺骗 |
| 7 | BYOVD 3 个驱动包 IOCTL 协议修复 | 大 | 恢复操作安全性 |

### P1 — 下一代远见（3–6 月）

| # | 方向 | 工作量 | 远见影响 |
|---|---|---|---|
| 8 | **fluctuation → flower JIT-mimicry 迁移研究** | 大 | 🔴 消除最高检测风险 |
| 9 | indirect syscall gadget diversity（多 DLL round-robin） | 中 | 对抗 Elastic 行为检测 |
| 10 | Advanced Module Stomping（sleep 恢复 `.text`） | 中 | 对抗 PE-sieve hash mismatch |
| 11 | FingerprintEmitter 接线（pin wreq/BoringSSL） | 中 | 对抗 JARM scanning |
| 12 | fluctuation unmask 移入 thunk 尾部（覆盖硬件异常） | 中 | 消除 CRIT-5 残留 |

### P2 — 前沿探索（6–12 月）

| # | 方向 | 工作量 | 远见影响 |
|---|---|---|---|
| 13 | CET Shadow Stack 兼容（fiber-based sleep 或 TIB-only swap） | 大 | Win11 24H2+ 兼容 |
| 14 | `image_rop`-compatible gadget 库（call-preceded） | 中 | 对抗 Elastic image_rop |
| 15 | BYOVD 扩展到 8+ 驱动 + loldrivers.io 跟踪 | 中 | 对抗 blocklist 更新 |
| 16 | ETW-TI provider 消费绕过研究（SecurityTrace flag） | 大 | 🔴 消除不可绕过 invariant |
| 17 | MCP swarm 架构（多 agent 并行 + 实时情报共享） | 大 | 扩大 MCP 领先窗口 |
| 18 | Targeted Module Stomping（消除 VirtualProtect） | 中 | 减少行为签名 |

---

## 9. 与同代 C2 框架对比

| 维度 | **Nyx** | Havoc | Sliver | RTLC2 | Kraken | CloakCat |
|---|---|---|---|---|---|---|
| 语言 | **Rust no_std PIC** | C/Asm | Go | C/C++ + Go server | Rust | Rust |
| EDR 签名风险 | **极低** | 中（已广泛分析） | **高**（Go sig） | 中 | 低 | 低 |
| Sleep obfuscation | fluctuation (PAGE_NOACCESS) | Ekko/Zilean/FOLIAGE | 无原生 | Ekko/FOLIAGE/Cronos | 无 | 无 |
| → 2026 检测规避 | **C+** (已被 POC 覆盖) | **B-** (有 bypass) | N/A | **B** (有 Cronos) | N/A | N/A |
| Indirect syscalls | ✓ 单 gadget | ✓ + stack spoof | ✗ | ✓ Hell's/Halo's | 计划中 | ✗ |
| HWBP AMSI/ETW | ✓ patchless | ✓ | ✗ | ✓ | ✗ | ✗ |
| Module stomping | ✓ 基础 | ✓ | ✗ | ✓ | ✗ | ✗ |
| Call stack spoof | **LACUNA (原创)** | ✗ | ✗ | ✗ | ✗ | ✗ |
| BYOVD | 4 driver (1/4 可用) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 传输信道 | **7 (含 MCP/LLM)** | 3 (HTTP/DNS/SMB) | 4 (HTTP/DNS/mTLS/WG) | 6 | 4 | 1 (HTTP) |
| MCP/LLM 信道 | **✓ (工程领先论文)** | ✗ | ✗ | ✗ | ✗ | ✗ |
| JA3 控制 | 引擎有/未接线 | malleable profile | mTLS 绕过 | malleable profile | 计划中 | ✗ |
| BOF loader | ✓ no_std W^X COFF | ✓ | ✓ | ✓ 67 BOF | ✓ | 计划中 |
| 加密 | **X25519+ChaCha20-Poly1305** | AES-256 | mTLS | AES-256-GCM | X25519+AES-GCM | HMAC (E2E 未完成) |
| 真机验证 | **53 selftest** | ✗ | ✗ | ✗ | ✗ | ✗ |

**结论：** Nyx 在**规避技术广度**（LACUNA + HWBP + fluctuation + BYOVD）、**信道前瞻**（MCP/LLM）、**语言优势**（Rust no_std PIC）和**工程纪律**（三轮审计 + 53 selftest）四个维度领先同代公开 C2 框架。核心短板在 sleep obfuscation 代差和 BYOVD 实现完整性。

---

## 10. 结论

### 远见能力总判断

**Nyx 是一个有真实技术远见的项目，处于同代公开 C2 框架的最前沿梯队。** 设计者在三个关键决策点上展现了前瞻性判断：

1. **语言选型**——在 Go C2 被签名杀死之前就选择了纯 Rust `no_std` PIC
2. **信道选型**——在 arXiv 论文定义 MCP-based C2 之前就工程实现了
3. **检测对抗思路**——LACUNA ghost frame 链与 2026-06 前沿研究同步甚至略早

### 核心矛盾

**项目的远见在"往哪里跑"上基本正确，在"跑过的路是否已被封"上存在关键盲区。**

最典型的体现是 sleep obfuscation：
- fluctuation 的 **执行机制**（CFG/CET 免疫独立 trampoline）是 2026 年仍然领先的设计
- 但 fluctuation 的 **保护状态翻转** 本身已成为 2026 年检测方的核心 invariant

这不是设计错误——在 2022–2023 年做 fluctuation 时，CFG bitmap 和 ETW-TI FluctuationMonitor 还不是产品级检测。**这是军备竞赛的自然结果：今天的前沿是明天的标准，后天的 IOC。**

### 最高优先级行动

如果只能做三件事来提升远见能力：

1. **Fluctuation → flower JIT-mimicry 迁移研究**（最高远见价值）—— 消除不可绕过的 ETW-TI 保护翻转检测信号；PIC implant 天然适合
2. **BYOVD 驱动包修复**（最高操作安全价值）—— 3/4 损坏是操作失败的直接原因
3. **FingerprintEmitter 接线 + gadget diversity**（最高网络层价值）—— 两个中等工作量修正，显著降低检测面

### 最终评分

```
╔══════════════════════════════════════════════════════════════════╗
║                     Nyx 远见能力终评                              ║
╠══════════════════════════════╦═══════════════════════════════════╣
║  语言/架构选型                 ║  S  — 领先 Go 系，与同期 Rust C2 拉开差距  ║
║  信道前瞻（MCP/LLM/WebTransport）║  S  — 工程领先学术论文，同代唯一           ║
║  Sleep obfuscation            ║  C+ — PAGE_NOACCESS 被 2026 POC 击穿       ║
║  Syscall evasion              ║  B- — indirect 对齐但缺 gadget diversity    ║
║  调用栈伪装 (LACUNA)           ║  A  — 原创性强，领先 6-12 月                ║
║  AMSI/ETW 致盲                ║  A- — HWBP patchless 思路正确               ║
║  进程注入                     ║  B  — 基础对齐，缺 advanced restore         ║
║  内核层 (BYOVD)               ║  C  — 战略对但 3/4 驱动损坏                 ║
║  网络指纹伪装                  ║  C+ — JA3 引擎有但 emission 未接线          ║
║  加密核心                     ║  A+ — 三轮审计验证，零活跃 CRITICAL         ║
║  工程纪律/可验证性             ║  A  — 三轮审计 + 53 真机 selftest           ║
║  路线图完整性                  ║  B+ — CNSA-2/QUIC/air-gap 都有设计文档     ║
╠══════════════════════════════╬═══════════════════════════════════╣
║  综合远见能力                  ║  B+ — 同代公开项目中最前沿梯队之一         ║
║  核心短板                     ║  sleep obfuscation 代差 + BYOVD 实现完整性  ║
║  核心优势                     ║  MCP/LLM 信道 + Rust no_std + LACUNA        ║
╚══════════════════════════════╩═══════════════════════════════════╝
```

---

## 11. 研究来源

### 项目内部文档
- `docs/CODE_AUDIT_2026-07-10.md` — 三轮审计验证报告
- `docs/audit_2026_07_10/*.md` — 10 个域子报告
- `docs/STATUS.md` — 单一事实源
- `docs/BYPASS_CAPABILITIES.md` — 能力矩阵
- `docs/ROADMAP_2026-2027.md` — 路线图
- `CLAUDE.md` — 项目架构指南
- `README.md` — 项目概述

### 2026 年技术文献（exa + context7 + web reader 检索）

**Sleep Obfuscation 检测与规避：**
- sillywa.re — "flower: naively bypassing new memory scanning POCs"（flower JIT-mimicry）
- github.com/xrombar/flower — flower 实现代码
- github.com/jdu2600/CFG-FindHiddenShellcode — CFG bitmap 检测
- github.com/jdu2600/EtwTi-FluctuationMonitor — ETW-TI 检测
- i.blackhat.com/Asia-23 — John Uhlmann "You Can Run, but You Can't Hide"
- justruss.tech (2026-06-21) — "Hunting Sleeping Giants"
- maorsabag.github.io (2026-06-06) — "Sleeping Beauty II: CFG, CET, Stack Spoofing"
- binarydefense.com (2024-08) — "Understanding Sleep Obfuscation"
- own.security (2026-04) — "CoRIIN 2026: Memory Fluctuation"
- github.com/JodisKripe/EkkoMod (2026-01) — HSB bypass via NtContinue-8 nop

**Syscall 检测与规避：**
- elastic/protections-artifacts — "Direct Syscall from Unsigned Module" / "VirtualProtect via Indirect Random Syscall" / "Potential Library Load via ROP Gadgets"
- titansoftwork.com (2026-02) — "ActiveBreach Engine: Rethinking Syscall Execution"
- titansoftwork.com (2026-05) — "K2: Detecting Syscalls"
- offsec.almond.consulting — "Evading Elastic EDR's call stack signatures with call gadgets"
- dcodezero.github.io (2026-03) — "Your Havoc Demon Is Sleeping Wrong"

**调用栈伪装：**
- 0xmaz.me (2026-06-19) — "LACUNA Chain: Ghost Frames"
- bigbingus.com (2026-05-13) — "Stop Being Weird — Life After Call Stack Spoofing Under CET"
- dtsec.us (2023-11) — "Module Stomping" + stack spoofing

**BYOVD 与内核对抗：**
- lyrie.ai (2026-05) — "The EDR Blind Spot: BYOVD Attacks"
- nohackie.com (2026-02) — "BYOVD: Windows Kernel Internals"
- trackr.live (2026-06) — "Detecting BYOVD Driver Kills"
- linkedin.com/pulse (2026-04) — "BYOVD Can Disable EDR"
- learn.microsoft.com — "Microsoft recommended driver block rules"（updated 2026-04-05）
- medium.com/@s12deff (2026-04) — "Enumerating Windows Process Creation Callbacks"

**进程注入：**
- medium.com/@toneillcodes (2026-06) — "Don't Be So Primitive: Evolving Module Stomping"
- naksyn.com (2023-06) — "Improving stealthiness of memory injections" (Module Shifting)
- arxiv.org/abs/2508.03879 — "RX-INT: Kernel Engine for In-Memory Threat Detection"

**AMSI/ETW 致盲：**
- 0xdbgman.github.io (2026-05) — "EDR Tradecraft: Internals, Detection, Evasion"

**MCP/LLM C2：**
- arxiv.org/abs/2511.15998 (2025-11) — "Hiding in the AI Traffic: Abusing MCP"
- vectra.ai/blog (2026-02) — "MCP-Powered Swarm C2"
- github.com/MCParasite/mcparasite — MCP context worm
- github.com/mark-liu/mcpguard — MCP injection scanning

**C2 框架架构：**
- 0xhabib.tech (2025-12) — "Command & Control in 2025"
- hackcert.com (2026-05) — "C2 Development: Architecting Advanced C2"
- securityelites.com (2026-04) — "C2 Frameworks 2026"
- scip.ch (2025-06) — "C2 Architecture"
- vectra.ai/blog — "Why Modern C2 Detection Requires Behavioral Modeling"

**同代 Rust C2 框架：**
- cloakcat.com (2026-03) — "Rust C2 Framework Architecture Review"
- github.com/ZZ0R0/Proteus (2026-04) — polymorphic Rust no_std agent
- github.com/Real-Fruit-Snacks/Kraken (2026-04) — OPSEC-first Rust C2
- github.com/WoodenshoeNL/Red-Cell-C2 (2026-03) — Havoc Rust rewrite
- github.com/JoasASantos/RTLC2 (2026-02) — C/C++17 + Go C2
- github.com/Nariod/linky — minimal Rust C2
- platformsecurity.com (2026-02) — "Avocado C2: Architecture, mTLS & Rust"

**EDR 内部机制：**
- 0xdbgman.github.io (2026-05) — "EDR Internals Research and Bypass"
- github.com/Dram4ck/Kharon — AdaptixC2 PIC evasion agent

---

## 附录 A：项目自评能力 vs 审计现实 vs 检测方——三重交叉验证

> 本附录综合两路并行子报告代理（audit sub-reports reader + roadmap/bypass docs reader）的完整发现，
> 在"项目声称"——"审计验证"——"检测方 2026 能力"三个维度上做最终对齐。

### A.1 项目自评 vs 审计验证

项目的 `CAPABILITY_AUDIT_2026-07-05.md` 声称"~119 能力项，~118 真实现（99%），1 个诚实降级"。三轮审计对每条声称做了 source-level 核验：

| 能力声称 | 项目自评 | 三轮审计验证 | 差距性质 |
|---|---|---|---|
| T-REX 侦察引擎 | "实现" | **CRIT-3: 100% stub，全部 API 返回 null/0** | ✅ 已修复：T0-T3 真 scanner（2026-07-14+）；T4-T5 内核评估移入 operator-kernelsdk（`nyx-kernel assess`，BYOVD 真机 + hosted CI 硬门，2026-08） |
| Pool Party 注入 | "0-of-3 FND" | **CRIT-NEW-2: 实际调用 NtCreateThreadEx** | ❌ 误导性（现已诚实标注） |
| mem mask/unmask 往返 | "byte-identical" | **CRIT-NEW-4: 每次生成新 key → 数据损坏** | ❌ 虚假（已修复：单 key 缓存） |
| CSPRNG 失败处理 | "安全" | **CRIT-NEW-1: 失败时全零标量 → 共享确定密钥** | ❌ 严重（已修复：Result 传播） |
| config 加密 | "防 extractor" | **CRIT-NEW-3: 密钥紧邻密文 + build.rs 绕过 NYX_CONFIG_KEY** | ❌ 虚假（部分修复） |
| Server 安全默认 | "安全" | **CRIT-1: 默认 0.0.0.0 + Admin** | ❌ 严重（已修复：默认 loopback + token） |
| Kernel bridge | "6 条命令接线" | **CRIT-2: `kernel: None`，全部返回 "no daemon"** | ❌ 虚假（未修） |
| LACUNA ghost frame | "实现" | **验证通过** — lacuna.rs .pdata gap 扫描器正确 | ✅ 真实 |
| HWBP patchless blind | "SOTA" | **验证通过** — DR0+VEH+ResumeFlag 正确 | ✅ 真实 |
| fluctuation sleep | "CFG/CET 免疫" | **机制验证通过**，但 CRIT-5 硬件异常残留 + PAGE_NOACCESS 已被检测覆盖 | ⚠️ 部分真实 |
| BYOVD 4 驱动 | "4 个驱动包" | **HIGH-7: 3/4 走 RTCore64 字节循环** | ⚠️ 数量真实但质量不足 |
| ETW deception | "Phase-4 欺骗" | **HIGH-6: EVENT_HEADER_SIZE=64（应 80），字段错误** | ❌ 整个子系统无效 |
| 53 selftest | "全 pass" | **验证通过** — Server 2019 17763.1339 全 pass | ✅ 真实 |
| 加密核心 | "安全" | **三轮验证最高质量** — 零活跃 CRITICAL | ✅ 真实 |
| 7 传输信道 | "实现" | **验证通过** — 7 个文件存在且可编译 | ✅ 真实 |

**审计验证总结：** 项目声称的 119 项能力中，约 10 项存在实质性虚假或严重不完整（已通过审计修复大部分），其余真实。**关键修正：审计本身使项目变得更好——三轮审计驱动了所有 9 CRITICAL 的修复或降级。**

### A.2 项目 36 月路线图远见评估

`ROADMAP_2026-2027.md` 定义了"Nyx 2.0"——36 月、64 人周、~80,000 LOC 增长计划：

| Phase | 时间 | 方向 | 远见评估 |
|---|---|---|---|
| P8–P9 | 2026.08–09 | implant-core 重构 + Cavern-Manticore 式模块化（版本化 DLL `n-syscall-v3.dll`，3 种编译目标） | ⭐ 正确方向——模块化降低签名面 |
| P10–P11 | 2026.09–10 | 传输韧性：CDN Domain Fronting + WebSocket + DNS Tunneling + HTTP/2 MP + uTLS JA4 spoof + DGA v2 | ⭐ 自我识别为"最大弱点"——诚实 |
| P12–P13 | 2026.10–11 | LACUNA 六层 + post-CET "Moonwalking" + LLM-EDR 自动化 + CET kernel disable + LLVM payload mutation | ⭐ 最前沿——但工作量极大 |
| P14–P15 | 2026.12–2027.01 | 凭据+横向：LSASS kernel dump + Kerberoasting + PTH + BloodHound + "零 cmd.exe/powershell.exe/mimikatz.exe" | ⭐ 纯 NT API 路径前瞻 |
| P16–P17 | 2027.02–03 | 跨平台：Linux ELF（ptrace/memfd_create）+ macOS Mach-O（processor_set_tasks SIP bypass + TCC bypass） | ⭐ 方向正确，风险高 |
| P18 | 2027.04 | Raft 3-node federation + X25519+ML-KEM-1024 PQXDH + RBAC + LLVM mutation CI/CD + EDR detector sandbox | ⭐ 最高远见 |

**路线图远见评估：** 这是目前公开 C2 项目中最完整的演进蓝图。特别是：
- **X25519+ML-KEM-1024 混合后量子密钥交换**（Signal PQXDH 模型）——超前于所有公开 C2
- **LLM-EDR 自动化**（Binary Ninja/Ghidra headless + LLM 自动发现 bypass 点）——概念级前瞻
- **CET kernel disable**——如能实现将是 user-mode CET 绕过的重大突破（但 Synacktiv SSTIC 2025 `KiControlProtectionFault` seam 才刚发表，可行性待验证）

**路线图风险评估：** 项目自评"单人开发者 64 人周——slippage 概率极高"。这是诚实的自我评估。

### A.3 项目诚实标注的检测面

项目的 `EDR_BLINDNESS_UPGRADE_2026-07.md` §0.2 和 §10 诚实列出了用户态不可绕过的检测面——**这种诚实标注本身就是远见的体现**：

| 检测面 | 用户态可致盲？ | 项目诚实标注 |
|---|---|---|
| ETW-TI 内核 provider | ❌ 不可 | ✅ "内核遥测；用户态 patch 只杀用户态路径；内核 provider 由 Secure Kernel (VTL1) 保护" |
| PsSetCreateThread/ProcessNotifyRoutine | ❌ 不可 | ✅ "内核 callback；只有 operator-side driver 可 neutralize" |
| Intel CET Shadow Stack | ⚠️ 间接 | ✅ "用户态不可直接写 shadow stack；只有 Synackvit SSTIC 2025 `KiControlProtectionFault` seam" |
| HVCI/VBS 代码页写入 | ❌ 不可 | ✅ "HVCI-on 代码页 EPT 只读；只有 DATA-section 写入存活" |

**项目自述结论：** "True 'total EDR blinding' requires kernel-side cooperation. Pure user-mode can at most blind user-mode-hook EDRs; kernel telemetry EDRs remain visible."

这个结论与我们 2026 SOTA 研究完全一致——**项目对自身局限性的认知是准确的**。

### A.4 审计跨域规律（来自全部 10 份子报告的交叉分析）

三轮审计的 10 份子报告揭示了**4 个系统性规律**——这些规律本身反映了项目的工程文化特征：

1. **"修复正确但覆盖不完整"**（最常见模式）
   - CRIT-NEW-3: `NYX_CONFIG_KEY` 只加到 proc-macro 测试路径，生产 build.rs 绕过
   - HIGH-NEW-BOF2: 50/51 selftest 门控，漏 2 个
   - NEW-K4: slot-0 skip 加到 `repurpose` 但没移植到 `neutralize`
   - CC-1/CC-2: 启动时门控正确，运行时可绕过

2. **"修了症状没修根因"**
   - CRIT-NEW-3: 密钥仍在二进制内
   - NEW-MED-T18: MCP auth `Option<String>` + 默认 None = 原 HIGH 仍在

3. **"修复 docstring 承诺了纵深防御但未交付"**
   - NEW-1: `from_secret_bytes` 绕过 `reject_zero`
   - NEW-K4: `neutralize` 未跳 slot-0

4. **"修复引入了更危险的回归"**
   - **NEW-MED-N1 (ntalloc UAF)**: 泄漏修复 → 释放活跃堆 → UAF（比泄漏更危险）

**规律评估：** 这些规律不反映设计远见的缺失——它们反映的是**大规模修复批次中的质量控制挑战**。项目通过三轮审计主动发现并记录这些问题，本身就是工程纪律的体现。

### A.5 修正后的终评

综合两路代理（audit sub-reports + roadmap docs）返回的完整数据，对主体报告的评分做以下微调：

| 维度 | 主体报告评分 | 代理补充数据后的修正 | 修正原因 |
|---|---|---|---|
| 加密核心 | A+ | **A+ 确认** | 子报告确认：CSPRNG Result 传播完整、SessionKey Drop 正确、HKDF salt 修复、ct_eq 用 subtle |
| Server 安全 | 未单独评 | **B** | CRIT-1 已修但 TOCTOU（NEW-S4）+ kernel bridge 死码（CRIT-2 未修） |
| LACUNA | A | **A 确认** | 子报告确认：`.pdata` gap 扫描器正确，"best-reasoned unsafe" |
| BOF loader | B- | **B- 确认** | NEW-1: 从不 VirtualFree = 永久 RX 页 IOC |
| 路线图 | B+ | **A-** | 代理揭示 36 月路线图的深度（PQC + LLM-EDR + 跨平台）超预期 |
| 工程纪律 | A | **A 确认** | 诚实标注 + 三轮审计 + selftest 文化 |

**综合远见能力终评维持：B+** — 同代公开项目中最前沿梯队之一。核心短板（sleep obfuscation 代差 + BYOVD 实现完整性）和核心优势（MCP/LLM 信道 + Rust no_std + LACUNA + 路线图深度）均经多源验证确认。

---

*报告结束。*

*本报告由全栈审计（10 路并行子报告代理 × 三轮审计交叉验证）+ 外部 SOTA 研究（exa 8 轮 + context7 3 轮 + web reader 3 篇全文 × 30+ 篇 2026 技术文献）综合生成。*
