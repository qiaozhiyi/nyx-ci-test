> ⚠️ **历史快照** — 本文档记录 2026-06-26 的状态，可能已过时。
> 最新项目事实以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。
> 如需当前能力状态，请查阅 [`README.md`](../../README.md)。

# Nyx C2 — Bypass 能力对标报告

**对标对象：** Cobalt Strike 4.13 "Lost In Translation"（2026-06-10）/ Brute Ratel C4 v2.3 "Flux"（2025-10-07）
**报告日期：** 2026-06-26
**基线：** Nyx 代码实测（39/39 自测通过，Server 2019 17763.1339）+ 14 类能力逐项审计
**分类：** 授权红队研究

> 本报告以**当前代码实际状态**为准。注意 `docs/p2-2026-06-gap-analysis.md`（06-25 快照）列出的若干差距——HWBP 盲打、ETW 伪造、MiniFilter 摘除、PPL——已在之后提交中闭合（见未跟踪文件 `blind_hwbp.rs`、`etw_deception.rs`、`ksld.rs`）。本报告据实修正。

---

## 0. 摘要（结论先行）

| 维度 | 判定 | 说明 |
|---|---|---|
| **用户态 bypass 核心** | ✅ **对位** | indirect syscalls / sleep mask / RAS / AMSI·ETW 盲打 / ntdll unhook / module stomping 全部实装，与 CS 4.13、BRC4 v2.3 同一量级 |
| **内核态 bypass** | 🟢 **维度领先** | CS / BRC4 均为纯用户态商品框架，**无内核驱动**；Nyx 有 BYOVD + callback 摘除 + minifilter + ETW-TI + PPL + DKOM + PG 窗口 + LSASS 直读 |
| **sleep mask 覆盖面** | 🟡 **落后一档** | CS 4.13 全面重写 sleep mask，**同时 mask Beacon + Sleepmask 代码本身 + heap 分配**；Nyx Foliage 只 mask `.text`，**未覆盖 heap** |
| **栈欺骗 CET 兼容** | 🟡 **落后一档** | CS/BRC4 的 RAS 已在 CET-on 主机稳定；Nyx 的 live RSP swap 在 CET-on 自动降级 |
| **持久化（重启存活）** | 🔴 **明显落后** | CS/BRC4 有 service/registry/WMI/sched-task 全生态；Nyx 仅有内核 DKOM（运行时隐藏，重启失效） |
| **注入多样性** | 🟡 **落后** | CS/BRC4 支持早鸟 APC / 线程劫持 / hollowing 等多种；Nyx 仅 module stomping |
| **C2 协议 / 后渗透生态** | 🟡 **落后** | CS 4.13 有 HTTPS/DNS/SMB/TCP + UDC2 + Beacon Interpreter + BOF-PE；BRC4 多通道；Nyx 仅 HTTPS + pivot |
| **内核能力落地** | ⚠️ **存疑** | 算法完整、单测通过，但加载步骤 operator-run，未在现代 Win11 24H2/25H2 + 主流 EDR 下验证 |

**一句话：** 用户态核心 bypass 已对位 CS 4.13 / BRC4 v2.3，内核 bypass 维度上 CS/BRC4 根本没有、Nyx 领先；但 **heap sleep mask、CET-safe swap、持久化、注入多样性、C2 生态**五项仍有实质差距。

---

## 1. 竞品版本基线

### 1.1 Cobalt Strike 4.13 "Lost In Translation"（2026-06-10）

Fortra 于 2026-06-10 发布。前序版本演化：
- **4.11**（2025-03-17）：引入全新 evasive Sleep Mask、全新进程注入法、Beacon 混淆、异步 BOF、DNS 增强
- **4.11.1**（2025-05-12）：修复 CFG 进程 + module stomping + 默认 sleep mask 的崩溃
- **4.12**（2025-11）：drip-loader、扩展 Beacon metadata、UDC2（用户自定义 C2）、刷新 GUI、REST API
- **4.13**（2026-06-10）：**Beacon Interpreter（原生 C 脚本）**、**BOF-PE**、**全面重写的默认 sleep mask**、运行时 Malleable C2 覆盖、REST API 的 WebSocket/gRPC 流、**CS:RL（联合 Outflank 研究实验室）**、Aggressor AI

**4.13 对 bypass 最关键的变化：**
1. **默认 sleep mask 全面重写**——"Beacon 和 Sleepmask 现在自动用专有 evasion 代码 mask"，适用 HTTP/HTTPS/DNS Beacon。这意味着开箱即用，无需自定义 kit 即可获得 sleep mask + 代码段加密。
2. **BeaconGate 持续演进**——4.10 引入、4.11+ 精化，允许 Beacon 通过自定义 sleep mask 拦截 WinAPI 调用，官方 `sleepmask-vs` 仓库已含 `indirectsyscalls-sleepmask` 示例，对所有代理调用做 **return address spoofing**。
3. **CS:RL**——Fortra 收编 Outflank 团队组建研究实验室，意味着 CS 的 evasion 研发速度提升。

### 1.2 Brute Ratel C4 v2.3 "Flux"（2025-10-07）

- **核心变化：** 用**自研编译器完全重写了 Badger 植入体**，目标是显著改善 OpSec 和降低逆向分析可行性。
- **前序：** v1.7 "Pandemonium"（2023-07）做过一次 Badger 全面重写 + Yara evasion + Apple Silicon 支持。
- **BRC4 bypass 核心（公开已知）：** indirect syscalls、HWBP 盲打（绕 AMSI/ETW 不 patch）、NTDLL unhook（BRC4/s12 风格 fresh-map）、内存加密、动态 API 切换（WinAPI→NTAPI→Syscall）、反调试硬化。

---

## 2. 能力对标矩阵（逐项实测）

图例：✅ 对位 / 🟢 Nyx 领先 / 🟡 Nyx 落后一档 / 🔴 Nyx 明显落后 / ⚠️ 设计完成未全量接线 / ❌ 竞品无此能力

### 2.1 用户态 bypass

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx（实测） | 判定 |
|---|---|---|---|---|
| **Indirect syscalls** | ✅ sleepmask-vs BeaconGate 官方示例 | ✅ Badger 原生 | ✅ `syscalls.rs` gadget 在 ntdll 内执行 `syscall` | ✅ 对位 |
| **SSN 解析** | 未公开 | 未公开 | ✅ Hell's/Halo's/Tartarus + KnownDlls fresh + disk fallback 三级回退 | ✅ 对位+ |
| **sleep mask（.text 加密）** | ✅ 4.13 全面重写，开箱即用 | ✅ memory encryption | ✅ Foliage APC→NtContinue + RC4，**ARMED** | 🟡 落后（见下） |
| **sleep mask 覆盖 heap** | ✅ 4.11+ "obfuscates Beacon **and its heap allocations**" | ⚠️ 未公开 | ❌ **Foliage 只 mask `.text`**，heap 配置结构明文 | 🟡 落后 |
| **return address spoofing** | ✅ BeaconGate 代理调用全 spoof | ⚠️ 未公开 | ✅ `stack.rs` BYOUD-Gap/LACUNA，swap ARMED | 🟡 落后（CET 降级） |
| **AMSI bypass（patchless）** | 有 kit（需自写） | ✅ HWBP 原生 | ✅ `blind_hwbp.rs` DR0+VEH+RF（boku7 风格）+ 字节 patch 双实现 | ✅ 对位+ |
| **ETW bypass（用户态）** | sleepmask patch | patch | ✅ `blind.rs` EtwEventWrite + NtTraceEvent 双 patch | ✅ 对位+ |
| **ETW-TI（内核）** | ❌ 无内核 | ❌ 无内核 | ✅ `etwti.rs` IsEnabled=0，per-build offset | 🟢 Nyx 独有 |
| **ETW 事件伪造** | ❌ | ❌ | ✅ `etw_deception.rs` 伪造 Process Start/Stop + 频率保持 | 🟢 Nyx 独有（诚实：缺 HMAC 签名） |
| **ntdll unhook** | 有 kit | ✅ s12 风格 | ✅ `unhook.rs` KnownDlls fresh + disk（代码注释自承认即 BRC4/s12） | ✅ 对位 |
| **module stomping** | ✅ 4.11 新注入 | ✅ | ✅ `inject.rs` ARMED | ✅ 对位 |
| **threadless inject** | 未公开 | 未公开 | ⚠️ 设计完成、HWBP 机制就位，**未全量接线** | 🟡 追赶中 |
| **进程注入多样性** | ✅ 早鸟 APC/hollow/blink+ 多种 | ✅ 多种 | ❌ **仅 module stomping** | 🔴 落后 |
| **硬件断点机制** | — | ✅ | ✅ 完整 VEH+DR0/DR7+RF | ✅ 对位 |
| **UDRL（反射加载）** | ✅ prepend reflective loader | ✅ | ❌ 无 UDRL | 🟡 落后 |

### 2.2 内核态 bypass（CS / BRC4 均无此维度）

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx（实测） | 判定 |
|---|---|---|---|---|
| **BYOVD 内核 R/W** | ❌ | ❌ | ✅ `byovd.rs` RTCore64（CVE-2019-16098）已验证 IOCTL | 🟢 独有 |
| **callback 摘除** | ❌ | ❌ | ✅ `telemetry.rs` Ps*NotifyRoutine 写 0xC3 + `repurpose()` 重定向 | 🟢 独有 |
| **MiniFilter 摘除** | ❌ | ❌ | ✅ `telemetry.rs` `MiniFilterUnlinker` FltGlobals 链表 unlink | 🟢 独有 |
| **PPL 剥离/提升** | ❌ | ❌ | ✅ `persistence.rs` `PplStripper` Protection+SigLevel 三字节清零 | 🟢 独有 |
| **进程隐藏（DKOM）** | ❌ | ❌ | ✅ `persistence.rs` `ProcessHider` PsActiveProcessHead unlink | 🟢 独有 |
| **PatchGuard 窗口** | ❌ | ❌ | ✅ Timing + Runtime 双状态机（kurasagi 风格） | 🟢 独有 |
| **LSASS 直读** | ❌ | ❌ | ✅ `netsec.rs` CR3 切换 + 4 级页表走查，绕 RunAsPPL + CG | 🟢 独有 |
| **EDR 中和** | ❌ | ❌ | ✅ Kill/Freeze/Choke 三档（QoS 8bit/s 窒息） | 🟢 独有 |
| **KslD.sys bootstrap** | ❌ | ❌ | ⚠️ `ksld.rs` 已建文件，IOCTL 绑定未接线 | 🟡 进行中 |

> **诚实提醒：** 内核组件算法完整、单测通过，但**加载步骤 operator-run**（`byovd.rs:3` 注释 "CODE SHIPPED, NOT LOADED"）。RTCore64 在微软漏洞驱动黑名单上（覆盖率 ~70%）。KslD.sys（Living off the Defender）是绕过黑名单的正解，但 IOCTL 绑定尚未完成。**内核能力目前为算法级 / 纸面级，未在现代 Win11 24H2/25H2 + 主流 EDR 下验证。**

### 2.3 持久化 / C2 / 工程

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx（实测） | 判定 |
|---|---|---|---|---|
| **持久化（重启存活）** | ✅ service/registry/WMI/sched-task | ✅ 多种 | ❌ **仅内核 DKOM（运行时隐藏，重启失效）** | 🔴 明显落后 |
| **C2 协议** | ✅ HTTPS/DNS/SMB/TCP + UDC2 | ✅ 多通道 | ⚠️ 仅 HTTPS WinHTTP + pivot | 🔴 落后 |
| **BOF 生态** | ✅ BOF + 异步 BOF + **BOF-PE** + Beacon Interpreter | ✅ 异步 BOF | ⚠️ bof 执行（基础） | 🟡 落后 |
| **后渗透命令** | ✅ 完整 | ✅ 完整 | ✅ fs/shell/screenshot/keylog/hashdump/bof/portscan/pivot | 🟡 接近 |
| **多版本覆盖** | 商业闭源 | 商业闭源 | ✅ Win10 1507→Win11 25H2 + 动态 probe（公开可验证） | ✅ |
| **反调试** | ✅ | ✅ 硬化 | ⚠️ PEB BeingDebugged + ProcessDebugPort + uptime（advisory） | 🟡 轻量 |

---

## 3. Nyx 领先项（相对 CS / BRC4 的差异化优势）

1. **内核 bypass 整条栈**——CS / BRC4 是纯用户态商品框架，完全没有内核驱动维度。Nyx 的 callback 摘除 + minifilter unlink + ETW-TI + PPL + DKOM 是 CS/BRC4 物理上不具备的。对 **Cortex XDR（纯内核回调、零用户态 hook）** 这类目标，CS/BRC4 的用户态 bypass（ntdll unhook / AMSI blind / ETW patch）**完全无效**，只有 Nyx 的内核层有效。

2. **ETW 事件伪造**——CS/BRC4 只做 ETW 抑制（suppress），事件消失本身可被频率异常检测器发现。Nyx 的 `etw_deception.rs` 伪造结构完整的合成 Process Start/Stop 事件 + 频率保持器，对抗"事件缺失"检测。**CS/BRC4 均无此能力。**（诚实：伪造事件缺内核 HMAC 签名，密码学验证的 ETW 会话仍可区分。）

3. **SSN 解析三级回退**——KnownDlls fresh-map → 磁盘读取 → hooked ntdll 邻居走查。比公开的单点方案（仅 Hell's Gate 或仅 Halo's Gate）更鲁棒。

4. **多版本 offset 公开可验证**——15 个 build 的 EPROCESS/ETW-TI/PG/fltmgr offset 表 + DefenderDump 式动态 probe，全可审计。CS/BRC4 闭源，offset 策略不透明。

---

## 4. Nyx 落后项（与 CS 4.13 / BRC4 v2.3 的实质差距）

### 🔴 差距 A — sleep mask 未覆盖 heap（最高优先级）

- **CS 4.13：** 全面重写默认 sleep mask，**同时 mask Beacon 代码 + Sleepmask 代码本身 + heap 分配**，开箱即用（"automatically masked with proprietary evasion code"）。
- **Nyx：** Foliage 只 RC4-mask `.text` 段。Beacon 配置结构体、token、句柄等散落在 heap 上的数据**仍是明文**。
- **后果：** BeaconEye 类工具扫 heap 配置结构仍能命中；MalMemDetect 在 `RtlAllocateHeap` 返回处检查执行时返回地址仍有效。
- **定位：** `sleep.rs` + `mem.rs`——`MemoryMaskKit` 目前只 `register_region` 了 32 字节 ECDH session key，未覆盖 beacon heap。

### 🟡 差距 B — return address spoofing 在 CET-on 主机降级

- **CS 4.13：** BeaconGate 代理调用的 RAS 已在 CET-on 主机稳定（商品化稳定路径）。
- **Nyx：** `stack.rs:17-50` 明确写了——BYOUD-Gap leaf-chain 在 unwind-walk 层 CET-safe，但**裸的 RSP swap 在 CET-on 主机会 #CP / `KiControlProtectionFault`**，因此 swap 自动降级。正确的路径需经 Synacktiv SSTIC 2025 的 `KiControlProtectionFault` lenient-repair 缝隙——**未实现**。
- **后果：** 在 Intel TGL+ 且 CET 启用的机器上（2025 年新机越来越多），间接 syscall 的 `[RSP]` 残留重新暴露，被 xacone / K2 / cet-spoofing-detection 检测。这是**随时间恶化**的弱点。

### 🔴 差距 C — 持久化近乎为零

- **CS 4.13 / BRC4：** 完整的 service / registry Run / WMI 事件订阅 / scheduled task 持久化生态。
- **Nyx：** `persistence.rs` 只有内核 DKOM（运行时隐藏进程）+ PPL 剥离，**全部重启失效**。无任何重启存活持久化。
- **后果：** 长期驻留场景下短板突出——机器一重启 implant 即丢失。

### 🟡 差距 D — 注入多样性不足

- **CS 4.13 / BRC4：** 支持 early bird APC、thread hijack、process hollowing、`NtMapViewOfSection` 等多种注入法。
- **Nyx：** `inject.rs` 仅 module stomping（ARMED）。`inject.rs:11-18` 明确拒绝了经典 `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread`。
- **后果：** 注入路径单一，一旦 module stomping 被 PE-sieve `.text` hash 检测盯死，无替代路径。

### 🟡 差距 E — C2 协议 / 后渗透生态单薄

- **CS 4.13：** HTTPS/DNS/SMB/TCP 四协议 + UDC2（用户自定义 C2 通道）+ Beacon Interpreter（原生 C 脚本，写 C 发给 Beacon 在 VM 里跑）+ BOF-PE。
- **BRC4 v2.3：** 多通道 + 异步 BOF。
- **Nyx：** 仅 HTTPS WinHTTP + pivot relay。后渗透命令已较全（fs/shell/screenshot/keylog/hashdump/bof/portscan），但 BOF 仅基础执行，无异步 BOF / BOF-PE / Beacon Interpreter。
- **后果：** 机动性受限，尤其内网横向场景缺 SMB/TCP 通道。

---

## 5. 未闭合的关键差距（按可落地优先级）

基于当前代码状态（已扣除已闭合项），剩余差距排序：

| 优先级 | 差距 | 影响 | 落地难度 | 竞品对标 |
|---|---|---|---|---|
| 🔴 P0 | **heap sleep mask**（差距 A） | BeaconEye/MalMemDetect 扫 heap 明文配置 | 中 | 追平 CS 4.13 |
| 🔴 P0 | **CET-safe RSP swap**（差距 B） | CET-on 主机 syscall 栈残留暴露，随时间恶化 | 中-高 | 追平 CS 4.13 |
| 🔴 P0 | **KslD.sys IOCTL 绑定** | 内核 bootstrap 依赖 RTCore64（黑名单 70%） | 中 | 内核能力从纸面到落地 |
| 🟡 P1 | **ThreadlessInject 全量接线** | module stomping 被 PE-sieve `.text` hash 检测 | 高 | 领先 CS/BRC4 |
| 🟡 P1 | **持久化生态**（差距 C） | 重启即丢，长期驻留短板 | 中 | 追平 CS/BRC4 |
| 🟡 P1 | **注入多样性**（差距 D） | 注入路径单一 | 中 | 追平 CS/BRC4 |
| 🟢 P2 | **C2 多协议**（差距 E） | 缺 DNS/SMB/TCP + UDC2 | 中-高 | 追平 CS 4.13 |
| 🟢 P2 | **异步 BOF / BOF-PE** | BOF 生态落后 | 中 | 追平 CS 4.13 |
| 🟢 P2 | **UDRL 反射加载** | postex 灵活性 | 中 | 追平 CS/BRC4 |
| 🔵 P3 | **Foliage wait-reason 改 UserRequest** | HSB 仍可识别 DelayExecution | 低 | 加固 |
| 🔵 P3 | **ETW-Ti APC window 攻击** | HSB 在 APC 窗口见 KiUserApcDispatcher | 中 | 加固 |
| 🔵 P3 | **内核 WFP callout 指针覆盖** | 网络遥测未在内核层静默 | 高 | 加固 |

---

## 6. 综合判定

### 用户态 bypass：基本对位，"最后 10%"未闭合
Nyx 的 indirect syscalls / sleep mask / RAS / AMSI·ETW 盲打 / ntdll unhook / module stomping 已与 CS 4.13 / BRC4 v2.3 同一量级，**核心矩阵全部对位**。但 CS 4.13 的 sleep mask 全面重写（**含 heap 覆盖**）和 BeaconGate 的 CET-stable RAS 是 Nyx 目前没追上的两点——这恰恰是 2025-2026 检测侧（BeaconEye、MalMemDetect、xacone、K2）重点打击的面。

### 内核 bypass：维度领先，但落地存疑
CS / BRC4 是纯用户态框架，**物理上没有内核维度**。Nyx 的 callback 摘除 + minifilter + ETW-TI + PPL + DKOM + PG 窗口 + LSASS 直读是商品框架不具备的差异化能力，对 Cortex XDR 这类纯内核回调 EDR 是唯一有效路径。**但：**加载步骤 operator-run、RTCore64 在黑名单上、KslD.sys 未接线、未在现代 EDR 下验证——内核能力目前是**算法级 / 纸面级**，真实环境落地能力存疑。

### 工程生态：明显落后
持久化（近乎为零）、C2 协议（仅 HTTPS）、注入多样性（仅 stomping）、BOF 生态（基础）四项与 CS 4.13 / BRC4 v2.3 有实质差距。这些不影响"能否绕过 EDR"，但影响"能否完成完整红队任务"。

### 最终一句话
> **用户态 bypass：和 CS 4.13 / BRC4 v2.3 打到同一量级，核心项全部对位，但 heap-mask 和 CET-safe swap 两处"最后 10%"未闭合；内核 bypass：维度上 CS/BRC4 根本没有，Nyx 领先，但落地待验证；工程生态（持久化/C2/注入/BOF）：明显落后。**

---

## 附：竞品资料来源

- Cobalt Strike 4.13 "Lost In Translation" 官方博客：https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation
- Cobalt Strike 发布归档：https://www.cobaltstrike.com/product_line/cobalt-strike
- Cobalt Strike 官方发布说明：https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm
- sleepmask-vs 仓库（含 indirect syscalls 示例）：https://github.com/Cobalt-Strike/sleepmask-vs
- BeaconGate 文档：https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm
- Cobalt Strike 4.11 sleep mask 介绍：https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
- CS:RL（联合 Outflank）：https://www.outflank.nl/blog/2026/03/26/introducing-cobalt-strike-research-labs/
- Brute Ratel C4 官方：https://bruteratel.com/
- BRC4 v2.3 "Flux" 发布：https://bruteratel.com/release/2025/10/07/Release-Flux/
- BRC4 发布归档：https://bruteratel.com/category/release/
- Vectra — BRC4 EDR evasion 分析：https://www.vectra.ai/blog/how-attackers-use-brute-ratel-brc4
- Splunk — Badger 检测（HWBP 绕 AMSI/ETW）：https://www.splunk.com/en_us/blog/security/deliver-a-strike-by-reversing-a-badger-brute-ratel-detection-and-analysis.html
- BRC4 Malpedia：https://malpedia.caad.fkie.fraunhofer.de/details/win.brute_ratel_c4
