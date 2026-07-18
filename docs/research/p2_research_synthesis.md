# Nyx P2 — 研究全景综合 & 实现缺口分析

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> 基于四份研究文档的完整阅读 + 当前代码库的对照审计。

---

## 一、研究文档体系梳理

项目共有 4 份 P2 文档，层次分明：

| 文档 | 定位 | 核心价值 |
|------|------|---------|
| `p2-edr-bypass-plan.md` | **分层攻击计划**（Tier 0/1/2/3） | 威胁模型 + 优先级排序；有两次修订（BYOVD → EvilEDR 主路） |
| `p2-windows-bypass-research.md` | **学术/行业文献综述**（节 A–Q） | 每项研究→Nyx 模块的映射表；2026 mid-year 增补 |
| `p2-integration-analysis.md` | **逐 Kit 构建规格**（build-spec） | 最权威的落地手册；§2.1–2.6 是实际编码的 spec |
| `p2-2026-research-addendum.md` | **2026 研究增补**（call-stack/CET 时代） | **最新、最重要**：重排优先级；LACUNA Chain 是 SOTA |

---

## 二、研究发现的关键结论（最终版，经所有文档综合）

### 2.1 间接系统调用已有已知检测上限 ← 新发现，很重要

**xacone（"Catching Potential Indirect Syscalls"）**：VEH + 硬件断点挂 `Nt*+0x14`（即 `ret`），检查 `*RSP` 是否落在合法 DLL 导出范围内。当前 `stub.rs` 的间接 stub 虽然 `syscall` 指令 RIP 在 ntdll（合法），但 **return address 仍指向 implant 内存** → 被 flag。

→ **这意味着 `stack.rs` 的 spoof 不是可选功能，是补齐现有能力的必要项。**

### 2.2 CET 杀死了旧式 return-address 操纵

Intel CET（Win11 24H2 opt-in，未来默认）：每次 `CALL` 同时写 RSP-stack 和只读 shadow stack；`RET` 校验两者一致，否则 `#CP` fault。SilentMoonwalk / ThreadStackSpoofer / 一切直接修改 RSP-stack 返回地址的方案 **在 CET 环境下直接崩溃**。

→ **`stack.rs` 的 skeleton 隐含的"Gen-2/3 spoof"在 CET 上无效，必须改用 BYOUD-Gap 方案。**

### 2.3 LACUNA Chain / Ghost Frames — 2026-06 SOTA（当前最强调用栈绕过）

**0xmaz（Alzhrani）**，PoC: `github.com/MazX0p/LACUNA-Chain`。

核心洞见：**`RtlLookupFunctionEntry(addr)` 返回 NULL 时，unwinder 把它当 leaf 函数，RSP 仅进 8 字节，不崩溃。** 每个 DLL 的 `.pdata` 条目之间存在大量"gap"地址（ntdll: 3913 个 gap, 73745 字节覆盖范围；kernelbase: 3982 个）。这些 gap 地址：
- **零 `.pdata` 修改**（clean，无 forensic artifact）
- **CET-safe**（不碰 shadow stack）
- 可作为 bridge frames 隐藏真实帧

额外发现：
- **Ghost Functions**：1031 个 ntdll gap 含真实可执行代码（编译器 helper/inlined thunk），无 `.pdata` 条目
- **Ghost Gadget**：`ntdll+0xFC47B` 处 `JMP [RBX]`（80 字节 ghost 中），dual-use（执行重定向 + 零 artifact bridge）
- **Win32u NOP Gap Chain**：win32u.dll 全是 24 字节 syscall stub + 8 字节 NOP gap（1242 个），EDR 的 module-of-origin 规则把 win32u 列为可信 → 直接武器化白名单
- **BYOUD-MF**：`UWOP_PUSH_MACHFRAME`（opcode 10），`KiUserApcDispatcher` 等四个 dispatcher 携带它，可做任意 RSP 跳转，无 `.pdata` 写
- **BYOUD-RT**：从 `TEB.StackBase (GS:[0x08])` 计算运行时 RSP 偏移，无需预标定，适合注入 shellcode
- **ETW-Ti APC 窗口攻击**：ETW-Ti 的栈采集是异步的（USER_APC 在下一个 alertable wait 时交付），T+0 到 T+5 之间线程无监控 → 在非 alertable 状态完成操作、清理栈，再进入 alertable wait，采集到的是伪造栈

**Lab 结果**：完整 LACUNA Chain 绕过 Sysmon E10、ETW-Ti STACKWALK、shadow/user compare；仅剩行为 kernel callbacks。

### 2.4 FOLIAGE 的检测更新（Kyle Avery / Hunt-Sleeping-Beacons）

更新后的 HSB 检测：wait-reason `UserRequest` **AND** `KiUserApcDispatcher` 出现在调用栈上。普通 FOLIAGE 实现绕不过这个，因为 APC 线程无法调用混淆的 return-address-spoof shellcode。

→ **必须把 call-stack spoof 集成进 sleep 链本身**，使 APC 帧解析到 image-commit 地址。结合 LACUNA 的 ETW-Ti APC 窗口技术（§1.4 of addendum）是完整解法。

### 2.5 ETW-TI 内核 blind — BYOVD 单次写入（S12, 2026-05）

```
ntoskrnl base
  + EtwThreatIntProvRegHandle  → _ETW_REG_ENTRY
  + 0x020 (GuidEntry)          → _ETW_GUID_ENTRY  
  + 0x060 (ProviderEnableInfo)
  + 0x000 (IsEnabled)          = 0   ← 单次 QWORD 写，kernel 停止所有 TI 事件
```

**运行时解析偏移**（永远不硬编码）。HVCI 兼容（数据节操纵，非 inline hook）。对应 EDRSandblast `ETWThreatIntel.c`。

### 2.6 PatchGuard / 内核 Tier — 只能做数据节操纵（Outflank Peekaboo 2026）

HVCI 下 EPT 把 code page 标为 R-X，写入触发 VM-exit → `KeBugCheckEx`。**内联 hook 完全死亡。** 数据节是 EPT RW-，未受 HVCI 检查。
- 可行方案：`EPROCESS.ActiveProcessLinks` 断链 + 在终止 callback 中修复（时序修复，在 `PspProcessDelete` 校验前完成 repair）
- 需要签名内核驱动（BYOVD/DMA bootstrap）

### 2.7 ETW 欺骗（高于盲化，future）

Olaf Hartong，BH USA 2025："I'm in Your Logs Now"。不是抑制 ETW，而是**伪造/注入良性遥测事件**，攻击 SOC 对 ETW 的信任。`blind.rs` 的未来演进方向：suppress + **forge**。

### 2.8 EvilEDR — 操作者策略（非 implant 特性）

USENIX Security 2025。将攻击者控制的 EDR 部署在企业 EDR 旁边，利用其合法功能：
- Live-response console = C2
- File download = 数据外泄（绕过 MOTW）
- EPP Takeover：通过 Windows Security Center API 注册自己为默认 EPP，无告警
- Host isolation：让企业 EDR 显示 offline，不记日志

→ 这是**操作者层面**的工具，不是 implant kit。

### 2.9 TCAs — 遥测复杂度攻击（arXiv:2511.04472）

通过递归子进程生成深度嵌套、超大遥测，溢出序列化/存储限制（JSON/BSON 深度 + 大小）→ 报告截断/缺失 → **拒绝分析（DoA）**。评估 12 个商业+OSS 平台，7 个失败。正交于 call-stack/ETW 层。

### 2.10 CET 内核阴影栈 — Synacktiv SSTIC 2025 精读

- Win11 24H2 **尚非默认**，opt-in via Core Isolation / registry。未来可能默认。
- VTL1 secure kernel + EPT 让 shadow-stack page 对 VTL0 只读。`CR0.WP`/PTE 旁路失效。
- **`#CP` handler 是宽容的**：`nt!KiControlProtectionFault` 走 shadow stack，若任一存储的 return address 匹配 RSP 处的，则不 BSOD，调用 `VslKernelShadowStackAssist` 修复。exception unwind 路径（`RtlRestoreContext`）也利用此 seam 保持一致性。
- JOP gadget 依然有效（不碰 stack）；IBT 尚未在 Windows 上执行。

---

## 三、当前代码库缺口对照

| 模块 | 状态 | 缺口 |
|------|------|------|
| `syscalls.rs` / `stub.rs` | ✅ 间接系统调用运行时，有 `syscall` gadget | ❌ return address 仍指向 implant → xacone-class 检测 |
| `stack.rs` | ⚠️ skeleton / no-op | ❌ 全部待实现；隐含方案与 CET 不兼容 |
| `kits.rs` `SleepmaskKit` | ⚠️ seam 就绪（NoMask 占位） | ❌ 需要真正的 Foliage 实现 |
| `sleep.rs` | ⚠️ skeleton，转发到 kits | ❌ 等待 kit 实现 |
| `blind.rs` | ⚠️ 当前 patch `EtwEventWrite` | ❌ 应改为 PEB-walk 解析 `NtTraceEvent` byte0→`0xC3`；需加 provider-disable |
| `resolve.rs` | ✅ PEB walk、djb2、LiveNtdll | ❌ 缺 `.pdata` gap/ghost 扫描（LACUNA 所需） |
| `kits.rs` `ProcessInjectKit` | ⚠️ NotImpl | ❌ module stomping 待实现（P2.1c） |
| 内核 tier | 无代码 | P2.2；operator-side 工具，非 implant；engagement-gated |

---

## 四、修订后的 Build 顺序（最终，基于 2026 Addendum）

> 关键变化：call-stack spoof **从 "P2.1b" 升格为与 SleepmaskKit 并列的 co-primary**，且必须先于 sleep mask 完成（sleep mask 的 APC 链需要干净的帧才能绕过更新后的 HSB）。

### P2.1a-i — Gap/Ghost 扫描器（`resolve.rs` 扩展）
**这是第一步，所有后续依赖它。**

- 扩展 `resolve.rs`：在 init 时扫描 ntdll / kernelbase / win32u / wow64 的 `.pdata`，枚举 gap 地址 + ghost function 地址
- 缓存一个 `GapPool`（gap 地址列表）供 spoof 使用
- 纯读内存，HVCI/CFG 无关
- selftest：在 Win10/11 上 gap 数量 > 0

**所需知识**：PE `.pdata` (`IMAGE_RUNTIME_FUNCTION_ENTRY`) 格式；`RtlLookupFunctionEntry` 的 NULL-返回语义

### P2.1a-ii — BYOUD-Gap 调用栈 Spoof（`stack.rs` 真实实现）

- 将 `with_spoofed_stack` 从 no-op 改为真实实现
- 使用 `GapPool` 中的 gap/ghost 地址作为 leaf bridge frames
- `BYOUD-RT`：从 `TEB.StackBase (GS:[0x08])` 减当前 RSP，运行时计算偏移，无需预标定
- 集成入 `syscalls.rs` 的 `trampoline_for`，每次间接系统调用都使 `[RSP]` 解析为签名 DLL 中的 gap 地址
- CET-safe（不修改 shadow stack；gap 是 leaf → unwinder 只进 8 字节）
- Fallback：CET-off 主机上的 LayeredSyscall VEH 方案

**验证**：自建一个类 xacone 的 VEH 检测器（build it），确认 `[RSP]` export 检查通过；ETW-Ti STACKWALK 无告警

### P2.1a-iii — SleepmaskKit Foliage（`kits.rs` 真实实现）

**依赖 P2.1a-ii（APC 链需要干净的帧绕过更新后的 HSB）**

- 实现 `struct Foliage` impl `SleepmaskKit`
- 10 步 APC → `NtContinue` 链（见 `p2-integration-analysis.md §2.1`）
- 加密：`SystemFunction032`（从 advapi32 PEB-walk 解析，RC4，image-commit，规避 Moneta 私有提交检测）
- Sleep：`NtWaitForSingleObject`（wait-reason `UserRequest`，不是 `NtDelayExecution` 的 `DelayExecution`）
- APC 帧通过 P2.1a-ii 的 spoof 包装，使 `KiUserApcDispatcher` 不出现在栈上
- 利用 ETW-Ti APC 窗口（non-alertable 期间操作，alertable wait 时提供干净栈）
- 一行替换：`const SLEEPMASK_KIT: NoMask = NoMask` → `const SLEEPMASK_KIT: Foliage = Foliage`

**验证**：HSB（更新版）零命中；Moneta；PE-sieve；BeaconEye；MalMemDetect；Defender 内存扫描

### P2.1b — ETW 强化（`blind.rs` 升级）

- 将 `patch_etw()` 从 `EtwEventWrite` 改为 `NtTraceEvent` byte0 → `0xC3`（fluxsec 方案）
  - `EtwEventWrite` 和 `EtwEventWriteFull` 都通过 `NtTraceEvent` → 一个补丁覆盖全部
  - 通过 PEB-walk 解析 `NtTraceEvent`，**不能用 `GetProcAddress("NtTraceEvent")`**（字符串解析本身是 EDR 红旗）
- 添加 **provider-disable**（设置 provider GUID `IsEnabled` = false）作为双保险
- 验证：`logman … tracerpt … .csv` 确认 ETW provider 沉默

### P2.1c — ProcessInjectKit 模块踩踏（`kits.rs` 扩展）

- `LoadLibrary` 一个合法小众签名 DLL
- `NtProtectVirtualMemory` `.text` → RW → memcpy shellcode → RX
- 区域"住"在受信任模块内 → 绕过 Moneta 可执行私有内存检查 + unbacked 调用栈检查
- 将 `NotImpl` → 真实 impl

### P2.2 — 内核 Tier（engagement-gated，operator-side）

**注意：PIC no_std implant 不能承载内核驱动。P2.2 是操作者工具，不是 implant kit。**

- `EtwTiKit`：S12 方案（运行时解析 `EtwThreatIntProvRegHandle` 偏移 → QWORD 写 IsEnabled=0）
- `CallbackKit` / `PatchGuardKit`：Outflank 数据节 + 时序修复方案（断链 `EPROCESS.ActiveProcessLinks` + termination callback 中在 `PspProcessDelete` 校验前 repair）
- HVCI-aware：数据节操纵 HVCI 兼容；在 HVCI-on 主机上内核 tier 降级到 floor
- 需要签名驱动（BYOVD / DMA bootstrap）

---

## 五、关键技术债务 & 注意事项

### 当前 `blind.rs` 的问题
当前补丁的是 `EtwEventWrite`，但研究显示应补丁 `NtTraceEvent`。原因：
- 使用 `export_addr(b"ntdll.dll", b"EtwEventWrite")` 等同于间接地用了名字解析，且 `EtwEventWrite` 有多个变体
- `NtTraceEvent` 是底层 syscall stub，一个补丁覆盖所有上层调用者
- 现有实现用 `VirtualProtect`（通过 `kernel32.dll` 解析），这是 EDR 信号（code-integrity scan / ETW TI）。应升级为通过间接系统调用的 `NtWriteVirtualMemory`

### `stack.rs` 的设计问题
skeleton 的注释（Gen-2/3 style: "allocate a fake frame region, write a chain of jmp/ret gadgets, swap RSP"）在 CET 下会崩溃。需要从设计层面改为 BYOUD-Gap，概念完全不同：不是操纵 RSP，而是在现有 RSP 链中插入无 `.pdata` 覆盖的 gap 地址作为 leaf frame。

### 共享基础设施（只建一次，多处复用）
- **Timer + APC helper**：sleep mask（APC chain）+ spoof（timer-based frame setup）+ 未来 threadless inject 共用
- **`SystemFunction032` wrapper**：sleep mask 加密
- **image base + `.text` range 发现**：PEB walk + `resolve.rs` 已有部分，需要补全 `.pdata` gap 扫描

---

## 六、不同文档间的矛盾与演进

| 议题 | 旧版认知（`p2-edr-bypass-plan.md`） | 最新认知（`p2-2026-research-addendum.md`） |
|------|-------------------------------------|-------------------------------------------|
| BYOVD 地位 | Tier 2 主路，高优先级 | 降为 fallback；EDR-Repurposing 是主路 |
| call-stack spoof 优先级 | P2.1b（在 sleep mask 之后） | 升为 **co-primary**，且必须先于 sleep mask |
| stack spoof 方案 | Gen-2/3（操纵 RSP-stack 返回地址） | **BYOUD-Gap**（`.pdata` gap leaf frames，CET-safe） |
| `blind.rs` patch 目标 | `EtwEventWrite` | `NtTraceEvent` byte0 → `0xC3` |
| HSB 绕过复杂度 | wait-reason `UserRequest` 即可 | 还需 `KiUserApcDispatcher` 不在栈上（需要 spoof 集成） |
| 内核 tier 实现位置 | implant kit | **operator-side 工具**（PIC implant 不能承载 kernel driver） |

---

## 七、验证矩阵（完整版）

| Kit / 变更 | 验证工具 | 目标结果 |
|-----------|----------|---------|
| `stack.rs` BYOUD-Gap | 自建 xacone-style VEH detector；ETW-Ti STACKWALK | `[RSP]` export 检查通过；无 STACKWALK 告警 |
| `SleepmaskKit` Foliage | HSB（更新版）；Moneta；PE-sieve；BeaconEye；MalMemDetect | 零命中 |
| Defender 内存扫描 | Windows Defender on looping sleep | 无检测 |
| `blind.rs` NtTraceEvent | logman + tracerpt；fluxsec Sanctum method | provider 输出为空 |
| `ProcessInjectKit` | Moneta exec-private check；PE-sieve unbacked check | 区域通过为合法模块 |
| P2.2 EtwTiKit | Sysmon EID 6；ETW-TI consumer | TI consumer 沉默 |
| P2.2 CallbackKit | HVCI-on + HVCI-off VM 各一 | 进程隐藏有效；无 BSOD |

---

## 八、一句话总结每份文档的独特贡献

- **`p2-edr-bypass-plan.md`**：威胁模型分层（6 层 EDR 机制）+ 最终告诉我们 BYOVD 是 fallback，EvilEDR 是主路
- **`p2-windows-bypass-research.md`**：文献 mapping（A–Q 节）+ 2026 mid-year 增补（Curing io_uring、Nation State Minds 白皮书、HookChain DEF CON 32）
- **`p2-integration-analysis.md`**：**最权威构建规格**，每个 Kit 的 no_std 约束、具体 API 调用序列、acceptance bar
- **`p2-2026-research-addendum.md`**：**最新、最重要**，颠覆两个假设（call-stack co-primary；CET 杀死旧 spoof），引入 LACUNA Chain（SOTA），提供 ETW-Ti 内核 blind 的完整指针链
