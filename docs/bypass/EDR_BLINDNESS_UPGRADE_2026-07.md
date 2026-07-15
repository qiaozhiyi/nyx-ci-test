# EDR Blindness Upgrade Blueprint — 截止 2026-07 SOTA

> **授权红队 / 安全研究文档。** 本文档基于对 40+ 篇 2024-2026 公开一手研究的深读(FND Security、SafeBreach、Outflank、Synacktiv SSTIC 2025、Black Hat EU/USA 2025、DEF CON 32、Praetorian、fluxsec、Elastic Security Labs、0xmaz、klezVirus 等),结合对 Nyx 全栈 bypass 代码(`implant-win` / `operator-kernelsdk` / `implant-evasionsdk`)的逐文件审计,产出一份**自主决策的"最小噪音 EDR 彻底致盲"升级蓝图**。
>
> **核对日期:** 2026-07-01 · **分支:** `main` · **适用对象:** Nyx 框架
> **冲突优先级:** 当本文与 `docs/STATUS.md` 冲突时,STATUS.md 描述的是"已实装状态",本文是"应达到的 SOTA 目标"。

---

## 0. 核心设计决策(自主,不再询问)

### 0.1 设计原则:最小噪音致盲 = 检测面归零,不是绕过

2026 的 EDR 检测已从"抓单一技术特征"演进为**多平面关联检测**。FND Security 2025/05 的"2-of-3 关联规则"是核心模型:

> 进程注入的经典链 = **远程分配 + 远程写入 + 远程执行**。任意**两个**针对同一 PID 共现即触发告警。

这条规则可以推广到所有检测面:**致盲不是"让某个特征不可见",而是"让多个检测平面同时看不到关联"**。本蓝图的每条升级都按"关闭多少个检测平面"排序,不是按"技术新颖度"排序。

### 0.2 不可绕过的硬约束(诚实声明)

| 检测平面 | 用户态能否致盲 | 说明 |
|---|---|---|
| **ETW-TI(内核 provider)** | ❌ **不能** | 内核态 telemetry,用户态 patch `NtTraceEvent` 只掐用户态通路,内核 provider 由 Secure Kernel(VTL1)保护 |
| **`PsSetCreateThreadNotifyRoutine` 线程回调** | ❌ 不能 | 内核回调,只能 operator 侧驱动 `CallbackNeutralizer` 中和 |
| **`PsSetCreateProcessNotifyRoutineEx` 进程回调** | ❌ 不能 | 同上 |
| **Intel CET shadow stack** | 🔶 仅间接 | 用户态无法直接写 shadow stack;只能通过 Synacktiv SSTIC 2025 的 `KiControlProtectionFault` lenient-repair seam 间接存活 |
| **HVCI/VBS code-page 写** | ❌ 不能 | HVCI-on 下 code-page 是 EPT 只读;只有 DATA-section 写存活 |

**结论:真正的"EDR 彻底致盲"必须有内核侧(operator-kernelsdk)协同。** 纯用户态最多做到"对用户态 hook EDR 致盲",对内核 telemetry EDR 仍可见。本蓝图因此分为**用户态最大化致盲** + **内核态协同协议**两层。

### 0.3 最终架构决策:EDR Blindness Orchestrator

我决定引入一个**新的协调层**——`EDR Blindness Orchestrator`,它不是一个 crate,而是**beacon entry bootstrap + beacon sleep cycle + operator driver 的统一时间窗编排协议**。核心思想:

```
┌─────────────────────────────────────────────────────────────┐
│  T0  Bootstrap(一次性,最低噪音冷启动致盲)                  │
│   1. VM/沙箱探测(5-check quiet suite,零 API)               │
│   2. CET 探测 → 决定栈欺骗路径                               │
│   3. 用户态致盲(HookChain IAT redirect,不碰 ntdll .text)   │
│   4. HWBP patchless AMSI/ETW blind(主)→ byte-patch(fallback)│
│   5. gap pool 扫描(为 LACUNA 六层栈欺骗)                   │
├─────────────────────────────────────────────────────────────┤
│  T1  Beacon 循环(每周期,持续性致盲)                        │
│   1. HookChain IAT 完整性校验(EDR 若重新 hook,重 redirect) │
│   2. AMSI 重盲化(demand-loaded)                             │
│   3. LACUNA 六层栈欺骗(call-driven,CET-aware)               │
│   4. Foliage 睡眠掩码(.text+堆 RC4,spoofed CONTEXT)         │
├─────────────────────────────────────────────────────────────┤
│  T2  敏感操作窗口(注入/横向/凭据,operator 协同)            │
│   1. beacon 通过 C2 信令请求 operator 启动内核时间窗          │
│   2. operator: KslD → ETW-TI deception(IsEnabled 保持 1 +    │
│      伪造事件填充 log-gap)+ CallbackNeutralizer(repurpose,  │
│      DATA 写,HVCI-safe)+ MiniFilter unlink                 │
│   3. beacon 执行操作(Pool Party section-backed,0-of-3)      │
│   4. operator 恢复回调 / 停止伪造                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. 2026-07 SOTA 全景对照表(Nyx 现状 vs 业界 SOTA)

| 检测层 | 2026 SOTA 技术 | Nyx 现状 | Gap | 优先级 |
|---|---|---|---|---|
| **VM/沙箱感知** | CPUID vendor + RDTSC + MAC OUI + SbieDll + SMBIOS | ❌ 零(antidebug.rs 仅 BeingDebugged) | **巨大** | **P0** |
| **用户态 hook 绕过** | **HookChain subsystem-layer IAT redirect**(DEF CON 32,94% EDR 无此层 hook) | 🔶 indirect syscall(NTDLL 层) | **中** | **P1** |
| **栈欺骗** | **LACUNA 六层**(0xVenus 2025)+ **Ghost In The Stack Moonwalking**(BH EU 2025,call-driven,CET-native) | 🔶 BYOUD-Gap 单层 + CET degrade | **中大** | **P2** |
| **注入执行** | **Pool Party section-backed**(0-of-3)+ Dirty Vanity(fork,0-of-3) | ❌ module stomp + threadless HWBP(2-of-3) | **大** | **P3** |
| **ETW-TI 致盲** | **ETW deception**(伪造 IsEnabled=1 + 合成事件,绕 Sanctum 完整性探测) | 🔶 IsEnabled=0(Sanctum 现可探测) | 中 | P4 |
| **内核回调中和** | repurpose(DATA 写,HVCI-safe)+ counter-registration | ✅ repurpose 已有 | 小 | — |
| **AMSI/ETW blind** | HWBP patchless(主) | ✅ 已是主路径 | SOTA | — |
| **睡眠掩码** | Foliage + MemoryBouncing(beat Elastic fluctuation) | 🔶 Foliage 有,MemoryBouncing 缺 | 小中 | P5 |
| **beacon↔operator 协同** | C2 信令时间窗协议 | ❌ 无协议 | **架构** | **P6** |
| **KslD 内核 R/W** | Living-off-Defender(MS 签名,无 blocklist) | ✅ 已有,SOTA | SOTA | — |

---

## 2. P0 — VM/沙箱感知层(最大盲区,零成本关闭)

### 2.1 现状
`grep -r "cpuid\|rdtsc\|qemu\|vmware\|vbox\|hyperv\|MAC.*OUI" crates/implant-win/src/` → **零命中**。`antidebug.rs` 只有 `PEB.BeingDebugged` + `ProcessDebugPort` + `GetTickCount64`(且 `entry.rs:36` 调用 `looks_sandboxed(0)` 实质禁用 uptime 分支)。整个 VM/虚拟态感知层是**零**。

### 2.2 SOTA 依据
- **MITRE T1497.001** — 系统检查是恶意软件 VM 逃避的标准分类
- **Black Hat EU 2020 "My Ticks Don't Lie"** — RDTSC 时序 VM-exit 检测
- **Unit 42 Trap Flag** — 单比特 CPU 差异检测仿真
- **Check Point Evasions DB** — MAC OUI / 注册表 / 进程枚举全集

### 2.3 设计决策:5-check quiet suite(零 API 优先)

**核心洞察(2026 关键):CPUID hypervisor bit + BIOS "Microsoft" + RDTSC 时序在 VBS/HVCI 启用的 Win11 物理机上也会触发**。因此必须:
- **过滤 VM 专有 vendor 字符串**(`VMwareVMware` / `innotek GmbH` / `TCGTCGTCGTCG` / `VBox…`),**绝不**单独依赖 `Microsoft Hv`(VBS 基线)
- **RDTSC 作为佐证,不作为主判**(VBS 下 CPUID 也被 trap)

**Quiet suite 排序(按噪音升序,按 confidence 降序):**

| 级别 | 检查 | API/指令 | 噪音 | FP 风险 |
|---|---|---|---|---|
| 1 | **CPUID vendor 字符串**(leaf 0x40000000) | `CPUID` 单指令,ring-3 合法 | **~0** | 低(过滤 MS) |
| 2 | **SbieDll 模块自检** | `GetModuleHandleA`(kernel32,已在 IAT) | ~0 | 零(仅沙箱) |
| 3 | **RDTSC-CPUID 时序比** | `RDTSC`+`CPUID` 纯指令 | 低 | 中(VBS 干扰) |
| 4 | **SMBIOS firmware 表字符串** | `GetSystemFirmwareTable('RSMB')`(kernel32) | 低 | 中(过滤 MS) |
| 5 | **MAC OUI**(注册表 NetworkAddress,NT-direct,免 IPHLPAPI) | `NtOpenKey`+`NtQueryValueKey`(ntdll) | 低 | 零(VM OUI) |

**新模块:`crates/implant-win/src/envprobe.rs`** — 5 个检查全部 PEB-walk 解析(Check 1/3 纯指令,免 API)。命中任意 VM-专有信号 → beacon 进入 dormant(不退出,不报错,只是降低 beacon 频率到极低,避免沙箱行为分析)。

### 2.4 与 antidebug.rs 的整合
`entry.rs::bootstrap()` 改为调用 `envprobe::looks_like_analysis_env()`(5-check quiet suite)+ 现有 `antidebug::looks_sandboxed(min_uptime)`。**修复 `looks_sandboxed(0)` bug**——改为 `looks_sandboxed(600)`(10 分钟 uptime 阈值)。

---

## 3. P1 — HookChain Subsystem-Layer IAT Redirect(用户态 hook 根治)

### 3.1 现状
Nyx 的 `syscalls.rs` 走 indirect syscall(NTDLL gadget trampoline)。这在 2026 正在 burning:
- **HallWatch**(2024):patch `0xCC` 到每个 Nt* stub 的 `syscall` 字节,VEH 审计
- **Ghost Hunting**(fluxsec 2025):HWBP + DR trap on `syscall` 指令,校验 SSN + 返回地址
- **Elastic shadow-stack comparison**(2025):对比 data-stack walk vs shadow-stack walk

裸 indirect syscall 在这些检测下**返回地址仍在 implant 内存**。

### 3.2 SOTA 依据
**HookChain(DEF CON 32,Helvio Junior)**:
- EDR 只 hook NTDLL(94% EDR 在 subsystem 层 win32u/kernelbase 无 hook,Vectra 引用)
- HookChain **不碰 ntdll .text**,而是改写 **subsystem DLL 的 IAT**(`kernel32.dll`/`kernelbase.dll`/`win32u.dll`/`user32.dll` 的 import 槽指向 ntdll Nt* 的条目)
- 改写后,任何经 subsystem DLL 的调用绕过 EDR 的 ntdll hook,直达攻击者 stub → indirect syscall
- **win32u.dll 是 2026 关键**:`NtUser*`/`NtGdi*` 现走 win32u,不走 ntdll,绝大多数 EDR 对此盲

**机制(精确)**:
1. PEB walk 枚举 `kernel32/kernelbase/win32u/user32/advapi32`
2. 解析每个 PE 的 `IMAGE_DIRECTORY_ENTRY_IMPORT`
3. 定位指向 `ntdll!Nt*` 的 IAT 槽
4. 动态解析 SSN(Hell/Halo/Tartarus,已有)
5. `VirtualProtect` IAT 页 → RW,覆写槽为攻击者 stub 指针,恢复保护
6. stub 做 indirect syscall(已有 trampoline)

### 3.3 设计决策

**新模块:`crates/implant-win/src/hookchain.rs`** + `crates/implant-evasionsdk/src/lib.rs` 新增 `HookChainKit` trait。

- **bootstrap 阶段**:对当前进程的 6 个 subsystem DLL 做 IAT redirect
- **每周期校验**:EDR 若重 hook 并恢复 IAT,重新 redirect
- **与现有 indirect syscall 协同**:HookChain 是"上游",让 EDR hook 成为死代码;indirect syscall 是"下游",让 syscall 指令落在 ntdll。两者叠加 = **用户态 hook EDR 完全致盲**(但仍可见 ETW-TI 内核 provider,见 §6)

**实现要点**:
- IAT 解析复用 `resolve.rs` 的 PE 解析能力(已有 export table 解析,加 import table 解析)
- `VirtualProtect` 走 PEB-walk(kernel32,已加载),不走 indirect syscall(避免递归)
- 与 LACUNA 栈欺骗协同:HookChain redirect 后的调用栈本来就更干净(经 subsystem DLL),LACUNA 再补 leaf-gap 尾

---

## 4. P2 — LACUNA 六层栈欺骗 + Post-CET Moonwalking

### 4.1 现状
Nyx `stack.rs` + `frame.rs` 是**单层 BYOUD-Gap**:gap/ghost/nop 三池,leaf-bridge 合成。`swap.rs::should_execute()` 在 CET-on 时 **pessimistic degrade**(Win11 24H2+ 栈欺骗完全失效)。`stack.rs:40-51` 文档了 Synacktiv SSTIC 2025 lenient-repair seam 但**未实现**。

### 4.2 SOTA 依据
- **LACUNA Chain Ghost Frames**(0xVenus 2025/01):六层 `.pdata` lacunae,声称同时击败 ETW-TI / 内核回调 / CET shadow stack / 返回地址校验
- **Ghost In The Stack**(Magnosi, BH EU 2025):**Moonwalking** = call-driven 合成链(真实 `call` 推 shadow stack),CET-native
- **Synacktiv SSTIC 2025**:`KiControlProtectionFault` lenient-repair seam(`VslKernelShadowStackAssist`)
- **Elastic "Finding Truth in the Shadows"**:shadow-stack comparison 检测——**唯一解法是让 shadow stack 同意 data stack,即 call-driven**

### 4.3 六层升级(自主决策)

| 层 | Nyx 现状 | 升级 | 纯算法/执行层 |
|---|---|---|---|
| 1 leaf gaps | ✅ `gaps` 池 | 保留 | 纯算法(`frame.rs`) |
| 2 ghosts | ✅ `ghosts` 池 | 保留 | 纯算法 |
| 3 NOPs | ✅ `nops` 池 | 保留 | 纯算法 |
| 4 tail-padding | 🔶 混在 gaps | ➕ 显式 `tails` 桶 | 纯算法(`gap.rs`) |
| 5 backed cap | ❌ 模型为 terminal | ➕ `backed` 池 + 真实 `unwind_size` 建模 | 纯算法(`frame.rs`) |
| **6 CET transition** | ❌ degrade | ➕ **call-driven(Moonwalking,首选)+ lenient-seam(fallback)** | **执行层(`stack.rs`)** |

**关键决策:CET transition 走 call-driven(Moonwalking),不走 swap。**
- Naïve `mov rsp` swap 在 CET-on 必 `#CP`(shadow stack 不匹配)
- Moonwalking 用真实 `call` 推 shadow stack → data stack 与 shadow stack 一致 → Elastic comparison 通过
- 这要求在 ntdll/kernelbase 找 `call [rsp+X]`/`jmp [rsp+X]` gadget(已有 gap scan 能力可复用)

**`swap.rs` 决策扩展**:
```rust
pub enum SwapDecision {
    Execute,                              // CET off(现有)
    ExecuteViaMoonwalking(BuildProfile),  // CET on + call-driven(新,首选)
    ExecuteViaLenientSeam(BuildProfile),  // CET on + KiControlProtectionFault(新,fallback)
    Degrade(&'static str),                // 探测失败
}
```

---

## 5. P3 — Pool Party Section-Backed 注入(0-of-3 关联)

### 5.1 现状
`inject.rs` 有 module stomp(全 6 步)+ threadless HWBP。两者在 FND 2-of-3 模型下都命中 **2-of-3**(alloc + write),且 module stomp 的 `CreateRemoteThread(LoadLibraryA)` 触发内核线程回调。

### 5.2 SOTA 依据 + 设计决策

**获胜者(自主选定):Pool Party TP-Worker + section-backed payload + module-stomped callback**

5 轴评分(🟢不可见 / 🔴可见):

| 轴 | module stomp(现) | Pool Party + section(新) |
|---|---|---|
| (a) 线程回调 | 🔴 CreateRemoteThread | 🟢 复用现有 worker 线程 |
| (b) 进程回调 | 🟢 | 🟢 |
| (c) ETW-TI alloc/write | 🔴 VirtualAllocEx+WPM | 🟢 NtCreateSection+MapViewOfSection |
| (d) Moneta/RWX | 🟡 image-backed | 🟢 image-backed(stomp) |
| (e) PE-sieve .text hash | 🔴 mismatch | 🟡(stomp 到非 .text 节缓解) |

Pool Party 唯一残余是 (e),通过 **stomp 到已 mismatch 的模块(EDR 自己 hook 过的)**或**非 .text 可执行节**缓解。

**新模块:**
- `crates/implant-win/src/inject.rs` 增加 `pool_party_inject(pid, shellcode)`(TP_WORK 结构 + worker queue splice)
- `Command::Inject { method, pid, shellcode }` wire tag 26,method=0 Pool Party(默认)/ 1 threadless(W^X 修)/ 2 module stomp(fallback)
- **8 处接线点**(protocol/server/rest/TUI/implant,见早期 §1 设计)

**关键:payload 交付用 `NtCreateSection`+`NtMapViewOfSection`,不走 `VirtualAllocEx`/`WriteProcessMemory`**——这是把 2-of-3 降到 0-of-3 的关键。

---

## 6. P4 — ETW-TI Deception(超越 IsEnabled=0)

### 6.1 现状
`etwti.rs` 写 `ProviderEnableInfo.IsEnabled=0`。`etw_deception.rs` 有事件伪造框架但未完整接线。

### 6.2 SOTA 依据
**Sanctum EDR(fluxsec 全谱研究)**:现代 EDR 探测 EnableInfo **完整性** + 流启发式,不只看 flag 值。`IsEnabled=0` 本身在 2026 已是检测信号。

**Black Hat USA 2025(Olaf Hartong)**:ETW deception 哲学——**不是禁用日志,而是伪造"看起来正常"的事件流**,填 log-gap。

### 6.3 设计决策:从 blind 升级到 deceive
- **operator 侧**:保持 `IsEnabled=1`(不禁用),改用 `EtwDeceiver`(已有 `etw_deception.rs`)+ `EventFrequencyKeeper` 在敏感操作窗口期**注入合成 Process Start/Stop 事件**,匹配 host 基线频率
- 这绕过 Sanctum 的完整性探测(provider 仍"启用")+ 频率异常探测(事件流连续)
- **诚实边界**(代码已标注):伪造事件缺内核 HMAC 签名,对验证会话认证的 EDR(少数)仍可区分——这是固有边界

---

## 7. P5 — MemoryBouncing(beat Elastic fluctuation detector)

### 7.1 现状
`implant-evasionsdk/src/lib.rs:244` 文档了 MemoryBouncing/MemoryHopping(naksyn,明确"beat Elastic fluctuation detector")为 roadmap,未实装。Foliage 的 RC4 .text 掩码会**触发 Elastic 的 fluctuation 信号**(内容变化检测)。

### 7.2 设计决策
实装 `MemoryBouncingKit`(`SleepmaskKit` 新 impl):周期性 **map/unmap** 而非 encrypt/decrypt,让内存区域在 scan 时刻**不存在**(unmapped),而非"存在但加密"。这绕过基于"区域内容变化"的 fluctuation detector。

---

## 8. P6 — Beacon↔Operator 内核协同协议(架构闭环)

### 8.1 现状(最大架构 gap)
`implant-win`(beacon)和 `operator-kernelsdk`(驱动)是**两个独立角色,无 C2 信令通道**。beacon 做注入时无法触发 operator 启用 K3/K4/K5 时间窗——内核侧能力在 beacon 操作中**用不上**。

### 8.2 设计决策:Blindness Window Protocol

**新 protocol 消息(扩展 `protocol/src/msg.rs`):**

| 消息 | 方向 | 用途 |
|---|---|---|
| `RequestBlindWindow { op_token, duration_ms }` | beacon → server → operator | beacon 请求内核致盲时间窗 |
| `BlindWindowActive { op_token, expires_at }` | operator → server → beacon | 窗口已开启,可执行操作 |
| `BlindWindowClosed { op_token }` | operator → server → beacon | 窗口关闭 |

**operator 侧窗口期操作序列:**
1. `EtwTiKit` → deception 模式(保持 IsEnabled=1 + 注入合成事件)
2. `CallbackKit::repurpose()`(DATA 写,HVCI-safe)→ 线程/进程/图像回调 redirect
3. `MiniFilterKit::detach_edr()` → 文件/注册表 minifilter 卸链
4. (可选)`PplKit::attack_edr_ppl()` 若目标 EDR 是 PPL
5. beacon 执行操作(Pool Party,0-of-3)
6. 窗口结束:恢复回调 / 停止伪造 / 重链 minifilter

**这把内核能力从"独立工具"变成"beacon 的力量倍增器"**,真正实现"对内核 telemetry EDR 致盲"。

---

## 9. 实施路线图(优先级排序)

| 阶段 | 内容 | 工作量 | 收益 |
|---|---|---|---|
| **Phase 1** | P0 envprobe.rs(5-check quiet suite)+ 修复 `looks_sandboxed(0)` | S | 关闭最大盲区 |
| **Phase 2** | P1 hookchain.rs(subsystem IAT redirect)+ HookChainKit trait | M | 用户态 hook 根治 |
| **Phase 3** | P3 Pool Party 注入(section-backed)+ inject Command 接线 | M | 注入 0-of-3 |
| **Phase 4** | P2 LACUNA 六层(纯算法层 1-5 先,执行层 6 后) | M-L | post-CET 栈欺骗 |
| **Phase 5** | P6 Blindness Window Protocol(beacon↔operator 协同) | M | 架构闭环 |
| **Phase 6** | P4 ETW deception 完整接线 + P5 MemoryBouncing | S-M | 致盲深化 |

**Phase 1-3 是质变项**——补上后从"各层 SOTA 但没连 + VM 盲区"变成"端到端用户态致盲 + 环境感知"。
**Phase 4-6 是极限项**——post-CET 栈欺骗 + 内核协同,达到 2026 公开研究天花板。

---

## 10. 诚实的能力边界(本蓝图不能突破的)

| 边界 | 原因 | 缓解 |
|---|---|---|
| HVCI-on 下 code-page 写 | EPT 只读,VM-exit → bugcheck | 全部用 DATA 写(repurpose 非 neutralize) |
| CET shadow stack 直接写 | VTL1 保护 | Moonwalking(call-driven)或 lenient-seam,非直接写 |
| ETW-TI 内核 provider 用户态致盲 | 内核态 | 必须 operator 驱动协同(P6) |
| 伪造事件缺 HMAC 签名 | 非固有 | 不可解(需内核签名密钥) |
| KslD.sys 未来被 blocklist | MS 可能 patch | 监控 LOLDrivers 更新,准备 driverless CVE fallback |

---

## 11. 参考来源(全部一手深读)

### 用户态 hook / syscall
- [HookChain — 0xmaz Deep Dive](https://0xmaz.me/posts/HookChain-A-Deep-Dive-into-Advanced-EDR-Bypass-Techniques/)
- [HookChain GitHub(白皮书)](https://github.com/helviojunior/hookchain)
- [Vectra — 94% EDR 无 subsystem hook](https://www.vectra.ai/topics/edr-evasion)
- [fluxsec — Ghost Hunting(检测 indirect syscall)](https://fluxsec.red/edr-syscall-hooking)
- [HallWatch — patch syscall 指令检测](https://radar.offseq.com/threat/hallwatch-usermode-indirect-syscall-detection-b92b44af)
- [xacone — Catching Indirect Syscalls](https://xacone.github.io/mitigate-indirect-syscalls.html)

### 栈欺骗 / CET
- [LACUNA Chain Ghost Frames — 0xmaz](https://0xmaz.me/posts/LACUNA-Chain-Ghost-Frames-defeats-All-EDR-layers-of-call-stack-based-detection/)
- [Ghost In The Stack — BH EU 2025 PDF](http://i.blackhat.com/BH-EU-25/eu-25-Magnosi-Ghost-in-the-stack.pdf)
- [Synacktiv SSTIC 2025 — shadow stack mitigation](https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf)
- [Elastic — Finding Truth in the Shadows(shadow-stack comparison)](https://www.elastic.co/security-labs/finding-truth-in-the-shadows)
- [klezVirus — BYOUD + Moonwalk++](https://klezvirus.github.io/posts/Byoud/)

### 注入
- [FND — CONTEXT-Only Attack Surface(2-of-3 模型)](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)
- [SafeBreach — Pool Party](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)
- [Outflank — Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
- [Deep Instinct — Dirty Vanity](https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass)
- [CCob — ThreadlessInject](https://github.com/CCob/ThreadlessInject)

### 内核 telemetry
- [FND — KslD.sys Weaponizing(2026/04)](https://blog.fndsec.net/2026/04/16/ksld-sys-weaponizing-windows-defenders-own-signed-driver/)
- [S12 — Silencing ETW-TI via BYOVD](https://medium.com/@s12deff/silencing-etw-threat-intelligence-via-byovd-c2ba9e3bb072)
- [Praetorian — ETW-TI + Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)
- [0xDBGMan — EDR Tradecraft](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)

### VM / 沙箱
- [MITRE T1497.001](https://attack.mitre.org/techniques/T1497/001/)
- [Black Hat EU 2020 — My Ticks Don't Lie](https://i.blackhat.com/eu-20/Thursday/eu-20-DElia-My-Ticks-Dont-Lie-New-Timing-Attacks-For-Hypervisor-Detection.pdf)
- [Unit 42 — Trap Flag](https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/)
- [Check Point Evasions DB](https://evasions.checkpoint.com/)

### Sleep mask / 内存
- [Kyle Avery — Avoiding Memory Scanners(HSB 已检测 Foliage)](https://kyleavery.com/posts/avoiding-memory-scanners/)
- [naksyn — Improving Stealthiness(MemoryBouncing beat Elastic)](https://naksyn.com/edr%2520evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html)

---

*文档结束。本文是自主决策的升级蓝图,基于 2026-07 公开研究 SOTA + Nyx 全栈代码审计。下一步:按 §9 路线图,从 Phase 1(envprobe.rs)开始实施。*
