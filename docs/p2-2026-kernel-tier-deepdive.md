# P2 — 内核态 Tier 深度情报 + Rust Kit 接口设计（2026-06-23）

> 12 组内核专项 Exa 检索 + 主源核实。**仅记录内核 tier 的真正增量**（已对 H2 sweep / 根语料 / survey 去重）。授权红队研究。
> 解决的核心问题：**如何在 HVCI/PatchGuard/KDP/PPL/CET 全家桶下拿到并使用内核 R/W 原语，且噪声可控**。
> 配套接缝代码：`crates/operator-kernelsdk/src/lib.rs`（trait + no-op 默认，standalone crate，不影响 workspace）。

---

## 0. 内核 bootstrap 问题——5 条路，按噪声排序（★ 已重排）

之前内核 tier 卡在"BYOVD 太老太吵"。本轮发现**至少 4 条更优路径**，BYOVD 降为 fallback：

| 排名 | 路径 | 噪声 | HVCI 兼容 | 现状 | 备注 |
|---|---|---|---|---|---|
| **1** | **Living off the Defender — KslD.sys**（武器化目标自己的 Defender 签名驱动） | **极低**（用目标自带组件，无新驱动加载） | ✅ | **PoC 公开**（KslDump/KslKatz/KslKatzBof 2026-03/04） | ★ 最佳：不触发 Sysmon EID 6，不受 blocklist 影响 |
| 2 | **Driverless CVE**（CVE-2026-40369 等） | 低 | ✅ | **完整 exploit 公开**（orinimron123 2026-05） | 12 字节浏览器沙箱逃逸→内核增量→SYSTEM；目标未打 2026-05 补丁时 |
| 3 | **DMA / PCILeech**（PCIe FPGA） | 极低 | ✅ | 成熟（ufrisk/pcileech + FWGenerator） | 需物理硬件，不普适但最隐蔽 |
| 4 | **运行时 PatchGuard bypass**（kurasagi/TheiaPg） | 中 | ✅ | PoC 公开（Win11 24H2-25H2，263★） | 拿到 PG 绕过后可做 inline 操作（HVCI 仍限代码节） |
| 5 | **BYOVD**（LOLDrivers 当前未封锁项） | 中（Sysmon EID 6 可见） | ✅（数据节） | 工业化（GentleKiller 478 受害者） | Fallback；驱动选型见 §5 |

→ **P2.2 内核 bootstrap 默认路径应改为 KslD.sys（Living off the Defender），而非 BYOVD。**

---

## 1. 内核 R/W 原语获取（一切的基础）

### 1.1 ★ KslD.sys — 武器化 Defender 自己的签名驱动（fndsec 2026-04）
- **机制：** Windows Defender 自带的签名驱动 `KslD.sys` 暴露内核 IOCTL 接口，可被滥用于内核 R/W + 提权。"Why bring your own knife when Defender already left one."
- **衍生工具链：** `andreisss/KslDump`（加载器）→ `vergamota/KslKatz`（KslDump + GhostKatz dump LSASS）→ `PrincipleCheck/KslKatzBof`（69★，BOF）→ `Muz1K1zuM/kslkatz_bof`（Havoc C2 BOF port）。
- **检测：** `detect.fyi` "Ghost in LSASS: Detecting KslKatz"（2026-03）—— 但用目标自带组件，无新驱动加载事件。
- **Nyx 落点：** `KernelRw` trait 的 `LivingOffDefender` impl；**P2.2 默认 bootstrap**。

### 1.2 ★ Driverless — CVE-2026-40369（完整 exploit 已公开）
- **机制：** `NtQuerySystemInformation`/`ExpGetProcessInformation` 的 `ProbeForWrite` 校验绕过 → **任意内核内存增量原语** → 破坏内核结构 → 劫持执行 → KASLR 绕过 → SYSTEM。VoidSec："Twelve Bytes to Escape the Browser Sandbox"。
- **PoC：** `orinimron123/CVE-2026-40369-EXPLOIT`（2026-05-13，完整代码）；Positive Technologies `PT-2026-40204`；Mallory/Threadlinqs/BestHub 多处分析。
- **窗口：** 目标未打 2026-05 Patch Tuesday 时可用；企业补丁延迟 3-6 月。
- **Nyx 落点：** `KernelRw` 的 `DriverlessCve` impl（browser-sandbox-entry 场景）。

### 1.3 ★ CR3-based IOCTL 原语（WinNotify, exploitpack 2026-06）
- **机制：** 一类驱动接受 **CR3（页表/地址空间上下文）作为 IOCTL 参数** → 攻击者切换地址空间上下文做任意内核 R/W。全新原语类，不依赖特定漏洞。
- **Nyx 落点：** `KernelRw` 的 `Cr3Ioctl` impl——扫 LOLDrivers 里"接受 CR3 的 IOCTL"的驱动。

### 1.4 DMA / PCILeech（ufrisk/pcileech）
- PCIe FPGA 硬件直接 DMA 内核内存（读写原语）。`VoltCyclone/PCILeechFWGenerator`（自动生成定制固件）+ `VimRev/dma-lab`（FPGA 配置）。
- 不普适（需硬件），但**对软件防御完全不可见**（无驱动、无 syscall、无 ETW）。

### 1.5 BYOVD + LOLDrivers（fallback，详见 §5）
- 运行时内核 R/W；HVCI 兼容（数据节）。当前未封锁驱动见 §5 目录。

### 1.6 辅助：`piffd0s/ntoskrnl-metadata`（2026-05）——EPROCESS 等结构成员偏移跨版本提取器；`arXiv:2606.07732` Windows IOCTL Census（语料级多架构 IOCTL 数据库，找可滥用 IOCTL 的研究基建）。

---

## 2. 内核遥测中和（拿到 R/W 之后做什么）

### 2.1 ETW-TI 盲化（S12，已确认）
单次 QWORD 写：`nt!EtwThreatIntProvRegHandle → _ETW_REG_ENTRY +0x020 → _ETW_GUID_ENTRY +0x060 ProviderEnableInfo +0x000 IsEnabled=0`。运行时解析偏移（`bordergate.co.uk` 2026-03 给了结构明细）。HVCI 兼容。

### 2.2 内核回调移除/复用（CallbackKit）
- **数组位置：** `PspCreateProcessNotifyRoutine`（64 槽）/`PspCreateThreadNotifyRoutine`/`PspLoadImageNotifyRoutine`/`CmpCallBackVector`；ObCallbacks 双向链表。
- **正确做法：** **不 NULL**（PatchGuard 查 NULL→bugcheck），覆写为 **KCFG-compliant `ret`-only stub**（`V-i-x-x/kernel-callback-removal` 222★ 参考实现）。
- **★ 回调"复用" > 移除：** 不删回调，而是把它指向一个合法-looking 的例程，让回调照常被调用但 no-op（或转发给攻击者）。data-only、PG 不触发。
- **Win32k 回调劫持**（n0qword 2026-04）：滥用 `win32k.sys` 内核→用户回调分发（`KernelCallbackTable`）做跨进程代码执行（threadless-flavored 注入向量）。
- **ObCallbacks**（patchi.fyi "Peregrine" 2025-12）：EDR 用 ObRegisterCallbacks 剥 7 项危险句柄权限（PROCESS_VM_READ/WRITE…）；Peregrine 工具可枚举这些回调。

### 2.3 MiniFilter 断链
`FltGlobals` 双向链表摘除 EDR 节点（Flink/Blink）。**绕过 kCFG**（kCFG 保护派发表不保护链表）。HVCI 兼容。

### 2.4 WFP（两条路）
- 用户态 `EDRSilencer`（`FwpmFilterAdd0`，仅 admin，无驱动）——但留 Event ID 5447 + packet-block/drop 痕迹。
- 内核 WFP Callout 函数指针覆写为 ret-stub。
- **★ 第三条路（本轮新）：EDRChoker QoS 饥饿**（见 H2 sweep §A1）——pacer.sys 在 WFP 之下，8 bit/s 限速，无 WFP 痕迹，**噪声最低**。

### 2.5 EDR 进程中和（Kill/Freeze/Choke）
- **Kill：** BYOVD `ZwTerminateProcess`（内核态绕 PPL）。
- **Freeze：** WerFaultSecure + MiniDumpWriteDump coma（用户态，绕 PPL，admin）。
- **Choke：** EDRChoker QoS（用户态，admin，噪声最低）。
- **PoisonX BYOVD**（xcitium 2026-04）：逆向 0-day 驱动 IOCTL handler **专门绕 CrowdStrike Falcon** 的示例。

---

## 3. 内核持久化 / 保护（PG / DKOM / PPL / KDP）

### 3.1 ★ 运行时 PatchGuard 绕过（新，已公开）
- `NeoMaster831/kurasagi`（263★，Win11 24H2-25H2 Runtime PG Bypass）+ `quokka867/TheiaPg`（Win11 25H2）。
- **意义：** 之前只能靠 Outflank Peekaboo"数据节 + 时序修复"；现在有**运行时 PG 绕过**替代，操作空间更大（仍受 HVCI 代码节限制）。
- **PG 内部：** `r0keb/PatchGuard-Internals`（2025-05）。

### 3.2 Outflank Peekaboo（时序修复，语料已有）
`EPROCESS.ActiveProcessLinks` 断链 + `PsSetCreateProcessNotifyRoutineEx` 终止回调中、`PspProcessDelete` 校验前 repair。HVCI+PG 兼容的唯一持久进程隐藏。`gm7.org`/`gbhackers`(2026) + `troutvirusstaro/DKOM-2026`/`Gasu16/HideProcessDKOM` PoC。

### 3.3 ★ PPL 武器化（S12 2026-02，三篇）
- **"Weaponizing PPL for Process Immortality"**——反向：让**攻击者自己的进程**变 PPL 保护（不被杀/不被 dump）。
- **PPLReaper**（`S12cybersecurity`，unsigned kernel driver + userland）——攻击 PPL 进程。
- **"Demonstrating Defender Evasion via PPL Manipulation"**。
- **9 种 RunAsPPL=1 下 dump LSASS**（adscanpro 2026-05，含 WerFaultSecure 路径）。

### 3.4 ★ KDP（Kernel Data Protection）绕过已演示
- `sit-cybersecurity` "Goodbye Secure Pool, Hello KDP Pool"（2026-04）；KDP 用 VTL1 保护 ntoskrnl .data 段 + 安全池。
- **zer0mat "Whoops! I did it again — patched Windows Kernel at Milan0day 2026"**——KDP 保护段被 patch 的演示。KDP 不再是硬墙。

### 3.5 Secure Kernel / VSM / SkBridge（Connor McGarr 2025-09）
- **Secure Calls**：NT kernel ↔ Secure Kernel 的桥接机制。`connormcgarr/SkBridge`——从 VTL0 发 VSM secure calls 到 VTL1 的 harness（研究 SKPG/VTL1 边界）。`Vtl1Mon` 监控 VTL1。
- **SKPG（Secure Kernel PG）**：VTL1 运行，对 VTL0 数据操纵有额外保护——**仍 largely unexplored**（诚实：这是当前最深的天花板）。

### 3.6 Hyper-V 逃逸（语料 + CVE 实化）
CVE-2026-45607 / CVE-2026-32149（Hyper-V RCE，guest→host）；NDSS'26 "Breaking Isolation: Hypervisor Cross-Domain Attacks"。坐实 M-Trends hypervisor 趋势。

---

## 4. 内核态凭据访问

- **KslKatz / KslKatzBof**（§1.1）——用 KslD.sys 内核 R/W 直接读 LSASS 内存（绕 RunAsPPL + Credential Guard）。
- **KernelKatz**（OST）——内核直读 lsass.exe 内核内存。
- **检测：** `detect.fyi` KslKatz 检测框架（LSASS 异常访问模式）。
- **Nyx 落点：** `CredKit` trait——`hashdump.rs` 的内核态升级（当前 hashdump 是用户态 SAM hive）。

---

## 5. 当前可用漏洞驱动目录（2026 LOLDrivers，含原语）

| 驱动 | 来源 | 原语 | blocklist 态势 |
|---|---|---|---|
| **KslD.sys** | Windows Defender 自带 | 内核 R/W（Living off the Defender） | **永不上榜**（MS 自带） |
| **wsftprm.sys** | RedSun 引用 | 内核 R/W（未确认细节） | 未封锁（2026-04） |
| **shield.sys** | Horizon DataSys（`#344` 2026-05） | 任意内核 R/W，3 变体 | 法证类，~30-40% 覆盖 |
| **TRIXX.sys** | TechPowerUp（`#291`） | MmMapIoSpace 物理内存 R/W + PCI 配置 + 端口 I/O | 硬件工具类，40-60% |
| **TcIo.sys + TcRouter.sys** | Beckhoff TwinCAT 3（`#296`） | PhysMem R/W + PCI + 端口 I/O | **工业/SCADA <10%（蓝海）** |
| PoisonX | 0-day（xcitium 2026-04） | IOCTL handler 绕 CrowdStrike | n/a |
| CVE-2026-0828 | Safetica（`0xKern3lCrush` 2026-02） | EDR 驱动 IOCTL 弱点 | n/a |

**选型原则：** 工业/SCADA 驱动覆盖率最低（蓝海）；优先 KslD.sys（目标自带）> 工业驱动 > 硬件工具 > 法证 > 反作弊（已 90%+ 封锁）。`THN` "Making Vulnerable Drivers Exploitable Without Hardware"（2026-05）= 无需专用硬件的武器化路径。

---

## 6. 防御方内核枚举（Peregrine）——告诉我们内核 implant **不能长什么样**

`patchi.fyi/Peregrine`（2025-12）：枚举 **ObCallbacks** + 扫驱动黑名单 + 查 HVCI/test-signing/hypervisor 存在性。→ 内核 tier 必须避开：被 blacklist 的驱动、可枚举的 ObCallback 异常、test-signing/HVCI-off 痕迹。

---

## 7. ★ Rust Kit 接口设计（为后续开发留接缝）

> 全部 operator-side（PIC implant 不能承载内核驱动）。standalone crate `crates/operator-kernelsdk/`（自己的空 `[workspace]`，不影响主 workspace，仿 `implant-win` 模式）。每个 kit = trait + no-op 默认，换 impl 不动调用点。

```rust
//! crates/operator-kernelsdk — 内核 tier operator 工具的 kit 接缝（P2.2+）。
//! standalone crate（非 workspace 成员），仅定义 trait + no-op 默认；
//! 真实实现（BYOVD/KslD/DMA/CVE）后续作为 impl 落地，不动 trait。
#![cfg(target_os = "windows")]

/// §1 — 内核 R/W 原语。一切内核 tier 的基础。
/// impl: ByovdDriver / DmaPciLeech / DriverlessCve(2026-40369) / LivingOffDefender(KslD) / Cr3Ioctl
pub trait KernelRw: Send + Sync {
    /// 读任意内核虚拟地址。运行时解析偏移，绝不硬编码。
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError>;
    /// 写任意内核虚拟地址（数据节；HVCI 下代码节会 VM-exit）。
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError>;
    /// 便捷：读一个 KERNEL_STRUCT 成员（偏移由 ntoskrnl-metadata 运行时解析）。
    fn kread_u64(&self, kaddr: usize) -> Result<u64, KrwError> { /* default via kread */ }
}

/// §2.1 — ETW-TI 盲化。单次 QWORD 写 ProviderEnableInfo.IsEnabled=0。
/// impl: S12Byovd / DriverlessCveBootstrap
pub trait EtwTiKit {
    /// 运行时 chase: nt!EtwThreatIntProvRegHandle → +0x020 → +0x060 → IsEnabled=0
    fn blind(&self, krw: &dyn KernelRw) -> Result<(), KitError>;
    /// 可选：检测自身被盲化（ProviderEnableInfo 完整性，Sanctum/Peregrine 会查）
    fn is_blinded(&self, krw: &dyn KernelRw) -> Result<bool, KitError>;
}

/// §2.2 — 内核回调 Ps/Ob/Cm。覆写为 KCFG-ret stub（不 NULL，否则 PG bugcheck）。
pub trait CallbackKit {
    /// enumerate → 对每个 EDR 回调覆写 ret-stub（data-only，PG/kCFG 兼容）
    fn neutralize(&self, krw: &dyn KernelRw) -> Result<usize, KitError>;
    /// 回调"复用"变体：指向攻击者例程而非 ret-stub（更隐蔽）
    fn repurpose(&self, krw: &dyn KernelRw, redirect: usize) -> Result<(), KitError>;
}

/// §2.3 — MiniFilter 断链（FltGlobals，绕 kCFG）。
pub trait MiniFilterKit { fn detach_edr(&self, krw: &dyn KernelRw) -> Result<(), KitError>; }

/// §2.4 — WFP。两条 impl：UserModeEdrSilencer(无驱动) / KernelCalloutOverwrite。
pub trait WfpKit { fn silence_edr(&self, edr_pids: &[u32]) -> Result<(), KitError>; }

/// §3.1/3.2 — PatchGuard 兼容。两条 impl：RuntimePgBypass(kurasagi) / OutflankTimingRepair。
pub trait PatchGuardKit {
    fn enter_unchecked(&self, krw: &dyn KernelRw) -> Result<PgGuard, KitError>;
}
pub struct PgGuard; impl Drop for PgGuard { fn drop(&mut self){ /* repair / re-arm */ } }

/// §3.2 — 进程隐藏（EPROCESS 断链 + PG guard）。
pub trait ProcHideKit { fn hide(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError>; }

/// §3.3 — PPL。双向：攻击 EDR PPL / 让自己变 PPL(Immortal)。
pub trait PplKit {
    fn attack_edr_ppl(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError>;
    fn make_immortal(&self, pid: u32) -> Result<(), KitError>;
}

/// §2.5 — EDR 进程中和（Kill/Freeze/Choke）。
pub enum NeutralizeMethod { Kill /*ZwTerminate*/, Freeze /*WerFaultSecure*/, Choke /*EDRChoker QoS*/ }
pub trait EdrNeutralizeKit {
    fn neutralize(&self, pid: u32, m: NeutralizeMethod) -> Result<(), KitError>;
}

/// §4 — 内核态凭据（LSASS 直读，绕 RunAsPPL + CredGuard）。
pub trait CredKit { fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError>; }

/// 组装一个 engagement 的内核 tier。trait 对象 + 运行时选 impl。
pub struct KernelTier {
    pub rw: Box<dyn KernelRw>,
    pub etw_ti: Option<Box<dyn EtwTiKit>>,
    pub callbacks: Option<Box<dyn CallbackKit>>,
    pub minifilter: Option<Box<dyn MiniFilterKit>>,
    pub wfp: Option<Box<dyn WfpKit>>,
    pub pg: Option<Box<dyn PatchGuardKit>>,
    pub hide: Option<Box<dyn ProcHideKit>>,
    pub ppl: Option<Box<dyn PplKit>>,
    pub cred: Option<Box<dyn CredKit>>,
}
```

**接缝契约（与 `kits.rs` 同哲学）：** 每个 trait = 一个可替换实现点；beacon/postex/operator CLI 通过 trait 对象调用，换实现不改调用点。`KernelTier` 在 operator 选定 bootstrap 路径（KslD/CVE/DMA/BYOVD）后，运行时装配。**HVCI 降级策略：** `KernelRw` 的 impl 在 HVCI-on 时只做数据节操作，代码节操作返回 `KrwError::HvciCodePage`，operator 自动降级到用户态 floor。

---

## 8. 诚实天花板 + 2026-08 展望

- **SKPG（VTL1 PatchGuard）** 仍 largely unexplored——最深天花板，SkBridge 只到研究阶段。
- **遥测消失检测 / NDR 行为建模** 不可消除（只能降置信）。
- **2026-08 BH/DC：** BTR 驱动细节 + 可能的新内核 LotLK + 新 ntoskrnl LPE。
- **本轮把"内核 tier 可落地性"从 ⚠️ 提升到 ✅-ish**：bootstrap 不再卡在 BYOVD（KslD/driverless CVE/CR3-IOCTL/运行时 PG 多路），且每路都有公开 PoC。
