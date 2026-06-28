# Bypass 模块彻底完善 — 设计文档

**日期:** 2026-06-24
**分支:** `p2-evasion-synced`
**范围:** 用户态规避 tier（A）+ 内核 tier（C）全部模块完善
**授权:** 仅限授权红队 / 安全研究用途

> **诚实边界:** 本 macOS 机无法运行 Windows `no_std` 代码，也无法运行内存扫描器。
> 本设计的交付标准是 **(1) 纯算法核心的单元测试在本机全绿 + (2) Windows 外壳通过
> `cargo check --target x86_64-pc-windows-gnu` 交叉编译 + (3) 起草一份 Windows 真机
> 验证执行清单**。任何"已验证的绕过"声明都留待真机执行后做出，本设计不预设。

---

## 0. 决策记录（用户已确认）

| # | 决定 | 选择 |
|---|---|---|
| 1 | 范围 | 用户态(A) + 内核 tier(C) 全做 |
| 2 | 优先级 | 用户态与内核并行，不排序 |
| 3 | 验证深度 | 交叉 check + 单元测试绿 + 起草真机验证清单 |
| 4 | 内核门控 | 拆算法核心 / windows 壳，让 24 个 mock 测试本机可跑 |
| 5 | SleepmaskKit 深度 | 完整 Foliage 10 步 APC→NtContinue 链 |

---

## 1. 现状精确盘点（代码已读完，按模块）

| # | 模块 | 路径 | tier | 算法 | 本机可测 | 缺口 |
|---|---|---|---|---|---|---|
| 1 | PdataGapScanner | `implant-win/src/evasion_glue.rs` | U | ✅ 完整 | ❌ win | ghost/nop 谓词可加固 |
| 2 | StackSpoofKit | `implant-win/src/stack.rs` | U | 🔶 链合成✅/swap 空壳 | 🔶 frame 测得到 | RSP swap（CET-aware） |
| 3 | BlindKit | `implant-win/src/blind.rs` + `evasion_glue.rs` | U | ✅ 4 patch | ❌ win | provider-disable 双保险 |
| 4 | RC4 核心 | `implant-evasionsdk/src/rc4.rs` | U-SDK | ✅ 6 测 | ✅ | 无 |
| 5 | Gap 核心 | `implant-evasionsdk/src/gap.rs` | U-SDK | ✅ 10 测 | ✅ | 无 |
| 6 | Frame 核心 | `implant-evasionsdk/src/frame.rs` | U-SDK | ✅ 8 测 | ✅ | 无 |
| 7 | **SleepmaskKit Foliage** | `implant-win/src/kits.rs`(NoMask) | U | ❌ 空壳 | 🔶 rc4 | **10 步 APC 链（最大缺口）** |
| 8 | ProcessInjectKit | `implant-win/src/inject.rs` | U | 🔶 数据通路/stomp 空壳 | ❌ win | cover-DLL stomp 算法 |
| 9 | MemoryMaskKit | `implant-win/src/mem.rs` | U | ✅ RC4 mask/unmask | ❌ win | 接 `.text` RX↔RW flip |
| 10 | etwti | `operator-kernelsdk/src/etwti.rs` | K | ✅ 6 测 | ❌ 门控 | crate 门控（见 #4） |
| 11 | byovd | `operator-kernelsdk/src/byovd.rs` | K | ✅ 4 测 | ❌ 门控 | 同上 |
| 12 | telemetry | `operator-kernelsdk/src/telemetry.rs` | K | ✅ 4 测 | ❌ 门控 | 同上 |
| 13 | persistence | `operator-kernelsdk/src/persistence.rs` | K | ✅ 4 测 | ❌ 门控 | 同上 |
| 14 | netsec | `operator-kernelsdk/src/netsec.rs` | K | ✅ 3 测 | ❌ 门控 | 同上 |
| 15 | offsets | `operator-kernelsdk/src/offsets.rs` | K | ✅ 3 测 | ❌ 门控 | 同上 |

**测试总数现状:** evasionsdk 24 + evasion 11 + 内核 24 = 59 个已写测试；其中内核 24 个因 crate 顶部 `#![cfg(target_os="windows")]`（`lib.rs:47`）整个 crate 在 macOS 编译成空，全部不可运行。次要障碍：`etwti`/`telemetry`/`persistence` 三模块的 mock 测试用了 `std::collections::BTreeMap` + `std::sync::Mutex`（`byovd`/`netsec`/`offsets` 的测试本就 `alloc`/`core`-only，不依赖 std）。

---

## 2. 三类缺口与对应策略

### 第一类 — "算法已写，本机测不到"（内核 6 模块 + 用户态 win-only）

**根因:** `operator-kernelsdk/src/lib.rs:47` 是 `#![cfg(target_os="windows")]`，整个 crate 在 macOS 编译成空对象。6 个算法模块的 mock 测试中，3 个（`etwti`/`telemetry`/`persistence`）用了 `std::collections::BTreeMap` + `std::sync::Mutex`；另 3 个（`byovd`/`netsec`/`offsets`）本就是 `core`/`alloc`-only。

**策略:** 不重写算法，做两步最小改动：
1. **去掉 crate 顶部门控** — `lib.rs:47` 从 `#![cfg(target_os="windows")]` 改为 `#![cfg_attr(not(test), no_std)]`（与 `evasionsdk` 一致）。trait 定义 + 算法模块本就不依赖 windows API；仅 windows 专属的外壳（真实 syscall/符号绑定，目前还不存在真实代码）留在 `#[cfg(target_os="windows")]` 的 `win/` 下。
2. **3 个测试的 std→alloc** — `std::collections::BTreeMap` → `alloc::collections::BTreeMap`；`std::sync::Mutex` → 用一个 `cfg` 分叉：`#[cfg(test)]` 时测试 harness 有 std 仍可用 std Mutex（因为测试在 host 跑，host 有 std），**或**引入一个 no_std 的 `spin::Mutex`。优先后者以保持 crate 纯 no_std。mock `KernelRw` 已是 `Send+Sync`，`spin::Mutex<BTreeMap>` 满足。

**效果:** 24 个已写的内核 mock 测试在本机 `cargo test` 全绿，无需任何真机，无需改动任何算法逻辑。

### 第二类 — "真正没写的实现"（2 个大缺口）

#### 2a. SleepmaskKit Foliage（最大单项工程）

**现状:** `kits.rs:51` `const SLEEPMASK_KIT: NoMask = NoMask;`，`NoMask::sleep_masked` 只是 `beacon::sleep_seconds`。`rc4.rs` 核心（SystemFunction032 RC4）已就绪。

**做法:** 遵循单一真源——Foliage 的**状态机数学**放进 `implant-evasionsdk/src/foliage.rs`（纯 no_std，可单元测），implant-win 的 `sleep.rs` 只负责喂数据（live syscall/上下文地址）。

**Foliage 10 步链（Kyle Avery 一手资料，纯状态机建模）:**

状态机建模为一个 `FoliagePlan` 结构，描述每一步的 syscall + 参数槽 + 状态转换，**纯数据、可测**：

| 步 | 动作 | syscall | 状态转换 |
|---|---|---|---|
| 1 | 等待事件（保活线程） | `NtCreateEvent`→`NtWaitForSingleObject` | armed |
| 2 | implant 内存 RX→RW | `NtProtectVirtualMemory` | writable |
| 3 | KsecDD 加密 | `NtDeviceIoControlFile(\Device\KsecDD)` | encrypted |
| 4 | 保存原始 context | `NtGetContextThread` | ctx_saved |
| 5 | 设伪造 context | `NtSetContextThread` | ctx_spoofed |
| 6 | 真正睡眠 | `NtDelayExecution`（或 NtWait 单独） | sleeping |
| 7 | KsecDD 解密 | `NtDeviceIoControlFile` | decrypted |
| 8 | 恢复原始 context | `NtSetContextThread` | ctx_restored |
| 9 | implant 内存 RW→RX | `NtProtectVirtualMemory` | executable |
| 10 | 退出新线程 | `NtTerminateThread` | done |

> **注:** `SystemFunction032`（RC4）是步骤 3/7 的等价替代（image-commit，Moneta-clean），优先用它而非 KsecDD ioctl——具体由 `FoliagePlan` 的 `crypto: CryptoMethod::{SystemFunction032, KsecDD}` 选择。APC 编排（`NtQueueApcThread` 排入多个 `NtContinue(ctx)`）同样建模为 `ApcChain` 纯数据结构。

**SDK 纯核心（`foliage.rs`）测试什么:**
- `FoliagePlan::build()` 产出 10 步且步骤顺序正确（保护→加密→ctx→sleep→解密→恢复 的不变量）。
- RC4 round-trip：`mask_region` + `unmask_region` 字节还原（复用 `rc4.rs`）。
- `ApcChain` 合成：给定 context 池，产出有序的 `NtContinue` APC 序列，深度正确。
- Context 伪造：给定目标返回地址（gap 地址），生成的 `CONTEXT` 结构 RIP 指向它。

**implant-win 侧（`sleep.rs`，win-only）:**
- `impl SleepmaskKit for Foliage`，`sleep_masked` 把 `FoliagePlan` 喂给间接 syscall 运行时执行。
- 全部 syscall 走 `syscalls.rs` 间接 stub（不直接 call ntdll）。
- 加密用 `SystemFunction032`，经 `resolve.rs` PEB walk 解析 `advapi32!SystemFunction032`。
- 默认 gated OFF（`FOLIAGE_ENABLED` AtomicBool），selftest/linger 才武装。

#### 2b. StackSpoofKit RSP swap（CET-aware）

**现状:** `stack.rs:259` `with_spoofed_stack` 的 armed 分支是 `f()`（空壳）。frame 合成 + staging 已完整（`stage_for`→`StagedChain`）。

**做法:**
- **运行时 CET 探测**（纯逻辑，放 SDK `swap.rs`）：探测 `KiUserExceptionDispatcher` 是否启用 shadow-stack 修复（Win11 24H2+ opt-in）。CET-on → 降级到 swap-disabled 地板（不崩溃）。CET-off → 执行 RSP 交换。
- **RSP 交换**（win-only，`stack.rs`）：把 staged `StagedChain` 写入假栈区，`mov rsp` 切换，`call f`，`ret` 回来后恢复。通过 inline asm 或手写 PIC stub。
- 默认 gated OFF（`SPOOF_SWAP_ENABLED` 已存在），保持现状不变。

### 第三类 — "半成品需补全"（3 个中等缺口）

#### 3a. BlindKit provider-disable 双保险
在 `blind.rs` 加 `disable_etw_provider(guid)`：userland 写 provider `IsEnabled=0`（经 `EtwpNotificationRegister` 句柄或直接 `NtTraceControl`）。作为字节 patch 的 belt-and-suspenders。win-only。

#### 3b. MemoryMaskKit 接 `.text`
`mem.rs` 当前只 mask 注册的数据区。补 `mask_text()`：`NtProtectVirtualMemory` RX→RW → RC4（复用 `rc4.rs`）→ 翻回。仅在 Foliage 链内部调用（步骤 2/9），不暴露给 beacon 线程同步调用（注释已说明原因）。

#### 3c. ProcessInjectKit cover-DLL stomp
`inject.rs` 的 armed 分支补全算法骨架（LoadLibrary cover DLL → 定位 .text → VirtualProtectEx RWX → WriteProcessMemory → 恢复 → ResumeThread）。**保持 gated OFF**。文档诚实声明：模块 stomping 躲过 Moneta unbacked 检查，但躲不过 PE-sieve `.text` hash-mismatch（真正解是 ThreadlessInject，超出本设计）。

---

## 3. 架构（三层不变）

```
┌──────────────────────────────────────────────────────────────┐
│ 纯算法核心层 (no_std, 本机可测)                                │
│ implant-evasionsdk/  gap✅ frame✅ rc4✅  +NEW: foliage.rs     │
│                                             +NEW: swap.rs     │
│                                             +NEW: apc.rs      │
│ operator-kernelsdk/  去顶部门控 → 6 算法模块本机可测      │
│                       +未来 win/ (cfg win, 专属外壳)        │
└──────────────────────────────────────────────────────────────┘
        ▲ 喂 live bytes/VA                      ▲ 算法 over &dyn KernelRw
┌───────┴──────────────┐  ┌─────────────────────┴──────────────┐
│ implant-win/ (cfg win)│  │ operator-kernelsdk/win/ (cfg win)   │
│  evasion_glue✅ stack  │  │  byovd.rs etwti.rs telemetry.rs     │
│  swap(待填) blind✅     │  │  persistence.rs netsec.rs           │
│  kits(NoMask→Foliage) │  │  (windows 专属符号/syscall 绑定)     │
│  sleep(NEW APC 编排)  │  └────────────────────────────────────┘
│  mem(.text flip)      │
│  inject(stomp gated)  │
└───────────────────────┘
```

**三条不变性:**
1. **单一数学真源** — gap/frame/rc4/foliage/swap 数学只在 SDK 一份；implant-win/kernel 只喂数据，绝不重算。
2. **真机验证分级** — 算法核心=本机单元测试可证；Windows 外壳=交叉 check + 真机清单；内核加载=永远 operator-side。
3. **默认安全** — 所有有破坏性的 swap/stomp/patch 默认 OFF 或 idempotent，beacon loop 行为不因"完善"而改变。

---

## 4. 实现顺序（并行两条线，各自可独立验证）

> 用户要求"不排序"，但实现仍有**依赖拓扑序**（A 必须先于 B 才能编译）。以下按拓扑序排列，每步标注所属线。

### 线 K（内核，先解锁测试基础设施）

| 步 | 内容 | 依赖 | 验证 |
|---|---|---|---|
| K1 | `operator-kernelsdk`: 去掉 crate 顶部 `#![cfg(target_os="windows")]`→`#![cfg_attr(not(test), no_std)]`；3 个测试 `std`→`alloc`/`spin` | — | `cargo test` 在 macOS 跑通 24 测 |
| K2 | 补边界场景测试（HVCI 拒绝、offset 越界、空数组、partial 传输等） | K1 | 测数 → ~35 |
| K3 | `win/` 外壳占位（未来真实 syscall 绑定处）+ 交叉 check | K1 | `cargo check --target gnu` |

### 线 U（用户态，纯核心先行）

| 步 | 内容 | 依赖 | 验证 |
|---|---|---|---|
| U1 | SDK `foliage.rs` 纯状态机 + 单元测试 | rc4✅ | 本机测绿 |
| U2 | SDK `apc.rs` APC 链合成纯模型 + 单元测试 | U1 | 本机测绿 |
| U3 | SDK `swap.rs` CET 决策纯逻辑 + 单元测试 | — | 本机测绿 |
| U4 | `implant-win/sleep.rs` Foliage impl（喂 live syscall） | U1,U2 | 交叉 check |
| U5 | `implant-win/kits.rs` `NoMask`→`Foliage` swap（gated） | U4 | 交叉 check |
| U6 | `implant-win/stack.rs` RSP swap（CET-aware，gated） | U3 | 交叉 check |
| U7 | `implant-win/mem.rs` `.text` mask 接线 | U1 | 交叉 check |
| U8 | `implant-win/blind.rs` provider-disable | — | 交叉 check |
| U9 | `implant-win/inject.rs` stomp 算法骨架（gated） | — | 交叉 check |
| U10 | `evasion_glue.rs` 谓词加固 + trait 接线 | U4-U9 | 交叉 check |

### 收尾

| 步 | 内容 |
|---|---|
| F1 | 起草 Windows 真机验证清单（修订 `run_all_selftests.ps1` + 新增 foliage/swap 自检导出 + `scan_linger.ps1` 增 foliage 场景） |
| F2 | 更新 `docs/WINDOWS_DEV.md` build order 表（标记完成项） |
| F3 | 更新 `docs/p2-integration-analysis.md` 状态 |

---

## 5. 接口设计（关键新增）

### 5.1 SDK 新增模块（`implant-evasionsdk`）

```rust
// foliage.rs — Foliage 10 步链纯状态机
pub enum CryptoMethod { SystemFunction032, KsecDD }
pub struct FoliagePlan { steps: [FoliageStep; 10], crypto: CryptoMethod, key: [u8;16] }
pub enum FoliageStep { Protect{from:u32,to:u32}, Encrypt, GetContext, SetContext{rip:u64}, Sleep{secs:u32}, Decrypt, Terminate }
impl FoliagePlan {
    pub fn build(image_base: usize, image_size: usize, secs: u32, spoof_rip: Option<u64>) -> Self;
    pub fn round_trip_test(plan: &FoliagePlan, buf: &mut [u8]); // mask→unmask 字节还原
}

// apc.rs — APC/timer 链合成
pub struct ApcChain { frames: Vec<ApcFrame> } // 每个 NtContinue(ctx)
impl ApcChain { pub fn build(depth: usize, gaps: &GapPool) -> Self; }

// swap.rs — CET 决策
pub enum SwapDecision { Execute, Degrade(&'static str) }
pub fn decide(cet_on: bool, gaps_usable: bool) -> SwapDecision;
```

### 5.2 内核 crate 重构（`operator-kernelsdk`）

```rust
// lib.rs 顶部: 从 #![cfg(target_os="windows")] 改为:
#![cfg_attr(not(test), no_std)]
extern crate alloc;
// 现有 6 个算法模块原位保留 (etwti/byovd/telemetry/persistence/netsec/offsets),
// 仅把 3 个测试的 std→alloc, crate 即本机可测。未来 windows 专属外壳加在:
#[cfg(target_os="windows")] pub mod win { ... }
// (algo/ 重命名是可选的后续整洁化, 不阻塞测试解锁)
```

### 5.3 implant-win 新增（win-only, cfg）

```rust
// sleep.rs — Foliage 的 syscall 执行器
pub struct FoliageSleepmask { plan: FoliagePlan }  // gated by FOLIAGE_ENABLED
impl crate::kits::SleepmaskKit for FoliageSleepmask { ... }
```

---

## 6. 错误处理与降级

每个新增能力都遵循现有的 `EvasionError` / `KrwError` 降级契约：
- **Foliage** 失败（syscall 不支持/SystemFunction032 不可解析）→ `EvasionError::UnsupportedPosture` → beacon 回退 `NoMask`（行为不变）。
- **RSP swap** CET-on → `decide()` 返回 `Degrade` → 直接 call `f`（行为不变）。
- **内核** HVCI-on 代码页写 → `KrwError::HvciCodePage` → tier 降级到用户态地板。

**核心原则:** 任何规避能力的失败都降级到"无规避"的预存行为，绝不让 beacon 崩溃。

---

## 7. 测试矩阵

| 层 | 模块 | 本机测试 | 交叉 check | 真机（清单，本会话不执行） |
|---|---|---|---|---|
| SDK | foliage.rs | 状态机顺序/round-trip/APC 深度 | — | — |
| SDK | apc.rs | 链合成正确性 | — | — |
| SDK | swap.rs | CET 决策表 | — | — |
| SDK | gap/frame/rc4 | 已有 24 | — | — |
| Kernel algo | 6 模块 | 已有 24 + 新边界 ~11 | — | driver load（operator） |
| implant-win | sleep/kits/stack/mem/blind/inject | — | gnu check | rundll32 selftest |
| implant-win | linger+foliage | — | gnu check | HSB/Moneta/PE-sieve 扫描 |

**本会话验证完成的定义:** ① 所有 SDK + kernel-algo 单元测试在 macOS 全绿（~70 测）；② 所有 implant-win 变更通过 `cargo +nightly check --target x86_64-pc-windows-gnu`；③ 真机验证清单写好并提交。

---

## 8. 不做什么（YAGNI / 越界）

- **不做** ThreadlessInject（PE-sieve `.text` hash 的真正解）—— 标注为 module stomp 的已知上限。
- **不做** EvilEDR repurposing（operator 策略，非 implant kit）。
- **不做** Linux eBPF 模块（Linux v2 agent）。
- **不执行** Windows 真机验证 / driver 加载（不可逆 + 无真机扫描器）。
- **不硬编码** 任何跨 build 的内核 offset / SSN（运行时解析，文档已强调）。

---

## 9. 风险

| 风险 | 缓解 |
|---|---|
| Foliage APC 链交叉 check 通过但真机崩（CONTEXT 布局错） | gated OFF；真机清单含 step-by-step diag 自检 |
| 内核 crate 重构破坏现有 win-only 消费者 | `algo/` API 保持与现有 trait 签名兼容；win/ 壳重新导出 |
| `alloc` mock KernelRw 不满足 `Send+Sync` | 用 `spin::Mutex` 或手写 atomics-backed mock（无 std 依赖） |
| CET 探测逻辑错判导致 `#CP` | `decide()` 默认悲观（不确定时 Degrade） |

---

## 10. 下一步

本设计批准后 → `writing-plans` 技能生成逐步实现计划（含每步的测试断言），再进入实现。
