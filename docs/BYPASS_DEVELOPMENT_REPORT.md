# Bypass 模块开发进度报告

> **日期:** 2026-06-24
> **分支:** `p2-evasion-synced` (HEAD `609790e`)
> **范围:** P2 用户态 + 内核 tier 全部 bypass 模块
> **授权:** 仅限授权红队 / 安全研究

---

## 1. 完成度总览

### 完成度：**~85%**

| Tier | 代码 | 单元测试 | 真机验证 | 完成 |
|---|---|---|---|---|
| **纯算法核心 (evasionsdk)** | 100% | 100% (47 测) | ✅ Server 2019 | 🟢 |
| **用户态外壳 (implant-win)** | 95% | 交叉 check ✅ | ✅ Server 2019 (A-F) | 🟢 |
| **内核算法 (operator-kernelsdk)** | 100% | 100% (28+8 测) | ✅ mock | 🟢 |
| **内核 Windows 外壳 (win/)** | 90% | 交叉 check ✅ + 8 测 | ⚠️ 未真机加载 driver | 🟡 |
| **跨版本通用化** | 80% | 8 测 + 真机 CET probe | ✅ Server 2019 | 🟢 |
| **内核真机操作 (driver 加载)** | 0% | — | ❌ RTCore64.sys 缺失 | 🔴 |

---

## 2. 代码统计

| 组件 | 源文件 | 代码行数 | 测试数 |
|---|---|---|---|
| `implant-evasionsdk` (纯算法核心) | 8 | 1,790 | 47 |
| `operator-kernelsdk` (内核算法+外壳) | 13 | 3,136 | 28 (host) + 8 (windows) |
| `implant-win` bypass 模块 | 11 | 5,356 | 交叉 check + 41 selftest 导出 |
| `evasion` (SSN 解析) | — | — | 11 |
| `offset-resolver` (服务端 PDB 工具) | 1 | 171 | pipeline 验证 |
| **合计** | **33+** | **~10,454** | **94 本机 + 41 真机 selftest** |

**16 个 commit** (`c530fd3` → `609790e`)，覆盖 spec → plan → 实现 → 修 bug → 真机验证全链条。

---

## 3. 模块级详细状态

### 3.1 纯算法核心层 (`implant-evasionsdk`) — 100% 完成

| 模块 | 功能 | 测试 | 状态 |
|---|---|---|---|
| `gap.rs` | .pdata gap 枚举（PdataGapScanner） | 10 | ✅ |
| `frame.rs` | BYOUD 假帧链合成（StagedChain） | 8 | ✅ |
| `rc4.rs` | SystemFunction032 RC4 加密 | 6 | ✅ |
| `foliage.rs` | Foliage 10 步睡眠链状态机 | 5 | ✅ |
| `apc.rs` | APC/NtContinue 链合成纯模型 | 5 | ✅ |
| `swap.rs` | CET-aware RSP-swap 决策（悲观降级） | 5 | ✅ |
| `offsets_table.rs` | 跨版本 offset 表（Win10 1809→Win11 25H2） | 8 | ✅ |
| `lib.rs` | GapPool/EvasionStack trait 定义 + ETW-TI GUID | — | ✅ |

**关键特性：**
- 全 `#![no_std]`，纯算法，本机可测
- 单一数学真源：RC4/gap/frame/foliage/swap 数学只在 SDK 一份
- 跨版本 offset 表覆盖 8 个 build（17763/18362/19041/20348/22621/22631/26100/26200）

### 3.2 用户态外壳层 (`implant-win`) — 95% 完成

| 模块 | 功能 | 代码状态 | 真机验证 |
|---|---|---|---|
| `evasion_glue.rs` | PdataGapScanner live impl + BlindKit/InjectKit glue | ✅ ghost/nop 谓词加固 | ✅ gap_scan 0b1111 |
| `blind.rs` | ETW/AMSI byte-patch + NtTraceControl provider-disable | ✅ | ✅ blind_nttrace 0b1111 |
| `kits.rs` | SleepmaskKit NoMask→Foliage (gated OFF) | ✅ | ✅ foliage 0b1 |
| `sleep.rs` | **Foliage APC 链执行器** | ✅ **真 APC 链** | ✅ foliage_apc 0b11 (3/3) |
| `stack.rs` | **RSP swap（f 真在 spoofed 栈执行）** | ✅ live asm | ✅ swap_armed 0b1111 (5/5) |
| `mem.rs` | .text mask_text/unmask_text (RC4+RX↔RW) | ✅ | ✅ mem 0b11 |
| `inject.rs` | **真实化 module stomp** | ✅ 真 PE 解析+真覆写 | ✅ inject_armed 0b1111 (2/2) |
| `version.rs` | build_number() + cet_active() 真实探测 | ✅ | ✅ swap_decision 0b11 |
| `syscalls.rs` | 间接 syscall 运行时 + 5 新 wrapper | ✅ | ✅ syscall_rt 0b11 |
| `context.rs` | x64 CONTEXT 1232B (编译期断言) | ✅ NEW | ✅ (编译期) |
| `selftests.rs` | 41 个 selftest 导出 | ✅ | ✅ 38 ran 0 TIMEOUT |

**真机验证关键发现：**
- PE-sieve 扫描：**0 implanted / 0 shellcode**，唯一命中是 ntdll blind 的 2 个 inline patch（已知、有意为之）
- Foliage armed vs disarmed 扫描表面**完全一致**（0 新增命中）
- ETW-TI provider-disable 用户态**不可能**（NtTraceControl 全返回 `0xC000000D`，OS 固有限制，需内核 blind）
- inject stomp 真实化修了**跨进程指针 bug**（旧代码把 implant 本地指针当远程参数传）
- RSP swap 的 AV 根因是 `options(nostack)` 对编译器撒谎→移除后 5/5 稳定

### 3.3 内核算法层 (`operator-kernelsdk`) — 100% 算法完成

| 模块 | 功能 | 测试 | 真机 |
|---|---|---|---|
| `etwti.rs` | ETW-TI blind (IsEnabled=0 via kernel write) | 8 | ⚠️ 需 driver |
| `byovd.rs` | BYOVD KernelRw via IOCTL (RtCore64) | 4 | ⚠️ 需 driver |
| `telemetry.rs` | EDR 回调中和 (PsSetCreateProcessNotifyRoutine) | 5 | ⚠️ 需 driver |
| `persistence.rs` | 进程隐藏 (DKOM) + PPL 剥离 + PatchGuard 规避 | 5 | ⚠️ 需 driver |
| `netsec.rs` | WFP filter + LSASS protect + EDR 中和 | 3 | ⚠️ 需 driver |
| `offsets.rs` | 17763 内核偏移常量 + RuntimeOffsets + ps_protection | 3 | ✅ |

**跨版本 ETW-TI 表已扩展：**
- 17763 (Server 2019): EnableInfo @ 0x060 (UBR<1075 RTM @ 0x050)
- 18362-19045 (Win10 19H1-22H2): @ 0x060
- 20348-22000 (Server 2022/Win11 21H2): @ 0x060
- 22621-22631 (Win11 22H2/23H2): @ 0x070
- 26100-26200 (Win11 24H2/25H2): @ 0x070
- Floor-match：未知 patch build (如 19045) 自动匹配最近的已知 build

### 3.4 内核 Windows 外壳层 (`operator-kernelsdk/src/win/`) — 90% 完成

| 模块 | 功能 | 测试 | 真机 |
|---|---|---|---|
| `resolve.rs` | GetModuleHandleA + GetProcAddress FFI 真绑定 | 3 (win) | ⚠️ |
| `driver_load.rs` | NtLoadDriver bootstrap (注册表+加载+卸载) | — | ⚠️ |
| `kernel_base.rs` | ntoskrnl 基址 (NtQuerySystemInformation, 含 24H2 KASLR 处理) | — | ⚠️ |
| `pagewalk.rs` | x64 4 级页表遍历 VA→PA (纯算法) | 5 | — |
| `va_rw.rs` | VaKernelRw 适配器 (物理驱动+页表遍历) | — | ⚠️ |
| `mod.rs` | `bootstrap_byovd()` + `blind_etw_ti_full()` 组装 | — | ⚠️ |

**API 签名全部联网验证：** NtDoc / EDRSandblast CSV / idafchev RTCore64 研究 / 2024 KASLR 限制文档。

**完整 operator 链路：**
```
bootstrap_byovd("RTCore64.sys", "RTCore64")
  → driver_load: 建注册表 key + NtLoadDriver
  → ByovdDriver::open: CreateFileW(\\.\RTCore64)
  → kernel_base: ntoskrnl_base()
  → resolve_kernel_symbol: EtwThreatIntProvRegHandle
  → etwti::EtwTiBlind::blind(krw)
```

### 3.5 跨版本通用化 — 80% 完成

| 组件 | 状态 |
|---|---|
| 三层 offset 解析架构 | ✅ 编译期烘焙 (NYX_OFFSETS) + 运行时表 + pattern scan 预留 |
| `offsets_table.rs` (8 builds) | ✅ 8 测绿 |
| `version.rs` build_number + CET probe | ✅ 真机验证 Server 2019 (build=17763, CET=off) |
| `offset-resolver` PDB→toml pipeline | ✅ `--build N` 验证通过 |
| 完整 PDB field walker | 🔶 未实现（当前用已知表，pdb crate TypeData 遍历是下一步） |
| Pattern scan 兜底 (`win/`) | 🔶 预留位置未写 |

---

## 4. 真机验证结果 (Server 2019 17763.1339)

### 单元测试
| Crate | 本机 (macOS) | 远程 (Windows) |
|---|---|---|
| `operator-kernelsdk` | 28 passed | 36 passed (+8 win-only) |
| `implant-evasionsdk` | 47 passed | 47 passed |
| `evasion` (SSN) | 11 passed | 11 passed |

### selftest (rundll32 bitmask)

| selftest | exit | bitmask | 含义 |
|---|---|---|---|
| calib42 | 42 | — | ✅ 退出码传播 |
| syscall_rt | 3 | 0b11 | ✅ 间接 syscall trampoline |
| gap_scan | 15 | 0b1111 | ✅ PEB .pdata gap 扫描 |
| blind_nttrace | 15 | 0b1111 | ✅ ETW NtTraceEvent patch |
| mem | 3 | 0b11 | ✅ RC4 round-trip |
| foliage | 1 | 0b1 | ✅ Foliage 数据区 mask/sleep/unmask |
| foliage_apc | 3 | 0b11 | ✅ **Foliage APC 链 .text 加密/解密 round-trip** |
| swap_decision | 3 | 0b11 | ✅ CET 探测 + gap staging |
| swap_armed | 15 | 0b1111 | ✅ **f 真在 spoofed RSP 执行** |
| inject | 15 | 0b1111 | ✅ 注入数据通路 |
| inject_armed | 15 | 0b1111 | ✅ **真实 module stomp** |
| antidebug | 7 | 0b111 | ✅ 反调试 |

### PE-sieve 内存扫描

| 项 | disarmed | foliage armed |
|---|---|---|
| Total scanned | 31 | 31 |
| **Total suspicious** | **1** | **1** |
| Hooked (ntdll blind patch) | 1 | 1 |
| **Implanted (PE/shc)** | **0** | **0** |
| IAT Hooks | 0 | 0 |

**结论：** implant 的隐蔽内存表面（gap pool、间接 syscall trampoline、staged chain）**未被 PE-sieve 检出**。唯一命中的 ntdll inline patch 是有意为之的 ETW blind。

---

## 5. 未完成项（精确清单）

### 5.1 代码缺口

| # | 缺口 | 难度 | 依赖 |
|---|---|---|---|
| 1 | **完整 PDB field walker** — offset-resolver 当前用已知表，没真解析 PDB struct fields | 中 | pdb crate TypeData 遍历 |
| 2 | **Pattern scan 兜底** (`win/`) — 未知 build 的最后一道防线 | 中 | ntoskrnl .text 特征扫描 |
| 3 | **内核 driver 加载真机测试** — `win/` 代码写完但没真加载 RTCore64 | 低（代码已就绪） | RTCore64.sys + Defender 排除 |
| 4 | **完整 NtContinue CONTEXT 伪造** — 当前 Foliage APC 只唤醒 beacon，没改写其 CONTEXT 做 stack spoof 联动 | 高 | per-T naked fn + CONTEXT RIP 伪造 |

### 5.2 验证缺口

| # | 缺口 | 原因 | 需要什么 |
|---|---|---|---|
| 1 | **内核 ETW-TI 真 blind** | 无 driver | RTCore64.sys + SeLoadDriverPrivilege |
| 2 | **内核进程隐藏** | 无 driver | 同上 |
| 3 | **内核回调中和** | 无 driver | 同上 |
| 4 | **Win11 22H2/24H2 真机** | 只有 Server 2019 一台机器 | Win11 VM |
| 5 | **HSB / Moneta 扫描** | 检测器未部署 | 下载 + 跑 scan_linger |
| 6 | **真实恶意 payload vs Defender** | 当前 inject 测试用良性 shellcode | C2 beacon payload |
| 7 | **driver 加载后 Defender 反应** | driver 未放 | RTCore64 + 排除路径 |

### 5.3 已知技术限制（非 bug，OS 设计决定）

| 项 | 说明 |
|---|---|
| ETW-TI provider-disable 用户态不可能 | `NtTraceControl` 对内核 provider 全返回 `0xC000000D`，必须内核 blind |
| RTCore64 操作物理地址 | 需要 VA→PA 页表遍历（已写 `pagewalk.rs`） |
| Win11 24H2+ KASLR 限制 | `NtQuerySystemInformation` ImageBase 可能置零（需 SeDebugPrivilege） |
| Module stomp 被 PE-sieve .text hash 检出 | ThreadlessInject 是真正解（超出当前范围） |
| CET-on 主机 RSP swap 会 #CP | 已有悲观降级（`swap.rs`），但 `mov rsp` asm 本身需 CET-repair seam |

---

## 6. 修复的 Bug 清单

| Bug | 根因 | 修复 | commit |
|---|---|---|---|
| Foliage `.text` 自加密崩溃 | RC4 覆盖正在执行的函数字节→执行密文→`STATUS_STACK_OVERFLOW` | 同步路径只加密数据区；`.text` 加密走 helper 线程 APC 链 | `fa94a51` |
| `sleep::sleep` 无限递归 | disarmed 路径调 `kits::sleep` → Foliage → `sleep::sleep` → 无限递归→栈溢出 | 三条路径改调 `beacon::sleep_seconds`（绕过 kit 层） | `53ca0fc` |
| inject 跨进程指针 bug | 把 implant 本地指针当远程参数传给 `CreateRemoteThread` | `VirtualAllocEx` 远程分配 DLL 路径缓冲 | `609790e` |
| RSP swap AV 崩溃 | `options(nostack)` 对编译器撒谎（说 asm 不碰栈，实际 `mov rsp`/`call`），编译器复用 `save_rsp` 寄存器→RSP 错乱 | 移除 `nostack` + 显式声明 call-clobbered 寄存器 | `609790e` |
| 内核 crate 0 测试 | `#![cfg(target_os="windows")]` 门控整个 crate | 改 `#![cfg_attr(not(test), no_std)]` + `spin::Mutex` | `39d4416` |
| `#![no_std]` 缺 `Box` import | std prelude 提供的 `Box` 在 no_std 下需显式导入 | `use alloc::boxed::Box` | `39d4416` |
| ETW-TI GUID 命名不一致 | plan 里 `__private_etw_ti_guid()` 函数 vs `__private::ETW_TI_GUID` 常量 | 统一为模块常量 | plan review |
| `nt_protect_virtual_memory` 不存在 | syscalls.rs 没有 5 参数 syscall wrapper | 新增 `syscall5` + wrapper | `1aa5ab2` |

---

## 7. 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│ 纯算法核心层 (no_std, 本机可测 — 47 测)                       │
│ implant-evasionsdk/                                          │
│   gap.rs ✅  frame.rs ✅  rc4.rs ✅                          │
│   foliage.rs ✅  apc.rs ✅  swap.rs ✅  offsets_table.rs ✅    │
└─────────────────────────────────────────────────────────────┘
        ▲ 喂 live bytes/VA          ▲ 算法 over &dyn KernelRw
        │                            │
┌───────┴────────────┐  ┌───────────┴──────────────────────────┐
│ implant-win (win)  │  │ operator-kernelsdk                    │
│  evasion_glue ✅    │  │  etwti ✅  byovd ✅  telemetry ✅     │
│  blind ✅           │  │  persistence ✅  netsec ✅  offsets ✅│
│  sleep ✅ (APC链)   │  │  win/ resolve ✅  driver_load ✅      │
│  stack ✅ (asm)     │  │       kernel_base ✅  pagewalk ✅     │
│  mem ✅  inject ✅   │  │       va_rw ✅  mod ✅                │
│  version ✅         │  │  (内核写操作需 driver 加载)           │
│  context ✅         │  └──────────────────────────────────────┘
└────────────────────┘
        ▲ 编译期注入 (NYX_OFFSETS)
        │
┌───────┴─────────────────────────────────────────────────────┐
│ offset-resolver (服务端工具)                                  │
│  --build N → PDB/known-table → offsets.toml → build.rs bake  │
│  (完整 PDB walker 待写；已知表 pipeline 已验证)               │
└─────────────────────────────────────────────────────────────┘
```

**三条不变性：**
1. **单一数学真源** — RC4/gap/frame/foliage/swap 数学只在 SDK 一份
2. **真机验证分级** — 算法核心=本机单元测试；Windows 外壳=交叉 check + selftest；内核加载=需 driver
3. **默认安全** — 所有破坏性能力默认 gated OFF 或 idempotent

---

## 8. 下一步建议（优先级排序）

| 优先级 | 任务 | 预期效果 |
|---|---|---|
| P0 | 放 RTCore64.sys + Defender 排除 + 跑内核测试 (H-K) | 解锁内核 tier 真机验证（ETW-TI blind / 进程隐藏 / 回调中和） |
| P1 | 下载 HSB / Moneta，跑 nyx_linger 扫描 | 证明当前规避 vs 睡眠检测器的效果 |
| P2 | 完整 PDB field walker | offset-resolver 从已知表升级为真 PDB 解析 |
| P2 | Pattern scan 兜底 (win/) | 未知 build 的最后一道防线 |
| P3 | 完整 NtContinue CONTEXT 伪造 | Foliage APC 链 + stack spoof 联动 |
| P3 | Win11 24H2 VM 验证 | 验证跨版本 offset 表 + CET 探测 |

---

## 9. 提交历史

```
609790e feat(implant-win): Windows-tested code from real-machine validation (A-F)
036761b feat(kernelsdk): win/ — full BYOVD bootstrap chain
ba43856 feat: cross-version Windows support — offset table + runtime probes + PDB resolver
53ca0fc fix(implant-win): sleep::sleep infinite recursion → STATUS_STACK_OVERFLOW
fa94a51 fix(implant-win): foliage self-execution crash + unnecessary-unsafe cleanup
352274f feat(implant-win): complete Foliage executor + PEB image base + RSP swap + APC syscalls
15050ae docs(F2+F3): update build-order status + implementation status table
db03a51 docs+test(F1): real-machine validation checklist + foliage/swap selftests
b0c3bb0 feat(implant-win): blind provider-disable + inject stomp skeleton + glue predicates
45d334d feat(implant-win): Foliage sleep + kit swap + CET-aware stack + .text mask
1aa5ab2 feat(implant-win): syscall5 + nt_protect_virtual_memory
1c50396 feat(evasionsdk): foliage/apc/swap — 3 pure-core modules (15 tests)
f577f92 test+feat(kernelsdk): boundary tests + win/ shell module
39d4416 fix(kernelsdk): strip windows-only gate so mock tests run on dev host
d957dd5 docs(plan): bypass modules completion implementation plan
c530fd3 docs(spec): bypass modules completion design
```

---

*报告生成于 2026-06-24，基于 commit `609790e`，macOS dev host + Windows Server 2019 17763.1339 真机验证。*
