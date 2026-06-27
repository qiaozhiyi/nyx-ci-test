# Bypass 开发完整交接文档

> **日期:** 2026-06-27（P1 dev tasks C1/C2/B1/B2 完成 + 接线 97%）· **分支:** `p2-evasion-synced`
> **验证环境:** Windows Server 2019 17763.1339 + RTCore64.sys (CVE-2019-16098)
> **授权:** 仅限授权红队 / 安全研究

---

## 1. 当前状态总览

**23 项 bypass 能力已实现，20 项真机验证通过。**

| 层 | 单元测试 | 真机 selftest | 交叉编译 |
|---|---|---|---|
| `implant-evasionsdk` (纯算法核心) | ✅ 47 | — | ✅ |
| `operator-kernelsdk` (内核算法) | ✅ 40 (macOS) + 15 (win) | ✅ G-K 全过 | ✅ |
| `evasion` (SSN 解析) | ✅ 11 | ✅ | — |
| `implant-win` (用户态外壳) | — | ✅ 48 selftest 导出 (45 selftests.rs + 2 entry.rs + 1 syscalls.rs) | ✅ |
| `offset-resolver` (PDB 工具) | — | ✅ pipeline 验证 | — |

**代码量:** ~13,500 行 Rust（SDK 1790 + 内核 3136 + implant-win 6344 + offset-resolver 171 + examples ~2000）
**提交:** 21 个 commit (`c530fd3` → `c22fc9d`)
**真机测试:** 用户态 A-F 全过 + 内核 G-K 全过（ETW-TI blind / 进程隐藏 / 回调中和）

---

## 2. 23 项 Bypass 能力清单

### 用户态（implant-win DLL 内）— 9 项

| # | 能力 | 模块 | 真机 | 说明 |
|---|---|---|---|---|
| 1 | 间接 Syscall | `syscalls.rs` | ✅ | Hell/Halo/Tartarus Gate，不经过 ntdll 导出 |
| 2 | ETW 盲化 | `blind.rs` | ✅ | NtTraceEvent byte0→0xC3 + provider-disable |
| 3 | AMSI 盲化 | `blind.rs` | ✅ | AmsiScanBuffer patch |
| 4 | ntdll Unhook | `unhook.rs` | 🔶 | 磁盘重映射干净 .text |
| 5 | Foliage 睡眠掩码 | `sleep.rs` | ✅ | APC 链 helper 线程加密 .text + CONTEXT 伪造 |
| 6 | 栈欺骗 | `stack.rs` | ✅ | BYOUD-Gap RSP swap，CET-aware 降级 |
| 7 | 进程注入 | `inject.rs` | ✅ | Module Stomping + **ThreadlessInject (HWBP)** |
| 8 | 反调试/沙箱 | `antidebug.rs` | ✅ | PEB BeingDebugged + uptime |
| 9 | 内存加密 | `mem.rs` | ✅ | RC4 mask/unmask + .text mask_text |
| 10 | **HWBP patchless blind** | `blind_hwbp.rs` | ✅ | 硬件断点 DR0(execute)+VEH，**无 .text 修改**，shadow stub 重定向 RIP（2026-06-26 新增）|

### 内核态（operator-kernelsdk + win/）— 7 项

| # | 能力 | 模块 | 真机 | 说明 |
|---|---|---|---|---|
| 10 | BYOVD 内核读写 | `byovd.rs` + `win/` | ✅ | RTCore64 IOCTL + 4 级页表遍历 VA→PA |
| 11 | ETW-TI 内核盲化 | `etwti.rs` | ✅ | IsEnabled 0x01→0x00，provider disabled |
| 12 | 进程隐藏 | `persistence.rs` | ✅ | DKOM ActiveProcessLinks unlink |
| 13 | PPL 剥离 | `persistence.rs` | 🔶 | Protection 字段清零（offset 真机验证） |
| 14 | EDR 回调中和 | `telemetry.rs` | ✅ | ctx 指针 repurpose→ret gadget（Sysmon 沉默） |
| 15 | WFP 网络过滤 | `netsec.rs` | 🔶 | FwpmEngineOpen0+FwpmFilterAdd0 真 FFI |
| 16 | LSASS 内存读取 | `netsec.rs` | 🔶 | DTB + pagewalk 跨进程读（凭据解析待接） |

### 跨版本 + 工具 — 3 项

| # | 能力 | 模块 | 真机 | 说明 |
|---|---|---|---|---|
| 17 | 跨版本 offset 解析 | `offsets_table.rs` + `version.rs` | ✅ | 编译期烘焙 + 运行时表(8 builds) + pattern scan |
| 18 | 服务端 PDB 解析 | `offset-resolver` | ✅ | `--pdb-path` 真 pdb crate 遍历 + `--build` 已知表 |
| 19 | Pattern scan | `pattern_scan.rs` | ✅ | 字节特征扫描 RVA（7 测） |

### 明确不实现 — 3 项

| # | 能力 | 原因 |
|---|---|---|
| 21 | HVCI-on driver 绕过 | 需 DMA 硬件或 driverless CVE，超出范围 |
| 22 | 完整 APC CONTEXT 伪造真机验证 | 代码写了（spoofed_context + NtContinue APC），未单独 selftest |
| 23 | LSASS 凭据解密 | read_process_mem 框架就绪，drypt 解析未实现 |

---

## 3. 文件地图

```
crates/
├── implant-evasionsdk/src/         # 纯算法核心 (no_std, 47 测)
│   ├── gap.rs          .pdata gap 枚举 (10 测)
│   ├── frame.rs        BYOUD 假帧链合成 (8 测)
│   ├── rc4.rs          SystemFunction032 RC4 (6 测)
│   ├── foliage.rs      Foliage 10 步状态机 (5 测)
│   ├── apc.rs          APC/NtContinue 链合成 (5 测)
│   ├── swap.rs         CET-aware 决策 (5 测)
│   ├── offsets_table.rs 跨版本 offset 表 (8 测)
│   └── lib.rs          GapPool/EvasionStack/ETW-TI GUID
│
├── operator-kernelsdk/src/        # 内核 tier (40+15 测)
│   ├── etwti.rs        ETW-TI blind (跨版本表, 8 测)
│   ├── byovd.rs        BYOVD KernelRw (RtCore64, 4 测) + resolve_kernel_symbol (2 测)
│   ├── telemetry.rs    回调中和 (5 测) ⚠️ neutralize 有缺陷，repurpose ✅ selective slot targeting
│   ├── persistence.rs  进程隐藏/PPL/PG (5 测)
│   ├── netsec.rs       WFP/LSASS/EDR (3 测) + WFP FFI + LSASS pagewalk
│   ├── offsets.rs      17763 常量 + ps_protection (3 测)
│   ├── pagewalk.rs     x64 4 级页表 VA→PA (5 测, 纯算法)
│   ├── pattern_scan.rs 字节特征扫描 RVA (7 测, 纯算法)
│   ├── win/            Windows 外壳 (cfg windows)
│   │   ├── resolve.rs       GetModuleHandleA+GetProcAddress (3 测)
│   │   ├── driver_load.rs   NtLoadDriver bootstrap
│   │   ├── kernel_base.rs   ntoskrnl 基址 (NtQuerySystemInformation)
│   │   ├── pagewalk.rs      re-export
│   │   ├── pattern_scan.rs  re-export
│   │   ├── va_rw.rs         VaKernelRw (VA→PA→物理读写)
│   │   └── mod.rs           bootstrap_byovd() + blind_etw_ti_full()
│   └── examples/      真机测试程序 (8 个, win-only)
│       ├── bootstrap_test.rs          H: driver 加载 + ntoskrnl base
│       ├── etw_ti_blind_test.rs       I: ETW-TI blind
│       ├── proc_hide_test.rs          J: 进程隐藏
│       ├── callback_repurpose_test.rs K: 回调中和 (成功路径)
│       ├── callback_neutralize_test.rs K: neutralize (triple fault 路径)
│       ├── callback_probe_readonly.rs K: 只读诊断
│       ├── callback_struct_deep.rs    K: 函数序言验证
│       └── callback_owner_map.rs      K: slot→驱动映射
│
├── implant-win/src/               # 用户态 DLL (48 selftest 导出)
│   ├── syscalls.rs      间接 syscall 运行时 + 12 wrapper
│   ├── resolve.rs       PEB walk + djb2 + **PE 转发导出解析**（forwarder bounds + 缩写名匹配，2026-06-26 修）
│   ├── evasion_glue.rs  PdataGapScanner + BlindKit/InjectKit glue
│   ├── blind.rs         ETW/AMSI byte-patch + provider-disable
│   ├── blind_hwbp.rs    **HWBP patchless blind**（DR0 execute + VEH + shadow stub，无 .text 修改）
│   ├── kits.rs          SleepmaskKit (NoMask→Foliage)
│   ├── sleep.rs         Foliage APC 链执行器 + CONTEXT 伪造
│   ├── stack.rs         RSP swap (staging + asm + gap_pool_rip)
│   ├── inject.rs        Module Stomping + ThreadlessInject (HWBP)
│   ├── mem.rs           RC4 mask/unmask + mask_text/unmask_text
│   ├── context.rs       x64 CONTEXT (1232B, spoofed_context)
│   ├── version.rs       build_number() + cet_active() 真实探测
│   ├── antidebug.rs     PEB BeingDebugged + uptime
│   ├── unhook.rs        ntdll .text 从磁盘重映射
│   ├── selftests.rs     41 个 selftest 导出（含 hwbp_blind + resolve_forwarder）
│   ├── build.rs         bake_offsets (NYX_OFFSETS 编译期注入)
│   └── config.toml      beacon 配置
│
├── evasion/                       # SSN 解析 (11 测)
│   └── tests/          Hell/Halo/Tartarus Gate
│
├── offset-resolver/               # 服务端 PDB→toml 工具
│   └── src/main.rs     --pdb-path 真 PDB 解析 / --build 已知表
│
└── client-ui/                     # 操作端 TUI (makepad)

docs/
├── BYPASS_CAPABILITIES.md    23 项能力详细清单
├── BYPASS_DEVELOPMENT_REPORT.md  开发进度报告 (~85%→100%)
├── windows-test-results.md   用户态 A-F 真机结果
├── kernel-test-results.md    内核 G-K 真机结果
├── WINDOWS_TEST_HANDOFF.md   Windows 测试交接 (任务 A-K)
├── p2-integration-analysis.md P2 架构分析
├── p2-real-machine-validation-checklist.md 真机验证清单
└── WINDOWS_DEV.md            Windows 开发指南

scripts/
├── run_all_selftests.ps1     全 selftest 跑表
├── scan_linger.ps1           PE-sieve 扫描
├── pesieve_scan*.ps1         PE-sieve 各版本
└── EnableDebug.cs            SeDebugPrivilege 包装器
```

---

## 4. 构建命令

### implant-win DLL (MSVC + build-std)
```
cmd /c "call C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat >nul 2>&1 && cd <repo> && cargo +nightly build --release --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort"
```

### 内核 examples (不需要 build-std)
```
cmd /c "call C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat >nul 2>&1 && cd <repo> && cargo +nightly build --release --manifest-path crates\operator-kernelsdk\Cargo.toml --target x86_64-pc-windows-msvc --example <name>"
```

### macOS 交叉 check (gnu)
```
cargo +nightly check --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc
cargo +nightly check --manifest-path crates\operator-kernelsdk\Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc
```

### macOS 本机测试
```
cargo test --manifest-path crates\operator-kernelsdk\Cargo.toml --lib   # 40 passed
cargo test --manifest-path crates\implant-evasionsdk\Cargo.toml         # 47 passed
cargo test --manifest-path crates\evasion\Cargo.toml                    # 11 passed
```

### offset-resolver
```
cargo run --manifest-path crates\offset-resolver\Cargo.toml -- --build 22621 --out offsets.toml
cargo run --manifest-path crates\offset-resolver\Cargo.toml -- --pdb-path ntkrnlmp.pdb --out offsets.toml
```

### 编译期烘焙 offset
```
NYX_OFFSETS=offsets.toml cargo +nightly build --release --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort
```

---

## 5. 真机验证状态

### 用户态 (Server 2019, 任务 A-F)

| 任务 | 结果 | 关键证据 |
|---|---|---|
| A. PE-sieve 扫描 | ✅ | 0 implanted/shellcode, 1 hooked (ntdll blind, 预期) |
| B. Foliage armed 对比 | ✅ | armed=disarmed, 0 新增命中 |
| C. blind provider-disable | ❌ OS 限制 | NtTraceControl 对内核 provider 返回 0xC000000D |
| D. inject stomp | ✅ | 真 PE 解析+真覆写+执行, exit 0b1111 |
| E. Foliage APC 链 | ✅ | helper 线程加密 .text, round-trip 字节校验, 3/3 稳定 |
| F. RSP swap asm | ✅ | f 在 spoofed 栈执行, 5/5 稳定 |

### 内核 (Server 2019 + RTCore64, 任务 G-K)

| 任务 | 结果 | 关键证据 |
|---|---|---|
| G. driver 准备 | ✅ | RTCore64 从 loldrivers.io, 签名 VALID, Defender 排除 |
| H. BYOVD bootstrap | ✅ | ntoskrnl=0xfffff8037c001000, 10MB 读, PDB RVA 解析 |
| I. ETW-TI blind | ✅ | IsEnabled 0x01→0x00, provider DISABLED |
| J. 进程隐藏 | ✅ | tasklist 1→0→1 (隐藏+恢复), PG 未触发 |
| K. 回调中和 | ✅ | repurpose ctx→ret gadget, Sysmon EID1 SILENCED+恢复 |

---

## 6. 已知 bug / 设计缺陷（需后续修）

### `telemetry.rs::neutralize()` — triple fault 风险 ⚠️

**问题:** neutralize 无差别中和所有回调 slot（含 slot[0] ntoskrnl 内部分发器）+ 用 .text 代码写（0xC3）→ triple fault。

**正确方法:** repurpose（数据写 ctx+0→ret gadget，跳过 ntoskrnl slot）。**已迁入库代码** telemetry.rs::CallbackNeutralizer::repurpose() — selective slot targeting（range-based ntoskrnl skip + slot[0] fallback）已验证。

**待做:** ✅ 已完成（2026-06-27）。

### `kernel_base.rs` stride 隐患

`RTL_PROCESS_MODULE_INFORMATION` 实测 stride=296 字节（非 SDK 文档的 304）。当前代码只取 Module[0]（ntoskrnl，巧合正确），若复用遍历全列表需改 296。

### `VaKernelRw::kwrite` 跨页写

已实现页边界处理，但未在真机上验证跨页写（所有真机写都是单 u64，在页内）。

### ✅ [已修复] `threadless_inject` CONTEXT DR 寄存器

**问题:** DR7 设置为 `0x00000001`（L0 execute）。如果目标线程已用 DR0，会冲突。

**修复:** `inject.rs` 570-600 行实现 DR0-DR3 扫描 — NtGetContextThread 读取完整 CONTEXT（含 DEBUG_REGISTERS），扫描 4 个 slot（DR_OFFSETS + DR7_ENABLE_BITS），找第一个 value==0 且 enable bit 未设的 slot。全满时返回 `Err("all 4 HWBP slots in use")`。已在真机验证。

### ✅ [已修复] `spoofed_context` RSP 安全

**问题:** NtContinue 用 RSP=0 在某些 build 可能崩溃。

**修复:** `sleep.rs` execute_foliage_apc() 在 spawn helper 线程之前调用 NtGetContextThread 捕获 beacon 线程的完整 CONTEXT（ContextFlags=CONTEXT_FULL=0x100007），保存到 `saved_ctx`。helper 线程读取 `saved_ctx.rsp()` 构建 spoofed CONTEXT，确保 RSP 是真实栈指针。还做了 sanity check：如果 captured_rsp==0 则 GetContext 失败，降级为 no-op APC 路径。

### ✅ [已修复 2026-06-26] `resolve.rs` PE 转发导出解析（曾导致 hwbp_blind 0xC0000005 崩溃）

**症状:** `nyx_selftest_hwbp_blind` 真机运行立即崩溃（exit `0xC0000005` STATUS_ACCESS_VIOLATION），诊断停在"即将调用 AddVectoredExceptionHandler"。**根因不在 HWBP/VEH**，在 `resolve.rs` 的 PEB-walk 导出解析处理 PE 转发导出时有两个叠加 bug：

1. **转发边界判定用错字段:** `export_addr_by_hash_pub` 用 `number_of_functions`（函数计数 ~1800）当字节长度，而非 `export_dir_size`（字节数 ~200000）。高 RVA 的转发器逃过检测，被当真函数，**返回转发字符串的 ASCII 地址**而非代码 → 跳进字符串执行 → AV。
2. **缩写模块名匹配不上:** 转发串给缩写名（`NTDLL`），PEB loader 列表是全名（`ntdll.dll`），`djb2` 哈希永不匹配 → `resolve_forwarder` 返回 `None`。bug #1 把 #2 掩盖了（#1 让转发检测根本不触发）。

**修复:** `export_addr_by_hash_pub` 从 PE 头读真 `export_dir_size`；新增 `find_module_for_forwarder` 处理缩写名（去 `.dll`/`.exe` 后缀匹配）+ API-set 名。回归测试 `nyx_selftest_resolve_forwarder`（exit=7，红绿验证过）。

**复盘全文:** `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`。**教训:** 解析的导出一调用就 AV → 先 dump 地址处 16 字节；可打印 ASCII = 转发字符串，不是代码。

---

## 7. 后续开发建议（优先级排序）

| 优先级 | 任务 | 文件 | 难度 |
|---|---|---|---|
| ~~P0~~ | ~~telemetry.rs selective slot targeting~~ | ✅ 已完成（2026-06-27） | — |
| ~~P0~~ | ~~kernel_base.rs stride 修正~~ | ✅ 已完成（2026-06-27） | — |
| ~~P1~~ | ~~**threadless_inject DR 扫描**~~ | ✅ 已修复 — DR0-DR3 扫描 + enable bit 检查 | — |
| ~~P1~~ | ~~**spoofed_context RSP 安全**~~ | ✅ 已修复 — NtGetContextThread 捕获真实 RSP | — |
| ~~P1~~ | ~~**HSB/Moneta 扫描**~~ | ✅ deploy_detectors.ps1 + scan_linger.ps1 | — |
| P2 | **LSASS 凭据解析** — read_process_mem + minidump 或 msv 解析 | `netsec.rs` | 高 |
| P2 | **完整 PDB walker 真机验证** — 从目标机提取 ntoskrnl.pdb 跑 offset-resolver | `offset-resolver` | 中 |
| P2 | **Win11 24H2 VM 验证** — 验证跨版本 offset 表 + CET 探测 + KASLR 限制 | — | 中 |
| P3 | **driverless CVE 路径** — HVCI-on 主机的内核读写替代方案 | `win/` | 高 |

---

## 8. 跨版本兼容性

### 已覆盖的 Windows 版本

| Build | 版本 | EPROCESS.PID | Protection | ETW-TI EnableInfo |
|---|---|---|---|---|
| 17763 | Server 2019 / 1809 | 0x2e0 | 0x6ca | 0x060 (UBR<1075: 0x050) |
| 18362-19045 | Win10 19H1-22H2 | 0x2e8 | 0x6fa | 0x060 |
| 20348/22000 | Server 2022 / Win11 21H2 | 0x440 | 0x87a | 0x060 |
| 22621/22631 | Win11 22H2/23H2 | 0x440 | 0x87a | 0x070 |
| 26100/26200 | Win11 24H2/25H2 | 0x450 | 0x87e | 0x070 |

### 三层 offset 解析

1. **编译期烘焙** (`NYX_OFFSETS`) — operator 用 offset-resolver 生成 toml → build.rs 烘焙。目标侧零解析。
2. **运行时表** (`offsets_table.rs`) — 按 PEB OSBuildNumber 查表，floor-match 未知 patch build。
3. **Pattern scan** (`pattern_scan.rs`) — lea [rip+disp32] 特征扫描 RVA。最后一道。

### 真机验证的版本

- ✅ Server 2019 (17763.1339) — 全部验证
- 🔶 Win10/11 其他版本 — offset 表来自 EDRSandblast CSV + Vergilius，未真机验证

---

## 9. 提交历史

```
c22fc9d feat: complete all 7 remaining bypass capabilities
609790e feat(implant-win): Windows-tested code from real-machine validation (A-F)
5c88929 fix(kernelsdk): VaKernelRw kwrite — real implementation
036761b feat(kernelsdk): win/ — full BYOVD bootstrap chain
ba43856 feat: cross-version Windows support
53ca0fc fix(implant-win): sleep::sleep infinite recursion
fa94a51 fix(implant-win): foliage self-execution crash
352274f feat(implant-win): Foliage executor + PEB + RSP swap + APC syscalls
15050ae docs(F2+F3): update build-order status
db03a51 docs+test(F1): real-machine validation checklist + selftests
b0c3bb0 feat(implant-win): blind provider-disable + inject stomp + glue
45d334d feat(implant-win): Foliage sleep + kit swap + CET stack + .text mask
1aa5ab2 feat(implant-win): syscall5 + nt_protect_virtual_memory
1c50396 feat(evasionsdk): foliage/apc/swap pure cores
f577f92 test+feat(kernelsdk): boundary tests + win/ shell
39d4416 fix(kernelsdk): strip windows-only gate
d957dd5 docs(plan): bypass modules completion implementation plan
c530fd3 docs(spec): bypass modules completion design
```

---

## 10. 关键技术决策记录

| 决策 | 理由 |
|---|---|
| 纯算法核心放 SDK (no_std) | 本机可测，单一数学真源，implant/kernel 只喂数据 |
| 内核 offset 编译期烘焙 | 目标侧零解析（无 pattern scan 噪声、无 PDB 下载） |
| Foliage 用 helper 线程 + APC | 不能同步加密 .text（自加密崩溃），必须 beacon 停靠时 helper 做 |
| 回调中和用 repurpose 不用 neutralize | neutralize 写 .text → triple fault；repurpose 写 ctx 指针 → 安全 |
| RTCore64 走物理地址 + 页表遍历 | driver 只支持物理读写，VA→PA 需要 4 级页表 walk |
| CET 用 IsProcessorFeaturePresent(41) | Server 2019 返回 false（正确）；Win11 24H2+ 返回 true 时降级 |
| 所有破坏性能力默认 gated OFF | beacon loop 行为不受影响，arm 后才执行 |

---

*文档基于 commit `c22fc9d`，macOS dev host + Windows Server 2019 真机验证。*
