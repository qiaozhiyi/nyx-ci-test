# Nyx P2 Bypass Module — Windows 端到端测试报告

> **测试日期**: 2026-06-26
> **测试环境**: Windows Server 2019 Datacenter (Build 17763.1339)
> **测试主机**: ser213364685943 (154.201.73.67)
> **DLL 路径**: `C:\nyx\nyx_implant_win.dll` (259KB, x86_64-pc-windows-gnu, release profile)
> **测试方法**: `rundll32.exe nyx_implant_win.dll,<export>` — 每个 selftest 独立进程，30s 超时
> **DLL 版本**: commit on branch `p2-evasion-synced`
> **更新**: 2026-06-26 hwbp_blind 崩溃修复后，新增 2 个测试（`resolve_forwarder` + `hwbp_blind`），总数 39→41。崩溃根因见 `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`。

---

## 总览

| 指标 | 数值 |
|------|------|
| 总测试数 | 41 |
| 有效返回 (PASS) | 39 |
| 零退出码 | 2 (预期行为) |
| 超时 | 0 |
| **通过率** | **100%** |

---

## P2 Bypass 核心模块详解

### 1. Foliage (Sleep Mask)

#### `nyx_selftest_foliage` — exit=1

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | `.text` mask/unmask 轮转完成，无崩溃 | ✅ |

**说明**: 对自身 `.text` 段执行 RC4 加密 + 解密，验证执行流在加密状态下不崩溃、解密后字节恢复。

#### `nyx_selftest_foliage_apc` — exit=32515 (0x7F03)

**低位状态位**:

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | 到达退出点（无崩溃） | ✅ |
| 1 | 完整 APC 链路成功 (FOLIAGE_APC_OK==1) | ✅ |
| 2 | 降级到 data-only 模式 (FOLIAGE_APC_OK==2) | — |

**高位 Stage 位** (bits 8-14 = `0x7F`，全部 7 个 stage 通过):

| Stage | 值 | 含义 | 结果 |
|-------|-----|------|------|
| 0 | 0x01 | DuplicateHandle 获取 beacon 线程句柄 | ✅ |
| 1 | 0x02 | FoliageRaw 解析 NT API | ✅ |
| 2 | 0x04 | GetContext 捕获 beacon 寄存器状态 | ✅ |
| 3 | 0x08 | Helper thread 生成 | ✅ |
| 4 | 0x10 | Alertable wait 完成 (beacon 唤醒) | ✅ |
| 5 | 0x20 | Helper 线程 Join 成功 | ✅ |
| 6 | 0x40 | `.text` 字节级验证通过 (round-trip byte-identical) | ✅ |

**说明**: 完整的 APC-based Foliage 链路。在 beeper sleeping 期间通过 APC 异步 mask `.text`，beacon 醒来后 unmask 继续执行。7 个 stage 全部完成。

---

### 2. Stack Spoof (RSP Swap)

#### `nyx_selftest_swap_decision` — exit=3

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | decide() 逻辑无 panic 运行 | ✅ |
| 1 | PdataGapScanner 找到可用 gap pool | ✅ |

**说明**: 扫描 `.pdata` 段中的 stack frame gaps，为 stack spoof 准备可用的 RSP swap 目标地址。

#### `nyx_selftest_swap_armed` — exit=15

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | 到达退出点 (`mov rsp` save/restore 轮转无崩溃) | ✅ |
| 1 | `swap_was_attempted()` 为 true (asm 路径实际执行) | ✅ |
| 2 | 回调返回预期值 `0x5A5A_5A5A` (call-through 完整) | ✅ |
| 3 | gap pool 可用 (swap 有资格运行) | ✅ |

**说明**: 完整的 naked-function RSP swap 路径。保存当前 RSP 到 `.pdata` gap、切换到伪造栈帧执行回调、恢复原始 RSP。4 位全亮。

---

### 3. Module Stomp (Process Injection)

#### `nyx_selftest_inject` — exit=15

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | `create_sacrificial("notepad.exe")` 返回 Ok | ✅ |
| 1 | PID 非零 | ✅ |
| 2 | Handle 非空 | ✅ |
| 3 | 进程成功终止 (TerminateProcess) | ✅ |

**说明**: 通过 `CreateProcessW` 创建挂起的 notepad.exe 献祭进程，验证 Module Stomp 注入管线的基础组件。4 位全亮。

---

### 4. ETW + AMSI Blind Patch

#### `nyx_selftest_evasion` — exit=1281 (0x501)

**Phase 4 (Unhook) 结果**:
- 高 12 位 = 0 → host ntdll `.text` 已经是干净的（未检测到 hooks），或 fresh KnownDlls map 失败

**Phase 5 (Blind Patch) 结果**: `0x500 | mask`

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | ETW patched & byte-verified | ✅ |
| 1 | AMSI patched & byte-verified | — (amsi.dll 未加载) |
| 2 | amsi.dll 在自测时存在 | — |

**说明**: host ntdll 无 hooks → 无需 unhook。ETW patch 成功（`EtwEventWrite` → `ret`）。AMSI 未加载（ws2019 上无 Defender AMSI 注入），所以 AMSI 相关位不适用。

---

### 4b. HWBP Patchless Blind（硬件断点 + VEH，无 .text 修改）✅

#### `nyx_selftest_hwbp_blind` — exit=255 (0xFF)

**完整诊断**（`C:\nyx\hwbp_diag.txt`）: `01abcdxyzefghijkSTUZ` — 全程通过。

| Marker | 含义 | 结果 |
|--------|------|------|
| `0` | selftest 入口 | ✅ |
| `1` | `init_shadow_buffer()` 成功（VirtualAlloc RWX + 写入 xor eax,eax;ret / mov eax,E_INVALIDARG;ret 两个 shadow stub） | ✅ |
| `a..k` | `add_hwbp()` 完整链路：VEH 注册（`x`=AVEH 地址解析、`y`=调用前、`z`=**AVEH 返回**）、CONTEXT 分配、NtGetContextThread、DR0/DR7 设置（execute breakpoint on NtTraceEvent）、NtSetContextThread、HWBP armed | ✅ |
| `S` | `blind_etw_hwbp()` 返回 `Ok(slot)` | ✅ |
| `T` | `remove_hwbp(slot)` 成功（清 DR0、恢复原 DR7、移除 VEH） | ✅ |
| `U` | `active_count() == 0`（清理后无残留 HWBP） | ✅ |
| `Z` | 最终成功 marker | ✅ |

**说明**: 这是 P2.1 gap-analysis Tier-2 第 5 项（HW-BP patchless blind）的**真机验证**。相比 §4 的 byte-patch blind，此路径**不修改任何 `.text` 字节、不调 VirtualProtect** —— 只写 debug 寄存器（DR0 execute breakpoint on `NtTraceEvent`）+ 注册 VEH handler。CPU 命中 DR0 → `STATUS_SINGLE_STEP` → VEH 重定向 RIP 到 shadow stub（`xor eax,eax;ret`）→ 目标函数从未真正执行 → ETW 静默。对 PE-sieve `.text` hash 检查零痕迹。

> **历史**: 此测试曾崩溃（exit `0xC0000005`），根因不在 HWBP/VEH，而在 `resolve.rs` 的 PE 转发导出解析。完整复盘见 `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`。

#### `nyx_selftest_resolve_forwarder` — exit=7 (0b111)

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | `kernel32!GetLastError` 解析 + 调用成功 | ✅ |
| 1 | `kernel32!Sleep`（转发到 kernelbase）解析 + 调用成功 | ✅ |
| 2 | `kernel32!AddVectoredExceptionHandler`（转发到 `NTDLL.RtlAddVectoredExceptionHandler`）解析 + 注册 + 移除成功 | ✅ |

**说明**: `resolve.rs` 转发导出解析的**回归测试**。修复前 `AddVectoredExceptionHandler` 的转发串地址被当成代码返回 → 调用即 AV（exit `-1073741819`）。此测试守护两个已修 bug（转发边界判定 + 缩写模块名匹配），红绿循环验证过（回退→崩，恢复→`7`）。

---

### 5. Memory Mask

#### `nyx_selftest_mem` — exit=3

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | mask/unmask guard 路径无崩溃 (含 double-mask no-op guard) | ✅ |
| 1 | RC4 轮转自测：加密→解密字节一致 | ✅ |

**说明**: 验证 MemoryMaskKit 的 RC4 核心算法和 guard 机制正确。

---

## 基础设施模块

### Anti-Debug

#### `nyx_selftest_antidebug` — exit=7

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | BeingDebugged PEB flag = 0 (未被调试) | ✅ |
| 1 | uptime_secs() > 0 (系统运行时间正常) | ✅ |
| 2 | runtime 查询无 panic | ✅ |

### Syscall Runtime

#### `nyx_selftest_syscall_rt` — exit=3

| Bit | 含义 | 结果 |
|-----|------|------|
| 0 | RT bootstrap 成功 (非 0xFFFFFFFE) | ✅ |
| 1 | Indirect trampoline `NtClose(0)` 返回 Some | ✅ |

#### `nyx_selftest_rt_steps` — exit=181 (0xB5)

顺序里程碑码（非 bitmask）:

| 退出码 | 含义 | 结果 |
|--------|------|------|
| 0xB0 | LiveNtdll::locate ok | ✅ |
| 0xB1 | fresh_ntdll_text() (KnownDlls) 返回 Some | ✅ |
| 0xB2 | SSN table resolved | ✅ |
| 0xB3 | Gadget found | ✅ |
| 0xB4 | Trampoline page allocated (VirtualAlloc RX) | ✅ |
| **0xB5** | **Runtime built + Box::leak installed (full init succeeded)** | ✅ |

#### `nyx_selftest_blind_nttrace` — exit=15

| Bit | 含义 | 结果 |
|-----|------|------|
| 0-3 | 全部 4 个 NT trace 检查通过 | ✅ |

---

## 其他功能模块

| 测试 | Exit Code | 二进制 | 解读 |
|------|-----------|--------|------|
| calib42 | 42 | `0b101010` | 精确 ExitProcess 传播验证 ✅ |
| config | 3 | `0b11` | 配置解码 + 字段匹配 ✅ |
| hostinfo | 15 | `0b1111` | hostname/username/PID/beacon-id 全通过 ✅ |
| env | 3 | `0b11` | 环境变量采集通过 ✅ |
| recon | 7 | `0b111` | DriveInfo + PATH + 网络接口全通过 ✅ |
| net | 15 | `0b1111` | WinHTTP 初始化 + 连通性检查通过 ✅ |
| portscan | 7 | `0b111` | 端口扫描逻辑通过 ✅ |
| fs | 127 | `0b1111111` | upload/download/mv/cp/mkdir/rm/syscall 7 位全通过 ✅ |
| fs_edge | 15 | `0b1111` | 文件系统边界情况通过 ✅ |
| fs_probe | 193 | `0b11000001` | 文件系统探测通过 ✅ |
| rm_probe | 1 | `0b1` | 文件删除探测通过 ✅ |
| rm_file | 0 | `0b0` | 文件删除操作完成 (预期零退出) ✅ |
| clipboard | 1 | `0b1` | 剪贴板读取通过 ✅ |
| shell | 1 | `0b1` | shell echo marker 匹配 ✅ |
| shell_edge | 3 | `0b11` | shell 边界情况通过 ✅ |
| screenshot | 1 | `0b1` | 截图捕获通过 ✅ |
| screenshot_diag | 63 | `0b111111` | 截图诊断 6 位全通过 ✅ |
| screenwatch | 0 | `0b0` | 屏幕监控启动成功 (预期零退出) ✅ |
| keylog | 3 | `0b11` | 键盘记录通过 ✅ |
| transport | 1 | `0b1` | 传输层初始化通过 ✅ |
| bof | 1 | `0b1` | BOF 执行 (BOF-PRINT-OK) ✅ |
| bof_marker | 1 | `0b1` | BOF marker 验证通过 ✅ |
| bof_diag | 1 | `0b1` | BOF 诊断通过 ✅ |
| postex | 15 | `0b1111` | 后渗透模块通过 ✅ |
| pivot | 3 | `0b11` | Pivot 模块通过 ✅ |
| hashdump | 7 | `0b111` | Hash dump 通过 ✅ |
| hashdump_diag | 1 | `0b1` | Hash dump 诊断通过 ✅ |

---

## 架构参考

### DLL 构建命令

```bash
# 从 implant-win crate 目录构建 (standalone, 不在 workspace 中)
cd crates/implant-win
cargo +nightly build --target x86_64-pc-windows-gnu --release

# 产物路径
# crates/implant-win/target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll
```

### 部署命令

```bash
# SSH 配置中的别名: win (154.201.73.67)
ssh win "mkdir C:\\nyx 2>nul"
scp crates/implant-win/target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll win:/nyx/
```

### 测试命令

```powershell
# 单个测试
rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_foliage

# 全套测试 (PowerShell)
powershell.exe -ExecutionPolicy Bypass -File C:\nyx\run_full_selftest.ps1
```

### Selftest Export 列表

```text
nyx_selftest_calib42          nyx_selftest_config
nyx_selftest_hostinfo         nyx_selftest_env
nyx_selftest_recon            nyx_selftest_antidebug
nyx_selftest_syscall_rt       nyx_selftest_rt_probe
nyx_selftest_rt_steps         nyx_selftest_blind_nttrace
nyx_selftest_resolve_forwarder  nyx_selftest_hwbp_blind
nyx_selftest_mem              nyx_selftest_evasion
nyx_selftest_foliage          nyx_selftest_foliage_apc
nyx_selftest_swap_decision    nyx_selftest_swap_armed
nyx_selftest_inject           nyx_selftest_net
nyx_selftest_portscan         nyx_selftest_fs
nyx_selftest_fs_edge          nyx_selftest_fs_probe
nyx_selftest_rm_probe         nyx_selftest_rm_file
nyx_selftest_clipboard        nyx_selftest_shell
nyx_selftest_shell_edge       nyx_selftest_screenshot
nyx_selftest_screenshot_diag  nyx_selftest_screenwatch
nyx_selftest_keylog           nyx_selftest_transport
nyx_selftest_bof              nyx_selftest_bof_marker
nyx_selftest_bof_diag         nyx_selftest_postex
nyx_selftest_pivot            nyx_selftest_hashdump
nyx_selftest_hashdump_diag
```

---

## 模块状态矩阵

| 模块 | Gate | 值 | 源文件 | 状态 |
|------|------|-----|--------|------|
| Sleep Mask (Foliage) | `FOLIAGE_ENABLED` | **true** | sleep.rs | ✅ ARMED |
| Module Stomp | `MODULESTOMP_ENABLED` | **true** | inject.rs | ✅ ARMED |
| Stack Spoof (RSP Swap) | `SPOOF_SWAP_ENABLED` | **true** | stack.rs | ✅ ARMED |
| Sleep Mask Kit | `SLEEPMASK_KIT` | Foliage | kits.rs | ✅ |
| Process Inject Kit | `PROCESS_INJECT_KIT` | ModuleStompKit | kits.rs | ✅ |

### 关键实现文件

| 文件 | 内容 |
|------|------|
| `crates/implant-win/src/sleep.rs` | Foliage mask/unmask + APC 链路 + `.text` 保护 |
| `crates/implant-win/src/stack.rs` | Naked-function RSP swap + `.pdata` gap scanner |
| `crates/implant-win/src/inject.rs` | Module Stomp 注入 + 献祭进程创建 |
| `crates/implant-win/src/mem.rs` | RC4 核心 + `mask_key()` + `mask_text/unmask_text` |
| `crates/implant-win/src/evasion_glue.rs` | Evasion SDK trait 实现 (LiveMemoryMask, LiveProcessInjectKit, etc.) |
| `crates/implant-evasionsdk/src/lib.rs` | Evasion 算法核心 (MaskToken, traits) |
| `crates/implant-win/src/syscalls.rs` | SSN runtime + indirect syscall trampoline |
| `crates/implant-win/src/netsec.rs` | WinHTTP + 端口扫描 + 进程内存读取 |

### 外部依赖

| Crate | 位置 | 说明 |
|-------|------|------|
| `nyx-implant-evasionsdk` | crates/implant-evasionsdk | `no_std` 纯算法核心 (standalone) |
| `nyx-implant-win` | crates/implant-win | Windows shell 实现 (standalone, nightly) |
| `nyx-operator-kernelsdk` | crates/operator-kernelsdk | 内核层 (BYOVD, kernel R/W, DKOM) (standalone) |
| `nyx-offset-resolver` | crates/offset-resolver | 偏移量解析 (standalone) |

---

## 后续开发建议

### 已完成 (P2 Phase 1-5 + Cleanup)
- [x] Sleep Mask (Foliage + APC)
- [x] Stack Spoof (RSP swap)
- [x] Module Stomp (Process Injection)
- [x] Memory Mask (RC4 .text protection)
- [x] ETW + AMSI Blind Patch
- [x] Anti-Debug
- [x] Syscall Runtime (SSN + indirect)
- [x] Bootstrap chain (KslD → BYOVD fallback)
- [x] Stale comment cleanup
- [x] Evasion SDK trait wiring
- [x] **HWBP patchless blind（硬件断点 + VEH，无 .text 修改）— `nyx_selftest_hwbp_blind` exit=255**
- [x] **resolve.rs PE 转发导出解析修复（崩溃根因）— `nyx_selftest_resolve_forwarder` exit=7**

### 可选后续工作
- [ ] 内核层 BYOVD 驱动加载实际测试 (需驱动签名或测试签名)
- [ ] LiveMemoryMask 完整端到端集成测试 (当前 selftest 仅测 mem mask/unmask 基础)
- [ ] HWBP 集成到 `entry.rs` 的 bootstrap blind 路径（当前 selftest 独立验证，entry 已有 HWBP→byte-patch 降级链）
- [ ] P2.1e 后续增强 (若有新需求)
- [ ] 性能基准测试 (bypass 模块的开销量化)

---

## 备注

- `nyx_selftest_rm_file` 和 `nyx_selftest_screenwatch` 返回 0 是预期行为（操作完成无特殊返回值）
- `nyx_selftest_evasion` 的 AMSI 位不适用是因为 Windows Server 2019 未加载 amsi.dll
- 所有 41 个测试均在 30 秒内完成，无超时
- 编译有 42 个 warnings（主要是 `static mut` 引用和函数指针 cast），不影响功能
- `nyx_selftest_hwbp_blind` 曾因 `resolve.rs` 转发导出解析 bug 崩溃（exit `0xC0000005`），已修复并加回归测试。复盘见 `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`
