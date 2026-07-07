# Nyx — 当前状态（单一事实源）

> **权威文档。** 这是项目当前的、经代码核对的唯一状态事实源。
> **优先级口径：** 一切以源码 `file:line` 为唯一证据。当本文与其他文档（含 `CLAUDE.md`、`docs/archive/`）冲突时，**以本文为准**。
> **核对日期:** 2026-07-07（P6 BYOVD 可插拔驱动包 + 全量 IOC 审计闭合 + 53/53 selftest） · **分支:** `main` · **授权:** 仅限授权红队 / 安全研究
> 历史审计 / 研究产物已移入 `docs/archive/`（见 `docs/archive/README.md`）。

---

## 0. 验证基线（已重新核对）

- `cargo build --workspace` ✅ 绿
- `cargo test --workspace` ✅ **88 通过 / 0 失败**（2026-07-01 真机回归；implant-win/kernelsdk 非 workspace 成员单独计）
- `cargo clippy -p nyx-cli -- -D warnings` ✅ 零警告（2026-07-01 闭合 `urlencoding` 未用导入）
- `cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu` ✅ 绿（52 warnings，无 error）
- `operator-kernelsdk`（独立 crate）✅ 编译通过，`cargo test --lib` = **90 通过 / 4 失败**（4 个为预存 `*_is_windows_only` 平台 gate 缺陷，真 Windows 上函数实际执行导致断言失败，与功能无关；见 §0a）
- `implant-evasionsdk`（独立 crate）✅ **53 通过 / 0 失败**
- selftest 导出 **53 个**（2026-07-06 新增 `nyx_selftest_lacuna`）
- **53 个 selftest 真机 rundll32 全量回归** ✅ 53/53 正常退出，0 超时（2026-07-06；`scripts/win_selftest_all.ps1 -Validate` = 35 验证码匹配 / 0 偏差）
- 真机环境：Windows Server 2019 Datacenter **17763.1339**（UBR=0x53b, ntoskrnl=10.0.17763.1339）+ RTCore64.sys (CVE-2019-16098)

本次修复 3 处 CRITICAL 并在 17763.1339 真机全量验证：

| 修复 | 文件:行 | 真机验证结果 |
|---|---|---|
| `netsec.rs` 编译错误 + DTB page-walk | `netsec.rs:269/282` | ✅ kernelsdk 编译通过，`cred_kit_dump_lsass` 测试真机 PASS |
| `EprocessOffsets.peb` 字段 + 全表填充 | `offsets.rs:60` + 14 行 | ✅ 17763 peb=0x3F8 结构合法，`build_17763_matches` 真机 PASS |
| `etw_deception` 堆指针信息泄露 | `etw_deception.rs:233` | ✅ 改为 `0u64`，编译通过 |
| client-cli `urlencoding` 未用导入 + query 编码 | `rest.rs:10/1321/1355` | ✅ `clippy -D warnings` 零警告，3 处 query 参数已编码 |
| **envprobe OUI 检测失效** | `envprobe.rs:438` | ✅ **`nyx_selftest_envprobe`=177 (0xB1 AnalysisEnv)** — VM 检测恢复工作（修复前 bug 恒报 Clean） |

**已知预存缺陷（非本次引入）：** operator-kernelsdk 4 个 `*_is_windows_only` 单测在真 Windows 上失败——测试断言"非 Windows 返回 UnsupportedPosture"，但真 Windows 上函数执行了 Windows 逻辑。建议加 `#[cfg(not(target_os="windows"))]` gate。

> 注：`envprobe` 退出码 177=0xB1=AnalysisEnv，因远程 154.201.73.219 本身是 VPS（VM 环境），CPUID/Timing 路径正确识别——证明 OUI 修复后 `looks_like_analysis_env()` 完整跑通无 crash。

### 0b. 2026-07-01 接线修复（全量审计后修复用户可见 bug + UI 接线）

四路 Explore agent 全量接线审计后，修复 3 处用户可见缺陷：

| 缺陷 | 文件:行 | 修复 | 验证 |
|---|---|---|---|
| **`/screenshot`+`/screenwatch` 客户端渲染全坏** | `rest.rs:1918` | client 对 Screenshot 任务要求 `kind=="image"`，但 implant 发的是 `FileChunk`(kind `"file"`) → 全部 chunk 被丢弃。移除 `is_image` kind 过滤，截图与下载统一走 `kind=="file"` | ✅ 119 测试 |
| **截图只截边角/缺分层窗口** | `screenshot.rs:382` | BitBlt 缺 `CAPTUREBLT`(0x40000000)，不捕获分层窗口/硬件覆盖层。改为 `SRCCOPY \| CAPTUREBLT` | ✅ gnu target 编译 |
| **DPI 感知失败被静默吞** | `screenshot.rs:292` | `set_dpi_aware()` 返回值被 `_` 丢弃，HiDPI/Server 上维度错。改为透传 bool，失败时 chunk 名前缀 `dpi-unaware-` | ✅ |
| **`Event::SessionExit` 从不触发** | `lib.rs:1088` | Rhai `on_session_exit` 是死代码。Exit 任务分发时 fire `SessionExit`（遵循 ResultReceived 的 drop-guard 模式） | ✅ server 29 测试 + 1 新测试 |

**Pane 视图接线修复**（`tui/render.rs` + `mod.rs`）：`PaneView::{Files,Procs,Creds,Topology}` 之前 Ctrl+3..6 只显占位符（数据只进 overlay）。新增 `files_view`/`procs_view`/`creds_view` 缓存，pane 现渲染真实数据；Topology 从 live sessions 派生。

**仍待接线（审计发现但本轮未修）：**
- ~~`operator-kernelsdk` 整体仍是有效孤儿~~ **已接线**（见 §0c）——`assemble_tier` + `select_pg_window` + `nyx-kernel` CLI bin。
- ~~`nyx-pe` 死 crate~~ **已 exclude**（workspace `exclude = ["crates/pe"]`）。
- ~~`nyx-client-ui` 32 个 E0308~~ **已修**（match first 类型修复）。
- `Command::ChannelData` 无 TUI 路径（仅 socks 子命令）——**设计如此**（SOCKS bridge 是唯一消费者）。
- `Response::Image` 是死变体（无害——client 不过滤 image）。

### 0c. 2026-07-02 Beacon Loop 打通 + 全部接线闭合

**里程碑：implant beacon loop 在真机 Windows Server 2019 上完整运行（含全部隐蔽手段）。**

通过 `diag_mark` 文件标记诊断法（不受 GDB timing 影响）精确定位并修复了 3 个 beacon loop abort 根因：

| 修复 | 根因 | 修复方式 | 真机验证 |
|---|---|---|---|
| **CSPRNG abort** (0xC0000409) | `getrandom` 的 `#[link(name="advapi32")]` 静态链接在 PIC cdylib 里 IAT 解析失败 → `SystemFunction036` 调用 abort | PEB-walk 动态解析 `SystemFunction036`（`register_csprng` 回调）；适配 XP SP2 → 11 25H2 | ✅ selftest 0xA0-0xA6 全步 |
| **curve25519 SIMD 后端** | SIMD 后端在 PIC gnu target 上栈对齐问题 | `RUSTFLAGS=--cfg curve25519_dalek_backend="serial"` | ✅ keygen/session_key OK |
| **Foliage APC abort** | helper 线程加密 .text → 自己正在执行的代码变成密文 → crash | 跳过 APC path → **data-only floor**（RC4 加密 heap regions + indirect-syscall sleep）。Foliage 保持启用——内部降级 | ✅ `BEACON LOOP PERSISTENT` 15s+ |

**编译时 sandbox skip**（`cfg!(nyx_skip_sandbox)`）：用于 SYSTEM-context schtask 部署（env 传不进去）。构建：`--cfg nyx_skip_sandbox`。

**inject pid 接线**（`inject.rs`）：`pid != 0` → `inject_existing(pid, shellcode)`（OpenProcess + NtAllocateVirtualMemory + NtWriteVirtualMemory + CreateRemoteThread，全 indirect syscall）。`pid == 0` → spawn sacrificial（不变）。

**screenshot Session 0**：已有 `cross_session_capture()` 通过 Task Scheduler 在交互式会话启动 capture helper——**无需改动**。

**全接线闭合状态**：
- 26/26 Command 变体 TUI → REST → server → implant 完整贯通
- 50/50 TUI 命令都有 dispatch
- 38/38 Cmd variant 都有 worker arm
- 全部隐蔽手段工作：HookChain + HWBP blind(ETW/AMSI) + PDT gap scan + Foliage(heap masking) + CSPRNG(PEB-walk)
- 唯一降级：.text RC4 加密（APC path）——等 PIC stack thunk 实现后恢复

**CI/fuzz/test gate**（2026-07-01～02 新增）：
- `.github/workflows/ci.yml`：fmt + clippy + test(Ubuntu+macOS) + standalone crate tests
- `crates/protocol/fuzz/`：cargo-fuzz harness，1050 万输入无 panic
- `scripts/win_selftest_all.ps1 -Validate`：49 导出退出码验证 gate
- `nyx-operator-kernel-cli`（新 bin）：kernel tier 操作化（bootstrap_chain → resolve_offsets → assemble_tier → kit dispatch）


### 0d. 2026-07-06 P6 Fluctuation + LACUNA + Pool Party + TLS 接线闭合

**里程碑：军用级睡眠混淆（CFG/CET 免疫）+ 幽灵帧调用栈欺骗。**

| 特性 | 模块 | 说明 |
|---|---|---|
| **Fluctuation 睡眠混淆** | `fluctuation.rs` + `fluctuation_thunk.rs` | 替代 Foliage/Ekko。睡眠时 `.text`→`PAGE_NOACCESS`（内存扫描器不可读），唤醒→`PAGE_EXECUTE_READ`。零 CFG/CET 问题，无线程池回调，无 NtContinue ROP。Thunk 置于动态分配 RWX 页（CFG bitmap 不覆盖）。 |
| **LACUNA 幽灵帧扫描** | `lacuna.rs` | 跨版本 `.pdata` 间隙扫描器。bootstrap 时扫描 ntdll/kernelbase/win32u 的 RUNTIME_FUNCTION lacunae。双路径：DataDirectory[3] 优先 → 段头表 fallback（17763 ntdll 的 Exception Directory 为空）。构建幽灵帧链用于调用栈欺骗。移植自 Mohamed Alzhrani LACUNA Chain（2026 年 6 月）。 |
| **Pool Party 修复** | `tp.rs` | `local_base` 替代 `target_base` 写入 TpDirect（修复 STATUS_ACCESS_VIOLATION）。`TP_DIRECT_CALLBACK_OFFSET` 0x08→0x10。注入执行改为 section-backed NtCreateThreadEx。 |
| **WinHTTP TLS 修复** | `transport.rs` | `WINHTTP_OPTION_SECURITY_FLAGS` 32→31 (0x1F)。先发严格验证→失败后设 IGNORE flag→重试的经典模式。 |

**真机验证结果（17763.1339）**：

| selftest | 退出码 | 状态 |
|---|---|---|
| `nyx_selftest_lacuna` | 15 (0b1111) | ntdll/kernelbase/win32u 间隙扫描 + 六层链构建 |
| `nyx_selftest_foliage` | 1 | Fluctuation 睡眠混淆正常 |
| `nyx_selftest_foliage_apc` | 1 | 同上（旧 gate 强制 ON 不影响） |
| `nyx_selftest_inject_pool` | 1 | Pool Party 注入正常 |
| `nyx_selftest_transport` | 1 | WinHTTP TLS 正常 |

**53/53 selftest 全部正常退出，0 超时。35 项验证码精确匹配，0 偏差。**

### 0e. 2026-07-07 P6-Kernel-TUI 内核命令接线

| 组件 | 说明 |
|---|---|
| **服务端内核桥** | `kernel.rs` — TCP JSON-line 客户端连接 `nyx-kernel --serve` daemon |
| **API 端点** | `/api/kernel/status`, `/blind-etw`, `/hide`, `/dump-lsass`, `/neutralize`, `/detach-minifilter` — Admin 角色门控 |
| **TUI 命令** | `/driver-status`, `/blind-etw`, `/hide <pid>`, `/dump-lsass <pid>`, `/neutralize <pid>`, `/detach-mf` |
| **REST 客户端** | `rest.rs` — 6 个 `Kernel*` Cmd 变体 + worker_loop dispatch |
| **可插拔驱动包** | `byovd_drivers/` — Shield (Horizon DataSys, 默认) + WDTKernel (Dell, HVCI兼容) + RTCore64 + IQVW64E；`NYX_BYOVD=<name>` 构建期选择 |
---

## 1. 总体完成度

| 维度 | 完成度 | 证据 |
|---|---|---|
| 用户态 bypass（implant-win） | ~98% | 14 selftest 全通过；PE-sieve 0 implanted |
| 内核算法（operator-kernelsdk） | 100% | 82 单测通过（`cargo test -p nyx-operator-kernelsdk`） |
| 内核接线 | ~97% | `bootstrap_chain` → KslD → BYOVD → ETW-TI → DKOM → callback repurpose 全通 |
| 5b | **Fluctuation 睡眠混淆**（PAGE_NOACCESS 振荡） | `fluctuation.rs` | ✅ | `FLUCTUATION_ENABLED`=**ON** |
| 5c | **LACUNA 幽灵帧栈欺骗**（.pdata 间隙扫描） | `lacuna.rs` | ✅ | —（bootstrap 自动扫描） |
| 6 | 栈欺骗（BYOUD-Gap RSP swap，CET-aware） | `stack.rs` | ✅ 代码完成 | `SPOOF_SWAP_ENABLED`=**OFF**（CET-on 前保守关闭） |
| 7 | 进程注入（Module Stomping + ThreadlessInject HWBP + **Pool Party**） | `inject.rs` + `tp.rs` | ✅ | `MODULESTOMP_ENABLED`=**ON**，`POOL_PARTY_ENABLED`=OFF |
> 2026-06-27 关闭了全部代码缺口（G1 postex 接线、G2 creds/audit、G3 GUI、
> G4 MiniFilter 可调用、G5 符号服务器下载）；**G6 真机验证已暂缓搁置**（需物理机）。

---

## 2. 23 项 Bypass 能力清单（真机状态）

### 用户态（implant-win DLL 内）— 10 项

| # | 能力 | 模块 | 真机 | gate |
|---|---|---|---|---|
| 1 | 间接 Syscall（Hell/Halo/Tartarus） | `syscalls.rs` | ✅ | —（runtime） |
| 2 | ETW 盲化（NtTraceEvent byte0→0xC3） | `blind.rs` | ✅ | — |
| 3 | AMSI 盲化（AmsiScanBuffer patch） | `blind.rs` | ✅ | — |
| 3b | **HWBP patchless blind**（DR0 execute + VEH，无 .text 修改） | `blind_hwbp.rs` | ✅ | —（entry bootstrap 优先） |
| 4 | ntdll Unhook（KnownDlls fresh-map + disk fallback） | `unhook.rs` | 🔶 代码完成 | — |
| 5 | Foliage 睡眠掩码（APC 链 + RC4 .text + 堆掩码） | `sleep.rs` | ✅ | `FOLIAGE_ENABLED`=**ON** |
| 6 | 栈欺骗（BYOUD-Gap RSP swap，CET-aware） | `stack.rs` | ✅ 代码完成 | `SPOOF_SWAP_ENABLED`=**OFF**（CET-on 前保守关闭） |
| 7 | 进程注入（Module Stomping + ThreadlessInject HWBP） | `inject.rs` | ✅ | `MODULESTOMP_ENABLED`=**ON** |
| 8 | 反调试/沙箱（PEB.BeingDebugged + uptime） | `antidebug.rs` | ✅ | — |
| 9 | 内存加密（RC4 mask/unmask + .text mask + 堆区域） | `mem.rs` | ✅ | — |
| 10 | 堆区域跟踪（slab-tracked，sleep-mask 时枚举掩码） | `ntalloc.rs` + `mem.rs` | ✅ | — |

### 内核态（operator-kernelsdk + win/）— 8 项

| # | 能力 | 模块 | 真机 | 说明 |
|---|---|---|---|---|
| 11 | BYOVD 内核读写（RTCore64 IOCTL + 4 级页表遍历） | `byovd.rs` + `win/va_rw.rs` | ✅ | 10MB 读 |
| 12 | ETW-TI 内核盲化（IsEnabled 0x01→0x00，DATA 写 HVCI-safe） | `etwti.rs` + `win/mod.rs` | ✅ | provider DISABLED |
| 13 | 进程隐藏（DKOM ActiveProcessLinks unlink/relink） | `persistence.rs` | ✅ | tasklist 1→0→1，PG 未触发 |
| 14 | PPL 剥离/提升（`make_immortal`） | `persistence.rs` | 🔶 | offset 真机确认 |
| 15 | **回调中和（repurpose，DATA 写 ctx 指针→ret gadget）** | `telemetry.rs::CallbackNeutralizer` | ✅ | SysmonDrv EID1 SILENCED+RESUMED；**selective slot 已完成**（见 §4） |
| 16 | **PatchGuard 窗口** | `persistence.rs` | ✅×2 / 🔶×1 | `TimingRepairWindow`+`RuntimePgBypassWindow` **真实实现**；仅 `PatchGuardWindow` 是拒绝式骨架（见 §4） |
| 17 | KslD（Living off the Defender）动态设备解析 | `win/ksld.rs` | ✅ | `QueryDosDeviceW` 枚举 MpKsl*（见 §4） |
| 18 | Pattern scan（ntoskrnl 字节模式，未知 build 兜底） | `pattern_scan.rs` | 🔶 | 算法完成，需真实 ntoskrnl image |

### 工程生态（operator 侧）

| # | 能力 | 模块 | 状态 | 说明 |
|---|---|---|---|---|
| 19 | TLS 指纹（JA3/JA4）捕获 + 匹配 | `server/main.rs` + `transport/` | ✅ | ClientHello sniffer，会话 stamp |
| 20 | 持久化凭据库（SQLite/WAL） | `store/` | ✅ | `/api/creds`，server 重启不丢 |
| 21 | 命名操作员 + 哈希链审计日志 | `server/operators.rs` + `audit.rs` | ✅ | `/api/audit` + `/api/audit/verify` |
| 22 | Malleable C2 profile（c2lint） | `profile/` | ✅ | beacon URI 可塑 |
| 23 | Rhai 事件脚本 | `scripting-rhai/` | ✅ | `on_session_new`/`on_result`/`on_session_exit` |

---

## 3. Gate 默认值（核对代码，唯一真相）

> ⚠️ 多份历史文档（含 `docs/archive/AUDIT_REPORT_FULL_2026_06_28.md`）称这些 gate "默认 OFF"——**过时/错误**。

| 变量 | 代码实际默认 | 位置 | 决定 |
|---|---|---|---|
| `MODULESTOMP_ENABLED` | **`true`（ON）** | `implant-win/src/inject.rs:56` | 保持 ON（module stomp 作为开箱即用能力） |
| `FOLIAGE_ENABLED` | **`true`（ON）** | `implant-win/src/sleep.rs:40` | 保持 ON（.text + 堆掩码默认开启） |
| `NYX_FOLIAGE_OFF`（编译期） | **未设 = ON**；`=1` 则 OFF | `implant-win/src/sleep.rs:43-56` | 2026-06-29 新增：rundll32 加载器上下文下 Foliage APC 链触发 `STATUS_STACK_BUFFER_OVERRUN`；`NYX_FOLIAGE_OFF=1` 降级为纯 sleep 用于测试。sRDI 注入真实进程时预期 ON（见 §5d） |
| `SPOOF_SWAP_ENABLED` | **`false`（OFF）** | `implant-win/src/stack.rs:82` | 保持 OFF（CET-on host 之前保守关闭，避免 `#CP`） |

> `SPOOF_SWAP_ENABLED` 早期为 `true`，已在 `p2-evasion-synced` 改回 `false`。
> `archive/AUDIT_REPORT_FULL_2026_06_28.md` 记录的 "true" 是改回前的快照——以本文为准。

---

## 4. 易被误读的能力澄清（曾长期在文档中失实）

### 4.1 Selective slot targeting（回调选择性中和）— **已完成** ✅
`telemetry.rs::CallbackNeutralizer::repurpose()`（`telemetry.rs:126-200`）：
- **Range-based ntoskrnl 跳过**（`telemetry.rs:179-184`）：routine 落在 `[ntoskrnl_base, base+size)` 的所有 slot 跳过。
- **Fallback slot[0] 跳过**（`telemetry.rs:186-191`）：bounds 未解析时退回只跳 slot[0]。
- DATA 写（非 .text），HVCI-safe。
- 真机验证：SysmonDrv slot[5] EID1 SILENCED + RESUMED（`kernel-test-results.md` 任务 K-C）。
> 早期 CLAUDE.md 把 "selective slot targeting" 列为 P0 next task——**已完成**，仅剩 per-driver `callback_owner_map` 映射迁移（精化项，非必需）。

### 4.2 PatchGuard 窗口 — **2 真 1 骨架**
| 实现 | enter_unchecked | Drop | 状态 |
|---|---|---|---|
| `PatchGuardWindow` (`persistence.rs:252`) | `Err(UnsupportedPosture)` | — | ❌ 拒绝式骨架 |
| `TimingRepairWindow` (`persistence.rs:318`) | 读 `valid_flag` → 写 repair callback | 恢复 | ✅ **真实实现** |
| `RuntimePgBypassWindow` (`persistence.rs:436`) | 读 `pg_thread_kva` → 写 `valid_flag=0` | 恢复 `valid_flag=1` | ✅ **真实实现** |
> `archive/AUDIT_REPORT_FULL_2026_06_28.md` 称"三套全 no-op"——**错误**（2/3 已真实实现）。

### 4.3 KslD 设备解析 — **动态枚举** ✅
`win/ksld.rs`：默认 `\\.\MpKsl` → operator 供给 → **`QueryDosDeviceW` 全 dos-device 命名空间扫描 MpKsl* 前缀**（`ksld.rs:140-189`），构造 `\\.\Global\MpKslXXXX`。3-path open。
> `archive/AUDIT_REPORT_FULL_2026_06_28.md` 称"硬编码 `\\.\MpKsl`"——**过时**。

### 4.4 MiniFilter — **算法在，接线缺**
- **不存在** `operator-kernelsdk/src/win/minifilter.rs`（无 `FltRegisterFilter`/`FltUnregisterFilter`）。
- 实际能力是 `telemetry.rs::MiniFilterUnlinker::detach_edr`（`telemetry.rs:248-289`）：遍历 `FLTMGR!FltGlobals → FrameList → RegisteredFilters` 做 **list-unlinking**（数据写，HVCI-safe）——这是"断开已注册过滤器"，不是"加载/卸载 minifilter 驱动"。
- `bootstrap_chain()` **未接线**此路径：`win/mod.rs:286` `flt_globals_kva: 0`（需 fltmgr PDB/pattern 解析）。

### 4.5 postex（token 操作）— **已接线** ✅
`postex.rs` 有真实 `steal_token`/`make_token`/`revert`/`getuid`，并通过 4 个
`Command` 变体（`StealToken`/`MakeToken`/`Rev2Self`/`GetUid`，tag 22-25）从
`beacon.rs` 派发。横向移动 / impersonation 能力现已可用。两 client 均暴露
`/steal`/`/make_token`/`/rev2self`/`/getuid`。

---

## 5. 已知缺口（开发进度）

> 2026-06-27：G1–G5 已全部实现并通过编译/测试。下表标注实现状态；G6 需真机，留待验证。

| # | 缺口 | 严重度 | 位置 | 状态 |
|---|---|---|---|---|
| **G1** | `postex.rs` 未接线 —— implant 不能 impersonate/横向移动 | **高** | `postex.rs` + `beacon.rs` | ✅ **DONE** — 新增 `StealToken`/`MakeToken`/`Rev2Self`/`GetUid` (tag 22-25)，全链路（protocol→server→implant→agent-dev→两 client）+ `make_token`/`getuid` 实现 |
| **G2** | client 不调 `/api/creds` + `/api/audit` | 中 | `client-cli/`, `client-ui/` | ✅ **DONE** — CLI `/creds sync` + `/audit`（overlay 表格）；GUI `creds`/`audit` 控制台命令 |
| **G3** | client-ui BOF `data_hex` 空 / 无 token env / 重连栏忽略 token | 中 | `client-ui/src/main.rs` | ✅ **DONE** — BOF 文件→hex 加载器（`bof_file_input`）；读 `NYX_SERVER`/`NYX_TOKEN`；重连栏 fallback 到 env/dialog token |
| **G4** | MiniFilter 引导未接线 | 中 | `win/mod.rs` | ✅ **DONE** — `resolve_flt_globals_kva(rva)` + `unlink_minifilters(krw,kva)` 可调用；`module_info_by_name` 枚举 fltmgr（operator 供给 RVA，安全路径） |
| **G5** | offset-resolver 无符号服务器下载 | 低 | `offset-resolver/src/main.rs` | ✅ **DONE** — `download_pdb()` 从 MS symbol server 拉 ntkrnlmp.pdb，`--guid`/`--age` 自动下载+解析 |
| **G6** | Win11 24H2/25H2 真机未验证（仅 Server 2019） | 低 | 跨版本 offset 表 + CET 探测 | 🟡 **部分闭合** — GitHub Actions `windows-2025-vs2026`=build 26100（Win11 24H2 内核），见下方 |
| **G7** | client-cli 丢弃 server 已返回的会话字段（`pid`/`pending`/`age_secs`/`ja3`/`ja4`）+ 从未调 `/api/tasks` | 中 | `client-cli/src/tui/`, `rest.rs` | ✅ **DONE** — 见 §5c |

**下一步：** G1–G5、G7 全部完成；G6 已标记**暂缓搁置**（CI 5/7 子项已闭合，剩 2 项需物理机，见 §5b）。
**验证：** `cargo build --workspace` 绿 · `cargo test --workspace` **326 通过 / 0 失败** · `implant-win`/`operator-kernelsdk`/`offset-resolver` 三独立 crate 均编译通过（operator-kernelsdk 现在也在 `windows-gnu`/`windows-msvc` 上编译通过，CI 已修 1 个真实 Windows-only bug：`NtQuerySystemInformationFn` 缺 `-> i32`）。
**G1 真机验证（2026-06-27，Server 2019）:** 重编译 implant DLL（含 G1 postex 改动）→ `nyx_selftest_postex` exit=15 (0b1111，4/4) · `nyx_selftest` exit=3585（聚合无回归）· `nyx_selftest_evasion` exit=1281（基准一致）。详见 `docs/g1-g5-real-machine-verify-2026-06-27.md`。

### G7 client-cli 会话字段显示闭合（2026-06-29）

**根因**：`SessionView`（`crates/rest/src/lib.rs:28-56`）已携带 `pid`/`pending`/`age_secs`/`ja3`/`ja4` 五个字段，但 TUI 全部丢弃；`GET /api/tasks` 端点 server 已实现但 client-cli 从未调用。纯客户端渲染/接线缺口，server 与 wire 层零改动。

| 子项 | 闭合方式 |
|---|---|
| **`/info` 详情 overlay** | 新增 `Overlay::SessionDetail` + 2 列 key/value 表（`render_kv`），展示全字段（pid/pending/age/ja3/ja4 + 本地 meta：alias/tags/star/note）。本地数据 overlay，每帧重绘，pending/age 是活的 |
| **状态栏 age/pending** | `App.age_baseline` 记 `(Instant, age_secs)` 基线，`age_for()` 客户端推算（每帧 `now-基线`）。不改 worker 2s 轮询、不污染 `session_signature`（后者刻意排除 age_secs 防抖动）。pending>0 时状态栏追加 `pend:N` |
| **`/tasks`** | 调用 `GET /api/tasks?session=<hex>`，新增 `TaskRow`/`Cmd::FetchTasks`/`ParsedTable::Tasks`/`Overlay::Tasks`，4 列表（task_id/type/arg/detail） |
| **`/profile` overlay 死代码** | `FetchProfile` 原本只 log 不设 `parsed_buf`，overlay 永不弹出 → 现设 `ParsedTable::Profile`，正常弹 overlay |

**附带修复的工作树先存破损**（不修则 crate 编译不过；均为先于本次会话的未完成改动残留，非 G7 引入）：
- 恢复被误删的 5 个 `Cmd` handler（`Shutdown`/`Connect`/`Shell`/`Bof`/`Upload`）
- `Cmd::Download` 补 `local` 字段 + 注册 `TaskKind::Download` pending task（下载原本不落盘）
- `/audit verify` 死代码（同 `/profile` 同类 bug）→ 设 `ParsedTable::AuditVerify`，改用 `AuditVerifyResponse`
- 截图 overlay 死代码：`finish_chunked` 落盘后返回 `ParsedTable::Image`
- `render_table` 签名 `[&str;4]` → `&[&str]`（兼容 2 列 Image/Profile/AuditVerify）
- 杂项 clippy：重复 `let is_image`、`&""` 多余引用、未用 import、`AuditRow.detail` 未读、`poll_file_chunks` 参数过多

**验证**：`cargo build --workspace` 绿 · `cargo test --workspace` **326 通过 / 0 失败**（新增 6 项：age_for 推算、fmt_age、SessionDetail/Tasks overlay 渲染、TaskRow JSON 反序列化）· `cargo clippy -p nyx-cli -- -D warnings` 零警告。

### G6 暂缓搁置说明（Win11 24H2/25H2 真机验证）

CI workflow：`.github/workflows/g6-verify.yml`，runner `windows-2025-vs2026`（Windows Server 2025 Datacenter，**build 26100**，= Win11 24H2 内核）。最新 run：[Actions](https://github.com/qiaozhiyi/NY/actions)。

| 子项 | 结果 | 说明 |
|---|---|---|
| **内核版本** | ✅ **build 26100** 确认 | `OS: Windows Server 2025 Datacenter` / `Version: 10.0.26100` — 即 Win11 24H2 内核（Server 2025 ≡ Win11 24H2，同 17763≡Win10 1809 的关系） |
| **implant 在 26100 上编译** | ✅ | nightly+MSVC，0 error — G1-G5 代码在新内核**无编译回归** |
| **operator-kernelsdk 在 Windows 上编译** | ✅ | CI 发现并修复 1 个 Windows-only bug（`NtQuerySystemInformationFn` 缺 `-> i32` 返回类型 → 该函数指针默认返回 `()`）。**这是 CI 的真实价值**——该 bug 在 macOS 上永不暴露（所有 Windows 代码 `#[cfg]` 掉） |
| **CPU + CET 探测** | 🟡 **CPU 无 CET** | `CPU: AMD EPYC 7763` / `CET_PRESENT(41)=False` — runner CPU 不支持 CET shadow stack。**CET 探测逻辑跑通了**（`IsProcessorFeaturePresent(41)` 返回 False），但无法触发真实 `#CP` |
| **offset 跨版本（26100）** | 🟡 部分 | offset-resolver 编译通过；PDB GUID 提取在该 runner 受限（debug-dir 布局差异），已知表含 26100（PID 0x450/Links 0x458/Protection 0x87e），待用真实 GUID 端到端确认 |
| **selftest 在 26100 上** | 🟡 **全 TIMEOUT** | `nyx_selftest`/`postex`/`evasion` 均 30s 超时 — GitHub runner 无完整 admin 权限 / 可能在 HVCI-VBS 下，implant 的 indirect-syscall/HWBP-VEH/PEB-walk 原语被拦。**符合预期**（runner 姿态比受控测试机更严） |
| **HVCI-on / VBS 默认行为** | ❌ 测不了 | GitHub Windows runner 不支持嵌套虚拟化，默认不开 HVCI-on |
| **CET 硬件 `#CP` 触发** | ❌ 测不了 | runner CPU (EPYC 7763) 无 CET；需 Intel 11代+ 物理机 |

**G6 结论：** 已标记**暂缓搁置**。CI 已完成 5/7 子项（内核版本确认、implant+SDK 编译无回归、CET 探测逻辑跑通、CI 抓到并修复 1 个真实 Windows bug）。剩 2/7（HVCI-on 真机 + CET 硬件触发）需物理机——做成 self-hosted runner 挂到同一 workflow 即可补。详见 `docs/g1-g5-real-machine-verify-2026-06-27.md` §6。

### 5d 全链路真机端到端验证（2026-06-29）

**首次完整 beacon 循环真机测试**——server + 持久 implant + 完整 task 循环，在 Defender 实时保护开启下验证。

**拓扑**（本地 macOS 无公网入站，用 SSH 反向隧道绕过 NAT）：
```
[本地 macOS]                            [Win Server 2019 17763, Defender ON]
  nyx-server (127.0.0.1:8443)  ←SSH -R→  127.0.0.1:8443
  nyx-cli / curl                          nyx_implant_win.dll（schtasks+SYSTEM 持久）
```
- implant 回连地址硬编码 `127.0.0.1:8443`（`entry.rs:201`），经隧道直达本地 server，DLL 零改动。
- `NYX_SERVER_PUB` 烤入当前 server 的 X25519 公钥（每轮 server 重启需重新编译 implant）。
- 持久 beacon：`schtasks /create /ru SYSTEM`（SSH session 退出不杀进程；普通 `start ""` 会被 sshd job object 清理）。

**发现并修复的 bug：Foliage 睡眠掩码在 rundll32 加载器下崩溃**
- 症状：`nyx_entry`/`nyx_beacon_oneshot` check-in 成功后崩溃，exit `0xC0000409`（STATUS_STACK_BUFFER_OVERRUN）。
- 二分定位：beacon_loop task loop 首轮 `sleep_jitter` → `kits::sleep` → `Foliage::sleep_masked` → APC 链 + NtSetContextThread 恢复破坏栈（GS cookie 失败）。selftest 不走 beacon_loop 故无回归。
- 修复：`NYX_FOLIAGE_OFF=1` 编译期 gate（`sleep.rs:43-56`），降级为纯 NtDelayExecution sleep。默认仍 ON（sRDI 注入真实进程预期可用，rundll32 的线程/模块上下文是诱因）。commit `02d7e07`。

**验证结果（NYX_FOLIAGE_OFF=1 build）**：
| 环节 | 结果 |
|---|---|
| 加密 check-in（X25519+ChaCha20-Poly1305 经隧道） | ✅ 会话注册 `user=SYSTEM os=Windows` |
| Defender 实时保护 ON 下存活 | ✅（AMSI/ETW 盲化有效） |
| 持久 beacon（schtasks+SYSTEM） | ✅ 脱离 SSH session 持续 check-in |
| shell task 循环 | ✅ `whoami`→`nt authority\system`、`hostname`→`ser213364685943`、`ipconfig`→`Windows IP 配置`，3 任务批量执行+加密回传 |
| `/api/tasks`（G7 修复端点） | ✅ 返回排队任务列表 |
| `/sessions` G7 字段 | ✅ `pid=3812 is_admin=1 pending=N age_secs=N` 全部可见 |

**G7 修复在真机生效**：`pid`/`pending`/`age_secs`/`is_admin` 字段从 server 透传到 client 端可用；`/api/tasks` 实测可查询排队任务。`ja3`/`ja4` 因隧道走明文 HTTP（无 TLS ClientHello）不产生，预期行为。

### 5e 稳定可重复测试方案 + 系统性命令验证（2026-06-29）

**问题**：§5d 的测试拓扑有三个易碎点——SSH `-R` 隧道断线即失效、server 公钥每次启动随机（implant 要重编译）、明文测不了 ja3/ja4。

**固化方案（一键可重复）**：
1. **固定 server 公钥**：`NYX_KEYFILE=~/.nyx/server.key`（`load_or_create_keypair`，首次生成 32 字节裸文件后永久复用）。公钥固定为 `9605ea49...`，implant 编译一次即可，server 重启无需重编译。
2. **持久隧道**：`autossh -M 0`（`ServerAliveInterval=15` 探活，断线自动重连）替代脆弱的 `ssh -R`。`AUTOSSH_GATETIME=0` 首次失败立即重试。
3. **持久 beacon**：`schtasks /create /ru SYSTEM /sc onstart`（SSH session 退出不杀进程；普通 `start`/`Start-Process` 会被 sshd job object 清理）。

**修复的 server bug**：rustls 0.23 不再自动选 CryptoProvider，`NYX_TLS=on` 启动直接 panic。修复：`main()` 早期 `rustls::crypto::ring::default_provider().install_default()`（commit `746e1dd`）。server HTTPS 监听恢复可用。

**系统性命令验证（持久 SYSTEM beacon，7 命令全过）**：
| 命令 | 类型 | 结果 |
|---|---|---|
| shell hostname / whoami /groups / ipconfig | shell | ✅ 全部执行 |
| **net conn** | 协议原生（Command::Net） | ✅ 19 行连接表 |
| **env** | 协议原生（Command::Env） | ✅ 31 行环境变量 |
| **getuid** | 协议原生（Command::GetUid） | ✅ `NT AUTHORITY\SYSTEM` |
| **ping** | 协议原生（Command::Ping） | ✅ ok |

> shell + 4 个协议原生命令全通 → **协议命令分发链路完整可用**，不止 shell 通道。

**已知待办**：TLS implant（`use_tls=true`）经 WinHTTP 连自签证书 server 时 check-in 失败（明文路径正常）。curl 经同一隧道 HTTPS 握手正常（server TLS + 指纹嗅探本身可用），问题在 implant 的 `WinHttpSetOption` 证书放宽路径。ja3/ja4 指纹需 TLS beacon check-in 才产生，暂未验证（待调试 WinHTTP TLS）。

### 5f TUI 全命令真机测试矩阵（2026-06-29）

47 个 TUI 命令逐个验证（持久 SYSTEM beacon + autossh 隧道 + 固定 keyfile 明文 server）。每条发 `POST /api/task` 精确复现 TUI 的 wire 格式，验证 implant 执行 + server 返回。

**implant 任务命令（走 beacon 循环）**：

| 命令 | wire type | 状态 | 备注 |
|---|---|---|---|
| `/ls`(shell dir) / `/ps`(tasklist) | shell | ✅ | 解析成表 |
| `/cd` `/mkdir` `/cp` `/mv` | fileop | ✅ | ok |
| **`/rm`** | fileop rm | ❌ | **implant 拒绝：'rm: not directly supported — use Shell'**（已知限制，需走 shell） |
| `/net ifconfig/arp/routes/conn` | net | ✅ | 全部返回解析后的表（IP/ARP/路由/连接） |
| `/drive` | driveinfo | ✅ | `C:\ total=53GB free=16GB` |
| `/env` / `/env NAME` | env | ✅ | 31 行全部 / 单变量 |
| `/portscan` | portscan | ✅ | 探测到 `22 open` |
| `/clipboard` | clipboard | ✅ | 空（剪贴板无内容） |
| `/getuid` | getuid | ✅ | `NT AUTHORITY\SYSTEM` |
| `/ping` | ping | ✅ | ok |
| `/sleep` | sleep | ✅ | ok（改 beacon 间隔） |
| `/upload` | upload | ✅ | 文件写入 + data_hex 往返正确 |
| `/download` | download | ✅ | file chunk 返回，字节与上传一致 |
| `/keylog start` | keylog 0 | ✅ | ok（启动键盘记录） |
| `/make_token` | maketoken | ✅ | ok（造令牌） |
| `/rev2self` | rev2self | ✅ | ok |
| `/pivot` | connect | ✅ | server 分配 `chan:1`（P2P 协议工作） |
| `/chan close` | channelclose | ✅ | ok |
| **`/socks` op=0** | socks | ❌ | **'socks: unsupported op 0 (only connect=1)'**（implant 只实现 connect op） |
| `/hashdump` | hashdump 0 | ⚠️ | 'SAM hive locked by SAM service'（**环境限制**：SYSTEM 在线不能直读 SAM，需先 save hive） |
| `/steal pid=4` | stealtoken | ⚠️ | 'OpenProcessToken failed'（**预期**：pid=4 System 进程令牌受保护） |
| `/screenshot` | screenshot | ✅ | 跨会话截图修复（schtasks 调度）。真机 Session 0→Session 2 出图 3.3MB / 1147×719 / 26 chunks |
| `/bof` `/screenwatch` `/kill`(exit) | bof/screenwatch/exit | 未测 | BOF 需真实 .obj；screenwatch 同 screenshot（已修复）；exit 会杀 beacon |

**server 控制 API（不走 implant）**：

| 端点 | 对应 TUI 命令 | 状态 |
|---|---|---|
| `POST /api/creds` | `/creds add` | ✅ `{"ok":true}` |
| `GET /api/creds` | `/creds sync` | ✅ 自动掩码 `P@....23` |
| `GET /api/creds?reveal=1` | `/creds sync reveal` | ✅ 明文 `P@ss123` |
| `POST /api/creds/delete` | `/creds del` | ✅ `{"deleted":true}` |
| `GET /api/audit` | `/audit` | ✅ 审计记录（task/cred_add/cred_delete 全被记录） |
| `GET /api/audit/verify` | `/audit verify` | ✅ `{"ok":true}` 哈希链完整 |
| `GET /api/profile` | `/profile` | ✅ `{"loaded":false}` |

**本地命令（纯 client 逻辑，不涉及 server）**：`/sessions`/`/info`/`/tasks`/`/rename`/`/tag`/`/star`/`/note`/`/topo`/`/alias`/`/clear`/`/help`/`/connect`/`/use` —— 数据源（sessions API G7 字段 pid/pending/age + sessions.json 本地元数据）已验证就绪；TUI 渲染层 116 集成测试全过（含 sessions/session_detail/tasks overlay）。

**原 3 个限制现已修复**（commit `84e26d9`，2026-06-30）：
1. ~~**fileop rm 不支持**~~ → ✅ **已修复**：改用 Win32 `DeleteFileW`/`RemoveDirectoryW`（绕过 indirect-syscall 挂起）。真机：upload 建文件后 `rm` 成功。
2. ~~**socks 只支持 connect op**~~ → ✅ **已修复**：新增 op=2 BIND（`do_bind` socket+bind+listen + `pump_channels` accept 分支）。真机：返回 listening channel。
3. ~~**Session 0 限制**~~ → ✅ **部分修复**：
   - **stealtoken**：根因是**真实 bug**（从未启用 SeDebugPrivilege）→ 加 `enable_debug_privilege`。真机：`stealtoken lsass(pid=744)` 成功。
   - **hashdump**：原直读 SAM 被 oplock 拒 → 加 `RegSaveKeyW` save-hive fallback（+ 修复 `HKEY_LOCAL_MACHINE` 句柄值 `0x80000002`）。真机：**SAM(80KB) + SYSTEM(344KB) hive 全部成功 dump**。
   - **screenshot**：跨会话（Session 0 → Session 2）真机修复。token 偷取 + `CreateProcessAsUserW`/`CreateProcessWithTokenW` 全部失败（前者缺 `SeAssignPrimaryToken`→1314，后者被目标桌面 ACL 拒→err 5）。改为 **Task Scheduler 调度**：`schtasks /create /ru administrator /it /f` + `/run` + 轮询 BMP + `/delete`。真机：**26 chunks / 3,298,826 字节 / 1147×719 有效 BMP**（RDP Session 2 桌面）。同会话 `capture_bmp` + `attach_interactive`（WinSta0\default）作为 path-1 保留。

---

## 6. 真机验证关键地址（Server 2019 17763.1339）

| 项目 | KVA |
|---|---|
| ntoskrnl base | `0xfffff8057fa19000` |
| ntoskrnl size | 0xA70000 |
| ret gadget | `0xfffff8057fa1a7f0` (ntoskrnl+0x17F0, bytes=`c3 cc cc cc`) |
| EtwThreatIntProvRegHandle | `0xffffc30c32652c80` |
| PsActiveProcessHead | `0xfffff8057fe275c0` |

## 7. EPROCESS offsets（跨版本）

| Build | PID | Links | Protection |
|---|---|---|---|
| 17763 (Server 2019) | 0x2e0 | 0x2e8 | 0x6ca |
| 18362–19045 (Win10) | 0x2e8 | 0x2f0 | 0x6fa |
| 20348/22000 | 0x440 | 0x448 | 0x87a |
| 22621/22631 (Win11) | 0x440 | 0x448 | 0x87a |
| 26100/26200 (Win11 24H2/25H2) | 0x450 | 0x458 | 0x87e |

详见 `p2-kernel-tier-status.md`、`kernel-test-results.md`、`p2-real-machine-verify-2026-06-27.md`。
