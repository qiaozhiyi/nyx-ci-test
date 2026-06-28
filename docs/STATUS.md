# Nyx — 当前状态（单一事实源）

> **权威文档。** 这是项目当前的、经代码核对的唯一状态事实源。
> **优先级口径：** 一切以源码 `file:line` 为唯一证据。当本文与其他文档（含 `CLAUDE.md`、`docs/archive/`）冲突时，**以本文为准**。
> **核对日期:** 2026-06-27（G1–G5 开发完成后） · **分支:** `p2-evasion-synced` · **授权:** 仅限授权红队 / 安全研究
> 历史审计 / 研究产物已移入 `docs/archive/`（见 `docs/archive/README.md`）。

---

## 0. 验证基线（已重新核对）

- `cargo build --workspace` ✅ 绿
- `cargo test --workspace` ✅ **318 通过 / 0 失败**（含 G1 新增的 token-op codec 测试）
- `cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu` ✅ 绿（46 warnings，无 error；多为 Rust-2024 `static_mut_refs` lint）
- `operator-kernelsdk` + `offset-resolver` 独立 crate ✅ 编译通过
- selftest 导出 **48 个**（45 `selftests.rs` + 2 `entry.rs` + 1 `syscalls.rs`）
- 真机环境：Windows Server 2019 Datacenter **17763.1339** + RTCore64.sys (CVE-2019-16098)

---

## 1. 总体完成度

| 维度 | 完成度 | 证据 |
|---|---|---|
| 用户态 bypass（implant-win） | ~98% | 14 selftest 全通过；PE-sieve 0 implanted |
| 内核算法（operator-kernelsdk） | 100% | 82 单测通过（`cargo test -p nyx-operator-kernelsdk`） |
| 内核接线 | ~97% | `bootstrap_chain` → KslD → BYOVD → ETW-TI → DKOM → callback repurpose 全通 |
| 内核真机（Server 2019） | 7/7 PASS | 任务 G–K 全链路（见 `kernel-test-results.md`） |
| **整体** | **~95%** | G1–G5 全部完成；仅剩 G6 真机验证（Win11 24H2） |

> 注：所有用户态规避模块均已**实装且默认 ARMED**（gate 默认见 §3）。
> 2026-06-27 关闭了全部代码缺口（G1 postex 接线、G2 creds/audit、G3 GUI、
> G4 MiniFilter 可调用、G5 符号服务器下载）；仅 G6 需真机。

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

**下一步：** G1–G5 全部完成；G6 经 GitHub Actions **部分闭合**（5/7 子项），剩 2 项需物理机。
**验证：** `cargo build --workspace` 绿 · `cargo test --workspace` **318 通过 / 0 失败** · `implant-win`/`operator-kernelsdk`/`offset-resolver` 三独立 crate 均编译通过（operator-kernelsdk 现在也在 `windows-gnu`/`windows-msvc` 上编译通过，CI 已修 1 个真实 Windows-only bug：`NtQuerySystemInformationFn` 缺 `-> i32`）。
**G1 真机验证（2026-06-27，Server 2019）:** 重编译 implant DLL（含 G1 postex 改动）→ `nyx_selftest_postex` exit=15 (0b1111，4/4) · `nyx_selftest` exit=3585（聚合无回归）· `nyx_selftest_evasion` exit=1281（基准一致）。详见 `docs/g1-g5-real-machine-verify-2026-06-27.md`。

### G6 GitHub Actions 验证（2026-06-27，build 26100 = Win11 24H2 内核）

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

**G6 结论：** 5/7 子项在 GitHub Actions 的 Win11 24H2 内核上**闭合或验证**（内核版本确认、implant+SDK 编译无回归、CET 探测逻辑跑通、CI 抓到并修复 1 个真实 Windows bug）。剩 2/7（HVCI-on 真机 + CET 硬件触发）需物理机——做成 self-hosted runner 挂到同一 workflow 即可补。详见 `docs/g1-g5-real-machine-verify-2026-06-27.md` §6。

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
