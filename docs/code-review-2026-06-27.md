# Nyx C2 — 逐函数代码 Review 记录

> **日期:** 2026-06-27 · **分支:** `p2-evasion-synced`
> **方法:** 对承载 P0 路径的 8 个核心文件逐函数/逐变量 review，每条带 `file:line` 证据 + 严重度
> **覆盖:** blind_hwbp.rs / stack.rs / syscalls.rs(spoof 路径) / sleep.rs / mem.rs / context.rs / telemetry.rs / persistence.rs(PG) / ksld.rs / netsec.rs(WFP+LSASS)
> **授权:** 仅限授权红队 / 安全研究

严重度图例：🔴 阻塞/P0 · 🟠 正确性 bug（会崩或行为错） · 🟡 检测面/IOC · 🔵 加固建议

---

## 0. 先说结论：Tier-0 修复现状

经 git working tree 核实，**Tier-0 四项已在工作区落地**（未提交，未编译验证）：

| 项 | 状态 | 证据 |
|---|---|---|
| 0-A gate 矛盾 | ✅ 已修 | `stack.rs:82` `false` + docstring 一致；`sleep.rs:40`/`inject.rs:56` docstring 对齐 |
| 0-B HWBP diag 下线 | ✅ 已修 | `blind_hwbp.rs:105` `if !DIAG_ENABLED { return }` + `:94` default false |
| 0-C repurpose selective | ⚠️ 部分修 | `telemetry.rs:147` 只跳 `i==0`，**未跳其他 ntoskrnl 内部 slot**（见 R1） |
| 0-D threadless trigger | ✅ 已修 | `inject.rs:605` `sc_addr = trigger_addr`（不再 `let _ =`） |

**但 0-C 的修复不完整**，且 review 又发现 5 个新问题。下面逐条列。

---

## 1. blind_hwbp.rs（595 行）

### 函数清单（职责）
| 函数 | 行 | 职责 | 评价 |
|---|---|---|---|
| `ShadowType` enum | 23-27 | ETW/AMSI shadow 选择 | OK |
| `diag(ch)` | 104-151 | selftest 写 marker 到 `C:\nyx\hwbp_diag.txt` | ✅ 已 gate（`DIAG_ENABLED`） |
| `set_diag_enabled` | 97-99 | 运行时开关 diag | OK |
| `init_shadow_buffer()` | 155-191 | VirtualAlloc RWX + 写两个 shadow stub | ⚠️ 见 R2 |
| `shadow_addr(st)` | 193-201 | shadow stub 地址映射 | OK |
| `vehtag(ch)` | 217-225 | VEH 诊断 hex 缓冲 | ⚠️ 见 R3 |
| `read_veh_diag()` | 228-230 | 读 VEH 诊断缓冲 | OK |
| `hwbp_veh_handler(ep)` | 233-323 | VEH 主逻辑：DR6 判定→RIP 重定向→RF | ⚠️ 见 R4 |
| `ctx_write/read_*_at` | 328-340 | CONTEXT 缓冲读写 | OK |
| `add_hwbp(target, st)` | 348-495 | 设 DR0 + DR7 + 注册 VEH | ⚠️ 见 R5 |
| `remove_hwbp(slot)` | 498-561 | 恢复 DR7 + 摘 VEH | OK |
| `free_ctx_buf(buf)` | 564-572 | VirtualFree MEM_RELEASE | OK |
| `blind_etw_hwbp()` | 583-587 | HWBP on NtTraceEvent | OK |
| `blind_amsi_hwbp()` | 590-594 | HWBP on AmsiScanBuffer | OK |

### 发现

**R2 🟡 — shadow buffer 是 RWX（`blind_hwbp.rs:173`）**
`VirtualAlloc(..., 0x3000, 0x40)` —— `0x40` = `PAGE_EXECUTE_READWRITE`。shadow stub 只有 14 字节代码，初始写完后再没改过。RWX 私有页是 Moneta/EDR 的明确指标。**应为 RW 写完→VirtualProtect 改 RX**，消除 RWX-at-rest。这与 HWBP "patchless" 的卖点（零 RWX、零 VirtualProtect-on-code）直接矛盾——shadow buffer 的 RWX 暴露了存在。

**R3 🟡 — `vehtag` 无条件写 `VEH_DIAG_BUF`（`blind_hwbp.rs:234`）**
`hwbp_veh_handler:234` 第一行 `vehtag(b'V')` 无 gate。`VEH_DIAG_BUF` 是内存缓冲不落盘（severity 比 diag 低），但每次异常都写，且 `vehtag` 里 `POS` 是 `static mut`（`:218`），VEH 可重入（异常嵌套）时有数据竞争。**应同样 gate 在 DIAG_ENABLED 后，或用 atomic POS。**

**R4 🟠 — VEH 命中校验用 `ExceptionAddress`（`blind_hwbp.rs:285-286`）**
```rust
let fault_addr = read_unaligned(exr.add(0x10));  // ExceptionAddress @ +0x10
if fault_addr == e.target || rip == e.target { ... }
```
`ExceptionRecord.ExceptionAddress` 偏移是 `0x10` ✅（正确）。但逻辑是 "fault_addr OR rip == target"——若别的线程/代码恰好 RIP 落在 target（比如 ETW 自己合法调用），会被误重定向。**HWBP 是 per-thread 的（DR7 L0=local），单线程 beacon 不会误触**，所以实际风险低，但跨线程场景（helper 线程也调 NtTraceEvent）会误伤。文档应标注 per-thread 假设。

**R5 🟠 — `add_hwbp` DR7 槽位写死 slot 0（`blind_hwbp.rs:446/471`）**
```rust
ctx_write_u64_at(base, CTX_DR0, target_addr);  // 只写 DR0
new_dr7 |= 1u64;  // 只设 L0
```
但 `HWBP_ENTRIES` 是 4 槽数组（`:87`），`add_hwbp` 选了 `slot`（`:359`）却**永远写 DR0/DR7-bit-0**。即第 2 个 HWBP（blind_amsi_hwbp）会覆盖第 1 个（blind_etw_hwbp）的 DR0。**结果：ETW + AMSI 同时 blind 时，AMSI 踩掉 ETW。** 这是真 bug——ETW blind 静默失效。修法：按 `slot` 写 `CTX_DR0 + slot*8` 和 `DR7 |= 1 << (slot*2)`，R/W0/LEN0 bits 按 slot 偏移。

---

## 2. stack.rs（487 行，spoof 路径）

### 函数清单
| 函数 | 行 | 职责 | 评价 |
|---|---|---|---|
| `set_gap_pool(pool)` | 108-110 | 安装全局 GapPool | OK |
| `gap_pool_rip()` | 127-131 | 取首个 gap 地址（Foliage 用） | OK |
| `StagedChain::stage(pool)` | 155-172 | 合成 leaf-bridge 链 | OK |
| `stage_for(pool)` | 201-205 | stage + 记录 depth | OK |
| `spoof_wrap(f)` | 225-230 | syscall 热路径 hook | OK |
| `with_spoofed_stack(gaps, f)` | 254-277 | 决策：swap/degrade | OK（gate=false 后安全） |
| `cet_active()` | 283-285 | 探测 PF_CET=41 | OK |
| `do_rsp_swap(chain, f)` | 317-437 | 真 `mov rsp` asm 执行 | ⚠️ 见 R6/R7 |
| `spoof_trampoline()` | 454-466 | asm call 的具体跳板 | OK |
| `run_f_on_spoof<T,F>` | 477-481 | per-单态化桥 | OK |

### 发现

**R6 🔴 — `do_rsp_swap` 假 RSP 链布局错误（`stack.rs:344-353`）**
```rust
let depth = chain.slots().len().min(cap / 2);
let rsp_idx = cap / 2 - depth;
for (i, &slot) in chain.slots().iter().take(cap/2).enumerate() {
    *buf.add(rsp_idx + i) = slot;  // chain[0] 在 rsp_idx，chain[last] 在 rsp_idx+depth-1
}
let mut fake_rsp = buf.add(rsp_idx) as usize;  // RSP 指向 chain[0]
```
注释（`:347-349`）说 "[RSP] 必须是 LAST-queued frame (innermost)"，但代码把 `chain[0]`（outermost）放在 RSP 处。栈回溯从 `[RSP]` 开始，应该先看到 innermost（最近调用），再往上 outermost。**当前布局让回溯看到反序**——首个 frame 是最外层而非最近层。这对短回溯（EDR 通常看前几帧）可能仍"看起来像合法 DLL 地址"，但与 `frame::build_leaf_bridge` 的语义不符。需验证 EDR 实际读帧顺序后定夺。严重度取决于检测器实现。

**R7 🟠 — `spoof_wrap` 在 `swap_enabled()==false` 时仍 stage（`stack.rs:256`）**
`with_spoofed_stack:256` 无条件 `stage_for(gaps)`，即使 swap 关。stage 分配 `Vec<u64>` 并写全局 `LAST_STAGED_DEPTH`——每次 syscall 都分配，**热路径有 allocator 开销**。CET-on 主机（swap 永久关）每次 syscall 白分配。修法：`if !swap_enabled() && !cet_safe_for_staging() { return f() }` 提前返回。

---

## 3. syscalls.rs spoof 接入（`syscallN` × 4）

`syscall4/5/6/11`（`:310/335/363/396`）各自包 `spoof_wrap(|| {...})`。**确认全部接入** ✅。由于 R7，这 4 个热路径在 swap 关时都有 stage 开销。

---

## 4. sleep.rs（747 行）+ mem.rs（248 行）+ context.rs（215 行）

### heap-mask 缺口（P0 核心，确认）
- `sleep.rs:110` `own_text_region()` 只读 PEB→ImageBase→`.text`，**无 heap 枚举**
- `sleep.rs:626` `foliage_helper` mask 范围 = `[base, base+len)` = 纯 `.text`
- `mem.rs:41` `MAX_REGIONS=8`，`mem.rs:142` `apply_rc4_to_regions` 只遍历 8 个注册槽
- `mem.rs:90` `register_key` 只注册 32B ECDH key
- **结论：sleep 期间 beacon config blob / token cache / bof 输出缓冲 全部 heap 明文。** BeaconEye/MalMemDetect 命中面完全没盖。

### 其他发现
**R8 🟠 — `mask_text`/`unmask_text` 用全局 runtime，Foliage helper 用 raw export（`mem.rs:218` vs `sleep.rs:480`）**
`mem.rs:mask_text:218` 走 `crate::syscalls::global()`（共享 trampoline）；`sleep.rs:626` `foliage_helper` 走 raw export（注释 `:219-227` 说为避单 trampoline 竞态）。两套路径对同一 `.text` 操作，若 `mask_text` 在 helper 线程被误调会踩 trampoline。`mask_text` 的 doc（`:215`）说"caller MUST guarantee beacon thread not executing"——但没机制强制。建议 `mask_text` 加 `#[track_caller]` + 断言当前线程 != beacon 线程（难，no_std）或直接删 `mask_text`，Foliage 链自己内联（已是如此）。

**R9 🔵 — `spoofed_context` 用单全局 `CTX_BUF`（`context.rs:136`）**
`spoofed_context:153` 返回 `&mut CTX_BUF`。注释说"single-threaded beacon loop guarantees NtContinue fires before next call"。但 Foliage helper 线程也调它（`sleep.rs:674`）。helper 构建 ctx → queue APC → beacon NtContinue 消费。若 helper 在 beacon 消费前再次调 `spoofed_context`（连续两次 sleep cycle 紧邻），覆盖未消费的 ctx。实际单 helper 单 APC 序列下不触发，但脆弱。

---

## 5. telemetry.rs repurpose（`:126-174`）

**R1 🔴 — selective targeting 只跳 slot[0]，不跳其他 ntoskrnl 内部 slot（`telemetry.rs:147`）**
```rust
if i == 0 { continue; }  // 只跳 slot 0
```
真机映射（`examples/callback_owner_map.rs`）显示：slot[0]=ntoskrnl 内部、slot[2]=WdFilter、slot[5]=SysmonDrv、slot[9]=KslD。**但还有 ntoskrnl 的 PiDDB/GdikDef 等内部 slot 散布在其他 index。** 当前代码会把它们当 EDR callback 重定向 → triple fault（`neutralize` 在 K-A 真机已经验证 slot[0] triple fault，`:251`）。修法：不只是 `i==0`，而是按 `routine` 是否落在 ntoskrnl image range 过滤（`callback_owner_map.rs` 已有 read-only 映射逻辑，迁入即可）。

---

## 6. persistence.rs PG 窗口（`:228-441`）

**R10 🔴 — 三套 PG 窗口全是 no-op（确认未修）**
- `PatchGuardWindow::enter_unchecked:256` → 无条件 `Err(UnsupportedPosture)`
- `TimingRepairWindow::enter_unchecked:309` → 读 valid_flag 但 Drop `:351` 是 `let _valid_flag = valid_flag;`
- `RuntimePgBypassWindow::enter_unchecked:399` → 注释 `:426` "actual suspension is driver-side"，Drop `:438` 是 `let _ = pg_thread_kva;`

**含义：所有内核 DKOM（hide_pid/strip_protection）都靠"<1s 硬扛"，真机侥幸没 BSOD。这是内核层落地最大阻塞。** 计划见 plan doc Task-1-D。

**R11 🟠 — `RuntimePgBypassWindow` 返回 armed guard 但没真 suspend（`:430-440`）**
`enter_unchecked` 设 `armed=true` 返回 guard，但线程没被 suspend——guard 的存在让调用方**以为** PG 被冻，实际没冻，DKOM 仍暴露。这是比 R10 更危险的"假安全"——调用方基于错误假设操作。

---

## 7. ksld.rs（418 行）

**R12 🔴 — 设备名用字面量 `\\.\MpKsl`，真实 Defender 设备名带版本后缀（`ksld.rs:51-54`）**
头注释 `:42-50` 自己承认真实名是 `MpKslxxxx`（随 Defender 版本变），需 `IoGetDeviceObjectPointer(\Device\MpKsl*)` 动态解析。代码 `open()`（`:158`）直接用 `KSLD_DEFAULT_DEVICE = \\.\MpKsl`。**在真实 Defender-on 主机上 `CreateFileW(\\.\MpKsl)` 大概率失败**（设备名不匹配），bootstrap 回退 RTCore64。即 KslD 路径形同虚设。修法：用户态枚举——读 `HKLM\SYSTEM\CurrentControlSet\Services` 找 `MpKsl` 前缀的 device，或 `QueryDosDeviceW` 枚举 `\Device\` 匹配 `MpKsl*`。

**R13 🔵 — IOCTL 包 size 是 u32 但循环按 `0x1000` 切（`ksld.rs:211/252`）**
packet `KSLD_SIZE_OFF:4` 写 u32，chunk `.min(0x1000)` —— 0x1000 < u32::MAX，OK。但没校验 driver 实际是否支持跨页读。RTCore64 是单字节循环（byovd.rs），KslD 是 0x1000 块——两者协议假设不同，需对 KslDump 源码二次确认 size 字段语义。

---

## 8. netsec.rs（WFP `:99-214` + LSASS `:289-318`）

**R14 🟠 — WFP `num_filter_conditions=0` 全量 block（`netsec.rs:206`）**
注释 `:204-205` 自承 hack。PID 只进 `display_data`（`:211`）。**生产用会断全网出站**，不是 EDR 定向。修法：加 `FWPM_FILTER_CONDITION0` 数组，condition = `FWP_CONDITION_ALE_APP_ID`（按 EDR exe 路径）或进程 PID condition。

**R15 🟠 — LSASS `dump_lsass` 固定 4GiB+1MiB 盲读（`netsec.rs:314-315`）**
`user_mode_base = 0x1_0000_0000`（4GiB）+ `read_size = 0x100_000`（1MiB）。LSASS 关键结构（LogonSessionList、DPAPI keys、msv1_0/wdigest/tspkg）散布在更高地址，1MiB 盲读抓不到。`dump_lsass` 当前**不能产出可用凭据**。修法见 plan Task-4（KslKatz 风格 LogonSession walk）。

**R16 🔵 — `wfp_add_block_rules` 不关 engine handle（`netsec.rs:148-150`）**
注释说"intentionally NOT closed — filters persist while session open"。但函数返回后 handle 丢失（无 caller 持有）→ 泄漏 + filters 生命周期不明。应返回 handle struct 或显式 `FwpmEngineClose0`。

---

## 9. 汇总：按严重度

| # | 严重 | 文件:行 | 问题 | 修复工作量 |
|---|---|---|---|---|
| R10 | 🔴 | persistence.rs:256/351/438 | PG 三窗口全 no-op，内核 DKOM 全靠侥幸 | 高（计划 Task-1-D）|
| R12 | 🔴 | ksld.rs:51-54 | 设备名字面量，真机必失败 | 中 |
| R1 | 🔴 | telemetry.rs:147 | repurpose 只跳 slot[0]，ntoskrnl 内部 slot 仍 triple fault | 中 |
| R5 | 🟠 | blind_hwbp.rs:446/471 | DR7 写死 slot 0，第 2 个 HWBP 踩第 1 个 | 低 |
| R11 | 🟠 | persistence.rs:430-440 | RuntimePgBypass 返回假 armed guard | 高（并入 R10）|
| R14 | 🟠 | netsec.rs:206 | WFP 全量 block 非 PID 定向 | 中 |
| R15 | 🟠 | netsec.rs:314 | LSASS 盲读不出凭据 | 高 |
| R6 | 🟠/🔴 | stack.rs:344-353 | 假栈链顺序可能反（需 EDR 验证）| 中 |
| R7 | 🟠 | stack.rs:256 | swap 关时仍 stage，热路径开销 | 低 |
| R8 | 🟠 | mem.rs:218 vs sleep.rs:480 | mask_text/helper 两套路径踩 trampoline 风险 | 低 |
| R2 | 🟡 | blind_hwbp.rs:173 | shadow buffer RWX（与 patchless 卖点矛盾）| 低 |
| R3 | 🟡 | blind_hwbp.rs:234 | vehtag 无 gate + static mut 竞态 | 低 |
| R4 | 🟡 | blind_hwbp.rs:285 | VEH 命中校验跨线程误伤（per-thread 假设未标注）| 低 |
| R9 | 🔵 | context.rs:136 | 单全局 CTX_BUF 跨线程脆弱 | 低 |
| R13 | 🔵 | ksld.rs:211 | KslD size 字段语义未对源码确认 | 低 |
| R16 | 🔵 | netsec.rs:148 | WFP handle 泄漏 | 低 |

**P0 阻塞项（必须在内核层可用前修）：R1 + R10 + R12。** 修法见开发计划文档。

---

*本 review 基于 2026-06-27 工作区代码逐函数核实。每个结论带 `file:line`。Tier-0 四项已落地（0-C 部分修），review 新增 16 项发现（3 🔴 / 7 🟠 / 3 🟡 / 3 🔵）。*
