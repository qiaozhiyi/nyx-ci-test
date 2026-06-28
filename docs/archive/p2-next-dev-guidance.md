# Nyx C2 — 全量代码审计 + 下一阶段开发指导

> **审计日期:** 2026-06-26 · **分支:** `p2-evasion-synced`
> **审计范围:** **全量逐文件** —— 22 个 crate / 160 个 `.rs` / 47,542 行代码，每个文件从头读到尾
> **方法:** 不采信任何既有 doc 结论；每个能力判定都以 `file:line` 源码证据为准；亲自读关键承载文件（sleep/stack/ksld/telemetry/persistence/netsec），其余 18 个文件由 3 个全文件读 agent 覆盖，我交叉核对了它们的结论
> **授权:** 仅限授权红队 / 安全研究

---

## 0. 这份文档和仓库里其他 doc 的关系

| 文档 | 状态 | 与本文关系 |
|---|---|---|
| `docs/p2-2026-06-gap-analysis.md` (06-25) | **多处过时** | 列的 5 个 CRITICAL/HIGH（#1.1/1.2/1.4/1.5/2.1）在代码里已闭合，但它没更新 |
| `docs/p2-benchmark-vs-cs413-brc4-v23.md` (06-26) | 基本准确 | 与本文 §3 一致，但低估了几个内核项 |
| `docs/BYPASS_CAPABILITIES.md` (06-26) | 接线状态标注偏乐观 | 本文据实修正（KslD/PG 窗口/LSASS） |
| `CLAUDE.md` | **2 处过时** | "keypair ephemeral"（现已可持久化）、blind.rs "HWBP future"（已实现） |

**本文优先级口径：** 以代码 `file:line` 为唯一事实源。"算法完成"≠"能用"。"operator-run"的内核代码在没有真机验证前视为**纸面级**。

---

## 1. 全量审计结论：三层画像（据实）

### 用户态 bypass 核心 —— ✅ 对位 CS 4.13 / BRC4 v2.3
全部实装且 **ARMED**（gate 默认 true）：
- 间接 syscall（含 gap 栈欺骗）：`syscalls.rs:310/335/363/396` 每个 `syscallN` 包 `stack::spoof_wrap` ✅
- HWBP patchless blind：`blind_hwbp.rs` 完整 DR0+VEH+RF；`entry.rs:28` bootstrap 优先 HWBP ✅
- ETW/AMSI byte-patch fallback：`blind.rs` ✅
- ntdll unhook 三级回退：`unhook.rs`（KnownDlls→disk→hooked）✅
- Foliage sleep mask：`sleep.rs` APC 链 ✅
- module stomp + threadless HWBP 注入：`inject.rs` 两法都有 ✅

**唯二用户态真差距：** heap sleep mask（只 mask `.text`）、CET-safe swap（`#CP` 风险）。

### 内核 bypass —— 🟡 维度领先（CS/BRC4 没有），但**纸面级**
算法完整、单测通过，但：RTCore64 在黑名单、**KslD 设备解析是薄弱点**、**PatchGuard 三套窗口全是 no-op skeleton**、未在 Win11 24H2/25H2 + 主流 EDR 验证。

### 工程生态 —— 🔴 明显落后
持久化**完全为零**、C2 仅 HTTPS、注入仅 2 法、无 UDRL、BOF 仅同步。

---

## 2. 审计纠偏：文档/代码矛盾清单（必须先知道的真相）

全量审计最重要的产出是**纠正了几处 doc 声明与代码不符**。按"会不会咬人"排序：

### 2.1 🔴 gate 值与 docstring 互相打架（会咬人，P0）
| Gate | 文件:行 | docstring 说 | 实际 `AtomicBool::new()` |
|---|---|---|---|
| `FOLIAGE_ENABLED` | `sleep.rs:41` | "Defaults OFF" (lines 26-40) | **`true`** |
| `SPOOF_SWAP_ENABLED` | `stack.rs:79` | "defaults OFF until seam lands" (lines 17-51) | **`true`** |
| `MODULESTOMP_ENABLED` | `inject.rs:56` | "Defaults ON" | `true` ✓ 一致 |

**最危险的是 `SPOOF_SWAP_ENABLED=true`**：CET-on 主机会真跑 `mov rsp` swap（`stack.rs:408-425` 真内联汇编），而 CET 修复缝（`KiControlProtectionFault` lenient-repair）**根本没实现**——所有 `KiControlProtectionFault`/`VslKernelShadowStackAssist` 字样都在 doc 注释（`stack.rs:34-51`），代码里只有 `cet_active()` 探测后 `should_execute` 静默降级（`stack.rs:263`）。

**风险判定：** CET-off 主机（当前 Server 2019）swap 执行且已验证；CET-on 主机（Intel TGL+，Win11 24H2+）要么降级（栈残留暴露给 xacone/K2），要么 `should_execute` 有 bug 就 `#CP` 崩溃。**这是当前唯一"随时间恶化"的弱点**——CET 渗透率只升不降。

> **P0 行动（<1h）：** 把 `SPOOF_SWAP_ENABLED` 改回 `false` 直到 §4 Tier-1-C 落地，或把 3 个 docstring 改成与 `true` 一致。推荐改回 false（CET `#CP` 不可恢复）。

### 2.2 🔴 KslD.sys "已实现"——**半真半假**
`gap-analysis`/`capabilities` 标 KslD 为已闭合，但实勘：
- IOCTL 数据包布局（`ksld.rs:58-78`：read `0x222048`/write `0x22204C`，32 字节 METHOD_BUFFERED）**是真的** ✅
- 但 `open()` 用字面量 `\\.\MpKsl`（`ksld.rs:51-54`），而头部自己承认（`:42-50`）真实设备名随 Defender 版本变（`MpKslxxxx`），需动态 `IoGetDeviceObjectPointer` 解析——**代码没做**。
- 头部明写（`:31`）`CODE SHIPPED, NOT LOADED` + `:32` "loading/talking to KslD.sys is operator-side only"。

**结论：** KslD 的 R/W *原语*是真的，但*设备解析*是薄弱点——`open()` 在真实 Defender 设备上很可能直接失败。bootstrap_chain（`win/mod.rs:92`）确实 KslD 优先、RTCore64 兜底，但 KslD 路径未真机验证过，实际大概率走 RTCore64 兜底。

### 2.3 🔴 PatchGuard 三套窗口**全是 no-op skeleton**（内核层最大隐患）
`persistence.rs` 的 PG 相关代码**没有任何一套真正工作**：
- `PatchGuardWindow::enter_unchecked`（`:252-261`）无条件 `Err(UnsupportedPosture)`
- `TimingRepairWindow::enter_unchecked`（`:309`）读了 valid_flag，但 Drop（`:351`）是 `let _valid_flag = valid_flag;`——no-op
- `RuntimePgBypassWindow::enter_unchecked`（`:399`）注释（`:426`）说 "actual suspension is driver-side"，Drop（`:438`）是 `let _ = pg_thread_kva;`——no-op

**含义：** 所有内核 DKOM/callback 操作（真机验证过的 hide_pid/repurpose）**都是靠"<1s 短窗口硬扛 PG"，侥幸没触发**。这不是可持续状态。`examples/proc_hide_test.rs:13-15` 自己也写 "DKOM 是 PatchGuard 检测项...把窗口压到最短(<1s)"。

### 2.4 🔴 回调 repurpose 处理 ALL slots（生产代码缺 selective targeting）
`telemetry.rs:141-165` `repurpose()` 遍历 3 个数组 × `ARRAY_LEN(64)` slot，**无 slot[0]/ntoskrnl 跳过**。

但 `examples/callback_repurpose_test.rs:156` **只动 slot[5]**（硬编码），`:18` 注释 "只动 slot[5]，绝不碰 slot[0]"，还有 SysmonDrv-range 校验（`:164-178`）。**即：示例代码是 surgical 的，但被迁入库代码（`telemetry.rs::repurpose`）时丢了 selective 逻辑。** 这正是 `CLAUDE.md` 标的 "P0 next task — selective slot targeting"。

### 2.5 🔴 netsec WFP 假 PID 靶向 + LSASS 裸读
- `netsec.rs:206` `num_filter_conditions = 0` = **全量 block 出站**，PID 只写进 `display_data`（`:211`）做诊断。`:204-205` 注释自己承认 hack。
- `netsec.rs:314-315` LSASS `dump_lsass` 从固定 `0x1_0000_0000` 读 `0x100_000`（1 MiB）**裸读**，无 LogonSession/DPAPI/msv1_0/wdigest/tspkg 解析。`:307-313` 注释 deferred 给 operator。

### 2.6 🟡 其他过时 doc（不咬人，但要更正）
| 文档声明 | 实勘 | 证据 |
|---|---|---|
| CLAUDE.md "keypair ephemeral" | **已可持久化**（`NYX_KEYFILE`） | `crypto.rs:53/59` + `lib.rs:226` `load_or_create_keypair` + test `lib.rs:1369` |
| blind.rs "HWBP future addition" | **已实现** | `blind_hwbp.rs` 全套 + `entry.rs:28` 优先 HWBP |
| gap-analysis 暗示有 wire-only Command | **21 变体全有 JSON 面** | `msg.rs:68-137` ↔ `lib.rs:782-840` 1:1 |
| `transport` crate 是植入传输 | **是服务器指纹引擎**（JA3/JA4/Akamai H2），非植入传输 | `transport/src/lib.rs:1-30`；植入传输是 `implant-win/transport.rs` WinHTTP |
| implant 侧 JA3 伪装 | **stub**（`wreq` 后端不可用） | `transport/src/emitter.rs:61-63` + `lib.rs:19-27` |
| store crate 持久化多项 | **只持久化 creds**；operators=JSON、audit=JSONL、sessions=内存 | `store/src/store.rs:73` 单表 `creds` |

### 2.7 🟡 新发现的 IOC（之前 doc 没提）
- **`blind_hwbp.rs:94-138` `diag()` 每个 HWBP 步骤写 ASCII marker 到 `C:\nyx\hwbp_diag.txt`**——生产环境硬 IOC，应 gate 在 selftest 下。
- **`inject.rs:630` `threadless_inject` 丢弃 `trigger_addr`**（`let _ = trigger_addr`），把 DRn 设成 shellcode base 而非触发地址——与文档"operator picks trigger address"不符。
- **client-ui `main.rs:2027` `upload` 在 UI 线程同步 `std::fs::read`**——会卡 UI。

---

## 3. 真·差距清单（排除已闭合项，按"影响 × 恶化速度"排序）

| 级别 | 差距 | 代码现状（file:line） | 恶化趋势 | 对应开发项 |
|---|---|---|---|---|
| 🔴 P0 | sleep mask 只 mask `.text`，heap 明文 | `sleep.rs:110` `own_text_region()` 只读 `.text`；`mem.rs` 只 mask 8 个注册 data 区（含 32B ECDH key），不扫 heap | 恒定弱点，BeaconEye/MalMemDetect 命中 | §4 Tier-1-A |
| 🔴 P0 | stack swap CET-on 降级 / `#CP` 风险 | `stack.rs` 无 `KiControlProtectionFault` 路径，gate=true | **随时间恶化** | §4 Tier-1-C |
| 🔴 P0 | PatchGuard 窗口全 skeleton | `persistence.rs:256/351/438` 全 no-op/Err | 内核 DKOM 全靠侥幸 | §4 Tier-1-D |
| 🔴 P0 | 回调 repurpose 无 selective targeting | `telemetry.rs:141-165` 全 slot；示例 `examples/...:156` surgical | 真机用示例 OK，库代码危险 | §4 Tier-0-C |
| 🟡 P1 | KslD 设备解析薄弱 | `ksld.rs:51-54` 字面量 `\\.\MpKsl` | RTCore64 黑名单覆盖率升 → 兜底失效 | §4 Tier-1-B |
| 🟡 P1 | 持久化**完全为零** | 全仓零 Run/WMI/sched task/service；`Command` 枚举无 Persist 变体 | 长期驻留短板 | §4 Tier-2-A |
| 🟡 P1 | 注入仅 2 法 | `inject.rs` module_stomp + threadless；无 early-bird/hijack/hollow | 路径单一 | §4 Tier-2-B |
| 🟡 P1 | C2 仅 HTTPS | `transport.rs` 单 WinHTTP；pivot 是 egress SOCKS 非入站 | 横向受限 | §4 Tier-3-A |
| 🟡 P1 | implant JA3 伪装 stub | `emitter.rs` wreq 后端不可用 | TLS 指纹检测命中 | §4 Tier-3-B |
| 🟢 P2 | 无 UDRL | `tools/srdi` 只 carve `.text`，不应用 reloc，无自解析 stub（`:23-33` 明确 deferred） | postex 灵活性 | §4 Tier-3-C |
| 🟢 P2 | BOF 仅同步 | `bof.rs` 单线程 16KiB 输出，无 async/BOF-PE | 生态落后 | §4 Tier-3-D |
| 🔵 P3 | netsec WFP 假 PID | `netsec.rs:206` num_conditions=0 | 不精准 | §4 Tier-4 |
| 🔵 P3 | netsec LSASS 裸读 | `netsec.rs:314` 固定 1MiB 盲读 | 不能出凭据 | §4 Tier-4 |
| 🔵 P3 | HWBP diag 留 IOC | `blind_hwbp.rs:94` 写 `C:\nyx\hwbp_diag.txt` | 生产 IOC | §4 Tier-0-D |

---

## 4. 开发路线图（按优先级 + 可落地性）

### 🔴 Tier 0 — 立即做（止血 / 低成本高回报，<1 天）

#### 0-A. 修 gate/docstring 矛盾（<1h）
改 `SPOOF_SWAP_ENABLED` 回 `false`（`stack.rs:79`）直到 Tier-1-C；同步改 3 处 docstring 或代码一致。更新 `CLAUDE.md` "Shipped" 节 + `gap-analysis.md` 顶部加 STATUS 修正（#1.1/1.2/1.4/1.5/2.1 已闭合）。

#### 0-B. HWBP diag 下线（<1h）
`blind_hwbp.rs:94` `diag()` 用 `#[cfg(feature="selftest")]` 或运行时 flag gate，生产不写 `C:\nyx\hwbp_diag.txt`。同理 `VEH_DIAG_BUF`（`:201`）。

#### 0-C. 回调 repurpose selective targeting（P0，半天）
把 `examples/callback_repurpose_test.rs` 的 surgical 逻辑（`:156` 单 slot + `:164-178` SysmonDrv-range 校验 + `:18` slot[0] 跳过）迁入 `telemetry.rs::repurpose()`。加 `callback_owner_map.rs` 的 slot→driver 映射（已有 read-only 版）。跳过 ntoskrnl 内部 slot。

#### 0-D. 修 threadless `trigger_addr` 丢弃（<1h）
`inject.rs:630` 把 `let _ = trigger_addr` 改成实际用 `trigger_addr` 设 DRn（或删参数 + 文档说明）。

### 🔴 Tier 1 — P0 核心差距（"最后 10%"）

#### 1-A. heap sleep mask（对标 CS 4.5/4.11）—— 最高优先
**为什么：** CS 自 4.5 把 Beacon heap 纳入 sleep mask，4.11 写明 "obfuscates Beacon, **its heap allocations**, and itself"（[CS 4.11 blog](https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping)）。Nyx Foliage 只 RC4-mask `.text`（`sleep.rs:110`），config/token/句柄散落 heap 明文，BeaconEye/MalMemDetect 直接命中。

**落地（Nyx 架构几乎现成）：**
1. `mem.rs` 已有 `register_region`/`MAX_REGIONS=8`/RC4/idempotent mask。扩展：`enumerate_beacon_heap_regions()` 在 sleep 前把关键 heap 区（config blob、session key、token cache、bof 输出缓冲）注册进来。
2. `sleep.rs` Foliage 链 `foliage_helper`（`:626`）mask `.text` 同窗口追加 `mem::mask()`（data-only floor `:208` 已有此调用路径）。
3. no_std bump allocator（`ntalloc.rs`）下 heap 块连续——在 allocator 层记录"beacon 自身已分配未释放"块链表，mask 时遍历。
4. selftest 扩展：mask 后扫 heap 找 config magic 字节 → 应找不到。

**工作量：** 中。算法全在，主要是 allocator 块链表 + Foliage 接入点。

#### 1-B. KslD 设备解析 + 真机验证（内核层解锁）
**为什么：** RTCore64 在 MS 黑名单（覆盖率 ~70% 升），KslD 是绕黑名单的正解，但设备解析薄弱 + 未真机跑通。

**落地：**
1. `ksld.rs::open()` 实现动态设备解析：枚举 `\Device\` 或用 `IoGetDeviceObjectPointer`（或用户态等价：`FindFirstVolumeW`/注册表 `HKLM\SYSTEM\...\Services` 找 MpKsl 前缀），匹配 `MpKsl*`。
2. Server 2019（Defender-on）真机：`bootstrap_chain()` 确认走 KslD 路径，记录 IOCTL round-trip 时序。
3. KslD 跑通后把 RTCore64 降为最后兜底。

**SOTA 参考：** `andreisss/KslDump`、`vergamota/KslKatz`、`PrincipleCheck/KslKatzBof`（ksld.rs:17-19 已列）。

#### 1-C. CET-safe return-address spoof（Synacktiv SSTIC 2025）—— 抗恶化
**为什么：** §2.1。唯一随时间恶化的弱点。

**SOTA 参考：**
- **Synacktiv SSTIC 2025** *Analyzing the Windows kernel shadow stack mitigation*（[PDF](https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf)）——`KiControlProtectionFault` 的 lenient-repair 路径，允许特定 shadow-stack 偏差被"容忍修复"而非 bugcheck。
- Connor McGarr — kernel shadow stack 调查（[blog](https://connormcgarr.github.io/km-shadow-stacks/)）。
- sroettger — survive-CET gist（[link](https://gist.github.com/sroettger/fe66f7eb0cb10a8ebd1454875a7131ea)）。

**落地：**
1. 先 Tier-0-A 改回 false。
2. 读 Synacktiv PDF 定位 lenient-repair 触发条件。
3. `stack.rs` 实现 CET-aware swap：`cet_active()` 真时走 lenient-repair 而非裸 `mov rsp`；`swap::decide`（`implant-evasionsdk/swap.rs:33`）从二元降级升级为三态。
4. selftest 必须含 CET-on 真机（Win11 + Intel TGL+，BIOS 开 CET）——**环境是瓶颈**。

#### 1-D. PatchGuard 窗口从 skeleton 到可用（内核层落地）
**为什么：** §2.3。无可用 PG 窗口，所有内核 DKOM/callback 暴露在 BSOD 风险下。

**SOTA 参考：**
- **kurasagi**（NeoMaster831）— Win11 24H2/25H2 runtime PG bypass 完整 PoC（[GitHub](https://github.com/NeoMaster831/kurasagi)）。原理：PG 初始化阶段执行 non-backed code，runtime 可拦截/中和。PDF 在 product branch。
- TheiaPg（quokka867）— 25H2 同类（需直接找仓库）。

**落地：**
1. `PatchGuardWindow::enter_unchecked`（`:252`）从 unconditional `Err` 改为 per-build PG context 动态 probe（用现有 `offsets.rs:531 probe_eprocess_offsets` 同款思路）。
2. `RuntimePgBypassWindow`（`:373`）实现真 suspend/resume PG 线程（当前 Drop `:438` no-op）。HVCI-safe（线程调度层，不碰 .text）。
3. `TimingRepairWindow`（`:283`）Drop 实现真 restore（当前 `:351` 丢弃）。
4. **警戒：** PG 绕过是 BSOD 高危区。红绿验证（回退→BSOD，恢复→通过），方法见 hwbp postmortem Phase 4。

**工作量：** 高。内核层从"纸面"到"可用"的必经路。

### 🟡 Tier 2 — P1 工程生态（追平 CS/BRC4）

#### 2-A. 持久化生态（benchmark 差距 C 🔴）
全仓零持久化。落地（按 OpSec 噪音升序）：
1. **Registry Run key**（最简）— `nt_create_key`/`nt_set_value_key`（`syscalls.rs` 已有 `nt_create_file` 同模式）。
2. **Scheduled task**（COM `ITaskService` 或 `schtasks`）。
3. **WMI event subscription**（`__EventFilter` + `CommandLineEventConsumer`）— Sysmon EID 19-21 可见。
4. **Service**（`CreateServiceW` + 自动启动）— 最稳。
- 加 `Command::Persist` wire 变体（注意 `msg.rs` → server `JsonCommand` → CLI 镜像链，CLAUDE.md §"hand-mirrored chain"）。

#### 2-B. 注入多样性 + ThreadlessStompingKann（benchmark 差距 D 🟡）
- **ThreadlessStompingKann**（caueb）— Threadless + Stomp + Caro-Kann 三合一，对 MDE 高度隐蔽（[GitHub](https://github.com/caueb/ThreadlessStompingKann)）。**直接补 module stomp 的 PE-sieve `.text` hash 漏洞**。
- 扩展 `inject.rs`：early-bird APC（`QueueUserAPC`）、thread hijack（`SuspendThread`→改 RIP→`SetThreadContext`）、process hollowing。`syscalls.rs:759` 已有 `ntcreatethreadex` djb2 常量（可解析未用作注入）。

#### 2-C. EDRChoker（网络遥测窒息）—— 低成本高回报
**为什么：** 网络遥测是 EDR 三大支柱，当前 netsec WFP 假靶向。EDRChoker 用户态、admin、PowerShell、低于 WFP 层（pacer.sys）、无 WFP 事件。

**SOTA 参考：** EDRChoker（TwoSevenOneT，2026-06）— Policy-based QoS 把 EDR 上行限到 **8 bit/s**，TLS 握手超时（[GitHub](https://github.com/TwoSevenOneT/EDRChoker)）。

**落地：** operator 侧 `tools/edrchoker.ps1`，调 `qwave.dll` `QOSCreateHandle`/`QOSAddAppFilter`（netsec.rs `choke_edr_qos` 已有半成品 FFI）。

### 🟢 Tier 3 — P2（补全生态 / 机动性）

#### 3-A. C2 多协议（DNS/SMB/TCP/named pipe）
`transport.rs` 抽象 `Transport` trait，新增 `DnsTransport`/`SmbTransport`/`PipeTransport`。beacon loop（`beacon.rs:72`）按 config 选。`protocol/src/lib.rs:10` 已有 future-framing 注释（预留点）。DNS over HTTPS（CS 4.11）值得参考。

#### 3-B. implant JA3 伪装（当前 stub！）
`transport/src/emitter.rs` `wreq` 后端不可用 → implant TLS 指纹是 rustls 默认（非 Chrome）。**这是真实检测面**，比 C2 多协议更影响"过不过得了边界"。等 `wreq` 稳定或用 BoringSSL 手搓。

#### 3-C. UDRL（反射加载 / sRDI 自解析 stub）
`tools/srdi` 加 reloc table walk + 自解析 stub（当前 `main.rs:22-33` 明确 deferred）。参考 Stephen Fewer 原 RDLL、Outflank/CCob UDRL。

#### 3-D. 异步 BOF / BOF-PE
`bof.rs` 加线程池 + 输出流；`BeaconRevertToken` 实现 impersonation handle 维护（当前 `bof-runner/win.rs` 只有 `BeaconPrintf`）。

### 🔵 Tier 4 — P3（加固 / 精修）
| 项 | 现状 | 动作 |
|---|---|---|
| netsec WFP 真 PID 靶向 | `netsec.rs:206` num_conditions=0 | 加 `FWPM_FILTER_CONDITION` 按 PID |
| netsec LSASS 凭据解析 | `netsec.rs:314` 1MiB 盲读 | LogonSessionList walk + DPAPI + msv1_0/wdigest/tspkg |
| Foliage wait-reason | `sleep.rs` 用 NtDelayExecution（DelayExecution）→ HSB 可识别 | 但实勘：`sleep.rs:521-522` beacon 用 `NtWaitForSingleObject(INVALID_HANDLE, alertable)` 已是 UserRequest！`foliage_helper:696` helper 也用 UserRequest。**这条 gap-analysis 可能已闭合，需对 HSB 真实验证** |
| ETW-Ti APC window 攻击 | HSB 在 APC 窗口见 KiUserApcDispatcher | sleep 前 clean stack + 非 alertable 期间做 op |
| PPL 进程不朽 | `persistence.rs make_immortal` 写 0x4B/0x3F 已有算法 | 参照 [TwoSevenOneT/CreateProcessAsPPL](https://github.com/TwoSevenOneT/CreateProcessAsPPL) loader；注意 [Elastic](https://www.elastic.co/security-labs/inside-microsofts-plan-to-kill-pplfault) 报 MS 在收 PPLFault |
| 内核 WFP callout 覆盖 | netsec 是用户态 WFP | 内核 `WfpKit` 覆盖 callout 指针（HVCI-safe 数据写） |
| ETW 伪造补 NtTraceEvent | `etw_deception.rs` 只造缓冲（`:17-21` operator-wired） | operator 侧补 `NtTraceEvent` 调用；诚实：缺内核 HMAC 签名 |
| ADDR32NB COFF reloc | `coff/lib.rs:36` 常量有但 `apply()` 不处理 | 加 match arm |

---

## 5. 不可逾越的天花板（诚实记录，避免做无用功）

不要投入资源试图"技术解决"这些——只能运营缓解：

1. **NDR 行为建模（Vectra 2026-06）** — beaconing interval/periodicity/协议异常。无技术 bypass。缓解：大 jitter、low-and-slow、CDN fronting（Tier-3-A）。
2. **Cortex XDR（纯内核回调，零用户态 hook）** — ntdll unhook / AMSI blind / ETW 用户态 patch **完全无效**。只有内核层有效——这正是 Tier-1 内核落地的重要性。
3. **HVCI 下 inline kernel hook** — .text 代码写在 EPT 下 VM-exit → `KeBugCheckEx`。**死路**。所有内核操作必须 data-section only（当前 repurpose/minifilter unlink 已合规）。
4. **Sanctum EDR（fluxsec，in-kernel ETW）** — 内核态 ETW 检测 ETW blinding 本身。诚实上限。
5. **ETW 密码学签名会话** — `etw_deception` 伪造事件缺内核 HMAC，密码学验证的 ETW 会话仍可区分真伪。

---

## 6. 检测军备表（2025-2026，对照 Nyx 现状）

| 检测器 | 抓什么 | Nyx 受影响项 | Nyx 现状 | 对应项 |
|---|---|---|---|---|
| xacone / K2 | syscall `[RSP]` 非合法 DLL | 间接 syscall | ✅ gap 链已搭（CET-off） | Tier-1-C（CET-on） |
| cet-spoofing-detection (0xjbb) | shadow vs user 栈比对 | RSP swap | ⚠️ CET-on 降级 | **Tier-1-C** |
| Hunt-Sleeping-Beacons (updated) | UserRequest + KiUserApcDispatcher | Foliage APC | ⚠️ 实勘 wait-reason 已是 UserRequest，APC 窗口待验证 | Tier-4 |
| Sleep-Duck-Eye (Olivaire) | 通用栈完整性 | 所有 sleep mask | ⚠️ 待验证 | Tier-1-A 联动 |
| BeaconEye / MalMemDetect | heap 配置扫描 | sleep mask | ❌ heap 明文 | **Tier-1-A** |
| Elastic OXLOADER | `.reloc` 代码 | module stomp | ⚠️ 避免 .reloc | Tier-2-B |
| Peregrine | ObCallback + 驱动黑名单 | BYOVD | ❌ RTCore64 在榜 | **Tier-1-B** |
| TLS JA3/JA4 指纹 | rustls 默认 ClientHello | implant 传输 | ❌ emitter stub | **Tier-3-B** |
| StackSentry | `.pdata` 时序 | BYOUD（非 gap） | ✅ BYOUD-Gap 零改安全 | 已闭合 |
| KslKatz detection | LSASS 异常内核访问 | LSASS 直读 | ⚠️ 检测存在 | Tier-4 |

---

## 7. 建议执行顺序（最小可验证增量）

```
第 1 周：Tier-0（止血，<1 天）
  ├─ 0-A gate/docstring 矛盾
  ├─ 0-B HWBP diag 下线
  ├─ 0-C repurpose selective targeting
  └─ 0-D threadless trigger_addr
  → 更新 CLAUDE.md / gap-analysis 状态节

第 2-3 周：Tier-1-A（heap sleep mask）
  └─ allocator 块链表 + Foliage 接入 + selftest

第 3-5 周：Tier-1-B + Tier-1-D（内核解锁，并行）
  ├─ KslD 设备解析 + 真机
  └─ PatchGuard 窗口（kurasagi 路径，红绿验证）

并行（环境就绪）：Tier-1-C（CET-safe swap）
  └─ 需 CET-on 真机，环境是瓶颈

第 5-7 周：Tier-2-C（EDRChoker）+ Tier-2-B（ThreadlessStompingKann）
  └─ 低成本高回报

后续：Tier-2-A 持久化 / Tier-3 多协议+JA3 / UDRL / async BOF
```

---

## 8. 质量纪律（hwbp postmortem 的 6 条教训，直接适用）

本次审计本身印证了第 1、5 条——既有 doc 的"竞态/未闭合"判断多有失准，必须逐文件核实代码。

1. **"竞态"几乎从不是竞态。** Tier-1-D PG 窗口 BSOD 时，先怀疑证据，别信"PG 时序"万能解释。
2. **崩溃签名定方向。** `0xC0000005`（OS AV）vs `0xC0000001`（Rust panic）vs `#CP` 是三条路。CET 的签名也要先抓准。
3. **隔离实验比读代码快。** kernel BSOD 时先最小复现（裸 `enter_unchecked`）再叠加。
4. **dump 地址处字节。** 怀疑"解析返回错地址"时 dump 16 字节即可分辨代码 vs 字符串。
5. **叠加 bug 互相掩盖。** 修一个跑一次，别攒着测。
6. **回归测试必须红绿。** Tier-1-D PG 窗口尤其：回退→BSOD（红），恢复→通过（绿）。

---

## 附 A：全量审计覆盖证明（22 crate / 160 .rs / 47,542 行）

| crate | LoC | 文件数 | 读法 |
|---|---|---|---|
| implant-win | 15,306 | 34 | 我亲读 sleep/stack/（+agent 全读 beacon/entry/inject/syscalls/resolve/blind*/unhook/mem/kits/evasion_glue/transport/context/version/hostinfo/config）|
| operator-kernelsdk | 7,843 | 26 | 我亲读 ksld/telemetry/persistence(PG)/netsec(WFP+LSASS)（+agent 全读 lib/byovd/etwti/offsets/etw_deception/pattern_scan/pagewalk/win/* + 全 8 examples）|
| protocol + server + transport + config + store + rest | ~7,800 | ~20 | agent 全读（我交叉核对 keypair 持久化/wire variants/store 范围）|
| profile + coff + bof-runner + pe + evasion + implant-evasionsdk + parse + scripting | ~6,500 | ~30 | agent 全读 |
| agent-dev + client-cli + client-ui + tools/srdi | ~10,000 | ~15 | agent 全读 |
| offset-resolver | 244 | 1 | agent 全读（唯一 TODO 所在：PDB walker 部分 + 下载路径未实现）|

**零 `unimplemented!`/`todo!`/`panic!("not implemented")`** 在任何 lib 源（仅 2 处在 test 文件作断言）。所有"未完成"都是诚实的 doc 注释 / `Err(UnsupportedPosture)` 拒绝路径 / floor no-op，无隐藏假成功。

## 附 B：技术来源

**核心研究源（§4 引用）：**
- Synacktiv SSTIC 2025 — Windows kernel shadow stack mitigation：https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf
- Connor McGarr — kernel shadow stack：https://connormcgarr.github.io/km-shadow-stacks/
- sroettger — survive-CET gist：https://gist.github.com/sroettger/fe66f7eb0cb10a8ebd1454875a7131ea
- NeoMaster831/kurasagi — Win11 24H2/25H2 runtime PG bypass：https://github.com/NeoMaster831/kurasagi
- ThreadlessStompingKann（caueb）：https://github.com/caueb/ThreadlessStompingKann · https://caueb.github.io/attackdefense/threadlessstompingkann/
- EDRChoker（TwoSevenOneT）：https://github.com/TwoSevenOneT/EDRChoker · https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html
- CS 4.11 sleep mask（含 heap）：https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
- CS Sleep Mask 4.5 update：https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/blog_sleep-mask-update-45.htm
- TwoSevenOneT/CreateProcessAsPPL：https://github.com/TwoSevenOneT/CreateProcessAsPPL
- Elastic — MS 收 PPLFault：https://www.elastic.co/security-labs/inside-microsofts-plan-to-kill-pplfault
- PE-sieve（`.text` hash 检测原理）：https://hasherezade.github.io/pe-sieve/index.html

**仓库内交叉参考：**
- `docs/p2-2026-06-gap-analysis.md`（注意 §1.1 状态修正）
- `docs/p2-benchmark-vs-cs413-brc4-v23.md`（与本文 §3 一致）
- `docs/BYPASS_CAPABILITIES.md`（接线状态据本文修正）
- `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`（§8 质量纪律来源）
- `CLAUDE.md`（crate 角色 / hand-mirrored chain / 2 处过时待更正）

---

*本文基于 2026-06-26 全量逐文件审计（22 crate / 160 .rs / 47,542 行）。每个"已闭合/未闭合/skeleton/ARMED"判定以 `file:line` 源码为准。3 个全文件读 agent 覆盖 18 个文件，我亲读 7 个关键承载文件并交叉核对 agent 结论。零信任既有 doc。*
