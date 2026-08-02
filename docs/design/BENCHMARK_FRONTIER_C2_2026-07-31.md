# Nyx vs 前沿商业 C2 — 多角度基准评测（2026-07-31）

> **状态**：Active — 本文是 2026-07-31 修复冲刺（分支 `refactor/ah-audit-followups`，11-commit sprint）**之后**的权威当前状态基准，取代 `docs/testing/p2-benchmark-vs-cs413-brc4-v23.md`（2026-06-26 快照）与 `docs/research/commercial_c2_security_research.md`（研究素材，非产品承诺）中的过时对位结论。
> **口径**：Nyx 侧全部以**当前代码 + CHANGELOG [Unreleased]** 为准（`file:line` 证据）；商业框架侧以厂商官方发布页为准。能力状态沿用 [`STATUS.md`](../STATUS.md) 四档：已交付 / 受限交付 / 实验性 / 规划中。诚实优先——未接线、未验证的能力不得视为"可用"。
> **数据基线说明**：[`AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 早于本次冲刺，属**基线快照**；凡与本文件或当前代码冲突处，以当前代码为准（例如 loader 反射加载、BOF API、transport 接线三项在冲刺后状态已变化）。

---

## 1. 版本基线

### 1.1 Cobalt Strike 4.13（Fortra，2026-06-10，"Lost In Translation"）

来源：[cobaltstrike.com 官方博客 4.13](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)、[官方 releasenotes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm)、[research 摘要](docs/research/commercial_c2_security_research.md §1.1)。

| 能力 | 说明（来源） |
|---|---|
| **Beacon Interpreter** | 4.13 新增：原生 C 脚本解释器（C VM），operator 编写 C 代码直接发给 Beacon 在 VM 内执行，无需重新编译 payload（官方 blog 4.13） |
| **BOF-PE** | 4.13 新增：在 Beacon 进程内映射并执行完整 PE（EXE/DLL），较 fork-and-run 更隐蔽（blog 4.13；research §1.1） |
| **LLVM Beacon** | 4.13 以 LLVM 工具链构建 Beacon 变体，弱化 MinGW/Clang 段布局指纹（blog 4.13） |
| **Payload Store** | 4.13 集中管理/检索 payload 与工件（blog 4.13） |
| **Malleable Profile 运行时覆盖** | 4.13 支持不重启 listener 即可按需覆盖 profile 项（blog 4.13） |
| **REST API + WebSocket/gRPC 流** | 4.13 扩展 REST API，新增 WebSocket 与 gRPC 流式接口（blog 4.13） |
| **drip-loading + UDC2** | 4.12 引入 drip-loader（分片慢速投递）与 UDC2 用户自定义 C2（releasenotes；research §1.1 时间线） |
| **sleepmask/UDC2 容量上限 100MB** | 4.13 起 sleepmask 与 UDC2 上限 100MB（blog 4.13；research §1.1 表） |
| **SOCKS5 IPv6 + SSH beacon** | SOCKS5 代理支持 IPv6；SSH Beacon 覆盖 Linux/Unix 目标（releasenotes） |
| **4.12 基线** | Arsenal Kit 统一入口、Beacon metadata 扩展（releasenotes；research §1.1） |

### 1.2 Brute Ratel C4 Catalyst v2.6.3（2026-07-30）

来源：[bruteratel.com 发布页](https://bruteratel.com/category/release/)、厂商 releases.txt（2026-07-30 Catalyst 线）。

| 能力 | 说明（来源） |
|---|---|
| **custom-compiler Badger** | 自研编译器生成每代唯一 Badger：消除 MinGW/Clang 段布局与 runtime 初始化指纹，体积 **-30%**（bruteratel release notes） |
| **safe_http 2–3KB PIC stub** | 2.5+ 引入的极小型 HTTP 反射加载引导桩（release notes） |
| **coffexec_async** | 异步 BOF 执行（release notes；research §1.2 已述 v2.2 起异步 BOF） |
| **dotnet store（10 assemblies）** | 内置 .NET 装配件存储（release notes） |
| **Shadowcloak** | 无需 mimikatz 的 LSASS 内存转储方案（release notes） |
| **dcsync / mimikatz / kerberoast / PtH** | 凭据收割与横向全套（release notes） |
| **module stomping + PEB LDR hook** | 注入面：模块踩踏 + PEB 加载器链挂接（release notes） |
| **110+ 命令** | 命令面远超 100（release notes） |
| **Ratel API + bruteratel.py** | 脚本化/REST 化团队操作（release notes） |
| **working-hours callbacks** | 办公时间回调调度（release notes） |
| **扩展 malleability（2.6）** | 自定义响应类型/响应头等流量塑形（release notes） |

### 1.3 Nyx 当前（分支 `refactor/ah-audit-followups`，2026-07-31 冲刺后）

来源：本仓库代码 + [`CHANGELOG [Unreleased]`](../../CHANGELOG.md)（文件:行证据）+ [`STATUS.md`](../STATUS.md)。冲刺（wp-protocol / wp-store / wp-kernel-daemon / wp-loader / wp-implant-core / wp-implant-inject / wp-bof-runner / wp-agent-dev / wp-server-a / wp-server-b / wp-ui / wp-scripting / wp-transport / wp-offsets + wave-2）共 13+ 工作包，workspace check + test 全绿（`nyx-server` 72 / `nyx-transport` 109 / `nyx-protocol` 49 / `nyx-store` 28）。

| 冲刺变更 | 代码证据 |
|---|---|
| 协议贡献性校验：拒绝低阶点 X25519（RFC 7748 §6.1） | `crates/protocol/src/crypto.rs:222-248, 302-319, 370-386` |
| encode 侧帧上限 `MAX_CT_LEN`（512 KiB） | `crates/protocol/src/frame.rs:22` |
| `FileOp::Ls` wire 变体（tag 5）+ 服务器 `ls` 映射 | `crates/protocol/src/msg.rs:274-307` |
| beacon 发送纪律（成功后才推进 counter）+ S2C 重放保护 + 可恢复 OOM | `crates/implant-win/src/beacon.rs:250-271` |
| ZeroBits 修复（`nt_allocate_virtual_memory` 6 参）+ PoolParty `SYSTEM_HANDLE_INFORMATION_EX` 布局修正 | `crates/implant-win/src/inject.rs:676, 1049` |
| BOF CS ABI `go(args, alen)` + W^X（执行时无 W+X 页）+ RAII 释放 + externals 扩展（kernel32/ntdll 经 `GetModuleHandleA`/`GetProcAddress`） | `crates/bof-runner/src/win.rs:444-498, 409-414` |
| 信道门禁：SmbPipe/Tcp 拒绝 `SetChannel` + 拒交易；tcp/smb I/O 超时（FIONBIO+select 10s / `WaitNamedPipeW` 5s） | `crates/implant-win/src/beacon.rs:698`、`crates/implant-win/src/channels/mod.rs`、`channels/tcp.rs`、`channels/smb.rs` |
| store：`mask_secret` UTF-8 安全 `first2….last2`；token 消费原子 fail-closed `UPDATE…WHERE used=0`；`busy_timeout`；DB 0600；`send_counter`/`last_recv` 迁移持久化 | `crates/store/src/model.rs:73-82`、`crates/store/src/session_store.rs` |
| server：GC 活跃豁免 + 会话重新准入；任务分批 ≤ 上限；kill-date 严格校验（月天数/闰年/1970+）；argon2id 走 `spawn_blocking` 且预算耗尽 fail-closed；单一 boot-time `TransportStack`（`ExtC2RelayConfig::from_env`）供 Slack/MCP；Slack HMAC key fail-closed boot | `crates/server/src/implant_gen.rs:258-268, 340-374`、`crates/server/src/extc2_relay.rs:57-59, 122-127, 214-218, 381-413` |
| 内核 daemon 认证：`--serve` 缺 `NYX_DAEMON_TOKEN` 退出 7；连接首行 `auth <token>` 常量时间比较；`pid<=0` 拒绝；每连接 60 ops/min 限流 | `crates/operator-kernel-cli/src/main.rs:157-177, 536-551` |
| PatchGuard 窗口门禁：5 行 `KNOWN_PG_CONTEXT_BUILDS` 全部 `verified=false`，`select_pg_window` 对未验证 build 返回 None | `crates/operator-kernelsdk/src/offsets.rs:443, 471, 582, 752` |
| KernelRw 契约（driver unload 真实路径，`DriverHandle` trait） | `crates/operator-kernelsdk/src/lib.rs:454, 489, 518` |
| offset-resolver `--build` 必填（PDB 无法自检 build，静默默认已删除） | `crates/offset-resolver/src/main.rs:11-42` |
| rhai 全局预算：累计 op 上限（`on_progress` 永不复位）+ 单次派发上限 + 墙钟 + `nyx_log` 频率 | `crates/scripting-rhai/src/` |
| UI：任务历史 session 级 App store（切会话不清空）+ 结果带 `session_id` + pending 过期合成错误 | `client-ui-web`（CHANGELOG wp-ui） |
| `nyx-mutate` crate 整体删除 | `Cargo.toml` members、`crates/server/Cargo.toml`（CHANGELOG Removed） |
| **真实反射加载器已接线（2026-08-02 终扫）**：pic-loader（Rust no_std PIC）经 regen.sh 产出 6,080B 零重定位 .bin，`wrap_payload` 按最终布局发射 `[LAYER1+bridge][key][magic|len|nonce][ct||tag][LAYER2]`；LAYER1 桥接寄存器对齐 pic-loader Win64 ABI；**Unicorn 仿真探针**（`tools/loader-emu`，CI Gate 5）在任意宿主执行真实字节：magic 定位/头部解析/DllMain 触发全 PASS；release 门禁 = 仿真探针，零 Windows 依赖 | `crates/nyx-loader/src/on_target.rs`（LAYER1_BOOTSTRAP+bridge）、`pic-loader/regen.sh`、`tools/loader-emu/loader_emu.py` |

**未在本次冲刺闭合、仍属差距的状态（诚实标注）：** 睡眠混淆仍短路到 `beacon::sleep_seconds`（`crates/implant-win/src/kits.rs:39-79` 死路径，Foliage/Fluctuation/mem::mask 未接线）；TLS 指纹 emitter 仍在 `impersonation` feature 后（`crates/transport/src/fingerprint.rs:201-229`，Err stub）；DoH/DNS/LLM 三 Transport 零消费者（仅 Slack/MCP 经 server `TransportStack` 接线）；无持久化、无横向凭据执行（hashdump LSASS 显式 deferred：`crates/implant-win/src/hashdump.rs` method=2 诚实 Err）。

---

## 2. 十维度差距矩阵

评分：0–5（0=无，5=商品级成熟），允许 0.5 步进。**Nyx 列反映 2026-07-31 冲刺后状态**。加权总分 = Σ(维度分 × 权重)，满分为 Σ(5 × 权重) = 500。

| 维度（权重） | Nyx | CS 4.13 | BRc4 2.6.3 | 判据要点 |
|---|---|---|---|---|
| **端点逃避实装**（15） | **3.0** | **5.0** | **4.5** | Nyx：indirect syscall/SSN 三级回退、BYOUD-Gap CET-safe 栈欺骗、AMSI·ETW 盲打、module stomping+threadless 真装；但睡眠混淆未接线、heap 未 mask、注入面窄。CS：sleepmask 全量重写（代码+heap，100MB）+ BeaconGate RAS + BOF-PE。BRc4：custom-compiler + 模块踩踏 + PEB LDR hook，CET-safe 未证实 |
| **加载器与投递**（10） | **3.0** | **5.0** | **4.5** | Nyx：**真实 Layer-2 反射加载已接线并经仿真探针验证**（pic-loader 6,080B .bin、Win64 ABI 桥接、DllMain 触发断言）；缺 CS UDRL 生态/Arsenal Kit 的成熟度与 drip-loading。CS：UDRL 生态+Arsenal Kit+drip-loading+Payload Store。BRc4：custom-compiler Badger + safe_http 2–3KB PIC 桩 |
| **C2信道与流量仿冒**（10） | **2.0** | **5.0** | **4.0** | Nyx：HTTPS WinHTTP 主信道 + SOCKS pivot；8 信道枚举但 SmbPipe/Tcp 门禁、DoH/DNS/LLM 零消费者；Slack/MCP 经 boot-time TransportStack 接线（HMAC fail-closed）；Malleable 解析+c2lint；TLS emitter 为 stub。CS：HTTPS/DNS/SMB/TCP + UDC2 + profile 运行时覆盖 + WS/gRPC 流。BRc4：多通道 + 2.6 扩展 malleability |
| **BOF与扩展执行**（10） | **2.0** | **5.0** | **4.5** | Nyx：CS ABI `go(args,alen)` + W^X + RAII 释放 + externals 扩展（kernel32/ntdll 动态解析）+ coff 解析 7 测试；无 async BOF/BOF-PE/Interpreter。CS：BOF+异步 BOF+BOF-PE+Beacon Interpreter（C VM）。BRc4：coffexec_async + dotnet store |
| **后渗透工具集**（10） | **2.5** | **5.0** | **4.5** | Nyx：28 wire Command——fs/shell/upload/download/FileOp(Ls)/env/clipboard/portscan/net/screenshot/keylog/screenwatch/hashdump(SAM/SYSTEM)/bof/socks/pivot/token 操作/inject；缺持久化、缺 LSASS dump（显式 deferred）。CS：全生态+SSH beacon。BRc4：110+ 命令 + Shadowcloak |
| **横向移动与凭据**（10） | **1.5** | **5.0** | **4.5** | Nyx：token 窃取/伪造/还原 + SAM/SYSTEM hive 流 + portscan/net + SOCKS pivot；无 kerberoast/PtH/PtT/psExec/WMI/WinRM，无持久化。CS：完整横向+持久化矩阵。BRc4：dcsync/mimikatz/kerberoast/PtH |
| **服务端与团队协作**（10） | **3.5** | **4.5** | **3.5** | Nyx：axum 14 API+7 beacon 路由、argon2id RBAC+`spawn_blocking` 卸载、哈希链审计、SQLite WAL+计数持久化、kill-date 严格、GC 活跃豁免+重新准入、任务分批、贡献性 X25519+帧上限、extc2 fail-closed；单 operator 团队协作功能薄。CS：成熟 team server + REST/WS/gRPC + 协作。BRc4：Ratel API + bruteratel.py |
| **自动化与脚本生态**（5） | **2.0** | **5.0** | **3.5** | Nyx：scripting-rhai 3 event bus + 全局预算（累计 op/派发上限/墙钟/频率）；无 operator 级脚本语言。CS：Aggressor Script + Aggressor AI + Beacon Interpreter。BRc4：Ratel API/bruteratel.py 自动化 |
| **操作UI**（5） | **2.5** | **5.0** | **3.5** | Nyx：Tauri2+React+Three.js，29 GUI 命令，3D 拓扑，session 级任务历史 + pending 过期；缺会话元数据 overlay 与报告闭环。CS：成熟 GUI + Beacon Graph + 4.13 刷新。BRc4：检测风险分级 UI（detectionSeverity） |
| **跨平台**（5） | **0.5** | **4.0** | **3.0** | Nyx：仅 Windows 植入体（implant-core 抽象 P8 未动工）；server 可 mac/Linux 跑。CS：Windows Beacon + SSH Beacon 覆盖 Unix。BRc4：Windows 为主，跨平台面窄 |
| **工程与发布**（10） | **3.5** | **5.0** | **4.0** | Nyx：488 测试、CI 门禁（`--build` 固定、fork-PR 守卫、权限硬化）、release 探针 fail-closed、CHANGELOG 纪律、能力四档口径；未过现代 Win11+EDR 支持矩阵回归。CS：商业级发布/支持矩阵/多年硬化。BRc4：商业发布但漏洞披露史存在 |

**加权总分（满分 500）：**

| 框架 | 加权分 | 归一化 |
|---|---|---|
| **Nyx（冲刺后）** | **230.0** | **46.0%** |
| Cobalt Strike 4.13 | 490.0 | 98.0% |
| BRc4 Catalyst 2.6.3 | 412.5 | 82.5% |

> 读法：百分比是"相对商品级成熟度"的加权代理，不是任务完成度。Nyx 的 46% 主要由三道硬墙拖低——**加载器（1.0）**、**跨平台（0.5）**、**横向/凭据（1.5）**；逃避与服务端/工程三个维度（3.0/3.5/3.5）已进入可对位区间。

---

## 3. 各维度差距细述

### 3.1 端点逃避实装（15）— 冲刺后 3.0

**Nyx 现有**：indirect syscall + Hell/Halo/Tartarus SSN 三级回退；BYOUD-Gap/LACUNA CET-safe 栈欺骗（leaf frame 不进 shadow stack）；AMSI/ETW patchless 盲打（DR0+VEH+RF）；ntdll unhook（KnownDlls fresh+disk）；module stomping + threadless inject（HWBP，已自测）；内核侧 evasion SDK（ETW-TI 盲化、DKOM、PPL 剥离、callback/minifilter 摘除、LSASS 直读）——但属 operator 工具且 PG 门禁后为实验性。

**前沿**：CS 4.13 默认 sleepmask 重写覆盖 Beacon 代码+heap（100MB 上限）、BeaconGate 全代理调用 RAS；BRc4 custom-compiler 每代唯一二进制、模块踩踏+PEB LDR hook。

**差距与收敛（→P8–P13）**：
- **睡眠混淆接线**：修 `kits.rs:39-79` 短路，接通 Foliage 加密 + heap 区域注册（P2.1a/最高优先；对应 P12 前的基础逃避）。
- **heap sleep mask**：`MemoryMaskKit::register_region` 从 32B session key 扩到 beacon 配置结构体/句柄（P12 前完成，追平 CS）。
- **CET-safe 栈欺骗保持并验证**：BYOUD-Gap 已在维度领先（见 §4），需物理机 CET-on 验证 + LACUNA 多层链扩展（P12a/P12b）。
- **注入多样性**：module stomping 被 PE-sieve `.text` hash 盯死时无替代；补 early-bird APC/thread-hijack（P12/P15 窗口）。
- **ETW-Ti APC 窗口利用**（P12b）、CET 内核禁用（P12e，经 BYOVD）。

### 3.2 加载器与投递（10）— 冲刺后 1.0（能力缺失但诚实）

**Nyx 现有**：`nyx-loader` 加密+组装真；`tools/srdi` 反射加载工具（sRDI，PE 导出表 OOB 已修复 CRITICAL-25/26/27）；**反射加载 fail-loud**——`LAYER2_PEB_WALK` 65B 碎片已删除，`generate_loader_stub`/`wrap_payload` 返回 `Result`，`--encrypt` 强制，release 探针门禁 fail-closed。**这是本次冲刺最重要的诚实化**：loader 从"纸面 1.0 却宣称可用"改为"明确不可交付，直到真实 layer-2 存在"。

**前沿**：CS UDRL 生态（PE 头擦除、TLS callback 处理、Arsenal Kit 模板）+ drip-loading 分片投递 + Payload Store；BRc4 custom-compiler Badger（-30% 体积）+ safe_http 2–3KB PIC 桩。

**差距与收敛（→P13d/P8c/P9c）**：
- **真实 layer-2 反射加载**：在目标上完成映射→重定位→导入→TLS→头擦除（P2.1b；对应 P13d stager 体系）。
- **UDRL 强化**：PE 头擦除、`.pdata` 处理、section 权限收敛（P13d）。
- **分段投递**：Stage0 PIC <512B → Stage1 sRDI → Stage2 模块拉取，每段不同信道（P13d）。
- **模块热更新 + 签名验证**：ED25519 模块签名，防信道劫持后下发恶意模块（P9c/P9e）。

### 3.3 C2信道与流量仿冒（10）— 冲刺后 2.0

**Nyx 现有**：HTTPS WinHTTP 主信道（TLS SetOption 时序正确）；SOCKS5 pivot + ChannelData/Close 原语；8 信道枚举（Https/DohDns/Dns/SmbPipe/Tcp/SlackApi/LlmApi/Mcp），**SmbPipe/Tcp 门禁为未实现**（`SetChannel` 拒 + `dispatch_send_recv` 拒交易），tcp/smb I/O 已加 10s/5s 超时；Slack/MCP 经 server boot-time `TransportStack` 接线（extc2 中继 + HMAC-SHA256 帧完整性 + key 派生防跨信道重放）；JA3/JA4 服务端指纹；Malleable C2 解析 + c2lint + 7 变换（`mask` 非 CS 线兼容已文档化）；TLS 指纹 emitter 为 Err stub（feature 后）。

**前沿**：CS HTTPS/DNS/SMB/TCP 四协议 + UDC2 + profile 运行时覆盖 + WebSocket/gRPC 流 + drip-loading；BRc4 多通道 + 2.6 自定义响应类型/响应头。

**差距与收敛（→P10/P11）**：
- **transport 接线**：DoH/DNS/LLM 三个 Transport impl 零消费者——补 server/implant 消费路径（P10a，接线非重写，trait 已存在）。
- **信道编排器**：`TransportStack` 主→降级→再降级 + 自动健康切换（P10f；server 侧 boot-time stack 已是雏形）。
- **TLS 指纹 emitter 实装**：`build_impersonating_client` 从 Err stub 到 uTLS 式指纹库（P11a，Chrome/FF/Edge JA4 池）。
- **DNS 隧道 / WebSocket / H2 多路复用**（P10c/P10d/P10e）；**办公时间回调**（P11e，对齐 BRc4 working-hours）。
- **Malleable v2**：HTTP Method/URI/Header/Cookie/body 模板编译期嵌入（P11c）。

### 3.4 BOF与扩展执行（10）— 冲刺后 2.0

**Nyx 现有**：coff 解析器（AMD64 解析+重定位，7 测试）；bof-runner 执行器——**CS ABI `go(args, alen)`**（`bof-runner/src/win.rs:489-498`）、**W^X**（写页 `PAGE_READWRITE`→执行前翻 `PAGE_EXECUTE_READ`，调用时无 W+X 页）、RAII 释放（`win.rs:455-459`）、externals 扩展（kernel32/ntdll 经 `GetModuleHandleA`/`GetProcAddress` 动态解析，`win.rs:409-414`）；agent-dev BOF 参数透传。

**前沿**：CS BOF + 异步 BOF（fork-and-run）+ **BOF-PE**（进程内 PE）+ Beacon Interpreter（C VM）；BRc4 coffexec_async + dotnet store（10 assemblies）。

**差距与收敛（→P9/P12/P13）**：
- **BOF API 扩面**：BeaconPrintf 之外补 DataParser（BeaconDataParse 系列）等标准 BOF API（P9 窗口）。
- **异步 BOF**：NCC 风格事件驱动驻留模型，不 fork（P12/P13 窗口）。
- **BOF-PE 等价**：进程内映射完整 PE（P13d sRDI 的 BOF 化）。
- **模块隔离执行**：每模块独立页 + 独立线程 + 卸载即 VirtualFree + 栈擦除（P9d）。

### 3.5 后渗透工具集（10）— 冲刺后 2.5

**Nyx 现有**：28 wire Command——fs 操作/upload/download/FileOp（新增 `Ls` tag 5）/shell/driveinfo/env/clipboard/portscan/net/screenshot/keylog/screenwatch/hashdump（SAM/SYSTEM hive 流 + 离线解密工作流说明）/BOF/socks/pivot/steal·make·rev2self token/getuid/inject/trex/ping/sleep/SetChannel/exit。

**前沿**：CS 全生态（mimikatz 集成、进程注入全家桶、SSH beacon、持久化）；BRc4 110+ 命令 + Shadowcloak LSASS 转储。

**差距与收敛（→P14/P15）**：
- **hashdump LSASS**：method=2 显式 deferred（loudest IOC）——对齐 Shadowcloak 需内核直读路径（P14a，已有 operator-kernelsdk 雏形）。
- **持久化**：当前为零（仅运行时 DKOM）——service/registry/WMI/sched-task 生态（P15 窗口）。
- **进程注入多样性**：见 §3.1。
- **凭据面**：DPAPI/浏览器凭据、SAM 离线解析自动化（P14e/P14d）。

### 3.6 横向移动与凭据（10）— 冲刺后 1.5

**Nyx 现有**：token 窃取/伪造/还原/getuid；SAM/SYSTEM hive 流（需 SYSTEM 上下文 + 离线解密）；portscan/net（`NetSessionEnum` 系）；SOCKS pivot 通道。

**前沿**：CS psExec/WinRM/WMI/SSH beacon 横向 + PtH/PtT + kerberoast/AS-REP + 持久化；BRc4 dcsync/mimikatz/kerberoast/PtH。

**差距与收敛（→P14/P15）**：
- **Kerberoasting/AS-REP**（P14b/P14c）；**SAM 离线解析→NTLM hash**（P14d）；**DPAPI 主密钥**（P14e）；**Kerberos 票据操作**（P14f）。
- **PtH**（P15d，`InitializeSecurityContext`+`SEC_WINNT_AUTH_IDENTITY`，无 mimikatz）；**PtT**（P15e）。
- **WMI/PSRemoting 远程执行**（P15a/P15b，纯 Rust 无 `wmic.exe`/`powershell.exe`）；**SMB Beacon**（P15c，内网无出网主机中继）。
- 完整验收链：`pth → wmi_exec → inject beacon → smb relay back`（P15 验收标准）。

### 3.7 服务端与团队协作（10）— 冲刺后 3.5

**Nyx 现有**：axum 14 静态 API + 7 beacon 路由 + 6 kernel（条件）路由；argon2id RBAC + **`spawn_blocking` 卸载 + 预算耗尽 fail-closed**；哈希链审计日志；SQLite WAL + `send_counter`/`last_recv` 迁移持久化；kill-date 严格校验；任务分批 ≤ 上限；GC 活跃豁免 + 会话重新准入（`TaskResponse` 重注册）；贡献性 X25519 + 帧上限（协议面）；extc2 `TransportStack` 单例 + Slack HMAC fail-closed boot。

**前沿**：CS 商业 team server + REST/WS/gRPC 流 + 多 operator 协作；BRc4 Ratel API + bruteratel.py。

**差距与收敛（→M3/P18）**：
- **会话/资产/任务/证据统一时间线**（M3 验收）；**任务归属/移交/审批**（M3）。
- **审计可检索导出** + RBAC 角色化（P18c：admin/operator/viewer + 权限 + 不可篡改审计）。
- **服务器联邦**（P18a：Raft 3 节点 + 会话迁移 + operator 协作锁）。
- 已闭合面（冲刺）无需再投：kill-date、GC、批处理、argonc 卸载、fail-closed extc2。

### 3.8 自动化与脚本生态（5）— 冲刺后 2.0

**Nyx 现有**：scripting-rhai 3 event bus（server 接入）+ **全局预算**：累计 op 上限（`on_progress` 永不复位）+ 单次派发上限 + 墙钟 deadline + `nyx_log` 调用/字节频率限流。

**前沿**：CS Aggressor Script + Aggressor AI + Beacon Interpreter；BRc4 Ratel API/bruteratel.py 自动化。

**差距与收敛（→M3/P18）**：
- **operator 级脚本面**：事件驱动的脚本化操作（对齐 Aggressor）——M3 扩展机制（manifest/版本/权限/依赖/测试样例）。
- **AI 辅助**：Aggressor AI 等价物或 LLM 驱动任务链（P12d LLM-EDR 工具链为研究侧）。
- **载荷 CI/CD**：`git push → 变形 → 三编译目标 → 签名 → 分发`（P18d）。

### 3.9 操作UI（5）— 冲刺后 2.5

**Nyx 现有**：Tauri2+React+Three.js；29 GUI 命令（`client-ui-web/src/components/CommandInput.tsx`）；3D 拓扑；**session 级任务历史**（App store，切会话不清空）+ 结果 `session_id` + **pending 过期合成错误**。

**前沿**：CS 4.13 刷新 GUI + Beacon Graph；BRc4 detectionSeverity/detectionClass 风险分级展示。

**差距与收敛（→M3）**：
- **会话元数据 overlay**（P2.1g/最高优先遗留）；**报告闭环**（证据→报告导出，M3 验收）。
- **风险分级展示**（对齐 BRc4 detectionSeverity：BYOVD/注入/内核命令标红）。
- **主 JS 包体积预算**（当前 ~825KB 超构建工具警戒线，M3 明确要求按需加载）。

### 3.10 跨平台（5）— 冲刺后 0.5

**Nyx 现有**：Windows 植入体（implant-win，独立 nightly GNU 工具链）；server/operator 侧 mac/Linux 开发主机可跑；Linux/macOS 植入体为零。

**前沿**：CS SSH Beacon（Unix 覆盖）+ Windows Beacon；BRc4 Windows 为主 + 部分跨平台。

**差距与收敛（→P8/P16/P17）**：
- **implant-core 抽象**：协议/beacon 调度/模块加载/HAL/crypto 提取为平台无关 crate（P8a–P8f）——一切跨平台的地基。
- **Linux 植入体**（P16：ELF PIC + syscall SSN + ptrace/memfd 注入 + shadow/keyring 凭据 + systemd 持久化 + 容器逃逸）。
- **macOS 植入体**（P17：Mach-O dylib + SIP/TCC 绕过 + keychain + ESF 规避）。

### 3.11 工程与发布（10）— 冲刺后 3.5

**Nyx 现有**：488 测试（workspace ~267 实跑全绿）；CI 门禁（offset-resolver `--build` 固定、fork-PR 守卫、权限硬化）；release 探针 fail-closed（`scripts/release/*.ps1`）；CHANGELOG 纪律（每条引用 commit/`file:line`）；能力四档口径（STATUS.md）；v0.3.1/v0.3.2 关闭全部 27 CRITICAL；selftest 48 导出符号。

**前沿**：CS 商业发布/支持矩阵/多年现场硬化；BRc4 商业发布（存在泄露版本风险）。

**差距与收敛（→M0–M4）**：
- **能力台账**（M0：每项状态/证据/限制/负责人）；**四层测试门禁 L1–L4**（M1）。
- **支持矩阵回归**：Win11 24H2/25H2 + 主流 EDR 下的真实环境验证（P18e detector sandbox 化）。
- **稳定/实验通道 + 升级回退演练**（M4）；**检测器沙箱 CI**（P18e）。
- **CRITICAL-19 beacon 任务隔离**（架构项，v0.4.0 排期）。

---

## 4. 领先点（Nyx 真实领先）

### 4.1 BYOUD-Gap CET-safe 栈欺骗 vs CS Draugr

CS 官方 `sleepmask-vs` 的 Draugr 模板用**传统 .pdata 覆写**伪造调用栈：把 [RSP] 链指向合法模块非 leaf 函数中间点。在 CET（shadow stack）启用的 Win11 24H2+ 上，RSP 与 shadow stack 不匹配触发 **#CP fault**——这是官方模板的已知缺陷（research §1.1 对比表）。Nyx 的 `stack.rs` BYOUD-Gap/LACUNA 走 **leaf frame + gap 地址**，不进 shadow stack，unwind-walk 层 CET-safe；且为运行时 gap 池扫描而非硬编码。**这是 CS 与 BRc4（未公开确认 CET-safe）都没有的维度优势**。诚实标注：裸 RSP swap 路径在 CET-on 仍会降级（`stack.rs` 明确文档化），领先的是 BYOUD-Gap leaf-chain 路径本身。

### 4.2 内核 SDK（BYOVD / ETW-TI / DKOM）——CS 与 BRc4 均无此维度

CS 4.13 与 BRc4 2.6.3 均为**纯用户态商品框架**，物理上没有内核驱动维度（OST 属 Outflank 独立产品，非 CS 本体；CS:RL 的 ETW-TI 盲化仍在研究实验室阶段）。Nyx 的 `operator-kernelsdk`（BYOVD R/W、ETW-TI 盲化、DKOM 进程隐藏、PPL 剥离、callback/minifilter 摘除、PG 窗口、LSASS 直读）对 Cortex XDR 这类**纯内核回调、零用户态 hook** 的 EDR 是唯一有效路径。诚实标注：PG 窗口现已被 `verified=false` 门禁（冲刺后不再有 bugcheck 彩票），驱动加载走显式 unload 契约，整体为实验性、未过现代环境回归。

### 4.3 Fail-Loud 诚实性（工程文化领先）

本次冲刺的最大结构性变化：**把"宣称可用"改为"诚实报缺"**——loader 反射加载 fail-loud（能力缺失但绝不静默假装可用）、hashdump LSASS 显式 Err（loudest IOC）、SmbPipe/Tcp 信道拒绝而非接受后挂死、Slack HMAC key 缺失即 boot 失败、token 消费原子 fail-closed、release 探针门禁 fail-closed、PG 未验证即拒绝。CS/BRc4 闭源，无法做同等透明审计。这对**授权演练的可信度**（知道什么能用、什么不能用）是真实差异化。

---

## 5. 结论：有效能力评分对比 + 收敛路线

### 5.1 有效能力评分

| 框架 | 加权分/500 | 归一化 | 一句话 |
|---|---|---|---|
| **Nyx（2026-07-31 冲刺后）** | **230.0** | **46.0%** | 逃避/服务端/工程三轴可对位；加载器、跨平台、横向/凭据三道硬墙拖低 |
| Cobalt Strike 4.13 | 490.0 | 98.0% | 商品级全维度成熟，逃避面（sleepmask/BOF-PE/Interpreter）与生态无可争议第一 |
| BRc4 Catalyst 2.6.3 | 412.5 | 82.5% | custom-compiler + Shadowcloak + 110 命令，用户态逃避强、生态次之 |

> 归一化百分比的语义：**相对商品级成熟度的加权代理**。Nyx 46% 不代表任务完成度，而是"十一个维度距商品级的加权距离"；其中逃避（3.0/5）、服务端（3.5/5）、工程（3.5/5）已进入同一量级区间。

### 5.2 收敛路线

**阶段一：已闭合（2026-07-31 冲刺，勿再投入）**

协议贡献性 X25519 + 帧上限 + `FileOp::Ls`；beacon 发送纪律 + S2C 重放 + OOM；ZeroBits/PoolParty/BOF ABI/W^X；信道门禁 + I/O 超时；store 原子 token + char-safe mask + busy_timeout + 计数持久化；server GC 活跃豁免 + 重新准入 + 批处理 + kill-date 严格校验 + argon2 卸载 + TransportStack 接线 + Slack fail-closed；内核 daemon 认证；PG 门禁；KernelRw 契约；`--build` 必填；rhai 全局预算；UI session 历史 + pending 过期；`nyx-mutate` 删除；loader fail-loud。**验收证据**：workspace check + test 全绿（server 72 / transport 109 / protocol 49 / store 28）。

**阶段二：2–4 月（P8–P9 + 整改计划 M0/M1）**——把"已对位但未接线"变成"可用"：

1. **睡眠混淆接线 + heap mask**（修 `kits.rs` 短路；最高优先遗留项）。
2. **真实反射加载 layer-2**（loader 从 fail-loud 到真交付；对齐 CS UDRL）。
3. **transport 消费路径**（DoH/DNS/LLM 接线；TLS emitter 实装 P11a）。
4. **BOF API 扩面 + 异步 BOF**（追平 coffexec_async）。
5. **implant-core 抽象**（P8a–P8f 地基，为跨平台铺路）。
6. **持久化基础 + 首个横向执行原语**（psExec/WMI 之一 + kerberoast；对齐 P14/P15 子集）。
7. **CET 物理机验证 + 现代 Win11 24H2/25H2 + 单一 EDR 支持矩阵回归**（M1 验收门）。

**阶段三：6 月+（P10–P18）**——追平生态、拉开内核/工程差异：

1. **多信道编排器 + 流量仿冒深度**（P10f/P11：CDN 前置、WS、DNS 隧道、H2、Malleable v2、办公时间回调）。
2. **LACUNA 六层链 + LLM-EDR 自动化 + CET 内核禁用**（P12/P13）。
3. **凭据/横向全矩阵**（P14/P15：DPAPI、票据操作、PtH/PtT、WMI/WinRM/SMB beacon；验收链 `pth→wmi_exec→inject→smb relay`）。
4. **Linux/macOS 植入体**（P16/P17，依托 P8 implant-core）。
5. **联邦 + PQC + RBAC + 检测器沙箱 CI**（P18）。
6. **发布工程**（M3/M4：协作闭环、报告导出、稳定/实验通道、升级回退）。

---

## 附：来源清单

| 来源 | 用途 | 时效 |
|---|---|---|
| [Cobalt Strike 4.13 官方博客](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation) | §1.1 能力事实 | 2026-06-10 发布页 |
| [CS 官方 releasenotes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm) | §1.1 版本演化/4.12 事实 | 持续更新 |
| [Brute Ratel C4 发布页](https://bruteratel.com/category/release/) + releases.txt | §1.2 Catalyst v2.6.3 事实 | 2026-07-30 |
| [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) | §1.3/§3 Nyx 基线（**早于冲刺，作基线快照**） | 2026-07-18，冲刺后需以代码为准 |
| [`docs/research/commercial_c2_security_research.md`](../research/commercial_c2_security_research.md) | §1/§4 商业框架技术细节（CS 4.13 时间线、Draugr vs BYOUD-Gap、BRc4 编译器） | 研究素材，非产品承诺 |
| [`docs/STATUS.md`](../STATUS.md) + [`CHANGELOG.md`](../../CHANGELOG.md) | §1.3/§2/§3 Nyx 冲刺后状态（file:line 证据） | 2026-08-01 |
| 仓库代码（`crates/*` file:line，见 §1.3 表） | §1.3/§3 Nyx 能力实证 | 分支 `refactor/ah-audit-followups` |
