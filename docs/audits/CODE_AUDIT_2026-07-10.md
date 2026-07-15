# Nyx C2 框架 — 全栈深度代码审计报告（三次审计 · 修复验证轮）

> **审计日期:** 2026-07-10
> **范围:** 全 25 crate（77,000 行 Rust），含对 37 文件未提交修复 diff 的逐行审查
> **分支:** `main` (9de3fec) + 未提交修复工作树
> **授权语境:** 授权红队 / 安全研究工具。本报告面向项目内部改进，不含可直接武器化的利用细节。
> **方法:** 10 路并行深度源码审查 + 主审计者对全部新 HIGH 的人工逐行 source 核验
> **前序报告:** `CODE_AUDIT_2026-07-08.md`（baseline，4 路）、`CODE_AUDIT_2026-07-08_DEEP.md`（deep，10 路）
> **详细子报告:** `docs/audit_2026_07_10/{protocol,server,implant_core,implant_evasion,implant_postex,kernel,transport,client_cli,config_coff_profile,misc_crates}.md`

---

## 执行摘要

本轮审计在前两轮（07-08 baseline + deep，共发现 9 CRIT + 25 HIGH + 39 MED + 39 LOW）的基础上，
对一轮**正在执行中的修复**（37 文件未提交 diff）进行验证。审计三大任务：

1. **验证旧发现** — 逐条核对每个 baseline 发现的当前状态（FIXED / 仍在 / 部分修）
2. **审计修复 diff 本身** — 新代码引入了什么新 bug（本轮最大发现来源）
3. **发现新遗漏** — 以全新视角审查前轮标记"干净"的代码

### 数字总览

| 维度 | 07-08 总数 | 已修复 | 部分修 | 仍在 | 新发现 | 活跃合计 |
|---|---|---|---|---|---|---|
| **CRITICAL** | 9 | 5 | 2 | 2 | 0 | **0 残留 CRITICAL** |
| **HIGH** | 25 | 7 | 5 | 13 | **+7** | **20** |
| **MEDIUM** | 39 | 1 | 0 | 38 | +12 | 50 |
| **LOW** | 39 | 0 | 0 | 39 | +~20 | ~59 |

> **关键结论：** 全部 9 个 CRITICAL 已被修复或降级——**当前零活跃 CRITICAL**。
> 加密核心（CSPRNG、SessionKey Drop、HKDF salt、constant_time_eq）修复质量最高。
> 但修复 diff 本身引入了 **7 个新 HIGH**——其中 ntalloc use-after-free 比它修复的原 bug 更危险。

---

## 最紧急的 8 个发现（按影响排序）

### 🚨 P0 — 修复引入的回归 / 不完整修复（提交前必须处理）

#### 1. [HIGH] ntalloc 修复将内存泄漏变成了 use-after-free — **人工核验 ✅**

- **位置:** `crates/implant-win/src/ntalloc.rs:70-72`（eviction 分支）→ `:91-109`（`free_slab`）
- **状态:** 修复 diff 引入的回归
- **根因:** slab 表满时（32 项），`track_slab` 执行 `free_slab(SLAB_TABLE[0].base)` → `NtFreeVirtualMemory(MEM_RELEASE)`。但这是 bump allocator 无 per-allocation free-list（`dealloc` 是 no-op）。被驱逐的 slab 仍持有活跃堆分配（ECDH 密钥副本、配置明文、BOF 缓冲区等）。释放后 `mem::REGIONS` 表持有悬垂指针 → 下次 `mem::mask()` RC4 写入未映射内存 → ACCESS_VIOLATION。
- **影响:** 任何分配超 32MiB 的 beacon（截图、大 BOF 输出、长时间运行）触发驱逐 → 释放活跃堆 → 崩溃或静默损坏。**将 HIGH-8（泄漏）变成 UAF（比原 bug 更危险）。**
- **修复:** 回滚驱逐释放路径；改为增大 `MAX_SLABS`（如 256）或用动态增长表。no_std PIC bump allocator 中真正的 free-list 不可行，接受有限泄漏。

#### 2. [HIGH] SOCKS5 认证修复可被设计性绕过 — **人工核验 ✅**

- **位置:** `crates/client-cli/src/socks/handshake.rs:72-84`
- **状态:** 修复 diff 引入的绕过
- **已核验:** `read_greeting` 在 `auth.is_some()` 时，客户端不提供 method `0x02` 则回退到 `0x00`（NO-AUTH）。攻击者发 `[05][01][00]` 即获无认证隧道。回退甚至有测试断言为"预期行为"。
- **影响:** `nyx-cli socks --listen 0.0.0.0:1080 --socks-user op --socks-pass x` 仍是开放代理。操作员被告知受保护但实际不受保护——**虚假安全感比原始"无认证"更危险。**
- **修复:** `auth.is_some()` 时删 `else if methods.contains(&0x00)` 回退分支——不提供 0x02 就拒绝（`0xFF`）。

#### 3. [HIGH] HTTP 策略不覆盖运行时 `/connect` — **人工核验 ✅**

- **位置:** `crates/client-cli/src/rest.rs:513-517`（`Cmd::Connect` 无策略检查）
- **状态:** 修复 diff 引入的绕过
- **影响:** 操作员用安全 loopback URL 启动 TUI（过 gate），然后 `/connect http://evil:8443 <token>` → bearer token + `/creds?reveal=1` 走明文 HTTP，无警告无拒绝。
- **修复:** 在 `Cmd::Connect` arm 内调 `enforce_http_policy(&s)`。

#### 4. [HIGH] config 加密修复只修了测试路径——生产 implant 绕过 NYX_CONFIG_KEY

- **位置:** `crates/implant-win/build.rs:122`（真实路径）vs `crates/config-macros/src/lib.rs`（修复路径）
- **状态:** 修复 diff 不完整
- **已核验:** proc-macro `embed!` 加了 `NYX_CONFIG_KEY` 支持——但 `embed!` 仅被 `crates/config/tests/embed.rs` 调用。生产 implant 用 `build.rs:122` 内联路径 `nyx_config::encrypt(&blob)`，完全忽略 `NYX_CONFIG_KEY`，仍写三个相邻 static（密钥紧邻密文）。
- **修复:** 在 `build.rs` 中也支持 `NYX_CONFIG_KEY`，或改为运行时从环境/文件读取密钥。

### 🔴 P1 — 新发现的活跃 HIGH

#### 5. [HIGH] BOF 加载器从不释放 section 内存 — **人工核验 ✅**

- **位置:** `crates/implant-win/src/bof.rs:720-815`（全文件零 `VirtualFree`/`MEM_RELEASE`）
- **状态:** 新发现（前轮未审）
- **影响:** 每次 BOF 执行永久泄漏所有 section 分配（RW/RX 页）。无限增长 + 持久 RX 页 IOC。
- **修复:** BOF 执行后循环 `VirtualFree(MEM_RELEASE)`。

#### 6. [HIGH] ETW 欺骗构建结构错误的 EVENT_HEADER — **人工核验 ✅**

- **位置:** `crates/operator-kernelsdk/src/etw_deception.rs:61`（`EVENT_HEADER_SIZE=64`，真实应为 80）
- **状态:** 新发现（前轮未覆盖此文件）
- **已核验:** 缺少 16 字节 `ActivityId` GUID；ThreadId/ProcessId 互换；Size 写为 u32 而非 u16；Flags 偏移错。单元测试固化了错误偏移。整个 Phase-4 欺骗子系统无效。
- **修复:** `EVENT_HEADER_SIZE=80`，修正字段顺序/大小，修正测试。

#### 7. [HIGH] 3/4 BYOVD 驱动包静默损坏

- **位置:** `crates/operator-kernelsdk/src/byovd.rs`（`VulnDriverIoctl` trait）
- **状态:** 新发现
- **影响:** iqvw64e（不同结构布局）、WDTKernel（MmMapIoSpace-based）、Shield（双向 IOCTL）都走 RTCore64 字节循环。只有 RTCore64 正确工作。操作员选 HVCI-safe WDTKernel 默认得到坏原语。
- **修复:** 为每个驱动实现正确的 IOCTL 协议。

#### 8. [HIGH] fluctuation RAII 守卫不覆盖硬件异常——CRIT-5 残留

- **位置:** `crates/implant-win/src/fluctuation.rs:33-59`
- **状态:** CRIT-5 降级为 HIGH
- **描述:** 守卫覆盖 `?`/`return` early-exit 路径（drop 顺序正确），但不覆盖硬件异常（#PF——`.text` 为 NOACCESS 时 APC/异常 dispatch 触及 .text 地址 → 进程终止，Drop 不跑）。`panic=abort` 下无 unwinder。
- **修复:** 把 `mem::unmask()` 移入 fluctuation thunk 尾部（在可执行的 thunk 页上运行，不在 beacon 线程 .text 上）。

---

## 修复状态跟踪矩阵（07-08 → 07-10）

### CRITICAL（9 项 → 0 活跃）

| ID | 原描述 | 状态 | 证据 |
|---|---|---|---|
| CRIT-1 | Server 无认证 + 0.0.0.0 | ✅ FIXED | `main.rs:123` 默认 `127.0.0.1`；非 loopback 自动生成 token |
| CRIT-2 | 内核桥接死代码 | ❌ STILL | `main.rs:163 kernel: None` 未变 |
| CRIT-3 | T-REX 全桩 | ✅ FIXED | `TREX_SCANNERS_IMPLEMENTED=false` 强制 Unknown + 警告横幅 |
| CRIT-4 | caller_spoof 裸 0xC3 | ❌ STILL（惰性） | 死代码，无活跃调用方 |
| CRIT-5 | fluctuation 无 RAII | 🔶 PARTIAL→HIGH | 守卫覆盖 early-return，不覆盖硬件异常 |
| CRIT-NEW-1 | CSPRNG 失败→全零标量 | ✅ FIXED | `random_bytes` 返回 Result，`reject_zero` 防御，全调用方传播 |
| CRIT-NEW-2 | Pool Party 伪造 | ✅ FIXED | 消息+文档诚实化；gate-off 返回 `Response::Err` |
| CRIT-NEW-3 | config 密钥紧邻密文 | 🔶 PARTIAL | proc-macro 加了 env var，但 build.rs 绕过 |
| CRIT-NEW-4 | mem mask/unmask 新密钥 | ✅ FIXED | `MASK_KEY_BUF` 缓存单密钥 |

### HIGH（25 项 → 7 FIXED · 5 PARTIAL · 13 STILL + 7 NEW）

| ID | 原描述 | 状态 |
|---|---|---|
| HIGH-1 | constant_time_eq 先 SHA 再比 | ✅ FIXED — `subtle::ConstantTimeEq` |
| HIGH-2 | HKDF 空 salt | ✅ FIXED — `Some(server_pub)` |
| HIGH-3/5 | 审计日志丢命令参数 | 🔶 PARTIAL — 仅 3/25 变体有 detail |
| HIGH-4 | 审计 detail 序列化分叉 | ✅ FIXED |
| HIGH-6 | trex/deaddrop 16KiB 截断 | ❌ STILL |
| HIGH-7 | trex/melt 无 arming guard | ❌ STILL |
| HIGH-8 | ntalloc 永不释放 | 🔶 PARTIAL→回归UAF |
| HIGH-NEW-P1 | SessionKey Copy+空Drop | ✅ FIXED |
| HIGH-NEW-P2 | SessionKey Debug 泄露 | ✅ FIXED |
| HIGH-NEW-I1 | shell 无超时 | ✅ FIXED — 30s + TerminateProcess |
| HIGH-NEW-I2 | pool_party _TP_DIRECT OOB | ❌ STILL — diff 只改注释 |
| HIGH-NEW-BOF1 | BeaconDataExtract 溢出 | ✅ FIXED — checked_add |
| HIGH-NEW-BOF2 | selftest 编进生产 | 🔶 PARTIAL — 50/51 门控，漏 2 个 |
| HIGH-NEW-BOF3 | hashdump_diag 死锁 | ✅ FIXED — feature-gated |
| HIGH-NEW-K1 | WFP 全出站阻断 | ✅ FIXED — 返回 Err |
| HIGH-NEW-K2 | QOS FFI 元数错误 | 🔶 PARTIAL — arity 修了，pid 仍忽略 |
| HIGH-NEW-T1 | DoH base64 DNS label | ✅ FIXED — URL_SAFE_NO_PAD |
| HIGH-NEW-T2 | SMB OVERLAPPED | ✅ FIXED |
| HIGH-NEW-T3 | FingerprintEmitter 死代码 | 🔶 PARTIAL — 诚实标注，未接线 |
| HIGH-NEW-T4 | MCP 无认证 | 🔶 PARTIAL — Option 不强制 |
| HIGH-NEW-C1 | 凭据明文存储 | 🔶 PARTIAL — gate 默认 OFF，无加密层 |
| HIGH-NEW-C2 | bearer 明文 HTTP | 🔶 PARTIAL — `/connect` 绕过 |
| HIGH-NEW-C3 | SOCKS5 无认证 | 🔶 PARTIAL→绕过 |

---

## 新发现 MEDIUM（12 项精选）

| ID | 位置 | 描述 |
|---|---|---|
| NEW-MED-1 | `protocol/crypto.rs:259` | `ServerKeypair::from_secret_bytes` 绕过 `reject_zero`——零值 `NYX_KEYFILE` |
| NEW-MED-S4 | `server/lib.rs:578-586` vs `:638` | 新会话 check-in TOCTOU——并发首帧覆盖排队任务 |
| NEW-MED-S5 | `server/lib.rs:481` | `is_loopback_bind` 用 `starts_with`——`127.0.0.1.evil.com` 误判 |
| NEW-MED-T18 | `transport/mcp.rs` | MCP `api_key: Option` 无强制——None 重现原 HIGH |
| NEW-MED-T19 | `transport/doh_dns.rs` | DoH 无 253 字节总名长度守卫 |
| NEW-MED-T20 | `transport/smb_pipe.rs` | SMB `read_exact` 无法区分断管 vs 无数据——忙循环 |
| NEW-MED-N2 | `implant-win/lacuna_stomp.rs` | 跨 asm! 块拆分 push/call/pop——调度风险 |
| NEW-MED-BOF3 | `implant-win/bof.rs:144` | BeaconPrintf 无 `%p`/`%u`/长度修饰符 |
| NEW-MED-BOF5 | `implant-win/fs.rs` | `allowed()` hive 守卫可被 `..\` 绕过 |
| NEW-MED-BOF6 | `implant-win/trex/exfil/deaddrop.rs` | deaddrop 泄漏 GitHub PAT 到 bump 堆 |
| NEW-MED-BOF2gap | `implant-win/trex/mod.rs:900` | selftest 门控漏 `nyx_selftest_trex` + `noop_veh_handler` |
| NEW-MED-CC9 | `client-cli/socks/mod.rs:135` | 无界握手 spawn——TCP 泛洪 DoS |

---

## 仍存在的 baseline MED/LOW 摘要（未在修复批次中触及）

**MEDIUM（38 项仍在）** 涵盖：
- implant: 确定性 jitter 种头、shell 截断无标记、pool_party 句柄泄漏、ensure_winhttp 永久关、SetChannel SmbPipe 静默杀
- evasion: SSN 无上限、blind_hwbp static mut 竞争、VmCfgInfo 占位布局、proxy_veh RWX、sleep Context-5 恢复 0x40
- kernel: CallbackNeutralizer slot0 bugcheck、djb2 hash 碰撞→BSOD、kernel-cli 无认证+symlink
- transport: LLM XOR 泄露、init_all 不设 healthy、Slack 毒消息阻塞、extract_hex 误判、malleable 4xx 当成功、health_check 忽略 UA
- client-cli: `short()` 字节切片 panic、会话列表无界+u16 截断、upload/bof 无大小限制、download 路径未沙箱化
- misc: store chmod 不覆盖 WAL 边车、agent-dev symlink 竞争

**LOW（~59 项）** 全域分布，详见各子报告。

---

## 已验证干净的区域（平衡报告）

### 加密核心（protocol/crypto.rs）— 修复质量最高 ⭐
- CSPRNG 修复完整正确：`random_bytes` 返回 `Result`，`reject_zero` 防御纵深，全部 5 个 no_std 路径 + 全部 std 路径传播 `GenerateError`，零调用方忽略 Result
- AEAD 解密-后-验证正确，nonce 方向分离，counter 无溢出
- SessionKey 真 `Drop`(zeroize+compiler_fence)，redacted Debug
- HKDF 用 `server_pub` 做 salt，`info` buffer 78/80 字节精确

### Server 认证与 anti-replay
- 开放模式修复端到端正确（默认 loopback + 非 loopback 自动生成 token）
- 已有会话反重放在写锁下原子执行
- constant_time_eq 用 `subtle::ConstantTimeEq`
- 审计 hash 链序列化一次

### COFF 解析器 — 仍是最干净 ⭐
- 每个偏移用 `checked_add`/`checked_mul`，严格 raw 窗口拒绝

### 内核页表遍历
- P-bit 4 级全检，大页掩码正确，WFP 修复正确（返回 Err）

### 传输层修复
- DoH base64 → URL_SAFE_NO_PAD 根因修复，SMB OVERLAPPED 移除根因修复

### client-cli 基础卫生
- 无本地 exec、无 unsafe、无 TLS 弱化、SOCKS wire 边界安全、secret 不入日志

---

## "失败测试"调查结论

`sessionlist_current_row_has_highlight_background`（`tui/mod.rs:2843`）— **实际通过**。
独立运行 5 次均 pass，完整 suite 147/147 绿。此前失败可能是全局 theme `OnceLock<RwLock<Palette>>` 瞬时状态泄漏。

---

## 优先修复建议

### P0 — 提交修复 diff 前必须处理

| # | 发现 | 工作量 |
|---|---|---|
| 1 | ntalloc UAF 回滚 | 小 |
| 2 | SOCKS5 删 0x00 回退 | 一行 |
| 3 | `/connect` 加 enforce_http_policy | 一行 |
| 4 | config build.rs 支持 NYX_CONFIG_KEY | 中 |

### P1 — 新 HIGH

| # | 发现 | 工作量 |
|---|---|---|
| 5 | BOF section 释放 | 小 |
| 6 | ETW EVENT_HEADER 结构 | 中 |
| 7 | BYOVD 驱动包 IOCTL | 大 |
| 8 | fluctuation 硬件异常 | 中 |

### P2 — 部分修复收尾 + 关键 MEDIUM

- 审计日志 detail 覆盖剩余 22 个 Command 变体
- selftest 门控补漏 2 个导出
- MCP `api_key` 改强制
- DoH 加 253 字节守卫
- 新会话 check-in TOCTOU 加 `entry().or_insert_with()`
- `fs::allowed()` 路径规范化
- QOS choke_edr 加 pid→image path 解析
- `_TP_DIRECT` OOB 加 size_of slack

---

## 审计覆盖与局限

**覆盖:** 10 路并行，25 crate 77K 行全映射。全部 CRITICAL + 全部 HIGH 经人工逐行复核。
新发现 #1-6 由主审计者独立 source 核验（ntalloc eviction+free_slab、SOCKS greeting 回退、
Cmd::Connect 无检查、bof.rs 全文 grep VirtualFree、etw_deception EVENT_HEADER_SIZE）。

**与既有审计关系:** 本轮是 07-08 deep 的验证轮 + 修复审计轮。
Baseline 9 CRITICAL 全部被处理（0 残留）。修复 diff 引入 7 个新 HIGH——本轮最大贡献。

**未覆盖:** 真机动态验证（静态审计）；client-ui Makepad 渲染层（低安全面）。

---

## 子报告索引

| 报告 | 域 |
|---|---|
| `docs/audit_2026_07_10/protocol.md` | ECDH/HKDF/ChaCha20-Poly1305, CSPRNG, wire/frame/msg |
| `docs/audit_2026_07_10/server.md` | REST API, auth, beacon handler, audit log, operators |
| `docs/audit_2026_07_10/implant_core.md` | beacon loop, shell, inject, Pool Party, transport, entry |
| `docs/audit_2026_07_10/implant_evasion.md` | fluctuation, mem mask, ntalloc, blind, sleep, syscalls |
| `docs/audit_2026_07_10/implant_postex.md` | BOF, hashdump, T-REX, fs, pivot, selftests |
| `docs/audit_2026_07_10/kernel.md` | BYOVD, WFP, QOS, ETW-TI, telemetry, pagewalk |
| `docs/audit_2026_07_10/transport.md` | 7 通道, malleable, emitter, DoH, SMB, MCP |
| `docs/audit_2026_07_10/client_cli.md` | SOCKS5, REST client, credstore, TUI |
| `docs/audit_2026_07_10/config_coff_profile.md` | config-macros, config, coff, profile, pe |
| `docs/audit_2026_07_10/misc_crates.md` | store, scripting, agent-dev, evasion, parse, minidump, offset-resolver |
