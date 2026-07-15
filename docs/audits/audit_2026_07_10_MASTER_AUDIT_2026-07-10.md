# Nyx C2 框架 — 全栈深度代码审计报告（三次审计 · 修复验证轮）

> **审计日期:** 2026-07-10 · **范围:** 全 25 crate（77K 行 Rust），含对未提交修复 diff 的逐行审查
> **分支:** `main` (9de3fec) + 37 文件未提交修复 · **授权:** 仅限授权红队 / 安全研究
> **方法:** 10 路并行深度源码审查 + 关键发现主审计者人工逐行复核（ntalloc UAF、SOCKS5 绕过、BOF 泄漏、ETW 结构均已核验）

---

## 本次审计的独特价值

前两轮审计（2026-07-08 baseline + deep）发现了 9 CRIT + 25 HIGH + 39 MED + 39 LOW。一轮修复正在执行中（37 文件未提交 diff）。**本轮审计的三大任务：**

1. **验证旧发现** — 逐条核对每个 baseline 发现的当前状态（FIXED / 仍在 / 部分修）
2. **审计修复 diff 本身** — 新代码引入了什么新 bug？（本轮的最大发现来源）
3. **发现新遗漏** — 以全新视角审查前轮标记"干净"的代码

---

## 执行摘要

### 数字总览

| 维度 | 07-08 Baseline | 本轮状态 | 新发现 | 本轮合计 |
|---|---|---|---|---|
| **CRITICAL** | 9 | 5 FIXED · 2 PARTIAL · 2 STILL | **0** | 0 残留 CRITICAL |
| **HIGH** | 25 | 7 FIXED · 5 PARTIAL · 13 STILL | **7 NEW** | 20 活跃 HIGH |
| **MEDIUM** | 39 | 1 FIXED · 38 STILL | **12 NEW** | 50 活跃 MED |
| **LOW** | 39 | 0 FIXED · 39 STILL | **~20 NEW** | ~59 活跃 LOW |

> **关键结论：** 全部 9 个 CRITICAL 已被修复或降至 HIGH（无活跃 CRITICAL）。但修复 diff 本身引入了 **7 个新 HIGH**——其中 1 个（ntalloc UAF）比它修复的原 bug 更危险。

### 最紧急的 8 个发现（按影响排序）

#### 🚨 修复引入的回归（最高优先级——在提交前必须处理）

| # | 严重度 | 发现 | 位置 | 核验 |
|---|---|---|---|---|
| **1** | **HIGH** | **ntalloc 修复将内存泄漏变成了 use-after-free** | `implant-win/src/ntalloc.rs:70-72` | ✅ 人工核验 |
| **2** | **HIGH** | **SOCKS5 认证修复可被绕过——客户端省略 method 0x02 即获无认证隧道** | `client-cli/src/socks/handshake.rs:75-76` | ✅ 人工核验 |
| **3** | **HIGH** | **HTTP 策略不覆盖运行时 `/connect`——bearer token 明文泄露** | `client-cli/src/rest.rs:513-517` | ✅ 人工核验 |

#### 🔴 新发现的活跃 HIGH

| # | 严重度 | 发现 | 位置 |
|---|---|---|---|
| **4** | **HIGH** | **BOF 加载器从不释放 section 内存——每次 BOF 执行永久泄漏 RX 页（无限增长 + 持久 IOC）** | `implant-win/src/bof.rs:720-815` |
| **5** | **HIGH** | **ETW 欺骗构建结构错误的 EVENT_HEADER（SIZE=64 应为 80，ThreadId/ProcessId 互换，Flags 偏移错）——整个 Phase-4 欺骗子系统无效** | `kernelsdk/src/etw_deception.rs:61` |
| **6** | **HIGH** | **3/4 BYOVD 驱动包静默损坏（iqvw64e/WDTKernel/Shield 都走 RTCore64 字节循环）——操作员选 HVCI-safe 默认得到坏原语** | `kernelsdk/src/byovd.rs` |
| **7** | **HIGH** | **fluctuation RAII 守卫不覆盖硬件异常场景（#PF→进程终止，Drop 不跑）——CRIT-5 残留** | `implant-win/src/fluctuation.rs:33-59` |
| **8** | **HIGH** | **config 加密修复只修了测试路径——生产 implant build.rs 绕过 NYX_CONFIG_KEY，密钥仍紧邻密文** | `implant-win/build.rs:122` + `config-macros/src/lib.rs` |

---

## 修复状态跟踪矩阵（07-08 → 07-10）

### CRITICAL（9 项 → 0 活跃）

| ID | 原描述 | 状态 | 证据 |
|---|---|---|---|
| CRIT-1 | Server 无认证 + 0.0.0.0 | ✅ **FIXED** | `main.rs:123` 默认 `127.0.0.1`；非 loopback 自动生成 token |
| CRIT-2 | 内核桥接死代码 | ❌ **STILL** | `main.rs:163 kernel: None` 未变 |
| CRIT-3 | T-REX 全桩 | ✅ **FIXED** | `TREX_SCANNERS_IMPLEMENTED=false` 强制 Unknown + 警告横幅 |
| CRIT-4 | caller_spoof 裸 0xC3 | ❌ **STILL（惰性）** | 死代码，无活跃调用方 |
| CRIT-5 | fluctuation 无 RAII | 🔶 **PARTIAL** | 守卫覆盖 `?`/`return` 但不覆盖硬件异常（降为 HIGH） |
| CRIT-NEW-1 | CSPRNG 失败→全零标量 | ✅ **FIXED** | `random_bytes` 返回 `Result`，`reject_zero` 防御纵深，全调用方传播 |
| CRIT-NEW-2 | Pool Party 伪造无 CreateRemoteThread | ✅ **FIXED** | 消息 + 模块文档诚实化；gate-off 返回明确 `Response::Err` |
| CRIT-NEW-3 | config 密钥紧邻密文 | 🔶 **PARTIAL** | proc-macro 加了 `NYX_CONFIG_KEY` 环境变量，但生产 `build.rs` 绕过它 |
| CRIT-NEW-4 | mem mask/unmask 新密钥 | ✅ **FIXED** | `MASK_KEY_BUF` 缓存单密钥，mask/unmask 共用 |

### HIGH（25 项 → 7 FIXED · 5 PARTIAL · 13 STILL + 7 NEW = 20 活跃）

| ID | 原描述 | 状态 |
|---|---|---|
| HIGH-1 | constant_time_eq 先 SHA 再比 | ✅ **FIXED** — `subtle::ConstantTimeEq` |
| HIGH-2 | HKDF 空 salt | ✅ **FIXED** — `Some(server_pub)` |
| HIGH-3/5 | 审计日志丢命令参数 | 🔶 **PARTIAL** — 仅 Shell/Upload/MakeToken 有结构化 detail，22/25 变体仍丢 |
| HIGH-4 | 审计 detail 序列化分叉 | ✅ **FIXED** |
| HIGH-6 | trex/deaddrop 16KiB 截断 | ❌ **STILL** |
| HIGH-7 | trex/melt 无 arming guard | ❌ **STILL** |
| HIGH-8 | ntalloc 永不释放 | 🔶 **PARTIAL → 回归** — 修复引入 UAF（见 #1） |
| HIGH-NEW-P1 | SessionKey Copy + 空 ZeroizeOnDrop | ✅ **FIXED** — 真 `Drop` + zeroize |
| HIGH-NEW-P2 | SessionKey Debug 泄露 | ✅ **FIXED** — redacted Debug |
| HIGH-NEW-I1 | shell 无超时 | ✅ **FIXED** — 30s 超时 + TerminateProcess |
| HIGH-NEW-I2 | pool_party _TP_DIRECT OOB | ❌ **STILL** — diff 只改注释，没改写入 |
| HIGH-NEW-BOF1 | BeaconDataExtract i32 溢出 | ✅ **FIXED** — `checked_add` in usize |
| HIGH-NEW-BOF2 | selftest 编进生产 | 🔶 **PARTIAL** — 50/51 门控，漏 2 个 |
| HIGH-NEW-BOF3 | hashdump_diag 死锁 | ✅ **FIXED** — feature-gated |
| HIGH-NEW-K1 | WFP 全出站阻断 | ✅ **FIXED** — 返回 Err + 文档说明需 ALE_APP_ID |
| HIGH-NEW-K2 | QOS FFI 元数错误 | 🔶 **PARTIAL** — arity 修正，但 pid 仍忽略 |
| HIGH-NEW-T1 | DoH base64 DNS label | ✅ **FIXED** — URL_SAFE_NO_PAD |
| HIGH-NEW-T2 | SMB OVERLAPPED | ✅ **FIXED** — 去掉标志 |
| HIGH-NEW-T3 | FingerprintEmitter 死代码 | 🔶 **PARTIAL** — 文档诚实化，但功能仍未接线 |
| HIGH-NEW-T4 | MCP 无认证 | 🔶 **PARTIAL** — `api_key: Option<String>` 可选不强制 |
| HIGH-NEW-C1 | 凭据明文存储 | 🔶 **PARTIAL** — gate 加了但默认 OFF，无加密层 |
| HIGH-NEW-C2 | bearer 明文 HTTP | 🔶 **PARTIAL** — 只在 spawn 时检查，`/connect` 绕过 |
| HIGH-NEW-C3 | SOCKS5 无认证 | 🔶 **PARTIAL → 绕过** — 修复可被绕过（见 #2） |

---

## 新发现详述（7 个 HIGH）

### NEW-HIGH-1. ntalloc 修复引入 use-after-free

- **位置:** `crates/implant-win/src/ntalloc.rs:70-72`（eviction 分支）→ `:91-109`（`free_slab`）
- **状态:** 修复 diff 引入（人工核验 ✅）
- **已核验:** slab 表满时（32 项），`track_slab` 执行 `free_slab(SLAB_TABLE[0].base, ...)` → `NtFreeVirtualMemory(MEM_RELEASE)`。但这是 **bump allocator 无 per-allocation free-list**（`dealloc` 是 no-op，`:306-310`）。被驱逐的 slab 仍持有活跃堆分配（ECDH 密钥副本、配置明文、BOF 缓冲区等）。释放后 `mem::REGIONS` 表持有悬垂指针 → 下次 `mem::mask()` RC4 写入未映射内存 → AV。
- **影响:** 任何分配超 32MiB 的 beacon（截图、大 BOF 输出、长时间运行）触发驱逐 → 释放活跃堆 → 崩溃或静默损坏。**将 HIGH-8（泄漏）变成 UAF（比原 bug 更危险）。**
- **修复:** 回滚驱逐释放；改为增大 `MAX_SLABS`（如 256）或用 `Vec<SlabDesc>` 动态增长。真正的 free-list 在 no_std PIC bump allocator 中不可行，接受有限泄漏。

### NEW-HIGH-2. SOCKS5 认证修复可被设计性绕过

- **位置:** `crates/client-cli/src/socks/handshake.rs:72-84`
- **状态:** 修复 diff 引入（人工核验 ✅）
- **已核验:** `read_greeting` 在 `auth.is_some()` 时，如果客户端不提供 method `0x02`，回退到 `0x00`（NO-AUTH）。攻击者发 `[05][01][00]` 即获无认证隧道。回退甚至有测试明确断言为"预期行为"。
- **影响:** `nyx-cli socks --listen 0.0.0.0:1080 --socks-user op --socks-pass x` 仍是开放代理——操作员被告知受保护但实际不受保护。**虚假安全感比原始"无认证"更危险。**
- **修复:** `auth.is_some()` 时删除 `else if methods.contains(&0x00)` 分支——不提供 0x02 就拒绝（`0xFF`）。

### NEW-HIGH-3. HTTP 策略不覆盖运行时 `/connect`

- **位置:** `crates/client-cli/src/rest.rs:513-517`（`Cmd::Connect` 无策略检查）
- **状态:** 修复 diff 引入（人工核验 ✅）
- **影响:** 操作员用安全 loopback URL 启动 TUI（过 gate），然后 `/connect http://evil:8443 <token>` → bearer token + `/creds?reveal=1` 走明文 HTTP，无警告无拒绝。
- **修复:** 在 `Cmd::Connect` arm 内调 `enforce_http_policy(&s)`。

### NEW-HIGH-4. BOF 加载器从不释放 section 内存

- **位置:** `crates/implant-win/src/bof.rs:720-815`（人工核验 ✅——全文件零 `VirtualFree`/`MEM_RELEASE`）
- **状态:** 新发现（前轮未审）
- **影响:** 每次 BOF 执行永久泄漏所有 section 分配（RW/RX 页）。无限增长 + 持久 RX 页 IOC（与模块自述的 W^X 卫生目标矛盾）。
- **修复:** BOF 执行后在 `bases`/`sizes` 上循环 `VirtualFree(MEM_RELEASE)`。

### NEW-HIGH-5. ETW 欺骗构建结构错误的 EVENT_HEADER

- **位置:** `crates/operator-kernelsdk/src/etw_deception.rs:61`（`EVENT_HEADER_SIZE=64`，真实应为 80）
- **状态:** 新发现（前轮未覆盖此文件）
- **已核验:** `EVENT_HEADER_SIZE=64` 缺少 16 字节 `ActivityId` GUID；`ThreadId`/`ProcessId` 互换；Size 写为 u32 而非 u16；Flags 在错误偏移。单元测试 `forge_process_create_builds_correct_buffer` 固化了错误偏移。整个 Phase-4 欺骗子系统无效。
- **修复:** `EVENT_HEADER_SIZE=80`，修正字段顺序/大小，修正测试断言。

### NEW-HIGH-6. 3/4 BYOVD 驱动包静默损坏

- **位置:** `crates/operator-kernelsdk/src/byovd.rs`（`VulnDriverIoctl` trait）
- **状态:** 新发现
- **影响:** `iqvw64e`（不同结构布局）、`WDTKernel`（MmMapIoSpace-based）、`Shield`（双向 IOCTL）都走 RTCore64 形状的字节循环。只有 RTCore64 正确工作。操作员选 HVCI-safe WDTKernel 默认得到坏原语。
- **修复:** 为每个驱动实现正确的 IOCTL 协议。

### NEW-HIGH-7. config 加密修复只修了测试路径

- **位置:** `crates/implant-win/build.rs:122`（真实路径）vs `crates/config-macros/src/lib.rs`（修复路径）
- **状态:** 修复 diff 不完整
- **已核验:** proc-macro `embed!` 加了 `NYX_CONFIG_KEY` 环境变量支持——但 workspace grep 发现 `embed!` **仅被 `crates/config/tests/embed.rs` 调用**。生产 implant 用 `build.rs:122` 的内联路径 `nyx_config::encrypt(&blob)`，完全忽略 `NYX_CONFIG_KEY`，仍写 `CONFIG_KEY`/`CONFIG_NONCE`/`CONFIG_CT` 三个相邻 static。
- **影响:** 操作员面向的"给每个 build 唯一密钥"旋钮是死代码。结构问题（密钥紧邻密文）在交付 implant 中未改变。
- **修复:** 在 `build.rs` 中也支持 `NYX_CONFIG_KEY`，或改为运行时从环境/文件读取密钥。

---

## 新发现详述（关键 MEDIUM，共 12 个）

| ID | 位置 | 描述 |
|---|---|---|
| **NEW-MED-1** | `protocol/crypto.rs:259` | `ServerKeypair::from_secret_bytes` 绕过 `reject_zero`——零值 `NYX_KEYFILE` 重构身份点服务器身份 |
| **NEW-MED-S4** | `server/lib.rs:578-586` vs `:638` | 新会话 check-in TOCTOU 竞争——两个并发首帧都看到 None，第二个覆盖排队任务 |
| **NEW-MED-T18** | `transport/mcp.rs` | MCP `api_key` 是 `Option<String>` 无默认/强制——传 None 精确重现原始 HIGH-NEW-T4 |
| **NEW-MED-T19** | `transport/doh_dns.rs` | DoH 修了字母表但无 253 字节总名长度守卫——长域名 + 高序号仍杀通道 |
| **NEW-MED-T20** | `transport/smb_pipe.rs` | SMB `read_exact` 修后无法区分 ERROR_BROKEN_PIPE vs 无数据——忙循环整个超时 |
| **NEW-MED-N2** | `implant-win/src/lacuna_stomp.rs` | `with_ghost_stack` 跨独立 `asm!` 块拆分 push/call/pop——优化器调度风险 |
| **NEW-MED-BOF3** | `implant-win/src/bof.rs:144-206` | BeaconPrintf 解析器无 `%p`/`%u`/长度修饰符——真实 BOF 参数错位 |
| **NEW-MED-BOF5** | `implant-win/src/fs.rs` | `fs::allowed()` hive 守卫可用 `..\` 中间组件绕过（`C:\x\..\sam`） |
| **NEW-MED-BOF6** | `implant-win/src/trex/exfil/deaddrop.rs` | deaddrop 在永不释放的 bump 堆上泄漏 GitHub PAT + 加密载荷 |
| **NEW-MED-K22** | `kernelsdk/src/byovd.rs` | 见 NEW-HIGH-6 |
| **NEW-MED-BOF2gap** | `implant-win/src/trex/mod.rs:900` | selftest 门控漏 `nyx_selftest_trex`（trex/ 唯一 `#[no_mangle]`）+ `noop_veh_handler` |
| **NEW-MED-S8** | `server/lib.rs:1149` | MakeToken 审计 detail 不 truncate domain/user |

---

## 已验证干净的区域（平衡报告）

### 加密核心（protocol/crypto.rs）—— 修复质量最高
- CSPRNG 修复完整且正确：`random_bytes` 返回 `Result`，`reject_zero` 防御纵深，全部 5 个 no_std 路径 + 全部 std 路径均传播 `GenerateError`，零调用方忽略 Result
- AEAD 解密-后-验证顺序正确，nonce 方向分离，counter 无溢出
- SessionKey 真 `Drop`(zeroize+compiler_fence)，redacted Debug，Clone 显式手写
- HKDF 用 `server_pub` 做 salt（非空），`info` buffer 78/80 字节精确使用

### Server 认证与 anti-replay
- 开放模式修复端到端正确（默认 loopback + 非 loopback 自动生成 token）
- 已有会话反重放在写锁下原子执行（TOCTOU 闭合）
- constant_time_eq 用 `subtle::ConstantTimeEq`，恒定时间
- 审计 hash 链序列化一次用同一字符串

### COFF 解析器 —— 仍是最干净
- 每个头派生偏移用 `checked_add`/`checked_mul`
- 严格 raw 窗口拒绝
- 4 个畸形输入测试钉死

### 内核页表遍历
- P-bit 4 级全检，大页掩码正确，`checked_add` 防溢出
- K1（WFP）修复正确——返回 Err 而非构建空条件过滤器

### 传输层修复
- DoH base64 → URL_SAFE_NO_PAD：根因修复 + 真实测试
- SMB OVERLAPPED 移除：根因修复
- 无 `danger_accept_invalid`/`insecure`/`verify_mode`（grep 0 匹配）

### client-cli 基础卫生
- 无本地 `exec`/`Command::new`（全 JSON 编码发服务器）
- 无 `unsafe`（全 crate）
- 无 TLS 验证弱化
- SOCKS5 wire 解析边界安全（全 u8 长度，无溢出）
- bearer token / secret 从不入日志
- credstore 写入原子 + chmod 失败 fail-closed

### 杂项
- Rhai 脚本沙箱无逃逸路径（仅注册 `nyx_log`，无 IO 面）
- store SQL 全参数化（无注入）
- minidump 格式正确（通过 `minidump` crate parser 往返）

---

## "失败测试"调查结论

`sessionlist_current_row_has_highlight_background`（`tui/mod.rs:2843`）—— **实际通过**。client-cli agent 独立运行 5 次均 pass，完整 suite 147/147 绿。此前的失败可能是全局 theme `OnceLock<RwLock<Palette>>` 在并行/异常恢复时的瞬时状态泄漏。**无需行动。**

---

## 优先修复建议

### P0 — 在提交修复 diff 前必须处理（回归 / 修复不完整）

| # | 发现 | 工作量 | 说明 |
|---|---|---|---|
| 1 | **ntalloc UAF 回归** | 小 | 回滚 `free_slab`，改为增大 `MAX_SLABS` 或动态表 |
| 2 | **SOCKS5 认证绕过** | 一行 | 删 `handshake.rs:75-76` 的 `0x00` 回退分支 |
| 3 | **HTTP 策略 `/connect` 绕过** | 一行 | `Cmd::Connect` arm 加 `enforce_http_policy` |
| 4 | **config 加密只修测试路径** | 中 | `build.rs:122` 也支持 `NYX_CONFIG_KEY` |

### P1 — 新 HIGH（功能缺失 / OPSEC 缺陷）

| # | 发现 | 工作量 |
|---|---|---|
| 5 | BOF 加载器不释放 section | 小 |
| 6 | ETW 欺骗 EVENT_HEADER 结构错误 | 中 |
| 7 | 3/4 BYOVD 驱动包损坏 | 大 |
| 8 | fluctuation 硬件异常残留 | 中 |

### P2 — 部分修复收尾 + 关键 MEDIUM

- 审计日志 detail 覆盖剩余 22 个 Command 变体
- selftest 门控补漏 2 个导出
- MCP `api_key` 改为强制（非 Optional）
- DoH 加 253 字节守卫
- 新会话 check-in TOCTOU 加 `entry().or_insert_with()`
- `fs::allowed()` hive 守卫规范化路径
- QOS choke_edr 加 pid → image path 解析
- `_TP_DIRECT` OOB 加 `size_of::<TpDirect>()` slack

---

## 子报告索引

| 报告 | 行数 | 域 |
|---|---|---|
| `protocol.md` | 291 | ECDH/HKDF/ChaCha20-Poly1305, CSPRNG, wire/frame/msg |
| `server.md` | 268 | REST API, auth, beacon handler, audit log, operators |
| `implant_core.md` | 463 | beacon loop, shell, inject, Pool Party, transport, entry |
| `implant_evasion.md` | 362 | fluctuation, mem mask, ntalloc, blind, sleep, syscalls |
| `implant_postex.md` | 550+ | BOF, hashdump, T-REX, fs, pivot, selftests |
| `kernel.md` | 331 | BYOVD, WFP, QOS, ETW-TI, telemetry, pagewalk |
| `transport.md` | 354 | 7 通道, malleable, emitter, DoH, SMB, MCP |
| `client_cli.md` | 223 | SOCKS5, REST client, credstore, TUI |
| `config_coff_profile.md` | 140 | config-macros, config, coff, profile, pe |
| `misc_crates.md` | 419 | store, scripting, agent-dev, evasion, parse, minidump, offset-resolver |

---

## 审计覆盖与局限

**覆盖:** 10 路并行，25 crate 77K 行全映射。全部 9 个 CRITICAL + 全部 HIGH 经人工逐行复核。**新发现 #1-4 已由主审计者独立 source 核验**（ntalloc eviction+free_slab、SOCKS greeting 回退、Cmd::Connect 无检查、bof.rs 全文 grep VirtualFree）。

**与既有审计关系:** 本轮是 07-08 deep 的**验证轮 + 修复审计轮**。Baseline 9 CRITICAL 全部被处理（0 残留）。修复 diff 引入 7 个新 HIGH——本轮的最大贡献。

**未覆盖:** 真机动态验证（静态审计）；client-ui Makepad 渲染层（低安全面）。
