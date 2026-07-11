# Nyx C2 框架 — 深度代码审计报告

> **审计日期:** 2026-07-08 · **审计范围:** 全 24 crate（75,800 行 Rust） · **分支:** `main` (9de3fec)
> **审计方法:** 4 路并行深度源码审查（crypto/wire · server/REST · implant-win · kernelsdk/transport）+ 关键发现人工复核
> **授权语境:** 授权红队 / 安全研究工具。本报告面向项目内部改进,不含可直接武器化的利用细节。

---

## 执行摘要

| 严重度 | 数量 | 域分布 |
|---|---|---|
| **CRITICAL** | 5 | 2 server · 3 implant |
| **HIGH** | 8 | 2 crypto · 3 server · 4 implant · (kernel/transport 无) |
| **MEDIUM** | 11 | 4 server · 4 implant · 2 kernel · 2 transport · (crypto 无) |
| **LOW** | 12 | 散布各域 |

**最紧急的 3 个问题:**
1. **Server 默认无认证启动** — 未设 `NYX_TOKEN` 时,`/api/task`(下发 implant 任务)、`/api/creds?reveal=1`(明文凭据)、`/api/kernel/*` 对任何能连到 8443 端口的客户端开放,且角色为 Admin。
2. **T-REX 侦察引擎是 100% 桩代码** — 所有 NT/Win32 API 包装器返回 null/0/空,`assess_user_mode()` 永远返回 `ThreatTier::Clean`,即使在 CrowdStrike Fortress 主机上。操作员会基于假结果部署不足的规避手段。
3. **`caller_spoof` 裸 `0xC3` 回退** — 当首选 `ADD RSP,imm8;RET` 模式未找到时,扫描器接受 ntdll `.text` 中任意 `0xC3` 字节作为返回桩。`0xC3` 常出现在多字节指令的操作数/位移中,跳到指令中间 = `STATUS_ACCESS_VIOLATION`(即 STATUS.md 记录的 0xC0000005 崩溃的根因)。

**最干净的域:** 加密核心(protocol/crypto.rs)和内核页表遍历(pagewalk.rs)设计严谨。AEAD 解密-后-验证顺序正确,nonce 空间按方向分离,反重放在写锁下权威执行。内核 72 个 `unwrap()` 无一在攻击者可控的生产路径上。传输层无硬编码密钥、无禁用 TLS 验证。

---

## CRITICAL 发现

### CRIT-1. Server 默认以无认证 + Admin 角色启动
- **位置:** `crates/server/src/lib.rs:767-771`(`authenticate` 开放模式分支);`crates/server/src/main.rs:110-114`(bootstrap 只在有 env 时加载)
- **已核验:** `authenticate()` 在 `api_token` 为 None 时落入 `_anonymous` + `Role::Admin`
- **描述:** 当 `NYX_OPERATORS_FILE`、`NYX_BOOTSTRAP_OPERATOR`、`NYX_TOKEN` 均未设置时(快速测试的最小阻力路径,也是 `AppState::default()`),`authenticate()` 对所有请求返回 `Allowed(_anonymous, Admin)`。默认绑定 `0.0.0.0:8443`(`main.rs:147`)。
- **影响:** 任何能连到 8443 端口的客户端可下发任意 implant 任务、读取明文凭据、调用内核端点(若接线)。一次 `curl POST /api/task` 即可在所有活跃 beacon 上执行任意 shell。
- **修复:** 无显式 `NYX_ALLOW_OPEN=1` 时拒绝启动;或首次启动自动生成 token 并打印到 stderr(已有先例:server pubkey)。至少在开放模式下默认绑 `127.0.0.1`。

### CRIT-2. 内核守护进程桥接是死代码 — 所有 `/api/kernel/*` 永远返回 "no daemon"
- **位置:** `crates/server/src/main.rs:129`(`kernel: None`);路由 `lib.rs:328-336`;处理器 `kernel.rs:122-126`
- **已核验:** `main.rs` 确认 `kernel: None`,从不构造 `KernelBridge`
- **描述:** `AppState.kernel` 构造为 `None` 且从未接线。`KernelBridge::new()` 存在但无调用点。每个内核处理器命中 `None => "no daemon"` 分支。STATUS.md 声称的 "6 个内核 TUI 命令接线" 在服务端不可用。
- **影响:** 正确性 bug(非直接漏洞):操作员依赖内核桥接会得到静默失败。但 STATUS.md 的安全叙事(Admin 门控)建立在一个从未运行的特性上。
- **修复:** 在 `main.rs` 从 `NYX_KERNEL_DAEMON` env 构造 `KernelBridge` 并设入 `AppState`;或移除路由和 `kernel.rs` 模块直到特性完成,并修正 STATUS.md。

### CRIT-3. T-REX 侦察引擎全部是桩代码 — 在任何主机上都返回 "Clean"
- **位置:** `crates/implant-win/src/trex/mod.rs:779-847`(全部 helper 桩);被 `assess_user_mode()` `:162-191` 调用
- **已核验:** `create_toolhelp_snapshot() → null_mut()`、`open_sc_manager() → null_mut()`、`query_system_module_info() → null`、`get_ntoskrnl_base() → None`、`probe_etw_provider_enabled() → false` 等,全部 no-op
- **描述:** T-REX 的每个 NT/Win32 API 包装器都是空实现。因为 `scan_processes` 在 snapshot 为 null 时立即返回(`:235`),`scan_service_registry` 在 key 为 null 时返回(`:269`),`assess_user_mode()` **永远**返回 `ThreatTier::Clean` + 空产品列表。决策引擎看到无产品 → `Clean` → `recommend()` 输出 "Minimal: indirect syscalls + sleep obfuscation sufficient. No kernel evasion needed." — 即使在 Fortress(HVCI+CET)主机上。`assess_kernel()`(`:195-213`)同样空洞。
- **影响:** **操作失败 + 虚假安全感。** 操作员在 CrowdStrike 保护的主机上运行 T-REX 得到 "Clean — no evasion needed",以不足的规避部署 → 立即检测。`nyx_selftest_trex`(`:876`)在每个主机上退出 0xE0(Clean)— 该退出码无意义。T-REX 是 2026-07-07 新写的,从未在真实对抗环境中验证。
- **修复:** (a) 用 PEB-walk API 解析实现(代码库已有 `crate::resolve::export_addr` — 用它替代桩),或 (b) 标记 `#[allow(dead_code)]` + 在 `assess_user_mode` 加 `UNIMPLEMENTED` 横幅,使无操作员信任其输出。

### CRIT-4. `caller_spoof` 裸 `0xC3` 字节回退 — 跳入指令中间导致 0xC0000005 崩溃
- **位置:** `crates/implant-win/src/caller_spoof.rs:135-141`(fallback 扫描);被 `caller_spoof_thunk.rs:34` 消费
- **已核验:** fallback 循环 `if b == 0xC3 { return Some(ReturnStub { addr: mod_base + j, ... }) }` 确实匹配任意 0xC3 字节
- **描述:** 当首选 `ADD RSP,imm8;RET`(`48 83 C4 ?? C3`)模式未找到时,扫描器接受 ntdll `.text` 中**任意** `0xC3` 字节作为返回桩。`0xC3` 频繁作为无关多字节指令的操作数/位移(如 `mov rax, 0x...C3`)。thunk 推送此地址为假返回地址;目标 `RET` 后 RIP 落在该字节 — 若它在指令中间,CPU 从该偏移解码垃圾 → `STATUS_ACCESS_VIOLATION`。这是 STATUS.md(`:32`)归因于 "raw-byte trampoline debugging" 的崩溃的**具体根因**。
- **影响:** **崩溃。** 每当首选模式未找到(在某些 ntdll prologue 布局的构建上可能),回退返回指令中间地址,下一次欺骗调用 AV。
- **修复:** 完全移除裸 `0xC3` 回退;或验证匹配的 `0xC3` 在函数边界(前面有 `0xCC` 填充或 `C3`/`C2` RET)。不在已解码指令起始的 RET 不能用作返回桩。

### CRIT-5. `fluctuation` 睡眠掩码无 unwind 安全守卫 — mask/unmask 之间 panic 永久砖化 DLL
- **位置:** `crates/implant-win/src/fluctuation.rs:66-78`(DR 保存/清除 → mask → thunk → unmask → DR 恢复)
- **已核验:** `mask()` → `thunk_fn()` → `unmask()` 顺序执行,中间无 Drop 守卫
- **描述:** `do_fluctuate` 执行 `save_dr` → `clear_dr` → `mem::mask()`(加密 .text + 堆)→ `thunk_fn()`(翻 PAGE_NOACCESS,睡眠,翻回 RX)→ `mem::unmask()`(解密)。无 `Drop` 守卫。若 `thunk_fn()` panic(或线程在 PAGE_NOACCESS 窗口被 APC/异常杀死),`unmask()` 永不执行 → `.text` 保持加密状态,thunk 已翻回 RX 但字节是密文 → 后续每条 `.text` 指令解码为垃圾 → beacon 线程返回时崩溃。DR 状态也丢失。代码库已知 RAII 模式(`syscalls.rs:209` 的 `FreshMapGuard`)— 只是这里没应用。
- **影响:** **永久 implant 死亡。** 睡眠窗口内任何 panic/异常导致 `.text` 不可恢复的密文。
- **修复:** 用 `struct MaskGuard` 包裹,`Drop` 无条件调 `mem::unmask()`;同样 `DrGuard` 恢复 DR 状态。(注:此 `no_std` 构建 `panic=abort`,`Drop` 在 panic 时不跑 — 但在 early-return/`?` 错误路径上会跑,这是现实的失败模式。)

---

## HIGH 发现

### 加密 / 线协议

**HIGH-1. `constant_time_eq` 先 SHA-256 再比摘要 — 对输入长度非恒定时间**
- 位置:`crates/server/src/lib.rs:446-471`、`crates/protocol/src/crypto.rs`(共享)
- 描述:实现对两边各做 SHA-256 再比 32 字节摘要。`sha2` 的 update 时间与输入长度成正比,攻击者可用变长 bearer token 计时区分长度类,收窄 operator token 暴力破解。该函数用于门控整个控制 API。
- 修复:用 `subtle::ConstantTimeEq`(已是 chacha20poly1305 的传递依赖)对原始字节比较。

**HIGH-2. HKDF 使用空 salt(无域分离 / 密钥承诺)**
- 位置:`crates/protocol/src/crypto.rs:206`
- 描述:`derive_session_key` 用 `salt = None`。`info` 绑定了双 pubkey + `"nyx-session-v1"` 标签(好),但无 per-session nonce 或 transcript 绑定。若 implant 复用 ephemeral 密钥或两台 server 共享长期密钥,会推导出确定性相关的密钥,且无法检测。
- 修复:在 HKDF salt 混入 per-session 随机 nonce(check-in 明文发送,16 字节);或 `salt = HKDF-Extract(early, transcript_hash)`。

### Server / REST

**HIGH-3. 审计日志只记录命令名,丢弃参数 — 取证归因失效**
- 位置:`crates/server/src/lib.rs:1123-1130`
- 描述:`audit.append("task", ..., json!({"command": cmd_name}))` 只记 `cmd_name`(`"shell"`、`"upload"`),丢弃参数。`Shell { args: "powershell -enc ..." }` 被审计为 `{"command":"shell"}`。无法区分 `Exit` 和 `Shell rm -rf /`。
- 修复:按变体记录脱敏参数摘要(shell 记 args 截断;upload/inject 记名+字节长度;MakeToken 记 domain\user 不记 password)。

**HIGH-4. 审计 `detail` 序列化分叉 — `hash` 基于 fallback "null" 但记录带原字段**
- 位置:`crates/server/src/audit.rs:106-136`(`:118` fallback 到 `"null"`)
- 描述:若 `serde_json::to_string(detail)` 失败,`hash` 基于 `"null"` 计算,但持久化记录带原 `detail`。`verify_chain` 重序列化 `rec.detail` → hash 不匹配 → 误报篡改。
- 修复:序列化 `detail` 一次,同一字符串用于 hash 和持久化。

**HIGH-5. `post_task` 未审计 shell 参数注入面**
- 位置:`crates/server/src/lib.rs:1124`
- 描述:审计 `detail` 中的 `command` 字段是静态 `&str`,无 args。对交付给客户的审计链路,这等于"谁任务了什么"无法回答。
- 修复:同 HIGH-3。

### Implant-win

**HIGH-6. `trex/exfil/deaddrop.rs` base64 缓冲固定 16KiB 静默截断**
- 位置:`deaddrop.rs:140-141`(`b64_buf = [0u8; 16384]`);`base64_encode:93`(`wi + 4 <= output.len()` 静默跳过)
- 描述:固定 16384 字节缓冲,超 ~12000 字节载荷静默截断,无错误。截断的 base64 POST 到 GitHub Gist,检索+解码得截断明文 → 解密失败或垃圾。操作员收到 HTTP 201(成功)但数据不可恢复。
- 修复:改 `Vec<u8>` 按 `len * 4/3 + 4` 分配;或超限返回 `Err`。

**HIGH-7. `trex/melt.rs` `self_destruct()` 无武装守卫 — 任何调用 = 不可逆死亡**
- 位置:`melt.rs:133-144`
- 描述:`pub unsafe fn self_destruct()` 无确认 token、无武装标志、无两阶段提交。立即清零敏感缓冲、翻 RX→RW 并释放、清 PE header、关句柄、`NtTerminateThread`。一个损坏的函数指针或逻辑 bug 到达此函数 = implant 消失,零恢复,零取证。
- 修复:加 `static ARMED: AtomicBool`,`arm_self_destruct(secret: u64)` 必须匹配编译期常量才能武装。

**HIGH-8. `ntalloc.rs` bump allocator 永不释放;过 16 slab 静默泄漏 + 丢跟踪**
- 位置:`ntalloc.rs:269`(`dealloc` no-op);`:54-71`(`track_slab` 溢出左移丢最旧)
- 描述:`NtHeapAllocator::dealloc` 是完全空操作。`MAX_SLABS = 16`;满 16 后左移丢最旧 slab 描述符,但从不 `NtFreeVirtualMemory`。1 MiB 区域永久泄漏(仍 commit)。长时间 beacon(重复截图 3.3MB/次、BOF 加载、下载)快速耗尽 16 MiB。`new_slab_min` 返回 null → `Vec::push` 在 no_std PIC DLL 上 abort。未跟踪的泄漏 slab 在睡眠掩码枚举时永不掩码 → 睡眠期明文密钥留内存。
- 修复:实现 free-list(或压力下释放超大 slab);跟踪表动态增长(Vec-backed)而非固定 16。

---

## MEDIUM 发现(摘要表)

| ID | 位置 | 描述 |
|---|---|---|
| **MED-1** | `server/main.rs:193` | `oneshot(...).unwrap()` 在 TLS 连接服务错误时 panic;`panic=abort` → 整个 team server 死。单行修复:`if let Ok(svc)` |
| **MED-2** | `server/main.rs:245` | `sniff_and_store` 每个 TLS 连接预认证分配 16KiB;无连接速率限制 → 预认证内存放大 |
| **MED-3** | `server/tls.rs:83-104` | 自签 dev cert 用 rcgen 默认值;`HOSTNAME` env 控制 SAN;无硬 guard 防止用于实战 |
| **MED-4** | `server/kernel.rs:58-80` | `send_op` 跨 30s 阻塞读持有 Mutex;单慢 daemon 卡住所有内核 API;async 中用同步 `std::net` |
| **MED-5** | `implant/syscalls.rs:117` | 无 SSN 合理性边界;被 hook 的 ntdll 上 Halo's Gate 可能返回垃圾 SSN → 错误 syscall 执行 |
| **MED-6** | `implant/inject.rs:594-600` | `threadless_inject` 同时设 DR0 HWBP 和 RIP=shellcode(冗余);RIP 修改经 NtSetContextThread 产生 ETW-TI |
| **MED-7** | `implant/blind_hwbp.rs:87-90` | `HWBP_ENTRIES`/`VEH_HANDLE` `static mut` 无同步;VEH handler 可在任意线程触发 → 数据竞争 |
| **MED-8** | `implant/cfg_user.rs:212-220` | `VmCfgInfo` 结构布局错误(40 字节 vs 实际 16);CFG 进程上 `NtSetInformationVirtualMemory` 返回 STATUS_INVALID_PARAMETER |
| **MED-9** | `implant/proxy_veh.rs:357-365` | section-backed handler 用 trampoline 跳到私有内存;浅扫描通过但深度检查 IOC 重开 |
| **MED-10** | `kernelsdk/pagewalk.rs:110-113` | 物理地址无 RAM/MMIO 验证;损坏页表可导向 MMIO 写 → 设备/总线 wedge → BSOD |
| **MED-11** | `transport/traits.rs:128-146` | `TransportStack` 回退无退避/迟滞;网络抖动 → 通道快速切换(Slack→DoH→LLM→MCP)= 噪杂 IOC |

---

## LOW 发现(摘要表)

| ID | 位置 | 描述 |
|---|---|---|
| LOW-1 | `protocol/wire.rs:156` | `Reader::blob` 解码侧无上限(编码侧有);防御脆弱,依赖每个调用者记着 cap |
| LOW-2 | `protocol/msg.rs:295` | `Bof` 编码静默截断 >256 args;操作员的 BOF 以截断参数运行 |
| LOW-3 | `server/lib.rs:760` | 开放/legacy 模式恒为 Admin;无只读 operator 角色 |
| LOW-4 | `server/operators.rs:91` | `OperatorRegistry::resolve` HashMap 非恒定时间;可枚举存在的 operator 名(被 argon2 掩盖) |
| LOW-5 | `server/audit.rs:141` | `AuditWriter::query` 每次读全文件(至 5000)到 Vec;大日志内存尖峰 |
| LOW-6 | `implant/caller_spoof.rs:120` | stub 扫描 cap 1MiB;24H2/25H2 ntdll `.text` 可能超 1MiB → 退到裸 0xC3 回退(CRIT-4) |
| LOW-7 | `implant/fluctuation_thunk.rs:53` | thunk 在 RWX 页(0x40)非 W^X;Moneta/PE-sieve IOC |
| LOW-8 | `implant/trex/mod.rs:709` | Defender vs ATP 进程名匹配:709 行吞掉所有 `msmpeng`,717 行消费者 Defender 不可达 |
| LOW-9 | `implant/trex/delivery.rs:246` | APC 排队但未确保目标线程 alertable;非 alertable 线程上 shellcode 永不执行 |
| LOW-10 | `kernelsdk/netsec.rs:673` | LSASS freeze dump 写固定路径 `C:\Windows\Temp\nyx_freeze_<pid>.dmp` — 平凡 IOC |
| LOW-11 | `transport/malleable.rs:158` | `o365_api` 硬编码假 JWT(`fake-signature`)— 静态 YARA IOC |
| LOW-12 | `transport/doh_dns.rs:50` / `smb_pipe.rs:74` | DoH 默认 Cloudflare;SMB 默认 pipe `\\.\pipe\nyx` — greppable IOC |

---

## INFO(已验证干净的域)

这些是审计明确检查并确认无问题的区域——平衡报告,避免"全黑":

### 加密核心(protocol/crypto.rs)— 设计严谨
- **AEAD 解密-后-验证顺序正确:** `ChaCha20Poly1305::decrypt` 在返回明文前验证 tag(I-4)。server 仅在 `Ok` 后处理明文。
- **Nonce 空间按方向分离:** `crypto.rs:256-261` 用首字节区分方向,防双向 nonce 碰撞。
- **反重放在写锁下权威执行:** `counter <= last_recv`(`<=` 正确,等号拒绝重放上一帧)在 `get_mut` 写锁内(`lib.rs:636`),TOCTOU 已闭合。50 迭代并发测试通过(`lib.rs:1821`)。
- **CSPRNG 正确:** implant 用 `SystemFunction036`(RtlGenRandom)经 PEB-walk;fail-closed(未注册则 abort 而非弱随机)。
- **前向保密存在:** 终止会话(ephemeral 密钥已清零)在长期密钥泄漏后不可解密。
- **所有 tag 派发优雅:** Command 1-28、Response 1-7 全部处理,未知 → `WireError::BadTag`。

### 内核 SDK(kernelsdk)— 72 个 unwrap 全部安全
- 72 个 `unwrap()` 中 ~62 在 `#[cfg(test)]`;其余在固定大小数组切片的 `try_into()`(不可失败)。无生产路径 unwrap 在攻击者可控值上。
- **页表遍历 present-bit + 大页正确:** 4 级全检 P=0;1GB/2MB 掩码正确;`checked_add` 防溢出。
- **PatchGuard 窗口能力门控:** `TimingRepairWindow`/`RuntimePgBypassWindow` 真实实现,`PgGuard` RAII `#[must_use]` + Drop 修复。
- **LSASS 经内核原语读,绕过 PPL:** 从不 `OpenProcess` LSASS;`freeze_edr_coma` 对 PPL 返回 `Err` 不崩溃。
- **BYOVD IOCTL 中途失败处理:** `KrwError::Partial{ok:i}` 告知成功字节数。

### 传输层 — 无硬编码密钥、无禁用 TLS
- **无硬编码 secret:** Slack/Anthropic/MCP token 全是函数参数;无 `xoxb-`/`sk-ant-` 字面量。
- **TLS 验证未禁用:** `danger_accept_invalid`/`insecure` grep 零匹配;ureq/reqwest 默认验证。
- **Malleable profile 注入安全:** reqwest `.header()` CRLF 安全;无原始字符串拼接到请求行。

### 其他
- **SQL 注入干净:** store/ 全用 `params![]` 绑定参数。
- **resolve.rs forwarder 修复正确:** `export_dir_size`(字节)非 `number_of_functions`(计数);缩写名匹配正确。
- **bof.rs W^X 正确:** RW 写+重定位 → 翻 RX;`BeaconDataExtract` 边界检查防恶意长度前缀过读。
- **screenshot.rs 整数溢出保护:** `checked_mul` + `MAX_PIXELS` cap。
- **`hex::decode` 路径返回 Result:** 无 panic;长度预检阻断分配炸弹。

---

## 优先修复建议

### P0 — 立即修复(阻塞实战部署)
1. **CRIT-1** server 开放模式:加 `NYX_ALLOW_OPEN` gate 或自动生成 token。**一行级改动,最高影响。**
2. **CRIT-3** T-REX 桩代码:要么实现,要么显著标注 UNIMPLEMENTED。当前是积极误导。
3. **CRIT-4** caller_spoof 裸 0xC3:移除回退或加指令边界验证。
4. **CRIT-5** fluctuation Drop 守卫:加 `MaskGuard`/`DrGuard` RAII。
5. **MED-1** `oneshot().unwrap()`:改 `if let Ok`,防单连接 DoS 杀全 server。

### P1 — 近期修复(影响正确性/取证)
6. **CRIT-2** kernel 桥接死代码:接线或移除 + 修 STATUS.md。
7. **HIGH-1** constant_time_eq:换 `subtle::ConstantTimeEq`。
8. **HIGH-3/5** 审计日志记参数:这是交付给客户的产物。
9. **HIGH-8** ntalloc 泄漏:实现 free-list 或动态跟踪表。
10. **HIGH-6/7** T-REX deaddrop/melt 安全。

### P2 — 计划修复(防御纵深/检测面)
- MED-5~11、LOW-1~12 按优先级排期。

---

## 审计覆盖与局限

**覆盖:** 4 个并行 agent 深审 crypto/wire、server/REST、implant-win(含 T-REX/P6/P7 全部新模块)、kernelsdk+transport。24 crate 中 75K LOC 全部映射,关键模块逐文件审查。5 个 CRITICAL 全部经人工 `sed` 复核源码确认。

**未覆盖(建议后续):**
- `client-cli`(10.6K LOC)和 `client-ui`(6.3K LOC)未深度审计(TUI 渲染层,安全面较小)。
- `coff.rs`(BOF loader,557 LOC)未单独审(implant 审计覆盖了 `bof.rs` 但非 `coff` crate)。
- 真机动态验证未执行(本次为静态审查)。
- fuzz harness 存在(`crates/protocol/fuzz/`)但未审其覆盖率。

**与既有审计的关系:**
- `docs/audit_2026_07_05/`(10 份子报告,2026-07-05)覆盖类似域,但早于 T-REX/P6/P7(7月7日)和 7 通道传输层(7月7日)。本次审计覆盖了这些新代码,发现既有审计未触及的 CRITICAL(T-REX 桩、caller_spoof 回退、fluctuation 守卫)。
- `wire_protocol_SECURITY_AUDIT.md` 的 2 个 HIGH(MAX_CT_LEN、MIN_CT_LEN)已在当前代码修复。
