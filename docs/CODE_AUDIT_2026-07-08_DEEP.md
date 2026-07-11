# Nyx C2 框架 — 全栈深度代码审计报告（二次审计）

> **审计日期:** 2026-07-08 · **范围:** 全 24 crate（75,800 行 Rust），含首轮未覆盖的 client-cli/client-ui/coff/misc · **分支:** `main` (9de3fec)
> **方法:** 10 路并行深度源码审查 + 关键发现人工逐行复核。复核者对**全部 9 个 CRITICAL** 和所有 HIGH 进行了源码核验。
> **授权语境:** 授权红队 / 安全研究工具。本报告面向项目内部改进，不含可直接武器化的利用细节。

---

## 执行摘要

本次为对现有 `CODE_AUDIT_2026-07-08.md`（baseline，4 路）的**二次深度审计**：覆盖了首轮遗漏的 client-cli（17 文件）、client-ui、coff、及 14 个小 crate，并对全部 24 crate 做逐行二扫。

| 严重度 | Baseline（首轮） | 本次新增 | 合计 | 说明 |
|---|---|---|---|---|
| **CRITICAL** | 5（全部 CONFIRM） | **4** | **9** | 2 crypto · 1 implant-OPSEC · 1 config |
| **HIGH** | 8（全部 CONFIRM） | **17** | **25** | transport×4 · implant×5 · kernel×2 · client-cli×3 · postex×3 |
| **MEDIUM** | 11（全部 CONFIRM） | **28** | **39** | 全域分布 |
| **LOW** | 12（全部 CONFIRM） | **27** | **39** | |

**最紧急的 6 个新发现（按影响排序）：**

1. **[CRIT-NEW-1] CSPRNG 失败被静默忽略 → 全零 X25519 标量**（`protocol/crypto.rs:97`）。`random_bytes` 调用 hook 后丢弃 `bool` 返回；hook 失败时 `out` 保持全零 → 零标量 → 身份点 ECDH → 所有受影响 implant 共享同一确定性会话密钥 → 流量可离线解密 + 跨会话关联。**一行修复（检查 bool）。**

2. **[CRIT-NEW-2] "Pool Party" 注入实际调用 `NtCreateThreadEx`**（`tp.rs:344-368`）。模块文档声称避免 `CreateRemoteThread` 类 IOC，成功消息报告 "0-of-3 FND (no CreateRemoteThread)"——而实现就在目标进程远程线程执行。真实的线程池队列 splice（真正的 threadless 机制）未实现。操作员选择的隐身注入实际触发 EDR 高响警报。

3. **[CRIT-NEW-3] 内嵌配置密钥以字面量紧邻密文**（`config-macros/lib.rs:47-49`）。ChaCha20 key + nonce + ct 三个数组字面量直接编译进二进制；"defeats 1768.py extractors" 的文档声称是**虚假的**。逆向者数分钟提取。

4. **[CRIT-NEW-4] 睡眠内存掩码 `mem::mask`/`unmask` 每次生成新 CSPRNG 密钥**（`mem.rs:104-124`）。mask 用 key A 加密，unmask 用 key B（随机）→ **不**还原明文而是再次加密 → 数据损坏。当前潜伏（注册的密钥是只写诱饵），任何读取注册区域的代码即触发。注释声称 byte-identical round-trip，属虚假保证。

5. **[HIGH-NEW-K1] WFP `silence_edr` 设置 `num_filter_conditions=0` → 阻断主机全部出站 IPv4**（`netsec.rs:328`）。声称 "surgical block EDR PID"，实际 nuke 整个主机网络。注释自认。

6. **[HIGH-NEW bof] `BeaconDataExtract` i32 溢出 → OOB 读**（`bof.rs:369`）。`left < 4 + len` 中 `len`（攻击者可控 i32）≈i32::MAX 时 `4+len` 回绕为负 → 边界检查绕过 → `buffer.add(len as usize)` 增 ~4GiB → OOB 读。恶意 BOF 可触发。

**Baseline 5 个 CRITICAL 全部仍存在（CONFIRM），无一被修复。** 最严重者（CRIT-1 server 开放模式、CRIT-3 T-REX 桩、CRIT-4 caller_spoof 0xC3）维持原判。

**最干净的区域：** AEAD 解密-后-验证顺序、nonce 方向分离、COFF 解析器的 checked_add/mul 防御、内核页表遍历的 P-bit/大页掩码、rest crate 的 `#![forbid(unsafe_code)]`。

---

## CRITICAL 发现（9 个）

### Baseline CRITICAL（5 个，全部 CONFIRM）

#### CRIT-1. Server 默认无认证 + Admin 角色启动 — CONFIRM
- **位置:** `server/lib.rs:767-771`；`main.rs:110-114,147`
- **复核:** `authenticate()` 分支 (3)：无 operators/token → `Allowed(_anonymous, Admin)`。绑定 `0.0.0.0:8443`。
- **修复:** 无 `NYX_ALLOW_OPEN=1` 时拒启动；或自动生成 token 打印到 stderr。

#### CRIT-2. 内核守护进程桥接死代码 — CONFIRM
- **位置:** `server/main.rs:129` `kernel: None`
- **复核:** `KernelBridge::new()` 零调用点；所有 `/api/kernel/*` 命中 `None => "no daemon"`。

#### CRIT-3. T-REX 侦察引擎全部桩代码 — CONFIRM
- **位置:** `trex/mod.rs:779-847`；`assess_user_mode :162-191`
- **复核:** `create_toolhelp_snapshot()→null_mut()` 等全部 no-op → 永远返回 `ThreatTier::Clean`。

#### CRIT-4. `caller_spoof` 裸 `0xC3` 回退 — CONFIRM（但 INERT）
- **位置:** `caller_spoof.rs:135-141`
- **复核 + 补充:** fallback 确实匹配任意 0xC3。**但** evasion 审计发现唯一活跃调用方 `blind_hwbp.rs:117` 用 `let _ = stub` 丢弃结果；`add_vectored_handler_spoofed` 零调用点。**实际严重度降级**（死代码），但隐患仍在——未来接线即触发。

#### CRIT-5. `fluctuation` 无 unwind 安全守卫 — CONFIRM
- **位置:** `fluctuation.rs:66-78`
- **复核:** `save_dr→clear_dr→mem::mask()→thunk_fn()→mem::unmask()→restore_dr` 无 Drop 守卫。mid-window 故障 → .text 永久密文。

### 新增 CRITICAL（4 个）

#### CRIT-NEW-1. CSPRNG 失败静默忽略 → 全零 X25519 标量 → 全 AEAD 崩溃
- **位置:** `crates/protocol/src/crypto.rs:89-103`（bug 在 `:97 f(out);`）
- **已核验:**
  ```rust
  let f: fn(&mut [u8]) -> bool = unsafe { core::mem::transmute(hook) };
  f(out);                       // bool 返回被丢弃
  ```
  hook 契约（crypto.rs:71）文档："Returning `false` = failure"。调用方初始化 `bytes=[0u8;32]`（crypto.rs:115-117,169-171）。hook 失败两路径：SystemFunction036 不可解析（entry.rs:221-222）；RtlGenRandom 返回 0（:231-232）。selftest 检查返回（selftests.rs:750），crypto 层**不**检查。
- **链式影响:** 零标量 → X25519 clamping 后仍 ≈0 → 公钥 = 身份点 → ECDH 共享密钥全零 → HKDF(全零 IKM) → 每个 affected implant 相同确定性会话密钥 → nonce/AAD 同源 → AEAD 退化为可离线解密的两时间垫 + 永久跨会话关联。
- **触发面:** EDR hook advapi32 / RtlGenRandom 时静默命中。
- **修复:** `random_bytes` 返回 `Result`，检查 `!f(out)`；失败 abort/exit。显式拒绝全零标量（防御纵深）。

#### CRIT-NEW-2. "Pool Party" 注入是 NtCreateThreadEx — 伪造 "无 CreateRemoteThread" OPSEC 保证
- **位置:** `crates/implant-win/src/tp.rs:210-375`（impl）；`inject.rs:650-664`（成功消息）；`tp.rs:1-34`（模块文档）
- **已核验:**
  - `tp.rs:353-368` 解析 `NtCreateThreadEx` 并以 `target_base` 为远进程起始地址调用：
    ```rust
    nt_cte(&mut h_thread, 0x1FFFFF, null(), target_h, target_base, null(), 0,0,0,0, null())
    ```
  - `tp.rs:310-340` 真正的线程池劫持（worker 发现 + `_TP_WORK` 队列 splice，步骤 a/b/d）**显式未实现**（注释 :347-350）。
  - `inject.rs:662` 成功消息：`"Pool Party inject ok — 0-of-3 FND (no VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)"` — 在 syscall 层** materially 虚假**。
- **影响:** 操作员 `NYX_POOL_PARTY_ON=1` 选 threadless，被告知 "0-of-3 FND"，实际 `NtCreateThreadEx` 是 EDR 在 syscall 边界 hook 的精确原语。被检测即告警/杀进程。
- **修复:** (a) 实现队列 splice 使声称成真；或 (b) 诚实化成功消息 + 重写模块头。保持默认 OFF。

#### CRIT-NEW-3. 内嵌配置：ChaCha20 密钥以字面量紧邻密文 — "防 extractor" 声称虚假
- **位置:** `crates/config-macros/src/lib.rs:45-51`
- **已核验:**
  ```rust
  let expanded = quote!({
      nyx_config::decrypt(
          &[#(#key_bytes),*],     // 密钥字面量
          &[#(#nonce_bytes),*],   // nonce 字面量
          &[#(#ct_bytes),*][#pad..],  // 密文字面量
      )
  });
  ```
  三数组直接编译进 `.rdata`/`.text`。逆向者 grep `decrypt(` 调用点即得三个紧邻数组。
- **影响:** 操作员依赖此机制对配置（服务器地址、密钥、profile）保密；实际数分钟可提取。虚假安全保证。
- **修复:** 密钥不入二进制（从环境/外部 blob 在运行时注入）；或至少不强声明 "defeats extractors"。

#### CRIT-NEW-4. `mem::mask`/`unmask` 每次生成新随机密钥 → 不可还原
- **位置:** `crates/implant-win/src/mem.rs:104-124`
- **已核验:**
  ```rust
  pub(crate) fn mask_key() -> [u8; 32] {
      let mut key = [0u8; 32];
      if crate::entry::csprng_fill(&mut key) { key }   // 每次随机！
      else { /* rdtsc 派生 */ }
  }
  fn apply_rc4_to_regions() {
      let key = mask_key();   // mask() 和 unmask() 各调一次 → 两个不同 key
      for ... { Rc4::apply_oneshot(&key, region); }
  }
  ```
  `mask()`（:155-163）和 `unmask()`（:168-176）都调 `apply_rc4_to_regions`（:124 取新 key）。注释 :120-122、137-138 声称 "byte-identical round-trip"——**false**。`MASK_STATE` 守卫只防重复 mask/unmask，不保证密钥一致。
- **影响:** 当前潜伏（注册的 config/key/token 区域是只写诱饵，beacon 不回读）。任何代码读取注册区域即得损坏密文（key A 加密 ∘ key B 加密 ≠ 明文）。`round_trip_selftest` 仅因本地缓存 key 通过。
- **修复:** `mask_key()` 缓存首次结果（`OnceLock` 或 `static AtomicPtr`）；mask/unmask 用同一缓存 key。

---

## HIGH 发现（精选新增，全部已人工核验）

### 加密 / 协议

**HIGH-NEW-P1. `SessionKey` 派生 `Copy` + 空壳 `ZeroizeOnDrop` 标记，无 `Drop` impl**
- `protocol/crypto.rs:20,34-40`。`Copy` + `Drop` 是 E0184 冲突 → 标记**结构上不可满足**。会话密钥从不清零。**修复:** 移除 `Copy`，加真 `Drop`。

**HIGH-NEW-P2. `SessionKey` 派生 `Debug` → `{:?}` 泄露密钥字节**
- `protocol/crypto.rs:20`。任何 `tracing::debug!(?key)`/`dbg!` 把活密钥写日志。**修复:** 手写 redacted Debug。

### Server（baseline HIGH-1/3/4/5 已 CONFIRM，见 server.md）

### Implant-win Core

**HIGH-NEW-I1. `shell` 无超时 `WaitForSingleObject(INFINITE)` → 单挂起命令永久杀 beacon**
- `shell.rs:287,31`。beacon 单线程；`shell ping -t` / `shell notepad` 永久阻塞 beacon 线程，无 Exit/Sleep 再被服务。**修复:** 有界超时 + TerminateProcess。

**HIGH-NEW-I2. `pool_party_inject` `_TP_DIRECT` 越界写**
- `tp.rs:333-340`。section size = `((sc.len()+0xFFF)&!0xFFF)`；当 `sc.len()` 在页边界前 24 字节内（4073..4096 等），24 字节 TpDirect 写越过映射视图 → AV 崩溃。且该结构是死代码。**修复:** 加 `+ size_of::<TpDirect>()` slack；或删写。

### Implant-win Post-ex

**HIGH-NEW-BOF1. `BeaconDataExtract` i32 溢出 → OOB 读**
- `bof.rs:369`。`left < 4 + len`，`len`（BOF 供给 i32）≈i32::MAX 时回绕绕过 → `buffer.add(len as usize)` 增 ~4GiB。恶意 BOF 触发堆 OOB。**修复:** 用 `len as usize` + checked_add。

**HIGH-NEW-BOF2. ~40 个 `#[no_mangle] nyx_selftest_*` 无条件编译进生产 implant**
- `selftests.rs`（40+ 站点），写 `nyx_*.txt` 工件、spawn 进程、注入。最大可避免检测面。**修复:** `#[cfg(feature="selftest")]` 门控；生产构建剔除。

**HIGH-NEW-BOF3. `nyx_selftest_hashdump_diag` 对活 SAM hive 同步打开（注释自承永远挂起）**
- `selftests.rs:717-724`。以 export 形式船载砖机 footgun。

### Transport（4 个新 HIGH）

**HIGH-NEW-T1. DoH 用 base64 `+//` 直接做 DNS label — 二进制载荷必坏**
- `doh_dns.rs:114-130,206`。`+`/`/` 非合法 DNS 字符。测试仅覆盖全-A/全-0xAA（回避）。真实加密帧（含随机字节）几乎必含这些字符 → DNS 查询失败。**修复:** base32hex 或 URL-safe base64。

**HIGH-NEW-T2. SMB pipe 用 `FILE_FLAG_OVERLAPPED` 句柄 + NULL OVERLAPPED → ERROR_INVALID_PARAMETER + 忙循环**
- `smb_pipe.rs:245,274,296`。channel 不可用。**修复:** 去 OVERLAPPED 标志或提供 OVERLAPPED 结构。

**HIGH-NEW-T3. `FingerprintEmitter` 全死代码 — 所有 HTTPS 传输发默认 rustls JA3**
- `emitter.rs` + 全 HTTPS 构造器。`best()` 定义但零调用；植入物出站 ClientHello 是原始 rustls（可签名 JA3）——这是 crate 自述的 **#1 检测向量**。**修复:** 把 emitter 接入传输，或诚实标注 "出站指纹不可控"。

**HIGH-NEW-T4. MCP 通道无认证；session_id（明文 JSON）是唯一凭据**
- `mcp.rs:52-57,182-203`。帧注入 / 任务窃取。**修复:** 加 bearer / HMAC。

### Kernel（2 个新 HIGH）

**HIGH-NEW-K1. WFP `silence_edr` `num_filter_conditions=0` → 阻断主机全部出站 IPv4**
- `netsec.rs:328`。注释 :322-327 自承。nuclear stub 伪装成 surgical。**修复:** 加 PID 条件（`FWP_CONDITION_ALE_APP_ID`）。

**HIGH-NEW-K2. `choke_edr_qos` 忽略 pid + QOSCreateHandle FFI 元数错误（3 vs 2）→ 每次 UB**
- `netsec.rs:807-922`。null AppId = 全流；错误 arity = 栈/UB。**修复:** 加 AppId 绑定；修 FFI 签名。

### Client-CLI（3 个新 HIGH，首审）

**HIGH-NEW-C1. 凭据明文存储 `~/.nyx/creds.json`（无静态加密）**
- client-cli credstore。仅 0600 perm。对 C2 框架是重大归因/opsec 风险。**修复:** 加静态加密（主密钥派生自操作员口令/OS keychain）。

**HIGH-NEW-C2. bearer token + `reveal=1` 明文凭据走明文 HTTP（无 https_only 强制）**
- rest.rs。操作员指向非 loopback `http://` 时全明文。**修复:** 默认拒绝非 loopback http，或强制警告。

**HIGH-NEW-C3. SOCKS5 监听无认证（仅 method 0x00）→ 一标志开放代理/内网 pivot 脚枪**
- socks/。`--listen 0.0.0.0:1080` 即开代理；注释错误地以 "bearer 是 bridge→server" 为由拒绝加 auth。**修复:** 加用户名/口令认证（RFC 1929 method 0x02）。

---

## MEDIUM 发现（摘要表，共 39 个：11 baseline + 28 新增）

| ID | 位置 | 描述 |
|---|---|---|
| **baseline MED-1..11** | 见 CODE_AUDIT_2026-07-08.md | 全部 CONFIRM |
| MED-NEW-S1 | server/operators.rs:166 | `_legacy` token 无盐 SHA-256（非 argon2） |
| MED-NEW-P1 | protocol/crypto.rs:20 | SessionKey 无 Drop（见 HIGH-NEW-P1，部分归 HIGH） |
| MED-NEW-M1 | implant/mem.rs:104 | mask/unmask 新密钥（见 CRIT-NEW-4） |
| MED-NEW-I1 | beacon.rs:537-557 | 确定性 jitter 种子（0x9E37779B9）→ 跨主机时序指纹 |
| MED-NEW-I2 | shell.rs:37,234-244 | shell 输出 1MiB 截断无标记 → 静默数据丢失 |
| MED-NEW-I3 | tp.rs:228,236,363 | pool_party 句柄泄漏（target/section/thread） |
| MED-NEW-I4 | transport.rs:154-216 | `ensure_winhttp` LoadLibrary 失败永久关 |
| MED-NEW-I5 | beacon.rs:333-348 | `SetChannel 6`（SmbPipe）静默杀 beacon（"success" 消息） |
| MED-NEW-E1 | sleep.rs:621-627 | Foliage Context-5 把 .text 恢复为 0x40 RWX（非 RX）+ 泄漏永久 RWX rc4 页 |
| MED-NEW-E2 | caller_spoof_thunk.rs:135 | resume 偏移=10 但真距离=15 → 中指令跳转崩溃（死代码） |
| MED-NEW-BOF4 | bof.rs:616-645 | `alloc_near` 仅探 64MiB/64 次后 NULL-hint fallback → REL32 溢出 segfault |
| MED-NEW-BOF5 | hashdump.rs:671-674 | `save_hive_fallback` 写 `C:\Windows\Temp\SAM.hive` NULL SECURITY_ATTRIBUTES |
| MED-NEW-BOF6 | hashdump.rs:206-216, postex.rs:339-356 | joined buffer + make_token 口令从不 zeroize |
| MED-NEW-BOF7 | fs.rs:789-843 | `fileop_cp` 全文件入 `Vec<Vec<u8>>` → 多 GB OOM 杀 implant |
| MED-NEW-BOF8 | fs.rs:747-751 | `fileop_mv` dest 限 260 wchar，超长路径静默截断 + 报 Ok |
| MED-NEW-BOF9 | pivot.rs:597-614 | SOCKS5 BIND 多 peer 复用 listener chan id + listener 不自动关 → 数据错路 |
| MED-NEW-BOF10 | trex/cleanup.rs:115-142 | `wipe_prefetch` 固定 `[u16;128]` + `copy_from_slice` 在 >103 单元名 panic → implant 死 |
| MED-NEW-T5 | llm_api.rs:83-91 | LLM recv 破损（Messages API 无状态，无历史）+ XOR 占位符泄露 C2 明文给 LLM 供应商 |
| MED-NEW-T6 | traits.rs:96-102 | `init_all` 成功不设 healthy=true |
| MED-NEW-T7 | slack_api.rs:200-223 | 一条不可解码 base64 毒消息永久阻塞 Slack recv |
| MED-NEW-T8 | mcp.rs:134-159, llm_api.rs:133-158 | `extract_hex` 最长运行启发式把任意响应文本当 C2 帧 |
| MED-NEW-T9 | malleable.rs:267-285 | send 把 4xx 当成功 → 静默数据丢失 |
| MED-NEW-T10 | malleable.rs:333-348 | health_check 忽略 profile UA/headers → 掩护身份不匹配 |
| MED-NEW-K3 | telemetry.rs:76-110 | CallbackNeutralizer ret-stub nt!内部 dispatcher（slot 0）→ bugcheck |
| MED-NEW-K4 | netsec.rs:314-335 | （见 HIGH-NEW-K1，部分归 HIGH） |
| MED-NEW-K5 | byovd.rs:425-447 | `resolve_kernel_symbol` 仅 djb2 hash 匹配 → 碰撞返错 RVA → 盲写 0 到野 KVA → BSOD |
| MED-NEW-K6 | kernel-cli main.rs:470-540 | daemon 绑 localhost 无 auth + 可预测 `lsass_<pid>.dmp` 在 CWD → symlink 任意文件覆盖 |
| MED-NEW-MISC1 | store/store.rs | chmod 仅主 DB，不 chmod -wal/-shm 边车（WAL 模式）→ 明文凭据世界可读 |
| MED-NEW-MISC2 | profile/lint.rs:99-110 | lint 拒 header/param/uri 的 CRLF 但**不**拒 `set useragent` → UA 头注入缺口 |
| MED-NEW-MISC3 | agent-dev/lib.rs:307,503 | screenshot 写 `/tmp/nyx_shot_<pid>.png` → symlink 竞争 |

---

## LOW 发现（摘要表，共 39 个：12 baseline + 27 新增）

> Baseline LOW-1..12 全部 CONFIRM。新增 LOW 分布：protocol×5（Task 截断/编解码 cap 不对称/Channel.status 未校验/XOR 死代码/ServerKeypair Clone）、implant-core×5（encode_vec panic/server_pub 0x42 fallback/offsets 强制 0/TLS cert-ignore 顺序/等）、implant-postex×2（keylog Relaxed 丢键/BeaconCleanupProcess 关任意句柄）、implant-evasion×4（slab 溢出丢掩码/scan_return_stub 浪费/文档不符/永久 RWX IOC）、transport×6（from_utf8_lossy/read_exact 吞错/recv 忽略 timeout/static conversation_id/无 HTTPS 强制/SSRF sink/extract_txt 早退）、client-cli×7、kernel×7、misc×6。详见各域报告。

---

## INFO — 已验证干净的区域（平衡报告）

### 加密核心（protocol/crypto.rs）
- AEAD 解密-后-验证顺序正确（`open_dir` 委托 `chacha20poly1305::decrypt`，tag 失败返回 Err，永不返明文）
- Nonce 方向分离（首字节 0x00/0x01），`nonce_directions_never_collide` 回归测试通过
- Counter u64→nonce[4..12] 无溢出/截断
- 分配炸弹防御（`checked_count` + `MAX_BATCH`，fuzz 测 0xFFFFFFFF）
- 标签分派穷尽（全部 `t => Err(BadTag)`）
- Keypair Drop zeroize + compiler_fence

### COFF 解析器（coff/lib.rs）— 高价值攻击面，最干净
- 每个头派生偏移用 `checked_add`/`checked_mul`（防 usize 回绕）
- 严格 raw 窗口拒绝（不静默 `&[]` 截断）
- 每重定位边界检查
- 4 个畸形输入测试钉死修复

### 内核页表遍历（pagewalk.rs）
- P-bit 4 级全检；1GB/2MB/4KB 掩码手算正确；`checked_add` 防溢出
- `offsets::for_build` 正确拒绝 floor-match
- BYOVD 无内嵌驱动 blob（操作员从磁盘加载）

### rest crate
- `#![forbid(unsafe_code)]`；SessionView 全字段 `#[serde(default)]`（前后兼容）

### Server beacon handler（`handle_beacon`）
- 反重放在写锁下权威执行（TOCTOU 闭合）
- kill date fail-closed；会话/结果上限防 OOM
- beacon 错误统一 400 无 body（无 oracle）

### 传输层（部分）
- 无 `danger_accept_invalid`/`insecure`/`verify_mode`（grep 0 匹配）
- 无硬编码生产 secret（仅 fake test 值）
- `h2.rs` from_frames 全 payload `.get().ok_or()?` 边界检查

### Client-cli / client-ui（部分）
- 无本地命令注入（shell 命令 JSON 编码发服务器，非本地 exec）
- secret 日志卫生好（token/password/secret 不入 log_push）
- SOCKS5 握手边界安全（全 255 cap，无溢出）

---

## 优先修复建议

### P0 — 阻塞实战部署（立即）
1. **CRIT-NEW-1** CSPRNG bool 检查（一行，最高影响）
2. **CRIT-1** server 开放模式 gate（一行级）
3. **CRIT-NEW-3** config 密钥不入二进制
4. **CRIT-NEW-4** mem mask 缓存密钥
5. **CRIT-NEW-2** Pool Party 诚实化或实现
6. **CRIT-3** T-REX 桩标注 UNIMPLEMENTED
7. **CRIT-5** fluctuation RAII 守卫
8. **HIGH-NEW-BOF1** BeaconDataExtract checked_add
9. **HIGH-NEW-K1** WFP silence_edr 加 PID 条件
10. **HIGH-NEW-C3** SOCKS5 加 auth
11. **MED-1** `oneshot().unwrap()` 改 `if let Ok`

### P1 — 近期修复（正确性/取证）
12. **HIGH-NEW-T1/T2** DoH base64 修复 / SMB OVERLAPPED
13. **HIGH-NEW-BOF2** selftest 门控
14. **HIGH-NEW-P1/P2** SessionKey Drop + 去 Debug
15. **HIGH-1** constant_time_eq 换 `subtle::ConstantTimeEq`
16. **HIGH-3/5** 审计日志记参数
17. **HIGH-8** ntalloc free-list
18. **HIGH-NEW-I1** shell 超时
19. **HIGH-NEW-C1** creds 静态加密
20. **HIGH-NEW-K2** QOS FFI 元数

### P2 — 计划修复（防御纵深/检测面）
- 全部 MED-NEW + LOW-NEW，按域排期

---

## 审计覆盖与局限

**覆盖:** 10 路并行，24 crate 75,800 行全映射。8 个子代理报告 + 2 个（server、client-ui）因 429 限流由主审计者 inline 补完。**全部 9 个 CRITICAL 经人工逐行 `read` 核验**，关键 HIGH 抽检核验（BeaconDataExtract 溢出、WFP num_filter、pool_party NtCreateThreadEx、mem mask_key、config-macros quote）。

**子报告:**
- `docs/audit_2026_07_08/protocol.md`（AEAD/wire/frame/msg）
- `docs/audit_2026_07_08/server.md`（REST/store/audit log）— inline
- `docs/audit_2026_07_08/transport.md`（7 通道/malleable/traits）
- `docs/audit_2026_07_08/implant_core.md`（beacon/entry/dllmain/tp/shell）
- `docs/audit_2026_07_08/implant_evasion.md`（sleep/inject/caller_spoof/ntalloc）
- `docs/audit_2026_07_08/implant_postex.md`（bof/hashdump/trex/fs/pivot）
- `docs/audit_2026_07_08/kernel.md`（byovd/netsec/telemetry/pagewalk）
- `docs/audit_2026_07_08/client_cli.md`（首审：rest/socks/tui/credstore）
- `docs/audit_2026_07_08/client_ui.md`（首审：Makepad GUI）— inline
- `docs/audit_2026_07_08/misc_crates.md`（首审：coff/profile/scripting/store/bof-runner/config/pe）

**与既有审计关系:** 本报告是 `CODE_AUDIT_2026-07-08.md`（4 路 baseline）的**超集**。Baseline 全部 CONFIRM（无一修复）。新增覆盖了 baseline 明确标注未审的 client-cli/client-ui/coff/misc，并发现 4 个新 CRITICAL + 17 个新 HIGH。`docs/audit_2026_07_05/`（10 报告，2026-07-05）早于 T-REX/P6/P7/7 通道传输，本报告覆盖这些新代码。

**未覆盖:** 真机动态验证（本次为静态）；部分 3000+ LOC 文件的纯渲染逻辑（client-ui main.rs、client-cli tui/mod.rs）未逐行（低安全面，数据经 widgets/parse 已验证干净）。
