# Nyx Server / REST / Store / Audit-log — 深度审计 (2026-07-10)

> **审计者:** ZCode (server domain agent)
> **范围:** `crates/server/src/{lib,main,audit,operators,kernel,tls}.rs` + `crates/store/src/{lib,model,store}.rs` + `crates/server/tests/beacon_limits.rs`
> **方法:** 逐行 `Read` 全部生产路径 + `git diff` 复核全部未提交修复 + 新代码独立审计
> **授权语境:** 授权红队工具，内部改进用。不含可直接武器化的载荷细节。
> **未提交变更范围:** `git diff --stat` 显示 server crate +167 lib.rs / +55 main.rs / +17 audit.rs / +7 Cargo.toml / +2 beacon_limits.rs。`operators.rs`、`kernel.rs`、`tls.rs`、`crates/store/` **无未提交改动**。

---

## 摘要

修复执行总体质量高。**CRIT-1（默认开放 + 0.0.0.0 + Admin）实质修复**，**HIGH-1（先 hash 再常量时间比较）修复**，**HIGH-4（审计序列化分叉）修复**，**HIGH-3/5（审计丢参数）部分修复**，**MED-1（oneshot unwrap 杀进程）修复**。**CRIT-2（kernel bridge 死代码）完全未动**。

本次新发现：1 个 MEDIUM（新会话 TOCTOU 竞态，与既有会话防御不对称）、若干 LOW（`is_loopback_bind` 前缀绕过、HIGH-3 仅覆盖 3/25 命令变体、MED-2/MED-3 未动、NEW-S1 未动等）。

| 旧 ID | 状态 | 当前位置 |
|---|---|---|
| **CRIT-1** | ✅ **FIXED** | `main.rs:123-150` + `lib.rs:481-486` |
| **CRIT-2** | ❌ **STILL PRESENT** | `main.rs:163` `kernel: None` |
| **HIGH-1** | ✅ **FIXED** | `lib.rs:458-461` |
| **HIGH-3/5** | ⚠️ **PARTIALLY FIXED** | `lib.rs:1142-1154` |
| **HIGH-4** | ✅ **FIXED** | `audit.rs:106-149` |
| **MED-1** | ✅ **FIXED** | `main.rs:229-238` |
| **MED-2** | ❌ **STILL PRESENT** | `main.rs:281-288` |
| **MED-3** | ❌ **STILL PRESENT** | `tls.rs:83-104` |
| **MED-NEW-S1** | ❌ **STILL PRESENT** | `operators.rs:166` |

---

## 第一部分：旧发现复核（逐条带行号与证据）

### [CRITICAL→已修复] CRIT-1. 开放模式默认 Admin + 绑 0.0.0.0
- **状态:** ✅ **FIXED**（实质修复；残留 1 个 LOW 见下）
- **已核验:**
  - 默认绑定改为 loopback：`main.rs:123` `let addr = std::env::var("NYX_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());`（旧值为 `"0.0.0.0:8443"`）。
  - 非环回 + 无认证的 footgun 被拦截：`main.rs:131-150` 计算 `is_network_bind = !is_loopback_bind(&addr)` 与 `no_auth = operators.is_open() && api_token.is_none()`；命中时除非显式 `NYX_ALLOW_OPEN=1`（仅记 WARN），否则 `generate_api_token()`（`lib.rs:469-474`，32 字节 OsRng→64 hex）注入 `api_token` 并打印到 stderr。
  - 认证链路确实生效：`authenticate()`（`lib.rs:768-803`）在 `operators.is_open()` 为真时进入分支 (2) 校验 `st.api_token`，故自动生成的 token 会被 `constant_time_eq` 校验。开放分支 (3) `_anonymous/Admin` 仅在 `api_token` 为 `None` 时触达——而 loopback 是该路径的合法 dev 场景。
- **修复质量评估:** 默认安全（loopback-first）+ 网络暴露强制 token 的策略正确。`generate_api_token` 使用 `OsRng.fill_bytes`（`lib.rs:472`），256-bit 熵，是合格的生成路径。新增 3 个单测（`lib.rs:1723-1753`）覆盖长度/字符集/非碰撞与 loopback 分类。
- **残留风险:** 见下文 **[LOW] NEW-S4**（`is_loopback_bind` 前缀匹配可被构造主机名绕过，需操作员自伤配置）。

### [CRITICAL→未修] CRIT-2. Kernel bridge 死代码（`kernel: None`）
- **状态:** ❌ **STILL PRESENT**（零改动）
- **已核验:** `main.rs:163` `kernel: None,`（与 07-08 `main.rs:129` 同一行，行号仅因上方插入而偏移）。`grep "KernelBridge::new"` 在整个 server crate 无调用点。`lib.rs:137` `AppState::default()` 同样为 `kernel: None`。所有 `/api/kernel/*` 路由（`lib.rs:330-338`）的 handler（`kernel.rs:112-224`）在 `st.kernel` 为 `None` 时统一返回 `{"ok":false,"err":"no daemon"}`（如 `kernel.rs:122-125,143,162,...`）。
- **影响:** `KernelBridge::send_op`（`kernel.rs:51-80`）含持锁阻塞 I/O（MED-4），但因路径不可达而休眠。整个 kernel 功能面（blind-etw/hide/dump-lsass/neutralize/detach-minifilter）在产品中不可用，文档与路由存在误导。
- **修复:** 在 `main.rs` 中按 `NYX_KERNEL_DAEMON` 构造 `KernelBridge::new(KernelConfig::default())` 并置入 `state.kernel`，或移除路由直到功能落地。

### [HIGH→已修] HIGH-1. constant_time_eq 先 SHA-256 再比较
- **状态:** ✅ **FIXED**
- **已核验:** `lib.rs:458-461`：
  ```rust
  pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
      use subtle::ConstantTimeEq;
      a.ct_eq(b).unwrap_u8() == 1
  }
  ```
  旧的 SHA-256 预哈希路径（`Sha256::update(a)`/`update(b)` 再逐字节 OR）已删除。`Cargo.toml:40` 新增 `subtle = "2"`（lockfile 确认 `subtle 2.6.1`）。
- **调用点恒定时间性核验:**
  1. `authenticate` legacy token（`lib.rs:790`）：`constant_time_eq(want.as_bytes(), presented.as_bytes())`。`want = "Bearer {expected}"`，`presented` 来自请求头。两者长度可变——但 `subtle::ConstantTimeEq for [u8]` 在长度不等时返回 `Choice(0)` 且其比较工作量仅依赖 `min(a.len(),b.len())`，**不泄露差异位置**。旧实现的缺陷（SHA update 时间 ∝ 输入长度）已消除。长度差异是否泄露：`ct_eq` 在长度不等时仍执行逐字节扫描至较短者末端后折叠长度标志，运行时间仅取决于 `min(len)`，不泄露差值——合格。
  2. `operators::verify_secret` 的 `plain:` 标记（`operators.rs:183-185`）：`constant_time_eq(got.as_bytes(), hex.as_bytes())`，两侧均为 64 hex 字符定长——恒定时间。
- **修复质量评估:** 正确。注释（`lib.rs:448-457`）准确说明了 `ct_eq` 在长度不等时的行为与两个调用点的等长前提。

### [HIGH→部分修] HIGH-3/5. 审计丢弃命令参数
- **状态:** ⚠️ **PARTIALLY FIXED**（仅 3/25 变体补齐，其余仍丢参数）
- **已核验:** `lib.rs:1135-1154` 在 `post_task` 中、`command` 被 move 进 task 之前构建 `audit_detail`：
  ```rust
  let audit_detail = match &command {
      Command::Shell { args } => json!({"task_id":task_id,"command":"shell","args":truncate(args,256)}),
      Command::Upload { name, data } => json!({...,"name":name,"bytes":data.len()}),
      Command::MakeToken { domain, user, .. } => json!({...,"user":format!("{}\\{}",domain,user)}),
      _ => json!({"task_id":task_id,"command":cmd_name}),  // ← 兜底仍只记静态名
  };
  ```
- **正确点:** MakeToken 显式丢弃 `password`（`..`），仅记 `DOMAIN\user`——避免把口令写入审计日志（防口令二次泄露，正确）。Shell args 经 `truncate(args,256)` 有界。`truncate`（`lib.rs:491-498`）char-safe、边界（恰好 `max` 不加省略号）由单测覆盖。
- **仍丢参数的变体（兜底 `_` 分支）：** `Download{path}`、`Bof{name,args,blob}`、`Inject{pid,spawn_to,shellcode}`、`StealToken{pid}`、`Connect{host,port}`、`Socks{addr,port}`、`Portscan{host,ports}`、`Net{query}`、`Env{name}`、`Hashdump{method}`、`Keylog{action}`、`ChannelData{chan,data}`、`Sleep{...}`、`FileOp{op,path,dest}`、`Screenshot{monitor}`、`Screenwatch{interval}`、`SetChannel{channel}`。这些在事后取证中只可见"跑了一个 bof"，看不到 bof 名/参数、注入目标 pid、下载路径、端口扫描范围等。对一个 red-team 工具的 action 报告而言，这是取证粒度缺口。
- **影响:** HIGH-3 的根因（事后无法重建"做了什么"）仅对 shell/upload/maketoken 解决；其余高价值操作（bof、inject、download、lateral 原语）仍不可回溯。降级为 MEDIUM（不再是"全丢"，但覆盖不全）。
- **修复:** 扩展 match 臂覆盖其余变体，沿用 MakeToken 的脱敏思路（如 `Inject` 记 `{pid, spawn_to, "shellcode_bytes": shellcode.len()}` 而非字节、`Bof` 记 `{name, "args": args, "bytes": blob.len()}`、`Download` 记 `{path: truncate(path,512)}`）。

### [HIGH→已修] HIGH-4. 审计 detail 序列化分叉（hash 与存储不一致）
- **状态:** ✅ **FIXED**
- **已核验:** `audit.rs:106-149`。`append` 签名改为 `mut detail: serde_json::Value`，序列化一次：
  ```rust
  let detail_json = match serde_json::to_string(&detail) {
      Ok(s) => s,
      Err(_) => { detail = Value::Null; "null".to_string() }  // 两处同步置零
  };
  let hash = hash_record(..., &detail_json, &prev);
  let rec = AuditRecord { ..., detail, ... };  // 存的是同一个 detail
  ```
  `verify_chain`（`audit.rs:199-226`）对读回的 `rec.detail` 再次 `serde_json::to_string(&rec.detail)`（`:210`）。由于 `serde_json::Value` 的序列化对 object key 排序、数字格式是确定性的（按字典序输出 key），存盘-读盘-重序列化与原始 `to_string(&detail)` 字节一致 → 重算 hash 匹配。失败兜底两处同步为 `Value::Null` + `"null"`，`verify_chain` 对 `Value::Null` 产出 `"null"`，亦匹配。
- **修复质量评估:** 正确闭合了 hash/存储分叉。新增/既有测试 `append_chains_and_persists`、`chain_break_detected`、`recovers_chain_across_reopen`（`audit.rs:279-345`）覆盖链续、篡改检测、跨重启。
- **残留（LOW，非回归）:** `verify_chain` 的 `serde_json::to_string(&rec.detail).unwrap_or_else(|_| "null".into())`（`:210`）在解析侧也做了与写入侧一致的兜底，对称——合格。但如果未来 detail 含非确定性类型（如自定义序列化），仍可能复发；当前全为 `serde_json::Value`，安全。

### [MEDIUM→已修] MED-1. `oneshot().unwrap()` 杀整个 server
- **状态:** ✅ **FIXED**
- **已核验:** `main.rs:229-238`（旧 `main.rs:193`）：
  ```rust
  match tower::ServiceExt::oneshot(make_svc, peer).await {
      Ok(svc) => { let svc = ...; let _ = builder.serve_connection(io, svc).await; }
      Err(e) => tracing::warn!(%peer, error=%e, "make_service build failed; connection dropped")
  }
  ```
  单连接 MakeService 构建失败现在仅丢一条连接 + warn，不再 `unwrap()` → 不再在 `panic=abort` 下杀进程。
- **修复质量评估:** 正确。注释（`:223-228`）解释了"单连接失败不能拖垮整个 accept loop（会带掉所有 beacon）"的意图。

### [MEDIUM→未动] MED-2. 预认证 16KiB 分配无速率限制
- **状态:** ❌ **STILL PRESENT**
- **位置:** `main.rs:281-288`（`sniff_and_store`）：`rec_len` 上限 16384（`:282`），`vec![0u8; rec_len]`（`:288`）每连接分配。无每 peer 速率/并发限制。
- **影响:** 预认证（TLS 路径在 ClientHello 嗅探阶段、无 token）内存放大。每个连接最多 ~16KiB，连接数无界 → 大量并发握手可制造内存尖峰。缓解：单连接量级小（16KiB），需极高并发。
- **修复:** 在 accept loop 外层加 per-peer 连接速率/并发闸（如 token bucket）。

### [MEDIUM→未动] MED-3. 自签 dev cert 无硬 guard
- **状态:** ❌ **STILL PRESENT**
- **位置:** `tls.rs:83-104`（`self_signed_config`）：rcgen 生成，SAN 由 `HOSTNAME`/`COMPUTERNAME` env 控制（`tls.rs:106-110`），`tracing::warn!("...do NOT use in engagements")`（`:88-91`）但无启动拒绝。
- **影响:** 误用自签证书进实战 = TLS 固定 IOC（指纹/SAN 可被防守方聚类）。`tls.rs` 无未提交改动。
- **修复:** 当 `NYX_BIND` 非环回且使用自签时拒绝启动（除非显式 `NYX_ALLOW_SELFSIGNED=1`）。

### [LOW→未动] LOW-3 / MED-NEW-S1. `_legacy` 无盐 SHA-256 + 恒 Admin
- **状态:** ❌ **STILL PRESENT**（`operators.rs` 无改动）
- **位置:** `operators.rs:166` `secret_hash: format!("plain:{}", sha256_hex(tok))`；`operators.rs:182-186` `verify_secret` 对 `plain:` 前缀做 SHA-256 再 `constant_time_eq`；`operators.rs:167` `role: Role::Admin`。
- **缓解因素（仍成立）:** `_legacy` 不持久化（`operators.rs:171` 注释），无文件可窃取；攻击面为 HIGH-1（已修）的计时 oracle 残留 + 在线网络暴力（受限于 server 速率）。
- **修复:** legacy token 也走 argon2（每次启动重 hash 成本可接受），或文档明确 NYX_TOKEN 仅 CI/dev。

### [LOW→未动] LOW-4. operator resolve 名枚举计时
- **状态:** ❌ **STILL PRESENT**
- **位置:** `operators.rs:91-106` `resolve`：`HashMap::get(name)` 先于 `verify_secret`。不存在名 → 快速 None；存在名 → 走 argon2（慢）→ 名枚举计时。argon2 部分掩盖。`operators.rs` 无改动。
- **修复:** 对不存在的名执行一次 dummy argon2 verify 再返回 None。

### [LOW→未动] LOW-5. audit query 全文件读
- **状态:** ❌ **STILL PRESENT**
- **位置:** `audit.rs:154-189` `query`：`BufReader::lines()` 全文件扫描，硬上限 5000（`:158`）。大日志内存尖峰但已封顶。`audit.rs` 该函数无改动（diff 仅触及 `append`）。

---

## 第二部分：未提交修复中的新缺陷（审计 diff 本身）

### [LOW] NEW-A1. `AppState::default()` 中 `generate().expect()` 在 `panic=abort` 下仍有理论风险
- **位置:** `lib.rs:126-127`
- **已核验:** `ServerKeypair::generate().expect("default AppState keypair: OsRng is infallible on supported targets")`。`generate()` 现返回 `Result`（`crypto.rs:238`），std 构建下 `OsRng` 不可失败，故 `Err` 不可达。
- **影响:** 仅测试代码触达（生产 `main.rs` 用显式 struct literal）。即便触发，OsRng 在支持平台上不返回 Err。**非真实风险**，记录为代码质量。
- **修复:** 无需修；或测试 helper 用 `unwrap()`（测试中 panic 可接受）。

### [INFO] NEW-A2. `s.key.clone()`（既有会话读锁路径）正确
- **位置:** `lib.rs:584` `(false, s.key.clone())`；`lib.rs:625` `let reply_key = key.clone();`
- **已核验:** `SessionKey` 不再 `Copy`（`crypto.rs:31` `pub struct SessionKey([u8; KEY_LEN]);`，手动 `impl Clone` at `:42-46`，手动 `impl Drop` zeroize at `:76-81`）。diff 把旧 `s.key`（隐式 Copy）改为 `s.key.clone()` 以适配 Drop。会话密钥在会话生命周期内不变，故 clone 与原值始终一致——`open_frame(&key,&raw)`（`:589`）与新会话回复 `&reply_key`（`:647`）均正确。clone 的 Drop 会 zeroize 副本。
- **结论:** 修复正确，无新缺陷。

### [INFO] NEW-A3. Cargo.toml 依赖添加正确
- **位置:** `crates/server/Cargo.toml:37-43`
- **已核验:** `subtle = "2"`（lockfile `2.6.1`）、`rand = { workspace = true, features = ["getrandom"] }`（workspace `rand 0.8`，lockfile `0.8.6`）。`generate_api_token` 用 `rand::rngs::OsRng.fill_bytes`（`lib.rs:472`），rand 0.8 的 `OsRng` 需 `getrandom` feature——已启用。无版本冲突。

---

## 第三部分：新发现（07-08 baseline 之外）

### [MEDIUM] NEW-S4. 新会话（check-in）路径存在 TOCTOU 竞态，与既有会话防御不对称
- **位置:** `lib.rs:578-586`（读锁判定 `is_new`）与 `lib.rs:638`（无锁 `insert`）
- **状态:** NEW（07-08 未发现；07-08 赞扬了"既有会话"的写锁原子反重放，但未审视"新会话"路径）
- **已核验:**
  - 既有会话路径**正确**：`lib.rs:663-670` 在 `get_mut` 写锁内原子执行 `counter <= last_recv` 判定 + `last_recv = counter` 提交。注释（`:653-662`）准确。单测 `anti_replay_concurrent_same_counter_only_one_wins`（`:1916`）覆盖。
  - 新会话路径**未原子化**：
    1. `:578` `st.sessions.get(&raw.pubkey)`（读锁）→ `None` → 置 `is_new=true`，读锁释放。
    2. `:588` `open_frame`（无锁）。
    3. `:591` `if is_new`（无锁判定）。
    4. `:638` `st.sessions.insert(raw.pubkey, session)`（写锁，但**不检查是否已存在**）——DashMap `insert` 静默覆盖。
  - 竞态窗口：两个并发 beacon 携**相同** ephemeral pubkey + 相同 counter（首帧 counter 通常 0）。两者都走 `None` 分支 → 都 `is_new=true` → 都 decrypt 成功（同一 key）→ 都 insert。后者覆盖前者，`last_recv` 被重置为该帧 counter。
- **可触发性评估:** 诚实 X25519 客户端不会复用 ephemeral key，故正常 implant 不会触发。攻击者重放首帧（counter=0）时，读锁 `:581` 的 `raw.counter <= s.last_recv` 在"已有会话"时会拒绝重放——**但当两个重放帧都赶在首个 insert 完成前到达**（窗口 = 读锁释放到 insert 之间，含一次 ECDH+AEAD 解密耗时，约数十微秒至毫秒），两者都见 `None`、都成功。后果：会话被重置、`SessionNew` 事件重复触发、pending tasks 队列被清空（新 `Session` 的 `pending: Vec::new()` 覆盖旧队列里可能已由 operator 排入的任务）。
- **影响:** (1) 重复 `SessionNew` 事件污染 operator 视图与 Rhai hook；(2) **operator 已排入但 implant 尚未拉取的 pending tasks 静默丢失**（被覆盖的空队列替换）——操作员看到 task ack 200 但 implant 永不执行，且无错误；(3) `last_recv` 重置使后续该 session 的反重放下界倒退。非 RCE，但属"静默任务丢失 + 取证噪音"，对一个任务投递系统是正确性缺陷。
- **为什么 07-08 漏掉:** 该报告的"已验证干净"节（handle_beacon）聚焦既有会话反重放，未单独审视 new-session 分支的 check-then-act 原子性。
- **修复:** 把 `:591-649` 的新会话注册改为原子的 `entry().or_insert` 风格，例如用 `st.sessions.entry(raw.pubkey).or_insert_with(...)` 在写锁内完成"判定不存在 + 插入"；若 `entry` 已被占用则视作既有会话走 `counter <= last_recv` 校验。或在 insert 前用 `if st.sessions.contains_key(&raw.pubkey) { 走既有路径 }` 并接受残留窗口（弱于 entry 方案）。

### [LOW] NEW-S5. `is_loopback_bind` 前缀匹配可被构造主机名误判为 loopback
- **位置:** `lib.rs:481-486`
- **状态:** NEW（CRIT-1 修复引入的辅助函数）
- **已核验:**
  ```rust
  pub fn is_loopback_bind(addr: &str) -> bool {
      addr.starts_with("127.") || addr.starts_with("localhost")
          || addr.starts_with("[::1]") || addr.starts_with("::1")
  }
  ```
  - `"127.0.0.1.evil.com:8443"` → `starts_with("127.")` → **true**（实为网络主机名）。
  - `"localhost.evil.com:8443"` → `starts_with("localhost")` → **true**。
  - 大小写：`"Localhost:8443"` / `"LOCALHOST:8443"` → **false**（`starts_with` 大小写敏感），会被判为网络绑定 → 触发 auto-token（fail-safe 方向，可接受）。
- **影响:** 仅当操作员**主动**把 `NYX_BIND` 设为形如 `127.xxx`/`localhost.xxx` 的网络主机名时，auto-token 守卫被绕过（误判为 loopback → 不生成 token → 网络暴露且开放）。这是自伤配置，非远程可利用。但 CRIT-1 修复的安全保证在此边角失效。
- **缓解:** 默认仍是 loopback；攻击需操作员错误配置。
- **修复:** 用 `addr.parse::<SocketAddr>()` 或分离 host/port 后精确比对（`127.0.0.0/8` 数值判定、`localhost` 精确等值、`::1` 精确）。新增单测（`:1741-1753`）未覆盖此前缀绕过场景。

### [LOW] NEW-S6. 审计 detail 兜底仍丢多数命令参数（HIGH-3 残留，降级）
- **状态:** NEW（对 HIGH-3 修复覆盖度的补充观察；详见上方 HIGH-3/5 条目）
- **位置:** `lib.rs:1142-1154` 的 `_` 兜底臂
- **已核验:** 25 个 `Command` 变体中仅 `Shell`/`Upload`/`MakeToken` 3 个有结构化 detail，其余 22 个（含 `Bof`/`Inject`/`Download`/`StealToken`/`Connect`/`Portscan` 等高取证价值操作）仍只记 `{"task_id","command":cmd_name}`。
- **修复:** 见 HIGH-3/5 条目。

### [LOW] NEW-S7. `generate_api_token` 经 `eprintln!` 输出，去向未约束
- **位置:** `main.rs:142-146`
- **已核验:** 自动生成的 token 用 `eprintln!` 打印到 stderr（仿 server-pubkey 模式）。若 stderr 被重定向到世界可读日志、journald、或容器采集器，token 会落盘。
- **影响:** 取决于部署的日志采集。CRIT-1 修复的 token 是访问 implants 的钥匙，泄露 = 持有全部任务能力。
- **修复:** (1) 文档提示 stderr 去向；(2) 或写一个 0600 文件（仿 `NYX_KEYFILE`）并提示路径，而非 stderr。

### [LOW] NEW-S8. 审计 `MakeToken` detail 中 `domain`/`user` 未截断
- **位置:** `lib.rs:1149-1152` `format!("{}\\{}", domain, user)`
- **已核验:** `domain`/`user` 来自操作员 JSON 请求，未 `truncate`，直接进审计日志。Shell args 已截断（`:1144`），但此处遗漏。
- **影响:** 操作员可投递超长 domain/user 膨胀 `audit.jsonl`（低，操作员自身行为）。
- **修复:** `truncate(&format!("{}\\{}",domain,user), 256)`。

### [LOW] NEW-S9. cred store / audit 错误仍回显内部 DB 错误（NEW-S3 残留）
- **状态:** STILL PRESENT（07-08 NEW-S3，未修）
- **位置:** `lib.rs:1318` `format!("cred store: {e}")`；`:1377`；`:1433`；`:1460` `format!("audit: {e}")`；`:1483`。
- **影响:** rusqlite 错误可能含 SQL/路径片段，经 `format!` 回给客户端（已认证或开放模式）。
- **修复:** 返回通用 `"internal error"`，细节只进 `tracing::error!`。

---

## 第四部分：已验证干净的区域（带证据）

### Beacon handler 既有会话反重放（`lib.rs:650-714`）— 严密
- **写锁内原子反重放:** `:663` `get_mut` 写锁，`:667` `counter <= last_recv` 判定与 `:670` `last_recv = counter` 提交在同一锁内，不可被并发 beacon 拆分。注释（`:653-662`）明确这是权威检查，上方 `:578-585` 读锁仅优化。
- **kill date fail-closed:** `:512-522` 时钟错误 `map_err` 返回 Err（拒绝 beacon），而非 `unwrap_or(0)`（会绕过 kill date）。boot 时 `main.rs:47-54` 同样 fail-closed。
- **会话/结果/pending 上限:** `MAX_SESSIONS=4096`（`:596`）、`MAX_RESULTS_PER_SESSION=4096`（`:695` drain 最旧）、`MAX_PENDING_PER_SESSION=1024`（`:1121` 503 背压）。
- **beacon 错误不回显:** `:355-358` 统一 `400 BAD_REQUEST` 无错误体 → 无 implant 侧 oracle。
- **请求路径无 `.unwrap()`/`.expect()`:** `awk` 扫描（生产段）仅 `AppState::default()` 两处（测试专用）。

### SessionKey 的 `Clone`/`Drop` 修复（`crypto.rs:31-81`）正确
- 见 NEW-A2。clone 的副本被 Drop zeroize，无密钥泄露。

### 审计日志原子写 + 权限
- `operators.rs:218-239` `persist` temp+rename，Unix 0600（`:233`）。
- `audit.rs:87-93` open 后 set 0600。
- `audit.rs:107-113` 锁中毒 fail-closed（丢一条记录 + log，不 panic）。

### Cred store SQL 注入面 — 干净
- `store.rs` 全部查询用 `params![]`（`:94-113` upsert、`:120-123` list、`:134-138` get、`:148-151` delete、`:158` count）。无字符串拼接 SQL。
- `Mutex<Connection>` 序列化写（`:39,93,119,...`），锁中毒返回 `StoreError::Poisoned`（不 panic）。

### 角色门控一致
- Viewer 在所有写路径被 403：`post_task`（`:1098-1103`）、`get_results`（`:1207-1213`）、`post_creds`（`:1347-1352`）、`delete_cred`（`:1402-1407`）、`verify_audit`（`:1470-1476`）、kernel `gate`（`kernel.rs:84-97` 要求 Admin）。
- `list_creds?reveal=1` 对 Viewer 拒绝（`:1305-1310`）。
- `get_audit` 非 Admin 强制限制为自身记录（`:1455-1457` `q.operator = Some(op.name)`）。

### Operator registry poison 安全
- `is_open()`（`operators.rs:79-87`）poison 时 fail-closed（返回 false → 走认证 → 拒绝）。
- `list()`（`:108-116`）poison 返回 `io::Error`。

### TLS 证书加载
- `load_pem_cert`/`load_pem_key`（`tls.rs:59-76`）正确处理空证书/空密钥错误。

### 新增单测质量
- `generate_api_token_is_64_hex_chars_and_unique`（`lib.rs:1723`）覆盖长度/字符集/非碰撞/非全零。
- `is_loopback_bind_classifies_common_addresses`（`:1741`）覆盖 IPv4/localhost/IPv6（**但未覆盖前缀绕过**，见 NEW-S5）。
- `truncate_passes_short_and_cuts_long_with_ellipsis`（`:1757`）覆盖短/空/长/边界。

---

## 未逐行复核（诚实声明）
- `crates/server/tests/end_to_end.rs`（734 LOC）：测试代码，未审。
- `kernel.rs` 内部 `send_op` 逻辑（`:51-80`）：因 CRIT-2 证明其死代码（`kernel: None` 不可达），未逐行再审其阻塞持锁细节（MED-4 风险休眠）。

---

## 修复优先级建议（按残余风险）

1. **CRIT-2**（kernel 死代码）：接线或删路由——当前路由存在即误导。
2. **NEW-S4**（新会话 TOCTOU）：改 `entry().or_insert_with`，闭合并发首帧行为；补一个两并发首帧的单测。
3. **HIGH-3 残留（NEW-S6）**：扩展审计 detail 覆盖 `Bof`/`Inject`/`Download`/`StealToken`/`Connect`/`Portscan` 等高价值变体。
4. **MED-3**（自签 cert guard）：非环回 + 自签 → 拒绝启动。
5. **MED-2**（预认证分配速率限制）：accept loop 外层加 per-peer 闸。
6. **NEW-S5/S7/S8/S9 + LOW-3/4/5 + MED-NEW-S1**：清理项，可批量处理。
