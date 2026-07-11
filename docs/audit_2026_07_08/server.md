# Server / REST / Store / Audit-log — 深度审计 (2026-07-08)

> **审计者:** Main (inline，原 AuditServer 子代理因 429 限流失产)
> **范围:** `crates/server/src/` (lib.rs 2204 LOC, main.rs, kernel.rs, audit.rs, operators.rs, tls.rs) + `crates/store/`
> **方法:** 逐行 `read` 关键路径，复核 2026-07-08 baseline 全部 server 项
> **授权语境:** 授权红队工具，内部改进用。

---

## Baseline 复核（CONFIRM = 仍存在 / FIXED = 已修）

| ID | 状态 | 当前位置 | 备注 |
|---|---|---|---|
| **CRIT-1** 开放模式默认 Admin | ✅ CONFIRM | `lib.rs:767-771` `authenticate()` 分支 (3)；`main.rs:147` `0.0.0.0:8443` | 无 `NYX_OPERATORS_FILE`/`NYX_TOKEN`/`NYX_BOOTSTRAP_OPERATOR` 时，`is_open()==true` → 跳过分支(1)(2) → `Allowed(_anonymous, Admin)`。绑定 `0.0.0.0`。**最高危**。 |
| **CRIT-2** kernel bridge 死代码 | ✅ CONFIRM | `main.rs:129` `kernel: None` | `KernelBridge::new()` 无调用点；所有 `/api/kernel/*` 命中 `None => "no daemon"`。 |
| **HIGH-1** constant_time_eq 先 SHA 再比 | ✅ CONFIRM | `lib.rs:455-471` | `Sha256::update(a)` / `update(b)` 再比 32B 摘要。`sha2` update 时间 ∝ 输入长度。用于 `authenticate()` legacy token 路径 (`lib.rs:759`)，bearer 长度可变 → 长度类计时区分。 |
| **HIGH-3/5** 审计丢弃命令参数 | ✅ CONFIRM | `lib.rs:1128` | `json!({"task_id": task_id, "command": cmd_name})` — 仅 `cmd_name`（静态 `&str`），无 args。`Shell{args}` 被记为 `{"command":"shell"}`。 |
| **HIGH-4** 审计 detail 序列化分叉 | ✅ CONFIRM | `audit.rs:118` vs `:120-129` | hash 基于 `detail_json`（fallback `"null"`），但持久化记录 `rec.detail` 是原 `Value`（`:126`），写时重序列化（`:131`）。`verify_chain` 重算 hash ≠ 存储 hash → 误报篡改。 |
| **MED-1** `oneshot().unwrap()` | ✅ CONFIRM | `main.rs:193` | TLS 路径 `tower::ServiceExt::oneshot(make_svc, peer).await.unwrap()`。release profile `panic=abort` → 单连接服务错误杀整个 server。 |
| **MED-2** 预认证 16KiB 分配无速率限制 | ✅ CONFIRM | `main.rs:238-246` | `rec_len` 上限 16384（`:239`），`vec![0u8; rec_len]` 每连接分配。无每 peer 连接速率限制 → 预认证内存放大。 |
| **MED-3** 自签 dev cert 无硬 guard | ✅ CONFIRM | `tls.rs:83-104` | rcgen 生成，SAN 由 `HOSTNAME`/`COMPUTERNAME` env 控制；`tracing::warn!("do NOT use in engagements")` 但无启动拒绝。 |
| **MED-4** kernel send_op 阻塞持锁 | ⚠️ 部分 | `kernel.rs` (未逐行复核，CRIT-2 已证其死代码) | 因 kernel bridge 从未接线，此路径不可达；风险降级为"潜在"。 |
| **LOW-3** 开放/legacy 恒 Admin | ✅ CONFIRM | `operators.rs:167,769` | `_legacy`/`_anonymous` 均为 `Role::Admin`；无只读默认。 |
| **LOW-4** operator resolve 非恒定时间 | ✅ CONFIRM | `operators.rs:91-106` | `HashMap::get(name)` 先于 `verify_secret`（argon2）；不存在名快速返回 None，存在名走 argon2（慢）→ 名枚举计时。argon2 部分掩盖。 |
| **LOW-5** audit query 全文件读 | ✅ CONFIRM | `audit.rs:141-146` | 读全文件至 Vec，硬上限 5000（`:145`）。大日志内存尖峰但已封顶。 |

---

## 新发现（baseline 之外）

### [MEDIUM] NEW-S1. `_legacy` token 用无盐 SHA-256 存储（无 argon2）
- **位置:** `operators.rs:166` `secret_hash: format!("plain:{}", sha256_hex(tok))`
- **已核验:** bootstrap operator 用 `hash_argon2`（`:146`），但 `NYX_TOKEN` 路径用 `plain:<sha256>` 标记。`verify_secret`（`:182-186`）对 `plain:` 前缀做 SHA-256 再 constant_time_eq。
- **描述:** `NYX_TOKEN` 是最简部署路径（单 token 共享），却用最弱哈希。无盐 SHA-256 对 GPU/rainbow table 暴力破解无抵抗力。
- **影响:** 缓解因素——`_legacy` 记录**不持久化**（`:171` 注释 "synthesized from NYX_TOKEN each boot"），无文件可窃取。攻击面仅剩 HIGH-1 的计时 oracle + 网络在线暴力（受限于 server 处理速度）。
- **修复:** legacy token 也走 argon2（每次启动重新 hash 成本可接受）；或文档明确 NYX_TOKEN 仅用于 CI/dev。

### [LOW] NEW-S2. 明文 HTTP 模式下 operator API 凭据裸传
- **位置:** `main.rs:202-213`（无 TLS 分支）；`lib.rs:1283-1286`（reveal=1 返回明文 secret）
- **已核验:** 无 `NYX_TLS` 时 `axum::serve` 裸 HTTP。open 模式 + 明文 = `GET /api/creds?reveal=1` 的 Authorization bearer 与返回的明文 hash 全程明文。
- **影响:** 网络位置窃听者获取全部凭据。CRIT-1 的放大。
- **修复:** open 模式强制绑 `127.0.0.1`（与 CRIT-1 修复合并）。

### [LOW] NEW-S3. 错误响应回显内部 DB 错误
- **位置:** `lib.rs:1273` `format!("cred store: {e}")`；`:1332`、`:1388` 同模式
- **已核验:** cred store 错误经 `format!` 回给客户端。rusqlite 错误可能含 SQL/路径片段。
- **影响:** operator API（已认证或 open 模式）；信息泄露面小但非零。
- **修复:** 返回通用 `"internal error"`，细节只进 `tracing::error`。

---

## 已验证干净的区域

### Beacon handler（`handle_beacon`, `lib.rs:473-685`）— 防御严谨
- **反重放在写锁下权威执行:** advisory 读检查（`:554` `raw.counter <= s.last_recv`）仅优化；authoritative 检查在 `get_mut` 写锁内（`:636` `<=` 正确，等号拒绝重放上一帧），TOCTOU 已闭合。注释明确说明双检查意图。
- **kill date fail-closed:** `:485-495` 时钟错误返回 `Err`（拒绝），而非 `unwrap_or(0)`（会绕过 kill date）。
- **会话/结果上限:** `MAX_SESSIONS=4096`（`:569`）、`MAX_RESULTS_PER_SESSION=4096`（`:664`，溢出 drain 最旧）、`MAX_PENDING_PER_SESSION=1024`（`:1090`，503 背压）。防 OOM。
- **beacon 错误不回显:** `:351-356` 错误统一返回 `400 BAD_REQUEST`，无错误体 → 无 implant 侧 oracle。
- **无 `.unwrap()`/`.expect()` 在请求路径:** 注释（`:549-550`）明确因 `panic=abort` 而避免；缺失 session 用 `ok_or_else` 干净返回。

### Operator registry poison 安全
- `is_open()`（`operators.rs:79-87`）poison 时 fail-closed（返回 false → 走认证分支 → 拒绝）。
- `list()`（`:108-116`）poison 时返回 `io::Error`。

### 审计日志原子写 + 权限
- `persist()`（`operators.rs:218-239`）temp+rename，Unix 0600。
- `audit.rs:88-93` open 后 set 0600。

### Cred store 角色门控
- `reveal=1` 对 `Role::Viewer` 拒绝（`lib.rs:1260-1266`）；post/delete 对 Viewer 拒绝。

### TLS 证书加载
- `load_pem_cert`/`load_pem_key`（`tls.rs:59-76`）正确处理空证书/空密钥错误；operator 证书路径干净。

---

## 未逐行复核（诚实声明）
- `crates/store/src/` SQL 层：baseline 已确认全用 `params![]`（无注入），本次未重读 3 文件。建议后续确认 schema/migration。
- `server/tests/end_to_end.rs`（734 LOC）：测试代码，未审。
- `kernel.rs` 全文：因 CRIT-2 已证其死代码（`kernel: None`），未逐行审其内部逻辑。
