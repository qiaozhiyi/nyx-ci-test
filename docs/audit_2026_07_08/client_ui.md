# Client-UI (Makepad GUI) — 深度审计 (2026-07-08)

> **审计者:** Main (inline，原 AuditClientUI 子代理因 429 限流失产)
> **范围:** `crates/client-ui/src/` (main.rs ~3168 LOC, bridge.rs ~2041, parse.rs, theme.rs, widgets/* 7 文件) + `crates/rest/src/lib.rs`（共享视图类型）
> **状态:** 此 crate 在 2026-07-05/08 审计中**从未被覆盖**。本次为首逐行审计。
> **授权语境:** 授权红队工具，内部改进用。

---

## 威胁模型说明

client-ui 是**操作员 GUI**，解析**操作员自己选择的 team server** 的数据。"恶意 server" 威胁模型较弱（操作员控制连接目标）。相关风险：① panic 崩溃 GUI；② 敏感信息（token/password/hash）泄露；③ 恶意/受损 server 的畸形 JSON 导致崩溃。

---

## 发现

### [LOW] NEW-UI1. 全局 `RwLock` `.write().unwrap()` — poison 级联崩溃
- **位置:** `main.rs:1429,1432,1444,1463,2251-2307`（~20 处）；globals `SESSIONS`/`LOG_LINES`/`BOFS`/`CONSOLE`
- **已核验:** `*SESSIONS.write().unwrap() = snap.sessions;` 等。任一线程持锁时 panic → lock poison → 后续每次 UI 更新 `.write().unwrap()` 再 panic → 级联崩溃。
- **描述:** std `RwLock` poison 语义：一次 panic 永久毒化，之后所有 `.unwrap()` 必 panic。help banner（`:2251-2307`）连续 20 次独立 `LOG_LINES.write().unwrap()`，任一失败则后续全 panic。
- **影响:** 需先有一次持锁 panic（低概率，UI 线程）。一旦发生，GUI 不可恢复。Makepad 无 panic catch → 进程退出。
- **修复:** 用 `parking_lot::RwLock`（无 poison）或 `.write().unwrap_or_else(|e| e.into_inner())`（跳过 poison）。

### [LOW] NEW-UI2. worker 线程 `reqwest::Client::builder().build().expect(...)` 静默杀 IO 线程
- **位置:** `bridge.rs:382-385`
- **已核验:** `.expect("reqwest client build")` 在 `std::thread::spawn` 闭包内。reqwest 构建失败 → worker 线程 panic 退出（不影响 UI 线程）→ channel 永不 drain → GUI 冻结（无报错提示）。
- **影响:** 极低概率（reqwest 构建基本不失败）。但失败时 UI 静默死寂，操作员无诊断。
- **修复:** 构建失败时 `to_ui.send` 一条错误快照再 `return`。

### [INFO] NEW-UI3. `FetchCreds { reveal: true }` 将明文 secret 写入事件日志
- **位置:** `bridge.rs:1125-1130`
- **已核验:** reveal=1 时 `format!("  {kind:8} {realm}\\{user}: {secret}")` 推入 `log_buf` → `Snapshot.log_lines` → UI 事件日志渲染。`LOG_BUFFER_CAP=1024` 在内存中轮转。
- **定性:** **操作员预期行为**（操作员主动 reveal 凭据）。非漏洞。注意点：明文 secret 留驻 UI 内存 + 屏幕可截取。与 server 端 mask 默认行为一致。
- **无需修复**（设计如此）。

---

## 已验证干净的区域

### `crates/rest/src/lib.rs` — `#![forbid(unsafe_code)]`，干净
- `authed()`（`:99-104`）：token 有则 `.bearer_auth(t)`，无则透传。简单正确。
- `SessionView`/`ResultView`/`TaskAck`：全字段 `#[serde(default)]`（`:22-24` 注释）→ server 加字段不破坏旧客户端，缺字段优雅降级。
- `session_signature()`（`:110-123`）：纯字符串拼接，排除 `age_secs` 防抖动。无注入面。
- `arch_name()`：固定 match，协议对齐。

### JSON 解析无 panic
- `fetch_sessions`/`enqueue_task`/`poll_result`/`fetch_tasks`（`bridge.rs:1696-1790`）：全部 `.json().await?` → `anyhow::Result` 传播。**恶意 server 的畸形 JSON 返回 `Err`，被 `log_push("! ...: {e}")` 优雅处理，不 panic。**

### Secret 处理正确
- **MakeToken password 不入日志：** `bridge.rs:1039` 记 `make_token({domain}\{user})`，无 password。password 仅进 JSON body（`:1037`）发往 server。
- **CredAdd secret 不入日志：** `:1390` 记 `cred added: {kind} {realm}\{user}`，无 secret。
- **bearer token 仅内存：** `worker_loop` 局部 `server: Option<(String, Option<String>)>`（`:381`），不落盘。

### Widgets — 零 unwrap/panic/unsafe
- `widgets/{cred_table,file_tree,console_list,bof_panel,session_graph,process_table,mod}.rs`：grep `.unwrap()|\.expect(|panic!|unsafe` **零匹配**。纯展示逻辑，server 数据经 `nyx-parse` 中性行映射。

### parse.rs — 薄适配器
- 委托 `nyx_parse`（单源真相），本地仅 `From<foreign>` 映射。无独立解析逻辑 → 无独立 bug 面（审计 `nyx-parse` 见 misc 报告）。

### Worker 架构合理
- UI 线程永不阻塞 IO（channel 传 `Vec` 快照）；20s connect 超时防挂起（`:412-429`）；指数退避防轮询空转；`LOG_BUFFER_CAP=1024` 防 OOM。

---

## 未逐行复核（诚实声明）
- `main.rs` 3168 LOC 的 Makepad 事件/渲染逻辑未全读（低安全面：纯 UI 渲染，数据经 widgets/parse 已验证干净）。
- `theme.rs`：纯样式常量，跳过。
