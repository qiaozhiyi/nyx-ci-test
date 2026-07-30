# NY 反人类代码审计报告 (Anti-Human Pattern Audit)

**审计日期**: 2026-07-23
**审计范围**: `NY/` 全量 23 个 Rust crate + 工具 + 脚本
**审计方式**: 6 并行子 agent 逐行审计 + 主 agent 聚合
**侧重**: **维护者视角** — 哪些代码在对抗开发者，而非单纯的安全漏洞

> 前置参考: `FULL_CODE_AUDIT_2026-07-21.md`（27 CRITICAL + 46 HIGH 安全发现）。
> 本报告**不重复**上次审计已知的安全漏洞，聚焦于代码**设计/结构/习惯**层面的反人类问题。

---

## 总体评价

| 维度 | 评分(1-10) | 说明 |
|------|-----------|------|
| 密码学正确性 | 8 | X25519+HKDF+ChaCha20-Poly1305 设计良好，SessionKey 有 Zeroize |
| 并发正确性 | 7 | DashMap + DashMap Entry API 良好；kernel.rs Mutex 是污点 |
| 审计追踪 | 9 | SHA-256 链式完整性 + per-record flush，设计到位 |
| 模块边界 | 4 | **严重问题**: implant-win 是 57 文件/32328 行的巨型单 crate |
| 函数粒度 | 3 | 35 个函数超过 50 行，最长达 291 行 |
| 代码复用 | 2 | **严重问题**: djb2 5次、PE 解析 6次、itoa 5次、ExitProcess 5次 |
| 错误处理一致性 | 4 | server 用 `anyhow::Result` 好；implant 在 panic=abort 下仍有 22+ 个 unwrap |
| FFI 安全性 | 5 | unsafe 无法避免，但 transmute(usize→fn ptr) 是 UB，CONTEXT 硬编码偏移脆弱 |
| 测试覆盖 | 5 | protocol/server/store 测试良好；implant-win 仅 selftests.rs 有测试 |
| 文档完整性 | 7 | crypto/frame/server 模块文档出色；operator-kernel-cli 几乎无文档 |

---

## 第一部分：结构反人类 —— 代码组织问题

### ⚠️ AH-1: implant-win 是 57 文件/32,328 行巨型单 crate

**位置**: `crates/implant-win/src/` (57 .rs 文件)

```
beacon.rs (839L) → entry.rs (726L) → resolve.rs (808L) → inject.rs (1088L)
→ screenshot.rs (1583L) → bof.rs (1071L) → blind_hwbp.rs (1108L)
→ keylog.rs (1158L) → syscalls.rs (993L) → fs.rs (1091L) → trex/mod.rs (1896L) …
```

**反人类点**:
- 57 个文件全部在一个 crate 里，模块间无编译边界
- Rust 的 `pub(crate)` 在这里无助 — 所有模块互相可见
- 改一个 `static mut` 可能影响 30 个文件，编译器不会提示
- `no_std` + `panic=abort` + `#![cfg(target_os = "windows")]` — 任何 refactor 都需在 Windows 目标上验证

**建议**: 拆分为至少 3 个 crate:
- `implant-core`: resolve + syscalls + ntalloc（无上层依赖）
- `implant-evasion`: blind + blind_hwbp + fluctuation + hookchain + sleep
- `implant-tasks`: beacon + fs + shell + screenshot + keylog + inject + bof + trex

### ⚠️ AH-2: 巨型函数（35 个超 50 行，Top 10 超 150 行）

| 行数 | 函数 | 文件 |
|------|------|------|
| **291** | `cross_session_capture()` | `screenshot.rs` |
| **253** | `beacon_loop()` | `beacon.rs` |
| **227** | `add_hwbp()` | `blind_hwbp.rs` |
| **204** | `capture_bmp()` | `screenshot.rs` |
| **204** | `run()` | `bof.rs` |
| **203** | `build()` | `fluctuation_thunk.rs` |
| **202** | `post_frame_enhanced()` | `transport.rs` |
| **189** | `post_frame()` | `transport.rs` |
| **187** | `run_shell_inner()` | `shell.rs` |
| **186** | `hijack_worker_factory()` | `tp.rs` |

**反人类点**:
- `cross_session_capture()` 291 行 = 一整屏都看不完。包含 token 窃取、进程创建、文件读回、清理 — 至少应拆为 5-6 函数
- `add_hwbp()` 227 行包含: slot claim + shadow resolve + VEH register + DR write + slot publish — **5 个独立阶段挤在一个函数里**
- 这些函数**无法单独测试** — 任何修改都要理解全部 200+ 行上下文

### ⚠️ AH-3: 代码重复（DRY 灾难级）

**djb2 哈希 — 5 份独立实现**:
- `resolve.rs:28-36` — 规范实现 `pub(crate) fn djb2()`
- `resolve.rs:74-81` — **内联重复**（未调用上面的 djb2!）
- `resolve.rs:280-286` — 再次内联
- `resolve.rs:429-434` — 再次内联
- `resolve.rs:484-490` — 再次内联

**PE 头部解析 — 6 份独立实现**:
- `resolve.rs` — `e_lfanew` + data directory walk
- `unhook.rs` — 再次实现
- `hookchain.rs` — 再次实现
- `insomniac.rs` — 再次实现
- `caller_spoof.rs` — 再次实现
- `proxy_veh.rs` — 再次实现

**ExitProcess 解析 — 5 份**:
- `entry.rs:264-279` (nyx_entry)
- `entry.rs:435-438` (nyx_beacon_oneshot)
- `entry.rs:466-469` (nyx_screenshot_session)
- `entry.rs:326-334` (exit_in_entry)
- `config.rs:108-123` (fatal_config)

**itoa/十进制格式化 — 5 份**: `beacon.rs`, `hashdump.rs`, `pivot.rs`, `entry.rs`, `screenshot.rs`

**反人类点**:
- 发现一个 djb2 bug? 需要改 5 处。每次都会漏掉一两处
- exfil/deaddrop.rs 里的 `&&`/`||` 优先级 bug（CRITICAL-20）就是重复实现的结果
- 某处 "修好了"，其他地方仍是坏的 — 语义 drift

### ⚠️ AH-4: 服务端巨型 struct + 巨型函数

**`AppState` — 17 个字段** (`server/lib.rs:95-155`):
```rust
pub struct AppState {
    pub server_pub: [u8; 32],
    pub server_key: ServerKeypair,
    pub token: Option<String>,
    pub profiles: Vec<Arc<Profile>>,
    pub creds: Arc<CredStore>,
    pub operators: Arc<OperatorRegistry>,
    pub audit: Arc<AuditWriter>,
    pub kernel_bridge: Option<Arc<KernelBridge>>,
    pub template: Option<Arc<Vec<u8>>>,
    pub implants: Option<Arc<ImplantStore>>,
    pub sessions: DashMap<SessionId, Session>,
    pub persist: Option<SessionPersistence>,
    pub extc2_relay: Option<ExtC2RelayConfig>,
    pub fingerprints: DashMap<SocketAddr, Fingerprint>,
    pub chans: DashMap<u32, (tokio::sync::mpsc::Sender<...>, ...)>,
    pub profile: Option<Arc<Profile>>,
    pub cfg: Arc<ServerConfig>,
}
```

**反人类点**: 每新增一个功能就在 `AppState` 加一个字段。17 个字段中至少有 4 组逻辑分组:
- `AuthGroup { token, operators }`
- `StoreGroup { creds, implants, audit }`
- `SessionGroup { sessions, persist, fingerprints }`
- `RelayGroup { extc2_relay, kernel_bridge, chans }`

**`main()` — 395 行** (`server/main.rs:7-402`): env 解析 + state 构建 + listener 初始化的**全部**代码
**`generate_implant()` — 475 行** (`server/implant_gen.rs:438-914`): 鉴权、校验、限流、密钥生成、配置构建、加密、模板突变、占位符重定位、PE 补丁、PE 验证、SHA-256、数据库写入、审计 — 12 个步骤

**`handle_frame()` — 355 行** (`server/lib.rs:1134-1489`): 新会话注册 + 已有会话的**全部**逻辑

---

## 第二部分：错误处理反人类

### 🔴 AH-5: panic=abort 下 22+ 个 unwrap()/expect()

这是**最反人类的架构矛盾**：

```
Cargo.toml: panic = "abort"
  +
beacon.rs/inject.rs/transport.rs/bof.rs/...: .unwrap() / .expect()
  =
进程静默死亡，零诊断
```

**具体点位**:
| 文件 | 行 | 代码 | 触发条件 |
|------|-----|------|----------|
| `transport.rs` | 337,591 | `fns.set_option.unwrap()` | WinHTTP 解析失败 |
| `inject.rs` | 711,726,761 | `susp_status.unwrap()` | NtSuspendThread 失败 |
| `bof.rs` | 98-101 | 4x `.unwrap()` in `vq_readable()` | 畸形 COFF |
| `tp.rs` | 576,590 | `.unwrap()` on syscall | NtCreateThreadPoolWork 失败 |
| `heap.rs` | 51 | `.unwrap()` in `to_string_lossy()` | 理论上不可达但— |
| `trex/melt.rs` | 142 | `.expect("NtTerminateThread…")` | 导出解析失败 |
| `channels/smb.rs` | 125-128 | 4x `.unwrap()` on fn ptr | kernel32 导出解析失败 |

**反人类点**:
- 日志说 "beacon 失联" → 操作员不知道是网络问题还是 `WinHttpSetOption` 返回 NULL
- 调试: 必须 attach debugger 到 Windows 目标上才能看到 crash site
- 有一个 `unwrap()` 曾经确实是 `expect()`，注释说 "已修复为 match"… 但其他 21 个还在

### 🟡 AH-6: TransportError 只有 Debug 没有 Display

**位置**: `crates/transport/src/traits.rs`

```rust
#[derive(Debug, Clone)]  // ← 只有 Debug!
pub enum TransportError {
    Dead(&'static str),       // ← &str，不能带运行时上下文
    Transient(&'static str),  // ← 同上
}
```

**反人类点**:
- 操作员看到 `Dead("Slack token invalid")` — 没有 HTTP 状态码、没有响应 body、没有 URL
- `StackError` 用 `{:?}` 格式化内层的 `TransportError` — **Debug 输出泄漏到用户界面**
- llm_api.rs 和 mcp.rs 用 `e.to_string().contains("timed out")` 检测超时 — ureq 改了 error 格式就静默失败

### 🟡 AH-7: kernel.rs 的 Mutex 横跨阻塞 TCP I/O

```rust
// kernel.rs:36
conn: Mutex<Option<TcpStream>>,

// kernel.rs:58 — 在 async handler 中获取 std::sync::Mutex
let mut guard = self.conn.lock().map_err(...)?;

// kernel.rs:62-72 — 持锁期间做阻塞 TCP I/O
s.set_read_timeout(Some(Duration::from_secs(30)))?;  // → 阻塞 tokio worker
// ... stream.read_exact → 最多阻塞 30s
```

**反人类点**:
- 一个 kernel API 调用阻塞时，**所有**其他 kernel API 调用排队 — 全串行化
- 6 个 handler 结构完全相同（鉴权 → 审计 → bridge check → send_op → JSON），**一个宏就能消除 120 行重复**

---

## 第三部分：抽象层反人类

### 🔴 AH-8: 无 x86-64 解码器的 "mutation" 引擎

**位置**: `crates/nyx-mutate/src/lib.rs`

`insert_nops`、`rotate_registers`、`substitute` 三个 mutation pass 用**启发式字节匹配**代替真正的 x86-64 解码器:

```rust
// rotate_registers 假设 0x40..=0x4F 都是 REX 前缀
// → 这些字节也可能是指令本身 (inc/dec reg on x86)、ModRM、立即数
```

```rust
// looks_like_key: ≥20 独特字节/32 → "这是个密钥"
// → 高熵代码/数据也会匹配 → XOR 后损坏二进制
```

**反人类点**:
- 注释承认 "All mutation passes lack a real x86-64 decoder... fundamentally unsound"
- 但 `MutationPasses` struct literal 可以**轻易开启**这些 pass
- 默认关闭是防御，但代码留在树里 = 总会有人打开
- 要么引入 `iced-x86` 做正经解码，要么删除这些 unsafe pass

### 🔴 AH-9: `static mut` 泛滥（13 处）

```
blind.rs:232       BLIND_ERR              — 诊断
bof.rs:122-578     8 个 static mut         — BOF 输出/printf/args
context.rs:179     CTX_BUF                 — CONTEXT 缓冲区
keylog.rs:107-400  3 个 static mut         — 键盘日志缓冲区
mem.rs:46          MASK_KEY_BUF            — RC4 密钥
ntalloc.rs:229     FALLBACK_MEM            — 分配器回退内存
pivot.rs:73        CHANNELS                — SOCKS 中继
screenshot.rs:969  XSESS_FAIL              — 截图错误码
channels/smb.rs:99 K32 / WSA               — 函数指针缓存
transport.rs:161   WINHTTP                 — 函数指针缓存
```

**反人类点**:
- 每个 `static mut` 都是 UB（Rust aliasing 模型下）
- 虽然 beacon 单线程，但**编译器不知道** — 可能重排/CSE 读写
- 维护者改一个 `static mut` 的写入时机 → 非确定性崩溃
- `ntalloc.rs:FALLBACK_MEM` 被**全局分配器**访问 → 任何 alloc 路径都可能竞争
- 每个 `static mut` 需单独审计 "真的只在单线程下访问吗？"

### 🟡 AH-10: `transmute(usize → fn ptr)` — 按 Rust 规范是 UB

**位置**: `entry.rs`, `resolve.rs`, `inject.rs`, `transport.rs` 等 ~30 处

```rust
let addr: usize = peb_walk_resolve("ntdll.dll", "NtDelayExecution");
let f: unsafe extern "system" fn(...) = core::mem::transmute(addr);
```

**反人类点**:
- Rust 不保证 `usize` 可以表示函数指针，在 wasm/CHERI 等平台上不可移植
- 当前在 x86-64 上可行，但 `cargo careful` / Miri 会报 UB
- 每次 refactor 都要记住 "这里不能用 Miri 检测"

---

## 第四部分：并发/异步反人类

### 🟡 AH-11: 三个 Store 共用一个 `_schema_version` 行

**位置**: `crates/store/src/`

```
store.rs:96         CURRENT_SCHEMA_VERSION = 1
session_store.rs:131 CURRENT_SCHEMA_VERSION = 2
implant_store.rs:129 CURRENT_SCHEMA_VERSION = 1
```

三个 Store 打开**同一个 SQLite 文件**，各自读 `_schema_version` 表，各自迁移，各自写回。

**并发场景**:
1. SessionStore 读到 version=0，需要 v2 迁移 → 执行 DDL，写 version=2
2. ImplantStore 读到 version=0，需要 v1 迁移 → 执行 DDL，写 version=1 ← **覆盖了 v2!**
3. 下次启动 SessionStore 读到 v1 → "哦我需要 v1→v2 迁移" → 重跑（幸好是幂等 DDL）
4. 但如果 ImplantStore 有 v2 迁移 → "v1 已经够了，跳过" → **迁移根本没执行**

**反人类点**: 三个人往同一行写不同的版本号。写入无事务保护。某天 `ImplantStore` 升级到 v2 而 SessionStore 已经是 v2 → **ImplantStore 的 v2 迁移永远不执行**。

### 🟡 AH-12: `mask_secret` — 文档承诺 "first2….last2" 实现是 `"********"`

**位置**: `crates/store/src/model.rs:72-74`

```rust
/// Mask a secret for list/preview rendering: `first2….last2` when long enough,
/// else a bare `….`.
pub fn mask_secret(_s: &str) -> String {
    "********".to_string()     // ← 无视参数！文档在撒谎！
}
```

**反人类点**: 这是典型的 "先写文档，实现是 stub，然后忘了"。维护者看文档以为有 partial masking，调用者依赖文档做 UI 渲染 — 结果全是 `********`。如果某天有人 "修完" 实现 → 行为静默改变。

---

## 第五部分：CI/构建反人类

### 🟡 AH-13: implant-win 不在 workspace 里

**位置**: `Cargo.toml:23-28`

```toml
# NOTE: crates/implant-win is intentionally NOT a workspace member.
# It is #![no_std] + #![no_main] + targets x86_64-pc-windows-gnu on nightly
```

**反人类点**:
- `cargo check --workspace` 不检查 implant-win
- `cargo clippy --workspace` 不检查 implant-win
- `cargo fmt --workspace` 不检查 implant-win
- implant-win 的编译需要 nightly + Windows 工具链 → **macOS 开发机上检查不了**

**实际后果**: implant-win 是代码量最大的 crate (32K 行)，但 CI 对它的覆盖最弱。已有 test 在 `crates/implant-win/tests/` 但需要 Windows runner。

### 🟡 AH-14: `#![allow(dead_code)]` 全局抑制

**位置**: 
- `crates/transport/src/lib.rs` — 整个 crate
- `crates/operator-kernel-cli/src/main.rs:32` — `unused_imports, unreachable_code, dead_code`

全局 `allow` 意味着编译器不再警告死代码 → 死代码累积 → 新人读代码时花时间理解从不执行的路径。

---

## 第六部分：API 设计反人类

### 🟡 AH-15: `HealthCheck` 返回 `Option<u64>` — 把 5 种失败合成一个 None

```rust
fn health_check(&self) -> Option<u64>  // None = DNS? TLS? 404? timeout? auth?
```

DNS 解析失败、TLS 握手失败、HTTP 403、HTTP 500、超时 → 全部返回 `None`。
然后 `init()` 里硬编码猜原因: `Err(TransportError::Dead("unreachable"))`。

### 🟡 AH-16: 传输 Stack recv 无重试但 send 有

```rust
// TransportStack::send — 丰富的重试循环：probe → init → retry → demote
// TransportStack::recv — 一次 map_err，失败即死
```

send 路径有完整的 channel 生命周期管理 (Fresh → Active → demote on Dead)，但 recv 是一次性的。一旦 recv 遇到暂时故障 → 整帧丢失。

### 🟡 AH-17: `duplicate_extract_hex` — 字节级相同的两个函数

`crates/transport/src/llm_api.rs` 和 `crates/transport/src/mcp.rs` 各有一份 25 行的 `extract_hex()` 函数，逐字节相同。不抽象到共享模块的理由：无。

---

## 第七部分：运营 IOC 反人类（维护者暴露风险）

硬编码的路径是持久的 forensic artifacts:
```
C:\Windows\Temp\~dfftmp.bmp       # 截图
C:\Windows\Temp\nyx_shot_diag.txt # 诊断
C:\nyx\diag_*                     # 诊断标记
C:\nyx\hwbp_diag.txt              # HWBP 诊断
```

维护者改了截图实现，路径还在 → 部署后 analyst 通过路径关联不同 implant。

---

## 优先级排序

### 立即修复（影响所有维护者操作）

| 优先级 | ID | 问题 | 工作量 |
|--------|-----|------|--------|
| **P0** | AH-5 | panic=abort 下 22+ unwrap → 替换为 Result/优雅降级 | 中（逐个审计） |
| **P0** | AH-3 | 代码重复 — 统一 djb2/PE解析/itoa/exit 实现 | 中（重构） |
| **P0** | AH-9 | static mut 替换为 AtomicPtr/OnceLock/SyncUnsafeCell | 大（13 处） |
| **P1** | AH-2 | 巨型函数拆分 — beacon_loop/cross_session_capture/add_hwbp | 大（35 函数） |
| **P1** | AH-1 | implant-win crate 拆分 | 巨大 |
| **P1** | AH-4 | AppState 分组 + main()/generate_implant() 拆分 | 中 |
| **P2** | AH-11 | Store _schema_version 独立化 | 小 |
| **P2** | AH-7 | kernel.rs Mutex 重构为 tokio::sync::Mutex + 消除重复 | 小 |
| **P2** | AH-8 | nyx-mutate 删除 unsafe pass 或引入解码器 | 中 |
| **P3** | AH-12 | mask_secret 修复 | 极小 |
| **P3** | AH-13 | implant-win 纳入 workspace（至少 clippy） | 中 |
| **P3** | AH-17 | extract_hex 去重 | 极小 |

---

## 总结

代码库整体设计水准属于**中上**，密码学、协议层、审计系统有深思熟虑的防御。但 **implant-win 是一个反人类重灾区**: 32K 行塞在一个 crate 里，函数大到无法理解，代码复制粘贴到处可见，`static mut` + `unwrap` 在 `panic=abort` 下组成静默死亡组合拳。

**一句总结**: 这是一份 "写的时候爽、改的时候想自杀" 的代码。安全漏洞上次审计已列出 27 CRITICAL + 46 HIGH；本次审计暴露的是 —— 为什么那些 CRITICAL 会在 2026 年 7 月还存在？因为维护者每次改一行代码都要对抗巨型函数、代码重复、non-workspace crate、and-no-std-constraints。

---

*报告由 6 并行 ZCode 子 agent + 主 agent 聚合。基于 FULL_CODE_AUDIT_2026-07-21.md 的安全发现，聚焦于维护者体验反模式。*
