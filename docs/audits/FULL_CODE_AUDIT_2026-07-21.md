# NY 全量代码审计报告

**审计日期**: 2026-07-21
**审计范围**: `/Users/qiaozhiyi/Desktop/pentest/NY` 全量代码库
**审计方式**: 12 个并行子 agent 逐行审计，覆盖 23 个 Rust crate、2 个工具、约 40 个脚本（PowerShell/Python/Bash/C#）
**审计性质**: 防御性代码审计（授权安全研究）— 寻找框架**自身代码**中的 bug、内存安全问题、密码学误用、静默失败、逻辑错误、注入风险

**代码规模**: ~78,849 行 Rust + ~2,500 行脚本

---

## 执行摘要（Executive Summary）

### 严重度统计

| 严重度 | 数量 | 说明 |
|--------|------|------|
| **CRITICAL** | **27** | 内存破坏 / UB / 主机崩溃 / RCE / 注入漏洞 — 必须修复后才能用于实战 |
| **HIGH** | **46** | 静默失败 / 句柄泄漏 / 鉴权绕过 / TOCTOU — 强烈建议修复 |
| **MEDIUM** | ~50 | 健壮性 / 信息泄露 / 可绕过的检查 |
| **LOW/INFO** | ~40 | 代码质量 / 运营 IOC / 设计说明 |

### 最高优先级修复项（Top 12 — 必须在实战部署前修复）

1. **`inject.rs:1014` — `CreateRemoteThread` 传 NULL `lpStartAddress`** — 主注入路径**完全不工作**（CRITICAL）
2. **`inject.rs:215` — 模块覆写 `WriteProcessMemory` 越界写入** — 任何 >8KiB 的 shellcode 都会破坏傀儡进程（CRITICAL）
3. **`inject.rs:719` — 无 VEH 的硬件断点线程注入** — 第一次执行就触发 `EXCEPTION_SINGLE_STEP` 终止目标（CRITICAL）
4. **`fluctuation_thunk.rs:126-211` — Win64 ABI 栈对齐错误** — `movaps` 触发 #GP，beacon 在第一次睡眠时崩溃（CRITICAL）
5. **`ntalloc.rs:261-280` — 自定义分配器 dealloc UAF** — 对齐指针释放错误地址，堆元数据破坏（CRITICAL）
6. **`blind_hwbp.rs` — `static mut` 全局状态 UB + 锁竞争杀死进程** — VEH 处理器返回 `EXCEPTION_CONTINUE_SEARCH` 致进程终止（CRITICAL ×2）
7. **`beacon.rs:183-294` — kill-date `expires_at` 解析但从未检查** — implant 永不过期（CRITICAL）
8. **`beacon.rs:259-293` — 单个任务 panic 终止整个 beacon**（CRITICAL，架构性）
9. **`deaddrop.rs:119-135` — JSON 解析器 `&&`/`||` 优先级 bug 导致 OOB panic**（CRITICAL）
10. **`selftests.rs:347-378` — 截屏自测堆缓冲区溢出** — 运营 RPC 可触发，8.3MB 写入 1MB 缓冲区（CRITICAL）
11. **`server/lib.rs:998` — `is_loopback_bind` 字符串前缀匹配可绕过自动 token 保护** — 配置错误的 bind 可发布**开放 team server**（HIGH）
12. **`server/kernel.rs:114-226` — 所有特权内核操作（dump_lsass、hide、blind_etw）零审计日志**（HIGH）

### 整体评价

代码库整体工程质量**较高**：
- `#![forbid(unsafe_code)]` 在适当位置（protocol、parse、minidump-assembler）
- SQL 全部使用参数化查询（store crate）
- 审计日志有 SHA-256 链式完整性保护（server）
- 大量防御性编程（`checked_add`、`saturating_sub`、`unwrap_or` 配合 `Option`）
- 脚本无 `Invoke-Expression`/`eval`/`pickle`/`shell=True` 注入面
- CI 有 fmt/clippy/test/release gate

但存在**系统性问题**：
- **panic = abort 下大量 `.unwrap()`/`.expect()`/`assert!()`/`unreachable!()`** — 在 PIC implant 中任何 panic = 进程终止
- **`static mut` 全局状态在 aliasing 模型下是 UB** — 多处（blind_hwbp、mem、screenshot、transport）
- **句柄/内存泄漏在错误路径上普遍** — inject、trex/delivery、screenshot
- **静默失败模式**：NTSTATUS/BOLL 返回值频繁被 `let _ =` 丢弃
- **运营脚本可预测的临时路径** — `$env:TEMP\scan_*`、`C:\nyx\loader_probe_result.txt`

---

## 详细发现（按严重度）

### CRITICAL 发现（27 项）

#### CRYPTO/PROTOCOL（2 项）

**[CRITICAL-1] `config::decrypt` 在 AEAD tag 不匹配时 panic** — `crates/config/src/lib.rs:86-97`
- `cipher.decrypt(...).expect(...)` — 在 `panic="abort"` 下，嵌入配置段一字节损坏即终止 implant 进程
- **修复**: 返回 `Result<Vec<u8>, chacha20poly1305::Error>`

**[CRITICAL-2] `hkdf_sha256` 在调用方控制输出长度时 panic** — `crates/protocol/src/crypto.rs:508-512`
- 公开 API，`okm.len() > 255*32` 即 panic — 任意调用方可致主机终止
- **修复**: 返回 `Result<(), HkdfError>`

#### IMPLANT-WIN SYSCALL/MEM/EVASION CORE（9 项）

**[CRITICAL-3] `fluctuation_thunk` 步骤 1-3 栈对齐错误** — `crates/implant-win/src/fluctuation_thunk.rs:126-211`
- 每步 `sub rsp, 0x20`（8 的偶数倍），但调用入口 RSP ≡ 8 (mod 16)，故 `call` 时 RSP ≡ 8 — 违反 Win64 ABI
- 任何被调用者（NtProtectVirtualMemory/NtDelayExecution）的 `movaps` 触发 #GP/#PF
- 字段崩溃确定性：beacon 第一次睡眠时崩溃，.text 仍为 PAGE_NOACCESS
- **修复**: 步骤 1-3 改为 `sub rsp, 0x28` / `add rsp, 0x28`

**[CRITICAL-4] `NtHeapAllocator` dealloc UAF** — `crates/implant-win/src/ntalloc.rs:261-280, 326-331`
- 对齐 >8 时，仅当 `offset >= 8` 才在 `aligned_addr - 8` 存储 raw 指针
- 但 dealloc 无条件读取 `*(ptr - 8)` 作为 raw
- 当 RtlAllocateHeap 返回已对齐块（align=16，LFH 常见），`offset = 0`，dealloc 读到未初始化字节 → 释放错误地址 → 堆破坏
- **修复**: 无条件在 `aligned_addr - 8` 存储 raw

**[CRITICAL-5] `restore_dr_state` 用 `NtContinue` 可能恢复陈旧 RIP/RSP** — `crates/implant-win/src/fluctuation.rs:181-215, 239-269`
- `save_dr_state` 用 `CONTEXT_FULL_AMD64` (0x10001F) 快照含 RIP/RSP 的完整上下文
- `restore_dr_state` 在此 buffer 上调 `NtContinue`，CONTROL 位被恢复 → RIP 跳回不存在的栈帧 → 进程死亡
- **修复**: 用 `CONTEXT_DEBUG_REGISTERS` (0x100010) 恢复 buffer

**[CRITICAL-6] `blind_hwbp` 的 `static mut` 状态在别名模型下 UB** — `crates/implant-win/src/blind_hwbp.rs:89-92, 99-120`
- `HWBP_ENTRIES`、`HWBP_COUNT`、`VEH_HANDLE`、`SHADOW_BUF` 均为 `static mut`
- 从 add_hwbp/remove_hwbp 修改，从 hwbp_veh_handler 读取 — 无同步
- 编译器可能重排/CSE 读取 → 非确定性崩溃
- **修复**: 改用 `[AtomicPtr<HwbpEntry>; 4]` / 原子计数器

**[CRITICAL-7] VEH 处理器在锁竞争时返回 `EXCEPTION_CONTINUE_SEARCH`** — `crates/implant-win/src/blind_hwbp.rs`
- STATUS_SINGLE_STEP (#DB) 触发时 `try_lock` 失败即返回 SEARCH → OS 终止进程
- APC 可在锁获取/释放间中断；递归异常（shadow stub 自身 fault）死锁
- **修复**: 永不在处理器内失败获锁；改用无锁设计

**[CRITICAL-8] `do_rsp_swap` 泄漏 `f` 且无条件 `assume_init`** — `crates/implant-win/src/stack.rs:295-428`
- `forget(f)` 假设 spoof_trampoline 总 ptr::read f 一次 — 若 asm 触发异常则泄漏
- `MaybeUninit::assume_init()` 无条件 — 若 asm 破坏 `out` 而蹦床未写入，则 UB
- 2KiB FAKE_STACK 太小：128 u64 深度上限，嵌套调用爆栈
- **修复**: 用 AtomicBool SWAP_DONE 跟踪；仅 SWAP_DONE 时 forget/assume_init；增大 cap 到 ≥8KiB

**[CRITICAL-9] `install_ghost_chain` 在未初始化内存上构建 slice** — `crates/implant-win/src/lacuna_stomp.rs:43-53`
- `Vec::with_capacity(len)` → `as_ptr() as *mut usize` → `forget(v)` → `from_raw_parts_mut(ptr, len)` → `copy_from_slice`
- `with_capacity` 的槽是未初始化的；`from_raw_parts_mut` 重解释为已初始化
- OOM 时返回零 cap Vec，`as_ptr()` 悬垂 → `from_raw_parts_mut` on dangling = 即时 UB
- **修复**: `extend_from_slice` 后再取指针；检查 `v.capacity() >= len`

**[CRITICAL-10] `Layout::from_size_align(...).unwrap()` 在全局分配器热路径** — `crates/implant-win/src/ntalloc.rs:341, 369`
- realloc 调用，任何畸形 Layout 致 abort
- `new_size` 受 beacon 任务大小影响
- **修复**: `match ... { Ok => alloc, Err => null_mut() }`

**[CRITICAL-11] 整数溢出：`size + align` 和 `frames_len * 8`** — `ntalloc.rs:261`, `lacuna_stomp.rs:98`
- `size + align` 接近 `usize::MAX` 时环绕 → 小 buffer → 堆溢出（教科书式）
- `frames_len * 8` 环绕 → RSP 破坏
- **修复**: `checked_add`/编译期 cap

#### IMPLANT-WIN COLLECTION（2 项）

**[CRITICAL-12] `keylog` `BUF`/`BUF_LEN` 数据竞争** — `crates/implant-win/src/keylog.rs:593-603, 744-757, 769-829`
- hook 线程（`buf_push_release`）和轮询路径（`buf_push`）无互斥写 `static mut BUF`
- 轮询门是 `hook_is_active()`（Acquire），但 `HOOK_THREAD_LIVE` 在 `CreateThread` 返回后才置 true
- 在 Rust 内存模型下是 UB
- **修复**: hook 线程自身在 SetWindowsHookExW 后置 `HOOK_THREAD_LIVE`；或统一单一写者

**[CRITICAL-13] 截屏窗口站句柄泄漏 + UAF** — `crates/implant-win/src/screenshot.rs:329-420, 426-455`
- `attach_interactive` 用进程级 `static mut` 存原始/打开的 winsta 句柄
- 重入时第二次调用覆盖 `CAPTURE_WINSTA_ORIGINAL` 为已切换的 WinSta0 → detach 恢复错误 + 关闭借用的 pseudo-handle
- MSDN: GetProcessWindowStation 的返回值不可关闭
- **修复**: 用局部变量传递句柄

#### IMPLANT-WIN INJECTION/EXECUTION（4 项）

**[CRITICAL-14] `inject_existing` 传 `None` 作为 `lpStartAddress`** — `crates/implant-win/src/inject.rs:1014-1024`
- shellcode 基地址放在 `lpParameter` 槽，`lpStartAddress` = NULL
- 内核拒绝 NULL 起始地址 → 主注入路径**永远不工作**
- 运营依赖此路径会得到误导性 "CreateRemoteThread failed" 错误
- **修复**: `Some(transmute(remote_base))` 作为第 4 参，`null_mut()` 作为第 5 参

**[CRITICAL-15] 模块覆写 `WriteProcessMemory` 写入 `shellcode.len()` 字节到 `min(vsize, 0x2000)` 区域** — `crates/implant-win/src/inject.rs:215`
- 无 `shellcode.len() <= text.len` 检查
- 任何 >8KiB 的 shellcode 覆写到 .rdata/.data → 傀儡进程崩溃
- **修复**: 写前检查 `if shellcode.len() > text.len { return Err }`

**[CRITICAL-16] 无 VEH 的线程硬件断点注入** — `crates/implant-win/src/inject.rs:719-726`
- DR0 = sc_addr, DR7 = 0x1（启用本地**执行**断点），RIP = sc_addr
- 执行断点在指令**前**陷阱 → 第一条指令即触发 EXCEPTION_SINGLE_STEP
- 无 VEH → 进程终止
- **修复**: 实现 full threadless-inject 模式（trigger 在热 API，VEH 重定向）

**[CRITICAL-17] BOF entry 符号查无边界检查** — `crates/implant-win/src/bof.rs:1014-1017`
- `defined` 循环检查 `<= bases.len()`，但 `go` entry 路径只检查 `< 1`
- `section_number = 32767` 通过 `< 1` 检查，索引 panic → abort
- 操作员控制的字节（团队服务器 BOF）可致 beacon 死亡
- **修复**: 镜像 `defined` 循环的守卫

#### IMPLANT-WIN BEACON/TREX（3 项）

**[CRITICAL-18] Kill-date `expires_at` 解析但从未检查** — `crates/implant-win/src/beacon.rs:183-294`
- `config_placeholder.rs:183` 解码 `expires_at`，`beacon_loop` 绑定 `implant`，但 `implant.expires_at` 之后零引用
- 无 `if now > implant.expires_at { return; }` 任何地方
- **影响**: implant 永不过期，运营时间盒安全控制失效
- **修复**: 每周期顶部比较 `hostinfo::now() >= implant.expires_at`，返回或自毁

**[CRITICAL-19] 单个 panic 任务终止整个 beacon（无任务隔离）** — `crates/implant-win/src/beacon.rs:259-293`
- `execute(rt, t.command, ...)` 内联调用，`panic="abort"` 下任何 panic 终止进程
- 无 `catch_unwind`（且 abort 下无法工作）
- `Command::Bof` → 任意目标文件，`Command::Inject` → 运营 shellcode，`Command::Trex` → FFI 到 SCM/WMI/registry
- **修复**: 架构性 — 每个 command 路径 panic-free by construction；或将高风险任务 spawn 到牺牲子进程

**[CRITICAL-20] `json_extract_str` OOB panic** — `crates/implant-win/src/trex/exfil/deaddrop.rs:119-135`
- `&&` 优先级高于 `||`，故 `i < len && json[i] == ' ' || json[i] == '"'` 在 `i >= len` 时仍索引
- 行 122 `i += 1` 无边界检查
- 截断/短 GitHub 响应（网络抖动、代理注入、401/403 body）可触发 → abort
- **修复**: `while i < len && (json[i] == ' ' || json[i] == '"') { i += 1; }`；守卫 `i += 1`

#### IMPLANT-WIN ENTRY/SELFTESTS（1 项）

**[CRITICAL-21] 截屏自测堆缓冲区溢出** — `crates/implant-win/src/selftests.rs:347-378`
- `need = w*h*4`；`pixels = vec![0u8; need.min(1<<20)]`（1MiB cap）
- `GetDIBits(..., h, pixels.as_mut_ptr(), ...)` 写 `w*h*4` 字节到 `min(need, 1<<20)` 缓冲区
- 任何 >512×512 屏幕（所有真实屏幕）→ NT 堆元数据覆盖
- 运营 RPC `run nyx_selftest_screenshot_diag` → implant 死亡或更糟
- **修复**: 分配 `need` 字节（无 `.min(1<<20)`），或 `iLines = (1<<20 / 4 / w).min(h)`

#### TRANSPORT/REST（3 项）

**[CRITICAL-22] Slack 频道未鉴权 C2 帧注入** — `crates/transport/src/slack_api.rs:192-208`
- `poll_history` 解码频道中第一条非 bot 消息为 C2 帧
- 发送方验证仅 "user_id != our bot_user_id"
- 任何人类成员、其他 bot、workspace admin 可发 base64 blob → 注入 implant 任务帧
- **修复**: 要求每消息 HMAC/MAC，或 pin 单一允许发送者

**[CRITICAL-23] MCP/LLM `extract_hex` 启发式帧注入** — `crates/transport/src/mcp.rs:190-215`, `llm_api.rs:139-164`
- 两条 recv 路径从第三方文本提取"最长 ≥8 hex 数字"，hex 解码为 C2 帧
- 任何影响 Claude/MCP 输出的方（prompt 注入、被攻陷的 MCP 工具、MITM）可选择 implant 接受的命令字节
- 无完整性检查、无长度/MAC 帧
- **修复**: hex blob 内帧化：长度前缀 + HMAC（session_key 键控），验证 tag 前拒绝解码

**[CRITICAL-24] XOR "混淆"作为 C2 帧机密性层** — `crates/transport/src/llm_api.rs:80-85, 190-225`
- 帧对静态 32 字节 `session_key`（字节索引循环）XOR
- 无 nonce、无认证
- 模块文档自承"任何恢复已知明文帧者可解密所有后续流量"
- 已知明文（C2 帧字节高度可预测）→ XOR-of-ciphertexts = XOR-of-plaintexts
- **修复**: 移除 XOR 层（让协议 AEAD 做机密性），或换正式 AEAD

#### TOOLS（4 项）

**[CRITICAL-25] sRDI 导出表遍历无边界检查 OOB 读** — `tools/srdi/src/main.rs:335-395`
- `resolve_export_rva()` 读 `pe[exp_file + 0x18..0x28]`，循环中 `pe[names_file + i*4..+4]`、`pe[ordinals_file + i*2..+2]`、`pe[funcs_file + ordinal*4..+4]` 全无 `pe.len()` 检查
- `ordinal` 是文件读出的 u16，可达 65535 → ~262KB 越界
- `num_names` 是文件 u32，无上界
- **影响**: 畸形/恶意 PE → panic 或内存泄漏到 emitted `.bin` → 注入时崩溃/RCE
- **修复**: 每次读前守卫；cap `num_names` 在合理上限

**[CRITICAL-26] sRDI `rva_to_off` 信任攻击者控制的 `VirtualSize`** — `tools/srdi/src/main.rs:401-415`
- 返回 `raw_ptr + (rva - v_addr)` 无 `pe.len()` 检查
- **修复**: 加 `max_read` 上界检查

**[CRITICAL-27] sRDI 输出缓冲区大小无溢出检查** — `tools/srdi/src/main.rs:123, 173, 198`
- `text.len() as u32` 静默截断 >4GiB 文件
- 头部谎报长度 → 加载器读越界/执行未初始化内存
- **修复**: `if text.len() > u32::MAX { return Err }`

**[CRITICAL-28] `EnableDebug.cs` `cmd /c` 参数注入** — `scripts/EnableDebug.cs:42-55`
- `app = args[0]`（未引用）；内参仅 bare `"..."` 包装，无 `"`/`%`/`&`/`|` 转义
- 任何含 `& calc.exe &` 的路径 → calc 作为 SYSTEM 执行（schtasks /RU SYSTEM）
- **修复**: 移除 `cmd /c` shim；用 `ProcessStartInfo.ArgumentList`

---

### HIGH 发现（46 项）

#### CRYPTO/PROTOCOL（3 项）

- **`seal_dir`/`encrypt` `.expect()` on AEAD encrypt** — `crypto.rs:422-430`, `config/lib.rs:70-78`：团队服务器单次密封失败即终止整个进程
- **`Task::encode_vec` 静默截断 >256 任务批次** — `msg.rs:683-690`：运营排队 >256 任务时 257+ 被丢弃且 `Ok` 返回
- **`from_secret_bytes` 跳过全零标量拒绝** — `crypto.rs:259-264, 309-314`：持久化路径绕过 `reject_zero`，全零密钥导出确定性共享密钥

#### TRANSPORT/REST（5 项）

- **SMB pipe `recv` 不遵守 `timeout_ms`** — `smb_pipe.rs:279-311`：同步 `ReadFile` 无限阻塞，死信管道楔住中继线程
- **`smb_pipe.rs` 5 个 `unsafe` 块无 `// SAFETY:` 论证** — `228, 235-245, 264-273, 287-295, 319-321`
- **SSRF：传输 URL 构造器无 allowlist** — `llm_api.rs:59,72`, `mcp.rs:81`, `doh_dns.rs:94`, `malleable.rs:101`：潜在 SSRF（操作员配置流可致）
- **REST 客户端 `authed()` 无 token 时 fail-open** — `rest/lib.rs:124-129`：返回请求不变，无警告
- **`sniff_client_hello` 静默吞头读错误** — `tls.rs:350-354`：错误时返回零填充 5 字节伪装 TLS 记录

#### SERVER（7 项）

- **`is_loopback_bind` 字符串前缀匹配可绕过** — `lib.rs:998`：`localhost.localdomain`、`::1:8443`、`::ffff:127.0.0.1` 等未识别 → 跳过自动 token → **开放 team server**
- **kernel.rs 6 个特权处理零审计日志** — `kernel.rs:114-226`：`dump_lsass`、`hide`、`blind_etw`、`neutralize`、`detach_minifilter` 无 `audit.append`
- **会话一次性 token TOCTOU** — `lib.rs:1175-1352`：`mark_token_used` 在 entry insert 前提交，并发 check-in 可注册双会话
- **`verify_audit` 仅阻 Viewer** — `lib.rs:2247`：Operator 可无限制触发 1M 行 SHA-256 扫描（DoS）
- **`get_audit` 全局 seq 泄漏** — `audit.rs:120`：非 admin 运营可推断系统总活动量
- **`generate_implant` `expires` 解析失败静默默认永不过期** — `implant_gen.rs:456-465`：ISO 8601 字符串 `s.parse::<i64>()` 失败 → `unwrap_or(0)` → 永生
- **只读端点零审计** — `list_creds`、`list_sessions`、`list_implants`、`get_tasks`、`get_audit`：凭据列表/implant 蓝图无审计记录

#### STORE（2 项）

- **原始一次性 auth token 明文持久化在 `sessions.auth_token`** — `session_store.rs:60, 111, 170-194`：磁盘镜像恢复每个历史 bootstrap token
- **一次性 token 消费非原子** — `implant_store.rs:188-216`：`get_by_token_hash` 和 `mark_token_used` 两调用，锁不跨越 get→mark 窗口

#### IMPLANT-WIN SYSCALL/MEM/EVASION（9 项）

- **PEB 走链中无界 C 字符串读** — `resolve.rs`：畸形 PE（hooked ntdll）让扫描跑出映射镜像
- **`proxy_veh` `NtProtectVirtualMemory` restore NTSTATUS 静默忽略** — `proxy_veh.rs:449-455`：失败时 code cave 留 RW，VEH 指针指向非可执行 → #PF
- **`MaskGuard` Drop 在 panic=abort 下不可达** — `fluctuation.rs:42-70`：早期返回路径留下 RC4 加密区域
- **`caller_spoof` 扫描 cap 1MiB 太小** — `caller_spoof.rs:128`：Win11 23H2/24H2 ntdll .text ~1.6-2.0MiB → 静默降级
- **`unhook` 磁盘 ntdll 回退无签名/路径验证** — `unhook.rs`：defender 控制的替代 + `SystemRoot` env 可致 SSN 篡改 → BSOD
- **`cfg_user` `NtSetInformationVirtualMemory` NTSTATUS 忽略** — `cfg_user.rs`：CFG 违反 FastFail 即终止
- **`sleep` `own_text_region` PEB 走链对反射注入失败** — `sleep.rs`：无 LDR entry 时返回 None 或错误 base → 翻转错误页 → 主机崩溃
- **`hookchain` IAT 重定向不验证解析的 export RVA** — `hookchain.rs`：forwarder 字符串误当指针 → #UD
- **`stack.rs` / `mem.rs` 多处 `static mut` 全局状态**：`MASK_KEY_BUF`、`BLIND_ERR` torn write

#### IMPLANT-WIN COLLECTION（8 项）

- **`hashdump` `stream_file` nosync 探测与同步重开 TOCTOU** — `hashdump.rs:51-95`：探测确认安全后同步重开仍可挂
- **`fs.rs` `allowed()` 路径遍历守卫漏 `\config\RegBack\*`** — `fs.rs:201-298`：RegBack SAM 可恢复哈希未阻
- **`recon.rs` `probe_one` 忽略 `ioctlsocket` 失败** — `recon.rs:482-534`：socket 留阻塞，`connect` 阻塞 21s × 65535 端口 = 16 天 beacon 黑屏
- **`postex.rs` `steal_token` 无 PID 验证** — `postex.rs:174-246`：`OpenProcess` on operator-supplied PID 无范围检查
- **`postex.rs` `make_token` 截断时无 NUL 终止** — `postex.rs:341-353`：`LogonUserW` 读过缓冲区
- **`shell.rs` 命令行拼接无引用 + `lpApplicationName = NULL`** — `shell.rs:194-204`：PATH 解析 cmd.exe，操作员输入未引用
- **`keylog.rs` hook 线程在 `HOOK_THREAD_LIVE` 发布前安装 hook** — `keylog.rs:873-891`：与 CRITICAL-12 同数据竞争
- **`screenshot.rs` `cross_session_capture` 固定路径 `C:\Windows\Temp\~dfftmp.bmp`** — `screenshot.rs:985, 1149-1156`：TOCTOU + 可预测 IOC

#### IMPLANT-WIN INJECTION（8 项）

- **`nt_suspend_thread` 返回值静默丢弃** — `inject.rs:696`：suspend 失败仍读写 CONTEXT，陈旧竞争
- **`inject_existing`/`threadless_inject` 失败路径泄漏 RWX 页** — `inject.rs:991-1011`：Moneta/PE-sieve 检测，每次失败累积
- **`stomp_and_resume` VirtualProtectEx→RX 失败时留 RWX 且静默吞错** — `inject.rs:217-219`：比原始 RX 更可疑
- **`do_inject` 不验证 `pid`** — `inject.rs:776-863`：可目标 self/0/4/lsass/csrss → 蓝屏
- **`module_stomp` gate OFF 时泄漏两进程句柄** — `inject.rs:165-181`：操作员关 stomp 时每次注入泄漏 2 HANDLE
- **TCP channel `connect` 无超时** — `channels/tcp.rs:328-345`：21s TCP RTO 楔住 beacon
- **SMB channel `ReadFile`/`WriteFile` 同步无超时** — `channels/smb.rs:259-317`：管道服务器挂楔住 beacon
- **`Channel::from_wire_u8` 值 2/3/4 歧义** — `channels/mod.rs:98-120`：新协议服务器选 SmbPipe 实际选 LlmApi

#### IMPLANT-WIN BEACON/TREX（2 项）

- **`Command::Sleep` 忽略 `jitter_pct`** — `beacon.rs:535-547`：运营重任务抖动被静默丢弃
- **dead-drop 上传静默截断 >12KiB 载荷** — `trex/exfil/deaddrop.rs:154-163`：截断 AEAD blob tag 不匹配但返回 `Ok`

#### IMPLANT-WIN ENTRY/SELFTESTS（5 项）

- **`option_env!("NYX_SPOOF_OFF")` 编译期读，运营逃生舱不工作** — `entry.rs:133-140`
- **`nyx_selftest_inject_armed` 泄漏挂起 notepad** — `selftests.rs:1248-1258`：每次调用累积一个挂起进程
- **`set_modulestomp_enabled` 恢复硬编码 false 而非先前值** — `selftests.rs:1222, 1270`：自测后 beacon 静默降级
- **`nyx_selftest_screenshot_diag` `.unwrap_or(0)` → `transmute` → call 无 null 检查** — `selftests.rs:273-360`：8 个 GDI 导出
- **`nyx_selftest_mem` 变异 live beacon 内存区域** — `selftests.rs:2490-2510`：mask/unmask 序列在 RPC 触发时破坏 live 状态

#### KERNEL SDK（4 项）

- **`persistence.rs` `RuntimePgBypassWindow` 自引用裸指针** — `persistence.rs:463`：仅在 PgGuard<'a> 生命周期巧合下 sound
- **`etwti.rs` `for_build(17763)` 静默返回 patched UBR offset** — `etwti.rs:124-156`：RTM Server 2019 错误内核写
- **BYOVD Iqvw64e/RtCore64 `raw_rw` 传裸用户指针到内核驱动** — `byovd.rs:166/315`：竞态 VirtualFree → BSOD
- **`nyx-mutate` `randomize_keys` 静默截断 >65535 密钥的恢复 tail** — `lib.rs:447-457`：implant 无法 un-XOR 截断条目

#### TOOLS/SCRIPTS（7 项）

- **`deploy_detectors.ps1` 无校验和下载扫描器 EXE** — `:23-101`：供应链风险 + 临时目录可预测
- **6 个扫描脚本 `$env:TEMP\scan_*` 可预测可写路径** — `pesieve_scan.ps1` 等：TOCTOU + 符号链接
- **`EnableSeDebugPrivilege` 启用从不撤销** — `EnableDebug.cs:33`：最高危权限持久持有
- **`C:\nyx\loader_probe_result.txt` 世界可读 + TOCTOU** — `loader_probe.ps1:62`：攻击者可交换文件伪造 OK，release gate PASS 谎报
- **`setup_release_env.ps1` 关闭 Defender MAPS + 广泛 ExclusionPath** — `:151-176`：可检测 IOC
- **`release/wrap_blob.ps1` 仅大小健全性检查 + TOCTOU** — `:87-100`：可替换的 release 工件
- **`EnableDebug.cs` STARTUPINFO `cb` 未设** — `:21-24`：死 P/Invoke 路径错误

---

## 系统性问题（跨文件模式）

### 1. `panic = "abort"` + `.unwrap()`/`.expect()`/`assert!()`/`unreachable!()`

**位置**: 全库 ~30+ 处

PIC implant 设置 `panic = "abort"`（`Cargo.toml:67,73`），任何 panic = 进程终止。但代码中大量使用：
- `crypto.rs:422` `cipher.encrypt(...).expect("AEAD encrypt only fails on alloc failure")` — 团队服务器 OOM 即死
- `config/lib.rs:86` `cipher.decrypt(...).expect(...)` — 配置段一字节损坏即死
- `frame.rs:53` `assert!(!plaintext.is_empty(), ...)` — 运营 bug 致死
- `bof.rs:1014` `bases[(entry_sym.section_number - 1) as usize]` — 畸形 BOF 致死
- `ntalloc.rs:341` `Layout::from_size_align(...).unwrap()` — 分配器热路径
- `coff/lib.rs:393` `unreachable!()` — 畸形重定位致死

**建议**: 全库审计所有 panic 站点；可恢复错误返回 `Result`；`unreachable!()` 改 `return Err`。

### 2. `static mut` 全局状态在别名模型下 UB

**位置**: `blind_hwbp.rs`、`mem.rs`、`screenshot.rs`、`transport.rs`、`keylog.rs` 等

Edition 2024 起 `static_mut_refs` lint；当前 `static mut` 变异在 Rust 内存模型下是 UB，即使单线程。

**建议**: 改 `AtomicPtr` / `Mutex` / `OnceCell`。

### 3. 句柄/内存泄漏在错误路径

**位置**: `inject.rs`、`trex/delivery.rs`、`screenshot.rs`、`kits.rs`

OpenProcess/OpenThread/VirtualAllocEx/CreateRemoteThread 创建的 HANDLE/分配在错误路径未关闭/释放。每次失败累积。注入尤其严重：失败后留下私有 RWX 未支持页 = 最响亮的 EDR IOC。

**建议**: 用 RAII 包装（`Drop`）；或确保每个错误路径显式清理。

### 4. 静默失败：`let _ =` 丢弃 `Result`

**位置**: `proxy_veh.rs:449`、`inject.rs:217, 349`、`cfg_user.rs`、`unhook.rs`、`netsec.rs`

NTSTATUS/BOOL 返回值频繁 `let _ =` 丢弃。规避原语静默失败，implant 误以为已安装。

**建议**: 全库 `let _ =` 审计；evasion 原语失败必须记录到 diag buffer。

### 5. 运营脚本可预测临时路径

**位置**: `$env:TEMP\scan_*`、`C:\nyx\loader_probe_result.txt`、`C:\Windows\Temp\~dfftmp.bmp`、`C:\Windows\Temp\nyx_freeze_<pid>.dmp`

可预测 + 世界可写 = TOCTOU + 符号链接攻击面。release gate 的 `loader_probe_result.txt` 尤其危险（PASS 谎报发布 broken payload）。

**建议**: 用 GUID/随机后缀；限制 DACL；release gate 用 hash 验证。

### 6. 无栈隔离的 BOF/Inject 任务

beacon 循环内联执行 `Command::Bof`/`Command::Inject`，任何 panic 终止整个 beacon。CS 等同类工具将高风险任务 spawn 到牺牲子进程。

**建议**: 架构性改造 — BOF/Inject spawn 到牺牲进程，beacon 主循环仅观察退出码。

---

## 干净区域（已审计无发现）

- **`crates/parse/src/lib.rs`** — `#![forbid(unsafe_code)]`，所有解析器对畸形输入 best-effort skip，无 `.unwrap()` 攻击者数据
- **`crates/protocol/src/wire.rs`** — blob cap 对称强制，`take` 边界检查
- **`crates/protocol/src/lib.rs`** — 仅 re-export
- **`crates/minidump-assembler/src/lib.rs`** — `#![deny(unsafe_code)]`，正确 data_size/base_rva 分割，单范围 API 边界由构造保证
- **`crates/evasion/src/syscalls.rs`** — `checked_mul`/`checked_add` 在 STRIDE 走链
- **`crates/implant-evasionsdk/src/rc4.rs`** — KAT 验证
- **`crates/operator-kernelsdk/src/pagewalk.rs`** — `checked_add` 守卫存在
- **`crates/operator-kernelsdk/src/pattern_scan.rs`** — wildcard Option<u8>，abs+1 循环推进
- **`crates/server/src/operators.rs` constant_time_eq** — 用 `subtle::ConstantTimeEq`，正确
- **`crates/server/src/audit.rs`** — JSONL + 长度前缀哈希输入，防伪刻闭环
- **`crates/profile/src/parser.rs`** — 递归 cap 64，`checked_add(1)` 守卫 u32 溢出，无 panic
- **Bash 脚本** — 一致 `set -euo pipefail`，无 `eval`/`curl|sh`/`set -x` 泄漏
- **PowerShell release 脚本** — EAP relax/restore 模式正确，list-form 原生调用

---

## 推荐修复优先级

### P0 — 阻塞实战部署（CRITICAL，27 项）

修复顺序建议：
1. 注入路径（CRITICAL-14/15/16）— 否则主功能不工作或崩目标
2. fluctuation_thunk 栈对齐（CRITICAL-3）— 否则 beacon 第一次睡眠崩溃
3. ntalloc dealloc UAF（CRITICAL-4）— 否则堆破坏随机崩溃
4. blind_hwbp UB + 锁竞争（CRITICAL-6/7）— 否则 HWBP 路径进程死
5. kill-date 未强制（CRITICAL-18）— 否则 implant 永生
6. 自测堆溢出（CRITICAL-21）— 移除或 gate 在生产外
7. sRDI OOB（CRITICAL-25/26/27）— 畸形输入致 RCE
8. EnableDebug cmd 注入（CRITICAL-28）
9. Slack/MCP/LLM C2 帧注入（CRITICAL-22/23/24）
10. beacon 任务隔离（CRITICAL-19）— 架构性

### P1 — 强烈建议（HIGH，46 项）

服务器端：`is_loopback_bind` 解析化、kernel 审计日志、token 原子消费、`expires` ISO 解析
Implant：句柄/内存泄漏清理、ioctlsocket 失败处理、PATH 绝对化 cmd.exe、PID 验证
持久化：auth token 哈希存储、WAL 文件权限、secure_delete

### P2 — 健壮性（MEDIUM/LOW）

panic 站点清理、`static mut` 现代化、SSRF allowlist、Rhai 错误日志、临时路径随机化

---

## 审计覆盖确认

| Agent | 范围 | 文件数 | 状态 |
|-------|------|--------|------|
| A | protocol/config/parse crypto | 8 | ✅ |
| B | transport/rest 网络 | 13 | ✅ |
| C | server team server | 8 | ✅ |
| D | store/profile 持久化 | 13 | ✅ |
| E | implant syscall/mem/evasion | 21 | ✅ |
| F | implant 采集 | 14 | ✅ |
| G | implant 注入/执行 | 5 | ✅ |
| H | implant transport/beacon/trex | 13 | ✅ |
| I | implant entry/config/selftests | 6 | ✅ |
| J | loader/coff/bof/minidump | 13 | ✅ |
| K | kernel SDK/scripting/agent-dev | 38 | ✅ |
| L | tools + 脚本 | 33 | ✅ |

**全量覆盖**: 23 个 Rust crate（~78,849 LOC）+ 2 个工具（~843 LOC）+ ~40 个脚本（~2,500 LOC）逐行审计完成。

---

## 附录：运营 IOC（防御方检测线索）

审计期间识别的 Nyx 工具链指纹：
- **计划任务**: `nyx_server`、`nyx_agentN`、`nyx_selftest`
- **文件路径**: `C:\nyx\nyx_implant_win.dll`、`C:\nyx\loader_probe_result.txt`、`C:\nyx\selftest_results.csv`、`C:\nyx\trex_report.txt`、`C:\Windows\Temp\~dfftmp.bmp`、`C:\Windows\Temp\nyx_freeze_*.dmp`
- **Defender 姿态**: `MAPSReporting=0` + `SubmitSamplesConsent=2` + `ExclusionPath` 含 `C:\nyx`、`C:\actions-runner\_work\NY\NY` + `ExclusionProcess` 含 `cargo.exe`/`rustc.exe`
- **网络**: 端口 8443/18455、Slack/MCP/LLM API 作为 C2 传输、GitHub Gist 作为 dead-drop
- **TLS**: 无 SPKI pinning，企业 TLS 检查设备可静默拦截 C2
- **HTTP**: User-Agent `git/2.45.0`（dead-drop）、`Mozilla/5.0`（fallback）

---

*报告由 12 个并行 ZCode 子 agent 生成，主 agent 聚合。每条发现含文件:行号、代码证据、修复建议。*
