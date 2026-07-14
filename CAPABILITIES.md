# Nyx C2 框架 — 功能清单（基于实际代码）

> 本文档描述截至 2026-07-14 `main` 分支代码中**实际已实现**的功能。
> 所有标注"桩"/"门控关闭"的功能在代码中有明确的状态标记，不会误导操作员。

---

## 目录

1. [架构概述](#1-架构概述)
2. [Team Server（团队服务器）](#2-team-server团队服务器)
3. [Implant（植入体 / Beacon）](#3-implant植入体--beacon)
4. [Client CLI（操作员客户端）](#4-client-cli操作员客户端)
5. [Transport（传输层）](#5-transport传输层)
6. [Kernel SDK（内核 SDK）](#6-kernel-sdk内核-sdk)
7. [Evasion（规避层）](#7-evasion规避层)
8. [Wire Protocol（线协议）](#8-wire-protocol线协议)
9. [配置参考](#9-配置参考)

---

## 1. 架构概述

```
┌──────────────┐     ECDH+AEAD      ┌──────────────┐
│  Implant     │ ◄─── encrypted ──► │  Team Server │
│  (Windows    │     beacon frames  │  (Rust/axum) │
│   PIC DLL)   │                    │              │
└──────────────┘                    └──────┬───────┘
      │                                     │ REST API
      │ 7 transport channels                │ (JSON, bearer auth)
      │ (HTTPS/DoH/Slack/                   │
      │  LLM/MCP/Malleable/SMB)             │
      │                            ┌────────┴────────┐
      └── Indirect syscalls        │  Client CLI     │
          PEB-walk resolve         │  (TUI + SOCKS)  │
          no IAT, no_std           └─────────────────┘
```

- **Implant**: `#![no_std]` + `#![no_main]` PIC DLL，x86_64-pc-windows-gnu，nightly 编译
- **Team Server**: Rust + axum + rustls + SQLite，环境变量配置（无 CLI 参数）
- **Client CLI**: Rust + ratatui TUI + reqwest，60+ 交互命令
- **Kernel SDK**: 操作员侧 ring-0 工具包（implant 不直接使用），需独立 kernel daemon

---

## 2. Team Server（团队服务器）

### 2.1 HTTP 路由

**Beacon 信道**（无认证，加密门控，512 KiB body 上限）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/beacon` | 默认 beacon 端点 |
| GET/POST | `<profile URI>` | 从 Malleable C2 profile 动态注册的 URI |

**控制 API**（操作员认证，4 MiB body 上限）：

| 方法 | 路径 | 角色要求 | 说明 |
|---|---|---|---|
| GET | `/api/sessions` | 任意 | 列出已注册 beacon（含 JA3/JA4） |
| POST | `/api/task` | 非 Viewer | 向 session 派发任务 |
| GET | `/api/tasks?session=` | 任意 | 查看 session 待处理任务 |
| GET | `/api/results?session=` | 非 Viewer | **排空式**拉取任务结果 |
| GET | `/api/profile` | 任意 | 当前 Malleable C2 profile 摘要 |
| GET | `/api/creds` | 任意（Viewer 不可 reveal） | 凭据库 |
| POST | `/api/creds` | 非 Viewer | 添加/更新凭据 |
| POST | `/api/creds/delete` | 非 Viewer | 删除凭据 |
| GET | `/api/audit` | 任意（非 Admin 仅自己） | 审计日志查询 |
| GET | `/api/audit/verify` | 非 Viewer | 审计哈希链验证 |
| POST | `/api/generate-implant` | 认证 | 生成 per-implant 二进制 |
| GET | `/api/implants` | 认证 | 列出已生成的 implant |
| POST | `/api/implant/revoke` | 认证 | 吊销 implant |

**Kernel daemon 桥接**（仅 `NYX_KERNEL_DAEMON` 设置时挂载，Admin 专属）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/kernel/status` | 驱动状态 |
| POST | `/api/kernel/blind-etw` | 内核 ETW-TI 致盲 |
| POST | `/api/kernel/hide?pid=` | DKOM 进程隐藏 |
| POST | `/api/kernel/dump-lsass?pid=` | 内核 LSASS dump |
| POST | `/api/kernel/neutralize?pid=&method=` | EDR 中和（kill/freeze/choke） |
| POST | `/api/kernel/detach-minifilter` | 卸载 EDR minifilter |

### 2.2 操作员认证模型

**三种角色**：
- **Admin** — 完全访问（含 kernel 路由 + 全部审计日志）
- **Operator** — 可派发任务、拉取结果、管理凭据
- **Viewer** — 只读（不可派发/拉取结果/添加凭据/reveal 密钥）

**认证优先级**：
1. 非空操作员注册表 → Bearer token 必须为 `name:secret`（每操作员独立 argon2 验证）
2. 空注册表 + `NYX_TOKEN` → 共享 legacy token，身份 `_legacy`，Admin
3. 空 → 开放模式，身份 `_anonymous`，Admin

**安全特性**：
- Argon2 密码哈希 + constant-time SHA-256 比较（legacy）
- 用户名枚举 timing oracle 已修复（dummy argon2 KDF 等时化）
- `ct_eq` 长度 oracle 已修复（先检查长度再做 constant-time 比较）
- Poisoned mutex fail-closed
- 原子写入（temp + rename, 0600）

### 2.3 审计系统

- **格式**：JSON-lines，同步追加，flush-per-record，0600
- **哈希链**：`SHA-256(len-prefix(seq, ts, operator, action, target, detail_json, prev_hash))`
- **链断裂检测**：`GET /api/audit/verify` 返回第一个被篡改的 seq
- **重启恢复**：启动时从现有日志恢复 seq + last_hash
- **OOM 防护**：newest-first 方向使用 VecDeque 环形缓冲（cap 5000）
- **审计动作**：task / cred_add / cred_delete / implant_generated / implant_revoked

### 2.4 Implant 生成

`POST /api/generate-implant` 接受以下参数：

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `callback` | String | （必填） | 回连主机 |
| `port` | u16 | 8443 | 回连端口 |
| `format` | String | `"dll"` | `dll` / `shellcode` / `exe` |
| `uri` | String | `/beacon` | Beacon URI |
| `sleep` | u32 | 60 | Beacon 间隔（秒） |
| `jitter` | u8 | 20 | 0-100% |
| `tls` | bool | true | 使用 TLS |
| `features` | u32 | 0 | 功能位图（bit 30 = 二进制变异） |
| `expires` | Option\<String\> | None | ISO 8601 过期时间 |

**生成流程**：
1. 速率限制：10 次/小时 per (callback, port)
2. 生成随机 key_seed（32B）+ auth_token（32B 一次性）+ config_nonce（12B）
3. HKDF 派生 implant_priv → X25519 公钥 → ECDH config_key
4. ChaCha20-Poly1305 加密配置
5. Patch `.nyx_cfg` section：`0xDEADBEEF` magic + XOR 掩码私钥 + server_pub + 密文
6. 可选二进制变异（NOP 插入、寄存器旋转、密钥随机化）
7. SHA-256 记录到 DB + 审计日志

**Token 验证**：首次 check-in 的 auth_token SHA-256 查 DB（必须未使用 + 未吊销），fail-closed。

### 2.5 数据库（SQLite WAL）

**`creds` 表**：PK = (realm, user, kind)

| 列 | 类型 | 说明 |
|---|---|---|
| realm | TEXT | 域 |
| user | TEXT | 用户名 |
| kind | TEXT | `hash` / `password` / `ticket` / `key` |
| secret | TEXT | 明文 |
| source | TEXT | 来源 |
| beacon | TEXT | 关联 beacon |
| collected_at | INTEGER | 采集时间戳 |
| notes | TEXT | 备注 |

**`implants` 表**：

| 列 | 类型 | 说明 |
|---|---|---|
| id | INTEGER PK | 自增 |
| implant_pub | TEXT UNIQUE | X25519 公钥 hex |
| auth_token_hash | TEXT | SHA-256(auth_token) |
| auth_token_used | INTEGER | 0/1 |
| created_at | TEXT | ISO 8601 |
| callback_host | TEXT | 回连主机 |
| callback_port | INTEGER | 回连端口 |
| format | TEXT | dll/shellcode/exe |
| sha256 | TEXT | 二进制哈希 |
| revoked | INTEGER | 0/1 |

### 2.6 Session 管理

- Session 键 = 32 字节 implant 临时公钥
- 内存中 DashMap，不持久化
- **C→S 反重放**：write guard 内 `counter <= last_recv` 检查（关闭 TOCTOU）
- **S→C 反重放**：implant 端跟踪 `last_server_counter`（审计修复后新增）
- GC：每 60 秒，按 max_age（默认 7 天）/ max_idle（默认 24h）驱逐
- Fingerprint GC：每 60 秒，驱逐 >60s 的 TLS 指纹缓存（防 DoS）
- 并发 check-in 竞态已修复（仅 winner 发 `SessionNew`）
- Check-in 重试上限：5 次（防协议失步死循环）

---

## 3. Implant（植入体 / Beacon）

### 3.1 全部 28 个命令的实现状态

| # | 命令 | 状态 | 说明 |
|---|---|---|---|
| 1 | `Ping` | ✅ 完整 | 心跳 |
| 2 | `Sleep` | ✅ 完整 | 调整 sleep 间隔 + jitter |
| 3 | `Shell` | ✅ 完整 | cmd.exe /c，30s 超时，1 MiB 上限 |
| 4 | `Upload` | ✅ 完整 | 写文件到目标磁盘 |
| 5 | `Download` | ✅ 完整 | 流式下载（128 KiB 分块），注册表 hive 保护 |
| 6 | `Exit` | ✅ 完整 | 退出 beacon 循环 |
| 7 | `Bof` | ✅ 完整 | COFF 加载 + 重定位 + ~15 个 Beacon-API shim |
| 8 | `Connect` | ⚠️ 部分 | P2P/rportfwd，仅 TCP |
| 9 | `Socks` | ⚠️ 部分 | SOCKS5 relay，CONNECT/BIND（无 UDP ASSOCIATE） |
| 10 | `FileOp` | ✅ 完整 | Cd / Mkdir / Rm / Mv / Cp |
| 11 | `Screenshot` | ✅ 完整 | GDI BitBlt 全虚拟屏幕捕获，跨 session 支持 |
| 12 | `Portscan` | ✅ 完整 | TCP 端口扫描，250ms/port |
| 13 | `Net` | ✅ 完整 | ifconfig / arp / netstat / route（via iphlpapi） |
| 14 | `DriveInfo` | ✅ 完整 | 磁盘/分区枚举 |
| 15 | `Clipboard` | ✅ 完整 | 剪贴板读取 |
| 16 | `Env` | ✅ 完整 | 环境变量查询 |
| 17 | `Keylog` | ✅ 完整 | 双模式：GetAsyncKeyState 轮询 + WH_KEYBOARD_LL 钩子 |
| 18 | `Screenwatch` | ⚠️ 临时 | 3 帧突发截图（同步 beacon 循环限制） |
| 19 | `Hashdump` | ⚠️ 混合 | method 0=SAM ✅, 1=SYSTEM ✅, 2=LSASS ❌（刻意延迟）, 3=macOS ❌ |
| 20 | `ChannelData` | ✅ 完整 | 操作员→implant relay 写入 |
| 21 | `ChannelClose` | ✅ 完整 | 关闭 relay 通道 |
| 22 | `StealToken` | ✅ 完整 | 复制进程 token（SeDebugPrivilege） |
| 23 | `MakeToken` | ✅ 完整 | LogonUser（交互/网络/新凭据） |
| 24 | `Rev2Self` | ✅ 完整 | 恢复身份（保留 token） |
| 25 | `GetUid` | ✅ 完整 | 当前线程身份 |
| 26 | `Inject` | ⚠️ 混合 | method 0=Pool Party（门控）, 1=Threadless HWBP ✅, 2=Module Stomp ✅ |
| 27 | `Trex` | ❌ 桩 | T-REX EDR 侦察引擎（`TREX_SCANNERS_IMPLEMENTED=false`） |
| 28 | `SetChannel` | ✅ 完整 | 切换传输信道（7 种） |

### 3.2 Bootstrap 时辅助能力

| 能力 | 状态 | 说明 |
|---|---|---|
| AMSI 致盲 | ✅ 完整 | `AmsiScanBuffer` → E_INVALIDARG |
| ETW 致盲 | ✅ 完整 | `EtwEventWrite` → xor rax,rax;ret + `NtTraceEvent` |
| HWBP 无补丁致盲 | ✅ **默认路径** | DR0 执行断点 + VEH 重定向（PE-sieve 不可见） |
| ntdll 解 hook | ✅ 完整 | KnownDlls 映射 + 磁盘回退 |
| VM/沙箱检测 | ✅ 完整 | CPUID vendor + sandbox DLL + MAC OUI + RDTSC timing |
| 主机信息采集 | ✅ 完整 | hostname/user/pid/admin/arch/SID/MAC/beacon_id |

### 3.3 DLL 导出点

| 导出名 | 说明 |
|---|---|
| `nyx_entry` | PIC/反射入口，解析 ntdll → SSN 表 → beacon 循环 |
| `nyx_beacon_oneshot` | 单次 check-in 测试 |
| `nyx_linger` | 保活 ~30s（PE-sieve 扫描目标） |
| `nyx_linger_foliage` | Foliage 睡眠掩码保活（rundll32 下提前退出） |
| `nyx_selftest_*` | 各子系统自测（exit code = 结果码） |

---

## 4. Client CLI（操作员客户端）

### 4.1 启动模式

```bash
# TUI 模式（默认）
nyx-cli --server http://host:8443 --token <TOKEN>

# 无头 SOCKS5 代理
nyx-cli socks <session> --listen 127.0.0.1:1080
```

### 4.2 TUI 交互命令（60+）

**Session / 连接管理**
- `/sessions [filter]` — 列出/切换 beacon
- `/connect <url> [token]` — 切换 team server
- `/use <id>` — 选择 beacon
- `/info` — beacon 详情（含 JA3/JA4）
- `/rename` / `/tag` / `/untag` / `/star` / `/note` — session 元数据
- `/kill` — 退出 beacon（需确认）

**文件操作**
- `/ls [path]`, `/cd`, `/mkdir`, `/rm`（需确认）, `/mv`, `/cp`
- `/upload <local> <remote>`, `/download <remote> [local]`

**进程 / 侦察**
- `/ps`, `/portscan`, `/net`, `/drive`, `/clipboard`, `/env`
- `/screenshot`, `/screenwatch`, `/trex`

**凭据 / Token**
- `/creds [list|find|sync|export|add|del]`
- `/hashdump [sam|system|shadow]`
- `/steal <pid>`, `/make_token`, `/rev2self`, `/getuid`

**执行**
- `/bof <file> [args]` — BOF 执行
- `/inject <method> <pid|spawn_to> <file>` — shellcode 注入
- 非 `/` 开头 = shell 命令

**Pivot / Relay**
- `/pivot <host> <port>` — P2P/rportfwd
- `/socks start|stop` — SOCKS5 监听器
- `/chan close <id>` — 关闭通道

**键盘记录**
- `/keylog start|stop|dump|stream [secs]|unstream`

**Lateral / Beacon 控制**
- `/sleep <secs> [jitter%]`, `/ping`, `/channel`, `/topo`

**Server / Audit / Implant**
- `/audit [operator] [action] [limit]`, `/audit verify`
- `/tasks`, `/profile`
- `/generate <callback> [port] [options]`, `/implants`, `/revoke`

**Kernel Daemon**（P6）
- `/driver-status`, `/blind-etw`, `/hide`（确认）, `/dump-lsass`（确认）, `/neutralize`（确认）, `/detach-mf`

**本地配置**
- `/help`, `/clear`, `/theme`, `/config`, `/alias`

### 4.3 TUI 布局

- **6 种 pane 视图**：Console / SessionList / Files / Procs / Creds / Topology
- **tmux 式分屏**：Ctrl+B 前缀 → v/% 分列, s/" 分行, x 关闭, hjkl 移动
- **11 种 overlay**：Files / Procs / Creds / Audit / Sessions / SessionDetail / Image / Tasks / Profile / AuditVerify
- **鼠标支持**：滚轮滚动、点击聚焦/选择、右键关闭、中键分屏
- **状态持久化**：`~/.nyx/config.json`（别名/主题）、`~/.nyx/creds.json`（凭据）、`~/.nyx/sessions.json`（session 元数据）

### 4.4 SOCKS5 代理

- RFC 1928 + RFC 1929 合规
- 非环回绑定强制要求用户名/密码认证
- CONNECT only（不支持 BIND/UDP ASSOCIATE）
- 单排空约束（P0-A）：in-TUI relay 由 worker 线程的 `/api/results` 排空喂入
- 通道上限 14（implant 端 MAX_CHANNELS=16）

---

## 5. Transport（传输层）

### 5.1 传输栈

`TransportStack` 按优先级自动故障转移：

```
HTTPS → DoH DNS → Slack API → LLM API → MCP → WebTransport → SMB Pipe
```

### 5.2 各信道状态

| 信道 | 状态 | 说明 |
|---|---|---|
| **HTTPS/TLS** | ✅ 完整 | rustls，JA3/JA4 入站计算/验证完整；**JA3 出站伪装未接线**（阻塞在 wreq 6.0） |
| **SMB Named Pipe** | ✅ 完整（Windows） | `\\.\pipe\nyx`，4B 长度前缀 + payload，1 MiB 帧 |
| **DoH DNS** | ✅ 完整 | Cloudflare/Google/Quad9，URL-safe base64 分块，1 QPS |
| **LLM API (Claude)** | ✅ 完整 | XOR 混淆（⚠ 非真正加密），5 RPM，4 KiB 帧 |
| **Slack API** | ✅ 完整 | Bot token，chat.postMessage + conversations.history |
| **MCP JSON-RPC** | ✅ 完整 | tools/call 隧道，Bearer 认证（P1-15） |
| **Malleable C2** | ✅ 完整 | 3 个预置 profile（jQuery CDN / O365 API / Windows Update） |
| **WebTransport** | ❌ 桩 | 所有方法返回 Dead，需 quinn/quiche/msquic |

### 5.3 TLS 指纹

- **入站（server 侧）**：✅ 完整 — `sniff_client_hello` 在 rustls 消费前 peek ClientHello，计算 JA3/JA4
- **出站（implant 侧）**：❌ 未接线（P1-14）— 所有 HTTPS 流量使用 rustls 默认 ClientHello
- **HTTP/2 Akamai 指纹**：⚠ 部分 — SETTINGS/WINDOW_UPDATE/PRIORITY 解析完整，pseudo-header 顺序需 HPACK

### 5.4 预置 Malleable Profile

| Profile | 方法 | URI 池 | User-Agent | 伪装目标 |
|---|---|---|---|---|
| `jquery_cdn` | GET | cdnjs/jsDelivr | Chrome | jQuery CDN 流量 |
| `o365_api` | POST | /v1.0/me/messages | Office | Microsoft Graph API |
| `windows_update` | GET | .cab 文件 | Windows-Update-Agent | WSUS 更新 |

---

## 6. Kernel SDK（内核 SDK）

> 操作员侧 ring-0 工具包，通过独立的 `nyx-kernel --serve` daemon 运行。

### 6.1 BYOVD 驱动

| 驱动 | 设备 | 状态 | 说明 |
|---|---|---|---|
| **KslD.sys** | `\\.\KslD` / `\\.\MpKsl` | ✅ 干净（MS 签名） | 首选路径（"Living off the Defender"） |
| **Shield** | `\\.\EAZShield` | ✅ 干净 | 默认回退 |
| **WdtKernel** | `\\.\__WDT__` | ✅ 干净 + HVCI 兼容 | 仅物理地址（`MmMapIoSpace`） |
| RTCore64 | `\\.\RTCore64` | ❌ 已列入黑名单 | 参考实现（CVE-2019-16098） |
| IQVW64E | `\\.\iqvw64e` | ❌ 已列入黑名单 | 任意长度 memcpy（CVE-2015-2291） |

### 6.2 内核能力

| 能力 | 状态 | 说明 |
|---|---|---|
| 内核 R/W | ✅ | 5 个后端，KslD 首选 |
| ETW-TI 内核致盲 | ✅ | 4 跳指针链，EnableInfo=0 |
| Ps*NotifyRoutine 中和 | ✅ | RET stub 覆盖回调槽 |
| MiniFilter RegisteredFilters 解链 | ✅ | DKOM unlink |
| PatchGuard 绕过窗口 | ✅ | TimingRepair（全版本）+ RuntimePgBypass（24H2+） |
| 进程隐藏（ActiveProcessLinks 解链） | ✅ | DKOM |
| PPL 剥离 + 不朽化 | ✅ | Protection=0x72, SigLevel=0x3F |
| ETW 欺骗（伪造事件） | ✅ | EVENT_HEADER 构造 |
| LSASS 内核读取 | ✅ | DTB + 4 级页表走查 |
| EDR 中和 | ✅ | kill（ZwTerminateProcess）/ freeze（WerFaultSecure coma）/ choke（QoS） |
| WFP PID 出站阻断 | ❌ 门控 | 返回 Err（PID 过滤不安全） |
| 自主偏移解析 | ✅ | pattern scan + RIP-relative lea 解析 |

### 6.3 支持的 Windows 版本

EPROCESS 偏移表覆盖 14 个 build：10240, 10586, 14393, 15063, 16299, 17134, **17763**, 18362, **19041**, 20348, **22621**, 22631, **26100**, 26200

Patch-equivalent 映射：19042-19045→19041, 18363→18362, 22000→20348

未知 build 回退：DefenderDump 式不变量扫描（PID=4, "System", protection=0x72）

---

## 7. Evasion（规避层）

### 7.1 默认启用的规避

| 技术 | 文件 | 说明 |
|---|---|---|
| **HWBP 无补丁致盲** | `blind_hwbp.rs` | DR0 执行断点 + VEH 重定向，PE-sieve 不可见 |
| **.text 波动（PAGE_NOACCESS 睡眠）** | `fluctuation.rs` | 睡眠时 .text→PAGE_NOACCESS + DR0-7 清零，唤醒时 NtContinue 恢复 |
| **RC4 内存掩码（数据区域）** | `mem.rs` | 配置/ECDH 密钥/BOF 缓冲区 RC4 加密（掩码密钥缓存一次） |
| **PEB 走行 API 解析** | `resolve.rs` | 无 IAT，所有 API 运行时解析 |
| **间接系统调用** | `syscalls.rs` | SSN 从 fresh ntdll 解析，syscall;ret gadget 执行 |
| **ntdll fresh map 解 hook** | `unhook.rs` | KnownDlls\ntdll 映射 + 磁盘回退 |
| **VM/沙箱检测** | `envprobe.rs` | CPUID + sandbox DLL + MAC OUI + RDTSC timing |
| **PIC bump allocator** | `ntalloc.rs` | NtAllocateVirtualMemory 后端，slab 跟踪，无释放（安全） |
| **PdataGapScanner** | `evasion_glue.rs` | 扫描 ntdll/kernelbase/win32u .pdata gap |

### 7.2 门控关闭的规避（需显式启用）

| 技术 | 门控 | 原因 |
|---|---|---|
| **栈欺骗 RSP 交换** | `SPOOF_SWAP_ENABLED`（默认 OFF） | CET shadow-stack 会 #CP（Intel TGL+ / Win11 24H2+） |
| **Foliage APC .text 加密** | `FOLIAGE_APC_ENABLED`（默认 OFF） | PIC thunk 未在真机验证 + REL32/循环依赖致命 bug |
| **环境绑定密钥** | `keying_levels`（server 强制 0） | Temporal 层含 GetTickCount64，server 无法预测 |
| **Pool Party threadless 注入** | `tp::pool_party_enabled()`（默认 OFF） | _TP_WORK/_TP_DIRECT 偏移需真机验证 |
| **Module Stomp 执行尾** | `modulestomp_enabled`（默认 OFF） | 跨进程写/执行需目标侧验证 |

---

## 8. Wire Protocol（线协议）

### 8.1 加密层

- **密钥交换**：X25519 ECDH（implant 临时密钥 × server 长期密钥）
- **AEAD**：ChaCha20-Poly1305
- **Nonce 方向分离**：`nonce[0]` = 方向标记（0x01 C→S, 0x02 S→C）
- **AAD**：implant 公钥绑定每一帧
- **反重放**：C→S（server write guard `counter <= last_recv`）+ S→C（implant `last_server_counter`）
- **HKDF**：salt=server_pub, info=server_pub‖implant_pub

### 8.2 SessionInfo（首次 check-in）

| 字段 | 类型 | 说明 |
|---|---|---|
| beacon_id | u32 | KUSER_SHARED_DATA xorshift32 混合 PID |
| hostname | string | GetComputerNameW |
| username | string | GetUserNameW |
| os | string | "Windows" |
| arch | u8 | 0=x86_64, 1=aarch64, 2=x86 |
| pid | u32 | GetCurrentProcessId |
| is_admin | u8 | TokenElevation |
| auth_token | Option\<[u8;32]\> | per-implant 一次性 token |

### 8.3 Command（28 种）

详见 [§3.1 Implant 命令表](#31-全部-28-个命令的实现状态)

### 8.4 Response（7 种）

| Tag | 变体 | 说明 |
|---|---|---|
| 1 | `Output(Vec<u8>)` | 命令输出 |
| 2 | `Ok` | 空成功确认 |
| 3 | `Err(String)` | implant 端错误 |
| 4 | `FileChunk` | 流式下载分块（name, seq, eof, data） |
| 5 | `BofOutput(Vec<u8>)` | BOF 输出 |
| 6 | `Channel` | relay 通道状态/数据（chan, status, data） |
| 7 | `Image(Vec<u8>)` | PNG 截图字节 |

---

## 9. 配置参考

### 9.1 Team Server 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `NYX_BIND` | `127.0.0.1:8443` | 绑定地址（非环回 + 无认证 = 自动 token） |
| `NYX_TOKEN` | — | Legacy 共享 bearer token |
| `NYX_ALLOW_OPEN` | — | `=1` 允许开放 team server |
| `NYX_KILLDATE` | — | Unix 秒 kill date |
| `NYX_KEYFILE` | — | Server X25519 私钥路径 |
| `NYX_PROFILE` | — | Malleable C2 profile 路径 |
| `NYX_CREDS` | `~/.nyx/server-creds.db` | 凭据 DB 路径 |
| `NYX_OPERATORS_FILE` | `~/.nyx/operators.json` | 操作员注册表 |
| `NYX_BOOTSTRAP_OPERATOR` | — | `name:secret` 初始化首个 Admin |
| `NYX_AUDIT_LOG` | `~/.nyx/audit.jsonl` | 审计日志路径 |
| `NYX_KERNEL_DAEMON` | — | kernel daemon `host:port` |
| `NYX_TEMPLATE` | — | DLL 模板路径（启用 implant 生成） |
| `NYX_SCRIPT` | — | Rhai 操作员脚本路径 |
| `NYX_SESSION_MAX_AGE` | 604800 | Session 最大存活秒数 |
| `NYX_SESSION_MAX_IDLE` | 86400 | Session 最大空闲秒数 |

### 9.2 Implant 环境变量 / 编译时 cfg

| 变量 / cfg | 默认 | 说明 |
|---|---|---|
| `NYX_SKIP_SANDBOX` | — | 跳过沙箱检测（SYSTEM 上下文部署） |
| `NYX_FS_ALLOW_PROTECTED` | — | 允许访问 SAM/SYSTEM 注册表 hive |
| `NYX_FOLIAGE_APC_ON=1` | OFF | 编译时启用 Foliage APC 路径 |
| `NYX_FLUCTUATION_OFF=1` | ON | 编译时禁用 .text 波动 |

### 9.3 Client 环境变量

| 变量 | 说明 |
|---|---|
| `NYX_SERVER` | team server URL |
| `NYX_TOKEN` | bearer token |
| `NYX_ALLOW_HTTP=1` | 允许非环回明文 HTTP |
| `NYX_CREDS_ENCRYPT=1` | 拒绝本地凭据持久化 |
