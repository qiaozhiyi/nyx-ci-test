# Nyx 多信道传输层设计

> ⚠️ **关键现状（AUTHORITATIVE_FACTS §0/§1/§3 #4，2026-07-18 审计）**：`transport` crate 已有 **6 个 Transport impl**（Malleable / DoH / Slack / LLM / MCP / SMB），**全部零消费者**——trait 与实现都已存在，但 implant/server 侧**无任何消费路径**。implant 实际回连通道仍为单一 HTTPS（axum + rustls）。TLS 指纹伪装（`build_impersonating_client`）是 **Err stub**，JA3/JA4 嗅探引擎已实现但 emission 未接线。**本文件描述的六级信道栈是目标架构，非现状。** 数字与状态以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。

> **2026-07-07 · 情报基线:**
> Shrike (2026) — 20+ 隐蔽信道检测 · ArchWorks (2026) — L0-L9 隧道分层检测
> QuicFuscate (2026) — Rust 模块化 QUIC 传输栈 · HTTP/3 Multiplexing Covert (2026)
> MASQUE CONNECT-UDP (IETF 2026) · WebTransport over HTTP/3 (IETF 2026)

---

## 当前 vs 目标

> ⚠️ "当前"列经 2026-07-18 审计修正。transport crate 的 6 个 Transport impl 是**真实存在但零消费者**的代码，不算作"已生效信道"。

| 维度 | 当前（2026-07-18 审计） | 目标 |
|------|------|------|
| 协议（implant 实际回连） | **1（HTTPS via WinHTTP/axum+rustls）** | 6（QUIC / WS / H2 / DNS / ICMP / HTTPS） |
| transport crate Transport impl | **6 个（Malleable/DoH/Slack/LLM/MCP/SMB），全部零消费者** | 6 个全接线 + 自动降级 |
| 信道模式 | 单信道 | 多信道自动降级 |
| 传输层 | 硬编码 WinHTTP（implant） | `Transport` trait 可插拔（trait 已定义，未消费） |
| JA4 指纹 | **引擎已实现（JA3/JA4 计算），emission 未接线（Err stub）** | 每信道独立 JA4/JA4H 随机化 |
| 隐蔽性 | 低（单一直连 HTTPS） | 五级降级链 |

---

## 六级信道栈

```
优先级 ←── 隐蔽性高 ──────────────────── 带宽高 ──→ 备用

L1: QUIC/HTTP3      ★★★★★   ~50 Mbps    浏览器流量不可区分
L2: WebSocket/WSS   ★★★★☆   ~10 Mbps    长连接，混在 Web 应用流量中
L3: HTTP/2 MP       ★★★★☆   ~20 Mbps    多路复用，流交错作为覆盖信号
L4: DNS Tunneling   ★★★★★   ~500 B/s    无处不在，DoH 加密
L5: ICMP Tunneling  ★★★★☆   ~1 KB/s     防火墙常放行 ping
L6: HTTPS (现有)    ★★★☆☆   全速        最老旧，最后备用
```

### L1: QUIC/HTTP3

| 特性 | 细节 |
|------|------|
| 载体 | UDP/443，QUIC Initial 包加密 TLS 1.3 |
| 隐蔽性 | 与 Chrome/Firefox HTTP3 流量一致 |
| 多路复用 | 单连接多 Stream：1=心跳 2=任务 3=数据 |
| 覆盖信道 | QUIC padding + CID 轮转 + stream ID 时序调制 |
| Rust 实现 | `quinn` (QUIC) or `s2n-quic` (AWS) |
| 检测对抗 | JA4 指纹 = Chrome 126 · ALPN = h3 · SNI = cdn.cloudflare.com |

### L2: WebSocket over TLS

| 特性 | 细节 |
|------|------|
| 载体 | `wss://` Upgrade from HTTPS |
| 隐蔽性 | 同 Web 应用 WebSocket（Slack/Teams/Discord） |
| 长连接 | 单连接双向，心跳 = ping/pong 帧 |
| 检测对抗 | 伪装 `Origin: https://app.slack.com` · `User-Agent: Chrome` |

### L3: HTTP/2 Multiplexing

| 特性 | 细节 |
|------|------|
| 载体 | TLS 1.3 + HTTP/2 SETTINGS + stream 多路复用 |
| 隐蔽性 | 流交错 + flow control 作为覆盖信号 |
| 技术 | PRIORITY frame 调制 · padding frame 数据嵌入 |

### L4: DNS Tunneling

| 特性 | 细节 |
|------|------|
| 载体 | DNS-over-HTTPS (DoH) TXT 查询 / CNAME 链 |
| 隐蔽性 | 与 Cloudflare/Google DoH 客户端无区别 |
| 分片 | Base64 → 每片 220 字节 → `chunk-N.c2.domain` TXT |
| 速率 | 1 QPS（模拟正常 DNS）· 10KB ≈ 45 秒 |

### L5: ICMP Tunneling

| 特性 | 细节 |
|------|------|
| 载体 | ICMP Echo Request/Reply (ping) payload |
| 隐蔽性 | 无端口/无握手 · 防火墙常放行 |
| 分片 | 每包 ≤ 1472 字节 payload · 支持重传 |

### L6: HTTPS (现有 WinHTTP)

保留作为最终降级路径。添加 JA4 指纹随机化。

---

## Transport 抽象层设计

```rust
// crates/transport/src/traits.rs

pub trait Transport: Send {
    /// Send encrypted frame. Returns Ok if delivered.
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receive next frame (blocking with timeout).
    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError>;

    /// Channel health: latency in ms, or None if dead.
    fn health(&self) -> Option<u64>;

    /// Unique channel identifier.
    fn name(&self) -> &'static str;

    /// Close channel.
    fn close(&mut self);
}

pub struct TransportStack {
    channels: Vec<(Box<dyn Transport>, u8)>, // (transport, priority 0=highest)
    active: usize,                            // index of active channel
    health_interval: Duration,
}

impl TransportStack {
    /// Send on active channel. On failure, try next priority.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        // Try active first, fall through priority chain
    }

    /// Background health check. Switch channel on 3 consecutive failures.
    pub fn check_health(&mut self) {
        // Ping each channel, promote healthiest
    }
}
```

---

## 实施计划

> ⚠️ **现状修正（AUTHORITATIVE_FACTS §0/§1/§3 #4）**：P19a（Transport trait）与 6 个 Transport impl **已存在**，本阶段的核心缺口是**接线消费者**（让 implant/server 实际调用这 6 个 impl），以及修复 TLS emitter stub（见下方"即刻行动"）。

```
P0.（最高优先）transport 消费者接线——为 6 个零消费者 Transport impl 在 implant/server 补消费路径
P0'. TLS emitter 接线——修复 transport/src/emitter.rs 的 Err stub（build_impersonating_client）

P19a. Transport trait ✅ 已存在（crates/transport/src/traits.rs）+ 6 个 impl ✅ 已存在
  缺口：消费者接线（implant/server 侧调用方）

P19b. L6: HTTPS upgrade (1 周)
  crates/transport/src/https.rs — 现有 WinHTTP 封装 + JA4 指纹池

P19c. L2: WebSocket (2 周)
  crates/transport/src/ws.rs — tungstenite/ tokio-tungstenite over TLS

P19d. L4: DNS Tunneling (2 周)
  crates/transport/src/dns.rs — DoH 客户端 + TXT/CNAME 编码/解码

P19e. L1: QUIC/HTTP3 (3 周)
  crates/transport/src/quic.rs — quinn-based QUIC transport

P19f. L3: HTTP/2 MP (1 周)
  crates/transport/src/h2.rs — h2 crate multiplexed streams

P19g. L5: ICMP (1 周)
  crates/transport/src/icmp.rs — raw socket ICMP echo

P19h. TransportStack 集成 (1 周)
  TransportStack + 自动降级 + 健康检查 + JA4 轮换

总计: 12 周 · ~5,000 LOC（不含消费者接线与 emitter 修复的 P0 工作）
```

---

## 即刻行动

> ⚠️ 优先级已重排：先做消费者接线与 emitter 修复（AUTHORITATIVE_FACTS §3 #4/#5），再做 P19b 起的新信道。

```
0.（最高优先）transport 消费者接线——6 个 Transport impl 接到 implant beacon / server 路由
0'. TLS emitter 修复——transport/src/emitter.rs 的 build_impersonating_client 从 Err stub 改为真实现
1. P19a — ✅ traits.rs 已存在，无需新建
2. P19b — 封装现有 WinHTTP 为 Transport impl
3. P19d — DNS Tunneling（最高性价比——零额外依赖，无处不在）
```
