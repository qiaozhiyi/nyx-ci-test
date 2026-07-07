# Nyx 多信道传输层设计

> **2026-07-07 · 情报基线:**
> Shrike (2026) — 20+ 隐蔽信道检测 · ArchWorks (2026) — L0-L9 隧道分层检测
> QuicFuscate (2026) — Rust 模块化 QUIC 传输栈 · HTTP/3 Multiplexing Covert (2026)
> MASQUE CONNECT-UDP (IETF 2026) · WebTransport over HTTP/3 (IETF 2026)

---

## 当前 vs 目标

| 维度 | 当前 | 目标 |
|------|------|------|
| 协议 | 1 (HTTPS) | 6 (QUIC / WS / H2 / DNS / ICMP / HTTPS) |
| 信道模式 | 单信道 | 多信道自动降级 |
| 传输层 | 硬编码 WinHTTP | `Transport` trait 可插拔 |
| JA4 指纹 | 无 | 每信道独立 JA4/JA4H 随机化 |
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

```
P19a. Transport trait (1 周)
  crates/transport/src/traits.rs — Transport + TransportStack

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

总计: 12 周 · ~5,000 LOC
```

---

## 即刻行动

```
1. P19a — 创建 crates/transport/src/traits.rs: Transport trait + TransportStack
2. P19b — 封装现有 WinHTTP 为 Transport impl
3. P19d — DNS Tunneling（最高性价比——零额外依赖，无处不在）
```
