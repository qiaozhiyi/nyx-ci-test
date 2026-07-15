# T-REX 传输与加密层 · 2026 前沿方案

> **制定日期:** 2026-07-07
> **情报基线:**
> QUICstep (POPETS 2026) — QUIC 连接迁移绕过 GFW 审查
> MASQUE (IETF 2026) — HTTP/3 隧道框架，单 TLS 连接复用
> Multipath QUIC (IETF draft-20) — 多路径 QUIC，per-path 拥塞控制
> QuicCC-SMD (MDPI 2026) — QUIC 流 Markov 链流量整形，ML 分类器 +7% 抗检测
> NIST FIPS 203 ML-KEM (2024) · Signal PQXDH (2023) · TLS 1.3 Hybrid KEM (IETF 2026)
> FF-MR (MDPI 2026) — DoH 隐蔽信道多注意力检测
> Dead Drop Resolver Taxonomy (Delta ThreatLabs 2026)

---

## 1. 传输层：五级隐蔽信道栈

```
                          ┌────────────────────────────────┐
                          │     T-REX Exfiltration Stack     │
                          │                                  │
  最隐蔽 ←─────────────── 隐蔽性 ──────────────────→ 最高带宽
                          │                                  │
  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────────┐
  │ L1: DoH │   │L2: QUIC │   │L3: MASQUE│   │ L4: DeadDrop │
  │ DNS TXT │   │Streaming│   │HTTP/3    │   │ GitHub Gist  │
  │ Covert  │   │Covert   │   │Tunnel    │   │ Stego Image  │
  └────┬────┘   └────┬────┘   └────┬────┘   └──────┬──────┘
       │              │              │               │
       └──────────────┴──────────────┴───────────────┘
                          │
               ┌──────────┴──────────┐
               │   L5: Fallback      │
               │   HTTPS + JA4 Rot.  │
               └─────────────────────┘
```

### L1: DoH DNS Covert Channel（最高隐蔽，最低带宽）

| 特性 | 实现 |
|------|------|
| **载体** | DNS-over-HTTPS 查询（`application/dns-message`），封装在 TLS 1.3 内 |
| **隐蔽性** | 与 Google/Cloudflare DoH 流量不可区分。无明文 DNS 端口 53 |
| **记录类型** | TXT（最大 255 字节/记录）、CNAME 链（多级跳转） |
| **编码** | Base64URL → 分片（每片 ≤ 220 字节，留 35 字节域名开销） |
| **DoH 服务器池** | `cloudflare-dns.com`, `dns.google`, `doh.opendns.com`, `doh.securedns.eu` —— 轮换 |
| **SNI 伪装** | SNI = `cloudflare-dns.com` → 与真实 DoH 客户端完全一致 |
| **速率限制** | 每秒 1 查询（模拟正常 DNS 行为），10KB 报告 ≈ 45 秒 |
| **检测对抗** | FF-MR 多注意力检测器依赖流量特征融合——L1 加入随机延迟（±200ms）+ 填充查询（50% 概率）打破时序模式 |

### L2: QUIC Streaming Covert Channel（高隐蔽，中带宽）

> **核心技术:** QuicCC-SMD (MDPI 2026) — Markov 链流量整形 + 凸优化变形矩阵

| 特性 | 实现 |
|------|------|
| **载体** | HTTP/3 over QUIC 视频流（伪装 YouTube / TikTok 流量） |
| **隐蔽性** | QUIC 包头加密 → DPI 零可见。流特征经 Markov 链匹配合法分布 |
| **嵌入方式** | QUIC 帧 padding + 包插入 + 微延迟调制（3 维联合优化） |
| **嵌入率** | 1.5% 有效载荷（QuicCC-SMD 论文实测最优平衡点） |
| **流量整形** | 在线凸优化器 → 每 10 个包校准一次变形矩阵 → 目标分布 = YouTube 4K 流 |
| **ML 抗检测** | 比 3 个基线高 ≥7% F1 分数。对 XGBoost/CNN/Transformer 分类器均有效 |
| **服务器伪装** | QUIC 服务器返回伪造的 YouTube 视频元数据（无实际视频传输） |

### L3: MASQUE HTTP/3 Tunnel（中隐蔽，高带宽）

> **核心技术:** MASQUE (IETF 2026) — `extended CONNECT` + HTTP Datagrams + Capsule Protocol

| 特性 | 实现 |
|------|------|
| **载体** | HTTP/3 `CONNECT-UDP` 隧道，与普通 Web 流量复用同一 QUIC 连接 |
| **隐蔽性** | 单 TLS 连接同时承载 Web 请求 + 隧道数据。iCloud Private Relay 同样使用 MASQUE |
| **协议** | `SETTINGS_ENABLE_CONNECT_PROTOCOL` → `CONNECT-UDP` → Capsule Protocol → HTTP Datagram |
| **伪装** | 前端请求 `GET /api/telemetry` → 返回 JSON（模拟应用遥测），隧道数据混在 QUIC DATAGRAM 帧中 |
| **抗审查** | QUICstep 模式：握手包走 MASQUE 隧道，数据包走原生路径。GFW QUIC-SNI 审查绕过（实测 50/50 成功率）|
| **多路径** | IETF Multipath QUIC (draft-20): 双 NIC（WiFi + Cellular）同时传输同一连接，单路径断不影响 |

### L4: Dead Drop Resolver — 隐写图像 + 合法平台

> **核心技术:** DDR Taxonomy (Delta ThreatLabs 2026) — LSB 隐写 + 平台 API 检索

| 特性 | 实现 |
|------|------|
| **载体** | PNG 图像 LSB 隐写（每像素 3 位 R/G/B LSB = 3bpP） |
| **平台** | GitHub Gist API (raw), Pastebin, imgur, Discord CDN |
| **编码** | 报告 → ChaCha20 加密 → Base64 → LSB 嵌入 1920×1080 PNG（可嵌入 ~ 2.3MB） |
| **检索** | `GET /gists/{id}/raw` → 下载图像 → LSB 提取 → 解密 |
| **账户轮换** | 预生成 100 个 GitHub PAT tokens → 每次使用不同账户 → 读取后自删除 gist |
| **CDN 分发** | 图像上传到 imgur → 从 Discord CDN 拉取（Discord 不记录源 IP） |
| **时序** | 上传 + 通知 + 拉取 = 完整异步外传，无实时连接 |

### L5: HTTPS + JA4 指纹旋转（最高带宽，最低隐蔽）

| 特性 | 实现 |
|------|------|
| **载体** | HTTPS `POST /api/v2/metrics` — 模拟 Datadog/NewRelic 遥测上报 |
| **JA4 指纹** | Chrome 124/125/126 · Firefox 125/126 · Edge 124 · Safari 17 — 每次随机 |
| **uTLS 实现** | Rust 移植 `refraction-networking/utls`：ClientHello 扩展/密码套件/椭圆曲线 = 浏览器精确匹配 |
| **SNI 伪装** | SNI = `ingest.datadoghq.com` → 真实 C2 在 HTTP Host header |
| **Domain Fronting** | Cloudflare Workers / Azure Front Door / AWS CloudFront 三选一 |
| **流量填充** | 请求体随机填充至 4KB/16KB/64KB，模拟监控探针上报 |

---

## 2. 加密层：X25519 + ML-KEM-1024 混合

> **标准对齐:** NIST FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA) + FIPS 205 (SLH-DSA)
> **TLS 1.3:** IETF `draft-ietf-tls-ecdhe-mlkem` — `X25519MLKEM768`
> **Signal PQXDH:** X25519 + Kyber-1024 (2023 生产部署)

### 密钥交换：双密钥混合 KEM

```
┌────────────────────────────────────────────────────────────┐
│                  T-REX 密钥交换流程                          │
│                                                            │
│  服务器预置（Stage 0 嵌入）：                                │
│    - X25519 公钥 (32 bytes)                                 │
│    - ML-KEM-1024 公钥 (1568 bytes)                          │
│                                                            │
│  T-REX 运行时：                                             │
│    1. 生成临时 X25519 密钥对 (eph_sk, eph_pk)               │
│    2. X25519 ECDH: ss_x = X25519(eph_sk, server_pk_x)     │
│    3. ML-KEM Encaps: (ss_kyber, ct) = ML-KEM-1024.Encaps(  │
│         server_pk_kyber)                                    │
│    4. 混合: ss = HKDF-SHA512(ss_x || ss_kyber,             │
│         "T-REX v2 PQXDH 2026-07", 64)                      │
│    5. 对称加密: ChaCha20-Poly1305(key=ss, nonce=random)    │
│    6. 外传载荷: ct (1568 bytes) || nonce (12 bytes) ||     │
│        密文 || Poly1305 tag (16 bytes)                      │
│                                                            │
│  前向安全性: 经典 X25519 保证                              │
│  后量子安全: ML-KEM-1024 保证（NIST 安全级别 5）            │
│  混合保证: 攻击者需同时攻破 X25519 和 ML-KEM 才能解密       │
└────────────────────────────────────────────────────────────┘
```

### Rust 实现路线（crates/protocol/src/pq.rs）

```rust
// 使用纯 Rust 的 pqcrypto 或 aws-lc-rs crate
use ml_kem::MlKem1024;       // NIST FIPS 203 ML-KEM-1024
use x25519_dalek;             // 现有 X25519 实现
use chacha20poly1305;         // 现有 AEAD
use hkdf::HkdfSha512;         // 现有 HKDF

struct PqHybridKem {
    server_x25519_pk: [u8; 32],
    server_mlkem_pk:  [u8; 1568],
}

impl PqHybridKem {
    fn encapsulate(&self) -> (SharedSecret, Ciphertext) {
        let (eph_sk, eph_pk) = x25519_dalek::EphemeralSecret::random().into();
        let ss_x = eph_sk.diffie_hellman(&self.server_x25519_pk);
        
        let (ss_kyber, ct) = MlKem1024::encapsulate(&self.server_mlkem_pk)?;
        
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ss_x.as_bytes());
        ikm[32..].copy_from_slice(&ss_kyber);
        
        let ss = HkdfSha512::extract(None, &ikm)
            .expand(b"T-REX v2 PQXDH 2026-07", 32);
        
        (ss, Ciphertext { eph_pk, kyber_ct: ct })
    }
}
```

### 级联加密（双重保险）

对于极端敏感环境，采用**双层加密**：

```
外层: ML-KEM-1024 + X25519 混合 KEM → ChaCha20-Poly1305
内层: 外传载荷再用 receiver 的 Age 公钥加密 (age-encryption.org/v1)
      → X25519 + ChaCha20-Poly1305 (age 内部机制)

结果: 即使 ML-KEM 未来被攻破，内层 age 加密仍保护数据
      即使 age 被攻破，外层 ML-KEM 混合仍保护数据
```

---

## 3. 信道选择与抗干扰

### 自动信道选择决策树

```
                    ┌──────────────┐
                    │ 网络环境探测  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        DNS over HTTPS  QUIC 可用   仅 TCP 可用
        端口 443 开放   端口 443 UDP  端口 443 TCP
              │            │            │
              ▼            ▼            ▼
          L1: DoH      L2/L3: QUIC   L5: HTTPS
                        / MASQUE      + JA4 rotate
```

### 反审查模式（GFW / 国家级防火墙）

启用 QUICstep 模式：

1. **握手分离**: QUIC Initial 包通过 WireGuard → 境外 VPS 中继
2. **数据直连**: QUIC Short Header 包走原生路径 → 无 VPN 开销
3. **迁移触发**: 检测到 SNI 阻断 → 自动 QUIC 连接迁移到新 4-tuple
4. **回退**: 连续 3 次迁移失败 → 降级到 DoH 信道

### 反取证模式

每信道独立 JA4 指纹 + 独立 SNI + 独立 User-Agent → 跨信道无关联性。

---

## 4. 与 T-REX v1 的对比

| 维度 | v1（当前 trex.rs） | v2（新方案） |
|------|-------------------|------------|
| **外传** | 无（返回 beacon） | 5 级隐蔽信道栈 |
| **加密** | X25519 + ChaCha20 | X25519 + ML-KEM-1024 混合 + 级联 age |
| **传输** | 单 WinHTTP | QUIC/HTTP3 · MASQUE · DoH · DeadDrop |
| **抗审查** | 无 | QUICstep 握手分离 + 连接迁移 |
| **流量伪装** | 无 | QuicCC-SMD Markov 链流量整形 |
| **JA4 指纹** | 无 | Chrome 124-126 / Firefox 125-126 / Safari 17 / Edge 124 |
| **多路径** | 无 | Multipath QUIC (WiFi + Cellular) |
| **后量子** | 无 | ML-KEM-1024 (NIST FIPS 203 安全级别 5) |
| **隐写** | 无 | LSB PNG 隐写 + GitHub Gist Dead Drop |
| **反取证** | 无 | 自毁序列 + 磁盘/内存痕迹清除 |

---

## 5. 即刻行动

```
1. 创建 crates/protocol/src/pq.rs — ML-KEM-1024 + X25519 混合 KEM
2. 创建 crates/transport/src/quic.rs — QUIC/HTTP3 传输层
3. 创建 crates/transport/src/doh.rs — DoH DNS 隐蔽信道
4. 创建 crates/transport/src/masque.rs — MASQUE HTTP/3 隧道
5. 创建 crates/transport/src/stego.rs — LSB 隐写 + Dead Drop Resolver
```
