# Nyx 协议加密层 · 2026 CNSA 2.0 全面升级方案

> **制定日期:** 2026-07-07
> **合规目标:** CNSA 2.0 (NSA 2025) · NIST FIPS 203/204/205/206 (2024) · NIST IR 8547 (2024)
> **协议参考:** Signal PQXDH (2023 生产) · MLS RFC 9420 · Noise Protocol Framework · IETF TLS 1.3 Hybrid KEM (draft-ietf-tls-ecdhe-mlkem)

---

## 0. 当前状态 vs CNSA 2.0 差距

| 组件 | 当前 Nyx | CNSA 2.0 要求 | 差距 |
|------|---------|-------------|------|
| **密钥交换** | X25519 ECDH | ML-KEM-1024 + ECDH 混合 | ❌ 缺后量子 KEM |
| **对称加密** | ChaCha20-Poly1305 | AES-256-GCM（CNSA 2.0 推荐）or 等效 256-bit AEAD | ⚠️ ChaCha20 256-bit 等效，但非 CNSA 明确列名 |
| **哈希/KDF** | HKDF-SHA256 | SHA-384 或 SHA-512 | ❌ SHA-256 不足 |
| **数字签名** | 无 | ML-DSA-87 (FIPS 204) 或 LMS/XMSS | ❌ 完全缺失 |
| **前向安全性** | 每会话 ECDH | 每消息 Double Ratchet | ❌ 无 per-message FS |
| **后妥协安全** | 无 | PCS（重密钥后恢复安全） | ❌ 完全缺失 |
| **抗重放** | 单调计数器 | 单调计数器 ✅ | ✅ 已达标 |
| **协议框架** | 自定义 Frame seal/open | Noise Protocol 或 Signal Double Ratchet | ⚠️ 自定义不如标准协议审查充分 |
| **NIST FIPS 合规** | 无 | FIPS 203/204/205/206 | ❌ |

---

## 1. 目标架构：NyxCipher v3.0

```
┌─────────────────────────────────────────────────────────────────┐
│                    NyxCipher v3.0 Protocol Stack                 │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Application Layer                         │ │
│  │  Command · Response · File · Stream · Heartbeat             │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │               Double Ratchet (per-message FS + PCS)          │ │
│  │  Root Key → Sending Chain Key → Message Key (AEAD)           │ │
│  │  Receiving Chain Key → Message Key (AEAD)                    │ │
│  │  DH Ratchet: X25519 + ML-KEM-1024 hybrid per ratchet step   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │         Noise Handshake: Noise_IK_25519_MLKEM1024            │ │
│  │  Pattern: IK (static-static + ephemeral-static)              │ │
│  │  Cipher: ChaCha20-Poly1305                                   │ │
│  │  Hash: SHA-512 (CNSA 2.0)                                    │ │
│  │  Hybrid KEM: X25519 + ML-KEM-1024 simultaneous               │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                     Transport Layer                           │ │
│  │  TLS 1.3 + X25519MLKEM768 (CNSA 2.0 profile)                │ │
│  │  or  QUIC/HTTP3 + same hybrid KEM                            │ │
│  │  or  Raw TCP + Noise transport                               │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                Cryptographic Primitives                       │ │
│  │                                                               │ │
│  │  KEM:     ML-KEM-1024  (NIST FIPS 203, CNSA 2.0 approved)    │ │
│  │  DH:      X25519       (RFC 7748, hybrid component)          │ │
│  │  AEAD:    AES-256-GCM  (NIST FIPS 197 / SP 800-38D)          │ │
│  │           ChaCha20-Poly1305  (RFC 8439, high-perf fallback)  │ │
│  │  Hash:    SHA-512      (FIPS 180-4, CNSA 2.0 ≥ SHA-384)     │ │
│  │  KDF:     HKDF-SHA512  (RFC 5869, CNSA 2.0 compliant)       │ │
│  │  Sign:    ML-DSA-87    (NIST FIPS 204, CNSA 2.0 approved)    │ │
│  │  Backup:  SLH-DSA-128s (NIST FIPS 205, defense-in-depth)    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: Hybrid KEM + Hash Upgrade（2 周）

> **最小可行升级。** 保持现有协议结构，替换底层原语。向下兼容。

### P1a. ML-KEM-1024 + X25519 Hybrid KEM

```rust
// crates/protocol/src/pq.rs
use ml_kem_1024::MlKem1024;   // pure Rust, no_std
use x25519_dalek;              // existing
use hkdf::HkdfSha512;          // upgraded from SHA256
use chacha20poly1305;          // existing (256-bit equivalent AEAD)

pub struct HybridSharedSecret {
    pub ss: [u8; 32],          // derived shared secret
    pub kem_ciphertext: [u8; 1568], // ML-KEM-1024 ciphertext for server
    pub eph_x25519_pk: [u8; 32],    // ephemeral X25519 public key
}

impl HybridSharedSecret {
    /// Hybrid KEM encapsulate: X25519 + ML-KEM-1024 → single 256-bit secret.
    /// Security: breaks only if BOTH X25519 AND ML-KEM-1024 are broken.
    pub fn encapsulate(
        server_x25519_pk: &[u8; 32],
        server_mlkem_pk:  &[u8; 1568],
    ) -> Result<Self, Error> {
        // 1. Ephemeral X25519
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let eph_pk = x25519_dalek::PublicKey::from(&eph);
        let ss_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(*server_x25519_pk));

        // 2. ML-KEM-1024 encaps
        let (ss_kyber, ct) = MlKem1024::encapsulate(server_mlkem_pk, rng)?;

        // 3. Hybrid KDF: ss = HKDF-SHA512(ss_x || ss_kyber, "Nyx v3 PQXDH 2026-07", 32)
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ss_x.as_bytes());
        ikm[32..].copy_from_slice(&ss_kyber);

        let ss = HkdfSha512::extract(None, &ikm)
            .expand(b"Nyx v3 PQXDH 2026-07", 32);

        Ok(HybridSharedSecret {
            ss,
            kem_ciphertext: ct,
            eph_x25519_pk: *eph_pk.as_bytes(),
        })
    }

    /// Decap: server recovers shared secret from KEM ciphertext + eph pk.
    pub fn decapsulate(
        server_x25519_sk: &[u8; 32],
        server_mlkem_sk:  &[u8; 3168], // ML-KEM-1024 secret key
        kem_ct:           &[u8; 1568],
        eph_x25519_pk:    &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let ss_x = x25519_dalek::StaticSecret::from(*server_x25519_sk)
            .diffie_hellman(&x25519_dalek::PublicKey::from(*eph_x25519_pk));
        let ss_kyber = MlKem1024::decapsulate(kem_ct, server_mlkem_sk)?;

        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ss_x.as_bytes());
        ikm[32..].copy_from_slice(&ss_kyber);

        Ok(HkdfSha512::extract(None, &ikm)
            .expand(b"Nyx v3 PQXDH 2026-07", 32))
    }
}
```

### P1b. Wire Format（向下兼容）

```
Frame Layout (v3):
┌──────────────────────────────────────────────────────────────┐
│ Version: u8 = 0x03                                           │
│ Flags: u8                                                    │
│   bit 0 = PQ mode (1 = hybrid KEM, 0 = classic X25519 only)  │
│   bit 1 = ML-DSA signed (1 = signed, 0 = unsigned)           │
├──────────────────────────────────────────────────────────────┤
│ [if PQ mode]                                                 │
│   kem_ciphertext: [u8; 1568]   // ML-KEM-1024 ciphertext     │
│   eph_x25519_pk:  [u8; 32]     // Ephemeral X25519 pubkey    │
├──────────────────────────────────────────────────────────────┤
│ [if signed]                                                  │
│   ml_dsa_sig: [u8; 4627]       // ML-DSA-87 signature        │
├──────────────────────────────────────────────────────────────┤
│ nonce: [u8; 12]                                              │
│ ciphertext: [u8; N]            // AES-256-GCM or ChaCha20    │
│ tag: [u8; 16]                  // AEAD authentication tag    │
└──────────────────────────────────────────────────────────────┘
```

### P1c. AEAD Choice: AES-256-GCM 主 · ChaCha20-Poly1305 备

CNSA 2.0 明确要求 AES-256-GCM。但 ChaCha20-Poly1305 (256-bit) 在无 AES-NI 硬件上快 3x。采用双模式：

- **有 AES-NI** (CPUID 检测): AES-256-GCM (硬件加速)
- **无 AES-NI**: ChaCha20-Poly1305 (软件快速)

---

## 3. Phase 2: Double Ratchet — Per-Message Forward Secrecy（4 周）

> **核心升级。** 当前 Nyx 每会话一个密钥。升级后每消息一个密钥。

### 架构：Signal Double Ratchet + PQ Hybrid

```
Root Key (from Hybrid KEM)
    │
    ├── DH Ratchet (X25519 + ML-KEM-1024 hybrid)
    │   └── Receiving Root Key (RK)
    │
    ├── Symmetric Ratchet
    │   ├── Sending Chain Key (CK_s)
    │   │   └── HKDF-SHA512 → Message Key (MK_s) + next CK_s
    │   └── Receiving Chain Key (CK_r)
    │       └── HKDF-SHA512 → Message Key (MK_r) + next CK_r
    │
    └── Each MK used exactly ONCE → ChaCha20/AES-256 encrypt ONE message → deleted
```

### Key schedule

```rust
// crates/protocol/src/ratchet.rs

pub struct DoubleRatchet {
    // DH ratchet state
    dh_sending_pair: Option<(EphemeralSecret, PublicKey)>,  // our current DH keypair
    dh_receiving_pk: Option<PublicKey>,                       // peer's current DH pubkey
    // Symmetric ratchet state
    root_key: [u8; 32],
    sending_chain: ChainKey,
    receiving_chain: ChainKey,
    // Message counter (anti-replay)
    sending_count: u64,
    receiving_count: u64,
    previous_sending_count: u64,  // skipped message keys
    // PQ state
    kem_last_sent: Option<[u8; 1568]>,      // last KEM ciphertext we sent
    kem_last_received: Option<[u8; 1568]>,  // last KEM ciphertext from peer
}

impl DoubleRatchet {
    /// Encrypt and advance sending chain.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8])
        -> (u64, Vec<u8>)
    {
        let mk = self.sending_chain.derive_message_key();
        let ct = aead_seal(&mk.key, &mk.nonce, plaintext, ad);
        self.sending_chain.advance();
        self.sending_count += 1;
        (self.sending_count - 1, ct)
    }

    /// Decrypt and advance receiving chain.
    pub fn ratchet_decrypt(&mut self, msg_num: u64, ciphertext: &[u8], ad: &[u8])
        -> Result<Vec<u8>, Error>
    {
        // Anti-replay: msg_num must be >= receiving_count
        if msg_num < self.receiving_count {
            return Err(Error::Replay);
        }
        // Skip ahead if needed (out-of-order delivery)
        while self.receiving_count < msg_num {
            self.receiving_chain.advance();
            self.receiving_count += 1;
        }
        let mk = self.receiving_chain.derive_message_key();
        let pt = aead_open(&mk.key, &mk.nonce, ciphertext, ad)?;
        self.receiving_chain.advance();
        self.receiving_count += 1;
        Ok(pt)
    }

    /// DH ratchet step: incorporate peer's new DH public key.
    /// Also performs ML-KEM encaps if PQ mode.
    pub fn dh_ratchet(&mut self, peer_dh_pk: PublicKey, peer_kem_ct: Option<[u8; 1568]>) {
        let ss_dh = self.dh_sending_pair.0.diffie_hellman(&peer_dh_pk);
        let ss_kem = peer_kem_ct.map(|ct| MlKem1024::decapsulate(&self.kem_sk, &ct));
        // Hybrid KDF
        let ss = hybrid_kdf_sha512(ss_dh, ss_kem);
        // Update root key + chains
        let (new_rk, new_ck_s, new_ck_r) = hkdf_derive_chains(&self.root_key, &ss);
        self.root_key = new_rk;
        self.sending_chain = new_ck_s;
        self.receiving_chain = new_ck_r;
    }
}
```

---

## 4. Phase 3: ML-DSA Command Signing（2 周）

> **CNSA 2.0 合规。** 每个 task/command 用 ML-DSA-87 签名，implant 验证后再执行。

```rust
// crates/protocol/src/sign.rs

use ml_dsa_87::MlDsa87;  // FIPS 204

/// Server signs a command before sending.
pub fn sign_command(
    server_sk: &MlDsa87SigningKey,
    command: &Command,
    session_id: &[u8; 32],
    sequence: u64,
) -> [u8; 4627]  // ML-DSA-87 signature size
{
    let mut msg = Vec::new();
    msg.extend_from_slice(session_id);
    msg.extend_from_slice(&sequence.to_le_bytes());
    msg.extend_from_slice(&command.encode());
    server_sk.sign(&msg)
}

/// Implant verifies command signature before execution.
pub fn verify_command(
    server_pk: &MlDsa87VerifyingKey,
    command: &Command,
    session_id: &[u8; 32],
    sequence: u64,
    signature: &[u8; 4627],
) -> Result<(), Error>
{
    let mut msg = Vec::new();
    msg.extend_from_slice(session_id);
    msg.extend_from_slice(&sequence.to_le_bytes());
    msg.extend_from_slice(&command.encode());
    server_pk.verify(&msg, signature)
}
```

---

## 5. Phase 4: Noise Protocol Standardization（3 周）

> **替换自定义 Frame 格式为标准 Noise 协议。** 行业审查更充分，互操作更强。

### Noise Pattern: `Noise_IK_25519_MLKEM1024_ChaChaPoly_SHA512`

```
Pattern: IK
  <- s (static key from server, pre-shared)
  ...
  -> e, es, s, ss    (client: ephemeral + static)
  <- e, ee, se       (server: ephemeral)

Hybrid KEM integration:
  - Each DH operation: X25519 DH + ML-KEM-1024 encaps
  - Handshake output: 2 CipherStates (send + recv)
  - Transport: CipherState.EncryptWithAd / DecryptWithAd
```

### Implementation

```rust
// crates/protocol/src/noise.rs
use snow::{Builder, HandshakeState, TransportState};

pub fn build_noise_handshake(
    server_static_pk: &[u8; 32],
    server_mlkem_pk: &[u8; 1568],
) -> HandshakeState {
    let mut builder = Builder::new(
        "Noise_IK_25519_MLKEM1024_ChaChaPoly_SHA512"
            .parse()
            .expect("valid pattern")
    );
    builder.local_private_key(&our_static_sk);
    builder.remote_public_key(server_static_pk);
    builder.set_pq_public_key(server_mlkem_pk);  // PQ extension
    builder.build_handshake_state()
}
```

---

## 6. Implementation Roadmap

```
Week 1-2:  P1 Hybrid KEM + SHA-512 upgrade (minimal diff)
           └─ crates/protocol/src/pq.rs
           └─ Frame v3 wire format (backward compatible flag)
           └─ cargo test --workspace (must pass all 88 tests)

Week 3-6:  P2 Double Ratchet
           └─ crates/protocol/src/ratchet.rs
           └─ Per-message key derivation + anti-replay
           └─ DH ratchet with PQ hybrid

Week 7-8:  P3 ML-DSA Command Signing
           └─ crates/protocol/src/sign.rs
           └─ server::sign + implant::verify
           └─ Malformed signature → implant self-quarantine

Week 9-11: P4 Noise Protocol Standardization
           └─ crates/protocol/src/noise.rs
           └─ Replace Frame::seal/open with Noise transport
           └─ Backward compatibility: v2 Frame fallback for legacy implants
```

---

## 7. CNSA 2.0 Compliance Checklist

| 要求 | 状态 | 实现 |
|------|------|------|
| **AES-256-GCM** 对称加密 | ✅ P1c | 有 AES-NI 时激活 |
| **SHA-384 or SHA-512** 哈希 | ✅ P1a | HKDF-SHA512 |
| **ML-KEM-1024** 密钥交换 | ✅ P1a | X25519 + ML-KEM-1024 混合 |
| **ML-DSA-87** 数字签名 | ✅ P3 | 命令签名 + 验证 |
| **SLH-DSA-128s** 备选签名 | ✅ P3 | `#[cfg(feature = "slh-dsa")]` |
| **Per-message forward secrecy** | ✅ P2 | Double Ratchet |
| **Post-compromise security** | ✅ P2 | DH ratchet recovery |
| **Anti-replay** | ✅ 现有 | 单调计数器 + Double Ratchet msg_num |
| **Noise or standard protocol** | ✅ P4 | Noise_IK pattern |
| **TLS 1.3 Hybrid KEM** (transport) | ✅ | X25519MLKEM768 via rustls |
| **NIST FIPS validated modules** | ⚠️ | 使用 NIST-validated crates: `ml-kem`, `ml-dsa` |

---

## 8. 即刻行动

```
1. P1a — cargo add ml-kem-1024 ml-dsa-87 (pure Rust, no_std compatible)
2. P1a — Create crates/protocol/src/pq.rs: HybridSharedSecret
3. P1b — Frame v3 wire format: version byte 0x03 + PQ flag
4. P1c — CPUID AES-NI detection → AEAD selector
```
