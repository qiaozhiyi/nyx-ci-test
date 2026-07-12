# Nyx Implant Generation System — Architecture & Implementation Plan

> **Date:** 2026-07-12  
> **Status:** Planning  
> **Goal:** Operator-facing server-side implant generation, crypographically per-implant uniqueness, sRDI shellcode conversion, mutation engine.  
> **Principles:** Use existing crypto stack exclusively (X25519+HKDF+ChaCha20-Poly1305). Zero XOR, zero weak primitives. Per-implant unique binary every time.

---

## 1. Current State & Gap Analysis

### 1.1 What We Already Have

| Component | File | Status |
|---|---|---|
| X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD | `crates/protocol/src/crypto.rs` | ✅ Complete |
| Per-build config encryption (ChaCha20-Poly1305) | `crates/config/src/lib.rs` | ✅ Complete |
| Compile-time config embedding via proc-macro | `crates/config-macros/src/lib.rs` | ✅ Complete |
| Server keypair persistence (NYX_KEYFILE) | `crates/server/src/main.rs:64-71` | ✅ Complete |
| Server AppState (sessions, keypair, store, audit) | `crates/server/src/lib.rs:73-103` | ✅ Complete |
| REST API framework (axum) | `crates/server/src/lib.rs:319-345` | ✅ 13 endpoints |
| SQLite credential store (rusqlite, WAL) | `crates/store/src/store.rs` | ✅ Complete |
| Audit log (hash-chained) | `crates/server/src/audit.rs` | ✅ Complete |
| PEB-walk + djb2 API resolution | `crates/implant-win/src/resolve.rs` | ✅ Complete |
| Basic sRDI extractor (NYX1 header) | `tools/srdi/src/main.rs` | 🟡 v1 only (no loader) |
| CI pipeline (DLL build + selftest) | `.github/workflows/windows-ci.yml` | ✅ Complete |
| Evasion kits (Fluctuation, ModuleStomp) | `crates/implant-win/src/kits.rs` | ✅ Complete |

### 1.2 What's Missing

| Category | Gap | Severity |
|---|---|---|
| **Implant Generation** | No `/api/generate-implant` endpoint | 🔴 Critical |
| **Per-Implant Keys** | Every implant shares the same `server_pub`, no per-implant keypair | 🔴 Critical |
| **One-Time Auth** | No token system — captured DLL can replay-connect to C2 | 🔴 Critical |
| **Environment Keying** | No binding to target machine identity | 🔴 Critical |
| **Binary Uniqueness** | Same DLL SHA256 every time — YARA-signable | 🔴 Critical |
| **sRDI Shellcode** | `tools/srdi` extracts `.text` but doesn't emit self-loading PIC blob | 🟡 Important |
| **Mutation Engine** | No per-generation binary randomization | 🟡 Important |
| **Payload Store** | No version control or management of generated payloads | 🟡 Important |

---

## 2. Reference Architecture (Industry Survey)

Our design draws from the following patterns observed in top-tier C2s as of July 2026:

| Framework | Pattern Adopted | What We Adapt |
|---|---|---|
| **Cobalt Strike 4.13** | Payload Store, Malleable Profile Overrides | Centralized payload version management |
| **Cobalt Strike 4.11** | sRDI prepend loader (default), stage.transform-obfuscate | DLL → PIC shellcode conversion |
| **Brute Ratel C4 v2.3** | Custom compiler, safe_http, per-payload uniqueness | Per-implant compiler-level uniqueness |
| **Nighthawk 0.4** | Stackable environment keying, mutation engine, Stager Kit | Multi-layer HKDF keying, binary mutation |
| **Sliver** | Per-binary X.509 certs, sRDI pipeline, polymorphic encoders | Implant crypto generation, shellcode conversion |
| **ShardC2** | Implant key per session, PostgreSQL-backed builds | Token management DB schema |
| **Avocado C2** | Docker cargo build for Rust implants | Cross-compilation pipeline |

### 2.1 Key Design Decisions

1. **No Docker cargo build on server.** Unlike Avocado/Linky, we pre-compile the DLL template (via CI) and patch at request time. This gives sub-100ms generation without requiring a Rust toolchain on the server.

2. **ChaCha20-Poly1305 config encryption, not XOR.** The `config` crate already uses ChaCha20-Poly1305. We extend this pattern to per-implant config blobs rather than downgrading to XOR.

3. **Per-implant X25519 keypair.** Each implant gets its own ephemeral keypair. The implant's public key IS its identity (already the wire protocol design). The private key is encrypted in the config blob.

4. **HKDF-based multi-layer keying.** Inspired by Nighthawk's stackable keying but using HKDF-SHA256 rather than XOR chains.

5. **Mutation at the binary level.** Since we pre-compile, we apply post-compilation transformations: NOP insertion, instruction substitution, string key randomization, register rotation.

---

## 3. System Architecture

### 3.1 Overall Data Flow

```
┌── CI Pipeline (offline, one-time) ──────────────────────────────┐
│  cargo +nightly build --release --features selftest               │
│  → nyx_implant_win.dll (template)                                 │
│  → Upload to server as base template                              │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌── Server: POST /api/generate-implant ────────────────────────────┐
│  Input: { callback, format, keying, evasion_options }             │
│                                                                    │
│  Step 1: Generate per-implant secrets                              │
│    - X25519 implant_keypair (ephemeral)                            │
│    - 32B auth_token (random, one-time)                             │
│    - 32B config_key (HKDF-derived)                                 │
│                                                                    │
│  Step 2: Build config blob                                         │
│    - server_pub ‖ auth_token ‖ implant_priv ‖ callback ‖ features  │
│    - Encrypt: ChaCha20-Poly1305(config_key, nonce, plaintext)      │
│                                                                    │
│  Step 3: Patch DLL template                                        │
│    - Find 0xAA * 1024 placeholder in .nyx_cfg section              │
│    - Write: [4B magic 0xDEADBEEF][2B config_len][encrypted_config] │
│                                                                    │
│  Step 4: (Optional) sRDI conversion                                │
│    - Prepend PIC loader stub                                       │
│    - Apply mutation engine                                         │
│    → Output: PIC shellcode blob                                    │
│                                                                    │
│  Step 5: Store + return                                             │
│    - INSERT INTO implants (auth_token, implant_pub, created_at,    │
│      expires_at, callback, features)                               │
│    - Return binary as application/octet-stream                     │
│                                                                    │
│  ⏱️ < 100ms (template patch only)                                  │
│  ⏱️ < 2s (with sRDI + mutation)                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 DLL Template Placeholder Layout

```
Section .nyx_cfg (new section appended at build time via linker script):

Offset  Size   Content
────────────────────────────────────────
0x000   4      Magic placeholder marker: 0x41414141 ("AAAA")
0x004   4      Config blob max size (u32 LE, default 1024)
0x008   1024   0xAA padding (placeholder bytes)

After patching by server:
────────────────────────────────────────
0x000   4      Magic: 0xDEADBEEF (indicates "patched")
0x004   2      Config actual length (u16 LE)
0x006   N      Encrypted config (ChaCha20-Poly1305)
0x006+N 16     Poly1305 authentication tag
0x006+N+16..   Padding to 1024-byte boundary (0x00)
```

### 3.3 Config Blob Structure (Plaintext)

```
[1B]   version (u8, = 1)
[32B]  server_pub (X25519, from server keypair)
[32B]  auth_token (random, one-time use)
[32B]  implant_x25519_secret (private key of per-implant keypair)
[2B]   callback_host_len (u16 LE)
[N]    callback_host (ASCII, e.g. "1.2.3.4")
[2B]   callback_port (u16 LE)
[4B]   features_bitmap (u32 LE):
          bit 0: foliage_enabled
          bit 1: module_stomp_enabled
          bit 2: hwbp_blind
          bit 3: unhook_enabled
          bit 4: caller_spoof
          bit 5: proxy_veh
          bit 6: pool_party_enabled
          bit 7: insomniac_unwinding
          bits 8-31: reserved
[4B]   keying_levels (u32 LE): number of HKDF layers required
[8B]   expires_at (u64 LE, Unix timestamp, 0 = no expiry)
[4B]   config_checksum (first 4 bytes of BLAKE3 hash of all above)

Total: ~160 bytes (variable due to callback_host)
```

### 3.4 Per-Implant Crypto Stack

```
Generation (Server):

  implant_kp = X25519::generate()           // per-implant ephemeral keypair
  config_key = HKDF-SHA256(
    ikm:   ECDH(server_priv, implant_kp.public),
    salt:  "nyx-implant-config-v1",
    info:  server_pub ‖ implant_kp.public
  )
  config_nonce = OsRng::gen::<[u8; 12]>()

  encrypted_config = ChaCha20-Poly1305::seal(
    key:   config_key,
    nonce: config_nonce,
    aad:   server_pub ‖ implant_kp.public,
    msg:   config_plaintext
  )

  // embedded in DLL .nyx_cfg section:
  //   [0xDEADBEEF] [config_len] [config_nonce ‖ encrypted_config ‖ tag]

Loading (Implant, DllMain or nyx_entry):

  // 1. Read .nyx_cfg section
  if magic != 0xDEADBEEF → fallback to compile-time defaults (dev mode)
  
  // 2. Extract config_nonce and ciphertext
  config_nonce = read(nonce_offset, 12)
  encrypted = read(config_offset, config_len)

  // 3. Derive config_key using embedded implant private key
  implant_pub = X25519::public_from_secret(embedded_secret)
  shared = X25519::diffie_hellman(embedded_secret, baked_server_pub)
  config_key = HKDF-SHA256(ikm: shared, salt: "nyx-implant-config-v1",
                           info: server_pub ‖ implant_pub)

  // 4. Decrypt + verify tag
  plaintext = ChaCha20-Poly1305::open(
    key: config_key, nonce: config_nonce,
    aad: server_pub ‖ implant_pub,
    ct: encrypted
  )? → verified → parse config fields

  // 5. Use config
  auth_token → sent to server on first check-in
  callback → used for beacon connection
  features → set runtime feature gates
```

### 3.5 Environment Keying (HKDF Multi-Layer)

```
Base config_key = HKDF-SHA256(ECDH(implant_priv, server_pub), ...)

If keying_levels > 0, apply additional HKDF layers:

  Layer 1 (username_key):
    username = GetUserNameW()
    config_key = HKDF-SHA256(config_key, b"env-layer-1", username ‖ domain)

  Layer 2 (machine_key):
    machine_sid = LookupAccountSidW()
    config_key = HKDF-SHA256(config_key, b"env-layer-2", machine_sid)

  Layer 3 (network_key):
    ip_mac = get_primary_ip() ‖ get_mac_address()
    config_key = HKDF-SHA256(config_key, b"env-layer-3", ip_mac)

  Layer 4 (temporal_key):
    pid = GetCurrentProcessId()
    tick = GetTickCount64() / 1000  // coarse seconds
    config_key = HKDF-SHA256(config_key, b"env-layer-4", pid ‖ tick)

Each layer is OPTIONAL. Operator selects at generation time: { layers: ["username", "machine"] }.
Wrong environment → HKDF produces wrong key → ChaCha20 tag verification fails → implant exits silently.
```

### 3.6 One-Time Authentication Token

```
First check-in (implant → server):

  POST /beacon
  Body: [32B implant_pub][8B counter=0][chechkin_frame(auth_token in AAD)]

Server validation:
  1. Read auth_token from decrypted frame AAD
  2. Query DB: SELECT * FROM implant_tokens WHERE token = auth_token
  3. Check: NOT expired AND NOT used
  4. If valid → mark as used, bind to session
  5. If invalid/used → reject, log to deauth.log

Token rotation:
  POST /api/implant/{session_id}/rotate-token
  → Server generates new auth_token
  → Sends via encrypted task to implant
  → Old token invalidated
  → New token takes effect next check-in
```

### 3.7 sRDI Shellcode Conversion

```
Input:  Patched DLL (from Step 3)
Output: Position-independent shellcode blob

Architecture:
  ┌─────────────────────────────────────────────┐
  │  PIC Loader Stub (Rust #![no_std], ~3KB)    │
  │                                              │
  │  Phase 1: Self-locate (call/pop trick)       │
  │  Phase 2: PEB walk → ntdll (resolve.rs)      │
  │  Phase 3: Find embedded encrypted DLL         │
  │  Phase 4: Derive key (HKDF from stub hash)   │
  │  Phase 5: ChaCha20 decrypt DLL                │
  │  Phase 6: Reflective PE load:                 │
  │    - Allocate memory (NtAllocateVirtualMemory)│
  │    - Copy headers + sections                  │
  │    - Process relocations                      │
  │    - Resolve imports (PEB walk + djb2)       │
  │    - Apply section permissions                │
  │    - Call DllMain(DLL_PROCESS_ATTACH)         │
  │  Phase 7: Call nyx_entry() if export found   │
  │                                              │
  │  Zero IAT. Pure PIC. No RWX (RW→RX flip).   │
  └─────────────────────────────────────────────┘

Output format:
  [PIC loader stub (~3KB)]
  [4B magic: 0x4E595831 "NYX1"]
  [4B encrypted_dll_len (u32 LE)]
  [12B ChaCha20 nonce]
  [encrypted DLL]
  [16B Poly1305 tag]
```

### 3.8 Mutation Engine

```
Applied during sRDI conversion. Each generation produces different bytes.

Mutations:
  1. NOP insertion
     - Insert 0-16 random NOP-equivalent bytes between basic blocks
     - Variants: nop, xchg eax,eax, lea rax,[rax+0], mov edi,edi

  2. Instruction substitution (semantically equivalent, different bytes)
     - mov rax, 0   →  xor eax, eax
     - add rax, 1   →  inc rax (when flags not needed)
     - push rax; pop rbx  →  mov rbx, rax
     - lea rcx, [addr]   →  mov rcx, addr (when position-dependent)

  3. Register rotation (non-ABI-critical paths only)
     - Swap r8↔r9, r10↔r11, r12↔r13, r14↔r15 usage

  4. String key randomization
     - Each string XOR/ChaCha20 key unique per build
     - No two implants share the same key for any string

  5. djb2 seed randomization
     - Initial hash seed different per build
     - API hash values change → IAT pattern changes

  6. Call stub randomization
     - Prepended call-to-resolve stub at random offset
     - Different number of push/pop pairs in prologue

  ⏱️ < 500ms for all mutations
  Result: SHA256 completely different each time
```

### 3.9 Payload Store

```
Database table: implants

CREATE TABLE implants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    implant_pub     TEXT NOT NULL UNIQUE,        -- hex-encoded X25519 public key
    auth_token_hash TEXT NOT NULL,               -- BLAKE3(auth_token) for lookup
    auth_token_used INTEGER NOT NULL DEFAULT 0,  -- 0 = fresh, 1 = consumed
    created_at      TEXT NOT NULL,               -- ISO 8601
    created_by      TEXT,                        -- operator username
    expires_at      TEXT,                        -- ISO 8601 or NULL
    callback_host   TEXT NOT NULL,
    callback_port   INTEGER NOT NULL,
    format          TEXT NOT NULL,               -- "dll" | "shellcode" | "exe"
    features_bitmap INTEGER NOT NULL DEFAULT 0,
    keying_levels   INTEGER NOT NULL DEFAULT 0,
    sha256          TEXT NOT NULL,               -- hex-encoded SHA256 of output binary
    size_bytes      INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    notes           TEXT
);

CREATE INDEX idx_implants_pub ON implants(implant_pub);
CREATE INDEX idx_implants_token ON implants(auth_token_hash);
CREATE INDEX idx_implants_created ON implants(created_at);
```

---

## 4. Implementation Plan

### Phase 1: Config Placeholder + Server Endpoint (Week 1)

**crates/implant-win/src/config_placeholder.rs** (new file, ~80 LOC):
```
- #[link_section = ".nyx_cfg"] static NYX_CONFIG: [u8; 1024] = [0xAA; 1024]
- pub fn load_runtime_config() -> ParsedConfig { ... }
- Magic detection: 0xDEADBEEF vs 0x41414141
- ChaCha20-Poly1305 decrypt path
- Fallback to compile-time config if not patched
```

**crates/server/src/implant_gen.rs** (new file, ~150 LOC):
```
- POST /api/generate-implant handler
- Generate per-implant X25519 keypair
- Generate 32B auth_token
- Build config plaintext (struct → bytes)
- HKDF config_key derivation
- ChaCha20-Poly1305 encrypt config
- Find 0xAA placeholder in DLL template
- Write magic + encrypted config
- INSERT into implants table
- Return binary
```

**crates/store/src/store.rs** (add ~50 LOC):
```
- impl CredStore: create table implants (or new ImplantStore struct)
- insert_implant()
- mark_token_used()
- list_implants()
- revoke_implant()
- get_implant_by_token()
```

### Phase 2: sRDI Loader (Week 2)

**crates/nyx-loader** (new crate, ~400 LOC):
```
- #![no_std] + #![no_main]
- PIC self-locate (call/pop)
- PEB walk → ntdll/kernel32 (reuse resolve.rs logic)
- ChaCha20 decrypt embedded DLL
- Reflective PE loader:
  - NtAllocateVirtualMemory
  - Copy headers + sections
  - Process base relocations (.reloc section)
  - Build import table (PEB walk + djb2)
  - NtProtectVirtualMemory (set section permissions)
  - DllMain(DLL_PROCESS_ATTACH)
  - Optional: call nyx_entry()
- Build script: compile to .o → objcopy .text → embed as bytes
```

**tools/srdi/src/main.rs** (update, ~150 LOC):
```
New --loader flag: embed PIC loader stub
New --encrypt flag: ChaCha20 encrypt DLL portion
Output format change: [loader stub][NYX1 header][encrypted DLL]
```

### Phase 3: Environment Keying + One-Time Token (Week 2-3)

**crates/implant-win/src/entry.rs** (modify, ~60 LOC):
```
- In nyx_entry / DllMain: call load_runtime_config()
- If magic == 0xDEADBEEF:
  - Derive config_key via HKDF
  - Apply environment keying layers if configured
  - Decrypt config
  - Store auth_token for first check-in
```

**crates/implant-win/src/beacon.rs** (modify, ~30 LOC):
```
- First check-in: include auth_token in SessionInfo AAD
- Handle server response: token_rotated, token_revoked
```

**crates/server/src/lib.rs** (modify, ~40 LOC):
```
- Beacon handler: extract auth_token from frame AAD
- Validate against implants table
- Mark as used on first successful check-in
- POST /api/implant/{id}/rotate-token
- POST /api/implant/{id}/revoke
```

### Phase 4: Mutation Engine + Payload Store UI (Week 3-4)

**crates/nyx-mutate** (new crate, ~300 LOC):
```
- Binary manipulation library
- NOP insertion pass
- Instruction substitution pass
- Register rotation pass
- String key randomization pass
- djb2 seed randomization pass
- Call stub randomization pass
- Deterministic: same seed → same output (for reproducibility)
```

**crates/client-cli/src/tui/** (modify, ~100 LOC):
```
- /generate command: POST /api/generate-implant
- /implants command: list generated implants
- /revoke <id> command
- /payload-info <id> command
```

---

## 5. Security Properties

| Property | Mechanism | Status |
|---|---|---|
| Per-implant keypair | X25519 ephemeral generation per implant | Phase 1 |
| Config confidentiality | ChaCha20-Poly1305 AEAD (existing crypto) | Phase 1 |
| Config integrity | Poly1305 tag verification on load | Phase 1 |
| Anti-replay | One-time auth token, DB-enforced | Phase 2 |
| Environment binding | HKDF multi-layer keying (optional) | Phase 3 |
| Binary uniqueness | Mutation engine + per-build random keys | Phase 4 |
| Token revocation | Server-side DB-based, operator-triggered | Phase 2 |
| Forward secrecy (comms) | Already: ECDH per session with monotonic counter | ✅ Existing |
| Forward secrecy (config) | Per-implant keypair ensures compromise of one implant ≠ compromise of all | Phase 1 |

## 6. Files Changed Summary

| File | Action | LOC |
|---|---|---|
| `crates/implant-win/src/config_placeholder.rs` | Create | ~80 |
| `crates/implant-win/src/entry.rs` | Modify | +60 |
| `crates/implant-win/src/beacon.rs` | Modify | +30 |
| `crates/server/src/implant_gen.rs` | Create | ~150 |
| `crates/server/src/lib.rs` (routes) | Modify | +50 |
| `crates/server/src/main.rs` (template loading) | Modify | +30 |
| `crates/store/src/implant_store.rs` | Create | ~80 |
| `crates/store/src/store.rs` (or new) | Modify | +50 |
| `crates/nyx-loader/` | Create | ~400 |
| `tools/srdi/src/main.rs` | Modify | +150 |
| `crates/nyx-mutate/` | Create | ~300 |
| `crates/client-cli/src/tui/` | Modify | +100 |
| `docs/NYX_IMPLANT_GENERATION_ARCHITECTURE.md` | This document | — |
| **Total** | | **~1,480 LOC** |

## 7. References

- Cobalt Strike 4.13 (June 2026): Beacon Interpreter, BOF-PE, LLVM Beacon, Payload Store
- Cobalt Strike 4.11 (March 2025): prepend/sRDI loader, stage.transform-obfuscate, async BOFs
- Brute Ratel C4 v2.3 Flux (October 2025): custom compiler, safe_http, coffexec_async
- Brute Ratel C4 Mercury v2.5 (March 2026): private feature updates
- Nighthawk 0.4 Janus (September 2025): Open Agent, NHStager, Plugin Loader, Mutation Engine
- Nighthawk Labs (May 2026): Configurator, HawkEye AI, Python Modules
- Sliver: per-binary X.509 certs, sRDI pipeline, Donut integration
- ShardC2: implant key per session, PostgreSQL-backed build pipeline
- Avocado C2: Docker-based cargo build + rust-embed certificate baking
- sRDI (Monoxgas/SBS): original shellcode reflective DLL injection
- InfraGuard: one-time payload tokens with SQLite enforcement
