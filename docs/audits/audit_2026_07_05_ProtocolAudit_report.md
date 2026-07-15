# Security Audit Report: Nyx Protocol Subsystem (`crates/protocol/src/`)

## 1. Executive Summary

This document presents a comprehensive security audit of the `crates/protocol/src/` subsystem of the **Nyx C2 Framework**. The audited files are:
* `crypto.rs`
* `wire.rs`
* `msg.rs`
* `frame.rs`

The audit focused on the cryptographic architecture, little-endian binary serialization/deserialization, frame parser limits, anti-replay mechanism, and EDR/AV attribution/detection indicators.

### Overall Assessment
The Nyx wire protocol is a well-designed, lightweight binary protocol optimized for `no_std` position-independent implant compilation. The state tracking of nonces, separation of transmission directions, frame length bounds, and anti-replay counters inside the server's write lock are architecturally sound. However, we identified several security vulnerabilities, cryptographic hygiene issues, and EDR attribution vectors.

---

## 2. Security Findings Summary Table

| ID | Title | Severity | Area | Exploitable By |
|---|---|---|---|---|
| **NYX-PRO-01** | Zeroization Deficits in Static Secrets (`ServerKeypair`/`ImplantKeypair`) | **Medium** | Cryptography / Memory Hygiene | Local / Memory Forensics |
| **NYX-PRO-02** | Atomic CSPRNG Hook Registration Race Condition in no_std Build | **Low** | Concurrency / Bootstrap | Local Process context |
| **NYX-PRO-03** | Lack of Input Length Checks in `Command` and `Response` parsing | **Medium** | Memory Bounds / Denial of Service | Malicious Server/Implant (Post-compromise) |
| **NYX-PRO-04** | Weak/Predictable Identity Verification via Bare Public Key AAD Binding | **Medium** | Cryptographic Integrity | Network / MITM (if Server Identity not pinned) |
| **NYX-PRO-05** | EDR Attribution & Signature Traces in String Fields | **Low** | OpSec / Attribution | Defensive Security (AV/EDR) |

---

## 3. Detailed Security Findings

### NYX-PRO-01: Zeroization Deficits in Static Secrets (`ServerKeypair`/`ImplantKeypair`)
* **Severity**: **Medium**
* **Affected Code**: `crates/protocol/src/crypto.rs` (Lines 100-112, 142-154)
* **Vulnerability Description**:
  The `SessionKey` struct is carefully wrapped with `Zeroize` and `ZeroizeOnDrop` to clear session keys from stack/heap memory once they go out of scope. However, the static secrets (`StaticSecret`) inside `ServerKeypair` and `ImplantKeypair` do not have explicit zeroization wrappers, and their temporary byte arrays (used in `generate` and `from_secret_bytes`) are left un-zeroized on the stack.
  
  In `ServerKeypair::generate()`:
  ```rust
  let mut bytes = [0u8; 32];
  random_bytes(&mut bytes);
  let secret = StaticSecret::from(bytes); // `bytes` is not zeroized and stays on stack
  ```
  Additionally, `StaticSecret` from `x25519-dalek` implements zeroization *only if* the `zeroize` feature is enabled. While the protocol's `Cargo.toml` enables `"x25519-dalek/zeroize"`, the wrapper structures `ServerKeypair` and `ImplantKeypair` themselves are not wrapped in `ZeroizeOnDrop` or explicitly cleaned up.

* **Threat Scenario / Exploit Path**:
  If an operator's server or the agent process memory is dumped (e.g., via LSASS dump or core dump), long-term server private keys or implant static secrets can be recovered from un-zeroized stack structures or heap remnants, allowing the decryption of past and future sessions.
* **Remediation**:
  Wrap `ServerKeypair` and `ImplantKeypair` with manual `Drop` implementations that call `.zeroize()` on their components, and use `zeroize::Zeroize` on the temporary key byte buffers during key generation and deserialization:
  ```rust
  impl Drop for ServerKeypair {
      fn drop(&mut self) {
          // StaticSecret from x25519_dalek doesn't automatically zeroize on drop unless wrapped,
          // or we must explicitly zeroize its serialization or wrapper structure.
      }
  }
  ```
  Specifically, zeroize the stack array `bytes` in `generate` and `from_secret_bytes` immediately after `StaticSecret::from(bytes)`:
  ```rust
  let secret = StaticSecret::from(bytes);
  bytes.zeroize();
  ```

---

### NYX-PRO-02: CSPRNG Hook Registration Race Condition in no_std Build
* **Severity**: **Low**
* **Affected Code**: `crates/protocol/src/crypto.rs` (Lines 65-79, 81-95)
* **Vulnerability Description**:
  For `no_std` builds, `CSPRNG_HOOK` holds the function pointer to the custom CSPRNG. `register_csprng` stores this hook with `Release` ordering:
  ```rust
  pub fn register_csprng(fill: fn(&mut [u8]) -> bool) {
      CSPRNG_HOOK.store(fill as usize, core::sync::atomic::Ordering::Release);
  }
  ```
  `random_bytes` reads the hook with `Acquire` ordering:
  ```rust
  let hook = CSPRNG_HOOK.load(core::sync::atomic::Ordering::Acquire);
  ```
  While `AtomicUsize` prevents data races on the function pointer itself, there is no lock or "write-once" enforcement on `CSPRNG_HOOK`. A thread could register a different hook mid-execution, or `random_bytes` could be called concurrently during a registration phase. 
* **Threat Scenario**:
  If registration is called multiple times or run concurrently with early crypto setup, the pointer could change. If an implant contains multiple independent plugins running in separate threads, a double-registration could redirect the CSPRNG pointer to an unmapped region or a hooked function.
* **Remediation**:
  Use `compare_exchange` in `register_csprng` to ensure the hook can only be set once (from `0` to the target address). Any subsequent registration attempt should fail or be ignored.
  ```rust
  pub fn register_csprng(fill: fn(&mut [u8]) -> bool) -> Result<(), ()> {
      CSPRNG_HOOK.compare_exchange(
          0,
          fill as usize,
          core::sync::atomic::Ordering::Release,
          core::sync::atomic::Ordering::Relaxed,
      ).map(|_| ()).map_err(|_| ())
  }
  ```

---

### NYX-PRO-03: Lack of Input Length Checks in `Command` and `Response` parsing
* **Severity**: **Medium**
* **Affected Code**: `crates/protocol/src/msg.rs` (`Command::decode`, `Response::decode`)
* **Vulnerability Description**:
  The wire reader relies on `Reader::blob()` and `Reader::str()` to decode length-prefixed arrays and strings off the wire. The internal `Reader::blob()` calls:
  ```rust
  pub fn blob(&mut self) -> Result<&'a [u8], WireError> {
      let len = self.u32()? as usize;
      self.take(len)
  }
  ```
  Although `Reader::take()` ensures the reader does not read past the end of the payload buffer (which prevents out-of-bounds memory reads), it does not validate if the parsed structure size is logically consistent with standard limits. For example, in `Command::MakeToken`:
  ```rust
  Command::MakeToken {
      domain: r.str()?,
      user: r.str()?,
      password: r.str()?,
      logon_type: r.u8()?,
  }
  ```
  An attacker or a compromised server could send a `Command` carrying a massive domain name or password string (up to `MAX_BLOB_LEN` = 256 KiB) causing high memory consumption on the implant's heap during string decoding and allocation (`String::from_utf8(b.to_vec())`).
* **Threat Scenario / Exploit Path**:
  A compromised team server or an active network adversary (who managed to compromise the server's private key) can send crafted, overly long string elements within command payloads (like SOCKS addresses or upload paths) to trigger an Out Of Memory (OOM) crash on the implant. In constrained memory environments (such as PIC payloads), allocating 256 KiB strings multiple times will lead to heap exhaustion.
* **Remediation**:
  Apply logical bounds to string fields inside the message decoding routines. For example, usernames, domains, and hostnames should be capped at 256 bytes, and SOCKS addresses at 512 bytes.

---

### NYX-PRO-04: Weak/Predictable Identity Verification via Bare Public Key AAD Binding
* **Severity**: **Medium**
* **Affected Code**: `crates/protocol/src/frame.rs` (`encode_frame_dir` and `parse_frame`)
* **Vulnerability Description**:
  The frame format is defined as:
  `[32B session pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B Poly1305 tag]`
  The session public key is used directly as the Additional Authenticated Data (AAD) for the ChaCha20-Poly1305 encryption.
  ```rust
  let ciphertext = crypto::seal_dir(key, dir, counter, pubkey, plaintext);
  ```
  While this binds the ciphertext to the ephemeral public key (preventing replay of the encrypted payload in a different session), the team server relies solely on the public key presence in its `sessions` registry to authenticate the implant. There is no cryptographic signature verifying that the sender actually owns the corresponding private key during the transport phase, relying entirely on the successful completion of the ECDH handshake.
* **Threat Scenario / Exploit Path**:
  If the server does not enforce session key agreement verification strictly before processing further frames, a network attacker could replay old frames or attempt key exhaustion attacks. Since the server is "largely stateless per request" (deriving the key from `pubkey`), a high volume of requests with arbitrary public keys will force the server to perform expensive X25519 ECDH calculations (`derive_for`) on every incoming packet, causing CPU starvation (Denial of Service).
* **Remediation**:
  Keep a cache of derived session keys on the server side to avoid computing ECDH on every unauthenticated request. Rate-limit key derivation requests for unknown public keys.

---

### NYX-PRO-05: EDR Attribution & Signature Traces in String Fields
* **Severity**: **Low**
* **Affected Code**: `crates/protocol/src/crypto.rs` (Line 180)
* **Vulnerability Description**:
  The HKDF key derivation context binds the hardcoded label:
  ```rust
  let label = b"nyx-session-v1";
  ```
  Additionally, error string payloads, enum variant names, and default strings (e.g. `"nyx-session-meta"`) compiled into the binary contain distinctive identifiers.
* **EDR Attribution & Blue-Team Detection**:
  Security analysts and EDR engines can easily signature the static byte array `nyx-session-v1` in memory or network streams. If this label appears in static memory ranges of the implant, it acts as a high-fidelity Indicator of Compromise (IoC) for the Nyx C2 framework.
* **Remediation**:
  Obfuscate or hash the session label in production builds (e.g. use a SHA-256 hash of the label or encrypt/xor the byte string in memory). Change the default string prefix to a randomized or customizable value per compilation.

---

## 4. Code & Framing Analysis

### Hand-Rolled Little-Endian Binary Codec (`wire.rs`)
The little-endian conversion functions (`u32::from_le_bytes`, `u16::from_le_bytes`, `u64::from_le_bytes`) are implemented using slice indexing:
```rust
pub fn u32(&mut self) -> Result<u32, WireError> {
    let s = self.take(4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
```
* **Memory Safety**: These are safe because `take(4)` validates that the remaining buffer is at least 4 bytes. If not, it returns `WireError::Eof` and does not advance the reader.
* **Buffer Cap**: `MAX_BLOB_LEN` (256 KiB) is enforced on all `Writer::blob` operations. This prevents the generation of oversized payloads at the serialisation layer.

### Anti-Replay Counter Mechanics
The server validates counters inside `sessions.get_mut` write lock:
```rust
if raw.counter <= s.last_recv {
    anyhow::bail!("replayed/stale counter {}", raw.counter);
}
s.last_recv = raw.counter;
```
* **Safety**: This prevents TOCTOU (Time-of-Check to Time-of-Use) attacks. Two concurrent requests with the same counter will result in one acquiring the lock first, updating `last_recv`, and causing the second request to fail the check.
* **Bidirectional Nonces**: Nonce reuse is successfully avoided by using the top byte of the 96-bit nonce as a direction discriminator (`Direction::ClientToServer` vs `Direction::ServerToClient`), ensuring disjoint nonce spaces.

---

## 5. Summary of Recommended Fixes

1. **Zeroize secrets**: Add explicit `zeroize` calls in `crypto.rs` to clean up temporary buffers.
2. **Atomic Compare-and-Swap**: Enforce write-once state on `CSPRNG_HOOK` inside `crypto.rs`.
3. **Command Payload Restrictions**: Restrict parsed string sizes inside `msg.rs` decode match arms.
4. **Label Obfuscation**: Obfuscate the hardcoded `nyx-session-v1` string in `crypto.rs`.
