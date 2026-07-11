# Nyx Protocol Crate — Line-by-Line Security Audit (2026-07-08)

**Scope:** `crates/protocol/src/` (crypto.rs, wire.rs, frame.rs, msg.rs, lib.rs) + `crates/protocol/fuzz/fuzz_targets/decode_vec.rs` + `crates/protocol/tests/roundtrip.rs`.
**Reviewer focus:** AEAD correctness / nonce discipline, HKDF binding, anti-replay surface, hand-rolled binary codec bounds, frame parsing, message roundtrip, CSPRNG + zeroization.

Baseline items in this crate: **HIGH-2** (HKDF empty salt), **LOW-1** (Reader::blob no decode-side cap), **LOW-2** (Bof>256 args silent truncate). All three **CONFIRMED STILL PRESENT** at the lines below. One **NEW CRITICAL** and several NEW LOW/MEDIUM findings added.

---

## Findings

### [CRITICAL] (NEW) no_std CSPRNG failure silently ignored → potential all-zero X25519 scalar
- **位置:** `crates/protocol/src/crypto.rs:89-103` (the bug is line `97: f(out);`)
- **已核验:** `random_bytes` loads the registered hook and calls it but **discards its `bool` return**:
  ```rust
  let f: fn(&mut [u8]) -> bool = unsafe { core::mem::transmute(hook) };
  f(out);                       // <-- bool return thrown away
  ```
  Every caller initializes the buffer to zero first (`ServerKeypair::generate` / `ImplantKeypair::generate`, crypto.rs:115-117, 169-171: `let mut bytes = [0u8; 32]; random_bytes(&mut bytes);`). The hook contract is documented (crypto.rs:71: *"Returning `false` = failure (the caller should abort / treat as fatal)"*) but never enforced. The hook (`implant-win/src/entry.rs:208-232 csprng_fill`) returns `false` in two real cases: (1) `SystemFunction036` export not resolvable via PEB walk → `addr == usize::MAX` (entry.rs:221-222), cached so every subsequent call also fails; (2) `RtlGenRandom` itself returns 0 (entry.rs:231-232). The implant's own selftest checks the return (`selftests.rs:750: if !csprng_fill(&mut buf) { exit(0xAF) }`) — the crypto layer does not.
- **描述:** When the CSPRNG hook fails, `random_bytes` returns normally leaving `out == [0u8; 32]`. `StaticSecret::from([0u8; 32])` builds an **all-zero scalar**. After X25519 clamping the scalar stays effectively zero → the public key is the identity point → the ECDH shared secret is the identity (all-zero) → `derive_session_key` runs HKDF over an all-zero IKM → a **predictable, identical session key for every affected implant**. The nonce/AAD are also derived from the same broken key, so the entire AEAD collapses to a two-time-pad an adversary can compute offline.
- **影响:** (a) Silent total crypto breakdown — the implant still beacons and "encrypts" but traffic is trivially decryptable by anyone who notices the all-zero / identity public key in the frame header. (b) Every implant hitting this failure generates the *same* deterministic keypair → permanent cross-session correlation / de-anonymization. (c) Reachable on hardened hosts where advapi32 export resolution or `RtlGenRandom` is blocked/hooked by an EDR. This is exactly a "false security guarantee operators rely on" + "total opsec failure" per the rubric.
- **修复:** Make `random_bytes` return `Result` (or abort on failure) and **act on the hook's bool**:
  ```rust
  if !f(out) {
      // CSPRNG failure is fatal — never proceed with predictable key material.
      // no_std PIC: write a diag marker and exit/abort; std: panic.
      #[cfg(not(feature = "std"))] { /* signal fatal init failure */ }
      #[cfg(feature = "std")] panic!("CSPRNG fill failed");
  }
  ```
  Then propagate the error out of `ServerKeypair::generate` / `ImplantKeypair::generate` so a zero scalar can never be constructed. As defense-in-depth, reject an all-zero scalar explicitly (`StaticSecret::from(bytes)` where `bytes == [0u8;32]` is treated as fatal) since a zero scalar is never legitimate.

---

### [HIGH] HIGH-2 (baseline, CONFIRMED) HKDF extract run with empty salt
- **位置:** `crates/protocol/src/crypto.rs:206`
- **已核验:** `let hk = Hkdf::<Sha256>::new(None, shared);` — `Hkdf::new(None, …)` sets the salt to a string of HashLen zeros (the documented `None`-salt mode). Present exactly as cited in the baseline.
- **描述:** No salt is supplied to HKDF-Extract. The IKM is the raw 32-byte X25519 shared secret. Domain separation falls entirely on the `info` buffer (`"nyx-session-v1" || server_pub || implant_pub`, built at crypto.rs:207-224), which is strong — so the practical collision risk is low. RFC 5869 §3.1 nonetheless recommends a non-empty salt when one is available; the server's long-term public key is a natural, known, per-server salt that is currently only placed in `info`.
- **影响:** Without a salt, HKDF-Extract provides no key-rotation / cross-protocol domain separation at the extract stage; the only binding is the `info` label. Low real-world risk today (the `info` binding makes cross-protocol reuse implausible), but it is a hardening gap and the kind of deviation reviewers flag.
- **修复:** `Hkdf::<Sha256>::new(Some(server_pub), shared)` (or `Some(&[server_pub, implant_pub].concat())`). The pubkeys already go into `info`; using one as the salt layers extract-stage separation on top. Keep `info` as-is. Re-baseline the roundtrip tests — keys change.

---

### [MEDIUM] (NEW) `SessionKey` claims `ZeroizeOnDrop` but is never zeroized — marker has no `Drop` impl
- **位置:** `crates/protocol/src/crypto.rs:20` (derive), `:34-40` (Zeroize + bare marker), confirmed no `Drop` via grep (only `ServerKeypair`@154 and `ImplantKeypair`@192 have Drop).
- **已核验:**
  ```rust
  #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]     // line 20 — Copy
  pub struct SessionKey([u8; KEY_LEN]);
  impl Zeroize for SessionKey { fn zeroize(&mut self) { self.0.zeroize(); } }  // 34-38
  impl ZeroizeOnDrop for SessionKey {}                   // 40 — bare marker, no Drop added
  ```
  There is **no** `impl Drop for SessionKey`. Worse, `Copy` is derived, and Rust forbids `impl Drop` on a `Copy` type (E0184) — so the marker's promise is *structurally unsatisfiable* as long as `Copy` stays. The doc comment at crypto.rs:17-19 explicitly says the struct exists *"so ZeroizeOnDrop can be implemented"*, yet only the marker (not the behavior) was implemented.
- **描述:** The actual AEAD session key is never cleared. `derive_session_key` (crypto.rs:229-230) zeroizes the intermediate `okm` array but returns `SessionKey::new(okm)` — a *separate* copy of the bytes that lives on the caller's side (e.g. `Session.key`, server/src/lib.rs:58) and persists in freed memory after the value is dropped. Every implicit `Copy` (it is stored in `Session`, passed around) leaves additional residual copies. The existing test `session_key_wrapper_zeroizes_in_place` (roundtrip.rs:356-387) only proves that an *explicit* `.zeroize()` call clears the bytes — it does not (cannot) assert drop behavior.
- **影响:** Per-session AEAD keys remain recoverable from process memory / crash dumps / hibernation files after the session ends — a forensic + attribution gap. Operators rely on the `ZeroizeOnDrop` marker (it is the stated reason the wrapper type exists); the reliance is false.
- **修复:** Remove `Copy` from the derive (keep `Clone` only if a call site truly needs it; most take `&SessionKey`). Add a real destructor:
  ```rust
  impl Drop for SessionKey { fn drop(&mut self) { self.0.zeroize(); } }
  ```
  Audit call sites: `seal_dir`/`open_dir`/`encode_frame_dir` already take `&SessionKey`, and `derive_for`/`session_key` return by value (a move, fine). `Session.key` continues to work as an owned field.

---

### [MEDIUM] (NEW) `SessionKey` derives `Debug` — key material reachable via `{:?}`
- **位置:** `crates/protocol/src/crypto.rs:20`
- **已核验:** `#[derive(Clone, Copy, Debug, …)]` on the struct holding `[u8; KEY_LEN]`. The derived `Debug` formats the raw key bytes (as a byte-array `[.., .., ..]`).
- **描述:** Any code path that logs/errors the session key via `{:?}` / `dbg!` / `tracing::debug!(?key)` dumps the live AEAD key into logs/diagnostics. The protocol crate cannot see all downstream call sites, so the exposure surface is unbounded.
- **影响:** Secret-key leak into operator logs / crash telemetry / `RUST_LOG=trace` output. Forensic + operational-secrets exposure.
- **修复:** Hand-roll `impl fmt::Debug for SessionKey { fn fmt(..) { f.debug_tuple("SessionKey").finish(&()) } }` (redacted) — or use `zeroize`'s pattern of not deriving `Debug` on secrets. Do the same audit for any other secret-carrying type (the `ServerKeypair`/`ImplantKeypair` structs already redact via their own field types — verify `StaticSecret`/`PublicKey` Debug does not leak).

---

### [LOW] LOW-1 (baseline, CONFIRMED) `Reader::blob` has no decode-side length cap
- **位置:** `crates/protocol/src/wire.rs:156-159`
- **已核验:**
  ```rust
  pub fn blob(&mut self) -> Result<&'a [u8], WireError> {
      let len = self.u32()? as usize;   // up to 4 GiB, unchecked
      self.take(len)
  }
  ```
  The encode side caps at `MAX_BLOB_LEN` (256 KiB, wire.rs:40/94-103, with tests at :181-237), but the decode side trusts the u32 prefix verbatim. `take()` (wire.rs:166-173) does bounds-check against `remaining()`, so no OOB read and no allocation here (it returns a borrow into the input) — but a caller doing `.to_vec()` on a huge declared length would copy up to the buffer's actual size.
- **描述:** Asymmetric cap. In production this is mitigated by the frame layer: `Reader` only ever runs over AEAD plaintext that was already bounded by `frame::MAX_CT_LEN` (512 KiB, frame.rs:22/111), so the worst case is ~512 KiB. But the codec itself has no defense-in-depth cap, and any future caller that feeds `Reader` unframed data inherits the 4 GiB surface.
- **影响:** Low today (frame-layer bound). Latent DoS / over-read surface if `Reader` is reused outside the AEAD-plaintext path.
- **修复:** Add a cap in `Reader::blob` mirroring the encode side:
  ```rust
  let len = self.u32()? as usize;
  if len > MAX_BLOB_LEN { return Err(WireError::BadLen(len)); }
  self.take(len)
  ```

---

### [LOW] LOW-2 (baseline, CONFIRMED) `Command::Bof` args > 256 silently truncated on encode
- **位置:** `crates/protocol/src/msg.rs:295-298`
- **已核验:**
  ```rust
  w.u32(args.len().min(MAX_WIRE_COUNT) as u32);   // writes min(len, 256)
  for a in args.iter().take(MAX_WIRE_COUNT) {      // emits only first 256
      w.str(a)?;
  }
  ```
  Decode (msg.rs:433-441) reads back `n = min(n_raw, MAX_WIRE_COUNT)` args — so the roundtrip is *consistent* but **lossy**: args 257+ vanish with no error to either side.
- **描述:** A caller that builds `Command::Bof { args: vec_with_300_strings, .. }` gets a wire frame carrying only the first 256 args; the rest are dropped silently. The count field is "honest" (it says 256), so neither encoder nor decoder signals data loss.
- **影响:** An operator BOF invocation with >256 string args silently runs with a truncated arg list — a correctness/silent-failure bug, not a memory-safety issue.
- **修复:** Either reject `args.len() > MAX_WIRE_COUNT` at encode (`Err(WireError::BadLen(args.len()))`) so the caller learns of the truncation, or raise the cap and document it. Silent truncation is the part to kill.

---

### [LOW] (NEW) `Task::encode_vec` silently truncates task batches > 256
- **位置:** `crates/protocol/src/msg.rs:642-643` (and symmetric decode at `:653`)
- **已核验:**
  ```rust
  w.u32(tasks.len().min(MAX_WIRE_COUNT) as u32);   // 256
  for t in tasks.iter().take(MAX_WIRE_COUNT) {
  ```
  Same silent-truncation pattern as LOW-2, but on the server→implant task dispatch batch. (`TaskResponse::encode_vec` at :684-685 deliberately uses `MAX_BATCH`=65536 instead — the asymmetry is intentional for responses, which stream FileChunks.)
- **描述:** If an operator queues >256 tasks for one implant before it beacons, only the first 256 are delivered; the remainder are dropped with no error. The count field is consistent so decode succeeds unaware.
- **影响:** Silent loss of queued tasks (e.g. a scripted sweep issuing 300 file-ops per beacon). Correctness bug, not security.
- **修复:** Return `Err(WireError::BadLen(tasks.len()))` when `tasks.len() > MAX_WIRE_COUNT`, or document the cap and have the server spill the overflow across beacon cycles. Reject the silent drop either way.

---

### [LOW] (NEW) Encode/decode length-cap asymmetry — large field values encode but fail to decode
- **位置:** encode `wire.rs:108-110` (`Writer::str` → `blob`, cap = `MAX_BLOB_LEN` 256 KiB) vs decode caps in `msg.rs`: `Shell` 4096 (:421), `Upload` name 4096 (:424), `Download` 4096 (:428), `SessionInfo.{hostname,username,os}` 256 (:80-82), `Bof` name 256 (:432), `Connect/Socks` host/addr 512 (:445/:452), `Portscan` 512 (:467-468), `Net` 512 (:471), `Env` 256 (:476), `MakeToken` domain/user/password 256 (:490-492), `Inject` spawn_to 4096 (:500), `Response::Err` 4096 (:590), `FileChunk` name 4096 (:592).
- **已核验:** `Writer::str` only rejects > 256 KiB; `checked_str(r, max_len)` (msg.rs:43-49) rejects anything over the per-field `max_len` (e.g. 4096). So `Command::Shell { args: "x".repeat(5000) }` **encodes** (5000 < 256 KiB) but **fails to decode** on the receiver (5000 > 4096) → `WireError::BadLen`.
- **描述:** The in-memory `Command` API permits values the wire codec cannot round-trip. An operator constructing a >4096-byte shell command (long base64 blob, scripted one-liner) gets a frame the implant rejects on decode — the command silently never executes.
- **影响:** Silent command-loss for oversized-but-plausible operator input. Not attacker-reachable (post-AEAD, authenticated), so LOW.
- **修复:** Enforce the same field-level caps on the encode path (a per-variant `Writer` helper, or validate in the constructors / server JSON layer) so encode-side rejection matches decode-side. At minimum document the per-field maxima next to the `Command` variants.

---

### [LOW] (NEW) `Response::Channel.status` not validated on decode (accepts 0–255; spec is 0–3)
- **位置:** `crates/protocol/src/msg.rs:607-611`
- **已核验:**
  ```rust
  6 => Response::Channel {
      chan: r.u32()?,
      status: r.u8()?,          // <-- any 0..255 accepted
      data: r.blob()?.to_vec(),
  },
  ```
  Contrast with `FileChunk.eof` at msg.rs:594-597 which **is** validated:
  ```rust
  let eof_raw = r.u8()?;
  if eof_raw > 1 { return Err(WireError::BadTag(eof_raw)); }
  ```
  The docstring (msg.rs:533-535) defines status as `0=open, 1=data, 2=closed, 3=error`.
- **描述:** A malformed/authenticated frame carrying `status=200` passes the codec and pushes an out-of-spec value into the handler. The handler must exhaustively match or it falls through silently. The `FileOp`/`Command` tag dispatches all reject unknowns via `t => return Err(WireError::BadTag(t))` (msg.rs:261, 511, 613) — the Channel status sub-field is an inconsistent gap. (Same class of unvalidated u8 discriminator: `Connect.proto` :444, `Socks.op` :451, `Inject.method` :498, `Hashdump.method` :482, `MakeToken.logon_type` :493 — all documented with small enums, none range-checked on decode. Channel.status is the most consequential since the relay state machine switches on it.)
- **影响:** Defense-in-depth gap; a value the spec says is impossible reaches relay logic. Low (post-AEAD, but the codec should be the boundary that enforces the contract).
- **修复:** Validate `status <= 3` (and the other documented-enum u8 fields) on decode, returning `WireError::BadTag(v)` on overflow — matching the existing `eof` and tag-dispatch pattern.

---

### [LOW] (NEW) Pointless XOR "obfuscation" of the HKDF label — dead code that misleads reviewers
- **位置:** `crates/protocol/src/crypto.rs:211-219`
- **已核验:**
  ```rust
  let mut label = *b"nyx-session-v1";       // compile-time constant — literal IS in the binary
  for b in &mut label { *b ^= 0x42; }        // XOR forward
  let mut recovered_label = [0u8; 14];
  for i in 0..14 { recovered_label[i] = label[i] ^ 0x42; }   // XOR back to original
  info[..recovered_label.len()].copy_from_slice(&recovered_label);
  ```
  The net effect is `info` receives the plaintext `"nyx-session-v1"`. The `*b"nyx-session-v1"` literal is a compile-time constant and is emitted to the binary's read-only data section regardless; the runtime XOR does not hide it (and a release optimizer may constant-fold the XOR↔unXOR to a no-op).
- **描述:** The code looks like an attempt to keep the protocol label out of a `strings(1)` dump, but it cannot work (the source literal is in the binary) and adds two pointless loops + a 14-byte stack buffer. It misleads a reviewer into thinking the label is protected when it is not.
- **影响:** No security impact; pure code-smell / false sense of obfuscation. Wastes reviewer attention.
- **修复:** Delete the XOR dance; write `info[..14].copy_from_slice(b"nyx-session-v1");` directly. If genuine string-hiding is desired, it must be done at build time (e.g. `include_bytes!` of an obfuscated blob, or `const`-folded XOR with the literal emitted in pre-XOR form only) — not this way.

---

### [LOW] (NEW) `ServerKeypair` derives `Clone` — long-term identity secret is duplicable
- **位置:** `crates/protocol/src/crypto.rs:107` (`#[derive(Clone)]` on `ServerKeypair { secret: StaticSecret, public: PublicKey }`)
- **已核验:** `derive(Clone)` on the struct whose `secret` field is the team server's long-term X25519 identity (the half baked into every implant). Each `Clone` duplicates the secret in memory; each clone's `Drop` (crypto.rs:154-159) zeroizes independently, but N clones mean N residual copies until all drop.
- **描述:** The server identity is the highest-value secret in the system (compromise = impersonate / decrypt every session). Allowing `Clone` broadens the surface for accidental duplication (e.g. `keypair.clone()` into a temporary, an `Arc`::get_mut refactor, etc.). `ImplantKeypair` (crypto.rs:162) does *not* derive Clone — the inconsistency suggests ServerKeypair's Clone is incidental rather than required.
- **影响:** Increased forensic exposure of the long-term secret; a foot-gun. Low unless something actually clones it.
- **修复:** Drop `Clone` from `ServerKeypair`; if shared access is needed, wrap in `Arc<ServerKeypair>` (which does not require the inner to be `Clone`). Confirm no call site relies on cloning the keypair itself.

---

## 已验证干净的区域 (checked and sound)

- **AEAD tag verification order (decrypt-before-verify).** `open_dir` (crypto.rs:297-314) delegates to `chacha20poly1305::Aead::decrypt`, which returns `Err` on any tag mismatch and **never returns plaintext on failure**. `parse_frame` (frame.rs:87-120) only slices the header + ciphertext copy — no plaintext is inspected before `open_frame_dir`/`open_dir` authenticates. Confirmed correct decrypt-then-process ordering. Tested by `wrong_key_does_not_decrypt` (roundtrip.rs:69-80).

- **Nonce direction separation (first-byte discriminator).** `Direction::discriminator` (crypto.rs:256-261) writes `0x00` (C2S) / `0x01` (S2C) into `nonce[0]`; `nonce_for` (crypto.rs:265-270) places the counter in `nonce[4..12]` and leaves `nonce[1..4]` zero. The two directions are disjoint for every counter value. Regression-tested both ways by `nonce_directions_never_collide` (roundtrip.rs:240-276): same key+counter+AAD+plaintext produces distinct ciphertexts across directions, and cross-direction open fails. Sound.

- **Counter / nonce overflow.** Counter is `u64` occupying exactly `nonce[4..12]` (8 bytes) — no truncation, no wrap feasible within physical limits (2⁶⁴ frames). `nonce_for` does no arithmetic that could overflow. The protocol crate surfaces `RawFrame.counter` (frame.rs:39, 93-97) for the server to enforce monotonic anti-replay; it intentionally does not track counter state itself (correct separation — anti-replay is server-side, out of this crate).

- **`parse_frame` bounds (frame.rs:87-120).** Min-length guard (`frame.len() < FRAME_HEADER` → `Eof`, :88-90); pubkey slice `frame[..PUBKEY_LEN]` is safe under that guard (:92); counter/ct_len reads via `try_into().expect("8/4 bytes")` are safe because the slices are exactly sized under the guard (:93-102); `ct_end = FRAME_HEADER + ct_len` cannot overflow usize (ct_len ≤ 512 KiB, :103); length-exact + `[MIN_CT_LEN, MAX_CT_LEN]` range enforced in one check (:111); trailing bytes rejected. The two `.expect()`s are unreachable panic-wise (guarded). Tested by `truncated_frame_is_rejected`, `frame_with_trailing_bytes_is_rejected`, `frame_with_oversized_ct_len_is_rejected`, `frame_with_zero_width_plaintext_is_rejected`, and the `MAX_CT_LEN`/`MIN_CT_LEN` constant pins (roundtrip.rs:159-198, 333-441).

- **`Reader` integer safety (wire.rs:119-174).** `remaining()` is `data.len() - pos`, and `pos` only advances by successful `take()` amounts so `pos ≤ data.len()` invariant holds (no subtract-underflow). `take(n)` checks `n > remaining()` *before* indexing/advancing (wire.rs:167-172), so `pos + n ≤ data.len()` at the slice — no OOB, no usize overflow on 32- or 64-bit. `u32/u16/u64` readers all go through `take`. Sound.

- **Allocation-bomb defense (msg.rs).** `checked_count` (msg.rs:35-41) rejects `declared > MAX_BATCH` (65536) with `BadLen` and otherwise reserves `min(declared, remaining)` — never a raw `Vec::with_capacity(u32)`. Per-loop iteration is secondarily capped at `MAX_WIRE_COUNT` (tasks/BOF args) or `MAX_BATCH` (responses). Tested by `decode_vec_rejects_absurd_count_without_huge_alloc` (roundtrip.rs:278-305) with `n = 0xFFFFFFFF`. Sound.

- **Tag-dispatch exhaustiveness.** `Command::decode` (msg.rs:413-513), `Response::decode` (msg.rs:586-615), `FileOp::decode` (msg.rs:254-263) all end with `t => return Err(WireError::BadTag(t))`. No fall-through. Tested by `bad_fileop_tag_errors` (msg.rs:785-795). Sound. (Caveat: sub-field u8 discriminators like `Channel.status` are NOT validated — see the LOW finding above.)

- **CSPRNG (std build) + keypair Drop.** std `random_bytes` (crypto.rs:57-60) uses `OsRng` directly — sound. `Drop for ServerKeypair` (crypto.rs:154-159) and `Drop for ImplantKeypair` (crypto.rs:192-197) both `secret.zeroize()` + `compiler_fence(SeqCst)`. Intermediate `shared_bytes` and `okm` arrays are explicitly `.zeroize()` after use (crypto.rs:149, 187, 230). Sound — **except** the returned `SessionKey` itself, which is the MEDIUM finding above.

- **HKDF transcript/identity binding (modulo the salt).** `info` binds `"nyx-session-v1" || server_pub || implant_pub` (crypto.rs:219-224) — both ECDH identities and a protocol-version label are bound into the expand step. The AAD on every AEAD op is the implant pubkey (frame.rs:64, 128), double-binding the session identity (key-derivation + AEAD auth). A flipped pubkey in the frame header either fails key derivation or fails the AAD tag check. Sound (the only gap is the empty *salt*, HIGH-2 above).

- **AEAD infallibility on encrypt.** `seal_dir` (crypto.rs:280-293) uses `.expect("chacha20poly1305 encrypt is infallible")` — correct: ChaCha20-Poly1305 encrypt only fails on nonce reuse, which is a programming error the caller must prevent; panicking is the right contract.

- **Fuzz harness coverage.** `fuzz/fuzz_targets/decode_vec.rs` polices the absolute contract "decode arbitrary input → Ok|Err, never panic" across `Task::decode_vec`, `TaskResponse::decode_vec`, and raw `Reader` (blob/str/u32/u8/u16/u64) walks. The harness rationale (server `panic = abort` ⇒ any decode panic = process death = DoS) is correct and the targets exercise the attacker-facing surface. Sound and well-targeted.

- **Roundtrip test coverage.** `tests/roundtrip.rs` (442 lines) covers ECDH mutuality, per-session key uniqueness, frame seal/open, wrong-key rejection, task/response batch roundtrips (incl. empty), truncated/trailing/oversized/zero-width frame rejection, nonce-direction non-collision, allocation-bomb rejection, channel-response variants, the `MAX_CT_LEN`/`MIN_CT_LEN` constants, and `SessionKey` in-place zeroize. Every `Command`/`Response` variant has a roundtrip case in either `roundtrip.rs` or the inline `msg.rs` `tests` module (msg.rs:709-912). Sound.

---

## Summary

| Severity | Count | Items |
|---|---|---|
| CRITICAL (NEW) | 1 | CSPRNG-failure-ignored |
| HIGH (baseline) | 1 | HIGH-2 HKDF empty salt (confirmed) |
| MEDIUM (NEW) | 2 | SessionKey no-Drop ZeroizeOnDrop lie; SessionKey Debug leak |
| LOW (baseline) | 2 | LOW-1 Reader::blob no cap (confirmed); LOW-2 Bof>256 truncate (confirmed) |
| LOW (NEW) | 5 | Task::encode_vec truncate; encode/decode cap asymmetry; Channel.status unvalidated; XOR label dead code; ServerKeypair Clone |

**Baseline disposition:** HIGH-2 → **CONFIRMED** (crypto.rs:206). LOW-1 → **CONFIRMED** (wire.rs:156-159). LOW-2 → **CONFIRMED** (msg.rs:295-298). None of the three baseline items have been fixed.

**Top priority:** the CSPRNG-failure CRITICAL — a one-line discarded `bool` that can silently reduce the entire AEAD to a deterministic, decryptable, cross-implant-identical scheme. Trivial to fix, catastrophic if hit.
