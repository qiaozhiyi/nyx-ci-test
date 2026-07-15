# Nyx Protocol Crate — Line-by-Line Security Audit (2026-07-10 deep re-verify)

**Scope:** `crates/protocol/src/` (crypto.rs, wire.rs, frame.rs, msg.rs, lib.rs) + `crates/protocol/tests/roundtrip.rs` + `crates/protocol/fuzz/fuzz_targets/decode_vec.rs`.
**Baseline:** `docs/audit_2026_07_08/protocol.md` (1 CRIT-new + 1 HIGH-baseline + 2 MED-new + 7 LOW). Cross-crater caller verification: `implant-win/{beacon,entry,selftests}.rs`, `agent-dev/src/lib.rs`, `server/src/{lib,main}.rs`, `server/tests/beacon_limits.rs`.
**Method:** full file read of all 6 domain files + `git diff` of crypto.rs (heavy), lib.rs, roundtrip.rs (no diff on frame.rs, wire.rs, msg.rs); grep of every call site of `ServerKeypair::generate` / `ImplantKeypair::generate` / `GenerateError` / `CryptoError` / `SessionKey` across the live tree (`.claude/worktrees/*` stale snapshots excluded).

---

## Headline

The 07-08 **CRITICAL** (CSPRNG-failure-ignored → all-zero scalar) is **FIXED**, and the fix is **substantially correct** at every call site I audited — including all three `no_std` implant paths where the failure is fatal. The two 07-08 **MEDIUMs** (SessionKey no-Drop ZeroizeOnDrop lie; SessionKey Debug leak) are **FIXED** with a real `Drop` and a redacted `Debug`. The **HIGH-2** (HKDF empty salt) is **FIXED** (salt now = `server_pub`). The XOR-label dead code is **FIXED** (deleted).

The fix-in-progress is **high quality**. I found **no correctness regression** in the new `Result`-returning `generate()` plumbing and **no call site that ignores the `Result`**. The remaining findings below are: residual LOWs the fix did *not* touch (correctly out of scope, but still open), one **new MEDIUM** in the fix itself (`from_secret_bytes` is the one keypair-construction path that still bypasses the zero-scalar check — a defense-in-depth gap the fix's own comments promise but don't deliver), and a few **new LOWs** spotted with fresh eyes.

---

## RE-VERIFICATION of prior 07-08 findings

### [CRITICAL] CRIT-NEW-1: CSPRNG failure silently ignored → all-zero scalar
- **位置:** `crates/protocol/src/crypto.rs:157-175` (the fix), callers across `crates/implant-win/src/{beacon.rs:42,194, entry.rs:549, selftests.rs:777,819}`
- **状态:** **FIXED** (and fix is correct)
- **已核验:** The no_std `random_bytes` now returns `Result<(), CryptoError>` and **acts on the hook's bool** (crypto.rs:165-167):
  ```rust
  if !f(out) {
      return Err(CryptoError::CsprngFailed);
  }
  ```
  The discarded-`bool` line that was the bug is gone. A new `reject_zero` helper (crypto.rs:180-186) adds defense-in-depth: even if the hook lies with `true` but leaves the buffer zeroed, `fill_random_checked` (crypto.rs:210-220) converts that to `GenerateError::ZeroScalar`. Both keypair generators now thread `GenerateError` out:
  ```rust
  pub fn generate() -> Result<Self, GenerateError> { ... fill_random_checked(&mut bytes)?; ... }   // ServerKeypair crypto.rs:238
  pub fn generate() -> Result<Self, GenerateError> { ... fill_random_checked(&mut bytes)?; ... }   // ImplantKeypair crypto.rs:298
  ```
  **Caller verification (the part that matters most — a fix that compiles but drops the error at a call site is no fix):**
  - `implant-win/src/beacon.rs:42-50` (beacon_loop): `Err(_) => { diag_mark(b"ERR_KEYGEN_CSPRNG"); return; }` — aborts the loop, never proceeds to key derivation. Correct.
  - `implant-win/src/beacon.rs:194-199` (beacon_oneshot): `Err(_) => { diag_mark(b"ERR_ONESHOT_CSPRNG"); return 0xAF; }` — returns the CSPRNG-fatal exit code. Correct.
  - `implant-win/src/entry.rs:549-551` (selftest round-trip): `Err(_) => report_exit(exit_proc, 0xE00)` — aborts selftest. Correct.
  - `implant-win/src/selftests.rs:777-781` (nyx_selftest_csprng): exhaustively matches **both** `GenerateError::CsprngFailed => exit(0xAF)` and `GenerateError::ZeroScalar => exit(0xAE)`. This is the single most thorough call site — it distinguishes the two failure modes for diagnostics. Correct.
  - `implant-win/src/selftests.rs:819-821` (loopdiag): `Err(_) => exit(0xAF)`. Correct.
  - `agent-dev/src/lib.rs:39-40`: `.map_err(|_| anyhow!(...))?` — propagates as an `anyhow::Result`. Correct.
  - `server/src/lib.rs:126-127` (AppState::default): `.expect("... OsRng is infallible on supported targets")` — acceptable for the std build where `OsRng` is documented infallible; the `Err` arm is unreachable in practice.
  - `server/src/lib.rs:241-242` (load_or_create_keypair): `.map_err(|_| anyhow!("CSPRNG failure ..."))?` — propagates. Correct.
  - `server/src/main.rs:70-71`: `.expect("... OsRng is infallible on supported targets")` — acceptable for std.
  - All 8 test-site callers in `server/src/lib.rs` and `roundtrip.rs` use `.unwrap()` / `.expect(...)` — fine for std tests.
  **Zero call site ignores the `Result`.** The `pub enum CryptoError` (crypto.rs:120-129) is `#[cfg(not(feature = "std"))]` and deliberately **not** re-exported from `lib.rs` (grep confirms only `GenerateError` is re-exported at lib.rs:34) — so it stays an internal detail of the no_std fill path, which is correct (callers only ever see `GenerateError`).
- **影响:** The catastrophic silent-crypto-breakdown path is closed. The `reject_zero` belt-and-suspenders check means even a hypothetical future regression in the hook's `bool` reporting cannot construct an all-zero scalar through `generate()`. The one residual gap is `from_secret_bytes` (see NEW-MED-1 below).
- **修复:** None required for this finding. (Defense-in-depth suggestion in NEW-MED-1.)

---

### [HIGH] HIGH-NEW-P1: SessionKey derives Copy + shell ZeroizeOnDrop, no Drop
- **位置:** `crates/protocol/src/crypto.rs:31-81`
- **状态:** **FIXED**
- **已核验:** `Copy` is removed (the struct at crypto.rs:31 has no derives at all now). A real destructor exists (crypto.rs:76-81):
  ```rust
  impl Drop for SessionKey {
      fn drop(&mut self) {
          self.0.zeroize();
          core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
      }
  }
  ```
  The bare `impl ZeroizeOnDrop for SessionKey {}` marker (which promised behavior it could not deliver, since `Copy` forbids `Drop` per E0184) is gone. `Clone`/`PartialEq`/`Eq`/`Hash`/`Debug` are now hand-rolled (crypto.rs:42-68) so the struct can keep `Drop`.
  **Copy-removal call-site verification** (the critical question the context raised: *does removing Copy break any call site that relies on implicit copy?*):
  - `seal_dir`/`open_dir`/`encode_frame_dir`/`open_frame_dir`/`open_frame`/`encode_frame` all take `&SessionKey` (crypto.rs:404, 427; frame.rs:57, 82, 123, 135) — no copy needed.
  - `derive_for`/`session_key`/`derive_session_key` return `SessionKey` by value (moves, not copies) — crypto.rs:268, 312, 331.
  - `server/src/lib.rs:57-58` stores `pub key: SessionKey` as an owned field — fine (move into the struct).
  - `server/src/lib.rs:584` `s.key.clone()` — uses the new explicit `Clone` impl (crypto.rs:42-46). The comment at lib.rs:620-623 documents the intent ("SessionKey is no longer Copy so it has a real Drop that zeroizes; the clone is zeroized on drop."). Correct.
  - `server/src/lib.rs:623` `let reply_key = key.clone();` — same pattern, explicit clone before move-into-`Session`. Correct.
  - `Session` does **not** derive `Clone`/`Copy` (lib.rs:57 has no derives), so the non-`Copy` `SessionKey` field doesn't break it.
  No implicit-copy call site exists. The removal is clean.
- **影响:** Per-session AEAD keys are now actually zeroized on drop (plus a compiler fence to defeat dead-store elimination). The `ZeroizeOnDrop` contract the wrapper type exists to provide is now real. Forensic/attribution exposure of live AEAD keys in freed memory is closed.
- **修复:** None required.

---

### [HIGH] HIGH-NEW-P2: SessionKey derives Debug → leaks key bytes
- **位置:** `crates/protocol/src/crypto.rs:63-68`
- **状态:** **FIXED**
- **已核验:** Hand-rolled `Debug` (crypto.rs:63-68):
  ```rust
  impl core::fmt::Debug for SessionKey {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          f.write_str("SessionKey(<redacted>)")
      }
  }
  ```
  New regression test `session_key_debug_does_not_leak_bytes` (roundtrip.rs:392-405) asserts neither `"DE"` (hex of the `[0xDE;32]` fixture) nor a missing `"redacted"` marker survives a `format!("{:?}", key)`. The test is sound — it constructs a key of all-`0xDE` bytes and would fail if the derived `Debug` ever came back. The struct has no `#[derive(Debug)]` anywhere now (line 31 is bare).
- **影响:** A stray `{:?}` / `dbg!` / `tracing::debug!(?key)` can no longer dump the live AEAD key into logs/telemetry.
- **修复:** None required.

---

### [HIGH] HIGH-2: HKDF empty salt
- **位置:** `crates/protocol/src/crypto.rs:342`
- **状态:** **FIXED**
- **已核验:** The diff shows `Hkdf::<Sha256>::new(None, shared)` → `Hkdf::<Sha256>::new(Some(server_pub), shared)` (crypto.rs:342). The comment at crypto.rs:336-341 documents the RFC 5869 §3.1 rationale and the choice of `server_pub` (public, fixed, non-attacker-controlled). The `info` buffer still also binds both pubkeys (crypto.rs:346-353), so separation is now layered at both extract and expand stages.
  The `info` buffer math is correct: buffer is `[0u8; 80]`, used bytes = 14 (label) + 32 (server_pub) + 32 (implant_pub) = 78, and `hk.expand(&info[..pos], ...)` slices exactly `pos == 78` (crypto.rs:356) — no trailing zero bytes leak into the expand info. (Prior code computed the same 78 but via the deleted XOR dance.)
- **影响:** Extract-stage domain separation is now present. The hardening gap is closed. (Note: this changes every derived session key, so it is a protocol break — any in-flight implants built against the old `None`-salt derivation will fail to establish sessions with a server running the new code. That's expected for a pre-release red-team tool and the prior audit explicitly flagged "Re-baseline the roundtrip tests — keys change"; the tests do pass with the new salt because both sides use the same code.)
- **修复:** None required.

---

### [LOW] LOW-1: Reader::blob has no decode-side length cap
- **位置:** `crates/protocol/src/wire.rs:156-159`
- **状态:** **STILL PRESENT**
- **已核验:** `wire.rs` has **no git diff** — untouched by the fix-in-progress. `Reader::blob` (wire.rs:156-159) still reads `let len = self.u32()? as usize;` with no cap, then `self.take(len)`. The encode side (`Writer::blob`, wire.rs:94-103) still caps at `MAX_BLOB_LEN` (256 KiB). The asymmetry is unchanged. Mitigations noted in 07-08 still hold: `take()` bounds-checks against `remaining()` (wire.rs:167) so no OOB, and in production `Reader` only runs over AEAD plaintext already bounded by `frame::MAX_CT_LEN` (512 KiB).
- **修复:** Unchanged from 07-08: add `if len > MAX_BLOB_LEN { return Err(WireError::BadLen(len)); }` in `Reader::blob`.

---

### [LOW] LOW-2: Command::Bof args > 256 silently truncated on encode
- **位置:** `crates/protocol/src/msg.rs:295-298`
- **状态:** **STILL PRESENT**
- **已核验:** `msg.rs` has **no git diff**. The encode path still writes `w.u32(args.len().min(MAX_WIRE_COUNT) as u32)` + `for a in args.iter().take(MAX_WIRE_COUNT)` (msg.rs:295-298); decode reads back `n = (n_raw as usize).min(MAX_WIRE_COUNT)` (msg.rs:435). Consistent but lossy — args 257+ vanish silently. Unchanged.
- **修复:** Unchanged from 07-08: reject `args.len() > MAX_WIRE_COUNT` at encode with `Err(WireError::BadLen(args.len()))`.

---

### [LOW] Task::encode_vec silently truncates task batches > 256
- **位置:** `crates/protocol/src/msg.rs:642-643`
- **状态:** **STILL PRESENT**
- **已核验:** No diff on msg.rs. `Task::encode_vec` still does `.min(MAX_WIRE_COUNT)` + `.take(MAX_WIRE_COUNT)` (msg.rs:642-643), decode mirrors with `.min(MAX_WIRE_COUNT)` (msg.rs:653). Silent truncation of tasks 257+. Unchanged. (And as the 07-08 report noted, `TaskResponse::encode_vec` deliberately uses `MAX_BATCH`=65536 instead — the asymmetry is intentional for response streaming.)
- **修复:** Unchanged from 07-08: `Err(WireError::BadLen(tasks.len()))` on overflow.

---

### [LOW] Encode/decode length-cap asymmetry (large field values encode but fail to decode)
- **位置:** encode `wire.rs:108-110` (`Writer::str` → `blob`, cap = `MAX_BLOB_LEN` 256 KiB) vs decode per-field caps in `msg.rs` (`Shell`/`Upload name`/`Download`/`Inject spawn_to`/`Response::Err`/`FileChunk name` = 4096; `SessionInfo.{hostname,username,os}`/`Bof name`/`Env`/`MakeToken.{domain,user,password}` = 256; `Connect/Socks host|addr`/`Portscan`/`Net` = 512)
- **状态:** **STILL PRESENT**
- **已核验:** No diff on wire.rs or msg.rs. `Writer::str` → `Writer::blob` (wire.rs:108-110) still only rejects > 256 KiB; `checked_str(r, max_len)` (msg.rs:43-49) still rejects per-field on decode. So `Command::Shell { args: "x".repeat(5000) }` still encodes (5000 < 256 KiB) but fails to decode (5000 > 4096). Unchanged.
- **修复:** Unchanged from 07-08: enforce per-field caps on the encode path too.

---

### [LOW] Response::Channel.status not validated on decode (accepts 0–255; spec is 0–3)
- **位置:** `crates/protocol/src/msg.rs:607-611`
- **状态:** **STILL PRESENT**
- **已核验:** No diff on msg.rs. `Response::Channel` decode still does `status: r.u8()?` (msg.rs:609) with no range check, while the sibling `FileChunk.eof` (msg.rs:594-597) still validates `if eof_raw > 1 { return Err(WireError::BadTag(eof_raw)); }`. The inconsistency is unchanged. Same class of unvalidated u8 discriminator: `Connect.proto` (msg.rs:444), `Socks.op` (msg.rs:451), `Inject.method` (msg.rs:498), `Hashdump.method` (msg.rs:482), `MakeToken.logon_type` (msg.rs:493), `Screenshot.monitor` (msg.rs:465), `Keylog.action` (msg.rs:478), `SetChannel.channel` (msg.rs:510), `SessionInfo.arch`/`is_admin` (msg.rs:83,85). None range-checked.
- **修复:** Unchanged from 07-08: `if status > 3 { return Err(WireError::BadTag(status)); }`.

---

### [LOW] XOR "obfuscation" of HKDF label — dead code
- **位置:** `crates/protocol/src/crypto.rs:347-353`
- **状态:** **FIXED**
- **已核验:** The diff deleted the two XOR loops and the `recovered_label` buffer. Now (crypto.rs:347-348):
  ```rust
  let label = b"nyx-session-v1";
  info[..label.len()].copy_from_slice(label);
  ```
  Direct copy. The misleading "obfuscation" is gone. (Caveat below in NEW-LOW-2: the label literal is now an unadorned `&[u8]` in `.rodata` and trivially visible to `strings(1)` — but that was always true, and the prior XOR didn't change it. This is a code-quality fix, not a regression.)

---

### [LOW] ServerKeypair derives Clone
- **位置:** `crates/protocol/src/crypto.rs:224`
- **状态:** **STILL PRESENT**
- **已核验:** `#[derive(Clone)]` is still on `ServerKeypair` (crypto.rs:224). The fix-in-progress touched this file heavily but left the `Clone` derive. `ImplantKeypair` (crypto.rs:286) still does **not** derive `Clone` — the inconsistency noted in 07-08 persists. I checked whether any live call site actually clones a `ServerKeypair`: grep for `keypair.clone()` / `ServerKeypair` clone usage in the server crate found the keypair stored as an owned field in `AppState` (server/src/lib.rs:66 `pub keypair: ServerKeypair`) and wrapped in `Arc` for handler sharing — no direct `.clone()` of the keypair itself appears in the live (non-worktree) tree. So the `Clone` is currently unused incidental surface, exactly as 07-08 assessed.
- **修复:** Drop `Clone` from `ServerKeypair`; use `Arc<ServerKeypair>` if shared access is needed.

---

## NEW findings (fresh-eyes pass on the fix diff + code the prior audit called clean)

### [MEDIUM] (NEW-1) `ServerKeypair::from_secret_bytes` bypasses the zero-scalar check — the one keypair path not covered by `reject_zero`
- **位置:** `crates/protocol/src/crypto.rs:259-264`
- **状态:** **NEW** (not in 07-08 baseline; exposed by reading the fix's own defense-in-depth comments)
- **已核验:** The fix added `reject_zero` (crypto.rs:180-186) and threaded it through `fill_random_checked` → both `generate()` paths (crypto.rs:240, 300). The docstring on `GenerateError::ZeroScalar` (crypto.rs:202-204) explicitly promises: *"Defense in depth: a hooked/broken RNG that lies with `true` is still caught."* And `reject_zero`'s own docstring (crypto.rs:177-179) says an all-zero scalar *"Never [legitimate]"*.
  But `from_secret_bytes` (crypto.rs:259-264) — the path that reconstructs the server identity from `NYX_KEYFILE` — does **not** call `reject_zero`:
  ```rust
  pub fn from_secret_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
      let secret = StaticSecret::from(bytes);   // <- no zero check
      bytes.zeroize();
      let public = PublicKey::from(&secret);
      Self { secret, public }
  }
  ```
  An operator who (accidentally or via a corrupted/truncated keyfile) persists a 32-byte all-zero secret and reloads it constructs a server identity at the curve identity point. The server then derives the same broken all-zero shared secret with every implant — the exact catastrophic outcome `reject_zero` exists to prevent, but only on the `generate()` path. The `try_into().map_err(|_| anyhow!("keyfile ... is not 32 bytes"))` at server/src/lib.rs:237-239 validates the *length* but not the *value*.
- **描述:** The fix's defense-in-depth invariant ("an all-zero scalar is never legitimate and is always rejected") has a hole: persisted-keyfile reconstruction skips the check. The practical likelihood is low (an operator has to write a zero keyfile — though `dd if=/dev/zero of=$NYX_KEYFILE bs=32 count=1` or a filesystem-integrity failure would do it), but the *inconsistency* is the real issue: the codebase now asserts in comments that zero scalars are always caught, yet one constructor silently allows one. A reviewer relying on the docstring would assume `from_secret_bytes` is safe.
- **影响:** If a zero keyfile is loaded, the server identity collapses to the identity point → every session key is deterministic/decryptable → total opsec failure, same class as the original CRIT-NEW-1 but reachable only via operator error / file corruption rather than EDR hooking. MEDIUM (not HIGH) because it requires a misconfigured keyfile, not an attacker-reachable input.
- **修复:** Add the same `reject_zero` guard to `from_secret_bytes`, returning `Result<Self, GenerateError>` (or a dedicated `ZeroScalar` error). Since this changes the signature, update the two call sites: `server/src/lib.rs:240` (the `Ok(...)` arm of `load_or_create_keypair`) and any test. Defense-in-depth should be uniform across *all* keypair-construction paths, not just the random ones.

---

### [LOW] (NEW-2) Duplicated/mismatched doc-comment block above `random_bytes` (fix artifact)
- **位置:** `crates/protocol/src/crypto.rs:83-111`
- **状态:** **NEW** (artifact of the fix diff)
- **已核验:** The fix replaced the old doc comment but left the **old block in place** above the new one. Lines 83-97 are the *stale* doc comment (ending "...falls back to `OsRng` (which works on std targets)."), and lines 98-111 are the *new* doc comment (ending "...the pre-fix bug: the hook's `bool` return was discarded."). Both sit immediately above the `#[cfg(feature = "std")] fn random_bytes` at line 112-115. The diff shows the new block was inserted *after* the old one rather than replacing it.
  The two blocks **disagree**: the stale block claims `getrandom` → `RtlGenRandom` "via normal static linking" for the std build and explains the no_std path uses PEB-walk; the new block says the std build uses `OsRng` → `getrandom` (no static-linking claim) and that the no_std hook "CAN fail at runtime". A reader sees contradictory rationale. (The new block is the correct/authoritative one.)
- **描述:** Leftover stale documentation from the edit. No functional impact, but it's confusing and the stale block describes the std path inaccurately relative to the actual `OsRng.fill_bytes(out)` implementation.
- **影响:** None (doc only). Reviewer confusion / maintenance hazard.
- **修复:** Delete the stale block at crypto.rs:83-97, keeping the new block at 98-111.

---

### [LOW] (NEW-3) `random_bytes` no_std fallback-to-`OsRng` branch defeats the "CSPRNG failure is fatal" contract on an unregistered hook
- **位置:** `crates/protocol/src/crypto.rs:169-174`
- **状态:** **NEW** (spotted in the fix's new code)
- **已核验:**
  ```rust
  } else {
      // Fallback: OsRng. On a no_std PIC cdylib without a registered hook this
      // may abort at link/runtime; but if it returns it filled the buffer.
      rand_core::OsRng.fill_bytes(out);
      Ok(())
  }
  ```
  The whole point of the registered-hook design (documented at crypto.rs:89-97 stale block) is that `getrandom`'s `#[link(name="advapi32")]` produces a static import-table entry the PIC cdylib loader can't resolve, so the no_std implant **must** use the PEB-walk hook. If the hook is unregistered (`CSPRNG_HOOK == 0`), this branch calls `OsRng` — which on a real PIC implant will either fail to link (build-time) or abort at runtime (`0xC0000409` STATUS_STACK_BUFFER_OVERRUN, per the stale doc). The comment acknowledges this ("may abort at link/runtime"). But there's a subtler problem: if a future `getrandom`/`rand_core` version makes `OsRng` *succeed* on no_std via some other path (e.g. a rdynamic indirection), this branch would return `Ok(())` having used a CSPRNG source the implant didn't vet — silently bypassing the `register_csprng` gating that exists precisely so the implant controls its entropy source. The `reject_zero` defense-in-depth still catches an all-zero result, but not e.g. a predictably-seeded or weakened source.
- **描述:** The fallback branch is a "best-effort" that assumes `OsRng` is correct on no_std, which contradicts the architecture's stated reason for having a hook at all. In the current build it likely aborts (so it's self-correcting), but it's a latent contract violation if the no_std `OsRng` ever silently succeeds.
- **影响:** Low today (the branch is effectively unreachable/dead-on-implant). Latent: if `OsRng` ever returns on no_std, the implant uses an unvetted entropy source without a diagnostic.
- **修复:** Consider returning `Err(CryptoError::CsprngFailed)` when `hook == 0` in the `not(feature = "std")` build (the hook is mandatory for the implant), keeping the `OsRng` fallback only for `std`. Or at minimum `debug_assert!(hook != 0, "no_std implant must register_csprng before keygen")`.

---

### [LOW] (NEW-4) `reject_zero` uses an ad-hoc `ZeroScalarMarker` error instead of `GenerateError::ZeroScalar`
- **位置:** `crates/protocol/src/crypto.rs:180-190, 219`
- **状态:** **NEW** (style, spotted in the fix)
- **已核验:** `reject_zero` returns `Result<(), ZeroScalarMarker>` (crypto.rs:180) where `ZeroScalarMarker` is a private unit struct (crypto.rs:190). The docstring (crypto.rs:188-189) explains it's "kept out of the public `CryptoError` enum so the std build, which never hits it, doesn't need the enum." Then `fill_random_checked` maps it: `reject_zero(out).map_err(|_| GenerateError::ZeroScalar)` (crypto.rs:219). This works, but it's an extra indirection type that exists only to be immediately discarded by `map_err(|_| ...)`. The same `cfg` gating could be done by giving `reject_zero` the signature `fn reject_zero(bytes: &[u8;32]) -> Result<(), GenerateError>` directly (with the `ZeroScalar` variant `#[cfg(not(feature="std"))]`-gated or always present — `GenerateError` is already `pub` and has the variant at crypto.rs:204).
- **描述:** Minor abstraction leak / dead-weight type. `ZeroScalarMarker` carries no information and is always mapped away. Not a bug.
- **影响:** None (code clarity / dead type).
- **修复:** Optional — collapse `reject_zero` to return `Result<(), GenerateError>` directly and delete `ZeroScalarMarker`.

---

### [LOW] (NEW-5) `info` buffer oversized by 2 bytes (80 vs 78 needed) — harmless but under-documented
- **位置:** `crates/protocol/src/crypto.rs:346`
- **状态:** **NEW** (spotted reading the fix; not in 07-08)
- **已核验:** `let mut info = [0u8; 80];` — but only 14+32+32 = 78 bytes are written (crypto.rs:348-353), and `hk.expand(&info[..pos], ...)` correctly slices `pos == 78` (crypto.rs:356). So the last 2 bytes (`info[78..80]`) are always zero and never read. This is **safe** (the expand call is precise), but the `[0u8; 80]` is not `[0u8; 78]`. The comment at crypto.rs:344-345 says "= 78 bytes" then declares 80. Likely a leftover alignment/rounding choice; it leaves a 2-byte zero tail on the stack that a very pedantic reviewer might mistake for accidental padding that leaks into `info` (it does not, because of the `..pos` slice).
- **描述:** Trivial buffer-size mismatch with the documented math. No functional impact (slicing is exact). Mild reviewer-confusion hazard.
- **影响:** None.
- **修复:** `let mut info = [0u8; 78];` to match the comment, or update the comment to note the 2-byte alignment slack.

---

## 已验证干净的区域 (checked and sound — re-verified this pass)

- **AEAD tag verification order (decrypt-then-process).** `open_dir` (crypto.rs:426-443) delegates to `chacha20poly1305::Aead::decrypt`, which returns `Err` on any tag mismatch and never returns plaintext on failure. `parse_frame` (frame.rs:87-120) slices header + ciphertext only — no plaintext is inspected before `open_frame_dir` authenticates. Re-confirmed. Tested by `wrong_key_does_not_decrypt` (roundtrip.rs:68-80).

- **Nonce direction separation (first-byte discriminator).** `Direction::discriminator` (crypto.rs:385-390) writes `0x00`/`0x01` into `nonce[0]`; `nonce_for` (crypto.rs:394-399) places the counter in `nonce[4..12]`, leaves `nonce[1..4]` zero. The two directions are disjoint for every counter. Re-confirmed by `nonce_directions_never_collide` (roundtrip.rs:240-276): same key+counter+AAD+plaintext → distinct ciphertexts across directions; cross-direction open fails. Sound. The fix diff did not touch this.

- **Counter / nonce overflow.** Counter is `u64` in `nonce[4..12]` (8 bytes) — no truncation, no physical wrap. `nonce_for` (crypto.rs:394-399) does no arithmetic that could overflow. `RawFrame.counter` (frame.rs:39, 93-97) is surfaced for server-side anti-replay. Sound.

- **`parse_frame` bounds (frame.rs:87-120).** Min-length guard (`< FRAME_HEADER` → `Eof`, :88-90); pubkey slice safe under guard (:92); `try_into().expect("8/4 bytes")` safe (slices exactly sized under guard, :93-102); `ct_end = FRAME_HEADER + ct_len` cannot overflow (ct_len ≤ 512 KiB); length-exact + `[MIN_CT_LEN, MAX_CT_LEN]` range in one check (:111); trailing bytes rejected. The two `.expect()`s are unreachable panic-wise. Re-verified by `truncated_frame_is_rejected`, `frame_with_trailing_bytes_is_rejected`, `frame_with_oversized_ct_len_is_rejected`, `frame_with_zero_width_plaintext_is_rejected`, and the `MAX_CT_LEN`/`MIN_CT_LEN` constant pins (roundtrip.rs:159-198, 333-488). No diff on frame.rs. Sound.

- **`Reader` integer safety (wire.rs:119-174).** `remaining()` = `data.len() - pos` with `pos ≤ data.len()` invariant; `take(n)` checks `n > remaining()` *before* indexing/advancing (wire.rs:167-172); all `u32/u16/u64` readers go through `take`. No OOB, no usize overflow. No diff on wire.rs. Sound.

- **Allocation-bomb defense (msg.rs).** `checked_count` (msg.rs:35-41) rejects `declared > MAX_BATCH` (65536) with `BadLen` and otherwise reserves `min(declared, remaining)` — never a raw `Vec::with_capacity(u32)`. Tested by `decode_vec_rejects_absurd_count_without_huge_alloc` (roundtrip.rs:278-305) with `n = 0xFFFFFFFF`. No diff on msg.rs. Sound.

- **Tag-dispatch exhaustiveness (msg.rs).** `Command::decode` (msg.rs:511), `Response::decode` (msg.rs:613), `FileOp::decode` (msg.rs:261) all end `t => return Err(WireError::BadTag(t))`. No fall-through. Tested by `bad_fileop_tag_errors` (msg.rs:785-795). Sound. (Sub-field u8 discriminators like `Channel.status` remain unvalidated — LOW above.)

- **`reject_zero` is in the right place and covers both `generate()` paths.** `fill_random_checked` (crypto.rs:210-220) is the single chokepoint: it calls `random_bytes` *then* `reject_zero`, and both `ServerKeypair::generate` (crypto.rs:240) and `ImplantKeypair::generate` (crypto.rs:300) go through it. The check runs after the fill and before `StaticSecret::from(bytes)`, so an all-zero buffer can never reach `StaticSecret`. Correct placement. (Gap: `from_secret_bytes` — see NEW-MED-1.)

- **HKDF `info` transcript binding.** `info` = `"nyx-session-v1" || server_pub || implant_pub` (crypto.rs:347-353), bound at expand stage; salt = `server_pub` bound at extract stage (crypto.rs:342); AAD on every AEAD op = implant pubkey (frame.rs:64, 128). Both ECDH identities + a version label are bound into derivation, and the session identity is double-bound (derivation + AEAD auth). A flipped pubkey in the frame header fails either key derivation or the AAD tag check. Sound.

- **`SessionKey` zeroize-on-drop is now real.** `Drop` (crypto.rs:76-81) calls `self.0.zeroize()` + `compiler_fence(SeqCst)`. `Copy` removed so the destructor actually runs. Intermediate `okm` (crypto.rs:359), `shared_bytes` (crypto.rs:273, 317), and `bytes` (crypto.rs:242, 302) all explicitly `.zeroize()`. The `key.clone()` sites in the server (lib.rs:584, 623) produce independent clones each with their own `Drop` — no residual un-zeroized copy. Sound.

- **AEAD infallibility on encrypt.** `seal_dir` (crypto.rs:413-421) `.expect("chacha20poly1305 encrypt is infallible")` — correct: ChaCha20-Poly1305 encrypt only fails on nonce reuse, a programming error the caller prevents via the direction discriminator + monotonic counter. Sound.

- **`GenerateError` is correctly `pub` and re-exported; `CryptoError` is correctly *not* re-exported.** lib.rs:34 re-exports `GenerateError` (the type every caller sees); `CryptoError` is `#[cfg(not(feature="std"))]` and stays internal to the no_std fill path (grep confirms no external caller references it). The split is deliberate and correct — callers only depend on `GenerateError`, keeping the no_std-specific fill-failure detail out of the public API. Sound.

- **`SessionKey::new` / `as_bytes` / `Clone` / `PartialEq` / `Eq` / `Hash` do not leak.** `as_bytes` returns `&[u8; KEY_LEN]` (crypto.rs:37-39) — a borrow, no copy; the explicit `Clone` (crypto.rs:42-46) is the only duplication path and is deliberate. `PartialEq` (crypto.rs:48-54) compares bytes only when a caller invokes `==`; the comment correctly notes it's test-only. `Hash` (crypto.rs:57-61) hashes bytes only when inserted into a hash structure. None of these print the key. Sound.

- **Fuzz harness (`fuzz/fuzz_targets/decode_vec.rs`) still targets the attacker-facing decode surface.** File present (3255 bytes), exercises `Task::decode_vec`, `TaskResponse::decode_vec`, and raw `Reader` walks. The `server panic = abort` ⇒ decode-panic = DoS rationale holds. Sound.

- **Roundtrip test coverage is comprehensive and was updated for the new signatures.** The diff shows every `generate()` test call site updated to `.unwrap()`/`.expect()`, plus two new regression tests: `session_key_debug_does_not_leak_bytes` (roundtrip.rs:392-405, for HIGH-NEW-P2) and `keypair_generate_never_yields_zero_scalar` (roundtrip.rs:412-434, for CRIT-NEW-1). The latter asserts the derived pubkey differs from `[0u8;32]` for both keypair types — a direct behavioral assertion of the fix. Coverage spans ECDH mutuality, per-session key uniqueness, frame seal/open, wrong-key rejection, batch roundtrips (incl. empty), frame edge cases, nonce-direction non-collision, allocation-bomb rejection, channel/bof/inject/token variants, and constant pins. Sound.

---

## Summary

| Severity | Count | Items |
|---|---|---|
| CRITICAL (07-08) | 1 → **0** | CRIT-NEW-1 CSPRNG-ignored → **FIXED** (crypto.rs:157-175) |
| HIGH (07-08) | 3 → **0** | HIGH-NEW-P1 SessionKey no-Drop → **FIXED** (crypto.rs:76-81); HIGH-NEW-P2 SessionKey Debug → **FIXED** (crypto.rs:63-68); HIGH-2 HKDF empty salt → **FIXED** (crypto.rs:342) |
| MEDIUM (NEW) | 1 | NEW-1 `from_secret_bytes` bypasses `reject_zero` (crypto.rs:259-264) |
| LOW (07-08, still present) | 5 | LOW-1 Reader::blob no cap; LOW-2 Bof>256 truncate; Task::encode_vec truncate; encode/decode cap asymmetry; Channel.status unvalidated |
| LOW (07-08, fixed) | 2 → **0** | XOR label dead code → **FIXED**; (ServerKeypair Clone → still present, counted below) |
| LOW (07-08, still present) | 1 | ServerKeypair Clone (crypto.rs:224) |
| LOW (NEW) | 4 | NEW-2 duplicated doc block; NEW-3 OsRng-fallback contract gap; NEW-4 ZeroScalarMarker dead type; NEW-5 info buffer oversized |

**Baseline disposition:**
- CRIT-NEW-1 → **FIXED** (verified at all 5 no_std + all std call sites; no caller ignores the `Result`)
- HIGH-NEW-P1 → **FIXED** (real `Drop`, `Copy` removed, no call site breaks)
- HIGH-NEW-P2 → **FIXED** (redacted `Debug`, regression test present)
- HIGH-2 → **FIXED** (`Some(server_pub)` salt)
- LOW-1, LOW-2, Task truncate, cap asymmetry, Channel.status, ServerKeypair Clone → **STILL PRESENT** (no diff to wire.rs/msg.rs; Clone left on ServerKeypair)
- XOR label → **FIXED**

**Top priority (NEW):** NEW-MED-1 (`from_secret_bytes`) — close the last hole in the zero-scalar rejection invariant so the fix's own docstring ("never legitimate / always caught") holds uniformly. One-line guard + a `Result` return.

**Overall assessment:** The fix-in-progress for the protocol/crypto layer is **high quality and substantially complete**. The catastrophic CSPRNG CRITICAL and all three HIGHs are correctly resolved with no regressions at any call site. The remaining open items are LOWs that were correctly out of scope for this fix pass, plus one new MEDIUM defense-in-depth gap worth closing while the fix is still uncommitted.
