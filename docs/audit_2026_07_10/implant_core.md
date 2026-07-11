# Implant Core (crates/implant-win) — Line-by-Line Audit (2026-07-10 deep pass)

**Scope:** `entry.rs`, `dllmain.rs`, `beacon.rs`, `shell.rs`, `inject.rs`, `tp.rs`,
`transport.rs`, `context.rs`, `config.rs`, `resolve.rs`, `version.rs`, `hostinfo.rs`,
`lib.rs`. (Also read the in-domain-spirit `mem.rs`, `bof.rs`, `fluctuation.rs` diffs
because they are load-bearing for re-verifying CRIT-NEW-4 and the bof.rs overflow fix.)

**Mode:** static review only. Every line number cited was read directly from the file
this pass, with `git diff` applied to see the fix-in-progress code. Severity rubric per
`_CONTEXT.md` (CRIT/HIGH/MED/LOW/INFO). The `状态` field is mandatory for prior findings.

---

## RE-VERIFICATION SUMMARY (07-08 baseline)

| Prior ID | Severity | Status | New lines | One-line verdict |
|---|---|---|---|---|
| CRIT-NEW-2 | CRITICAL | **FIXED** | `tp.rs:1-44`, `inject.rs:662` | Honesty note rewritten; success message now says "NtCreateThreadEx (remote-thread IOC present — NOT threadless)" |
| CRIT-NEW-4 | CRITICAL | **FIXED** | `mem.rs:121-147` | `mask_key()` caches key in `MASK_KEY_BUF`; `&'static` return; callers updated |
| HIGH-NEW-I1 | HIGH | **FIXED** | `shell.rs:35-38, 295-303` | `INFINITE` → `SHELL_TIMEOUT=30_000`; on `WAIT_TIMEOUT` `TerminateProcess` + marker |
| HIGH-NEW-I2 | HIGH | **STILL PRESENT** | `tp.rs:245, 343-350` | `_TP_DIRECT` 24 B write still at `local_base + shellcode.len()`; section only page-rounded; unchanged by diff |
| MED-NEW-I1 | MED | **STILL PRESENT** | `beacon.rs:555-557` | `SEED = AtomicU32::new(0x9E37_79B9)`; still fixed constant; comment unchanged |
| MED-NEW-I2 | MED | **PARTIALLY FIXED** | `shell.rs:296-303` | Timeout path appends a marker; the **1 MiB cap path still does not** |
| MED-NEW-I3 | MED | **STILL PRESENT** | `tp.rs:238,246,363,373` | `target_h`/`section_h`/`h_thread` never closed on any path |
| MED-NEW-I4 | MED | **STILL PRESENT** | `transport.rs:156-216` | `DONE.store(true)` still fires on first `LoadLibraryA` failure; permanent deaf |
| MED-NEW-I5 | MED | **STILL PRESENT** | `beacon.rs:346-361` | `SetChannel` out-of-range → `SmbPipe` → success ack; `transport.rs:60` still `return None` |
| (LOW) `.expect` panics | LOW | **STILL PRESENT** | `beacon.rs:67,125,163,217,250,288` | Six `.expect()`s on `encode_vec`/`encode` unchanged |

---

## CRITICAL

### [CRITICAL] pool_party still lies in `do_inject` code-comment block (the *code* is honest, a *stale doc comment* is not) — LOWER-SEVERITY RESIDUE of CRIT-NEW-2
- **位置:** `crates/implant-win/src/inject.rs:626-631` (the `do_inject` doc), `:633-637` (second methods list)
- **状态:** NEW (residue — CRIT-NEW-2 itself is FIXED, this is a stale doc the fix missed)
- **已核验:** The fix correctly rewrote (a) the `tp.rs` module header (`tp.rs:1-44` — accurate "PARTIAL / HONESTY NOTE / NOT threadless") and (b) the runtime success message (`inject.rs:662`: `") — section delivery ok, executed via NtCreateThreadEx (remote-thread IOC present — NOT threadless)"`). BUT the **`do_inject` rustdoc at `inject.rs:626-631`** still reads:
  ```
  /// - `0` — **Pool Party** (section-backed delivery + NtCreateThreadEx).
  ///   Worker-queue splice is deferred; current path avoids VirtualAllocEx/WPM.
  ```
  followed by a *contradictory* second list at `:633-637`:
  ```
  /// - `0` — Pool Party (thread-pool section-backed). **Not yet implemented**;
  ///   silently falls back to method 2 (module stomp) with a warning prefix so
  ///   the operator knows the requested technique was substituted.
  ```
- **描述:** The `do_inject` doc now contains two mutually inconsistent method-0
  descriptions, and the second one ("Not yet implemented; silently falls back") is
  itself stale — the code at `inject.rs:650-694` no longer "silently falls back"; on
  `gate OFF or pid==0` it returns an explicit `Response::Err` (`:689-694`). A future
  maintainer reading the rustdoc gets a wrong mental model of both the capability and
  the fallback behavior.
- **影响:** Doc/behaviour drift. Not operator-facing at runtime (the message and the
  `Err` are correct), but it will mislead the next person editing this file into
  reintroducing the silent-fallback or removing the honesty note.
- **修复:** Collapse the two method lists into one; state method 0 = section delivery
  + `NtCreateThreadEx` (remote-thread IOC present, NOT threadless); on `gate OFF /
  pid==0` return `Response::Err` (not silent fallback).

> Note: I am recording the CRIT-NEW-2 **re-verification** here as FIXED. The stale-doc
> residue above is a LOW-severity cleanup; I list it under CRITICAL only because it is
> the direct continuation of the prior CRIT and an auditor skimming should see that the
> headline lie is gone. The actual remaining severity is LOW.

---

## HIGH

### [HIGH] pool_party_inject: out-of-bounds write of 24-byte `_TP_DIRECT` past the mapped section view — STILL PRESENT
- **位置:** `crates/implant-win/src/tp.rs:245` (section sizing), `:343-350` (the write)
- **状态:** STILL PRESENT (HIGH-NEW-I2; the `tp.rs` diff only rewrote the module doc comment — it did NOT touch the write)
- **已核验:**
  ```rust
  // tp.rs:245
  let section_size: i64 = ((shellcode.len() + 0xFFF) & !0xFFF) as i64;
  // tp.rs:343-350
  let direct_addr = unsafe { (local_base as *mut u8).add(shellcode.len()) };
  let direct_view: *mut TpDirect = direct_addr as *mut TpDirect;
  unsafe {
      (*direct_view).type_tag = 0x5444_4952_4543_5450; // 8 B
      (*direct_view).fn_table = 0;                       // 8 B
      (*direct_view).callback = target_base as usize;    // 8 B
  }
  ```
  `TpDirect` is `#[repr(C)]` over three `usize` fields = **24 bytes** (`tp.rs:157-166`).
  The section is rounded only to a 4096-byte page. The write starts at
  `local_base + shellcode.len()` and spans `+24`. For any `shellcode.len()` in the top
  24 bytes of a page (4073..=4096, 8169..=8192, 12201..=12288, …) the 24-byte write
  runs off the end of the mapped view.
- **描述:** Same root cause as 07-08. Heap/section overflow → `STATUS_ACCESS_VIOLATION`
  (0xC0000005). Under `panic=abort`/no SEH this is process death inside
  `pool_party_inject`. The written struct is also **dead code** — no worker ever
  dereferences it (the honest module doc now says the queue-splice half is unimplemented),
  so the write carries the full OOB risk with zero benefit.
- **影响:** Operator-supplied shellcode of a trigger length crashes the implant in the
  (off-by-default, opt-in) Pool Party path. The fix-in-progress did not address it.
- **修复:** Size the section with explicit slack:
  `((shellcode.len() + core::mem::size_of::<TpDirect>() + 0xFFF) & !0xFFF)` — or, since
  the `_TP_DIRECT` is unreachable dead code, **delete the write entirely** until the
  queue-splice path that would consume it is implemented.

---

## MEDIUM

### [MED] Deterministic sleep-jitter seed shared by every beacon — STILL PRESENT
- **位置:** `crates/implant-win/src/beacon.rs:555-557` (esp. `:557`)
- **状态:** STILL PRESENT (MED-NEW-I1; not in the diff)
- **已核验:**
  ```rust
  // beacon.rs:555-557
  // Cheap LCG over a static seed — no need for a CSPRNG here (this only
  // shapes sleep length, not anything secret). xorshift32.
  static SEED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x9E37_79B9);
  ```
  Every process starts the xorshift32 stream from the same constant `0x9E37_79B9`. The
  comment still justifies it on secrecy grounds, which misses the real issue.
- **描述:** Because the seed is a fixed per-process constant (not mixed with host
  entropy), every Nyx beacon exhibits the identical jitter sequence on its first
  cycles. Two beacons on different hosts in the same network produce the same
  inter-request timing pattern until their respective counters (advanced every cycle,
  identically) drift — which they do identically, so they stay in lockstep.
- **影响:** An NDR/flow sensor correlating beacon cadence across hosts sees a repeating
  timing signature — a network-level fingerprint that scales with fleet size.
- **修复:** Seed the xorshift from `hostinfo::beacon_id()` once at `beacon_loop` start
  (store into the static). `hostinfo::beacon_id()` (`hostinfo.rs:217-231`) already mixes
  `KUSER_SHARED_DATA` tick count with the PID via xorshift32 — exactly the per-host
  entropy this needs.

### [MED] Shell output truncated at 1 MiB with NO truncation marker on the cap path — PARTIALLY FIXED
- **位置:** `crates/implant-win/src/shell.rs:44` (`MAX_OUTPUT = 1 << 20`), `:242-252` (cap branch), `:283-289` (terminate on cap), `:296-303` (timeout marker), `:315` (`Response::Output(out)`)
- **状态:** PARTIALLY FIXED (MED-NEW-I2)
- **已核验:** The fix added a timeout marker ONLY on the `WAIT_TIMEOUT` branch:
  ```rust
  // shell.rs:296-303
  let wait_result = wait_for_single(pi.h_process, SHELL_TIMEOUT);
  if wait_result == WAIT_TIMEOUT {
      ...
      out.extend_from_slice(b"\n<nyx: shell command timed out and was killed>\n");
  }
  ```
  But the **1 MiB cap path does NOT append a marker.** When `out.len() >= MAX_OUTPUT`
  (`:243-251`) the loop breaks with `capped = true`; the child is `TerminateProcess`'d
  (`:283-289`); the bounded wait then succeeds immediately (child already dead, so
  `wait_result != WAIT_TIMEOUT`); control reaches `:315` `Response::Output(out)` and
  returns the first 1 MiB verbatim — no `…<truncated at 1 MiB>` suffix.
- **描述:** The fix closed the *timeout* silent-truncation case but left the *cap*
  silent-truncation case open. An operator running a command whose stdout exceeds 1 MiB
  (`type huge.log`, `dir /s`, registry dumps, `whoami /groups` in a huge forest) still
  receives the first 1 MiB looking like complete output.
- **影响:** Decisions made on silently-truncated tail data, no telemetry. The most
  common large-output case (a big log/cat) hits the cap path, not the timeout path — so
  this is the more frequently triggered of the two truncation cases.
- **修复:** Append a constant marker when `capped` is true, before building the
  `Response`, mirroring the timeout marker:
  ```rust
  if capped {
      out.extend_from_slice(b"\n<nyx: shell output truncated at 1 MiB>\n");
  }
  ```
  (place it just before line 315).

### [MED] pool_party_inject leaks target/section/thread handles on every path — STILL PRESENT
- **位置:** `crates/implant-win/src/tp.rs` — `target_h` (`:238`), `section_h` (`:246`), `h_thread` (`:373`)
- **状态:** STILL PRESENT (MED-NEW-I3; not in the diff)
- **已核验:** `OpenProcess` → `target_h` (`:238`), `NtCreateSection` → `section_h`
  (`:246`), `NtCreateThreadEx` → `h_thread` (`:373`). None are closed on the `Ok` path
  (`:380-384`) nor on most `Err` returns (`:240, 260, 283, 317, 365`). Only `local_base`
  is explicitly unmapped (`:316, 361`). Note `section_h` is **never closed anywhere** —
  not even in a cleanup epilogue.
- **描述:** Per-injection handle leak toward the target process + a leaked section
  handle + (on success) a leaked thread handle. Repeated `Inject` calls exhaust the
  implant's handle table and leave forensic artifacts (handles to victim PIDs) visible
  to EDR / `Process Explorer` / `System.Diagnostics.Process.GetProcesses`.
- **影响:** Forensic IOC accumulation + eventual handle-table exhaustion in long-lived
  beacons that inject repeatedly.
- **修复:** Resolve `CloseHandle` once, then close `target_h`, `section_h`, `h_thread`
  on every exit path. Cleanest shape: a single labelled-cleanup epilogue or RAII guard.
  Don't forget to close `section_h` even on success.

### [MED] ensure_winhttp permanently deafens the beacon on a transient LoadLibrary failure — STILL PRESENT
- **位置:** `crates/implant-win/src/transport.rs:156-216` (esp. `:173-177`)
- **状态:** STILL PRESENT (MED-NEW-I4; `transport.rs` has NO uncommitted diff)
- **已核验:**
  ```rust
  // transport.rs:173-177
  if !winhttp_loaded {
      // Can't load winhttp — transport unavailable.
      DONE.store(true, Ordering::Release);   // permanent — never retried
      return;
  }
  ```
  `DONE` is the one-shot gate; once set, every later `ensure_winhttp` early-returns
  (`:157-159`) and `WINHTTP` stays `None`. Note the function table-resolve success path
  at `:192-215` correctly sets `DONE` only after a full resolve — but the load-failure
  branch at `:173-177` sets it unconditionally on the first failed `LoadLibraryA`.
- **描述:** If the first `LoadLibraryA("winhttp.dll")` fails (transient low-memory,
  loader-lock contention during early process init, a brief SRW-lock hold, a GPO that
  delays KnownDlls resolution), the beacon marks the transport permanently unavailable.
  Every subsequent `channel_post_frame` returns `None` forever.
- **影响:** The beacon check-in retry loop (`beacon.rs:79-92`) then spins forever
  against a "transport down" that was actually a one-shot transient — silent permanent
  death indistinguishable from a real network failure.
- **修复:** Only set `DONE=true` after the function table is fully resolved (`:214`,
  already correct). On load-failure leave `DONE=false` so the next cycle re-attempts
  (optionally with a backoff counter to avoid hot-spinning against a genuinely absent
  winhttp.dll).

### [MED] Setting channel to SmbPipe (or any out-of-range id) still silently kills the beacon with a success ack — STILL PRESENT
- **位置:** `crates/implant-win/src/beacon.rs:346-361` (dispatch, `_ => Channel::SmbPipe` at `:354`), `crates/implant-win/src/transport.rs:60` (`Channel::SmbPipe => return None`)
- **状态:** STILL PRESENT (MED-NEW-I5; neither file is in the diff)
- **已核验:** `beacon.rs:346-361`:
  ```rust
  Command::SetChannel { channel } => {
      let ch = match channel {
          0 => crate::transport::Channel::Https,
          ...
          5 => crate::transport::Channel::WebTrans,
          _ => crate::transport::Channel::SmbPipe,   // any unknown id → SmbPipe
      };
      crate::transport::set_channel(ch);
      ...
      out.extend_from_slice(b"Channel set to: ");
      out.extend_from_slice(crate::transport::channel_name(ch).as_bytes()); // "smb-pipe"
      vec![Response::Output(out)]
  }
  ```
  `transport.rs:60`: `Channel::SmbPipe => return None`. The beacon task loop treats
  `None` as "transport failed, retry next cycle" (`beacon.rs:129-136` → `continue`).
- **描述:** No SMB-pipe transport exists. `SetChannel 6` (or any out-of-range id, which
  silently maps to 6) returns `"Channel set to: smb-pipe"` — a success message — and
  the beacon then never succeeds again.
- **影响:** Silent, permanent beacon death with a success acknowledgement for the
  command that caused it. Operator believes the channel switch worked; the beacon simply
  stops checking in. The `tp.rs`/`inject.rs` honesty fix did not extend here.
- **修复:** Reject `Channel::SmbPipe` (and any out-of-range id) at `SetChannel` with
  `Response::Err("smb-pipe transport not implemented")`. At minimum do not report
  `Output` for an unimplemented channel.

---

## LOW

### [LOW] `.expect()` on `encode_vec`/`encode` still panics the implant if any single response blob exceeds 256 KiB — STILL PRESENT
- **位置:** `crates/implant-win/src/beacon.rs:67, 125, 163, 217, 250, 288`
- **状态:** STILL PRESENT (prior LOW; not in the diff)
- **已核验:** e.g. `beacon.rs:125`
  ```rust
  let frame = encode_frame(&pubkey, counter, &key,
      &TaskResponse::encode_vec(&pending).expect("beacon batch encodes within MAX_BLOB_LEN"));
  ```
  `TaskResponse::encode_vec` returns `Err(WireError::BadLen)` if any blob inside a
  response exceeds `wire::MAX_BLOB_LEN` (256 KiB). `.expect()` then panics →
  `panic=abort` → `ExitProcess(0xC000_0001)` via `lib.rs:157-178`.
- **描述:** The `BATCH_FLUSH = 200 KiB` heuristic (`beacon.rs:30, 161`) bounds
  *accumulated* batch size, not *individual* blob size. A single producer that emits a
  > 256 KiB `FileChunk`/`Output`/`Image` (an un-chunked screenshot BMP, a large
  `hashdump` hive read, a download) converts the wire layer's defense-in-depth length
  check into a process-killing panic.
- **影响:** Latent implant death dependent on every response producer respecting the
  256 KiB cap.
- **修复:** Replace the `.expect()`s with `match … { Ok(b) => …, Err(_) => { /* drop
  the oversized response, emit Response::Err("oversized") */ } }`.

### [LOW] mem.rs `mask_key()` SAFETY comment overclaims "beacon is single-threaded" — the keylogger spawns a background thread
- **位置:** `crates/implant-win/src/mem.rs:126, 141` (SAFETY comments), `crates/implant-win/src/keylog.rs:861` (`CreateThread`)
- **状态:** NEW (documentation-accuracy issue found this pass)
- **已核验:** `mask_key()` justifies its `static mut MASK_KEY_BUF` write with "the
  beacon is single-threaded (documented invariant) so there is no concurrent mutation"
  (`mem.rs:124-127, 139-142`). But `keylog.rs:861` resolves `kernel32!CreateThread` and
  spawns a background thread (`keylog.rs:441` "called by `CreateThread`"). So the process
  is NOT single-threaded once keylogging is armed.
- **描述:** The blanket "beacon is single-threaded" invariant is false. The `MASK_KEY_BUF`
  race is **benign in practice** because the keylogger thread does not call
  `crate::mem::mask`/`unmask`/`mask_key` (verified: the keylog/pivot `crate::mem::`
  references are all `core::mem::transmute`, not the masking module), so only the beacon
  thread ever touches `MASK_KEY_BUF`. But the stated reasoning is wrong, and a future
  change that makes the keylogger (or any other spawned thread) mask regions would
  silently introduce a data race on a `static mut`.
- **影响:** No current functional bug. Forensic-maintainability hazard: the SAFETY
  argument is incorrect, so it cannot be relied on when reasoning about future changes.
- **修复:** Tighten the SAFETY comment to the actual invariant: "`MASK_KEY_BUF` is only
  ever read/written from the beacon thread; no other thread calls into the `mem` masking
  API." Consider using an `AtomicU8`-keyed `OnceCell`-style pattern instead of a bare
  `static mut` to make the invariant structural rather than convention-based.

### [LOW] do_inject Pool Party success path never closes the (leaked) handles even though the sibling methods do — inconsistency
- **位置:** `crates/implant-win/src/inject.rs:650-664` (Pool Party Ok path), `:742-748` (threadless Ok path closes handles via `nt_close`)
- **状态:** NEW (consistency/maintainability, found this pass)
- **已核验:** The threadless path (`:742-748`) explicitly closes `proc.handle` and
  `proc.main_thread` via `nt_close`. The Pool Party Ok path (`:652-663`) builds and
  returns the success message without closing anything — it relies entirely on
  `pool_party_inject` to clean up, which (per MED-NEW-I3 above) it does not.
- **描述:** Inconsistent cleanup discipline between sibling inject methods; the Pool
  Party path is the leaky one and also the one without any caller-side handle hygiene.
- **影响:** Same handle-leak forensic/exhaustion consequence as MED-NEW-I3; listed
  separately because the fix is at a different call site.
- **修复:** Either have `pool_party_inject` close all its own handles on every path
  (preferred), or have the `do_inject` Ok branch close the handles `pool_party_inject`
  returns (would require `pool_party_inject` to hand them back).

---

## 已验证干净的区域 (INFO — checked and sound this pass)

- **CRIT-NEW-2 honesty rewrite — VERIFIED CORRECT (the headline lie is gone).** `tp.rs:1-44`
  module doc now accurately states "only the *payload delivery* half … is implemented …
  Execution … falls back to `NtCreateThreadEx` … the classic remote-thread IOC IS
  present … Calling this 'threadless' or '0-of-3 FND' is incorrect." The runtime message
  at `inject.rs:662` matches: `"section delivery ok, executed via NtCreateThreadEx
  (remote-thread IOC present — NOT threadless)"`. The `do_inject` gate also now returns
  an explicit `Response::Err` instead of silently degrading when the gate is off
  (`inject.rs:689-694`). The only residue is the stale *doc-comment* lists (CRIT-NEW-2
  residue note above) — the operator-visible behavior is honest.

- **CRIT-NEW-4 mask_key cache fix — VERIFIED CORRECT.** `mem.rs:121-147`: `mask_key()`
  now caches the 32-byte RC4 key in `static mut MASK_KEY_BUF` guarded by `MASK_KEY_INIT`
  (Acquire/Release pairing), and returns `&'static [u8; 32]`. The two callers
  (`apply_rc4_to_regions:154,169` and `round_trip_selftest`) both take the shared
  reference. The original bug (key A on mask, key B on unmask → keystream∘keystream
  corruption) is genuinely fixed: mask and unmask now provably use the same key. The
  rdtsc fallback is also cached, so mask/unmask agree even when the CSPRNG is down.

- **HIGH-NEW-I1 bounded shell wait — VERIFIED CORRECT.** `shell.rs:35-38` defines
  `SHELL_TIMEOUT = 30_000` and `WAIT_TIMEOUT = 0x0000_0102`. `:295` waits with the
  bounded timeout; `:296-303` on `WAIT_TIMEOUT` resolves `TerminateProcess`, kills the
  child, and appends `\n<nyx: shell command timed out and was killed>\n`. The previous
  INFINITE-wait permanent-death scenario is closed. (The companion cap-path marker is
  still missing — see MED-NEW-I2 partial fix.)

- **bof.rs BeaconDataExtract i32-overflow OOB read — VERIFIED FIXED (the `+16` line diff).**
  `bof.rs:368-392`: negative length is rejected first (`:369-375`); the bounds check is
  now done in `usize` via `4usize.checked_add(len_u).unwrap_or(usize::MAX)` compared
  against `left as usize` (`:379-386`), eliminating the old `left < 4 + len` signed-wrap
  bypass when `len ≈ i32::MAX`. The cursor advance uses `len_u` (`:388`). This is a
  correct, complete fix for the OOB read.

- **beacon.rs CSPRNG-failure handling — VERIFIED CORRECT (the `+19` beacon diff).**
  `beacon.rs:42-50`, `:194-200`, and `entry.rs:549-552`/selftest all now `match` on
  `ImplantKeypair::generate()`'s `Result`, diagnosing + aborting cleanly on
  `Err(GenerateError::CsprngFailed | ZeroScalar)` instead of proceeding with a
  zero/identity-point scalar. `fill_random_checked` (`crypto.rs:210-220`) rejects the
  all-zero scalar as defense-in-depth. `csprng_fill` (`entry.rs:208-233`) caches
  `SystemFunction036` and returns `false` cleanly on resolution/call failure.
  Registration ordering is sound: every beacon entry path registers the CSPRNG before
  keygen (`bootstrap():183`, `init_minimal():292`).

- **dllmain.rs — STILL SOUND.** `DllMain` (`dllmain.rs:47-61`) is `mov eax,1; ret` with
  `options(nostack, nomem)` + `unreachable_unchecked()`. No loader-lock reentrancy, no
  TLS callback, no GS cookie. The Server-2025 `STATUS_STACK_BUFFER_OVERRUN` mitigation
  is coherent. No diff this pass — unchanged and still correct.

- **beacon.rs counter/nonce discipline — STILL SOUND.** 64-bit `counter` is read-then-
  incremented at check-in (`:77-78`), task POST (`:125-126`), flush (`:163-170`),
  oneshot (`:225-226, 250-251, 288-289`). `Direction::ServerToClient` on open (`:143`).
  Failed check-ins still advance the counter (correct — AEAD nonce must never repeat).

- **beacon.rs AEAD/frame error recovery — STILL SOUND.** `parse_frame`,
  `open_frame_dir`, `Task::decode_vec` failures all `continue` (`:138-148`) — a
  malformed server response cannot kill the beacon.

- **beacon.rs command dispatch — STILL exhaustive by construction.** `execute`
  (`:331-497`) has no `_ =>` default arm; adding a new `Command` variant breaks the
  build. All 21 variants route to real handlers.

- **context.rs — STILL SOUND.** `Context` is `#[repr(C, align(16))]` over `[u8; 1232]`;
  `const _: () = assert!(size_of == 1232)`, `assert!(align_of == 16)` (`:162-169`),
  `assert!(1232 == 0x4D0)` (`:172`). Accessor offsets match WinNT.h x64. `SegSs` is
  written via `write_unaligned` at `0x42` (`:209`) — correct offset, unaligned-safe.
  `CTX_BUF` is `.fill(0)` each call (`:200`).

- **resolve.rs — STILL SOUND, well-defended.** Forwarder detection
  (`export_addr_by_hash_pub:449-507`) uses the export-directory **size** (not function
  count) for the forwarder bounds check (`:467, 479-480`) — the documented prior
  `AddVectoredExceptionHandler` AV root cause. `find_module_by_hash`/`find_module_for_forwarder`
  carry `_guard < 256/512` iteration caps (`:269, 421, 561`) preventing infinite loops on
  a corrupted loader list. Ordinal bounds-checked against `num_funcs` (`:85-87, 494-497`).

- **config.rs tamper response — STILL SOUND.** `load()` (`:50-80`) on Poly1305 tag
  mismatch / malformed blob escalates `ExitProcess → TerminateProcess → int3`; the
  trailing `spin_loop` is only the `-> !` type satisfier. Plaintext returned for
  `mem::register_owned` masking.

- **transport.rs response read — STILL SOUND.** Per-read buffer clamped to
  `min(avail, 1<<20)` (`:395`); total response capped at `MAX_RESPONSE_BYTES = 16 MiB`,
  returns `None` cleanly on overflow (`:405-409`). Handles closed on every error branch
  and on success.

- **version.rs — STILL SOUND.** `read_build_number_raw` uses `read_unaligned` (`:53`),
  returns 0 on missing PEB. CET probe caches into `AtomicU8` (`:66-74`), returns `false`
  (correct for pre-24H2) when `IsProcessorFeaturePresent` unresolved. `dec_u32` bounded
  by `[0u8; 10]`.

- **shell.rs pipe/handle hygiene — STILL SOUND (and the fix improved it).** Parent's
  write end closed before draining (`:236`); read end non-inheritable (`:182`); on
  `CreateProcessW` failure both pipe ends closed (`:226-227`); on success
  `h_process`/`h_thread`/`child_std_out_read` all closed (`:311-313`). Final-chunk clamp
  against `MAX_OUTPUT` (`:269`). The new bounded-wait + TerminateProcess on timeout
  (`:295-303`) is correct and closes the deadlock window.

- **hostinfo.rs beacon_id — SOUND and reusable.** `beacon_id()` (`:217-231`) mixes
  `KUSER_SHARED_DATA` TickCountLow with PID via xorshift32, guards the zero state, and
  is the natural entropy source the jitter-seed fix (MED-NEW-I1) should consume.

- **lib.rs panic handler — STILL SOUND.** Resolves `ExitProcess` and exits
  `0xC000_0001` (`:166-171`); infinite spin is the explicit last-resort fallback. Does
  not format `PanicInfo`, so no secret/config leak via panic.

---

## Baseline cross-check

None of the 13 original 07-08 baseline findings (`CRIT-1..5`, `HIGH-1..8`, `MED/LOW`
in sibling modules) live in these 13 audited files. The 10 "NEW" findings from the
07-08 *implant-core* sub-report are the items in the RE-VERIFICATION SUMMARY table
above. Verified call-sites:
- `beacon.rs:362-379` (`Command::Trex`) faithfully renders `trex::assess_user_mode()`.
- `beacon.rs:466-496` (`Command::Inject`/`StealToken`/`MakeToken`/…) route to
  `inject::do_inject` and `postex`; the beacon itself is a faithful dispatcher.
- The keylogger thread (`keylog.rs:861`) does not call into `crate::mem` masking, so the
  mem.rs single-threaded masking invariant holds in practice (see LOW note for the
  imprecise comment).

---

## FIX-CODE QUALITY NOTES (the uncommitted diff itself)

The fix-in-progress touched 6 files in this domain. Quality assessment of each hunk:

1. **`beacon.rs` (+19): CSPRNG-failure `match` on keygen.** Correct and complete.
   Both `beacon_loop` (`:42-50`) and `beacon_oneshot` (`:194-200`) handle `Err`. The
   `diag_mark` calls are no-ops without `--cfg nyx_diag`. No new bugs introduced.
   *Minor:* the oneshot doc-comment lost a line (`:186-187` — the "2 = check-in
   succeeded AND …" bullet became orphaned text "its response POSTed back"), harmless.

2. **`bof.rs` (+16): BeaconDataExtract overflow fix.** Correct and complete (see INFO
   above). The `checked_add` + `usize` comparison is the right idiom. No new bug.

3. **`entry.rs` (+5): selftest keygen match.** Correct; `report_exit(exit_proc, 0xE00)`
   on CSPRNG failure. No new bug.

4. **`inject.rs` (+2): success-message rewrite + Err on gate-off.** Correct and an
   improvement (explicit `Response::Err` instead of silent degrade, `:689-694`). Residue:
   stale rustdoc (see CRIT-NEW-2 residue note).

5. **`mem.rs` (+54): mask_key caching.** Correct root-cause fix (see INFO above). Residue:
   imprecise SAFETY comment (see LOW note). No functional bug.

6. **`shell.rs` (+30): bounded wait + timeout marker + TerminateProcess.** Correct for
   the timeout case. Residue: the cap-path truncation marker is still missing
   (MED-NEW-I2 partial).

7. **`tp.rs` (+40): doc-comment honesty rewrite only.** The entire `tp.rs` diff is the
   module header rewrite — it does **not** touch the `_TP_DIRECT` OOB write
   (HIGH-NEW-I2 still present) nor the handle leaks (MED-NEW-I3 still present). The
   honesty note is accurate and valuable, but it is a *documentation* fix for a *code*
   problem; the underlying `NtCreateThreadEx` execution is unchanged.

**Net assessment of the fix pass:** 3 of 10 prior findings genuinely fixed
(CRIT-NEW-2 msg, CRIT-NEW-4, HIGH-NEW-I1) + the bof.rs overflow (bonus). 1 partially
fixed (MED-NEW-I2 — timeout marker only). 5 still present (HIGH-NEW-I2, MED-NEW-I1/I3/
I4/I5) + the LOW `.expect` cluster. The fixes that landed are high-quality and address
root causes; the gap is coverage, not correctness.
