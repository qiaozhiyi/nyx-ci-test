# Implant Core (crates/implant-win) — Line-by-Line Audit (2026-07-08)

**Scope:** `beacon.rs`, `entry.rs`, `dllmain.rs`, `lib.rs`, `context.rs`, `config.rs`,
`envelopes.rs`, `transport.rs`, `tp.rs`, `shell.rs`, `version.rs`, `build.rs`.

**Mode:** static review only. Every line number cited was read directly from the file
this pass. New findings beyond the 2026-07-08 baseline; the baseline items (CRIT-1..5,
HIGH-1..8, MED/LOW) live in sibling modules (`trex/`, `caller_spoof.rs`, `fluctuation.rs`,
`server/`, `protocol/crypto.rs`) — none of the 13 baseline findings map onto these 12
files. Where the beacon calls a flagged sibling (e.g. `trex::assess_user_mode`), the
beacon itself renders the result faithfully; the stub is the sibling's bug, noted inline.

Severity rubric per `_CONTEXT.md` (CRIT/HIGH/MED/LOW/INFO).

---

## CRITICAL

### [CRITICAL] "Pool Party" inject is NtCreateThreadEx — success message falsely reports "0-of-3 FND (no CreateRemoteThread)"
- **位置:** `crates/implant-win/src/tp.rs:210-375` (impl), `crates/implant-win/src/inject.rs:650-664` (dispatch + success message), `tp.rs:1-34` (module doc)
- **已核验:**
  - `tp.rs:353-374` — the "execute" step resolves `NtCreateThreadEx` and calls it with
    `target_base` as the start address in the **remote** process:
    ```rust
    let mut h_thread: *mut c_void = core::ptr::null_mut();
    let st = unsafe { nt_cte( &mut h_thread, 0x1FFFFF, core::ptr::null(), target_h,
        target_base, core::ptr::null(), 0, 0, 0, 0, core::ptr::null()) };
    ```
  - `tp.rs:310-340` — the actual thread-pool hijack (steps a/b/d: worker discovery,
    `_TP_WORK` queue splice) is explicitly **not implemented**: *"steps (a)/(b)/(d) need
    a real target to validate the queue-splice mechanics and are left as the validation
    surface."* The `_TP_DIRECT` written at `tp.rs:336-340` is never referenced by any
    thread-pool dispatcher.
  - `inject.rs:662` — on `Ok(())` the operator sees:
    ```
    Pool Party inject ok (pid=…) — 0-of-3 FND (no VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)
    ```
  - `tp.rs:6-22` module doc: *"Pool Party abuses the Windows Thread Pool … to deliver
    shellcode without the classic IOCs (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)."*
- **描述:** The technique the operator opts into (`NYX_POOL_PARTY_ON=1`) and the message
  they rely on both advertise **threadless** injection with **no CreateRemoteThread-class
  IOC**. The implementation fires `NtCreateThreadEx` — the underlying syscall behind
  `CreateRemoteThread`, and the exact primitive EDRs hook at the syscall boundary. The
  "0-of-3 FND (no … CreateRemoteThread)" claim is materially false at the layer that
  actually matters for detection.
- **影响:** Operator selects method 0 specifically to avoid remote-thread IOCs, then
  reads a success line asserting none fired. On an instrumented host the beacon's
  injected process is killed/alerted on the `NtCreateThreadEx` the operator was told
  never happened. Total opsec failure masked as a success — the operator cannot trust
  the OPSEC telemetry the implant emits.
- **修复:** Either (a) actually implement the TP-worker queue splice (the documented
  steps a/b/d) so the claim becomes true, or (b) make the success message honest —
  e.g. `"Pool Party: section delivery ok, executed via NtCreateThreadEx (remote-thread
  IOC present — NOT threadless)"` and rewrite the `tp.rs` module header to stop
  claiming the technique avoids `CreateRemoteThread`-class primitives. Gate stays
  OFF-by-default regardless.

---

## HIGH

### [HIGH] `shell` blocks the beacon thread forever on a non-terminating command → permanent implant death
- **位置:** `crates/implant-win/src/shell.rs:287` (`wait_for_single(pi.h_process, INFINITE)`), `:31` (`const INFINITE: u32 = 0xFFFF_FFFF`)
- **已核验:** After draining stdout, the shell path waits with no timeout:
  ```rust
  wait_for_single(pi.h_process, INFINITE);
  ```
  `h_std_input` is `null` (`shell.rs:185`), so a child that only reads stdin EOFs fast —
  but a child that **does not read stdin and never exits** (`ping -t`, `notepad`, a
  server, `cmd` with a typo that drops to an interactive prompt, a compile loop writing
  past the 1 MiB cap after the kill path was already taken) is never reaped.
- **描述:** `WaitForSingleObject(INFINITE)` has no bound. The beacon loop runs on a
  single thread; one hanging `Shell` task parks that thread permanently. No later
  check-in fires, no `Exit`/`Sleep`/tasking is ever serviced.
- **影响:** A single operator command (`shell ping -t 127.0.0.1`, `shell notepad`, …)
  silently kills the implant with no error surfaced. Re-acquisition may be impossible.
  The 1-MiB cap path (`shell.rs:236-244, 276-282`) only terminates the child when the
  cap is hit *while still reading* — a child that blocks before producing 1 MiB
  (e.g. a hung network tool) bypasses it entirely.
- **修复:** Wait with a bounded timeout (e.g. `WaitForSingleObject(h, 30_000)`) and on
  `WAIT_TIMEOUT` `TerminateProcess` the child, appending a `… (timed out, killed)`
  marker to the output. Surface the timeout in `Response::Output`.

### [HIGH] `pool_party_inject`: out-of-bounds write of `_TP_DIRECT` past the section view
- **位置:** `crates/implant-win/src/tp.rs:333-340`
- **已核验:**
  ```rust
  let direct_addr = unsafe { (local_base as *mut u8).add(shellcode.len()) };
  let direct_view: *mut TpDirect = direct_addr as *mut TpDirect;
  unsafe {
      (*direct_view).type_tag = 0x5444_4952_4543_5450; // 8 B
      (*direct_view).fn_table = 0;                       // 8 B
      (*direct_view).callback = target_base as usize;    // 8 B
  }
  ```
  Section size is `((shellcode.len() + 0xFFF) & !0xFFF)` (`tp.rs:235`) — rounded up to a
  4096 page. The local view size returned by `NtMapViewOfSection` equals that page-rounded
  size. The write therefore needs `shellcode.len() + 24 <= section_size`. For
  `shellcode.len()` in the top 24 bytes of any page (e.g. 4073..=4096, 8169..=8192, …)
  the 24-byte `_TP_DIRECT` write runs off the end of the mapped view.
- **描述:** Heap/section overflow → `STATUS_ACCESS_VIOLATION` (0xC0000005) crash on the
  narrow set of shellcode lengths within 24 B of a page boundary. The written struct is
  also dead code (no worker ever dereferences it — see CRITICAL above), so the write
  carries risk with zero benefit.
- **影响:** Operator-supplied shellcode of a trigger length crashes the implant inside
  `pool_party_inject`; under `panic=abort`/no SEH this is process death.
- **修复:** Size the section with explicit slack: `((shellcode.len() + size_of::<TpDirect>() + 0xFFF) & !0xFFF)`,
  or — since the `_TP_DIRECT` is unreachable — delete the write entirely until the
  queue-splice path that would consume it is implemented.

---

## MEDIUM

### [MED] Deterministic sleep-jitter seed shared by every beacon → cross-host timing fingerprint
- **位置:** `crates/implant-win/src/beacon.rs:537-557` (esp. `:544`)
- **已核验:**
  ```rust
  static SEED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x9E37_79B9);
  ```
  Each process starts the xorshift32 stream from the same constant; the comment
  (`:542-543`) justifies it with *"no need for a CSPRNG here (this only shapes sleep
  length, not anything secret)"* — which misses the real issue.
- **描述:** Because the seed is a fixed per-process constant (not mixed with host
  entropy), **every** Nyx beacon exhibits the identical jitter sequence on its first
  cycles. Two beacons on different hosts in the same network produce the same
  inter-request timing pattern.
- **影响:** An NDR/flow sensor correlating beacon cadence across hosts sees a
  repeating timing signature — a network-level fingerprint that scales with fleet size
  and burns operators at scale.
- **修复:** Seed the xorshift from `hostinfo::beacon_id()` (or the CSPRNG already
  registered in `entry.rs:183`) once at `beacon_loop` start, stored into the static.

### [MED] Shell output truncated at 1 MiB with no truncation marker → silent data loss
- **位置:** `crates/implant-win/src/shell.rs:37` (`MAX_OUTPUT = 1 << 20`), `:234-244` (`capped` set, loop breaks), `:299` (`Response::Output(out)`)
- **已核验:** When `out.len() >= MAX_OUTPUT` the read loop breaks and the child is
  killed (`:276-282`), but `out` is returned verbatim:
  ```rust
  Response::Output(out)
  ```
  No `…<truncated at 1 MiB>` suffix is appended; the `capped` flag only drives child
  termination, not the surfaced bytes.
- **影响:** An operator running a command whose stdout exceeds 1 MiB (`type huge.log`,
  `dir /s`, registry dumps) receives the first 1 MiB looking like complete output and
  acts on a truncated tail silently. Decisions made on incomplete data, no telemetry.
- **修复:** Append a constant marker (`b"\n<nux: shell output truncated at 1 MiB>\n"`)
  when `capped` is true, before building the `Response`.

### [MED] `pool_party_inject` leaks target/section/thread handles on every path
- **位置:** `crates/implant-win/src/tp.rs` — `target_h` (`:228`), `section_h` (`:236`), `h_thread` (`:363`)
- **已核验:** `OpenProcess` → `target_h`, `NtCreateSection` → `section_h`,
  `NtCreateThreadEx` → `h_thread`. None are closed on the `Ok` path (`:370-371`) nor on
  most `Err` returns (`:250, 273, 307, 373`). Only `local_base` is explicitly unmapped
  (`:351, 306`).
- **影响:** Per-injection handle leak toward the target process + a leaked section
  handle + a leaked thread handle. Repeated `Inject` calls exhaust the implant's handle
  table and leave forensic artifacts (handles to victim PIDs) visible to EDR/
  `Process Explorer`.
- **修复:** Close `target_h`, `section_h`, `h_thread` on every exit path (a single
  `cleanup:` epilogue or `CloseHandle` at each `return`).

### [MED] `ensure_winhttp` permanently deafens the beacon on a transient `LoadLibrary` failure
- **位置:** `crates/implant-win/src/transport.rs:154-216` (esp. `:173-177`)
- **已核验:**
  ```rust
  if !winhttp_loaded {
      DONE.store(true, Ordering::Release);   // permanent — never retried
      return;
  }
  ```
  `DONE` is the one-shot gate; once set, every later `ensure_winhttp` early-returns
  (`:157-159`) and `WINHTTP` stays `None`.
- **描述:** If the first `LoadLibraryA("winhttp.dll")` fails (transient low-memory,
  loader-lock contention during early process init, a brief SRW-lock hold), the beacon
  marks the transport permanently unavailable. Every subsequent `channel_post_frame`
  returns `None` forever.
- **影响:** The beacon check-in retry loop (`beacon.rs:68-84`) then spins forever
  against a "transport down" that was actually a one-shot transient — silent permanent
  death indistinguishable from a real network failure.
- **修复:** Only set `DONE=true` after the function table is fully resolved. On
  load-failure leave `DONE=false` so the next cycle re-attempts (optionally with a
  backoff counter to avoid hot-spinning).

### [MED] Setting channel to `SmbPipe` (or any unknown id) silently kills the beacon
- **位置:** `crates/implant-win/src/transport.rs:60` (`Channel::SmbPipe => return None`), `crates/implant-win/src/beacon.rs:333-348` (dispatch, `_ => Channel::SmbPipe`)
- **已核验:** `channel_post_frame` maps `Channel::SmbPipe` to `return None`
  unconditionally (`:60`). `beacon.rs:341` maps any `SetChannel { channel }` value not
  in 0..6 to `Channel::SmbPipe`. The beacon task loop treats `None` as "transport
  failed, retry next cycle" (`beacon.rs:121-128` → `continue`).
- **描述:** There is no SMB-pipe transport implementation. An operator who issues
  `SetChannel 6` (or any out-of-range id, which silently maps to 6) gets back
  `"Channel set to: smb-pipe"` (`beacon.rs:344-347`) — a success message — and the
  beacon then never succeeds again.
- **影响:** Silent, permanent beacon death with a *success* acknowledgement for the
  command that caused it. Operator believes the channel switch worked; the beacon
  simply stops checking in.
- **修复:** Either reject `Channel::SmbPipe` at `SetChannel` with `Response::Err`
  ("smb-pipe transport not implemented"), or implement it. At minimum, do not report
  `Output` for an unimplemented channel.

---

## LOW

### [LOW] `.expect()` on `encode_vec` panics the implant if any single response blob exceeds 256 KiB
- **位置:** `crates/implant-win/src/beacon.rs:117, :155, :237, :275` (and `:59, :204` for `SessionInfo::encode`)
- **已核验:** e.g. `:117`
  ```rust
  let frame = encode_frame(&pubkey, counter, &key,
      &TaskResponse::encode_vec(&pending).expect("beacon batch encodes within MAX_BLOB_LEN"));
  ```
  `TaskResponse::encode_vec` returns `Err(WireError::BadLen)` if any blob inside a
  response exceeds `wire::MAX_BLOB_LEN` (256 KiB) — see `protocol/src/wire.rs:40,50` and
  `msg.rs:638-647`. `.expect()` then panics → `panic=abort` → `ExitProcess` via
  `lib.rs:157-178`.
- **描述:** The `BATCH_FLUSH = 200 KiB` heuristic (`beacon.rs:30, 153`) bounds
  *accumulated* batch size, not *individual* blob size. A single producer that emits a
  > 256 KiB `FileChunk`/`Output`/`Image` (e.g. an un-chunked screenshot BMP or download)
  converts the wire layer's defense-in-depth length check into a process-killing panic.
- **影响:** Latent implant death dependent on every response producer respecting the
  256 KiB cap. Out-of-scope producers (`screenshot.rs`, `fs.rs`) are the likely trigger.
- **修复:** Replace the `.expect()`s with `match … { Ok(b) => …, Err(_) => { /* drop
  the oversized response, emit Response::Err("oversized") */ } }`. The encode path
  already reports the error; the beacon should not turn it into a panic.

### [LOW] `bake_server_pub` dev fallback (all-`0x42`) silently used when `NYX_SERVER_PUB` is unset
- **位置:** `crates/implant-win/build.rs:49-60`
- **已核验:**
  ```rust
  Err(_) => { [0x42u8; 32] /* …"a real (non-identity) X25519 point" */ }
  ```
  The baked `pub static SERVER_PUB` (`build.rs:67`) lands as plaintext in `.rdata`
  (see also INFO below).
- **描述:** A release build that forgets `NYX_SERVER_PUB` silently bakes the published
  0x42 key. The resulting beacon's ECDH output will never match the operator's real
  server key, so the server drops every check-in as a failed AEAD open; the beacon
  retries forever against a server that "can't see" it.
- **影响:** Misconfigured engagement build → silent dead beacon, masked by the dev
  fallback. The 0x42 marker is at least greppable post-hoc, but the failure is
  invisible at runtime.
- **修复:** In release/profile-opt builds, fail the build (`panic!`) when
  `NYX_SERVER_PUB` is unset; keep the fallback only for `cargo test`/dev profiles.

### [LOW] `parse_offsets_toml` silently coerces unparseable kernel offsets to `0`
- **位置:** `crates/implant-win/build.rs:251-255`
- **已核验:**
  ```rust
  let n = if let Some(hex) = val.strip_prefix("0x")… {
      usize::from_str_radix(hex, 16).unwrap_or(0)        // typo → 0
  } else {
      val.parse::<usize>().unwrap_or(0)                   // typo → 0
  };
  ```
- **描述:** A single malformed token in `offsets.toml` (`eprocess.token = 0x2z0`,
  missing `0x`, stray whitespace inside the number) bakes that offset as `0`.
- **影响:** The implant then reads kernel fields at offset 0 of `EPROCESS`/the ETW
  provider block → wrong token/PID/image-name → wrong disable result or struct
  misread at runtime, with no build-time signal. The whole point of `NYX_OFFSETS`
  (zero runtime resolution against the *real* offsets) is silently defeated.
- **修复:** `unwrap_or_else(|e| panic!("NYX_OFFSETS: bad value for {key}: {val} ({e})"))`
  so a typo fails the build loudly.

### [LOW] TLS cert-ignore retry sets `WINHTTP_OPTION_SECURITY_FLAGS` *after* a failed `WinHttpSendRequest` [INFERENCE]
- **位置:** `crates/implant-win/src/transport.rs:327-366`
- **已核验:** First `WinHttpSendRequest` (`:327-335`); on failure, if
  `NYX_TLS_INSECURE=1`, `WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, …)`
  (`:338-344`) is called on the *same* request handle, then `WinHttpSendRequest` again
  (`:346-354`). Opt-in only (default: hard cert failure → `None`).
- **描述:** WinHTTP conventionally requires `WINHTTP_OPTION_SECURITY_FLAGS` to be set
  *before* `WinHttpSendRequest`; setting it on a handle whose send already failed (and
  which has begun receive-state machine transitions) may be rejected or silently
  ignored, so the "retry with relaxed validation" may not actually relax anything.
- **影响:** Operators who set `NYX_TLS_INSECURE=1` expecting self-signed-redirector
  support may find the retry still fails (or succeeds without the relaxation they
  intended). Engagement-only path, low blast radius.
- **修复:** Set the security flags on the request handle *before* the first
  `WinHttpSendRequest` when `tls_insecure_retry()` is true, rather than as a post-failure
  retry. Confirm against a live self-signed redirector.

---

## 已验证干净的区域 (INFO — checked and sound)

- **`dllmain.rs:46-61` — no loader-lock / reentrancy / TLS-callback hazard.** `DllMain`
  is a `mov eax,1; ret` with `options(nostack, nomem)` plus `unreachable_unchecked()`;
  it touches no CRT state, registers no TLS callback, holds the loader lock for zero
  work. All init is lazy via the `nyx_*` exports. The Server-2025 `STATUS_STACK_BUFFER_OVERRUN`
  mitigation (skip CRT startup, no GS cookie check) is coherent with `-Wl,-e,DllMain`.

- **`beacon.rs` counter / nonce discipline — no reuse.** The 64-bit `counter` is
  strictly monotonic across check-in (`:67,70`), task POST (`:117-118`), every mid-loop
  flush (`:154-162`), and `beacon_oneshot` (`:209,213,238,276`). It is always read
  *then* incremented, so two frames never share a nonce. Failed check-ins still advance
  the counter (correct — AEAD nonce must never repeat even for never-delivered frames).
  Direction is split (`Direction::ServerToClient` on open, `:135`) matching the
  first-byte direction separator in the nonce.

- **`beacon.rs` AEAD / frame error recovery — fail-soft, no panic.** `parse_frame`,
  `open_frame_dir`, `Task::decode_vec` failures all `continue` to the next cycle
  (`:130-140`) rather than abort; a malformed server response cannot kill the beacon.

- **`beacon.rs` command dispatch — exhaustive by construction.** The `execute` match
  (`:318-484`) has no `_ =>` default arm, so adding a new `Command` variant in
  `nyx_protocol` breaks the implant build — a new task type can never silently fall
  through. All 21 documented `Command` variants route to real handlers.

- **`envelopes.rs` + `build.rs` step/terminator emission — exhaustive.** `envelopes.rs`
  only re-exports baked statics (no logic). `build.rs:431-445` (`steps_expr`) and
  `:451-469` (`terminator_expr`) are exhaustive `match`es with no default arm — a new
  `nyx_profile::Step`/`Terminator` variant fails the build rather than silently
  producing an empty envelope. Unsupported-but-parseable terminators are rejected
  loudly at build time (`build.rs:353-366`).

- **`context.rs` — CONTEXT layout verified at compile time.** `Context` is
  `#[repr(C, align(16))]` over `[u8; 1232]`; `const _: () = assert!(size_of == 1232)`
  and `assert!(align_of == 16)` (`:165-169`) plus `1232 == 0x4D0` (`:172`) fail the
  build on any layout drift. Accessor offsets (`:86-139`) match WinNT.h x64 (`0x30`
  ContextFlags, `0x38` SegCs, `0x44` EFlags, `0x98` Rsp, `0xF8` Rip). Reads use slice
  copies (`:63-83`), never unaligned raw deref. The static `CTX_BUF` (`:179`) is
  zeroed each call (`:200`) so stale fields cannot leak across cycles.

- **`transport.rs` response read — overflow-hardened, handles closed on every path.**
  Per-read buffer is clamped to `min(avail, 1<<20)` (`:395`) with an inline note that
  passing the raw server-influenced `avail` previously caused a heap overflow; total
  response is capped at `MAX_RESPONSE_BYTES = 16 MiB` and on overflow returns `None`
  cleanly (`:405-409`) instead of partial ciphertext. `req`/`conn`/`session` are
  closed on every error branch (`:277-279, 356-371, 374-378`) and on success
  (`:424-426`).

- **`shell.rs` pipe/handle hygiene — correct EOF + no handle leaks.** Parent's write
  end is closed *before* draining (`:229`) so `ReadFile` sees EOF when the child exits;
  read end is marked non-inheritable (`:175`) so only the child holds a writer. On
  `CreateProcessW` failure both pipe ends are closed (`:219-220`); on success
  `h_process`/`h_thread`/`child_std_out_read` are all closed (`:295-297`). Output is
  clamped against `MAX_OUTPUT` on the final chunk (`:262`).

- **`version.rs` — PEB read is unaligned-safe, probes degrade cleanly.**
  `read_build_number_raw` uses `core::ptr::read_unaligned` (`:53`) and returns 0 on a
  missing PEB (`:48-51`). CET probe caches into an `AtomicU8` sentinel (`:66-74`) and
  returns `false` (correct for pre-24H2) when `IsProcessorFeaturePresent` is unresolved
  (`:85`). `dec_u32` (`:112-128`) is bounded by the `[0u8; 10]` buffer for all `u32`.

- **`config.rs` tamper response — clean crash, not a hang.** `load()` on Poly1305 tag
  mismatch / malformed blob escalates `ExitProcess → TerminateProcess → int3`
  (`:59-77`); the trailing `spin_loop` loop is only the `-> !` type satisfier. Decrypted
  plaintext is handed back for the caller to register with the memory mask
  (`beacon.rs:40` `mem::register_owned`) so it is RC4-masked during sleep.

- **`lib.rs:155-178` panic handler — clean exit preferred over the spin IOC.** Resolves
  `ExitProcess` and exits `0xC000_0001`; the infinite spin is explicitly the last-resort
  fallback (comment `:158-160` acknowledges a pinned core is a loud IOC). The handler
  does not format or log `PanicInfo`, so no secret/config material leaks via a panic.

- **`entry.rs` sandbox gate + diag hygiene.** The anti-analysis gate reads
  `NYX_SKIP_SANDBOX` via `GetEnvironmentVariableA` (`:57-70`) and also honors the
  `nyx_skip_sandbox` cfg for SYSTEM-context deploys where env can't pass through
  schtask. `diag_mark` is a compile-time no-op without `--cfg nyx_diag` (`:364-367`),
  so production builds leave no `C:\nyx\diag_*` forensic markers.

- **Server pubkey in `.rdata` (architectural note, not a bug).** `SERVER_PUB` is a
  `pub static [u8;32]` (`build.rs:67`), so the real server long-term key sits as
  plaintext, stable per team-server across every beacon build for that engagement. This
  is inherent to X25519 (the implant must know the server pubkey before any key
  exchange; there is no pre-shared symmetric to encrypt it with). Noted as an IOC a
  defender-with-the-binary can extract once and YARA across the fleet; the per-build
  config-blob re-randomization (`build.rs:119-154`) does not help here. No code change
  recommended beyond the LOW note on the dev fallback.

---

## Baseline cross-check (these 12 files)

None of the 13 prior baseline findings (`CRIT-1..5`, `HIGH-1..8`, `MED/LOW`) live in
the audited files. Verified call-sites:
- `beacon.rs:349-365` (`Command::Trex`) calls `crate::trex::assess_user_mode()` and
  faithfully renders the returned `assessment.tier`/`products`/`recommendation`. The
  **stubbiness** of that assessment is CRIT-3's concern in `trex/mod.rs` (sibling
  module), not the beacon's rendering of it.
- `beacon.rs` does not directly touch `caller_spoof.rs` (CRIT-4), `fluctuation.rs`
  (CRIT-5), `trex/melt.rs` (HIGH-7), or `ntalloc.rs` (HIGH-8); those are reached via
  the evasion init in `entry.rs:bootstrap()` and the kits layer.

All findings above are **NEW** relative to the 2026-07-08 baseline.
