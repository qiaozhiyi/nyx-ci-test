# Implant Evasion / Memory Subsystem — Line-by-Line Audit (2026-07-08)

**Scope:** `crates/implant-win/src/` — `sleep.rs, fluctuation.rs, fluctuation_thunk.rs, lacuna.rs, lacuna_stomp.rs, blind.rs, blind_hwbp.rs, inject.rs, unhook.rs, antidebug.rs, hookchain.rs, syscalls.rs, caller_spoof.rs, caller_spoof_thunk.rs, proxy_veh.rs, cfg_user.rs, heap.rs, mem.rs, ntalloc.rs, stack.rs, pic_thunk.rs, kits.rs`.

**Method:** static review of every `unsafe` block, syscall stub, SSN/table resolution, indirect-syscall stack setup, HWBP DR save/restore, module-stomping perms, stack-spoof RSP swap / CET, and the RC4 mask/unmask crypto path. All line numbers are from the file as read.

---

## Baseline re-verification

### CRIT-4 — caller_spoof bare `0xC3` fallback — CONFIRM (downgraded to effectively LOW — currently inert)
- **位置:** `caller_spoof.rs:135-141`
- **已核验:** the fallback scan still returns the *first* `0xC3` byte as a stub with `stack_clean: 0`:
  ```rust
  // Pattern 2 (fallback): any C3 (RET) — treat as stack_clean=0.
  for (j, &b) in bytes.iter().enumerate() {
      if b == 0xC3 {
          return Some(ReturnStub { addr: mod_base + j, stack_clean: 0 });
      }
  }
  ```
  A bare `0xC3` may be an *operand byte* of a multi-byte instruction (not a real `RET`); jumping there executes garbage.
- **现状:** the only live caller of `scan_return_stub()` is `blind_hwbp.rs:117`, which **discards the result** (`let _ = stub;` at `:120`). `add_vectored_handler_spoofed` / `call_with_spoofed_return_4` (the consumers that would actually *use* a bad stub) have **no call sites** anywhere in `crates/implant-win/src`. So the dangerous fallback is unreachable in production today.
- **影响:** if any future code wires `add_vectored_handler_spoofed`, a mid-instruction `0xC3` lands control flow into garbage.
- **修复:** drop the fallback (return `None` if no `48 83 C4 XX C3` found); validate the byte is at a function boundary (preceded by `0xCC`/`0xC3` padding or aligned).

### LOW-6 — caller_spoof 1 MiB scan cap — CONFIRM
- **位置:** `caller_spoof.rs:120`
- **已核验:** `let bytes = core::slice::from_raw_parts(region_base as *const u8, region_size.min(0x100000));` — only the first 1 MiB of `.text` is scanned.
- **影响:** modern ntdll `.text` exceeds 1 MiB; the cap silently reduces coverage. Cosmetic (a stub is virtually always found within the first 1 MiB).
- **修复:** scan the full `region_size` (chunked if allocator-friendly), or document the cap.

### CRIT-5 — fluctuation no unwind / Drop guard — CONFIRM
- **位置:** `fluctuation.rs:66-78`
- **已核验:** the mask window is bracketed by raw statements with no RAII:
  ```rust
  let saved_dr = save_dr_state(rt);   // :66
  clear_dr_state(rt);                 // :67
  crate::mem::mask();                 // :69  <-- regions now RC4-ciphertext
  let thunk_fn: ... = transmute(page);
  thunk_fn();                         // :71  <-- .text flipped PAGE_NOACCESS for the sleep window
  crate::mem::unmask();               // :72  <-- only reached on clean return
  restore_dr_state(rt, &saved_dr);    // :78
  ```
- **影响:** if anything faults between `mask()` and `unmask()` — e.g. an async exception / APC whose dispatch touches the implant's own VEH handler now that `.text` is `PAGE_NOACCESS`, or a thunk step failing — `unmask()` / `restore_dr_state()` never run. Result: `.text` stays `PAGE_NOACCESS` (permanent implant death) **and** registered regions stay ciphertext **and** DR0-DR7 stay cleared (EDR-blind HWBPs silently lost). `panic = "abort"` means there is no unwinder to save you, so this needs an explicit guard.
- **修复:** wrap the window in a `struct Guard` whose `Drop` unconditionally restores `.text` perms, calls `mem::unmask()`, and restores DR state — or drive the whole window from the separate RWX thunk so the beacon thread's `.text`-relative recovery code is never on the fault path.

### HIGH-8 — ntalloc leak / slab table — CONFIRM (+ a new masking-gap wrinkle, see NEW-L4)
- **位置:** `ntalloc.rs:269` (dealloc), `:52-71` (track_slab)
- **已核验:** `unsafe fn dealloc(&self, _ptr, _layout) {}` — no-op (intentional bump allocator). Slab table at `:46-47` is `static mut SLAB_TABLE: [SlabDesc; 16]` / `SLAB_COUNT`.
- **现状:** leak confirmed (by design for a PIC bump allocator). The overflow path (`:60-71`) shifts entries left and drops the **oldest** slab from the table to "keep tracking alive" — but the dropped slab is still allocated and **no longer enumerated** by `enumerate_slabs()`.
- **影响:** see NEW-L4 (the dropped slab escapes sleep-mask coverage).

### MED-5 — SSN sanity / no upper bound — CONFIRM
- **位置:** `syscalls.rs:117-118`, `:201-203`
- **已核验:** `let max_ssn = table.iter().map(|(_, s)| *s).max().unwrap_or(0);` with no plausibility check, then `trampoline_bytes = ((max_ssn+1) * STUB_SIZE)`. `trampoline_for(ssn)` (`:201`) does `trampoline.add((ssn as usize) * STUB_SIZE)` with no bounds check. `ssn_by_hash` (`:172`) only rejects `u32::MAX`.
- **影响:** a poisoned/hooked fresh-ntdll read that yields a bogus SSN (e.g. `0xFFFF`) is never validated against the real Win10/11 range (~0..512). The bogus SSN (a) inflates the trampoline alloc to ~2 MiB, and (b) more importantly, the stub at that slot sets `mov eax, <bogus>` then `syscall` → a **wrong syscall** executes (kernel returns `STATUS_INVALID_SYSTEM_SERVICE`, or on some builds maps to an unrelated syscall). Indexing itself stays in-bounds (max is the table max), so no OOB write — the risk is wrong-SSN execution.
- **修复:** clamp/reject at resolve time: `if ssn > 0x400 { discard entry }` and `if max_ssn > 0x400 { return None }`.

### MED-6 — threadless inject sets both DR0 and RIP — CONFIRM
- **位置:** `inject.rs:593-600`
- **已核验:**
  ```rust
  ctx[0x48..0x48+8].copy_from_slice(&sc_addr.to_le_bytes()); // DR0 = shellcode  (:594)
  ctx[0x70..0x70+8].copy_from_slice(&0x1u64.to_le_bytes());  // DR7 = 0x1 (L0, exec BP) (:595)
  ...
  ctx[0x0F8..0x0F8+8].copy_from_slice(&sc_addr.to_le_bytes()); // RIP = shellcode (:600)
  ```
- **影响:** DR7 bit0 enables DR0 as a **local execute** breakpoint. With `RIP == DR0 == shellcode`, the moment the thread resumes the CPU delivers a `#DB` (execute BP faults *before* the instruction) → `STATUS_SINGLE_STEP`. If no handler catches it the target crashes; if a handler does, RIP is diverted and the shellcode's first instruction never runs as intended. The two mechanisms (direct RIP redirect vs HWBP redirect) contradict each other. The comment at `:597-599` ("HWBP serves as a secondary redirection if the shellcode returns") is not how an execute BP behaves.
- **修复:** pick one: either set RIP only (direct exec, drop DR0/DR7), or set DR0+DR7 only and leave RIP (HWBP-driven redirect with an in-target VEH/UEF handler). Do not set both to the same address.

### MED-7 — blind_hwbp `static mut` race — CONFIRM
- **位置:** `blind_hwbp.rs:87-90`
- **已核验:** `static mut HWBP_ENTRIES: [Option<HwbpEntry>; 4]`, `HWBP_COUNT`, `VEH_HANDLE`, `SHADOW_BUF` — all `static mut`. The VEH handler `hwbp_veh_handler` (`:309`) runs on **whatever thread takes the `#DB`** and reads `HWBP_ENTRIES[i]` via `read_volatile` (`:368`), while the beacon thread writes them in `add_hwbp`/`remove_hwbp`. That is a data race (Rust UB); `read_volatile` does not make it sound.
- **影响:** torn read of an `Option<HwbpEntry>` during install/remove → handler misroutes or dereferences a half-written target/shadow → crash or wrong redirect. Low real-world frequency (HWBPs are rarely toggled mid-run) but it is genuine UB.
- **修复:** back the table with `AtomicU64`-packed entries (or a `spin::Mutex` taken by both the beacon mutator and the handler), never `static mut`.

### MED-8 — `VmCfgInfo` layout placeholders — CONFIRM
- **位置:** `cfg_user.rs:212-220`
- **已核验:**
  ```rust
  struct VmCfgInfo {
      number_of_entries: u32,
      _pad: u32,
      _z1: usize,        // <-- assumed placeholder
      _z2: usize,        // <-- assumed placeholder
      entry_ptr: *mut CfgTargetInfo,
      out_ptr: *mut u32,
  }
  ```
  The real `MI_CFG_INFORMATION` / call-target descriptor layout for `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)` is version-sensitive; the two `usize` placeholders (`_z1`/`_z2`) are a guess. `size_of::<VmCfgInfo>()` is passed as the last arg (`:243`).
- **影响:** if the real struct places `entry_ptr` at a different offset on the target build, the kernel reads the wrong pointer → `STATUS_INVALID_PARAMETER` (CFG marking silently fails → the indirect-call target stays non-CFG-valid → `#FC` on CFG-enabled hosts) or, worst case, a kernel-side pointer it interprets from our padding.
- **修复:** derive the layout from a version-checked PHNT definition, or probe one known CFG-valid address first and assert the call returns success before relying on it.

### MED-9 — proxy_veh trampoline `jmp rax` + ntdll RWX — CONFIRM
- **位置:** `proxy_veh.rs:357-365`
- **已核验:** the trampoline written into an ntdll code cave is `48 B8 <handler> FF E0` (`mov rax, imm64; jmp rax`), and the cave page is flipped to `PAGE_EXECUTE_READWRITE` (`0x40`, `:346`) for the write then back to `PAGE_EXECUTE_READ` (`:375`).
- **影响:** (1) The `jmp rax` target is the implant VEH handler — an indirect branch whose target must be CFG-valid; only the *trampoline cave address* is marked CFG-valid (`:380`), not necessarily the handler. On a CFG-enforcing host the `jmp rax` to a non-CFG-valid handler raises `#FC`. (2) Briefly turning an ntdll `.text` page RWX is a strong code-integrity IOC (PE-sieve / Defender `.text`-hash). (3) No check that the located cave (`find_code_cave`, `:307`) is at least 12 bytes; an undersized cave overruns into the next function.
- **修复:** mark the handler address CFG-valid too (or route through a CFG-valid indirect thunk); validate cave size >= 12 before writing; prefer `PAGE_READWRITE` write + restore to the *original* protection rather than RWX.

### LOW-7 — fluctuation thunk on RWX page — CONFIRM
- **位置:** allocation `fluctuation.rs:53`; design `fluctuation_thunk.rs:4`
- **已核验:** the thunk page is allocated `0x3000, 0x40` (RWX): `let st = alloc(!0usize, &mut page, 0, &mut sz, 0x3000, 0x40);` (`fluctuation.rs:53`); the thunk bytes are copied in (`:60`) and executed (`:71`) **without ever flipping to RX**. `fluctuation_thunk.rs:4` documents "Placed on a RWX page".
- **影响:** a live RWX page is a first-class memory-scanner IOC (Moneta/PE-sieve).
- **修复:** allocate RW, copy, `NtProtectVirtualMemory` to `PAGE_EXECUTE_READ` (0x20), then execute; the thunk is write-once.

---

## NEW findings

### NEW-H1 — `mem::mask()`/`unmask()` derive a fresh key per call -> the synchronous round-trip is broken
- **位置:** `mem.rs:104-117` (`mask_key`), `:123-141` (`apply_rc4_to_regions`), `:155-176` (`mask`/`unmask`)
- **已核验:**
  ```rust
  pub(crate) fn mask_key() -> [u8; 32] {
      let mut key = [0u8; 32];
      if crate::entry::csprng_fill(&mut key) { key }   // <-- RANDOM every call
      else { /* _rdtsc-based, also differs every call */ }
  }
  fn apply_rc4_to_regions() {
      let key = mask_key();          // <-- called once per mask(), AND once per unmask()
      ... Rc4::apply_oneshot(&key, region);
  }
  pub fn mask()   { /* CAS 0->1 */ apply_rc4_to_regions(); }   // key K1
  pub fn unmask() { /* CAS 1->0 */ apply_rc4_to_regions(); }   // key K2 != K1
  ```
  `entry::csprng_fill` (`entry.rs:208`) wraps `SystemFunction036` (RtlGenRandom) — genuine CSPRNG, fresh bytes every call (it caches the *function address*, not the output). The doc at `:100-103` claims a "per-run" key, but the implementation is **per-call**. Contrast `round_trip_selftest` (`:290-294`) which binds `let key = mask_key()` once and reuses it — so the selftest passes while the production path does not.
- **影响:** on the **default beacon sleep path** (`beacon.rs:406/539/556 -> kits::sleep -> Foliage::sleep_masked -> fluctuation::sleep`, enabled by default per `fluctuation.rs:13-18`) `do_fluctuate` calls `mem::mask()` (`fluctuation.rs:69`) then `mem::unmask()` (`:72`) with **different keys**. The registered regions (the leaked ECDH session-key copy via `beacon.rs:45/191` and the leaked config plaintext via `:40/184`) end up as `keystream(K1) composed-with keystream(K2) composed-with plaintext` — i.e. **not** restored to plaintext. The documented "verified round-trip restores byte-identical" guarantee (`mem.rs:5-6`, `:165-167`) is **false** for this path.
  - Currently no *functional* comms death: the beacon uses its own local `key`/`Config` (the registered copies are write-only scan-decoys — `register_key`/`register_owned` leak independent copies). So this is a **latent landmine + broken security contract**, not active death today.
  - It escalates to **CRITICAL** the instant any code reads a registered region back (e.g. reading config from the registered plaintext, or a BOF output buffer registered via `register_owned`).
- **修复:** derive the key **once** at first use and cache it in a `static AtomicU64`/`OnceLock<[u8;32]>`; `mask`/`unmask`/`apply_rc4_to_regions` must share that single key. (The Foliage `mask_text_and_heap` path already does this correctly — it takes a caller-supplied `key: &[u8]`; mirror that contract.)

### NEW-M2 — `execute_foliage_apc` leaves `.text` RWX, not RX (+ leaks an RWX page)
- **位置:** `sleep.rs:621-627` (Context 5), `:472` (rc4 page)
- **已核验:** the Ekko ROP chain's step-5 context restores `.text` to `PAGE_EXECUTE_READWRITE` (`0x40`):
  ```rust
  // Context 5: VirtualProtect(.text, .text_len, PAGE_EXECUTE_READWRITE=0x40, &OldProtect)
  rop_prot_rx.set_r8(0x40 as u64); // PAGE_EXECUTE_READWRITE   (:627)
  ```
  yet the function's own doc (`:406`) says "5. VirtualProtect(.text, RX) — restore execute protection". The RC4 shim is also copied to a page allocated `0x40` RWX (`:472`) that is never freed or locked to RX.
- **影响:** if/when the gated Foliage-APC path runs, the implant's own `.text` ends the cycle **RWX** — a permanent, glaring IOC every memory scanner keys on (deviates from the documented RX). The leaked RWX rc4 page is a second permanent-RWX region.
- **修复:** set Context-5 protection to `0x20` (`PAGE_EXECUTE_READ`) to match the doc and the original `.text` protection; free (or flip to RX then free) the rc4 page after the chain completes.
- **Reachability:** gated behind the Foliage-APC thunk wiring (default off; kits routes to `fluctuation`, not this chain), so not on the default path — but it ships wrong.

### NEW-M3 — `caller_spoof_thunk` resume-offset is off by 5 bytes
- **位置:** `caller_spoof_thunk.rs:135` (`let offset_to_resume: u8 = 10;`)
- **已核验:** the `call $+5; pop rax` idiom puts `addr(pop rax)` in `rax`; `add rax, 10` then pushes that as the "resume" return address. But the real distance from `pop rax` to the `resume:` label is **15 bytes**, not 10:
  ```
  pop rax            : +0   (0x58)
  add rax, 10        : +1   (48 83 C4 0A)   <-- the comment's "1+3+4+2=10" forgot THIS 4-byte add
  push rax           : +5   (50)
  push qword [r10]   : +6   (41 FF 32)
  mov rax,[r10+8]    : +9   (49 8B 42 08)
  jmp rax            : +13  (FF E0)
  resume: pop r15    : +15  (41 5F)
  ```
  The comment at `:132` computes `1+3+4+2 = 10` but omits the 4-byte `add rax, imm8` it itself emits at `:138-139`. So the pushed resume address lands at `+10` = the `0x8B` operand byte of `mov rax,[r10+8]`; when the callee `RET`s -> ntdll-`RET` -> pops that address, the CPU decodes `8B 42 08 FF E0 ...` = `mov eax,[rdx+8]; jmp rax` -> jumps to whatever the target returned in `rax` (e.g. a VEH handle) -> crash.
- **影响:** every invocation of a thunk from `caller_spoof_thunk::build` misroutes. Reachability: `build` is called only from `caller_spoof.rs:256` (`add_vectored_handler_spoofed`), which itself has **no callers** in the beacon loop — so currently dead/shipped-broken, not crashing in production.
- **修复:** set `offset_to_resume = 15` (or, better, emit `lea rax, [rip + resume]` and let the assembler compute it — no magic constant).

### NEW-L4 — ntalloc slab-overflow shift silently drops a slab from mask enumeration
- **位置:** `ntalloc.rs:60-71` (shift), consumed via `mem.rs:200` (`enumerate_beacon_heap_regions` -> `ntalloc::enumerate_slabs`)
- **已核验:** when `SLAB_COUNT >= 16` the table shifts left and **drops the oldest slab** from `SLAB_TABLE`. `enumerate_beacon_heap_regions` (`mem.rs:199-202`) pulls exactly `ntalloc::enumerate_slabs()`, so the dropped slab (still allocated, still holding beacon data) is **never handed to the sleep mask**.
- **影响:** beyond 16 slabs (16 MiB of heap — reachable with screenshots / large BOF output), the oldest heap pages — which may hold config/transport/credential data — sit in **plaintext during sleep**, defeating the mask for exactly the regions an EDR memory scan is most likely to catch. The code comment ("keeps tracking alive") is the opposite of what happens.
- **修复:** grow the slab table (or switch to a linked list of slab pages) instead of shifting; never silently evict an allocated region from mask coverage.

### NEW-L5 — `blind_hwbp::init_countermeasures` scans ntdll `.text` and throws the result away
- **位置:** `blind_hwbp.rs:116-121`
- **已核验:** `if let Some(stub) = crate::caller_spoof::scan_return_stub() { diag(b'R'); let _ = stub; }` — runs a full up-to-1 MiB byte scan of ntdll `.text` on every bootstrap (a minor read-side IOC surface) and then discards `stub`. This is the only live reach of CRIT-4's fallback.
- **影响:** dead work + the only path that can select a bogus bare-`0xC3` stub; since the result is unused, no functional harm today.
- **修复:** delete the block, or actually store the stub for the caller-spoof thunk once that path is repaired (NEW-M3) and wired.

### NEW-L6 — doc/code mismatches (cosmetic, but in security-critical paths)
- `hookchain.rs:345-352`: comment says *"PAGE_EXECUTE_READ (0x20) — NOT RWX"* directly above `f(.., 0x40 /* RWX initially */)`. The page is later locked to RX by `lockdown_stub_page()` (`:396-409`), so the *net* behavior is correct — but the inline comment is wrong and will mislead the next editor.
- `mem.rs:82` and `:92`: `register_owned` / `register_key` docs say *"Returns false if the region table is full (8 slots)"* but `MAX_REGIONS = 32` (`:44`). Misleads capacity reasoning.
- **修复:** align comments with code.

### NEW-L7 — injection paths leave a permanent private RWX region
- **位置:** `inject.rs:547` (`threadless_inject` VirtualAllocEx `0x40`), `:816` (`create_remote_thread` NtAllocateVirtualMemory `0x40`); module-stomping at `:210-219` correctly restores RX (0x20).
- **已核验:** both classic-injection allocations stay `PAGE_EXECUTE_READWRITE` for the shellcode's lifetime. Documented (`:514-516`) but still a standing IOC (Moneta "private executable").
- **修复:** where the technique allows (shellcode that doesn't self-modify), flip to RX after the write.

---

## Verified-clean areas (with evidence)

- **`stack.rs` — RSP-swap spoof is correctly CET-gated.** `SPOOF_SWAP_ENABLED` defaults `false` (`:82`); `with_spoofed_stack` fast-paths to a direct call when disarmed (`:255-257`) and, when armed, consults `nyx_implant_evasionsdk::swap::should_execute(cet_on, gaps_usable)` (`:265`) before any `mov rsp` (`:265-267` degrades on CET-on). `do_rsp_swap` enforces 16-byte RSP alignment (`:404`), declares no `nostack` and clobbers all volatile regs (`:411-432`), and guards reentrancy (`:359-364`). The module doc (`:17-51`) gives an accurate two-layer (unwinder vs shadow-stack) CET analysis. This is the best-reasoned unsafe code in the crate.
- **`unhook.rs` — fresh-ntdll map is bounds-checked + RAII-unmapped.** ZeroBits/CommitSize passed **by value** (`:109-120`, the documented H5 lesson), `SECTION_MIN_ACCESS` chosen to survive the system ACL (`:62`), disk fallback translates RVA->file-offset (`:313-315`), `parse_sections_raw` bounds-checks every header read (`:467-505`), and `FreshMapGuard::drop` unmaps the second view so the IOC is transient (`syscalls.rs:227-233`). Honest IOC documentation (`:24-50`).
- **`syscalls.rs` — indirect-stub page is written once then flipped RX once.** No per-call `VirtualProtect` churn and no cross-thread stub race: all stubs are pre-filled (`:141-148`) and the whole region is flipped to `PAGE_EXECUTE_READ` a single time (`:150-158`). `scan_syscall_gadget` reads in 64 KiB chunks (`:245-256`) to stay friendly to the bump allocator.
- **`blind.rs` — P0 byte-patch is idempotent and ABI-correct.** Patches end in plain `ret` (not `ret imm16`) — correct for Microsoft x64 (`:15-21`, `:51-62`); `write_patch` restores the **original** protection after the copy (`:117`); `already_patched` short-circuits redundant `VirtualProtect` signals (`:100`). Documented as the loud P0 baseline vs the HWBP upgrade.
- **`blind_hwbp` shadow buffer downgrades RW->RX.** `init_shadow_buffer` (`:214-264`) allocates `PAGE_READWRITE`, writes the stubs, then `VirtualProtect` to `PAGE_EXECUTE_READ` (`:261`) — closes the RWX IOC that the older fluctuation/proxy_veh paths still have. The VEH handler's RF-based single-phase redirect (`:382-388`: set RIP=shadow, set RF, clear DR6, `EXCEPTION_CONTINUE_EXECUTION`) is the correct boku7 pattern.
- **`hookchain.rs` — RVA->SSN built from pristine export dir, IAT restored, stubs locked down.** `build_rva_ssn_table` joins the (hook-proof) in-process export directory with the runtime SSN table (`:254-290`); IAT rewrite flips to `PAGE_READWRITE` (not RWX) and restores original protection (`:221-231`); `apply()` ends with `lockdown_stub_page()` -> RX (`:449-450`); binary search is correct (`:294-311`).
- **`ntalloc.rs` — ZeroBits passed by value (the fix that makes allocation succeed).** `NtAllocateVirtualMemory` ZeroBits is `usize` by value (`:104-113`), with an honest comment documenting the prior stack-address bug; oversized slabs are sized to the request (`:131-152`, fixing the documented 8 MiB/1 MiB overrun).
- **`caller_spoof.rs` PE walk — correct section-offset math.** `scan_stub_in_module` computes the section table offset as `e_lfanew + 4 + 20 + size_of_optional_header` (`:95-96`), explicitly *not* using `ImageNtHeaders64` struct size (the comment at `:336-339` explains why OptionalHeader varies). This is the right cross-arch derivation.
- **`lacuna.rs` / `lacuna_stomp.rs` — .pdata gap scanner is structurally sound.** `IMAGE_RUNTIME_FUNCTION_ENTRY` (12 bytes, sorted) handling is correct; the ghost-chain leaf-frame spoof exploits the documented `RtlLookupFunctionEntry -> NULL -> leaf (RSP+=8)` behavior. `with_ghost_stack` (`lacuna_stomp.rs:67-103`) documents the no-unwind contract; the `add rsp, N*8` restore matches the push count.

---

## Summary table

| ID | Sev | File:Line | Status |
|----|-----|-----------|--------|
| CRIT-4 | (was CRIT) | caller_spoof.rs:135-141 | CONFIRM, **inert** (result discarded blind_hwbp.rs:120; no live consumer) |
| LOW-6 | LOW | caller_spoof.rs:120 | CONFIRM |
| CRIT-5 | CRIT | fluctuation.rs:66-78 | CONFIRM (no Drop/unwind guard) |
| HIGH-8 | HIGH | ntalloc.rs:269,52-71 | CONFIRM (+NEW-L4 masking gap) |
| MED-5 | MED | syscalls.rs:117 | CONFIRM (no SSN bound) |
| MED-6 | MED | inject.rs:593-600 | CONFIRM (DR0+RIP dual-set) |
| MED-7 | MED | blind_hwbp.rs:87-90 | CONFIRM (`static mut` race) |
| MED-8 | MED | cfg_user.rs:212-220 | CONFIRM (placeholder layout) |
| MED-9 | MED | proxy_veh.rs:357-365 | CONFIRM (`jmp rax` CFG + RWX) |
| LOW-7 | LOW | fluctuation.rs:53 | CONFIRM (RWX thunk page) |
| NEW-H1 | HIGH | mem.rs:104-176 | per-call RC4 key breaks synchronous round-trip (latent; false guarantee) |
| NEW-M2 | MED | sleep.rs:621-627,472 | Foliage-APC leaves .text RWX + leaks RWX page |
| NEW-M3 | MED | caller_spoof_thunk.rs:135 | resume offset off-by-5 (dead code, ships broken) |
| NEW-L4 | LOW | ntalloc.rs:60-71 | slab-overflow shift evicts a slab from mask coverage |
| NEW-L5 | LOW | blind_hwbp.rs:116-121 | scans ntdll then discards result |
| NEW-L6 | LOW | hookchain.rs:345 / mem.rs:82,92 | doc/code mismatches |
| NEW-L7 | LOW | inject.rs:547,816 | permanent private RWX injection regions |

**Highest-priority fixes:** CRIT-5 (add a Drop guard to the fluctuation mask window), NEW-H1 (cache the RC4 mask key so the synchronous round-trip is sound), MED-6 (drop the DR0/RIP contradiction in `threadless_inject`), MED-7 (de-`static mut` the HWBP table).
