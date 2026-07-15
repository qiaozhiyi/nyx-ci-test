# Implant Evasion / Memory Subsystem — Line-by-Line Audit (2026-07-10 deep pass)

**Scope:** `crates/implant-win/src/` evasion domain — `fluctuation.rs, fluctuation_thunk.rs, sleep.rs, mem.rs, ntalloc.rs, blind.rs, blind_hwbp.rs, caller_spoof.rs, caller_spoof_thunk.rs, stack.rs, syscalls.rs, unhook.rs, antidebug.rs, hookchain.rs, cfg_user.rs, proxy_veh.rs, lacuna.rs, lacuna_stomp.rs, evasion_glue.rs, pic_thunk.rs, tp.rs`.

**Method:** static review of every in-progress fix (`git diff`), every prior finding re-verified at its cited line, and a fresh pass over all 21 domain files. Line numbers are from the file as read on 2026-07-10 (working tree, with uncommitted fixes applied).

**Build context (load-bearing):** `crates/implant-win` is `#![no_std]` + `#![no_main]`, built with nightly + `x86_64-pc-windows-gnu`, `opt-level="z"`, LTO, `panic="abort"`, strip. The beacon is **single-threaded** except for (a) the HWBP VEH handler which runs on whatever thread takes `#DB`, and (b) the Foliage helper thread (gated, default off).

---

## Part 1 — Audit of the in-progress fixes (the `git diff`)

These are the new-code changes the fix plan introduced. New code = new bugs. Each is reviewed line-by-line.

---

### [HIGH] FIX-AUDIT-1 — fluctuation RAII guard: correct on early-return, INERT on hardware fault (panic=abort)
- **位置:** `fluctuation.rs:33-59` (guards), `:97-109` (usage in `do_fluctuate`)
- **状态:** CRIT-5 PARTIALLY FIXED — the guard closes the realistic `?`/`return` early-exit window, but NOT the original fault scenario.
- **已核验:** the diff adds two guards:
  ```rust
  struct MaskGuard;
  impl Drop for MaskGuard { fn drop(&mut self) { crate::mem::unmask(); } }
  struct DrGuard<'a> { saved: DrState, rt: &'a crate::syscalls::Runtime }
  impl<'a> Drop for DrGuard<'a> {
      fn drop(&mut self) { unsafe { restore_dr_state(self.rt, &self.saved); } }
  }
  ```
  Declared at `:102-103` in reverse order so Rust's reverse-declaration drop order runs `MaskGuard` (unmask) BEFORE `DrGuard` (restore DR) — matching the original explicit order. This is **correct**: drop order is reverse declaration order, and the comment documents the intent accurately.
- **描述:** the original CRIT-5 named two failure classes: (1) "async exception / APC whose dispatch touches the implant's own VEH handler now that `.text` is `PAGE_NOACCESS`", and (2) "a thunk step failing". The guard handles class (2)-via-`return`, but the comment at `:36-38` is honest about the limit: *"`panic = abort"` means Drop does NOT run on a true panic"*. This is correct as far as it goes, but the more dangerous case is a **hardware access violation** (class 1): if `.text` is `PAGE_NOACCESS` and an APC/exception fires whose dispatch touches a `.text`-relative address, the CPU raises `#PF`/`#AV`. That is a hardware exception, not a Rust `panic!` and not a `return` — with `panic=abort` there is no unwinder, and an uncaught SEH exception terminates the process without running `Drop`. So the guard does NOT save the case the finding originally called out (VEH dispatch into NOACCESS `.text`).
  - What the guard DOES save: if `thunk_fn()` returns normally but a future edit adds a `?`/`return`/`Result::Err` path between `mask()` and the old explicit `unmask()`, the regions are restored. That is a real improvement over the bare statement sequence.
- **影响:** a mid-sleep async exception that touches NOACCESS `.text` still leaves the beacon permanently dead (`.text` stays `PAGE_NOACCESS`) and DR state lost. The guard narrows the window but does not close it.
- **修复:** the only fully-sound fix is to drive the entire mask→sleep→unmask window from the **thunk page itself** (which stays executable), so the beacon thread's `.text`-relative recovery code is never on the fault path. The current `fluctuation_thunk` already does the `.text` RX-restore inside the thunk (`fluctuation_thunk.rs:89-108` step 3) — so for `.text` perms the thunk is self-healing. The remaining exposure is the **registered data regions** (mem::mask/unmask): if the beacon faults before the thunk runs or after, those stay ciphertext. Consider moving `mem::unmask()` into the thunk's tail (after the RX restore, before `RET`) so it runs on the executable thunk page, not the beacon thread.
- **Verdict:** ship the guard (it is a strict improvement and harms nothing), but do not consider CRIT-5 fully resolved. Downgrade the residual to **HIGH**.

---

### [MEDIUM] FIX-AUDIT-2 — mem.rs mask-key cache: sound under single-threaded beacon, latent UB if ever reached from the VEH handler
- **位置:** `mem.rs:38-48` (statics), `:121-147` (`mask_key`), `:153-170` (`apply_rc4_to_regions`)
- **状态:** CRIT-NEW-4 / NEW-H1 FIXED for the default path; one latent concern.
- **已核验:** the diff replaces per-call `csprng_fill` with a cached `static mut MASK_KEY_BUF: [u8; 32]` + `MASK_KEY_INIT: AtomicU8` flag:
  ```rust
  pub(crate) fn mask_key() -> &'static [u8; 32] {
      if MASK_KEY_INIT.load(Ordering::Acquire) == 1 {
          return unsafe { &MASK_KEY_BUF };              // fast path
      }
      let mut key = [0u8; 32];
      if !crate::entry::csprng_fill(&mut key) { /* rdtsc fallback */ }
      unsafe { MASK_KEY_BUF = key; }
      MASK_KEY_INIT.store(1, Ordering::Release);
      unsafe { &MASK_KEY_BUF }
  }
  ```
  `apply_rc4_to_regions` (`:154`) and `round_trip_selftest` (`:321-323`) now both call `mask_key()` once and reuse the `&'static [u8;32]` — so `mask()` and `unmask()` use the **same** key. The core bug (different keys → keystream∘keystream corruption) is **fixed**. The Acquire/Release pairing on the init flag is correct for the happens-before on the bytes.
- **描述 / 残留问题:**
  1. **Race on the slow path (theoretical):** two threads both observing `MASK_KEY_INIT==0` both run the slow path, both write `MASK_KEY_BUF` (a `static mut`), both store `1`. Under the single-threaded-beacon invariant this is fine, and the first call happens at init before any second thread exists. But the comment at `:124-126` and `:141` justifies `static mut` safety on "single-threaded beacon" — yet `mem::mask()` is also reachable from `fluctuation::do_fluctuate` which runs on the beacon thread (fine), and `mask_text_and_heap` is documented as called "by the Foliage helper" (`:237`) — a **separate thread**. If the Foliage helper ever calls into `mask_key()` before the beacon thread initializes it, you get a genuine data race on `MASK_KEY_BUF` (concurrent `static mut` writes are UB in Rust regardless of atomicity of the flag). Today the Foliage helper uses the caller-supplied `key` path (`mask_text_and_heap(key: &[u8], ...)`), not `mask_key()`, so this is latent — but the `static mut` is a footgun for the next editor.
  2. **Zero-key on rdtsc-fallback first byte:** if `csprng_fill` fails, the rdtsc-derived key is fine, but note the entire 32-byte key is derived from a single 64-bit `_rdtsc()` seed via a wrapping-mul LCG — low entropy if `_rdtsc()` returns a near-fixed value (early boot). Not a correctness bug (round-trip still works), just weaker than the doc's "per-boot unpredictable" claim.
  3. **`static mut` assignment is a Rust-2024 `static_mut_refs`/`static_mut_refs` lint** and under the strict aliasing model a `&MASK_KEY_BUF` shared across calls is technically a shared reference to a `static mut` — UB under stacked borrows. In practice on `windows-gnu` with `opt-level=z` this compiles and runs, but it is not sound by the language model.
- **影响:** the round-trip corruption (the original CRIT) is fixed on every path that is live today. The race/UB are latent.
- **修复:** replace `static mut MASK_KEY_BUF` with a `static MASK_KEY_BUF: core::sync::atomic::AtomicU64` x4 (or an `UnsafeCell` behind the init flag) and read it via `ptr::read_volatile` after the Acquire — or simpler, since the key is process-lifetime and set once, use `core::sync::atomic::AtomicPtr` to a leaked `Box<[u8;32]>` installed once. The latter is pattern-equivalent to what `OnceLock` does and is sound.
- **Verdict:** the fix achieves its stated goal (mask/unmask agree). Ship it. Track the `static mut` UB as a follow-up cleanup.

---

### [HIGH] FIX-AUDIT-3 — ntalloc eviction-free: frees a slab that may still hold live allocations (USE-AFTER-FREE)
- **位置:** `ntalloc.rs:55-83` (`track_slab` overflow), `:85-109` (`free_slab`), `:218-284` (alloc loop)
- **状态:** HIGH-8 PARTIALLY FIXED — the masking-gap (NEW-L4) is closed and the leak is bounded, but the fix introduces a **use-after-free**.
- **已核验:** the overflow branch now does:
  ```rust
  let evicted = SLAB_TABLE[0];
  if evicted.base != 0 {
      free_slab(evicted.base as *mut u8, evicted.len as usize);  // MEM_RELEASE the oldest slab
  }
  // shift left, insert new at end
  ```
  `free_slab` (`:91-109`) calls `NtFreeVirtualMemory(..., MEM_RELEASE=0x8000)` with `region_size=0` (correct MEM_RELEASE semantics — frees the entire region). `MAX_SLABS` is bumped 16→32 (`:30`), delaying overflow to ~32 MiB.
- **描述:** **this is a bump allocator with no per-allocation free-list** (`dealloc` is a no-op, `:306-310`). Every allocation handed out by `alloc()` lives forever (the allocator never reclaims individual objects). When `track_slab` evicts `SLAB_TABLE[0]`, that slab **still holds live allocations** — heap objects that beacon code holds raw pointers to (Vec buffers, String buffers, the leaked ECDH key copy from `beacon.rs:53`, config plaintext copies, etc.). `free_slab` then `MEM_RELEASE`s the entire region, unmapping those pages from the process address space. The next dereference of any pointer into the evicted slab → `STATUS_ACCESS_VIOLATION`.
  - The comment at `:65-69` claims "freeing the evicted slab bounds the leak AND keeps every live slab tracked so the sleep-mask still covers the full live heap" — true for the masking goal, but it achieves that by **freeing memory the program is still using**.
  - Worse: `beacon.rs:53` registers the leaked ECDH session-key copy via `mem::register_key`, and `beacon.rs:40` registers config plaintext via `register_owned`. Those are heap allocations (in slabs). If the slab holding them is evicted and freed, the `REGIONS` table in `mem.rs:60` now holds a **dangling pointer** → the next `mem::mask()` RC4s into unmapped memory → AV.
- **影响:** any beacon that allocates past 32 MiB (screenshots, large BOF output, downloads, long runtime with config/transport churn) triggers eviction → frees live heap → crash, or worse, silent corruption if the OS reuses the VA range. This converts HIGH-8 (a leak) into a **UAF / crash**. The masking-gap fix (NEW-L4) is achieved but by an unsafe means.
- **修复:** **do not free evicted slabs.** A bump allocator cannot reclaim memory it has handed out. The correct fix for NEW-L4 (evicted slab escapes mask coverage) is to **never evict** — grow the slab table dynamically (linked list of slab pages), or raise `MAX_SLABS` to a value that is effectively unreachable (e.g. 4096 = 4 GiB, costs 4096×16B = 64 KiB of static). The leak-by-design is acceptable for a PIC implant (documented at `:306-310`); the masking coverage is the real requirement, and a bigger/growable table satisfies it without freeing live memory.
- **Verdict:** **REVERT the `free_slab` call** (keep the `MAX_SLABS=32` bump and the honest comment, but make eviction a no-op-free + diag, or grow the table). As written, this is a regression from a leak to a UAF.

---

### [INFO] FIX-AUDIT-4 — evasion_glue.rs: `*key` deref is correct, no behavior change
- **位置:** `evasion_glue.rs:280-285`
- **状态:** CLEAN (mechanical adaptation to the new `mask_key()` signature).
- **已核验:** `mask_key()` now returns `&'static [u8;32]` instead of `[u8;32]`, so `mask_text(region.base, region.len, key)` passes the reference directly (it takes `&[u8]`), and `MaskToken::new(region.base, region.len, *key)` dereferences to copy the 32 bytes into the token. Both are correct. `mask_text` signature (`mem.rs:334`) takes `key: &[u8]`; the old call passed `&key` (double-ref, coerced); the new call passes `key` (single ref) — both coerce to `&[u8]`. No bug.
- **Verdict:** ship.

---

### [INFO] FIX-AUDIT-5 — tp.rs: honesty note is now accurate (NtCreateThreadEx fallback documented)
- **位置:** `tp.rs:1-34` (doc rewrite), `:352-384` (execution path)
- **状态:** CLEAN (documentation correction; no executable code changed in the diff).
- **已核验:** the new module doc correctly states only the "payload delivery" half (section-backed, no `VirtualAllocEx`/`WriteProcessMemory`) is implemented, and execution falls back to `NtCreateThreadEx(target, section_view)` at `:374-379` — confirmed by reading the live code. The `_TP_DIRECT`/`_TP_WORK` structures (`:157-188`) are defined but the worker-discovery/queue-splice (steps a/b/d, `:320-337`) is scaffolded, not wired. The doc's "Calling this threadless or 0-of-3 FND is incorrect" is accurate and useful for operators.
- **残留:** the section is mapped into the target with `PAGE_EXECUTE_READWRITE` (`:311`, `0x40`) and stays RWX for the shellcode's lifetime — same permanent-RWX IOC as `inject.rs:547/816` (NEW-L7). The shellcode runs from an RWX section view. Gated behind `POOL_PARTY_ENABLED` (default off, `:40`), so not on the default path.
- **Verdict:** ship the doc fix. Note the RWX-section IOC as a known limitation.

---

## Part 2 — Prior 07-08 findings: re-verification

Code has moved. Each finding re-checked at its cited location in the current working tree.

---

### CRIT-4 — caller_spoof bare `0xC3` fallback — STILL PRESENT (inert)
- **位置:** `caller_spoof.rs:135-141`
- **状态:** STILL PRESENT, INERT (no live consumer).
- **已核验:** the fallback loop is byte-identical to 07-08:
  ```rust
  for (j, &b) in bytes.iter().enumerate() {
      if b == 0xC3 {
          return Some(ReturnStub { addr: mod_base + j, stack_clean: 0 });
      }
  }
  ```
  The only live caller remains `blind_hwbp.rs:117-121`, which discards the result (`let _ = stub;`). `add_vectored_handler_spoofed` (`caller_spoof.rs:239`) and `call_with_spoofed_return_4` (`:165`) have **no call sites** in the beacon loop (grep confirms: zero `add_vectored_handler_spoofed(` / `call_with_spoofed_return_4(` invocations outside their own definitions and the doc example).
- **影响:** unchanged — a bare `0xC3` may be an operand byte; jumping there executes garbage. Unreachable today.
- **修复:** unchanged — drop the fallback; return `None` if no `48 83 C4 XX C3` found. Low priority (dead).

---

### CRIT-5 — fluctuation no unwind / Drop guard — PARTIALLY FIXED (see FIX-AUDIT-1)
- **位置:** `fluctuation.rs:94-109` (was `:66-78`)
- **状态:** PARTIALLY FIXED.
- **已核验:** the `MaskGuard`/`DrGuard` RAII structs (`:33-59`) now bracket the window (`:102-109`). Drop order is correct (reverse declaration → unmask before DR-restore). The guard covers early `return`/`?` but not hardware faults (honest comment at `:36-38`). See FIX-AUDIT-1 for full analysis.
- **修复:** see FIX-AUDIT-1 (move `mem::unmask` into the thunk tail for full coverage).

---

### CRIT-NEW-4 / NEW-H1 — mem::mask/unmask new key each call — FIXED (see FIX-AUDIT-2)
- **位置:** `mem.rs:121-147` (`mask_key`), `:153-170` (`apply_rc4_to_regions`)
- **状态:** FIXED.
- **已核验:** key is now cached in `MASK_KEY_BUF` / `MASK_KEY_INIT`, returned as `&'static [u8;32]`. `mask()` and `unmask()` call `apply_rc4_to_regions()` which calls `mask_key()` once → both passes use the same key. `round_trip_selftest` (`:320-324`) reuses the same cached key. The corruption bug is gone. Residual: `static mut` UB (see FIX-AUDIT-2). The misleading doc at `:92` and `:102` ("8 slots") still says 8 but `MAX_REGIONS=32` (`:55`) — NEW-L6 doc drift persists.

---

### HIGH-8 — ntalloc leak / slab table — PARTIALLY FIXED → REGRESSION (see FIX-AUDIT-3)
- **位置:** `ntalloc.rs:55-83`, `:85-109`, `:306-310`
- **状态:** PARTIALLY FIXED — the leak is bounded but the fix introduces UAF.
- **已核验:** `MAX_SLABS` raised 16→32 (`:30`); overflow now frees the oldest slab via `free_slab` (`:72`). NEW-L4 (evicted slab escapes mask coverage) is resolved because the evicted slab is unmapped (nothing to mask). But the evicted slab holds **live allocations** (bump allocator, no free-list) → freeing it is a use-after-free. See FIX-AUDIT-3.
- **修复:** revert `free_slab`; grow the table instead.

---

### MED-NEW-E1 / NEW-M2 — Foliage Context-5 restores .text as 0x40 RWX — STILL PRESENT
- **位置:** `sleep.rs:621-627`
- **状态:** STILL PRESENT.
- **已核验:**
  ```rust
  // Context 5: VirtualProtect(.text, .text_len, PAGE_EXECUTE_READWRITE=0x40, &OldProtect)
  rop_prot_rx.set_r8(0x40 as u64); // PAGE_EXECUTE_READWRITE   (:627)
  ```
  The function doc (`:406`) still says "5. VirtualProtect(.text, RX) — restore execute protection". Code says `0x40` (RWX). The leaked rc4 shim page is still allocated `0x40` RWX at `:472` and never freed or flipped to RX in this window. (The `Box`es for `key_buf`/`old_protect_box` ARE reclaimed at `:696-699` — that part is fine.)
- **影响:** if the Foliage-APC path runs, the implant's `.text` ends the cycle **RWX** — a permanent memory-scanner IOC, contradicting the documented RX. Gated behind `FOLIAGE_APC_ENABLED` (default off; `kits.rs:55` routes to `fluctuation`, not this chain), so not on the default path — but it ships wrong.
- **修复:** set Context-5 `r8` to `0x20` (`PAGE_EXECUTE_READ`) to match the doc and original `.text` protection; flip the rc4 shim page to RX after the copy (`:480`).

---

### MED-NEW-E2 / NEW-M3 — caller_spoof_thunk resume offset wrong — STILL PRESENT (5-byte error)
- **位置:** `caller_spoof_thunk.rs:135` (`let offset_to_resume: u8 = 10;`)
- **状态:** STILL PRESENT (dead code, ships broken).
- **已核验:** re-derived the byte distance from the `pop rax` (whose address lands in `rax` via `call $+5; pop rax`) to the `resume:` label (`pop r15` at `:156`):
  ```
  pop rax                  : 0x58                          (1 byte)   +0
  add rax, imm8 (offset)   : 48 83 C0 0A                   (4 bytes)  +1
  push rax                 : 50                            (1 byte)   +5
  push qword [r10]         : 41 FF 32                      (3 bytes)  +6
  mov rax, [r10+8]         : 49 8B 42 08                   (4 bytes)  +9
  jmp rax                  : FF E0                         (2 bytes)  +13
  resume: pop r15          : 41 5F                                    +15
  ```
  Distance from `pop rax` to `resume:` = **15 bytes**. The code adds **10**. The pushed resume address lands at `+10` = inside `mov rax,[r10+8]` (the `08` operand byte). On callee `RET` → ntdll-`RET` → pops `+10` → CPU decodes `08 FF E0 41 5F ...` = garbage → crash. The 07-08 finding said 15; I confirm 15. The comment at `:114-134` recomputes "1+3+4+2=10" but omits the 4-byte `add rax, imm8` it itself emits at `:138-139` (and the `pop rax` itself). Both omissions; net error is 5.
- **影响:** every invocation misroutes. Reachability: `build` is called only from `caller_spoof.rs:256` (`add_vectored_handler_spoofed`), which has no callers in the beacon loop — dead/shipped-broken.
- **修复:** set `offset_to_resume = 15`. Better: emit `lea rax, [rip + resume]` and let the assembler compute it — no magic constant. Lowest priority (dead code) but should be fixed before the path is ever wired.

---

### MED-5 — SSN sanity / no upper bound — STILL PRESENT
- **位置:** `syscalls.rs:117-118`, `:201-203`, `:168-177`
- **状态:** STILL PRESENT.
- **已核验:** `let max_ssn = table.iter().map(|(_, s)| *s).max().unwrap_or(0);` (`:117`) — no plausibility bound. `trampoline_for(ssn)` (`:201-203`): `self.trampoline.add((ssn as usize) * STUB_SIZE)` — no bounds check. `ssn_by_hash` (`:168-177`) only rejects `u32::MAX`. A poisoned SSN (e.g. `0xFFFF`) inflates the trampoline alloc to ~2 MiB and, more importantly, the stub sets `mov eax, <bogus>; syscall` → wrong syscall executes. Indexing stays in-bounds (max is the table max), so no OOB write — risk is wrong-SSN execution.
- **影响:** a bogus SSN from a hooked/corrupted fresh-ntdll read → `STATUS_INVALID_SYSTEM_SERVICE` or an unrelated syscall.
- **修复:** clamp at resolve: `if ssn > 0x400 { discard }`; reject `max_ssn > 0x400` in `init()`.

---

### MED-7 — blind_hwbp `static mut` race — STILL PRESENT
- **位置:** `blind_hwbp.rs:87-90`
- **状态:** STILL PRESENT.
- **已核验:** `static mut HWBP_ENTRIES: [Option<HwbpEntry>; 4]`, `HWBP_COUNT`, `VEH_HANDLE`, `SHADOW_BUF` (`:87-90`) all `static mut`. The VEH handler `hwbp_veh_handler` (`:309`) runs on **whatever thread takes the `#DB`** and reads `HWBP_ENTRIES[i]` via `read_volatile` (`:368`), while the beacon thread writes them in `add_hwbp`/`remove_hwbp` (`:700`, `:715`). `read_volatile` does not make a `static mut` read sound. Torn read of `Option<HwbpEntry>` during install/remove → handler misroutes.
- **影响:** genuine Rust UB; low real-world frequency (HWBPs rarely toggled mid-run).
- **修复:** back the table with `AtomicU64`-packed entries or a `spin::Mutex` shared by mutator and handler; never `static mut`.

---

### MED-8 — `VmCfgInfo` layout placeholders — STILL PRESENT
- **位置:** `cfg_user.rs:212-220`
- **状态:** STILL PRESENT.
- **已核验:**
  ```rust
  struct VmCfgInfo {
      number_of_entries: u32,
      _pad: u32,
      _z1: usize,        // assumed placeholder
      _z2: usize,        // assumed placeholder
      entry_ptr: *mut CfgTargetInfo,
      out_ptr: *mut u32,
  }
  ```
  `size_of::<VmCfgInfo>()` passed as last arg (`:243`). The real `MI_CFG_INFORMATION` / call-target descriptor layout for `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)` is version-sensitive; the two `usize` placeholders are a guess. Wrong offset → kernel reads wrong pointer → `STATUS_INVALID_PARAMETER` (CFG marking silently fails → `#FC` on CFG hosts) or worse.
- **修复:** derive layout from a version-checked PHNT definition; or probe one known CFG-valid address and assert success before relying on it.

---

### MED-9 — proxy_veh trampoline `jmp rax` + ntdll RWX — STILL PRESENT
- **位置:** `proxy_veh.rs:342-384`
- **状态:** STILL PRESENT.
- **已核验:** trampoline `48 B8 <handler> FF E0` (`mov rax, imm64; jmp rax`, `:358-365`); cave page flipped `PAGE_EXECUTE_READWRITE` (`0x40`, `:346`) for the write then back to `PAGE_EXECUTE_READ` (`:375`). Only the trampoline cave address is marked CFG-valid (`:380`), not the handler — so on a CFG-enforcing host the `jmp rax` to a non-CFG-valid handler raises `#FC`. Briefly turning an ntdll `.text` page RWX is a code-integrity IOC. No check that `find_code_cave` returns ≥12 bytes.
- **修复:** mark the handler CFG-valid; validate cave size ≥12; prefer `PAGE_READWRITE` write + restore to original protection.

---

### LOW-6 — caller_spoof 1 MiB scan cap — STILL PRESENT
- **位置:** `caller_spoof.rs:120`
- **已核验:** `region_size.min(0x100000)` — only first 1 MiB scanned. Cosmetic (stub virtually always found early).

### LOW-7 — fluctuation thunk on RWX page — STILL PRESENT
- **位置:** `fluctuation.rs:81` (alloc `0x3000, 0x40`), `fluctuation_thunk.rs:4`
- **已核验:** `let st = alloc(!0usize, &mut page, 0, &mut sz, 0x3000, 0x40);` — RWX, copied in (`:88`), executed (`:106`) without flipping to RX. Then freed at `:117`. The page is short-lived (one sleep window) but is live RWX during sleep — a memory-scanner IOC for that window.
- **修复:** alloc RW, copy, `NtProtectVirtualMemory` → `PAGE_EXECUTE_READ` (0x20), then execute.

### NEW-L5 — blind_hwbp scans ntdll then discards — STILL PRESENT
- **位置:** `blind_hwbp.rs:116-121`
- **已核验:** `if let Some(stub) = crate::caller_spoof::scan_return_stub() { diag(b'R'); let _ = stub; }` — full up-to-1 MiB scan then discard. Only live reach of CRIT-4's fallback.

### NEW-L6 — doc/code mismatches — PARTIALLY STILL PRESENT
- `hookchain.rs:345`: comment says *"PAGE_EXECUTE_READ (0x20) — NOT RWX"* directly above `0x40 /* RWX initially */`. Net behavior correct (locked to RX by `lockdown_stub_page` `:396-409`), but comment is wrong.
- `mem.rs:92` and `:102`: `register_owned`/`register_key` docs say *"8 slots"* but `MAX_REGIONS=32` (`:55`). Note the `register_region` doc at `:50-54` was updated to say "32" — the two sibling docs were missed.
- `fluctuation.rs:33-38` doc is now accurate (honest about panic=abort).

### NEW-L7 — injection permanent private RWX — STILL PRESENT (out of domain files, noted for completeness)
- `inject.rs:547`, `:816`; plus `tp.rs:311` (section mapped RWX). Documented IOCs.

---

## Part 3 — New findings (not in 07-08 baseline)

---

### [NEW-MED-N1] ntalloc `free_slab` use-after-free (the FIX-AUDIT-3 regression)
- **位置:** `ntalloc.rs:70-73` (free call), `:91-109` (`free_slab`)
- **状态:** NEW — introduced by the in-progress fix.
- See FIX-AUDIT-3 above for the full writeup. This is the single most urgent item in the domain: the fix for HIGH-8/NEW-L4 converts a leak into a use-after-free. **The eviction `free_slab` must be removed** (or the table grown) before this diff is committed.

---

### [NEW-MED-N2] lacuna_stomp `with_ghost_stack` unbalanced stack on closure panic/AV — `add rsp` assumes no frame growth
- **位置:** `lacuna_stomp.rs:66-103`
- **状态:** NEW.
- **已核验:**
  ```rust
  for i in (0..frames_len).rev() {
      let addr = core::ptr::read(frames_ptr.add(i));
      asm!( "push {}", in(reg) addr );
  }
  f();
  let pop_bytes = frames_len * 8;
  asm!( "add rsp, {}", in(reg) pop_bytes );
  ```
  The `push` loop lowers RSP by `frames_len * 8`; after `f()` returns, `add rsp, frames_len * 8` restores it. This is balanced **only if `f()` returns with the same RSP it entered with** (standard ABI leaf/non-leaf). That holds for a normal return. BUT:
  1. The `push` instructions are emitted inline in the function's own frame. Rust/LLVM assumes it owns its stack frame; inserting raw `push`/`add rsp` around an inline closure call can confuse the compiler's stack-pointer tracking, especially under `opt-level=z` LTO where frame elimination is aggressive. There is no `nomem`/`nostack` option here (correctly — it DOES touch the stack), but LLVM may still move/clobber RSP-relative locals across the `asm!` boundary if it does not see the `push` as adjusting the frame. The `asm!` blocks are not `options(att_syntax)` and use the default `preserves_flags` off — but the real risk is that `f()` is a closure that LLVM may inline, and the `add rsp` is in a *separate* `asm!` block from the `push`es, so LLVM could schedule stack-relative loads/stores between them.
  2. The doc at `:60-61` honestly says "closure must not unwind (panic/exception) while ghost frames are on the stack — the stack would be corrupted." Under `panic=abort` a Rust panic is process death, so that's fine. But a **hardware exception** (e.g. an AV inside `f()` that the VEH handler catches and `EXCEPTION_CONTINUE_EXECUTION` resumes) would resume with RSP at the post-`push` value — the `add rsp` still runs, so it's actually balanced on resume. The real residual is risk (1).
- **影响:** if LLVM mis-schedules around the split `asm!`, RSP-relative locals in `with_ghost_stack`'s frame could be read at the wrong offset → silent corruption. Hard to trigger but it is an `asm!`-vs-optimizer hazard.
- **修复:** merge the push/call/pop into a **single** `asm!` block so LLVM sees the full RSP lifecycle as one opaque operation, and use `options(nostack)` only on the inner call trampoline (or hand-write the whole sequence). At minimum, add `add rsp, N` *inside the same asm block* that calls `f`, and mark the whole thing `nomem` on the push/pop only.

---

### [NEW-LOW-N3] fluctuation `DrState.ctx_buf` is a 1232-byte stack copy passed by value — stack pressure + the `restore_dr_state` copy is redundant
- **位置:** `fluctuation.rs:124-128` (`DrState` with `ctx_buf: [u8; 1232]`), `:188` (`let mut buf = saved.ctx_buf;`)
- **状态:** NEW (cosmetic / minor).
- **已核验:** `DrState` is 1232 bytes + 6×u64 = ~1280 bytes, held by value in `DrGuard` (`:48-50`) on the stack, then `restore_dr_state` copies it again into a local `buf` (`:188`). That is ~2.5 KiB of stack for the DR-restore path, on a thread whose stack the thunk just manipulated. Not a bug (Windows default thread stack is 1 MiB), but the second copy (`:188`) is unnecessary — `restore_dr_state` takes `&DrState` and could write into `saved.ctx_buf` directly (the `DrGuard` owns it mutably in `drop`). The `core::ptr::write_unaligned` calls (`:195-212`) then operate on `&mut saved.ctx_buf` in place.
- **影响:** wasted stack; no correctness issue.
- **修复:** operate on `self.saved.ctx_buf` directly in `DrGuard::drop` (remove the `let mut buf = saved.ctx_buf` copy).

---

### [NEW-LOW-N4] `mem.rs` doc says mask_key is "per-run from the syscall runtime's SSN table" — code uses CSPRNG, not SSN
- **位置:** `mem.rs:13-14` (module doc), `:111-120` (`mask_key` doc)
- **状态:** NEW (doc drift introduced alongside the fix).
- **已核验:** the module doc (`:13-14`) says *"key derived per-run from the syscall runtime so the keystream differs across boots"* and `mask_key`'s doc (`:111-112`) says *"Derive a per-run RC4 key from the syscall runtime's SSN table"*. But the implementation (`:129-137`) calls `crate::entry::csprng_fill` (RtlGenRandom) — a true CSPRNG, NOT the SSN table. The SSN-table derivation is what `sleep.rs::mask_key_16` (`:227-241`) does (a *different* function in a *different* module). The `mem.rs` doc describes the wrong algorithm.
- **影响:** pure documentation misdirection; the code is fine (CSPRNG is strictly better than an SSN-derived key for entropy).
- **修复:** update the `mem.rs` doc to say "CSPRNG (RtlGenRandom), cached once" — drop the SSN-table claim.

---

### [NEW-LOW-N5] `lacuna::bootstrap_scan` leaks three `Vec<GhostRegion>` if the ntdll scan is empty
- **位置:** `lacuna.rs:128-153`
- **状态:** NEW (minor leak; bump allocator, no free-list — so "leak" is the norm here, but it's avoidable).
- **已核验:** `bootstrap_scan` allocates `ntdll_ghosts`, `kb_ghosts`, `w32_ghosts` (`:133-135`). If `ntdll_ghosts.is_empty()` (`:147`), it returns early without installing a chain, and all three Vecs are dropped normally (fine — Vec drop is a no-op on the bump allocator). If non-empty, `build_ghost_chain` (`:148`) produces a `GhostChain` whose `frames` Vec is then leaked by `lacuna_stomp::install_ghost_chain` (`lacuna_stomp.rs:43-47`, intentional process-lifetime leak). The original three scan Vecs drop. So this is actually clean — no leak. **Retracted on closer reading.** Noting only to show the path was checked.

---

## Verified-clean areas (with evidence)

- **`stack.rs` — RSP-swap spoof is correctly CET-gated and reentrancy-guarded.** `SPOOF_SWAP_ENABLED` defaults false; `with_spoofed_stack` fast-paths to a direct call when disarmed (`:255-257`) and consults `nyx_implant_evasionsdk::swap::should_execute(cet_on, gaps_usable)` (`:265`) before any `mov rsp`. `do_rsp_swap` enforces 16-byte RSP alignment, declares no `nostack`, and guards reentrancy (`:359`). The 256-u64 fake-stack buffer is process-lifetime leaked once (`:324-338`). Best-reasoned unsafe code in the crate. Unchanged since 07-08.
- **`unhook.rs` — fresh-ntdll map is bounds-checked + RAII-unmapped.** ZeroBits/CommitSize passed by value; `SECTION_MIN_ACCESS` chosen to survive the system ACL; `FreshMapGuard::drop` unmaps (`syscalls.rs:227-233`). Honest IOC docs. Unchanged.
- **`syscalls.rs` — indirect-stub page written once then flipped RX once.** All stubs pre-filled (`:141-148`), whole region flipped to `PAGE_EXECUTE_READ` a single time (`:150-158`). No per-call `VirtualProtect`. `scan_syscall_gadget` reads in 64 KiB chunks (`:245-256`). Unchanged (MED-5 SSN-bound aside).
- **`blind.rs` — P0 byte-patch is idempotent and ABI-correct.** Patches end in plain `ret` (not `ret imm16`); `write_patch` restores original protection (`:117`); `already_patched` short-circuits redundant `VirtualProtect` (`:100`). Unchanged.
- **`blind_hwbp` shadow buffer downgrades RW→RX.** `init_shadow_buffer` (`:214-264`) allocates `PAGE_READWRITE`, writes stubs, flips to `PAGE_EXECUTE_READ` (`:261`) — closes the RWX IOC. The VEH handler's RF-based single-phase redirect (`:382-388`: set RIP=shadow, set RF, clear DR6, `EXCEPTION_CONTINUE_EXECUTION`) is the correct boku7 pattern. (MED-7 `static mut` race aside.)
- **`hookchain.rs` — RVA→SSN from pristine export dir, IAT restored, stubs locked down.** IAT rewrite flips to `PAGE_READWRITE` (not RWX) and restores (`:221-231`); `apply()` ends with `lockdown_stub_page()` → RX (`:449-450`); binary search correct. (NEW-L6 comment drift aside.) The `apply()` reset of `STUB_PAGE`/`STUB_CURSOR` (`:430-431`) correctly allocates a fresh RWX page per call to avoid writing into a locked-down RX page — the old page is leaked RX, harmless.
- **`ntalloc.rs` — ZeroBits passed by value** (`:182`), oversized slabs sized to the request (`:168-189`). (FIX-AUDIT-3 UAF aside.)
- **`caller_spoof.rs` PE walk — correct section-offset math.** `scan_stub_in_module` computes the section table offset as `e_lfanew + 4 + 20 + size_of_optional_header` (`:96`), explicitly not using `ImageNtHeaders64` struct size (comment `:336-339`). Correct cross-arch derivation. (CRIT-4 fallback aside.)
- **`lacuna.rs` / `lacuna_stomp.rs` — .pdata gap scanner is structurally sound.** `IMAGE_RUNTIME_FUNCTION_ENTRY` (12 bytes, sorted) handling correct; ghost-chain leaf-frame spoof exploits the documented `RtlLookupFunctionEntry → NULL → leaf (RSP+=8)` behavior. `with_ghost_stack` documents the no-unwind contract (`:60-65`); the `add rsp, N*8` matches the push count. (NEW-MED-N2 asm-scheduling hazard aside.)
- **`antidebug.rs` — clean.** `is_debugged` reads `PEB+2` via `gs:[0x60]` with `nostack, preserves_flags, readonly` (`:33-37`) — correct and zero-noise. `is_remote_debugged` uses the indirect-syscall runtime first (`:57-77`) with a correct export fallback. `uptime_secs` is a thin `GetTickCount64/1000`. No unsafe violations.
- **`pic_thunk.rs` — honest research-grade scaffolding.** Gated behind `FOLIAGE_APC_ENABLED` (default off). The `PicThunkParams` offset constants (`:94-106`) are asserted against the struct via `offset_of!` in tests. No live execution path today.
- **`tp.rs` — doc now honest about the NtCreateThreadEx fallback** (FIX-AUDIT-5). Section-delivery half is sound (no `VirtualAllocEx`/`WriteProcessMemory`). Gated default off.
- **`fluctuation_thunk.rs` — the thunk's `.text` RX-restore is self-healing.** Step 3 (`:89-108`) restores `.text` to `PAGE_EXECUTE_READ` *inside* the thunk (on the RWX thunk page), so even if the beacon thread faults, the thunk's own RX-restore runs as long as the thunk reaches step 3. This is why the NOACCESS `.text` window is recoverable for the perms (the residual CRIT-5 exposure is the registered data regions, not `.text` perms — see FIX-AUDIT-1).

---

## Summary table

| ID | Sev | File:Line | Status (vs 07-08) |
|----|-----|-----------|-------------------|
| **FIX-AUDIT-1** (=CRIT-5) | HIGH | fluctuation.rs:33-59,97-109 | PARTIALLY FIXED — guard closes early-return window, NOT hardware-fault window (panic=abort) |
| **FIX-AUDIT-2** (=NEW-H1) | (FIXED→MED) | mem.rs:38-48,121-147 | FIXED for round-trip; residual `static mut` UB latent under Foliage-helper reach |
| **FIX-AUDIT-3 / NEW-MED-N1** | HIGH | ntalloc.rs:70-73,91-109 | REGRESSION — eviction `free_slab` frees live allocations (UAF); revert and grow table |
| FIX-AUDIT-4 | INFO | evasion_glue.rs:280-285 | CLEAN |
| FIX-AUDIT-5 | INFO | tp.rs:1-34 | CLEAN (doc honesty) |
| CRIT-4 | (CRIT→LOW) | caller_spoof.rs:135-141 | STILL PRESENT, inert (result discarded blind_hwbp.rs:120) |
| MED-5 | MED | syscalls.rs:117,201 | STILL PRESENT (no SSN bound) |
| MED-7 | MED | blind_hwbp.rs:87-90 | STILL PRESENT (`static mut` race) |
| MED-8 | MED | cfg_user.rs:212-220 | STILL PRESENT (VmCfgInfo placeholder layout) |
| MED-9 | MED | proxy_veh.rs:342-384 | STILL PRESENT (`jmp rax` CFG + ntdll RWX) |
| MED-NEW-E1 / NEW-M2 | MED | sleep.rs:621-627 | STILL PRESENT (Context-5 = 0x40 RWX, not 0x20 RX) |
| MED-NEW-E2 / NEW-M3 | MED | caller_spoof_thunk.rs:135 | STILL PRESENT (offset 10, should be 15; dead code) |
| LOW-6 | LOW | caller_spoof.rs:120 | STILL PRESENT (1 MiB cap) |
| LOW-7 | LOW | fluctuation.rs:81 | STILL PRESENT (RWX thunk page) |
| NEW-L5 | LOW | blind_hwbp.rs:116-121 | STILL PRESENT (scan then discard) |
| NEW-L6 | LOW | hookchain.rs:345 / mem.rs:92,102 | PARTIALLY STILL PRESENT (mem.rs:50-54 fixed; :92/:102 missed) |
| NEW-L7 | LOW | inject.rs:547,816; tp.rs:311 | STILL PRESENT (permanent RWX) |
| **NEW-MED-N2** | MED | lacuna_stomp.rs:66-103 | NEW — split `asm!` push/call/pop is an optimizer-scheduling hazard |
| NEW-LOW-N3 | LOW | fluctuation.rs:124-128,188 | NEW — redundant 1232B stack copy in restore_dr_state |
| NEW-LOW-N4 | LOW | mem.rs:13-14,111-112 | NEW — doc claims SSN-derived key, code uses CSPRNG |

---

## Highest-priority fixes (ordered)

1. **NEW-MED-N1 / FIX-AUDIT-3 (ntalloc UAF)** — **revert `free_slab` before committing the diff.** It frees live heap. Grow the table or make eviction leak-only. This is a correctness regression introduced by the fix itself.
2. **FIX-AUDIT-1 (CRIT-5 residual)** — move `mem::unmask()` into the fluctuation thunk's tail (after `.text` RX-restore, before `RET`) so the registered-data-region restore runs on the executable thunk page, not the beacon thread. Only then is the NOACCESS/ciphertext window fully recoverable on a fault.
3. **MED-5 (SSN bound)** — one-line clamp `if ssn > 0x400 { discard }` at resolve; prevents wrong-syscall execution from a poisoned read.
4. **MED-8 (VmCfgInfo layout)** — the CFG-bypass silently failing on a wrong-offset build means `#FC` on CFG hosts; derive from PHNT or probe-and-assert.
5. **FIX-AUDIT-2 residual (`static mut`)** — replace `MASK_KEY_BUF` `static mut` with a sound once-init pattern (AtomicPtr to leaked Box, or UnsafeCell behind the flag).
6. **MED-7 (blind_hwbp race)** — de-`static mut` the HWBP table (AtomicU64-packed or Mutex).
7. **MED-NEW-E1 (sleep.rs Context-5 RWX)** — change `:627` `0x40` → `0x20`; ships wrong though gated off.

The remaining items (CRIT-4 fallback, MED-9 proxy_veh, MED-NEW-E2 offset, LOW-*) are in dead/gated code paths and are lower urgency, though CRIT-4 and MED-NEW-E2 should be fixed before their respective paths are ever wired live.
