# Nyx C2 Framework - Implant Injection Subsystem Security Audit Report

This report details the security, cryptographic, detection, and design findings identified during a thorough code audit of the Nyx C2 Windows implant source files under `crates/implant-win/src/`:
- `inject.rs` (Process Injection & HWBP Threadless Injection)
- `stack.rs` (Call-Stack Spoofing & RSP Swapping)
- `bof.rs` (COFF Loader & Beacon API Shims)
- `syscalls.rs` (Indirect Syscall Runtime)

---

## Executive Summary
The target files implement critical evasion and execution capabilities of the Windows implant. The audit identified two **High** severity vulnerabilities: a logic bug in the HWBP injection routing that will cause immediate target process crashes, and a global buffer overflow in the BOF loader API that allows memory corruption. Several **Medium** severity findings were also uncovered, including design flaws in the call-stack spoofing mechanism that expose the implant to EDR stack-walking detection, a reentrancy race condition in the syscall runtime, and missing bounds checks in the BOF argument parser.

---

## Detailed Audit Findings

### Finding 1: Broken HWBP Execution Redirection Logic & Thread Handle Abuse (Severity: High)
* **Affected File**: `crates/implant-win/src/inject.rs` (`threadless_inject` and `do_inject`)
* **Description**:
  The `threadless_inject` function attempts to hijack execution of a sacrificial process's main thread by placing a hardware execution breakpoint (HWBP) on a trigger address. The logic contains two fatal defects:
  1. **Handle as Address**: In `do_inject` (lines 732–733), the trigger address is passed as `proc.main_thread as usize`. `proc.main_thread` is a thread *handle* (a kernel-assigned index in the host process's handle table, e.g., `0x78`), not a memory address in the target virtual address space. Setting a hardware breakpoint on `0x78` will never trigger because the thread will never execute instructions in the NULL page.
  2. **No Exception Handler in Target**: A hardware breakpoint triggers a `STATUS_SINGLE_STEP` / `#DB` exception. If the target process (`notepad.exe`) has no active exception handler (such as a Vectored Exception Handler (VEH)) or debugger registered to catch this exception and adjust the instruction pointer (`RIP`), the default Windows exception dispatcher (WerFault) is invoked, immediately terminating the target process. Since the loader does not map or register any exception handler in the target process, hitting the breakpoint will immediately crash the process.
* **Threat Scenario**:
  An operator triggers HWBP threadless injection. The implant creates `notepad.exe` in a suspended state, writes the shellcode, sets `DR0` to the value of the thread handle (`0x7c`), and resumes the thread. The thread executes normally, never hitting `0x7c`. If the trigger address is corrected to the thread's entry point but no remote exception handler is registered, the thread executes its first instruction, triggers the HWBP exception, fails to find a handler, and crashes `notepad.exe` in a loud manner. An EDR or SIEM log flags a system process crashing due to a debug exception, revealing the injection attempt.
* **Remediation**:
  If the goal is to perform a stealthy thread hijack without creating a remote thread, the implant should avoid hardware breakpoints (which require complex exception handling in the remote target) and instead update the thread's instruction pointer (`RIP`) directly in the suspended state.
  1. In `do_inject`, read the thread's current context.
  2. Modify `RIP` (offset `0x0F8` in the `CONTEXT` struct) to point to the remote shellcode allocation address (`remote_base`).
  3. Set the context and resume the thread.
  This redirects execution immediately and safely without raising debug exceptions in the target.

---

### Finding 2: Global Buffer Overflow in `BeaconGetSpawnTo` (Severity: High)
* **Affected File**: `crates/implant-win/src/bof.rs` (`BeaconGetSpawnTo`)
* **Description**:
  The `BeaconGetSpawnTo` shim returns a pointer to a static writable buffer `SPAWN` initialized with `C:\Windows\System32\cmd.exe\0`. The buffer size is defined exactly as `28` bytes:
  ```rust
  static mut SPAWN: [u8; 28] = [0; 28];
  ```
  However, Cobalt Strike community BOFs frequently call `BeaconGetSpawnTo` and attempt to append command-line arguments (e.g., ` /c whoami`) directly to the returned buffer using functions like `strcat`, assuming it is backed by a large buffer (typically 1024 or 2048 bytes). Writing past the 28-byte boundary causes a global buffer overflow, corrupting adjacent static variables and data in the implant's `.data` section.
* **Threat Scenario**:
  An operator executes a community BOF that runs a local command. The BOF calls `BeaconGetSpawnTo` and appends ` /c net user` to the returned buffer. The write overflows `SPAWN` and overwrites nearby critical statics such as `MODULESTOMP_ENABLED` or `GLOBAL_RT`, leading to corrupted execution states, memory access violations, and a crash of the implant thread.
* **Remediation**:
  Increase the size of the static `SPAWN` buffer to `1024` or `2048` bytes to safely accommodate splicing of command-line arguments by community BOFs.
  ```rust
  #[no_mangle]
  pub unsafe extern "C" fn BeaconGetSpawnTo(_x86: i32) -> *mut u8 {
      static mut SPAWN: [u8; 1024] = [0; 1024];
      const TEMPLATE: &[u8] = b"C:\\Windows\\System32\\cmd.exe\0";
      unsafe {
          core::ptr::copy_nonoverlapping(
              TEMPLATE.as_ptr(),
              SPAWN.as_mut_ptr(),
              TEMPLATE.len(),
          );
          SPAWN.as_mut_ptr()
      }
  }
  ```

---

### Finding 3: Implant Memory Disclosure in Call-Stack Spoofing (Severity: Medium)
* **Affected File**: `crates/implant-win/src/stack.rs` (`do_rsp_swap`, `spoof_trampoline`, and `run_f_on_spoof`)
* **Description**:
  The call-stack spoofing routine swaps `RSP` to a fake stack populated with `.pdata` gap addresses. However, after the swap, the inline assembly executes a nested `call`:
  ```rust
            "mov rsp, {fake}",        // 2. swap onto the spoofed (gap) stack
            "call {tramp}",           // 3. trampoline → f (on spoofed RSP)
  ```
  Executing `call {tramp}` pushes the return address to `do_rsp_swap` (which is inside the implant's `.text` section) onto the stack. Furthermore, `spoof_trampoline` and `run_f_on_spoof` are standard compiled Rust functions in the implant. When they execute, they push their own return addresses (pointing to the implant) onto the stack.
  As a result, at the moment the syscall is triggered, the active stack frames starting from `RSP` upwards contain multiple return addresses pointing directly to the implant's private/unbacked memory space before reaching the gap addresses.
* **Threat Scenario**:
  An EDR hook intercepts a sensitive syscall (e.g. `NtAllocateVirtualMemory`) and walks the caller thread's stack starting from `RSP`. Because the first few frames point to the implant's `spoof_trampoline`, `run_f_on_spoof`, and `do_rsp_swap` in unbacked memory, the EDR flags the call stack as anomalous and blocks execution, rendering the stack spoofing mechanism completely ineffective.
* **Remediation**:
  To ensure no implant return addresses remain on the stack during the syscall:
  1. Do not use a nested `call` from the implant once the stack pointer is swapped.
  2. Instead, push a signed-DLL landing gadget address directly onto the fake stack as the return address for the syscall.
  3. Load the syscall parameters into registers (`RCX`/`R10`, `RDX`, `R8`, `R9`) and execute a `jmp` instruction directly to the syscall gadget in `ntdll.dll`.
  4. The landing gadget should route execution back to a restoration sequence in the implant once the syscall returns.

---

### Finding 4: Missing Bounds Checking in BOF Argument Parser (Severity: Medium)
* **Affected File**: `crates/implant-win/src/bof.rs` (`BeaconDataExtract`, `BeaconGetInt`, `BeaconGetShort`, `BeaconGetStr`)
* **Description**:
  The Beacon-API parsing shims do not validate that reads occur within the bounds of the input buffer.
  - `BeaconDataExtract` reads a 4-byte length (`len`) from the buffer pointer, and then advances the buffer pointer by `len` bytes without checking if the bytes to be read fall within the `size` of the parsed arguments buffer.
  - `BeaconGetInt` and `BeaconGetShort` read raw integers directly from the current buffer pointer without checking if there are sufficient bytes remaining.
  - `BeaconGetStr` scans for a NUL byte up to `4096` bytes without verifying that it does not read past the end of the arguments buffer.
  If presented with truncated or malformed argument packets, these shims will read out-of-bounds, causing Access Violations (segmentation faults) or disclosing stale heap memory to the BOF.
* **Threat Scenario**:
  A corrupted command packet containing a malformed BOF argument is received by the implant. The BOF calls `BeaconGetInt`. The parser attempts to read 4 bytes from an out-of-bounds address, crossing a page boundary into unmapped memory, causing the implant to crash and terminating the session.
* **Remediation**:
  Implement explicit bounds checks in all parsing functions using the `size` and current pointer offset:
  ```rust
  #[no_mangle]
  pub unsafe extern "C" fn BeaconGetInt(d: *mut DataParseState) -> i32 {
      if d.is_null() || (*d).buffer.is_null() {
          return 0;
      }
      let consumed = (*d).buffer as usize - (*d).original as usize;
      let left = (*d).size - consumed as i32;
      if left < 4 {
          return 0;
      }
      let v = *((*d).buffer as *const i32);
      (*d).buffer = (*d).buffer.add(4);
      v
  }
  ```
  Apply similar checks to `BeaconDataExtract` (validate `left >= 4` and then `left >= 4 + len`), `BeaconGetShort`, and `BeaconGetStr` (restrict the search loop to the remaining buffer size).

---

### Finding 5: Concurrency Race Condition & Frequent `VirtualProtect` Calls in Syscall Trampoline (Severity: Medium/Low)
* **Affected File**: `crates/implant-win/src/syscalls.rs` (`trampoline_for`)
* **Description**:
  The indirect syscall runtime uses a single shared memory page (`self.trampoline`) to hold the syscall stub. Whenever an indirect syscall is made, `trampoline_for` writes the stub to the page, calls `VirtualProtect` to make it RWX, copies the stub, and then calls `VirtualProtect` to make it RX.
  This introduces two critical issues:
  1. **Reentrancy Race Condition**: If the implant is running in a multi-threaded process, or if an Asynchronous Procedure Call (APC) is executed (such as during the Foliage sleep dance) and invokes an indirect syscall, it can overwrite the shared trampoline page *after* a thread has resolved the trampoline address but *before* it executes it. The thread will execute the wrong syscall stub, causing critical state mismatch, memory corruption, or crashes.
  2. **EDR Heuristic Triggers**: Calling `VirtualProtect` twice on every syscall to swap memory page permissions (RWX/RX) on a private page creates a highly suspicious behavioral signature that EDRs actively monitor.
* **Threat Scenario**:
  During the Foliage sleep cycle, the main thread is suspended and an APC fires to manipulate the context. The APC executes a syscall, overwriting the shared trampoline page. When the main thread resumes and executes the trampoline (expecting its original syscall), it runs the APC's syscall instead, corrupting register states and crashing the implant.
* **Remediation**:
  To eliminate both the race condition and the frequent `VirtualProtect` calls:
  1. Allocate the trampoline page as RX at startup.
  2. Temporarily flip the page to RWX, write the stubs for *all* required syscalls at fixed offsets once during initialization, and flip it back to RX permanently.
  3. Modify the syscall wrappers to jump directly to the specific offset of the required syscall stub in the page.
  This makes the runtime completely thread-safe and reentrant, and avoids any runtime `VirtualProtect` calls on the syscall hot path.

---

### Finding 6: Process and Thread Handle Leaks in Injection Dispatch (Severity: Low)
* **Affected File**: `crates/implant-win/src/inject.rs` (`do_inject`, `module_stomp`, `threadless_inject`)
* **Description**:
  When a sacrificial process is created via `create_sacrificial`, the process and thread handles are returned to the caller. However, in `do_inject`, these handles are never closed using `CloseHandle` (either on success or failure of the injection techniques). They are leaked, causing handle table exhaustion over time.
* **Threat Scenario**:
  The operator runs multiple commands that spawn sacrificial processes (e.g. injection, post-exploitation jobs). Each invocation leaks the process and thread handles. Over a long-running session, the implant process exhausts the system handles, causing subsequent system operations to fail.
* **Remediation**:
  Always close the process and thread handles in `do_inject` once the injection routine has completed or failed:
  ```rust
  if let Some(ch) = export_addr(b"kernel32.dll", b"CloseHandle") {
      type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
      let close: CloseHandleFn = core::mem::transmute(ch);
      close(proc.handle);
      close(proc.main_thread);
  }
  ```

---

### Finding 7: Memory Staging Overflow Risk & Heap Corruption in Call-Stack Spoofing (Severity: Low)
* **Affected File**: `crates/implant-win/src/stack.rs` (`do_rsp_swap`)
* **Description**:
  The call-stack spoofing routine allocates a static heap-allocated buffer of 2 KiB (`cap = 256` u64 slots) named `FAKE_STACK` to act as the temporary stack. If a closure `f()` executed on the spoofed stack invokes nested functions that allocate large local variables or buffers on the stack (e.g. >1 KiB), the stack pointer can easily overflow the 2 KiB allocation limit. Because `FAKE_STACK` is a raw heap buffer and has no guard page, an overflow will silently overwrite adjacent heap memory, causing unpredictable heap corruption.
* **Threat Scenario**:
  A function running inside `with_spoofed_stack` attempts to allocate a local buffer on the stack (such as a file path buffer or dynamic data structure). The stack allocation exceeds the remaining portion of the 2 KiB buffer, overwriting the metadata or data of adjacent heap blocks. The implant subsequently crashes or exhibits unstable behavior when the allocator accesses the corrupted heap blocks.
* **Remediation**:
  Increase the size of `FAKE_STACK` to a safer margin (e.g., `16` KiB or `64` KiB) to match standard Windows thread stack ceilings, and implement thread-safety checks if multi-threaded execution is possible. Alternatively, use a thread-local stack buffer or register a guard page at the stack limit.
