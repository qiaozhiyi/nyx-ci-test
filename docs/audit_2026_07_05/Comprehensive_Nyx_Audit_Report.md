# Nyx C2 Framework: Comprehensive Security Audit & Evasion Integrity Report

**Date:** July 5, 2026  
**Auditor:** Team Antigravity (Multi-Agent Subsystem Audits)  
**Status:** Completed  
**Subsystems Audited:**
1. Protocol & Cryptography (`crates/protocol/src/`)
2. Transport, Rest & Networking (`crates/transport/src/`, `crates/rest/src/`)
3. Team Server & Credential Vault (`crates/server/src/`, `crates/store/src/`)
4. Implant Core, Memory & Allocation (`crates/implant-win/src/` core files)
5. Implant Evasion & Telemetry Blinding (`crates/implant-win/src/` evasion files)
6. Process Injection, Stack Spoofing & BOF Runner (`crates/implant-win/src/` injection/bof files)
7. Implant Post-Exploitation Capabilities (`crates/implant-win/src/` capabilities files)
8. Kernel-Tier Operator SDK (`crates/operator-kernelsdk/src/`)

---

## 1. Executive Summary

This report synthesizes the collective findings of a comprehensive code-level security audit performed across the entire **Nyx C2 Framework** repository. The framework was evaluated for:
* **Security Vulnerabilities & Logic Bugs** (memory corruption, access control bypasses, OOM vectors).
* **Cryptographic Integrity & Anti-Replay Faults** (key derivation flaws, timing side-channels, verification gaps).
* **Detection, Signature, & Attribution/Traceability Risks** (hardcoded indicators, spelling errors in OS namespace paths, anomalous telemetry patterns).
* **Stability & Kernel Crash (BSOD) Triggers** (non-canonical pointers, incorrect physical memory page-boundary reads, unaligned page walks).

The audit identified **multiple Critical- and High-severity vulnerabilities** that could lead to:
1. **Unauthenticated Admin Access (Server Fail-Open)**: Corrupted configuration files silently fail-open operator registrations.
2. **Implant Execution Crashes**: HookChain re-patching, CLR AMSI blinding, context switching, and Foliage sleep-masking execution paths contain bugs that result in access violations or general protection faults.
3. **Target System BSODs**: The Kernel SDK's virtual read adapter (`VaKernelRw::kread`) reads across non-contiguous physical page boundaries, risking immediate hardware/bus faults.
4. **Attribution & Detection Traps**: KnownDlls spelling errors make the unhooker fall back to suspicious disk reads, and dynamic offset resolution triggers over 11,000 IOCTL calls in seconds.

---

## 2. Master Vulnerability Matrix

| Finding ID | Severity | Component / Crate | Vulnerability Type | Description / Impact |
| :--- | :--- | :--- | :--- | :--- |
| **NYX-SRV-01** | **Critical** | `server/src/operators.rs` | Auth Fail-Open | Corrupted operator configuration files silently yield empty registries, causing the server to fall back to an open, unauthenticated admin mode. |
| **NYX-CORE-01** | **Critical** | `implant-win/src/sleep.rs` | Memory Mismatch | `ImageBaseAddress` PEB lookup reads the host EXE base instead of the implant DLL/shellcode, encrypting the host code and crashing the process. |
| **NYX-KERN-01** | **Critical** | `operator-kernelsdk/src/win/va_rw.rs` | Kernel Page Fault / BSOD | `VaKernelRw::kread` reads physical memory sequentially across 4KB virtual page boundaries without re-translating, triggering system-wide BSOD. |
| **NYX-EV-01** | **High** | `implant-win/src/unhook.rs` | Path Corruption / OPSEC | KnownDlls path array spells `\KnownDlls\ntdl` (missing 'l') and uses length 14, forcing a loud disk-read fallback of `ntdll.dll`. |
| **NYX-EV-02** | **High** | `implant-win/src/hookchain.rs` | Access Violation | Re-patching imports writes directly to `STUB_PAGE` after it has been locked to RX, causing an access violation crash. |
| **NYX-EV-03** | **High** | `implant-win/src/blind.rs` | Uninitialized Output | CLR `AmsiScanBuffer` byte-patch returns `S_OK` without writing to `AMSI_RESULT`, causing random blocks or crashes from stack garbage. |
| **NYX-CORE-02** | **High** | `implant-win/src/ntalloc.rs` | Concurrency / Race | Non-atomic slab property updates permit concurrent threads to allocate overlapping ranges, leading to heap corruption. |
| **NYX-CORE-03** | **High** | `implant-win/src/context.rs` | GPF / Crash | context restoration leaves segment registers (`SegCs`/`SegSs`) zeroed, leading to General Protection Fault crashes. |
| **NYX-INJ-01** | **High** | `implant-win/src/inject.rs` | Logic Bug / Crash | HWBP execution redirection triggers exceptions without target-process handler registration, crashing injected processes. |
| **NYX-INJ-02** | **High** | `implant-win/src/bof.rs` | Buffer Overflow | `BeaconGetSpawnTo` uses a static 28-byte buffer, causing global overflow in the `.data` section when loading arguments. |
| **NYX-CAP-01** | **High** | `implant-win/src/fs.rs` | Validation Bypass | Safety path checks can be bypassed using double slashes (`\\`) or relative dots (`.`), allowing extraction of locked registry hives. |
| **NYX-CAP-02** | **High** | `implant-win/src/pivot.rs` | SOCKS Routing / DOS | SOCKS BIND socket channel collisions overwrite active relays, causing Winsock send errors on listening sockets and tearing down tunnels. |
| **NYX-SRV-02** | **High** | `server/src/lib.rs` | Privilege Escalation | Control API endpoints fail to enforce role authorization checks, enabling read-only `Viewer` operators to task beacons or retrieve credentials. |
| **NYX-SRV-03** | **High** | `server/src/main.rs` | Denial of Service | Connection peeking and TLS handshakes lack timeouts, enabling socket exhaustion (Slowloris) attacks that block C2 access. |
| **NYX-TRN-01** | **High** | `transport/src/tls.rs` | Logical Defect / OPSEC | Grease detection bitmask is mathematically incorrect, misclassifying 240 non-GREASE ciphers and corrupting JA4 fingerprints. |
| **NYX-TRN-02** | **High** | `transport/src/tls.rs` | Server Fingerprinting | TLS record peeking truncates handshakes exceeding 16 KiB instead of rejecting, letting defenders actively fingerprint the server. |
| **NYX-KERN-02** | **High** | `operator-kernelsdk/src/netsec.rs` | Resource Leak | Handles used for EDR neutralization (WER coma/QoS throttle) go out of scope and leak, making telemetry disabling permanent. |
| **NYX-PRO-01** | **Medium** | `protocol/src/crypto.rs` | Memory Hygiene | Static secrets and temporary key byte arrays lack zeroization wrappers, leaving key segments readable in memory dumps. |
| **NYX-PRO-03** | **Medium** | `protocol/src/msg.rs` | Denial of Service | Lack of string length validation during message parsing allows OOM memory exhaustion via oversized payloads. |
| **NYX-CAP-03** | **Medium** | `implant-win/src/screenshot.rs` | Resource Leak | Process-wide interactive window station handle is closed immediately after assignment, causing GDI leakage or session crashes. |
| **NYX-CAP-04** | **Medium** | `implant-win/src/keylog.rs` | Logic Bug | CapsLock toggle state is polled via the LSB of `GetAsyncKeyState` instead of `GetKeyState`, leading to corrupted capitalization logging. |
| **NYX-SRV-04** | **Medium** | `server/src/audit.rs` | Hash Collision | Audit log chain records are hashed without delimiters or length prefixes, allowing integrity verification bypass via character shifting. |
| **NYX-SRV-05** | **Medium** | `server/src/lib.rs` | Side-Channel Timing | Constant-time token verification uses `.zip()` over asymmetric lengths, leaking the exact length of the secret authorization token. |

---

## 3. Subsystem Audit Details

### 3.1 Protocol & Cryptography (`crates/protocol/src/`)
* **Memory Hygiene (NYX-PRO-01)**: While `SessionKey` implements `ZeroizeOnDrop`, `StaticSecret` and stack allocations used during key generation (`ServerKeypair`/`ImplantKeypair`) are not cleared. Forensics tools extracting memory dumps can recover long-term server private keys.
* **Payload OOM Limits (NYX-PRO-03)**: `Reader::blob()` and `Reader::str()` deserialize strings up to 256 KiB with no logical check against message types. Massive SOCKS parameters or filenames can exhaust the implant's heap memory.
* **CSPRNG Registration (NYX-PRO-02)**: The atomic function pointer `CSPRNG_HOOK` lacks write-once checks. Multi-threaded setups could trigger race conditions or re-registrations directing control flow to unmapped memory.

### 3.2 Transport & Rest (`crates/transport/src/`, `crates/rest/src/`)
* **GREASE Detection (NYX-TRN-01)**: `is_grease` implements the mask `(v & 0x0f0f) == 0x0a0a`. This fails to verify that the high byte equals the low byte, corrupting calculated JA4 values.
* **JA4 Fingerprint Compliance**: The JA4 engine contains deviations (hexadecimal counts, missing capping at 99, and dashes instead of commas as separators), yielding signatures that do not match standard threat intelligence data. Additionally, GREASE extensions are not filtered before checking the first extension, causing prefix flapping.
* **TLS Truncation Fingerprint (NYX-TRN-02)**: ClientHello records larger than 16 KiB are truncated rather than rejected, leaving trailing data in the TCP buffer. When rustls reads the remaining bytes, it generates a protocol error, allowing defenders to identify the Nyx server by sending oversized handshakes.

### 3.3 Team Server & Store (`crates/server/src/`, `crates/store/src/`)
* **Fail-Open Config Parsing (NYX-SRV-01)**: `OperatorRegistry::load_or_bootstrap` wraps database parsing errors in `.unwrap_or_default()`. If `operators.json` is corrupted or empty, the registry loads as empty and defaults to an unauthenticated open admin mode.
* **Missing Role Enforcement (NYX-SRV-02)**: `Role::Viewer` is not enforced in API routing paths. Viewer accounts can task implants, retrieve plaintext passwords, or delete credentials.
* **Timing Attack on API Token (NYX-SRV-05)**: `constant_time_eq` evaluates comparisons using `a.iter().zip(b.iter())`. The iterator terminates early if lengths mismatch, leaking the authorization token length.

### 3.4 Implant Core & Sleep Mask (`crates/implant-win/src/`)
* **Image Base Retrieval (NYX-CORE-01)**: Foliage sleep-masking retrieves the image base address from the PEB. Since the PEB points to the host executable (e.g., `rundll32.exe`) rather than the loaded DLL, the sleep-mask attempts to encrypt the host code pages (crashing the process) and leaves the implant's code memory plaintext.
* **Foliage Thread Code Execution**: The sleep-mask helper thread executes its encryption routines from the `.text` section of the implant. When the helper thread begins encrypting the `.text` section, it immediately encrypts its own running code, triggering a CPU access violation.
* **Spoofed Context Segment Registers (NYX-CORE-03)**: Spoofed contexts passed to `NtContinue` zero out `SegCs` and `SegSs` registers. Restoring these zeroed registers triggers a General Protection Fault.

### 3.5 Implant Evasion (`crates/implant-win/src/`)
* **KnownDlls Path Corruption (NYX-EV-01)**: The Unicode path array is spelled `\KnownDlls\ntdl` (missing the second 'l') and configured with a length of 14 bytes. `NtOpenSection` returns `STATUS_OBJECT_NAME_NOT_FOUND`, forcing the implant to load `ntdll.dll` from disk, triggering EDR file-read alerts.
* **AMSI / CLR Blinding Stack Garbage (NYX-EV-03)**: Blinding patches `clr.dll!AmsiScanBuffer` to return `S_OK` (0) immediately. However, the `AMSI_RESULT` out-pointer is never written to. The CLR reads uninitialized stack garbage and intermittently blocks assembly execution based on random stack data.
* **HookChain Page Protection (NYX-EV-02)**: HookChain lockdowns stub allocations to RX. Subsequent re-patching cycles copy code into the locked page without transitioning the protection back to RWX/RW, causing access violations.

### 3.6 Implant Capabilities (`crates/implant-win/src/`)
* **Guardrail Validation Bypass (NYX-CAP-01)**: The allowed path check splits string segments by delimiters and verifies adjacent pairs for blocklisted files. Operators passing double backslashes (`\\`) or current directory markers (`.`) bypass the check, enabling extraction of locked hives.
* **SOCKS Pivoting Channel Collision (NYX-CAP-02)**: reverse-pivoting SOCKS5 BIND registers listening and accepted sockets under the same channel ID. `slot_of` queries always retrieve the passive listening socket first, sending data to it and causing Winsock send errors.
* **Window Station Resource Abuse (NYX-CAP-03)**: SYSTEM screenshots capture session GDI handles via `SetProcessWindowStation` and immediately call `CloseWindowStation`, invalidating session access.

### 3.7 Kernel SDK (`crates/operator-kernelsdk/src/`)
* **Out-of-Bounds Physical Page Reading (NYX-KERN-01)**: `VaKernelRw::kread` translates virtual addresses once and reads physical memory sequentially. If the virtual range crosses a 4KB boundary, it reads non-contiguous physical memory, leading to corrupted data or immediate system-wide BSOD.
* **Telemetry Coma Handle Leak (NYX-KERN-02)**: Throttling and dump-locking handles are kept in local scopes. Once the functions return, the handles are leaked, preventing operators from restoring EDR processes cleanly.
* **CreateFileW Failure Check Bug**: Verification queries check for handle validity using `.is_null()`. Since `CreateFileW` returns `INVALID_HANDLE_VALUE` (`-1`) on failure, errors pass undetected.

---

## 4. Remediation Action Plan

### 4.1 Server Hardening
1. **Enforce Fail-Closed Registry Loading**: Replace `.unwrap_or_default()` in `operators.rs` with error propagation (`?`) to prevent open admin fallback.
2. **Apply Role Validation**: Insert role checks on all write/read routes inside `lib.rs` to validate non-viewer operations.
3. **Normalize Token Comparison**: Hash inputs before evaluation in `constant_time_eq` to normalize comparison loops.
4. **Implement Handshake Timeouts**: Wrap TLS peeking and handshakes in `tokio::time::timeout` blocks.

### 4.2 Implant & Evasion Repair
1. **Correct KnownDlls Pathing**: Update the path structure in `unhook.rs` to spell `\KnownDlls\ntdll` with a length of 16.
2. **AMSI Patch Modification**: Update `BlindTarget::Clr` to use the `AMSI_PATCH` returning `0x80070057` (`E_INVALIDARG`), prompting the CLR to fail-open.
3. **HookChain Reprotection**: Add protection state transitions (RWX -> write -> RX) in `hookchain.rs` during re-patching cycles.
4. **Foliage Execution Offloading**: Move Foliage helper thread execution to dynamically allocated RX pages outside `.text`.
5. **Path Normalization**: Collapses redundant delimiters and resolve relative paths in `fs.rs` allowed check logic.

### 4.3 Kernel-Tier Stability
1. **Implement Page-Aware Reading**: Update `VaKernelRw::kread` to chunk reads by page boundaries and re-translate each virtual page.
2. **Close Neutralization Handles**: Implement drop-guards or return handles in `freeze_edr_coma` and `choke_edr_qos` to allow clean restoration.
3. **Correct CreateFileW Failure Check**: Verify handle output against `INVALID_HANDLE_VALUE` (`-1`).
