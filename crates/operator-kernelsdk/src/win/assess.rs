//! Real T4-T5 kernel assessment over a live `KernelRw` (BYOVD / KslD / DMA).
//!
//! This is the operator-side replacement for the implant's user-mode T-REX
//! kernel stubs (deleted from `crates/implant-win/src/trex/mod.rs` in wI):
//! given a working kernel read/write primitive it
//!
//! 1. enumerates loaded kernel modules (`NtQuerySystemInformation` class 11)
//!    and counts drivers + EDR driver-name matches,
//! 2. reads the System Code Integrity options (class 103) for
//!    TESTSIGN / HVCI / VBS,
//! 3. counts the `PspCreateProcessNotifyRoutine` / `PspLoadImageNotifyRoutine`
//!    callback arrays via the SAME pattern-scan path `win::resolve_offsets`
//!    uses (verified RVA windows in `pattern_scan`), reading each 64-slot
//!    array through the `KernelRw` and decoding `EX_CALLBACK` entries,
//! 4. probes the ETW-TI provider enable state with the same pointer chase
//!    `EtwTiBlind` uses (handle → GUID entry → `ProviderEnableInfo.IsEnabled`).
//!
//! ## Honesty contract (mirrors the removed stubs' intent)
//! Every field is measured or left at its default — nothing is fabricated.
//! `status` is [`KernelAssessmentStatus::Assessed`] iff at least one of the
//! two user-mode NtQuery paths (module enumeration / code integrity) returned
//! real data; a completely failed assessment is `NotAssessed`, never a fake
//! 'clean'. A callback window that cannot be resolved counts 0 for that array
//! (honest per-array); the ETW-TI probe is `false` when the provider chain
//! cannot be walked (no registered provider / unknown build / read failure).

#![cfg(target_os = "windows")]

use crate::byovd;
use crate::etwti::EtwTiOffsets;
use crate::pattern_scan;
use crate::win::kernel_base;
use crate::{KernelAssessment, KernelAssessmentStatus, KernelRw};
use core::ffi::c_void;

/// `NtQuerySystemInformation` information classes used by the assessment.
/// (Module enumeration, class 11, is wrapped by `kernel_base::loaded_modules`.)
const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;

/// Bit positions in `SYSTEM_CODEINTEGRITY_INFORMATION.Options`
/// (T-REX spec: HVCI_KMCI_ENABLED bit9, VBS approx bit12, TESTSIGN bit1).
const CI_TESTSIGN_BIT: u32 = 1;
const CI_HVCI_KMCI_BIT: u32 = 9;
const CI_VBS_APPROX_BIT: u32 = 12;

/// `EX_CALLBACK` rundown-ref flags occupy the low 4 bits of each array slot;
/// the callback routine pointer is the slot with those cleared.
const EX_CALLBACK_LOW_MASK: u64 = 0xF;

/// Number of slots in each Ps*NotifyRoutine array (`PVOID[64]`).
const CALLBACK_ARRAY_SLOTS: u32 = 64;

/// `SYSTEM_CODEINTEGRITY_INFORMATION` (class 103 response).
#[repr(C)]
struct SystemCodeIntegrityInformation {
    options: u32,
    reserved: [u32; 2],
}

/// `KUSER_SHARED_DATA.KdDebuggerEnabled` — user-mode readable at the fixed
/// shared-page address on x64 (no `KernelRw` needed).
const KUSER_SHARED_DATA_KD_DEBUGGER_ENABLED: usize = 0x7FFE_0000 + 0x2D4;

/// Run the real kernel assessment. See the module docs for the honesty
/// contract (never fabricate; `Assessed` iff a real NtQuery path succeeded).
///
/// # Safety
/// Reads kernel memory via `krw` (callback arrays, ETW-TI provider chain) and
/// calls `NtQuerySystemInformation`. Single-threaded operator context.
pub unsafe fn assess_kernel_impl(krw: &dyn KernelRw) -> KernelAssessment {
    let mut out = KernelAssessment::default();
    let mut any_query_ok = false;

    // ---- T4: module enumeration (user-mode NtQuery path #1) ----
    match unsafe { kernel_base::loaded_modules() } {
        Ok(modules) => {
            any_query_ok = true;
            out.total_drivers = modules.len() as u32;
            out.edr_drivers = modules
                .iter()
                .filter(|m| is_edr_driver_name(&m.name))
                .count() as u32;
        }
        Err(_) => {
            // Not fatal — the code-integrity path may still succeed; the
            // status flip stays honest (only flipped when SOMETHING is real).
        }
    }

    // ---- T4: code integrity (user-mode NtQuery path #2) ----
    if let Some(options) = unsafe { query_code_integrity() } {
        any_query_ok = true;
        out.test_signing_enabled = options & (1 << CI_TESTSIGN_BIT) != 0;
        out.hvci_enabled = options & (1 << CI_HVCI_KMCI_BIT) != 0;
        out.vbs_enabled = options & (1 << CI_VBS_APPROX_BIT) != 0;
    }

    // ---- kernel debugger (user-mode KUSER_SHARED_DATA probe) ----
    out.kernel_debugger_present = kd_debugger_enabled();

    // ---- T5: callback arrays (same resolution path as `resolve_offsets`) ----
    if let Some((process_kva, image_kva)) = unsafe { resolve_notify_arrays(krw) } {
        // Honest per-array: a window that resolved to 0 counts 0 (never read
        // address 0 through the driver).
        if process_kva != 0 {
            out.process_callbacks = count_callbacks(krw, process_kva);
        }
        if image_kva != 0 {
            out.image_load_callbacks = count_callbacks(krw, image_kva);
        }
        // Registry callbacks (`CmpCallBackVector`): no verified pattern site
        // exists in `pattern_scan` yet, so the window cannot be resolved —
        // honest 0 (same rule as a resolved-to-0 window).
        out.registry_callbacks = 0;
    }

    // ---- T5: ETW-TI provider enable state (EtwTiBlind chase) ----
    out.etw_ti_active = unsafe { probe_etw_ti_active(krw) };

    out.status = if any_query_ok {
        KernelAssessmentStatus::Assessed
    } else {
        KernelAssessmentStatus::NotAssessed
    };
    out
}

/// Query `SYSTEM_CODEINTEGRITY_INFORMATION` (class 103). Returns the Options
/// DWORD, or `None` if the query fails (older builds / restricted callers).
unsafe fn query_code_integrity() -> Option<u32> {
    type NtQuerySystemInformationFn =
        unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    let nqsi: NtQuerySystemInformationFn = unsafe {
        crate::win::resolve::resolve_sym(b"ntdll.dll", b"NtQuerySystemInformation")
    }
    .ok()?;

    let mut info = SystemCodeIntegrityInformation {
        options: 0,
        reserved: [0; 2],
    };
    let mut ret_len: u32 = 0;
    let status = unsafe {
        nqsi(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut info as *mut _ as *mut c_void,
            core::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
            &mut ret_len,
        )
    };
    if status < 0 {
        return None;
    }
    Some(info.options)
}

/// Read `KUSER_SHARED_DATA.KdDebuggerEnabled` (x64 fixed shared page).
/// User-mode readable — no kernel primitive required.
fn kd_debugger_enabled() -> bool {
    // SAFETY: KUSER_SHARED_DATA is mapped read-only at a fixed address in
    // every user-mode process on x64 Windows; reading one byte never faults.
    unsafe { core::ptr::read_volatile(KUSER_SHARED_DATA_KD_DEBUGGER_ENABLED as *const u8) != 0 }
}

/// Resolve the `PspCreateProcessNotifyRoutine` / `PspLoadImageNotifyRoutine`
/// array KVAs via the SAME pattern-scan path `win::resolve_offsets` uses
/// (verified RVA windows in `pattern_scan`). Returns `(process, load_image)`;
/// an unresolved window is 0 (the caller counts 0 for that array — honest).
unsafe fn resolve_notify_arrays(krw: &dyn KernelRw) -> Option<(usize, usize)> {
    let (base, size) = unsafe { kernel_base::ntoskrnl_module_info() }.ok()?;
    const NTOSKRNL_SCAN_SIZE: usize = 2 * 1024 * 1024;
    let scan_len = size.min(NTOSKRNL_SCAN_SIZE);
    let mut image = alloc::vec![0u8; scan_len];
    krw.kread(base, &mut image).ok()?;

    let resolve = |site: &pattern_scan::RefSite, range: core::ops::Range<u32>| -> usize {
        pattern_scan::resolve_rva_in_range(&image, site, range)
            .map(|rva| base + rva as usize)
            .unwrap_or(0)
    };
    let process_kva = resolve(
        &pattern_scan::PSP_CREATE_PROCESS_NOTIFY_ROUTINE,
        pattern_scan::PROCESS_NOTIFY_ARRAY_RANGE,
    );
    let image_kva = resolve(
        &pattern_scan::PSP_LOAD_IMAGE_NOTIFY_ROUTINE,
        pattern_scan::LOAD_IMAGE_NOTIFY_ARRAY_RANGE,
    );
    Some((process_kva, image_kva))
}

/// Count non-zero `EX_CALLBACK` slots in a 64-slot notify array at `kva`.
/// Each slot is decoded by clearing the low 4 bits (`EX_RUNDOWN_REF` flags);
/// a slot that is zero after masking is not counted. A read failure stops the
/// walk — unknown slots are never invented.
fn count_callbacks(krw: &dyn KernelRw, kva: usize) -> u32 {
    let mut n = 0u32;
    for slot in 0..CALLBACK_ARRAY_SLOTS {
        match krw.kread_u64(kva + slot as usize * 8) {
            Ok(entry) if entry & !EX_CALLBACK_LOW_MASK != 0 => n += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    n
}

/// Probe whether the ETW-TI provider (`Microsoft-Windows-Threat-Intelligence`)
/// is currently ENABLED. Reuses the `EtwTiBlind` knowledge: resolve
/// `nt!EtwThreatIntProvRegHandle` (exported-symbol primary, pattern-scan
/// fallback), then chase handle → GUID entry → `ProviderEnableInfo.IsEnabled`.
/// `IsEnabled != 0` ⇒ an EDR is subscribed ⇒ active. Any failure (unresolved
/// handle, unknown build, NULL hop, read error) ⇒ honest `false`.
unsafe fn probe_etw_ti_active(krw: &dyn KernelRw) -> bool {
    // 1. Resolve the handle KVA.
    let (base, size) = match unsafe { kernel_base::ntoskrnl_module_info() } {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut full_image = alloc::vec![0u8; size.min(16 * 1024 * 1024)];
    if krw.kread(base, &mut full_image).is_err() {
        return false;
    }
    let handle_rva = byovd::resolve_kernel_symbol(&full_image, b"EtwThreatIntProvRegHandle")
        .or_else(|| {
            pattern_scan::scan_all_known(&full_image)
                .get("EtwThreatIntProvRegHandle")
                .copied()
        });
    let handle_kva = match handle_rva {
        Some(rva) if rva != 0 => base + rva as usize,
        _ => return false,
    };

    // 2. Build the chase offsets for this host's build (RtlGetVersion — no
    //    hardcoded build numbers). Unknown build → cannot chase safely.
    let offsets = match EtwTiOffsets::for_build(detect_build()) {
        Some(o) => o,
        None => return false,
    };

    // 3. Walk the same chain `EtwTiBlind::resolve_is_enabled_kva` uses.
    let guid_entry = match krw.kread_u64(handle_kva) {
        Ok(v) if v != 0 => v as usize,
        _ => return false,
    };
    let prov_block = match krw.kread_u64(guid_entry + offsets.guid_entry_to_provider_block) {
        Ok(v) if v != 0 => v as usize,
        _ => return false,
    };
    let is_enabled_kva =
        prov_block + offsets.provider_block_to_enable_info + offsets.is_enabled_within_enable_info;
    match krw.kread_u64(is_enabled_kva) {
        Ok(v) => v != 0, // enabled (non-zero) ⇒ ETW-TI active
        Err(_) => false,
    }
}

/// Detect the Windows build number via `RtlGetVersion` (mirrors the CLI's
/// `detect_build`). Returns 0 on failure — `EtwTiOffsets::for_build` then
/// returns `None` and the ETW-TI probe honestly reports `false`.
fn detect_build() -> u32 {
    #[repr(C)]
    struct RtlOsVersionInfoExW {
        os_version_info_size: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        platform_id: u32,
        sz_csd_version: [u16; 128],
        service_pack_major: u16,
        service_pack_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }
    type RtlGetVersionFn = unsafe extern "system" fn(*mut RtlOsVersionInfoExW) -> i32;
    let rtl_get_version: RtlGetVersionFn = match unsafe {
        crate::win::resolve::resolve_sym(b"ntdll.dll", b"RtlGetVersion")
    } {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut info = RtlOsVersionInfoExW {
        os_version_info_size: core::mem::size_of::<RtlOsVersionInfoExW>() as u32,
        major_version: 0,
        minor_version: 0,
        build_number: 0,
        platform_id: 0,
        sz_csd_version: [0; 128],
        service_pack_major: 0,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 0,
        reserved: 0,
    };
    // SAFETY: RtlGetVersion fills the struct; the size field is set correctly.
    let status = unsafe { rtl_get_version(&mut info) };
    if status == 0 {
        info.build_number
    } else {
        0
    }
}

/// Byte-level EDR kernel-driver name matcher — the module-enumeration twin of
/// the string-level WMI matcher (the implant's `match_driver_name`). Rules are
/// the 2026 EDR driver naming space (EDRSandblast / eSentire Surveyor lists):
/// vendor prefixes that never appear in the service-name space; the `.sys`
/// suffix is implicit (every kernel driver has it). `name` must be lowercased
/// ASCII (as produced by [`kernel_base::loaded_modules`]). Multi-token rules
/// are parenthesised so `&&` cannot silently bind tighter than the `||` chain.
fn is_edr_driver_name(name: &[u8]) -> bool {
    let n = core::str::from_utf8(name).unwrap_or("");
    (n.contains("csagent") || n.contains("csdevice")) // CrowdStrike
        || (n.contains("sentinel") && n.contains("monitor")) // SentinelOne
        || n.contains("cbfs")
        || n.contains("carbon") // Carbon Black
        || (n.contains("elastic") && n.contains("defend")) // Elastic
        || n.contains("cortex")
        || n.contains("traps") // Cortex XDR / Traps
        || (n.contains("sophos") && n.contains("driver")) // Sophos
        || n.contains("klif")
        || n.contains("klam") // Kaspersky
        || n.contains("mfe")
        || n.contains("mfenc") // McAfee
        || n.contains("symefa")
        || n.contains("symevnt") // Symantec
        || n.contains("eamonm")
        || n.contains("ehdrv") // ESET
        || n.contains("bdvedisk")
        || n.contains("trufos") // Bitdefender
        || n.contains("sysmon")
        || n.contains("procmon") // Sysinternals
        || n.contains("windefend")
        || n.contains("wdfilter") // Defender ATP
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrwError;
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    /// Mock `KernelRw` over a Mutex-protected sparse byte map (missing bytes
    /// read as 0 — `kread` never errors, so counting is over real values).
    /// Mirrors the mock in `etwti.rs`.
    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
    impl MockKrw {
        fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }
        fn set_u64(&self, addr: usize, val: u64) {
            let mut m = self.0.lock();
            for (i, b) in val.to_le_bytes().iter().enumerate() {
                m.insert(addr + i, *b);
            }
        }
    }
    impl KernelRw for MockKrw {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            let m = self.0.lock();
            for (i, b) in dst.iter_mut().enumerate() {
                *b = *m.get(&(kaddr + i)).unwrap_or(&0);
            }
            Ok(())
        }
        fn kwrite(&self, _kaddr: usize, _src: &[u8]) -> Result<(), KrwError> {
            Err(KrwError::Unavailable("read-only mock"))
        }
    }

    #[test]
    fn edr_matcher_hits_known_driver_names() {
        assert!(is_edr_driver_name(b"csagent.sys"));
        assert!(is_edr_driver_name(b"csdevice.sys"));
        assert!(is_edr_driver_name(b"windefend.sys"));
        assert!(is_edr_driver_name(b"wdfilter.sys"));
        assert!(is_edr_driver_name(b"klif.sys"));
        assert!(is_edr_driver_name(b"sentinelmonitor.sys"));
        assert!(is_edr_driver_name(b"sysmon.sys"));
    }

    #[test]
    fn edr_matcher_never_hits_generic_drivers() {
        assert!(!is_edr_driver_name(b"tcpip.sys"));
        assert!(!is_edr_driver_name(b"ntfs.sys"));
        assert!(!is_edr_driver_name(b"fltmgr.sys"));
        assert!(!is_edr_driver_name(b"ntoskrnl.exe"));
        assert!(!is_edr_driver_name(b""));
    }

    #[test]
    fn callback_count_decodes_ex_callback_low_bits() {
        // Slot 0: empty. Slots 1-2: set, incl. one with EX_RUNDOWN_REF flags in
        // the low 4 bits (still counted — the routine pointer is the masked
        // value). Remaining slots read as 0 → not counted.
        let krw = MockKrw::new();
        let kva = 0x1000usize;
        krw.set_u64(kva + 0 * 8, 0);
        krw.set_u64(kva + 1 * 8, 0xFFFF_F800_0000_0001); // low 4 bits set
        krw.set_u64(kva + 2 * 8, 0xFFFF_F800_0000_1234);
        assert_eq!(count_callbacks(&krw, kva), 2);
        // A slot whose masked value is zero (e.g. a raw rundown-ref counter
        // with no routine) must NOT be counted.
        krw.set_u64(kva + 3 * 8, 0x5); // masked → 0
        assert_eq!(count_callbacks(&krw, kva), 2);
    }

    #[test]
    fn callback_count_empty_array_is_zero() {
        let krw = MockKrw::new();
        assert_eq!(count_callbacks(&krw, 0x2000), 0);
    }

    #[test]
    fn code_integrity_bit_positions_match_spec() {
        // The T-REX spec bits: TESTSIGN=bit1, HVCI_KMCI=bit9, VBS≈bit12.
        let options = (1u32 << CI_TESTSIGN_BIT) | (1u32 << CI_HVCI_KMCI_BIT) | (1u32 << CI_VBS_APPROX_BIT);
        assert_ne!(options & (1 << 1), 0);
        assert_ne!(options & (1 << 9), 0);
        assert_ne!(options & (1 << 12), 0);
        // A clean host (only ENABLED set) has none of the three.
        assert_eq!(1u32 & (1 << CI_TESTSIGN_BIT), 0);
        assert_eq!(1u32 & (1 << CI_HVCI_KMCI_BIT), 0);
        assert_eq!(1u32 & (1 << CI_VBS_APPROX_BIT), 0);
    }
}
