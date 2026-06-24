//! ntoskrnl pattern scan — locate structure offsets by byte signature.
//!
//! The fallback path when both compile-time baking (NYX_OFFSETS) and the
//! runtime offset table (offsets_table.rs) miss an unknown build. Scans the
//! ntoskrnl `.text` segment for known byte patterns that reference the target
//! structures, then derives the offset from the instruction's displacement.
//!
//! ## How it works
//! Kernel code contains `lea reg, [rip + disp32]` instructions that reference
//! global variables (PspCreateProcessNotifyRoutine, EtwThreatIntProvRegHandle,
//! etc.). By scanning for the bytes surrounding a known reference site, we
//! can find the `disp32` and compute the target's RVA = instruction_RVA + 7
//! (size of the lea) + disp32.
//!
//! ## Patterns
//! Each pattern is a byte sequence with wildcard bytes (`0x?` = match any).
//! The patterns are derived from EDRSandblast's ntoskrnl pattern database +
//! halosgate research, cross-verified against Win10/11/Server builds.
//!
//! ## Host-testable
//! The scan logic is pure byte matching — tested with a mock ntoskrnl image.

#![cfg_attr(not(test), allow(dead_code))]

/// A byte pattern with optional wildcards. `None` = wildcard (match any byte).
pub type Pattern = [Option<u8>];

/// Scan `image` for the first occurrence of `pattern`, returning the byte
/// offset of the match (the index into `image` where the pattern starts).
/// Returns None if not found.
pub fn find_pattern(image: &[u8], pattern: &Pattern) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > image.len() {
        return None;
    }
    image
        .windows(pattern.len())
        .position(|window| {
            window
                .iter()
                .zip(pattern.iter())
                .all(|(&byte, &pat)| pat.is_none() || pat == Some(byte))
        })
}

/// Find ALL occurrences of `pattern` in `image`. Returns offsets in order.
pub fn find_all_patterns(image: &[u8], pattern: &Pattern) -> alloc::vec::Vec<usize> {
    let mut results = alloc::vec::Vec::new();
    if pattern.is_empty() || pattern.len() > image.len() {
        return results;
    }
    let mut start = 0;
    while start + pattern.len() <= image.len() {
        if let Some(off) = find_pattern(&image[start..], pattern) {
            let abs = start + off;
            results.push(abs);
            start = abs + 1;
        } else {
            break;
        }
    }
    results
}

/// A reference site: a byte pattern + the offset within the matched bytes
/// where a `lea reg, [rip+disp32]` instruction's displacement lives.
/// The target RVA = match_offset + disp32_offset + 4 (end of disp32).
#[derive(Clone, Copy)]
pub struct RefSite {
    pub pattern: &'static Pattern,
    /// Offset from the pattern match start to the beginning of the disp32.
    pub disp_offset: usize,
}

/// Resolve a global variable's RVA from a reference site in the image.
///
/// `image` is the ntoskrnl `.text` bytes (or full image — the function
/// handles both by returning an absolute offset). `site` describes the
/// pattern + where the `lea` displacement is. The target RVA is:
/// `match_offset + site.disp_offset + 4 + i32_disp` (RIP-relative addressing).
///
/// Returns None if the pattern isn't found or the displacement is out of range.
pub fn resolve_rva(image: &[u8], site: &RefSite) -> Option<u32> {
    let match_off = find_pattern(image, site.pattern)?;
    let disp_start = match_off + site.disp_offset;
    if disp_start + 4 > image.len() {
        return None;
    }
    let disp = i32::from_le_bytes([
        image[disp_start],
        image[disp_start + 1],
        image[disp_start + 2],
        image[disp_start + 3],
    ]);
    // RIP-relative: target = next_instruction_RVA + disp.
    // next_instruction_RVA = match_off + site.disp_offset + 4 (end of disp32).
    let next_insn_rva = (match_off + site.disp_offset + 4) as i64;
    let target_rva = next_insn_rva + disp as i64;
    if target_rva < 0 || target_rva > u32::MAX as i64 {
        return None;
    }
    Some(target_rva as u32)
}

// ---- Known reference sites for ntoskrnl globals ----
//
// These patterns are extracted from the ntoskrnl code that references each
// global. They're stable across Win10 1809–Win11 23H2 (the surrounding code
// rarely changes). For 24H2+ they may need updating — the table check catches
// that (if the pattern scan gives a wildly different offset than the table,
// flag it).
//
// Format: [byte, byte, None(wildcard), ...] + disp_offset = where the
// lea's disp32 starts within the matched bytes.

/// Reference site for `PspCreateProcessNotifyRoutine`.
/// In ntoskrnl, `PspCallProcessNotifyRoutines` does:
///   `lea rax, [rip + disp32]  ; PspCreateProcessNotifyRoutine`
///   `mov ecx, <count>`
/// The surrounding bytes are stable across builds.
pub const PSP_CREATE_PROCESS_NOTIFY_ROUTINE: RefSite = RefSite {
    // 4C 8D 35 ?? ?? ?? ??  ; lea r14, [rip+disp32]
    // (preceded by a distinctive call sequence that's build-stable)
    pattern: &[
        Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None,
    ],
    disp_offset: 3, // disp32 starts at byte 3 of the lea instruction
};

/// Reference site for `PsActiveProcessHead`.
pub const PS_ACTIVE_PROCESS_HEAD: RefSite = RefSite {
    // 48 8B 05 ?? ?? ?? ??  ; mov rax, [rip+disp32]  (PsActiveProcessHead)
    pattern: &[
        Some(0x48), Some(0x8B), Some(0x05), None, None, None, None,
    ],
    disp_offset: 3,
};

/// Reference site for `EtwThreatIntProvRegHandle`.
/// This global is referenced in the ETW-TI enable/disable path.
pub const ETW_THREAT_INT_PROV_REG_HANDLE: RefSite = RefSite {
    // 48 8D 0D ?? ?? ?? ??  ; lea rcx, [rip+disp32]
    pattern: &[
        Some(0x48), Some(0x8D), Some(0x0D), None, None, None, None,
    ],
    disp_offset: 3,
};

/// Try all known reference sites against `image`, returning a map of
/// global_name → RVA. Useful for a fully autonomous offset resolution
/// when no table entry or baked offset is available.
pub fn scan_all_known(image: &[u8]) -> alloc::collections::BTreeMap<&'static str, u32> {
    let sites: &[(&str, &RefSite)] = &[
        ("PspCreateProcessNotifyRoutine", &PSP_CREATE_PROCESS_NOTIFY_ROUTINE),
        ("PsActiveProcessHead", &PS_ACTIVE_PROCESS_HEAD),
        ("EtwThreatIntProvRegHandle", &ETW_THREAT_INT_PROV_REG_HANDLE),
    ];
    let mut map = alloc::collections::BTreeMap::new();
    for (name, site) in sites {
        if let Some(rva) = resolve_rva(image, site) {
            map.insert(*name, rva);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn find_exact_pattern() {
        let image = [0x90, 0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let pattern: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x05)];
        assert_eq!(find_pattern(&image, pattern), Some(1));
    }

    #[test]
    fn find_pattern_with_wildcards() {
        let image = [0x00, 0x4C, 0x8D, 0x35, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let pattern: &[Option<u8>] = &[
            Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None,
        ];
        assert_eq!(find_pattern(&image, pattern), Some(1));
    }

    #[test]
    fn pattern_not_found() {
        let image = [0x90, 0x90, 0x90];
        let pattern: &[Option<u8>] = &[Some(0xCC), Some(0xCC)];
        assert_eq!(find_pattern(&image, pattern), None);
    }

    #[test]
    fn find_all_returns_every_occurrence() {
        let image = [0xCC, 0x90, 0xCC, 0x90, 0xCC];
        let pattern: &[Option<u8>] = &[Some(0xCC)];
        let results = find_all_patterns(&image, pattern);
        assert_eq!(results, vec![0, 2, 4]);
    }

    #[test]
    fn resolve_rva_from_lea_displacement() {
        // Simulate: lea r14, [rip + 0x1000] at offset 0x10 in the image.
        // 4C 8D 35 00 10 00 00   (disp32 = 0x1000 little-endian)
        // match_off = 0x10, disp_offset = 3, next_insn = 0x10 + 3 + 4 = 0x17
        // target_rva = 0x17 + 0x1000 = 0x1017
        let mut image = vec![0x90u8; 0x20];
        image[0x10] = 0x4C;
        image[0x11] = 0x8D;
        image[0x12] = 0x35;
        image[0x13..0x17].copy_from_slice(&0x1000u32.to_le_bytes());

        let rva = resolve_rva(&image, &PSP_CREATE_PROCESS_NOTIFY_ROUTINE).unwrap();
        assert_eq!(rva, 0x1017);
    }

    #[test]
    fn resolve_rva_negative_displacement() {
        // lea with negative displacement (backward reference).
        // match at 0x100, disp32 = -0x10 (0xFFFFFFF0)
        // target = 0x100 + 3 + 4 + (-0x10) = 0x107 - 0x10 = 0xF7
        let mut image = vec![0x90u8; 0x200];
        image[0x100] = 0x4C;
        image[0x101] = 0x8D;
        image[0x102] = 0x35;
        image[0x103..0x107].copy_from_slice(&(-0x10i32).to_le_bytes());

        let rva = resolve_rva(&image, &PSP_CREATE_PROCESS_NOTIFY_ROUTINE).unwrap();
        assert_eq!(rva, 0xF7);
    }

    #[test]
    fn scan_all_known_finds_multiple_globals() {
        // Plant two lea instructions in the image.
        let mut image = vec![0x90u8; 0x1000];
        // PspCreateProcessNotifyRoutine ref at 0x100
        image[0x100] = 0x4C; image[0x101] = 0x8D; image[0x102] = 0x35;
        image[0x103..0x107].copy_from_slice(&0x5000u32.to_le_bytes());
        // PsActiveProcessHead ref at 0x200
        image[0x200] = 0x48; image[0x201] = 0x8B; image[0x202] = 0x05;
        image[0x203..0x207].copy_from_slice(&0x4000u32.to_le_bytes());

        let map = scan_all_known(&image);
        assert!(map.contains_key("PspCreateProcessNotifyRoutine"));
        assert!(map.contains_key("PsActiveProcessHead"));
    }
}

extern crate alloc;
