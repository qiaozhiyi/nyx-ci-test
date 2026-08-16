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
//! Each pattern is a byte sequence with optional wildcard bytes (`0x?` = match any).
//! The patterns are derived from EDRSandblast's ntoskrnl pattern database +
//! halosgate research, cross-verified against Win10/11/Server builds.
//!
//! ## Host-testable
//! The scan logic is pure byte matching — tested with a mock ntoskrnl image.
//
// `pattern_scan` is consumed by `win::resolve_offsets` (the autonomous offset
// resolver) on the non-test build path. No blanket dead-code suppression.

/// A byte pattern with optional wildcards. `None` = wildcard (match any byte).
pub type Pattern = [Option<u8>];

/// Scan `image` for the first occurrence of `pattern`, returning the byte
/// offset of the match (the index into `image` where the pattern starts).
/// Returns None if not found.
pub fn find_pattern(image: &[u8], pattern: &Pattern) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > image.len() {
        return None;
    }
    image.windows(pattern.len()).position(|window| {
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

/// Resolve a global variable's RVA from a reference site, restricted to an
/// expected address range. Like [`resolve_rva`] but iterates ALL occurrences
/// of the pattern and returns the first match whose computed RVA falls within
/// `expected_range`.
///
/// This is critical when the same byte pattern (e.g., `lea r14, [rip+disp32]`)
/// appears in multiple functions — the range filter disambiguates them.
pub fn resolve_rva_in_range(
    image: &[u8],
    site: &RefSite,
    expected_range: core::ops::Range<u32>,
) -> Option<u32> {
    if site.pattern.is_empty() || site.pattern.len() > image.len() {
        return None;
    }
    let mut start = 0;
    while start + site.pattern.len() <= image.len() {
        if let Some(off) = find_pattern(&image[start..], site.pattern) {
            let abs = start + off;
            let disp_start = abs + site.disp_offset;
            if disp_start + 4 > image.len() {
                break;
            }
            let disp = i32::from_le_bytes([
                image[disp_start],
                image[disp_start + 1],
                image[disp_start + 2],
                image[disp_start + 3],
            ]);
            let next_insn_rva = (abs + site.disp_offset + 4) as i64;
            let target_rva = next_insn_rva + disp as i64;
            if target_rva >= 0 && target_rva <= u32::MAX as i64 {
                let rva = target_rva as u32;
                if expected_range.contains(&rva) {
                    return Some(rva);
                }
            }
            start = abs + 1;
        } else {
            break;
        }
    }
    None
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

/// Reference site for `PspCreateProcessNotifyRoutine` — scans the **Process**
/// notify-array target in the ntoskrnl image.
/// In ntoskrnl, `PspCallProcessNotifyRoutines` does:
///   `lea r14, [rip + disp32]  ; PspCreateProcessNotifyRoutine`
///   `mov ecx, <count>`
/// The surrounding bytes are stable across builds.
///
/// ⚠ This byte encoding is currently IDENTICAL to
/// [`PSP_CREATE_THREAD_NOTIFY_ROUTINE`], but the two reference DIFFERENT
/// globals and are disambiguated by their verified RVA windows
/// ([`PROCESS_NOTIFY_ARRAY_RANGE`] / [`THREAD_NOTIFY_ARRAY_RANGE`]) at the
/// call site. Keep them as separate named constants — do NOT merge them — so
/// a future build where one reference changes encoding only affects that
/// target's constant.
pub const PSP_CREATE_PROCESS_NOTIFY_ROUTINE: RefSite = RefSite {
    // 4C 8D 35 ?? ?? ?? ??  ; lea r14, [rip+disp32]
    pattern: &[Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None],
    disp_offset: 3, // disp32 starts at byte 3 of the lea instruction
};

/// Reference site for `PspCreateThreadNotifyRoutine` — scans the **Thread**
/// notify-array target in the ntoskrnl image.
/// In ntoskrnl, `PspCallThreadNotifyRoutines` references this array.
///
/// **Disambiguation required:** this uses the same `lea r14, [rip+disp32]`
/// (4C 8D 35) encoding as [`PSP_CREATE_PROCESS_NOTIFY_ROUTINE`] but targets a
/// DIFFERENT global. Use [`resolve_rva_in_range`] with the verified window
/// [`THREAD_NOTIFY_ARRAY_RANGE`] to distinguish them (verified 17763.1339 PDB:
/// Thread sits 0x200 BELOW Process — `0x4D9970` vs `0x4D9D70`). Keep this
/// constant separate from the Process one — a build where the Thread reference
/// changes encoding must only touch this constant.
pub const PSP_CREATE_THREAD_NOTIFY_ROUTINE: RefSite = RefSite {
    // 4C 8D 35 ?? ?? ?? ??  ; lea r14, [rip+disp32]  (same encoding as process, DIFFERENT target)
    pattern: &[Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None],
    disp_offset: 3,
};

/// Reference site for `PspLoadImageNotifyRoutine`.
/// In ntoskrnl, `PspCallLoadImageNotifyRoutines` references this array.
/// Uses `lea rbx, [rip+disp32]` — **distinct** encoding from process/thread.
pub const PSP_LOAD_IMAGE_NOTIFY_ROUTINE: RefSite = RefSite {
    // 48 8D 1D ?? ?? ?? ??  ; lea rbx, [rip+disp32]
    pattern: &[Some(0x48), Some(0x8D), Some(0x1D), None, None, None, None],
    disp_offset: 3,
};

/// Reference site for `PsActiveProcessHead`.
pub const PS_ACTIVE_PROCESS_HEAD: RefSite = RefSite {
    // 48 8B 05 ?? ?? ?? ??  ; mov rax, [rip+disp32]  (PsActiveProcessHead)
    pattern: &[Some(0x48), Some(0x8B), Some(0x05), None, None, None, None],
    disp_offset: 3,
};

/// Reference site for `EtwThreatIntProvRegHandle`.
/// This global is referenced in the ETW-TI enable/disable path.
pub const ETW_THREAT_INT_PROV_REG_HANDLE: RefSite = RefSite {
    // 48 8D 0D ?? ?? ?? ??  ; lea rcx, [rip+disp32]
    pattern: &[Some(0x48), Some(0x8D), Some(0x0D), None, None, None, None],
    disp_offset: 3,
};

// ---- Verified RVA windows for the Ps*NotifyRoutine arrays ----
//
// The Process and Thread reference sites are byte-IDENTICAL (`4C 8D 35`), so
// a naive first-match scan aliases them (both keys get the same RVA). The
// arrays are disambiguated by RVA window. The windows below are verified
// against the 17763.1339 PDB (dbghelp SymFromName — see
// `examples/bootstrap_test.rs` + `docs/testing/kernel-test-results.md`):
//
// ```text
//   PspCreateThreadNotifyRoutine    RVA 0x4D9970   (64 × PVOID array)
//   PspLoadImageNotifyRoutine       RVA 0x4D9B70   (+0x200)
//   PspCreateProcessNotifyRoutine   RVA 0x4D9D70   (+0x400)
// ```
//
// The three arrays are CONTIGUOUS in ntoskrnl `.data`, each 0x200 bytes, in
// the fixed relative order Thread < LoadImage < Process (NOTE: Process is at
// a HIGHER RVA than Thread on the verified build — the earlier doc claim was
// wrong). The absolute positions drift across UBRs (~0x7D000 between 17763.1
// and 17763.1339), but the relative order + 0x200 spacing is stable, so the
// three windows below are DISJOINT: any candidate RVA computed by a reference
// site falls into at most one window. Each window is deliberately wider than
// the 0x200 array spacing (to tolerate partial drift) yet never overlaps its
// neighbour's window.
//
// [`crate::win::resolve_offsets`] additionally asserts the three resolved
// KVAs are pairwise distinct at resolve time — the final safety net if a
// build's layout ever violates the verified order.

/// Verified RVA window of `PspCreateProcessNotifyRoutine` (17763.1339 PDB).
pub const PROCESS_NOTIFY_ARRAY_RANGE: core::ops::Range<u32> = 0x4D_9C00..0x4D_A000;
/// Verified RVA window of `PspCreateThreadNotifyRoutine` (17763.1339 PDB).
/// Disjoint from [`PROCESS_NOTIFY_ARRAY_RANGE`] — Thread sits 0x200 BELOW
/// Process on the verified build.
pub const THREAD_NOTIFY_ARRAY_RANGE: core::ops::Range<u32> = 0x4D_8000..0x4D_9A00;
/// Verified RVA window of `PspLoadImageNotifyRoutine` (17763.1339 PDB).
pub const LOAD_IMAGE_NOTIFY_ARRAY_RANGE: core::ops::Range<u32> = 0x4D_9A00..0x4D_9C00;

/// Try all known reference sites against `image`, returning a map of
/// global_name → RVA. Useful for a fully autonomous offset resolution
/// when no table entry or baked offset is available.
///
/// The three Ps*NotifyRoutine arrays (which share reference encodings with
/// MANY other ntoskrnl sites — `4C 8D 35`/`48 8D 1D` appear all over `.text`)
/// resolve via [`resolve_rva_in_range`] against their own verified RVA window
/// ([`PROCESS_NOTIFY_ARRAY_RANGE`] etc.). A target whose computed RVA falls
/// outside its window (e.g. a drifted UBR position, or a non-array site that
/// merely shares the encoding) is OMITTED rather than misreported — in
/// particular the byte-identical Process/Thread pair can no longer alias to
/// the same RVA. `PsActiveProcessHead` / `EtwThreatIntProvRegHandle` keep the
/// unfiltered first-match (unique-enough encodings; out of this module's
/// anti-alias scope).
pub fn scan_all_known(image: &[u8]) -> alloc::collections::BTreeMap<&'static str, u32> {
    let sites: &[(&str, &RefSite, core::ops::Range<u32>)] = &[
        (
            "PspCreateProcessNotifyRoutine",
            &PSP_CREATE_PROCESS_NOTIFY_ROUTINE,
            PROCESS_NOTIFY_ARRAY_RANGE,
        ),
        (
            "PspCreateThreadNotifyRoutine",
            &PSP_CREATE_THREAD_NOTIFY_ROUTINE,
            THREAD_NOTIFY_ARRAY_RANGE,
        ),
        (
            "PspLoadImageNotifyRoutine",
            &PSP_LOAD_IMAGE_NOTIFY_ROUTINE,
            LOAD_IMAGE_NOTIFY_ARRAY_RANGE,
        ),
        ("PsActiveProcessHead", &PS_ACTIVE_PROCESS_HEAD, 0..0),
        (
            "EtwThreatIntProvRegHandle",
            &ETW_THREAT_INT_PROV_REG_HANDLE,
            0..0,
        ),
    ];
    let mut map = alloc::collections::BTreeMap::new();
    for (name, site, range) in sites {
        // Notify-array targets: range-filtered (verified window). The other
        // two globals use the unfiltered first match (range 0..0 sentinel).
        if !range.is_empty() {
            if let Some(rva) = resolve_rva_in_range(image, site, range.clone()) {
                map.insert(*name, rva);
            }
        } else if let Some(rva) = resolve_rva(image, site) {
            map.insert(*name, rva);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_exact_pattern() {
        let image = [0x90, 0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let pattern: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x05)];
        assert_eq!(find_pattern(&image, pattern), Some(1));
    }

    #[test]
    fn find_pattern_with_wildcards() {
        let image = [0x00, 0x4C, 0x8D, 0x35, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let pattern: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None];
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
    fn resolve_rva_in_range_disambiguates_same_pattern() {
        // Two identical `lea r14, [rip+disp32]` instructions at different offsets.
        // One references RVA 0x100, the other 0x500.
        let mut image = vec![0x90u8; 0x1000];
        // First: at 0x100 → RVA 0x107 + 0xF9 = 0x100 (disp32 = -7, i.e. 0xFFFFFFF9)
        image[0x100] = 0x4C;
        image[0x101] = 0x8D;
        image[0x102] = 0x35;
        image[0x103..0x107].copy_from_slice(&(-7i32).to_le_bytes());
        // Second: at 0x200 → RVA 0x207 + 0x2F9 = 0x500 (disp32 = 0x2F9)
        image[0x200] = 0x4C;
        image[0x201] = 0x8D;
        image[0x202] = 0x35;
        image[0x203..0x207].copy_from_slice(&0x2F9i32.to_le_bytes());

        // resolve_rva returns the first match (0x100)
        let first = resolve_rva(&image, &PSP_CREATE_PROCESS_NOTIFY_ROUTINE).unwrap();
        assert_eq!(first, 0x100);

        // resolve_rva_in_range can pick the second one
        let in_range =
            resolve_rva_in_range(&image, &PSP_CREATE_THREAD_NOTIFY_ROUTINE, 0x400..0x600);
        assert_eq!(in_range, Some(0x500));

        // And still find the first with the right range
        let in_range =
            resolve_rva_in_range(&image, &PSP_CREATE_PROCESS_NOTIFY_ROUTINE, 0x000..0x200);
        assert_eq!(in_range, Some(0x100));
    }

    #[test]
    fn resolve_rva_in_range_no_match_outside() {
        let mut image = vec![0x90u8; 0x20];
        image[0x10] = 0x4C;
        image[0x11] = 0x8D;
        image[0x12] = 0x35;
        image[0x13..0x17].copy_from_slice(&0x1000u32.to_le_bytes());

        // RVA is 0x1017 — not in this range
        let result =
            resolve_rva_in_range(&image, &PSP_CREATE_PROCESS_NOTIFY_ROUTINE, 0x5000..0x6000);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_rva_in_range_load_image_unique_pattern() {
        // PspLoadImageNotifyRoutine uses `lea rbx, [rip+disp32]` (48 8D 1D),
        // which is unique — no disambiguation needed.
        let mut image = vec![0x90u8; 0x20];
        image[0x08] = 0x48;
        image[0x09] = 0x8D;
        image[0x0A] = 0x1D;
        image[0x0B..0x0F].copy_from_slice(&0x200u32.to_le_bytes());

        let rva = resolve_rva_in_range(&image, &PSP_LOAD_IMAGE_NOTIFY_ROUTINE, 0x100..0x400);
        assert_eq!(rva, Some(0x20F)); // next_insn = 0x0F, + 0x200 = 0x20F
    }

    #[test]
    fn scan_all_known_finds_multiple_globals() {
        // Plant the three notify-array refs at their VERIFIED 17763.1339 PDB
        // positions (Thread 0x4D9970 < LoadImage 0x4D9B70 < Process 0x4D9D70,
        // 0x200 apart) plus a PsActiveProcessHead ref.
        let mut image = vec![0x90u8; 0x1000];
        // PspCreateThreadNotifyRoutine ref at 0x100 (lea r14, [rip+disp32])
        image[0x100] = 0x4C;
        image[0x101] = 0x8D;
        image[0x102] = 0x35;
        // next_insn = 0x107; disp = 0x4D9970 - 0x107 = 0x4D9869
        image[0x103..0x107].copy_from_slice(&0x4D9869i32.to_le_bytes());
        // PspLoadImageNotifyRoutine ref at 0x200 (lea rbx, [rip+disp32])
        image[0x200] = 0x48;
        image[0x201] = 0x8D;
        image[0x202] = 0x1D;
        // next_insn = 0x207; disp = 0x4D9B70 - 0x207 = 0x4D9969
        image[0x203..0x207].copy_from_slice(&0x4D9969i32.to_le_bytes());
        // PspCreateProcessNotifyRoutine ref at 0x300 (lea r14, [rip+disp32])
        image[0x300] = 0x4C;
        image[0x301] = 0x8D;
        image[0x302] = 0x35;
        // next_insn = 0x307; disp = 0x4D9D70 - 0x307 = 0x4D9A69
        image[0x303..0x307].copy_from_slice(&0x4D9A69i32.to_le_bytes());
        // PsActiveProcessHead ref at 0x400 (mov rax, [rip+disp32])
        image[0x400] = 0x48;
        image[0x401] = 0x8B;
        image[0x402] = 0x05;
        // next_insn = 0x407; disp = 0x40E5C0 - 0x407 = 0x40E1B9
        image[0x403..0x407].copy_from_slice(&0x40E1B9i32.to_le_bytes());

        let map = scan_all_known(&image);
        assert_eq!(map.get("PspCreateProcessNotifyRoutine"), Some(&0x4D9D70));
        assert_eq!(map.get("PspCreateThreadNotifyRoutine"), Some(&0x4D9970));
        assert_eq!(map.get("PspLoadImageNotifyRoutine"), Some(&0x4D9B70));
        assert_eq!(map.get("PsActiveProcessHead"), Some(&0x40E5C0));
    }

    #[test]
    fn scan_all_known_disambiguates_shared_encoding_no_alias() {
        // The historical aliasing failure: a `4C 8D 35` ref targeting the
        // PROCESS array appears FIRST in the image. The naive first-match scan
        // used to report that SAME RVA for BOTH Process and Thread keys. With
        // the verified per-target windows the Process-targeting ref must only
        // land in the Process key, and the Thread key must pick the Thread ref.
        let mut image = vec![0x90u8; 0x1000];
        // Decoy at 0x000 → RVA 0x4D9D70 (Process range) — appears FIRST.
        image[0x000] = 0x4C;
        image[0x001] = 0x8D;
        image[0x002] = 0x35;
        // next_insn = 0x007; disp = 0x4D9D70 - 0x7 = 0x4D9D69
        image[0x003..0x007].copy_from_slice(&0x4D9D69i32.to_le_bytes());
        // Real Thread ref at 0x100 → RVA 0x4D9970 (Thread range).
        image[0x100] = 0x4C;
        image[0x101] = 0x8D;
        image[0x102] = 0x35;
        image[0x103..0x107].copy_from_slice(&0x4D9869i32.to_le_bytes());

        let map = scan_all_known(&image);
        // The decoy's RVA (0x4D9D70) is in the PROCESS window, so it lands in
        // the Process key; the Thread key gets the REAL Thread ref — no alias.
        assert_eq!(map.get("PspCreateProcessNotifyRoutine"), Some(&0x4D9D70));
        assert_eq!(map.get("PspCreateThreadNotifyRoutine"), Some(&0x4D9970));
        assert_ne!(
            map.get("PspCreateProcessNotifyRoutine"),
            map.get("PspCreateThreadNotifyRoutine"),
            "Process/Thread must never alias to the same RVA"
        );
    }

    #[test]
    fn scan_all_known_omits_shared_encoding_outside_verified_windows() {
        // A `4C 8D 35` ref whose RVA falls outside every verified window (a
        // drifted UBR position, or a non-array site sharing the encoding) must
        // be OMITTED from both keys — never reported as a wrong target.
        let mut image = vec![0x90u8; 0x1000];
        image[0x100] = 0x4C;
        image[0x101] = 0x8D;
        image[0x102] = 0x35;
        // next_insn = 0x107; disp = 0x12345678 - 0x107 = 0x12345571
        image[0x103..0x107].copy_from_slice(&0x12345571i32.to_le_bytes());

        let map = scan_all_known(&image);
        assert!(!map.contains_key("PspCreateProcessNotifyRoutine"));
        assert!(!map.contains_key("PspCreateThreadNotifyRoutine"));
        assert!(!map.contains_key("PspLoadImageNotifyRoutine"));
    }
}

extern crate alloc;
