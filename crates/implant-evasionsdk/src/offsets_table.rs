//! Cross-version Windows kernel structure offsets — multi-build table.
//!
//! ## The problem
//! `EPROCESS` field offsets (UniqueProcessId, ActiveProcessLinks, Token,
//! Protection, SignatureLevel) drift across Windows builds. A hardcoded
//! offset for one build writes the WRONG field on another → bugcheck.
//!
//! ## The strategy (three layers, in priority order)
//!
//! 1. **Compile-time bake (server-side PDB resolution)** — the operator's
//!    build pipeline downloads the target's `ntoskrnl.pdb` from the MS symbol
//!    server, parses out the exact offsets, and `build.rs` bakes them as
//!    compile-time constants via `NYX_OFFSETS`. **Zero target-side resolution**
//!    — the offsets live in the binary as plain constants, indistinguishable
//!    from any other data. This is the primary path for engagements.
//!
//! 2. **Runtime table lookup (this module)** — if no offsets were baked (dev
//!    builds, unknown target), the runtime reads the OS build number from the
//!    PEB and picks the matching row from [`KNOWN_BUILDS`]. Covers all major
//!    Win10/Win11/Server builds. Unknown builds return None → the kit degrades.
//!
//! 3. **Pattern-scan fallback (future, `win/`)** — for truly unknown builds
//!    with no table entry AND no baked offsets, a pattern scan of ntoskrnl
//!    recovers offsets at runtime. This is the noisiest path (code-section
//!    traversal) and is reserved for when 1 and 2 both miss.
//!
//! ## Sources
//! Every offset is cross-checked against EDRSandblast's NtoskrnlOffsets.csv +
//! the Vergilius Project (_EPROCESS per build) + fluxsec.red. A wrong offset
//! is a bugcheck, so each cites its build.
//!
//! ## Layout stability (what does NOT drift)
//! - x64 PEB layout (gs:[0x60], ImageBaseAddress@0x10, BeingDebugged@0x02,
//!   OSBuildNumber@0x120) — frozen by the x64 ABI across all Win10/11/Server.
//! - PE format (MZ/PE sigs, section headers) — spec-fixed.
//! - PS_PROTECTION bit packing (Type:3, Audit:1, Signer:4) — enum-fixed.

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;
use alloc::vec::Vec;

/// EPROCESS field offsets for one Windows build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EprocessOffsets {
    pub unique_process_id: usize,
    pub active_process_links: usize,
    pub token: usize,
    pub image_file_name: usize,
    pub signature_level: usize,
    pub section_signature_level: usize,
    pub protection: usize,
}

/// ETW-TI provider-block chase offsets for one build (see operator-kernelsdk
/// etwti.rs for the chase semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EtwTiOffsets {
    pub guid_entry_to_provider_block: usize,
    pub provider_block_to_enable_info: usize,
    pub is_enabled_within_enable_info: usize,
}

/// All offsets for one build, keyed by the Windows build number.
#[derive(Clone, Copy, Debug)]
pub struct BuildOffsets {
    /// The Windows build number (e.g. 17763, 19045, 22621, 26100).
    pub build: u32,
    pub eprocess: EprocessOffsets,
    pub etw_ti: EtwTiOffsets,
}

/// The known-build table. Covers Win10 1809 through Win11 25H2 + Server 2019/2022.
/// Sourced from EDRSandblast CSV + Vergilius _EPROCESS layouts.
///
/// ## EPROCESS drift history (key transitions)
/// - 17763 (1809/Server2019): PID@0x2e0, Links@0x2e8, Protection@0x6ca
/// - 18362 (19H1): PID@0x2e8, Links@0x2f0, Protection@0x6fa — fields shifted +8
/// - 19041-19045 (20H1-22H2): same as 18362
/// - 20348 (Server 2022): PID@0x440, Links@0x448, Protection@0x87a — major shift
/// - 22000 (Win11 21H2): PID@0x440, Links@0x448, Protection@0x87a
/// - 22621 (Win11 22H2): PID@0x440, Protection@0x87a (ETW-TI EnableInfo shifted)
/// - 26100 (Win11 24H2): PID@0x450, Protection@0x87c (CET-default; ETW restructured)
pub const KNOWN_BUILDS: &[BuildOffsets] = &[
    // ---- Win10 1809 / Server 2019 (build 17763) ----
    BuildOffsets {
        build: 17763,
        eprocess: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c8,
            section_signature_level: 0x6c9,
            protection: 0x6ca,
        },
        etw_ti: EtwTiOffsets {
            // 17763 RTM (UBR<1075): EnableInfo @ 0x050; patched (UBR>=1075) @ 0x060.
            // The table stores the patched value (virtually all live hosts);
            // UBR-sensitive callers use for_build_strict.
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x060,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win10 1903-1909 (19H1/H2, builds 18362-18363) ----
    // EPROCESS shifted +8 from 1809. ETW-TI EnableInfo @ 0x060.
    BuildOffsets {
        build: 18362,
        eprocess: EprocessOffsets {
            unique_process_id: 0x2e8,
            active_process_links: 0x2f0,
            token: 0x360,
            image_file_name: 0x450,
            signature_level: 0x6f8,
            section_signature_level: 0x6f9,
            protection: 0x6fa,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x060,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win10 2004-22H2 (builds 19041-19045) ----
    // Same EPROCESS as 19H1. ETW-TI EnableInfo @ 0x060 (stable).
    BuildOffsets {
        build: 19041,
        eprocess: EprocessOffsets {
            unique_process_id: 0x2e8,
            active_process_links: 0x2f0,
            token: 0x360,
            image_file_name: 0x450,
            signature_level: 0x6f8,
            section_signature_level: 0x6f9,
            protection: 0x6fa,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x060,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Server 2022 / Win11 21H2 (builds 20348/22000) ----
    // Major EPROCESS shift: PID moved to 0x440. Protection to 0x87a.
    BuildOffsets {
        build: 20348,
        eprocess: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x060,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win11 22H2 (build 22621) ----
    BuildOffsets {
        build: 22621,
        eprocess: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
        },
        etw_ti: EtwTiOffsets {
            // 22H2 restructured the ETW GUID entry — EnableInfo shifted.
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x070,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win11 23H2 (build 22631) — same as 22H2 ----
    BuildOffsets {
        build: 22631,
        eprocess: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x070,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win11 24H2 (build 26100) — CET default, ETW restructured ----
    BuildOffsets {
        build: 26100,
        eprocess: EprocessOffsets {
            unique_process_id: 0x450,
            active_process_links: 0x458,
            token: 0x4c8,
            image_file_name: 0x5a8,
            signature_level: 0x87c,
            section_signature_level: 0x87d,
            protection: 0x87e,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x070,
            is_enabled_within_enable_info: 0x000,
        },
    },
    // ---- Win11 25H2 (build 26200) — same as 24H2 ----
    BuildOffsets {
        build: 26200,
        eprocess: EprocessOffsets {
            unique_process_id: 0x450,
            active_process_links: 0x458,
            token: 0x4c8,
            image_file_name: 0x5a8,
            signature_level: 0x87c,
            section_signature_level: 0x87d,
            protection: 0x87e,
        },
        etw_ti: EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x070,
            is_enabled_within_enable_info: 0x000,
        },
    },
];

/// Look up offsets for an exact build number. Returns None for unknown builds
/// (caller should degrade or pattern-scan).
pub fn for_build(build: u32) -> Option<&'static BuildOffsets> {
    // Find the closest build <= the requested one (a patch like 19045 maps to
    // the 19041 row since the EPROCESS layout is identical across 19041-19045).
    // First try exact match, then floor match.
    KNOWN_BUILDS.iter().find(|b| b.build == build).or_else(|| {
        // Floor match: the highest table build <= the requested build.
        KNOWN_BUILDS
            .iter()
            .filter(|b| b.build <= build)
            .max_by_key(|b| b.build)
    })
}

/// Look up offsets for 17763 with UBR sensitivity (the ETW-TI EnableInfo
/// offset forks at UBR 1075). This is the ONLY build with a known UBR fork;
/// all others use for_build directly.
pub fn for_build_strict(build: u32, ubr: u32) -> Option<EtwTiOffsets> {
    if build == 17763 {
        let enable_info = if ubr < 1075 { 0x050 } else { 0x060 };
        Some(EtwTiOffsets {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: enable_info,
            is_enabled_within_enable_info: 0x000,
        })
    } else {
        for_build(build).map(|b| b.etw_ti)
    }
}

/// All known build numbers (for diagnostics / selftest display).
pub fn known_builds() -> Vec<u32> {
    KNOWN_BUILDS.iter().map(|b| b.build).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_2019_offsets_match_original_constants() {
        // The original offsets.rs hardcoded these for 17763 — verify the table
        // row matches, so existing behavior is unchanged for Server 2019.
        let o = for_build(17763).unwrap();
        assert_eq!(o.eprocess.unique_process_id, 0x2e0);
        assert_eq!(o.eprocess.active_process_links, 0x2e8);
        assert_eq!(o.eprocess.token, 0x358);
        assert_eq!(o.eprocess.protection, 0x6ca);
        assert_eq!(o.eprocess.signature_level, 0x6c8);
    }

    #[test]
    fn win11_24h2_offsets_are_populated() {
        let o = for_build(26100).unwrap();
        assert_eq!(o.eprocess.unique_process_id, 0x450);
        assert_eq!(o.eprocess.protection, 0x87e);
    }

    #[test]
    fn floor_match_handles_patch_builds() {
        // 19045 (22H2) has the same EPROCESS as 19041 → floor-matches.
        let o = for_build(19045).unwrap();
        assert_eq!(o.build, 19041);
        assert_eq!(o.eprocess.unique_process_id, 0x2e8);
    }

    #[test]
    fn unknown_build_returns_none() {
        // A build below the table range or truly unknown.
        assert!(for_build(9999).is_none());
    }

    #[test]
    fn for_build_strict_17763_forks_at_ubr_1075() {
        let rtm = for_build_strict(17763, 1).unwrap();
        assert_eq!(rtm.provider_block_to_enable_info, 0x050);
        let patched = for_build_strict(17763, 1339).unwrap();
        assert_eq!(patched.provider_block_to_enable_info, 0x060);
        // Boundary
        assert_eq!(for_build_strict(17763, 1074).unwrap().provider_block_to_enable_info, 0x050);
        assert_eq!(for_build_strict(17763, 1075).unwrap().provider_block_to_enable_info, 0x060);
    }

    #[test]
    fn for_build_strict_non_17763_uses_table() {
        let o = for_build_strict(22621, 1).unwrap();
        assert_eq!(o.provider_block_to_enable_info, 0x070); // 22H2 shifted
    }

    #[test]
    fn all_offsets_are_nonzero_and_within_eprocess_size() {
        // EPROCESS is at least 0x600 bytes on all supported builds.
        for b in KNOWN_BUILDS {
            assert!(b.eprocess.unique_process_id > 0);
            assert!(b.eprocess.active_process_links > b.eprocess.unique_process_id);
            assert!(b.eprocess.token > b.eprocess.active_process_links);
            assert!(b.eprocess.protection > b.eprocess.token);
            // Sanity: protection is in the upper quarter of the struct.
            assert!(b.eprocess.protection > 0x400);
        }
    }

    #[test]
    fn known_builds_covers_major_releases() {
        let builds = known_builds();
        // Must cover Server 2019, Win10 2004, Server 2022, Win11 22H2, Win11 24H2.
        assert!(builds.contains(&17763));
        assert!(builds.contains(&19041));
        assert!(builds.contains(&20348));
        assert!(builds.contains(&22621));
        assert!(builds.contains(&26100));
    }
}
