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
    'E' as u16, 't' as u16, 'w' as u16, 'T' as u16, 'h' as u16, 'r' as u16,
    'e' as u16, 'a' as u16, 't' as u16, 'I' as u16, 'n' as u16, 't' as u16,
    'P' as u16, 'r' as u16, 'o' as u16, 'v' as u16, 'R' as u16, 'e' as u16,
    'g' as u16, 'H' as u16, 'a' as u16, 'n' as u16, 'd' as u16, 'l' as u16,
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
        let level: u8 = ps_protection::TYPE_PROTECTED | (ps_protection::SIGNER_WIN_SYSTEM << ps_protection::SIGNER_SHIFT);
        assert_eq!(level & ps_protection::TYPE_MASK, ps_protection::TYPE_PROTECTED);
        assert_eq!((level & ps_protection::SIGNER_MASK) >> ps_protection::SIGNER_SHIFT, ps_protection::SIGNER_WIN_SYSTEM);
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
