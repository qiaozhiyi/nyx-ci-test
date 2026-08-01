//! The Windows loader + executor.
//!
//! Loads COFF BOFs with a **W^X** mapping — every section is allocated
//! `PAGE_READWRITE`, its raw bytes are copied, relocations are applied while
//! the write window is still open, and only THEN are code sections
//! (`Characteristics & IMAGE_SCN_MEM_EXECUTE`) flipped to `PAGE_EXECUTE_READ`
//! via `VirtualProtect`. At the moment `go()` is invoked, no page is W+X.
//! Data sections stay `PAGE_READWRITE`.
//!
//! Externals are resolved from the `BeaconPrintf` shim plus a table of common
//! kernel32/ntdll/CRT exports (`GetModuleHandleA/W`, `GetProcAddress`,
//! `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `LoadLibraryA`,
//! `GetLastError`, the memcpy family, …) fetched at load time via
//! `GetModuleHandleA` + `GetProcAddress`.
//!
//! ## REL32 trampoline table
//! BOF sections are loaded via `VirtualAlloc` at low addresses while the
//! Beacon-API shim lives in the DLL at a high address — and the resolved
//! kernel32/ntdll exports live higher still — often >2 GiB apart, exceeding
//! the REL32 range. We allocate ONE shared trampoline page near the BOF
//! holding an absolute-jump stub (`jmp [rip+0]; dq target`) per external, and
//! expose each stub address as the symbol the relocations resolve to. The
//! page is written `PAGE_READWRITE` and flipped to `PAGE_EXECUTE_READ` before
//! `go()` can branch through it (it IS executed); the scratch hint page that
//! seeds the near-address allocator stays `PAGE_READWRITE` and is never
//! executed.

use std::collections::HashMap;
use std::ffi::c_void;

use nyx_coff::{apply, parse, SymbolResolver};

use crate::layout;

extern "system" {
    fn GetModuleHandleA(lp_module_name: *const std::os::raw::c_char) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const std::os::raw::c_char) -> *mut c_void;
    fn VirtualAlloc(
        addr: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualProtect(
        lp_address: *mut c_void,
        dw_size: usize,
        fl_new_protect: u32,
        lpfl_old_protect: *mut u32,
    ) -> i32;
    fn VirtualFree(lp_address: *mut c_void, dw_size: usize, dw_free_type: u32) -> i32;
}
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
/// `MEM_RELEASE` — passed to `VirtualFree` to release the entire reservation.
/// When used, `dw_size` MUST be 0.
const MEM_RELEASE: u32 = 0x8000;

/// RAII guard over a `VirtualAlloc`-ed region.
///
/// Owns one `VirtualAlloc` reservation and releases it on `Drop` via
/// `VirtualFree(ptr, 0, MEM_RELEASE)`. Holding the only pointer to the
/// region, so there is no aliasing and no double-free.
///
/// `Drop` is a no-op when `ptr` is null — this lets callers wrap the result of
/// a `VirtualAlloc` that may legitimately have failed without branching.
///
/// `size` is stored for diagnostics only; `MEM_RELEASE` ignores it and always
/// frees the whole reservation.
struct VirtualAllocGuard {
    ptr: *mut u8,
    #[allow(dead_code)]
    size: usize,
}

impl VirtualAllocGuard {
    /// Wrap a `VirtualAlloc`-returned pointer. Safe to call with a null
    /// pointer; `Drop` becomes a no-op in that case.
    fn new(ptr: *mut u8, size: usize) -> Self {
        Self { ptr, size }
    }

    fn ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for VirtualAllocGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was produced by a matching `VirtualAlloc(...,
            // MEM_RESERVE, ...)` call and is not null. `MEM_RELEASE` requires
            // size 0 and frees the whole reservation. Ownership is unique to
            // this guard (no aliasing, no second owner), so no double-free.
            unsafe {
                VirtualFree(self.ptr as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

pub struct Resolver {
    pub externals: HashMap<String, u64>,
    pub defined: HashMap<String, u64>,
}

impl SymbolResolver for Resolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        self.defined
            .get(name)
            .copied()
            .or_else(|| self.externals.get(name).copied())
    }
}

pub struct Loaded {
    /// Base of the `VirtualAlloc`-ed reservation holding the relocated BOF
    /// sections, or null if `load()` allocated nothing (never set today, but
    /// kept defensively so `Drop` is a no-op on a never-allocated value).
    /// Freed in `Drop` via `VirtualFree(base, 0, MEM_RELEASE)`.
    base: *mut u8,
    /// Size passed to the matching `VirtualAlloc`. Used only for diagnostics;
    /// `MEM_RELEASE` ignores it.
    #[allow(dead_code)]
    total: usize,
    pub defined: HashMap<String, u64>,
    pub entry: u64,
}

impl Drop for Loaded {
    fn drop(&mut self) {
        if !self.base.is_null() {
            // SAFETY: `base` came from `VirtualAlloc(..., MEM_RESERVE, ...)`
            // inside `load()`, is unique to this `Loaded`, and is not null.
            // `MEM_RELEASE` with size 0 frees the entire reservation.
            unsafe {
                VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

// SAFETY: `Loaded::base` is a raw pointer to private memory (code sections
// PAGE_EXECUTE_READ, data sections PAGE_READWRITE — never W+X, see `load()`)
// owned solely by this `Loaded` value; no other thread holds an aliasing
// reference at the Rust level (the BOF machine code runs synchronously during
// `execute()` and does not outlive the call). `HashMap<String,u64>` and `u64`
// are `Send`, so the whole struct is safe to move across threads.
unsafe impl Send for Loaded {}
// NOTE: `Sync` is deliberately NOT implemented. Sharing `&Loaded` across
// threads would expose the BOF's `base` region to data races, and BOF
// execution is single-threaded by contract (`agent-dev` spawns one owned
// thread that takes ownership of the `Loaded`). If a future caller needs to
// share `&Loaded` across threads, audit the region and the
// `SyncUnsafeCell<[u8; OUT_CAP]>` capture buffer in `shim.rs` first — the
// buffer relies on `!Sync for Loaded` as a load-bearing part of its SAFETY
// proof, so do NOT blindly re-add `Sync`.

pub fn load(blob: &[u8], entry: &str, externals: HashMap<String, u64>) -> Result<Loaded, String> {
    let coff = parse(blob).map_err(|e| format!("parse: {e:?}"))?;

    // One page-aligned region per section (empty sections take 0 pages).
    let sizes: Vec<usize> = coff
        .sections
        .iter()
        .map(|s| layout::page_align((s.virtual_size.max(s.raw.len() as u32)) as usize))
        .collect();
    let total: usize = sizes.iter().sum::<usize>().max(layout::PAGE_SIZE);

    // RAII: `guard` owns the BOF section region and frees it (MEM_RELEASE) if
    // this function returns early via `?` or panics. On the success path we
    // `mem::forget` the guard and hand ownership to the returned `Loaded`,
    // whose own `Drop` frees the region.
    //
    // W^X: allocate PAGE_READWRITE (write window open). Relocations are
    // applied below while the sections are still writable; only after that do
    // we flip code sections to PAGE_EXECUTE_READ.
    let base = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            layout::PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return Err("VirtualAlloc failed".into());
    }
    let guard = VirtualAllocGuard::new(base as *mut u8, total);
    let base = guard.ptr();

    let mut bases: Vec<u64> = Vec::with_capacity(coff.sections.len());
    let mut offset = 0usize;
    for (s, sz) in coff.sections.iter().zip(&sizes) {
        let addr = unsafe { base.add(offset) } as u64;
        bases.push(addr);
        if !s.raw.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(s.raw.as_ptr(), addr as *mut u8, s.raw.len()) };
        }
        offset += sz;
    }

    let mut defined: HashMap<String, u64> = HashMap::new();
    for sym in &coff.symbols {
        if sym.section_number >= 1 && (sym.section_number as usize) <= bases.len() {
            let addr = bases[(sym.section_number - 1) as usize] + sym.value as u64;
            defined.insert(sym.name.clone(), addr);
        }
    }

    let resolver = Resolver {
        externals,
        defined: defined.clone(),
    };
    for (i, s) in coff.sections.iter().enumerate() {
        if s.relocations.is_empty() {
            continue;
        }
        let patched = apply(s, &coff, bases[i], &resolver)
            .map_err(|e| format!("reloc `{}`: {:?}", s.name, e))?;
        unsafe {
            std::ptr::copy_nonoverlapping(patched.as_ptr(), bases[i] as *mut u8, patched.len())
        };
    }

    // Close the write window (W^X): flip every code section
    // (IMAGE_SCN_MEM_EXECUTE) to PAGE_EXECUTE_READ; data sections stay
    // PAGE_READWRITE. Mirrors crates/implant-win/src/bof.rs:991-1005.
    for (i, s) in coff.sections.iter().enumerate() {
        let target = layout::final_protection(s.characteristics);
        if target == layout::PAGE_READWRITE {
            continue; // data section: already RW, nothing to flip
        }
        let mut old: u32 = 0;
        let ok = unsafe {
            VirtualProtect(bases[i] as *mut c_void, sizes[i], target, &mut old)
        };
        if ok == 0 {
            return Err("VirtualProtect -> PAGE_EXECUTE_READ failed".into());
        }
    }

    let entry_sym = coff
        .symbols
        .iter()
        .find(|s| s.name == entry)
        .ok_or_else(|| format!("entry symbol `{entry}` not found"))?;
    if entry_sym.section_number < 1 {
        return Err(format!("entry `{entry}` is external/undefined"));
    }
    let entry_addr = bases[(entry_sym.section_number - 1) as usize] + entry_sym.value as u64;

    // Success: hand the reservation to `Loaded`. `Drop` for `Loaded` becomes
    // the sole owner of the free; forget the guard so it does not also free.
    let loaded = Loaded {
        base: guard.ptr(),
        total,
        defined,
        entry: entry_addr,
    };
    std::mem::forget(guard);
    Ok(loaded)
}

// ── trampoline table ─────────────────────────────────────────────────────────

/// Allocate ONE shared trampoline page near `near_addr` and write an absolute
/// indirect jump (`jmp [rip+0]` + 8-byte target) for each `(name, target)`
/// entry, one stub per `layout::TRAMP_STUB_STRIDE` bytes. The page is
/// allocated `PAGE_READWRITE`, the stubs are written, and then the whole page
/// is flipped to `PAGE_EXECUTE_READ` (W^X — the stubs ARE executed by the BOF,
/// so the write window is closed before `go()` can branch through them).
///
/// Returns the page base address plus the guard that owns it; the guard will
/// `VirtualFree` the page on `Drop`, so the caller MUST keep it alive for as
/// long as the BOF might branch through the stubs (i.e. for the duration of
/// `go()`). Returns `None` if the allocation or the protection flip fails —
/// the caller then falls back to addressing each target directly (REL32 may
/// overflow, but we degrade rather than abort).
fn alloc_tramp_table(
    near_addr: u64,
    targets: &[(String, u64)],
) -> Option<(u64, VirtualAllocGuard)> {
    if targets.is_empty() {
        return None;
    }
    let count = targets.len().min(layout::TRAMP_STUBS_PER_PAGE);
    // Stubs must never overlap in the shared page.
    debug_assert!(layout::TRAMP_STUB_STRIDE >= layout::TRAMP_STUB_LEN);
    let hint = near_addr.saturating_sub(0x1000_0000); // 256 MiB below
                                                      // SAFETY: `hint` is an arbitrary address, only handed to `VirtualAlloc`;
                                                      // `try_alloc_tramp` documents this contract.
    let guard = unsafe { try_alloc_tramp(hint as *mut c_void) }.or_else(|| {
        // SAFETY: null hint lets the OS pick an address.
        unsafe { try_alloc_tramp(std::ptr::null_mut()) }
    })?;
    let base = guard.ptr() as u64;
    // SAFETY: `guard.ptr()` is a fresh PAGE_READWRITE page; we are the sole
    // writer. The stubs are not reachable yet — relocations that point at them
    // are applied later by `load()` — so closing the write window afterwards
    // cannot race any read or execution of the stub bytes.
    unsafe {
        for (i, (_, target)) in targets.iter().take(count).enumerate() {
            write_trampoline(base + layout::tramp_stub_offset(i) as u64, *target);
        }
        let mut old: u32 = 0;
        let ok = VirtualProtect(
            base as *mut c_void,
            layout::PAGE_SIZE,
            layout::PAGE_EXECUTE_READ,
            &mut old,
        );
        if ok == 0 {
            // Flip failed: the page cannot be executed. Drop the guard (the
            // page is freed) and let the caller degrade to direct addresses.
            return None;
        }
    }
    Some((base, guard))
}

/// SAFETY: caller may pass any `hint` (including dangling); it is only fed to
/// `VirtualAlloc`, which tolerates arbitrary addresses.
unsafe fn try_alloc_tramp(hint: *mut c_void) -> Option<VirtualAllocGuard> {
    let ptr = VirtualAlloc(
        hint,
        layout::PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        layout::PAGE_READWRITE, // W^X: written RW, flipped to RX by the caller
    );
    if ptr.is_null() {
        None
    } else {
        Some(VirtualAllocGuard::new(ptr as *mut u8, layout::PAGE_SIZE))
    }
}

/// Write `jmp [rip+0]; dq <target>` at `addr`.
unsafe fn write_trampoline(addr: u64, target: u64) {
    let p = addr as *mut u8;
    // ff 25 00 00 00 00 = jmp [rip+0]
    core::ptr::write(p, 0xffu8);
    core::ptr::write(p.add(1), 0x25u8);
    core::ptr::write(p.add(2), 0x00u8);
    core::ptr::write(p.add(3), 0x00u8);
    core::ptr::write(p.add(4), 0x00u8);
    core::ptr::write(p.add(5), 0x00u8);
    // 8-byte absolute target (little-endian). `p.add(6)` is 6 mod 8 — i.e. NOT
    // u64-aligned — so we MUST use `write_unaligned` here. Plain `ptr::write`
    // requires alignment; on it this would be UB (x86-64 hardware tolerates
    // misalignment, but LLVM is free to exploit the alignment assumption and
    // Miri flags it). `write_unaligned` emits an unaligned store.
    core::ptr::write_unaligned(p.add(6) as *mut u64, target);
}

// ── externals table ──────────────────────────────────────────────────────────

/// Resolve the real addresses of the common kernel32/ntdll exports (plus the
/// CRT memcpy family) at load time via `GetModuleHandleA` + `GetProcAddress`.
///
/// Every resolved export becomes an external symbol for the BOF's
/// relocations. Most of these live >2 GiB from the low-address BOF allocation,
/// so they are entered into the table *through the trampoline* (see
/// [`beacon_apis`]); a symbol that fails to resolve is simply absent and the
/// relocator reports it as `Unresolved` if the BOF actually needs it.
fn external_targets() -> Vec<(String, u64)> {
    let mut out = Vec::with_capacity(layout::EXTERN_SINGLES.len() + layout::CRT_NAMES.len());
    for &(module, name) in layout::EXTERN_SINGLES {
        if let Some(addr) = resolve_export(module, name) {
            out.push((name.to_string(), addr));
        }
    }
    for &name in layout::CRT_NAMES {
        for &module in layout::CRT_MODULES {
            if let Some(addr) = resolve_export(module, name) {
                out.push((name.to_string(), addr));
                break;
            }
        }
    }
    out
}

/// `GetModuleHandleA(module)` + `GetProcAddress(handle, name)`. Returns `None`
/// when the module is not loaded or the export does not exist. `GetModuleHandleA`
/// only queries the loaded-module list — it never loads the DLL.
fn resolve_export(module: &str, name: &str) -> Option<u64> {
    let module_c = std::ffi::CString::new(module).ok()?;
    let name_c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `module_c`/`name_c` are NUL-terminated and live for the duration
    // of the calls. `GetModuleHandleA` does not load anything, and
    // `GetProcAddress` only reads the export table of an already-loaded module.
    let h = unsafe { GetModuleHandleA(module_c.as_ptr()) };
    if h.is_null() {
        return None;
    }
    let p = unsafe { GetProcAddress(h, name_c.as_ptr()) };
    if p.is_null() {
        return None;
    }
    Some(p as usize as u64)
}

/// Build the external symbol table. `near_addr` should be near the BOF's
/// allocated memory so REL32 relocations can reach the trampoline stubs.
///
/// Returns the symbol table plus the trampoline-table guard. The guard MUST be
/// kept alive for the lifetime of the BOF execution (the relocated BOF jumps
/// through the stubs into the shim / kernel32 exports); it is freed on `Drop`.
fn beacon_apis(near_addr: u64) -> (HashMap<String, u64>, Option<VirtualAllocGuard>) {
    // Real addresses: the BeaconPrintf shim first, then the resolved
    // kernel32/ntdll/CRT exports.
    let real = crate::shim::BeaconPrintf as *const () as usize as u64;
    let mut targets: Vec<(String, u64)> = vec![("BeaconPrintf".to_string(), real)];
    targets.extend(external_targets());

    let (table_base, table_guard) = match alloc_tramp_table(near_addr, &targets) {
        Some((b, g)) => (Some(b), Some(g)),
        // Allocation/flip failed: fall back to the direct target addresses.
        // REL32 may overflow on high-ASLR systems; we degrade rather than
        // abort (a later `RelocOverflow` surfaces the precise cause).
        None => (None, None),
    };

    let mut apis: HashMap<String, u64> = HashMap::with_capacity(targets.len());
    for (i, (name, real_addr)) in targets.iter().enumerate() {
        let addr = match table_base {
            Some(b) if i < layout::TRAMP_STUBS_PER_PAGE => {
                b + layout::tramp_stub_offset(i) as u64
            }
            _ => *real_addr,
        };
        apis.insert(name.clone(), addr);
    }
    (apis, table_guard)
}

// ── execute ─────────────────────────────────────────────────────────────────

pub struct ExecResult {
    pub output: String,
    pub defined: HashMap<String, u64>,
}

/// Load + run a BOF's `go()`: wire up the externals table (BeaconPrintf shim
/// + kernel32/ntdll/CRT exports, each through its REL32 trampoline stub),
/// reset output, call `go(args, alen)`, return captured output.
///
/// `args` is the packed CS argument blob (`[u32 tag][u32 len][bytes]` per
/// argument, as produced by `agent-dev`'s `pack_bof_args`); the entry receives it
/// verbatim as `go(args.as_ptr(), args.len() as i32)`. Pass `&[]` for a
/// no-args BOF — the entry is then invoked with a NULL buffer and length 0
/// (the canonical CS no-args call), preserving the `BeaconDataParse(NULL, 0)`
/// idiom used by BOFs that take no arguments.
pub fn execute(blob: &[u8], args: &[u8]) -> Result<ExecResult, String> {
    // RAII order matters here. `hint_guard`, `_tramp_guard`, and `loaded` are
    // dropped in *declaration order* at the end of this function, i.e. hint
    // first, then trampoline, then the BOF region. The BOF keeps running
    // synchronously until `go()` returns below; by the time any guard is
    // dropped the BOF code is no longer executing, so freeing is safe.

    // Use a dummy address to seed the trampoline allocator — we need a hint
    // near where the BOF will be loaded. Allocate a small scratch page first
    // to anchor the hint, then pass that to beacon_apis so the trampoline
    // table lands near the BOF sections. The scratch page is only an
    // allocation anchor: it is PAGE_READWRITE and is NEVER executed;
    // `hint_guard` frees it (MEM_RELEASE) at scope end.
    let hint_guard = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            layout::PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            layout::PAGE_READWRITE,
        )
    };
    let hint_guard = VirtualAllocGuard::new(hint_guard as *mut u8, layout::PAGE_SIZE);
    let near = if hint_guard.ptr().is_null() {
        0
    } else {
        hint_guard.ptr() as u64
    };

    let (apis, _tramp_guard) = beacon_apis(near);
    // `loaded` is the BOF section region; its `Drop` frees it. By the time
    // `load` returns, code sections are already PAGE_EXECUTE_READ (W^X), so
    // the entry below runs with no W+X page anywhere in the process.
    let mut loaded = load(blob, "go", apis)?;
    unsafe {
        crate::shim::nyx_bof_reset();
        // CS ABI: void go(char *args, int alen). An empty args slice becomes
        // a NULL buffer + length 0 — the no-args call BOFs expect from
        // `BeaconDataParse(NULL, 0)`.
        let (arg_ptr, arg_len) = if args.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (args.as_ptr(), args.len() as i32)
        };
        let go: extern "C" fn(*const u8, i32) = std::mem::transmute(loaded.entry);
        go(arg_ptr, arg_len);
        let output = std::ffi::CStr::from_ptr(crate::shim::nyx_bof_output())
            .to_string_lossy()
            .into_owned();
        // `Loaded` implements `Drop` (frees `base`), so we cannot move out of
        // a field by value. `mem::take` leaves an empty map in its place; the
        // map contents move into `ExecResult`, `Drop` only frees `base`.
        let defined = std::mem::take(&mut loaded.defined);
        Ok(ExecResult { output, defined })
    }
    // Drop order (declared order): hint_guard, _tramp_guard, loaded.
    // `go()` has already returned, so the BOF is not executing when its
    // memory (or the trampoline) is freed.
}
