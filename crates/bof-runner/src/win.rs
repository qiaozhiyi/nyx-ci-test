//! The Windows loader + executor.
//!
//! Loads COFF BOFs into RWX memory, resolves externals (BeaconPrintf shim),
//! applies AMD64 relocations, calls `go()`, and captures output.
//!
//! ## REL32 trampoline
//! BOF sections are loaded via `VirtualAlloc` at low addresses while the
//! Beacon-API shim lives in the DLL at a high address — often >2 GiB apart,
//! exceeding the REL32 range. We allocate a small trampoline page near the
//! BOF that does an absolute `jmp` to the real shim, and expose the trampoline
//! as the `BeaconPrintf` external symbol.

use std::collections::HashMap;
use std::ffi::c_void;

use nyx_coff::{apply, parse, SymbolResolver};

extern "system" {
    fn VirtualAlloc(
        addr: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(lp_address: *mut c_void, dw_size: usize, dw_free_type: u32) -> i32;
}
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
/// `MEM_RELEASE` — passed to `VirtualFree` to release the entire reservation.
/// When used, `dw_size` MUST be 0.
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_SIZE: usize = 0x1000;

fn page(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

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

// SAFETY: `Loaded::base` is a raw pointer to private RWX memory owned solely
// by this `Loaded` value; no other thread holds an aliasing reference at the
// Rust level (the BOF machine code runs synchronously during `execute()` and
// does not outlive the call). `HashMap<String,u64>` and `u64` are `Send`, so
// the whole struct is safe to move across threads.
unsafe impl Send for Loaded {}
// NOTE: `Sync` is deliberately NOT implemented. Sharing `&Loaded` across
// threads would expose the BOF's RWX `base` region to data races, and BOF
// execution is single-threaded by contract (`agent-dev` spawns one owned
// thread that takes ownership of the `Loaded`). If a future caller needs to
// share `&Loaded` across threads, audit the RWX region and the
// `SyncUnsafeCell<[u8; OUT_CAP]>` capture buffer in `shim.rs` first — the
// buffer relies on `!Sync for Loaded` as a load-bearing part of its SAFETY
// proof, so do NOT blindly re-add `Sync`.

pub fn load(blob: &[u8], entry: &str, externals: HashMap<String, u64>) -> Result<Loaded, String> {
    let coff = parse(blob).map_err(|e| format!("parse: {e:?}"))?;

    let total: usize = coff
        .sections
        .iter()
        .map(|s| page((s.virtual_size.max(s.raw.len() as u32)) as usize))
        .sum::<usize>()
        .max(PAGE_SIZE);

    // RAII: `guard` owns the BOF section region and frees it (MEM_RELEASE) if
    // this function returns early via `?` or panics. On the success path we
    // `mem::forget` the guard and hand ownership to the returned `Loaded`,
    // whose own `Drop` frees the region.
    let base = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if base.is_null() {
        return Err("VirtualAlloc failed".into());
    }
    let guard = VirtualAllocGuard::new(base as *mut u8, total);
    let base = guard.ptr();

    let mut bases: Vec<u64> = Vec::with_capacity(coff.sections.len());
    let mut offset = 0usize;
    for s in &coff.sections {
        let addr = unsafe { base.add(offset) } as u64;
        bases.push(addr);
        if !s.raw.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(s.raw.as_ptr(), addr as *mut u8, s.raw.len()) };
        }
        offset += page((s.virtual_size.max(s.raw.len() as u32)) as usize);
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

// ── trampoline ──────────────────────────────────────────────────────────────

/// Allocate a small trampoline page near `near_addr` and write an absolute
/// indirect jump (`jmp [rip+0]` + 8-byte target) to `target`.
///
/// Returns `Some(guard)` on success — the guard owns the RWX page and will
/// `VirtualFree` it on `Drop`, so the caller MUST keep the guard alive for as
/// long as the BOF might branch through the trampoline (i.e. for the duration
/// of `go()`). Returns `None` if both allocations fail; the caller then falls
/// back to addressing `target` directly (REL32 may overflow, but we degrade
/// rather than abort).
fn alloc_trampoline(near_addr: u64, target: u64) -> Option<VirtualAllocGuard> {
    let hint = near_addr.saturating_sub(0x1000_0000); // 256 MiB below
                                                      // SAFETY: `hint` is an arbitrary address, only handed to `VirtualAlloc`;
                                                      // `try_alloc_tramp` documents this contract.
    let guard = unsafe { try_alloc_tramp(hint as *mut c_void) }.or_else(|| {
        // SAFETY: null hint lets the OS pick an address.
        unsafe { try_alloc_tramp(std::ptr::null_mut()) }
    })?;
    // SAFETY: `guard.ptr()` is a fresh RWX page; we are the sole writer.
    unsafe { write_trampoline(guard.ptr() as u64, target) };
    Some(guard)
}

/// SAFETY: caller may pass any `hint` (including dangling); it is only fed to
/// `VirtualAlloc`, which tolerates arbitrary addresses.
unsafe fn try_alloc_tramp(hint: *mut c_void) -> Option<VirtualAllocGuard> {
    let ptr = VirtualAlloc(
        hint,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if ptr.is_null() {
        None
    } else {
        Some(VirtualAllocGuard::new(ptr as *mut u8, 0x1000))
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

// ── Beacon-API table ────────────────────────────────────────────────────────

/// Build the Beacon-API external table. `near_addr` should be near the BOF's
/// allocated memory so REL32 relocations can reach the trampoline.
///
/// Returns the symbol table plus the trampoline guard. The guard MUST be kept
/// alive for the lifetime of the BOF execution (the relocated BOF jumps
/// through the trampoline into `BeaconPrintf`); it is freed on `Drop`.
fn beacon_apis(near_addr: u64) -> (HashMap<String, u64>, Option<VirtualAllocGuard>) {
    let real = crate::shim::BeaconPrintf as *const () as usize as u64;
    let (tramp_addr, tramp_guard) = match alloc_trampoline(near_addr, real) {
        Some(g) => (g.ptr() as u64, Some(g)),
        // Allocation failed: fall back to the direct target address. REL32 may
        // overflow on high-ASLR systems; we degrade rather than abort.
        None => (real, None),
    };
    (
        [("BeaconPrintf".to_string(), tramp_addr)]
            .into_iter()
            .collect(),
        tramp_guard,
    )
}

// ── execute ─────────────────────────────────────────────────────────────────

pub struct ExecResult {
    pub output: String,
    pub defined: HashMap<String, u64>,
}

/// Load + run a BOF's `go()`: wire up Beacon-API, reset output, call `go`,
/// return captured output.
pub fn execute(blob: &[u8]) -> Result<ExecResult, String> {
    // RAII order matters here. `hint_guard`, `_tramp_guard`, and `loaded` are
    // dropped in *declaration order* at the end of this function, i.e. hint
    // first, then trampoline, then the BOF region. The BOF keeps running
    // synchronously until `go()` returns below; by the time any guard is
    // dropped the BOF code is no longer executing, so freeing is safe.

    // Use a dummy address to seed the trampoline allocator — we need a hint
    // near where the BOF will be loaded. Allocate a small scratch page first
    // to anchor the hint, then pass that to beacon_apis so the trampoline
    // lands near the BOF sections. The scratch page itself is unused after
    // seeding; `hint_guard` frees it (MEM_RELEASE) at scope end.
    let hint_guard = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    let hint_guard = VirtualAllocGuard::new(hint_guard as *mut u8, PAGE_SIZE);
    let near = if hint_guard.ptr().is_null() {
        0
    } else {
        hint_guard.ptr() as u64
    };

    let (apis, _tramp_guard) = beacon_apis(near);
    // `loaded` is the BOF section region; its `Drop` frees it.
    let mut loaded = load(blob, "go", apis)?;
    unsafe {
        crate::shim::nyx_bof_reset();
        let go: extern "C" fn() = std::mem::transmute(loaded.entry);
        go();
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
