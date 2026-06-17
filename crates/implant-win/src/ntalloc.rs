//! Bump allocator for the PIC implant, backed by NtAllocateVirtualMemory.
//!
//! A bump allocator over VirtualAlloc'd regions is the classic PIC-implant
//! choice (Stardust, Rustic64): one API to resolve, no free-list, no heap
//! handle, no loader-lock deadlock risk from RtlAllocateHeap.
//!
//! cfg(target_os = "windows") -- only compiles on Windows.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SLAB_SIZE: usize = 1 << 20;
const ALIGN: usize = 16;

static NT_ALLOC: AtomicU64 = AtomicU64::new(0);
static RESOLVED: AtomicBool = AtomicBool::new(false);
static SLAB_BASE: AtomicU64 = AtomicU64::new(0);
static SLAB_BUMP: AtomicU64 = AtomicU64::new(0);

type NtAllocVirtualMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *mut *mut core::ffi::c_void,
    usize,  // ZeroBits — BY VALUE (ULONG_PTR), not a pointer. Passing &mut here
            // put a stack address in the ZeroBits argument register; the kernel
            // validates ZeroBits ≤ 21 for user mode and rejected the allocation.
    *mut usize,
    u32,
    u32,
) -> i32;

unsafe fn ensure_resolved() {
    if RESOLVED.load(Ordering::Acquire) {
        return;
    }
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory") {
        NT_ALLOC.store(addr as u64, Ordering::Release);
    }
    RESOLVED.store(true, Ordering::Release);
}

unsafe fn new_slab() -> *mut u8 {
    let f: NtAllocVirtualMemory = match NT_ALLOC.load(Ordering::Acquire) {
        0 => return core::ptr::null_mut(),
        a => core::mem::transmute(a as usize),
    };
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut size: usize = SLAB_SIZE;
    // NtCurrentProcess() == (HANDLE)-1
    let cur_proc: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
    // ZeroBits = 0 (no zero-bit-constrained allocation; let the kernel pick a
    // user-range address). Passed BY VALUE per the real NT prototype.
    let status = f(cur_proc, &mut base, 0, &mut size, 0x3000, 0x04);
    if status < 0 || base.is_null() {
        return core::ptr::null_mut();
    }
    base as *mut u8
}

/// Static fallback buffer used before NtAllocateVirtualMemory is resolved
/// (during Rust runtime static-init at dll load). 64 KiB is plenty for the
/// handful of tiny allocations the runtime makes before control reaches our
/// entry. Once the entry runs and resolve succeeds, real slabs take over.
static FALLBACK_BUF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const FALLBACK_SIZE: usize = 1 << 16;
static mut FALLBACK_MEM: [u8; FALLBACK_SIZE] = [0; FALLBACK_SIZE];

/// Force the allocator to resolve NtAllocateVirtualMemory NOW (call from entry
/// before any alloc-heavy code). Public so the entry can prime it.
pub unsafe fn force_resolve() {
    ensure_resolved();
}

/// The resolved NtAllocateVirtualMemory address (0 = not yet resolved).
pub fn nt_alloc_addr() -> u64 {
    NT_ALLOC.load(Ordering::Acquire)
}

pub struct NtHeapAllocator;

unsafe impl core::alloc::GlobalAlloc for NtHeapAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        if size == 0 {
            return core::ptr::null_mut();
        }
        let aligned = (size + ALIGN - 1) & !(ALIGN - 1);

        ensure_resolved();
        if NT_ALLOC.load(Ordering::Acquire) != 0 {
            // Real allocator path.
            loop {
                // If no slab yet, allocate one first.
                if SLAB_BASE.load(Ordering::Acquire) == 0 {
                    let nb = new_slab();
                    if nb.is_null() {
                        break;
                    }
                    SLAB_BASE.store(nb as u64, Ordering::Release);
                    SLAB_BUMP.store(0, Ordering::Release);
                }
                let base = SLAB_BASE.load(Ordering::Acquire);
                let off = SLAB_BUMP.load(Ordering::Acquire);
                let new_off = off + aligned as u64;
                if new_off <= SLAB_SIZE as u64 {
                    if SLAB_BUMP.compare_exchange(off, new_off, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        return (base as usize + off as usize) as *mut u8;
                    }
                    continue;
                }
                let nb = new_slab();
                if nb.is_null() {
                    break;
                }
                SLAB_BASE.store(nb as u64, Ordering::Release);
                SLAB_BUMP.store(aligned as u64, Ordering::Release);
                return nb;
            }
        }

        // Fallback: bump within the static buffer. Safe because PIC is
        // single-threaded at init.
        let cur = FALLBACK_BUF.load(Ordering::Acquire);
        let nxt = cur + aligned as u64;
        if nxt <= FALLBACK_SIZE as u64 {
            FALLBACK_BUF.store(nxt, Ordering::Release);
            let base = core::ptr::addr_of_mut!(FALLBACK_MEM) as *mut u8;
            return base.add(cur as usize);
        }
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
