//! Stateless process-heap allocator for the bof-host PIC blob.
//!
//! The PIC dumper refuses any reachable WRITABLE data reference, so the
//! implant's `ntalloc` (which caches resolved API addresses + the heap handle
//! in atomics) is unusable here. This allocator resolves
//! `RtlGetProcessHeap`/`RtlAllocateHeap`/`RtlFreeHeap` through the PEB walk on EVERY
//! call — no cached state at all. Resolution is allocation-free
//! (`resolve::export_addr` hashes the export tables in place), so there is no
//! allocator-recursion cycle.
//!
//! `RtlAllocateHeap` on the process heap returns 16-aligned memory on x64, which
//! satisfies every `Layout` the COFF core produces (its largest alignment is
//! `u64`).

use crate::export_addr;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

type RtlGetProcessHeapFn = unsafe extern "system" fn() -> *mut c_void;
type RtlAllocateHeapFn = unsafe extern "system" fn(*mut c_void, u32, usize) -> *mut c_void;
type RtlFreeHeapFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;

/// Resolve + call `RtlGetProcessHeap`. Null on failure (kernel32 gone —
/// catastrophic; the alloc error handler will fire on the null return).
unsafe fn process_heap() -> *mut c_void {
    let Some(addr) = (unsafe { export_addr(b"ntdll.dll", b"rtlgetprocessheap") }) else {
        return core::ptr::null_mut();
    };
    let f: RtlGetProcessHeapFn = unsafe { core::mem::transmute(addr) };
    unsafe { f() }
}

/// Stateless `GlobalAlloc` over the Win32 process heap.
pub struct ProcessHeapAlloc;

unsafe impl GlobalAlloc for ProcessHeapAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = unsafe { process_heap() };
        if heap.is_null() {
            return core::ptr::null_mut();
        }
        let Some(addr) = (unsafe { export_addr(b"ntdll.dll", b"rtlallocateheap") }) else {
            return core::ptr::null_mut();
        };
        let f: RtlAllocateHeapFn = unsafe { core::mem::transmute(addr) };
        let size = if layout.size() == 0 { 1 } else { layout.size() };
        unsafe { f(heap, 0, size) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let heap = unsafe { process_heap() };
        if heap.is_null() {
            return;
        }
        let Some(addr) = (unsafe { export_addr(b"ntdll.dll", b"rtlfreeheap") }) else {
            return;
        };
        let f: RtlFreeHeapFn = unsafe { core::mem::transmute(addr) };
        let _ = unsafe { f(heap, 0, ptr as *mut c_void) };
    }
}
