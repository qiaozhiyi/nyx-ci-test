//! Heap (alloc) glue for the PIC implant.
//!
//! `#![no_std]` means no `std`, but `alloc` (Vec/String/Box) is still available
//! *if* a global allocator is registered. The [`alloc`] module (A3) wires an
//! NT-Heap-backed `GlobalAlloc`; until then we pull in `alloc`'s collection
//! types here so the PEB-walk + SSN resolution can own dynamic buffers.
//!
//! [`Str`] is a thin owned byte string used to hold export names out of the
//! export table without depending on `alloc::string::String`'s UTF-8 invariant
//! (export names are ASCII, but we copy raw bytes).

extern crate alloc;

pub use alloc::string::String;
pub use alloc::vec;
pub use alloc::vec::Vec;

/// An owned byte buffer used for export names (ASCII, no UTF-8 requirement).
/// Cheap clone-free: built once per export table walk, borrowed for hashing.
#[derive(Clone)]
pub struct Str(pub Vec<u8>);

impl Str {
    pub fn from_bytes(b: &[u8]) -> Self {
        Str(b.to_vec())
    }
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl core::ops::Deref for Str {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
