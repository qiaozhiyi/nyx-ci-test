//! Heap (alloc) glue for the PIC implant.
//!
//! `#![no_std]` means no `std`, but `alloc` (Vec/String/Box) is still available
//! *if* a global allocator is registered. The [`ntalloc`] module (A3) wires an
//! NT-Heap-backed `GlobalAlloc`; until then we pull in `alloc`'s collection
//! types here so the PEB-walk + SSN resolution can own dynamic buffers.
//!
//! `extern crate alloc` is declared once in lib.rs; this module just re-exports
//! its collection types.
//!
//! [`Str`] is a thin owned byte string used to hold export names out of the
//! export table without depending on `alloc::string::String`'s UTF-8 invariant
//! (export names are ASCII, but we copy raw bytes).

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
    /// Lossy UTF-8 conversion to a String (replaces invalid bytes with U+FFFD).
    /// `alloc::string::String` lacks `from_utf8_lossy` (that's a std method), so
    /// we hand-roll it: valid UTF-8 prefixes pass through, invalid bytes become
    /// the replacement char.
    pub fn to_string_lossy(&self) -> String {
        // Fast path: if it's already valid UTF-8, clone directly.
        match core::str::from_utf8(&self.0) {
            Ok(s) => s.into(),
            Err(_) => {
                // Slow path: replace invalid sequences with U+FFFD.
                let mut out = String::with_capacity(self.0.len());
                let mut i = 0;
                while i < self.0.len() {
                    // Try to take a maximal valid UTF-8 run.
                    match core::str::from_utf8(&self.0[i..]) {
                        Ok(s) => {
                            out.push_str(s);
                            break;
                        }
                        Err(e) => {
                            let valid_up_to = e.valid_up_to();
                            if valid_up_to > 0 {
                                out.push_str(
                                    core::str::from_utf8(&self.0[i..i + valid_up_to]).unwrap_or(""),
                                );
                            }
                            out.push('\u{FFFD}');
                            i += valid_up_to + 1;
                        }
                    }
                }
                out
            }
        }
    }
}

impl core::ops::Deref for Str {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
