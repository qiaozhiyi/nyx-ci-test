//! `.pdata` gap/ghost enumeration — pure-Rust core (no Windows deps).
//!
//! A Windows PE's `.pdata` section is a sorted array of `IMAGE_RUNTIME_FUNCTION_ENTRY`
//! (x64, 12 bytes: `BeginAddress`, `EndAddress`, `UnwindInfoAddress`, all RVAs).
//! Between consecutive entries lie "gap" addresses — code RVAs not covered by
//! any `RUNTIME_FUNCTION`. `RtlLookupFunctionEntry(addr)` returns `NULL` for
//! these, so the unwinder treats them as **leaf functions** (advances RSP by 8,
//! no `.xdata` lookup, no shadow-stack interaction). BYOUD-Gap / LACUNA Chain
//! weaponize these as leaf bridge frames in a spoofed call stack.
//!
//! This module is the OS-agnostic core: it operates on a parsed slice of
//! runtime-function entries + the image size and yields gap RVAs. The Windows
//! impl (in `implant-win`) feeds it the live ntdll / kernelbase / win32u /
//! wow64 `.pdata` table it recovers via the PEB walk.

#![cfg_attr(not(test), allow(dead_code))]

use crate::GapPool;
use alloc::vec::Vec;

/// PE `IMAGE_RUNTIME_FUNCTION_ENTRY` (x64 `.pdata`), 12 bytes, little-endian.
/// All fields are RVAs (offsets from the image base).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

impl RuntimeFunctionEntry {
    /// Parse one 12-byte entry from a little-endian slice. `None` if < 12 bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        Some(Self {
            begin_address: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            end_address: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            unwind_info_address: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// Parse a whole `.pdata` table (a contiguous run of 12-byte entries).
    pub fn parse_table(bytes: &[u8]) -> Vec<Self> {
        bytes.chunks_exact(12).filter_map(Self::from_bytes).collect()
    }
}

/// Kind of an enumerated gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapKind {
    /// Between two functions: `entry[i].end_address .. entry[i+1].begin_address`.
    /// The leaf-frame gaps BYOUD-Gap uses as `[RSP]` bridge frames.
    InterFunction,
    /// Past the last function up to `image_size` (trailing tail).
    TailPadding,
}

/// One enumerated gap address (RVA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    pub rva: u32,
    pub kind: GapKind,
}

/// Enumerate gap RVAs across a `.pdata` table covering `[0, image_size)`.
///
/// The table MUST be sorted ascending by `begin_address` (the PE spec
/// guarantees this). Gaps are the half-open ranges between one entry's
/// `end_address` and the next entry's `begin_address`, plus the trailing tail
/// after the last entry. Sampled every 8 bytes (each is a valid leaf-frame
/// anchor), capped at `max_per_gap` per range (0 = no cap).
pub fn enumerate_gaps(
    entries: &[RuntimeFunctionEntry],
    image_size: u32,
    max_per_gap: usize,
) -> Vec<Gap> {
    let mut out = Vec::new();
    if entries.is_empty() {
        push_samples(&mut out, 0, image_size, GapKind::TailPadding, max_per_gap);
        return out;
    }
    for win in entries.windows(2) {
        let a_end = win[0].end_address.max(win[0].begin_address);
        let b_begin = win[1].begin_address;
        if b_begin > a_end {
            push_samples(&mut out, a_end, b_begin, GapKind::InterFunction, max_per_gap);
        }
    }
    // SAFETY: the `entries.is_empty()` early-return above guarantees at least
    // one element here. Use `expect` rather than `unwrap` so the invariant is
    // documented at the call site and any future refactor that drops the guard
    // produces a diagnosable panic instead of a bare `unwrap`.
    let last = *entries
        .last()
        .expect("checked non-empty at the early-return above");
    let last_end = last.end_address.max(last.begin_address);
    if image_size > last_end {
        push_samples(&mut out, last_end, image_size, GapKind::TailPadding, max_per_gap);
    }
    out
}

fn push_samples(out: &mut Vec<Gap>, start: u32, end: u32, kind: GapKind, max_per_gap: usize) {
    let mut addr = start;
    let mut n = 0usize;
    while addr < end {
        out.push(Gap { rva: addr, kind });
        addr = addr.saturating_add(8); // 8-byte-aligned leaf anchors
        n += 1;
        if max_per_gap != 0 && n >= max_per_gap {
            break;
        }
    }
}

/// Build a `GapPool` (RVAs) from an enumerated gap list, splitting it into the
/// three buckets via caller-supplied predicates. The real Windows impl refines
/// ghost/NOP detection by inspecting bytes at each gap; exposing the
/// classification as predicates keeps this core testable in isolation.
///
/// `image` is the optional raw image bytes (for byte-pattern predicates).
pub fn classify_into_pool(
    gaps: &[Gap],
    image: Option<&[u8]>,
    ghost_pred: impl Fn(u32, Option<&[u8]>) -> bool,
    nop_pred: impl Fn(u32, Option<&[u8]>) -> bool,
) -> GapPool {
    let mut pool = GapPool::default();
    for g in gaps {
        if ghost_pred(g.rva, image) {
            pool.ghosts.push(g.rva as usize);
        } else if nop_pred(g.rva, image) {
            pool.nops.push(g.rva as usize);
        } else if g.kind == GapKind::TailPadding {
            // LACUNA layer 4: tail-padding lacunae get their own bucket so
            // build_leaf_bridge can round-robin across all four leaf pools.
            pool.tails.push(g.rva as usize);
        } else {
            pool.gaps.push(g.rva as usize);
        }
    }
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(begin: u32, end: u32) -> RuntimeFunctionEntry {
        RuntimeFunctionEntry { begin_address: begin, end_address: end, unwind_info_address: 0 }
    }

    #[test]
    fn parses_twelve_bytes_le() {
        let b = [0x00, 0x10, 0x00, 0x00, 0x40, 0x10, 0x00, 0x00, 0xFF, 0x20, 0x00, 0x00];
        let e = RuntimeFunctionEntry::from_bytes(&b).unwrap();
        assert_eq!(e.begin_address, 0x1000);
        assert_eq!(e.end_address, 0x1040);
        assert_eq!(e.unwind_info_address, 0x20FF);
    }

    #[test]
    fn from_bytes_rejects_short() {
        assert!(RuntimeFunctionEntry::from_bytes(&[0; 11]).is_none());
    }

    #[test]
    fn parse_table_round_trip() {
        let bytes = {
            let mut v = Vec::new();
            for &(b, e) in &[(0x1000u32, 0x1010u32), (0x1030u32, 0x1040u32)] {
                v.extend_from_slice(&b.to_le_bytes());
                v.extend_from_slice(&e.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
            }
            v
        };
        let t = RuntimeFunctionEntry::parse_table(&bytes);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0], entry(0x1000, 0x1010));
        assert_eq!(t[1], entry(0x1030, 0x1040));
    }

    #[test]
    fn enumerates_inter_function_gaps() {
        // f1 [0x1000,0x1010), f2 [0x1030,0x1040); image ends at last fn → no tail
        let entries = [entry(0x1000, 0x1010), entry(0x1030, 0x1040)];
        let gaps = enumerate_gaps(&entries, 0x1040, 0);
        let inter: Vec<u32> = gaps
            .iter()
            .filter(|g| g.kind == GapKind::InterFunction)
            .map(|g| g.rva)
            .collect();
        // gap [0x1010,0x1030) = 0x20 bytes → 4 eight-byte anchors
        assert_eq!(inter, vec![0x1010, 0x1018, 0x1020, 0x1028]);
    }

    #[test]
    fn contiguous_functions_have_no_inter_gap() {
        let entries = [entry(0x1000, 0x1010), entry(0x1010, 0x1020)];
        let gaps = enumerate_gaps(&entries, 0x2000, 0);
        assert!(gaps.iter().all(|g| g.kind == GapKind::TailPadding));
        assert_eq!(gaps[0].rva, 0x1020);
    }

    #[test]
    fn max_per_gap_caps_samples() {
        // image == last end so only the one inter gap is emitted
        let entries = [entry(0x1000, 0x1000), entry(0x2000, 0x2000)];
        let gaps = enumerate_gaps(&entries, 0x2000, 2);
        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0].rva, 0x1000);
        assert_eq!(gaps[1].rva, 0x1008);
    }

    #[test]
    fn trailing_tail_padding_to_image_size() {
        let entries = [entry(0x1000, 0x1010)];
        let gaps = enumerate_gaps(&entries, 0x1080, 0);
        // tail [0x1010,0x1080) = 0x70 bytes → 14 anchors
        assert_eq!(gaps.len(), 14);
        assert_eq!(gaps[0].rva, 0x1010);
        assert_eq!(gaps.last().unwrap().rva, 0x1078);
    }

    #[test]
    fn empty_entries_yields_full_image_tail() {
        let gaps = enumerate_gaps(&[], 0x20, 0);
        assert_eq!(gaps.len(), 4);
        assert_eq!(gaps[0].rva, 0x0);
    }

    #[test]
    fn classify_splits_into_buckets() {
        // image == last end → exactly 3 inter samples (0x1000,0x1008,0x1010)
        let entries = [entry(0x1000, 0x1000), entry(0x2000, 0x2000)];
        let gaps = enumerate_gaps(&entries, 0x2000, 3);
        let pool = classify_into_pool(
            &gaps,
            None,
            |rva, _| rva == 0x1000,
            |rva, _| rva == 0x1008,
        );
        assert_eq!(pool.ghost_count(), 1);
        assert_eq!(pool.nop_count(), 1);
        assert_eq!(pool.gap_count(), 1);
        assert!(pool.is_usable());
    }

    #[test]
    fn end_before_begin_does_not_panic() {
        // malformed entry with end < begin must be clamped, not underflow
        let malformed = RuntimeFunctionEntry { begin_address: 0x2000, end_address: 0x1000, unwind_info_address: 0 };
        let next = RuntimeFunctionEntry { begin_address: 0x3000, end_address: 0x3010, unwind_info_address: 0 };
        let _ = enumerate_gaps(&[malformed, next], 0x4000, 0); // must not panic
    }
}
