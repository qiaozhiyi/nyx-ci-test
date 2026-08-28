//! Real-machine B3 isolated-BOF probe.
//!
//! Mirrors the loader-probe-exe philosophy: a plain console process — no
//! rundll32 (which hangs in non-interactive Session 0 / wine), no window
//! station APIs. Loads the selftest DLL and calls the export directly; the
//! selftest ends the process via `ExitProcess(bitmask)`, so the probe's exit
//! code IS the selftest mask.
//!
//! `nyx_selftest_bof_isolated` expects **7 (0b0111)** on a healthy Windows
//! host: bit0 = fixtures are AMD64 COFF, bit1 = bof_print.o round-tripped
//! "BOF-PRINT-OK" through the sacrificial child's inherited stdout pipe,
//! bit2 = the crashing bof_crash.o surfaced as an error while this process
//! survived.
//!
//! Exit codes: selftest mask (7 = pass) on success; 0xE0 = LoadLibrary
//! failed; 0xE1 = export missing; 0xE2 = export returned (should never
//! happen — the selftest diverges); 0xE3 = usage.
//!
//! Run: `nyx-bof-isolated-probe.exe <nyx_implant_win.dll> [export]`
//!      `nyx-bof-isolated-probe.exe --hold-tp`  (Pool Party sacrificial:
//!       CreateThreadpoolWork + infinite callback; different PID from the
//!       inject_pool parent. Self-inject is refused in implant-tasks.)

#[cfg(target_os = "windows")]
use std::os::raw::c_void;
#[cfg(target_os = "windows")]
use std::process::ExitCode;

#[cfg(target_os = "windows")]
extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
    fn CreateThreadpool(reserved: *mut c_void) -> *mut c_void;
    fn SetThreadpoolThreadMinimum(pool: *mut c_void, min: u32) -> i32;
    fn CreateThreadpoolWork(
        callback: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void),
        context: *mut c_void,
        env: *mut c_void,
    ) -> *mut c_void;
    fn SubmitThreadpoolWork(work: *mut c_void);
    fn Sleep(ms: u32);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("nyx-bof-isolated-probe: windows-only (run on a Windows host or under wine)");
}

/// Stay inside a pool thread so the TpWorkerFactory handle remains live for
/// Pool Party's system-handle-table scan.
#[cfg(target_os = "windows")]
unsafe extern "system" fn hold_tp_cb(
    _instance: *mut c_void,
    _context: *mut c_void,
    _work: *mut c_void,
) {
    unsafe { Sleep(0xFFFF_FFFF) };
}

/// Parent `inject_pool` polls `%TEMP%\nyx_hold_tp.<pid>` so it does not
/// scan the handle table before this child has submitted work.
#[cfg(target_os = "windows")]
fn write_hold_tp_alive() {
    let pid = std::process::id();
    let tmp = std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .unwrap_or_else(|_| r"C:\Windows\Temp".into());
    let path = format!("{}\\nyx_hold_tp.{}", tmp, pid);
    let _ = std::fs::write(path, b"armed");
}

/// Sacrificial target for `nyx_selftest_inject_pool`: a *different* PID than
/// the parent probe, with a live worker factory. Hosted Session 0 proved
/// CreateThreadpool works inside this binary (CI f0237fe armed in-process,
/// then `do_inject` hit `refuse self-inject`).
#[cfg(target_os = "windows")]
fn hold_threadpool() -> ExitCode {
    unsafe {
        let pool = CreateThreadpool(core::ptr::null_mut());
        if !pool.is_null() {
            let _ = SetThreadpoolThreadMinimum(pool, 1);
        }
        let work = CreateThreadpoolWork(hold_tp_cb, core::ptr::null_mut(), core::ptr::null_mut());
        if work.is_null() {
            eprintln!("CreateThreadpoolWork failed");
            return ExitCode::from(0xE4);
        }
        SubmitThreadpoolWork(work);
        write_hold_tp_alive();
        loop {
            Sleep(60_000);
        }
    }
}

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--hold-tp") {
        return hold_threadpool();
    }
    if args.len() < 2 {
        eprintln!(
            "usage: {} <nyx_implant_win.dll> [export]\n       {} --hold-tp",
            args[0], args[0]
        );
        return ExitCode::from(0xE3);
    }
    let export = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("nyx_selftest_bof_isolated");

    let dll = match std::ffi::CString::new(args[1].as_str()) {
        Ok(s) => s,
        Err(_) => return ExitCode::from(0xE3),
    };
    let name = match std::ffi::CString::new(export) {
        Ok(s) => s,
        Err(_) => return ExitCode::from(0xE3),
    };

    unsafe {
        let h = LoadLibraryA(dll.as_ptr() as *const u8);
        if h.is_null() {
            eprintln!("LoadLibraryA({}) failed", args[1]);
            return ExitCode::from(0xE0);
        }
        let p = GetProcAddress(h, name.as_ptr() as *const u8);
        if p.is_null() {
            eprintln!("GetProcAddress({}) failed", export);
            return ExitCode::from(0xE1);
        }
        // The selftest diverges via ExitProcess(mask); this never returns.
        let f: unsafe extern "system" fn() = std::mem::transmute(p);
        f();
        eprintln!("selftest returned unexpectedly");
        ExitCode::from(0xE2)
    }
}
