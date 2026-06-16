//! nyx-implant-win — Windows position-independent implant.
//!
//! This is a **skeleton**. It documents the intended module layout; the real
//! implementation is gated behind a pinned nightly toolchain + Windows target
//! (see `../README.md`). It deliberately does not compile on the macOS dev host.
//!
//! Compile-time plan: `#![no_std]`, `#![no_main]`, `panic = "abort"`, a custom
//! NT-Heap global allocator, and PEB/hash API resolution. The wire/crypto layer
//! is reused verbatim from [`nyx_protocol`].

#![no_std]
#![no_main]

// --- intended modules (to be implemented) ---------------------------------
// mod entry;     // PIC entry: locate base, init global instance, call main
// mod alloc;     // NT Heap allocator (RtlCreateHeap / RtlAllocateHeap / RtlFreeHeap)
// mod resolve;   // PEB walk + djb2-hash module/API resolution
// mod core;      // task loop + IOCP reactor + transport abstraction
// mod transport; // http (malleable), dns+doh, smb, tcp, udc2
// mod evasion;   // syscalls / stack / sleep / stomp / blind / unhook / mem / antidebug / drip
// mod bof;       // COFF loader + Beacon API
// mod postex;    // token / lateral / lsass / kerberos / ldap / screenshot

#[panic_handler]
fn _panic(_: &core::panic::PanicInfo) -> ! {
    // panic = abort; in PIC we just trap.
    loop {
        core::hint::spin_loop();
    }
}
