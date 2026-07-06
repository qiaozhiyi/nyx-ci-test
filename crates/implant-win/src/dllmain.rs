//! Minimal `DllMain` — replaces the mingw-w64 CRT startup entry point.
//!
//! ## Why (Server 2025 / Windows 11 24H2 compatibility)
//!
//! On Windows Server 2025 (build 26100) the mingw-w64 CRT startup (`dllcrt2.o`
//! → `DllMainCRTStartup`) can crash with `STATUS_STACK_BUFFER_OVERRUN`
//! (0xC0000409) during DLL load. Two known causes:
//!
//! 1. **TLS pollution on foreign threads** (pengjiaxusz/rust-dll-thread-attach-
//!    tls-pollution): `DLL_THREAD_ATTACH` on non-Rust threads corrupts Rust TLS
//!    data, and subsequent `std::thread::spawn` aborts. Our implant is `#![no_std]`
//!    so this is less likely, but the mingw CRT has its own TLS init.
//! 2. **CRT startup objects** (`dllcrt2.o`): The default mingw-w64 DLL startup
//!    initialises the GS cookie, registers SEH frames, and sets up C++ exception
//!    handling. On Server 2025 these init paths interact badly with the hardened
//!    UCRT `try_get_function_slow` / function-pointer patching (same class as
//!    TheWover/donut#173).
//!
//! ## Fix
//!
//! 1. `-nostartfiles` in `.cargo/config.toml` tells the linker to skip CRT
//!    startup objects (`dllcrt2.o`, `crt2.o`). The entry point becomes this
//!    module's `DllMain` directly.
//! 2. This `DllMain` returns `1` (TRUE) unconditionally — it performs NO init.
//!    DLL process/thread attach succeeds without touching CRT TLS, SEH, or GS.
//!    All implant initialisation happens lazily when the beacon export
//!    (`nyx_entry`, `nyx_beacon_oneshot`, selftest, …) is called.
//!
//! ## Trade-off
//!
//! Without CRT startup we lose: `atexit` handlers, C++ static destructors,
//! `__main`/`__gcc_register_frame`. None of these are used by the `#![no_std]`
//! implant — it's a pure NT-syscall DLL with no C++ dependencies.

#![cfg(target_os = "windows")]

/// Windows DLL entry point. Returns TRUE unconditionally — no init is performed.
///
/// The linker is configured with `-nostartfiles`, so this function IS the
/// effective DLL entry point (not a callback from `DllMainCRTStartup`).
///
/// # DLL load reasons
/// - `DLL_PROCESS_ATTACH` (1): DLL is being loaded. We return TRUE to allow the
///   load but perform NO initialisation. The beacon/selftest export does its own
///   init lazily on first call.
/// - `DLL_THREAD_ATTACH` (2): A new thread is starting in a process that already
///   has this DLL loaded. We return TRUE immediately — this is the critical fix
///   for Server 2025: touching CRT/TLS here on foreign threads causes
///   `STATUS_STACK_BUFFER_OVERRUN`.
/// - `DLL_PROCESS_DETACH` (0): DLL is being unloaded. No-op.
/// - `DLL_THREAD_DETACH` (3): A thread is exiting. No-op.
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst: *mut core::ffi::c_void,
    _reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // Always succeed — the beacon/selftest export handles its own init.
    1
}
