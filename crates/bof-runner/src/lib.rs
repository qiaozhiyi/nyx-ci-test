//! BOF execution layer — the other half of the BOF story.
//!
//! `nyx-coff` parses + relocates a Windows COFF; this crate *runs* it: map the
//! sections into executable memory (`VirtualAlloc`), resolve every external
//! reference against a Beacon-API table, apply relocations, then call the BOF's
//! entry (`go`). Windows-only — it allocates RWX memory and jumps into
//! position-relocated machine code. Build with `--target x86_64-pc-windows-gnu`
//! and run under Wine (or real Windows).
//!
//! ## Current capability
//! Loads multi-section COFFs, applies `ADDR64` / `REL32[_1..5]`, calls `go()`,
//! and exposes the resolved symbol addresses so a caller can read results the
//! BOF wrote (e.g. a marker global). The Beacon-API shim (`BeaconPrintf` →
//! captured output) is a pure-Rust implementation — no C CRT dependency.

#[cfg(target_os = "windows")]
mod shim;
#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
pub use win::{execute, load, ExecResult, Loaded, Resolver};
