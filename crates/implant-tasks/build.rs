//! Build script for nyx-implant-tasks.
//!
//! No compile-time bakes live here — this build script only declares the
//! custom cfg flags used by this crate's modules so recent nightlies (which
//! enable check-cfg by default) don't reject them as `unexpected cfg
//! condition name`. Neither is set in a default build — they are opt-in
//! build flags passed via RUSTFLAGS (e.g. `--cfg nyx_diag` on the dev box).
//! Declaring them here marks them as known-to-be-absent rather than unknown
//! names.
//!
//! Note: tp.rs reads `option_env!("NYX_POOL_PARTY_ON")` at compile time; that
//! env var is evaluated against THIS crate's build environment now (it was
//! the shell crate's before the split) — same build invocation, same
//! semantics, no forwarding needed.

fn main() {
    // `nyx_fs_allow_protected` — fs.rs opt-in for protected-path file ops.
    println!("cargo::rustc-check-cfg=cfg(nyx_fs_allow_protected)");
    // `nyx_diag` — selftests.rs diag-byte gating (diag-marker builds).
    println!("cargo::rustc-check-cfg=cfg(nyx_diag)");
}
