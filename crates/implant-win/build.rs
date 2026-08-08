//! Build script for nyx-implant-win.
//!
//! No compile-time bakes remain here. The malleable-C2 envelopes bake moved
//! to the `nyx-implant-net` build script and the server-pubkey /
//! per-build-config bakes moved to `nyx-implant-core` in the WP-C crate split
//! (`envelopes.rs`, `config.rs` and the `server_pub` include live there now).
//!
//! The kernel-offsets bake (`bake_offsets`, driven by `NYX_OFFSETS`, emitting
//! `OUT_DIR/kernel_offsets.rs`) was REMOVED on 2026-08-08: nothing in the
//! tree — at HEAD or working copy — ever `include!`d the generated file or
//! read `OFFSETS_BAKED`. The implant's cross-version offset source of truth
//! is the runtime table `nyx_implant_evasionsdk::offsets_table`
//! (`version.rs::host_offsets`); the server-side `offset-resolver` output has
//! no remaining consumer here.

fn main() {
    // Declare the crate's custom cfg flags so recent nightlies (which enable
    // check-cfg by default) don't reject them as `unexpected cfg condition
    // name`. None of these is set in a default build — they are opt-in build
    // flags (e.g. -Z unstable-options builds pass --cfg nyx_diag on the dev
    // box) or read at runtime via `cfg!(...)`. Declaring them here marks them
    // as known-to-be-absent rather than unknown names.
    // (`nyx_fs_allow_protected` moved to the nyx-implant-tasks build script
    // with fs.rs; `nyx_diag` is ALSO declared there for selftests.rs — each
    // crate must declare the cfgs its own sources use.)
    println!("cargo::rustc-check-cfg=cfg(nyx_diag)");
    println!("cargo::rustc-check-cfg=cfg(nyx_skip_sandbox)");
}
