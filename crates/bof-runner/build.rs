// The Beacon-API shim is now a pure-Rust module (`src/shim.rs`). The C file
// `src/beacon_api.c` is retained for reference but is no longer compiled.
// If a future BOF runner needs C interop beyond what the Rust shim provides,
// uncomment the `cc::Build` block below and re-add `cc` to `build-dependencies`.

fn main() {
    // No-op: Rust shim replaces the C beacon_api.
    // Target guard retained for future C-based extensions.
    let _target = std::env::var("TARGET").unwrap_or_default();
}
