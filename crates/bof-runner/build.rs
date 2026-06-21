// Compile the Beacon-API C shim (beacon_api.c) into a static lib and link it.
// On non-Windows hosts this is a no-op (the runner is cfg(windows)-gated anyway).

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    cc::Build::new()
        .file("src/beacon_api.c")
        .compile("beacon_api");
    println!("cargo:rerun-if-changed=src/beacon_api.c");
}
