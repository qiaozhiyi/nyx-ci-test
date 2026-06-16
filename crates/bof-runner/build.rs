// Compile the Beacon-API C shim (beacon_api.c) into a static lib and link it,
// but only for the Windows GNU target (needs `x86_64-w64-mingw32-gcc`/`-ar`).
// On other hosts this is a no-op (the runner is cfg(windows)-gated anyway).

use std::env;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    let out = env::var("OUT_DIR").unwrap();
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let gcc = "x86_64-w64-mingw32-gcc";
    let ar = "x86_64-w64-mingw32-ar";

    let obj = format!("{out}/beacon_api.o");
    let lib = format!("{out}/libbeacon_api.a");
    let ok = Command::new(gcc)
        .args(["-c", "-O2", &format!("{dir}/src/beacon_api.c"), "-o", &obj])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        println!("cargo:warning=nyx-bof-runner: could not compile beacon_api.c (is mingw-w64 installed?) — BeaconPrintf unavailable");
        return;
    }
    let _ = Command::new(ar).args(["rcs", &lib, &obj]).status();
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=beacon_api");
    println!("cargo:rerun-if-changed=src/beacon_api.c");
}
