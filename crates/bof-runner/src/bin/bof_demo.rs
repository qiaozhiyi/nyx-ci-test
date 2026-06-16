//! BOF execution demo (Windows / Wine). Runs the marker BOF end-to-end:
//! load → relocate → execute `go()` → read the global it wrote.
//!
//! (A second fixture, `bof_print.o`, exercises the `BeaconPrintf` output shim.
//! That path works on real Windows but Wine's exception unwinder can't walk a
//! return address that lands in the injected RWX region, so it's not driven
//! from this Wine-tested demo.)

#[cfg(target_os = "windows")]
fn main() {
    let r = nyx_bof_runner::execute(include_bytes!("../../tests/fixtures/bof_marker.o"))
        .expect("BOF execute failed");
    let addr = r
        .defined
        .get("nyx_marker")
        .copied()
        .expect("nyx_marker symbol not found");
    let value = unsafe { *(addr as *const u32) };
    println!("nyx_marker = 0x{:08x}", value);
    if value == 0x1a2b3c4d {
        println!("BOF-EXEC-OK");
        std::process::exit(0);
    }
    eprintln!("BOF-EXEC-FAIL (expected 0x1a2b3c4d)");
    std::process::exit(1);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("nyx-bof-runner demo is Windows-only — build with --target x86_64-pc-windows-gnu and run under Wine");
    std::process::exit(2);
}
