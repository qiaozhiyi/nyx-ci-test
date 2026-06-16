//! BOF execution demo (Windows / Wine). Loads a fixture COFF whose `go()` writes
//! a known value to a global `nyx_marker`, runs it, and reads the marker back —
//! proving relocation + code execution end-to-end.

#[cfg(target_os = "windows")]
fn main() {
    let blob = include_bytes!("../../tests/fixtures/bof_marker.o");
    let loaded = nyx_bof_runner::execute(blob).expect("BOF execute failed");

    let marker = loaded
        .defined
        .get("nyx_marker")
        .copied()
        .expect("nyx_marker symbol not found");
    let value = unsafe { *(marker as *const u32) };
    println!("nyx_marker = 0x{:08x}", value);
    if value == 0x1a2b3c4d {
        println!("BOF-EXEC-OK");
        std::process::exit(0);
    } else {
        eprintln!("BOF-EXEC-FAIL (expected 0x1a2b3c4d)");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("nyx-bof-runner demo is Windows-only — build with --target x86_64-pc-windows-gnu and run under Wine");
    std::process::exit(2);
}
