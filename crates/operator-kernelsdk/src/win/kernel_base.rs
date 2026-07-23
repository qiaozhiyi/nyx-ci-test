//! ntoskrnl base address resolution — multi-path.
//!
//! The kernel base address is needed to resolve kernel symbols (EPROCESS
//! field offsets, Ps*NotifyRoutine arrays, EtwThreatIntProvRegHandle) via
//! RVA addition.
//!
//! ## Two paths (per the 2024+ KASLR restriction research)
//!
//! 1. **NtQuerySystemInformation(SystemModuleInformation)** — the classic path.
//!    Returns an RTL_PROCESS_MODULES array; Module[0] is ntoskrnl.exe with its
//!    ImageBase. Works on Win10 / Server 2019-2022 / Win11 ≤23H2. On Win11
//!    24H2+ (build 26100+), Microsoft zeroes ImageBase for callers without
//!    SeDebugPrivilege — but we're operator-side (admin + SeDebug), so it still
//!    works.
//!
//! 2. **EnumDeviceDrivers** — wraps the same NtQuerySystemInformation internally.
//!    Same restriction applies. Kept as a simpler API alternative.
//!
//! If both fail (zeroed ImageBase), the operator must supply the base from a
//! PDB or known-good RVA table (the offsets_table fallback).

#![cfg(target_os = "windows")]

use crate::KrwError;
use core::ffi::c_void;

/// SystemInformationClass for "loaded kernel modules".
const SYSTEM_MODULE_INFORMATION: u32 = 11;

/// A single kernel module entry (RTL_PROCESS_MODULE_INFORMATION, 296 bytes on x64).
/// Note: some sources list 304 but the actual x64 layout is 296. We only read Module[0]
#[repr(C)]
struct RtlProcessModuleInformation {
    section: *mut c_void,
    mapped_base: *mut c_void,
    image_base: *mut c_void, // ← the kernel VA of the module
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    name_offset: u16,
    full_path: [u8; 256],
}

/// Resolve the ntoskrnl.exe base address via NtQuerySystemInformation.
///
/// Returns the kernel VA of ntoskrnl.exe (always Module[0] in the list per
/// Windows convention), or an error if the query fails or ImageBase is zero
/// (Win11 24H2+ KASLR restriction without SeDebugPrivilege).
///
/// # Safety
/// Calls NtQuerySystemInformation with a heap buffer. Single-threaded operator
/// context. The buffer size is generous (256KB) to avoid STATUS_INFO_LENGTH_
/// MISMATCH on the first call.
pub unsafe fn ntoskrnl_base() -> Result<usize, KrwError> {
    let (base, _size) = unsafe { ntoskrnl_module_info()? };
    Ok(base)
}

/// Resolve both the ntoskrnl.exe base address AND image size.
///
/// Returns `(base, size)` where `base` is the kernel VA and `size` is the
/// image size in bytes. The size is needed by `CallbackNeutralizer::repurpose()`
/// for range-based ntoskrnl filtering (skip slots whose routine falls inside
/// `[base, base + size)`).
///
/// # Safety
/// Same as [`ntoskrnl_base`].
pub unsafe fn ntoskrnl_module_info() -> Result<(usize, usize), KrwError> {
    type NtQuerySystemInformationFn =
        unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

    let nqsi: NtQuerySystemInformationFn =
        unsafe { super::resolve::resolve_sym(b"ntdll.dll", b"NtQuerySystemInformation") }?;

    // Allocate a generous buffer. RTL_PROCESS_MODULES for ~300 drivers is ~90KB;
    // 256KB is headroom. Use a Vec (operator-side, std/alloc is fine).
    let mut buf = alloc::vec![0u8; 256 * 1024];
    let mut ret_len: u32 = 0;

    // First call: get the data.
    let status = unsafe {
        nqsi(
            SYSTEM_MODULE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut ret_len,
        )
    };
    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected on the first call
    // if the buffer is too small; it still writes ret_len. Re-allocate + retry.
    if status as u32 == 0xC0000004 {
        buf = alloc::vec![0u8; ret_len as usize + 0x1000];
        let status2 = unsafe {
            nqsi(
                SYSTEM_MODULE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret_len,
            )
        };
        if status2 < 0 {
            return Err(KrwError::Other(alloc::format!(
                "NtQuerySystemInformation retry failed: {:#x}",
                status2 as u32
            )));
        }
    } else if status < 0 {
        return Err(KrwError::Other(alloc::format!(
            "NtQuerySystemInformation failed: {:#x}",
            status as u32
        )));
    }

    // Parse: first ULONG = module count, then the array of entries.
    if buf.len() < 8 {
        return Err(KrwError::Other(
            "NtQuerySystemInformation buffer too short".into(),
        ));
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if count == 0 {
        return Err(KrwError::Other(
            "NtQuerySystemInformation returned 0 modules".into(),
        ));
    }

    // Module[0] is at offset 8 (after the count ULONG + 4 padding bytes on x64).
    // Each RTL_PROCESS_MODULE_INFORMATION is 296 bytes on x64.
    const ENTRY_SIZE: usize = 296;
    if buf.len() < 8 + ENTRY_SIZE {
        return Err(KrwError::Other(
            "buffer too short for first module entry".into(),
        ));
    }
    let entry_ptr = buf.as_ptr().wrapping_add(8) as *const RtlProcessModuleInformation;
    let entry = unsafe { &*entry_ptr };

    let base = entry.image_base as usize;
    if base == 0 {
        return Err(KrwError::Unavailable(
            "ntoskrnl ImageBase is zero (Win11 24H2+ KASLR restriction — need SeDebugPrivilege or fallback)",
        ));
    }
    let size = entry.image_size as usize;
    Ok((base, size))
}

/// A loaded kernel module's base + size, returned by [`module_info_by_name`].
pub struct ModuleInfo {
    pub base: usize,
    pub size: usize,
}

/// Query the loaded-kernel-module list (NtQuerySystemInformation class 11) and
/// return `(base, size)` for the first module whose full path ends with
/// `name` (case-insensitive ASCII compare, e.g. `"fltmgr.sys"`). Module[0] is
/// ntoskrnl; drivers follow. Used to resolve FLTMGR's base so its
/// `FltGlobals` global can be pattern-scanned for the MiniFilter unlinker.
///
/// Returns `Err(Unavailable)` if no module matches (driver not loaded) or its
/// ImageBase is zero (Win11 24H2+ KASLR restriction without SeDebugPrivilege).
///
/// # Safety
/// Same NtQuerySystemInformation contract as [`ntoskrnl_module_info`].
pub unsafe fn module_info_by_name(name: &[u8]) -> Result<ModuleInfo, KrwError> {
    type NtQuerySystemInformationFn =
        unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    let nqsi: NtQuerySystemInformationFn =
        unsafe { super::resolve::resolve_sym(b"ntdll.dll", b"NtQuerySystemInformation") }?;

    let mut buf = alloc::vec![0u8; 256 * 1024];
    let mut ret_len: u32 = 0;
    let status = unsafe {
        nqsi(
            SYSTEM_MODULE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut ret_len,
        )
    };
    if status as u32 == 0xC0000004 {
        buf = alloc::vec![0u8; ret_len as usize + 0x1000];
        let status2 = unsafe {
            nqsi(
                SYSTEM_MODULE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret_len,
            )
        };
        if status2 < 0 {
            return Err(KrwError::Other(alloc::format!(
                "NtQuerySystemInformation retry failed: {:#x}",
                status2 as u32
            )));
        }
    } else if status < 0 {
        return Err(KrwError::Other(alloc::format!(
            "NtQuerySystemInformation failed: {:#x}",
            status as u32
        )));
    }
    if buf.len() < 8 {
        return Err(KrwError::Other(
            "NtQuerySystemInformation buffer too short".into(),
        ));
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    const ENTRY_SIZE: usize = 296;
    // ASCII case-insensitive "ends with" against the module's full_path (which
    // is a fixed 256-byte NUL-padded UTF-8 path like
    // "\SystemRoot\System32\drivers\fltmgr.sys").
    let ends_with_ci = |path: &[u8; 256], needle: &[u8]| -> bool {
        let plen = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        if plen < needle.len() {
            return false;
        }
        let tail = &path[plen - needle.len()..plen];
        tail.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    };
    for i in 0..count {
        let off = 8 + i * ENTRY_SIZE;
        if off + ENTRY_SIZE > buf.len() {
            break;
        }
        let entry_ptr = buf.as_ptr().wrapping_add(off) as *const RtlProcessModuleInformation;
        let entry = unsafe { &*entry_ptr };
        if ends_with_ci(&entry.full_path, name) {
            let base = entry.image_base as usize;
            if base == 0 {
                return Err(KrwError::Other(alloc::format!(
                    "{} ImageBase is zero (KASLR restriction — need SeDebugPrivilege)",
                    core::str::from_utf8(name).unwrap_or("<mod>")
                )));
            }
            return Ok(ModuleInfo {
                base,
                size: entry.image_size as usize,
            });
        }
    }
    Err(KrwError::Other(alloc::format!(
        "module {} not found in loaded-kernel-module list",
        core::str::from_utf8(name).unwrap_or("<mod>")
    )))
}
