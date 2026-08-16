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
    first_module(&buf)
}

/// x64 size of one RTL_PROCESS_MODULE_INFORMATION entry (see struct note).
const ENTRY_SIZE: usize = 296;

/// Parse the module count from a SystemModuleInformation buffer.
fn parse_module_count(buf: &[u8]) -> Result<usize, KrwError> {
    if buf.len() < 8 {
        return Err(KrwError::Other(
            "NtQuerySystemInformation buffer too short".into(),
        ));
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize)
}

/// Borrow entry `i` from a SystemModuleInformation buffer. Module[0] is at
/// offset 8 (count ULONG + 4 padding bytes on x64).
fn module_entry(buf: &[u8], i: usize) -> Option<&RtlProcessModuleInformation> {
    let off = 8 + i * ENTRY_SIZE;
    if off + ENTRY_SIZE > buf.len() {
        return None;
    }
    let entry_ptr = buf.as_ptr().wrapping_add(off) as *const RtlProcessModuleInformation;
    // SAFETY: bounds checked above; layout is the documented C struct.
    Some(unsafe { &*entry_ptr })
}

/// Pure parse: `(base, size)` of Module[0] (ntoskrnl.exe by convention).
fn first_module(buf: &[u8]) -> Result<(usize, usize), KrwError> {
    let count = parse_module_count(buf)?;
    if count == 0 {
        return Err(KrwError::Other(
            "NtQuerySystemInformation returned 0 modules".into(),
        ));
    }
    let entry = module_entry(buf, 0)
        .ok_or_else(|| KrwError::Other("buffer too short for first module entry".into()))?;
    let base = entry.image_base as usize;
    if base == 0 {
        return Err(KrwError::Unavailable(
            "ntoskrnl ImageBase is zero (Win11 24H2+ KASLR restriction — need SeDebugPrivilege or fallback)",
        ));
    }
    Ok((base, entry.image_size as usize))
}

/// ASCII case-insensitive "does the NUL-padded `full_path` end with `needle`".
fn path_ends_with_ci(path: &[u8; 256], needle: &[u8]) -> bool {
    let plen = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    if plen < needle.len() {
        return false;
    }
    let tail = &path[plen - needle.len()..plen];
    tail.iter()
        .zip(needle.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// File name = bytes after the last path separator, NUL-stripped, lowercased.
fn entry_file_name(entry: &RtlProcessModuleInformation) -> alloc::vec::Vec<u8> {
    let plen = entry
        .full_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(entry.full_path.len());
    let mut start = 0usize;
    for (idx, &b) in entry.full_path[..plen].iter().enumerate() {
        if b == b'\\' || b == b'/' {
            start = idx + 1;
        }
    }
    entry.full_path[start..plen]
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect()
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
    find_module_by_name(&buf, name)
}

/// Pure parse: `(base, size)` of the first module whose full path ends with
/// `name` (case-insensitive), e.g. `b"fltmgr.sys"`.
fn find_module_by_name(buf: &[u8], name: &[u8]) -> Result<ModuleInfo, KrwError> {
    let count = parse_module_count(buf)?;
    for i in 0..count {
        let Some(entry) = module_entry(buf, i) else {
            break;
        };
        if path_ends_with_ci(&entry.full_path, name) {
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

/// One entry from the loaded-kernel-module list, returned by [`loaded_modules`].
pub struct LoadedModule {
    pub base: usize,
    pub size: usize,
    /// Lowercased ASCII file name (e.g. `b"ntoskrnl.exe"`, `b"fltmgr.sys"`),
    /// derived from the entry's full path tail. Safe to feed the EDR driver-name
    /// matcher in `win::assess`.
    pub name: alloc::vec::Vec<u8>,
}

/// Enumerate ALL loaded kernel modules (NtQuerySystemInformation class 11).
///
/// Unlike [`ntoskrnl_module_info`] / [`module_info_by_name`] (which return a
/// single module), this returns the full list — used by the kernel assessment
/// (`win::assess`) to count drivers and match EDR driver names. Module[0] is
/// ntoskrnl.exe; drivers follow.
///
/// # Safety
/// Same NtQuerySystemInformation contract as [`ntoskrnl_module_info`].
pub unsafe fn loaded_modules() -> Result<alloc::vec::Vec<LoadedModule>, KrwError> {
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
    parse_module_list(&buf)
}

/// Pure parse: the full loaded-module list (names lowercased file tails).
fn parse_module_list(buf: &[u8]) -> Result<alloc::vec::Vec<LoadedModule>, KrwError> {
    let count = parse_module_count(buf)?;
    let mut out = alloc::vec::Vec::with_capacity(count.min(1024));
    for i in 0..count {
        let Some(entry) = module_entry(buf, i) else {
            break;
        };
        out.push(LoadedModule {
            base: entry.image_base as usize,
            size: entry.image_size as usize,
            name: entry_file_name(entry),
        });
    }
    if out.is_empty() {
        return Err(KrwError::Other(
            "NtQuerySystemInformation returned 0 modules".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The parser's fixed stride must match the actual C layout — if the
    /// struct definition drifts, every offset below is wrong.
    #[test]
    fn entry_size_matches_struct_layout() {
        assert_eq!(
            core::mem::size_of::<RtlProcessModuleInformation>(),
            ENTRY_SIZE
        );
    }

    /// Build a synthetic SystemModuleInformation buffer: count ULONG + 4 pad
    /// bytes, then packed 296-byte entries (base, size, full_path).
    fn module_buf(entries: &[(usize, u32, &[u8])]) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 8 + entries.len() * ENTRY_SIZE];
        buf[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, (base, size, path)) in entries.iter().enumerate() {
            let off = 8 + i * ENTRY_SIZE;
            buf[off + 16..off + 24].copy_from_slice(&base.to_le_bytes()); // image_base
            buf[off + 24..off + 28].copy_from_slice(&size.to_le_bytes()); // image_size
            buf[off + 40..off + 40 + path.len()].copy_from_slice(path); // full_path
        }
        buf
    }

    #[test]
    fn first_module_returns_ntoskrnl_base_and_size() {
        let buf = module_buf(&[
            (
                0xFFFF_8000_1000_0000,
                0xC0_0000,
                b"\\SystemRoot\\System32\\ntoskrnl.exe",
            ),
            (
                0xFFFF_8000_2000_0000,
                0x8_0000,
                b"\\SystemRoot\\System32\\drivers\\FLTMGR.SYS",
            ),
        ]);
        let (base, size) = first_module(&buf).unwrap();
        assert_eq!(base, 0xFFFF_8000_1000_0000);
        assert_eq!(size, 0xC0_0000);
    }

    #[test]
    fn first_module_rejects_zero_base_and_empty_list() {
        // Win11 24H2+ KASLR restriction: ImageBase zeroed → Unavailable.
        let buf = module_buf(&[(0, 0xC0_0000, b"\\SystemRoot\\System32\\ntoskrnl.exe")]);
        assert!(matches!(first_module(&buf), Err(KrwError::Unavailable(_))));
        // Zero modules.
        let buf = module_buf(&[]);
        assert!(matches!(first_module(&buf), Err(KrwError::Other(_))));
        // Truncated buffer.
        assert!(matches!(first_module(&buf[..4]), Err(KrwError::Other(_))));
    }

    #[test]
    fn find_module_by_name_matches_case_insensitive_tail() {
        let buf = module_buf(&[
            (
                0xFFFF_8000_1000_0000,
                0xC0_0000,
                b"\\SystemRoot\\System32\\ntoskrnl.exe",
            ),
            (
                0xFFFF_8000_2000_0000,
                0x8_0000,
                b"\\SystemRoot\\System32\\drivers\\FLTMGR.SYS",
            ),
            (0xFFFF_8000_4000_0000, 0x2_0000, b"\\??\\C:\\EDR\\edr.sys"),
        ]);
        // Uppercase path, lowercase query → hit.
        let m = find_module_by_name(&buf, b"fltmgr.sys").unwrap();
        assert_eq!(m.base, 0xFFFF_8000_2000_0000);
        assert_eq!(m.size, 0x8_0000);
        // Not loaded → clear error, never a zero-base false success.
        assert!(matches!(
            find_module_by_name(&buf, b"clfsw32.sys"),
            Err(KrwError::Other(_))
        ));
        // Name must match the TAIL, not a prefix substring.
        assert!(matches!(
            find_module_by_name(&buf, b"System32"),
            Err(KrwError::Other(_))
        ));
    }

    #[test]
    fn parse_module_list_lowercases_file_tails() {
        let buf = module_buf(&[
            (
                0xFFFF_8000_1000_0000,
                0xC0_0000,
                b"\\SystemRoot\\System32\\ntoskrnl.exe",
            ),
            (
                0xFFFF_8000_2000_0000,
                0x8_0000,
                b"\\SystemRoot\\System32\\drivers\\FLTMGR.SYS",
            ),
            (
                0xFFFF_8000_4000_0000,
                0x2_0000,
                b"\\??\\C:\\EDR\\EdrSensor.sys",
            ),
        ]);
        let mods = parse_module_list(&buf).unwrap();
        assert_eq!(mods.len(), 3);
        assert_eq!(mods[0].name, b"ntoskrnl.exe");
        assert_eq!(mods[1].name, b"fltmgr.sys");
        assert_eq!(mods[2].name, b"edrsensor.sys");
        assert_eq!(mods[2].base, 0xFFFF_8000_4000_0000);
    }
}
