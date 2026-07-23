//! Windows-specific export resolution — `resolve_sym` real binding.
//!
//! Operator-side: the operator host is a normal user-mode process with a
//! normal PEB, so `GetModuleHandleA` + `GetProcAddress` work directly. This
//! replaces the stub `resolve_sym` in `byovd.rs` with a real resolver.
//!
//! We use `#[link(name = "kernel32")]` for the Win32 APIs (CreateFileW,
//! DeviceIoControl, CloseHandle) and `#[link(name = "ntdll")]` for the NT
//! APIs (NtLoadDriver, NtQuerySystemInformation, NtUnloadDriver). On MSVC
//! these link against the import libs; on GNU they resolve via the DLL name.

#![cfg(target_os = "windows")]

use crate::KrwError;
use core::ffi::c_void;

#[allow(dead_code)] // type aliases retained for documentation; code uses extern fns directly
type GetModuleHandleA = unsafe extern "system" fn(*const u8) -> *mut c_void;
#[allow(dead_code)]
type GetProcAddress = unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void;
#[allow(dead_code)]
type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> *mut c_void;

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    #[allow(dead_code)] // retained for future on-demand DLL loading
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
}

/// Resolve a Windows export to a typed function pointer. This is the real
/// binding that replaces the stub in `byovd.rs`.
///
/// `module` is a null-terminated ASCII string (e.g. `b"kernel32.dll\0"`).
/// `name` is a null-terminated ASCII string (e.g. `b"CreateFileW\0"`).
///
/// Returns the function address transmuted to `T`, or an error if the module
/// or export isn't found.
///
/// Note: kernel32/ntdll are always loaded in any Win32 process, so
/// `GetModuleHandleA` finds them. Other DLLs (advapi32, fltlib, …) may not be
/// loaded yet — we fall back to `LoadLibraryA` (kernel32 export, always
/// resolvable via GetModuleHandleA("kernel32")) to map them on demand.
///
/// # Safety
/// Caller must ensure `T` is a valid function pointer type matching the
/// export's actual signature.
pub unsafe fn resolve_sym<T>(module: &[u8], name: &[u8]) -> Result<T, KrwError> {
    // GetModuleHandleA and GetProcAddress expect null-terminated C strings.
    // The callers in byovd.rs pass `b"kernel32.dll"` (no null) — we need to
    // append one. Use a stack buffer (module names are short).
    let mut mod_buf = [0u8; 32];
    let mod_len = module.len().min(mod_buf.len() - 1);
    mod_buf[..mod_len].copy_from_slice(&module[..mod_len]);
    // mod_buf[mod_len] is already 0 (null terminator).

    let mut name_buf = [0u8; 64];
    let name_len = name.len().min(name_buf.len() - 1);
    name_buf[..name_len].copy_from_slice(&name[..name_len]);

    // Try GetModuleHandleA first (no load, works for already-mapped DLLs).
    let mut h = unsafe { GetModuleHandleA(mod_buf.as_ptr()) };
    if h.is_null() {
        // Module not mapped in this process yet (e.g. advapi32). Load it.
        // LoadLibraryA is a kernel32 export — kernel32 is always mapped.
        let load_lib: LoadLibraryAFn = unsafe { get_proc(kernel32_handle()?, b"LoadLibraryA")? };
        h = unsafe { load_lib(mod_buf.as_ptr()) };
        if h.is_null() {
            return Err(KrwError::Unavailable(
                "GetModuleHandleA+LoadLibraryA returned null",
            ));
        }
    }
    let addr = unsafe { GetProcAddress(h, name_buf.as_ptr()) };
    if addr.is_null() {
        return Err(KrwError::Unavailable("GetProcAddress returned null"));
    }
    Ok(unsafe { core::mem::transmute_copy::<*mut c_void, T>(&addr) })
}

/// Cached kernel32 module handle. kernel32.dll is always mapped in a Win32
/// process, so GetModuleHandleA never returns null for it.
fn kernel32_handle() -> Result<*mut c_void, KrwError> {
    let name = b"kernel32.dll";
    let mut buf = [0u8; 16];
    buf[..name.len()].copy_from_slice(name);
    let h = unsafe { GetModuleHandleA(buf.as_ptr()) };
    if h.is_null() {
        Err(KrwError::Unavailable(
            "kernel32.dll not mapped — not a Win32 process?",
        ))
    } else {
        Ok(h)
    }
}

/// Look up an export by name in an already-mapped module.
unsafe fn get_proc<T>(h: *mut c_void, name: &[u8]) -> Result<T, KrwError> {
    let mut buf = [0u8; 64];
    let n = name.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&name[..n]);
    let addr = unsafe { GetProcAddress(h, buf.as_ptr()) };
    if addr.is_null() {
        return Err(KrwError::Unavailable("GetProcAddress returned null"));
    }
    Ok(unsafe { core::mem::transmute_copy::<*mut c_void, T>(&addr) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_kernel32_createfilew() {
        // kernel32 is always loaded; CreateFileW always exists.
        let f: unsafe extern "system" fn(
            *const u16,
            u32,
            u32,
            *mut c_void,
            u32,
            u32,
            *mut c_void,
        ) -> *mut c_void = unsafe { resolve_sym(b"kernel32.dll", b"CreateFileW").unwrap() };
        // We got a non-null function pointer — proves resolution works.
        let _ = f;
    }

    #[test]
    fn resolve_ntdll_ntquerysysteminformation() {
        let f: unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32 =
            unsafe { resolve_sym(b"ntdll.dll", b"NtQuerySystemInformation").unwrap() };
        let _ = f;
    }

    #[test]
    fn nonexistent_export_returns_err() {
        let r: Result<usize, _> = unsafe { resolve_sym(b"kernel32.dll", b"ThisDoesNotExist123") };
        assert!(r.is_err());
    }
}
