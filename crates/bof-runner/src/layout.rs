//! Host-testable section-layout + externals-table logic for the BOF loader.
//!
//! `win.rs` (Windows-only) consumes these pure functions and constants; this
//! module is deliberately NOT `cfg(target_os = "windows")` so `cargo test` on
//! any host exercises the section-mapping / protection decisions and the
//! trampoline-table layout against the real COFF fixtures in
//! `tests/fixtures/`.

/// `IMAGE_SCN_MEM_EXECUTE` — marks a code section (`.text`).
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `PAGE_READWRITE` — every section is allocated with the write window open
/// (W^X); data sections keep this protection for the whole run.
pub const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_EXECUTE_READ` — code sections are flipped to this (via
/// `VirtualProtect`) after relocations are applied, before `go()` is invoked.
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_SIZE: usize = 0x1000;

/// True if a COFF section carries `IMAGE_SCN_MEM_EXECUTE` — i.e. it holds code
/// and must be executable by the time `go()` runs.
pub fn is_code(characteristics: u32) -> bool {
    characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

/// The protection to apply to a section once relocations are done (W^X): code
/// sections become `PAGE_EXECUTE_READ`; everything else stays
/// `PAGE_READWRITE`. At no point after this is a section simultaneously
/// writable and executable.
pub fn final_protection(characteristics: u32) -> u32 {
    if is_code(characteristics) {
        PAGE_EXECUTE_READ
    } else {
        PAGE_READWRITE
    }
}

/// Round `n` up to the next page boundary. `0` maps to `0` (an empty section
/// occupies no pages).
pub fn page_align(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ── REL32 trampoline table layout ───────────────────────────────────────────
//
// BOF sections are `VirtualAlloc`-ed at low addresses while the Beacon-API
// shim and the resolved kernel32/ntdll exports live at high addresses — often
// >2 GiB apart, which overflows the REL32 relocations the BOF uses to call
// them. The loader therefore allocates ONE shared trampoline page near the BOF
// and writes one absolute-jump stub per external symbol into it; the externals
// table maps each symbol name to its stub address.

/// One stub is `jmp [rip+0]` (6 bytes: `ff 25 00 00 00 00`) + an 8-byte
/// little-endian absolute target = 14 bytes.
pub const TRAMP_STUB_LEN: usize = 14;
/// Stride between stubs in the shared trampoline page: the stub length
/// rounded up to a 16-byte slot. Keeps the stubs at stable,
/// cache-line-friendly offsets (the 8-byte target of each stub is
/// deliberately written with `write_unaligned`; see `win::write_trampoline`).
pub const TRAMP_STUB_STRIDE: usize = TRAMP_STUB_LEN.div_ceil(16) * 16;
/// Maximum number of stubs that fit in one trampoline page.
pub const TRAMP_STUBS_PER_PAGE: usize = PAGE_SIZE / TRAMP_STUB_STRIDE;

/// Offset of stub `i` within the trampoline page.
pub fn tramp_stub_offset(index: usize) -> usize {
    index * TRAMP_STUB_STRIDE
}

// ── Externals table (names only; `win.rs` resolves them to addresses) ───────

/// Beacon-API shim names the loader resolves to the in-Rust shims in
/// `win.rs` (one trampoline stub each). This is the core CS `beacon.h`
/// surface: `BeaconPrintf` plus the `datap` argument parser, `BeaconIsAdmin`,
/// `BeaconGetSpawnTo`, the token family (`BeaconUseToken` /
/// `BeaconRevertToken`), the spawn family (`BeaconSpawnTemporaryProcess` /
/// `BeaconCleanupProcess`), the inject family (`BeaconInjectProcess` /
/// `BeaconInjectTemporaryProcess`), and the community `BeaconOutput`
/// extension. Each name appears exactly once (enforced by a test).
///
/// The inject family is implemented in the std Windows host (`shim.rs`) as
/// a real RW→RX write+execute chain. The PIC `bof-host` keeps the same
/// names **unresolved** (kernel32 is not mapped in the sacrificial child).
pub const BEACON_APIS: &[&str] = &[
    "BeaconPrintf",
    "BeaconOutput",
    "BeaconDataParse",
    "BeaconDataExtract",
    "BeaconDataInt",
    "BeaconDataShort",
    "BeaconDataLength",
    "BeaconIsAdmin",
    "BeaconGetSpawnTo",
    "BeaconUseToken",
    "BeaconRevertToken",
    "BeaconSpawnTemporaryProcess",
    "BeaconCleanupProcess",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
];

/// kernel32/ntdll exports resolved at load time via `GetModuleHandleA` +
/// `GetProcAddress`, as `(module, export name)` pairs. Each name appears at
/// most once in this list (enforced by a test); the first module in the pair
/// is the one it is resolved from.
pub const EXTERN_SINGLES: &[(&str, &str)] = &[
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetModuleHandleW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "VirtualFree"),
    ("kernel32.dll", "VirtualQuery"),
    ("kernel32.dll", "GetLastError"),
    ("kernel32.dll", "GetModuleFileNameA"),
    ("kernel32.dll", "GetModuleFileNameW"),
    ("kernel32.dll", "GetSystemDirectoryA"),
    ("kernel32.dll", "GetSystemDirectoryW"),
    ("kernel32.dll", "GetTempPathA"),
    ("kernel32.dll", "GetTempPathW"),
    ("kernel32.dll", "GetCurrentProcess"),
    ("kernel32.dll", "GetCurrentProcessId"),
    ("kernel32.dll", "GetCurrentThread"),
    ("kernel32.dll", "GetCurrentThreadId"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "GetTickCount"),
    ("kernel32.dll", "GetTickCount64"),
    ("kernel32.dll", "CreateFileA"),
    ("kernel32.dll", "CreateFileW"),
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "CloseHandle"),
    ("kernel32.dll", "GetFileSize"),
    ("kernel32.dll", "GetFileAttributesA"),
    ("kernel32.dll", "GetFileAttributesW"),
    ("kernel32.dll", "DeleteFileA"),
    ("kernel32.dll", "DeleteFileW"),
    ("kernel32.dll", "MoveFileA"),
    ("kernel32.dll", "MoveFileW"),
    ("kernel32.dll", "HeapAlloc"),
    ("kernel32.dll", "HeapFree"),
    ("kernel32.dll", "GetProcessHeap"),
    ("kernel32.dll", "GetCommandLineA"),
    ("kernel32.dll", "GetCommandLineW"),
    ("kernel32.dll", "GetEnvironmentVariableA"),
    ("kernel32.dll", "GetEnvironmentVariableW"),
    ("kernel32.dll", "GetComputerNameA"),
    ("kernel32.dll", "GetComputerNameW"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "TerminateProcess"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "VirtualProtectEx"),
    ("kernel32.dll", "VirtualFreeEx"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("ntdll.dll", "RtlMoveMemory"),
    ("ntdll.dll", "RtlZeroMemory"),
    ("ntdll.dll", "RtlFillMemory"),
    ("ntdll.dll", "RtlAllocateHeap"),
    ("ntdll.dll", "RtlFreeHeap"),
    ("ntdll.dll", "RtlGetCurrentPeb"),
];

/// CRT "memcpy family" names. These are resolved from the first module in
/// [`CRT_MODULES`] (in order) that exports them. They are stateless, so
/// whichever loaded CRT implementation wins is ABI-compatible for a BOF.
pub const CRT_NAMES: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strcat",
    "strstr",
    "strchr",
    "strrchr",
    "strtol",
    "atoi",
    "sprintf",
    "snprintf",
    "vsnprintf",
    "sscanf",
];

/// Modules searched (in order) for the [`CRT_NAMES`] exports. `kernel32` and
/// `ntdll` never export these on real Windows (Wine may), so the CRT modules
/// are the effective sources; searching first is harmless.
pub const CRT_MODULES: &[&str] = &["kernel32.dll", "ntdll.dll", "msvcrt.dll", "ucrtbase.dll"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_flag_is_the_exact_bit() {
        // clang `.text`: IMAGE_SCN_CNT_CODE | EXECUTE | READ | ALIGN_16BYTES.
        assert!(is_code(0x6050_0020));
        // `.data`: CNT_INITIALIZED_DATA | READ | WRITE | ALIGN_16BYTES.
        assert!(!is_code(0xc050_0040));
        assert!(!is_code(0));
        assert!(!is_code(0x0000_0020)); // CNT_CODE alone, no EXECUTE
    }

    #[test]
    fn protection_maps_code_to_rx_data_to_rw() {
        assert_eq!(final_protection(0x6050_0020), PAGE_EXECUTE_READ);
        assert_eq!(final_protection(0xc050_0040), PAGE_READWRITE);
        assert_eq!(final_protection(0), PAGE_READWRITE);
    }

    #[test]
    fn page_align_rounds_up() {
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), PAGE_SIZE);
        assert_eq!(page_align(PAGE_SIZE), PAGE_SIZE);
        assert_eq!(page_align(PAGE_SIZE + 1), 2 * PAGE_SIZE);
        assert_eq!(page_align(0x1234), 0x2000);
    }

    #[test]
    fn trampoline_stub_layout_fits_one_page() {
        assert_eq!(TRAMP_STUB_LEN, 14); // ff 25 00 00 00 00 + 8-byte target
        assert_eq!(tramp_stub_offset(0), 0);
        assert_eq!(tramp_stub_offset(1), TRAMP_STUB_STRIDE);
        // The whole table fits in one page: last stub ends before PAGE_SIZE.
        let last_end = tramp_stub_offset(TRAMP_STUBS_PER_PAGE - 1) + TRAMP_STUB_LEN;
        assert!(last_end <= PAGE_SIZE);
        assert_eq!(TRAMP_STUBS_PER_PAGE, PAGE_SIZE / TRAMP_STUB_STRIDE);
    }

    #[test]
    fn externals_have_unique_names() {
        // A duplicate name would silently shadow in the externals HashMap —
        // whichever entry landed last wins. The resolver table must be exact.
        let mut names: Vec<&str> = EXTERN_SINGLES.iter().map(|(_, n)| *n).collect();
        names.extend_from_slice(CRT_NAMES);
        names.sort_unstable();
        for w in names.windows(2) {
            assert_ne!(w[0], w[1], "duplicate external name `{}`", w[0]);
        }
        // Sanity: the whole table plus the Beacon-API shims fits in one
        // trampoline page.
        assert!(names.len() + BEACON_APIS.len() <= TRAMP_STUBS_PER_PAGE);
        // The CRT lists must be well-formed (non-empty, no blank entries).
        assert!(!CRT_NAMES.is_empty());
        assert!(!CRT_MODULES.is_empty());
        assert!(CRT_NAMES.iter().all(|n| !n.is_empty()));
        assert!(CRT_MODULES.iter().all(|m| !m.is_empty()));
    }

    #[test]
    fn beacon_apis_have_unique_names() {
        // Same shadowing hazard as the externals table, and none of the shim
        // names may collide with a kernel32/ntdll/CRT export name.
        let mut names: Vec<&str> = BEACON_APIS.to_vec();
        names.sort_unstable();
        for w in names.windows(2) {
            assert_ne!(w[0], w[1], "duplicate Beacon-API name `{}`", w[0]);
        }
        for &n in BEACON_APIS {
            assert!(!EXTERN_SINGLES.iter().any(|(_, e)| *e == n));
            assert!(!CRT_NAMES.contains(&n));
        }
    }

    #[test]
    fn inject_family_is_registered() {
        // A missing name would load-fail community BOFs with a loud
        // Unresolved — the previous deliberate omission. Both names must
        // sit in the table (and therefore in win.rs::beacon_shim_addr).
        assert!(BEACON_APIS.contains(&"BeaconInjectProcess"));
        assert!(BEACON_APIS.contains(&"BeaconInjectTemporaryProcess"));
    }
}
