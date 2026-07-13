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

use std::os::raw::c_char;
use std::sync::atomic::{AtomicUsize, Ordering};

const OUT_CAP: usize = 16 * 1024;
static mut OUT: [u8; OUT_CAP] = [0; OUT_CAP];
static OUT_LEN: AtomicUsize = AtomicUsize::new(0);

/// Reset the capture buffer before running a BOF.
#[no_mangle]
pub extern "C" fn nyx_bof_reset() {
    OUT_LEN.store(0, Ordering::SeqCst);
    unsafe {
        core::ptr::write((&raw mut OUT[0]) as *mut u8, 0);
    }
}

/// Return a pointer to the null-terminated captured output.
#[no_mangle]
pub extern "C" fn nyx_bof_output() -> *const c_char {
    let len = OUT_LEN.load(Ordering::SeqCst);
    if len < OUT_CAP {
        unsafe {
            core::ptr::write((&raw mut OUT[len]) as *mut u8, 0);
        }
    }
    unsafe { (&raw const OUT[0]) as *const c_char }
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
                    if !p.is_null() {
                        let mut si = 0usize;
                        loop {
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
        unsafe {
            core::ptr::write((&raw mut OUT[len]) as *mut u8, b);
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
    for i in pos..buf.len() {
        push_byte(buf[i]);
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
    for i in pos..buf.len() {
        push_byte(buf[i]);
    }
}
