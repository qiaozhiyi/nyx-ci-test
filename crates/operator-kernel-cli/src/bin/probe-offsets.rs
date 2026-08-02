#![cfg_attr(not(target_os = "windows"), allow(dead_code))]
use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleA(n: *const u8) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
}

#[cfg(target_os = "windows")]
fn main() {
    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast::<u8>()) };
    let init = unsafe { GetProcAddress(ntdll, c"LdrSystemDllInitBlock".as_ptr().cast::<u8>()) } as usize;
    let sz = unsafe { *(init as *const u32) } as usize;
    println!("LdrSystemDllInitBlock size=0x{sz:x}");

    for off in (0x40..=0xA0).step_by(8) {
        let v1 = unsafe { *((init + off) as *const usize) };
        let v2 = unsafe { *((init + off + 8) as *const usize) };
        let tag = if v1 > 0x10000 && v1 < 0x7FFFFFFFFFFF && v2 > 0x1000 {
            " <-- CFG bitmap candidate"
        } else { "" };
        println!("  off=0x{off:02x}: va=0x{v1:016x} sz=0x{v2:016x}{tag}");
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("probe-offsets: Windows-only diagnostic; nothing to do on this host");
}
