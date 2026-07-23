#![cfg(target_os = "windows")]
use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleA(n: *const u8) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
}

fn main() {
    let ntdll = unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr()) };
    let init = unsafe { GetProcAddress(ntdll, "LdrSystemDllInitBlock\0".as_ptr()) } as usize;
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
