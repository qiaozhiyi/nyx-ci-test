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

    for off in (0x00..=sz).step_by(8) {
        let v1 = unsafe { *((init + off) as *const usize) };
        let v2 = unsafe { *((init + off + 8) as *const usize) };
        // CFG bitmap candidates: large VA (> 0x10000), large size (> 0x100000)
        let tag = if v1 > 0x10000 && v1 < 0x700000000000 && v2 > 0x100000 {
            " <-- CFG BITMAP!"
        } else { "" };
        println!("  off=0x{off:03x}: va=0x{v1:016x} sz=0x{v2:016x}{tag}");
    }
}
