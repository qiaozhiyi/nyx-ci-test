#![cfg(target_os = "windows")]
// Read LdrpValidateUserCallTarget code to find CFG bitmap pointer.
use std::ffi::c_void;

extern "system" {
    fn GetModuleHandleA(n: *const u8) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
}

fn main() {
    let ntdll = unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr()) };
    let ldrp = unsafe {
        GetProcAddress(ntdll, "LdrpValidateUserCallTarget\0".as_ptr())
    } as *const u8;
    if ldrp.is_null() {
        println!("LdrpValidateUserCallTarget NOT FOUND (may not be exported)");
        // Try LdrpCfgProcessLoadConfig instead
        return;
    }
    println!("LdrpValidateUserCallTarget at {:p}", ldrp);

    // Disassemble: look for RIP-relative load of the CFG bitmap pointer.
    // Pattern: mov rax/reg, [rip + offset]  or  lea reg, [rip + offset]
    // On x64, RIP-relative loads are: 48 8B 05 XX XX XX XX (mov rax, [rip+disp32])
    let code = unsafe { std::slice::from_raw_parts(ldrp, 128) };
    for i in 0..code.len().saturating_sub(6) {
        // mov rax/rbx/rcx/rdx, [rip + disp32]
        if code[i] == 0x48 && code[i+1] == 0x8B && (code[i+2] & 0xC7) == 0x05 {
            let reg = (code[i+2] >> 3) & 7;
            let disp = i32::from_le_bytes([code[i+3], code[i+4], code[i+5], code[i+6]]);
            let target = unsafe { ldrp.add(i + 7).offset(disp as isize) };
            let val = unsafe { *(target as *const usize) };
            let regs = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"];
            println!("  +{}: mov {}, [rip{:+}] -> {:p} = 0x{:016x}",
                i, regs[reg as usize], disp, target, val);
        }
    }
}
