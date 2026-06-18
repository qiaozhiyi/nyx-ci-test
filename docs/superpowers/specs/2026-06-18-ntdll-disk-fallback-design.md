# NTDLL pristine-copy disk fallback (P2 evasion)

**Date:** 2026-06-18
**Status:** Approved, implementing
**Roadmap:** P2 evasion — fresh-map unhook fallback

## Problem

On the P2 dev host (Win2019, build 17763.1339), `unhook::fresh_ntdll_text()`
returns `None`: `\KnownDlls\ntdll` cannot be opened (system ACL / section
parse). `Runtime::init` falls back to the **hooked** in-process ntdll
(Halo's/Tartarus' neighbor-walk still recovers most SSNs — confirmed by
`nyx_selftest` → `0xE01`), but the implant loses the pristine `.text` and a
clean `syscall; ret` gadget.

This is a known IOC trade-off: `NtMapViewOfSection` of `SEC_IMAGE` ntdll from a
non-loader process is an ETW-TI signal some EDRs flag. The roadmap P2
alternative is to read a pristine copy from disk
(`%SystemRoot%\System32\ntdll.dll`) — no section-map IOC, but a disk-read IOC.

### Empirical baseline (real Win2019 host, `ssh win`)

| selftest | exit code | meaning |
|---|---|---|
| `nyx_selftest` (phase 0-3) | `0xE01` (3585) | PEB walk + exports + allocator + SSN + crypto **OK** |
| `nyx_selftest_evasion` (phase 4-5) | `0x501` | Phase 4 **failed → fell through**; Phase 5: ETW patched & verified |

`0x501 = 0x500 | 1` — Phase 4 produced **no `0x04XX` band**. This host is the
target scenario.

## Design

New priority chain in the implant bootstrap (`Runtime::init` + selftest Phase 4):

```
1. fresh_ntdll_text()          — KnownDlls SEC_IMAGE map (existing, no disk IOC)
        ↓ None
2. fresh_ntdll_text_disk()     — NEW: read pristine ntdll from disk
        ↓ None
3. hooked in-process ntdll     — existing fallback (Halo/Tartarus neighbor walk)
```

The disk path is isolated in one new function; the SEC_IMAGE fast path is
**unchanged**.

### Locked decisions

1. **Text source shape:** read the raw file into a heap `Vec<u8>`, expose via a
   new `DiskTextSource` whose `read(rva)` does RVA→file-offset translation. The
   SEC_IMAGE `FreshTextSource::read(rva)` does `base.add(rva)` (RVA = direct
   offset); a raw on-disk PE is **not** section-mapped, so `.text` RVA
   (e.g. `0x1000`) ≠ file offset (e.g. `0x600`). Distinct source type.
2. **File I/O API:** Win32 `CreateFileW` + `ReadFile` + `CloseHandle`. Path via
   `kernel32!GetSystemDirectoryW` (follows non-`C:` installs). No
   `NtMapViewOfSection`, no section object — deliberately different/weaker IOC.
3. **Selftest report:** add a new `0x0B00 + D` band for the disk path (D =
   byte-diff vs hooked). `0x0400 + D` (KnownDlls), `0x0500 | mask` (blind),
   `0x0FFF` (both fail) unchanged.

## New components

### `unhook.rs` — public additions

- `fresh_ntdll_text_disk() -> Option<DiskTextHandle>` — reads the raw file into
  a heap `Vec<u8>`, parses the section table, returns a handle owning the buffer
  + `.text` (rva, size). `None` on open/read/parse failure.
- `DiskTextSource` — implements `nyx_evasion::SyscallSource`; `read(rva, len)`
  translates RVA→file-offset then slices the heap buffer. Borrows the handle.
- `DiskTextHandle` — owns `Vec<u8>` + section table + `.text` (rva, size). Plain
  `Vec` → drops automatically (no RAII guard, no `unmap_fresh` — disk path is
  simpler than SEC_IMAGE).

### `unhook.rs` — private helpers

- `read_ntdll_file() -> Option<Vec<u8>>` — `GetSystemDirectoryW` → build
  `<dir>\ntdll.dll` wide path → `CreateFileW`/`ReadFile`/`CloseHandle`, loop to
  EOF or a ~2 MiB cap (defense vs a hostile server-influenced size).
- `rva_to_file_offset(sections, rva) -> Option<usize>` — bounds-checked
  RVA→offset walk. `pe` crate has this but is (a) private and (b) not a dep of
  `implant-win`; reimplemented inline (~12 lines, matches module style).
- `parse_sections_raw(image) -> Option<Vec<RawSection>>` — same section-table
  walk as `parse_text_section` but also captures `PointerToRawData` (the file
  offset the disk path needs). Existing `parse_text_section` unchanged.

## Integration points

### `syscalls.rs::Runtime::init`

```rust
match crate::unhook::fresh_ntdll_text() {
    Some(...) => { /* SEC_IMAGE path — unchanged */ }
    None => match crate::unhook::fresh_ntdll_text_disk() {
        Some(handle) => {
            // NEW disk path: DiskTextSource + scan_syscall_gadget_range over &handle.buf
        }
        None => { /* hooked ntdll fallback — unchanged */ }
    }
}
```

Names/RVAs still come from the hooked in-process ntdll (names are hook-proof —
inline hooks patch stub bytes, never the export directory). Disk path reuses
`scan_syscall_gadget_range` (operate on `&handle.buf`) + `nyx_evasion::resolve_table`.

### `entry.rs::nyx_selftest_evasion` Phase 4

```rust
match fresh_ntdll_text() {
    Some(...) => report 0x0400 + D   // unchanged
    None => match fresh_ntdll_text_disk() {
        Some(handle) => report 0x0B00 + D   // NEW: disk path worked
        None => fall through to Phase 5     // both failed
    }
}
```

`0x0B00 + D` is disjoint from `0x0400` (KnownDlls), `0x0500` (blind),
`0x0FFF` (both fail), and the `0x600/0x100/0xE00/0xF00` bands.

### `crates/implant-win/README.md:42`

Update the evasion-table row from "KnownDlls only — avoids IOC" to an honest
KnownDlls-first / disk-fallback statement with the IOC trade-off.

## IOC honesty

- **Disk path IOC:** a non-loader process reading `System32\ntdll.dll` is a
  known (weaker than `NtMapViewOfSection` mapping `SEC_IMAGE` `KnownDlls\ntdll`)
  EDR signal. The read goes through the normal kernel32 `CreateFileW`/`ReadFile`
  path (no section map), so it lacks the ETW-TI `NtMapViewOfSection(SEC_IMAGE)`
  telemetry that makes the KnownDlls map uniquely suspect.
- **Trade-off:** KnownDlls = in-memory (no disk IOC) but section-map IOC; disk =
  disk-read IOC but no section-map IOC. Chain tries least-suspicious first; disk
  only fires when it fails (as on this host).
- Disk path runs once at bootstrap (resolve only); buffer dropped after.
  Steady-state beacon never touches it (same as SEC_IMAGE path).

## Success criteria (empirical, not "it compiles")

1. Build on Windows stays clean (no new warnings beyond the 5 pre-existing).
2. On this Win2019 host, `nyx_selftest_evasion`: `0x501` → `0x0B00 + D`, D > 0
   (disk read pristine bytes; hooked in-process ntdll differs — proves the
   clean copy was actually used).
3. `nyx_selftest` still returns `0xE01` (no regression).
4. `cargo test --workspace` stays green on macOS dev host.

## Rejected alternatives

- **`NtCreateSection` + `NtMapViewOfSection` over the file handle:** rejected —
  that's *another* `NtMapViewOfSection` call with the same ETW-TI IOC as the
  KnownDlls path that just failed, plus a file open. Defeats the "different
  IOC" goal.
- **Silent fold (no new selftest code):** rejected — the objective is
  diagnostic (why KnownDlls was skipped); the `0x0B00` band makes the disk path
  observable.
