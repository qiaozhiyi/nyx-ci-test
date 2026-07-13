//! The Windows loader + executor.
//!
//! Loads COFF BOFs into RWX memory, resolves externals (BeaconPrintf shim),
//! applies AMD64 relocations, calls `go()`, and captures output.
//!
//! ## REL32 trampoline
//! BOF sections are loaded via `VirtualAlloc` at low addresses while the
//! Beacon-API shim lives in the DLL at a high address — often >2 GiB apart,
//! exceeding the REL32 range. We allocate a small trampoline page near the
//! BOF that does an absolute `jmp` to the real shim, and expose the trampoline
//! as the `BeaconPrintf` external symbol.

use std::collections::HashMap;
use std::ffi::c_void;

use nyx_coff::{apply, parse, SymbolResolver};

extern "system" {
    fn VirtualAlloc(
        addr: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
}
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_SIZE: usize = 0x1000;

fn page(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub struct Resolver {
    pub externals: HashMap<String, u64>,
    pub defined: HashMap<String, u64>,
}

impl SymbolResolver for Resolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        self.defined
            .get(name)
            .copied()
            .or_else(|| self.externals.get(name).copied())
    }
}

pub struct Loaded {
    pub defined: HashMap<String, u64>,
    pub entry: u64,
}

pub fn load(blob: &[u8], entry: &str, externals: HashMap<String, u64>) -> Result<Loaded, String> {
    let coff = parse(blob).map_err(|e| format!("parse: {e:?}"))?;

    let total: usize = coff
        .sections
        .iter()
        .map(|s| page((s.virtual_size.max(s.raw.len() as u32)) as usize))
        .sum::<usize>()
        .max(PAGE_SIZE);

    let base = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if base.is_null() {
        return Err("VirtualAlloc failed".into());
    }

    let mut bases: Vec<u64> = Vec::with_capacity(coff.sections.len());
    let mut offset = 0usize;
    for s in &coff.sections {
        let addr = unsafe { (base as *mut u8).add(offset) } as u64;
        bases.push(addr);
        if !s.raw.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(s.raw.as_ptr(), addr as *mut u8, s.raw.len()) };
        }
        offset += page((s.virtual_size.max(s.raw.len() as u32)) as usize);
    }

    let mut defined: HashMap<String, u64> = HashMap::new();
    for sym in &coff.symbols {
        if sym.section_number >= 1 && (sym.section_number as usize) <= bases.len() {
            let addr = bases[(sym.section_number - 1) as usize] + sym.value as u64;
            defined.insert(sym.name.clone(), addr);
        }
    }

    let resolver = Resolver {
        externals,
        defined: defined.clone(),
    };
    for (i, s) in coff.sections.iter().enumerate() {
        if s.relocations.is_empty() {
            continue;
        }
        let patched = apply(s, &coff, bases[i], &resolver)
            .map_err(|e| format!("reloc `{}`: {:?}", s.name, e))?;
        unsafe {
            std::ptr::copy_nonoverlapping(patched.as_ptr(), bases[i] as *mut u8, patched.len())
        };
    }

    let entry_sym = coff
        .symbols
        .iter()
        .find(|s| s.name == entry)
        .ok_or_else(|| format!("entry symbol `{entry}` not found"))?;
    if entry_sym.section_number < 1 {
        return Err(format!("entry `{entry}` is external/undefined"));
    }
    let entry_addr = bases[(entry_sym.section_number - 1) as usize] + entry_sym.value as u64;

    Ok(Loaded {
        defined,
        entry: entry_addr,
    })
}

// ── trampoline ──────────────────────────────────────────────────────────────

/// Allocate a small trampoline page near `near_addr` and write an absolute
/// indirect jump (`jmp [rip+0]` + 8-byte target) to `target`. Returns the
/// trampoline's address, or falls back to `target` if allocation fails.
fn alloc_trampoline(near_addr: u64, target: u64) -> u64 {
    let hint = near_addr.saturating_sub(0x1000_0000); // 256 MiB below
    unsafe {
        let ptr = try_alloc_tramp(hint as *mut c_void);
        let ptr = if ptr.is_null() {
            try_alloc_tramp(std::ptr::null_mut())
        } else {
            ptr
        };
        if ptr.is_null() {
            return target;
        }
        let tramp = ptr as u64;
        write_trampoline(tramp, target);
        tramp
    }
}

unsafe fn try_alloc_tramp(hint: *mut c_void) -> *mut c_void {
    VirtualAlloc(
        hint,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
}

/// Write `jmp [rip+0]; dq <target>` at `addr`.
unsafe fn write_trampoline(addr: u64, target: u64) {
    let p = addr as *mut u8;
    // ff 25 00 00 00 00 = jmp [rip+0]
    core::ptr::write(p, 0xffu8);
    core::ptr::write(p.add(1), 0x25u8);
    core::ptr::write(p.add(2), 0x00u8);
    core::ptr::write(p.add(3), 0x00u8);
    core::ptr::write(p.add(4), 0x00u8);
    core::ptr::write(p.add(5), 0x00u8);
    // 8-byte absolute target (little-endian)
    core::ptr::write(p.add(6) as *mut u64, target);
}

// ── Beacon-API table ────────────────────────────────────────────────────────

/// Build the Beacon-API external table. `near_addr` should be near the BOF's
/// allocated memory so REL32 relocations can reach the trampoline.
fn beacon_apis(near_addr: u64) -> HashMap<String, u64> {
    let real = crate::shim::BeaconPrintf as *const () as usize as u64;
    let tramp = alloc_trampoline(near_addr, real);
    [("BeaconPrintf".to_string(), tramp)].into_iter().collect()
}

// ── execute ─────────────────────────────────────────────────────────────────

pub struct ExecResult {
    pub output: String,
    pub defined: HashMap<String, u64>,
}

/// Load + run a BOF's `go()`: wire up Beacon-API, reset output, call `go`,
/// return captured output.
pub fn execute(blob: &[u8]) -> Result<ExecResult, String> {
    // Use a dummy address to seed the trampoline allocator — we need a hint
    // near where the BOF will be loaded. Allocate a small scratch page first
    // to anchor the hint, then pass that to beacon_apis so the trampoline
    // lands near the BOF sections.
    let hint_page = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    let near = if hint_page.is_null() {
        0
    } else {
        hint_page as u64
    };

    let apis = beacon_apis(near);
    let loaded = load(blob, "go", apis)?;
    unsafe {
        crate::shim::nyx_bof_reset();
        let go: extern "C" fn() = std::mem::transmute(loaded.entry);
        go();
        let output = std::ffi::CStr::from_ptr(crate::shim::nyx_bof_output())
            .to_string_lossy()
            .into_owned();
        Ok(ExecResult {
            output,
            defined: loaded.defined,
        })
    }
}
