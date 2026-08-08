//! Reachability closure + compaction + displacement re-patching.
//!
//! Produces `pic-loader.bin` from a built `nyx_pic_loader.dll`:
//!
//! 1. Walk `.text` from the exported `nyx_layer2_entry`, following direct
//!    calls/jumps and fallthrough (a BFS over decoded instructions).
//! 2. Collect every RIP-relative data reference made by reachable code.
//! 3. Re-layout: reachable code first (entry prologue at offset 0, then the
//!    rest in original address order), then 16-byte-aligned copies of every
//!    referenced data constant.
//! 4. Re-patch every RIP-relative disp32 and every direct branch displacement
//!    to the new layout (rel8 branches are safe: compaction only shrinks
//!    distances).
//! 5. Validate: entry at offset 0, no unresolved references, no absolute
//!    addressing, no memory-indirect calls (IAT thunks), no relocations in the
//!    source image, no writes to the data block (blob stays RX-safe).

use crate::decoder::{self, Decoded, Kind};
use crate::pe::Pe;
use std::collections::{BTreeMap, BTreeSet};

pub struct DumpOpts {
    /// Exported entry name.
    pub entry_name: &'static str,
    /// Print every patched displacement for debugging.
    pub debug: bool,
}

#[derive(Debug)]
pub struct DumpError(pub String);

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn fail<T>(msg: impl Into<String>) -> Result<T, DumpError> {
    Err(DumpError(msg.into()))
}

/// One decoded instruction.
struct Insn {
    va: u64,
    bytes: Vec<u8>,
    decoded: Decoded,
}

pub fn dump(pe: &Pe, opts: &DumpOpts) -> Result<Vec<u8>, DumpError> {
    let text = pe.section(".text").ok_or(DumpError("no .text section".into()))?;
    let text_lo = text.vaddr as u64;
    let text_hi = text_lo + text.vsize as u64;
    let code = pe.section_bytes(".text").ok_or(DumpError("no .text bytes".into()))?;

    // ── 1. decode the whole .text ─────────────────────────────────────────
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut addr = text_lo;
    while addr < text_hi {
        let at = (addr - text_lo) as usize;
        if at >= code.len() {
            break;
        }
        match decoder::decode(code, at, addr) {
            Ok(d) => {
                let end = at + d.len;
                if end > code.len() {
                    return fail(format!(
                        "instruction at {addr:#x} runs past .text end"
                    ));
                }
                insns.insert(
                    addr,
                    Insn { va: addr, bytes: code[at..end].to_vec(), decoded: d },
                );
                addr += d.len as u64;
            }
            Err(e) => {
                return fail(format!("decode error at {addr:#x}: {} ({})", e.msg, e.at));
            }
        }
    }

    // ── 2. BFS from the entry ─────────────────────────────────────────────
    let entry_rva = pe
        .export_rva(opts.entry_name)
        .ok_or(DumpError(format!("export '{}' not found", opts.entry_name)))?;
    let entry_va = entry_rva as u64;
    if !(text_lo..text_hi).contains(&entry_va) {
        return fail(format!("entry {entry_va:#x} outside .text"));
    }
    if !insns.contains_key(&entry_va) {
        return fail(format!("entry {entry_va:#x} not an instruction boundary"));
    }

    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    let mut stack = vec![entry_va];
    while let Some(a) = stack.pop() {
        if !reachable.insert(a) {
            continue;
        }
        let insn = &insns[&a];
        let d = insn.decoded;
        match d.kind {
            Kind::CallRel32 | Kind::JmpRel | Kind::JccRel => {
                if let Some(t) = d.target {
                    if (text_lo..text_hi).contains(&t) {
                        stack.push(t);
                    }
                }
            }
            // An LEA computes an address without dereferencing: the target
            // may be a function or a constant-anchor thunk in .text that is
            // only referenced by address. Follow it so the relayout gate
            // doesn't fail on a reachable lea of unreachable code.
            Kind::RipRelative { disp_pos, is_lea, .. } => {
                if is_lea {
                    let disp = read_disp32(&insn.bytes, disp_pos);
                    let target = calc_target(a + d.len as u64, disp);
                    if (text_lo..text_hi).contains(&target) {
                        stack.push(target);
                    }
                }
            }
            _ => {}
        }
        // fallthrough
        match d.kind {
            Kind::JmpRel | Kind::Terminal | Kind::IndirectJmpReg | Kind::IndirectJmpMem => {}
            _ => {
                let next = a + d.len as u64;
                if (text_lo..text_hi).contains(&next) {
                    stack.push(next);
                }
            }
        }
    }

    // ── 3. collect references from reachable code ─────────────────────────
    // data targets: va -> (max size needed, written?)
    let mut data_refs: BTreeMap<u64, (usize, bool)> = BTreeMap::new();
    let mut branch_refs: Vec<(u64, u64)> = Vec::new(); // (insn_va, target_va)
    let mut rip_patches: Vec<(u64, usize, usize, bool)> = Vec::new(); // (insn_va, disp_pos, size, write)
    let mut mem_indirect: Vec<(u64, &'static str)> = Vec::new();
    let mut abs_mem: Vec<u64> = Vec::new();
    let mut external_branch: Vec<(u64, u64)> = Vec::new();

    for &a in &reachable {
        let insn = &insns[&a];
        let d = insn.decoded;
        match d.kind {
            Kind::RipRelative { disp_pos, size, write, is_lea: _ } => {
                let disp = read_disp32(&insn.bytes, disp_pos);
                let target = calc_target(a + d.len as u64, disp);
                if target < text_lo || target >= text_hi {
                    // external data reference — must be copied into the blob
                    let e = data_refs.entry(target).or_insert((0, false));
                    e.0 = e.0.max(size);
                    e.1 = e.1 || write;
                } else {
                    // reference into code (e.g. lea of a function) — patch as
                    // a code-relative target.
                    if !reachable.contains(&target) {
                        return fail(format!(
                            "reachable code at {a:#x} references unreachable code {target:#x}"
                        ));
                    }
                    data_refs.entry(target).or_insert((1, false));
                }
                rip_patches.push((a, disp_pos, size, write));
            }
            Kind::AbsoluteMem => abs_mem.push(a),
            Kind::IndirectCallMem | Kind::IndirectJmpMem => {
                let what = if d.kind == Kind::IndirectCallMem {
                    "call"
                } else {
                    "jmp"
                };
                mem_indirect.push((a, what));
            }
            Kind::CallRel32 | Kind::JmpRel | Kind::JccRel => {
                if let Some(t) = d.target {
                    if (text_lo..text_hi).contains(&t) {
                        if !reachable.contains(&t) {
                            return fail(format!(
                                "reachable code at {a:#x} branches to unreachable {t:#x}"
                            ));
                        }
                        branch_refs.push((a, t));
                    } else {
                        external_branch.push((a, t));
                    }
                }
            }
            _ => {}
        }
    }

    if !mem_indirect.is_empty() {
        let list: Vec<String> = mem_indirect
            .iter()
            .map(|(a, w)| format!("{w} *[mem] at {a:#x}"))
            .collect();
        return fail(format!(
            "memory-indirect (IAT-style thunk) in reachable code: {}",
            list.join(", ")
        ));
    }
    if !abs_mem.is_empty() {
        return fail(format!(
            "absolute memory addressing (needs relocation) at {:?}",
            abs_mem.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>()
        ));
    }
    if !external_branch.is_empty() {
        return fail(format!(
            "reachable code branches outside .text: {:?}",
            external_branch
        ));
    }
    let relocs = pe.reloc_targets();
    if !relocs.is_empty() {
        return fail(format!(
            "source image has {} base relocations — raw shellcode cannot be fixed up",
            relocs.len()
        ));
    }

    // ── 4. re-layout ──────────────────────────────────────────────────────
    // The ENTRY FUNCTION goes first as a contiguous block (entry prologue at
    // blob offset 0, and intra-function fallthrough stays sequential), then
    // every other reachable instruction in original address order (which
    // preserves each function's internal contiguity and only shrinks branch
    // distances, so rel8 jumps stay valid).
    //
    // The entry body = closure over fallthrough + direct branches that stay
    // at or above the entry address (branches below it are calls/tail-jumps
    // to other functions).
    let mut entry_body: BTreeSet<u64> = BTreeSet::new();
    let mut st = vec![entry_va];
    while let Some(a) = st.pop() {
        if !entry_body.insert(a) {
            continue;
        }
        let insn = &insns[&a];
        match insn.decoded.kind {
            Kind::CallRel32 | Kind::JmpRel | Kind::JccRel => {
                if let Some(t) = insn.decoded.target {
                    if t >= entry_va && (text_lo..text_hi).contains(&t) && reachable.contains(&t)
                    {
                        st.push(t);
                    }
                }
            }
            _ => {}
        }
        match insn.decoded.kind {
            Kind::JmpRel | Kind::Terminal | Kind::IndirectJmpReg | Kind::IndirectJmpMem => {}
            _ => {
                let next = a + insn.decoded.len as u64;
                if next < text_hi && reachable.contains(&next) {
                    st.push(next);
                }
            }
        }
    }
    let mut code_insns: Vec<u64> = Vec::new();
    for &a in &entry_body {
        code_insns.push(a);
    }
    for &a in &reachable {
        if !entry_body.contains(&a) {
            code_insns.push(a);
        }
    }
    let mut new_addr: BTreeMap<u64, u64> = BTreeMap::new();
    let mut blob: Vec<u8> = Vec::new();
    for &a in &code_insns {
        new_addr.insert(a, blob.len() as u64);
        let insn = &insns[&a];
        blob.extend_from_slice(&insn.bytes);
    }

    // Data: 16-byte aligned copies of every referenced constant.
    let mut data_blocks: BTreeMap<u64, (usize, usize, bool)> = BTreeMap::new();
    // (orig_va) -> (src_off, size, write)
    for (tgt, (size, write)) in &data_refs {
        let size = (*size).max(1);
        let src_off = match pe.rva_to_off(*tgt as u32) {
            Some(o) => o,
            None => return fail(format!("data ref target {tgt:#x} outside image")),
        };
        if src_off + size > pe.data.len() {
            return fail(format!("data ref target {tgt:#x} truncated"));
        }
        data_blocks.insert(*tgt, (src_off, size, *write));
    }
    // round blob length to 16
    while blob.len() % 16 != 0 {
        blob.push(0);
    }
    let mut data_place: BTreeMap<u64, usize> = BTreeMap::new(); // orig_va -> blob_off
    for (tgt, (src_off, size, write)) in &data_blocks {
        if *size == 0 {
            continue;
        }
        // copy size bytes (extend to 16 if it's an xmm operand, and align)
        let mut sz = *size;
        let align16 = *size >= 16;
        let mut off = blob.len();
        if align16 {
            while off % 16 != 0 {
                blob.push(0);
                off += 1;
            }
            sz = sz.max(16);
        }
        let chunk: Vec<u8> = pe.data[*src_off..*src_off + *size].to_vec();
        data_place.insert(*tgt, off);
        blob.extend_from_slice(&chunk);
        while blob.len() < off + sz {
            blob.push(0);
        }
        if *write {
            return fail(format!(
                "reachable code WRITES to data constant at {tgt:#x} — blob would need RW memory"
            ));
        }
    }

    // ── 5. re-patch ───────────────────────────────────────────────────────
    for (insn_va, disp_pos, size, _write) in &rip_patches {
        let insn = &insns[insn_va];
        let old_disp = read_disp32(&insn.bytes, *disp_pos);
        let old_target = calc_target(insn_va + insn.decoded.len as u64, old_disp);
        let new_base = new_addr[&insn_va] + *disp_pos as u64 + 4;
        let new_target = if old_target < text_lo || old_target >= text_hi {
            // external data — find the blob offset
            *data_place.get(&old_target).ok_or(DumpError(format!(
                "data ref {old_target:#x} not placed"
            )))?
        } else {
            new_addr[&old_target] as usize
        };
        let new_disp = new_target as i64 - new_base as i64;
        if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
            return fail(format!("displacement overflow at {insn_va:#x}"));
        }
        patch_disp32(&mut blob, new_addr[&insn_va] as usize + *disp_pos, new_disp as i32);
        let _ = size;
    }
    for (insn_va, target_va) in &branch_refs {
        let insn = &insns[insn_va];
        let d = insn.decoded;
        // displacement field: for map-1 rel32 it's at offset 1; rel8 at 1;
        // map-2 jcc (0F 8x) rel32 at offset 2.
        let (disp_off, disp_len) = branch_field(insn);
        let new_base = new_addr[&insn_va] + disp_off as u64 + disp_len as u64;
        let new_tgt = new_addr[target_va];
        let new_disp = new_tgt as i64 - new_base as i64;
        if opts.debug {
            eprintln!(
                "branch: orig {insn_va:#x} -> {target_va:#x}  blob {:#x} -> {new_tgt:#x} disp {new_disp:#x}",
                new_addr[&insn_va]
            );
        }
        if disp_len == 1 {
            if new_disp < i8::MIN as i64 || new_disp > i8::MAX as i64 {
                return fail(format!(
                    "rel8 branch overflow at {insn_va:#x} (target {target_va:#x})"
                ));
            }
            let off = new_addr[&insn_va] as usize + disp_off;
            blob[off] = new_disp as i8 as u8;
        } else {
            if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
                return fail(format!("rel32 branch overflow at {insn_va:#x}"));
            }
            patch_disp32(&mut blob, new_addr[&insn_va] as usize + disp_off, new_disp as i32);
        }
    }

    // ── 6. final validation ───────────────────────────────────────────────
    // entry at offset 0
    if new_addr[&entry_va] != 0 {
        return fail("entry not at blob offset 0 — layout bug");
    }
    // every reachable instruction accounted for exactly once in the blob
    let blob_code_len: usize = code_insns.iter().map(|a| insns[a].decoded.len).sum();
    let code_end = new_addr.values().max().copied().unwrap_or(0) as usize
        + insns[&code_insns[code_insns.len() - 1]].decoded.len;
    if blob_code_len != code_end {
        return fail("internal layout error: code bytes do not tile the blob");
    }

    Ok(blob)
}

fn read_disp32(bytes: &[u8], pos: usize) -> i64 {
    if pos + 4 > bytes.len() {
        return 0;
    }
    let v = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    v as i32 as i64
}

/// (base + disp) with i128 arithmetic for negative displacements.
fn calc_target(base: u64, disp: i64) -> u64 {
    (base as i128 + disp as i128) as u64
}

fn patch_disp32(blob: &mut [u8], pos: usize, disp: i32) {
    let b = disp.to_le_bytes();
    blob[pos..pos + 4].copy_from_slice(&b);
}

/// Where the branch displacement field lives in a direct-branch instruction.
fn branch_field(insn: &Insn) -> (usize, usize) {
    let b = &insn.bytes;
    // one-byte map: [op][disp]
    if b.len() >= 1 && b[0] == 0x0F {
        // [0F][8x][disp32] — no modrm
        (2, 4)
    } else {
        match b[0] {
            0xE8 | 0xE9 => (1, 4),
            _ => (1, 1), // jcc rel8, jmp rel8, jrcxz
        }
    }
}
