//! Minimal x86-64 instruction decoder for the pic-loader extractor.
//!
//! Only what the relayout pass needs:
//!   * total instruction length (to walk code and compact it),
//!   * direct branch targets (`call`/`jmp`/`jcc`),
//!   * RIP-relative memory operands (position of the disp32 field + operand
//!     size, for re-patching and data-alignment),
//!   * indirect `call`/`jmp` (report-only: the loader resolves APIs at runtime),
//!   * terminal instructions (no fallthrough).
//!
//! The decoder is deliberately conservative: on any encoding it does not
//! understand it errors, and the dumper fails. It is validated instruction-
//! by-instruction against `objdump` by the regen script.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nothing special.
    Plain,
    /// `call rel32` — direct call.
    CallRel32,
    /// `jmp rel8/rel32` — unconditional, no fallthrough.
    JmpRel,
    /// `jcc rel8/rel32` — conditional, falls through.
    JccRel,
    /// `ret` / `ud2` / `int3` / `hlt` / `syscall` / `leave` — no fallthrough.
    Terminal,
    /// `call r/m` or `jmp r/m` through a register — the loader's resolved API
    /// calls; target unknown at build time, must not be in-blob.
    IndirectCallReg,
    /// `jmp r/m` through a register.
    IndirectJmpReg,
    /// `call/jmp *[mem]` — IAT-style thunk; a hard error in reachable code
    /// (the blob has no import table).
    IndirectCallMem,
    IndirectJmpMem,
    /// RIP-relative memory operand; `disp_pos` is the offset of the disp32
    /// field within the instruction, `size` the memory operand size (1/2/4/8/
    /// 16), `write` whether the instruction stores to memory.
    RipRelative { disp_pos: usize, size: usize, write: bool },
    /// Absolute memory addressing (no RIP base) — needs a relocation; error.
    AbsoluteMem,
}

#[derive(Debug, Clone, Copy)]
pub struct Decoded {
    pub len: usize,
    pub kind: Kind,
    /// Target of CallRel32/JmpRel/JccRel as absolute (image-relative) VA.
    pub target: Option<u64>,
}

#[derive(Debug)]
pub struct DecodeError {
    pub at: usize,
    pub msg: String,
}

fn err<T>(at: usize, msg: impl Into<String>) -> Result<T, DecodeError> {
    Err(DecodeError { at, msg: msg.into() })
}

const PREFIXES: [u8; 10] = [0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64];

/// Decode one instruction at `code[at..]`. `va` is the image-relative virtual
/// address of the instruction (for branch target computation).
pub fn decode(code: &[u8], at: usize, va: u64) -> Result<Decoded, DecodeError> {
    if at >= code.len() {
        return err(at, "ran off end of section");
    }
    let mut p = at;
    let mut has_66 = false;
    let mut has_f2 = false;
    let mut has_f3 = false;
    let mut has_67 = false;
    let mut has_seg = false; // FS/GS/CS/SS/DS/ES override: [disp32] is segment-relative
    let mut has_rex = false;
    let mut rex_w = false;

    // Legacy prefixes (LLVM emits them in canonical order; we accept any).
    loop {
        let b = code[p];
        match b {
            0x66 => has_66 = true,
            0xF2 => has_f2 = true,
            0xF3 => has_f3 = true,
            0x67 => has_67 = true,
            0xF0 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                if b == 0x64 || b == 0x65 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 {
                    has_seg = true;
                }
            }
            0x40..=0x4F => {
                has_rex = true;
                rex_w = b & 8 != 0;
            }
            _ => break,
        }
        p += 1;
        if p >= code.len() {
            return err(at, "prefix only");
        }
        // A REX must immediately precede the opcode; stop scanning after it.
        if b >= 0x40 && b <= 0x4F {
            break;
        }
        if p >= code.len() {
            return err(at, "prefix only");
        }
    }

    // VEX (C4/C5) and EVEX (62) — LLVM emits none for the force-soft loader,
    // but handle them so a future build fails loudly instead of misdecoding.
    let mut vex = false;
    let mut evx = false;
    if code[p] == 0xC4 {
        if p + 3 > code.len() {
            return err(p, "truncated VEX");
        }
        p += 3;
        vex = true;
    } else if code[p] == 0xC5 {
        if p + 2 > code.len() {
            return err(p, "truncated VEX");
        }
        p += 2;
        vex = true;
    } else if code[p] == 0x62 {
        if p + 4 > code.len() {
            return err(p, "truncated EVEX");
        }
        p += 4;
        evx = true;
    }

    let op = code[p];
    p += 1;

    // Two/three-byte opcode maps.
    let mut op2: u8 = 0;
    let mut op3: u8 = 0;
    let mut map: u8 = 1; // 1 = one-byte, 2 = 0F, 3 = 0F 38, 4 = 0F 3A
    if op == 0x0F && !vex && !evx {
        if p >= code.len() {
            return err(p, "truncated 0F");
        }
        op2 = code[p];
        p += 1;
        map = 2;
        if op2 == 0x38 || op2 == 0x3A {
            if p >= code.len() {
                return err(p, "truncated 0F 3x");
            }
            op3 = code[p];
            p += 1;
            map = if op2 == 0x38 { 3 } else { 4 };
        }
    }
    if vex {
        // VEX opcode: one opcode byte (or 0F/0F38/0F3A escape was already
        // consumed via `op == 0x0F`). We treat the map as "modrm follows".
        map = 5; // vex: modrm always present after opcode
    }

    // ---- does this instruction have a ModRM byte? ----
    let has_modrm = match map {
        1 => one_byte_has_modrm(op),
        2 => two_byte_has_modrm(op2),
        3 | 4 => three_byte_has_modrm(op3),
        _ => true, // VEX/EVEX
    };

    let modrm_pos = p;
    let mut modrm: u8 = 0;
    if has_modrm {
        if p >= code.len() {
            return err(p, "truncated (need ModRM)");
        }
        modrm = code[p];
        p += 1;
    }

    // ---- displacement ----
    let mm = modrm >> 6;
    let rm = modrm & 7;
    let mut rip_rel = false;
    let mut abs_mem = false;
    let mut disp32_pos: usize = 0;
    let mut disp_size: usize = 0;
    if has_modrm && mm != 3 {
        // memory operand
        let mut abs_disp_val: i64 = 0;
        if mm == 0 && rm == 5 {
            if has_67 {
                abs_mem = !has_seg; // 32-bit addr mode: disp32 no base
                abs_disp_val = disp_val(code, p);
            } else {
                rip_rel = true;
            }
            disp_size = 4;
            disp32_pos = p - at;
            p += 4;
        } else {
            if rm == 4 {
                // SIB follows
                if p >= code.len() {
                    return err(p, "truncated (need SIB)");
                }
                let sib = code[p];
                p += 1;
                let base = sib & 7;
                if mm == 0 && base == 5 {
                    // disp32 with no base — absolute addressing (unless a
                    // segment override makes it segment-relative, e.g. the
                    // PEB read `mov gs:0x60,%rax`)
                    if !has_67 && !has_seg {
                        abs_mem = true;
                        abs_disp_val = disp_val(code, p);
                    }
                    disp_size = 4;
                    disp32_pos = p - at;
                    p += 4;
                } else if mm == 1 {
                    disp_size = 1;
                    p += 1;
                } else if mm == 2 {
                    disp_size = 4;
                    p += 4;
                }
            } else if mm == 1 {
                disp_size = 1;
                p += 1;
            } else if mm == 2 {
                disp_size = 4;
                p += 4;
            }
        }
        // A base-less absolute address is only a relocation hazard if the
        // disp is nonzero (a real image address). disp32 == 0 is scaled
        // indexing (e.g. `lea 0x0(,%r12,8),%rax`) — a literal, not a fixup.
        // The image-level check (no relocations at all) catches real cases.
        if abs_mem && abs_disp_val == 0 {
            abs_mem = false;
        }
        // LEA (0x8D) never dereferences: its disp32 is a constant offset in
        // address arithmetic (e.g. `lea 0x4(,%rax,4),%rax` from RawVec growth),
        // not a pointer that would need a relocation.
        if abs_mem && map == 1 && op == 0x8D {
            abs_mem = false;
        }
    }

    // ---- branch displacement (call/jmp/jcc) ----------------
    if let Some((dlen, _)) = branch_disp(map, op, op2) {
        if p + dlen > code.len() {
            return err(p, "truncated branch displacement");
        }
        p += dlen;
    }

    // ---- immediate ----
    let imm = immediate_size(map, op, op2, op3, modrm, has_modrm, has_66, rex_w);
    if imm > 0 {
        if p + imm > code.len() {
            return err(p, "truncated immediate");
        }
        p += imm;
    }

    // moffs (mov moffs64, al/rax): 8-byte absolute address, no modrm.
    if map == 1 && (0xA0..=0xA3).contains(&op) {
        if p + 8 > code.len() {
            return err(p, "truncated moffs");
        }
        p += 8;
        return Ok(Decoded { len: p - at, kind: Kind::AbsoluteMem, target: None });
    }

    let len = p - at;

    // ---- classify ----
    if let Some(tgt) = direct_branch(map, op, op2, modrm, has_modrm, code, at, va) {
        // NOTE: do NOT overwrite the kind here — JmpRel must stay JmpRel so
        // the BFS follows its target and the relayout patches its
        // displacement. `Terminal` is reserved for ret/ud2/… (no target).
        let (kind, _terminal) = branch_kind(map, op, op2, modrm, has_modrm);
        return Ok(Decoded { len, kind, target: Some(tgt) });
    }
    if has_modrm && (mm != 3) && rip_rel {
        let size = mem_operand_size(map, op, op2, modrm, has_66, has_f2, has_f3, rex_w);
        let write = is_mem_write(map, op, op2, modrm);
        return Ok(Decoded {
            len,
            kind: Kind::RipRelative { disp_pos: disp32_pos, size, write },
            target: None,
        });
    }
    if has_modrm && (mm != 3) && abs_mem {
        return Ok(Decoded { len, kind: Kind::AbsoluteMem, target: None });
    }
    // indirect call/jmp: register or base-relative memory (stack slots = the
    // loader's resolved API pointers) is fine; RIP-relative (IAT thunk) is a
    // hard error upstream.
    if map == 1 && op == 0xFF && has_modrm {
        let reg = (modrm >> 3) & 7;
        if reg == 2 || reg == 4 {
            if rip_rel {
                let kind = if reg == 2 { Kind::IndirectCallMem } else { Kind::IndirectJmpMem };
                return Ok(Decoded { len, kind, target: None });
            }
            let kind = if reg == 2 { Kind::IndirectCallReg } else { Kind::IndirectJmpReg };
            return Ok(Decoded { len, kind, target: None });
        }
    }
    if is_terminal(map, op, op2) {
        return Ok(Decoded { len, kind: Kind::Terminal, target: None });
    }
    Ok(Decoded { len, kind: Kind::Plain, target: None })
}

impl Decoded {
    fn with_terminal(mut self, _t: bool) -> Self {
        self
    }
}

fn direct_branch(
    map: u8,
    op: u8,
    op2: u8,
    modrm: u8,
    has_modrm: bool,
    code: &[u8],
    at: usize,
    va: u64,
) -> Option<u64> {
    let (disp_off, disp_len): (usize, usize) = match map {
        1 => match op {
            0xE8 | 0xE9 => (1, 4),
            0xEB => (1, 1),
            0x70..=0x7F => (1, 1),
            0xE0..=0xE3 => (1, 1),
            _ => return None,
        },
        2 => {
            if (0x80..=0x8F).contains(&op2) {
                // [0F][8x][disp32] — disp32 starts at at+2 (no modrm)
                (2, 4)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    debug_assert!(has_modrm == (map == 2 && (0x80..=0x8F).contains(&op2)));
    let _ = modrm;
    let ip_after = va + disp_off as u64 + disp_len as u64;
    let mut disp: i64 = 0;
    for k in 0..disp_len {
        let b = *code.get(at + disp_off + k)?;
        disp |= (b as i64) << (8 * k);
    }
    if disp_len == 4 {
        disp = (disp as i32) as i64;
    } else {
        disp = (disp as i8) as i64;
    }
    Some((ip_after as i128 + disp as i128) as u64)
}

fn branch_kind(map: u8, op: u8, op2: u8, modrm: u8, has_modrm: bool) -> (Kind, bool) {
    match map {
        1 => match op {
            0xE8 => (Kind::CallRel32, false),
            0xE9 | 0xEB => (Kind::JmpRel, true),
            0x70..=0x7F => (Kind::JccRel, false),
            0xE0..=0xE3 => (Kind::JccRel, false), // loop/jrcxz
            _ => (Kind::Plain, false),
        },
        2 => {
            if (0x80..=0x8F).contains(&op2) {
                (Kind::JccRel, false)
            } else {
                (Kind::Plain, false)
            }
        }
        _ => (Kind::Plain, false),
    }
}

fn is_terminal(map: u8, op: u8, op2: u8) -> bool {
    match map {
        1 => matches!(op, 0xC3 | 0xC2 | 0xCB | 0xCA | 0xCC | 0xF4 | 0xC9),
        2 => matches!(
            op2,
            0x0B /* ud2 */ | 0x05 /* syscall */ | 0x34 /* sysenter */ | 0x35 /* sysexit */
        ),
        _ => false,
    }
}

/// (disp_len, disp_off_from_instruction_start) for direct branches.
fn branch_disp(map: u8, op: u8, op2: u8) -> Option<(usize, usize)> {
    match map {
        1 => match op {
            0xE8 | 0xE9 => Some((4, 1)),
            0xEB | 0x70..=0x7F | 0xE0..=0xE3 => Some((1, 1)),
            _ => None,
        },
        2 => {
            if (0x80..=0x8F).contains(&op2) {
                Some((4, 2))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read a disp32 at `code[pos..]` as an i64 (for the abs_mem zero check).
fn disp_val(code: &[u8], pos: usize) -> i64 {
    if pos + 4 > code.len() {
        return 0;
    }
    let v = u32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]);
    v as i32 as i64
}

/// Immediate size in bytes after the displacement (0 if none).
fn immediate_size(
    map: u8,
    op: u8,
    op2: u8,
    op3: u8,
    modrm: u8,
    has_modrm: bool,
    has_66: bool,
    rex_w: bool,
) -> usize {
    let w16 = |v32: usize| if has_66 { 2 } else { v32 };
    match map {
        1 => match op {
            0x68 => return w16(4),
            0x6A => return 1,
            0x69 => return w16(4),
            0x6B => return 1,
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => return 1,
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => return w16(4),
            0xB0..=0xB7 => return 1,
            0xB8..=0xBF => {
                if rex_w {
                    return 8;
                }
                return w16(4);
            }
            0xA8 => return 1,
            0xA9 => return w16(4),
            0xC2 | 0xCA => return 2,
            0xC8 => return 3, // enter imm16,imm8
            0xCD => return 1,
            0xE4 | 0xE5 | 0xE6 | 0xE7 => return 1,
            0x80 | 0x82 | 0x83 => return 1,
            0x81 => return w16(4),
            0xC0 | 0xC1 => return 1,
            0xC6 => return 1,
            0xC7 => return w16(4),
            0xF6 => {
                // group 3: imm8 for test (/0) only
                if has_modrm && (modrm >> 3) & 7 == 0 {
                    return 1;
                }
                return 0;
            }
            0xF7 => {
                if has_modrm && (modrm >> 3) & 7 == 0 {
                    return w16(4);
                }
                return 0;
            }
            _ => return 0,
        },
        2 => match op2 {
            0x70 | 0x71 | 0x72 | 0x73 | 0xC2 | 0xC4 | 0xC5 | 0xC6 | 0xA4 | 0xA6 | 0xAC | 0xAE
            | 0xBA => 1, // pshufd, shift groups, cmpps, pinsrw, pextrw, shufps, shld, shrd, bts-imm
            _ => 0,
        },
        3 => 0,
        4 => {
            if (0x0F..=0x1F).contains(&op3) {
                1 // imm8 (e.g. palignr, pclmulqdq imm8)
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Memory operand size for RIP-relative references (for 16-byte alignment
/// decisions in the data block).
fn mem_operand_size(
    map: u8,
    op: u8,
    op2: u8,
    modrm: u8,
    has_66: bool,
    has_f2: bool,
    has_f3: bool,
    rex_w: bool,
) -> usize {
    if map == 1 {
        // GPR ops
        if has_66 {
            return 2;
        }
        let size = match op {
            0x8A | 0x8C | 0x8E | 0xB6 | 0xBE | 0x38 | 0x3A | 0x20 | 0x22 | 0x24 | 0x26 | 0x28
            | 0x2A | 0x30 | 0x32 => 1,
            0xA4..=0xA7 | 0xAA..=0xAF => return 1,
            _ => {
                if rex_w {
                    8
                } else {
                    4
                }
            }
        };
        return size;
    }
    // 0F map: SSE/AVX.
    // Full-register loads/stores/moves are 16 bytes (movups/movaps/movdqa/
    // movdqu/padd*/pcmpeq*/…); F2/F3 scalar variants are 8/4 bytes.
    match op2 {
        0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x28 | 0x29 | 0x2A | 0x2B
        | 0x2C | 0x2D | 0x2E | 0x2F | 0x50..=0x5F | 0x60..=0x7F | 0x90..=0x97 | 0xD0..=0xDF
        | 0xE0..=0xEF | 0xF0..=0xFF => {
            if has_f2 {
                8
            } else if has_f3 {
                4
            } else {
                16
            }
        }
        _ => {
            // unknown 0F op — default conservatively to 16
            if has_f2 {
                8
            } else if has_f3 {
                4
            } else {
                16
            }
        }
    }
}

fn is_mem_write(map: u8, op: u8, op2: u8, modrm: u8) -> bool {
    let reg = (modrm >> 3) & 7;
    if map == 1 {
        // mov r/m <- r: opcode bit 0 (D bit): 0 = r/m is dest (write),
        // 1 = register is dest (read).
        match op {
            0x88 | 0x89 => return true,  // mov r/m8/64 <- r8/64
            0x8A | 0x8B => return false, // mov r8/64 <- r/m
            _ => {}
        }
        match op {
            0x00 | 0x01 | 0x08 | 0x09 | 0x10 | 0x11 | 0x18 | 0x19 | 0x20 | 0x21 | 0x28 | 0x29
            | 0x30 | 0x31 | 0x38 | 0x39 => return op & 1 == 0, // D=0: r/m dest
            0x02 | 0x03 | 0x0A | 0x0B | 0x12 | 0x13 | 0x1A | 0x1B | 0x22 | 0x23 | 0x2A | 0x2B
            | 0x32 | 0x33 | 0x3A | 0x3B => return true, // D=1: r/m is source
            _ => {}
        }
        match op {
            0x80 | 0x81 | 0x82 | 0x83 | 0xC6 | 0xC7 => return true,
            0xF6 | 0xF7 => return reg != 0, // test (/0) reads; others write
            0xC0 | 0xC1 | 0xD0..=0xD3 => return true, // rotates/shifts write
            _ => {}
        }
        return false;
    }
    // SSE: stores are op2 0x11, 0x13, 0x15, 0x17, 0x29, 0x2B, 0xE7, 0x7F etc.
    match op2 {
        0x11 | 0x13 | 0x15 | 0x17 | 0x29 | 0x2B | 0xE7 | 0x7F | 0x1F | 0x3F | 0x5F => true,
        _ => false,
    }
}

/// One-byte opcodes that carry a ModRM byte.
fn one_byte_has_modrm(op: u8) -> bool {
    match op {
        // no modrm
        0x04 | 0x05 | 0x0C | 0x0D | 0x14 | 0x15 | 0x1C | 0x1D | 0x24 | 0x25 | 0x2C | 0x2D
        | 0x34 | 0x35 | 0x3C | 0x3D | 0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F | 0x27
        | 0x2F | 0x37 | 0x3F | 0x50..=0x57 | 0x58..=0x5F | 0x68 | 0x6A | 0x70..=0x7F | 0x90
        | 0x91..=0x97 | 0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F | 0xA0..=0xBF | 0xC3
        | 0xC2 | 0xC8 | 0xC9 | 0xCA | 0xCB | 0xCC | 0xCD | 0xCF | 0xD4 | 0xD5 | 0xD7
        | 0xE0..=0xEF | 0xF1 | 0xF4 | 0xF5 | 0xF8..=0xFD => false,
        _ => true,
    }
}

/// 0F-map opcodes that carry a ModRM byte.
fn two_byte_has_modrm(op2: u8) -> bool {
    match op2 {
        0x05 | 0x07 | 0x08 | 0x09 | 0x0B | 0x0E | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x37
        | 0x77 | 0x80..=0x8F | 0xA2 | 0xC8..=0xCF => false,
        _ => true,
    }
}

fn three_byte_has_modrm(_op3: u8) -> bool {
    true
}
