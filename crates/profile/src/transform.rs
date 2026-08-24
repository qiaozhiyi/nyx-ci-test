//! Data-transform engine: apply (and invert) the Malleable C2 byte transforms
//! declared in a profile's `output` / `metadata` / `id` blocks.
//!
//! Transforms are applied in source order when *encoding* (implant → server)
//! and in reverse order when *decoding* (server → implant), so [`decode`] is
//! the exact inverse of [`encode`] for any step list.
//!
//! ## Honest boundary on `mask`
//! Cobalt Strike derives the `mask` XOR key internally (and that derivation has
//! changed across versions), so CS-wire interop for `mask` is **not** claimed
//! here. Nyx uses a self-consistent, invertible scheme: a 4-byte key derived
//! from the payload (FNV-1a, no extra dependency) is prepended to the output so
//! the receiver can always recover it. Real per-session randomness belongs at
//! the transport layer (server/implant already have a CSPRNG); this engine
//! exists to make the profile's transform pipeline testable and reusable.

#[cfg(feature = "std")]
use crate::ast::{Block, Item};

// The transform engine is compiled under BOTH `std` (workspace: server/agent-dev)
// and `no_std` (PIC implant). Under `no_std`, `Vec`/`String` are not in the
// prelude, so import them from `alloc` (a no-op under std — same types).
use alloc::{string::String, vec::Vec};

/// A single transform step, in the order it appears in a data block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Base64,
    Base64Url,
    Netbios,
    NetbiosU,
    Mask,
    Prepend(Vec<u8>),
    Append(Vec<u8>),
}

/// Where the transformed data is placed on the wire (the last statement in a
/// data block). Carried for the transport layer; the transform engine itself
/// only consumes [`Step`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    Header(String),
    Parameter(String),
    Print,
    UriAppend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    InvalidBase64(u8),
    InvalidNetbios,
    TooShort,
    PrefixMismatch,
    SuffixMismatch,
    InvalidPadding,
}

// Manual `Display` + `Error` impls (not thiserror) so this module is
// `no_std`+`alloc`-clean for the PIC implant. The Display strings match the old
// thiserror `#[error(...)]` attrs exactly — no behavior change on std.
impl core::fmt::Display for TransformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBase64(b) => write!(f, "invalid base64 byte {b:#x}"),
            Self::InvalidNetbios => {
                write!(f, "invalid netbios encoding (expected pairs of a-p / A-P)")
            }
            Self::TooShort => write!(f, "data too short for mask (need >= 4-byte key prefix)"),
            Self::PrefixMismatch => write!(f, "prepend prefix did not match"),
            Self::SuffixMismatch => write!(f, "append suffix did not match"),
            Self::InvalidPadding => {
                write!(
                    f,
                    "invalid padding suffix (bad length encoding or out-of-range pad)"
                )
            }
        }
    }
}

impl core::error::Error for TransformError {}

/// Encode by folding steps left-to-right.
pub fn encode(steps: &[Step], input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for s in steps {
        v = apply(s, v);
    }
    v
}

/// Decode by inverting steps right-to-left.
pub fn decode(steps: &[Step], input: &[u8]) -> Result<Vec<u8>, TransformError> {
    let mut v = input.to_vec();
    for s in steps.iter().rev() {
        v = unapply(s, v)?;
    }
    Ok(v)
}

/// Pull the transform steps (in order) out of a parsed `output`/`metadata`/`id`
/// block, ignoring terminators and unknown statements (lint reports those).
///
/// Needs `ast::Block` → unavailable under the `no_std` feature (build.rs
/// resolves steps host-side for the PIC implant instead).
#[cfg(feature = "std")]
pub fn steps_from_block(b: &Block) -> Vec<Step> {
    let mut out = Vec::new();
    for item in &b.items {
        if let Item::Stmt { keyword, args, .. } = item {
            match keyword.as_str() {
                "base64" => out.push(Step::Base64),
                "base64url" => out.push(Step::Base64Url),
                "netbios" => out.push(Step::Netbios),
                "netbiosu" => out.push(Step::NetbiosU),
                "mask" => out.push(Step::Mask),
                "prepend" => out.push(Step::Prepend(
                    args.first().map(|a| a.0.clone()).unwrap_or_default(),
                )),
                "append" => out.push(Step::Append(
                    args.first().map(|a| a.0.clone()).unwrap_or_default(),
                )),
                _ => {}
            }
        }
    }
    out
}

fn apply(s: &Step, v: Vec<u8>) -> Vec<u8> {
    match s {
        Step::Base64 => b64_encode(&v, STD_ALPHA),
        Step::Base64Url => b64_encode(&v, URL_ALPHA),
        Step::Netbios => netbios_encode(&v, false),
        Step::NetbiosU => netbios_encode(&v, true),
        Step::Mask => mask_apply(&v),
        Step::Prepend(p) => {
            let mut o = Vec::with_capacity(p.len() + v.len());
            o.extend_from_slice(p);
            o.extend_from_slice(&v);
            o
        }
        Step::Append(a) => {
            let mut o = v;
            o.extend_from_slice(a);
            o
        }
    }
}

fn unapply(s: &Step, v: Vec<u8>) -> Result<Vec<u8>, TransformError> {
    match s {
        Step::Base64 | Step::Base64Url => b64_decode(&v),
        Step::Netbios => netbios_decode(&v, false),
        Step::NetbiosU => netbios_decode(&v, true),
        Step::Mask => mask_unapply(&v),
        Step::Prepend(p) => {
            if v.len() >= p.len() && &v[..p.len()] == p.as_slice() {
                Ok(v[p.len()..].to_vec())
            } else {
                Err(TransformError::PrefixMismatch)
            }
        }
        Step::Append(a) => {
            let n = a.len();
            if v.len() >= n && &v[v.len() - n..] == a.as_slice() {
                Ok(v[..v.len() - n].to_vec())
            } else {
                Err(TransformError::SuffixMismatch)
            }
        }
    }
}

// ---- base64 (standard + url-safe, hand-rolled) -----------------------------

const STD_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(input: &[u8], alpha: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        out.push(alpha[((n >> 18) & 63) as usize]);
        out.push(alpha[((n >> 12) & 63) as usize]);
        out.push(alpha[((n >> 6) & 63) as usize]);
        out.push(alpha[(n & 63) as usize]);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alpha[((n >> 18) & 63) as usize]);
        out.push(alpha[((n >> 12) & 63) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(alpha[((n >> 18) & 63) as usize]);
        out.push(alpha[((n >> 12) & 63) as usize]);
        out.push(alpha[((n >> 6) & 63) as usize]);
        out.push(b'=');
    }
    out
}

/// Decode base64, accepting either alphabet and tolerating padding/whitespace.
fn b64_decode(input: &[u8]) -> Result<Vec<u8>, TransformError> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return Err(TransformError::InvalidBase64(c)),
        };
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

// ---- netbios (a-p / A-P) ---------------------------------------------------

fn netbios_encode(input: &[u8], upper: bool) -> Vec<u8> {
    let base = if upper { b'A' } else { b'a' };
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        out.push(base + (b >> 4));
        out.push(base + (b & 0x0F));
    }
    out
}

fn netbios_decode(input: &[u8], upper: bool) -> Result<Vec<u8>, TransformError> {
    if !input.len().is_multiple_of(2) {
        return Err(TransformError::InvalidNetbios);
    }
    let base = if upper { b'A' } else { b'a' };
    let top = base + 15;
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut i = 0;
    while i < input.len() {
        let (hi, lo) = (input[i], input[i + 1]);
        if !(base..=top).contains(&hi) || !(base..=top).contains(&lo) {
            return Err(TransformError::InvalidNetbios);
        }
        out.push(((hi - base) << 4) | (lo - base));
        i += 2;
    }
    Ok(out)
}

// ---- mask (XOR with prepended 4-byte key) ----------------------------------

fn mask_apply(input: &[u8]) -> Vec<u8> {
    let k = fnv1a32(input).to_le_bytes();
    let mut out = Vec::with_capacity(input.len() + 4);
    out.extend_from_slice(&k);
    for (i, &b) in input.iter().enumerate() {
        out.push(b ^ k[i % 4]);
    }
    out
}

fn mask_unapply(input: &[u8]) -> Result<Vec<u8>, TransformError> {
    if input.len() < 4 {
        return Err(TransformError::TooShort);
    }
    let k = [input[0], input[1], input[2], input[3]];
    let mut out = Vec::with_capacity(input.len() - 4);
    for (i, &b) in input[4..].iter().enumerate() {
        out.push(b ^ k[i % 4]);
    }
    Ok(out)
}

fn fnv1a32(b: &[u8]) -> u32 {
    let mut h = 0x811c9dc5u32;
    for &x in b {
        h ^= x as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

// ---- traffic-shaping padding (profile `set padding_min/max`) ---------------

/// Maximum padding length. The length is self-delimiting as TWO URL-safe
/// base64 chars (6 bits each, see [`pad_append`]), so `n <= 4095`.
pub const PAD_LEN_CAP: usize = 4095;

/// Append traffic-shaping padding to an already-transformed payload, blurring
/// the packet-length distribution (a metadata-level CS Malleable C2 residue:
/// content mimicry alone leaves sizes/timing detectable).
///
/// Wire layout: `encode(frame) || pad || len2`, where `pad` is `n` bytes and
/// `len2` is `n` itself as two 6-bit base64url chars. The padding rides AFTER
/// the transform chain (never through e.g. base64) so the receiver can locate
/// and strip it via [`pad_strip`] BEFORE [`decode`] — that ordering is the
/// round-trip contract. All emitted bytes come from the URL-safe base64
/// alphabet so a padded payload stays valid in every terminator position
/// (body, header value, URI suffix).
///
/// `seed` drives a xorshift32 chain (length pick + filler bytes). Padding is
/// traffic-shaping filler, not secret material, so a cheap PRNG seeded by the
/// caller's own randomness is enough — same discipline as `mask` above.
/// `max == 0` disables padding entirely: the buffer is left untouched, keeping
/// the wire format byte-identical to profiles without padding.
pub fn pad_append(out: &mut Vec<u8>, min: usize, max: usize, seed: u32) {
    let max = max.min(PAD_LEN_CAP);
    let min = min.min(max);
    if max == 0 {
        return;
    }
    let mut x = if seed == 0 { 0x9E37_79B9 } else { seed };
    x = xorshift32(x);
    let n = min + (x as usize) % (max - min + 1);
    for _ in 0..n {
        x = xorshift32(x);
        out.push(URL_ALPHA[(x as usize) & 63]);
    }
    out.push(URL_ALPHA[(n >> 6) & 63]);
    out.push(URL_ALPHA[n & 63]);
}

/// Strip the padding [`pad_append`] added: decode the 2-char length suffix,
/// drop it plus the `n` filler bytes, return the remaining payload. Fails on a
/// malformed suffix or an `n` outside `[min, max]` (profile desync / tamper).
/// Callers must invoke this ONLY when padding is enabled (`max > 0`) — with
/// padding disabled the wire carries no length suffix at all.
pub fn pad_strip(buf: &[u8], min: usize, max: usize) -> Result<&[u8], TransformError> {
    if buf.len() < 2 {
        return Err(TransformError::InvalidPadding);
    }
    let hi = b64url_val(buf[buf.len() - 2]).ok_or(TransformError::InvalidPadding)?;
    let lo = b64url_val(buf[buf.len() - 1]).ok_or(TransformError::InvalidPadding)?;
    let n = hi * 64 + lo;
    let max = max.min(PAD_LEN_CAP);
    let min = min.min(max);
    if n < min || n > max || n + 2 > buf.len() {
        return Err(TransformError::InvalidPadding);
    }
    Ok(&buf[..buf.len() - 2 - n])
}

fn b64url_val(c: u8) -> Option<usize> {
    URL_ALPHA.iter().position(|&a| a == c)
}

fn xorshift32(mut x: u32) -> u32 {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for msg in [
            &b""[..],
            b"A",
            b"AB",
            b"ABC",
            b"hello world",
            b"\x00\xff\x10",
        ] {
            let enc = encode(&[Step::Base64], msg);
            assert_eq!(decode(&[Step::Base64], &enc).unwrap(), msg);
        }
        // known vector
        assert_eq!(b64_encode(b"ABC", STD_ALPHA), b"QUJD");
    }

    #[test]
    fn base64url_alphabet() {
        let enc = encode(&[Step::Base64Url], b"\xfb\xff");
        // standard would be '+/'; url-safe must be '-_'
        assert!(
            enc.windows(2).any(|w| w == b"-_" || w[0] == b'-'),
            "url-safe alphabet used: {enc:?}"
        );
    }

    #[test]
    fn netbios_roundtrip() {
        for msg in [&b""[..], b"\x1f\x8b", b"\x00\x10\xff"] {
            assert_eq!(
                decode(&[Step::Netbios], &encode(&[Step::Netbios], msg)).unwrap(),
                msg
            );
            assert_eq!(
                decode(&[Step::NetbiosU], &encode(&[Step::NetbiosU], msg)).unwrap(),
                msg
            );
        }
        assert_eq!(netbios_encode(&[0x1fu8], false), b"bp");
    }

    #[test]
    fn mask_roundtrip() {
        let msg = b"the quick brown fox";
        assert_eq!(
            decode(&[Step::Mask], &encode(&[Step::Mask], msg)).unwrap(),
            msg
        );
    }

    #[test]
    fn prepend_append_roundtrip() {
        let steps = vec![
            Step::Prepend(b"SESSION=".to_vec()),
            Step::Append(b";".to_vec()),
        ];
        assert_eq!(decode(&steps, &encode(&steps, b"xyz")).unwrap(), b"xyz");
    }

    #[test]
    fn multistep_chain_roundtrip() {
        // mirror a real CS metadata block: mask; base64; prepend; append
        let steps = vec![
            Step::Mask,
            Step::Base64,
            Step::Prepend(b"SESSION=".to_vec()),
            Step::Append(b";".to_vec()),
        ];
        let msg = b"s3ss1on-met4data-payload";
        assert_eq!(decode(&steps, &encode(&steps, msg)).unwrap(), msg);
    }

    #[test]
    fn padding_roundtrip() {
        for (min, max) in [(0, 16), (8, 64), (32, 32), (0, PAD_LEN_CAP)] {
            for seed in [1u32, 0xDEAD_BEEF, 42] {
                let mut buf = b"payload".to_vec();
                pad_append(&mut buf, min, max, seed);
                assert!(buf.len() >= 7 + min + 2, "pad + 2-char suffix present");
                assert!(buf.len() <= 7 + max.min(PAD_LEN_CAP) + 2);
                let stripped = pad_strip(&buf, min, max).expect("strip must invert append");
                assert_eq!(stripped, b"payload");
            }
        }
    }

    #[test]
    fn padding_disabled_is_byte_identical() {
        let mut buf = b"payload".to_vec();
        pad_append(&mut buf, 0, 0, 123);
        assert_eq!(buf, b"payload", "max=0 → no padding, no length suffix");
    }

    #[test]
    fn padding_varies_length_across_seeds() {
        let lens: alloc::collections::BTreeSet<usize> = (1..64u32)
            .map(|seed| {
                let mut buf = Vec::new();
                pad_append(&mut buf, 0, 200, seed);
                buf.len()
            })
            .collect();
        assert!(lens.len() > 1, "padding must blur the length distribution");
    }

    #[test]
    fn pad_strip_rejects_malformed_suffix() {
        // Too short / non-base64url suffix / out-of-range length all fail.
        assert_eq!(pad_strip(b"x", 0, 16), Err(TransformError::InvalidPadding));
        assert_eq!(
            pad_strip(b"payload\x00\xff", 0, 16),
            Err(TransformError::InvalidPadding)
        );
        // Suffix decodes to n=10 but the buffer only has 7 payload bytes.
        let mut buf = b"payload".to_vec();
        buf.push(URL_ALPHA[0]);
        buf.push(URL_ALPHA[10]);
        assert_eq!(pad_strip(&buf, 0, 16), Err(TransformError::InvalidPadding));
        // n=4 within range but below a nonzero min → desync detected.
        let mut buf = b"payload".to_vec();
        buf.extend_from_slice(b"abcd");
        buf.push(URL_ALPHA[0]);
        buf.push(URL_ALPHA[4]);
        assert_eq!(pad_strip(&buf, 8, 16), Err(TransformError::InvalidPadding));
    }
}
