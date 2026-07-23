//! Minimal little-endian binary codec primitives. Used by [`crate::msg`] so
//! the wire format stays tiny, deterministic, and `no_std`-portable.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Codec errors. `no_std`-friendly: hand-rolled `Debug`/`Display` (thiserror's
/// derive needs `std::error::Error`, unavailable under `no_std`). When the `std`
/// feature is on, `std::error::Error` is also implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Eof,
    Utf8,
    BadLen(usize),
    BadTag(u8),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Eof => f.write_str("unexpected end of input"),
            WireError::Utf8 => f.write_str("invalid utf-8 string"),
            WireError::BadLen(n) => write!(f, "invalid length field: {n}"),
            WireError::BadTag(t) => write!(f, "invalid tag byte: {t}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WireError {}

/// Hard upper bound on any single length-prefixed blob or string written by
/// [`Writer::blob`] / [`Writer::str`]. A u32 length field can nominally address
/// 4 GiB, but a length that large on a beacon frame is either malformed or an
/// attempt to induce an oversized allocation. We cap it well below MAX_CT_LEN
/// (512 KiB) — anything that legitimately goes over the wire is split into
/// chunks elsewhere (file transfers, channel data, etc.). Defense-in-depth on
/// the encode side; the decode side already uses u32 lengths off the wire.
pub const MAX_BLOB_LEN: usize = 256 * 1024; // 256 KiB

/// Pure length check, factored out of [`Writer::blob`] so it can be unit-tested
/// in isolation and reused by callers that compute lengths indirectly.
///
/// Returns [`WireError::BadLen`] when `len` exceeds [`MAX_BLOB_LEN`] (the only
/// failure mode — lengths of 0 or any smaller value are fine on the encode
/// side; an empty string is a legitimately encodable value, even if a beacon
/// level frame rejects zero plaintext elsewhere — see `frame::MIN_CT_LEN`).
pub fn check_blob_len(len: usize) -> Result<(), WireError> {
    if len <= MAX_BLOB_LEN {
        Ok(())
    } else {
        Err(WireError::BadLen(len))
    }
}

pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// A length-prefixed (u32 LE) byte blob. Returns [`WireError::BadLen`] if
    /// `v.len()` exceeds [`MAX_BLOB_LEN`] — defense-in-depth against a caller
    /// bug or hostile input propagating a multi-GiB length field onto the wire
    /// (a u32 can nominally address 4 GiB, which would allocate
    /// `4 + v.len()` bytes and could OOM a constrained beacon heap). Empty
    /// blobs are allowed: a zero-length blob is a legitimate value (e.g. an
    /// empty Upload's payload chunk); the *frame* layer separately rejects
    /// zero-plaintext bodies via `frame::MIN_CT_LEN`.
    pub fn blob(&mut self, v: &[u8]) -> Result<(), WireError> {
        check_blob_len(v.len())?;
        let len = v
            .len()
            .try_into()
            .expect("checked against MAX_BLOB_LEN <= u32::MAX");
        self.u32(len);
        self.buf.extend_from_slice(v);
        Ok(())
    }

    /// A length-prefixed UTF-8 string. Same length contract as [`blob`]; the
    /// bytes are emitted as-is without a separate UTF-8 validation pass (the
    /// receiver validates on decode via [`Reader::str`]).
    pub fn str(&mut self, v: &str) -> Result<(), WireError> {
        self.blob(v.as_bytes())
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        let b = self.data.get(self.pos).copied().ok_or(WireError::Eof)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn blob(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        // Defense-in-depth: mirror Writer::blob's cap so a hostile or buggy
        // u32 length field can't drive a huge take() even if a future caller
        // routes through Reader without the frame layer's MAX_CT_LEN bound.
        check_blob_len(len)?;
        self.take(len)
    }

    pub fn str(&mut self) -> Result<String, WireError> {
        let b = self.blob()?;
        String::from_utf8(b.to_vec()).map_err(|_| WireError::Utf8)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if n > self.remaining() {
            return Err(WireError::Eof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_blob_len_accepts_at_cap() {
        // Boundary: exactly MAX_BLOB_LEN is OK (<=).
        assert!(check_blob_len(MAX_BLOB_LEN).is_ok());
    }

    #[test]
    fn check_blob_len_rejects_over_cap() {
        // One byte over the cap must fail — defense-in-depth against a caller
        // bug or hostile input propagating a multi-GiB length field.
        assert_eq!(
            check_blob_len(MAX_BLOB_LEN + 1),
            Err(WireError::BadLen(MAX_BLOB_LEN + 1))
        );
    }

    #[test]
    fn check_blob_len_accepts_zero() {
        // Empty blobs are legitimate (e.g. empty Upload chunk); only the frame
        // layer rejects zero-plaintext via MIN_CT_LEN.
        assert!(check_blob_len(0).is_ok());
    }

    #[test]
    fn writer_blob_at_cap_encodes() {
        let mut w = Writer::new();
        let v = vec![0u8; MAX_BLOB_LEN];
        w.blob(&v).expect("blob at cap should encode");
        // layout: u32 LE len + payload
        assert_eq!(&w.buf[0..4], (MAX_BLOB_LEN as u32).to_le_bytes());
        assert_eq!(w.buf.len(), 4 + MAX_BLOB_LEN);
    }

    #[test]
    fn writer_blob_over_cap_errors() {
        let mut w = Writer::new();
        let v = vec![0u8; MAX_BLOB_LEN + 1];
        let err = w.blob(&v).expect_err("over-cap blob must error");
        assert_eq!(err, WireError::BadLen(MAX_BLOB_LEN + 1));
        // Critical: nothing should have been written — no length prefix, no payload.
        assert!(w.buf.is_empty(), "writer must not partially emit on BadLen");
    }

    #[test]
    fn writer_str_over_cap_errors() {
        let mut w = Writer::new();
        let s = "x".repeat(MAX_BLOB_LEN + 1);
        let err = w.str(&s).expect_err("over-cap str must error");
        assert_eq!(err, WireError::BadLen(MAX_BLOB_LEN + 1));
        assert!(w.buf.is_empty());
    }

    #[test]
    fn writer_blob_empty_encodes_zero_len() {
        let mut w = Writer::new();
        w.blob(&[]).expect("empty blob should encode");
        assert_eq!(w.buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn reader_blob_rejects_over_cap() {
        // A hostile u32 length field must trip check_blob_len BEFORE take(),
        // even though take() would also Eof — defense-in-depth so Reader and
        // Writer enforce the same cap symmetrically.
        let over = (MAX_BLOB_LEN as u32 + 1).to_le_bytes();
        let mut r = Reader::new(&over);
        let err = r.blob().expect_err("over-cap declared len must error");
        assert_eq!(err, WireError::BadLen(MAX_BLOB_LEN + 1));
    }

    #[test]
    fn reader_blob_accepts_at_cap() {
        // Exactly MAX_BLOB_LEN is permitted by check_blob_len; take() then
        // fails with Eof since we don't supply payload here — but the failure
        // must be Eof, NOT BadLen.
        let mut buf = (MAX_BLOB_LEN as u32).to_le_bytes().to_vec();
        buf.extend(std::iter::repeat_n(0u8, MAX_BLOB_LEN));
        let mut r = Reader::new(&buf);
        r.blob().expect("blob at cap with full payload must decode");
    }
}
