//! Minimal little-endian binary codec primitives. Used by [`crate::msg`] so
//! the wire format stays tiny, deterministic, and `no_std`-portable.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid utf-8 string")]
    Utf8,
    #[error("invalid length field: {0}")]
    BadLen(usize),
    #[error("invalid tag byte: {0}")]
    BadTag(u8),
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

    /// A length-prefixed (u32 LE) byte blob.
    pub fn blob(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }

    /// A length-prefixed UTF-8 string.
    pub fn str(&mut self, v: &str) {
        self.blob(v.as_bytes());
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
