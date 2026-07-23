//! RC4 stream cipher — the crypto core for sleep-mask memory encryption.
//!
//! Windows `SystemFunction032` (exported by advapi32) uses RC4 to encrypt the
//! implant image in place during sleep: the implant hands the key + the image
//! buffer, and advapi32 does KSA + PRGA internally. This pure-`no_std` module
//! is the matching core for the Nyx [`SleepmaskKit`](crate::SleepmaskKit)
//! encrypt/decrypt window so we never need to link advapi32 for it on the
//! dev host and can validate the round-trip in unit tests. The Windows-side
//! key derivation (per-build randomized material) lives in the implant config;
//! here we only implement standard RC4 (KSA + PRGA), in place: encrypt and
//! decrypt are the same XOR operation.
#![cfg_attr(not(test), allow(dead_code))]

/// RC4 state: the 256-byte permutation plus the two PRGA walking indices.
///
/// One [`Rc4`] instance owns its keystream cursor, so each instance produces a
/// distinct keystream suffix. For sleep-mask encrypt/decrypt the caller usually
/// wants a fresh [`Rc4::new`] per mask window so the keystream starts from the
/// top of the permutation each cycle — see [`Rc4::apply_oneshot`].
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Build a cipher from `key` by running the Key-Scheduling Algorithm.
    ///
    /// Panics on an empty key — RC4 has no defined behavior for a zero-length
    /// key and the sleep-mask caller always has per-build key material, so this
    /// is a programming error rather than a recoverable one.
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "rc4: empty key");
        let mut s = [0u8; 256];
        let mut k = 0u8;
        while k != 255 {
            s[usize::from(k)] = k;
            k = k.wrapping_add(1);
        }
        s[255] = 255;
        let mut j: u8 = 0;
        let mut i: usize = 0;
        while i < 256 {
            let ki = key[i % key.len()];
            j = j.wrapping_add(s[i]).wrapping_add(ki);
            s.swap(i, usize::from(j));
            i += 1;
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR `buf` in place against the keystream (encrypt == decrypt).
    ///
    /// Advances the internal cursor so repeated calls on the same instance form
    /// a continuous keystream. An empty slice is a no-op but still leaves the
    /// state valid for the next call.
    #[inline]
    pub fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let t = self.s[usize::from(self.i)]
                .wrapping_add(self.s[usize::from(self.j)]);
            *byte ^= self.s[usize::from(t)];
        }
    }

    /// Convenience: fresh cipher from `key`, then XOR `buf` in place.
    ///
    /// Equivalent to `Rc4::new(key).apply(buf)` but in one call. Useful for the
    /// one-shot mask window where the keystream always starts from KSA-zero.
    #[inline]
    pub fn apply_oneshot(key: &[u8], buf: &mut [u8]) {
        let mut c = Self::new(key);
        c.apply(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical RC4 KAT (original spec test vector):
    /// RC4(b"Key", b"Plaintext") = BB F3 16 E8 D9 40 AF 0A D3
    #[test]
    fn kat_key_plaintext() {
        let mut buf = *b"Plaintext";
        Rc4::apply_oneshot(b"Key", &mut buf);
        assert_eq!(
            buf,
            [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
    }

    /// Wikipedia KAT: RC4(b"Wiki", b"pedia") = 10 21 BF 04 20.
    ///
    /// NOTE: hand-traced KSA+PRGA and cross-checked against an independent
    /// Python implementation — the canonical Wikipedia vector is
    /// `[10, 21, BF, 04, 20]`, *not* the occasionally-misquoted
    /// `[60, 20, 2D, E4, 50]`. We assert the verified value.
    #[test]
    fn kat_wiki_pedia() {
        let mut buf = *b"pedia";
        Rc4::apply_oneshot(b"Wiki", &mut buf);
        assert_eq!(buf, [0x10, 0x21, 0xBF, 0x04, 0x20]);
    }

    /// Applying the same key twice returns the original buffer (RC4 is an XOR
    /// stream cipher, so encrypt and decrypt are the identical operation).
    #[test]
    fn round_trip_symmetry() {
        let key = b"nyx-sleepmask-roundtrip-test";
        let original = *b"some payload bytes to mask";
        let mut buf = original;
        Rc4::apply_oneshot(key, &mut buf);
        // Must have actually changed — guards against a no-op regression.
        assert_ne!(buf, original, "apply did not modify the buffer");
        Rc4::apply_oneshot(key, &mut buf);
        assert_eq!(buf, original, "second apply did not restore the plaintext");
    }

    /// Empty buffer is a no-op; the cipher state survives for a later call.
    #[test]
    fn empty_apply_is_noop_and_state_survives() {
        let key = b"Key";
        let mut c = Rc4::new(key);
        let mut empty: [u8; 0] = [];
        c.apply(&mut empty); // must not panic / must not advance cursor meaningfully

        // State still valid: now encrypt the canonical plaintext and the first
        // byte must match the known-good KAT (proves KSA wasn't corrupted).
        let mut buf = *b"Plaintext";
        c.apply(&mut buf);
        assert_eq!(buf[0], 0xBB);
    }

    /// Same keystream as two separate `apply` calls concatenated (cursor
    /// continuity). Encrypting 9 bytes in one shot must equal 4 + 5 in two
    /// calls on the same instance.
    #[test]
    fn keystream_continuity_across_apply_calls() {
        let key = b"Key";
        let one_shot_expected = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];

        let mut split: [u8; 9] = *b"Plaintext";
        let mut c = Rc4::new(key);
        c.apply(&mut split[..4]);
        c.apply(&mut split[4..]);
        assert_eq!(split, one_shot_expected);
    }

    /// `Rc4::new` panics on an empty key rather than silently producing a
    /// degenerate keystream.
    #[test]
    #[should_panic(expected = "rc4: empty key")]
    fn empty_key_panics() {
        let _ = Rc4::new(b"");
    }
}
