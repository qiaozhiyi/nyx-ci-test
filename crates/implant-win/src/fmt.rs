//! Minimal formatting helpers (no `format!`/`to_string` under no_std).
//!
//! These are shared across entry.rs, hashdump.rs, and pivot.rs — each had its
//! own `push_dec` / `push_decimal` copy-paste.

/// Append `v` in decimal to `s` (u32 variant — for hashdump / pivot).
pub(crate) fn push_decimal_u32(s: &mut crate::heap::String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // tmp[i..] is valid ASCII digits; push each as a char.
    for &b in &tmp[i..] {
        s.push(b as char);
    }
}

/// Append `n` in decimal to `s` (u64 variant — for entry.rs).
pub(crate) fn push_decimal_u64(s: &mut crate::heap::String, n: u64) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut m = n;
    while m > 0 {
        i -= 1;
        buf[i] = b'0' + (m % 10) as u8;
        m /= 10;
    }
    for &b in &buf[i..] {
        s.push(b as char);
    }
}
