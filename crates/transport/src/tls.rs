//! TLS ClientHello parsing + JA3 / JA4 computation.
//!
//! JA3 = MD5(`version,ciphers,extensions,curves,ec_point_formats`), lists as
//! dash-joined decimals (GREASE *included* — JA3 predates GREASE removal).
//!
//! JA4 = `{ja4_a}_{ja4_b}_{ja4_c}` (per FoxIO JA4.md):
//! - `ja4_a` (10): transport(`t`) + version(2: `13`/`12`/…) + SNI(`d`/`i`) +
//!   cipher-count(2 hex) + extension-count(2 hex) + ALPN(2 chars).
//! - `ja4_b` (12 hex): SHA256[:12] of the GREASE-free cipher list, sorted, as
//!   4-hex values joined by `-`.
//! - `ja4_c`: `{a|i}` + SHA256[:12] of (GREASE/SNI/ALPN-free extensions, sorted,
//!   4-hex joined `-` + `_` + signature algorithms in original order, joined
//!   `-`). The leading `a`/`i` is `a` when SNI is the first extension in the
//!   original ClientHello (FoxIO convention), else `i`. **Confirm this prefix
//!   rule against a reference vector before relying on exact-match allowlisting.**

use md5::{Digest, Md5};
use sha2::Sha256;

/// Parsed TLS ClientHello (the fields JA3/JA4 need).
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    /// `(extension_type, raw_extension_data)`, in ClientHello order.
    pub extensions: Vec<(u16, Vec<u8>)>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
}

/// GREASE values: `0x?a?a` (both bytes equal, low nibble 0xa) for both cipher
/// suites and extension types.
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0xFF) && (v & 0x0F0F) == 0x0A0A
}

fn u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

/// Parse a TLS ClientHello from a raw record (`ContentType || Version || Length
/// || Handshake...`). Returns the fields JA3/JA4 need.
pub fn parse_client_hello(rec: &[u8]) -> Result<ClientHello, &'static str> {
    if rec.len() < 5 {
        return Err("record too short");
    }
    let hs = &rec[5..];
    if hs.len() < 4 {
        return Err("handshake header too short");
    }
    if hs[0] != 1 {
        return Err("handshake message is not a ClientHello");
    }
    let hlen = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let body = hs.get(4..4 + hlen).ok_or("handshake length mismatch")?;
    if body.len() < 2 + 32 {
        return Err("clienthello too short");
    }
    let legacy_version = u16be(body, 0);
    let mut p = 2 + 32; // version + random
    if p >= body.len() {
        return Err("missing session id");
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;

    if p + 2 > body.len() {
        return Err("missing cipher list");
    }
    let cs_len = u16be(body, p) as usize;
    p += 2;
    let mut cipher_suites = Vec::new();
    let cs_end = p + cs_len;
    let mut i = p;
    while i + 2 <= cs_end && i + 2 <= body.len() {
        cipher_suites.push(u16be(body, i));
        i += 2;
    }
    p = cs_end;

    if p >= body.len() {
        return Err("missing compression");
    }
    let comp_len = body[p] as usize;
    p += 1 + comp_len;

    if p + 2 > body.len() {
        // No extensions at all is legal.
        return Ok(ClientHello {
            legacy_version,
            cipher_suites,
            extensions: Vec::new(),
            sni: None,
            alpn: None,
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
        });
    }
    let ext_len = u16be(body, p) as usize;
    p += 2;
    let ext_end = p + ext_len;

    let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut supported_versions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();

    let mut q = p;
    while q + 4 <= ext_end && q + 4 <= body.len() {
        let etype = u16be(body, q);
        let elen = u16be(body, q + 2) as usize;
        q += 4;
        let edata = body
            .get(q..q + elen)
            .ok_or("extension data out of bounds")?;
        extensions.push((etype, edata.to_vec()));
        match etype {
            0 => {
                // SNI: list_len(2), name_type(1), name_len(2), name.
                if edata.len() >= 5 {
                    let nl = u16be(edata, 3) as usize;
                    if 5 + nl <= edata.len() {
                        sni = Some(String::from_utf8_lossy(&edata[5..5 + nl]).into_owned());
                    }
                }
            }
            10 => supported_groups.extend(read_u16_list(edata)),
            11 => {
                if !edata.is_empty() {
                    let fl = edata[0] as usize;
                    ec_point_formats = edata[1..1 + fl.min(edata.len() - 1)].to_vec();
                }
            }
            13 => signature_algorithms.extend(read_u16_list(edata)),
            16 => {
                // ALPN: list_len(2), proto_len(1), proto.
                if edata.len() >= 4 {
                    let pl = edata[2] as usize;
                    if 3 + pl <= edata.len() {
                        alpn = Some(String::from_utf8_lossy(&edata[3..3 + pl]).into_owned());
                    }
                }
            }
            43
                // supported_versions: list_len(1), versions(2 each).
                if !edata.is_empty() => {
                    let vl = edata[0] as usize;
                    let mut k = 1;
                    while k + 2 <= 1 + vl && k + 2 <= edata.len() {
                        supported_versions.push(u16be(edata, k));
                        k += 2;
                    }
                }
            _ => {}
        }
        q += elen;
    }

    Ok(ClientHello {
        legacy_version,
        cipher_suites,
        extensions,
        sni,
        alpn,
        supported_versions,
        supported_groups,
        ec_point_formats,
        signature_algorithms,
    })
}

fn read_u16_list(edata: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    if edata.len() < 2 {
        return out;
    }
    let total = u16be(edata, 0) as usize;
    let mut k = 2;
    while k + 2 <= 2 + total && k + 2 <= edata.len() {
        out.push(u16be(edata, k));
        k += 2;
    }
    out
}

/// Compute JA3 (MD5, 32 hex) for a parsed ClientHello.
pub fn ja3(ch: &ClientHello) -> String {
    let ciphers = ch
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let exts = ch
        .extensions
        .iter()
        .map(|(t, _)| t.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curves = ch
        .supported_groups
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ecpf = ch
        .ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let joined = format!(
        "{},{},{},{},{}",
        ch.legacy_version, ciphers, exts, curves, ecpf
    );
    let digest = Md5::digest(joined.as_bytes());
    hex::encode(digest)
}

fn sha256_12hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    hex::encode(&d[..6]) // first 6 bytes == first 12 hex chars
}

fn hex4(v: u16) -> String {
    format!("{:04x}", v)
}

/// Compute JA4 (`a_b_c`) for a parsed ClientHello.
pub fn ja4(ch: &ClientHello) -> String {
    // ja4_a
    let ver_val = ch
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(ch.legacy_version);
    let ver = match ver_val {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni = if ch.sni.is_some() { 'd' } else { 'i' };
    let ncs = ch
        .cipher_suites
        .iter()
        .filter(|c| !is_grease(**c))
        .count()
        .min(99);
    let nex = ch
        .extensions
        .iter()
        .filter(|(t, _)| !is_grease(*t))
        .count()
        .min(99);
    let alpn = ch
        .alpn
        .as_deref()
        .map(|a| a.chars().take(2).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "00".to_string());
    let ja4_a = format!("t{ver}{sni}{ncs:02}{nex:02}{alpn}");

    // ja4_b — sorted GREASE-free ciphers.
    let mut cs: Vec<u16> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    cs.sort_unstable();
    let ja4_b = if cs.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_12hex(
            cs.iter()
                .copied()
                .map(hex4)
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        )
    };

    // ja4_c — sorted GREASE/SNI/ALPN-free extensions + original-order sig algs.
    let mut exts: Vec<u16> = ch
        .extensions
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease(*t) && *t != 0 && *t != 16)
        .collect();
    let prefix = if ch
        .extensions
        .iter()
        .map(|(t, _)| *t)
        .find(|t| !is_grease(*t))
        == Some(0)
    {
        'a'
    } else {
        'i'
    };
    exts.sort_unstable();
    let ja4_c = if exts.is_empty() && ch.signature_algorithms.is_empty() {
        "000000000000".to_string()
    } else {
        let ext_str = exts.iter().copied().map(hex4).collect::<Vec<_>>().join(",");
        let sig_str = ch
            .signature_algorithms
            .iter()
            .copied()
            .map(hex4)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}{}",
            prefix,
            sha256_12hex(format!("{ext_str}_{sig_str}").as_bytes())
        )
    };

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

/// Read the first TLS record (the ClientHello) from a byte stream that has just
/// been accepted off the wire. Returns the raw record bytes (so the caller can
/// prepend them back in front of the rest of the stream before handing it to a
/// TLS stack) plus the JA3 and JA4 strings.
///
/// This is the team server's inbound fingerprint probe: it peeks the ClientHello
/// *before* rustls consumes the stream, computes the fingerprints, then replays
/// the bytes so the handshake completes normally.
pub fn sniff_client_hello<R: std::io::Read>(
    mut r: R,
) -> std::io::Result<(Vec<u8>, Option<String>, Option<String>)> {
    // TLS record header: ContentType(1) Version(2) Length(2). Read header first.
    let mut header = [0u8; 5];
    let _ = read_exact(&mut r, &mut header);
    // ContentType 22 = Handshake. If it isn't, this isn't a TLS ClientHello.
    if header[0] != 22 {
        return Ok((header.to_vec(), None, None));
    }
    let rec_len = ((header[3] as usize) << 8) | header[4] as usize;
    if rec_len > 16384 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello record size exceeds TLS maximum",
        ));
    }
    let mut payload = vec![0u8; rec_len];
    let n = read_exact(&mut r, &mut payload)?;
    let payload = payload[..n].to_vec();
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&payload);

    match parse_client_hello(&record) {
        Ok(ch) => {
            let ja3 = Some(ja3(&ch));
            let ja4 = Some(ja4(&ch));
            Ok((record, ja3, ja4))
        }
        Err(_) => Ok((record, None, None)),
    }
}

/// Read the full buffer, returning how many bytes were actually obtained (may be
/// less on EOF).
fn read_exact<R: std::io::Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}
