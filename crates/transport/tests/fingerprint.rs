//! Fingerprint engine tests: JA3/JA4 self-consistency + structure, ClientHello
//! parsing, and HTTP/2 (Akamai) frame parsing.

use md5::{Digest, Md5};
use nyx_transport::h2::from_frames;
use nyx_transport::tls::{ja3, ja4, parse_client_hello, ClientHello};
use nyx_transport::{akamai_h2, H2Fingerprint};

fn sample_hello() -> ClientHello {
    ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![0x1301, 0x1302, 0x1303],
        // SNI is the first extension (=> JA4_c prefix 'a').
        extensions: vec![(0, vec![]), (43, vec![]), (10, vec![]), (11, vec![])],
        sni: Some("example.com".into()),
        alpn: Some("h2".into()),
        supported_versions: vec![0x0304, 0x0303],
        supported_groups: vec![0x001d, 0x0017],
        ec_point_formats: vec![0],
        signature_algorithms: vec![0x0403, 0x0804],
    }
}

#[test]
fn ja3_matches_md5_of_canonical_join() {
    let ch = sample_hello();
    let expected = format!(
        "{},{},{},{},{}",
        0x0303, "4865-4866-4867", "0-43-10-11", "29-23", "0"
    );
    let want = hex::encode(Md5::digest(expected.as_bytes()));
    assert_eq!(ja3(&ch), want);
    assert_eq!(ja3(&ch).len(), 32);
}

#[test]
fn ja4_structure_and_consistency() {
    let ch = sample_hello();
    let f = ja4(&ch);
    let parts: Vec<&str> = f.split('_').collect();
    assert_eq!(parts.len(), 3, "JA4 is a_b_c: {f}");
    assert_eq!(parts[0].len(), 10, "ja4_a is 10 chars: {f}");
    assert!(parts[0].starts_with("t13d"), "transport=tls1.3+SNI: {f}");
    assert_eq!(parts[1].len(), 12, "ja4_b is 12 hex: {f}");
    assert!(
        parts[2].len() == 13 && parts[2].starts_with('a'),
        "ja4_c is prefix+12hex, SNI-first => 'a': {f}"
    );
    assert_eq!(parts[2][1..].len(), 12);
    // Determinism.
    assert_eq!(ja4(&ch), ja4(&sample_hello()));
}

#[test]
fn ja4_drops_grease_and_counts_ciphers_extensions() {
    let mut ch = sample_hello();
    // Inject GREASE into ciphers + extensions; counts/hashes must ignore them.
    ch.cipher_suites = vec![0x0a0a, 0x1301, 0x1a1a, 0x1302, 0x1303];
    ch.extensions = vec![
        (0x0a0a, vec![]),
        (0, vec![]),
        (0x2a2a, vec![]),
        (43, vec![]),
        (10, vec![]),
        (11, vec![]),
    ];
    let f = ja4(&ch);
    let a = f.split('_').next().unwrap();
    // 3 non-GREASE ciphers, 4 non-GREASE extensions, SNI present, alpn h2.
    assert_eq!(a, "t13d0304h2", "GREASE excluded from counts: {a}");
}

#[test]
fn ja4_no_sni_yields_i_prefix() {
    let mut ch = sample_hello();
    ch.sni = None;
    ch.extensions = vec![(43, vec![]), (10, vec![]), (11, vec![]), (0, vec![])];
    let f = ja4(&ch);
    let c = f.split('_').nth(2).unwrap();
    assert!(c.starts_with('i'), "no SNI-first => 'i' prefix: {f}");
}

#[test]
fn parses_a_real_clienthello_record() {
    // Minimal ClientHello: ver 0x0303, random(32), sid(0), 1 cipher (0x00ff),
    // compression(1: null), one extension = SNI for "a.com".
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id len
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]); // 1 cipher
    body.push(1);
    body.push(0x00); // compression: null
                     // SNI ext: type 0, len 8, data = list_len(2)+name_type(1)+name_len(2)+"a.com"
    let name = b"a.com";
    let mut ext = Vec::new();
    let list_len = 1 + 2 + name.len() as u16;
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0); // name type host
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);
    body.extend_from_slice(&((ext.len() + 4) as u16).to_be_bytes()); // extensions_len
    body.extend_from_slice(&[0x00, 0x00]); // SNI type
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // Handshake header (type 0x01, 3-byte len) + record header.
    let hlen = body.len();
    let mut hs = vec![
        0x01,
        (hlen >> 16) as u8,
        ((hlen >> 8) & 0xff) as u8,
        (hlen & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);
    let mut rec = vec![
        0x16,
        0x03,
        0x01,
        ((hs.len() >> 8) & 0xff) as u8,
        (hs.len() & 0xff) as u8,
    ];
    rec.extend_from_slice(&hs);

    let ch = parse_client_hello(&rec).expect("parse synthetic ClientHello");
    assert_eq!(ch.cipher_suites, vec![0x00ff]);
    assert_eq!(ch.sni.as_deref(), Some("a.com"));
}

#[test]
fn sniffs_client_hello_from_stream_and_returns_fingerprints() {
    use nyx_transport::sniff_client_hello;
    // Build the same synthetic ClientHello record as above.
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
    body.push(1);
    body.push(0x00);
    let name = b"a.com";
    let mut ext = Vec::new();
    let list_len = 1 + 2 + name.len() as u16;
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);
    body.extend_from_slice(&((ext.len() + 4) as u16).to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let hlen = body.len();
    let mut hs = vec![
        0x01,
        (hlen >> 16) as u8,
        ((hlen >> 8) & 0xff) as u8,
        (hlen & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);
    let mut rec = vec![
        0x16,
        0x03,
        0x01,
        ((hs.len() >> 8) & 0xff) as u8,
        (hs.len() & 0xff) as u8,
    ];
    rec.extend_from_slice(&hs);

    // Sniff from a cursor over the record bytes.
    let (replayed, ja3, ja4) = sniff_client_hello(std::io::Cursor::new(&rec)).unwrap();
    assert_eq!(
        replayed, rec,
        "sniff must return the full record for replay"
    );
    assert!(ja3.is_some(), "JA3 must be computed");
    assert!(ja4.is_some(), "JA4 must be computed");
    // Sanity: the JA3 must be a 32-hex MD5.
    assert_eq!(ja3.unwrap().len(), 32);

    // A non-TLS first byte yields no fingerprints.
    let (_, j3, j4) = sniff_client_hello(std::io::Cursor::new(&[0x47u8, 0, 0, 0, 0])).unwrap();
    assert!(j3.is_none() && j4.is_none());
}

#[test]
fn parses_http2_settings_and_window_update() {
    // Connection preface + SETTINGS(1:65536; 4:6291456) + WINDOW_UPDATE(15663105).
    let mut raw = Vec::new();
    raw.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // SETTINGS frame: len 12, type 0x04, flags 0, stream 0, payload 2 pairs.
    let settings = [
        0x00u8, 0x01, 0x00, 0x01, 0x00, 0x00, // id=1 val=65536
        0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // id=4 val=6291456
    ];
    push_frame(&mut raw, 0x04, 0, &settings);
    // WINDOW_UPDATE frame: len 4, type 0x08, stream 0, increment 15663105.
    let wu = 15663105u32.to_be_bytes();
    push_frame(&mut raw, 0x08, 0, &wu);

    let fp = from_frames(&raw).unwrap();
    assert_eq!(fp.settings, vec![(1, 65536), (4, 6291456)]);
    assert_eq!(fp.window_update, 15663105);
    assert_eq!(fp.priorities, 0);
}

#[test]
fn akamai_string_format() {
    let fp = H2Fingerprint {
        settings: vec![(1, 65536), (4, 6291456)],
        window_update: 15663105,
        priorities: 0,
        pseudo_order: vec!['m', 'a', 's', 'p'],
    };
    assert_eq!(akamai_h2(&fp), "1:65536;4:6291456|15663105|0|m,a,s,p");
}

fn push_frame(out: &mut Vec<u8>, ftype: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len();
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(ftype);
    out.push(0); // flags
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
}
