//! Adversarial (attacker-view) tests for the TLS fingerprint engine.
//!
//! Threat model: `parse_client_hello` / `sniff_client_hello` run on the team
//! server's inbound path, peeking bytes sent by ANY internet client before
//! rustls consumes them. A hostile (or merely broken) peer can send arbitrary
//! garbage with malicious length fields. The guarantee under test: NO input
//! may panic the parser, the JA3/JA4 computers, or the sniffer — errors are
//! returned as `Err` / `None` and the stream is replayed intact.

use nyx_transport::tls::{ja3, ja4, parse_client_hello, sniff_client_hello, ClientHello};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// A realistic TLS 1.3 ClientHello record with SNI, ALPN, supported_versions,
/// supported_groups, ec_point_formats, and signature_algorithms extensions.
fn realistic_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&[0x42u8; 32]); // random
    body.push(0); // session id len = 0
                  // ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20...
    body.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
    body.push(1);
    body.push(0x00); // compression: null

    let mut exts = Vec::new();
    // SNI: type 0
    let name = b"cdn.example.com";
    let mut sni = Vec::new();
    sni.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    push_ext(&mut exts, 0, &sni);
    // supported_versions: type 43 → TLS 1.3 + 1.2
    push_ext(&mut exts, 43, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    // supported_groups: type 10 → x25519, secp256r1
    push_ext(&mut exts, 10, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    // ec_point_formats: type 11 → uncompressed
    push_ext(&mut exts, 11, &[0x01, 0x00]);
    // signature_algorithms: type 13 → ecdsa_secp256r1_sha256, ed25519
    push_ext(&mut exts, 13, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x07]);
    // ALPN: type 16 → h2
    push_ext(&mut exts, 16, &[0x00, 0x03, 0x02, b'h', b'2']);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Handshake header + record header.
    let hlen = body.len();
    let mut rec = vec![
        0x16, // ContentType: handshake
        0x03,
        0x01, // record version TLS 1.0
        ((hlen + 4) >> 8) as u8,
        ((hlen + 4) & 0xff) as u8,
        0x01, // HandshakeType: ClientHello
        (hlen >> 16) as u8,
        ((hlen >> 8) & 0xff) as u8,
        (hlen & 0xff) as u8,
    ];
    rec.extend_from_slice(&body);
    rec
}

fn push_ext(out: &mut Vec<u8>, etype: u16, data: &[u8]) {
    out.extend_from_slice(&etype.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Assert both fingerprints compute without panicking and keep the structural
/// invariants:
/// JA3 = 32 hex; JA4 = `a_b_c`; ja4_a starts `t<ver2><d|i>` with 2-digit
/// counts and is exactly 10 chars; ja4_b = 12 hex; ja4_c = `{a|i}` prefix +
/// 12 hex (always 13 chars, including the empty case).
fn assert_fingerprints_sane(ch: &ClientHello) {
    let j3 = ja3(ch);
    assert_eq!(j3.len(), 32, "JA3 must always be 32 hex chars");
    assert!(j3.chars().all(|c| c.is_ascii_hexdigit()));
    let j4 = ja4(ch);
    let parts: Vec<&str> = j4.split('_').collect();
    assert_eq!(parts.len(), 3, "JA4 must always be a_b_c: {j4}");
    let a = parts[0];
    assert!(a.starts_with('t'), "ja4_a starts with transport 't': {j4}");
    assert!(
        a.len() >= 8 && a[1..3].chars().all(|c| c.is_ascii_digit()),
        "ja4_a has a 2-digit version: {j4}"
    );
    assert!(
        matches!(a.chars().nth(3), Some('d') | Some('i')),
        "ja4_a has an SNI flag at position 3: {j4}"
    );
    assert!(
        a[4..6].chars().all(|c| c.is_ascii_digit()) && a[6..8].chars().all(|c| c.is_ascii_digit()),
        "ja4_a cipher/extension counts are 2 digits each: {j4}"
    );
    assert_eq!(a.len(), 10, "ja4_a is always exactly 10 chars: {j4}");
    assert_eq!(parts[1].len(), 12, "ja4_b is always 12 hex: {j4}");
    assert!(
        parts[2].len() == 13 && matches!(parts[2].chars().next(), Some('a') | Some('i')),
        "ja4_c is always the a/i prefix + 12 hex: {j4}"
    );
}

// ---------------------------------------------------------------------------
// 1. Truncation & mutation fuzz over a real ClientHello record
// ---------------------------------------------------------------------------

#[test]
fn every_record_prefix_parses_without_panic() {
    let rec = realistic_hello();
    // Control: the full record parses and fingerprints fine.
    let ch = parse_client_hello(&rec).expect("fixture record must parse");
    assert_fingerprints_sane(&ch);
    assert_eq!(ch.sni.as_deref(), Some("cdn.example.com"));
    assert_eq!(ch.alpn.as_deref(), Some("h2"));

    for len in 0..rec.len() {
        // Must return (Ok or Err) — never panic, never hang.
        if let Ok(ch) = parse_client_hello(&rec[..len]) {
            // A truncated record that still "parses" (e.g. legal truncation at
            // an extension boundary) must still fingerprint sanely.
            assert_fingerprints_sane(&ch);
        }
    }
}

#[test]
fn every_single_byte_mutation_never_panics() {
    let rec = realistic_hello();
    for pos in 0..rec.len() {
        for pattern in [0xFFu8, 0x01, 0x80] {
            let mut bad = rec.clone();
            bad[pos] ^= pattern;
            if bad == rec {
                continue;
            }
            if let Ok(ch) = parse_client_hello(&bad) {
                assert_fingerprints_sane(&ch);
            }
        }
    }
}

#[test]
fn deterministic_pseudorandom_garbage_never_panics() {
    // xorshift64* PRNG — deterministic, no external dep. Feeds the parser pure
    // garbage of every length up to 512 bytes, plus garbage with a valid
    // record/handshake preamble so the deep length fields get exercised.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u8
    };

    for len in 0..=512usize {
        let garbage: Vec<u8> = (0..len).map(|_| next()).collect();
        if let Ok(ch) = parse_client_hello(&garbage) {
            assert_fingerprints_sane(&ch);
        }
    }

    for _ in 0..2000 {
        let len = 9 + (next() as usize) * 2; // >= record+handshake header size
        let mut g: Vec<u8> = (0..len).map(|_| next()).collect();
        g[0] = 0x16; // valid ContentType
        g[5] = 0x01; // valid HandshakeType: ClientHello
        if let Ok(ch) = parse_client_hello(&g) {
            assert_fingerprints_sane(&ch);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Targeted hostile length fields
// ---------------------------------------------------------------------------

/// Build a record from a hand-crafted body (adds handshake+record headers).
fn wrap_body(body: &[u8]) -> Vec<u8> {
    let hlen = body.len();
    let mut rec = vec![
        0x16,
        0x03,
        0x01,
        ((hlen + 4) >> 8) as u8,
        ((hlen + 4) & 0xff) as u8,
        0x01,
        (hlen >> 16) as u8,
        ((hlen >> 8) & 0xff) as u8,
        (hlen & 0xff) as u8,
    ];
    rec.extend_from_slice(body);
    rec
}

/// Minimal fixed prefix: version + random, then caller-controlled tail.
fn body_with_tail(tail: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(tail);
    body
}

#[test]
fn hostile_handshake_length_field_is_rejected() {
    let rec = realistic_hello();
    // Handshake length (bytes 6..9) claims more than the record carries.
    let mut bad = rec.clone();
    bad[6] = 0xFF;
    bad[7] = 0xFF;
    bad[8] = 0xFF;
    assert!(parse_client_hello(&bad).is_err());
    // Claims less: the parser must not read past the declared body.
    let mut bad2 = rec.clone();
    bad2[6] = 0;
    bad2[7] = 0;
    bad2[8] = 2;
    assert!(parse_client_hello(&bad2).is_err());
}

#[test]
fn hostile_session_id_len_is_rejected_or_bounded() {
    // sid_len = 255 with no room left.
    let body = body_with_tail(&[0xFF]);
    assert!(parse_client_hello(&wrap_body(&body)).is_err());
    // sid_len consumes the whole rest of the body.
    let mut tail = vec![200u8];
    tail.extend(std::iter::repeat_n(0u8, 200));
    let body = body_with_tail(&tail);
    assert!(parse_client_hello(&wrap_body(&body)).is_err());
}

#[test]
fn hostile_cipher_list_len_is_bounded() {
    // sid_len=0, then cs_len = 0xFFFF with a short body.
    let body = body_with_tail(&[0x00, 0xFF, 0xFF, 0x13, 0x01]);
    assert!(parse_client_hello(&wrap_body(&body)).is_err());
    // cs_len huge but body padded to match — parser must bound the walk to
    // the body and then fail on the missing compression list, not index OOB.
    let mut tail = vec![0x00, 0x10, 0x00]; // sid 0, cs_len 4096
    tail.extend(std::iter::repeat_n(0u8, 4096));
    let body = body_with_tail(&tail);
    let _ = parse_client_hello(&wrap_body(&body)); // no panic; result irrelevant
}

#[test]
fn hostile_compression_len_is_bounded() {
    // sid 0, one cipher, comp_len = 0xFF with no room.
    let body = body_with_tail(&[0x00, 0x00, 0x02, 0x13, 0x01, 0xFF]);
    // comp_len overruns the body: extensions are absent, which is legal — the
    // key assertion is no panic and no out-of-bounds read.
    let _ = parse_client_hello(&wrap_body(&body));
}

#[test]
fn hostile_extension_block_and_element_lengths_are_bounded() {
    // Valid fixed fields, ext block len = 0xFFFF but body short.
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]; // through compression
    tail.extend_from_slice(&[0xFF, 0xFF]); // ext block len
    tail.extend_from_slice(&[0x00, 0x00]); // one extension header, truncated
    let body = body_with_tail(&tail);
    let _ = parse_client_hello(&wrap_body(&body)); // must not panic

    // One extension whose OWN elen = 0xFFFF (overruns everything).
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
    tail.extend_from_slice(&[0x00, 0x06]); // ext block len = 6 (header + 2 data)
    tail.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB]); // SNI ext, elen 0xFFFF
    let body = body_with_tail(&tail);
    let res = parse_client_hello(&wrap_body(&body));
    assert!(res.is_err(), "extension data out of bounds must error");

    // SNI extension whose name_len overruns the extension data.
    let mut sni = Vec::new();
    sni.extend_from_slice(&[0x00, 0xFF]); // list len
    sni.push(0);
    sni.extend_from_slice(&[0xFF, 0xFF]); // name len 0xFFFF
    sni.extend_from_slice(b"short");
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
    let mut exts = Vec::new();
    push_ext(&mut exts, 0, &sni);
    tail.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    tail.extend_from_slice(&exts);
    let body = body_with_tail(&tail);
    let rec = wrap_body(&body);
    if let Ok(ch) = parse_client_hello(&rec) {
        // If it parses, the bogus SNI must not have been accepted blindly...
        assert_ne!(ch.sni.as_deref(), Some("short"));
        assert_fingerprints_sane(&ch);
    }

    // ALPN extension whose proto_len overruns its data.
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
    let mut exts = Vec::new();
    push_ext(&mut exts, 16, &[0x00, 0x10, 0xFF, b'h']);
    tail.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    tail.extend_from_slice(&exts);
    let body = body_with_tail(&tail);
    let _ = parse_client_hello(&wrap_body(&body));

    // supported_versions list_len = 0xFF (overruns extension data).
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
    let mut exts = Vec::new();
    push_ext(&mut exts, 43, &[0xFF, 0x03, 0x04]);
    tail.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    tail.extend_from_slice(&exts);
    let body = body_with_tail(&tail);
    let _ = parse_client_hello(&wrap_body(&body));

    // ec_point_formats list_len = 0xFF.
    let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
    let mut exts = Vec::new();
    push_ext(&mut exts, 11, &[0xFF, 0x00]);
    tail.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    tail.extend_from_slice(&exts);
    let body = body_with_tail(&tail);
    let _ = parse_client_hello(&wrap_body(&body));

    // supported_groups / signature_algorithms total_len = 0xFFFF.
    for etype in [10u16, 13] {
        let mut tail = vec![0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00];
        let mut exts = Vec::new();
        push_ext(&mut exts, etype, &[0xFF, 0xFF, 0x00, 0x1d]);
        tail.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        tail.extend_from_slice(&exts);
        let body = body_with_tail(&tail);
        let _ = parse_client_hello(&wrap_body(&body));
    }
}

// ---------------------------------------------------------------------------
// 3. JA3/JA4 on pathological parsed structures
// ---------------------------------------------------------------------------

#[test]
fn ja3_ja4_tolerate_pathological_field_counts() {
    // 200 ciphers + 200 extensions: the ja4_a counters must saturate at 99
    // (two decimal digits) instead of overflowing the fixed 10-char width.
    let ch = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: (0..200u16).map(|i| 0xC000 + i).collect(),
        extensions: (0..200u16).map(|i| (0x1000 + i, vec![0xAA; 3])).collect(),
        sni: Some("x".into()),
        alpn: Some("h2".into()),
        supported_versions: vec![0x0304],
        supported_groups: (0..100u16).map(|i| 0x0100 + i).collect(),
        ec_point_formats: vec![0; 250],
        signature_algorithms: (0..100u16).map(|i| 0x0400 + i).collect(),
    };
    let j4 = ja4(&ch);
    let a = j4.split('_').next().unwrap();
    assert_eq!(a, "t13d9999h2", "counts must saturate at 99: {j4}");
    assert_fingerprints_sane(&ch);
}

#[test]
fn ja3_ja4_tolerate_empty_and_grease_only_fields() {
    let empty = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![],
        extensions: vec![],
        sni: None,
        alpn: None,
        supported_versions: vec![],
        supported_groups: vec![],
        ec_point_formats: vec![],
        signature_algorithms: vec![],
    };
    let j4 = ja4(&empty);
    assert_eq!(j4, "t12i000000_000000000000_i000000000000");
    assert_eq!(ja3(&empty).len(), 32);

    // GREASE-only lists must hash as empty (000000000000) with 00 counts.
    let grease = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![0x0A0A, 0x1A1A, 0x2A2A],
        extensions: vec![(0x0A0A, vec![]), (0x3A3A, vec![1, 2])],
        sni: None,
        alpn: None,
        supported_versions: vec![0x4A4A], // GREASE version
        supported_groups: vec![0x5A5A],
        ec_point_formats: vec![],
        signature_algorithms: vec![0x6A6A], // sig algs are NOT grease-filtered
    };
    let j4 = ja4(&grease);
    let parts: Vec<&str> = j4.split('_').collect();
    assert!(parts[0].starts_with("t12i0000"), "GREASE excluded: {j4}");
    assert_eq!(parts[1], "000000000000", "GREASE-only ciphers hash empty");
}

#[test]
fn ja3_ja4_tolerate_non_utf8_sni_and_alpn() {
    // SNI/ALPN come from the wire; String::from_utf8_lossy is used at parse.
    // Drive ja3/ja4 directly with lossy-decoded garbage to prove no panic on
    // weird strings (control chars, unicode, very long names).
    let ch = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![0x1301],
        extensions: vec![(0, vec![])],
        sni: Some("\u{0}\u{1}\u{FFFD}\u{10FFFF}".repeat(64)),
        alpn: Some("\u{7F}\u{80}".into()),
        supported_versions: vec![0x0304],
        supported_groups: vec![],
        ec_point_formats: vec![],
        signature_algorithms: vec![],
    };
    assert_fingerprints_sane(&ch);
}

// ---------------------------------------------------------------------------
// 4. sniff_client_hello (the server's actual inbound seam)
// ---------------------------------------------------------------------------

#[test]
fn sniff_never_panics_and_bounds_allocation() {
    // Oversized declared record (> 16384) must error BEFORE allocating.
    let mut rec = vec![0x16, 0x03, 0x01, 0xFF, 0xFF];
    rec.extend(std::iter::repeat_n(0u8, 64));
    let err = sniff_client_hello(std::io::Cursor::new(&rec)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // Exactly at the cap is allowed to proceed (allocation is bounded).
    let mut rec = vec![0x16, 0x03, 0x01, 0x40, 0x00]; // 16384
    rec.extend(std::iter::repeat_n(0u8, 16384));
    let (replayed, _, _) = sniff_client_hello(std::io::Cursor::new(&rec)).unwrap();
    assert_eq!(replayed.len(), 5 + 16384);

    // One past the cap errors.
    let mut rec = vec![0x16, 0x03, 0x01, 0x40, 0x01]; // 16385
    rec.extend(std::iter::repeat_n(0u8, 64));
    assert!(sniff_client_hello(std::io::Cursor::new(&rec)).is_err());
}

#[test]
fn sniff_tolerates_truncated_and_garbage_streams() {
    let rec = realistic_hello();
    // Every truncation point of a real record: must return Ok with no panic,
    // replay exactly the bytes actually read, and produce no fingerprints once
    // the parse can no longer succeed.
    for len in 0..rec.len() {
        let (replayed, j3, j4) = sniff_client_hello(std::io::Cursor::new(&rec[..len])).unwrap();
        assert_eq!(
            replayed,
            rec[..len],
            "sniff must replay exactly what it read (len {len})"
        );
        if j3.is_some() || j4.is_some() {
            // Fingerprints only when a full parse succeeded.
            assert!(j3.is_some() && j4.is_some());
        }
    }

    // Non-TLS first byte → no fingerprints, bytes replayed.
    let garbage = [0x47, 0x45, 0x54, 0x20, 0x2F]; // "GET /"
    let (replayed, j3, j4) = sniff_client_hello(std::io::Cursor::new(&garbage)).unwrap();
    assert_eq!(replayed, garbage);
    assert!(j3.is_none() && j4.is_none());

    // Empty stream → no fingerprints (header read short), no panic.
    let (_, j3, j4) = sniff_client_hello(std::io::Cursor::new(&[] as &[u8])).unwrap();
    assert!(j3.is_none() && j4.is_none());
}

// ---------------------------------------------------------------------------
// 5. Regression tests for findings T-1/T-2/T-3 — originally pinned here as
//    KNOWN DEVIATIONS by the adversarial pass; now assert the fixed behavior.
// ---------------------------------------------------------------------------

/// T-1 regression: `ja4_a` is exactly 10 characters in every case. The ALPN
/// field is built from ASCII bytes (never lossy-decoded chars), so a hostile
/// non-ASCII ALPN can no longer widen the field past 2 bytes.
#[test]
fn ja4a_width_holds_with_non_ascii_alpn() {
    let ch = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![0x1301],
        extensions: vec![(0, vec![])],
        sni: Some("a.com".into()),
        // 0xC2 0x80 0xC2 0x80 on the wire → two U+0080 chars after lossy
        // decode, and not one ASCII byte → the field falls back to "00".
        alpn: Some("\u{80}\u{80}".into()),
        supported_versions: vec![0x0304],
        supported_groups: vec![],
        ec_point_formats: vec![],
        signature_algorithms: vec![],
    };
    let j4 = ja4(&ch);
    let a = j4.split('_').next().unwrap();
    assert_eq!(a, "t13d010100", "non-ASCII ALPN falls back to 00: {j4}");

    // A single-ASCII-byte ALPN pads to 2 bytes, keeping the width.
    let ch = ClientHello {
        alpn: Some("h\u{80}".into()),
        ..ch
    };
    let a = ja4(&ch).split('_').next().unwrap().to_string();
    assert_eq!(a, "t13d0101h0", "single ASCII ALPN byte pads with 0: {a}");

    // Deliberately exercise the truncation fuzz's worst case: every ja4_a is
    // exactly 10 chars regardless of ALPN weirdness (covered broadly by
    // assert_fingerprints_sane in sections 1-3).
    assert_eq!(a.len(), 10);
}

/// T-2 regression: ja4_c keeps the documented `{a|i}` + 12-hex shape in the
/// empty case too — no extensions AND no signature algorithms yields
/// `i000000000000` (prefix `i` because no SNI extension exists), never a
/// bare prefix-less 12 hex.
#[test]
fn ja4c_empty_case_keeps_prefix() {
    let ch = ClientHello {
        legacy_version: 0x0303,
        cipher_suites: vec![0x1301],
        extensions: vec![],
        sni: None,
        alpn: None,
        supported_versions: vec![],
        supported_groups: vec![],
        ec_point_formats: vec![],
        signature_algorithms: vec![],
    };
    let c = ja4(&ch).split('_').nth(2).unwrap().to_string();
    assert_eq!(c, "i000000000000", "empty case keeps the a/i prefix");
}

/// T-3 regression: `sniff_client_hello` honors the header read result; for a
/// stream shorter than 5 bytes it replays exactly the bytes actually read —
/// never zero-padded bytes the peer never sent.
#[test]
fn sniff_replays_real_bytes_for_short_streams() {
    let (replayed, j3, j4) = sniff_client_hello(std::io::Cursor::new(&[0x16u8, 0x03])).unwrap();
    assert_eq!(replayed, vec![0x16, 0x03]);
    assert!(j3.is_none() && j4.is_none());

    // Empty stream replays nothing.
    let (replayed, j3, j4) = sniff_client_hello(std::io::Cursor::new(&[] as &[u8])).unwrap();
    assert!(replayed.is_empty());
    assert!(j3.is_none() && j4.is_none());
}
