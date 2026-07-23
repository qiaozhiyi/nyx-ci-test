//! Round-trip tests for the protocol: key agreement, framing, message codec.

use nyx_protocol::{crypto, frame, msg, wire};

fn sample_info() -> msg::SessionInfo {
    msg::SessionInfo {
        beacon_id: 7,
        hostname: "ws7".into(),
        username: "CORP\\admin".into(),
        os: "Windows 11 24H2".into(),
        arch: 0,
        pid: 4812,
        is_admin: 1,
        auth_token: None,
    }
}

#[test]
fn ecdh_key_agreement_is_mutual() {
    let server = crypto::ServerKeypair::generate().unwrap();
    let implant = crypto::ImplantKeypair::generate().unwrap();

    let k_server = server.derive_for(&implant.public_bytes());
    let k_implant = implant.session_key(&server.public_bytes());

    assert_eq!(
        k_server, k_implant,
        "server and implant must derive the same key"
    );
}

#[test]
fn keys_differ_per_session() {
    let server = crypto::ServerKeypair::generate().unwrap();
    let a = crypto::ImplantKeypair::generate().unwrap();
    let b = crypto::ImplantKeypair::generate().unwrap();
    assert_ne!(
        a.session_key(&server.public_bytes()),
        b.session_key(&server.public_bytes()),
        "each session must get a distinct key"
    );
}

#[test]
fn frame_seal_open_roundtrip() {
    let server = crypto::ServerKeypair::generate().unwrap();
    let implant = crypto::ImplantKeypair::generate().unwrap();
    let key = implant.session_key(&server.public_bytes());

    let mut w = wire::Writer::new();
    sample_info()
        .encode(&mut w)
        .expect("test SessionInfo fields are tiny literals << MAX_BLOB_LEN");
    let plaintext = w.into_bytes();

    let frame = frame::encode_frame(&implant.public_bytes(), 0, &key, &plaintext)
        .expect("test encode of tiny SessionInfo plaintext is infallible");
    let raw = frame::parse_frame(&frame).unwrap();
    assert_eq!(raw.counter, 0);
    assert_eq!(raw.pubkey, implant.public_bytes());

    let pt = frame::open_frame(&key, &raw).unwrap();
    assert_eq!(pt, plaintext);

    let mut r = wire::Reader::new(&pt);
    let decoded = msg::SessionInfo::decode(&mut r).unwrap();
    assert_eq!(decoded, sample_info());
}

#[test]
fn wrong_key_does_not_decrypt() {
    let server = crypto::ServerKeypair::generate().unwrap();
    let implant = crypto::ImplantKeypair::generate().unwrap();
    let key = implant.session_key(&server.public_bytes());

    let frame = frame::encode_frame(&implant.public_bytes(), 0, &key, b"secret")
        .expect("test encode of tiny plaintext is infallible");
    let raw = frame::parse_frame(&frame).unwrap();

    let other = crypto::ImplantKeypair::generate().unwrap();
    let wrong_key = other.session_key(&server.public_bytes());
    assert!(frame::open_frame(&wrong_key, &raw).is_err());
}

#[test]
fn task_batch_roundtrip() {
    let tasks = vec![
        msg::Task {
            task_id: 1,
            command: msg::Command::Ping,
        },
        msg::Task {
            task_id: 2,
            command: msg::Command::Shell {
                args: "whoami /groups".into(),
            },
        },
        msg::Task {
            task_id: 3,
            command: msg::Command::Sleep {
                seconds: 30,
                jitter_pct: 20,
            },
        },
        msg::Task {
            task_id: 4,
            command: msg::Command::Upload {
                name: "loot.bin".into(),
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
        },
        msg::Task {
            task_id: 5,
            command: msg::Command::Exit,
        },
    ];
    let enc = msg::Task::encode_vec(&tasks).expect("encode_vec should succeed for test fixture");
    let dec = msg::Task::decode_vec(&enc).unwrap();
    assert_eq!(dec, tasks);
}

#[test]
fn response_batch_roundtrip() {
    let responses = vec![
        msg::TaskResponse {
            task_id: 2,
            response: msg::Response::Output(b"corp\\admin\n".to_vec()),
        },
        msg::TaskResponse {
            task_id: 1,
            response: msg::Response::Ok,
        },
        msg::TaskResponse {
            task_id: 9,
            response: msg::Response::FileChunk {
                name: "doc.pdf".into(),
                seq: 0,
                eof: 1,
                data: vec![1, 2, 3],
            },
        },
    ];
    let enc = msg::TaskResponse::encode_vec(&responses)
        .expect("encode_vec should succeed for test fixture");
    let dec = msg::TaskResponse::decode_vec(&enc).unwrap();
    assert_eq!(dec, responses);
}

#[test]
fn empty_batches_roundtrip() {
    assert!(msg::Task::decode_vec(&msg::Task::encode_vec(&[]).unwrap())
        .unwrap()
        .is_empty());
    assert!(
        msg::TaskResponse::decode_vec(&msg::TaskResponse::encode_vec(&[]).unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn truncated_frame_is_rejected() {
    assert!(frame::parse_frame(&[0u8; 4]).is_err());
}

#[test]
fn frame_with_trailing_bytes_is_rejected() {
    // Integrity: the AEAD authenticates exactly ct_len bytes, so a frame that
    // carries unauthenticated trailing data after the declared ciphertext must
    // be rejected (length-exact), not silently trimmed.
    let server = crypto::ServerKeypair::generate().unwrap();
    let implant = crypto::ImplantKeypair::generate().unwrap();
    let key = implant.session_key(&server.public_bytes());
    let frame = frame::encode_frame(&implant.public_bytes(), 0, &key, b"hi")
        .expect("test encode of tiny plaintext is infallible");
    let mut with_trailer = frame.clone();
    with_trailer.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // unauthenticated tail
    assert!(
        frame::parse_frame(&with_trailer).is_err(),
        "frames with trailing unauthenticated bytes must be rejected"
    );
    // The clean frame still parses.
    assert!(frame::parse_frame(&frame).is_ok());
}

#[test]
fn frame_with_oversized_ct_len_is_rejected() {
    // Defense-in-depth: a beacon frame's ciphertext is always small. Even if
    // the body is long enough to satisfy the length-exact check, parse_frame
    // must reject a ct_len beyond a sane cap — so that an extractor change (or
    // the raw-TLS serve_connection path that has no body limit) cannot turn a
    // bogus ct_len into a multi-MB allocation. Build a body that *matches* the
    // declared ct_len so only the cap, not the length check, rejects it.
    let cap_beyond: u32 = 0x0010_0000; // 1 MiB ct — past the MAX_CT_LEN cap
    let total = frame::FRAME_HEADER + cap_beyond as usize;
    let mut bad = vec![0u8; total];
    bad[40..44].copy_from_slice(&cap_beyond.to_le_bytes());
    assert!(
        frame::parse_frame(&bad).is_err(),
        "a ct_len beyond the beacon cap must be rejected even when the body matches it"
    );
}

#[test]
fn p2p_command_variants_roundtrip() {
    let tasks = vec![
        msg::Task {
            task_id: 1,
            command: msg::Command::Ping,
        },
        msg::Task {
            task_id: 2,
            command: msg::Command::Bof {
                name: "whoami.x64.o".into(),
                args: vec!["-v".into()],
                blob: vec![0xCC; 4],
            },
        },
        msg::Task {
            task_id: 3,
            command: msg::Command::Connect {
                proto: 0,
                host: "10.0.0.5".into(),
                port: 445,
                chan: 7,
            },
        },
        msg::Task {
            task_id: 4,
            command: msg::Command::Socks {
                chan: 1,
                op: 1,
                addr: "example.com".into(),
                port: 443,
            },
        },
    ];
    let enc = msg::Task::encode_vec(&tasks).expect("encode_vec should succeed for test fixture");
    let dec = msg::Task::decode_vec(&enc).unwrap();
    assert_eq!(dec, tasks);
}

#[test]
fn nonce_directions_never_collide() {
    // Regression for the catastrophic bidirectional nonce-reuse bug: the same
    // session key was used in both directions with the SAME nonce
    // (zero-padded counter) and the SAME AAD (implant pubkey). Implant sealed
    // at counter=0 on check-in and the server replied at send_counter=0 →
    // two-time-pad under ChaCha20-Poly1305. Fix: split the nonce space by
    // direction so equal counter values in opposite directions are distinct
    // nonces. This test seals the same plaintext at the same counter in both
    // directions and asserts the ciphertexts differ, which is only possible if
    // the nonces differ (same key, same AAD, same plaintext).
    let server = crypto::ServerKeypair::generate().unwrap();
    let implant = crypto::ImplantKeypair::generate().unwrap();
    let key = implant.session_key(&server.public_bytes());
    let pubkey = implant.public_bytes();
    let plain = b"identical plaintext, identical counter, different direction";

    let c2s = crypto::seal_dir(&key, crypto::Direction::ClientToServer, 0, &pubkey, plain)
        .expect("test seal of tiny plaintext is infallible");
    let s2c = crypto::seal_dir(&key, crypto::Direction::ServerToClient, 0, &pubkey, plain)
        .expect("test seal of tiny plaintext is infallible");

    assert_ne!(
        c2s, s2c,
        "same counter in opposite directions must produce distinct ciphertexts (nonce reuse otherwise)"
    );

    // And each direction must round-trip on its own.
    let pt_c2s =
        crypto::open_dir(&key, crypto::Direction::ClientToServer, 0, &pubkey, &c2s).unwrap();
    let pt_s2c =
        crypto::open_dir(&key, crypto::Direction::ServerToClient, 0, &pubkey, &s2c).unwrap();
    assert_eq!(pt_c2s, plain);
    assert_eq!(pt_s2c, plain);

    // Cross-direction open must FAIL: the direction is part of the nonce, so a
    // ciphertext sealed C2S must not open S2C and vice-versa.
    assert!(crypto::open_dir(&key, crypto::Direction::ServerToClient, 0, &pubkey, &c2s).is_err());
    assert!(crypto::open_dir(&key, crypto::Direction::ClientToServer, 0, &pubkey, &s2c).is_err());
}

#[test]
fn decode_vec_rejects_absurd_count_without_huge_alloc() {
    // Allocation-bomb regression: decode_vec read a u32 count and called
    // Vec::with_capacity(n) before reading any elements. A decrypted (auth'd)
    // beacon body carrying n = 0xFFFFFFFF would force a ~4 GiB reservation on
    // the server under panic=abort. The count must be rejected when it exceeds
    // a sane cap, and the reservation must never exceed the remaining bytes
    // (you can't have more elements than bytes left).
    let mut w = wire::Writer::new();
    w.u32(0xFFFF_FFFF); // absurd count
    let buf = w.into_bytes();
    let err = msg::Task::decode_vec(&buf).unwrap_err();
    assert!(
        matches!(err, wire::WireError::BadLen(_)),
        "absurd count must be BadLen, got {err:?}"
    );
    // Same for TaskResponse.
    let err = msg::TaskResponse::decode_vec(&buf).unwrap_err();
    assert!(matches!(err, wire::WireError::BadLen(_)));

    // A count larger than remaining bytes (but < the hard cap) must fail with
    // Eof when the loop overruns — not over-allocate. 1 task declared, 0 bytes
    // of task data follow.
    let mut w = wire::Writer::new();
    w.u32(1);
    let err = msg::Task::decode_vec(&w.into_bytes()).unwrap_err();
    assert!(matches!(err, wire::WireError::Eof), "got {err:?}");
}

#[test]
fn channel_response_variants_roundtrip() {
    let responses = vec![
        msg::TaskResponse {
            task_id: 2,
            response: msg::Response::BofOutput(vec![1, 2, 3]),
        },
        msg::TaskResponse {
            task_id: 3,
            response: msg::Response::Channel {
                chan: 7,
                status: 1,
                data: vec![0xAB],
            },
        },
    ];
    let enc = msg::TaskResponse::encode_vec(&responses)
        .expect("encode_vec should succeed for test fixture");
    let dec = msg::TaskResponse::decode_vec(&enc).unwrap();
    assert_eq!(dec, responses);
}

/// `MAX_CT_LEN` must stay at 512 KiB — the README's wire-format spec
/// documents this as the DoS cap, and `frame_with_oversized_ct_len_is_rejected`
/// above depends on it being the precise backstop. Catch a future edit that
/// silently shrinks (regress) or expands (DoS surface) the cap.
#[test]
#[allow(clippy::assertions_on_constants)]
fn frame_max_ct_len_constant_matches_docs() {
    // 512 KiB — matches the README wire-format spec.
    assert_eq!(frame::MAX_CT_LEN, 512 * 1024);
    // Sanity: it must always exceed any real-world frame ciphertext (so
    // legitimate large task blobs aren't rejected) while staying far below
    // a multi-MB DoS amplification range.
    assert!(frame::MAX_CT_LEN >= 256 * 1024);
    assert!(frame::MAX_CT_LEN <= 1024 * 1024);
}

/// `SessionKey` is a wrapped struct (not a bare `[u8;32]`) precisely so that
/// `ZeroizeOnDrop` can be implemented. Verify the contract:
///
/// 1. construction round-trips through `as_bytes()`
/// 2. `Zeroize::zeroize()` actually clears the inner bytes in-place
/// 3. equality holds for two keys built from the same input
///
/// This is a defense-in-depth sanity check on the wrapper type — the security
/// guarantee (drop zeroes memory) is provided by `ZeroizeOnDrop`, which we
/// can't directly assert without `unsafe` reads of freed memory.
#[test]
fn session_key_wrapper_zeroizes_in_place() {
    use nyx_protocol::crypto::SessionKey;
    use zeroize::Zeroize;

    let secret = [0xABu8; 32];
    let mut key = SessionKey::new(secret);
    // Round-trip through the accessor — this is the contract callers rely on.
    assert_eq!(
        key.as_bytes(),
        &secret,
        "as_bytes() must return the inner bytes"
    );

    // Two keys from the same input must compare equal (Eq + PartialEq + Hash
    // are derived on the wrapper; the inner array provides the impls).
    let key2 = SessionKey::new(secret);
    assert_eq!(key, key2, "SessionKey equality must be byte-equality");

    // Zeroize must clear the inner bytes in place. After this call, the
    // wrapper is logically destroyed — we don't read it via as_bytes() in
    // production code after zeroize, but we can verify the contract here.
    key.zeroize();
    assert_eq!(
        key.as_bytes(),
        &[0u8; 32],
        "Zeroize must clear the inner bytes"
    );

    // A freshly-zeroized key must NOT equal a real key (sanity for the Eq
    // derive — it should compare bytes, not pointer or wrapper identity).
    assert_ne!(key, key2, "zeroized key must differ from a real key");
}

/// P1-3 regression: `SessionKey` must NOT expose raw bytes through `Debug`.
/// A stray `{:?}` / `tracing::debug!(?key)` must print a redacted form, never
/// the actual key material (which would leak into logs / crash telemetry).
#[test]
fn session_key_debug_does_not_leak_bytes() {
    use nyx_protocol::crypto::SessionKey;
    let key = SessionKey::new([0xDEu8; 32]);
    let dbg = format!("{:?}", key);
    assert!(
        !dbg.contains("DE"),
        "Debug must not contain hex of key bytes; got: {dbg}"
    );
    assert!(
        dbg.contains("redacted"),
        "Debug must indicate redaction; got: {dbg}"
    );
}

/// P0-1 regression: keypair generation in the std build must succeed and must
/// NEVER produce an all-zero scalar (which would yield the curve identity point
/// → a deterministic, decryptable, cross-implant-identical session key). The
/// `OsRng` backend is infallible on supported targets, so `generate()` returns
/// `Ok` and the derived public key must differ from the all-zero identity.
#[test]
fn keypair_generate_never_yields_zero_scalar() {
    use nyx_protocol::{ImplantKeypair, ServerKeypair};
    let server = ServerKeypair::generate().expect("OsRng is infallible on std");
    let implant = ImplantKeypair::generate().expect("OsRng is infallible on std");
    // A zero scalar → identity point → all-zero public key. Reject it.
    assert_ne!(
        server.public_bytes(),
        [0u8; 32],
        "server pubkey must not be the curve identity (zero scalar)"
    );
    assert_ne!(
        implant.public_bytes(),
        [0u8; 32],
        "implant pubkey must not be the curve identity (zero scalar)"
    );
    // The two pubkeys must differ (independent randomness).
    assert_ne!(
        server.public_bytes(),
        implant.public_bytes(),
        "independent keypair generations must produce different pubkeys"
    );
}

/// H-2 (zero-width plaintext rejection, decode side): a frame whose declared
/// ct_len equals exactly TAG_LEN is the AEAD's "all tag, no data" degenerate
/// case. Such a frame carries zero plaintext bytes, which the wire codec
/// doesn't define a meaningful interpretation for. parse_frame must reject it
/// at the boundary so the decoder never has to handle an empty plaintext.
#[test]
fn frame_with_zero_width_plaintext_is_rejected() {
    // Build a frame whose ct_len equals exactly TAG_LEN (16). We craft the
    // raw bytes manually rather than going through encode_frame_dir, because
    // encode_frame_dir refuses to seal an empty plaintext (see the next test).
    let mut bad = vec![0u8; frame::FRAME_HEADER + frame::TAG_LEN];
    // ct_len = TAG_LEN at offset PUBKEY_LEN+8 .. +12.
    let l = crypto::PUBKEY_LEN;
    bad[l + 8..l + 12].copy_from_slice(&(frame::TAG_LEN as u32).to_le_bytes());
    assert_eq!(
        bad.len(),
        frame::FRAME_HEADER + frame::TAG_LEN,
        "test fixture must be length-exact"
    );
    let err = frame::parse_frame(&bad).unwrap_err();
    assert!(
        matches!(err, wire::WireError::BadLen(16)),
        "ct_len == TAG_LEN (zero plaintext) must be rejected by the parser, got {err:?}"
    );
}

/// H-2 (zero-width plaintext rejection, encode side): encode_frame_dir must
/// panic on an empty plaintext. The wire codec never legitimately produces
/// one (every batch carries at least a `u32 count`, every SessionInfo is
/// non-empty), so an empty plaintext here signals a caller bug — panicking
/// gives the developer a loud signal at the source rather than silently
/// producing a frame the receiver will reject anyway.
#[test]
#[should_panic(expected = "encode_frame_dir: empty plaintext is not a valid beacon frame")]
fn encode_frame_dir_panics_on_empty_plaintext() {
    let key = crypto::SessionKey::new([0u8; 32]);
    let pubkey = [0u8; crypto::PUBKEY_LEN];
    let _ = frame::encode_frame_dir(&pubkey, crypto::Direction::ClientToServer, 0, &key, b"");
}

/// MIN_CT_LEN constant pin — guards the lower bound against silent regressions.
/// The upper bound is already pinned by `frame_max_ct_len_constant_matches_docs`.
#[test]
#[allow(clippy::assertions_on_constants)]
fn frame_min_ct_len_constant_matches_docs() {
    // Must equal TAG_LEN + 1 — the smallest ciphertext that carries >=1 byte
    // of actual plaintext under ChaCha20-Poly1305.
    assert_eq!(frame::MIN_CT_LEN, frame::TAG_LEN + 1);
    // Sanity: MIN must be strictly greater than TAG_LEN (else zero-plaintext
    // frames would slip through) and strictly less than MAX (else no range).
    assert!(frame::MIN_CT_LEN > frame::TAG_LEN);
    assert!(frame::MIN_CT_LEN < frame::MAX_CT_LEN);
}
