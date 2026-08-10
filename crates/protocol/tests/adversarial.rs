//! Adversarial (attacker-view) tests for the Nyx wire protocol.
//!
//! Threat model: a network attacker (or a malicious/compromised peer) who can
//! flip, truncate, replay, or forge any byte on the wire. The guarantees under
//! test:
//!
//! - Any tampering with ciphertext / tag / AAD (pubkey) / counter (nonce input)
//!   MUST fail AEAD open — never panic, never yield plaintext.
//! - Direction flip MUST fail open (the direction discriminator is part of the
//!   96-bit nonce; the two directions share the session key).
//! - Replay: the protocol crate is deliberately stateless (a frame sealed at
//!   counter N opens deterministically at counter N). Anti-replay is enforced
//!   one layer up: `crates/server/src/lib.rs` (`handle_frame`: rejects
//!   `raw.counter <= session.last_recv`). We test the stateless primitive's
//!   semantics AND the monotonic-counter policy the server implements.
//! - `ct_len` outside `[MIN_CT_LEN, MAX_CT_LEN]` (17..=512 KiB) or not
//!   length-exact MUST be rejected at parse time with NO oversized allocation.
//! - Batch element counts > 65536 (`msg::MAX_BATCH`) MUST be rejected before
//!   any `Vec::with_capacity`; smaller counts must never over-allocate beyond
//!   the remaining input.
//! - Low-order X25519 peer pubkeys (RFC 7748 §6.1 contributory check) MUST be
//!   rejected by both derivation entry points.
//! - No input — truncated frame prefix, bit-flipped frame, mutated decrypted
//!   body — may ever cause a panic (both server and implant build with
//!   `panic = "abort"`; a panic is a remote kill).
//!
//! NOTE on frame layout: the actual wire format is
//! `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`
//! (see `frame.rs` / crate docs). There is no magic, no direction byte, and no
//! on-the-wire nonce — the 12-byte nonce is derived as
//! `dir(1B) || 0^3 || counter(8B LE)` and the pubkey doubles as the AEAD AAD.
//! "Nonce tampering" therefore maps to tampering with the counter field and
//! "dir-byte flip" maps to opening with the opposite `Direction`.

use nyx_protocol::{crypto, frame, msg, wire};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic session (fixed secrets — no CSPRNG dependence, reproducible).
fn session() -> ([u8; crypto::PUBKEY_LEN], crypto::SessionKey) {
    let server = crypto::ServerKeypair::from_secret_bytes([0x11; 32]);
    let implant = crypto::ImplantKeypair::from_secret_bytes([0x22; 32]);
    let key = implant.session_key(&server.public_bytes()).unwrap();
    // Cross-check both sides agree (guards the fixtures themselves).
    let k2 = server.derive_for(&implant.public_bytes()).unwrap();
    assert_eq!(key, k2);
    (implant.public_bytes(), key)
}

fn seal_frame(
    pubkey: &[u8; crypto::PUBKEY_LEN],
    dir: crypto::Direction,
    counter: u64,
    key: &crypto::SessionKey,
    pt: &[u8],
) -> Vec<u8> {
    frame::encode_frame_dir(pubkey, dir, counter, key, pt)
        .expect("test fixture encode is infallible for small plaintext")
}

/// Decode a 64-char hex string into 32 bytes (kept local so the protocol test
/// suite needs no extra dev-dependency).
fn hex32(s: &str) -> [u8; 32] {
    fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex"),
        }
    }
    let b = s.as_bytes();
    assert_eq!(b.len(), 64);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
    }
    out
}

const CT_OFFSET: usize = frame::FRAME_HEADER; // ciphertext starts after header

// ---------------------------------------------------------------------------
// 1. Tampering: ciphertext / tag / counter (nonce input) / pubkey (AAD)
// ---------------------------------------------------------------------------

#[test]
fn tamper_every_ciphertext_byte_fails_decrypt() {
    let (pubkey, key) = session();
    let pt = b"operator task batch: shell whoami /groups";
    let frame_bytes = seal_frame(&pubkey, crypto::Direction::ClientToServer, 7, &key, pt);
    // Control: untampered opens.
    let raw = frame::parse_frame(&frame_bytes).unwrap();
    assert_eq!(
        frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).unwrap(),
        pt
    );

    let ct_len = raw.ciphertext.len() - frame::TAG_LEN; // payload bytes only
    for i in 0..ct_len {
        let mut bad = frame_bytes.clone();
        bad[CT_OFFSET + i] ^= 0x01;
        let raw = frame::parse_frame(&bad).expect("tampered ct still parses");
        assert!(
            frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
            "flipping ciphertext byte {i} must fail AEAD open"
        );
    }
}

#[test]
fn tamper_every_tag_byte_fails_decrypt() {
    let (pubkey, key) = session();
    let frame_bytes = seal_frame(&pubkey, crypto::Direction::ClientToServer, 0, &key, b"ping");
    let total = frame_bytes.len();
    for i in 0..frame::TAG_LEN {
        let mut bad = frame_bytes.clone();
        bad[total - frame::TAG_LEN + i] ^= 0x80;
        let raw = frame::parse_frame(&bad).unwrap();
        assert!(
            frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
            "flipping tag byte {i} must fail AEAD open"
        );
    }
}

#[test]
fn tamper_counter_field_fails_decrypt() {
    // The on-the-wire counter feeds the AEAD nonce; flipping any counter byte
    // changes the nonce and MUST fail open (this is the "nonce tamper" case —
    // the nonce itself never crosses the wire).
    let (pubkey, key) = session();
    let counter = 0x0102u64;
    let frame_bytes = seal_frame(
        &pubkey,
        crypto::Direction::ClientToServer,
        counter,
        &key,
        b"x",
    );
    let raw = frame::parse_frame(&frame_bytes).unwrap();
    assert!(frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_ok());

    for i in 0..8 {
        let mut bad = frame_bytes.clone();
        bad[crypto::PUBKEY_LEN + i] ^= 0x01;
        let raw = frame::parse_frame(&bad).expect("counter tamper still parses");
        assert_ne!(raw.counter, counter, "fixture must change the counter");
        assert!(
            frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
            "flipping counter byte {i} (nonce input) must fail AEAD open"
        );
    }
}

#[test]
fn tamper_pubkey_aad_fails_decrypt() {
    // The pubkey is the AEAD AAD: flipping any header pubkey byte must fail
    // open even though parse_frame succeeds.
    let (pubkey, key) = session();
    let frame_bytes = seal_frame(&pubkey, crypto::Direction::ClientToServer, 3, &key, b"data");
    for i in 0..crypto::PUBKEY_LEN {
        let mut bad = frame_bytes.clone();
        bad[i] ^= 0x40;
        let raw = frame::parse_frame(&bad).unwrap();
        assert!(
            frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
            "flipping pubkey/AAD byte {i} must fail AEAD open"
        );
    }
}

#[test]
fn wrong_key_fails_decrypt() {
    let (pubkey, key) = session();
    let frame_bytes = seal_frame(&pubkey, crypto::Direction::ClientToServer, 0, &key, b"loot");
    let raw = frame::parse_frame(&frame_bytes).unwrap();

    // Attacker guesses / derives an unrelated session key.
    let other_server = crypto::ServerKeypair::from_secret_bytes([0x99; 32]);
    let wrong = server_side_wrong_key(&pubkey, &other_server);
    assert!(frame::open_frame_dir(&wrong, crypto::Direction::ClientToServer, &raw).is_err());
}

fn server_side_wrong_key(
    implant_pub: &[u8; crypto::PUBKEY_LEN],
    other_server: &crypto::ServerKeypair,
) -> crypto::SessionKey {
    // A different long-term server secret ⇒ different ECDH ⇒ different key.
    other_server.derive_for(implant_pub).unwrap()
}

// ---------------------------------------------------------------------------
// 2. Direction flip ("dir byte") must fail
// ---------------------------------------------------------------------------

#[test]
fn direction_flip_fails_decrypt_both_ways() {
    let (pubkey, key) = session();
    let pt = b"direction confusion probe";

    let c2s = seal_frame(&pubkey, crypto::Direction::ClientToServer, 42, &key, pt);
    let raw = frame::parse_frame(&c2s).unwrap();
    assert!(
        frame::open_frame_dir(&key, crypto::Direction::ServerToClient, &raw).is_err(),
        "a C2S frame opened as S2C must fail (direction is part of the nonce)"
    );
    assert!(frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_ok());

    let s2c = seal_frame(&pubkey, crypto::Direction::ServerToClient, 42, &key, pt);
    let raw = frame::parse_frame(&s2c).unwrap();
    assert!(
        frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
        "an S2C frame opened as C2S must fail"
    );
    assert!(frame::open_frame_dir(&key, crypto::Direction::ServerToClient, &raw).is_ok());
}

// ---------------------------------------------------------------------------
// 3. Replay semantics
// ---------------------------------------------------------------------------

#[test]
fn stateless_primitive_is_deterministic_and_policy_rejects_replay() {
    let (pubkey, key) = session();

    // (a) The protocol layer is deliberately stateless: the same frame opens
    // deterministically twice. This documents that replay REJECTION cannot
    // come from the AEAD layer — it is the server's monotonic-counter check
    // (`crates/server/src/lib.rs` handle_frame: `raw.counter <= last_recv`
    // ⇒ "replayed/stale counter"). Pin the primitive semantics so nobody
    // "fixes" the wrong layer.
    let f0 = seal_frame(
        &pubkey,
        crypto::Direction::ClientToServer,
        0,
        &key,
        b"check-in",
    );
    let raw0 = frame::parse_frame(&f0).unwrap();
    let pt1 = frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw0).unwrap();
    let pt2 = frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw0).unwrap();
    assert_eq!(
        pt1, pt2,
        "AEAD open is deterministic for a fixed (key, nonce, ct)"
    );

    // (b) Model the server's anti-replay policy exactly as implemented:
    // accept iff counter > last_recv; then last_recv = counter. A re-sent
    // (replayed) frame at the same counter MUST be rejected; an
    // out-of-order older frame MUST be rejected; the next counter passes.
    let mut last_recv: i128 = -1; // mirrors "no frame seen yet"
    let mut accept = |counter: u64| -> bool {
        let ok = (counter as i128) > last_recv;
        if ok {
            last_recv = counter as i128;
        }
        ok
    };
    assert!(accept(0), "first check-in passes");
    assert!(!accept(0), "replayed counter 0 must be rejected");
    assert!(accept(1), "next beacon passes");
    assert!(!accept(1), "replayed counter 1 must be rejected");
    assert!(!accept(0), "out-of-order older counter must be rejected");
    assert!(accept(2), "in-order next counter passes");

    // (c) A replayed frame at a counter the session has already consumed
    // carries no freshness: an attacker re-sending the recorded check-in
    // bytes verbatim MUST fail the server-side gate even though the bytes
    // still decrypt. Combined (a)+(b): bytes decrypt (a), policy rejects (b).
    let replayed = frame::parse_frame(&f0).unwrap();
    assert_eq!(replayed.counter, 0);
    assert!(
        (replayed.counter as i128) <= last_recv,
        "server gate must reject the replayed frame (counter {} <= last_recv {})",
        replayed.counter,
        last_recv
    );
}

// ---------------------------------------------------------------------------
// 4. ct_len bounds & allocation bombs
// ---------------------------------------------------------------------------

/// Build a raw frame by hand with an arbitrary declared ct_len and body.
fn handcrafted_frame(ct_len_declared: u32, body_len: usize) -> Vec<u8> {
    let mut f = vec![0u8; frame::FRAME_HEADER + body_len];
    f[40..44].copy_from_slice(&ct_len_declared.to_le_bytes());
    f
}

#[test]
fn ct_len_upper_bound_is_exact() {
    // Exactly MAX_CT_LEN with a matching body parses (single bounded 512 KiB
    // copy — the documented backstop), one byte over is rejected.
    let ok = handcrafted_frame(frame::MAX_CT_LEN as u32, frame::MAX_CT_LEN);
    assert!(
        frame::parse_frame(&ok).is_ok(),
        "ct_len == MAX_CT_LEN must parse"
    );

    let over = handcrafted_frame(frame::MAX_CT_LEN as u32 + 1, frame::MAX_CT_LEN + 1);
    let err = frame::parse_frame(&over).unwrap_err();
    assert!(
        matches!(err, wire::WireError::BadLen(n) if n == frame::MAX_CT_LEN + 1),
        "ct_len == MAX_CT_LEN+1 must be BadLen even with a matching body, got {err:?}"
    );
}

#[test]
fn ct_len_u32_max_does_not_allocate_or_wrap() {
    // The nastiest header: declared ct_len = 4 GiB-1 with a tiny body. Must
    // fail the length-exact check immediately — no multi-GiB allocation, no
    // usize overflow on the FRAME_HEADER + ct_len addition.
    let bad = handcrafted_frame(u32::MAX, 64);
    let err = frame::parse_frame(&bad).unwrap_err();
    assert!(
        matches!(err, wire::WireError::BadLen(n) if n == u32::MAX as usize),
        "u32::MAX ct_len must be BadLen, got {err:?}"
    );

    // A declared length that would overflow FRAME_HEADER + ct_len on a 32-bit
    // usize must likewise be rejected (regression guard for the addition).
    let bad2 = handcrafted_frame(u32::MAX - 20, 64);
    assert!(frame::parse_frame(&bad2).is_err());
}

#[test]
fn ct_len_lower_bound_and_length_exactness() {
    for (declared, body, why) in [
        (0u32, 0usize, "zero ct_len"),
        (1, 1, "below MIN_CT_LEN"),
        (
            frame::TAG_LEN as u32,
            frame::TAG_LEN,
            "all tag, no data (MIN-1)",
        ),
    ] {
        let f = handcrafted_frame(declared, body);
        assert!(
            matches!(frame::parse_frame(&f), Err(wire::WireError::BadLen(_))),
            "{why} must be BadLen"
        );
    }
    // Boundary: MIN_CT_LEN (=TAG_LEN+1) with matching body parses.
    let ok = handcrafted_frame(frame::MIN_CT_LEN as u32, frame::MIN_CT_LEN);
    assert!(frame::parse_frame(&ok).is_ok());

    // Length-exactness in both directions.
    let trailing = handcrafted_frame(32, 64); // body longer than declared
    assert!(
        matches!(
            frame::parse_frame(&trailing),
            Err(wire::WireError::BadLen(32))
        ),
        "unauthenticated trailing bytes must be rejected"
    );
    let short = handcrafted_frame(64, 32); // body shorter than declared
    assert!(
        matches!(frame::parse_frame(&short), Err(wire::WireError::BadLen(64))),
        "truncated ciphertext must be rejected"
    );
}

#[test]
fn batch_count_over_65536_is_rejected_without_allocation() {
    // Allocation bomb via decrypted body: declared element count > MAX_BATCH
    // (65536) must be BadLen BEFORE any Vec::with_capacity.
    let mut w = wire::Writer::new();
    w.u32(65_537);
    let buf = w.into_bytes();
    assert!(matches!(
        msg::Task::decode_vec(&buf),
        Err(wire::WireError::BadLen(65_537))
    ));
    assert!(matches!(
        msg::TaskResponse::decode_vec(&buf),
        Err(wire::WireError::BadLen(65_537))
    ));

    let mut w = wire::Writer::new();
    w.u32(u32::MAX);
    let buf = w.into_bytes();
    assert!(matches!(
        msg::Task::decode_vec(&buf),
        Err(wire::WireError::BadLen(_))
    ));
    assert!(matches!(
        msg::TaskResponse::decode_vec(&buf),
        Err(wire::WireError::BadLen(_))
    ));

    // Boundary: exactly 65536 declared with an empty payload. The declared
    // count no longer clamps the loop to the remaining byte count — a count
    // that does not match the readable payload is malformed:
    //   - Task::decode_vec rejects 65536 with BadLen (past MAX_WIRE_COUNT =
    //     256, which the encode side never exceeds);
    //   - TaskResponse::decode_vec accepts 65536 as within MAX_BATCH but
    //     errors with Eof on the first element read — never the old silent
    //     `Ok(vec![])`.
    // Neither may over-allocate: the capacity reservation is still clamped to
    // the remaining byte count (0 here).
    let mut w = wire::Writer::new();
    w.u32(65_536);
    assert!(matches!(
        msg::Task::decode_vec(&w.into_bytes()),
        Err(wire::WireError::BadLen(65_536))
    ));
    let mut w = wire::Writer::new();
    w.u32(65_536);
    assert!(matches!(
        msg::TaskResponse::decode_vec(&w.into_bytes()),
        Err(wire::WireError::Eof)
    ));

    // A u32 length-prefixed blob inside a decrypted body is likewise capped
    // (MAX_BLOB_LEN = 256 KiB) before any copy.
    let mut w = wire::Writer::new();
    w.u8(1); // Response::Output tag
    w.u32((wire::MAX_BLOB_LEN + 1) as u32); // over-cap blob length
    assert!(matches!(
        msg::Response::decode(&mut wire::Reader::new(&w.into_bytes())),
        Err(wire::WireError::BadLen(_))
    ));
}

#[test]
fn declared_count_mismatch_is_rejected_everywhere() {
    // P-1: the decoder must never silently decode fewer elements than the
    // declared count. Every count-prefixed decode path (Task / TaskResponse /
    // Bof args) rejects a mismatch with the codec's BadLen/Eof style:
    //   - declared > per-type wire cap  -> BadLen (encode side never emits it)
    //   - declared <= cap, payload short -> Eof from the element reads

    // TaskResponse, declared 1 with empty payload: previously the loop was
    // clamped to the remaining byte count and this returned Ok(vec![]).
    let mut w = wire::Writer::new();
    w.u32(1);
    assert!(matches!(
        msg::TaskResponse::decode_vec(&w.into_bytes()),
        Err(wire::WireError::Eof)
    ));

    // Mid-batch truncation: declared 2, only 1 element present -> Eof, for
    // both batch types.
    let one = msg::TaskResponse {
        task_id: 7,
        response: msg::Response::Ok,
    };
    let full = msg::TaskResponse::encode_vec(&[one.clone(), one.clone()]).unwrap();
    let truncated = msg::TaskResponse::encode_vec(&[one]).unwrap();
    // Re-declare the count of the truncated buffer as 2.
    let mut body = truncated.clone();
    body[..4].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        msg::TaskResponse::decode_vec(&body),
        Err(wire::WireError::Eof)
    ));
    // Sanity: the untampered 2-element batch still decodes.
    assert_eq!(msg::TaskResponse::decode_vec(&full).unwrap().len(), 2);

    let task = msg::Task {
        task_id: 1,
        command: msg::Command::Ping,
    };
    let truncated = msg::Task::encode_vec(&[task]).unwrap();
    let mut body = truncated.clone();
    body[..4].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        msg::Task::decode_vec(&body),
        Err(wire::WireError::Eof)
    ));

    // Declared count past MAX_WIRE_COUNT (256) with a full payload: Task
    // previously clamped the loop to 256 and silently dropped the remaining
    // 44 declared elements; now the count itself is rejected as malformed.
    let mut w = wire::Writer::new();
    w.u32(300);
    assert!(matches!(
        msg::Task::decode_vec(&w.into_bytes()),
        Err(wire::WireError::BadLen(300))
    ));

    // Same rule for Bof args inside Command::decode: a declared arg count
    // past MAX_WIRE_COUNT previously desynced the stream (the 257th arg was
    // re-interpreted as the blob length prefix).
    let mut w = wire::Writer::new();
    w.u8(7); // Command::Bof tag
    w.str("go").unwrap();
    w.u32(300); // declared arg count past the wire cap
    assert!(matches!(
        msg::Command::decode(&mut wire::Reader::new(&w.into_bytes())),
        Err(wire::WireError::BadLen(300))
    ));
}

// ---------------------------------------------------------------------------
// 5. X25519 low-order point rejection (RFC 7748 §6.1 contributory behavior)
// ---------------------------------------------------------------------------

#[test]
fn low_order_peer_pubkeys_are_rejected() {
    // The canonical libsodium "blacklist" of low-order Curve25519 public keys:
    // every one of these forces an all-zero shared secret with any scalar.
    // Accepting any of them would give the attacker a deterministic,
    // cross-implant-identical session key.
    let blacklist = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let server = crypto::ServerKeypair::from_secret_bytes([0x33; 32]);
    let implant = crypto::ImplantKeypair::from_secret_bytes([0x44; 32]);

    for hex in blacklist {
        let point = hex32(hex);
        let err = server
            .derive_for(&point)
            .unwrap_err_or_default("server must reject low-order point");
        assert!(
            matches!(err, crypto::KeyExchangeError::NonContributory),
            "server derive_for({hex}) must be NonContributory, got {err:?}"
        );
        let err = implant
            .session_key(&point)
            .unwrap_err_or_default("implant must reject low-order point");
        assert!(
            matches!(err, crypto::KeyExchangeError::NonContributory),
            "implant session_key({hex}) must be NonContributory, got {err:?}"
        );
        // The raw helper must agree.
        assert!(
            crypto::ecdh(&[0x44; 32], &point).is_none(),
            "raw ecdh({hex}) must return None"
        );
    }

    // Sanity: a valid peer pubkey still derives fine after the guard.
    let good = crypto::ImplantKeypair::from_secret_bytes([0x55; 32]);
    assert!(server.derive_for(&good.public_bytes()).is_ok());
}

/// Small extension trait so the low-order loop reads cleanly.
trait UnwrapErrMsg<T> {
    fn unwrap_err_or_default(self, msg: &str) -> crypto::KeyExchangeError;
}
impl<T> UnwrapErrMsg<T> for Result<T, crypto::KeyExchangeError> {
    fn unwrap_err_or_default(self, msg: &str) -> crypto::KeyExchangeError {
        match self {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Truncation & mutation fuzz (no panic, ever)
// ---------------------------------------------------------------------------

#[test]
fn every_truncated_frame_prefix_is_rejected_without_panic() {
    let (pubkey, key) = session();
    // A realistic check-in frame: SessionInfo inside.
    let mut w = wire::Writer::new();
    msg::SessionInfo {
        beacon_id: 7,
        hostname: "ws7".into(),
        username: "CORP\\admin".into(),
        os: "Windows 11 24H2".into(),
        arch: 0,
        pid: 4812,
        is_admin: 1,
        auth_token: Some([0xAB; 32]),
    }
    .encode(&mut w)
    .unwrap();
    let frame_bytes = seal_frame(
        &pubkey,
        crypto::Direction::ClientToServer,
        0,
        &key,
        &w.into_bytes(),
    );

    // Every proper prefix must parse as an error (frames are length-exact, so
    // a truncated frame can never parse successfully) and never panic.
    for len in 0..frame_bytes.len() {
        let prefix = &frame_bytes[..len];
        assert!(
            frame::parse_frame(prefix).is_err(),
            "prefix of len {len} must not parse as a valid frame"
        );
    }
    // Control: the full frame parses and opens.
    let raw = frame::parse_frame(&frame_bytes).unwrap();
    assert!(frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_ok());
}

#[test]
fn every_single_byte_mutation_never_panics_and_never_decrypts() {
    let (pubkey, key) = session();
    let frame_bytes = seal_frame(
        &pubkey,
        crypto::Direction::ClientToServer,
        9,
        &key,
        b"mutate me",
    );
    for pos in 0..frame_bytes.len() {
        for pattern in [0xFFu8, 0x01, 0x80] {
            let mut bad = frame_bytes.clone();
            bad[pos] ^= pattern;
            if bad == frame_bytes {
                continue;
            }
            if let Ok(raw) = frame::parse_frame(&bad) {
                // A mutation that still parses (header/pubkey/counter/ct/tag
                // bytes) must fail open — the tag covers everything that
                // matters and the counter is the nonce input.
                assert!(
                    frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
                    "mutation at byte {pos} (xor {pattern:#04x}) parsed AND opened"
                );
            }
        }
    }
}

#[test]
fn mutated_and_truncated_decrypted_bodies_never_panic_the_msg_codecs() {
    // A malicious SERVER (or an attacker who recovered a session key) can put
    // arbitrary bytes in the decrypted body. The msg decoders run on the
    // implant under panic="abort" — any panic is a beacon kill.
    let tasks = vec![
        msg::Task {
            task_id: 1,
            command: msg::Command::Bof {
                name: "x.o".into(),
                args: vec!["a".into(), "b".into()],
                blob: vec![0xCC; 8],
                isolate: true,
            },
        },
        msg::Task {
            task_id: 2,
            command: msg::Command::MakeToken {
                domain: "CORP".into(),
                user: "svc".into(),
                password: "p".into(),
                logon_type: 2,
            },
        },
    ];
    let body = msg::Task::encode_vec(&tasks).unwrap();

    // All prefixes.
    for len in 0..body.len() {
        let _ = msg::Task::decode_vec(&body[..len]); // must not panic; result irrelevant
    }
    // Single-byte mutations.
    for pos in 0..body.len() {
        for pattern in [0xFFu8, 0x01, 0x80] {
            let mut bad = body.clone();
            bad[pos] ^= pattern;
            let _ = msg::Task::decode_vec(&bad);
        }
    }

    // Same for a response batch (implant → server direction).
    let rs = vec![
        msg::TaskResponse {
            task_id: 1,
            response: msg::Response::FileChunk {
                name: "f.bin".into(),
                seq: 0,
                eof: 0,
                data: vec![1, 2, 3, 4],
            },
        },
        msg::TaskResponse {
            task_id: 2,
            response: msg::Response::Channel {
                chan: 3,
                status: 1,
                data: vec![9; 2],
            },
        },
    ];
    let body = msg::TaskResponse::encode_vec(&rs).unwrap();
    for len in 0..body.len() {
        let _ = msg::TaskResponse::decode_vec(&body[..len]);
    }
    for pos in 0..body.len() {
        for pattern in [0xFFu8, 0x01, 0x80] {
            let mut bad = body.clone();
            bad[pos] ^= pattern;
            let _ = msg::TaskResponse::decode_vec(&bad);
        }
    }

    // SessionInfo bodies (first frame off the wire, attackable pre-session).
    let mut w = wire::Writer::new();
    msg::SessionInfo {
        beacon_id: 1,
        hostname: "h".into(),
        username: "u".into(),
        os: "o".into(),
        arch: 1,
        pid: 2,
        is_admin: 0,
        auth_token: Some([7; 32]),
    }
    .encode(&mut w)
    .unwrap();
    let body = w.into_bytes();
    for len in 0..body.len() {
        let mut r = wire::Reader::new(&body[..len]);
        let _ = msg::SessionInfo::decode(&mut r);
    }
    for pos in 0..body.len() {
        for pattern in [0xFFu8, 0x01, 0x80] {
            let mut bad = body.clone();
            bad[pos] ^= pattern;
            let mut r = wire::Reader::new(&bad);
            let _ = msg::SessionInfo::decode(&mut r);
        }
    }
}

#[test]
fn open_frame_never_panics_on_degenerate_ciphertexts() {
    // RawFrames with ciphertexts below/around the tag length — reachable if a
    // future caller constructs RawFrame by hand. AEAD decrypt of ct < tag must
    // return Err, never panic (chacha20poly1305's decrypt path).
    let (_, key) = session();
    let pubkey = [0x10; crypto::PUBKEY_LEN];
    for len in 0..40usize {
        let raw = frame::RawFrame {
            pubkey,
            counter: 0,
            ciphertext: vec![0xA5; len],
        };
        assert!(
            frame::open_frame_dir(&key, crypto::Direction::ClientToServer, &raw).is_err(),
            "ciphertext of {len} zero-ish bytes must fail open, not panic"
        );
    }
}
