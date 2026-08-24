//! WP-C wire-format verification: profile traffic-shaping padding
//! (`set padding_min/max`) end-to-end over a real beacon POST round-trip.
//!
//! Drives the live axum server with hand-crafted beacon frames (the same
//! `encode_frame_dir` path the implant uses) so the exact on-wire bytes can be
//! asserted:
//!
//! 1. `padded_beacon_wire_roundtrip` — with `padding_min 32 / padding_max 128`
//!    the response body on the wire is `frame || pad(n) || len2` with
//!    `n ∈ [32, 128]`, lengths vary across transactions, the padded REQUEST
//!    body is decoded (not 400), and stripping + decrypting the response
//!    recovers a valid server frame.
//! 2. `tampered_padding_suffix_rejected` — corrupting the 2-byte length
//!    suffix (invalid base64url, or an in-alphabet value above padding_max)
//!    is rejected with 400, never silently accepted.
//! 3. `zero_padding_profile_byte_identical_to_legacy` — with `padding_max 0`
//!    the response is byte-for-byte identical to the no-profile (legacy)
//!    server for the identical sealed frame against the same server keypair:
//!    the backward-compatibility lock. Frame sealing is deterministic (nonce
//!    = direction discriminator ‖ counter, no random nonce), so byte equality
//!    is a valid oracle here.

use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use nyx_protocol::{
    encode_frame_dir, open_frame_dir, parse_frame, wire::Writer, Direction, ImplantKeypair,
    ServerKeypair, SessionInfo,
};
use nyx_server::{router, AppState};

const PAD_MIN: usize = 32;
const PAD_MAX: usize = 128;
/// The self-delimiting length suffix is two base64url chars (transform.rs).
const PAD_SUFFIX: usize = 2;

const PADDED_PROFILE: &str = r#"
set padding_min "32";
set padding_max "128";
http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } }
http-post { set uri "/api/v1/Telemetry"; client { output { print; } } server { output { print; } } }
"#;

/// Explicit zero must behave exactly like "options absent" (padding disabled).
const ZERO_PAD_PROFILE: &str = r#"
set padding_min "0";
set padding_max "0";
http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } }
http-post { set uri "/api/v1/Telemetry"; client { output { print; } } server { output { print; } } }
"#;

fn load_profile(src: &str) -> nyx_profile::Profile {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pad.profile");
    std::fs::write(&path, src).unwrap();
    nyx_server::load_profile(&path).expect("profile must load+lint")
}

/// Spin the axum router on an ephemeral loopback port; return the base URL.
async fn start_server(state: AppState) -> String {
    let app = router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    url
}

/// Seal a fresh check-in frame (new implant keypair, counter 0) the way the
/// implant would. Returns the keypair (to derive the session key later) and
/// the raw frame bytes.
fn seal_checkin(server_pub: &[u8; 32], beacon_id: u32) -> (ImplantKeypair, Vec<u8>) {
    let ikp = ImplantKeypair::generate().expect("implant keypair");
    let pubkey = ikp.public_bytes();
    let key = ikp.session_key(server_pub).expect("session key");
    let mut w = Writer::new();
    SessionInfo {
        beacon_id,
        hostname: "pad-wire-host".into(),
        username: "tester".into(),
        os: "linux".into(),
        arch: 2,
        pid: 4242,
        is_admin: 0,
        auth_token: None,
    }
    .encode(&mut w)
    .expect("SessionInfo encode");
    let frame = encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes())
        .expect("seal check-in frame");
    (ikp, frame)
}

/// POST raw bytes; return (status, response body). Non-2xx is a status, not a
/// panic; transport errors panic (the server must be reachable).
fn post_bytes(url: &str, body: &[u8]) -> (u16, Vec<u8>) {
    match ureq::post(url)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(body)
    {
        Ok(resp) => {
            let status = resp.status();
            let mut buf = Vec::new();
            resp.into_reader()
                .read_to_end(&mut buf)
                .expect("read response body");
            (status, buf)
        }
        Err(ureq::Error::Status(code, _)) => (code, Vec::new()),
        Err(e) => panic!("transport error on POST {url}: {e}"),
    }
}

/// (a)+(b): padded profile on a live server — wire bytes are shaped, lengths
/// fall in [base+32+2, base+128+2] and vary, and the padded request decodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn padded_beacon_wire_roundtrip() {
    let profile = load_profile(PADDED_PROFILE);
    let client_env = nyx_profile::post_client_envelope(&profile);
    let server_env = nyx_profile::post_server_envelope(&profile);
    assert_eq!(
        (client_env.padding_min, client_env.padding_max),
        (PAD_MIN, PAD_MAX),
        "profile padding options must reach the envelopes"
    );

    let state = AppState {
        profile: Some(profile),
        ..AppState::default()
    };
    let server_pub = state.keypair.public_bytes();
    let url = start_server(state).await;
    let beacon_url = format!("{url}/api/v1/Telemetry");

    let mut resp_wire_lens = BTreeSet::new();
    let mut req_wire_lens = BTreeSet::new();
    for i in 0..8u32 {
        let (ikp, frame) = seal_checkin(&server_pub, 100 + i);
        // Shape the request exactly like the implant does (agent-dev uses the
        // same ClientEnvelope::shape_body path).
        let (wire, extra) = client_env.shape_body(&frame);
        assert!(extra.is_empty(), "print terminator keeps bytes in the body");

        // (a) request side: wire length = frame + pad(n) + len2, n ∈ [32,128].
        let req_overhead = wire.len() - frame.len();
        assert!(
            (PAD_MIN + PAD_SUFFIX..=PAD_MAX + PAD_SUFFIX).contains(&req_overhead),
            "request pad overhead {req_overhead} outside [{}, {}]",
            PAD_MIN + PAD_SUFFIX,
            PAD_MAX + PAD_SUFFIX
        );
        req_wire_lens.insert(wire.len());

        // (b) the padded request body must decode server-side — not a 400.
        let (status, resp_body) = post_bytes(&beacon_url, &wire);
        assert_eq!(status, 200, "padded check-in must be accepted");

        // The response is padded too: strip first, then it must be a valid
        // server→client frame that opens under the session key.
        let stripped = server_env
            .strip_padding(&resp_body)
            .expect("response padding strip");
        let resp_overhead = resp_body.len() - stripped.len();
        assert!(
            (PAD_MIN + PAD_SUFFIX..=PAD_MAX + PAD_SUFFIX).contains(&resp_overhead),
            "response pad overhead {resp_overhead} outside [{}, {}]",
            PAD_MIN + PAD_SUFFIX,
            PAD_MAX + PAD_SUFFIX
        );
        let raw = parse_frame(stripped).expect("stripped response parses as a frame");
        assert_eq!(raw.pubkey, ikp.public_bytes());
        let key = ikp.session_key(&server_pub).expect("session key");
        open_frame_dir(&key, Direction::ServerToClient, &raw)
            .expect("stripped response opens under the session key");
        resp_wire_lens.insert(resp_body.len());
    }

    // Lengths must actually vary — the entire point of the shaping. With 8
    // samples over 97 possible pad lengths an all-equal outcome would mean the
    // PRNG is broken, not bad luck.
    assert!(
        req_wire_lens.len() > 1,
        "request wire lengths must vary across transactions: {req_wire_lens:?}"
    );
    assert!(
        resp_wire_lens.len() > 1,
        "response wire lengths must vary across transactions: {resp_wire_lens:?}"
    );
}

/// (d): a request whose 2-byte length suffix is tampered must be rejected
/// (400), never decoded into a bogus frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_padding_suffix_rejected() {
    let profile = load_profile(PADDED_PROFILE);
    let client_env = nyx_profile::post_client_envelope(&profile);

    let state = AppState {
        profile: Some(profile),
        ..AppState::default()
    };
    let server_pub = state.keypair.public_bytes();
    let url = start_server(state).await;
    let beacon_url = format!("{url}/api/v1/Telemetry");

    // Variant 1: suffix bytes outside the base64url alphabet.
    let (_ikp, frame) = seal_checkin(&server_pub, 200);
    let (mut wire, _) = client_env.shape_body(&frame);
    let n = wire.len();
    wire[n - 2] = 0xFF;
    wire[n - 1] = 0xFF;
    let (status, _) = post_bytes(&beacon_url, &wire);
    assert_eq!(
        status, 400,
        "invalid-base64url padding suffix must be rejected"
    );

    // Variant 2: in-alphabet suffix encoding n = 4095 (63*64+63, "__"), which
    // is above padding_max = 128 → pad_strip range check must fail.
    let (_ikp, frame) = seal_checkin(&server_pub, 201);
    let (mut wire, _) = client_env.shape_body(&frame);
    let n = wire.len();
    wire[n - 2] = b'_';
    wire[n - 1] = b'_';
    let (status, _) = post_bytes(&beacon_url, &wire);
    assert_eq!(
        status, 400,
        "out-of-range padding length suffix must be rejected"
    );

    // Sanity: the UNTAMPERED frame still passes, so the 400s above are the
    // padding check firing, not a broken server.
    let (status, _) = post_bytes(&beacon_url, &client_env.shape_body(&frame).0);
    assert_eq!(status, 200, "untampered control request must succeed");
}

/// (c): backward-compat lock — with `padding_max 0` the wire format is
/// byte-identical to a profile-less (legacy) server. Both servers share one
/// ServerKeypair and receive the identical sealed frame; frame sealing is
/// deterministic, so the replies must match byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_padding_profile_byte_identical_to_legacy() {
    let keypair = ServerKeypair::generate().expect("server keypair");
    let server_pub = keypair.public_bytes();

    let legacy = AppState {
        keypair: keypair.clone(),
        ..AppState::default()
    };
    let zero_pad = AppState {
        keypair,
        profile: Some(load_profile(ZERO_PAD_PROFILE)),
        ..AppState::default()
    };
    let legacy_url = format!("{}/beacon", start_server(legacy).await);
    let zero_pad_url = format!("{}/api/v1/Telemetry", start_server(zero_pad).await);

    let (ikp, frame) = seal_checkin(&server_pub, 300);
    let (s_legacy, b_legacy) = post_bytes(&legacy_url, &frame);
    let (s_zero, b_zero) = post_bytes(&zero_pad_url, &frame);
    assert_eq!(s_legacy, 200, "legacy server must accept the check-in");
    assert_eq!(s_zero, 200, "zero-padding profile must accept the check-in");
    assert_eq!(
        b_legacy, b_zero,
        "padding_max=0 response must be byte-identical to the legacy wire format"
    );

    // And it is the raw frame directly — parseable/openable with no stripping.
    let raw = parse_frame(&b_zero).expect("zero-padding response is a raw frame");
    assert_eq!(raw.pubkey, ikp.public_bytes());
    let key = ikp.session_key(&server_pub).expect("session key");
    open_frame_dir(&key, Direction::ServerToClient, &raw)
        .expect("zero-padding response opens under the session key");
}
