//! DoS-hardening tests for the beacon endpoint: the team server runs under
//! `panic = "abort"`, so any panic or unbounded allocation on attacker-controlled
//! input is a process-killing DoS. These tests pin down the defenses added in
//! the audit:
//!
//! - An oversized beacon body is rejected before any allocation (C2: no body
//!   size limit + a `u32 ct_len` → multi-GB alloc per request).
//! - A frame whose declared `ct_len` exceeds the cap is rejected (C2).
//! - `handle_beacon` never panics on a well-formed-but-undecryptable frame for
//!   an unknown pubkey (it must return an error, not abort the server) (C3).

use std::sync::Arc;

use nyx_server::{router, AppState};
async fn spawn(state: Arc<AppState>) -> String {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    url
}

/// Extract the HTTP status code from a ureq result. `Error::Status(code, _)`
/// carries a non-2xx status; a `Transport` error (connection reset by a panicked
/// handler, etc.) maps to 0 so the caller can detect "no HTTP response at all".
fn status_of(r: Result<ureq::Response, ureq::Error>) -> u16 {
    match r {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(_) => 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_beacon_body_is_rejected() {
    // A body well over the beacon cap must NOT be buffered into RAM. The router
    // applies a hard `DefaultBodyLimit`; axum rejects the body mid-read, which
    // surfaces to ureq as a transport error (status 0) or a 413 — either is
    // acceptable. The properties that MUST hold: (1) not 2xx, (2) the server
    // process is still alive afterwards (a follow-up request still answers).
    let url = spawn(Arc::new(AppState::default())).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // 4 MiB of zeros — 8x the 512 KiB cap, far larger than any real frame.
    let huge = vec![0u8; 4 * 1024 * 1024];
    let code = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&huge),
    );
    assert_ne!(
        code, 200,
        "oversized body must not be accepted (200); got status {code}"
    );

    // The server must still be alive — a second, well-formed-ish request still
    // gets an HTTP answer (not a connection-refused from a crashed process).
    let probe = vec![0u8; 44 + 16];
    let probe_code = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&probe),
    );
    assert!(
        probe_code != 0,
        "server must survive the oversized body and still answer (got transport error {probe_code})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_ct_len_is_rejected_without_oom() {
    // A minimal header that *claims* a ~1 GiB ciphertext but only ships a few
    // bytes. Before the fix `parse_frame` would try `frame[FRAME_HEADER..ct_end]`
    // and panic on the slice index (abort). Now it must return a clean 4xx.
    let url = spawn(Arc::new(AppState::default())).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // [32 pubkey][8 counter=0][4 ct_len = 0x40000000 (~1GiB)][a few ct bytes]
    let mut frame = vec![0u8; 32 + 8 + 4 + 8];
    let ct_len: u32 = 0x4000_0000;
    frame[40..44].copy_from_slice(&ct_len.to_le_bytes());
    let code = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&frame),
    );
    assert!(
        (400..500).contains(&code),
        "frame with absurd ct_len must be rejected with 4xx, got {code}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undecryptable_frame_for_unknown_pubkey_does_not_crash() {
    // A frame with a random pubkey and random "ciphertext" — the server can't
    // derive a useful key and open() must fail. The handler must return 400,
    // NOT panic/abort. (Regression guard for the TOCTOU/`.expect()` removal.)
    let url = spawn(Arc::new(AppState::default())).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // 44-byte header + 16-byte (tag-length) garbage ciphertext.
    let mut frame = vec![0xAAu8; 44 + 16];
    // counter = 1 so it's not trivially zero
    frame[32..40].copy_from_slice(&1u64.to_le_bytes());
    // ct_len = 16 (exactly a tag, minimum legal size)
    frame[40..44].copy_from_slice(&16u32.to_le_bytes());

    let code = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&frame),
    );
    assert!(
        (400..500).contains(&code),
        "decryption failure must be 4xx, not a 5xx/panic; got {code}"
    );

    // Server survived: a second request still gets answered (not a crashed process).
    let code2 = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&frame),
    );
    assert!(
        (400..500).contains(&code2),
        "second undecryptable frame should also be 4xx; got {code2}"
    );
}

/// Build a syntactically-valid encrypted check-in frame for a fresh implant
/// keypair against the given server pubkey, so we can drive the beacon handler
/// without the full dev agent. Returns (frame_bytes, pubkey).
fn valid_checkin_frame(server_pub: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    use nyx_protocol::{frame, wire::Writer, ImplantKeypair, SessionInfo};
    let ikp = ImplantKeypair::generate().unwrap();
    let key = ikp.session_key(server_pub);
    let pubkey = ikp.public_bytes();
    let mut w = Writer::new();
    SessionInfo {
        beacon_id: 1,
        hostname: "t".into(),
        username: "u".into(),
        os: "OS".into(),
        arch: 0,
        pid: 1,
        is_admin: 0,
        auth_token: None,
    }
    .encode(&mut w)
    .expect("test SessionInfo fields are tiny literals << MAX_BLOB_LEN");
    (
        frame::encode_frame(&pubkey, 0, &key, &w.into_bytes())
            .expect("test encode of tiny SessionInfo plaintext is infallible"),
        pubkey,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_task_rejects_when_pending_queue_is_full() {
    // H2: an authenticated operator can enqueue unbounded tasks per session →
    // OOM. Past MAX_PENDING_PER_SESSION the enqueue must be rejected (back-
    // pressure), not silently grow the queue.
    use nyx_server::MAX_PENDING_PER_SESSION;
    // RBAC: open mode now maps anonymous → Viewer (read-only), so post_task
    // would 403. Set a legacy api_token (→ _legacy Admin) and send it as a
    // Bearer — mirrors how a production operator authenticates.
    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
    // Seed one real session via a valid check-in (so post_task finds it).
    let (frame, pubkey) = valid_checkin_frame(&server_pub);
    let url = spawn(state.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let code = status_of(
        ureq::post(format!("{url}/beacon").as_str())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&frame),
    );
    assert!(code == 200, "check-in must succeed, got {code}");
    let session_hex = hex::encode(pubkey);

    // Enqueue MAX_PENDING_PER_SESSION tasks as the authenticated _legacy admin.
    for _ in 0..MAX_PENDING_PER_SESSION {
        let code = status_of(
            ureq::post(format!("{url}/api/task").as_str())
                .set("Authorization", "Bearer test-admin-token")
                .send_json(serde_json::json!({
                    "session": session_hex,
                    "command": { "type": "ping" }
                })),
        );
        assert_eq!(code, 200, "enqueue within cap must succeed");
    }
    // The very next enqueue must be rejected (4xx/5xx), not accepted.
    let over = status_of(
        ureq::post(format!("{url}/api/task").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .send_json(serde_json::json!({
                "session": session_hex,
                "command": { "type": "ping" }
            })),
    );
    assert!(
        over >= 400,
        "enqueue past MAX_PENDING_PER_SESSION ({MAX_PENDING_PER_SESSION}) must be rejected, got {over}"
    );
}
