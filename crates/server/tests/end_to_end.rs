//! End-to-end P0 test: spin the server, run the std dev agent, queue a shell
//! task through the control API, and assert the encrypted round-trip delivers
//! the command output. Exercises the full beacon loop (check-in + task/response).

use std::sync::Arc;
use std::time::Duration;

use nyx_server::{router, AppState};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkin_then_shell_task_roundtrips() {
    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Run the (blocking) dev agent on an OS thread.
    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/beacon".into(),
        profile: None,
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // 1. wait for the agent to check in.
    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = list.as_array()?;
        arr.first()?["id"].as_str().map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in");

    // 2. queue a shell task via the control API.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo nyx-p0-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue task")
        .into_json()
        .expect("task ack json");
    let task_id = ack["task_id"].as_u64().expect("task_id in ack");

    // 3. poll results until the shell output arrives.
    let output = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        arr.iter().find_map(|r| {
            if r["task_id"].as_u64() == Some(task_id) && r["kind"].as_str() == Some("output") {
                r["text"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .expect("never received shell output");
    assert!(
        output.contains("nyx-p0-ok"),
        "unexpected shell output: {output:?}"
    );

    // 4. shut the agent down cleanly via an Exit task.
    let exit = serde_json::json!({
        "session": session,
        "command": { "type": "exit" },
    });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    // allow the agent thread to process Exit and return.
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// P1 file-transfer round-trip: task an upload (verify the bytes landed on the
/// shared dev-host filesystem), then task a download of the same file and
/// reassemble the streamed FileChunks back through the control API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_then_download_roundtrips() {
    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The dev agent runs in-process, so it shares this filesystem: uploads land
    // in `work` and we can read them back directly to verify.
    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/beacon".into(),
        profile: None,
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let work_path = work.path().to_path_buf();
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        list.as_array()?.first()?["id"]
            .as_str()
            .map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in");

    // 1. Upload known bytes to a nested path.
    let payload = b"NYX-UPLOAD-PAYLOAD-{deadbeef}\n".to_vec();
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "upload", "name": "loot/secret.bin", "data_hex": hex::encode(&payload) },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue upload")
        .into_json()
        .expect("upload ack");
    let up_task = ack["task_id"].as_u64().expect("upload task_id");

    // Wait for the agent to ack (Response::Ok). The file is written inside the
    // same execute() call that produces the ack, so once acked the file exists.
    poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let acked = rs
            .as_array()?
            .iter()
            .any(|r| r["task_id"] == up_task && r["kind"] == "ok");
        if acked {
            Some(())
        } else {
            None
        }
    })
    .await
    .expect("upload never acked");
    let written = std::fs::read(work_path.join("loot/secret.bin")).expect("file missing after ack");
    assert_eq!(written, payload, "uploaded bytes must match");

    // 2. Download the same file back through the beacon and reassemble chunks.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "download", "path": "loot/secret.bin" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue download")
        .into_json()
        .expect("download ack");
    let dn_task = ack["task_id"].as_u64().expect("download task_id");

    let got = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut eof = false;
        for r in arr {
            if r["task_id"] == dn_task && r["kind"] == "file" {
                let seq = r["seq"].as_u64()? as u32;
                let data = hex::decode(r["data_hex"].as_str()?).ok()?;
                if r["eof"].as_u64()? == 1 {
                    eof = true;
                }
                if !chunks.iter().any(|(s, _)| *s == seq) {
                    chunks.push((seq, data));
                }
            }
        }
        if eof {
            chunks.sort_by_key(|(s, _)| *s);
            let mut out = Vec::new();
            for (_, d) in chunks {
                out.extend(d);
            }
            Some(out)
        } else {
            None
        }
    })
    .await
    .expect("download never completed");
    assert_eq!(got, payload, "downloaded bytes must match uploaded payload");

    // 3. teardown
    let exit = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// Malleable C2 transport: load a profile whose http-post URI is custom, serve
/// the beacon handler there, and confirm an agent beaconing over that URI (not
/// `/beacon`) can still check in and run a shell task end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malleable_beacon_uri_roundtrips() {
    let profile_src = r#"http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } } http-post { set uri "/api/v1/Telemetry"; client { output { print; } } server { output { print; } } }"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("custom.profile");
    std::fs::write(&path, profile_src).unwrap();

    let profile = nyx_server::load_profile(&path).expect("profile must load+lint");
    let state = AppState {
        profile: Some(profile.clone()),
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    };
    let server_pub = state.keypair.public_bytes();
    let app = router(Arc::new(state));

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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        // The profile's http-post URI — NOT /beacon.
        beacon_uri: "/api/v1/Telemetry".into(),
        // The agent gets the same profile so it can invert the server envelope.
        profile: Some(profile),
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // Check-in must succeed over the malleable URI.
    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        list.as_array()?.first()?["id"]
            .as_str()
            .map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in over the malleable URI");

    // A shell task must round-trip over the same malleable URI.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo malleable-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue shell")
        .into_json()
        .expect("shell ack");
    let task_id = ack["task_id"].as_u64().expect("task_id");
    let out = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        rs.as_array()?.iter().find_map(|r| {
            if r["task_id"] == task_id && r["kind"] == "output" {
                r["text"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .expect("no shell output over the malleable URI");
    assert!(out.contains("malleable-ok"), "unexpected output: {out:?}");

    let exit = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// Control-API guardrail: when NYX_TOKEN is set, `/api/*` requires a matching
/// `Authorization: Bearer` header; `/beacon` stays open (crypto-authenticated).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_token_guards_control_api() {
    let state = AppState {
        api_token: Some("sekret".into()),
        ..AppState::default()
    };
    let app = router(Arc::new(state));
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // No token -> 401 (ureq surfaces non-2xx as Err::Status).
    let no_auth_status = match ureq::get(format!("{url}/api/sessions").as_str()).call() {
        Err(ureq::Error::Status(code, _)) => code,
        Ok(r) => panic!("expected 401 rejection, got {}", r.status()),
        Err(e) => panic!("expected 401, got transport error: {e}"),
    };
    assert_eq!(
        no_auth_status, 401,
        "unauthenticated request must be rejected"
    );

    // Correct bearer token -> 200.
    let with_auth = ureq::get(format!("{url}/api/sessions").as_str())
        .set("Authorization", "Bearer sekret")
        .call()
        .expect("correct token should yield 200");
    assert_eq!(
        with_auth.status(),
        200,
        "correct bearer token must be accepted"
    );
}

/// All five control-API endpoints carry the `require_auth` guard. This pins
/// that coverage so a future handler added without the guard is caught, and
/// asserts the observable constant-time contract: a missing token and a
/// wrong token are indistinguishable (both 401 — the server reveals nothing
/// about how many leading bytes of the token matched).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_control_api_endpoints_require_bearer_auth() {
    let state = AppState {
        api_token: Some("sekret".into()),
        ..AppState::default()
    };
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

    // Every require_auth'd GET endpoint (auth runs before query parsing, so the
    // bogus ?session=x is fine — it never reaches validation).
    let gets = [
        "/api/sessions",
        "/api/tasks?session=x",
        "/api/results?session=x",
        "/api/profile",
    ];
    let get_status = |auth: Option<&str>, path: &str| -> u16 {
        let mut req = ureq::get(format!("{url}{path}").as_str());
        if let Some(a) = auth {
            req = req.set("Authorization", a);
        }
        match req.call() {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("transport error on GET {path}: {e}"),
        }
    };

    // No token AND wrong token must both be 401 on every endpoint.
    for g in gets {
        assert_eq!(
            get_status(None, g),
            401,
            "no-token GET {g} must be rejected"
        );
        assert_eq!(
            get_status(Some("Bearer wrong"), g),
            401,
            "wrong-token GET {g} must be rejected (indistinguishable from no token)"
        );
    }
    // POST /api/task: axum's `Json` extractor runs BEFORE the handler body (and
    // thus before require_auth), so a non-JSON body short-circuits to 415. Send a
    // valid JSON body so the request reaches the auth gate.
    for auth in [None, Some("Bearer wrong")] {
        let mut req = ureq::post(format!("{url}/api/task").as_str());
        if let Some(a) = auth {
            req = req.set("Authorization", a);
        }
        let code = match req.send_json(serde_json::json!({
            "session": "x", "command": { "type": "ping" }
        })) {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("transport error on POST /api/task: {e}"),
        };
        assert_eq!(code, 401, "POST /api/task with {auth:?} must be rejected");
    }
    // Correct token: auth passes on every endpoint (status != 401 — a GET may be
    // 200, a bodyless POST may 4xx, but neither is an auth failure).
    for g in gets {
        assert_ne!(
            get_status(Some("Bearer sekret"), g),
            401,
            "correct-token GET {g} must pass the auth gate"
        );
    }
}

/// Scripting wiring: the server must fire `SessionNew` (on check-in) and
/// `ResultReceived` (on a task result) into the event bus. We register a
/// LogHook and assert both events arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripting_events_fire_on_beacon_cycle() {
    let mut state = AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    };
    let log = nyx_scripting::LogHook::new();
    let recs = log.records.clone();
    state.events.register(Box::new(log));
    let server_pub = state.keypair.public_bytes();
    let app = router(Arc::new(state));

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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/beacon".into(),
        profile: None,
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        list.as_array()?.first()?["id"]
            .as_str()
            .map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in");

    // Check-in must have fired SessionNew into the LogHook.
    poll_until(Duration::from_secs(5), || async {
        let r = recs.lock().unwrap();
        if r.iter().any(|l| l.contains("session_new")) {
            Some(())
        } else {
            None
        }
    })
    .await
    .expect("SessionNew event never fired");

    // Task a shell so a ResultReceived fires.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo ev-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .unwrap()
        .into_json()
        .unwrap();
    let task_id = ack["task_id"].as_u64().unwrap();
    poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        rs.as_array()?.iter().find_map(|r| {
            if r["task_id"] == task_id && r["kind"] == "output" {
                r["text"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .expect("shell output");

    poll_until(Duration::from_secs(5), || async {
        let r = recs.lock().unwrap();
        if r.iter().any(|l| l.contains("result")) {
            Some(())
        } else {
            None
        }
    })
    .await
    .expect("ResultReceived event never fired");

    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(serde_json::json!({ "session": session, "command": { "type": "exit" } }));
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// `GET /api/profile` exposes the active Malleable C2 profile (or loaded:false).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_endpoint_exposes_loaded_profile() {
    let profile_src = r#"set useragent "Mozilla/5.0 NyxBrowser";
        http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } }
        http-post { set uri "/api/v1/Telemetry"; client { output { print; } } server { output { print; } } }"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("p.profile");
    std::fs::write(&path, profile_src).unwrap();

    let state = AppState {
        profile: Some(nyx_server::load_profile(&path).expect("profile load")),
        ..AppState::default()
    };
    let app = router(Arc::new(state));
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let v: serde_json::Value = ureq::get(format!("{url}/api/profile").as_str())
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(v["loaded"], true, "profile is loaded: {v}");
    assert_eq!(v["http_get_uri"], "/api/v1/Updates");
    assert_eq!(v["http_post_uri"], "/api/v1/Telemetry");
    assert_eq!(v["useragent"], "Mozilla/5.0 NyxBrowser");
}

/// M0 profile-envelope round-trip: the server applies a transform chain
/// (base64 + prepend + append) to http-post responses, and the agent — given
/// the same profile — inverts it to recover the encrypted frame. This proves
/// the Malleable C2 envelope is actually wired into the beacon loop (not just
/// parsed). A raw-frame agent would fail to decrypt here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_output_transform_envelope_roundtrips() {
    // The server wraps its http-post response: base64 the frame, then prepend a
    // JFIF-ish header and append a footer. The agent must undo all three.
    let profile_src = r#"http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } }
        http-post {
            set uri "/api/v1/Telemetry";
            client { output { print; } }
            server {
                output {
                    base64;
                    prepend "\xff\xd8\xff\xe0";
                    append "\xff\xd9";
                    print;
                }
                header "Content-Type" "image/jpeg";
            }
        }"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("env.profile");
    std::fs::write(&path, profile_src).unwrap();

    let profile = nyx_server::load_profile(&path).expect("profile must load+lint");
    let state = AppState {
        profile: Some(profile.clone()),
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    };
    let server_pub = state.keypair.public_bytes();
    let app = router(Arc::new(state));

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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/api/v1/Telemetry".into(),
        profile: Some(profile),
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // Check-in over the envelope-shaped transaction must succeed.
    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        list.as_array()?.first()?["id"]
            .as_str()
            .map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in through the transform envelope");

    // A shell task must round-trip: server envelopes the response, agent unwraps.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo envelope-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue shell")
        .into_json()
        .expect("shell ack");
    let task_id = ack["task_id"].as_u64().expect("task_id");
    let out = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        rs.as_array()?.iter().find_map(|r| {
            if r["task_id"] == task_id && r["kind"] == "output" {
                r["text"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .expect("no shell output through the transform envelope");
    assert!(out.contains("envelope-ok"), "unexpected output: {out:?}");

    let exit = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// Poll an async closure at ~5 Hz until it returns Some or the budget elapses.
async fn poll_until<T, F, Fut>(budget: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(v) = f().await {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ---- DoH DNS channel (spec-2): HTTP JSON /dns-query path -------------------
//
// Upload a sealed check-in frame through the RFC 8484 JSON endpoint exactly
// like DohDnsTransport would (chunked TXT queries), then poll task.{domain}
// for the sealed reply. Proves the authoritative responder is mounted on the
// axum router and the chunk→session→reply funnel works over HTTP.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_http_chunk_upload_then_task_poll_roundtrips() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use nyx_protocol::{
        encode_frame_dir, open_frame_dir, wire::Writer, Direction, ImplantKeypair, SessionInfo,
    };

    let state = Arc::new(AppState {
        doh: Some(nyx_server::dns_responder::DohState::new("c2.test".into())),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Seal a check-in frame.
    let ikp = ImplantKeypair::generate().unwrap();
    let pubkey = ikp.public_bytes();
    let key = ikp.session_key(&server_pub).unwrap();
    let mut w = Writer::new();
    SessionInfo {
        beacon_id: 9,
        hostname: "doh-http-host".into(),
        username: "tester".into(),
        os: "linux".into(),
        arch: 2,
        pid: 99,
        is_admin: 0,
        auth_token: None,
    }
    .encode(&mut w)
    .unwrap();
    let frame =
        encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes()).unwrap();

    // Upload the chunks via POST /dns-query (JSON, dns-json content type).
    for (i, chunk) in frame.chunks(160).enumerate() {
        let b64 = B64.encode(chunk);
        let mut labels: Vec<&str> = Vec::new();
        let mut rest = b64.as_str();
        while !rest.is_empty() {
            let split = rest.len().min(63);
            labels.push(&rest[..split]);
            rest = &rest[split..];
        }
        let name = format!("c0-{i}.{}.c2.test", labels.join("."));
        let body = serde_json::json!({ "name": name, "type": 16 });
        let resp: serde_json::Value = ureq::post(format!("{url}/dns-query").as_str())
            .set("Content-Type", "application/dns-json")
            .send_json(body)
            .expect("dns-query POST")
            .into_json()
            .expect("dns-query JSON");
        assert_eq!(resp["Status"], 0, "chunk upload must return Status 0");
    }

    // Poll task.c2.test until the sealed reply arrives.
    let reply = poll_until(Duration::from_secs(10), || async {
        let body = serde_json::json!({ "name": "task.c2.test", "type": 16 });
        let resp: serde_json::Value = ureq::post(format!("{url}/dns-query").as_str())
            .set("Content-Type", "application/dns-json")
            .send_json(body)
            .ok()?
            .into_json()
            .ok()?;
        let data = resp
            .get("Answer")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|rr| rr["data"].as_str())?;
        let frame = B64.decode(data).ok()?;
        Some(frame)
    })
    .await
    .expect("no reply via task.c2.test poll");

    // The reply must be a valid server→client frame for our session.
    let raw = nyx_protocol::parse_frame(&reply).expect("reply parses as a frame");
    assert_eq!(raw.pubkey, pubkey);
    open_frame_dir(&key, Direction::ServerToClient, &raw).expect("reply opens with session key");

    // health.c2.test A canary answers too.
    let body = serde_json::json!({ "name": "health.c2.test", "type": 1 });
    let resp: serde_json::Value = ureq::post(format!("{url}/dns-query").as_str())
        .set("Content-Type", "application/dns-json")
        .send_json(body)
        .expect("health query")
        .into_json()
        .expect("health JSON");
    assert_eq!(resp["Status"], 0);
}

// ---- TCP pivot channel (spec-3): reverse_tcp parent -------------------------
//
// The implant child connects out, sends one length-prefixed frame, reads the
// reply, closes. This test drives the server-side parent exactly like the
// child's send_recv would.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_pivot_reverse_tcp_roundtrips() {
    use nyx_protocol::{
        encode_frame_dir, open_frame_dir, wire::Writer, Direction, ImplantKeypair, SessionInfo,
    };

    let state = Arc::new(AppState::default());
    let server_pub = state.keypair.public_bytes();

    // Mount the pivot listener on an ephemeral port and serve connections
    // with the module's per-connection path (same code spawn() uses).
    let pivot = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pivot_addr = pivot.local_addr().unwrap();
    let pivot_state = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = pivot.accept().await.unwrap();
            let st = pivot_state.clone();
            tokio::spawn(async move {
                let _ = nyx_server::tcp_pivot::serve_connection(&st, stream, peer).await;
            });
        }
    });

    // Seal a check-in frame like the implant child would.
    let ikp = ImplantKeypair::generate().unwrap();
    let pubkey = ikp.public_bytes();
    let key = ikp.session_key(&server_pub).unwrap();
    let mut w = Writer::new();
    SessionInfo {
        beacon_id: 11,
        hostname: "tcp-pivot-host".into(),
        username: "tester".into(),
        os: "windows".into(),
        arch: 0,
        pid: 111,
        is_admin: 1,
        auth_token: None,
    }
    .encode(&mut w)
    .unwrap();
    let frame =
        encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes()).unwrap();

    // Child transaction: connect, write [4B LE len][frame], read reply.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(pivot_addr).await.unwrap();
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(&frame);
    sock.write_all(&out).await.unwrap();

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut len_buf))
        .await
        .expect("reply length prefix timeout")
        .unwrap();
    let reply_len = u32::from_le_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut reply))
        .await
        .expect("reply body timeout")
        .unwrap();

    // The reply must be a valid server→client frame for our session.
    let raw = nyx_protocol::parse_frame(&reply).expect("reply parses as a frame");
    assert_eq!(raw.pubkey, pubkey);
    open_frame_dir(&key, Direction::ServerToClient, &raw).expect("reply opens with session key");

    // The session registry must contain the new session (peer = pivot conn).
    assert!(state.sessions.contains_key(&pubkey));
}

// ---- DoH channel full beacon loop (spec-2) ----------------------------------
//
// The dev agent beacons over DoH DNS (channel=Doh, DohDnsTransport against the
// server's /dns-query responder): check-in → task → shell output, all over
// chunked TXT queries + task.{domain} polls. This is the end-to-end proof that
// the DNS channel is wired: client transport, authoritative responder, and the
// standard beacon funnel all work together.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_agent_full_beacon_loop_roundtrips() {
    let state = AppState {
        api_token: Some("test-admin-token".to_string()),
        doh: Some(nyx_server::dns_responder::DohState::new("c2.test".into())),
        ..AppState::default()
    };
    let state = Arc::new(state);
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/beacon".into(),
        profile: None,
        channel: nyx_agent_dev::BeaconChannelKind::Doh,
        doh_server: format!("{url}/dns-query"),
        doh_domain: "c2.test".into(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // 1. wait for the agent to check in (over DNS).
    let session = poll_until(Duration::from_secs(20), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = list.as_array()?;
        arr.first()?["id"].as_str().map(|s| s.to_string())
    })
    .await
    .expect("doh agent never checked in");

    // 2. queue a shell task.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo doh-wired-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue task")
        .into_json()
        .expect("task ack json");
    let task_id = ack["task_id"].as_u64().expect("task_id in ack");

    // 3. poll results until the shell output arrives (over DNS).
    let output = poll_until(Duration::from_secs(30), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        arr.iter().find_map(|r| {
            if r["task_id"] == task_id && r["kind"] == "output" {
                r["text"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .expect("no shell output via DoH channel");
    assert!(
        output.contains("doh-wired-ok"),
        "unexpected output: {output:?}"
    );

    // Send exit so the agent terminates, then join with a bound.
    let exit = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(15), join).await;
}

// ---- SOCKS relay full chain (pivot): operator → server → agent → socket ---
//
// The dev agent now hosts a real relay channel table (agent-dev/src/pivot.rs,
// std port of the implant's): Connect opens a socket, ChannelData writes to
// it, and pump_channels drains socket→operator data each cycle. This test
// drives the ENTIRE chain through the control API: connect to a local echo
// server, send bytes, receive the echoed bytes back as a Channel result.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_relay_full_chain_roundtrips() {
    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let work = tempfile::tempdir().expect("tempdir");
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
        work_dir: work.path().to_path_buf(),
        beacon_uri: "/beacon".into(),
        profile: None,
        channel: nyx_agent_dev::BeaconChannelKind::Https,
        doh_server: String::new(),
        doh_domain: String::new(),
        impersonate: None,
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = list.as_array()?;
        arr.first()?["id"].as_str().map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in");

    // A local echo server: reads 4 bytes, writes "pong".
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_thread = std::thread::spawn(move || {
        let (mut sock, _) = echo.accept().unwrap();
        let mut buf = [0u8; 4];
        use std::io::{Read, Write};
        sock.read_exact(&mut buf).unwrap();
        sock.write_all(b"pong").unwrap();
        std::thread::sleep(Duration::from_millis(50));
    });

    // 1. Connect: server assigns the chan id.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "connect", "host": "127.0.0.1", "port": echo_port },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue connect")
        .into_json()
        .expect("connect ack json");
    let chan = ack["chan"].as_u64().expect("chan in ack") as u32;

    // 2. Wait for the open ack (kind=channel, "<chan N#0>").
    poll_until(Duration::from_secs(15), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        arr.iter()
            .any(|r| r["kind"] == "channel" && r["text"] == format!("<chan {chan}#0>"))
            .then_some(())
    })
    .await
    .expect("connect never opened a channel on the agent");

    // 3. Send data through the relay.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "channeldata", "chan": chan, "data_hex": hex::encode(b"ping") },
    });
    let _: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("enqueue channeldata")
        .into_json()
        .expect("channeldata ack json");

    // 4. The echoed bytes come back as a Channel result (status 1, hex data).
    let echoed = poll_until(Duration::from_secs(15), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        arr.iter().find_map(|r| {
            if r["kind"] == "channel" && r["text"] == format!("<chan {chan}#1>") {
                r["data_hex"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    })
    .await
    .unwrap_or_else(|| {
        // Diagnostic: dump every result so a wiring failure is visible.
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .set("Authorization", "Bearer test-admin-token")
            .query("session", &session)
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        panic!("no echoed bytes via relay; results so far: {rs:?}");
    });
    assert_eq!(
        hex::decode(&echoed).expect("hex data"),
        b"pong",
        "relay must deliver the echo server's reply"
    );

    // 5. Teardown: close the channel, then exit the agent.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "channelclose", "chan": chan },
    });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body);
    let exit = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(format!("{url}/api/task").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(exit);
    let join = tokio::task::spawn_blocking(move || {
        let _ = echo_thread.join();
        agent.join()
    });
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
}

// ---- Collaboration API (M3): ownership + roster + report ---------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ownership_roster_and_report_roundtrip() {
    use nyx_protocol::{encode_frame_dir, wire::Writer, Direction, ImplantKeypair, SessionInfo};

    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        ..AppState::default()
    });
    let server_pub = state.keypair.public_bytes();
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Register a session directly via the beacon path (no agent needed).
    let ikp = ImplantKeypair::generate().unwrap();
    let pubkey = ikp.public_bytes();
    let key = ikp.session_key(&server_pub).unwrap();
    let mut w = Writer::new();
    SessionInfo {
        beacon_id: 5,
        hostname: "collab-host".into(),
        username: "tester".into(),
        os: "linux".into(),
        arch: 2,
        pid: 5,
        is_admin: 0,
        auth_token: None,
    }
    .encode(&mut w)
    .unwrap();
    let frame =
        encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes()).unwrap();
    ureq::post(format!("{url}/beacon").as_str())
        .send_bytes(&frame)
        .expect("beacon check-in");
    let session = hex::encode(pubkey);

    // 1. Assign an owner.
    let body = serde_json::json!({ "session": session, "owner": "alice" });
    let resp: serde_json::Value = ureq::post(format!("{url}/api/session/owner").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("set owner")
        .into_json()
        .expect("owner ack");
    assert_eq!(resp["ok"], true);

    // 2. Sessions list reflects the owner.
    let list: serde_json::Value = ureq::get(format!("{url}/api/sessions").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .call()
        .expect("list sessions")
        .into_json()
        .expect("sessions json");
    let view = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == session)
        .expect("session in list");
    assert_eq!(view["owner"], "alice");

    // 3. Clearing ownership works.
    let body = serde_json::json!({ "session": session, "owner": null });
    let _: serde_json::Value = ureq::post(format!("{url}/api/session/owner").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(body)
        .expect("clear owner")
        .into_json()
        .expect("clear ack");

    // 4. Operator roster (empty in open mode).
    let roster: serde_json::Value = ureq::get(format!("{url}/api/operators").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .call()
        .expect("operators")
        .into_json()
        .expect("operators json");
    assert!(roster.as_array().is_some());

    // 5. Report contains the session row.
    let report = ureq::get(format!("{url}/api/report").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .call()
        .expect("report")
        .into_string()
        .expect("report body");
    assert!(report.contains("# Nyx engagement report"), "report header");
    assert!(report.contains("collab-host"), "report lists sessions");
    assert!(report.contains("Credential vault"), "report vault section");
    assert!(report.contains("Audit tail"), "report audit section");

    // 6. Viewer cannot assign ownership.
    let body = serde_json::json!({ "session": session, "owner": "eve" });
    match ureq::post(format!("{url}/api/session/owner").as_str()).send_json(body) {
        // Token-configured server: anonymous is denied at the auth gate (401).
        // Open-mode server: anonymous maps to Viewer and the route denies (403).
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {}
        other => panic!("anonymous must be denied, got: {other:?}"),
    }
}
