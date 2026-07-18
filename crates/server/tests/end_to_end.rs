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
