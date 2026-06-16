//! End-to-end P0 test: spin the server, run the std dev agent, queue a shell
//! task through the control API, and assert the encrypted round-trip delivers
//! the command output. Exercises the full beacon loop (check-in + task/response).

use std::sync::Arc;
use std::time::Duration;

use nyx_server::{router, AppState};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkin_then_shell_task_roundtrips() {
    let state = Arc::new(AppState::default());
    let server_pub = state.keypair.public_bytes();
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
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
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // 1. wait for the agent to check in.
    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value =
            ureq::get(format!("{url}/api/sessions").as_str()).call().ok()?.into_json().ok()?;
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
        .send_json(body)
        .expect("enqueue task")
        .into_json()
        .expect("task ack json");
    let task_id = ack["task_id"].as_u64().expect("task_id in ack");

    // 3. poll results until the shell output arrives.
    let output = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let arr = rs.as_array()?;
        arr.iter().find_map(|r| {
            if r["task_id"].as_u64() == Some(task_id)
                && r["kind"].as_str() == Some("output")
            {
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
    let _ = ureq::post(format!("{url}/api/task").as_str()).send_json(exit);
    // allow the agent thread to process Exit and return.
    let join = tokio::task::spawn_blocking(move || agent.join());
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
}

/// P1 file-transfer round-trip: task an upload (verify the bytes landed on the
/// shared dev-host filesystem), then task a download of the same file and
/// reassemble the streamed FileChunks back through the control API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_then_download_roundtrips() {
    let state = Arc::new(AppState::default());
    let server_pub = state.keypair.public_bytes();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
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
    };
    let work_path = work.path().to_path_buf();
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value =
            ureq::get(format!("{url}/api/sessions").as_str()).call().ok()?.into_json().ok()?;
        list.as_array()?.first()?["id"].as_str().map(|s| s.to_string())
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
        .send_json(body)
        .expect("enqueue upload")
        .into_json()
        .expect("upload ack");
    let up_task = ack["task_id"].as_u64().expect("upload task_id");

    // Wait for the agent to ack (Response::Ok). The file is written inside the
    // same execute() call that produces the ack, so once acked the file exists.
    poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
            .query("session", &session)
            .call()
            .ok()?
            .into_json()
            .ok()?;
        let acked = rs
            .as_array()?
            .iter()
            .any(|r| r["task_id"] == up_task && r["kind"] == "ok");
        if acked { Some(()) } else { None }
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
        .send_json(body)
        .expect("enqueue download")
        .into_json()
        .expect("download ack");
    let dn_task = ack["task_id"].as_u64().expect("download task_id");

    let got = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
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
    let _ = ureq::post(format!("{url}/api/task").as_str()).send_json(exit);
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

    let state = AppState {
        profile: Some(nyx_server::load_profile(&path).expect("profile must load+lint")),
        ..AppState::default()
    };
    let server_pub = state.keypair.public_bytes();
    let app = router(Arc::new(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
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
    };
    let agent = std::thread::spawn(move || nyx_agent_dev::run(cfg));

    // Check-in must succeed over the malleable URI.
    let session = poll_until(Duration::from_secs(10), || async {
        let list: serde_json::Value =
            ureq::get(format!("{url}/api/sessions").as_str()).call().ok()?.into_json().ok()?;
        list.as_array()?.first()?["id"].as_str().map(|s| s.to_string())
    })
    .await
    .expect("agent never checked in over the malleable URI");

    // A shell task must round-trip over the same malleable URI.
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": "echo malleable-ok" },
    });
    let ack: serde_json::Value = ureq::post(format!("{url}/api/task").as_str())
        .send_json(body)
        .expect("enqueue shell")
        .into_json()
        .expect("shell ack");
    let task_id = ack["task_id"].as_u64().expect("task_id");
    let out = poll_until(Duration::from_secs(10), || async {
        let rs: serde_json::Value = ureq::get(format!("{url}/api/results").as_str())
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
    let _ = ureq::post(format!("{url}/api/task").as_str()).send_json(exit);
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
