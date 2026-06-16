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
    let cfg = nyx_agent_dev::Config {
        server_url: url.clone(),
        server_pub,
        sleep_seconds: 1,
        jitter_pct: 0,
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
